#include "keycard-qt/command_set.h"
#include "keycard-qt/keycard_channel.h"
#include "keycard-qt/backends/keycard_channel_backend.h"
#include "keycard-qt/pairing_storage.h"
#include "keycard-qt/globalplatform/gp_command_set.h"
#include "keycard-qt/globalplatform/gp_constants.h"
#include <QDebug>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>
#include <QIODevice>
#include <QThread>
#include <QEventLoop>
#include <QMetaObject>
#include <QWaitCondition>
#include <QCoreApplication>

namespace Keycard {

// AID for Keycard applet (default instance = 1)
// Base AID: A0 00 00 08 04 00 01 01 (8 bytes)
// Instance: 01 (1 byte) - default instance index
static const QByteArray KEYCARD_DEFAULT_INSTANCE_AID =
    QByteArray::fromHex("A00000080400010101");

// Helper: PBKDF2-HMAC-SHA256 for pairing password derivation
static QByteArray derivePairingToken(const QString& password)
{
    QByteArray salt = "Keycard Pairing Password Salt";
    QByteArray passwordBytes = password.toUtf8();
    int iterations = 50000;
    int keyLength = 32;
    
    QByteArray result(keyLength, 0);
    QByteArray U, T;
    
    // PBKDF2: derived_key = PBKDF2(password, salt, iterations, keyLength)
    // Using HMAC-SHA256
    for (int block = 1; block <= (keyLength + 31) / 32; ++block) {
        // U_1 = HMAC(password, salt || INT(block))
        QByteArray blockData = salt;
        blockData.append((char)((block >> 24) & 0xFF));
        blockData.append((char)((block >> 16) & 0xFF));
        blockData.append((char)((block >> 8) & 0xFF));
        blockData.append((char)(block & 0xFF));
        
        U = QMessageAuthenticationCode::hash(blockData, passwordBytes, QCryptographicHash::Sha256);
        T = U;
        
        // U_2 through U_iterations
        for (int i = 1; i < iterations; ++i) {
            U = QMessageAuthenticationCode::hash(U, passwordBytes, QCryptographicHash::Sha256);
            // T = U_1 XOR U_2 XOR ... XOR U_iterations
            for (int j = 0; j < U.size(); ++j) {
                T[j] = T[j] ^ U[j];
            }
        }
        
        // Copy T to result
        int offset = (block - 1) * 32;
        int copyLen = qMin(32, keyLength - offset);
        for (int i = 0; i < copyLen; ++i) {
            result[offset + i] = T[i];
        }
    }
    
    return result;
}

CommandSet::CommandSet(std::shared_ptr<Keycard::KeycardChannel> channel, 
                       std::shared_ptr<IPairingStorage> pairingStorage,
                       PairingPasswordProvider passwordProvider,
                       QObject* parent)
    : QObject(parent)
    , m_channel(channel)
    , m_pairingStorage(pairingStorage)
    , m_passwordProvider(passwordProvider)
    , m_secureChannel(new SecureChannel(channel.get()))
{   
    if (!m_channel) {
        qWarning() << "CommandSet: Null channel provided";
        return;
    }

    QThread* currentThread = QThread::currentThread();
    QThread* mainThread = QCoreApplication::instance()->thread();
    if (currentThread != mainThread) {
        qWarning() << "CommandSet: Created in wrong thread! Moving to main thread...";
        moveToThread(mainThread);
        qDebug() << "CommandSet: Moved to main thread";
    }

    // Connect to channel signals (we are the ONLY handler)
    // Use DirectConnection to ensure synchronous execution on main thread
    connect(m_channel.get(), &Keycard::KeycardChannel::targetDetected,
            this, &CommandSet::onTargetDetected,
            Qt::DirectConnection);
    
    connect(m_channel.get(), &Keycard::KeycardChannel::targetLost,
            this, &CommandSet::onTargetLost,
            Qt::DirectConnection);
    
    qDebug() << "CommandSet: Initialized with direct channel connections";
}

CommandSet::~CommandSet() {
};

void CommandSet::invalidateCachedPairing()
{
    m_pairingInfo = PairingInfo();
    m_pairingBoundInstanceUID.clear();
}

void CommandSet::clearStaleCardSessionState()
{
    if (m_secureChannel) {
        m_secureChannel->reset();
    }
    m_wasAuthenticated = false;
    m_cachedPIN.clear();
    m_hasCachedStatus = false;
    m_cachedStatus = ApplicationStatus();
    invalidateCachedPairing();
    m_needsSecureChannelReestablishment = true;
}

bool CommandSet::checkOK(const APDU::Response& response)
{
    if (!response.isOK()) {
        m_lastError = QString("APDU error: SW=%1").arg(response.sw(), 4, 16, QChar('0'));
        qWarning() << m_lastError;
        return false;
    }
    m_lastError.clear();
    return true;
}

APDU::Command CommandSet::buildCommand(uint8_t ins, uint8_t p1, uint8_t p2, const QByteArray& data)
{
    APDU::Command cmd(APDU::CLA, ins, p1, p2);
    if (!data.isEmpty()) {
        cmd.setData(data);
    }
    return cmd;
}

ApplicationInfo CommandSet::select(bool force)
{
    qDebug() << "CommandSet::select()";

    if (!force && m_appInfo.installed) {
        return m_appInfo;
    }
    
    // Build SELECT command for Keycard applet
    APDU::Command cmd(APDU::CLA_ISO7816, APDU::INS_SELECT, 0x04, 0x00);
    cmd.setData(KEYCARD_DEFAULT_INSTANCE_AID);
    cmd.setLe(0);  // Expect response data
    
    // Send command (no secure channel needed, but ensure card is connected)
    APDU::Response response = send(cmd, false);
    
    if (!checkOK(response)) {
        return ApplicationInfo();
    }
    
    const QString previousInstanceHex = m_cardInstanceUID;

    // Parse application info
    m_appInfo = parseApplicationInfo(response.data());

    QString newInstanceHex;
    if (!m_appInfo.instanceUID.isEmpty()) {
        newInstanceHex = m_appInfo.instanceUID.toHex();
    }

    // PC/SC (and some NFC stacks) can report the same target id for a different physical Keycard.
    // onTargetDetected then skips handleCardSwap(); detect swap here via applet instance UID.
    if (!previousInstanceHex.isEmpty() && !newInstanceHex.isEmpty()
        && newInstanceHex != previousInstanceHex) {
        qWarning() << "CommandSet: Applet instance UID changed (same channel target id?) —"
                   << "clearing pairing / secure channel (was:" << previousInstanceHex << "now:" << newInstanceHex << ")";
        clearStaleCardSessionState();
    }
    
    // Update card instance UID for pairing management
    // Only initialized cards have instance UIDs and need pairing
    if (!newInstanceHex.isEmpty()) {
        m_cardInstanceUID = newInstanceHex;
    } else {
        // Pre-initialized card: no instance UID yet, no pairing needed
        m_cardInstanceUID.clear();
        qDebug() << "CommandSet: Pre-initialized card detected (no instance UID yet)";
    }
    qDebug() << "CommandSet: Card selected, UID:" << m_cardInstanceUID;
    
    // Generate ECDH secret if card supports secure channel
    if (!m_appInfo.secureChannelPublicKey.isEmpty()) {
        m_secureChannel->generateSecret(m_appInfo.secureChannelPublicKey);
    }
    
    return m_appInfo;
}

PairingInfo CommandSet::pair(const QString& pairingPassword)
{
    qDebug() << "CommandSet::pair()";

    select();
    
    // Step 1: Send random challenge
    QByteArray challenge(32, 0);
    QRandomGenerator::global()->fillRange(
        reinterpret_cast<quint32*>(challenge.data()), 
        challenge.size() / sizeof(quint32)
    );
    
    APDU::Command cmd1 = buildCommand(APDU::INS_PAIR, APDU::P1PairFirstStep, 0, challenge);
    APDU::Response resp1 = send(cmd1, false);  // No secure channel yet, but ensure card connected
    
    if (!checkOK(resp1)) {
        // Check for specific error: no available pairing slots
        if (resp1.sw() == 0x6A84) {
            m_lastError = "No available pairing slots (SW=6A84). "
                         "All pairing slots are full. To fix:\n"
                         "1. Use an existing pairing from your saved pairings file\n"
                         "2. Use Keycard Connect app to clear pairings\n"
                         "3. Factory reset the card (WARNING: erases all data)";
            qWarning() << "========================================";
            qWarning() << " PAIRING FAILED: No available slots!";
            qWarning() << " Your Keycard has all pairing slots full.";
            qWarning() << "========================================";
            qWarning() << " Solutions:";
            qWarning() << " 1. Check if you have a saved pairing in your pairings file";
            qWarning() << " 2. Download Keycard Connect app and clear old pairings";
            qWarning() << " 3. Factory reset (WARNING: erases all keys!)";
            qWarning() << "========================================";
        } else {
            m_lastError = QString("Pair step 1 failed: %1").arg(resp1.errorMessage());
        }
        return PairingInfo();
    }
    
    if (resp1.data().size() < 64) {
        m_lastError = "Invalid pair response size";
        return PairingInfo();
    }
    
    QByteArray cardCryptogram = resp1.data().left(32);
    QByteArray cardChallenge = resp1.data().mid(32, 32);
    
    // Step 2: Derive secret hash using PBKDF2
    QByteArray secretHash = derivePairingToken(pairingPassword);
    
    // Verify card cryptogram: expected = SHA256(secretHash + challenge)
    QCryptographicHash hashVerify(QCryptographicHash::Sha256);
    hashVerify.addData(secretHash);
    hashVerify.addData(challenge);
    QByteArray expectedCryptogram = hashVerify.result();
    
    if (expectedCryptogram != cardCryptogram) {
        m_lastError = "Invalid card cryptogram - wrong pairing password";
        qWarning() << "========================================";
        qWarning() << " CommandSet: CRYPTOGRAM MISMATCH!";
        qWarning() << " This means the pairing password is WRONG!";
        qWarning() << "========================================";

        qWarning() << "Expected cryptogram:" << expectedCryptogram.toHex();
        qWarning() << "Received cryptogram:" << cardCryptogram.toHex();
        qWarning() << "========================================";
        qWarning() << " TIP: Card may need to be initialized first with KeycardInitialize.init()";
        qWarning() << " OR: Card was initialized with a different pairing password";
        qWarning() << "========================================";
        return PairingInfo();
    }
    
    // Compute our response: SHA256(secretHash + cardChallenge)
    QCryptographicHash hash2(QCryptographicHash::Sha256);
    hash2.addData(secretHash);
    hash2.addData(cardChallenge);
    QByteArray ourCryptogram = hash2.result();
    
    APDU::Command cmd2 = buildCommand(APDU::INS_PAIR, APDU::P1PairFinalStep, 0, ourCryptogram);
    APDU::Response resp2 = send(cmd2, false);  // No secure channel yet, but ensure card connected
    
    if (!checkOK(resp2)) {
        m_lastError = "Pair step 2 failed";
        return PairingInfo();
    }
    
    if (resp2.data().size() < 33) {
        m_lastError = QString("Invalid pair step 2 response: expected 33 bytes, got %1").arg(resp2.data().size());
        return PairingInfo();
    }

    // Parse pairing info: [pairingIndex (1)][pairingSalt (32)]
    uint8_t pairingIndex = static_cast<uint8_t>(resp2.data()[0]);
    QByteArray salt = resp2.data().mid(1, 32);  // exactly 32 bytes
    
    // Compute pairing key: SHA256(secretHash + salt)
    QCryptographicHash hash3(QCryptographicHash::Sha256);
    hash3.addData(secretHash);
    hash3.addData(salt);
    QByteArray pairingKey = hash3.result();
    
    m_pairingInfo = PairingInfo(pairingKey, pairingIndex);
    m_pairingBoundInstanceUID = m_cardInstanceUID;

    return m_pairingInfo;
}

bool CommandSet::openSecureChannel(const PairingInfo& pairingInfo)
{
    qDebug() << "CommandSet::openSecureChannel() pairingIndex:" << pairingInfo.index;
    
    if (!pairingInfo.isValid()) {
        m_lastError = "Invalid pairing info";
        return false;
    }
    
    m_pairingInfo = pairingInfo;
    m_pairingBoundInstanceUID = m_cardInstanceUID;

    // Build OPEN_SECURE_CHANNEL command
    // P1 = pairing index, data = our ephemeral public key
    QByteArray data = m_secureChannel->rawPublicKey();
    
    if (data.isEmpty()) {
        m_lastError = "No public key available - secure channel not initialized";
        return false;
    }
    
    APDU::Command cmd = buildCommand(APDU::INS_OPEN_SECURE_CHANNEL, pairingInfo.index, 0, data);
    APDU::Response resp = send(cmd, false);  // Opening secure channel, ensure card connected
    
    if (!checkOK(resp)) {
        m_lastError = "Failed to open secure channel";
        return false;
    }
    
    // Derive session keys from response
    // cardData format: [salt (32 bytes)][iv (16 bytes)]
    QByteArray cardData = resp.data();
    
    if (cardData.size() < 48) {
        m_lastError = "Invalid card data size for session key derivation";
        return false;
    }
    
    QByteArray salt = cardData.left(32);
    QByteArray iv = cardData.mid(32);
    
    // Derive encryption and MAC keys using SHA-512 (matching Go's DeriveSessionKeys)
    // hash = SHA512(secret + pairing_key + salt)
    // enc_key = hash[0:32]  (first 32 bytes)
    // mac_key = hash[32:64] (last 32 bytes)
    
    QCryptographicHash hash(QCryptographicHash::Sha512);
    hash.addData(m_secureChannel->secret());
    hash.addData(pairingInfo.key);
    hash.addData(salt);
    QByteArray result = hash.result();  // 64 bytes
    
    QByteArray encKey = result.left(32);   // First 32 bytes for AES-256
    QByteArray macKey = result.mid(32);    // Last 32 bytes for MAC
    
    // Initialize secure channel
    m_secureChannel->init(iv, encKey, macKey);
    
    // Perform mutual authentication
    if (!mutualAuthenticate()) {
        m_lastError = "Mutual authentication failed";
        return false;
    }

    m_needsSecureChannelReestablishment = false;
    
    // Cache status after opening secure channel (matching status-keycard-go)
    // This avoids blocking getStatus() calls later
    try {
        m_cachedStatus = getStatus();
        m_hasCachedStatus = true;
        qDebug() << "CommandSet: Cached status - PIN retries:" << m_cachedStatus.pinRetryCount
                 << "PUK retries:" << m_cachedStatus.pukRetryCount;
    } catch (...) {
        qWarning() << "CommandSet: Failed to cache status after opening secure channel";
        m_hasCachedStatus = false;
    }

    return true;
}

bool CommandSet::mutualAuthenticate()
{
    // Generate random 32-byte challenge
    QByteArray challenge(32, 0);
    QRandomGenerator::global()->fillRange(
        reinterpret_cast<quint32*>(challenge.data()),
        challenge.size() / sizeof(quint32)
    );
    
    APDU::Command cmd = buildCommand(0x11, 0, 0, challenge);  // INS_MUTUALLY_AUTHENTICATE
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

bool CommandSet::init(const Secrets& secrets)
{
    qDebug() << "CommandSet::init()";
    
    // Validate secrets
    if (secrets.pin.length() != 6) {
        m_lastError = "PIN must be 6 digits";
        qWarning() << m_lastError;
        return false;
    }
    
    if (secrets.puk.length() != 12) {
        m_lastError = "PUK must be 12 digits";
        qWarning() << m_lastError;
        return false;
    }
    
    if (secrets.pairingPassword.length() < 5) {
        m_lastError = "Pairing password must be at least 5 characters";
        qWarning() << m_lastError;
        return false;
    }

    auto appInfo = select();
    if (!m_appInfo.installed) {
        qWarning() << "CommandSet::init(): Failed to select applet";
        m_lastError = "Failed to select applet";
        return false;
    }
    
    // Build plaintext data: PIN + PUK + PairingToken
    // PairingToken = PBKDF2(password, salt, 50000 iterations, 32 bytes)
    QByteArray plainData;
    plainData.append(secrets.pin.toUtf8());
    plainData.append(secrets.puk.toUtf8());
    
    // Derive pairing token using PBKDF2-HMAC-SHA256
    QByteArray pairingToken = derivePairingToken(secrets.pairingPassword);
    plainData.append(pairingToken);
    
    qDebug() << "CommandSet: Pairing token derived:" << pairingToken.left(16).toHex() << "...";
    
    // Encrypt with one-shot encryption (using shared secret from SELECT)
    QByteArray encryptedData = m_secureChannel->oneShotEncrypt(plainData);
    
    if (encryptedData.isEmpty()) {
        m_lastError = "Failed to encrypt INIT data";
        return false;
    }
    
    // Send INIT command with encrypted data (no secure channel yet, but ensure card connected)
    APDU::Command cmd = buildCommand(APDU::INS_INIT, 0, 0, encryptedData);
    APDU::Response resp = send(cmd, false);
    
    if (!checkOK(resp)) {
        return false;
    }
    
    // After init, we need to SELECT again to get initialized state
    m_appInfo = select(true);
    // Cache PIN for auto-reauth after NFC session loss
    m_wasAuthenticated = true;
    m_cachedPIN = secrets.pin.toUtf8();
    resetSecureChannel();
    
    try {
        m_cachedStatus = getStatus();
        m_hasCachedStatus = true;
        qDebug() << "CommandSet: Updated cached status after PIN verification - PIN retries:" 
                    << m_cachedStatus.pinRetryCount << "PUK retries:" << m_cachedStatus.pukRetryCount;
    } catch (...) {
        qWarning() << "CommandSet: Failed to update cached status after PIN verification";
    }
    
    return true;
}

bool CommandSet::unpair(uint8_t index)
{
    qDebug() << "CommandSet::unpair() index:" << index;
    
    APDU::Command cmd = buildCommand(APDU::INS_UNPAIR, index);
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

ApplicationStatus CommandSet::getStatus(uint8_t info)
{
    qDebug() << "CommandSet::getStatus() info:" << info;
    
    APDU::Command cmd = buildCommand(APDU::INS_GET_STATUS, info);
    APDU::Response resp = send(cmd, true);
    
    if (!checkOK(resp)) {
        return ApplicationStatus();
    }
    
    return parseApplicationStatus(resp.data());
}

bool CommandSet::verifyPIN(const QString& pin)
{
    qDebug() << "CommandSet::verifyPIN() pinLength:" << pin.length();
    
    APDU::Command cmd = buildCommand(APDU::INS_VERIFY_PIN, 0, 0, pin.toUtf8());
    APDU::Response resp = send(cmd, true);  // Automatic: waitForCard() + ensureSecureChannel()


    // Check for wrong PIN (SW1=0x63, SW2=0xCX where X = remaining attempts)
    if ((resp.sw() & 0x63C0) == 0x63C0) {
        m_cachedStatus.pinRetryCount = resp.sw() & 0x000F;
        m_lastError = QString("Wrong PIN. Remaining attempts: %1").arg(m_cachedStatus.pinRetryCount);
        qWarning() << m_lastError;
        
        // Update cached status with remaining attempts from error response
        m_cachedStatus.pinRetryCount = m_cachedStatus.pinRetryCount;
        m_hasCachedStatus = true;  // Even with error, we have current retry count
        
        return false;
    }
    
    bool result = checkOK(resp);
    if (result) {
        // iOS: Cache PIN for auto-reauth after NFC session loss
        m_wasAuthenticated = true;
        m_cachedPIN = pin;
    }

    // Update cached status after PIN verification (matching status-keycard-go)
    try {
        m_cachedStatus = getStatus();
        m_hasCachedStatus = true;
        qDebug() << "CommandSet: Updated cached status after PIN verification - PIN retries:" 
                    << m_cachedStatus.pinRetryCount << "PUK retries:" << m_cachedStatus.pukRetryCount;
    } catch (...) {
        qWarning() << "CommandSet: Failed to update cached status after PIN verification";
    }
    return result;
}

// Helper function to parse BIP32 derivation path
static QByteArray parseDerivationPath(const QString& path, uint8_t& startingPoint)
{
    // Parse path like "m/44'/60'/0'/0/0" or "../0/0"
    QByteArray result;
    QDataStream stream(&result, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    
    QString cleanPath = path.trimmed();
    
    if (cleanPath == "m") {
        // Go compatibility: plain "m" means master root with empty derivation.
        startingPoint = APDU::P1DeriveKeyFromMaster;
        cleanPath.clear();
    } else if (cleanPath.startsWith("m/")) {
        startingPoint = APDU::P1DeriveKeyFromMaster;
        cleanPath = cleanPath.mid(2);  // Remove "m/"
    } else if (cleanPath.startsWith("../")) {
        startingPoint = APDU::P1DeriveKeyFromParent;
        cleanPath = cleanPath.mid(3);  // Remove "../"
    } else if (cleanPath.startsWith("./")) {
        startingPoint = APDU::P1DeriveKeyFromCurrent;
        cleanPath = cleanPath.mid(2);  // Remove "./"
    } else {
        startingPoint = APDU::P1DeriveKeyFromCurrent;
    }
    
    if (cleanPath.isEmpty()) {
        return result;
    }
    
    QStringList segments = cleanPath.split('/');
    for (const QString& segment : segments) {
        bool ok;
        uint32_t value = segment.endsWith("'") || segment.endsWith("h")
            ? segment.left(segment.length() - 1).toUInt(&ok) | 0x80000000
            : segment.toUInt(&ok);
        
        if (ok) {
            stream << value;
        }
    }
    
    return result;
}

// Security operations

bool CommandSet::changePIN(const QString& newPIN)
{
    qDebug() << "CommandSet::changePIN()";
    
    APDU::Command cmd = buildCommand(APDU::INS_CHANGE_PIN, APDU::P1ChangePinPIN, 0, newPIN.toUtf8());
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

bool CommandSet::changePUK(const QString& newPUK)
{
    qDebug() << "CommandSet::changePUK()";
    
    APDU::Command cmd = buildCommand(APDU::INS_CHANGE_PIN, APDU::P1ChangePinPUK, 0, newPUK.toUtf8());
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

bool CommandSet::unblockPIN(const QString& puk, const QString& newPIN)
{
    qDebug() << "CommandSet::unblockPIN()";
    
    // Concatenate PUK and new PIN
    QByteArray data = puk.toUtf8() + newPIN.toUtf8();
    APDU::Command cmd = buildCommand(APDU::INS_UNBLOCK_PIN, 0, 0, data);
    APDU::Response resp = send(cmd, true);
    
    // Check for wrong PUK (SW1=0x63, SW2=0xCX where X = remaining attempts)
    if ((resp.sw() & 0x63C0) == 0x63C0) {
        m_cachedStatus.pukRetryCount = resp.sw() & 0x000F;
        m_lastError = QString("Wrong PUK. Remaining attempts: %1").arg(m_cachedStatus.pukRetryCount);
        qWarning() << m_lastError;
        return false;
    }
    
    return checkOK(resp);
}

bool CommandSet::changePairingSecret(const QString& newPassword)
{
    qDebug() << "CommandSet::changePairingSecret()";
    
    QByteArray data = newPassword.toUtf8();
    APDU::Command cmd = buildCommand(APDU::INS_CHANGE_PIN, APDU::P1ChangePinPairingSecret, 0, data);
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

// Key management

QByteArray CommandSet::generateKey()
{
    qDebug() << "CommandSet::generateKey()";
    
    APDU::Command cmd = buildCommand(APDU::INS_GENERATE_KEY, 0, 0);
    APDU::Response resp = send(cmd, true);
    
    if (!checkOK(resp)) {
        return QByteArray();
    }
    
    // Response is the key UID (32 bytes)
    return resp.data();
}

QVector<int> CommandSet::generateMnemonic(int checksumSize)
{
    qDebug() << "CommandSet::generateMnemonic() checksumSize:" << checksumSize;
    
    APDU::Command cmd = buildCommand(APDU::INS_GENERATE_MNEMONIC, static_cast<uint8_t>(checksumSize), 0);
    APDU::Response resp = send(cmd, true);
    
    if (!checkOK(resp)) {
        return QVector<int>();
    }
    
    // Parse mnemonic indexes (2 bytes per index, big endian)
    QVector<int> indexes;
    QByteArray data = resp.data();
    for (int i = 0; i + 1 < data.size(); i += 2) {
        uint16_t index = (static_cast<uint8_t>(data[i]) << 8) | static_cast<uint8_t>(data[i + 1]);
        indexes.append(index);
    }
    
    return indexes;
}

QByteArray CommandSet::loadSeed(const QByteArray& seed)
{
    return loadKey(seed, APDU::P2LoadKeyBIP39);
}

QByteArray CommandSet::loadKey(const QByteArray& seed, uint8_t keyType)
{
    qDebug() << "CommandSet::loadKey() keyType:" << keyType;

    if (seed.size() != 64) {
        m_lastError = "Seed must be 64 bytes";
        qWarning() << m_lastError;
        return QByteArray();
    }

    APDU::Command cmd = buildCommand(APDU::INS_LOAD_KEY, APDU::P1LoadKeySeed, keyType, seed);
    APDU::Response resp = send(cmd, true);

    if (!checkOK(resp)) {
        return QByteArray();
    }

    // Response is the key UID (32 bytes)
    return resp.data();
}

bool CommandSet::removeKey()
{
    qDebug() << "CommandSet::removeKey()";
    
    APDU::Command cmd = buildCommand(APDU::INS_REMOVE_KEY, 0, 0);
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

bool CommandSet::deriveKey(const QString& path)
{
    qDebug() << "CommandSet::deriveKey() path:" << path;
    
    uint8_t startingPoint = APDU::P1DeriveKeyFromMaster;
    QByteArray pathData = parseDerivationPath(path, startingPoint);
    
    APDU::Command cmd = buildCommand(APDU::INS_DERIVE_KEY, startingPoint, 0, pathData);
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

// Signing

QByteArray CommandSet::sign(const QByteArray& data)
{
    qDebug() << "CommandSet::sign()";
    
    // Validate input first
    if (data.size() != 32) {
        m_lastError = "Data must be 32 bytes (hash)";
        qWarning() << m_lastError;
        return QByteArray();
    }
    
    APDU::Command cmd = buildCommand(APDU::INS_SIGN, APDU::P1SignCurrentKey, 1, data);
    APDU::Response resp = send(cmd, true);
    
    if (!checkOK(resp)) {
        return QByteArray();
    }
    
    // Response is signature: pubkey (65 bytes) + signature (rest)
    // We return just the signature part (typically 65 bytes: R + S + V)
    QByteArray fullResp = resp.data();
    if (fullResp.size() > 65) {
        return fullResp.mid(65);  // Skip public key, return signature
    }
    return fullResp;
}

QByteArray CommandSet::signWithPath(const QByteArray& data, const QString& path, bool makeCurrent, uint8_t scheme)
{
    qDebug() << "CommandSet::signWithPath() path:" << path << "makeCurrent:" << makeCurrent << "scheme:" << scheme;

    if (data.size() != 32) {
        m_lastError = "Data must be 32 bytes (hash)";
        qWarning() << m_lastError;
        return QByteArray();
    }

    uint8_t startingPoint = APDU::P1DeriveKeyFromMaster;
    QByteArray pathData = parseDerivationPath(path, startingPoint);

    uint8_t p1 = makeCurrent ? APDU::P1SignDeriveAndMakeCurrent : APDU::P1SignDerive;

    QByteArray cmdData = data + pathData;

    APDU::Command cmd = buildCommand(APDU::INS_SIGN, p1, scheme, cmdData);
    APDU::Response resp = send(cmd, true);

    if (!checkOK(resp)) {
        return QByteArray();
    }

    // SIGN response TLV: A0 [ 0x80(pubkey, 65 bytes), <sig-tag>(sig, variable) ]
    // Schnorr: sig-tag = 0x80 → return raw payload (64-byte R||s)
    // ECDSA:   sig-tag = 0x30 → return the FULL TLV item (0x30 + len + contents = DER sig)
    // For 0x80: payload IS the signature. For 0x30: the tag+length+contents IS the DER sig.
    QByteArray fullResp = resp.data();

    // Unwrap outer A0 tag
    QByteArray inner;
    if (!fullResp.isEmpty() && static_cast<uint8_t>(fullResp[0]) == 0xA0) {
        int offset = 1;
        uint8_t l = static_cast<uint8_t>(fullResp[offset++]);
        if (l == 0x81) l = static_cast<uint8_t>(fullResp[offset++]);
        inner = fullResp.mid(offset, l);
    } else {
        inner = fullResp;
    }

    // Skip first 0x80 tag (pubkey), extract signature from next tag
    int i = 0;
    bool pubkeySkipped = false;
    while (i < inner.size()) {
        int tagStart = i;                                  // start of this TLV item
        uint8_t tag = static_cast<uint8_t>(inner[i++]);
        if (i >= inner.size()) break;
        int tagLen = static_cast<uint8_t>(inner[i++]);
        if (tagLen == 0x81 && i < inner.size()) tagLen = static_cast<uint8_t>(inner[i++]);
        if (i + tagLen > inner.size()) break;
        if (!pubkeySkipped && tag == 0x80) {
            pubkeySkipped = true;                          // first 0x80 = pubkey
        } else if (pubkeySkipped) {
            if (tag == 0x80) {
                // Schnorr: 0x80 payload = raw 64-byte R||s
                return inner.mid(i, tagLen);
            } else {
                // ECDSA (0x30): full TLV item = DER-encoded signature
                return inner.mid(tagStart, i - tagStart + tagLen);
            }
        }
        i += tagLen;
    }

    // Fallback: return raw response (handles non-TLV or unexpected formats)
    qWarning() << "signWithPath: could not parse TLV response, returning raw bytes";
    return fullResp;
}

QByteArray CommandSet::signWithPathFullResponse(const QByteArray& data, const QString& path, bool makeCurrent, uint8_t scheme)
{
    qDebug() << "CommandSet::signWithPathFullResponse() path:" << path << "makeCurrent:" << makeCurrent << "scheme:" << scheme;

    if (data.size() != 32) {
        m_lastError = "Data must be 32 bytes (hash)";
        qWarning() << m_lastError;
        return QByteArray();
    }

    uint8_t startingPoint = APDU::P1DeriveKeyFromMaster;
    QByteArray pathData = parseDerivationPath(path, startingPoint);

    uint8_t p1 = makeCurrent ? APDU::P1SignDeriveAndMakeCurrent : APDU::P1SignDerive;

    QByteArray cmdData = data + pathData;

    APDU::Command cmd = buildCommand(APDU::INS_SIGN, p1, scheme, cmdData);
    APDU::Response resp = send(cmd, true);

    if (!checkOK(resp)) {
        return QByteArray();
    }

    return resp.data();
}

QByteArray CommandSet::signPinless(const QByteArray& data)
{
    qDebug() << "CommandSet: SIGN_PINLESS";
    
    // Validate input first
    if (data.size() != 32) {
        m_lastError = "Data must be 32 bytes (hash)";
        qWarning() << m_lastError;
        return QByteArray();
    }
    
    APDU::Command cmd = buildCommand(APDU::INS_SIGN, APDU::P1SignPinless, 1, data);
    APDU::Response resp = send(cmd, true);
    
    if (!checkOK(resp)) {
        return QByteArray();
    }
    
    // Skip public key, return signature
    QByteArray fullResp = resp.data();
    if (fullResp.size() > 65) {
        return fullResp.mid(65);
    }
    return fullResp;
}

bool CommandSet::setPinlessPath(const QString& path)
{
    qDebug() << "CommandSet::setPinlessPath() path:" << path;
    
    // Validate input first
    if (!path.startsWith("m/")) {
        m_lastError = "Pinless path must be absolute (start with m/)";
        qWarning() << m_lastError;
        return false;
    }
    
    uint8_t startingPoint = APDU::P1DeriveKeyFromMaster;
    QByteArray pathData = parseDerivationPath(path, startingPoint);
    
    APDU::Command cmd = buildCommand(APDU::INS_SET_PINLESS_PATH, 0, 0, pathData);
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

// Data storage

bool CommandSet::storeData(uint8_t type, const QByteArray& data)
{
    qDebug() << "CommandSet::storeData() type:" << type << "size:" << data.size();
    
    APDU::Command cmd = buildCommand(APDU::INS_STORE_DATA, type, 0, data);
    APDU::Response resp = send(cmd, true);
    
    return checkOK(resp);
}

QByteArray CommandSet::getData(uint8_t type)
{
    qDebug() << "CommandSet::getData() type:" << type;
    
    APDU::Command cmd = buildCommand(APDU::INS_GET_DATA, type, 0);
    APDU::Response resp = send(cmd, true);
    
    if (!checkOK(resp)) {
        return QByteArray();
    }
    
    return resp.data();
}

// Utilities

QByteArray CommandSet::identify(const QByteArray& challenge)
{
    qDebug() << "CommandSet::identify()";
    
    QByteArray challengeData = challenge;
    if (challengeData.isEmpty()) {
        // Generate random 32-byte challenge
        challengeData.resize(32);
        QRandomGenerator::global()->fillRange(
            reinterpret_cast<quint32*>(challengeData.data()), 
            challengeData.size() / sizeof(quint32)
        );
    }
    
    // IDENTIFY uses standard CLA (0x00), not secure channel CLA (0x80)
    APDU::Command cmd(APDU::CLA_ISO7816, APDU::INS_IDENTIFY, 0, 0);
    cmd.setData(challengeData);
    APDU::Response resp = send(cmd, false);  // Non-secure command, but ensure card connected
    
    if (!checkOK(resp)) {
        return QByteArray();
    }
    
    return resp.data();
}

QByteArray CommandSet::exportKey(bool derive, bool makeCurrent, const QString& path, uint8_t exportType)
{
    uint8_t p1 = APDU::P1ExportKeyCurrent;
    QByteArray pathData;

    if (derive) {
        uint8_t startingPoint = APDU::P1DeriveKeyFromMaster;
        pathData = parseDerivationPath(path, startingPoint);
        p1 = makeCurrent ? APDU::P1ExportKeyDeriveAndMakeCurrent : APDU::P1ExportKeyDerive;
        p1 |= startingPoint;
    }

    APDU::Command cmd = buildCommand(APDU::INS_EXPORT_KEY, p1, exportType, pathData);
    cmd.setLe(0xFF); // Request up to 255 bytes
    
    APDU::Response resp = send(cmd, true);
    
    if (!checkOK(resp)) {
        m_lastError = QString("EXPORT_KEY failed with SW: 0x%1").arg(resp.sw(), 4, 16, QChar('0'));
        return QByteArray();
    }

    return resp.data();
}

QByteArray CommandSet::exportKeyExtended(bool derive, bool makeCurrent, const QString& path, uint8_t exportType)
{
    uint8_t p1 = APDU::P1ExportKeyCurrent;
    QByteArray pathData;
    
    if (derive) {
        uint8_t startingPoint = APDU::P1DeriveKeyFromMaster;
        pathData = parseDerivationPath(path, startingPoint);
        p1 = makeCurrent ? APDU::P1ExportKeyDeriveAndMakeCurrent : APDU::P1ExportKeyDerive;
        p1 |= startingPoint;
    }
    
    APDU::Command cmd = buildCommand(APDU::INS_EXPORT_KEY, p1, exportType, pathData);
    cmd.setLe(0);  // Request all available response data
    
    APDU::Response resp = send(cmd, true);
    
    if (!checkOK(resp)) {
        m_lastError = QString("EXPORT_KEY_EXTENDED failed with SW: 0x%1").arg(resp.sw(), 4, 16, QChar('0'));
        return QByteArray();
    }
    
    return resp.data();
}

void CommandSet::factoryResetCleanup()
{
    // Remove pairing from storage (card is now in factory state)
    if (m_pairingStorage && !m_appInfo.instanceUID.isEmpty()) {
        qDebug() << "CommandSet::factoryReset(): Removing pairing from storage";
        m_pairingStorage->remove(m_appInfo.instanceUID.toHex());
    }
    // Clean up local state after successful factory reset
    m_secureChannel->reset();
    m_appInfo = ApplicationInfo();
    invalidateCachedPairing();
    m_cardInstanceUID.clear();
    m_wasAuthenticated = false;
    m_cachedPIN.clear();
    m_cachedStatus = Keycard::ApplicationStatus();
    select(true);
}

bool CommandSet::factoryReset()
{
    qDebug() << "CommandSet::factoryReset()";
    
    // STEP 1: Select the Keycard applet (required by protocol)
    ApplicationInfo appInfo = select();
    
    // Check if SELECT failed (card may not have Keycard applet installed)
    if (!appInfo.installed) {
        m_lastError = "Failed to select Keycard applet";
        qWarning() << m_lastError;
    }

    // STEP 2: Check if card supports native factory reset
    // v3.0 cards (and earlier) don't support INS_FACTORY_RESET (0xFD)
    if (!appInfo.hasFactoryResetCapability()) {
        qDebug() << "CommandSet::factoryReset(): Card doesn't support native factory reset (v3.0 or earlier)";
        qDebug() << "CommandSet::factoryReset(): Using GP fallback...";
        
        if (factoryResetFallback()) {
            qDebug() << "CommandSet::factoryReset(): GP fallback succeeded";
            factoryResetCleanup();
            return true;
        }
        
        qDebug() << "CommandSet::factoryReset(): GP fallback failed";
        return false;
    }
    
    // STEP 3: Try native factory reset first (for cards that support it)
    qDebug() << "CommandSet::factoryReset(): Attempting native factory reset command...";
    APDU::Command cmd = buildCommand(APDU::INS_FACTORY_RESET, APDU::P1FactoryResetMagic, APDU::P2FactoryResetMagic);
    APDU::Response resp = send(cmd, false);
    
    if (checkOK(resp)) {
        // Native factory reset succeeded
        qDebug() << "CommandSet::factoryReset(): Native factory reset successful!";
        factoryResetCleanup();
        return true;
    }
    
    // STEP 4: Native reset failed - try GP fallback
    
    if (factoryResetFallback()) {
        qDebug() << "CommandSet::factoryReset(): GP fallback succeeded";
        factoryResetCleanup();
        return true;
    }
    
    // STEP 4: First GP attempt failed - retry once
    qDebug() << "CommandSet::factoryReset(): GP fallback failed, retrying (attempt 2)...";
    
    if (factoryResetFallback()) {
        qDebug() << "CommandSet::factoryReset(): GP fallback retry succeeded";
        factoryResetCleanup();
        return true;
    }
    
    qDebug() << "CommandSet::factoryReset(): All factory reset attempts failed";
    return false;
}

bool CommandSet::factoryResetFallback()
{
    qDebug() << "CommandSet::factoryResetFallback() - Using GlobalPlatform commands";
    
    
    qDebug() << "CommandSet::factoryResetFallback(): Starting GlobalPlatform DELETE/INSTALL";
    
    GlobalPlatform::GlobalPlatformCommandSet gpCmd(m_channel.get());
    
    // STEP 1: Select ISD (Issuer Security Domain)
    qDebug() << "CommandSet::factoryResetFallback(): Selecting ISD...";
    if (!gpCmd.select()) {
        m_lastError = QString("GlobalPlatform SELECT ISD failed: %1").arg(gpCmd.lastError());
        qWarning() << m_lastError;
        return false;
    }
    qDebug() << "CommandSet::factoryResetFallback(): ISD selected";
    
    // STEP 2: Open SCP02 secure channel
    qDebug() << "CommandSet::factoryResetFallback(): Opening secure channel...";
    if (!gpCmd.openSecureChannel()) {
        m_lastError = QString("GlobalPlatform secure channel failed: %1").arg(gpCmd.lastError());
        qWarning() << m_lastError;
        return false;
    }
    qDebug() << "CommandSet::factoryResetFallback(): Secure channel opened";
    
    // STEP 3: Delete Keycard applet instance
    QByteArray keycardInstanceAID = GlobalPlatform::KEYCARD_INSTANCE_AID(1);
    qDebug() << "CommandSet::factoryResetFallback(): Deleting Keycard instance" << keycardInstanceAID.toHex();
    
    if (!gpCmd.deleteObject(keycardInstanceAID, false)) {
        m_lastError = QString("GlobalPlatform DELETE failed: %1").arg(gpCmd.lastError());
        qWarning() << m_lastError;
        
        return false;
    }
    qDebug() << "CommandSet::factoryResetFallback(): Keycard instance deleted";
    
    // STEP 4: Reinstall Keycard applet
    qDebug() << "CommandSet::factoryResetFallback(): Installing Keycard applet...";
    if (!gpCmd.installKeycardApplet()) {
        m_lastError = QString("GlobalPlatform INSTALL failed: %1").arg(gpCmd.lastError());
        qWarning() << m_lastError;
        return false;
    }
    
    qDebug() << "CommandSet::factoryResetFallback(): Factory reset via GlobalPlatform successful!";
    
    return true;
}

void CommandSet::resetSecureChannel()
{
    qDebug() << "CommandSet::resetSecureChannel() called - secure channel crypto state will be reset";
    
    // Reset cryptographic state but preserve:
    // - Pairing info (m_pairingInfo) - needed to re-open secure channel
    // - Authentication state (m_wasAuthenticated, m_cachedPIN) - for auto-reauth
    // - App info (m_appInfo) - card metadata still valid
    //
    // Use cases:
    // - iOS: Physical NFC session was closed and reopened
    // - Android: Explicitly close channel between operations (e.g., after authorize())
    
    if (m_secureChannel) {
        m_secureChannel->reset();
    }
    
    // Mark that we need to re-establish before next command
    // This will be checked by ensureSecureChannel() before any secure operation
    m_needsSecureChannelReestablishment = true;
    
    qDebug() << "CommandSet::resetSecureChannel() completed - m_needsSecureChannelReestablishment = true";
}

bool CommandSet::reestablishSecureChannel()
{
    qDebug() << "CommandSet::reestablishSecureChannel()";
    
    // Check if we have pairing info
    if (m_pairingInfo.index < 0) {
        m_lastError = "No pairing info available for re-establishment";
        qWarning() << m_lastError;
        return false;
    }
    
    // Re-open secure channel using cached pairing
    if (!openSecureChannel(m_pairingInfo)) {
        m_lastError = "Failed to re-open secure channel";
        qWarning() << m_lastError;
        return false;
    }

    m_needsSecureChannelReestablishment = false;
    
    // If we were authenticated before, re-authenticate with cached PIN
    if (m_wasAuthenticated && !m_cachedPIN.isEmpty()) {
        
        // IMPORTANT: Temporarily disable auto-reauth to avoid infinite recursion
        // (verifyPIN calls ensureSecureChannel, which would call this again)
        QString cachedPIN = m_cachedPIN;
        m_wasAuthenticated = false;
        m_cachedPIN.clear();
        
        if (!verifyPIN(cachedPIN)) {
            m_lastError = "Failed to re-authenticate with cached PIN";
            qWarning() << m_lastError;
            return false;
        }
    }
    
    return true;
}

bool CommandSet::ensurePairing()
{
    qDebug() << "CommandSet::ensurePairing() for card:" << m_cardInstanceUID;
    
    // Pre-initialized cards don't need pairing - they need to be initialized first
    // This matches status-keycard-go behavior: if !appInfo.Initialized, return early
    if (!m_appInfo.initialized) {
        qDebug() << "CommandSet: Card is pre-initialized, pairing not needed (card must be initialized first)";
        // Clear any invalid pairing info
        invalidateCachedPairing();
        return true;  // Not an error - just means card needs initialization
    }

    // Cached pairing is only valid for the applet instance it was obtained for. Another Keycard can
    // reuse the same PC/SC target id; onTargetDetected then skips handleCardSwap and stale pairing
    // would otherwise be used with the wrong card.
    if (m_pairingInfo.isValid()) {
        if (m_pairingBoundInstanceUID.isEmpty() || m_pairingBoundInstanceUID != m_cardInstanceUID) {
            qDebug() << "CommandSet: Discarding cached pairing (instance UID mismatch or unbound)";
            invalidateCachedPairing();
        } else {
            qDebug() << "CommandSet: Using cached pairing, index:" << m_pairingInfo.index;
            return true;
        }
    }
    
    // Try to load from storage
    if (m_pairingStorage) {
        qDebug() << "CommandSet: Loading pairing from storage";
        m_pairingInfo = m_pairingStorage->load(m_cardInstanceUID);
        
        if (m_pairingInfo.isValid()) {
            m_pairingBoundInstanceUID = m_cardInstanceUID;
            qDebug() << "CommandSet: Loaded pairing from storage, index:" << m_pairingInfo.index;
            return true;
        }
    }
    
    // No pairing found - need to pair
    qDebug() << "CommandSet: No pairing found, attempting to pair";
    
    if (!m_passwordProvider) {
        m_lastError = "No pairing available and no password provider configured";
        qWarning() << m_lastError;
        return false;
    }
    
    // Get pairing password from provider
    QString password = m_passwordProvider(m_cardInstanceUID);
    if (password.isEmpty()) {
        m_lastError = "Pairing password not provided (user cancelled or unavailable)";
        qWarning() << m_lastError;
        return false;
    }
    
    // Perform pairing
    qDebug() << "CommandSet: Pairing with card...";
    m_pairingInfo = pair(password);
    
    if (!m_pairingInfo.isValid()) {
        qWarning() << "CommandSet: Pairing failed:" << m_lastError;
        return false;
    }
    
    qDebug() << "CommandSet: Pairing successful";
    
    // Save to storage for future use
    if (m_pairingStorage) {
        qDebug() << "CommandSet: Saving pairing to storage for card:" << m_cardInstanceUID;
        if (!m_pairingStorage->save(m_cardInstanceUID, m_pairingInfo)) {
            qWarning() << "CommandSet: Failed to save pairing (will need to re-pair next time)";
        }
    }
    
    return true;
}

bool CommandSet::ensureSecureChannel()
{
    qDebug() << "CommandSet::ensureSecureChannel() needsReestablishment:" << m_needsSecureChannelReestablishment 
             << "isOpen:" << (m_secureChannel ? m_secureChannel->isOpen() : false)
             << "wasAuthenticated:" << m_wasAuthenticated;

    // STEP 1: Ensure we have pairing for the current card
    if (!ensurePairing()) {
        return false;  // Error already set by ensurePairing()
    }
    
    // STEP 2: Re-establishment needed after session loss
    if (!m_secureChannel || !m_secureChannel->isOpen()) {
        if (!reestablishSecureChannel()) {
            qWarning() << "CommandSet::ensureSecureChannel(): Failed to re-establish secure channel";
            return false;  // Error already set by reestablishSecureChannel()
        }
    }
    
    // Verify secure channel is actually open
    if (!m_secureChannel || !m_secureChannel->isOpen()) {
        m_lastError = "Secure channel is not open after re-establishment";
        qWarning() << m_lastError;
        return false;
    }
    
    // Secure channel is ready
    qDebug() << "CommandSet: Secure channel already open and ready";
    return true;
}

void CommandSet::clearAuthenticationCache()
{
    m_wasAuthenticated = false;
    m_cachedPIN.clear();
    m_needsSecureChannelReestablishment = false;
}

void CommandSet::handleCardSwap()
{
    qWarning() << "CommandSet: CARD SWAP DETECTED - Clearing ALL state";

    clearStaleCardSessionState();

    m_appInfo = ApplicationInfo();
    
    qWarning() << "CommandSet: All state cleared - flow must restart with new card";
}


bool CommandSet::waitForCard()
{
    qDebug() << "CommandSet::waitForCard(): Waiting for channel events";

    // Check if card is already connected
    if (m_channel && m_channel->isConnected()) {
        qDebug() << "CommandSet::waitForCard(): Card already connected";
        return true;
    }

    QEventLoop loop;
    bool cardDetected = false;
    bool detectionStopped = false;
    QString waitError;

    // Exit when a target is detected.
    QMetaObject::Connection cardConnection = QObject::connect(
        m_channel.get(), &Keycard::KeycardChannel::targetDetected,
        [&loop, &cardDetected](const QString& uid) {
            qDebug() << "CommandSet::waitForCard(): Card detected, UID:" << uid;
            cardDetected = true;
            loop.quit();
        });

    // Exit on channel errors.
    QMetaObject::Connection errorConnection = QObject::connect(
        m_channel.get(), &Keycard::KeycardChannel::error,
        [&loop, &waitError](const QString& error) {
            qDebug() << "CommandSet::waitForCard(): Error waiting for card:" << error;
            waitError = error;
            loop.quit();
        });

    // Exit when backend/platform reports detection has stopped.
    QMetaObject::Connection detectionStoppedConnection = QObject::connect(
        m_channel.get(), &Keycard::KeycardChannel::targetDetectionStopped,
        [&loop, &detectionStopped](bool forced) {
            Q_UNUSED(forced);
            qDebug() << "CommandSet::waitForCard(): Target detection stopped";
            detectionStopped = true;
            loop.quit();
        });

    // Use lambda to call setState (works even if setState is not a slot)
    // Qt::AutoConnection (default) handles thread safety automatically:
    // - Same thread: DirectConnection (synchronous)
    // - Different thread: QueuedConnection (asynchronous)
    bool success = QMetaObject::invokeMethod(
        m_channel.get(),
        [this]() {
            m_channel->setState(Keycard::ChannelState::WaitingForCard);
        }
    );

    if (!success) {
        qWarning() << "CommandSet::waitForCard(): Failed to set channel state to WaitingForCard";
        QObject::disconnect(cardConnection);
        QObject::disconnect(errorConnection);
        QObject::disconnect(detectionStoppedConnection);
        return false;
    }

    // Enter event loop
    loop.exec();

    // Clean up connections
    QObject::disconnect(cardConnection);
    QObject::disconnect(errorConnection);
    QObject::disconnect(detectionStoppedConnection);

    if (cardDetected) {
        qDebug() << "CommandSet::waitForCard(): Card successfully detected";
        return true;
    }

    if (!waitError.isEmpty()) {
        qWarning() << "CommandSet::waitForCard(): Card detection failed:" << waitError;
        m_lastError = waitError;
        return false;
    }

    if (detectionStopped) {
        qDebug() << "CommandSet::waitForCard(): Detection stopped before card was detected";
        m_lastError = "User cancelled NFC";
        throw std::runtime_error(m_lastError.toStdString());
    }

    qWarning() << "CommandSet::waitForCard(): Card detection failed";
    m_lastError = "Card detection failed";
    return false;
}

APDU::Response CommandSet::send(const APDU::Command& cmd, bool secure)
{
    qDebug() << "CommandSet::send() secure:" << secure;
        
    // 1. Ensure card is connected
    bool channelValid = (m_channel != nullptr);
    bool channelConnected = channelValid && m_channel->isConnected();
    qDebug() << "CommandSet::send(): channel valid:" << channelValid << "connected:" << channelConnected;
    
    if (!channelValid || !channelConnected) {
        qDebug() << "CommandSet::send(): Card not connected, waiting...";
        if (!waitForCard()) {
            qWarning() << "CommandSet::send(): Failed to wait for card";
            // Return error response
            QByteArray errorResp;
            errorResp.append(static_cast<char>(0x69)); // SW1: Command not allowed
            errorResp.append(static_cast<char>(0x85)); // SW2: Conditions not satisfied
            return APDU::Response(errorResp);
        }
        if (m_appInfo.instanceUID.isEmpty() || !m_secureChannel->isOpen())
            select();
    }
    
    // 2. Ensure secure channel if needed
    if (secure) {
        if (!ensureSecureChannel()) {
            qWarning() << "CommandSet::send(): Failed to ensure secure channel";
            // Return error response
            QByteArray errorResp;
            errorResp.append(static_cast<char>(0x69)); // SW1: Command not allowed
            errorResp.append(static_cast<char>(0x85)); // SW2: Conditions not satisfied
            return APDU::Response(errorResp);
        }

        qDebug() << "CommandSet::send(): Sending via secure channel";
        try {
            return m_secureChannel->send(cmd);
        }
        catch (const std::runtime_error& e) {
            qWarning() << "CommandSet::send(): Failed to send via secure channel:" << e.what();
            // Return error response
            throw std::runtime_error(e.what());
        }
    } else {
    // 3. Send directly via channel (no secure channel)
        qDebug() << "CommandSet::send(): Sending directly (no secure channel)";
        qDebug() << "CommandSet::send(): Channel valid:" << (m_channel != nullptr);
        try {
            qDebug() << "CommandSet::send(): About to serialize command...";
            QByteArray serialized = cmd.serialize();
            qDebug() << "CommandSet::send(): Serialized APDU:" << serialized.toHex() << "calling transmit()...";
            QByteArray rawResp = m_channel->transmit(serialized);
            qDebug() << "CommandSet::send(): transmit() returned successfully";
            return APDU::Response(rawResp);
        }
        catch (const std::runtime_error& e) {
            qWarning() << "CommandSet::send(): Failed to send directly:" << e.what();
            throw std::runtime_error(e.what());
        }
    }
}

// ========== Channel Management Implementation ==========

void CommandSet::startDetection() {
    qDebug() << "CommandSet::startDetection()";
    
    if (!m_channel) {
        qWarning() << "CommandSet: No channel available";
        return;
    }
    
    // This runs on main thread, so it's safe to call directly
    m_channel->setState(ChannelState::WaitingForCard);
    emit channelStateChanged(ChannelState::WaitingForCard);
}

void CommandSet::stopDetection() {
    qDebug() << "CommandSet::stopDetection()";
    
    if (!m_channel) {
        qWarning() << "CommandSet: No channel available";
        return;
    }
    
    // This runs on main thread, so it's safe to call directly
    m_channel->setState(ChannelState::Idle);
    emit channelStateChanged(ChannelState::Idle);
}

void CommandSet::onTargetDetected(const QString& uid) {
    qDebug() << "CommandSet::onTargetDetected:" << uid 
             << "(thread:" << QThread::currentThreadId() << ")";
    
    // Check if same card or new card
    if (uid != m_targetId) {
        // Different card - full reset needed
        qDebug() << "CommandSet: Card swap detected";
        m_targetId = uid;
        handleCardSwap();  // Clears ALL state
    } else {
        // Same card re-detected - crypto reset only
        qDebug() << "CommandSet: Same card re-detected";
        resetSecureChannel();  // Preserves pairing and auth state
    }
    m_cardReady.store(true);
    emit cardReady(uid);
}

void CommandSet::onTargetLost() {
    qDebug() << "CommandSet::onTargetLost"
             << "(thread:" << QThread::currentThreadId() << ")";
    
    resetSecureChannel();
    m_cardReady.store(false);
    // Notify card loss only if we had a card before
    if (!m_targetId.isEmpty()) {
        emit cardLost();
    }
}

} // namespace Keycard
