#pragma once

#include "types.h"
#include "types_parser.h"
#include "secure_channel.h"
#include "pairing_storage.h"
#include "apdu/command.h"
#include "apdu/response.h"
#include "keycard_channel.h"
#include <memory>
#include <functional>
#include <QObject>
#include <QSharedPointer>

namespace Keycard {

/**
 * @brief Callback to provide pairing password when needed
 * 
 * @param cardInstanceUID The card's instance UID (hex string)
 * @return Pairing password, or empty string if unavailable/cancelled
 */
using PairingPasswordProvider = std::function<QString(const QString& cardInstanceUID)>;

/**
 * @brief High-level command set for Keycard operations
 * 
 * Provides convenient methods for all Keycard APDU commands.
 * Handles secure channel management, automatic pairing, and response parsing.
 * 
 * Self-contained design: CommandSet manages its own pairing lifecycle through
 * dependency injection of storage and credential providers.
 */
class CommandSet : public QObject {
    Q_OBJECT
    
public:
    /**
     * @brief Create CommandSet with dependency injection
     * @param channel Communication channel (required)
     * @param pairingStorage Optional pairing storage for persistence (null = no storage)
     * @param passwordProvider Optional callback to get pairing password (null = no auto-pairing)
     * @param parent QObject parent
     */
    explicit CommandSet(std::shared_ptr<Keycard::KeycardChannel> channel, 
                       std::shared_ptr<IPairingStorage> pairingStorage,
                       PairingPasswordProvider passwordProvider,
                       QObject* parent = nullptr);
    ~CommandSet();
    
    // Connection and pairing
    /**
     * @brief Select the Keycard applet
     * @return ApplicationInfo on success
     */
    ApplicationInfo select(bool force = false);
    
    /**
     * @brief Get the channel
     * @return Channel
     */
    std::shared_ptr<Keycard::KeycardChannel> channel() const { return m_channel; }
    
    /**
     * @brief Pair with the card using pairing password
     * @param pairingPassword Password for pairing (5-25 chars)
     * @return PairingInfo on success
     */
    PairingInfo pair(const QString& pairingPassword);
    
    /**
     * @brief Open secure channel with paired card
     * @param pairingInfo Previously obtained pairing info
     * @return true on success
     */
    bool openSecureChannel(const PairingInfo& pairingInfo);
    bool mutualAuthenticate();  // Mutual authentication after opening secure channel
    
    /**
     * @brief Reset secure channel state (iOS: when NFC drawer closes)
     * Clears cryptographic state but preserves pairing info and authentication status
     */
    void resetSecureChannel();
    
    /**
     * @brief Re-establish secure channel after physical session loss (iOS)
     * Opens secure channel using cached pairing and re-authenticates with cached PIN if needed
     * @return true on success
     */
    bool reestablishSecureChannel();
    
    /**
     * @brief Clear cached authentication state (call at flow end for security)
     * Clears cached PIN and authentication flag but preserves pairing
     */
    void clearAuthenticationCache();
    
    /**
     * @brief Handle card swap (different card detected during flow)
     * Clears ALL state: secure channel, pairing, authentication, app info
     */
    void handleCardSwap();
    
    /**
     * @brief Initialize a new keycard
     * @param secrets PIN, PUK, and pairing password
     * @return true on success
     */
    bool init(const Secrets& secrets);
    
    /**
     * @brief Unpair a pairing slot
     * @param index Pairing slot index to unpair
     * @return true on success
     */
    bool unpair(uint8_t index);
    
    // Status and verification
    /**
     * @brief Get application status
     * @param info Status info type (P1 parameter)
     * @return ApplicationStatus on success
     */
    ApplicationStatus getStatus(uint8_t info = APDU::P1GetStatusApplication);
    
    /**
     * @brief Verify PIN
     * ⚠️ WARNING: 3 wrong attempts will BLOCK the PIN! Use with extreme caution!
     * Always call getStatus() first to check remaining attempts.
     * @param pin 6-digit PIN
     * @return true on success, false if wrong PIN (check remaining attempts)
     */
    bool verifyPIN(const QString& pin);
    
    // Security operations
    /**
     * @brief Change PIN (requires secure channel + previous PIN verification)
     * @param newPIN New 6-digit PIN
     * @return true on success
     */
    bool changePIN(const QString& newPIN);
    
    /**
     * @brief Change PUK (requires secure channel + previous PIN verification)
     * @param newPUK New 12-digit PUK
     * @return true on success
     */
    bool changePUK(const QString& newPUK);
    
    /**
     * @brief Unblock PIN using PUK
     * ⚠️ WARNING: 5 wrong PUK attempts will permanently block the card!
     * @param puk 12-digit PUK
     * @param newPIN New 6-digit PIN
     * @return true on success
     */
    bool unblockPIN(const QString& puk, const QString& newPIN);
    
    /**
     * @brief Change pairing password
     * @param newPassword New pairing password
     * @return true on success
     */
    bool changePairingSecret(const QString& newPassword);
    
    // Key management
    /**
     * @brief Generate a new key pair on the card
     * @return Key UID (32 bytes) on success
     */
    QByteArray generateKey();
    
    /**
     * @brief Generate BIP39 mnemonic on card
     * @param checksumSize Checksum size (4, 8, or 0 for random)
     * @return List of word indexes
     */
    QVector<int> generateMnemonic(int checksumSize = 4);
    
    /**
     * @brief Load seed to card (BIP39 only, P2=0x00)
     * @param seed BIP39 seed (64 bytes)
     * @return Key UID on success
     */
    QByteArray loadSeed(const QByteArray& seed);

    /**
     * @brief Load seed to card with explicit key type
     * @param seed Seed bytes (64 bytes)
     * @param keyType P2LoadKeyBIP39 (0x00) or P2LoadKeyLEE (0x01)
     * @return Key UID on success
     */
    QByteArray loadKey(const QByteArray& seed, uint8_t keyType = APDU::P2LoadKeyBIP39);
    
    /**
     * @brief Remove key from card
     * @return true on success
     */
    bool removeKey();
    
    /**
     * @brief Derive key at BIP32 path
     * @param path Derivation path (e.g., "m/44'/0'/0'/0/0")
     * @return true on success
     */
    bool deriveKey(const QString& path);
    
    // Signing
    /**
     * @brief Sign data with current key
     * @param data 32-byte hash to sign
     * @return Signature (65 bytes: R + S + V) on success
     */
    QByteArray sign(const QByteArray& data);
    
    /**
     * @brief Sign data with key at specific path
     * @param data 32-byte hash to sign
     * @param path Derivation path
     * @param makeCurrent If true, derived key becomes current
     * @param scheme Signing scheme: P2SignECDSA (0x00) or P2SignSchnorr (0x03)
     * @return Signature on success
     */
    QByteArray signWithPath(const QByteArray& data, const QString& path, bool makeCurrent = false, uint8_t scheme = APDU::P2SignECDSA);

    /**
     * @brief Sign data with key at specific path, returning full TLV response
     * @param data 32-byte hash to sign
     * @param path Derivation path
     * @param makeCurrent If true, derived key becomes current
     * @param scheme Signing scheme: P2SignECDSA (0x00) or P2SignSchnorr (0x03)
     * @return Full TLV response (includes public key and signature) on success
     */
    QByteArray signWithPathFullResponse(const QByteArray& data, const QString& path, bool makeCurrent = false, uint8_t scheme = APDU::P2SignECDSA);
    
    /**
     * @brief Sign without PIN (if pinless path set)
     * @param data 32-byte hash to sign
     * @return Signature on success
     */
    QByteArray signPinless(const QByteArray& data);
    
    /**
     * @brief Set path for pinless signing
     * @param path Absolute derivation path (must start with "m/")
     * @return true on success
     */
    bool setPinlessPath(const QString& path);
    
    // Data storage
    /**
     * @brief Store data on card
     * @param type Data type (0x00=public, 0x01=NDEF, 0x02=cash)
     * @param data Data to store
     * @return true on success
     */
    bool storeData(uint8_t type, const QByteArray& data);
    
    /**
     * @brief Get data from card
     * @param type Data type
     * @return Data on success
     */
    QByteArray getData(uint8_t type);
    
    // Utilities
    /**
     * @brief Identify the card
     * @param challenge Optional 32-byte challenge
     * @return Card identification
     */
    QByteArray identify(const QByteArray& challenge = QByteArray());
    
    /**
     * @brief Export public key (or private+public)
     * @param derive If true, derive first
     * @param makeCurrent If true and derive=true, make it current
     * @param path Derivation path (if derive=true)
     * @param exportType Export type (P2ExportKeyPublicOnly, P2ExportKeyPrivateAndPublic, etc.)
     * @return Key data (TLV encoded)
     */
    QByteArray exportKey(bool derive = false, bool makeCurrent = false, const QString& path = QString(), uint8_t exportType = APDU::P2ExportKeyPublicOnly);
    
    /**
     * @brief Export extended key (public or private+public)
     * @param derive If true, derive first
     * @param makeCurrent If true and derive=true, make it current
     * @param path Derivation path (if derive=true)
     * @param exportType Export type (P2ExportKeyPublicOnly, P2ExportKeyPrivateAndPublic, etc.)
     * @return Extended key data (TLV encoded)
     */
    QByteArray exportKeyExtended(bool derive = false, bool makeCurrent = false, const QString& path = QString(), uint8_t exportType = APDU::P2ExportKeyExtendedPublic);
    
    /**
     * @brief Factory reset the card
     * ⚠️ WARNING: This will erase all data on the card permanently!
     * @return true on success
     */
    bool factoryReset();
    
    /**
     * @brief Get last error message
     * @return Error message
     */
    QString lastError() const { return m_lastError; }
    
    /**
     * @brief Get remaining PIN attempts (after failed verifyPIN)
     * @return Remaining attempts, or -1 if not applicable
     */
    int remainingPINAttempts() const { return m_cachedStatus.pinRetryCount; }
    
    /**
     * @brief Get cached application status
     * 
     * Returns cached status fetched after opening secure channel or PIN verification.
     * This avoids blocking getStatus() calls.
     * 
     * @return Cached ApplicationStatus, or default if not available
     */
    ApplicationStatus cachedApplicationStatus() const { return m_cachedStatus; }
    
    /**
     * @brief Check if cached status is valid
     * @return true if status has been cached (secure channel was opened)
     */
    bool hasCachedStatus() const { return m_hasCachedStatus; }
    
    /**
     * @brief Wait for card to be present
     * Checks if card is connected, enables card detection if needed, and waits for card
     * @return true if card detected, false on error or when detection stops
     */
    bool waitForCard();

    /**
     * @brief Ensure pairing is available for current card
     * 
     * Automatic pairing lifecycle:
     * 1. Check cached pairing (fast path)
     * 2. Try to load from storage
     * 3. If missing, attempt to pair (needs password provider)
     * 4. Save newly created pairing
     * 
     * @return true if pairing is available, false otherwise
     */
    bool ensurePairing();

    /**
     * @brief Ensure secure channel is ready before secure operations
     * Checks flag and re-establishes if needed
     * @return true on success
     */
    bool ensureSecureChannel();
    
    // Accessors
    ApplicationInfo applicationInfo() const { return m_appInfo; }
    PairingInfo pairingInfo() const { return m_pairingInfo; }
    std::shared_ptr<IPairingStorage> pairingStorage() const { return m_pairingStorage; }
    
    // Test helpers (for unit testing only - bypasses crypto validation)
    #ifdef KEYCARD_ENABLE_TEST_HELPERS
    /**
     * @brief Directly inject secure channel state for testing
     * @param pairingInfo Mock pairing info
     * @param iv Mock initialization vector (16 bytes)
     * @param encKey Mock encryption key (16 bytes)
     * @param macKey Mock MAC key (16 bytes)
     * 
     * WARNING: This bypasses all cryptographic validation and should
     * ONLY be used in unit tests to test business logic without requiring
     * real cryptographic operations.
     */
    void testInjectSecureChannelState(const PairingInfo& pairingInfo,
                                       const QByteArray& iv,
                                       const QByteArray& encKey,
                                       const QByteArray& macKey) {
        m_pairingInfo = pairingInfo;
        m_pairingBoundInstanceUID = m_cardInstanceUID;
        m_secureChannel->init(iv, encKey, macKey);
    }
    #endif
    
    // ========== Channel Management API  ==========
    /**
     * @brief Start card detection
     * 
     * Sets channel to WaitingForCard state.
     * Thread-safe: Runs on main thread where channel lives.
     * 
     * @note This is the ONLY public way to start detection.
     *       CommunicationManager should use this instead of accessing channel directly.
     */
    void startDetection();
    
    /**
     * @brief Stop card detection
     * 
     * Sets channel to Idle state.
     * Thread-safe: Runs on main thread where channel lives.
     * 
     * @note This is the ONLY public way to stop detection.
     *       CommunicationManager should use this instead of accessing channel directly.
     */
    void stopDetection();

    /**
     * @brief Check if detection is active
     * @return true if detection is active, false otherwise
     */
    bool isDetectionActive() const { return m_channel && m_channel->isDetectionActive(); }
    
    /**
     * @brief Get current card UID
     * @return Card UID or empty string if no card
     */
    QString currentCardUID() const { return m_targetId; }

    /**
     * @brief Check if card is ready for commands
     * @return true if card is ready for commands
     */
    bool isCardReady() const { return m_cardReady.load(); }
    
signals:
    /**
     * @brief Emitted when card is ready for commands
     * @param uid Card UID
     * 
     * This is emitted after:
     * - Card detected by channel
     * - Secure channel state reset (if re-detection)
     * - SELECT applet executed successfully
     * 
     * @note Guaranteed to be emitted AFTER resetSecureChannel() has been called.
     *       This ensures CommunicationManager receives the signal only when
     *       CommandSet has finished preparing the card.
     */
    void cardReady(const QString& uid);
    
    /**
     * @brief Emitted when card is removed
     * 
     * This is emitted when the card is physically removed or connection lost.
     */
    void cardLost();
    
    /**
     * @brief Emitted when channel state changes
     * @param state New channel state
     * 
     * Allows CommunicationManager to track channel state without
     * direct channel access. Emitted for: Idle, WaitingForCard, Reading, etc.
     */
    void channelStateChanged(ChannelState state);
    
private slots:
    /**
     * @brief Handle card detection from channel (INTERNAL)
     * 
     * This is the ONLY handler for channel->targetDetected signal.
     * It runs synchronously on main thread before any other handlers.
     * 
     * Flow:
     * 1. Check if same card or new card
     * 2. Reset secure channel (for same card) or full reset (new card)
     * 3. Execute SELECT applet
     * 4. Emit cardReady() signal
     * 
     * @param uid Card UID from channel
     */
    void onTargetDetected(const QString& uid);
    
    /**
     * @brief Handle card removal from channel (INTERNAL)
     * 
     * This is the ONLY handler for channel->targetLost signal.
     * 
     * Flow:
     * 1. Clear card UID
     * 2. Reset secure channel state
     * 3. Emit cardLost() signal
     */
    void onTargetLost();
    
private:
    // Helper methods
    bool checkOK(const APDU::Response& response);
    APDU::Command buildCommand(uint8_t ins, uint8_t p1 = 0, uint8_t p2 = 0, 
                                const QByteArray& data = QByteArray());

    /**
     * @brief Send APDU command with automatic precondition management
     * @param cmd The APDU command to send
     * @param secure If true, ensures secure channel is open before sending
     * @return APDU response
     * 
     * This method automatically:
     * - Waits for card if not connected
     * - Ensures pairing exists (loads or creates)
     * - Ensures secure channel is open (if secure=true)
     * - Transmits the command via appropriate channel
     */
    APDU::Response send(const APDU::Command& cmd, bool secure = true);
    
    /**
     * @brief Internal implementation of waitForCard (must be called from correct thread)
     * @return true if card detected, false on error or when detection stops
     */
    bool waitForCardInternal();

    /**
     * @brief Clean up state after factory reset
     */
    void factoryResetCleanup();
    
    /**
     * @brief Factory reset fallback using GlobalPlatform commands
     * 
     * Used for older cards that don't support the FACTORY_RESET command.
     * This method:
     * 1. Selects the ISD (Issuer Security Domain)
     * 2. Opens SCP02 secure channel
     * 3. Deletes the Keycard applet instance
     * 4. Reinstalls the Keycard applet
     * 
     * @return true if successful, false otherwise
     */
    bool factoryResetFallback();

    void setCardReady(bool ready);

    /** Clears m_pairingInfo and the instance UID it was bound to (see m_pairingBoundInstanceUID). */
    void invalidateCachedPairing();

    /**
     * Resets secure channel crypto, auth cache, status cache, and pairing.
     * Used on physical card swap (target id change) and when SELECT shows a different applet instance
     * (same PC/SC target id, different Keycard).
     */
    void clearStaleCardSessionState();

    
    std::shared_ptr<Keycard::KeycardChannel> m_channel;
    std::shared_ptr<IPairingStorage> m_pairingStorage;  // Injected (can be null)
    PairingPasswordProvider m_passwordProvider;  // Injected (can be null)
    
    QSharedPointer<SecureChannel> m_secureChannel;
    ApplicationInfo m_appInfo;
    PairingInfo m_pairingInfo;
    /** Hex instance UID of the applet m_pairingInfo was loaded/opened for; invalidates fast-path if select() sees another card. */
    QString m_pairingBoundInstanceUID;
    QString m_cardInstanceUID;  // Current card UID (from select())
    QString m_targetId;         // Current target ID (from waitForCard())
    QString m_lastError;
    
    // Status caching (matching status-keycard-go behavior)
    ApplicationStatus m_cachedStatus;  // Cached status from last getStatus() call
    bool m_hasCachedStatus = false;    // True if m_cachedStatus is valid
    
    // iOS: Authentication state tracking for secure channel recovery
    bool m_wasAuthenticated = false;  // True if verifyPIN succeeded in this flow
    QString m_cachedPIN;              // Cached PIN for auto-reauth after NFC session loss
    bool m_needsSecureChannelReestablishment = false;  // Flag: secure channel must be re-opened before next command
    

    std::atomic_bool m_cardReady = false;
};

} // namespace Keycard

