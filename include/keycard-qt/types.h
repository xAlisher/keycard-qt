#pragma once

#include <QByteArray>
#include <QString>
#include <QVector>
#include <cstdint>

namespace Keycard {

/**
 * @brief Capability flags for keycard features
 */
enum class Capability : uint8_t {
    None = 0x00,
    SecureChannel = 0x01,
    KeyManagement = 0x02,
    CredentialsManagement = 0x04,
    NDEF = 0x08,
    FactoryReset = 0x10,
    LEEKey = 0x20,   // Bit 5 set in tag 0x8D when a LEE key is loaded (applet v3.2+)
    All = 0xFF
};

/**
 * @brief Application information returned by SELECT command
 */
struct ApplicationInfo {
    QByteArray instanceUID;           ///< Unique card instance ID
    QByteArray secureChannelPublicKey; ///< Card's public key for ECDH
    uint8_t appVersion;               ///< Application version
    uint8_t appVersionMinor;          ///< Application minor version
    uint8_t availableSlots;           ///< Available pairing slots
    bool installed;                   ///< True if keycard applet is installed
    bool initialized;                 ///< True if keycard is initialized
    QByteArray keyUID;                ///< Key UID if keys are loaded
    uint8_t capabilities;             ///< Capability flags (bitmask)
    
    ApplicationInfo()
        : appVersion(0)
        , appVersionMinor(0)
        , availableSlots(0)
        , installed(false)
        , initialized(false)
        , capabilities(static_cast<uint8_t>(Capability::All))  // Assume all capabilities if not specified
    {}
    
    /**
     * @brief Check if card has a specific capability
     */
    bool hasCapability(Capability cap) const {
        return (capabilities & static_cast<uint8_t>(cap)) != 0;
    }
    
    /**
     * @brief Check if card supports factory reset command
     */
    bool hasFactoryResetCapability() const {
        return hasCapability(Capability::FactoryReset);
    }

    /**
     * @brief Returns true when a LEE key is currently loaded on the card.
     * Reads bit 5 (0x20) of the capabilities byte from SELECT response tag 0x8D.
     * Only meaningful when keyInitialized is true.
     */
    bool isLEEKey() const {
        return hasCapability(Capability::LEEKey);
    }
};

/**
 * @brief Application status information
 */
struct ApplicationStatus {
    uint8_t pinRetryCount;   ///< Remaining PIN attempts
    uint8_t pukRetryCount;   ///< Remaining PUK attempts
    bool keyInitialized;     ///< True if keys are loaded
    QByteArray currentPath;  ///< Current derivation path
    bool valid;
    
    ApplicationStatus()
        : pinRetryCount(0)
        , pukRetryCount(0)
        , keyInitialized(false)
        , valid(false)
    {}
};

/**
 * @brief Pairing information for secure channel
 */
struct PairingInfo {
    QByteArray key;    ///< Pairing key
    int index;         ///< Pairing slot index
    
    PairingInfo() : index(-1) {}
    PairingInfo(const QByteArray& k, int idx) : key(k), index(idx) {}
    
    bool isValid() const { return !key.isEmpty() && index >= 0; }
};

/**
 * @brief Secrets for initializing a new keycard
 */
struct Secrets {
    QString pin;              ///< PIN (6 digits)
    QString puk;              ///< PUK (12 digits)
    QString pairingPassword;  ///< Pairing password
    
    Secrets() = default;
    Secrets(const QString& p, const QString& pu, const QString& pair)
        : pin(p), puk(pu), pairingPassword(pair) {}
};

/**
 * @brief Exported key information
 */
struct ExportedKey {
    QByteArray publicKey;   ///< Public key (if exported)
    QByteArray privateKey;  ///< Private key (if exported)
    QByteArray chainCode;   ///< Chain code for BIP32
    
    ExportedKey() = default;
};

/**
 * @brief Signature from signing operation
 */
struct Signature {
    QByteArray r;        ///< R component
    QByteArray s;        ///< S component
    uint8_t v;           ///< Recovery ID
    QByteArray publicKey; ///< Public key that signed
    
    Signature() : v(0) {}
};

/**
 * @brief Metadata stored on keycard
 */
struct Metadata {
    QString name;              ///< Wallet name
    QVector<uint32_t> paths;   ///< Derived key paths
    
    Metadata() = default;
};

// APDU command parameters
namespace APDU {
    // Class bytes
    constexpr uint8_t CLA = 0x80;
    constexpr uint8_t CLA_ISO7816 = 0x00;
    
    // Instruction bytes
    constexpr uint8_t INS_SELECT = 0xA4;
    constexpr uint8_t INS_INIT = 0xFE;
    constexpr uint8_t INS_PAIR = 0x12;
    constexpr uint8_t INS_UNPAIR = 0x13;
    constexpr uint8_t INS_IDENTIFY = 0x14;
    constexpr uint8_t INS_OPEN_SECURE_CHANNEL = 0x10;
    constexpr uint8_t INS_MUTUALLY_AUTHENTICATE = 0x11;
    constexpr uint8_t INS_GET_STATUS = 0xF2;
    constexpr uint8_t INS_VERIFY_PIN = 0x20;
    constexpr uint8_t INS_CHANGE_PIN = 0x21;
    constexpr uint8_t INS_UNBLOCK_PIN = 0x22;
    constexpr uint8_t INS_LOAD_KEY = 0xD0;
    constexpr uint8_t INS_DERIVE_KEY = 0xD1;
    constexpr uint8_t INS_GENERATE_MNEMONIC = 0xD2;
    constexpr uint8_t INS_REMOVE_KEY = 0xD3;
    constexpr uint8_t INS_GENERATE_KEY = 0xD4;
    constexpr uint8_t INS_SIGN = 0xC0;
    constexpr uint8_t INS_SET_PINLESS_PATH = 0xC1;
    constexpr uint8_t INS_EXPORT_KEY = 0xC2;
    constexpr uint8_t INS_GET_DATA = 0xCA;
    constexpr uint8_t INS_STORE_DATA = 0xE2;
    constexpr uint8_t INS_FACTORY_RESET = 0xFD;
    
    // P1 parameters
    constexpr uint8_t P1GetStatusApplication = 0x00;
    constexpr uint8_t P1GetStatusKeyPath = 0x01;
    
    constexpr uint8_t P1PairFirstStep = 0x00;
    constexpr uint8_t P1PairFinalStep = 0x01;
    
    constexpr uint8_t P1ChangePinPIN = 0x00;
    constexpr uint8_t P1ChangePinPUK = 0x01;
    constexpr uint8_t P1ChangePinPairingSecret = 0x02;
    
    constexpr uint8_t P1DeriveKeyFromMaster = 0x00;
    constexpr uint8_t P1DeriveKeyFromParent = 0x40;
    constexpr uint8_t P1DeriveKeyFromCurrent = 0x80;
    
    constexpr uint8_t P1ExportKeyCurrent = 0x00;
    constexpr uint8_t P1ExportKeyDerive = 0x01;
    constexpr uint8_t P1ExportKeyDeriveAndMakeCurrent = 0x02;
    
    constexpr uint8_t P1SignCurrentKey = 0x00;
    constexpr uint8_t P1SignDerive = 0x01;
    constexpr uint8_t P1SignDeriveAndMakeCurrent = 0x02;
    constexpr uint8_t P1SignPinless = 0x03;
    
    constexpr uint8_t P1LoadKeySeed = 0x03;

    // P2 values for SIGN instruction (confirmed by bitgamma, #96)
    constexpr uint8_t P2SignECDSA    = 0x00;
    constexpr uint8_t P2SignSchnorr  = 0x03;  // BIP340 Schnorr

    // P2 values for LOAD KEY instruction
    constexpr uint8_t P2LoadKeyBIP39 = 0x00;
    constexpr uint8_t P2LoadKeyLEE   = 0x01;

    constexpr uint8_t P1StoreDataPublic = 0x00;
    constexpr uint8_t P1StoreDataNDEF = 0x01;
    constexpr uint8_t P1StoreDataCash = 0x02;
    
    constexpr uint8_t P1FactoryResetMagic = 0xAA;
    
    // P2 parameters
    constexpr uint8_t P2ExportKeyPrivateAndPublic = 0x00;  // Export both private and public key
    constexpr uint8_t P2ExportKeyPublicOnly = 0x01;        // Export public key only
    constexpr uint8_t P2ExportKeyExtendedPublic = 0x02;    // Export extended public key (with chain code) - FIXED: was 0x03
    
    constexpr uint8_t P2FactoryResetMagic = 0x55;
    
    // Status words
    constexpr uint16_t SW_OK = 0x9000;
    constexpr uint16_t SW_SECURITY_CONDITION_NOT_SATISFIED = 0x6982;
    constexpr uint16_t SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;
    constexpr uint16_t SW_DATA_INVALID = 0x6984;
    constexpr uint16_t SW_CONDITIONS_NOT_SATISFIED = 0x6985;
    constexpr uint16_t SW_WRONG_DATA = 0x6A80;
    constexpr uint16_t SW_FILE_NOT_FOUND = 0x6A82;
    constexpr uint16_t SW_NO_AVAILABLE_PAIRING_SLOTS = 0x6A84;
    constexpr uint16_t SW_INCORRECT_P1P2 = 0x6A86;
    constexpr uint16_t SW_REFERENCED_DATA_NOT_FOUND = 0x6A88;
    constexpr uint16_t SW_WRONG_LENGTH = 0x6700;
    constexpr uint16_t SW_INS_NOT_SUPPORTED = 0x6D00;
    constexpr uint16_t SW_CLA_NOT_SUPPORTED = 0x6E00;
}

} // namespace Keycard

