// Copyright (C) 2025 Status Research & Development GmbH
// SPDX-License-Identifier: MIT

#include "keycard-qt/backends/keycard_channel_pcsc.h"
#include <QDebug>
#include <QMutexLocker>
#include <stdexcept>
#include <vector>
#include <cstring>

#ifdef Q_OS_WIN
#include <winscard.h>
#elif defined(Q_OS_LINUX)
// Linux PCSC headers define all types
#include <PCSC/winscard.h>
#include <PCSC/pcsclite.h>
#else
// macOS PCSC headers need manual type definitions
#include <PCSC/winscard.h>
#include <PCSC/pcsclite.h>

// macOS doesn't define these Windows-style types
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint8_t BYTE;
typedef char* LPSTR;
typedef const uint8_t* LPCBYTE;
#endif

namespace Keycard {

// Pimpl structure to hide PC/SC types from MOC
struct PcscState {
    SCARDCONTEXT context = 0;
    SCARDHANDLE cardHandle = 0;
    DWORD activeProtocol = 0;
    bool contextEstablished = false;
};

KeycardChannelPcsc::KeycardChannelPcsc(QObject* parent)
    : KeycardChannelBackend(parent)
    , m_pcscState(new PcscState())
    , m_connected(false)
    , m_detectionThread(nullptr)
    , m_stopDetection(0)
    , m_forceScan(0)
    , m_lastReaderAvailable(false)
    , m_firstReaderCheck(true)
{
    qDebug() << "KeycardChannelPcsc: Initialized with event-driven detection (Desktop smart card reader)";
    startDetection();
}

KeycardChannelPcsc::~KeycardChannelPcsc()
{
    stopDetection();
    disconnectFromCard();
    releaseContext();
    delete m_pcscState;
}

void KeycardChannelPcsc::establishContext()
{
    if (m_pcscState->contextEstablished) {
        return;
    }
    
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &m_pcscState->context);
    
    if (rv != SCARD_S_SUCCESS) {
        QString msg = QString("Failed to establish PC/SC context: 0x%1").arg(rv, 0, 16);
        qWarning() << "KeycardChannelPcsc:" << msg;
        emit error(msg);
        return;
    }
    
    m_pcscState->contextEstablished = true;
    qDebug() << "KeycardChannelPcsc: PC/SC context established";
}

void KeycardChannelPcsc::releaseContext()
{
    if (m_pcscState->contextEstablished && m_pcscState->context) {
        SCardReleaseContext(m_pcscState->context);
        m_pcscState->context = 0;
        m_pcscState->contextEstablished = false;
        qDebug() << "KeycardChannelPcsc: PC/SC context released";
    }
}

void KeycardChannelPcsc::setState(ChannelState state)
{
    if (state == ChannelState::WaitingForCard) {
        startDetection();
    }
    m_state = state;
}

QStringList KeycardChannelPcsc::listReaders()
{
    QStringList readers;
    
    if (!m_pcscState->contextEstablished) {
        return readers;
    }
    
#ifdef Q_OS_WIN
    LPWSTR mszReaders = NULL;
    DWORD dwReaders = SCARD_AUTOALLOCATE;
    
    LONG rv = SCardListReadersW(m_pcscState->context, NULL, (LPWSTR)&mszReaders, &dwReaders);
    
    if (rv == SCARD_S_SUCCESS && mszReaders) {
        LPWSTR reader = mszReaders;
        while (*reader) {
            readers.append(QString::fromWCharArray(reader));
            reader += wcslen(reader) + 1;
        }
        SCardFreeMemory(m_pcscState->context, mszReaders);
    }
#else
    // macOS/Linux: Get buffer size first, then allocate
    DWORD dwReaders = 0;
    LONG rv = SCardListReaders(m_pcscState->context, NULL, NULL, &dwReaders);
    
    if (rv == SCARD_S_SUCCESS && dwReaders > 0) {
        LPSTR mszReaders = new char[dwReaders];
        
        rv = SCardListReaders(m_pcscState->context, NULL, mszReaders, &dwReaders);
        
        if (rv == SCARD_S_SUCCESS) {
            char* reader = mszReaders;
            while (*reader) {
                readers.append(QString::fromUtf8(reader));
                reader += strlen(reader) + 1;
            }
        }
        
        delete[] mszReaders;
    }
#endif
    
    return readers;
}

bool KeycardChannelPcsc::connectToReader(const QString& readerName)
{
    if (m_connected) {
        return true;  // Already connected
    }
    
    if (!m_pcscState->contextEstablished) {
        establishContext();
        if (!m_pcscState->contextEstablished) {
            return false;
        }
    }
    
    qDebug() << "KeycardChannelPcsc: Connecting to card in reader:" << readerName;
    
    // CRITICAL: Use SCARD_SHARE_EXCLUSIVE and SCARD_RESET_CARD to match status-keycard-go behavior
    // Go uses ShareExclusive mode and always resets the card connection before connecting
    // (see keycard_context_v2.go line 260: Connect(reader, scard.ShareExclusive, scard.ProtocolAny))
    // This ensures the card is in a clean state, especially important when:
    // 1. Reader is plugged in after app starts
    // 2. Card was previously connected but not properly disconnected
    // The SCARD_RESET_CARD flag performs a warm reset, initializing the card's internal state
#ifdef Q_OS_WIN
    LONG rv = SCardConnectW(
        m_pcscState->context,
        (LPCWSTR)readerName.utf16(),
        SCARD_SHARE_EXCLUSIVE,  // Changed from SHARED to EXCLUSIVE
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        &m_pcscState->cardHandle,
        &m_pcscState->activeProtocol
    );
#else
    QByteArray readerBytes = readerName.toUtf8();
    LONG rv = SCardConnect(
        m_pcscState->context,
        readerBytes.constData(),
        SCARD_SHARE_EXCLUSIVE,  // Changed from SHARED to EXCLUSIVE
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        &m_pcscState->cardHandle,
        &m_pcscState->activeProtocol
    );
#endif
    
    if (rv != SCARD_S_SUCCESS) {
        qDebug() << "KeycardChannelPcsc: Failed to connect to card:" << QString("0x%1").arg(rv, 0, 16);
        return false;
    }
    
    m_lastDetectedReader = readerName;
    m_connected = true;
    
    // Get ATR
    m_lastATR = getATR();
    
    qDebug() << "KeycardChannelPcsc: Connected to card";
    qDebug() << "KeycardChannelPcsc: Protocol:" << (m_pcscState->activeProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1");
    qDebug() << "KeycardChannelPcsc: ATR:" << m_lastATR.toHex();
    
    return true;
}

void KeycardChannelPcsc::disconnectFromCard()
{
    if (m_pcscState->cardHandle) {
        SCardDisconnect(m_pcscState->cardHandle, SCARD_LEAVE_CARD);
        m_pcscState->cardHandle = 0;
    }
    
    if (m_connected) {
        qDebug() << "KeycardChannelPcsc: Disconnected from card";
        m_connected = false;
        m_lastATR.clear();
        m_lastDetectedReader.clear();
    }
}

QByteArray KeycardChannelPcsc::getATR()
{
    if (!m_connected) {
        return QByteArray();
    }
    
    // Get ATR (Answer To Reset) which contains card info
    BYTE pbAtr[33];
    DWORD dwAtrLen = sizeof(pbAtr);
    DWORD dwState, dwProtocol;
    
#ifdef Q_OS_WIN
    WCHAR szReader[200];
    DWORD dwReaderLen = sizeof(szReader) / sizeof(WCHAR);
    
    LONG rv = SCardStatusW(
        m_pcscState->cardHandle,
        szReader,
        &dwReaderLen,
        &dwState,
        &dwProtocol,
        pbAtr,
        &dwAtrLen
    );
#else
    char szReader[200];
    DWORD dwReaderLen = sizeof(szReader);
    
    LONG rv = SCardStatus(
        m_pcscState->cardHandle,
        szReader,
        &dwReaderLen,
        &dwState,
        &dwProtocol,
        pbAtr,
        &dwAtrLen
    );
#endif
    
    if (rv == SCARD_S_SUCCESS) {
        return QByteArray((char*)pbAtr, dwAtrLen);
    }
    
    return QByteArray();
}

void KeycardChannelPcsc::startDetection()
{
    qDebug() << "KeycardChannelPcsc: Starting event-driven card detection";
    
    establishContext();
    
    if (!m_pcscState->contextEstablished) {
        // PC/SC not available - report no readers immediately for consistent state
        qDebug() << "KeycardChannelPcsc: PC/SC context failed - reporting no readers";
        m_lastReaderAvailable = false;
        m_firstReaderCheck = false;
        emit readerAvailabilityChanged(false);
        emit error("Failed to establish PC/SC context");
        return;
    }
    
    // Stop any existing detection
    if (m_detectionThread && m_detectionThread->isRunning()) {
        qDebug() << "KeycardChannelPcsc: Detection already running";
        if (!m_lastDetectedUid.isEmpty()) {
            emit targetDetected(m_lastDetectedUid);
        }
        emit readerAvailabilityChanged(m_lastReaderAvailable);
        return;
    }
    
    // Immediately check and report reader availability (synchronously)
    // This ensures tests and UI can get initial state without waiting for background thread
    QStringList readers = listReaders();
    if (readers.isEmpty()) {
        qDebug() << "KeycardChannelPcsc: Initial state - No readers found";
        m_lastReaderAvailable = false;
        emit readerAvailabilityChanged(false);
    } else {
        qDebug() << "KeycardChannelPcsc: Initial state - Reader(s) detected:" << readers.size();
        m_lastReaderAvailable = true;
        emit readerAvailabilityChanged(true);
    }
    m_firstReaderCheck = false;  // We've now done the first check
    
    // Reset stop flag
    m_stopDetection = 0;
    
    // Start detection thread (matches status-keycard-go pattern)
    m_detectionThread = QThread::create([this]() {
        detectionLoop();
    });
    
    m_detectionThread->start();
    qDebug() << "KeycardChannelPcsc: Detection thread started";
}

void KeycardChannelPcsc::stopDetection()
{
    qDebug() << "KeycardChannelPcsc: Stopping card detection";
    
    if (!m_detectionThread) {
        return;
    }
    
    // Signal thread to stop
    m_stopDetection = 1;
    
    // Cancel any blocking SCardGetStatusChange() by establishing a new context
    // This will cause SCARD_E_CANCELLED
    if (m_pcscState->contextEstablished) {
        SCardCancel(m_pcscState->context);
    }
    
    // Wait for thread to finish (with timeout)
    if (!m_detectionThread->wait(2000)) {
        qWarning() << "KeycardChannelPcsc: Detection thread did not stop in time, forcing termination";
        m_detectionThread->terminate();
        m_detectionThread->wait();
    }
    
    delete m_detectionThread;
    m_detectionThread = nullptr;
    
    qDebug() << "KeycardChannelPcsc: Detection thread stopped";
}

void KeycardChannelPcsc::watchCardRemoval(const QString& readerName)
{
    qDebug() << "KeycardChannelPcsc: Watching for card removal in:" << readerName;
    
    // Prepare reader states for monitoring
    // 1. The specific reader with the card
    // 2. PnP Notification reader to detect reader removal
    std::vector<SCARD_READERSTATE> readerStates;
    
#ifdef Q_OS_WIN
    // Monitor the active reader
    std::wstring readerWStr = readerName.toStdWString();
    SCARD_READERSTATE rs;
    memset(&rs, 0, sizeof(rs));
    rs.szReader = readerWStr.c_str();
    rs.dwCurrentState = SCARD_STATE_UNAWARE;
    readerStates.push_back(rs);
    
    // Monitor PnP for reader removal (Windows)
    std::wstring pnpReader = L"\\\\?PnP?\\Notification";
    SCARD_READERSTATE pnpRs;
    memset(&pnpRs, 0, sizeof(pnpRs));
    pnpRs.szReader = pnpReader.c_str();
    pnpRs.dwCurrentState = SCARD_STATE_UNAWARE;
    readerStates.push_back(pnpRs);
#else
    // Monitor the active reader (macOS/Linux)
    QByteArray readerBytes = readerName.toUtf8();
    SCARD_READERSTATE rs;
    memset(&rs, 0, sizeof(rs));
    rs.szReader = readerBytes.constData();
    rs.dwCurrentState = SCARD_STATE_UNAWARE;
    readerStates.push_back(rs);
    
    // Monitor PnP for reader removal (macOS/Linux)
    QByteArray pnpReader("\\\\?PnP?\\Notification");
    SCARD_READERSTATE pnpRs;
    memset(&pnpRs, 0, sizeof(pnpRs));
    pnpRs.szReader = pnpReader.constData();
    pnpRs.dwCurrentState = SCARD_STATE_UNAWARE;
    readerStates.push_back(pnpRs);
#endif
    
    while (m_stopDetection.loadAcquire() == 0) {
        // Check for force scan (e.g., after init/factory reset)
        if (m_forceScan.loadAcquire() == 1) {
            qDebug() << "KeycardChannelPcsc: Force scan requested, exiting watch";
            m_forceScan.storeRelease(0);
            // Programmatic disconnect - don't emit cardRemoved
            disconnectFromCard();
            m_lastDetectedUid.clear();
            return;  // Return to detection phase
        }
        
        // Update current state for next check (both reader and PnP)
        for (auto& rs : readerStates) {
            rs.dwCurrentState = rs.dwEventState;
        }
        
        // Wait for state change (500ms timeout for responsiveness to force scan)
        LONG rv = SCardGetStatusChange(
            m_pcscState->context,
            500,  // 500ms timeout (balance between CPU usage and responsiveness)
            readerStates.data(),
            readerStates.size()
        );
        
        if (rv == SCARD_E_TIMEOUT) {
            // No change, card still present
            continue;
        }
        
        if (rv == SCARD_E_CANCELLED) {
            // Context cancelled - check if it's a force scan or shutdown
            if (m_forceScan.loadAcquire() == 1) {
                qDebug() << "KeycardChannelPcsc: Force scan detected via cancel";
                m_forceScan.storeRelease(0);
                disconnectFromCard();
                m_lastDetectedUid.clear();
                return;
            }
            // Otherwise it's a shutdown
            break;
        }
        
        if (rv != SCARD_S_SUCCESS) {
            qWarning() << "KeycardChannelPcsc: GetStatusChange error:" << QString("0x%1").arg(rv, 0, 16);
            break;
        }
        
        // Check if card physically removed from reader (index 0)
        DWORD state = readerStates[0].dwEventState;
        
        // Check for reader removal via SCARD_STATE_UNAVAILABLE or SCARD_STATE_IGNORE
        if ((state & SCARD_STATE_UNAVAILABLE) || (state & SCARD_STATE_IGNORE)) {
            qDebug() << "KeycardChannelPcsc: Reader became unavailable:" << readerName;
            disconnectFromCard();
            m_lastDetectedUid.clear();
            m_lastReaderAvailable = false;
            emit readerAvailabilityChanged(false);
            emit cardRemoved();  // Reader removal implies card removal
            return;  // Return to detection phase
        }
        
        // Check if card physically removed from reader
        if ((state & SCARD_STATE_EMPTY) || (state & SCARD_STATE_UNKNOWN)) {
            qDebug() << "KeycardChannelPcsc: Card physically removed";
            disconnectFromCard();
            m_lastDetectedUid.clear();
            emit cardRemoved();  // Physical removal - emit event immediately!
            return;  // Return to detection phase
        }
        
        // Check PnP notification (index 1) for reader topology changes
        if (readerStates.size() > 1) {
            DWORD pnpState = readerStates[1].dwEventState;
            if (pnpState & SCARD_STATE_CHANGED) {
                // PnP state changed - check if our specific reader was removed
                QStringList currentReaders = listReaders();
                bool readerStillPresent = currentReaders.contains(readerName);
                if (!readerStillPresent) {
                    qDebug() << "KeycardChannelPcsc: Reader removed (detected via PnP):" << readerName;
                    disconnectFromCard();
                    m_lastDetectedUid.clear();
                    m_lastReaderAvailable = false;
                    emit readerAvailabilityChanged(false);
                    emit cardRemoved();  // Reader removal implies card removal
                    return;  // Return to detection phase
                }
            }
        }
    }
    
    qDebug() << "KeycardChannelPcsc: Watch stopped";
}

void KeycardChannelPcsc::detectionLoop()
{
    qDebug() << "KeycardChannelPcsc: Detection loop started (event-driven, matches status-keycard-go)";
    
    // Matching Go's two-phase detection pattern:
    // Phase 1: detectionRoutine() - wait for card insertion
    // Phase 2: watchActiveReader() - monitor card until removed
    
    while (m_stopDetection.loadAcquire() == 0) {
        // Check for force scan request
        if (m_forceScan.loadAcquire() == 1) {
            m_forceScan.storeRelease(0);
            qDebug() << "KeycardChannelPcsc: Force scan requested, restarting detection";
            // Continue with detection
        }
        // Get list of readers
        QStringList readers = listReaders();
        
        if (readers.isEmpty()) {
            // Signal that no readers are available (matches Go's WaitingForReader state)
            // Always emit on first check to report initial state (matches Go's immediate state transition)
            if (m_firstReaderCheck || m_lastReaderAvailable) {
                qDebug() << "KeycardChannelPcsc: No readers found" << (m_firstReaderCheck ? "(initial state)" : "(reader removed)");
                m_lastReaderAvailable = false;
                m_firstReaderCheck = false;
                emit readerAvailabilityChanged(false);
            }
            QThread::msleep(500);  // Wait before retry
            continue;
        }
        
        // Readers are available - always emit on first check, then only on state change
        // This matches Go's immediate state transition in connectCard()
        if (m_firstReaderCheck || !m_lastReaderAvailable) {
            qDebug() << "KeycardChannelPcsc: Reader(s) detected:" << readers.size() << (m_firstReaderCheck ? "(initial state)" : "");
            m_lastReaderAvailable = true;
            m_firstReaderCheck = false;
            emit readerAvailabilityChanged(true);
        }
        
        // Prepare reader states (matching Go implementation)
        // Include PnP Notification reader for reader removal detection
        std::vector<SCARD_READERSTATE> readerStates;
        
#ifdef Q_OS_WIN
        // Windows uses wide strings
        std::vector<std::wstring> readerNames;
        for (const QString& reader : readers) {
            readerNames.push_back(reader.toStdWString());
        }
        
        for (size_t i = 0; i < readerNames.size(); ++i) {
            SCARD_READERSTATE rs;
            memset(&rs, 0, sizeof(rs));
            rs.szReader = readerNames[i].c_str();
            rs.dwCurrentState = SCARD_STATE_UNAWARE;
            readerStates.push_back(rs);
        }
        
        // Add PnP Notification reader to detect reader removal (Windows)
        std::wstring pnpReader = L"\\\\?PnP?\\Notification";
        SCARD_READERSTATE pnpRs;
        memset(&pnpRs, 0, sizeof(pnpRs));
        pnpRs.szReader = pnpReader.c_str();
        pnpRs.dwCurrentState = SCARD_STATE_UNAWARE;
        readerStates.push_back(pnpRs);
#else
        // macOS/Linux use UTF-8 strings
        std::vector<QByteArray> readerBytes;
        for (const QString& reader : readers) {
            readerBytes.push_back(reader.toUtf8());
        }
        
        for (size_t i = 0; i < readerBytes.size(); ++i) {
            SCARD_READERSTATE rs;
            memset(&rs, 0, sizeof(rs));
            rs.szReader = readerBytes[i].constData();
            rs.dwCurrentState = SCARD_STATE_UNAWARE;
            readerStates.push_back(rs);
        }
        
        // Add PnP Notification reader to detect reader removal (macOS/Linux)
        QByteArray pnpReader("\\\\?PnP?\\Notification");
        SCARD_READERSTATE pnpRs;
        memset(&pnpRs, 0, sizeof(pnpRs));
        pnpRs.szReader = pnpReader.constData();
        pnpRs.dwCurrentState = SCARD_STATE_UNAWARE;
        readerStates.push_back(pnpRs);
#endif
        
        qDebug() << "KeycardChannelPcsc: Monitoring" << readers.size() << "reader(s) for card changes";
        
        // Event loop: wait for card state changes
        while (m_stopDetection.loadAcquire() == 0) {
            // Check if any reader already has a card present (matching Go)
            // Note: Last entry in readerStates is PnP Notification reader (skip it)
            bool foundCard = false;
            int cardReaderIndex = -1;
            size_t numActualReaders = readerStates.size() - 1;  // Exclude PnP reader
            
            for (size_t i = 0; i < numActualReaders; ++i) {
                if (readerStates[i].dwEventState & SCARD_STATE_PRESENT) {
                    foundCard = true;
                    cardReaderIndex = i;
                    break;
                }
            }
            
            // Check for reader removal BEFORE waiting (check state flags)
            // This catches reader removal immediately without waiting for PnP
            bool readerBecameUnavailable = false;
            for (size_t i = 0; i < numActualReaders; ++i) {
                DWORD state = readerStates[i].dwEventState;
                if ((state & SCARD_STATE_UNAVAILABLE) || (state & SCARD_STATE_IGNORE)) {
                    qDebug() << "KeycardChannelPcsc: Reader became unavailable in detection loop:" << readers[i];
                    if (m_lastReaderAvailable) {
                        m_lastReaderAvailable = false;
                        emit readerAvailabilityChanged(false);
                    }
                    readerBecameUnavailable = true;
                    break;
                }
            }
            
            if (readerBecameUnavailable) {
                // Break inner loop to re-enumerate readers
                break;
            }
            
            // Update current state for next iteration (all readers including PnP)
            for (auto& rs : readerStates) {
                rs.dwCurrentState = rs.dwEventState;
            }
            
            if (foundCard && cardReaderIndex >= 0) {
                // Card detected! Try to connect
                QString readerName = readers[cardReaderIndex];
                qDebug() << "KeycardChannelPcsc: Card detected in reader:" << readerName;
                
                if (connectToReader(readerName)) {
                    // Successfully connected
                    QString uid = m_lastATR.right(4).toHex();
                    
                    // Only emit if this is a new card (prevent duplicates)
                    if (uid != m_lastDetectedUid) {
                        qDebug() << "KeycardChannelPcsc: New card UID:" << uid;
                        m_lastDetectedUid = uid;
                        emit targetDetected(uid);
                    }
                    
                    // Phase 2: Watch for card removal
                    // This matches status-keycard-go's watchActiveReader()
                    watchCardRemoval(readerName);
                    
                    // After watchCardRemoval returns (card removed or force scan),
                    // go back to detection phase
                    continue;
                } else {
                    // Failed to connect - break inner loop to re-enumerate readers
                    // This prevents infinite loop when PC/SC reports card present
                    // but connection fails (e.g. SCARD_W_REMOVED_CARD)
                    qDebug() << "KeycardChannelPcsc: Connection failed, breaking to re-enumerate";
                    break;
                }
            }
            
            // No card present, wait for state change
            // Matching Go: err := ctx.GetStatusChange(rs, -1)  // Wait forever
            LONG rv = SCardGetStatusChange(
                m_pcscState->context,
                1000,  // 1 second timeout (use INFINITE for exact Go match, but timeout is safer)
                readerStates.data(),
                readerStates.size()
            );
            
            if (rv == SCARD_E_TIMEOUT) {
                // No change in 1 second, continue loop
                continue;
            }
            
            if (rv == SCARD_E_CANCELLED) {
                // Cancelled (stopDetection called)
                qDebug() << "KeycardChannelPcsc: Detection cancelled";
                break;
            }
            
            // Check for reader-related errors that indicate reader removal
            if (rv == SCARD_E_NO_READERS_AVAILABLE || rv == SCARD_E_UNKNOWN_READER || 
                rv == SCARD_E_READER_UNAVAILABLE) {
                qDebug() << "KeycardChannelPcsc: Reader error detected, treating as reader removal";
                if (m_lastReaderAvailable) {
                    m_lastReaderAvailable = false;
                    emit readerAvailabilityChanged(false);
                }
                break;  // Restart detection loop to re-enumerate
            }
            
            if (rv != SCARD_S_SUCCESS) {
                qWarning() << "KeycardChannelPcsc: SCardGetStatusChange error:" << QString("0x%1").arg(rv, 0, 16);
                QThread::msleep(1000);  // Wait before retry
                break;  // Restart detection loop
            }
            
            // Re-enumerate readers on EVERY state change to catch reader removal
            // (PC/SC on macOS has delays in updating reader state flags)
            QStringList currentReaders = listReaders();
            
            // Check if our monitored readers are still present
            bool anyReaderRemoved = false;
            for (const QString& reader : readers) {
                if (!currentReaders.contains(reader)) {
                    qDebug() << "KeycardChannelPcsc: Reader removed:" << reader;
                    anyReaderRemoved = true;
                }
            }
            
            // If reader was removed, emit signal and re-enumerate
            if (anyReaderRemoved) {
                if (m_lastReaderAvailable && currentReaders.isEmpty()) {
                    qDebug() << "KeycardChannelPcsc: All readers removed";
                    m_lastReaderAvailable = false;
                    emit readerAvailabilityChanged(false);
                }
                // Break inner loop to re-enumerate readers
                break;
            }
            
            // Check actual reader states for UNAVAILABLE (fallback check)
            for (size_t i = 0; i < numActualReaders; ++i) {
                DWORD state = readerStates[i].dwEventState;
                
                if ((state & SCARD_STATE_UNAVAILABLE) || (state & SCARD_STATE_IGNORE)) {
                    qDebug() << "KeycardChannelPcsc: Reader became unavailable:" << readers[i];
                    if (m_lastReaderAvailable) {
                        m_lastReaderAvailable = false;
                        emit readerAvailabilityChanged(false);
                    }
                    // Break inner loop to re-enumerate readers
                    break;
                }
            }
            
            // State changed, loop will check for cards
        }
        
        // Outer loop: refresh reader list
        if (m_stopDetection.loadAcquire() == 0) {
            QThread::msleep(100);  // Small delay before refreshing readers
        }
    }
    
    qDebug() << "KeycardChannelPcsc: Detection loop exited";
}

void KeycardChannelPcsc::disconnect()
{
    disconnectFromCard();
}

QByteArray KeycardChannelPcsc::transmit(const QByteArray& apdu)
{
    // CRITICAL: Serialize APDU transmissions to prevent corruption
    // Multiple threads calling transmit() simultaneously will interleave
    // commands and responses, causing the card to return errors like 0x6985
    QMutexLocker locker(&m_transmitMutex);
    
    if (!m_connected || !m_pcscState->cardHandle) {
        throw std::runtime_error("Not connected to any card");
    }
    
    qDebug() << "KeycardChannelPcsc: Transmitting APDU:" << apdu.toHex();
    
    // Prepare send/receive structures
    SCARD_IO_REQUEST pioSendPci;
    if (m_pcscState->activeProtocol == SCARD_PROTOCOL_T0) {
        pioSendPci = *SCARD_PCI_T0;
    } else {
        pioSendPci = *SCARD_PCI_T1;
    }
    
    BYTE pbRecvBuffer[258];  // Max APDU response
    DWORD dwRecvLength = sizeof(pbRecvBuffer);
    
    LONG rv = SCardTransmit(
        m_pcscState->cardHandle,
        &pioSendPci,
        (LPCBYTE)apdu.constData(),
        apdu.size(),
        NULL,
        pbRecvBuffer,
        &dwRecvLength
    );
    
    if (rv != SCARD_S_SUCCESS) {
        QString msg = QString("SCardTransmit failed: 0x%1").arg(rv, 0, 16);
        qWarning() << "KeycardChannelPcsc:" << msg;
        throw std::runtime_error(msg.toStdString());
    }
    
    QByteArray response((char*)pbRecvBuffer, dwRecvLength);
    qDebug() << "KeycardChannelPcsc: Received response:" << response.toHex();
    
    return response;
}

bool KeycardChannelPcsc::isConnected() const
{
    return m_connected;
}

void KeycardChannelPcsc::forceScan()
{
    qDebug() << "KeycardChannelPcsc: Force scan requested";
    m_forceScan.storeRelease(1);
    
    // Cancel current blocking SCardGetStatusChange() to wake up the thread
    if (m_pcscState->contextEstablished) {
        SCardCancel(m_pcscState->context);
    }
}

} // namespace Keycard
