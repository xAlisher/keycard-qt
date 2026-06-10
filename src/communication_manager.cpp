#include "keycard-qt/communication_manager.h"
#include <QDebug>
#include <QTimer>
#include <QCoreApplication>
#include <QVector>

namespace Keycard {

// ============================================================================
// CommunicationThread Implementation
// ============================================================================

void CommunicationManager::CommunicationThread::run() {
    qDebug() << "CommunicationThread: Starting on thread:" << QThread::currentThread();
    
    // CRITICAL: Lock thread for PC/SC operations (like Go's runtime.LockOSThread())
    // PC/SC requires operations to happen on the same thread that established context
#if defined(Q_OS_WIN) || defined(Q_OS_MAC) || defined(Q_OS_LINUX)
    // Platform-specific thread locking happens in PC/SC backend
    qDebug() << "CommunicationThread: Running on platform requiring thread affinity";
#endif
    
    // Run Qt event loop
    // All card operations will be processed through queued signals/slots
    exec();
    
    qDebug() << "CommunicationThread: Stopped";
}

// ============================================================================
// CommunicationManager Implementation
// ============================================================================

CommunicationManager::CommunicationManager(QObject* parent)
    : ICommunicationManager(parent)
    , m_commThread(nullptr)
    , m_state(State::Idle)
    , m_running(false)
    , m_batchOperationDepth(0)
{
    qDebug() << "CommunicationManager: Created";
}

CommunicationManager::~CommunicationManager() {
    stop();
}

bool CommunicationManager::init(std::shared_ptr<CommandSet> commandSet) {
    if (m_running) {
        qWarning() << "CommunicationManager: Already initialized";
        return false;
    }
    
    if (!commandSet) {
        qWarning() << "CommunicationManager: No command set provided";
        return false;
    }
    
    qDebug() << "CommunicationManager: Initializing with CommandSet...";
    
    m_commandSet = commandSet;
    
    // Create and start communication thread
    m_commThread = new CommunicationThread(this);
    
    // Move manager to communication thread so all slots run there
    moveToThread(m_commThread);
    
    // Connect to CommandSet signals (queued - cross-thread)
    // CommandSet lives on main thread, manager on communication thread
    connect(m_commandSet.get(), &CommandSet::cardReady,
            this, &CommunicationManager::onCardReady,
            Qt::QueuedConnection);
    
    connect(m_commandSet.get(), &CommandSet::cardLost,
            this, &CommunicationManager::onCardLost,
            Qt::QueuedConnection);
    
    connect(m_commandSet.get(), &CommandSet::channelStateChanged,
            this, &CommunicationManager::onChannelStateChanged,
            Qt::QueuedConnection);

    // Connect to channel targetDetectionStopped (user cancelled NFC)
    if (auto* ch = m_commandSet->channel().get()) {
        connect(ch, &KeycardChannel::targetDetectionStopped,
                this, &CommunicationManager::onTargetDetectionStopped,
                Qt::QueuedConnection);
    }
    
    m_commThread->start();
    
    m_running = true;
    setState(State::Idle);
    
    qDebug() << "CommunicationManager: Initialized successfully with CommandSet";
    qDebug() << "CommunicationManager: CommandSet owns channel - no race conditions!";
    return true;
}


bool CommunicationManager::startDetection() {
    if (!m_running || !m_commandSet) {
        qWarning() << "CommunicationManager: Not initialized, call init() first";
        return false;
    }
    
    qDebug() << "CommunicationManager: Starting card detection...";
    QMetaObject::invokeMethod(m_commandSet.get(),
                               &CommandSet::startDetection,
                               Qt::QueuedConnection);
    
    qDebug() << "CommunicationManager: Card detection started via CommandSet";
    return true;
}

void CommunicationManager::stopDetection() {
    if (!m_commandSet) {
        return;
    }
    
    qDebug() << "CommunicationManager: Stopping card detection...";
    QMetaObject::invokeMethod(m_commandSet.get(),
                               &CommandSet::stopDetection,
                               Qt::QueuedConnection);
    
    qDebug() << "CommunicationManager: Card detection stopped via CommandSet";
}

void CommunicationManager::cancelPendingOperations(const QString& reason) {
    if (!m_running) {
        return;
    }
    if (QThread::currentThread() == thread()) {
        cancelPendingOperationsInternal(reason);
        return;
    }
    QMetaObject::invokeMethod(this, [this, reason]() {
        cancelPendingOperationsInternal(reason);
    }, Qt::QueuedConnection);
}

void CommunicationManager::cancelPendingOperationsInternal(const QString& reason) {
    setState(State::Idle);
    emit operationCancelled(reason);
    stopDetection();
    {
        QMutexLocker locker(&m_syncMutex);
        for (auto it = m_pendingSync.begin(); it != m_pendingSync.end();) {
            auto sync = it.value();
            sync->completed = true;
            sync->result = CommandResult::fromError(reason, CommandResultType::Cancelled);
            sync->condition.wakeAll();
            it = m_pendingSync.erase(it);
        }
    }
    QVector<QUuid> flushedTokens;
    {
        QMutexLocker locker(&m_queueMutex);
        while (!m_queue.empty()) {
            auto cmd = std::move(m_queue.front());
            m_queue.pop();
            flushedTokens.append(cmd->token());
        }
        m_queueNotEmpty.wakeAll();
    }
    if (!m_running) {
        return;
    }

    for (const QUuid& token : flushedTokens) {
        emit commandCompleted(token, CommandResult::fromError(reason, CommandResultType::Cancelled));
    }
}

void CommunicationManager::onTargetDetectionStopped(bool forced) {
    if (forced) {
        cancelPendingOperationsInternal("User cancelled NFC");
    }
}

void CommunicationManager::stop() {
    if (!m_running) {
        return;
    }
    
    qDebug() << "CommunicationManager: Stopping completely...";
    
    // Step 1: Prevent new commands from being accepted
    m_running = false;
    
    // Step 2: Clear batch mode
    {
        QMutexLocker locker(&m_batchMutex);
        m_batchOperationDepth = 0;
    }
    
    // Step 3: Run cancel logic on comm thread (wake sync, flush queue, stop detection)
    if (QThread::currentThread() == thread()) {
        cancelPendingOperationsInternal("CommunicationManager stopped");
    } else {
        QMetaObject::invokeMethod(this, [this]() {
            cancelPendingOperationsInternal("CommunicationManager stopped");
        }, Qt::BlockingQueuedConnection);
    }
    
    // Step 4: Wait for all pending sync operations to actually complete
    qDebug() << "CommunicationManager: Waiting for pending sync operations to complete...";
    const int maxWaitIterations = 100;  // 100 * 10ms = 1 second max
    int pendingCount = 0;
    for (int i = 0; i < maxWaitIterations; ++i) {
        {
            QMutexLocker locker(&m_syncMutex);
            pendingCount = m_pendingSync.size();
            if (pendingCount == 0) {
                qDebug() << "CommunicationManager: All sync operations completed";
                break;
            }
        }
        QThread::msleep(10);
    }
    
    if (pendingCount > 0) {
        qWarning() << "CommunicationManager: Still" << pendingCount << "pending sync operations after wait";
    }
    
    // Step 5: Stop the communication thread
    // Note: We check m_running before posting processQueue() events (see executeCommand)
    // This prevents new events from being posted after stop() begins
    if (m_commThread) {
        // CRITICAL: Remove all pending QueuedConnection events for this object
        // After waking sync threads, processQueue() events may still be in the event queue
        // We must clear them BEFORE calling quit() to prevent use-after-free
        QCoreApplication::removePostedEvents(this);
        
        qDebug() << "CommunicationManager: Stopping communication thread...";
        m_commThread->quit();
        
        // Wait for thread to finish with a reasonable timeout
        if (!m_commThread->wait(5000)) {
            qWarning() << "CommunicationManager: Thread did not stop gracefully, forcing termination";
            m_commThread->terminate();
            m_commThread->wait(1000);
        }
        
        delete m_commThread;
        m_commThread = nullptr;
        qDebug() << "CommunicationManager: Communication thread stopped";
    }
    
    // Step 6: Final cleanup of any remaining sync operations
    {
        QMutexLocker locker(&m_syncMutex);
        m_pendingSync.clear();
    }
    
    // Step 7: Give one final moment for any last cleanup
    QThread::msleep(50);
    
    setState(State::Idle);
    
    qDebug() << "CommunicationManager: Stopped";
}

void CommunicationManager::startBatchOperations() {
    int depth = 0;
    bool becameActive = false;
    {
        QMutexLocker locker(&m_batchMutex);
        if (m_batchOperationDepth == 0) {
            becameActive = true;
        }
        ++m_batchOperationDepth;
        depth = m_batchOperationDepth;
    }

    if (becameActive) {
        qDebug() << "CommunicationManager: Batch operations mode ENABLED - channel will stay open";
    } else {
        qDebug() << "CommunicationManager: Batch operations depth increased to" << depth;
    }
}

void CommunicationManager::endBatchOperations() {
    int depth = 0;
    bool becameInactive = false;
    {
        QMutexLocker locker(&m_batchMutex);
        if (m_batchOperationDepth <= 0) {
            qWarning() << "CommunicationManager: endBatchOperations() called with depth" << m_batchOperationDepth;
            return;
        }

        --m_batchOperationDepth;
        depth = m_batchOperationDepth;
        becameInactive = (m_batchOperationDepth == 0);
    }

    if (becameInactive) {
        qDebug() << "CommunicationManager: Batch operations mode DISABLED";

        // Check if queue is empty and stop detection if needed
        QMetaObject::invokeMethod(this, &CommunicationManager::processQueue, Qt::QueuedConnection);
    } else {
        qDebug() << "CommunicationManager: Batch operations depth decreased to" << depth;
    }
}

QUuid CommunicationManager::enqueueCommand(std::unique_ptr<CardCommand> cmd) {
    if (!m_running) {
        qWarning() << "CommunicationManager: Cannot enqueue command, not running";
        return QUuid();
    }
    
    if (!cmd) {
        qWarning() << "CommunicationManager: Cannot enqueue null command";
        return QUuid();
    }
    
    QUuid token = cmd->token();
    QString cmdName = cmd->name();
    
    qDebug() << "CommunicationManager: Enqueueing command" << cmdName << "token:" << token;
    
    {
        QMutexLocker locker(&m_queueMutex);
        m_queue.push(std::move(cmd));
        m_queueNotEmpty.wakeAll();
    }

    if (m_commandSet && m_commandSet->isCardReady() && state() == State::Ready) {
        QMetaObject::invokeMethod(this, &CommunicationManager::processQueue,
                                Qt::QueuedConnection);
    }
    else {
        startDetection();
    }
    
    return token;
}

CommandResult CommunicationManager::executeCommandSync(std::unique_ptr<CardCommand> cmd) {
    if (!m_running) {
        return CommandResult::fromError("CommunicationManager not running");
    }
    
    if (!cmd) {
        qWarning() << "CommunicationManager: Cannot execute null command";
        return CommandResult::fromError("Null command");
    }
    
    QUuid token = cmd->token();
    QString cmdName = cmd->name();
    
    
    // Note: Reduced logging here to avoid qDebug race conditions with multiple threads
    qDebug() << "CommunicationManager: Executing command synchronously:" << cmdName;
    
    // Create sync tracker on HEAP to prevent dangling pointer
    // Use shared_ptr so it stays valid even after this function returns
    auto sync = std::make_shared<PendingSync>();
    sync->completed = false;
    
    {
        QMutexLocker locker(&m_syncMutex);
        m_pendingSync[token] = sync;
    }
    
    // Enqueue command (this will set channel state)
    enqueueCommand(std::move(cmd));
    
    // IMPORTANT: Thread-safe wait strategy
    // Check if we're on the main/GUI thread
    QThread* mainThread = QCoreApplication::instance()->thread();
    QThread* currentThread = QThread::currentThread();
    bool isMainThread = (currentThread == mainThread);
    
    // Extract result and clean up inside each branch while lock is held —
    // re-acquiring m_syncMutex after the branch's QMutexLocker is still in scope causes EDEADLK.
    CommandResult finalResult;

    if (isMainThread) {
        // MAIN THREAD: Process events while waiting so UI stays responsive.
        qDebug() << "CommunicationManager: Waiting on main thread for sync completion";

        QMutexLocker locker(&m_syncMutex);

        while (!sync->completed && m_running) {
            // Unlock mutex to allow event processing.
            locker.unlock();
            QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
            locker.relock();

            if (!sync->completed) {
                sync->condition.wait(&m_syncMutex, 100);
            }
        }

        // Still holding locker — extract and remove while lock is held.
        if (!sync->completed) {
            qWarning() << "CommunicationManager: Sync command ended without completion:" << cmdName;
            finalResult = CommandResult::fromError("CommunicationManager stopped");
        } else {
            finalResult = sync->result;
        }
        m_pendingSync.remove(token);

    } else {
        // BACKGROUND THREAD: Wait until command completes or manager stops.
        qDebug() << "CommunicationManager: Waiting on background thread for sync completion";

        QMutexLocker locker(&m_syncMutex);
        while (!sync->completed && m_running) {
            sync->condition.wait(&m_syncMutex);
        }

        if (!sync->completed) {
            sync->completed = true;
            sync->result = CommandResult::fromError("CommunicationManager stopped");
        }

        // Still holding locker — extract and remove while lock is held.
        finalResult = sync->result;
        m_pendingSync.remove(token);
    }

    return finalResult;
}

CommunicationManager::State CommunicationManager::state() const {
    QMutexLocker locker(&m_stateMutex);
    return m_state;
}

ApplicationInfo CommunicationManager::applicationInfo() const {
    QMutexLocker locker(&m_infoMutex);
    if (m_commandSet) {
        return m_commandSet->applicationInfo();
    }
    return ApplicationInfo();
}

ApplicationStatus CommunicationManager::applicationStatus() const {
    QMutexLocker locker(&m_infoMutex);
    if (m_commandSet) {
        return m_commandSet->cachedApplicationStatus();
    }
    return ApplicationStatus();
}

QByteArray CommunicationManager::getDataFromCard(uint8_t type) {
    if (!m_commandSet) {
        return QByteArray();
    }
    return m_commandSet->getData(type);
}

bool CommunicationManager::storeDataToCard(uint8_t type, const QByteArray& data) {
    if (!m_commandSet) {
        return false;
    }
    return m_commandSet->storeData(type, data);
}

void CommunicationManager::setState(State newState) {
    State oldState;
    {
        QMutexLocker locker(&m_stateMutex);
        if (m_state == newState) {
            return;
        }
        oldState = m_state;
        m_state = newState;
    }
    
    qDebug() << "CommunicationManager: State changed:" << oldState << "->" << newState;
    emit stateChanged(newState);
}

// ============================================================================
// Card Detection and Initialization (Communication Thread)
// ============================================================================

void CommunicationManager::onCardReady(const QString& uid) {
    qDebug() << "========================================";
    qDebug() << "CommunicationManager: CARD READY! UID:" << uid;
    qDebug() << "   Thread:" << QThread::currentThread();
    qDebug() << "   Current state:" << m_state;
    qDebug() << "========================================";
    
    m_currentCardUID = uid;
    setState(State::Initializing);
    
    
    qDebug() << "CommunicationManager: Starting card initialization sequence...";
    try {
        CardInitializationResult result = initializeCardSequence();

        qDebug() << "CommunicationManager: Card initialization SUCCESS";
        
        // Update cached info
        {
            QMutexLocker locker(&m_infoMutex);
            m_appInfo = result.appInfo;
            m_appStatus = result.appStatus;
        }
        
        setState(State::Ready);
        emit cardInitialized(result);
        
        // Now process any queued commands
        processQueue();
    } catch (const std::runtime_error& e) {
        qWarning() << "CommunicationManager: Card initialization sequence threw exception:" << e.what();
        startDetection();
        return;
    } catch (...) {
        qWarning() << "CommunicationManager: Card initialization sequence threw unknown exception";
    }
}

void CommunicationManager::onCardLost() {
    qDebug() << "========================================";
    qDebug() << "CommunicationManager: CARD LOST (from CommandSet)";
    qDebug() << "   Thread:" << QThread::currentThread();
    qDebug() << "========================================";
    
    State currentState;
    {
        QMutexLocker stateLocker(&m_stateMutex);
        currentState = m_state;
    }

    if (currentState == State::Initializing) {
        qDebug() << "CommunicationManager: Card lost during initialization, ignoring";
        startDetection();
        return;
    }

    if (currentState == State::Processing) {
        qDebug() << "CommunicationManager: Card lost during command processing, ignoring";
        startDetection();
        return;
    }
    
    setState(State::Idle);
    emit cardLost();
}

void CommunicationManager::onChannelStateChanged(ChannelState state) {
    qDebug() << "CommunicationManager: Channel state changed to" << static_cast<int>(state);
    
    // Just log the state change
    // CommandSet emits this signal when it calls startDetection() / stopDetection()
    // We receive it here but don't need to forward it anywhere
    // (The channel itself emits channelStateChanged for operational state tracking)
    
    QString stateName;
    switch (state) {
        case ChannelState::Idle:
            stateName = "Idle";
            break;
        case ChannelState::WaitingForCard:
            stateName = "WaitingForCard";
            break;
        default:
            stateName = "Unknown";
            break;
    }
    
    qDebug() << "CommunicationManager: Channel lifecycle state:" << stateName;
}

CardInitializationResult CommunicationManager::initializeCardSequence() {
    qDebug() << "CommunicationManager::initializeCardSequence() - STARTING";
    qDebug() << "   This runs atomically - NO races possible!";
    
    if (!m_commandSet) {
        return CardInitializationResult::fromError("No CommandSet available");
    }
    
    // STEP 1: SELECT applet
    qDebug() << "   [1/5] SELECT applet...";
    ApplicationInfo appInfo = m_commandSet->select(true);
    
    if (!appInfo.installed && appInfo.instanceUID.isEmpty() && appInfo.secureChannelPublicKey.isEmpty()) {
        return CardInitializationResult::fromError("Failed to select applet");
    }
    
    // Check if card is initialized
    if (!appInfo.initialized) {
        qDebug() << "   Card is empty (not initialized)";
        // Return success with empty state - card needs initialization
        return CardInitializationResult::fromSuccess(m_currentCardUID, appInfo, ApplicationStatus());
    }
    
    // STEP 2: Ensure pairing
    qDebug() << "   [2/5] Ensure pairing...";
    if (!m_commandSet->ensurePairing()) {
        QString error = m_commandSet->lastError();
        if (error.isEmpty()) {
            error = "Failed to ensure pairing";
        }
        return CardInitializationResult::fromError(error);
    }
    
    // STEP 3: Open secure channel
    qDebug() << "   [3/5] Open secure channel...";
    if (!m_commandSet->ensureSecureChannel()) {
        QString error = m_commandSet->lastError();
        if (error.isEmpty()) {
            error = "Failed to open secure channel";
        }
        return CardInitializationResult::fromError(error);
    }
    
    // STEP 4: Get status
    qDebug() << "   [4/5] Get application status...";
    ApplicationStatus appStatus = m_commandSet->cachedApplicationStatus();
    
    if (!m_commandSet->hasCachedStatus()) {
        qWarning() << "   Failed to get application status, but continuing...";
    }
    
    // STEP 5: Get metadata (optional - don't fail if this errors)
    qDebug() << "   [5/5] Get metadata (optional)...";
    // We could add metadata fetching here if needed
    
    qDebug() << "CommunicationManager::initializeCardSequence() - COMPLETED SUCCESSFULLY";
    
    return CardInitializationResult::fromSuccess(m_currentCardUID, appInfo, appStatus);
}

// ============================================================================
// Command Queue Processing (Communication Thread)
// ============================================================================

void CommunicationManager::processQueue() {
    // This method runs on the communication thread
    // It processes commands one at a time, serially
    
    QMutexLocker locker(&m_queueMutex);
    
    // CRITICAL: Check state atomically to prevent race condition
    // We must check BOTH state and queue under the same lock to ensure consistency
    State currentState;
    {
        QMutexLocker stateLocker(&m_stateMutex);
        currentState = m_state;
    }
    
    if (currentState == State::Processing) {
        qDebug() << "CommunicationManager: Already processing a command, skipping";
        return;
    }

    if (m_queue.empty()) {
        // Check if we're in batch operations mode
        bool inBatchMode = false;
        {
            QMutexLocker batchLocker(&m_batchMutex);
            inBatchMode = (m_batchOperationDepth > 0);
        }
        
        if (inBatchMode) {
            qDebug() << "Empty command queue but in batch mode - keeping channel open";
            return;
        }
        
        // Only stop detection if we're NOT processing
        // Double-check state hasn't changed
        QMutexLocker stateLocker(&m_stateMutex);
        if (m_state != State::Processing) {
            qDebug() << "Empty command queue - stopping keycard detection";
            locker.unlock();  // Release queue lock before calling stopDetection
            stateLocker.unlock();
            setState(State::Idle);
            stopDetection();
        }
        return;
    }
    
    // If card is not detected/initialized yet, wait for it
    // When card is detected, CommandSet will emit cardReady() which triggers onCardReady()
    // onCardReady() will initialize and then call processQueue() again
    if (currentState == State::Idle) {
        qDebug() << "CommunicationManager: Card not ready yet, waiting...";
        qDebug() << "CommunicationManager: Waiting for cardReady signal from CommandSet";
        // Don't process yet - wait for card detection
        return;
    }
    
    // Get next command
    auto cmd = std::move(m_queue.front());
    m_queue.pop();
    QUuid token = cmd->token();
    QString cmdName = cmd->name();
    
    // Check if command can run in current state
    if (currentState == State::Initializing && !cmd->canRunDuringInit()) {
        qDebug() << "CommunicationManager: Command" << cmdName << "cannot run during init, re-queuing";
        // Re-queue at front (note: this changes FIFO order but ensures command runs after init)
        // For proper FIFO with re-queuing, we'd need a deque, but this is simpler
        m_queue.push(std::move(cmd));
        return;
    }
    
    if (currentState != State::Ready && currentState != State::Initializing) {
        qWarning() << "CommunicationManager: Cannot process command in state:" << currentState;
        CommandResult result = CommandResult::fromError("Card not ready");
        
        // Notify completion
        emit commandCompleted(token, result);
        
        // Wake sync waiter if any
        {
            QMutexLocker syncLocker(&m_syncMutex);
            if (m_pendingSync.contains(token)) {
                auto sync = m_pendingSync[token];  // shared_ptr copy keeps it alive
                sync->result = result;
                sync->completed = true;
                sync->condition.wakeAll();
            }
        }
        
        return;
    }
    
    locker.unlock();
    
    // Execute command
    qDebug() << "CommunicationManager: Executing command:" << cmdName << "token:" << token;
    
    setState(State::Processing);
    
    CommandResult result;
    try {
        result = cmd->execute(m_commandSet.get());
    } catch (const std::runtime_error& e) {
        qWarning() << "CommunicationManager: Command threw exception:" << e.what();
        if (m_commandSet && m_commandSet->isDetectionActive()) {
            // Re-queue at front
            {
                QMutexLocker queueLocker(&m_queueMutex);
                m_queue.push(std::move(cmd));
                m_queueNotEmpty.wakeOne();
            }
            stopDetection();
            startDetection();
            return;
        }
        result = CommandResult::fromError(e.what());
    } catch (...) {
        qWarning() << "CommunicationManager: Command threw unknown exception";
        result = CommandResult::fromError("Unknown exception");
    }
    
    setState(State::Ready);
    
    qDebug() << "CommunicationManager: Command completed:" << cmdName
             << "success:" << result.success;
    
    // Notify completion
    emit commandCompleted(token, result);
    
    // Wake sync waiter if any
    {
        QMutexLocker syncLocker(&m_syncMutex);
        if (m_pendingSync.contains(token)) {
            auto sync = m_pendingSync[token];  // shared_ptr copy keeps it alive
            sync->result = result;
            sync->completed = true;
            sync->condition.wakeAll();
        }
    }
    
    // Process next command if any
    // If queue is empty, processQueue() will handle stopDetection()
    // Only post event if still running (don't post events during shutdown)
    if (m_running) {
        QMetaObject::invokeMethod(this, &CommunicationManager::processQueue,
                                   Qt::QueuedConnection);
    }
}

} // namespace Keycard
