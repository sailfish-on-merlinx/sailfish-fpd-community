#include "fpdcommunity.h"
#include <QDebug>
#include <QDBusConnection>
#include <QDBusError>
#include <QDBusInterface>
#include <QCoreApplication>
#include <QDir>
#include <QDataStream>
#include <QFile>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#define FINGERPRINT_PATH "/var/lib/sailfish-fpd-community/"
#define FINGERPRINT_FILE "fingerprints.db"

FPDCommunity::FPDCommunity()
{
    qDebug() << Q_FUNC_INFO;

    connect(&m_androidFP, &AndroidFP::enrollProgress, this, &FPDCommunity::slot_enrollProgress);
    connect(&m_androidFP, &AndroidFP::succeeded, this, &FPDCommunity::slot_succeeded);
    connect(&m_androidFP, &AndroidFP::failed, this, &FPDCommunity::slot_failed);
    connect(&m_androidFP, &AndroidFP::removed, this, &FPDCommunity::slot_removed);
    connect(&m_androidFP, &AndroidFP::acquired, this, &FPDCommunity::slot_acquired);
    connect(&m_androidFP, &AndroidFP::authenticated, this, &FPDCommunity::slot_authenticated);
    connect(&m_androidFP, &AndroidFP::enumerated, this, &FPDCommunity::slot_enumerated);

    // configure cancel timer
    m_cancelTimer.setSingleShot(true);
    m_cancelTimer.setInterval(30000);
    connect(&m_cancelTimer, &QTimer::timeout, this, &FPDCommunity::slot_cancelIdentify);

    // set current user - nemo for now
    setUser(100000);
    registerDBus();
}

void FPDCommunity::registerDBus()
{
    qDebug() << Q_FUNC_INFO;
    if (!m_dbusRegistered)
    {
        // DBus
        QDBusConnection connection = QDBusConnection::systemBus();
        qDebug() << "Registering service on dbus" << SERVICE_NAME;
        if (!connection.registerService(SERVICE_NAME))
        {
            qCritical() << "Didnt register service";
            QCoreApplication::quit();
            return;
        }

        if (!connection.registerObject("/org/sailfishos/fingerprint1", this, QDBusConnection::ExportAllInvokables | QDBusConnection::ExportAllSignals | QDBusConnection::ExportAllProperties))
        {
            qCritical() << "Didnt register object"
                        "";
            QCoreApplication::quit();
            return;
        }
        m_dbusRegistered = true;

        qInfo() << "Sucessfully registered to dbus systemBus";
    }
}

// Code from https://stackoverflow.com/a/37489754/11848012
// with minor modifications
bool do_chown(const char *file_path, const char *user_name,
              const char *group_name)
{
    uid_t          uid;
    gid_t          gid;
    struct passwd *pwd;
    struct group  *grp;

    pwd = getpwnam(user_name);
    if (pwd == nullptr) {
        qWarning() << "Failed to get user id for" << user_name;
        return false;
    }
    uid = pwd->pw_uid;

    grp = getgrnam(group_name);
    if (grp == nullptr) {
        qWarning() << "Failed to get group id for" << group_name;
        return false;
    }
    gid = grp->gr_gid;

    if (chown(file_path, uid, gid) == -1) {
        qWarning() << "Failed to chown for" << file_path;
        return false;
    }
    return true;
}

static bool makePath(const char* path, const char* user = nullptr, const char* group = nullptr,
                     QFileDevice::Permissions permissions = QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)
{
    qDebug() << Q_FUNC_INFO << path << user << group << permissions;

    QFileInfo fi(path);
    if (fi.exists()) {
        return true;
    }

    QString leaf = fi.fileName();
    QDir dir = fi.absoluteDir();
    if (!makePath(dir.path().toLocal8Bit().data(), user, group, permissions)) {
        return false;
    }

    if (!dir.mkdir(leaf)) {
        qWarning() << "Failed to create directory" << path;
        return false;
    }

    if (!QFile::setPermissions(path, permissions))  {
        qWarning() << "Failed to set permissions" << path;
        return false;
    }

    if (user != nullptr && group != nullptr) {
      return do_chown(path, user, group);
    }

    return true;
}

void FPDCommunity::setUser(uint32_t uid)
{
    qDebug() << Q_FUNC_INFO << uid;

    // path for android store
    QString andrPath = AndroidFP::getDefaultGroupPath(uid);

    // create path if missing and set expected permissions / ownership
    if (!makePath(andrPath.toLocal8Bit().data(), "system", "system")) {
        qWarning() << "Unable to create Android store" << andrPath;
    }

    // path for storing string<->uint fp id map
    QDir fpDir(QStringLiteral(FINGERPRINT_PATH "/%1").arg(uid));
    if (!makePath(fpDir.absolutePath().toLocal8Bit().data())) {
        qWarning() << "Unable to create FPD store" << fpDir.absolutePath();
    }

    m_fingerDatabasePath = fpDir.absoluteFilePath(FINGERPRINT_FILE);

    // always setting group id to 0
    m_androidFP.setGroup(0, andrPath);

    // fingers are enumerated and loaded after that
    enumerate();
}

void FPDCommunity::saveFingers()
{
    qDebug() << Q_FUNC_INFO;

    QFile fingerprintFile(m_fingerDatabasePath);

    if (!fingerprintFile.open(QIODevice::WriteOnly)) {
        qWarning() << "Could not write " << m_fingerDatabasePath;
        return;
    }

    QDataStream out(&fingerprintFile);
    out.setVersion(QDataStream::Qt_5_6);
    out << m_fingerMap;
}

void FPDCommunity::loadFingers()
{
    qDebug() << Q_FUNC_INFO;

    QFile fingerprintFile(m_fingerDatabasePath);
    QDataStream in(&fingerprintFile);
    in.setVersion(QDataStream::Qt_5_6);

    // No map file at all means this installation has never enrolled anything.
    const bool everEnrolled = fingerprintFile.exists();

    if (!fingerprintFile.open(QIODevice::ReadOnly)) {
        qInfo() << "Could not read the file:" << m_fingerDatabasePath << "Error string:" << fingerprintFile.errorString();
        qInfo() << "Assuming empty fingerprint map";
        m_fingerMap.clear();
    } else {
        in >> m_fingerMap;
    }

    QList<uint32_t> enumeratedFingers = m_androidFP.fingerprints();

    // Never prune against a list that did not come from the HAL: the names are
    // persisted, so saveFingers() would make an unknown result permanent.
    if (!m_androidFP.enumerationAuthoritative()) {
        qWarning() << "Enumeration unavailable; keeping" << m_fingerMap.size()
                   << "stored finger(s) as-is and skipping reconcile";
        qDebug() << "Loaded finger map (unreconciled):" << m_fingerMap;
        return;
    }

    //Check each of the loaded prints to ensure it was loaded from the store
    QList<uint32_t> keys = m_fingerMap.keys();
    for (int i = 0; i < keys.size(); ++i) {
        if (!enumeratedFingers.contains(keys[i])) {
            qWarning() << "Loaded finger " << keys[i] << m_fingerMap.value(keys[i]) << "not found in store, removing";
            m_fingerMap.remove(keys[i]);
        }
    }

    // Check whether all enumerated fingerprints are in the map
    QList<uint32_t> mapped = m_fingerMap.keys();
    for (uint32_t k: enumeratedFingers) {
        if (!mapped.contains(k)) {
            qWarning() << "Unknown fingerprint found, adding to the list:" << k;
            m_fingerMap[k] = QStringLiteral("Unknown %1").arg(k);
        }
    }

    // The map lives in the rootfs, the templates in the Android store, which
    // outlives it: with no map at all these are from a previous installation.
    // They stay in the map only until finishRemoval() confirms the removal.
    if (!everEnrolled && !m_fingerMap.isEmpty()) {
        qWarning() << "No finger map at" << m_fingerDatabasePath << "but"
                   << m_fingerMap.size() << "template(s) enrolled; they are left"
                   << "over from a previous installation, removing";
        m_clearOrphans = true;
        return;
    }

    //Save after load incase any were removed or added
    saveFingers();

    qDebug() << "Loaded finger map:" << m_fingerMap;
}

int FPDCommunity::Enroll(const QString &finger, const QDBusMessage &message)
{
    const QString caller = message.service();
    qDebug() << Q_FUNC_INFO << finger << caller;

    // check if busy by other client
    if (!m_dbusCaller.isEmpty() && m_dbusCaller != caller) {
        qWarning() << Q_FUNC_INFO << "called while busy. Caller:" << caller;
        return FPREPLY_ALREADY_BUSY;
    }

    // check if we have this ID already
    if (m_fingerMap.values().contains(finger)) {
        qWarning() << "Finger" << finger << "is in the database already";
        return FPREPLY_KEY_ALREADY_EXISTS;
    }

    if (m_state == FPSTATE_IDLE) {
        setState(FPSTATE_ENROLLING);
        m_addingFinger = finger;
        m_dbusCaller = caller;
        m_androidFP.enroll(100000); //nemo userID
        emit EnrollProgressChanged(0);
        return FPREPLY_STARTED;
    }
    return FPREPLY_ALREADY_BUSY;
}

int FPDCommunity::Identify(const QDBusMessage &message)
{
    const QString caller = message.service();
    qDebug() << Q_FUNC_INFO << caller;

    // check if busy by other client
    if (!m_dbusCaller.isEmpty() && m_dbusCaller != caller) {
        qWarning() << Q_FUNC_INFO << "called while busy. Caller:" << caller;
        return FPREPLY_ALREADY_BUSY;
    }

    if (m_state != FPSTATE_IDLE) {
        return FPREPLY_ALREADY_BUSY;
    }

    if (m_fingerMap.size() == 0) {
        return FPREPLY_NO_KEYS_AVAILABLE;
    }

    setState(FPSTATE_IDENTIFYING);
    m_dbusCaller = caller;
    m_cancelTimer.start();
    m_androidFP.authenticate();
    return FPREPLY_STARTED;
}

void FPDCommunity::Clear(const QDBusMessage &message)
{
    const QString caller = message.service();
    qDebug() << Q_FUNC_INFO << caller;

    // check if busy by other client
    if (!m_dbusCaller.isEmpty() && m_dbusCaller != caller) {
        qWarning() << Q_FUNC_INFO << "called while busy. Caller:" << caller;
        return;
    }

    if (m_state == FPSTATE_IDLE) {
        setState(FPSTATE_REMOVING);
        m_dbusCaller = caller;
        m_androidFP.clear();
    }
}

QString FPDCommunity::GetState()
{
    qDebug() << Q_FUNC_INFO;
    return QtEnumToString(m_state);
}

QStringList FPDCommunity::GetAll()
{
    qDebug() << Q_FUNC_INFO;
    return m_fingerMap.values();
}

int FPDCommunity::Abort(const QDBusMessage &message)
{
    const QString caller = message.service();
    qDebug() << Q_FUNC_INFO << caller;

    // check if the call is initiated by some other client
    if (!m_dbusCaller.isEmpty() && m_dbusCaller != caller) {
        qWarning() << Q_FUNC_INFO << "called while busy. Caller:" << caller;
        return FPREPLY_ALREADY_IDLE;
    }

    if (m_state == FPSTATE_IDLE) {
        return FPREPLY_ALREADY_IDLE;
    }

    abort();
    return FPREPLY_STARTED;
}

int FPDCommunity::Verify(const QDBusMessage &message)
{
    const QString caller = message.service();
    qDebug() << Q_FUNC_INFO << caller;

    // check if busy by other client
    if (!m_dbusCaller.isEmpty() && m_dbusCaller != caller) {
        qWarning() << Q_FUNC_INFO << "called while busy. Caller:" << caller;
        return FPREPLY_ALREADY_IDLE;
    }

    if (m_state != FPSTATE_IDLE) {
        return FPREPLY_ALREADY_BUSY;
    }

    if (m_state == FPSTATE_IDLE) {
        setState(FPSTATE_VERIFYING);
        m_androidFP.enroll(100000); //nemo userID
        m_dbusCaller = caller;
        emit EnrollProgressChanged(0);
        return FPREPLY_STARTED;
    }

    return FPREPLY_ALREADY_BUSY;
}

int FPDCommunity::Remove(const QString &finger, const QDBusMessage &message)
{
    const QString caller = message.service();
    qDebug() << Q_FUNC_INFO << finger << caller;

    // check if busy by other client
    if (!m_dbusCaller.isEmpty() && m_dbusCaller != caller) {
        qWarning() << Q_FUNC_INFO << "called while busy. Caller:" << caller;
        return FPREPLY_ALREADY_BUSY;
    }

    if (m_state != FPSTATE_IDLE) {
        return FPREPLY_ALREADY_BUSY;
    }

    uint32_t key = 0;
    for (auto i = m_fingerMap.constBegin(); i != m_fingerMap.constEnd(); ++i) {
        if (i.value() == finger) {
            key = i.key();
            break;
        }
    }

    if (!key) {
        return FPREPLY_KEY_DOES_NOT_EXIST;
    }

    setState(FPSTATE_REMOVING);
    m_androidFP.remove(key);
    m_dbusCaller = caller;
    return FPREPLY_STARTED;
}

void FPDCommunity::abort()
{
    m_androidFP.cancel();
    m_cancelTimer.stop();
    emit Aborted();
    setState(FPSTATE_IDLE);
}

void FPDCommunity::enumerate()
{
    qDebug() << Q_FUNC_INFO;
    if (m_state == FPSTATE_IDLE) {
        setState(FPSTATE_ENUMERATING);
        m_androidFP.enumerate();
    }
}

void FPDCommunity::slot_enrollProgress(float pc)
{
    qDebug() << Q_FUNC_INFO << pc;
    emit EnrollProgressChanged((int)(pc * 100));

    if (m_state == FPSTATE_VERIFYING) {
        //Cancel the operation if veryfying
        emit Verified();
        abort();
    }
}

void FPDCommunity::slot_succeeded(uint32_t finger)
{
    qDebug() << Q_FUNC_INFO << finger;
    m_fingerMap[finger] = m_addingFinger;
    emit Added(m_addingFinger);
    m_addingFinger = "";
    saveFingers();
    emit ListChanged();
    setState(FPSTATE_IDLE);
}

void FPDCommunity::slot_failed(const QString &message)
{
    qDebug() << Q_FUNC_INFO << message;

    emit ErrorInfo(message); // always report error via signal
    if (m_state == FPSTATE_IDENTIFYING && message == "FINGER_NOT_RECOGNIZED") {
        // Clients (sailfish-devicelock-fpd) learn of a rejected finger from
        // this acquisition state, not from ErrorInfo.
        emit AcquisitionInfo(QtEnumToString(FPACQUIRED_UNRECOGNIZED));
        return; // giving a chance to try another finger
    }

    if (m_state != FPSTATE_IDLE) {
        // A HAL may keep the operation running after an error (the Xiaomi
        // AIDL service does after a timed lockout); stop it, or a later touch
        // completes an operation nobody waits for.
        m_cancelTimer.stop();
        if (message != QLatin1String("ERROR_CANCELED"))
            m_androidFP.cancel();
        emit Failed();
        setState(FPSTATE_IDLE);
    }
}

void FPDCommunity::slot_acquired(int info)
{
    qDebug() << Q_FUNC_INFO << info;
    AcquiredState newState;

    switch(info) {
    case ACQUIRED_GOOD:
        newState = FPACQUIRED_GOOD;
        break;
    case ACQUIRED_PARTIAL:
        newState = FPACQUIRED_PARTIAL;
        break;
    case ACQUIRED_INSUFFICIENT:
        newState = FPACQUIRED_INSUFFICIENT;
        break;
    case ACQUIRED_IMAGER_DIRTY:
        newState = FPACQUIRED_IMAGER_DIRTY;
        break;
    case ACQUIRED_TOO_SLOW:
        newState = FPACQUIRED_TOO_SLOW;
        break;
    case ACQUIRED_TOO_FAST:
        newState = FPACQUIRED_TOO_FAST;
        break;
    default:
        // Vendor messages (finger down/up and the like) say nothing about a
        // match; a rejected finger is reported from slot_failed().
        return;
    }

    // One signal per acquisition: mce takes each as user activity.
    emit AcquisitionInfo(QtEnumToString(newState));
}

void FPDCommunity::slot_removed(uint32_t finger)
{
    qDebug() << Q_FUNC_INFO << finger;

    // onRemoved() only says the HAL considers the operation finished, not that
    // the template left the store, so re-enumerate before dropping the name.
    // Fail-closed: keep the entry unless it is observed to be gone.

    // A terminating onRemoved(fid=0) would start a second round that races the
    // first and fails a removal that succeeded, so verify once per request.
    if (m_verifyingRemoval) {
        qDebug() << Q_FUNC_INFO << "verification already in flight; ignoring"
                 << "additional removed callback for" << finger;
        return;
    }

    m_removedFinger = finger;
    m_verifyingRemoval = true;
    m_androidFP.enumerate();
}

void FPDCommunity::finishRemoval()
{
    m_verifyingRemoval = false;
    const uint32_t finger = m_removedFinger;
    m_removedFinger = 0;

    if (!m_androidFP.enumerationAuthoritative()) {
        qWarning() << Q_FUNC_INFO << "cannot confirm removal of" << finger
                   << "- enumeration is not authoritative; keeping the entry";
        emit ErrorInfo(QStringLiteral("Removal could not be confirmed"));
        emit Failed();
        setState(FPSTATE_IDLE);
        return;
    }

    const QList<uint32_t> present = m_androidFP.fingerprints();
    QList<uint32_t> stillPresent;
    for (uint32_t k : (finger == 0 ? m_fingerMap.keys() : QList<uint32_t>{finger})) {
        if (present.contains(k))
            stillPresent.append(k);
    }

    if (!stillPresent.isEmpty()) {
        qWarning() << Q_FUNC_INFO << "HAL reported removal but" << stillPresent
                   << "are still enrolled; keeping them and failing the request";
        emit ErrorInfo(QStringLiteral("Fingerprint was not removed"));
        emit Failed();
        setState(FPSTATE_IDLE);
        return;
    }

    if (finger != 0) {
        emit Removed(m_fingerMap[finger]);
        m_fingerMap.remove(finger);
    } else {
        for (const QString &f : m_fingerMap.values())
            emit Removed(f);
        m_fingerMap.clear();
    }
    saveFingers();
    emit ListChanged();
    setState(FPSTATE_IDLE);
}

void FPDCommunity::slot_authenticated(uint32_t finger)
{
    qDebug() << Q_FUNC_INFO << finger;
    if (m_state != FPSTATE_IDENTIFYING) {
        qWarning() << "Ignoring a match outside an identify operation";
        return;
    }
    m_cancelTimer.stop();
    if (m_fingerMap.contains(finger)){
        emit Identified(m_fingerMap[finger]);
    } else {
        qWarning() << "Authenticated finger was not found in the map.  Assuming name";
        emit Identified(QStringLiteral("Unknown %1").arg(finger));
    }
    setState(FPSTATE_IDLE);
}

void FPDCommunity::slot_cancelIdentify()
{
    qDebug() << Q_FUNC_INFO;
    m_androidFP.cancel();
    emit Failed();
    setState(FPSTATE_IDLE);
}

void FPDCommunity::slot_enumerated()
{
    qDebug() << Q_FUNC_INFO;

    if (m_verifyingRemoval) {
        finishRemoval();
        return;
    }

    loadFingers();

    if (m_clearOrphans) {
        m_clearOrphans = false;
        setState(FPSTATE_REMOVING);
        m_androidFP.clear();
        return;
    }

    emit ListChanged();
    setState(FPSTATE_IDLE);
}

void FPDCommunity::setState(FPDCommunity::State newState)
{
    qDebug() << Q_FUNC_INFO << newState;

    if (newState == FPSTATE_IDLE)
        m_dbusCaller.clear();

    if (newState != m_state) {
        m_state = newState;
        emit StateChanged(QtEnumToString(m_state));
    }
}

