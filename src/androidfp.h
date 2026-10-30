#ifndef ANDROIDFP_H
#define ANDROIDFP_H

#include <QObject>
#include <QList>
#include <QString>
#include <QTimer>

#include "biometry.h"

class AndroidFP : public QObject
{
    Q_OBJECT
public:
    explicit AndroidFP(QObject *parent = nullptr);
    void setGroup(uint32_t gid, const QString &storePath);
    void enroll(uid_t user_id);
    void remove(uid_t finger);
    void cancel();
    void authenticate();
    void enumerate();
    void clear();
    QList<uint32_t> fingerprints() const;
    // False when the round was ended by the timeout or a failed call: an empty
    // fingerprints() then means "not known", not "the store is empty".
    bool enumerationAuthoritative() const;

    static QString getDefaultGroupPath(uint32_t uid);

signals:
    void failed(const QString& message);
    void succeeded(uint32_t fingerId); //After enrollment
    void removed(uint32_t finger); //0 for clear
    void authenticated(uint32_t fingerId);
    void enrollProgress(float progress); //Progress is 0..1
    void acquired(int info);
    void enumerated(); // fingerprint list ready

private:
    // HAL callbacks arrive on a backend thread (a binder thread, or the AIDL
    // backend's dispatcher). The static *_cb functions only queue these onto
    // this object's thread, where the timer, the finger list and calls back
    // into the HAL are safe.
    Q_INVOKABLE void enumerateCallback(quint32 finger, quint32 remaining);
    QTimer m_enumerateTimeout;
    Q_INVOKABLE void enrollCallback(quint32 finger, quint32 remaining);
    Q_INVOKABLE void removeCallback(quint32 finger, quint32 remaining);
    Q_INVOKABLE void acquiredCallback(int info);
    Q_INVOKABLE void authenticatedCallback(quint32 finger);
    Q_INVOKABLE void errorCallback(int error, int vendorCode);

    static void enrollresult_cb(uint64_t, uint32_t, uint32_t, uint32_t, void *);
    static void acquired_cb(uint64_t, UHardwareBiometryFingerprintAcquiredInfo, int32_t, void *);
    static void authenticated_cb(uint64_t, uint32_t, uint32_t, void *);
    static void removed_cb(uint64_t, uint32_t, uint32_t, uint32_t, void *);
    static void enumerate_cb(uint64_t, uint32_t fingerId, uint32_t, uint32_t remaining, void *context);
    static void error_cb(uint64_t, UHardwareBiometryFingerprintError error, int32_t vendorCode, void *context);

private:
    UHardwareBiometry m_biometry = nullptr;
    UHardwareBiometryParams fp_params;

    float m_enrollRemaining = 0.0;
    uint32_t m_removingFinger = 0;
    QList<uint32_t> m_fingers;
    bool m_enumerationAuthoritative = false;
    // Set once the HAL has replied to any enumerate, which is what makes a
    // later silent round meaningful.
    bool m_halAnswersEnumerate = false;
};

#endif // ANDROIDFP_H
