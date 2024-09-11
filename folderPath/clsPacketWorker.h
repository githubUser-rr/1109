#ifndef CLSPACKETWORKER_H
#define CLSPACKETWORKER_H

#include <QObject>
#include <QString>
#include "clsPacketOperation.h"


class clsPacketWorker : public QObject
{
    Q_OBJECT
public:
    clsPacketWorker(const QString& str);
    ~clsPacketWorker();

public slots:
    void createPacket();

signals:
    void createFinished();

private:
    clsPacketOperation* packet;
    QString path;
};

#endif // CLSPACKETWORKER_H
