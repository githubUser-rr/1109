#ifndef PACKETWORKER_H
#define PACKETWORKER_H

#include <QObject>
#include <iostream>

class PacketWorker : public QObject
{
    Q_OBJECT
public:
    PacketWorker(const std::string &str);

public slots:
    void createPacket();

signals:
    void createFinished();

private:
    std::string path;

};

#endif // PACKETWORKER_H
