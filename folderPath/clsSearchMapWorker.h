#ifndef CLSSEARCHMAPWORKER_H
#define CLSSEARCHMAPWORKER_H

#include <QObject>
#include <QMutex>
#include <QString>
#include <QHash>
#include <QDateTime>
#include <pcap.h>
#include <QSet>

#include "newstructs.h"

class clsSearchMapWorker : public QObject
{
    Q_OBJECT
public:
    clsSearchMapWorker(QString fName);
    ~clsSearchMapWorker();
    void controlMap();


    void setisLastPacket(bool isLast);
    void setPacketsInfo(const u_char* pkt_data,const pcap_pkthdr* hdr);
    void updateSessionMap(const QString &key, const strSessıonInfo &newMap);




signals:
    void finished();
private:

    static QSet<QString> pcapSet;
    QHash<QString,int> written;
    QHash<QString,strSessıonInfo> sessionMap;

    QVector<QVector<quint8>> p;
    //std::vector<std::vector<u_char>> p;
    QVector<pcap_pkthdr> h ;
    //std::vector<pcap_pkthdr> h;


    QDateTime startChrono;

    bool isLastPacket;
    bool isNewPacket;
    double start;
    double end;

    QString defaultPath;


    QMutex m;
    QString fileName;

    void printSessionInfo(QString ses ,strSessıonInfo sI);
    void printSesionExtracter(strSessıonInfo sInfo);
};

#endif // CLSSEARCHMAPWORKER_H
