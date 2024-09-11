#ifndef SEARCHMAPWORKER_H
#define SEARCHMAPWORKER_H

#include <QObject>
#include <iostream>
#include <QMutex>
#include <unordered_map>
#include <chrono>
#include <pcap.h>

#include "packetstruct.h"


class SearchMapWorker : public QObject
{
    Q_OBJECT
public:
    SearchMapWorker(string fName);
    ~SearchMapWorker();
    void controlMap();


    void setisLastPacket(bool isLast);
    void setPacketsInfo(const u_char* pkt_data,const pcap_pkthdr* hdr);
    void updateSessionMap(const string &key, const SessıonInfo &newMap);




signals:
    void finished();
private:

    std::unordered_map<std::string,int> written;
    std::unordered_map<std::string,SessıonInfo> sessionMap;

    std::vector<std::vector<u_char>> p;
    std::vector<pcap_pkthdr> h;

    std::time_t lastTakeData;
    std::chrono::time_point<std::chrono::high_resolution_clock> startChrono;

    bool isLastPacket;
    bool isNewPacket;
    double start;
    double end;

    string defaultPath;


    QMutex m;
    string fileName;

    void printSessionInfo(std::string ses ,SessıonInfo sI);
    void printSesionExtracter(SessıonInfo sInfo);



};

#endif // SEARCHMAPWORKER_H
