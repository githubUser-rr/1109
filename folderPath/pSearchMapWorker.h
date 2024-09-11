#ifndef PSEARCHMAPWORKER_H
#define PSEARCHMAPWORKER_H

#include <iostream>
#include <unordered_map>
#include <chrono>
#include <pthread.h>
#include <pcap.h>
#include "packetstruct.h"


class pSearchMapWorker
{
public:
    pSearchMapWorker(const std::string& name);
    ~pSearchMapWorker();

    void setIsLastPacket(bool isLast);
    void controlMap();
    void setPacketsInfo(const u_char* pkt_data,const pcap_pkthdr* hdr);
    void updateSessionMap(const string &key, const SessıonInfo &newMap);

    static void* startThread(void* arg);
    static const int totolCpu;
    static int currCpu;
    bool isCompleted;

private:
    pthread_mutex_t m;
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

    std::string defaultPath; // Changed to std::string
    std::string fileName;

    void printSessionInfo(std::string ses ,SessıonInfo sI);
    void printSesionExtracter(SessıonInfo sInfo);
};

#endif // PSEARCHMAPWORKER_H
