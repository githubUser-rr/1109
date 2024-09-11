#ifndef WORKERUPDATE_H
#define WORKERUPDATE_H

#include <QObject>
#include <iostream>
#include <vector>
#include <pcap.h>

#include "SearchMapWorker.h"
#include "packetstruct.h"

class workerUpdate : public QObject
{
    Q_OBJECT
public:
    workerUpdate(const SessıonInfo& sessionInfo, const std::vector<std::vector<u_char>>& packets, const std::vector<pcap_pkthdr>& headers, const std::string& outputPath);


signals:
    void printFinished();

public slots:
    void printSessionExtracter();

private:
    SessıonInfo sInfo;
    std::vector<std::vector<u_char>> p;
    std::vector<pcap_pkthdr> h;
    std::string outPath;
};

#endif // WORKERUPDATE_H
