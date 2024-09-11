#ifndef PACKETSTRUCT_H
#define PACKETSTRUCT_H


#include <string>
#include <vector>

using namespace std;

struct PacketInfo {
    string sourceIP;
    string destIP;
    string sourceMac;
    string destMac;
    uint16_t sourcePort;
    uint16_t destPort;
    string protocol ;
    string timestamp ;
    int packetLen;
    string message ;
    string smtpSender;
    string smtpRecipient;
    //uint8_t protocol; // 6 for TCP, 17 for UDP
};

struct SessıonInfo{
    string sourceIP;
    string destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    int streamIndex;
    int packetCount;
    int packetsLen;
    int sourceTodest;
    int sourceTodestLen;
    int destToSource;
    int destToSourceLen;
    string startTime;
    string endTime;
    std::vector<int> packetIndex;
    std::vector<std::string> messages;
    string protocol;
    string smtpSender;
    string smtpRecipient;
};

#endif // PACKETSTRUCT_H
