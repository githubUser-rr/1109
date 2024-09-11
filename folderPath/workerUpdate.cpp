#include "workerUpdate.h"
#include <iostream>

workerUpdate::workerUpdate(const SessıonInfo& sessionInfo,
                           const std::vector<std::vector<u_char>>& packets,
                           const std::vector<pcap_pkthdr>& headers,
                           const std::string& outputPath)
    :sInfo(sessionInfo),p(packets),h(headers),outPath(outputPath){
    //std::cout << "pcap worker" << std::endl;
    //std::cout << p.size() << " " << h.size() << std::endl;
}

void workerUpdate::printSessionExtracter() {
    std::string pcapName = this->outPath + "session_" + std::to_string(sInfo.streamIndex) + ".pcap";

    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == nullptr) {
        std::cerr << "Pcap dosya oluşturma hatası: " << pcap_geterr(handle) << std::endl;
            return;
    }

    pcap_dumper_t* d = pcap_dump_open(handle, pcapName.c_str());
    if (d == nullptr) {
        std::cerr << "Pcap dosya açma hatası: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    for (const auto& i : sInfo.packetIndex) {
        const pcap_pkthdr& header = this->h[i-1];
        const std::vector<u_char>& packet = this->p[i-1];
        pcap_dump(reinterpret_cast<u_char*>(d), &header, packet.data());
    }

    pcap_dump_close(d);
    pcap_close(handle);

    emit printFinished();
}

