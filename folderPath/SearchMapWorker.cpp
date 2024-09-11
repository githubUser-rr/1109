#include "SearchMapWorker.h"
#include "packetstruct.h"
#include "workerUpdate.h"

#include <iostream>
#include <QMutexLocker>
#include <QThread>
#include <fstream>
#include <ctime>
#include <filesystem>
#include <chrono>
#include <QThread>
#include <QThreadPool>

namespace fs = filesystem;


SearchMapWorker::SearchMapWorker(string fName) : fileName(fName) ,defaultPath("C:\\Users\\user\\Desktop\\parseSession\\"),isLastPacket(false),isNewPacket(false) {

    std::cout << "Search Map Worker Constructor " << std::endl;


    this->startChrono = std::chrono::high_resolution_clock::now();


    fs::path dirPath = fs::path(defaultPath) / this->fileName;
    if(fs::create_directory(dirPath)){
        this->defaultPath = dirPath.string() + "\\";
    }else{
        std::cerr << "Failed to create directory: " << dirPath.string() << std::endl;
    }
}

SearchMapWorker::~SearchMapWorker(){

    QMutexLocker locker(&this->m);
    this->written.clear();
    this->sessionMap.clear();
    this->h.clear();
    this->p.clear();
    std::cout << "Mutex serbest bırakıldı ve elemanlar temizlendi." << std::endl;

}


void SearchMapWorker::controlMap() {
    std::cout << "Control Map " << std::endl;
    while (true) {
        QThread::msleep(250);
        QMutexLocker locker(&this->m);
        //std::cout << this->h.size() << std::endl;
        if (!this->isNewPacket) {
            std::cout << "Yeni paket degil devam" << std::endl;
            continue;
        }
        auto sIt = sessionMap.begin();
        while (sIt != sessionMap.end()) {
            SessıonInfo& sI = sIt->second;
            std::string key = sIt->first;
            //std::cout << "Last process 1 " << std::endl;
            bool isneedsUpdate = (sI.packetCount >= 32 || this->isLastPacket);
            if (isneedsUpdate) {
                //std::cout << "Last process 2" << std::endl;
                auto cIt = written.find(key);
                if (cIt != written.end()) {
                    if (cIt->second != sI.packetCount) {
                        //std::cout << "Last process 3 " << std::endl;
                        printSesionExtracter(sI);
                        written[key] = sI.packetCount;
                        sIt = sessionMap.erase(sIt);
                    } else {
                        //std::cout << "Last process 4 " << std::endl;
                        sIt = sessionMap.erase(sIt);
                    }
                } else {
                    //std::cout << "Last process 5 " << std::endl;
                    printSesionExtracter(sI);
                    written[key] = sI.packetCount;
                    sIt = sessionMap.erase(sIt);
                }
            } else {
                //std::cout << "Last process 6 " << std::endl;
                sIt++;
            }

        }
        this->isNewPacket = false;
        locker.unlock();


        if (sessionMap.empty() && this->isLastPacket) {
            std::cout << "Last process 8 " << std::endl;
            std::chrono::duration<double> processTime = std::chrono::high_resolution_clock::now() - this->startChrono;
            std::cout << this->fileName << " pcap dosyasinin session parse islemi "
                      << processTime.count() << " saniyede tamamlandi."
                      << "Toplam session sayisi : " << written.size() << std::endl;
            break;
        }

    }

    emit finished();
}


void SearchMapWorker::setisLastPacket(bool isLast){
    std::cout << "setisLastPacket" << std::endl;
    QMutexLocker locker(&this->m);
    this->isLastPacket = isLast;
    locker.unlock();

}

void SearchMapWorker::setPacketsInfo(const u_char* pkt_data,const pcap_pkthdr* hdr){

    QMutexLocker locker(&this->m);
    std::vector<u_char> pData (pkt_data,pkt_data+hdr->len);

    this->h.push_back(*hdr);
    this->p.push_back(pData);
    this->isNewPacket = true;
    locker.unlock();

}




void SearchMapWorker::updateSessionMap(const std::string &key, const SessıonInfo &newMap) {
    //std::cout << "updateSessionMap" << std::endl;
    QMutexLocker locker(&this->m);

    this->sessionMap[key] = newMap;
    this->isNewPacket = true;
    locker.unlock();
}





void SearchMapWorker::printSessionInfo(std::string key ,SessıonInfo sI){
    string txtName = this->defaultPath + key + ".txt";
    std::ofstream mapTxt(txtName);
    if(!mapTxt){
        cerr << "Dosya açılamadı " << endl;
        return;
    }

    mapTxt << "Source IP :" << sI.sourceIP << "\n"
           << "Destination IP :" << sI.destIP << "\n"
           << "Source Port :" << sI.sourcePort << "\n"
           << "Destination Port :" << sI.destPort << "\n"
           << "Stream Index :" << sI.streamIndex << "\n"
           << "Packets Count :" << sI.packetCount << "\n"
           << "Total Len :" << sI.packetsLen << "\n"
           << "Source To Destination :" << sI.sourceTodest << "\n"
           << "Source To Destination Length :" << sI.sourceTodestLen << "\n"
           <<"Destination To Source :" << sI.destToSource << "\n"
           <<"Destination To Source Length :" << sI.destToSourceLen << "\n"
           << "Start Time :" << sI.startTime << "\n"
           << "End Time :" << sI.endTime << "\n" << endl;
    mapTxt << "İndeks: " ;
        for(int indeks:sI.packetIndex){
        mapTxt << indeks << "-";
    }
    mapTxt.close();
}



void SearchMapWorker::printSesionExtracter(SessıonInfo sInfo) {

    std::string pcapName = this->defaultPath + "session_" + sInfo.protocol + "_" + std::to_string(sInfo.streamIndex) + ".pcap";


    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == nullptr) {
        std::cerr << "Pcap dosya oluşturma hatası: " << pcap_geterr(handle) << std::endl;
    }

    pcap_dumper_t* d = pcap_dump_open(handle, pcapName.c_str());
    if (d == nullptr) {
        std::cerr << "Pcap dosya açma hatası: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
    }

    for (const auto& i : sInfo.packetIndex) {
        const pcap_pkthdr& header = this->h[i-1];
        const std::vector<u_char>& packet = this->p[i-1];
        pcap_dump(reinterpret_cast<u_char*>(d), &header, packet.data());
    }


    pcap_dump_close(d);
    pcap_close(handle);
}




