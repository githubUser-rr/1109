#include "pSearchMapWorker.h"
#include "packetstruct.h"

#include <iostream>
#include <fstream>
#include <ctime>
#include <filesystem>
#include <chrono>
#include <windows.h>
#include <unordered_map>
#include <string>

namespace fs = filesystem;

const int pSearchMapWorker::totolCpu= [](){
    SYSTEM_INFO sys;
    GetSystemInfo(&sys);
    return sys.dwNumberOfProcessors;
}();

int pSearchMapWorker::currCpu = 0;

pSearchMapWorker::pSearchMapWorker(const std::string& name) : fileName(name), defaultPath("C:\\Users\\user\\Desktop\\parseSession\\") , isCompleted(false)
    ,isLastPacket(false), isNewPacket(false){

    std::cout << "pSearchMapWorker Constructor " << std::endl;
    //std::cout << "isNewPacket: " << (int)this->isNewPacket << std::endl;
    currCpu++;

    if (pthread_mutex_init(&this->m,nullptr) != 0) {
        std::cout << "Mutex initialization failed" << std::endl;

    }else{
        std::cout << "Mutex tamam" << std::endl;
    }

    this->startChrono = std::chrono::high_resolution_clock::now();

    fs::path dirPath = fs::path(defaultPath) / this->fileName;
    if(fs::create_directory(dirPath)){
        this->defaultPath = dirPath.string() + "\\";
    }else{
        std::cerr << "Failed to create directory: " << dirPath.string() << std::endl;
    }

}

pSearchMapWorker::~pSearchMapWorker(){
    while (true) {
        if (pthread_mutex_trylock(&this->m) == 0) {
            // Lock başarılı
            this->written.clear();
            this->sessionMap.clear();
            this->h.clear();
            this->p.clear();


            pthread_mutex_unlock(&this->m);
            std::cout << "Mutex serbest birakildi ve elemanlar temizlendi." << std::endl;
            pthread_mutex_destroy(&this->m);
            this->isCompleted= true;
            break;
        } else {
            Sleep(150);
        }
    }
}

void pSearchMapWorker::setIsLastPacket(bool isLast){
    pthread_mutex_lock(&m);
    this->isLastPacket = isLast;
    pthread_mutex_unlock(&m);
}

void pSearchMapWorker::controlMap(){

    std::cout << "Control Map " << std::endl;
    while (true) {
        //std::cout << "isNewPacket: " << (int)this->isNewPacket << std::endl;

        Sleep(1500);
        pthread_mutex_lock(&m);
        //std::cout << "this->h.size(): " <<this->h.size() << std::endl;

        if (!this->isNewPacket) {
            std::cout << "Yeni paket degil devam"<< this->isNewPacket <<  std::endl;
            pthread_mutex_unlock(&m);
            continue;
        }

        auto sIt = sessionMap.begin();
        while (sIt != sessionMap.end()) {

            SessıonInfo& sI = sIt->second;
            std::string key = sIt->first;
            //std::cout << "Debug 5" << std::endl;

            bool isneedsUpdate = (sI.packetCount >= 32 || this->isLastPacket);

            if (isneedsUpdate) {
                auto cIt = written.find(key);
                if (cIt != written.end()) {
                    if (cIt->second != sI.packetCount) {
                        printSesionExtracter(sI);
                        written[key] = sI.packetCount;
                        sIt = sessionMap.erase(sIt);
                    } else {
                        sIt = sessionMap.erase(sIt);
                    }
                } else {
                    printSesionExtracter(sI);
                    written[key] = sI.packetCount;
                    sIt = sessionMap.erase(sIt);
                }
            } else {
                sIt++;
            }
        }
        this->isNewPacket = false;
        pthread_mutex_unlock(&m);


        if (sessionMap.empty() && this->isLastPacket) {
            //std::cout << "Last process 8 " << std::endl;
            std::chrono::duration<double> processTime = std::chrono::high_resolution_clock::now() - this->startChrono;
            std::cout << this->fileName << " pcap dosyasinin session parse islemi "
                      << processTime.count() << " saniyede tamamlandi."
                      << "Toplam session sayisi : " << written.size() << std::endl;
            //this->~pSearchMapWorker();
            break;
        }

    }

}

void pSearchMapWorker::setPacketsInfo(const u_char *pkt_data, const pcap_pkthdr *hdr){
    //std::cout << "setPacketsInfo ..." << std::endl;
    pthread_mutex_lock(&m);
    std::vector<u_char> pData (pkt_data,pkt_data+hdr->len);
    this->h.push_back(*hdr);
    this->p.push_back(pData);
    this->isNewPacket = true;
    //std::cout << "Yeni paket setPacketsInfo "<< this->isNewPacket << " " << this->isLastPacket <<  std::endl;
    pthread_mutex_unlock(&m);
}

void pSearchMapWorker::updateSessionMap(const string &key, const SessıonInfo &newMap){
    //std::cout << "updateSessionMap ..." << std::endl;
    pthread_mutex_lock(&m);
    this->sessionMap[key] = newMap;
    this->isNewPacket = true;
    //std::cout << "Yeni paket updateSessionMap "<< this->isNewPacket << " " << this->isLastPacket <<  std::endl;
    pthread_mutex_unlock(&m);

}

void* pSearchMapWorker::startThread(void *arg){
    /*pSearchMapWorker* w = static_cast<pSearchMapWorker*>(arg);
    w->controlMap();
    return nullptr;*/
    int nowCpu = currCpu % totolCpu;
    HANDLE tHandle = GetCurrentThread();
    DWORD_PTR affinity = 1 << nowCpu;

    if (SetThreadAffinityMask(tHandle, affinity) == 0) {
        std::cerr << "CPU affinity ayarlanamadı: " << GetLastError() << std::endl;
    } else {
        std::cout << "Thread " << nowCpu << ".CPU baglandi" << std::endl;
    }


    pSearchMapWorker* w = *static_cast<pSearchMapWorker**>(arg);
    w->controlMap();
    delete w;
    return nullptr;

}

void pSearchMapWorker::printSesionExtracter(SessıonInfo sInfo){

    //std::cout << "printSesionExtracter" << std::endl;
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















