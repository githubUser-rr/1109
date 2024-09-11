#include "clsSearchMapWorker.h"

#include "newstructs.h"


#include <QMutexLocker>
#include <QThread>
#include <fstream>
#include <QDir>
#include <QThread>
#include <QByteArray>






QSet<QString> clsSearchMapWorker::pcapSet;

clsSearchMapWorker::clsSearchMapWorker(QString fName) : fileName(fName),defaultPath("C:\\Users\\user\\Desktop\\parseSession\\"),isLastPacket(false),isNewPacket(false){

    this->startChrono = QDateTime::currentDateTime();



}

clsSearchMapWorker::~clsSearchMapWorker(){
    QMutexLocker locker(&this->m);
    this->written.clear();
    this->sessionMap.clear();
    this->h.clear();
    this->p.clear();
    qDebug() << "Mutex serbest bırakıldı ve elemanlar temizlendi.";

}

void clsSearchMapWorker::controlMap(){
    qDebug() << "Control Map " ;
    while (true) {
        QThread::msleep(250);
        QMutexLocker locker(&this->m);
        //qDebug() << this->h.size() ;
        if (!this->isNewPacket) {
            qDebug() << "Yeni paket degil devam";
            continue;
        }
        auto sIt = sessionMap.begin();
        while (sIt != sessionMap.end()) {

            strSessıonInfo& sI = sIt.value();
            QString key = sIt.key();
            //std::cout << "Last process 1 " << std::endl;
            bool isneedsUpdate = (sI.packetCount >= 32 || this->isLastPacket);
            if (isneedsUpdate) {

                auto cIt = written.find(key);
                if (cIt != written.end()) {
                    if (cIt.value() != sI.packetCount) {
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
            //qDebug() << "Last process 8 " ;
            /*QDateTime eTime = QDateTime::currentDateTime();
            qint64 processTime = startChrono.secsTo(eTime);*/
            QDateTime eTime = QDateTime::currentDateTime();
            qint64 msecs = startChrono.msecsTo(eTime);

            qint64 seconds = msecs /  1000 ;
            qint64 mSeconds = msecs % 1000 ;
            double durationSeconds = seconds + mSeconds / 1000.0 ;

            qDebug()  << this->fileName << " pcap dosyasinin session parse islemi "
                      << durationSeconds << " saniyede tamamlandi."
                      << "Toplam session sayisi : " << written.size() ;
            break;
        }

    }

    emit finished();

}

void clsSearchMapWorker::setisLastPacket(bool isLast){
    qDebug()<< "setisLastPacket";
    QMutexLocker locker(&this->m);
    this->isLastPacket = isLast;
    locker.unlock();

}

void clsSearchMapWorker::setPacketsInfo(const u_char *pkt_data, const pcap_pkthdr *hdr){
    QMutexLocker locker(&this->m);
    QVector<quint8> pData (pkt_data,pkt_data+hdr->len);

    this->p.push_back(pData);
    this->h.push_back(*hdr);

    // p == QVector<QVector<quint8>>
    this->isNewPacket = true;
    locker.unlock();

}

void clsSearchMapWorker::updateSessionMap(const QString &key, const strSessıonInfo &newMap){
    QMutexLocker locker(&this->m);

    this->sessionMap[key] = newMap;
    this->isNewPacket = true;
    locker.unlock();

}

void clsSearchMapWorker::printSessionInfo(QString ses, strSessıonInfo sI){
    //bu kullanılmıyor ihtiyaç olursa doldur
}

void clsSearchMapWorker::printSesionExtracter(strSessıonInfo sInfo){
    QString sourceToDestControl = sInfo.sourceIP + "_" + QString::number(sInfo.sourcePort) + "_" + sInfo.destIP + "_" + QString::number(sInfo.destPort) + "_" + sInfo.protocol;
    QString destToSourceControl = sInfo.destIP + "_" + QString::number(sInfo.destPort) + sInfo.sourceIP + "_" + QString::number(sInfo.sourcePort) + "_" + sInfo.protocol;
    QString pcapName = this->defaultPath + sourceToDestControl + ".pcap";


    QVector<QVector<quint8>> prePackets;
    QVector<pcap_pkthdr> preHeaders;

    bool isFound = false;
    int flag = -1;
    qDebug() << " -- ";
    if(pcapSet.contains(sourceToDestControl) || pcapSet.contains(destToSourceControl)){
        isFound = true;
        flag = pcapSet.contains(sourceToDestControl) ? 1 : 0;
        if(flag == 0){//bu durumda güncelle
            pcapName = this->defaultPath + destToSourceControl + ".pcap";
            qDebug() << pcapName;
        }
    }

    //QString pcapName = this->defaultPath + "session_" + sInfo.protocol + "_" + QString::number(sInfo.streamIndex) + ".pcap";

    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == nullptr) {
        qDebug() << "Pcap dosya oluşturma hatası: " << pcap_geterr(handle) ;
    }

    pcap_dumper_t* d = pcap_dump_open(handle, pcapName.toUtf8().constData());
    if (d == nullptr) {
        qDebug() << "Pcap dosya açma hatası: " << pcap_geterr(handle) ;
        pcap_close(handle);
    }


    if(isFound){
        qDebug() << "Session Bulundu okuyup üstüne yazılıyor.";
        //int flag = pcapSet.contains(sourceToDestControl) ? 1 : 0;
        char preerrbuf[PCAP_ERRBUF_SIZE];
        pcap_t* prehandle = nullptr;


        const char* filename = pcapName.toUtf8().constData();
        prehandle = pcap_open_offline(filename,preerrbuf);
        if(prehandle == nullptr){
            qWarning() << "Önceki pcap dosysı açma hatası !!" ;
            //pcap_dump_close(prehandle);
        }else{
            struct pcap_pkthdr* preHeader;
            const u_char* preData;
            int preResult;

            while((preResult = pcap_next_ex(prehandle,&preHeader,&preData)) >= 0){
                if(preResult == 0) {
                    continue;
                }
                if (preResult == -1 || preResult == PCAP_ERROR ) {
                    qDebug() << "PCAP okuma hatası: " << pcap_geterr(prehandle);
                    break;
                }


                //buna gerek yok
                QVector<quint8> packet_data(preData, preData + preHeader->caplen);
                prePackets.push_back(packet_data);
                preHeaders.push_back(*preHeader);
                //pcap_dump(reinterpret_cast<u_char*>(d),preHeader,preData);
                //qDebug() << "Yazıldı";
            }

            //pcap_dump(reinterpret_cast<u_char*>(d),&preHeaders,prePackets.data());
            pcap_close(prehandle);
        }


    }
    //burası olanları silip bunları yazıyor . append tarzı yazmak gerekiyor
    for(int i=0 ;i<=prePackets.size();i++){
        const pcap_pkthdr& newH = preHeaders[i];
        const QVector<quint8>& newP = prePackets[i];
        pcap_dump(reinterpret_cast<u_char*>(d), &newH,newP.data());
    }


    for (const auto& i : sInfo.packetIndex) {
        const pcap_pkthdr& header = this->h[i-1];
        const QVector<quint8>& packet = this->p[i-1];
        pcap_dump(reinterpret_cast<u_char*>(d), &header, packet.data());
    }
    pcapSet.insert(sourceToDestControl);
    pcap_dump_close(d);
    pcap_close(handle);

}
