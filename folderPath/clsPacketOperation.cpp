#include "clsPacketOperation.h"
#include "MoveWorker.h"


#include <QString>
#include <QThread>
#include <pcap.h>
#include <filesystem>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QDebug>
#include <QByteArray>
#include <QTextStream>



#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>



#define ETHERNET_HEADER_LENGTH 14




struct ipheader {
    quint8 iph_ihl : 4;   // IP başlığı uzunluğu
    quint8 iph_ver : 4;   // IP versiyonu
    quint8 iph_tos;       // Hizmet tipi
    quint16 iph_len;      // Toplam uzunluk
    quint16 iph_ident;    // Tanımlayıcı
    quint16 iph_flag : 3; // Bayraklar
    quint16 iph_offset : 13; // Parça offseti
    quint8 iph_ttl;       // Yaşam süresi
    quint8 iph_protocol;  // Protokol
    quint16 iph_chksum;   // Başlık checksum
    in_addr iph_sourceip; // Kaynak IP adresi
    in_addr iph_destip;   // Hedef IP adresi
};

struct ethHeader {
    quint8  destMac[6];
    quint8  sourceMac[6];
    quint16 eType; // Ethernet türü
};


struct tcphdr {
    quint16 th_sport;   // Kaynak port numarası
    quint16 th_dport;   // Hedef port numarası
    quint32 th_seq;     // Dizi numarası
    quint32 th_ack;     // Onay numarası
    quint8 th_offx2;    // Veri ofseti, rezerve edilmiş alanlar ve flags
    quint8 th_flags;    // Kontrol flagları
    quint16 th_win;     // Pencere boyutu
    quint16 th_sum;     // Checksum
    quint16 th_urp;     // Acil işlem göstergesi
};


struct udphdr {
    quint16 uh_sport;   // Kaynak port numarası
    quint16 uh_dport;   // Hedef port numarası
    quint16 uh_ulen;    // Toplam uzunluk
    quint16 uh_sum;     // Checksum
};




/**/

clsPacketOperation::clsPacketOperation(const QString &p) : filePath(p),handle(nullptr),defaultPath("C:\\Users\\user\\Desktop\\parseSession\\")
    ,defaultCsvPath ("C:\\Users\\user\\Desktop\\csvOut\\"),defaultTxtPath ("C:\\Users\\user\\Desktop\\txtOut\\")
    ,pCount(0),streamIndex(0),streamIndexUdp(0),objStartTime(QDateTime::currentDateTime()){
    qDebug() << "Cons !!" ;



    while(true){
        QFileInfo fInfo(filePath);
        QDateTime modifyDate = fInfo.lastModified();
        QDateTime currTime = QDateTime::currentDateTime();
        qint64 subSeconds = modifyDate.secsTo(currTime);


        if(subSeconds >= 4){
            qDebug() << "Simdiki zaman ile modify date farkı : " << subSeconds ;
            this->fileName = fInfo.fileName();
            this->directory = fInfo.path();
            break;
        }
        qDebug() << "Dosya yazma islemi devam ediyor , modify date  : " << subSeconds ;
        QThread::sleep(2);
    }

    try {
        QByteArray bArray = filePath.toUtf8();
        const char* pFileName = bArray.constData();
        this->handle = pcap_open_offline(pFileName,this->errbuf);
        if (this->handle == NULL) {
            qWarning() <<  "PCAP dosyasi acilamadi : " << this->errbuf ;

            controlOpen = false;
        }
        else {
            qDebug() << "Basarili" ;
            controlOpen = true;


            //SearchMapWorker , qt göre düzenle
            QString str = this->fileName.left(fileName.lastIndexOf('.'));
            this->clsSMap = new clsSearchMapWorker(str);
            QThread* cThread = new QThread;
            this->clsSMap->moveToThread(cThread);

            QObject::connect(cThread,&QThread::started,clsSMap,&clsSearchMapWorker::controlMap);
            QObject::connect(clsSMap,&clsSearchMapWorker::finished,cThread,&QThread::quit);
            QObject::connect(clsSMap,&clsSearchMapWorker::finished,clsSMap,&clsSearchMapWorker::deleteLater);
            QObject::connect(cThread,&QThread::finished,cThread,&QThread::deleteLater);
            cThread->start();





        }
    } catch (const std::exception& ex){
        QString errorMessage = QString::fromUtf8(ex.what());
        qWarning() << "Bilinmeyen Hata :" << errorMessage ;
    }


}

clsPacketOperation::~clsPacketOperation(){
    cout << "Destructor" << endl;

    for (auto it = sipHash.constBegin(); it != sipHash.constEnd(); ++it) {
        const sipSessionInfo& s = it.value();


        // Anahtar ve karşılık gelen değerleri yazdır
        qDebug() << "Key (cId):" << it.key();
        qDebug() << "Indexes:" << s.indeks ;
        qDebug() << "Messages:" << s.messages;
        qDebug() << "Source IP:" << s.sourceIp;
        qDebug() << "Destination IP:" << s.destIp;
        qDebug() << "Source Media Data:" << s.sourceMediaDatas;
        qDebug() << "Source Ports:" << s.sourcePorts;
        qDebug() << "Destination Media Data:" << s.destMediaDatas;
        qDebug() << "Destination Ports:" << s.destPorts;
        qDebug() << "Timestamp:" << s.tms.toString();


        qDebug() << "-----";
    }
    qDebug() << "Total SİP cagrisi : " << this->sipHash.size();
    this->sessionMap.clear();
    if(handle != nullptr){
        //pcap_close(handle);
        handle = nullptr;
    }
    //packets.clear();
    //packetCount=0;

    //thread başlangıcını kodla
    MoveWorker* mw =new MoveWorker(filePath);
    QThread* wThread = new QThread;
    mw->moveToThread(wThread);

    QObject::connect(wThread,&QThread::started,mw,&MoveWorker::moveFile);
    QObject::connect(mw,&MoveWorker::moveFinished,wThread,&QThread::quit);
    QObject::connect(mw,&MoveWorker::moveFinished,mw,&MoveWorker::deleteLater);
    /*QObject::connect(mw,&MoveWorker::failedMove,[this](){
        qDebug() <<"Dosya tasinamadı , hata mevcut tekrar deneniyor ..";
        filesystem::path sPath(this->filePath);
        filesystem::path dPath = filesystem::path("C:\\Users\\remzi\\Desktop\\usedFile") / this->fileName;
        cout << dPath << endl;
        try{
            filesystem::rename(sPath,dPath);
            cout << "Dosya tasindi" << endl;
        }catch(const filesystem::filesystem_error& fError){
            cout << "Dosya tasinamadi , hata :" << fError.what() << endl;
        }
    });*/
    QObject::connect(mw,&MoveWorker::failedMove,mw,&MoveWorker::deleteLater);
    QObject::connect(wThread,&QThread::finished,wThread,&QThread::deleteLater);
    wThread->start();
    wThread->wait();

    QDateTime currTime = QDateTime::currentDateTime();
    qint64 sub = currTime.secsTo(objStartTime);

    qDebug() << this->fileName << " dosyasinin paket islem süresi : " << sub << " saniye ."  ;
    this->packetsInfo.clear();
    this->pCount = 0;

    this->clsSMap = nullptr;

}

void clsPacketOperation::packetCapture(int loopcount){


    if(controlOpen != true){
        qWarning() << "Geçerli dosya seçiniz !!";
    }else{
        qDebug() << "Paket yakalama basliyor !!" ;
        pcap_handler qHand = reinterpret_cast<pcap_handler>(&clsPacketOperation::processPacket);
        u_char* userData = reinterpret_cast<u_char*>(this);
        pcap_loop(this->handle,loopcount,qHand,userData);
        pcap_close(this->handle);
        this->clsSMap->setisLastPacket(true);

        qDebug() << "Toplam yakalanan paket sayisi : " << pCount;







    }





}




void clsPacketOperation::printCsvFile(){



    QString name = this->defaultCsvPath + this->fileName.left(fileName.lastIndexOf('.')) + ".csv";
    QFile baseCsv(name);
    if(!baseCsv.open(QIODevice::WriteOnly | QIODevice::Text)){
        qWarning() <<  "CSV acilmadi !!";
    }

    QTextStream bStream(&baseCsv);
    bStream << "Source IP;Destination IP;"
               "Source Port;Destination Port;"
               "Stream Index;Packets Count;"
               "Total Len;Source To Destination;"
               "Source To Destination Length;"
               "Destination To Source;Destination To Source Length;Protokol;"
               "Start Time;End Time;Sender; Recipient;\n";



    QString sipMessageName = this->defaultCsvPath +  this->fileName.left(fileName.lastIndexOf('.')) + "_Messages.csv";
    QFile messagesCsv(sipMessageName);
    if(!messagesCsv.open(QIODevice::WriteOnly | QIODevice::Text)){
        qWarning() <<  "CSV acilmadi !!";
    }

    QTextStream mStream(&messagesCsv);
    mStream << "Packet Number ; Protocol ;Protocol Message ; \n";

    int cntrl = 0;


    for(auto it = sessionMap.begin();it!=sessionMap.end();++it){

        strSessıonInfo& value = it.value();
        qDebug() << value.smtpSender.size() << " - " << value.smtpRecipient.size() << " - " << value.mailB.size() ;
        value.smtpSender.replace(";"," - ");
        value.smtpRecipient.replace(";"," - ");
        //QString strSender = value.smtpSender.join(" ? ");
        //QString strRece = value.smtpRecipient.join(" ? ");
        //strSender = strSender.replace(';',',');
        //strRece = strRece.replace(';',',');
        //replace(strSender.begin(),strSender.end(),';',',');
        //replace(strRece.begin(),strRece.end(),';',',');
        bStream << value.sourceIP << ';' << value.destIP
                << ';' << value.sourcePort << ';' << value.destPort << ';' << value.streamIndex
                << ';' << value.packetCount << ';' << value.packetsLen << ';' << value.sourceTodest
                << ';' << value.sourceTodestLen << ';' << value.destToSource << ';' << value.destToSourceLen
                << ';' << value.protocol
                << ';' << value.startTime << ';' << value.endTime << ';' << value.smtpSender << ';' << value.smtpRecipient << "\n";

        for(int s=0;s<value.packetIndex.size();++s){
            if(value.messages[s] != " -- "){
                mStream << value.packetIndex[s] << ';' << value.protocol << ';' << value.messages[s] + "\n";


            }
        }



        QString txt  = this->defaultTxtPath + value.smtpSender + " - " + value.smtpRecipient + ".eml";

        for(int i=0 ; i< value.mailB.size() ; i++){
            QFile txtPath(txt);

            if(!txtPath.open(QIODevice::Append | QIODevice::Text)){
                qDebug() << "Txt acilamadi !! " << txtPath.errorString() ;
                txtPath.close();
            }else{

                QTextStream out(&txtPath);
                out << value.mailB[i];
                txtPath.close();
                qDebug() << txt << " yazildi";
            }
            txtPath.close();
        }


        cntrl++;
    }
    baseCsv.close();
    messagesCsv.close();

    //cout << name << " printCsvFile yazildi" << endl;




}


void clsPacketOperation::processPacket(void *user, const pcap_pkthdr *header, const u_char *pkt_data){


    clsPacketOperation* noStatic = reinterpret_cast<clsPacketOperation*>(user);

    QString tms = QString::number(header->ts.tv_sec) + "." + QString::number(header->ts.tv_usec);
    (noStatic->pCount)++;


    struct ipheader* ip_header = (struct ipheader*)(pkt_data + ETHERNET_HEADER_LENGTH);
    struct ethHeader* eth_header = (struct ethHeader*)pkt_data;

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->iph_sourceip), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->iph_destip), dest_ip, INET_ADDRSTRLEN);

    QString sMac ;
    for (int k = 0; k < 6; k++) {
        if (k > 0) {
            sMac += ":";
        }
        sMac += QString::number(eth_header->sourceMac[k], 16).rightJustified(2, '0').toUpper();

    }

    QString dMac;
    for (int l = 0; l < 6; l++) {
        if(l > 0){
            dMac += ":";
        }

        dMac += QString::number(eth_header->destMac[l], 16).rightJustified(2, '0').toUpper();
    }


    strPacketInfo pInfo;
    pInfo.sourceIP = source_ip;
    pInfo.destIP = dest_ip;
    pInfo.sourceMac = sMac;
    pInfo.destMac = dMac;
    pInfo.timestamp = tms;
    pInfo.packetLen = header->len ;


    noStatic->clsSMap->setPacketsInfo(pkt_data,header);



    if (ip_header->iph_protocol == IPPROTO_TCP || ip_header->iph_protocol == IPPROTO_UDP) {
        bool isTCP = (ip_header->iph_protocol == IPPROTO_TCP);
        const u_char* transport_header = pkt_data + ETHERNET_HEADER_LENGTH + sizeof(struct ipheader);
        int header_size = (isTCP ? (((struct tcphdr*)transport_header)->th_offx2 >> 4) * 4 : 8); //ilk kısım tcp size hesaplar , ikinci kısım UDP size'nı belirtir UDP size sabit
        const u_char* payload = transport_header + header_size;
        int payload_length = header->caplen - (ETHERNET_HEADER_LENGTH + sizeof(struct ipheader) + header_size);

        uint16_t src_port = ntohs(isTCP ? ((struct tcphdr*)transport_header)->th_sport : ((struct udphdr*)transport_header)->uh_sport);
        uint16_t dest_port = ntohs(isTCP ? ((struct tcphdr*)transport_header)->th_dport : ((struct udphdr*)transport_header)->uh_dport);



        // SIP
        if (src_port == 5060 || dest_port == 5060) {

            QStringList rList = noStatic->parseSipMessage(reinterpret_cast<const char*>(payload), payload_length);
            sipSessionInfo info = noStatic->parseSipSession(reinterpret_cast<const char*>(payload), payload_length,noStatic->pCount);
            //qDebug() << "Sip size : " << noStatic->sipSessionMap.size() ;


            //qDebug() << "SIP Message:" << info.message;
            //qDebug() << "Call ID:" << info.cId;
            //qDebug() << "SOURCE IP Address:" << info.sourceIp;
            //qDebug() << "DEST IP Address:" << info.destIp;
            //qDebug() << "Media:" << info.mediaData;
            //qDebug() << "Port Number:" << info.port;
            //qDebug() << "Zaman:" << info.tms.toString();


            //duruma göre bunrda from-to adresleri parseSipMessage içinde ayıklanabilir.
            pInfo.message = rList[0] ;
            pInfo.smtpSender = rList[1];
            pInfo.smtpRecipient = rList[2];
            pInfo.mailBody = "";

            // SMTP
        } else if (src_port == 25 || dest_port == 25) {
            QStringList smtpInfo = noStatic->parseSmtp(reinterpret_cast<const char*>(payload), payload_length);
            //sender << recipient << mailBody
            pInfo.smtpSender = smtpInfo[0];
            pInfo.smtpRecipient = smtpInfo[1];
            pInfo.mailBody = smtpInfo[2];
            pInfo.message = "";

            /*auto mails = noStatic->parseSmtp(reinterpret_cast<const char*>(payload), payload_length);
            pInfo.smtpSender = mails.first;
            pInfo.smtpRecipient = mails.second;
            pInfo.message = " -- ";*/

            // POP3
        } else if (src_port == 110 || dest_port == 110) {
            pInfo.message = noStatic->parsePopPayload(reinterpret_cast<const char*>(payload), payload_length);
            pInfo.mailBody = "";
            pInfo.smtpSender = "";
            pInfo.smtpRecipient = "";

        } else {
            pInfo.message = "";
            pInfo.smtpSender = "";
            pInfo.smtpRecipient = "";
            pInfo.mailBody = "";
        }




        pInfo.sourcePort = src_port;
        pInfo.destPort = dest_port;
        pInfo.protocol = isTCP ? "TCP" : "UDP";


        noStatic->createSessionMap(pInfo);
    }


}

void clsPacketOperation::createSessionMap(const strPacketInfo &p){


    QString key1 = p.sourceIP + "-" + QString::number(p.sourcePort) + "-" + p.destIP + "-" + QString::number(p.destPort) + "-" + p.protocol;
    QString key2 = p.destIP + "-" + QString::number(p.destPort) + "-" + p.sourceIP + "-" + QString::number(p.sourcePort) + "-" + p.protocol;

    size_t directionKey = -1 ;
    strSessıonInfo* sI = nullptr;


    auto s1 = this->sessionMap.find(key1);
    if(s1 != this->sessionMap.end()){
        sI = &s1.value();
        directionKey = 0;
    }else{
        auto s2 = this->sessionMap.find(key2);
        if(s2 != this->sessionMap.end()){
            sI = &s2.value();
            directionKey = 1;
        }
    }

    if(sI == nullptr){
        int s = (p.protocol == "TCP") ? streamIndex++ : (p.protocol == "UDP") ? streamIndexUdp++ : pCount;

        strSessıonInfo newSession = {p.sourceIP,
                                  p.destIP,
                                  p.sourcePort,
                                  p.destPort,
                                  s,
                                  1,
                                  p.packetLen,
                                  1,
                                  p.packetLen,
                                  0,
                                  0,
                                  p.timestamp,
                                  p.timestamp,
                                  {pCount},
                                  {p.message},
                                  p.protocol,
                                  p.smtpSender,
                                  p.smtpRecipient};

        sessionMap[key1] = newSession;
    }else{
        sI->packetCount++;
        sI->packetsLen += p.packetLen;
        sI->endTime = p.timestamp;
        sI->packetIndex.push_back(this->pCount);
        sI->messages.push_back(p.message);



        if (!p.smtpSender.isEmpty()) {
            if(!sI->smtpSender.contains(p.smtpSender)){
                sI->smtpSender = sI->smtpSender + " - " + p.smtpSender;
            }

            /*if(sI->smtpSender.isEmpty() || (sI->smtpSender != p.smtpSender)){
                sI->smtpSender = p.smtpSender;
            }else{
                sI->smtpSender = sI->smtpSender + " - " + p.smtpSender;
            }*/

            //sI->smtpSender.push_back(p.smtpSender);
            //sI->smtpSender = p.smtpSender;
        }
        if (!p.smtpRecipient.isEmpty()) {
            if(!sI->smtpRecipient.contains(p.smtpRecipient)){
                sI->smtpRecipient = sI->smtpRecipient + " - " + p.smtpRecipient;
            }

            /*if(sI->smtpRecipient.isEmpty() || (sI->smtpRecipient != p.smtpRecipient) ){
                sI->smtpRecipient = p.smtpRecipient;
            }else{
                sI->smtpRecipient = sI->smtpRecipient + " - " + p.smtpRecipient;
            }*/
            //sI->smtpRecipient.push_back(p.smtpRecipient);
            //sI->smtpRecipient = p.smtpRecipient;
        }
        if(!p.mailBody.isEmpty()){
            sI->mailB.push_back(p.mailBody);
        }

        // yön kontrolü
        if(directionKey == 0){
            sI->sourceTodest++;
            sI->sourceTodestLen += p.packetLen;
            this->clsSMap->updateSessionMap(key1,*sI);

        }else{
            sI->destToSource++;
            sI->destToSourceLen += p.packetLen;
            this->clsSMap->updateSessionMap(key2,*sI);

        }

    }


}





QString clsPacketOperation::parsePopPayload(const char *p, int pSize){

    if(pSize <= 0 && pSize > 65535) {
        return "Unknow Message";
    }
    QString command = " -- ";
    QString sender = " -- ";
    QString rcpt = " -- ";

    QString msg = QString::fromUtf8(p, pSize);
    int popPos = msg.indexOf("\r\n");
    if(popPos != -1) {
        command = msg.left(popPos);
    }

    command.replace(";", "|");

    // from ve to arama ekle
    int senderPos = msg.indexOf("From:");
    int recipientPos = msg.indexOf("To:");

    if(senderPos != -1 ){
        int endPos = msg.indexOf("\r\n",senderPos);
        sender = msg.mid(senderPos+5,endPos-senderPos-5);
    }

    if(recipientPos != -1){
        int endPos = msg.indexOf("\r\n",recipientPos);
        rcpt = msg.mid(recipientPos+3,endPos-recipientPos-3);
    }
    qDebug() << "Sender " << sender << " -- " << "Receient :" << rcpt ;
    return command;



}

QStringList clsPacketOperation::parseSipMessage(const char *p, int pSize){

    if(pSize <= 0 && pSize > 65535) {
        return QStringList() << "" << "" << "";

    }
    //call flow takibi yapılacak

    QStringList returnList;
    QString sender = "";
    QString recipient = "";

    QString msg = QString::fromUtf8(p, pSize);
    int endOfFirst = msg.indexOf("\r\n");
    if (endOfFirst == -1) return QStringList() << "" << "" << "";


    QString fLine = msg.left(endOfFirst); //ilk satır burdan mesaj türüne eriş
    /*if(fLine.contains("INVITE") || fLine.contains("200 OK")) {
        //SDP içeriğini parse et
        //Call-ID: elde et
        //(m = ) ara
        //(c= ) ara bu değerleri elde et
        //timestamp ekle bunlara en  son
        //qDebug() << "INVITE or 200 OK";
        int sdpStart = msg.indexOf("c=");
        if(sdpStart != -1){
            int newLine = msg.indexOf("\r\n",sdpStart);
            if(newLine != -1){

                QString sdp = msg.mid(sdpStart, newLine - sdpStart);
                //qDebug() << sdp;

            }


        }

    }*/

    fLine.replace(";", "|");

    int senderPos = msg.indexOf("From: ");
    int recipientPos = msg.indexOf("To: ");

    if(senderPos != -1 ){
        int endPos = msg.indexOf("\r\n",senderPos);
        sender = msg.mid(senderPos+6,endPos-senderPos-6);
    }

    if(recipientPos != -1){
        int endPos = msg.indexOf("\r\n",recipientPos);
        recipient = msg.mid(recipientPos+4,endPos-recipientPos-4);
    }

    returnList << fLine << sender << recipient ;



    return returnList;



}



sipSessionInfo clsPacketOperation::parseSipSession(const char *p, int pSize,int packetIndex){
    if(pSize <= 0 && pSize > 65535) {
        qDebug() << "Hatalı format ";
    }

    sipSessionInfo info;


    QString sipMessage = "";
    QString callId = "";
    QString ipAddres = "";
    QStringList media ;
    QStringList portNumber ;

    int control = -1 ;
    QString payload = QString::fromUtf8(p, pSize);


    //Call-ID ara
    int callIdIndex = payload.indexOf("Call-ID:") + 9;
    int newLineAftercCallId = payload.indexOf("\r\n",callIdIndex);
    callId = payload.mid(callIdIndex,newLineAftercCallId-callIdIndex);
    //qDebug() << callId;



    int endOfFirst = payload.indexOf("\r\n");

    sipMessage = payload.left(endOfFirst); //ilk satır burdan mesaj türüne eriş
    //qDebug() << sipMessage ;

    if(sipMessage.contains("INVITE") || sipMessage.contains("200 OK")) {
        control = sipMessage.contains("INVITE") ? 1 : 0 ;
        int returnLinePos = payload.indexOf("\r\n\r\n");
        int startIp = payload.indexOf("c=",returnLinePos);
        if(startIp != -1){
            int newLine = payload.indexOf("\r\n",startIp);
            QString sdp = payload.mid(startIp, newLine - startIp);
            int ipStart = sdp.indexOf("IP");
            ipAddres = sdp.mid(ipStart+4);
            //qDebug() << ipAddres;
        }

        int startMediaFlow = payload.indexOf("m=",returnLinePos);
        while(startMediaFlow != -1){
            int newLineAfterMedia = payload.indexOf("\r\n",startMediaFlow);
            QString mediaFlow = payload.mid(startMediaFlow,newLineAfterMedia-startMediaFlow);

            QStringList datas = mediaFlow.split(' ');

            media << datas[0];
            portNumber << datas[1];
            startMediaFlow = payload.indexOf("m=",newLineAfterMedia+2);
            //qDebug() << media << "-" << portNumber;
        }
    }


    if(sipHash.contains(callId)){
        sipSessionInfo &sip = sipHash[callId];

        //-1 li durumu ekle
        switch(control){
        case 1:
            if(sip.sourceIp.isEmpty()){
                sip.sourceIp = ipAddres;
            }
            sip.sourceMediaDatas.append(media);
            sip.sourcePorts.append(portNumber);
            break;

        case 0:
            if(sip.destIp.isEmpty()){
                sip.destIp = ipAddres;
            }
            sip.destMediaDatas.append(media);
            sip.destPorts.append(portNumber);
            break;

        case -1 :
            break;


        default:
            qDebug() << "Fail switch - case";
        }


        /*if(control == 1){//source to dest
            if(sip.sourceIp.isEmpty()){
                sip.sourceIp = ipAddres;
            }
            sip.sourceMediaDatas.append(media);
            sip.sourcePorts.append(portNumber);

        }else {
            if(sip.destIp.isEmpty()){
                sip.destIp = ipAddres;
            }
            sip.destMediaDatas.append(media);
            sip.destPorts.append(portNumber);
        }*/
        sip.messages << sipMessage;
        sip.tms = QDateTime::currentDateTime();
        sip.indeks.push_back(packetIndex);
        info = sip;
        //güncelleme iişlemleri
    }else{
        sipSessionInfo newsInfo;
        newsInfo.messages << sipMessage;
        switch(control){
        case -1 :
            newsInfo.sourceIp = "";
            newsInfo.destIp = "";
            newsInfo.sourceMediaDatas = QStringList();
            newsInfo.sourcePorts = QStringList();
            newsInfo.destMediaDatas = QStringList();
            newsInfo.destPorts = QStringList();
            newsInfo.tms = QDateTime::currentDateTime();
            newsInfo.indeks.push_back(packetIndex);
            break;
        case 0 : //dest to source
            newsInfo.sourceIp = "";
            newsInfo.destIp = ipAddres;
            newsInfo.sourceMediaDatas = QStringList();
            newsInfo.sourcePorts = QStringList();
            newsInfo.destMediaDatas.append(media);
            newsInfo.destPorts.append(portNumber);
            newsInfo.tms = QDateTime::currentDateTime();
            newsInfo.indeks.push_back(packetIndex);
            break;
        case 1: // source to dest
            newsInfo.sourceIp = ipAddres;
            newsInfo.destIp = "";
            newsInfo.sourceMediaDatas.append(media);
            newsInfo.sourcePorts.append(portNumber);
            newsInfo.destMediaDatas = QStringList();
            newsInfo.destPorts = QStringList();
            newsInfo.tms = QDateTime::currentDateTime();
            newsInfo.indeks.push_back(packetIndex);
            break;

        default:
            qDebug() << "Switch - case hatası";
            break;
        }
        this->sipHash[callId] = newsInfo;
        info = newsInfo;

    }
    //qDebug() << "size : " << this->sipHash.size();



    return info;


}




QStringList clsPacketOperation::parseSmtp(const char *p, int pSize){
    QStringList rList;

    if (p == nullptr || pSize < 0) {
        //cout << pSize << endl;
        rList << "" << "" << "";
        return rList;
    }

    QString msg = QString::fromUtf8(p, pSize);

    QString sender = "";
    QString recipient = "";
    QString mailBody = "" ;
    //qDebug() << msg << " -- " ;
    int senderPos = msg.indexOf("MAIL FROM:");
    int recipientPos = msg.indexOf("RCPT TO:");

    if(senderPos != -1){
        int start = msg.indexOf("<",senderPos) + 1;
        int end = msg.indexOf(">",senderPos);
        if (start != 0 && end != -1) {
            sender = msg.mid(start, end - start);
            //cout << "sender " << sender << endl;
        }
    }

    if(recipientPos != -1){
        int start = msg.indexOf("<",recipientPos) + 1;
        int end = msg.indexOf(">",recipientPos);
        if (start != 0 && end != -1) {
            recipient = msg.mid(start, end - start);
            //cout << "recipient " << recipient << endl;
        }
    }

    //body parse
    //sender - recipient - mailBody bir qstringlist yap boş olmadığını konrol et sonra append ile ekle
    int mailBodyPos = msg.indexOf("\r\n\r\n");
    if(mailBodyPos != -1){
        //qDebug() << sender << " -" << recipient << " -- ";
        mailBody = msg.mid(mailBodyPos+4);
        //qDebug() << "MSG : " << mailBody;
    }
    rList << sender << recipient << mailBody ;


    return rList;


}

