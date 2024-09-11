#include "clsPacketWorker.h"
#include "clsPacketOperation.h"

clsPacketWorker::clsPacketWorker(const QString& str)
    : path(str){


}

clsPacketWorker::~clsPacketWorker(){
    delete packet;
    packet = nullptr;
}

void clsPacketWorker::createPacket(){
    //qDebug() << "Create Packet" ;

    packet = new clsPacketOperation(path);
    packet->packetCapture(0);
    //packet->printPacketInfo();
    //packet->printCsvFile(); //bunu aç sonra

    /*delete packet;
    packet = nullptr;*/

    emit createFinished();

}


