QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

INCLUDEPATH += "C:\Users\user\Desktop\npcap\Include"
LIBS += -L"C:\Users\user\Desktop\npcap\Lib\x64" -lwpcap
LIBS += -lws2_32

#INCLUDEPATH += "C:/Users/remzi/Desktop/sstekLearn/npcap-sdk-1.13/Include"
#LIBS += -L"C:/Users/remzi/Desktop/sstekLearn/npcap-sdk-1.13/Lib/x64" -lwpcap
#LIBS += -lws2_32

SOURCES += \
    MoveWorker.cpp \
    PacketWorker.cpp \
    SearchMapWorker.cpp \
    clsPacketOperation.cpp \
    clsPacketWorker.cpp \
    clsSearchMapWorker.cpp \
    main.cpp \
    mainwindow.cpp \
    newstructs.cpp \
    pSearchMapWorker.cpp \
    packetoperation.cpp \
    packetstruct.cpp \
    workerUpdate.cpp


HEADERS += \
    MoveWorker.h \
    PacketWorker.h \
    SearchMapWorker.h \
    clsPacketOperation.h \
    clsPacketWorker.h \
    clsSearchMapWorker.h \
    mainwindow.h \
    newstructs.h \
    pSearchMapWorker.h \
    packetoperation.h \
    packetstruct.h \
    workerUpdate.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
