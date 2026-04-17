QT = core network

CONFIG += console
CONFIG -= app_bundle

INCLUDEPATH += include

SOURCES += \
    src/main.cpp \
    src/packetcapture.cpp \
    src/packetfilter.cpp

HEADERS += \
    include/packetcapture.h \
    include/packetfilter.h

LIBS += -lpcap
