#ifndef PACKETANALYZER_H
#define PACKETANALYZER_H

#include <QObject>
#include <QByteArray>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

struct PacketInfo {
    timeval timestamp;
    QString srcIP;
    QString dstIP;
    quint16 srcPort;
    quint16 dstPort;
    quint8 protocol;
    QString info;
    QByteArray rawData;
};

class PacketAnalyzer : public QObject {
    Q_OBJECT
    
public:
    explicit PacketAnalyzer(QObject *parent = nullptr);
    
public slots:
    void analyze(const QByteArray &data, const timeval &tv);
    
signals:
    void packetAnalyzed(const PacketInfo &info);
    
private:
    QString ipToString(const quint8 *ip);
};

#endif // PACKETANALYZER_H
