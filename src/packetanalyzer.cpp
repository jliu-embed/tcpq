#include "packetanalyzer.h"
#include <QDebug>

PacketAnalyzer::PacketAnalyzer(QObject *parent)
    : QObject(parent)
{
}

void PacketAnalyzer::analyze(const QByteArray &data, const timeval &tv) {
    PacketInfo info;
    info.timestamp = tv;
    info.rawData = data;
    
    if (data.size() < 20) {
        info.info = "Packet too small";
        emit packetAnalyzed(info);
        return;
    }
    
    const ip *ipHeader = reinterpret_cast<const ip*>(data.data());
    
    info.srcIP = ipToString(reinterpret_cast<const quint8*>(&ipHeader->ip_src));
    info.dstIP = ipToString(reinterpret_cast<const quint8*>(&ipHeader->ip_dst));
    info.protocol = ipHeader->ip_p;
    
    QString protocol;
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP:
            protocol = "TCP";
            if (data.size() >= 20 + sizeof(tcphdr)) {
                const tcphdr *tcp = reinterpret_cast<const tcphdr*>(data.data() + 20);
                info.srcPort = ntohs(tcp->th_sport);
                info.dstPort = ntohs(tcp->th_dport);
                info.info = QString("TCP %1 -> %2 [SYN/FIN/ACK]").arg(info.srcPort).arg(info.dstPort);
            }
            break;
        case IPPROTO_UDP:
            protocol = "UDP";
            if (data.size() >= 20 + sizeof(udphdr)) {
                const udphdr *udp = reinterpret_cast<const udphdr*>(data.data() + 20);
                info.srcPort = ntohs(udp->uh_sport);
                info.dstPort = ntohs(udp->uh_dport);
                info.info = QString("UDP %1 -> %2").arg(info.srcPort).arg(info.dstPort);
            }
            break;
        case IPPROTO_ICMP:
            protocol = "ICMP";
            info.info = "ICMP packet";
            break;
        default:
            protocol = QString("Proto-%1").arg(ipHeader->ip_p);
    }
    
    qDebug() << info.timestamp.tv_sec << info.srcIP << "->" << info.dstIP << protocol;
    emit packetAnalyzed(info);
}

QString PacketAnalyzer::ipToString(const quint8 *ip) {
    return QString("%1.%2.%3.%4").arg(ip[0]).arg(ip[1]).arg(ip[2]).arg(ip[3]);
}
