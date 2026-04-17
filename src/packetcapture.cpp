#include "packetcapture.h"
#include <QDebug>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

PacketCapture::PacketCapture(QObject *parent)
    : QObject(parent)
    , m_pcap(nullptr)
    , m_running(false)
{
}

PacketCapture::~PacketCapture() {
    stop();
}

bool PacketCapture::start(const QString &interface, const QString &filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    m_pcap = pcap_open_live(
        interface.toLocal8Bit().constData(),
        65535,
        1,  // promiscuous
        100,
        errbuf
    );
    
    if (!m_pcap) {
        emit error(QString("Failed to open %1: %2").arg(interface).arg(errbuf));
        return false;
    }
    
    // Compile and set filter
    if (!filter.isEmpty()) {
        struct bpf_program fp;
        if (pcap_compile(m_pcap, &fp, filter.toLocal8Bit().constData(), 1, 0) == -1) {
            emit error(QString("Filter error: %1").arg(pcap_geterr(m_pcap)));
            return false;
        }
        if (pcap_setfilter(m_pcap, &fp) == -1) {
            emit error(QString("Failed to set filter: %1").arg(pcap_geterr(m_pcap)));
            return false;
        }
        pcap_freecode(&fp);
    }
    
    m_interface = interface;
    m_filter = filter;
    m_running = true;
    
    emit started(interface);
    return true;
}

void PacketCapture::stop() {
    if (m_pcap) {
        pcap_close(m_pcap);
        m_pcap = nullptr;
    }
    m_running = false;
    emit stopped();
}

void PacketCapture::packetHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto *capture = reinterpret_cast<PacketCapture*>(user);
    
    QString srcIP, dstIP, info;
    quint16 srcPort = 0, dstPort = 0;
    quint8 protocol = 0;
    
    info = capture->protocolInfo(bytes, h->caplen, srcIP, dstIP, srcPort, dstPort, protocol);
    
    QByteArray data(reinterpret_cast<const char*>(bytes), h->caplen);
    emit capture->packetCaptured(data, srcIP, dstIP, srcPort, dstPort, protocol, info);
}

QString PacketCapture::protocolInfo(const u_char *bytes, int size,
                                   QString &srcIP, QString &dstIP,
                                   quint16 &srcPort, quint16 &dstPort,
                                   quint8 &protocol) {
    
    if (size < 20) return "Packet too small";
    
    // Check IP version
    quint8 version = (bytes[0] >> 4) & 0xF;
    
    if (version == 4) {
        const ip *ipHeader = reinterpret_cast<const ip*>(bytes);
        srcIP = inet_ntoa(ipHeader->ip_src);
        dstIP = inet_ntoa(ipHeader->ip_dst);
        protocol = ipHeader->ip_p;
        
        int ipHeaderLen = ipHeader->ip_hl * 4;
        
        switch (protocol) {
            case IPPROTO_TCP: {
                if (size >= ipHeaderLen + 20) {
                    const tcphdr *tcp = reinterpret_cast<const tcphdr*>(bytes + ipHeaderLen);
                    srcPort = ntohs(tcp->th_sport);
                    dstPort = ntohs(tcp->th_dport);
                    QString flags;
                    if (tcp->th_flags & TH_SYN) flags += "SYN ";
                    if (tcp->th_flags & TH_ACK) flags += "ACK ";
                    if (tcp->th_flags & TH_FIN) flags += "FIN ";
                    if (tcp->th_flags & TH_RST) flags += "RST ";
                    if (tcp->th_flags & TH_PUSH) flags += "PSH ";
                    return QString("TCP %1>%2 [%3]").arg(srcPort).arg(dstPort).arg(flags.trimmed());
                }
                return "TCP";
            }
            case IPPROTO_UDP: {
                if (size >= ipHeaderLen + 8) {
                    const udphdr *udp = reinterpret_cast<const udphdr*>(bytes + ipHeaderLen);
                    srcPort = ntohs(udp->uh_sport);
                    dstPort = ntohs(udp->uh_dport);
                    return QString("UDP %1>%2 len=%3").arg(srcPort).arg(dstPort).arg(ntohs(udp->uh_ulen));
                }
                return "UDP";
            }
            case IPPROTO_ICMP: {
                if (size >= ipHeaderLen + 8) {
                    const icmphdr *icmp = reinterpret_cast<const icmphdr*>(bytes + ipHeaderLen);
                    return QString("ICMP type=%1 code=%2").arg(icmp->icmp_type).arg(icmp->icmp_code);
                }
                return "ICMP";
            }
            default:
                return QString("IP proto=%1").arg(protocol);
        }
    }
    
    return "Unknown IP version";
}

QString PacketCapture::ipToString(const u_char *ip) {
    return QString("%1.%2.%3.%4").arg(ip[0]).arg(ip[1]).arg(ip[2]).arg(ip[3]);
}
