#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QObject>
#include <QString>
#include <pcap.h>

class PacketCapture : public QObject {
    Q_OBJECT
    
public:
    explicit PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();
    
    bool start(const QString &interface, const QString &filter = QString());
    void stop();
    
    bool isRunning() const { return m_running; }
    
signals:
    void packetCaptured(const QByteArray &data, 
                       const QString &srcIP, const QString &dstIP,
                       quint16 srcPort, quint16 dstPort,
                       quint8 protocol, const QString &info);
    void error(const QString &message);
    void started(const QString &interface);
    void stopped();
    
private:
    pcap_t *m_pcap;
    QString m_interface;
    bool m_running;
    QString m_filter;
    
    static void packetHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
    QString protocolInfo(const u_char *bytes, int size, QString &srcIP, QString &dstIP,
                        quint16 &srcPort, quint16 &dstPort, quint8 &protocol);
    QString ipToString(const u_char *ip);
};

#endif // PACKETCAPTURE_H
