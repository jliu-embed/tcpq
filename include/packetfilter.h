#ifndef PACKETFILTER_H
#define PACKETFILTER_H

#include <QObject>
#include <QString>
#include <QSet>
#include <QUuid>

struct FilterRule {
    enum Type {
        IP_Src,
        IP_Dst,
        IP_Both,
        Port_Src,
        Port_Dst,
        Port_Both,
        Protocol
    };
    
    Type type;
    QString value;
    bool negate;  // for ! operator
    
    bool matches(const QString &srcIP, const QString &dstIP, 
                 quint16 srcPort, quint16 dstPort, quint8 protocol) const;
};

class PacketFilter : public QObject {
    Q_OBJECT
    
public:
    explicit PacketFilter(QObject *parent = nullptr);
    
    void setFilter(const QString &filterString);
    void addRule(const FilterRule &rule);
    void clear();
    bool matches(const QString &srcIP, const QString &dstIP,
                 quint16 srcPort, quint16 dstPort, quint8 protocol) const;
    
    static QString protocolName(quint8 proto);
    static bool parseCIDR(const QString &cidr, QString &ip, int &mask);
    
signals:
    void filterChanged(const QString &filterString);
    
private:
    QList<FilterRule> m_rules;
    
    bool evaluateExpression(const QString &expr, const QString &srcIP,
                           const QString &dstIP, quint16 srcPort,
                           quint16 dstPort, quint8 protocol) const;
};

#endif // PACKETFILTER_H
