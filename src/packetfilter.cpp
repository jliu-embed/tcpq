#include "packetfilter.h"
#include <QDebug>
#include <QRegularExpression>

PacketFilter::PacketFilter(QObject *parent)
    : QObject(parent)
{
}

void PacketFilter::setFilter(const QString &filterString) {
    m_rules.clear();
    
    if (filterString.isEmpty()) return;
    
    // Parse simple filter expressions
    // Examples: "src 192.168.1.1", "dst port 80", "tcp port 8080", "ip src 10.0.0.1"
    
    QStringList tokens = filterString.split(' ', Qt::SkipEmptyParts);
    int i = 0;
    
    while (i < tokens.size()) {
        QString token = tokens[i].toLower();
        
        FilterRule rule;
        rule.negate = false;
        
        if (token == "not" || token == "!") {
            rule.negate = true;
            i++;
            continue;
        }
        
        if (token == "src") {
            if (i + 1 < tokens.size()) {
                rule.type = FilterRule::IP_Src;
                rule.value = tokens[++i];
            }
        }
        else if (token == "dst") {
            if (i + 1 < tokens.size()) {
                rule.type = FilterRule::IP_Dst;
                rule.value = tokens[++i];
            }
        }
        else if (token == "host") {
            if (i + 1 < tokens.size()) {
                rule.type = FilterRule::IP_Both;
                rule.value = tokens[++i];
            }
        }
        else if (token == "port") {
            if (i + 1 < tokens.size()) {
                rule.type = FilterRule::Port_Both;
                rule.value = tokens[++i];
            }
        }
        else if (token == "src" && i + 2 < tokens.size() && tokens[i+1].toLower() == "port") {
            rule.type = FilterRule::Port_Src;
            rule.value = tokens[i + 2];
            i += 2;
        }
        else if (token == "dst" && i + 2 < tokens.size() && tokens[i+1].toLower() == "port") {
            rule.type = FilterRule::Port_Dst;
            rule.value = tokens[i + 2];
            i += 2;
        }
        else if (token == "tcp") {
            rule.type = FilterRule::Protocol;
            rule.value = "6";  // TCP protocol number
        }
        else if (token == "udp") {
            rule.type = FilterRule::Protocol;
            rule.value = "17";  // UDP protocol number
        }
        else if (token == "icmp") {
            rule.type = FilterRule::Protocol;
            rule.value = "1";  // ICMP protocol number
        }
        else if (token == "ip") {
            rule.type = FilterRule::Protocol;
            rule.value = "4";  // IP protocol number (simplified)
        }
        else if (token == "and" || token == "or") {
            // Logical operators - for now just skip
        }
        else {
            // Try to interpret as raw value (port number or IP)
            bool isPort = rule.value.setNum(token.toInt());
            if (!rule.value.isEmpty()) {
                rule.type = FilterRule::Port_Both;
            }
        }
        
        if (!rule.value.isEmpty() || rule.type == FilterRule::Protocol) {
            m_rules.append(rule);
        }
        
        i++;
    }
    
    emit filterChanged(filterString);
}

bool PacketFilter::matches(const QString &srcIP, const QString &dstIP,
                         quint16 srcPort, quint16 dstPort, quint8 protocol) const {
    if (m_rules.isEmpty()) return true;
    
    for (const FilterRule &rule : m_rules) {
        if (rule.matches(srcIP, dstIP, srcPort, dstPort, protocol)) {
            if (!rule.negate) return true;
        }
    }
    
    return m_rules.isEmpty() ? true : false;
}

QString PacketFilter::protocolName(quint8 proto) {
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        default: return QString("Proto-%1").arg(proto);
    }
}

bool FilterRule::matches(const QString &srcIP, const QString &dstIP,
                        quint16 srcPort, quint16 dstPort, quint8 protocol) const {
    switch (type) {
        case IP_Src:
            return value == srcIP;
        case IP_Dst:
            return value == dstIP;
        case IP_Both:
            return value == srcIP || value == dstIP;
        case Port_Src:
            return value.setNum(srcPort) && value == QString::number(srcPort);
        case Port_Dst:
            return value.setNum(dstPort) && value == QString::number(dstPort);
        case Port_Both:
            return (value.setNum(srcPort) && value == QString::number(srcPort)) ||
                   (value.setNum(dstPort) && value == QString::number(dstPort));
        case Protocol: {
            bool ok;
            return protocol == value.toInt(&ok);
        }
    }
    return false;
}
