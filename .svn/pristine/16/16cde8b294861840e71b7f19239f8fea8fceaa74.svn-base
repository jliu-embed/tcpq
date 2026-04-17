#include <QCoreApplication>
#include <QDebug>
#include <QCommandLineParser>
#include <csignal>
#include "packetcapture.h"
#include "packetfilter.h"

static volatile sig_atomic_t g_running = 1;

void signalHandler(int) {
    g_running = 0;
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    app.setApplicationName("tcpq");
    app.setApplicationVersion("1.0.0");
    
    QCommandLineParser parser;
    parser.setApplicationDescription("tcpq - TCP Packet Analyzer with IP/Port filtering");
    parser.addHelpOption();
    parser.addVersionOption();
    
    QCommandLineOption interfaceOption(
        QStringList() << "i" << "interface",
        "Network interface to capture",
        "interface",
        "eth0"
    );
    QCommandLineOption filterOption(
        QStringList() << "f" << "filter",
        "Filter: [src|dst|host] IP or [src|dst] port NUM or tcp|udp|icmp",
        "expression",
        ""
    );
    QCommandLineOption countOption(
        QStringList() << "c" << "count",
        "Stop after NUM packets",
        "num",
        "0"
    );
    
    parser.addOption(interfaceOption);
    parser.addOption(filterOption);
    parser.addOption(countOption);
    parser.process(app);
    
    QString interface = parser.value(interfaceOption);
    QString filter = parser.value(filterOption);
    int maxCount = parser.value(countOption).toInt();
    
    qDebug() << "=== tcpq - TCP Packet Analyzer ===";
    qDebug() << "Interface:" << interface;
    if (!filter.isEmpty()) {
        qDebug() << "Filter:" << filter;
    }
    if (maxCount > 0) {
        qDebug() << "Packet count:" << maxCount;
    }
    
    PacketFilter packetFilter;
    if (!filter.isEmpty()) {
        packetFilter.setFilter(filter);
    }
    
    PacketCapture capture;
    int packetCount = 0;
    
    // Handle signals
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    qDebug() << "\nListening on" << interface << "...";
    qDebug() << "Press Ctrl+C to stop\n";
    qDebug() << "TIME       SRC_IP          DST_IP          PROTO  SRC_PORT  DST_PORT  INFO";
    qDebug() << "--------------------------------------------------------------------------------";
    
    // Note: This is a simplified version. Real implementation would need
    // threading to run pcap_loop() while Qt event loop is running
    
    capture.start(interface, filter);
    
    return app.exec();
}
