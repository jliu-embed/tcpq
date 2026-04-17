#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QGroupBox>
#include <QCheckBox>
#include <QComboBox>
#include <QMessageBox>
#include <QDebug>
#include <pcap.h>
#include <signal.h>
#include <sys/time.h>

static volatile sig_atomic_t g_running = 1;

void signalHandler(int) {
    g_running = 0;
}

class PacketCaptureThread : public QThread {
    Q_OBJECT
public:
    explicit PacketCaptureThread(QObject *parent = nullptr) : QThread(parent), m_pcap(nullptr) {}
    
    void setFilter(const QString &ipFilter, int portFilter, bool tcpOnly, bool udpOnly) {
        m_ipFilter = ipFilter;
        m_portFilter = portFilter;
        m_tcpOnly = tcpOnly;
        m_udpOnly = udpOnly;
    }
    
    void stop() {
        m_running = false;
        if (m_pcap) {
            pcap_breakloop(m_pcap);
        }
    }
    
signals:
    void packetReceived(const QString &time, const QString &srcIP, const QString &dstIP,
                       const QString &protocol, int srcPort, int dstPort, const QString &info);

protected:
    void run() override;

private:
    pcap_t *m_pcap;
    bool m_running = true;
    QString m_ipFilter;
    int m_portFilter = 0;
    bool m_tcpOnly = false;
    bool m_udpOnly = false;
    
    bool matchesFilter(const QString &srcIP, const QString &dstIP, int srcPort, int dstPort, int proto);
};

bool PacketCaptureThread::matchesFilter(const QString &srcIP, const QString &dstIP, int srcPort, int dstPort, int proto) {
    if (m_tcpOnly && proto != 6) return false;
    if (m_udpOnly && proto != 17) return false;
    
    if (!m_ipFilter.isEmpty()) {
        if (srcIP != m_ipFilter && dstIP != m_ipFilter) {
            return false;
        }
    }
    
    if (m_portFilter > 0) {
        if (srcPort != m_portFilter && dstPort != m_portFilter) {
            return false;
        }
    }
    
    return true;
}

void PacketCaptureThread::run() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = "eth0";
    
    m_pcap = pcap_open_live(device, 65535, 1, 100, errbuf);
    if (!m_pcap) {
        qDebug() << "Failed to open" << device << errbuf;
        return;
    }
    
    QString filterStr;
    if (!m_ipFilter.isEmpty()) {
        filterStr = QString("host %1").arg(m_ipFilter);
    }
    if (m_portFilter > 0) {
        if (!filterStr.isEmpty()) filterStr += " and ";
        filterStr += QString("port %1").arg(m_portFilter);
    }
    if (m_tcpOnly) {
        if (!filterStr.isEmpty()) filterStr += " and ";
        filterStr += "tcp";
    }
    if (m_udpOnly) {
        if (!filterStr.isEmpty()) filterStr += " and ";
        filterStr += "udp";
    }
    
    if (!filterStr.isEmpty()) {
        struct bpf_program fp;
        if (pcap_compile(m_pcap, &fp, filterStr.toLocal8Bit().constData(), 1, 0) == 0) {
            pcap_setfilter(m_pcap, &fp);
            pcap_freecode(&fp);
        }
    }
    
    qDebug() << "Capturing on" << device << "with filter:" << filterStr;
    
    struct pcap_pkthdr *header;
    const u_char *data;
    
    while (m_running && pcap_next_ex(m_pcap, &header, &data) >= 0) {
        if (header->caplen < 20) continue;
        
        const quint8 *bytes = data;
        quint8 version = (bytes[0] >> 4) & 0xF;
        
        if (version != 4) continue;
        
        const ip *ipHeader = reinterpret_cast<const ip*>(bytes);
        QString srcIP = QString("%1.%2.%3.%4")
            .arg(ipHeader->ip_src.s_addr & 0xFF)
            .arg((ipHeader->ip_src.s_addr >> 8) & 0xFF)
            .arg((ipHeader->ip_src.s_addr >> 16) & 0xFF)
            .arg((ipHeader->ip_src.s_addr >> 24) & 0xFF);
        
        QString dstIP = QString("%1.%2.%3.%4")
            .arg(ipHeader->ip_dst.s_addr & 0xFF)
            .arg((ipHeader->ip_dst.s_addr >> 8) & 0xFF)
            .arg((ipHeader->ip_dst.s_addr >> 16) & 0xFF)
            .arg((ipHeader->ip_dst.s_addr >> 24) & 0xFF);
        
        int proto = ipHeader->ip_p;
        int ipHeaderLen = ipHeader->ip_hl * 4;
        
        QString protocol;
        int srcPort = 0, dstPort = 0;
        QString info;
        
        if (proto == 6 && header->caplen >= ipHeaderLen + 20) {
            const tcphdr *tcp = reinterpret_cast<const tcphdr*>(bytes + ipHeaderLen);
            srcPort = ntohs(tcp->th_sport);
            dstPort = ntohs(tcp->th_dport);
            protocol = "TCP";
            QString flags;
            if (tcp->th_flags & TH_SYN) flags += "SYN ";
            if (tcp->th_flags & TH_ACK) flags += "ACK ";
            if (tcp->th_flags & TH_FIN) flags += "FIN ";
            if (tcp->th_flags & TH_RST) flags += "RST ";
            info = QString("%1>%2 [%3]").arg(srcPort).arg(dstPort).arg(flags.trimmed());
        } else if (proto == 17 && header->caplen >= ipHeaderLen + 8) {
            const udphdr *udp = reinterpret_cast<const udphdr*>(bytes + ipHeaderLen);
            srcPort = ntohs(udp->uh_sport);
            dstPort = ntohs(udp->uh_dport);
            protocol = "UDP";
            info = QString("%1>%2").arg(srcPort).arg(dstPort);
        } else if (proto == 1) {
            protocol = "ICMP";
            info = "ICMP";
        } else {
            protocol = QString("Proto-%1").arg(proto);
            info = protocol;
        }
        
        if (matchesFilter(srcIP, dstIP, srcPort, dstPort, proto)) {
            struct timeval tv = header->ts;
            struct tm *tm = localtime(&tv.tv_sec);
            char timeBuf[32];
            strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", tm);
            QString timeStr = QString("%1.%2").arg(timeBuf).arg(tv.tv_usec / 1000, 3, 10, QChar('0'));
            
            emit packetReceived(timeStr, srcIP, dstIP, protocol, srcPort, dstPort, info);
        }
    }
    
    if (m_pcap) {
        pcap_close(m_pcap);
        m_pcap = nullptr;
    }
}

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr) : QMainWindow(parent) {
        setupUI();
    }
    
private slots:
    void startCapture() {
        QString ipFilter = m_ipEdit->text().trimmed();
        int portFilter = m_portSpin->value();
        bool tcpOnly = m_tcpCheck->isChecked();
        bool udpOnly = m_udpCheck->isChecked();
        
        if (!ipFilter.isEmpty()) {
            QRegularExpression ipRegex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
            if (!ipRegex.match(ipFilter).hasMatch()) {
                QMessageBox::warning(this, "Invalid IP", "Please enter a valid IP address");
                return;
            }
        }
        
        if (m_captureThread == nullptr) {
            m_tableWidget->setRowCount(0);
            m_rowCount = 0;
        }
        
        if (m_captureThread) {
            m_captureThread->stop();
            m_captureThread->wait();
            delete m_captureThread;
        }
        
        m_captureThread = new PacketCaptureThread(this);
        m_captureThread->setFilter(ipFilter, portFilter, tcpOnly, udpOnly);
        connect(m_captureThread, &PacketCaptureThread::packetReceived,
                this, &MainWindow::onPacketReceived);
        connect(m_captureThread, &PacketCaptureThread::finished,
                this, &MainWindow::onCaptureFinished);
        
        m_captureThread->start();
        m_startBtn->setEnabled(false);
        m_stopBtn->setEnabled(true);
        m_statusLabel->setText("Capturing...");
    }
    
    void stopCapture() {
        if (m_captureThread) {
            m_captureThread->stop();
        }
    }
    
    void onPacketReceived(const QString &time, const QString &srcIP, const QString &dstIP,
                         const QString &protocol, int srcPort, int dstPort, const QString &info) {
        int row = m_tableWidget->rowCount();
        m_tableWidget->insertRow(row);
        
        m_tableWidget->setItem(row, 0, new QTableWidgetItem(time));
        m_tableWidget->setItem(row, 1, new QTableWidgetItem(srcIP));
        m_tableWidget->setItem(row, 2, new QTableWidgetItem(dstIP));
        m_tableWidget->setItem(row, 3, new QTableWidgetItem(protocol));
        m_tableWidget->setItem(row, 4, new QTableWidgetItem(QString::number(srcPort)));
        m_tableWidget->setItem(row, 5, new QTableWidgetItem(QString::number(dstPort)));
        m_tableWidget->setItem(row, 6, new QTableWidgetItem(info));
        
        m_rowCount++;
        m_statusLabel->setText(QString("Capturing... %1 packets").arg(m_rowCount));
        m_tableWidget->scrollToBottom();
    }
    
    void onCaptureFinished() {
        m_startBtn->setEnabled(true);
        m_stopBtn->setEnabled(false);
        m_statusLabel->setText(QString("Stopped. Total: %1 packets").arg(m_rowCount));
    }

private:
    void setupUI() {
        setWindowTitle("tcpq - Packet Analyzer");
        resize(900, 600);
        
        QWidget *central = new QWidget(this);
        setCentralWidget(central);
        
        QVBoxLayout *mainLayout = new QVBoxLayout(central);
        
        QGroupBox *filterGroup = new QGroupBox("Filter Settings", this);
        QHBoxLayout *filterLayout = new QHBoxLayout(filterGroup);
        
        QLabel *ipLabel = new QLabel("IP:", this);
        m_ipEdit = new QLineEdit(this);
        m_ipEdit->setPlaceholderText("Filter by IP");
        m_ipEdit->setMaximumWidth(200);
        
        QLabel *portLabel = new QLabel("Port:", this);
        m_portSpin = new QSpinBox(this);
        m_portSpin->setPlaceholderText("Port");
        m_portSpin->setMaximum(65535);
        m_portSpin->setMinimum(0);
        m_portSpin->setMaximumWidth(100);
        
        m_tcpCheck = new QCheckBox("TCP Only", this);
        m_udpCheck = new QCheckBox("UDP Only", this);
        
        filterLayout->addWidget(ipLabel);
        filterLayout->addWidget(m_ipEdit);
        filterLayout->addSpacing(20);
        filterLayout->addWidget(portLabel);
        filterLayout->addWidget(m_portSpin);
        filterLayout->addSpacing(20);
        filterLayout->addWidget(m_tcpCheck);
        filterLayout->addWidget(m_udpCheck);
        filterLayout->addStretch();
        
        mainLayout->addWidget(filterGroup);
        
        QHBoxLayout *btnLayout = new QHBoxLayout();
        m_startBtn = new QPushButton("Start Capture", this);
        m_stopBtn = new QPushButton("Stop", this);
        m_stopBtn->setEnabled(false);
        m_clearBtn = new QPushButton("Clear", this);
        
        connect(m_startBtn, &QPushButton::clicked, this, &MainWindow::startCapture);
        connect(m_stopBtn, &QPushButton::clicked, this, &MainWindow::stopCapture);
        connect(m_clearBtn, &QPushButton::clicked, [this]() {
            m_tableWidget->setRowCount(0);
            m_rowCount = 0;
        });
        
        btnLayout->addWidget(m_startBtn);
        btnLayout->addWidget(m_stopBtn);
        btnLayout->addWidget(m_clearBtn);
        btnLayout->addStretch();
        
        m_statusLabel = new QLabel("Ready", this);
        btnLayout->addWidget(m_statusLabel);
        
        mainLayout->addLayout(btnLayout);
        
        m_tableWidget = new QTableWidget(this);
        m_tableWidget->setColumnCount(7);
        m_tableWidget->setHorizontalHeaderLabels({"Time", "Source IP", "Dest IP", "Protocol", "Src Port", "Dst Port", "Info"});
        m_tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        m_tableWidget->setAlternatingRowColors(true);
        m_tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        
        mainLayout->addWidget(m_tableWidget);
        
        statusBar()->showMessage("Ready to capture");
    }
    
    QLineEdit *m_ipEdit;
    QSpinBox *m_portSpin;
    QCheckBox *m_tcpCheck;
    QCheckBox *m_udpCheck;
    QPushButton *m_startBtn;
    QPushButton *m_stopBtn;
    QPushButton *m_clearBtn;
    QTableWidget *m_tableWidget;
    QLabel *m_statusLabel;
    PacketCaptureThread *m_captureThread = nullptr;
    int m_rowCount = 0;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("tcpq");
    app.setApplicationVersion("1.0.0");
    
    MainWindow window;
    window.show();
    
    return app.exec();
}

#include "main.moc"
