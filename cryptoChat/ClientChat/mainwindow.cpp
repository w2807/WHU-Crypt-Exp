#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QNetworkInterface>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("ChatRoom");

    clnt_sock = new QTcpSocket(this);
	username = "User";

	connect(ui->connect_pb, &QPushButton::clicked, this, &MainWindow::ConnectToServer);
    connect(clnt_sock, &QTcpSocket::connected, this, [=]() {
		ui->tip_edit->setText("Connected to server");
        });
	connect(ui->disconnect_pb, &QPushButton::clicked, this, &MainWindow::DisconnectFromServer);
	connect(ui->send_pb, &QPushButton::clicked, this, &MainWindow::SendMessageToServer);
	connect(clnt_sock, &QTcpSocket::readyRead, this, &MainWindow::ReceiveMessageFromServer);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::ConnectToServer() {
    username = ui->username_edit->text();
    QString hostAddress = ui->host_edit->text();
    quint16 port = ui->port_edit->text().toUShort();

    qDebug() << "Connecting to host:" << hostAddress << "on port:" << port;

	clnt_sock->connectToHost(hostAddress, port);
    if (hostAddress.isEmpty() || port == 0) {
        qDebug() << "Invalid host address or port.";
        ui->tip_edit->setText("Please enter a valid IP and port.");
        return;
    }

    qDebug() << "Socket state:" << clnt_sock->state();
    if (!clnt_sock->waitForConnected(5000)) {
        qDebug() << "Connection failed. Error:" << clnt_sock->errorString();
        ui->tip_edit->setText("Failed to connect: " + clnt_sock->errorString());
    } else {
        qDebug() << "Connection successful. State:" << clnt_sock->state();
        ui->tip_edit->setText("Connected to server.");
    }
}

void MainWindow::DisconnectFromServer() {
	clnt_sock->disconnectFromHost();
	if (clnt_sock->state() == QTcpSocket::ConnectedState) {
		clnt_sock->waitForDisconnected();
	}
	ui->tip_edit->setText("Disconnected from server");
}

void MainWindow::SendMessageToServer() {
	QString message = ui->send_edit->toPlainText();
	message = "[" + username + "]: " + message;
    qDebug() << "Message sent:" << message;
	clnt_sock->write(message.toUtf8().data());
    clnt_sock->flush();
	ui->send_edit->clear();
}

void MainWindow::ReceiveMessageFromServer() {
    while (clnt_sock->bytesAvailable()) {
        QByteArray array = clnt_sock->readAll();
        QString msg = QString(array);

        int end = msg.indexOf(']');
        if (end > 0) {
            QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
            QString msg_head = msg.mid(0, end + 1) + " " + timestamp + "\n";
            QString msg_content = msg.mid(end + 1, -1);

            if (msg.mid(0, end) == username) {
                msg_head = QString("<b><span style='color:lightgreen;'>%1</span></b>").arg(msg_head);
            } else {
                msg_head = QString("<b><span style='color:lightblue;'>%1</span></b>").arg(msg_head);
            }

            ui->recieve_edit->append(msg_head + msg_content);
        }
    }
}

