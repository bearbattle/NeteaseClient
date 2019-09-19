#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "neteaseapi.h"
#include <QCryptographicHash>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::Test()
{
    QVariantMap data;
    data["username"] = ui->tb_Email->text();
    data["password"] = QCryptographicHash::hash(ui->tb_Password->text().toUtf8(), QCryptographicHash::Md5).toHex();
    data["rememberLogin"] = "true";
    QJsonDocument json = QJsonDocument::fromVariant(data);
    DoRequest(POST,QUrl("http://music.163.com/weapi/login"),json);
}
