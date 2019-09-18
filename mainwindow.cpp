#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "neteaseapi.h"

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
    data["username"] = "chao4150443@163.com";
    data["password"] = "7c3a8f898d0e9fa3b4f9fa1d48486ea7";
    data["rememberLogin"] = "true";
    QJsonDocument json = QJsonDocument::fromVariant(data);
    DoRequest(POST,QUrl("https://music.163.com/weapi/login"),json);
}
