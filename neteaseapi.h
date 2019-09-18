#ifndef NETEASEAPI_H
#define NETEASEAPI_H

#include <QUrl>
#include <QJsonDocument>

enum RequestMethod { GET, POST };
void DoRequest(RequestMethod method, QUrl url, QJsonDocument data);

#endif // NETEASEAPI_H
