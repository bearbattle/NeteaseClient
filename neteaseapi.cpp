#include <QMap>
#include <QVariantMap>
#include <QUrl>
#include <QString>
#include <QJsonObject>
#include <QJsonDocument>
#include <QRandomGenerator>
#include "neteaseapi.h"
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QEventLoop>
#include <QNetworkCookieJar>
#include <QNetworkCookie>
#include <QMessageBox>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

static const int aesKeySize = 16;
static const char* base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static const unsigned char* presetKey = (const unsigned char*)("0CoJUm6Qyw8W8jud");
static const unsigned char* iv = (const unsigned char*)("0102030405060708");
static const char* pubKey = "-----BEGIN PUBLIC KEY-----\r\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgtQn2JZ34ZC28NWYpAUd98iZ37BUrX/aKzmFbt7clFSs6sXqHauqKWqdtLkF2KexO40H1YTX8z2lSgBBOAxLsvaklV8k4cBFK9snQXE9/DDaFt6Rr7iVZMldczhC0JNgTz+SHXT6CBHuX3e9SdB1Ua44oncaTWz7OBGLbCiK45wIDAQAB\r\n-----END PUBLIC KEY-----";

QByteArray rsaEncrypt(QByteArray buffer)
{
    BIO *mem = BIO_new(BIO_s_mem());
    RSA* rsa;
    BIO_puts(mem, pubKey);
    if (rsa = PEM_read_bio_RSA_PUBKEY(mem, nullptr, nullptr, nullptr))
    {
       const int encryptSize = 128;
       Q_ASSERT(RSA_size(rsa) == encryptSize);
       unsigned char buf[encryptSize], encrypted[encryptSize];
       memset(buf, 0, sizeof(buf));
       std::copy_backward(buffer.crbegin(), buffer.crend(), buf + encryptSize);
       if (RSA_public_encrypt(encryptSize, buf, encrypted, rsa, RSA_NO_PADDING) != -1)
       {
           if(mem) BIO_free(mem);
           if(rsa) RSA_free(rsa);
           return QByteArray((char*)encrypted, encryptSize);
       }
    }

    if(mem) BIO_free(mem);
    if(rsa) RSA_free(rsa);
    qFatal("Encryption failed %s", ERR_error_string(ERR_get_error(), nullptr));
}

QByteArray aesEncrypt(QByteArray buffer, const unsigned char* key, const unsigned char* iv)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(key, aesKeySize * 8, &aes_key);
    int padSize = aesKeySize - (buffer.size() % aesKeySize);
    for (int i = 0; i < padSize; i++)
    {
        buffer.append(padSize);
    }
    QByteArray out(buffer.size(), 0);
    unsigned char iv2[aesKeySize];
    memcpy(iv2, iv, aesKeySize);
    AES_cbc_encrypt((const unsigned char*)buffer.constData(), (unsigned char*)out.data(), buffer.size(), &aes_key, iv2, AES_ENCRYPT);
    return out;
}

QString weapiEncrypt(QJsonDocument data)
{
    auto text = data.toJson(QJsonDocument::Compact);
    unsigned char secretKey[aesKeySize];
    for (int i = 0; i < aesKeySize; i++)
    {
        secretKey[i] = base62[QRandomGenerator::global()->bounded((quint32)(sizeof(base62) - 1))];
    }
    auto result1 = aesEncrypt(text, presetKey, iv).toBase64(QByteArray::Base64Encoding);
    auto result2 = aesEncrypt(result1, secretKey, iv).toBase64(QByteArray::Base64Encoding);
    auto rsaResult = rsaEncrypt(QByteArray((const char*)secretKey, 16)).toHex().toLower();
    return QString("params=%1&encSecKey=%2").arg(QString(QUrl::toPercentEncoding(QString(result2))), QString(QUrl::toPercentEncoding(QString(rsaResult))));
}

QNetworkAccessManager qnam;

void DoRequest(RequestMethod method, QUrl url, QJsonDocument data)
{
    QNetworkRequest req;
    req.setUrl(url);
    if (method == POST)
        req.setHeader(QNetworkRequest::ContentTypeHeader, QString("application/x-www-form-urlencoded"));
    req.setRawHeader("Cookie", "os=pc");
    req.setRawHeader("Referer", "https://music.163.com");
    req.setHeader(QNetworkRequest::UserAgentHeader, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.1.1 Safari/603.2.4");
    auto encodedData = weapiEncrypt(data);
    if (method == POST)
    {
        QNetworkReply *reply = qnam.post(req, encodedData.toUtf8());
        QEventLoop eventLoop;
        QObject::connect(reply, SIGNAL(finished()), &eventLoop, SLOT(quit()));
        eventLoop.exec();
        if(reply->error() == QNetworkReply::NoError)
        {
            QByteArray response = reply->readAll();
            QMessageBox::information(NULL, "Title", QString(response));
        }
        else // handle error
        {
            QMessageBox::warning(NULL, "Error", reply->errorString());

        }
    }
}
