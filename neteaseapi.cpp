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
#include <QNetworkCookieJar>
#include "qaesencryption.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
const int aesKeySize = 16;


QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::CBC);

QByteArray rsaEncrypt(QByteArray buffer)
{
    const char* pubKey = "-----BEGIN PUBLIC KEY-----\r\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgtQn2JZ34ZC28NWYpAUd98iZ37BUrX/aKzmFbt7clFSs6sXqHauqKWqdtLkF2KexO40H1YTX8z2lSgBBOAxLsvaklV8k4cBFK9snQXE9/DDaFt6Rr7iVZMldczhC0JNgTz+SHXT6CBHuX3e9SdB1Ua44oncaTWz7OBGLbCiK45wIDAQAB\r\n-----END PUBLIC KEY-----";
    BIO *mem = BIO_new(BIO_s_mem());
    RSA* rsa;
    BIO_puts(mem, pubKey);
    if (rsa = PEM_read_bio_RSA_PUBKEY(mem, nullptr, nullptr, nullptr))
    {
       const int encryptSize = 128;
       Q_ASSERT(RSA_size(rsa) == encryptSize);
       unsigned char buf[encryptSize], encrypted[encryptSize];
       memset(buf, 0, sizeof(buf));
       memcpy(buf + encryptSize - buffer.size(), buffer.constData(), (size_t)buffer.size());
       if (RSA_public_encrypt(encryptSize, buf, encrypted, rsa, RSA_NO_PADDING) != -1)
       {
           if(mem) BIO_free(mem);
           if(rsa) RSA_free(rsa);
           return QByteArray((char*)encrypted, encryptSize);
       }
    }
    qFatal("Encryption failed %s fuck", ERR_error_string(ERR_get_error(), nullptr));

    if(mem) BIO_free(mem);
    if(rsa) RSA_free(rsa);
}

QByteArray aesEncrypt(QByteArray buffer, const unsigned char* key, const unsigned char* iv)
{
    qDebug() << "Encrypting...";
    qDebug() << buffer.toHex().toLower();
    AES_KEY aes_key;
    AES_set_encrypt_key(key, aesKeySize * 8, &aes_key);
    int padSize = aesKeySize - buffer.size() % aesKeySize;
    for (int i = 0; i < padSize; i++)
    {
        buffer.append(padSize);
    }
    QByteArray out(buffer.size() + padSize, 0);
    unsigned char iv2[aesKeySize];
    memcpy(iv2, iv, aesKeySize);
    AES_cbc_encrypt((const unsigned char*)buffer.constData(), (unsigned char*)out.data(), buffer.size() + padSize, &aes_key, iv2, AES_ENCRYPT);
    qDebug() << out.toHex().toLower();
    return out;
}

QByteArray reverse(QByteArray a)
{
    QByteArray b(a.size(),0);
    std::copy(a.crbegin(),a.crend(),b.begin());
    return b;
}

QString weapiEncrypt(QJsonDocument data)
{
    // auto text = data.toJson(QJsonDocument::Compact);
    auto text = QByteArray("{\"username\":\"chao4150443@163.com\",\"password\":\"7c3a8f898d0e9fa3b4f9fa1d48486ea7\",\"rememberLogin\":\"true\"}");
    const char* base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const unsigned char* presetKey = (const unsigned char*)("0CoJUm6Qyw8W8jud");
    const unsigned char* iv = (const unsigned char*)("0102030405060708");
    unsigned char secretKey[aesKeySize];
    for (int i = 0; i < aesKeySize; i++)
    {
        // secretKey[i] = base62[QRandomGenerator::global()->bounded((quint32)(sizeof(base62) - 1))];
        secretKey[i] = 'A';
    }
    //auto result1 = encryption.encode(text, presetKey, iv).toBase64(QByteArray::Base64Encoding);
    auto result1 = aesEncrypt(text, presetKey, iv).toBase64(QByteArray::Base64Encoding);
    qDebug() << result1.size();

    auto result2 = aesEncrypt(result1, presetKey, iv).toBase64(QByteArray::Base64Encoding);
    auto rsaResult = rsaEncrypt(reverse(QByteArray((const char*)secretKey))).toHex().toLower();
    return QString("params=%1&encSecKey=%2").arg(QString(QUrl::toPercentEncoding(QString(result2)))).arg(QString(QUrl::toPercentEncoding(QString(rsaResult))));
}

void DoRequest(RequestMethod method, QUrl url, QJsonDocument data)
{
    /*
    QNetworkRequest req;
    req.setUrl(url);
    if (method == POST)
    req.setHeader(QNetworkRequest::ContentTypeHeader, QString("application/x-www-form-urlencoded"));
    req.setRawHeader(QString("Referer").toUtf8(), QString("https://music.163.com").toUtf8());
    req.setHeader(QNetworkRequest::UserAgentHeader, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:46.0) Gecko/20100101 Firefox/46.0");
    */

    qDebug() << weapiEncrypt(data);
}
