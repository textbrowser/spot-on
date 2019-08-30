/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from Spot-On without specific prior written permission.
**
** SPOT-ON IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** SPOT-ON, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _spoton_misc_h_
#define _spoton_misc_h_

#include <QAtomicInt>
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#include <QBluetoothAddress>
#endif
#include <QHostAddress>
#include <QPair>
#include <QReadWriteLock>
#include <QSqlDatabase>
#include <QString>
#include <QVariant>

#if defined(Q_OS_WIN)
extern "C"
{
#include <winsock2.h>
#include <ws2tcpip.h>
}
#else
extern "C"
{
#include <netinet/in.h>
#include <sys/socket.h>
}
#endif

/*
** Please read https://gcc.gnu.org/onlinedocs/gcc-4.4.1/gcc/Optimize-Options.html#Type_002dpunning.
*/

typedef union spoton_type_punning_sockaddr
{
    struct sockaddr sockaddr;
    struct sockaddr_in sockaddr_in;
    struct sockaddr_in6 sockaddr_in6;
    struct sockaddr_storage sockaddr_storage;
}
spoton_type_punning_sockaddr_t;

class spoton_crypt;

class spoton_misc
{
 public:
  static QByteArray findPublicKeyHashGivenHash(const QByteArray &randomBytes,
					       const QByteArray &hash,
					       const QByteArray &hashKey,
					       const QByteArray &haskType,
					       spoton_crypt *crypt);
  static QByteArray forwardSecrecyMagnetFromList
    (const QList<QByteArray> &list);
  static QByteArray publicKeyFromHash(const QByteArray &publicKeyHash,
				      spoton_crypt *crypt);
  static QByteArray publicKeyFromOID(const qint64 oid, spoton_crypt *crypt);
  static QByteArray publicKeyFromSignaturePublicKeyHash
    (const QByteArray &signaturePublicKeyHash, spoton_crypt *crypt);
  static QByteArray signaturePublicKeyFromPublicKeyHash
    (const QByteArray &publicKeyHash, spoton_crypt *crypt);
  static QByteArray urlToEncoded(const QUrl &url);
  static QByteArray xor_arrays(const QByteArray &a, const QByteArray &b);
  static QHash<QString, QByteArray> retrieveEchoShareInformation
    (const QString &communityName, spoton_crypt *crypt);
  static QHostAddress peerAddressAndPort(
#if defined(Q_OS_WIN)
					 const SOCKET socketDescriptor,
#else
					 const int socketDescriptor,
#endif
					 quint16 *port);
  static QList<QByteArray> findEchoKeys(const QByteArray &bytes1,
					const QByteArray &bytes2,
					QString &type,
					spoton_crypt *crypt);
  static QList<QByteArray> findForwardSecrecyKeys(const QByteArray &bytes1,
						  const QByteArray &bytes2,
						  QString &messageType,
						  spoton_crypt *crypt);
  static QList<QHash<QString, QVariant> > poptasticSettings
    (const QString &in_username, spoton_crypt *crypt, bool *ok);
  static QPair<QByteArray, QByteArray> decryptedAdaptiveEchoPair
    (const QPair<QByteArray, QByteArray>, spoton_crypt *crypt);
  static QPair<QByteArray, QByteArray> findGeminiInCosmos
    (const QByteArray &data, const QByteArray &hash, spoton_crypt *crypt);
  static QSqlDatabase database(QString &connectionName);
  static QString countryCodeFromIPAddress(const QString &ipAddress);
  static QString countryNameFromIPAddress(const QString &ipAddress);
  static QString databaseName(void);
  static QString homePath(void);
  static QString htmlEncode(const QString &string);
  static QString keyTypeFromPublicKeyHash(const QByteArray &publicKeyHash,
					  spoton_crypt *crypt);
  static QString massageIpForUi(const QString &ip, const QString &protocol);
  static QString nameFromPublicKeyHash(const QByteArray &publicKeyHash,
				       spoton_crypt *crypt);
  static QString prettyFileSize(const qint64 size);
  static QString removeSpecialHtmlTags(const QString &text);
  static bool acceptableTimeSeconds(const QDateTime &then, const int delta);
  static bool allParticipantsHaveGeminis(void);
  static bool authenticateAccount(QByteArray &name,
				  QByteArray &password,
				  const qint64 listenerOid,
				  const QByteArray &saltedCredentials,
				  const QByteArray &salt,
				  spoton_crypt *crypt);
  static bool importUrl(const QByteArray &c, // Content
			const QByteArray &d, // Description
			const QByteArray &t, // Title
			const QByteArray &u, // URL
			const QSqlDatabase &db,
			const int maximum_keywords,
			const bool disable_synchronous_sqlite_writes,
			QAtomicInt &atomic,
			QString &error,
			spoton_crypt *crypt);
  static bool isAcceptedIP(const QHostAddress &address,
			   const qint64 id,
			   spoton_crypt *crypt);
  static bool isAcceptedIP(const QString &address,
			   const qint64 id,
			   spoton_crypt *crypt);
  static bool isAcceptedParticipant(const QByteArray &publicKeyHash,
				    const QString &keyType,
				    spoton_crypt *crypt);
  static bool isAuthenticatedHint(spoton_crypt *crypt);
  static bool isIpBlocked(const QHostAddress &address,
			  spoton_crypt *crypt);
  static bool isIpBlocked(const QString &address,
			  spoton_crypt *crypt);
  static bool isMulticastAddress(const QHostAddress &address);
  static bool isPrivateNetwork(const QHostAddress &address);
  static bool isValidBuzzMagnet(const QByteArray &magnet);
  static bool isValidBuzzMagnetData(const QByteArray &data);
  static bool isValidForwardSecrecyMagnet(const QByteArray &magnet,
					  QList<QByteArray> &values);
  static bool isValidInstitutionMagnet(const QByteArray &magnet);
  static bool isValidSMPMagnet(const QByteArray &magnet,
			       QList<QByteArray> &values);
  static bool isValidSignature(const QByteArray &data,
			       const QByteArray &publicKeyHash,
			       const QByteArray &signature,
			       spoton_crypt *crypt);
  static bool isValidStarBeamMagnet(const QByteArray &magnet);
  static bool joinMulticastGroup(const QHostAddress &address,
				 const QVariant &loop,
#if defined(Q_OS_WIN)
				 const SOCKET socketDescriptor,
#else
				 const int socketDescriptor,
#endif
				 const quint16 port);
  static bool prepareUrlDistillersDatabase(void);
  static bool prepareUrlKeysDatabase(void);
  static bool publicKeyExists(const qint64 oid);
  static bool saveFriendshipBundle(const QByteArray &keyType,
				   const QByteArray &name,
				   const QByteArray &publicKey,
				   const QByteArray &sPublicKey,
				   const qint64 neighborOid,
				   const QSqlDatabase &db,
				   spoton_crypt *crypt,
				   const bool useKeyTypeForName = true);
  static bool saveGemini(const QPair<QByteArray, QByteArray> &gemini,
			 const QString &oid,
			 spoton_crypt *crypt);
  static bool saveReceivedStarBeamHash(const QSqlDatabase &db,
				       const QByteArray &hash,
				       const QString &oid,
				       spoton_crypt *crypt);
  static bool storeAlmostAnonymousLetter(const QList<QByteArray> &list,
					 spoton_crypt *crypt);
  static int minimumNeighborLaneWidth(void);
  static qint64 oidFromPublicKeyHash(const QByteArray &publicKeyHash);
  static qint64 participantCount(const QString &keyType,
				 spoton_crypt *crypt);
  static quint64 databaseAccesses(void);
  static spoton_crypt *cryptFromForwardSecrecyMagnet
    (const QByteArray &magnet);
  static spoton_crypt *parsePrivateApplicationMagnet(const QByteArray &magnet);
  static spoton_crypt *retrieveUrlCommonCredentials(spoton_crypt *crypt);
  static void alterDatabasesAfterAuthentication(spoton_crypt *crypt);
  static void cleanupDatabases(spoton_crypt *crypt);
  static void closeSocket
#if QT_VERSION < 0x050000
    (const int socketDescriptor);
#else
    (const qintptr socketDescriptor);
#endif
  static void correctSettingsContainer(QHash<QString, QVariant> settings);
  static void enableLog(const bool state);
  static void logError(const QString &error);
  static void populateUrlsDatabase(const QList<QList<QVariant> > &list,
				   spoton_crypt *crypt);
  static void prepareAuthenticationHint(spoton_crypt *crypt);
  static void prepareDatabases(void);
  static void prepareSignalHandler(void (*signal_handler) (int));
  static void purgeSignatureRelationships(const QSqlDatabase &db,
					  spoton_crypt *crypt);
  static void removeOneTimeStarBeamMagnets(void);
  static void retrieveSymmetricData(QPair<QByteArray, QByteArray> &gemini,
				    QByteArray &publicKey,
				    QByteArray &symmetricKey,
				    QByteArray &hashKey,
				    QByteArray &startsWith,
				    QString &neighborOid,
				    QString &receiverName,
				    const QByteArray &cipherType,
				    const QString &oid,
				    spoton_crypt *crypt,
				    bool *ok);
  static void saveParticipantStatus(const QByteArray &name,
				    const QByteArray &publicKeyHash,
				    const QByteArray &status,
				    const QByteArray &timestamp,
				    const int seconds,
				    spoton_crypt *crypt);
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  static void savePublishedNeighbor(const QBluetoothAddress &address,
				    const quint16 port,
				    const QString &statusControl,
				    const QString &orientation,
				    spoton_crypt *crypt);
#endif
  static void savePublishedNeighbor(const QHostAddress &address,
				    const quint16 port,
				    const QString &transport,
				    const QString &statusControl,
				    const QString &orientation,
				    spoton_crypt *crypt);
  static void setTimeVariables(const QHash<QString, QVariant> &settings);
  static void vacuumAllDatabases(void);

  template<typename T> static T readSharedResource(T *resource,
						   QReadWriteLock &mutex)
  {
    QReadLocker locker(&mutex);
    T value = T();

    if(resource)
      value = *resource;

    return value;
  }

  template<typename T> static void setSharedResource(T *resource,
						     const T &value,
						     QReadWriteLock &mutex)
  {
    QWriteLocker locker(&mutex);

    if(resource)
      *resource = value;
  }

 private:
  static QAtomicInt s_enableLog;
  static QReadWriteLock s_dbMutex;
  static QReadWriteLock s_logMutex;
  static quint64 s_dbId;
  spoton_misc(void);
  static void logErrorThread(const QString &error);
};

#endif
