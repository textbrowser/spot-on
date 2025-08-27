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

#ifndef _spoton_kernel_h_
#define _spoton_kernel_h_

#ifdef SPOTON_POPTASTIC_SUPPORTED
extern "C"
{
#include <curl/curl.h>
}
#endif

#include <QAtomicInt>
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#include <QBluetoothAddress>
#endif
#include <QDateTime>
#include <QFileSystemWatcher>
#include <QFuture>
#include <QHash>
#include <QHostAddress>
#include <QMultiMap>
#include <QPointer>
#include <QQueue>
#include <QReadWriteLock>
#include <QSqlDatabase>
#include <QTimer>
#include <QtConcurrent>

#include "Common/spot-on-common.h"
#include "Common/spot-on-send.h"

class spoton_crypt;
class spoton_fireshare;
class spoton_gui_server;
class spoton_import_published_pages;
class spoton_listener;
class spoton_mailer;
class spoton_neighbor;
class spoton_rss;
class spoton_starbeam_reader;
class spoton_starbeam_writer;
class spoton_urldistribution;
class spoton_web_server;

class spoton_kernel: public QObject
{
  Q_OBJECT

 public:
  spoton_kernel(void);
  ~spoton_kernel();
  static QAtomicInt s_interfaces;
  static QAtomicInt s_sendInitialStatus;
  static QMultiHash<qint64, QPointer<spoton_neighbor> > s_connectionCounts;
  static QPair<quint64, quint64> s_totalNeighborsBytesReadWritten;
  static QPair<quint64, quint64> s_totalUiBytesReadWritten;
  static QReadWriteLock s_totalNeighborsBytesReadWrittenMutex;
  static QReadWriteLock s_totalUiBytesReadWrittenMutex;
  static QList<QByteArray> findBuzzKey(const QByteArray &data,
				       const QByteArray &hash);
  static QList<QByteArray> findInstitutionKey(const QByteArray &data,
					      const QByteArray &hash);
  static QList<QPair<QByteArray, QByteArray> > adaptiveEchoTokens(void);
  static QPointer<spoton_kernel> instance(void);
  static QSqlDatabase urlDatabase(QString &connectionName);
  static QVariant setting(const QString &name);
  static QVariant setting(const QString &name, const QVariant &defaultValue);
  static bool duplicateEmailRequests(const QByteArray &data);
  static bool duplicateGeminis(const QByteArray &data);
  static bool messagingCacheContains(const QByteArray &data,
				     const bool do_not_hash = false);
  static int buzzKeyCount(void);
  static int interfaces(void);
  static qint64 uptimeMinutes(void);
  static spoton_crypt *crypt(const QString &key);
  static void addBuzzKey(const QByteArray &key,
			 const QByteArray &channelType,
			 const QByteArray &hashKey,
			 const QByteArray &hashType);
  static void clearBuzzKeysContainer(void);
  static void cryptSave(const QString &k, spoton_crypt *crypt);
  static void discoverAdaptiveEchoPair
    (const QByteArray &data,
     QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair);
  static void emailRequestCacheAdd(const QByteArray &data);
  static void geminisCacheAdd(const QByteArray &data);
  static void messagingCacheAdd(const QByteArray &data,
				const bool do_not_hash = false,
				const int add_msecs = 0);
  static void removeBuzzKey(const QByteArray &key);
  bool acceptRemoteBluetoothConnection(const QString &localAddress,
				       const QString &peerAddress) const;
  bool acceptRemoteConnection(const QHostAddress &localAddress,
			      const QHostAddress &peerAddress) const;
  bool hasStarBeamReaderId(const qint64 id) const;
  bool initialized(void) const;
  bool processPotentialStarBeamData
    (const QByteArray &data,
     QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair);
  void saveUrls(const QList<QByteArray> &urls);
  void writeMessage006X(const QByteArray &data,
			const QString &messageType,
			int *neighborIndex,
			bool *ok);

 private:
  QAtomicInt m_urlImportFutureInterrupt;
  QDateTime m_lastPoptasticStatus;
  QFileSystemWatcher m_settingsWatcher;
  QFuture<void> m_checkForTerminationFuture;
  QFuture<void> m_future;
  QFuture<void> m_poptasticPopFuture;
  QFuture<void> m_poptasticPostFuture;
  QFuture<void> m_readPrisonBluesFuture;
  QFuture<void> m_statisticsFuture;
  QHash<QByteArray, QVector<QVariant> > m_forwardSecrecyKeys;
  QHash<QPair<QByteArray, qint64>, QByteArray> m_droppedPackets;
  QHash<qint64, QPointer<spoton_listener> > m_listeners;
  QHash<qint64, QPointer<spoton_neighbor> > m_neighbors;
  QHash<qint64, QPointer<spoton_starbeam_reader> > m_starbeamReaders;
  QList<QByteArray> m_urlList;
  QList<QHash<QString, QVariant> > m_poptasticAccounts;
  QPointer<spoton_fireshare> m_fireShare;
  QPointer<spoton_gui_server> m_guiServer;
  QPointer<spoton_import_published_pages> m_importPublishedPages;
  QPointer<spoton_mailer> m_mailer;
  QPointer<spoton_rss> m_rss;
  QPointer<spoton_starbeam_writer> m_starbeamWriter;
  QPointer<spoton_urldistribution> m_urlDistribution;
  QPointer<spoton_web_server> m_webServer;
  QQueue<QHash<QString, QVariant> > m_poptasticCache;
  QReadWriteLock m_droppedPacketsMutex;
  QReadWriteLock m_forwardSecrecyKeysMutex;
  QReadWriteLock m_poptasticCacheMutex;
  QReadWriteLock m_urlListMutex;
  QReadWriteLock m_urlsProcessedMutex;
  QTimer m_controlDatabaseTimer;
  QTimer m_droppedTimer;
  QTimer m_forwardSecrecyKeysTimer;
  QTimer m_impersonateTimer;
  QTimer m_messagingCachePurgeTimer;
  QTimer m_poptasticPopTimer;
  QTimer m_poptasticPostTimer;
  QTimer m_prepareTimer;
  QTimer m_prisonBluesTimer;
  QTimer m_publishAllListenersPlaintextTimer;
  QTimer m_readPrisonBluesTimer;
  QTimer m_scramblerTimer;
  QTimer m_settingsTimer;
  QTimer m_statusTimer;
  QTimer m_urlImportTimer;
  QVector<QFuture<void > > m_urlImportFutures;
  QVector<QPointer<QProcess> > m_prisonBluesProcesses;
  bool m_initialized;
  int m_activeListeners;
  int m_activeNeighbors;
  int m_activeStarbeams;
  quint64 m_urlsProcessed;
  static QAtomicInt s_congestionControlSecondaryStorage;
  static QAtomicInteger<quint64> s_prisonBluesSequence;
  static QByteArray s_messagingCacheKey;
  static QDateTime s_institutionLastModificationTime;
  static QElapsedTimer s_uptime;
  static QHash<QByteArray, QList<QByteArray> > s_buzzKeys;
  static QHash<QByteArray, char> s_messagingCache;
  static QHash<QByteArray, qint64> s_emailRequestCache;
  static QHash<QByteArray, qint64> s_geminisCache;
  static QHash<QString, QVariant> s_settings;
  static QHash<QString, spoton_crypt *> s_crypts;
  static QList<QList<QByteArray> > s_institutionKeys;
  static QList<QPair<QByteArray, QByteArray> > s_adaptiveEchoPairs;
  static QMultiMap<qint64, QByteArray> s_messagingCacheLookup;
  static QReadWriteLock s_adaptiveEchoPairsMutex;
  static QReadWriteLock s_buzzKeysMutex;
  static QReadWriteLock s_cryptsMutex;
  static QReadWriteLock s_emailRequestCacheMutex;
  static QReadWriteLock s_geminisCacheMutex;
  static QReadWriteLock s_institutionKeysMutex;
  static QReadWriteLock s_institutionLastModificationTimeMutex;
  static QReadWriteLock s_messagingCacheMutex;
  static QReadWriteLock s_settingsMutex;
  static QString prisonBluesSequence(void);
  bool initializeSecurityContainers(const QString &passphrase,
				    const QString &answer);
  bool prepareAlmostAnonymousEmail(const QByteArray &attachmentData,
				   const QByteArray &fromAccount,
				   const QByteArray &goldbug,
				   const QByteArray &keyType,
				   const QByteArray &message,
				   const QByteArray &name,
				   const QByteArray &receiverName,
				   const QByteArray &subject,
				   const QByteArray &date,
				   const qint64 mailOid,
				   QByteArray &data);
  void checkForTermination(void);
  void cleanup(void);
  void cleanupDatabases(void);
  void cleanupListenersDatabase(const QSqlDatabase &db);
  void cleanupNeighborsDatabase(const QSqlDatabase &db);
  void cleanupStarbeamsDatabase(const QSqlDatabase &db);
  void connectSignalsToNeighbor(const QPointer<spoton_neighbor> &neighbor);
  void importUrls(void);
  void popPoptastic(void);
  void postPoptastic(void);
  void postPoptasticMessage(const QByteArray &attachmentData,
			    const QByteArray &message,
			    const QByteArray &name,
			    const QByteArray &subject,
			    const QByteArray &mode,
			    const QByteArray &fromAccount,
			    const QByteArray &date,
			    const qint64 mailOid);
  void postPoptasticMessage(const QString &receiverName,
			    const QByteArray &message);
  void postPoptasticMessage(const QString &receiverName,
			    const QByteArray &message,
			    const QByteArray &fromAccount,
			    const qint64 mailOid);
  void prepareListeners(void);
  void prepareNeighbors(void);
  void prepareStarbeamReaders(void);
  void prepareStatus(const QString &keyType);
  void purgeMessagingCache(void);
  void readPrisonBlues(void);
  void saveGeminiPoptastic(const QByteArray &publicKeyHash,
			   const QByteArray &gemini,
			   const QByteArray &geminiHashKey,
			   const QByteArray &timestamp,
			   const QByteArray &signature,
			   const QString &messageType);
  void updateStatistics
    (const QElapsedTimer &uptime, const QVector<int> &integers);
  void writePrisonBluesChat
    (const QByteArray &message, const QByteArray &publicKeyHash);

 private slots:
  void slotBuzzMagnetReceivedFromUI(const qint64 oid,
				    const QByteArray &magnet);
  void slotBuzzReceivedFromUI(const QByteArray &key,
			      const QByteArray &channelType,
			      const QByteArray &name,
			      const QByteArray &id,
			      const QByteArray &message,
			      const QByteArray &sendMethod,
			      const QString &messageType,
			      const QByteArray &hashKey,
			      const QByteArray &hashType,
			      const QByteArray &dateTime);
  void slotCallParticipant(const QByteArray &publicKeyHash,
			   const QByteArray &gemini,
			   const QByteArray &geminiHashKey);
  void slotCallParticipant(const QByteArray &keyType, const qint64 oid);
  void slotCallParticipantUsingForwardSecrecy(const QByteArray &keyType,
					      const qint64 oid);
  void slotCallParticipantUsingGemini(const QByteArray &keyType,
				      const qint64 oid);
  void slotDetachNeighbors(const qint64 listenerOid);
  void slotDisconnectNeighbors(const qint64 listenerOid);
  void slotDropped(const QByteArray &data);
  void slotDroppedTimeout(void);
  void slotForwardSecrecyInformationReceivedFromUI(const QByteArrayList &list);
  void slotForwardSecrecyResponseReceivedFromUI(const QByteArrayList &list);
  void slotImpersonateTimeout(void);
  void slotMessageReceivedFromUI(const qint64 oid,
				 const QByteArray &name,
				 const QByteArray &message,
				 const QByteArray &sequenceNumber,
				 const QByteArray &utcDate,
				 const qint64 hpOid,
				 const bool gitMessage,
				 const QString &keyType);
  void slotMessagingCachePurge(void);
  void slotNewNeighbor(const QPointer<spoton_neighbor> &neighbor);
  void slotPollDatabase(void);
  void slotPoppedMessage(const QByteArray &message);
  void slotPoptasticPop(void);
  void slotPoptasticPost(void);
  void slotPrepareObjects(void);
  void slotPrisonBluesTimeout(void);
  void slotPublicKeyReceivedFromUI(const qint64 oid,
				   const QByteArray &keyType,
				   const QByteArray &name,
				   const QByteArray &publicKey,
				   const QByteArray &signature,
				   const QByteArray &sPublicKey,
				   const QByteArray &sSignature,
				   const QString &messageType);
  void slotPublicizeAllListenersPlaintext(void);
  void slotPublicizeListenerPlaintext(const qint64 oid);
  void slotPurgeEphemeralKeyPair(const QByteArray &publicKeyHash);
  void slotPurgeEphemeralKeys(void);
  void slotPurgeEphemeralKeysTimeout(void);
  void slotReadPrisonBlues(void);
  void slotRequestScramble(void);
  void slotRetrieveMail(void);
  void slotSMPMessageReceivedFromUI(const QByteArrayList &list);
  void slotSaveForwardSecrecySessionKeys(const QByteArrayList &list);
  void slotScramble(void);
  void slotSendMail(const QByteArray &goldbug,
		    const QByteArray &message,
		    const QByteArray &name,
		    const QByteArray &publicKey,
		    const QByteArray &subject,
		    const QByteArray &attachmentData,
		    const QByteArray &keyType,
		    const QByteArray &receiverName,
		    const QByteArray &mode,
		    const QByteArray &fromAccount,
		    const QByteArray &date,
		    const bool sign,
		    const qint64 mailOid);
  void slotSettingsChanged(const QString &path);
  void slotStatusTimerExpired(void);
  void slotTerminate(const bool registered);
  void slotUrlImportTimerExpired(void);
  void slotUpdateSettings(void);
  void slotWriteMessage0061(const QByteArray &data);

 signals:
  void callParticipant(const QByteArray &data, const QString &messageType);
  void forwardSecrecyRequest(const QByteArrayList &list);
  void forwardSecrecyResponseReceived(const QByteArrayList &list);
  void newEMailArrived(void);
  void poppedMessage(const QByteArray &message);
  void publicizeListenerPlaintext(const QByteArray &data, const qint64 id);
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  void publicizeListenerPlaintext(const QBluetoothAddress &address,
				  const quint16 port,
				  const QString &orientation);
#endif
  void publicizeListenerPlaintext(const QHostAddress &address,
				  const quint16 port,
				  const QString &transport,
				  const QString &orientation);
  void receivedChatMessage(const QByteArray &data);
  void retrieveMail(const QByteArrayList &list, const QString &messageType);
  void sendBuzz(const QByteArray &buzz);
  void sendForwardSecrecyPublicKey(const QByteArray &data);
  void sendForwardSecrecySessionKeys(const QByteArray &data);
  void sendMessage(const QByteArray &message,
		   const spoton_send::spoton_send_method sendMethod);
  void sendMail(const QPairByteArrayInt64List &mail,
		const QString &messageType);
  void sendStatus(const QByteArrayList &status);
  void smpMessage(const QByteArrayList &list);
  void statusMessageReceived(const QByteArray &publicKeyHash,
			     const QString &status);
  void terminate(const bool registered);
  void write(const QByteArray &data,
	     const qint64 id,
	     const QPairByteArrayByteArray &adaptiveEchoPair);
};

#endif
