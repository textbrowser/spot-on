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

#ifndef _spoton_gui_server_h_
#define _spoton_gui_server_h_

#include <QFileSystemWatcher>
#include <QQueue>
#include <QPointer>
#include <QSslSocket>
#include <QTcpServer>
#include <QTimer>

#include "Common/spot-on-common.h"

class spoton_gui_server_tcp_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_gui_server_tcp_server(QObject *parent):QTcpServer(parent)
  {
  }

  ~spoton_gui_server_tcp_server()
  {
    while(!m_queue.isEmpty())
      {
	QPointer<QSslSocket> socket = m_queue.dequeue();

	if(socket)
	  socket->deleteLater();
      }
  }

  QSslSocket *nextPendingConnection(void)
  {
    if(m_queue.isEmpty())
      return 0;
    else
      return m_queue.dequeue();
  }

#if QT_VERSION >= 0x050000
  void incomingConnection(qintptr socketDescriptor);
#else
  void incomingConnection(int socketDescriptor);
#endif

 private:
  QQueue<QPointer<QSslSocket> > m_queue;

 signals:
  void modeChanged(QSslSocket::SslMode mode);
  void newConnection(void);
};

class spoton_gui_server: public spoton_gui_server_tcp_server
{
  Q_OBJECT

 public:
  spoton_gui_server(QObject *parent);
  ~spoton_gui_server();

 private:
  QFileSystemWatcher m_fileSystemWatcher;
#if QT_VERSION >= 0x050000
  QHash<qintptr, QByteArray> m_guiSocketData;
  QHash<qintptr, bool> m_guiIsAuthenticated;
#else
  QHash<int, QByteArray> m_guiSocketData;
  QHash<int, bool> m_guiIsAuthenticated;
#endif
  QTimer m_generalTimer;

 private slots:
  void slotAuthenticationRequested(const QString &peerInformation);
  void slotClientConnected(void);
  void slotClientDisconnected(void);
  void slotEncrypted(void);
  void slotFileChanged(const QString &path);
  void slotForwardSecrecyRequest(const QByteArrayList &list);
  void slotForwardSecrecyResponse(const QByteArrayList &list);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotNewEMailArrived(void);
  void slotReadyRead(void);
  void slotReceivedBuzzMessage(const QByteArrayList &list,
			       const QByteArrayList &keys);
  void slotReceivedChatMessage(const QByteArray &message);
  void slotSMPMessage(const QByteArrayList &list);
  void slotStatusMessageReceived(const QByteArray &publicKeyHash,
				 const QString &status);
  void slotTimeout(void);

 signals:
  void buzzMagnetReceivedFromUI(const qint64 oid,
				const QByteArray &magnet);
  void buzzReceivedFromUI(const QByteArray &channel,
			  const QByteArray &channelType,
			  const QByteArray &name,
			  const QByteArray &id,
			  const QByteArray &message,
			  const QByteArray &sendMethod,
			  const QString &messageType,
			  const QByteArray &hashKey,
			  const QByteArray &hashType,
			  const QByteArray &dateTime);
  void callParticipant(const QByteArray &keyType,
		       const qint64 oid);
  void callParticipantUsingForwardSecrecy(const QByteArray &keyType,
					  const qint64 oid);
  void callParticipantUsingGemini(const QByteArray &keyType,
				  const qint64 oid);
  void detachNeighbors(const qint64 oid);
  void disconnectNeighbors(const qint64 oid);
  void echoKeyShare(const QByteArrayList &list);
  void forwardSecrecyInformationReceivedFromUI(const QByteArrayList &list);
  void forwardSecrecyResponseReceivedFromUI(const QByteArrayList &list);
  void messageReceivedFromUI(const qint64 oid,
			     const QByteArray &name,
			     const QByteArray &message,
			     const QByteArray &sequenceNumber,
			     const QByteArray &utcDate,
			     const QString &keyType);
  void populateStarBeamKeys(void);
  void publicKeyReceivedFromUI(const qint64 oid,
			       const QByteArray &keyType,
			       const QByteArray &name,
			       const QByteArray &publicKey,
			       const QByteArray &signature,
			       const QByteArray &sPublicKey,
			       const QByteArray &sSignature,
			       const QString &messageType);
  void publicizeAllListenersPlaintext(void);
  void publicizeListenerPlaintext(const qint64 oid);
  void purgeEphemeralKeyPair(const QByteArray &publicKeyHash);
  void purgeEphemeralKeys(void);
  void retrieveMail(void);
  void shareLink(const QByteArray &link);
  void smpMessageReceivedFromUI(const QByteArrayList &list);
};

#endif
