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

#ifndef _spoton_chatwindow_h_
#define _spoton_chatwindow_h_

#include <QIcon>
#include <QPointer>
#include <QSslSocket>

#include "ui_chatwindow.h"

class spoton_chatwindow: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_chatwindow(const QIcon &icon,
		    const QString &id,
		    const QString &keyType,
		    const QString &participant,
		    const QString &publicKeyHash,
		    QSslSocket *kernelSocket,
		    QWidget *parent);
  ~spoton_chatwindow();
  QString id(void) const;
  void append(const QString &text);
  void center(QWidget *parent);
  void setName(const QString &name);
  void setSMPVerified(const bool state);

 private:
  QPointer<QSslSocket> m_kernelSocket;
  QString m_id;
  QString m_keyType;
  QString m_publicKeyHash;
  Ui_chatwindow ui;
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
  bool event(QEvent *event);
#endif
#endif
  void closeEvent(QCloseEvent *event);
  void keyPressEvent(QKeyEvent *event);

 private slots:
  void slotInitializeSMP(void);
  void slotPrepareSMP(void);
  void slotSendMessage(void);
  void slotSetIcons(void);
  void slotSetStatus(const QIcon &icon, const QString &name,
		     const QString &id);
  void slotVerifySMPSecret(void);

 signals:
  void initializeSMP(const QString &publicKeyHash);
  void messageSent(void);
  void prepareSMP(const QString &publicKeyHash);
  void verifySMPSecret(const QString &publicKeyHash, const QString &keyType,
		       const QString &oid);
};

#endif
