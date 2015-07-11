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

#ifndef _spoton_echo_key_share_h_
#define _spoton_echo_key_share_h_

#include <QMainWindow>
#include <QPointer>

#include "ui_echo-key-share.h"

class QKeyEvent;
class QSslSocket;
class spoton_crypt;

class spoton_echo_key_share: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_echo_key_share(QSslSocket *kernelSocket);
  ~spoton_echo_key_share();
  static createDefaultUrlCommunity(void);
  void show(QWidget *parent);

 private:
  QPointer<QSslSocket> m_kernelSocket;
  Ui_spoton_echokeyshare ui;
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
  bool event(QEvent *event);
#endif
#endif
  bool save(const QPair<QByteArray, QByteArray> &keys,
	    const QString &cipherType,
	    const QString &hashType,
	    const int iterationCount,
	    const QString &name,
	    const QVariant &category_oid);
  void addCategory(void);
  void deleteSelected(void);
  void keyPressEvent(QKeyEvent *event);
  void populate(void);
  void resetWidgets(void);
  void shareSelected(const QString &keyType);
  void showError(const QString &error);

 private slots:
  void slotClose(void);
  void slotItemChanged(QTreeWidgetItem *item, int column);
  void slotMenuAction(void);
};

#endif
