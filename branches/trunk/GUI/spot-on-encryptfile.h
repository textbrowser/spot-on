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

#ifndef _spoton_encryptfile_h_
#define _spoton_encryptfile_h_

#include <QFuture>
#include <QMainWindow>

#include "ui_spot-on-encryptfile.h"

class QKeyEvent;

class spoton_encryptfile: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_encryptfile(void);
  ~spoton_encryptfile();
  static const int LENGTH_OF_INITIALIZATION_VECTOR = 16;
  void show(QWidget *parent);

 private:
  QFuture<void> m_future;
  Ui_spoton_encryptfile ui;
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
  bool event(QEvent *event);
#endif
#endif
  void decrypt(const QString &fileName,
	       const QString &destination,
	       const QList<QVariant> &credentials,
	       const QString &modeOfOperation);
  void encrypt(const bool sign,
	       const QString &fileName,
	       const QString &destination,
	       const QList<QVariant> &credentials,
	       const QString &modeOfOperation);
  void keyPressEvent(QKeyEvent *event);

 private slots:
  void slotCancel(void);
  void slotCipherTypeChanged(const QString &text);
  void slotClose(void);
  void slotCompleted(const QString &error);
  void slotCompleted(const int percentage);
  void slotConvert(void);
  void slotReset(void);
  void slotSelect(void);
  void slotSetIcons(void);
  void slotStatus(const QString &status);

 signals:
  void completed(const QString &error);
  void completed(const int percentage);
  void status(const QString &status);
};

#endif
