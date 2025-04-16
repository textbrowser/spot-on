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

#ifndef _spoton_smpwindow_h_
#define _spoton_smpwindow_h_

#include <QPointer>

#include "spot-on-smp.h"
#include "ui_spot-on-smpwindow.h"

class QKeyEvent;
class spoton;

class spoton_smpwindow_smp
{
 public:
  spoton_smpwindow_smp(const QString &guess, spoton *spoton)
  {
    m_smp = new spoton_smp(spoton);
    m_smp->setGuess(guess);
  }

  ~spoton_smpwindow_smp()
  {
    delete m_smp;
  }

  QByteArray m_publicKey;
  QHash<QByteArray, char> m_cache;
  QString m_keyType;
  QString m_name;
  qint64 m_oid;
  spoton_smp *m_smp;
};

class spoton_smpwindow: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_smpwindow(spoton *parent);
  ~spoton_smpwindow();
  QMap<QString, QByteArray> streams(const QStringList &keyTypes) const;
  void populateSecrets(void);
  void show(spoton *parent);

 private:
  QHash<QByteArray, spoton_smpwindow_smp *> m_smps;
  QPointer<spoton> m_parent;
  Ui_spoton_smpwindow m_ui;
  void generateSecretData(spoton_smpwindow_smp *smp);
  void keyPressEvent(QKeyEvent *event);
  void showError(const QString &error);

 private slots:
  void slotClose(void);
  void slotExecute(void);
  void slotGenerateData(void);
  void slotParticipantDeleted(const QString &oid, const QString &type);
  void slotParticipantNameChanged(const QByteArray &publicKeyHash,
				  const QString &name);
  void slotPrepareSMPObject(void);
  void slotPurgeSMPStateMachines(void);
  void slotRefresh(void);
  void slotRemove(void);
  void slotSMPMessageReceivedFromKernel(const QByteArrayList &list);
  void slotSaveCombinationBoxOption(int index);
  void slotSaveSpinBoxOption(int value);
  void slotSetIcons(void);
};

#endif
