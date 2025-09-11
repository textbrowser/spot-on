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

#ifndef _spoton_rosetta_h_
#define _spoton_rosetta_h_

#include <QFileInfo>
#include <QFuture>
#include <QPointer>
#include <QTimer>

#ifdef SPOTON_GPGME_ENABLED
extern "C"
{
#include <gpgme.h>
}
#endif

#include "ui_spot-on-rosetta-gpg-new-keys.h"
#include "ui_spot-on-rosetta.h"

class QKeyEvent;
class spoton;
class spoton_rosetta_gpg_import;

class spoton_rosetta: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_rosetta(void);
  ~spoton_rosetta();
  QLineEdit *attachmentsGPGPath(void) const;
  void setName(const QString &text);
  void setParent(spoton *parent);
  void show(spoton *parent);

 private:
  enum class DestinationTypes
  {
    GPG = 0,
    ROSETTA,
    ZZZ
  };

  enum class GPGMessage
  {
    Destination = 0,
    InsertDate,
    Message,
    Origin,
    Size
  };

  QFuture<void> m_prepareGPGStatusMessagesFuture;
  QFuture<void> m_readPrisonBluesFuture;
  QMap<QString, QString> m_gpgMessages;
  QPointer<spoton> m_parent;
#ifdef SPOTON_GPGME_ENABLED
  QPointer<spoton_rosetta_gpg_import> m_gpgImport;
#endif
  QTimer m_gpgPullTimer;
  QTimer m_gpgReadMessagesTimer;
  QTimer m_gpgStatusTimer;
  QTimer m_prisonBluesReadTimer;
  QTimer m_prisonBluesTimer;
  QVector<QByteArray> m_gpgFingerprints;
  Ui_spoton_gpg_new_keys m_gpgNewKeysUi;
  Ui_spoton_rosetta ui;
  QByteArray copyMyRosettaPublicKey(void) const;
  QIcon offlineIcon(void) const;
  QIcon onlineIcon(void) const;
  QMap<QString, QByteArray> gpgEmailAddresses(void) const;
  static QByteArray gpgEncrypt(bool &ok,
			       const QByteArray &message,
			       const QByteArray &receiver,
			       const QByteArray &sender,
			       const bool askForPassphrase,
			       const bool sign);
#ifdef SPOTON_GPGME_ENABLED
  static QPointer<spoton_rosetta> s_rosetta;
  static QString s_status;
  static gpgme_error_t gpgPassphrase(void *hook,
				     const char *uid_hint,
				     const char *passphrase_info,
				     int prev_was_bad,
				     int fd);
#endif
  void closeEvent(QCloseEvent *event);
  void createGPGImportObject(void);
  void keyPressEvent(QKeyEvent *event);
  void populateContacts(void);
  void populateGPGEmailAddresses(void);
  void prepareGPGAttachmentsProgramCompleter(void);
  void prepareGPGStatusMessages
    (const QByteArray &sender,
     const QList<QByteArray> &publicKeys,
     const QList<QFileInfo> &list,
     const QStringList &fingerprints);
  void prisonBluesProcess(const bool pullOnly);
  void publishAttachments
    (const QString &destination,
     const QString &participant,
     const QStringList &attachments);
  void readPrisonBlues
    (const QByteArray &passphrase,
     const QList<QFileInfo> &directories,
     const QString &gpgProgram,
     const QVector<QByteArray> &vector);
  void resizeEvent(QResizeEvent *event);
  void saveGPGMessage(const QMap<GPGMessage, QVariant> &map);
  void showInformationMessage(const QString &message);
  void showMessage(const QString &message, const int milliseconds = 0);
  void sortContacts(void);
  void toDesktop(void);

 private slots:
  void slotAddContact(void);
  void slotAttachForGPG(void);
  void slotClear(void);
  void slotClearClipboardBuffer(void);
  void slotContactsChanged(int index);
  void slotConvertDecrypt(void);
  void slotConvertEncrypt(void);
  void slotCopyDecrypted(void);
  void slotCopyEncrypted(void);
  void slotCopyMyGPGKeys(void);
  void slotCopyMyRosettaPublicKeys(void);
  void slotCopyOrPaste(void);
  void slotDecryptClear(void);
  void slotDecryptReset(void);
  void slotDelete(void);
  void slotGPGFileProcessed(void);
  void slotGPGMessagesReadTimer(void);
  void slotGPGParticipantsChanged(QTableWidgetItem *item);
  void slotGPGPullTimer(void);
  void slotGPGStatusTimerTimeout(void);
  void slotImportGPGKeys(void);
  void slotLaunchPrisonBluesProcessesIfNecessary(const bool pullOnly);
  void slotNewGPGKeys(void);
  void slotParticipantAdded(const QString &type);
  void slotPopulateGPGEmailAddresses(void);
  void slotPrisonBluesTimeout(void);
  void slotProcessGPGMessage(const QByteArray &message);
  void slotPublishGPG(void);
  void slotPullGPG(void);
  void slotReadPrisonBluesTimeout(void);
  void slotRemoveGPGAttachment(const QUrl &url);
  void slotRemoveGPGKeys(void);
  void slotRemoveStoredINIGPGPassphrase(void);
  void slotRename(void);
  void slotSaveCheckBoxState(int state);
  void slotSaveGPGAttachmentProgram(void);
  void slotSaveGPGEmailIndex(int index);
  void slotSaveName(void);
  void slotSetIcons(void);
  void slotSplitterMoved(int pox, int index);
  void slotTabChanged(int index);
  void slotWriteGPG(void);

 signals:
  void gpgFileProcessed(void);
  void gpgKeysRemoved(void);
  void launchPrisonBluesProcessesIfNecessary(const bool pullOnly);
  void participantAdded(const QString &type);
  void participantDeleted(const QString &oid, const QString &type);
  void participantNameChanged
    (const QByteArray &publicKeyHash, const QString &name);
  void processGPGMessage(const QByteArray &message);
};

#endif
