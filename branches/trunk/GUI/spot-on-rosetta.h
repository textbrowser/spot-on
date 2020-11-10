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

#include <QPointer>

#ifdef SPOTON_GPGME_ENABLED
extern "C"
{
#include <gpgme.h>
}
#endif

#include "ui_spot-on-rosetta.h"

class QKeyEvent;
class spoton;
class spoton_rosetta_gpg_import;

class spoton_rosetta: public QMainWindow
{
  Q_OBJECT

 public:
  enum DestinationTypes
  {
    GPG = 0,
    ROSETTA,
    ZZZ
  };

  spoton_rosetta(void);
  void setName(const QString &text);
  void show(spoton *parent);

 private:
  Ui_spoton_rosetta ui;
  QPointer<spoton> m_parent;
#ifdef SPOTON_GPGME_ENABLED
  QPointer<spoton_rosetta_gpg_import> m_gpgImport;
#endif
  QByteArray copyMyRosettaPublicKey(void) const;
  QByteArray gpgEncrypt(const QByteArray &receiver,
			const QByteArray &sender) const;
#ifdef SPOTON_GPGME_ENABLED
  static QPointer<spoton_rosetta> s_rosetta;
  static gpgme_error_t gpgPassphrase(void *hook,
				     const char *uid_hint,
				     const char *passphrase_info,
				     int prev_was_bad,
				     int fd);
#endif
  void keyPressEvent(QKeyEvent *event);
  void populateContacts(void);
  void resizeEvent(QResizeEvent *event);
  void sortContacts(void);
  void toDesktop(void) const;

 private slots:
  void slotAddContact(void);
  void slotClear(void);
  void slotClearClipboardBuffer(void);
  void slotClose(void);
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
  void slotImportGPGKeys(void);
  void slotParticipantAdded(const QString &type);
  void slotRemoveGPGKeys(void);
  void slotRename(void);
  void slotSaveName(void);
  void slotSetIcons(void);
  void slotSplitterMoved(int pox, int index);

 signals:
  void gpgKeysRemoved(void);
  void participantAdded(const QString &type);
  void participantDeleted(const QString &oid, const QString &type);
  void participantNameChanged(const QByteArray &publicKeyHash,
			      const QString &name);
};

#endif
