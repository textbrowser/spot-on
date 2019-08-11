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

#include <QMainWindow>

#include "ui_spot-on-rosetta.h"

class QKeyEvent;
class spoton;
class spoton_crypt;

class spoton_rosetta: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_rosetta(void);
  void setName(const QString &text);
  void show(spoton *parent);

 private:
  Ui_spoton_rosetta ui;
  spoton *m_parent;
  QByteArray copyMyRosettaPublicKey(void) const;
  void keyPressEvent(QKeyEvent *event);
  void populateContacts(void);

 private slots:
  void slotAddContact(void);
  void slotClear(void);
  void slotClose(void);
  void slotConvert(void);
  void slotCopyConverted(void);
  void slotCopyMyRosettaPublicKey(void);
  void slotCopyOrPaste(void);
  void slotDecryptToggled(bool state);
  void slotDelete(void);
  void slotEncryptToggled(bool state);
  void slotRename(void);
  void slotSaveName(void);
  void slotSetIcons(void);
};

#endif
