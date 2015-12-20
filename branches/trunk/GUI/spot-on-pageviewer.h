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

#ifndef _spoton_pageviewer_h_
#define _spoton_pageviewer_h_

#include <QMainWindow>
#include <QSqlDatabase>

#include "ui_pageviewer.h"

class QPrinter;
class spoton_crypt;

class spoton_pageviewer: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_pageviewer(const QSqlDatabase &db,
		    const QString &urlHash,
		    spoton_crypt *crypt,
		    QWidget *parent);
  ~spoton_pageviewer();
  void setPage(const QString &text, const QUrl &url, const int compressedSize);

 private:
  QPalette m_originalFindPalette;
  QSqlDatabase m_database;
  QString m_urlHash;
  Ui_pageviewer m_ui;
  spoton_crypt *m_crypt;

 private slots:
  void slotFind(void);
  void slotFindInitialize(void);
  void slotPagePrintPreview(void);
  void slotPrint(QPrinter *printer);
  void slotRevisionChanged(int index);
};

#endif
