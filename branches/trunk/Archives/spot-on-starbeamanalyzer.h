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

#ifndef _spoton_starbeamanalyzer_h_
#define _spoton_starbeamanalyzer_h_

#include <QFuture>
#include <QHash>
#include <QMainWindow>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif

#include "ui_spot-on-starbeamanalyzer.h"

class QAtomicInt;
class QKeyEvent;
class QTableWidgetItem;

class spoton_starbeamanalyzer: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_starbeamanalyzer(QWidget *parent);
  ~spoton_starbeamanalyzer();
  bool add(const QString &fileName,
	   const QString &oid,
	   const QString &pulseSize,
	   const QString &totalSize);
  void show(QWidget *parent);

 private:
  QHash<QString, QPair<QAtomicInt *, QFuture<void> > > m_hash;
  Ui_spoton_starbeamanalyzer ui;
  void analyze(const QString &fileName,
	       const QString &pulseSize,
	       const QString &totalSize,
	       QAtomicInt *interrupt);
  void keyPressEvent(QKeyEvent *event);

 private slots:
  void slotCancel(bool state);
  void slotClose(void);
  void slotCopy(void);
  void slotDelete(void);
  void slotExcessiveProblems(const QString &fileName);
  void slotItemSelected(void);
  void slotPotentialProblem(const QString &fileName, const qint64 pos);
  void slotSetIcons(void);
  void slotUpdatePercent(const QString &fileName, const int percent);

 signals:
  void excessiveProblems(const QString &fileName);
  void potentialProblem(const QString &fileName, const qint64 pos);
  void updatePercent(const QString &fileName, const int percent);
};

#endif
