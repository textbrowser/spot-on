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

#include <QApplication>
#include <QKeyEvent>
#include <QWheelEvent>

#include "spot-on-textedit.h"

spoton_textedit::spoton_textedit(QWidget *parent):QTextEdit(parent)
{
}

spoton_textedit::~spoton_textedit()
{
}

QSize spoton_textedit::sizeHint(void) const
{
  QFontMetrics fm(font());
  int h = fm.height();
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
  int w = fm.horizontalAdvance(QLatin1Char('a'));
#else
  int w = fm.width(QLatin1Char('a'));
#endif

  return QSize(w, h);
}

void spoton_textedit::keyPressEvent(QKeyEvent *event)
{
  if(event)
    if(event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return)
      {
	emit returnPressed();
	event->ignore();
	return;
      }

  QTextEdit::keyPressEvent(event);
}

void spoton_textedit::wheelEvent(QWheelEvent *event)
{
  if(event)
    event->ignore();
}
