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
#include <QDragEnterEvent>
#include <QMimeData>
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
#include <QRegularExpression>
#endif
#include <QtDebug>

#include "Common/spot-on-misc.h"
#include "spot-on-textbrowser.h"

spoton_textbrowser::spoton_textbrowser(QWidget *parent):QTextBrowser(parent)
{
  m_removeSpecial = true;
}

spoton_textbrowser::~spoton_textbrowser()
{
}

QString spoton_textbrowser::removeSpecial(const QString &text)
{
  /*
  ** Let's remove <img> tags.
  */

  auto html(text);

  {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QRegularExpression rx
      ("\\<img[^\\>]*\\s*=\\s*\"([^\"]*)\"[^\\>]*\\>",
       QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch match;
    int pos = 0;

    do
      {
	while((match = rx.match(html, pos)).hasMatch())
	  {
	    html.remove(pos, match.capturedLength());
	    pos += match.capturedLength();
	  }

	match = rx.match(html);

	if(!match.hasMatch())
	  break;
	else
	  pos = match.capturedLength();
      }
    while(pos >= 0);
#else
    QRegExp rx
      ("\\<img[^\\>]*\\s*=\\s*\"([^\"]*)\"[^\\>]*\\>", Qt::CaseInsensitive);
    int pos = 0;

    do
      {
	while((pos = rx.indexIn(html, pos)) != -1)
	  {
	    html.remove(pos, rx.matchedLength());
	    pos += rx.matchedLength();
	  }

	pos = rx.indexIn(html, 0);
      }
    while(pos >= 0);
#endif
  }

  {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QRegularExpression rx
      ("\\<img[^\\>]*\\s*=\\s*\'([^\']*)\'[^\\>]*\\>",
       QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch match;
    int pos = 0;

    do
      {
	while((match = rx.match(html, pos)).hasMatch())
	  {
	    html.remove(pos, match.capturedLength());
	    pos += match.capturedLength();
	  }

	match = rx.match(html);

	if(!match.hasMatch())
	  break;
	else
	  pos = match.capturedLength();
      }
    while(pos >= 0);
#else
    QRegExp rx
      ("\\<img[^\\>]*\\s*=\\s*\'([^\']*)\'[^\\>]*\\>", Qt::CaseInsensitive);
    int pos = 0;

    do
      {
	while((pos = rx.indexIn(html, pos)) != -1)
	  {
	    html.remove(pos, rx.matchedLength());
	    pos += rx.matchedLength();
	  }

	pos = rx.indexIn(html, 0);
      }
    while(pos >= 0);
#endif
  }

  return html;
}

void spoton_textbrowser::append(const QString &text)
{
  if(m_removeSpecial)
    QTextBrowser::append(removeSpecial(text));
  else
    QTextBrowser::append(text);
}

void spoton_textbrowser::dragEnterEvent(QDragEnterEvent *event)
{
  QTextBrowser::dragEnterEvent(event);
  m_dropFile = QFileInfo();

  if(event && event->mimeData())
    {
      m_dropFile.setFile
	(QUrl::fromUserInput(event->mimeData()->text()).toLocalFile());

      if(toPlainText().
	 contains(QString("%1 (%2)").
		  arg(m_dropFile.absoluteFilePath()).
		  arg(spoton_misc::prettyFileSize(m_dropFile.size()))))
	{
	  event->ignore();
	  m_dropFile = QFileInfo();
	}
      else
	{
	  if(m_dropFile.isFile() && m_dropFile.isReadable())
	    event->accept();
	  else
	    m_dropFile = QFileInfo();
	}
    }
}

void spoton_textbrowser::dragLeaveEvent(QDragLeaveEvent *event)
{
  QTextBrowser::dragLeaveEvent(event);
  m_dropFile = QFileInfo();
}

void spoton_textbrowser::dragMoveEvent(QDragMoveEvent *event)
{
  if(event && m_dropFile.isFile() && m_dropFile.isReadable())
    event->accept();
  else
    {
      QTextBrowser::dragMoveEvent(event);
      m_dropFile = QFileInfo();
    }
}

void spoton_textbrowser::dropEvent(QDropEvent *event)
{
  if(event && m_dropFile.isFile() && m_dropFile.isReadable())
    {
      if(toPlainText().
	 contains(QString("%1 (%2)").
		  arg(m_dropFile.absoluteFilePath()).
		  arg(spoton_misc::prettyFileSize(m_dropFile.size()))))
	event->ignore();
      else
	{
	  append
	    (QString("<a href=\"%1 (%2)\">%1 (%2)</a>").
	     arg(m_dropFile.absoluteFilePath()).
	     arg(spoton_misc::prettyFileSize(m_dropFile.size())));
	  event->accept();
	}

      m_dropFile = QFileInfo();
    }
  else
    QTextBrowser::dropEvent(event);
}

void spoton_textbrowser::setContent(const QByteArray &text)
{
  if(m_removeSpecial)
    QTextBrowser::setHtml(removeSpecial(text));
  else
    QTextBrowser::setHtml(text);
}

void spoton_textbrowser::setHtml(const QString &text)
{
  if(m_removeSpecial)
    QTextBrowser::setHtml(removeSpecial(text));
  else
    QTextBrowser::setHtml(text);
}

void spoton_textbrowser::setRemoveSpecial(const bool state)
{
  m_removeSpecial = state;
}
