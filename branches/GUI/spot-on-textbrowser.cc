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
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
#include <QRegularExpression>
#endif

#include "spot-on-textbrowser.h"

spoton_textbrowser::spoton_textbrowser(QWidget *parent):QTextBrowser(parent)
{
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
  QTextBrowser::append(removeSpecial(text));
}

void spoton_textbrowser::setContent(const QByteArray &text)
{
  QTextBrowser::setHtml(removeSpecial(text));
}

void spoton_textbrowser::setHtml(const QString &text)
{
  QTextBrowser::setHtml(removeSpecial(text));
}
