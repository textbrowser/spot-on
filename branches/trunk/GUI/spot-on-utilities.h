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

#ifndef _spoton_utilities_h_
#define _spoton_utilities_h_

#include <QLineEdit>
#include <QPointer>
#include <QTabWidget>
#include <QTextEdit>
#include <QTimer>

class spoton_utilities_private: public QObject
{
  Q_OBJECT

 public:
  spoton_utilities_private(void):QObject()
  {
    m_centerTimer.setInterval(0);
    m_centerTimer.setSingleShot(true);
    connect(&m_centerTimer,
	    SIGNAL(timeout(void)),
	    this,
	    SLOT(slotCenterChildren(void)));
  }

  ~spoton_utilities_private()
  {
    m_centerTimer.stop();
  }

  void centerWidget(QWidget *child, QWidget *parent)
  {
    m_widgetsToCenter << QPair<QPointer<QWidget>, QPointer<QWidget> >
      (child, parent);

    if(!m_centerTimer.isActive())
      m_centerTimer.start();
  }

 private:
  QTimer m_centerTimer;
  QVector<QPair<QPointer<QWidget>, QPointer<QWidget> > > m_widgetsToCenter;

 private slots:
  void slotCenterChildren(void)
  {
    for(int i = 0; i < m_widgetsToCenter.size(); i++)
      {
	auto pair(m_widgetsToCenter.at(i));

	if(!pair.first || !pair.second)
	  continue;

	auto child(pair.first->geometry());

	child.moveCenter(pair.second->geometry().center());
	pair.first->setGeometry(child);
      }

    m_widgetsToCenter.clear();
  }
};

class spoton_utilities
{
 public:
  static void centerWidget(QWidget *child, QWidget *parent)
  {
    if(!child || !parent)
      return;

    s_utilitiesPrivate.centerWidget(child, parent);
  }

  static void enableTabDocumentMode(QWidget *parent)
  {
    if(!parent)
      return;

    foreach(auto tab, parent->findChildren<QTabWidget *> ())
      if(tab)
	tab->setDocumentMode(true);
  }

  static void searchText(QLineEdit *find,
			 QTextEdit *text,
			 const QPalette &originalFindPalette,
			 const QTextDocument::FindFlags options)
  {
    if(!find || !text)
      return;

    if(find->text().isEmpty())
      {
	find->setPalette(originalFindPalette);
	find->setProperty("found", true);
	text->moveCursor(QTextCursor::Left);
      }
    else if(!text->find(find->text(), options))
      {
	auto const found = find->property("found").toBool();

	if(found)
	  find->setProperty("found", false);
	else
	  {
	    QColor const color(240, 128, 128); // Light Coral
	    auto palette(find->palette());

	    palette.setColor(find->backgroundRole(), color);
	    find->setPalette(palette);
	  }

	if(options)
	  text->moveCursor(QTextCursor::End);
	else
	  text->moveCursor(QTextCursor::Start);

	if(found)
	  searchText(find, text, originalFindPalette, options);
      }
    else
      {
	find->setPalette(originalFindPalette);
	find->setProperty("found", true);
      }
  }

 private:
  spoton_utilities(void);
  static spoton_utilities_private s_utilitiesPrivate;
};

#endif
