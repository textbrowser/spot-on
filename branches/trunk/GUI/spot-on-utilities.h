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

#include <QApplication>
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
#else
#include <QDesktopWidget>
#endif
#include <QLineEdit>
#include <QScreen>
#include <QTextEdit>
#include <QWidget>

class spoton_utilities
{
 public:
  static void centerWidget(QWidget *child, QWidget *parent)
  {
    if(!child || !parent)
      return;

    /*
    ** From QDialog.
    */

#ifdef Q_WS_X11
    if(X11->isSupportedByWM(ATOM(_NET_WM_FULL_PLACEMENT)))
      return;
#endif

#ifdef Q_OS_SYMBIAN
    /*
    ** Perhaps implement symbianAdjustedPosition().
    */
#endif

    QPoint p(0, 0);
    int extrah = 0, extraw = 0;

    if(parent)
      parent = parent->window();

    QRect desk;

#if (QT_VERSION < QT_VERSION_CHECK(6, 0, 0))
    int scrn = 0;

    if(parent)
      scrn = QApplication::desktop()->screenNumber(parent);
#if QT_VERSION < QT_VERSION_CHECK(5, 11, 0)
    else if(QApplication::desktop()->isVirtualDesktop())
      scrn = QApplication::desktop()->screenNumber(QCursor::pos());
#endif
    else
      scrn = QApplication::desktop()->screenNumber(child);

#if QT_VERSION < QT_VERSION_CHECK(5, 11, 0)
    desk = QApplication::desktop()->availableGeometry(scrn);
#else
    desk = QGuiApplication::screens().value(scrn) ?
      QGuiApplication::screens().value(scrn)->geometry() : QRect();
#endif
#else
    auto screen = QGuiApplication::screenAt(child->pos());

    if(screen)
      desk = screen->geometry();
#endif

    auto const list = QApplication::topLevelWidgets();

    for(int i = 0; (extrah == 0 || extraw == 0) && i < list.size(); ++i)
      {
	auto current = list.at(i);

	if(current && current->isVisible())
	  {
	    auto const frameh = current->geometry().y() - current->y();
	    auto const framew = current->geometry().x() - current->x();

	    extrah = qMax(extrah, frameh);
	    extraw = qMax(extraw, framew);
	  }
      }

    if(extrah == 0 || extrah >= 40 || extraw == 0 || extraw >= 10)
      {
	extrah = 40;
	extraw = 10;
      }

    if(parent)
      {
	auto const pp = parent->mapToGlobal(QPoint(0,0));

	p = QPoint(pp.x() + parent->width() / 2,
		   pp.y() + parent->height() / 2);
      }
    else
      p = QPoint(desk.x() + desk.width() / 2, desk.y() + desk.height() / 2);

    p = QPoint(p.x() - child->width() / 2 - extraw,
	       p.y() - child->height() / 2 - extrah);

    if(p.x() + extraw + child->width() > desk.x() + desk.width())
      p.setX(desk.x() + desk.width() - child->width() - extraw);

    if(p.x() < desk.x())
      p.setX(desk.x());

    if(p.y() + extrah + child->height() > desk.y() + desk.height())
      p.setY(desk.y() + desk.height() - child->height() - extrah);

    if(p.y() < desk.y())
      p.setY(desk.y());

    child->move(p);
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
};

#endif
