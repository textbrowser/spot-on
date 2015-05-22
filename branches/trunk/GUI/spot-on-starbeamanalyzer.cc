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

#include <QCheckBox>
#include <QClipboard>
#include <QKeyEvent>
#include <QTableWidgetItem>
#include <QtCore>

#include "spot-on.h"
#include "spot-on-defines.h"
#include "spot-on-starbeamanalyzer.h"

spoton_starbeamanalyzer::spoton_starbeamanalyzer(QWidget *parent):
  QMainWindow(parent)
{
  ui.setupUi(this);
  setWindowTitle
    (tr("%1: StarBeam Analyzer").
     arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#if QT_VERSION >= 0x050000
  setWindowFlags(windowFlags() & ~Qt::WindowFullscreenButtonHint);
#endif
  statusBar()->setSizeGripEnabled(false);
#endif
  ui.tableWidget->setColumnHidden
    (ui.tableWidget->columnCount() - 1, true); // OID
  ui.tableWidget->setColumnHidden
    (ui.tableWidget->columnCount() - 2, true); // Results
  ui.tableWidget->horizontalHeader()->setSortIndicator(4, Qt::AscendingOrder);
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(ui.clear,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDelete(void)));
  connect(ui.copy,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopy(void)));
  connect(ui.tableWidget,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotItemSelected(void)));
  connect(this,
	  SIGNAL(excessiveProblems(const QString &)),
	  this,
	  SLOT(slotExcessiveProblems(const QString &)));
  connect(this,
	  SIGNAL(potentialProblem(const QString &,
				  const qint64)),
	  this,
	  SLOT(slotPotentialProblem(const QString &,
				    const qint64)));
  connect(this,
	  SIGNAL(updatePercent(const QString &,
			       const int)),
	  this,
	  SLOT(slotUpdatePercent(const QString &,
				 const int)));
  slotSetIcons();
}

spoton_starbeamanalyzer::~spoton_starbeamanalyzer()
{
  QMutableHashIterator<QString, QPair<QAtomicInt *, QFuture<void> > >
    it(m_hash);

  while(it.hasNext())
    {
      it.next();

      QPair<QAtomicInt *, QFuture<void> > pair(it.value());

      if(pair.first)
	pair.first->fetchAndAddRelaxed(1);

      pair.second.waitForFinished();
      delete pair.first;
      it.remove();
    }
}

void spoton_starbeamanalyzer::slotClose(void)
{
  close();
}

void spoton_starbeamanalyzer::show(QWidget *parent)
{
  QMainWindow::show();
  raise();

  if(parent)
    {
      QPoint p(parent->pos());
      int X = 0;
      int Y = 0;

      if(parent->width() >= width())
	X = p.x() + (parent->width() - width()) / 2;
      else
	X = p.x() - (width() - parent->width()) / 2;

      if(parent->height() >= height())
	Y = p.y() + (parent->height() - height()) / 2;
      else
	Y = p.y() - (height() - parent->height()) / 2;

      move(X, Y);
    }
}

void spoton_starbeamanalyzer::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

void spoton_starbeamanalyzer::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nuove").toString().
		  toLower());

  if(!(iconSet == "everaldo" || iconSet == "nouve" || iconSet == "nuvola"))
    iconSet = "nouve";

  ui.clear->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
bool spoton_starbeamanalyzer::event(QEvent *event)
{
  if(event)
    if(event->type() == QEvent::WindowStateChange)
      if(windowState() == Qt::WindowNoState)
	{
	  /*
	  ** Minimizing the window on OS 10.6.8 and Qt 5.x will cause
	  ** the window to become stale once it has resurfaced.
	  */

	  hide();
	  show(0);
	  update();
	}

  return QMainWindow::event(event);
}
#endif
#endif

bool spoton_starbeamanalyzer::add(const QString &fileName,
				  const QString &oid,
				  const QString &pulseSize,
				  const QString &totalSize)
{
  if(fileName.isEmpty() || oid.trimmed().isEmpty() ||
     pulseSize.trimmed().isEmpty() || totalSize.trimmed().isEmpty())
    return false;

  if(m_hash.contains(fileName))
    return false;

  ui.tableWidget->setSortingEnabled(false);

  QCheckBox *checkBox = 0;
  QTableWidgetItem *item = 0;
  int row = ui.tableWidget->rowCount();

  ui.tableWidget->setRowCount(row + 1);
  checkBox = new QCheckBox();
  checkBox->setProperty("filename", fileName);
  connect(checkBox,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotCancel(bool)));
  ui.tableWidget->setCellWidget(row, 0, checkBox);
  item = new QTableWidgetItem("0");
  item->setBackground(QBrush(QColor("lightgreen")));
  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
  ui.tableWidget->setItem(row, 1, item);
  item = new QTableWidgetItem(pulseSize.trimmed());
  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
  ui.tableWidget->setItem(row, 2, item);
  item = new QTableWidgetItem(totalSize.trimmed());
  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
  ui.tableWidget->setItem(row, 3, item);
  item = new QTableWidgetItem(fileName);
  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
  ui.tableWidget->setItem(row, 4, item);
  item = new QTableWidgetItem();
  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
  ui.tableWidget->setItem(row, 5, item);
  item = new QTableWidgetItem(oid.trimmed());
  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
  ui.tableWidget->setItem(row, 6, item);
  ui.tableWidget->setSortingEnabled(true);

  QAtomicInt *interrupt = new QAtomicInt();
  QFuture<void> future = QtConcurrent::run
    (this,
     &spoton_starbeamanalyzer::analyze,
     fileName,
     pulseSize,
     totalSize,
     interrupt);
  QPair<QAtomicInt *, QFuture<void> > pair;

  pair.first = interrupt;
  pair.second = future;
  m_hash.insert(fileName, pair);
  return true;
}

void spoton_starbeamanalyzer::analyze(const QString &fileName,
				      const QString &pulseSize,
				      const QString &totalSize,
				      QAtomicInt *interrupt)
{
  int ps = pulseSize.trimmed().toInt();

  if(ps <= 0)
    {
      emit updatePercent(fileName, 0);
      return;
    }

  QFile file(fileName);

  if(file.open(QIODevice::ReadOnly))
    {
      QByteArray bytes(ps, 0);
      bool excessive = false;
      bool first = true;
      bool interrupted = false;
      int percent = 0;
      int problems = 0;
      qint64 nPulses = 0;
      qint64 pos = 0;
      qint64 rc = 0;
      qint64 ts = qMax(static_cast<long long> (1),
		       qMax(file.size(), totalSize.trimmed().toLongLong()));

      nPulses = ts / ps;

      while((rc = file.read(bytes.data(), bytes.length())) > 0)
	{
	  if(bytes.count('\0') == bytes.length())
	    {
	      problems += 1;

	      double p = 100 * (static_cast<double> (problems) /
				static_cast<double> (nPulses));

	      if(p >= 75.00)
		{
		  excessive = true;
		  break;
		}

	      /*
	      ** Potential problem.
	      */

	      if(first)
		{
		  if(pos - ps >= 0)
		    emit potentialProblem(fileName, pos - ps);

		  first = false;
		}

	      emit potentialProblem(fileName, pos);
	    }

	  pos += ps;
	  percent = static_cast<int>
	    (qMin(static_cast<double> (100),
		  100 * static_cast<double> (file.pos()) /
		  static_cast<double> (ts)));

	  if(percent > 0 && percent % 5 == 0)
	    emit updatePercent(fileName, percent);

	  if(interrupt && interrupt->fetchAndAddRelaxed(0))
	    {
	      interrupted = true;
	      break;
	    }
	}

      file.close();
      first = true;

      /*
      ** Now that we've reviewed the file, let's review shadow portions.
      */

      if(!excessive && !interrupted)
	while(percent < 100)
	  {
	    problems += 1;

	    double p = 100 * (static_cast<double> (problems) /
			      static_cast<double> (nPulses));

	    if(p >= 75.00)
	      {
		excessive = true;
		break;
	      }

	    if(first)
	      {
		if(pos - ps >= 0)
		  emit potentialProblem(fileName, pos - ps);

		first = false;
	      }

	    emit potentialProblem(fileName, pos);
	    pos += ps;
	    percent = static_cast<int>
	      (qMin(static_cast<double> (100),
		    100 * static_cast<double> (pos) /
		    static_cast<double> (ts)));

	    if(percent > 0 && percent % 5 == 0)
	      emit updatePercent(fileName, percent);

	    if(interrupt && interrupt->fetchAndAddRelaxed(0))
	      {
		interrupted = true;
		break;
	      }
	  }

      if(excessive)
	emit excessiveProblems(fileName);
      else if(!interrupted)
	{
	  if(rc == -1)
	    emit updatePercent(fileName, 0);
	  else
	    emit updatePercent(fileName, 100);
	}
    }
  else
    emit updatePercent(fileName, 0);
}

void spoton_starbeamanalyzer::slotUpdatePercent(const QString &fileName,
						const int percent)
{
  QList<QTableWidgetItem *> list
    (spoton::findItems(ui.tableWidget, fileName, 4));

  if(!list.isEmpty())
    {
      QTableWidgetItem *item = ui.tableWidget->item
	(list.at(0)->row(), 1); // Percent

      if(item)
	{
	  if(percent >= 0 && percent <= 100)
	    item->setText(QString("%1%").arg(percent));
	  else if(percent < 0)
	    item->setText("0%");
	  else
	    item->setText("100%");
	}
    }
}

void spoton_starbeamanalyzer::slotDelete(void)
{
  int row = ui.tableWidget->currentRow();

  if(row < 0)
    return;

  QTableWidgetItem *item = ui.tableWidget->item(row, 4); // File

  if(!item)
    return;

  if(!m_hash.contains(item->text()))
    return;

  QPair<QAtomicInt *, QFuture<void> > pair = m_hash[item->text()];

  if(pair.first)
    pair.first->fetchAndAddRelaxed(1);

  pair.second.waitForFinished();
  delete pair.first;
  m_hash.remove(item->text());
  ui.results->clear();
  ui.tableWidget->removeRow(row);
}

void spoton_starbeamanalyzer::slotCancel(bool state)
{
  Q_UNUSED(state);

  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(!checkBox)
    return;

  if(m_hash.contains(checkBox->property("filename").toString()))
    {
      QAtomicInt *interrupt = m_hash
	[checkBox->property("filename").toString()].first;

      if(interrupt)
	interrupt->fetchAndAddRelaxed(1);
    }

  checkBox->setEnabled(false);
}

void spoton_starbeamanalyzer::slotPotentialProblem(const QString &fileName,
						   const qint64 pos)
{
  QList<QTableWidgetItem *> list
    (spoton::findItems(ui.tableWidget, fileName, 4));

  if(!list.isEmpty())
    {
      QTableWidgetItem *item = ui.tableWidget->item
	(list.at(0)->row(), 1); // Percent

      if(item)
	item->setBackground(QBrush(QColor(240, 128, 128)));

      item = ui.tableWidget->item(list.at(0)->row(), 5); // Results

      if(item)
	{
	  QString text(item->text());

	  if(!text.isEmpty())
	    text.append(",");

	  text.append(QString::number(pos));
	  item->setText(text);
	}
    }
}

void spoton_starbeamanalyzer::slotItemSelected(void)
{
  int row = ui.tableWidget->currentRow();

  if(row < 0)
    return;

  QString data("");
  QString fileName("");
  QString missingLinks("");
  QString pulseSize("");

  QTableWidgetItem *item = ui.tableWidget->item(row, 2); // Pulse Size

  if(item)
    pulseSize = item->text();

  item = ui.tableWidget->item(row, 4); // File Name

  if(item)
    fileName = QFileInfo(item->text()).fileName();

  item = ui.tableWidget->item(row, 5); // Results;

  if(item)
    missingLinks = item->text();

  data.append("magnet:?");
  data.append(QString("fn=%1&").arg(fileName));
  data.append(QString("ps=%1&").arg(pulseSize));
  data.append(QString("ml=%1&").arg(missingLinks));
  data.append("xt=urn:starbeam-missing-links");
  ui.results->setText(data);
}

void spoton_starbeamanalyzer::slotCopy(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(ui.results->toPlainText());
}

void spoton_starbeamanalyzer::slotExcessiveProblems(const QString &fileName)
{
  QList<QTableWidgetItem *> list
    (spoton::findItems(ui.tableWidget, fileName, 4));

  if(!list.isEmpty())
    {
      QTableWidgetItem *item =
	ui.tableWidget->item(list.at(0)->row(), 5); // Results

      if(item)
	item->setText
	  (tr("The number of pulses that are missing is "
	      "excessive (missing pulses / total pulses >= 75%)."));
    }
}
