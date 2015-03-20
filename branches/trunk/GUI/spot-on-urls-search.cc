/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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

#include "spot-on.h"
#include "spot-on-defines.h"

void spoton::slotDiscover(void)
{
  discoverUrls();
}

void spoton::discoverUrls(void)
{
  if(!m_urlCommonCrypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Did you prepare common credentials?"));
      return;
    }

  if(!m_urlDatabase.isOpen())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please connect to a URL database."));
      return;
    }

  m_ui.searchfor->clear();
  m_ui.urls->clear();
  m_ui.url_pages->setText(": 1 :");

  QString querystr("");
  QString search(m_ui.search->text().trimmed());

  m_urlCurrentPage = 1;
  m_urlLimit = 10;
  m_urlOffset = 0;
  m_urlPages = 0;
  m_urlQuery.clear();

  if(search.isEmpty())
    {
      for(int i = 0; i < 10 + 6; i++)
	for(int j = 0; j < 10 + 6; j++)
	  {
	    QChar c1;
	    QChar c2;

	    if(i <= 9)
	      c1 = QChar(i + 48);
	    else
	      c1 = QChar(i + 97 - 10);

	    if(j <= 9)
	      c2 = QChar(j + 48);
	    else
	      c2 = QChar(j + 97 - 10);

	    if(i == 15 && j == 15)
	      querystr.append
		(QString("SELECT title, url, description, date_time_inserted "
			 "FROM spot_on_urls_%1%2 ").arg(c1).arg(c2));
	    else
	      querystr.append
		(QString("SELECT title, url, description, date_time_inserted "
			 "FROM spot_on_urls_%1%2 UNION ").arg(c1).arg(c2));
	  }

      querystr.append(" ORDER BY 4 DESC ");
      querystr.append(QString(" LIMIT %1 ").arg(m_urlLimit));
      querystr.append(QString(" OFFSET %1 ").arg(m_urlOffset));
    }
  else
    {
      QHash<QString, char> discovered;
      QString keywordclause("");
      QString searchfor(tr("Searched for... "));
      QStringList keywords
	(search.toLower().split(QRegExp("\\W+"), QString::SkipEmptyParts));
      bool ok = true;

      for(int i = 0; i < keywords.size(); i++)
	{
	  if(!discovered.contains(keywords.at(i)))
	    discovered[keywords.at(i)] = '0';
	  else
	    continue;

	  searchfor.append(keywords.at(i));

	  if(i != keywords.size() - 1)
	    searchfor.append("... ");

	  QByteArray keywordHash
	    (m_urlCommonCrypt->keyedHash(keywords.at(i).toUtf8(), &ok).
	     toHex());

	  if(!ok)
	    continue;

	  if(i == keywords.size() - 1)
	    keywordclause.append
	      (QString("SELECT url_hash FROM "
		       "spot_on_keywords_%1 WHERE keyword_hash = '%2' ").
	       arg(keywordHash.mid(0, 2).constData()).
	       arg(keywordHash.constData()));
	  else
	    keywordclause.append
	      (QString("SELECT url_hash FROM "
		       "spot_on_keywords_%1 WHERE keyword_hash = '%2' UNION ").
	       arg(keywordHash.mid(0, 2).constData()).
	       arg(keywordHash.constData()));
	}

      searchfor.append(".");
      m_ui.searchfor->setText(searchfor);

      for(int i = 0; i < 10 + 6; i++)
	for(int j = 0; j < 10 + 6; j++)
	  {
	    QChar c1;
	    QChar c2;

	    if(i <= 9)
	      c1 = QChar(i + 48);
	    else
	      c1 = QChar(i + 97 - 10);

	    if(j <= 9)
	      c2 = QChar(j + 48);
	    else
	      c2 = QChar(j + 97 - 10);

	    /*
	    ** For absolute correctness, we ought to use parameters in
	    ** the SQL queries.
	    */

	    if(i == 15 && j == 15)
	      querystr.append
		(QString("SELECT title, url, description, date_time_inserted "
			 "FROM spot_on_urls_%1%2 WHERE "
			 "url_hash IN (%3) ").
		 arg(c1).arg(c2).arg(keywordclause));
	    else
	      querystr.append
		(QString("SELECT title, url, description, date_time_inserted "
			 "FROM spot_on_urls_%1%2 WHERE "
			 "url_hash IN (%3) UNION ").
		 arg(c1).arg(c2).arg(keywordclause));
	  }

      querystr.append(" ORDER BY 4 DESC ");
      querystr.append(QString(" LIMIT %1 ").arg(m_urlLimit));
      querystr.append(QString(" OFFSET %1 ").arg(m_urlOffset));
    }

  m_urlQuery = querystr;
  showUrls(">", m_urlQuery);
}

void spoton::showUrls(const QString &link, const QString &querystr)
{
  if(!m_urlDatabase.isOpen())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QSqlQuery query(m_urlDatabase);
  quint64 count = 0;

  query.prepare(querystr);

  if(query.exec())
    {
      while(query.next())
	{
	  if(!count)
	    m_ui.urls->clear();

	  QString description("");
	  QString title("");
	  QUrl url;
	  bool ok = true;

	  description = QString::fromUtf8
	    (m_urlCommonCrypt->
	     decryptedAfterAuthenticated(QByteArray::
					 fromBase64(query.value(2).
						    toByteArray()),
					 &ok));

	  if(ok)
	    title = QString::fromUtf8
	      (m_urlCommonCrypt->
	       decryptedAfterAuthenticated(QByteArray::
					   fromBase64(query.value(0).
						      toByteArray()),
					   &ok));

	  if(ok)
	    url = QUrl::fromUserInput
	      (QString::
	       fromUtf8(m_urlCommonCrypt->
			decryptedAfterAuthenticated(QByteArray::
						    fromBase64(query.value(1).
							       toByteArray()),
						    &ok)));

	  if(ok)
	    {
	      QString html("");
	      QString scheme(url.scheme().toLower().trimmed());
	      QUrl deleteUrl(url);

	      if(scheme.contains("delete-"))
		{
		  scheme.remove("delete-");
		  url.setScheme(scheme);
		}

	      deleteUrl.setScheme(QString("delete-%1").arg(url.scheme()));
	      html.append
		(QString("<a href=\"%1\">%2</a> | "
			 "<a href=\"%3\">Remove URL</a>").
		 arg(url.toString()).arg(title).arg(deleteUrl.toString()));
	      html.append("<br>");
	      html.append(QString("<font color=\"green\" size=3>%1</font>").
			  arg(url.toString()));
	      html.append("<br>");
	      html.append(QString("<font color=\"gray\" size=3>%1</font>").
			  arg(description));
	      html.append("<br>");
	      html.append(QString("<font color=\"gray\" size=3>%1</font>").
			  arg(query.value(3).toString()));
	      html.append("<br>");
	      m_ui.urls->append(html);
	      count += 1;
	    }
	}

      if(count > 0)
	if(link == ">")
	  if(m_urlOffset / m_urlLimit >= m_urlPages)
	    m_urlPages += 1;

      m_ui.urls->horizontalScrollBar()->setValue(0);
      m_ui.urls->verticalScrollBar()->setValue(0);
    }

  QApplication::restoreOverrideCursor();

  if(!count)
    {
      if(link == ">")
	{
	  QString str(m_ui.url_pages->text());

	  str.remove(tr("Next"));
	  m_ui.url_pages->setText(str.trimmed());
	}

      return;
    }

  QString str("");
  quint64 lower = 0;
  quint64 upper = 0;

  // 1  ... 10.
  // 11 ... 20.
  // Find the lower and upper bounds.

  lower = m_urlOffset / m_urlLimit + 1;
  upper = lower + m_urlLimit;

  if(m_urlPages < upper)
    upper = m_urlPages;

  if(upper > m_urlLimit) // Number of pages to display.
    lower = upper - m_urlLimit;
  else
    lower = 1;

  for(quint64 i = lower; i <= upper; i++)
    if(i != m_urlCurrentPage)
      str.append(QString(" <a href=\"%1\">%1</a> ").arg(i));
    else
      str.append(QString(" : %1 : ").arg(i));

  if(count >= m_urlLimit)
    str.append(tr(" <a href=\">\">Next</a> "));

  if(m_urlCurrentPage != 1)
    str.prepend(tr(" <a href=\"<\">Previous</a> "));

  m_ui.url_pages->setText(str.trimmed());
}

void spoton::slotPageClicked(const QString &link)
{
  if(link == "<")
    {
      if(m_urlCurrentPage > 1)
	m_urlCurrentPage -= 1;
      else
	m_urlCurrentPage = 1;

      if(m_urlOffset > m_urlLimit)
	m_urlOffset -= m_urlLimit;
      else
	m_urlOffset = 0;

      m_urlQuery.remove(m_urlQuery.indexOf(" OFFSET "), m_urlQuery.length());
      m_urlQuery.append(QString(" OFFSET %1 ").arg(m_urlOffset));
      showUrls(link, m_urlQuery);
    }
  else if(link == ">")
    {
      m_urlCurrentPage += 1;
      m_urlOffset += m_urlLimit;
      m_urlQuery.remove(m_urlQuery.indexOf(" OFFSET "), m_urlQuery.length());
      m_urlQuery.append(QString(" OFFSET %1 ").arg(m_urlOffset));
      showUrls(link, m_urlQuery);
    }
  else
    {
      m_urlCurrentPage = link.toULongLong();
      m_urlOffset = m_urlLimit * (m_urlCurrentPage - 1);
      m_urlQuery.remove(m_urlQuery.indexOf(" OFFSET "), m_urlQuery.length());
      m_urlQuery.append(QString(" OFFSET %1 ").arg(m_urlOffset));
      showUrls(link, m_urlQuery);
    }
}
