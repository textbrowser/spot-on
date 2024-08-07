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

#include "spot-on-defines.h"
#include "spot-on.h"

void spoton::discoverUrls(void)
{
  if(!m_urlCommonCrypt)
    return;

  if(!m_urlDatabase.isOpen())
    return;

  m_urlQueryElapsedTimer.start();
  m_ui.searchfor->clear();
  m_ui.urls->clear();
  m_ui.url_pages->setText("| 1 |");

  QString querystr("");
  auto search(m_ui.search->text().toLower().trimmed());

  m_urlCurrentPage = 1;
  m_urlLimit = static_cast<quint64>
    (qBound(10, m_settings.value("gui/searchResultsPerPage", 10).toInt(),
	    m_optionsUi.searchResultsPerPage->maximum()));
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
		(QString("SELECT title, "       // 0
			 "url, "                // 1
			 "description, "        // 2
			 "date_time_inserted, " // 3
			 "LENGTH(content), "    // 4
			 "url_hash "            // 5
			 "FROM spot_on_urls_%1%2 ").arg(c1).arg(c2));
	    else
	      querystr.append
		(QString("SELECT title, "       // 0
			 "url, "                // 1
			 "description, "        // 2
			 "date_time_inserted, " // 3
			 "LENGTH(content), "    // 4
			 "url_hash "            // 5
			 "FROM spot_on_urls_%1%2 UNION ALL ").
		 arg(c1).arg(c2));
	  }

      querystr.append(" ORDER BY 4 DESC ");
      querystr.append(QString(" LIMIT %1 ").arg(m_urlLimit));
      querystr.append(QString(" OFFSET %1 ").arg(m_urlOffset));
    }
  else
    {
      QSet<QString> keywords;
      QString keywordsearch("");
      QStringList keywordsearches;
      auto intersect = false;
      auto ok = true;
      auto searchfor(tr("<html>Searched for... "));

      do
	{
	  int e = -1;
	  int s = -1;

	  s = search.indexOf('"');

	  if(s < 0)
	    break;

	  e = search.indexOf('"', s + 1);

	  if(e < 0 || e - s - 1 <= 0)
	    break;

	  auto const bundle(search.mid(s + 1, e - s - 1).trimmed());

	  if(bundle.isEmpty())
	    break;

	  if(!keywords.isEmpty())
	    searchfor.append(" <b>OR</b> ");

	  keywords.clear();
	  keywordsearch.clear();
	  search.remove(s, e - s + 1);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
	  auto const list
	    (bundle.split(QRegularExpression("\\W+"), Qt::SkipEmptyParts));
#else
	  auto const list
	    (bundle.split(QRegExp("\\W+"), QString::SkipEmptyParts));
#endif

	  for(int i = 0; i < list.size(); i++)
	    keywords.insert(list.at(i));

	  if(!keywords.isEmpty())
	    searchfor.append("(");

	  QSetIterator<QString> it(keywords);

	  while(it.hasNext())
	    {
	      auto const value(it.next());

	      searchfor.append(value);

	      if(it.hasNext())
		searchfor.append(" <b>AND</b> ");

	      auto const keywordHash
		(m_urlCommonCrypt->keyedHash(value.toUtf8(), &ok));

	      if(!ok)
		continue;

	      auto const keywordHashHex(keywordHash.toHex());

	      keywordsearch.append
		 (QString("SELECT url_hash FROM "
			  "spot_on_keywords_%1 WHERE "
			  "keyword_hash = '%2' ").
		  arg(keywordHashHex.mid(0, 2).constData()).
		  arg(keywordHashHex.constData()));

	      if(it.hasNext())
		keywordsearch.append(" INTERSECT ");
	    }

	  if(!keywords.isEmpty())
	    {
	      intersect = true;
	      searchfor.append(")");
	    }

	  keywordsearches << keywordsearch;
	}
      while(true);

      keywords.clear();
      keywordsearch.clear();

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
      auto const list
	(search.toLower().trimmed().
	 split(QRegularExpression("\\W+"), Qt::SkipEmptyParts));
#else
      auto const list
	(search.toLower().trimmed().
	 split(QRegExp("\\W+"), QString::SkipEmptyParts));
#endif

      for(int i = 0; i < list.size(); i++)
	keywords.insert(list.at(i));

      if(intersect)
	if(!keywords.isEmpty())
	  searchfor.append(" <b>OR</b> ");

      QSetIterator<QString> it(keywords);

      while(it.hasNext())
	{
	  auto const value(it.next());

	  searchfor.append(value);

	  if(it.hasNext())
	    searchfor.append(" <b>OR</b> ");

	  auto const keywordHash
	    (m_urlCommonCrypt->keyedHash(value.toUtf8(), &ok));

	  if(!ok)
	    continue;

	  auto const keywordHashHex(keywordHash.toHex());

	  keywordsearch.append
	    (QString("SELECT url_hash FROM "
		     "spot_on_keywords_%1 WHERE "
		     "keyword_hash = '%2' ").
	     arg(keywordHashHex.mid(0, 2).constData()).
	     arg(keywordHashHex.constData()));

	  if(it.hasNext())
	    keywordsearch.append(" UNION ALL ");
	}

      if(!keywords.isEmpty())
	keywordsearches << keywordsearch;

      searchfor = searchfor.trimmed();

      if(!searchfor.endsWith('.'))
	searchfor.append(".");

      searchfor.append("</html>");
      m_ui.searchfor->setText(searchfor);
      keywordsearch.clear();

      QMap<QString, QString> prefixes;

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      for(int i = 0; i < keywordsearches.size(); i++)
	{
	  QSqlQuery query(m_urlDatabase);

	  query.setForwardOnly(true);

	  if(query.exec(keywordsearches.at(i)))
	    while(query.next())
	      {
		auto const hash(query.value(0).toString());
		auto const prefix(hash.mid(0, 2));

		if(!prefixes.contains(prefix))
		  prefixes.insert(prefix, QString("'%1'").arg(hash));
		else
		  {
		    auto str(prefixes.value(prefix));

		    str.append(QString(", '%1'").arg(hash));
		    prefixes.insert(prefix, str);
		  }
	      }
	}

      QApplication::restoreOverrideCursor();

      if(!prefixes.isEmpty())
	{
	  QMapIterator<QString, QString> it(prefixes);

	  while(it.hasNext())
	    {
	      it.next();

	      /*
	      ** For absolute correctness, we ought to use parameters in
	      ** the SQL queries.
	      */

	      querystr.append
		(QString("SELECT title, "       // 0
			 "url, "                // 1
			 "description, "        // 2
			 "date_time_inserted, " // 3
			 "LENGTH(content), "    // 4
			 "url_hash "            // 5
			 "FROM spot_on_urls_%1 WHERE "
			 "url_hash IN (%2) ").
		 arg(it.key()).arg(it.value()));

	      if(it.hasNext())
		querystr.append(" UNION ALL ");
	    }

	  querystr.append(" ORDER BY 4 DESC ");
	  querystr.append(QString(" LIMIT %1 ").arg(m_urlLimit));
	  querystr.append(QString(" OFFSET %1 ").arg(m_urlOffset));
	}
    }

  m_urlQuery = querystr;
  showUrls(">", m_urlQuery);
}

void spoton::showUrls(const QString &link, const QString &querystr)
{
  if(!m_urlCommonCrypt)
    return;
  else if(!m_urlDatabase.isOpen())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QSqlQuery query(m_urlDatabase);
  quint64 count = 0;

  if(!querystr.trimmed().isEmpty())
    {
      query.setForwardOnly(true);
      query.prepare(querystr);
    }

  if(query.exec() || querystr.trimmed().isEmpty())
    {
      QString html("<html>");

      html.append
	(QString("The query completed in %1 second(s).<br><br>").
	 arg(qAbs(static_cast<double> (m_urlQueryElapsedTimer.elapsed()) /
		  1000.0)));

      while(query.next())
	{
	  if(!count)
	    m_ui.urls->clear();

	  QByteArray bytes;
	  QString description("");
	  QString title("");
	  QUrl url;
	  auto const hash(query.value(5).toByteArray());
	  auto ok = true;

	  bytes =
	    m_urlCommonCrypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query.value(2).
						   toByteArray()),
					&ok);
	  description = QString::fromUtf8(bytes.constData(),
					  bytes.length()).trimmed();

	  if(ok)
	    {
	      bytes =
		m_urlCommonCrypt->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.value(0).
						       toByteArray()),
					    &ok);
	      title = QString::fromUtf8(bytes.constData(),
					bytes.length()).trimmed();
	      title = spoton_misc::removeSpecialHtmlTags(title).trimmed();
	    }

	  if(ok)
	    {
	      bytes =
		m_urlCommonCrypt->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.value(1).
						       toByteArray()),
					    &ok);
	      url = QUrl::fromUserInput(QString::fromUtf8(bytes.constData(),
							  bytes.length()));
	    }

	  if(ok)
	    {
	      description = spoton_misc::removeSpecialHtmlTags(description);

	      if(description.length() > spoton_common::
		 MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS)
		{
		  description = description.mid
		    (0, spoton_common::
		     MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS).trimmed();

		  if(description.endsWith("..."))
		    {
		    }
		  else if(description.endsWith(".."))
		    description.append(".");
		  else if(description.endsWith("."))
		    description.append("..");
		  else
		    description.append("...");
		}

	      QLocale locale;
	      auto const scheme(url.scheme().toLower().trimmed());
	      QUrl deleteUrl(hash);
	      QUrl exportUrl(hash);
	      QUrl shareUrl(hash);
	      QUrl viewUrl(hash);

	      if(scheme.contains("delete-"))
		spoton_misc::logError
		  (QString("spoton::showUrls(): malformed URL %1.").
		   arg(spoton_misc::urlToEncoded(url).constData()));

	      if(scheme.contains("export-"))
		spoton_misc::logError
		  (QString("spoton::showUrls(): malformed URL %1.").
		   arg(spoton_misc::urlToEncoded(url).constData()));

	      if(scheme.contains("share-"))
		spoton_misc::logError
		  (QString("spoton::showUrls(): malformed URL %1.").
		   arg(spoton_misc::urlToEncoded(url).constData()));

	      if(scheme.contains("view-"))
		spoton_misc::logError
		  (QString("spoton::showUrls(): malformed URL %1.").
		   arg(spoton_misc::urlToEncoded(url).constData()));

	      url.setScheme(scheme);

	      if(title.isEmpty())
		title = spoton_misc::urlToEncoded(url);

	      deleteUrl.setPath(hash + "/" + spoton_misc::urlToEncoded(url));
	      deleteUrl.setScheme("delete-");
	      exportUrl.setPath(hash + "%3" + spoton_misc::urlToEncoded(url));
	      exportUrl.setScheme(QString("export-%1").arg(url.scheme()));
	      shareUrl.setPath(hash + "%3" + spoton_misc::urlToEncoded(url));
	      shareUrl.setScheme(QString("share-%1").arg(url.scheme()));
	      viewUrl.setPath(hash + "%3" + spoton_misc::urlToEncoded(url));
	      viewUrl.setScheme(QString("view-%1").arg(url.scheme()));
	      html.append(QString::number(count + m_urlOffset + 1));
	      html.append(" | <a href=\"");
	      html.append(spoton_misc::urlToEncoded(url));
	      html.append("\">");
	      html.append(title);
	      html.append("</a>");
	      html.append(" | ");
	      html.append("<a href=\"");
	      html.append(spoton_misc::urlToEncoded(exportUrl));
	      html.append("\">");
	      html.append("Export Page As PDF</a>");
	      html.append(" | ");
	      html.append("<a href=\"");
	      html.append(spoton_misc::urlToEncoded(deleteUrl));
	      html.append("\">");
	      html.append("Remove URL</a>");
	      html.append(" | ");
	      html.append("<a href=\"");
	      html.append(spoton_misc::urlToEncoded(shareUrl));
	      html.append("\">");
	      html.append("Share URL</a>");
#if defined(SPOTON_WEBENGINE_ENABLED) || defined(SPOTON_WEBKIT_ENABLED)
	      html.append(" | ");
	      html.append("<a href=\"");
	      html.append(spoton_misc::urlToEncoded(viewUrl));
	      html.append("\">");
	      html.append("View Locally</a>");
#else
	      html.append(" | ");
	      html.append("View Locally (Missing Rendering Engine)");
#endif
	      html.append("<br>");
	      html.append(QString("<font color=\"green\" size=3>%1</font>").
			  arg(spoton_misc::urlToEncoded(url).constData()));

	      if(!description.isEmpty())
		{
		  html.append("<br>");
		  html.append(QString("<font color=\"gray\" size=3>%1</font>").
			      arg(description));
		}

	      html.append("<br>");
	      html.append
		(QString("<font color=\"gray\" size=3>%1 | %2 KiB</font>").
		 arg(query.value(3).toString().trimmed()).
		 arg(locale.toString(query.value(4).toLongLong() / 1024)));
	      html.append("<br><br>");
	      count += 1;
	    }
	}

      if(count > 0)
	if(link == ">")
	  if(m_urlOffset / m_urlLimit >= m_urlPages)
	    m_urlPages += 1;

      html.append("</html>");
      m_ui.urls->setHtml(html);
      m_ui.urls->horizontalScrollBar()->setValue(0);
      m_ui.urls->verticalScrollBar()->setValue(0);
    }

  QApplication::restoreOverrideCursor();

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
      str.append(QString(" | %1 | ").arg(i));

  if(count >= m_urlLimit)
    str.append(tr(" <a href=\">\">Next</a> "));

  if(m_urlCurrentPage != 1)
    str.prepend(tr(" <a href=\"<\">Previous</a> "));

  str = str.trimmed();

  if(str.isEmpty())
    m_ui.url_pages->setText("| 1 |");
  else
    m_ui.url_pages->setText(str);
}

void spoton::slotDiscover(void)
{
  m_ui.searchfor->clear();
  m_ui.urls->clear();
  m_ui.url_pages->setText("| 1 |");

  if(!m_urlCommonCrypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Did you prepare common credentials?"));
      QApplication::processEvents();
      return;
    }

  if(!m_urlDatabase.isOpen())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please connect to a URL database."));
      QApplication::processEvents();
      return;
    }

  discoverUrls();
}

void spoton::slotPageClicked(const QString &link)
{
  m_urlQueryElapsedTimer.start();

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
