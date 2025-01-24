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

extern "C"
{
#ifdef SPOTON_POPTASTIC_SUPPORTED
#include <curl/curl.h>
#endif
#ifndef SPOTON_POSTGRESQL_DISABLED
#include <libpq-fe.h>
#endif
}

#include <QtGlobal>
#include <iostream>

#include <QActionGroup>
#ifdef Q_OS_MACOS
#include <QNetworkAccessManager>
#include <QNetworkReply>
#endif
#include <QProgressDialog>
#include <QScopedPointer>
#include <QShortcut>
#include <QSplashScreen>
#include <QStandardItemModel>
#include <QSysInfo>
#ifdef SPOTON_WEBENGINE_ENABLED
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#if QT_VERSION >= 0x050600
#include <QWebEngineUrlRequestInterceptor>
#endif
#elif defined(SPOTON_WEBKIT_ENABLED)
#include <QWebSettings>
#endif
#include <QtConcurrent>
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#include <qbluetooth.h>
#endif

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_UNIX)
extern "C"
{
#include <signal.h>
#include <sys/types.h>
}
#endif

#ifdef SPOTON_GPGME_ENABLED
extern "C"
{
#include <gpgme.h>
}
#endif

#include "Common/spot-on-threefish.h"
#include "Common/spot-on-version.h"
#include "spot-on-defines.h"
#include "spot-on-documentation.h"
#include "spot-on-echo-key-share.h"
#include "spot-on-reencode.h"
#include "spot-on-rss.h"
#include "spot-on-smp.h"
#include "spot-on-status-activity.h"
#include "spot-on-utilities.h"
#include "spot-on.h"
#include "ui_spot-on-password-prompt.h"

#ifdef SPOTON_MCELIECE_ENABLED
#include <NTL/version.h>
#endif

/*
** Not pleasant! Please avoid this solution!
*/

QHash<QString, QStringList> spoton::s_publicKeySizes;
QList<int> spoton_common::LANE_WIDTHS = QList<int> () << 14500
						      << 20000
                                                      << 25000
                                                      << 50000
                                                      << 75000
						      << 100000
						      << 2097152
						      << 5242880
						      << 10485760
						      << 20971520;
QString spoton_common::POSTGRESQL_CONNECTION_OPTIONS =
  "connect_timeout=10;sslmode=verify-full";
QString spoton_common::SSL_CONTROL_STRING =
  "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";
QStringList spoton_common::ACCEPTABLE_URL_SCHEMES =
  QStringList() << "ftp" << "gopher" << "http" << "https";
QStringList spoton_common::SPOTON_ENCRYPTION_KEY_NAMES =
  QStringList() << "chat"
		<< "email"
	        << "open-library"
		<< "poptastic"
		<< "rosetta"
		<< "url";
QStringList spoton_common::SPOTON_SIGNATURE_KEY_NAMES =
  QStringList() << "chat-signature"
		<< "email-signature"
		<< "open-library-signature"
		<< "poptastic-signature"
		<< "rosetta-signature"
		<< "url-signature";
char spoton::s_keyDelimiter = '|';
const int spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE;
const int spoton_common::BUZZ_MAXIMUM_ID_LENGTH;
const int spoton_common::CACHE_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE;
const int spoton_common::CHAT_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::ELEGANT_STARBEAM_SIZE;
const int spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::GEMINI_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::HARVEST_POST_OFFICE_LETTERS_INTERVAL;
const int spoton_common::KERNEL_CERTIFICATE_DAYS_VALID;
const int spoton_common::KERNEL_URL_DISPATCHER_INTERVAL_STATIC;
const int spoton_common::LANE_WIDTH_DEFAULT;
const int spoton_common::LANE_WIDTH_MAXIMUM;
const int spoton_common::LANE_WIDTH_MINIMUM;
const int spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::MAXIMUM_ATTEMPTS_PER_POPTASTIC_POST;
const int spoton_common::MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS;
const int spoton_common::MAXIMUM_UDP_DATAGRAM_SIZE;
const int spoton_common::MINIMUM_STARBEAM_PULSE_SIZE;
const int spoton_common::MOSAIC_SIZE;
const int spoton_common::NAME_MAXIMUM_LENGTH;
const int spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::POPTASTIC_MAXIMUM_EMAIL_SIZE;
const int spoton_common::POPTASTIC_STATUS_INTERVAL;
const int spoton_common::REAP_POST_OFFICE_LETTERS_INTERVAL;
const int spoton_common::SEND_QUEUED_EMAIL_INTERVAL;
const int spoton_common::SPOTON_HOME_MAXIMUM_PATH_LENGTH;
const int spoton_common::STATUS_INTERVAL;
const int spoton_common::STATUS_TEXT_MAXIMUM_LENGTH;
const int spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM;
const int spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_PREFERRED;
const qint64 spoton_common::MAXIMUM_BLUETOOTH_PACKET_SIZE;
const qint64 spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE;
const qint64 spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH;
const qint64 spoton_common::MAXIMUM_SCTP_PACKET_SIZE;
const qint64 spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE;
const qint64 spoton_common::MAXIMUM_TCP_PACKET_SIZE;
const qint64 spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH;
const unsigned long int spoton_common::GEMINI_ITERATION_COUNT;
int spoton_common::CACHE_TIME_DELTA_MAXIMUM =
  spoton_common::CACHE_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::CHAT_TIME_DELTA_MAXIMUM =
  spoton_common::CHAT_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
  spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::GEMINI_TIME_DELTA_MAXIMUM =
  spoton_common::GEMINI_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::KERNEL_URL_DISPATCHER_INTERVAL =
  spoton_common::KERNEL_URL_DISPATCHER_INTERVAL_STATIC;
int spoton_common::MAIL_TIME_DELTA_MAXIMUM =
  spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
  spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM =
  spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM_STATIC;
spoton_utilities_private spoton_utilities::s_utilitiesPrivate;

static void qt_message_handler(QtMsgType type,
			       const QMessageLogContext &context,
			       const QString &msg)
{
  Q_UNUSED(context);
  Q_UNUSED(type);
  std::cerr << msg.toStdString() << std::endl;
  spoton_misc::logError(QString("A UI error (%1) occurred.").arg(msg));
}

static void signal_handler(int signal_number)
{
  /*
  ** _Exit() and _exit() may be safely called from signal handlers.
  */

  static int fatal_error = 0;

  if(fatal_error)
    _Exit(signal_number);

  fatal_error = 1;
  spoton_crypt::terminate(); // Safe.
  _Exit(signal_number);
}

int main(int argc, char *argv[])
{
  auto launchKernel = false;

  for(int i = 1; i < argc; i++)
    if(argv && argv[i])
      {
	if(strcmp(argv[i], "--launch-kernel") == 0)
	  launchKernel = true;
      }

  /*
  ** Disable JIT.
  */

  qputenv("QT_ENABLE_REGEXP_JIT", "0");
  qputenv("QV4_FORCE_INTERPRETER", "1");
  spoton_misc::prepareSignalHandler(signal_handler);
#ifndef SPOTON_POSTGRESQL_DISABLED
  PQinitOpenSSL(0, 0); // We will initialize OpenSSL and libcrypto.
#endif
#ifdef SPOTON_POPTASTIC_SUPPORTED
  curl_global_init(CURL_GLOBAL_ALL);
#endif
#if defined(Q_OS_WINDOWS)
  QApplication::addLibraryPath("plugins");
#endif
  qInstallMessageHandler(qt_message_handler);
#if defined(Q_OS_MACOS) || defined(Q_OS_WINDOWS)
#if (QT_VERSION < QT_VERSION_CHECK(6, 0, 0))
  QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling, true);
  QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps, true);
#endif
#endif

  QApplication qapplication(argc, argv);
  QTranslator translator1;
  QTranslator translator2;
  auto const path(QDir::currentPath() + QDir::separator() + "Translations");

  if(!translator1.load(QLocale(), "qtbase", "_", path, ".qm"))
    qDebug() << "Could not discover the Qt translation file(s).";
  else if(!qapplication.installTranslator(&translator1))
    qDebug() << "Could not install the Qt translator.";

  if(!translator2.load(QLocale(), "spot-on", "_", path, ".qm"))
    qDebug() << "Could not discover the Spot-On translation file(s).";
  else if(!qapplication.installTranslator(&translator2))
    qDebug() << "Could not install the Spot-On translator.";

#if SPOTON_GOLDBUG == 0
  QSplashScreen splash(QPixmap(":/Logo/spot-on-splash.png"));
#else
  QSplashScreen splash(QPixmap(":/Logo/goldbug-splash.png"));
#endif
  auto font(qapplication.font());

  splash.setEnabled(false);
  splash.show();
  splash.showMessage
    (QObject::tr("Preparing directories."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash.repaint();
  font.setStyleStrategy
    (QFont::StyleStrategy(QFont::PreferAntialias | QFont::PreferQuality));
  qapplication.setFont(font);
#if SPOTON_GOLDBUG == 0
  qapplication.setWindowIcon(QIcon(":/Logo/spot-on-logo.png"));
#else
  qapplication.setWindowIcon(QIcon(":/Logo/goldbug.png"));
#endif
  QDir().mkdir(spoton_misc::homePath());
#ifdef SPOTON_WEBENGINE_ENABLED
  splash.showMessage
    (QObject::tr("Preparing WebEngine."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash.repaint();
  QDir().mkdir(spoton_misc::homePath() + QDir::separator() + "WebEngineCache");
  QWebEngineProfile::defaultProfile()->setCachePath
    (spoton_misc::homePath() + QDir::separator() + "WebEngineCache");
  QWebEngineProfile::defaultProfile()->
    setHttpCacheMaximumSize(0); // Automatic.
  QWebEngineProfile::defaultProfile()->setHttpCacheType
    (QWebEngineProfile::NoCache);
  QWebEngineProfile::defaultProfile()->setHttpUserAgent("");
  QWebEngineProfile::defaultProfile()->setPersistentCookiesPolicy
    (QWebEngineProfile::NoPersistentCookies);
  QWebEngineProfile::defaultProfile()->setPersistentStoragePath
    (spoton_misc::homePath() +
     QDir::separator() + "WebEnginePersistentStorage");
#if (QT_VERSION < QT_VERSION_CHECK(6, 0, 0))
  QWebEngineSettings::defaultSettings()->setAttribute
    (QWebEngineSettings::AutoLoadImages, false);
  QWebEngineSettings::defaultSettings()->setAttribute
    (QWebEngineSettings::JavascriptEnabled, false);
  QWebEngineSettings::defaultSettings()->setAttribute
    (QWebEngineSettings::LocalContentCanAccessFileUrls, false);
  QWebEngineSettings::defaultSettings()->setAttribute
    (QWebEngineSettings::LocalStorageEnabled, false);
#else
  QWebEngineProfile::defaultProfile()->settings()->setAttribute
    (QWebEngineSettings::AutoLoadImages, false);
  QWebEngineProfile::defaultProfile()->settings()->setAttribute
    (QWebEngineSettings::JavascriptEnabled, false);
  QWebEngineProfile::defaultProfile()->settings()->setAttribute
    (QWebEngineSettings::LocalContentCanAccessFileUrls, false);
  QWebEngineProfile::defaultProfile()->settings()->setAttribute
    (QWebEngineSettings::LocalStorageEnabled, false);
#endif
#elif defined(SPOTON_WEBKIT_ENABLED)
  QWebSettings::globalSettings()->setAttribute
    (QWebSettings::AutoLoadImages, false);
  QWebSettings::globalSettings()->setAttribute
    (QWebSettings::JavascriptEnabled, false);
  QWebSettings::globalSettings()->setAttribute
    (QWebSettings::LocalContentCanAccessFileUrls, false);
  QWebSettings::globalSettings()->setAttribute
    (QWebSettings::PluginsEnabled, false);
  QWebSettings::globalSettings()->setAttribute
    (QWebSettings::PrivateBrowsingEnabled, true);
  QWebSettings::globalSettings()->setIconDatabasePath("");
  QWebSettings::globalSettings()->setMaximumPagesInCache(0);
  QWebSettings::globalSettings()->setOfflineStorageDefaultQuota(0);
  QWebSettings::globalSettings()->setOfflineStoragePath("");
  QWebSettings::globalSettings()->setOfflineWebApplicationCachePath("");
  QWebSettings::globalSettings()->setOfflineWebApplicationCacheQuota(0);
  QWebSettings::globalSettings()->setWebGraphic
    (QWebSettings::MissingImageGraphic, QPixmap());
  QWebSettings::globalSettings()->setWebGraphic
    (QWebSettings::MissingPluginGraphic, QPixmap());
#endif

  auto thread = qapplication.thread();

  if(!thread)
    thread = QThread::currentThread();

  if(thread)
    thread->setPriority(QThread::HighPriority);
  else
    qDebug() << "Cannot set the main thread's priority because "
      "the main thread does not exist.";

#ifdef Q_OS_MACOS
  /*
  ** Eliminate pool errors on MacOS.
  */

  CocoaInitializer ci;
#endif

  QCoreApplication::setApplicationName("SpotOn");
  QCoreApplication::setOrganizationName("SpotOn");
  QCoreApplication::setOrganizationDomain("spot-on.sf.net");
  QCoreApplication::setApplicationVersion(SPOTON_VERSION_STR);
  QSettings::setDefaultFormat(QSettings::IniFormat);
  QSettings::setPath
    (QSettings::IniFormat, QSettings::UserScope, spoton_misc::homePath());
  splash.showMessage
    (QObject::tr("Processing INI values."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash.repaint();

  QSettings settings;

#if defined(Q_OS_WINDOWS)
  if(!settings.contains("gui/etpDestinationPath"))
    {
      QDir dir(QDir::currentPath());

      dir.mkdir("Mosaics");
      dir.cd("Mosaics");
      settings.setValue("gui/etpDestinationPath", dir.absolutePath());
    }
  else
    {
      QDir dir;

      dir.mkpath(settings.value("gui/etpDestinationPath").toString());
    }
#else
  if(!settings.contains("gui/etpDestinationPath"))
    settings.setValue("gui/etpDestinationPath", QDir::homePath());
#endif

  if(!settings.contains("gui/gcryctl_init_secmem"))
    settings.setValue("gui/gcryctl_init_secmem", 0);

  if(!settings.contains("kernel/gcryctl_init_secmem"))
    settings.setValue("kernel/gcryctl_init_secmem", 0);

  if(!settings.contains("gui/tcp_nodelay"))
    settings.setValue("gui/tcp_nodelay", 1);

  splash.showMessage
    (QObject::tr("Initializing cryptographic containers."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash.repaint();

  auto ok = true;
  auto integer = settings.value
    ("gui/gcryctl_init_secmem",
     spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE).toInt(&ok);

  if(!ok)
    integer = spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE;
  else if(integer == 0)
    {
    }
  else if(integer > 999999999)
    integer = spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE;

  spoton_crypt::init
    (integer, settings.value("gui/cbc_cts_enabled", true).toBool());

  int rc = 0;
  spoton spoton(&splash, launchKernel);

  splash.finish(&spoton);
  rc = static_cast<int> (qapplication.exec());
#ifdef SPOTON_POPTASTIC_SUPPORTED
  curl_global_cleanup();
#endif
  spoton_crypt::terminate();
  return rc;
}

spoton::spoton(QSplashScreen *splash, const bool launchKernel):QMainWindow()
{
  splash->showMessage
    (tr("Preparing static variables."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();
  m_defaultStyleSheet = qobject_cast<QApplication *>
    (QApplication::instance())->styleSheet();
  m_urlCurrentPage = 1;
  m_urlLimit = 10;
  m_urlOffset = 0;
  m_urlPages = 0;
  m_wizardUi = nullptr;
  s_publicKeySizes["dsa"] = QStringList() << "3072";
  s_publicKeySizes["ecdsa"] = QStringList() << "224"
					    << "256"
					    << "384"
					    << "521";
  s_publicKeySizes["eddsa"] = QStringList() << "Ed25519";
  s_publicKeySizes["elgamal"] = QStringList() << "3072"
					      << "4096"
					      << "7680"
					      << "8192"
					      << "15360";
  s_publicKeySizes["mceliece"] = QStringList() << "m11t51"
					       << "m11t51-fujisaki-okamoto-a"
					       << "m11t51-fujisaki-okamoto-b"
					       << "m12t68"
    					       << "m12t68-fujisaki-okamoto-a"
					       << "m12t68-fujisaki-okamoto-b";
  s_publicKeySizes["ntru"] = QStringList() << "EES1087EP2"
					   << "EES1171EP1"
					   << "EES1499EP1";
  s_publicKeySizes["rsa"] = QStringList() << "3072"
					  << "4096"
					  << "7680"
					  << "8192"
					  << "15360";

  {
#ifdef Q_OS_MACOS
    /*
    ** Anomaly.
    */

    QNetworkAccessManager manager;
    auto reply = manager.get
      (QNetworkRequest(QUrl::fromUserInput("http://0.0.0.0")));

    if(reply)
      reply->deleteLater();
#endif
  }

  splash->showMessage
    (tr("Preparing URL prefixes."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();

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

	m_urlPrefixes << QString("%1%2").arg(c1).arg(c2);
      }

  m_locked = false;
  m_quit = false;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
#else
  qsrand(static_cast<uint> (QTime(0, 0, 0).secsTo(QTime::currentTime())));
#endif
  splash->showMessage
    (tr("Creating various containers."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();
  m_keysShared["buzz_channels_sent_to_kernel"] = "false";
  m_keysShared["keys_sent_to_kernel"] = "false";
  m_buzzStatusTimer.setInterval(15000);
  m_buzzFavoritesLastModificationTime = QDateTime();
  m_documentation = new spoton_documentation
    (QUrl("qrc:/Spot-On.html"), nullptr);
  m_documentation->setWindowTitle
    (tr("%1: Documentation").arg(SPOTON_APPLICATION_NAME));
  m_echoKeyShare = new spoton_echo_key_share(&m_kernelSocket, this);
  m_magnetsLastModificationTime = QDateTime();
  m_listenersLastModificationTime = QDateTime();
  m_pqUrlFaultyCounter = 0;
  m_releaseNotes = new spoton_documentation
    (QUrl("qrc:/Documentation/ReleaseNotes.html"), nullptr);
  m_releaseNotes->setWindowTitle
    (tr("%1: Release Notes").arg(SPOTON_APPLICATION_NAME));
  m_rss = new spoton_rss(this);
  m_smpWindow = new spoton_smpwindow(this);
  m_starbeamDigestInterrupt = 0;
  m_starbeamReceivedModel = new QStandardItemModel(this);
  m_statisticsModel = new QStandardItemModel(this);

  QStringList list;

  list << tr("Percent Received") << tr("File");
  m_starbeamReceivedModel->setHorizontalHeaderLabels(list);
  m_starsLastModificationTime = QDateTime();
  list.clear();
  list << tr("Statistic") << tr("Value");
  m_statisticsModel->setHorizontalHeaderLabels(list);
  list.clear();
  m_urlCommonCrypt = nullptr;
  splash->showMessage
    (tr("Creating the primary interface object."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();
  m_ui.setupUi(this);
  m_sbWidget = new QWidget(this);
  m_sb.setupUi(m_sbWidget);
  m_statusActivity = new spoton_status_activity(m_sb.down, m_sb.up, m_sbWidget);
  m_ui.buzzTab->setTabsClosable(false);
  splash->showMessage
    (tr("Preparing context-menu policies."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();
  m_ui.buzzTab->tabBar()->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.dooble_import_groupbox->setVisible(false);
  m_ui.email_page->addItem("1");
  m_ui.emailParticipants->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.etpMagnets->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.importUrls->setVisible(false);
  m_ui.listeners->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.listeners->setItemDelegate(new spoton_table_item_delegate(this));
  m_ui.mail->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.neighbors->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.neighbors->setItemDelegate(new spoton_table_item_delegate(this));
  m_ui.participants->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.received->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.tab->setSpotOn(this);
  m_ui.tab->tabBar()->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.transmitted->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.transmittedMagnets->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.urlParticipants->setContextMenuPolicy(Qt::CustomContextMenu);

  QSettings settings;

#if SPOTON_GOLDBUG == 0
  splash->showMessage
    (tr("Preparing style sheets."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  foreach(auto widget, findChildren<QWidget *> ())
    {
      widget->setProperty("original_style_sheet", widget->styleSheet());

      if(widget->contextMenuPolicy() == Qt::CustomContextMenu ||
	 widget->inherits("QLineEdit") ||
	 widget->inherits("QTextEdit"))
	continue;

      widget->setContextMenuPolicy(Qt::CustomContextMenu);

      if(settings.contains(QString("gui/widget_stylesheet_%1").
			   arg(widget->objectName())))
	widget->setStyleSheet
	  (settings.value(QString("gui/widget_stylesheet_%1").
			  arg(widget->objectName())).toString());

      connect(widget,
	      SIGNAL(customContextMenuRequested(const QPoint &)),
	      this,
	      SLOT(slotSetWidgetStyleSheet(const QPoint &)));
    }

  QApplication::restoreOverrideCursor();
#endif
  m_ui.buzz_frame->setVisible(m_ui.buzz_details->isChecked());
#if SPOTON_GOLDBUG == 0
  m_ui.proxy_frame->setVisible(m_ui.proxy->isChecked());
#endif
  list << "buzz"
       << "chat"
       << "email"
       << "listeners"
       << "neighbors"
       << "search"
       << "settings"
       << "starbeam"
       << "urls";
#if SPOTON_GOLDBUG == 1
  list << "add_friend";
#endif
  list << "about";

  for(int i = 0; i < m_ui.tab->count(); i++)
    {
      m_tabWidgets[i] = m_ui.tab->widget(i);

      QHash<QString, QVariant> hash;

      hash["enabled"] = true;
      hash["icon"] = m_ui.tab->tabIcon(i);
      hash["label"] = m_ui.tab->tabText(i);
      hash["name"] = list.value(i);
      m_tabWidgetsProperties[i] = hash;
    }

  list.clear();
#if SPOTON_GOLDBUG == 0
  m_ui.attachment_label->setText
    (tr("Please note that individual attachments are limited to %1 MiB. "
	"Traditional e-mail supports only single attachments. "
	"Inline attachments are not supported.").
     arg(spoton_common::EMAIL_ATTACHMENT_MAXIMUM_SIZE / 1048576));
#endif
  m_ui.version->setText
    (QString("<html><head/><body><p><a href=\"https://github.com/textbrowser/"
	     "spot-on/blob/master/branches/Documentation/ReleaseNotes.html\">"
	     "<span style=\" text-decoration: underline; color:#0000ff;\">"
	     "%1 Version %2</span></a></p></body></html>").
     arg(SPOTON_APPLICATION_NAME).
     arg(SPOTON_VERSION_STR));
  setWindowTitle(tr("%1").arg(SPOTON_APPLICATION_NAME));
  m_ui.menu_Tools->setWindowTitle
    (tr("%1: Tools").arg(SPOTON_APPLICATION_NAME));
  m_ui.menu_View->setWindowTitle(tr("%1: View").arg(SPOTON_APPLICATION_NAME));
  m_ui.listenerOrientation->model()->setData
    (m_ui.listenerOrientation->model()->index(1, 0), 0, Qt::UserRole - 1);
  m_ui.neighborOrientation->model()->setData
    (m_ui.neighborOrientation->model()->index(1, 0), 0, Qt::UserRole - 1);

  QString qversion("");
  auto const sslSupported = QSslSocket::supportsSsl();
  auto const tmp = qVersion();

  if(tmp)
    qversion = tmp;

  qversion = qversion.trimmed();

  if(qversion.isEmpty())
    qversion = "unknown";

  m_ui.buildInformation->setText
    (QString("<html>"
	     "<font color=\"#6a5acd\">Space Trees</font>"
	     "<br><br>"
	     "Compilation: %1, %2.<br>"
	     "%3.<br>"
	     "Operating System: %4.<br>"
	     "Options Enabled: %14.<br>"
	     "Qt: %5 (runtime %12), %6-bit.<br>"
	     "%7.<br>"
	     "libgcrypt: %8.<br>"
	     "libgpgme: %13.<br>"
	     "libntl: %9.<br>"
	     "libspoton: %10.<br>"
	     "Location of .spot-on: %11.<br><br>"
	     "Translators<br>"
	     "Chinese - Zhao Wang<br>"
	     "German - Ulrike M&#246;ller<br>"
	     "Hindi - Ramachandra Kulkarni<br>"
	     "Spanish - Eduardo Gonzales<br>"
	     "Swedish - Daniel Wester<br>"
	     "Thai - Sathitchai K.</html>").
#ifdef SPOTON_DATELESS_COMPILATION
     arg("January 1, 3000").
     arg("01:01:01").
#else
     arg(__DATE__).
     arg(__TIME__).
#endif
     arg(sslSupported ?
#ifdef OPENSSL_VERSION_TEXT
	 OPENSSL_VERSION_TEXT :
#else
	 SSLeay_version(SSLEAY_VERSION) :
#endif
	 "OpenSSL is not supported, according to Qt").
     arg(QSysInfo::prettyProductName() +
	 " " +
	 QSysInfo::currentCpuArchitecture()).
     arg(QT_VERSION_STR).
     arg(CHAR_BIT * sizeof(void *)).
#ifdef SPOTON_POPTASTIC_SUPPORTED
     arg(curl_version()).
#else
     arg("libCURL is not supported").
#endif
     arg(GCRYPT_VERSION).
#ifdef SPOTON_MCELIECE_ENABLED
     arg(NTL_VERSION).
#else
     arg("0.0").
#endif
     arg(SPOTON_VERSION_STR).
     arg(spoton_misc::homePath()).
     arg(qversion).
#ifdef SPOTON_GPGME_ENABLED
     arg(GPGME_VERSION).
#else
     arg("0.0").
#endif
     arg(optionsEnabled())
     );
  m_ui.emailSecrets->setVisible(false);
  m_ui.passphrase_strength_indicator->setVisible(false);
  m_ui.statisticsBox->setVisible(false);
  m_ui.urlSettings->setVisible(true);
  m_ui.urlsBox->setVisible(false);
  m_ui.showUrlSettings->setChecked(true);
  m_ui.urls_db_type->model()->setData
    (m_ui.urls_db_type->model()->index(0, 0), 0, Qt::UserRole - 1);
  m_ui.goldbug->setEnabled(false);
  m_ui.postgresqlConnect->setEnabled(false);
  m_ui.postgresqlConnect->setVisible(false);
  m_ui.postgresql_credentials->setEnabled(false);
  m_ui.postgresql_credentials->setVisible(false);

#ifndef SPOTON_POSTGRESQL_DISABLED
  foreach(auto const &driver, QSqlDatabase::drivers())
    if(driver.contains("qpsql", Qt::CaseInsensitive))
      {
	m_ui.postgresqlConnect->setEnabled(true);
	m_ui.postgresql_credentials->setEnabled(true);
	m_ui.urls_db_type->model()->setData
	  (m_ui.urls_db_type->model()->index(0, 0), QVariant(1 | 32),
	   Qt::UserRole - 1);
	break;
      }
#endif

#if QT_VERSION >= 0x050501
  m_ui.message->setPlaceholderText(tr("Please type a message..."));
#endif
  m_ui.search->setPlaceholderText(tr("Search"));
#if SPOTON_GOLDBUG == 0
  m_addParticipantWindow = new QMainWindow(nullptr);
  m_addParticipantWindow->layout()->setContentsMargins(5, 5, 5, 5);
  m_addParticipantWindow->setCentralWidget(m_ui.add_participant_groupbox);
  m_addParticipantWindow->setWindowIcon(windowIcon());
  m_addParticipantWindow->setWindowTitle
    (tr("%1: Add Participant").arg(SPOTON_APPLICATION_NAME));

  QAction *action = nullptr;
  auto menu = new QMenu("&File", this);

  action = menu->addAction(tr("&Close"),
			   m_addParticipantWindow,
			   SLOT(close(void)));
  action->setShortcut(tr("Ctrl+W"));
  m_addParticipantWindow->menuBar()->addMenu(menu);
#else
  QMenu *menu = nullptr;

  m_addParticipantWindow = nullptr;
#endif
  m_externalAddress = new spoton_external_address();
  m_notificationsWindow = new QMainWindow(nullptr);
  m_optionsWindow = new QMainWindow(nullptr);
  m_statisticsWindow = new QMainWindow(nullptr);
  m_notificationsUi.setupUi(m_notificationsWindow);
  m_optionsUi.setupUi(m_optionsWindow);
#ifndef SPOTON_LINKED_WITH_LIBGEOIP
  m_optionsUi.geoipPath4->setEnabled(false);
  m_optionsUi.geoipPath4->setToolTip
    (tr("%1 was configured without libGeoIP.").arg(SPOTON_APPLICATION_NAME));
  m_optionsUi.geoipPath6->setEnabled(false);
  m_optionsUi.geoipPath6->setToolTip
    (tr("%1 was configured without libGeoIP.").arg(SPOTON_APPLICATION_NAME));
  m_optionsUi.selectGeoIP4->setEnabled(false);
  m_optionsUi.selectGeoIP4->setToolTip
    (tr("%1 was configured without libGeoIP.").arg(SPOTON_APPLICATION_NAME));
  m_optionsUi.selectGeoIP6->setEnabled(false);
  m_optionsUi.selectGeoIP6->setToolTip
    (tr("%1 was configured without libGeoIP.").arg(SPOTON_APPLICATION_NAME));
#endif
#ifndef SPOTON_POPTASTIC_SUPPORTED
  m_sb.pop_poptastic->setToolTip(tr("Poptastic is not supported."));
#endif
  m_statisticsUi.setupUi(m_statisticsWindow);
  m_statisticsUi.view->setModel(m_statisticsModel);
  m_ui.statistics->setModel(m_statisticsModel);
  m_optionsWindow->setWindowTitle
    (tr("%1: Options").arg(SPOTON_APPLICATION_NAME));
  m_poptasticRetroPhoneDialog = new QDialog(this);
  m_poptasticRetroPhoneSettingsUi.setupUi(m_poptasticRetroPhoneDialog);
  m_poptasticRetroPhoneSettingsUi.poptastic_label->setScaledContents(true);
  m_sb.authentication_request->setVisible(false);
  m_sb.buzz->setVisible(false);
  m_sb.chat->setVisible(false);
  m_sb.email->setVisible(false);
  m_sb.forward_secrecy_request->setVisible(false);
  m_sb.status->setTextFormat(Qt::RichText);
  m_sb.warning->setVisible(false);
  m_notificationsWindow->setWindowTitle
    (tr("%1: Notifications").arg(SPOTON_APPLICATION_NAME));
#if defined(Q_OS_MACOS) || defined(Q_OS_WINDOWS)
  m_notificationsWindow->setWindowFlags
    (m_notificationsWindow->windowFlags() | Qt::WindowStaysOnTopHint);
#endif
  m_statisticsWindow->setWindowTitle
    (tr("%1: Statistics").arg(SPOTON_APPLICATION_NAME));
#if defined(Q_OS_MACOS) || defined(Q_OS_WINDOWS)
  m_statisticsWindow->setWindowFlags
    (m_statisticsWindow->windowFlags() | Qt::WindowStaysOnTopHint);
#endif
#if defined(Q_OS_MACOS)
  foreach(auto toolButton, m_sbWidget->findChildren<QToolButton *> ())
    toolButton->setStyleSheet
    ("QToolButton {border: none;}"
     "QToolButton::menu-button {border: none;}");
#endif
#ifndef SPOTON_MCELIECE_ENABLED
  m_ui.encryptionKeyType->model()->setData
    (m_ui.encryptionKeyType->model()->index(1, 0), 0, Qt::UserRole - 1);
#endif
#ifndef SPOTON_LINKED_WITH_LIBNTRU
  m_ui.encryptionKeyType->model()->setData
    (m_ui.encryptionKeyType->model()->index(2, 0), 0, Qt::UserRole - 1);
#endif
#if !defined(GCRYPT_VERSION_NUMBER) || GCRYPT_VERSION_NUMBER < 0x010600
  /*
  ** libgcrypt 1.6.x required!
  */

  m_ui.signatureKeyType->model()->setData
    (m_ui.signatureKeyType->model()->index(1, 0), 0, Qt::UserRole - 1);
  m_ui.signatureKeyType->model()->setData
    (m_ui.signatureKeyType->model()->index(2, 0), 0, Qt::UserRole - 1);
#endif
#if QT_VERSION < 0x050501 || !defined(SPOTON_BLUETOOTH_ENABLED)
  m_ui.listenerTransport->model()->setData
    (m_ui.listenerTransport->model()->index(0, 0), 0, Qt::UserRole - 1);
  m_ui.neighborTransport->model()->setData
    (m_ui.neighborTransport->model()->index(0, 0), 0, Qt::UserRole - 1);
#endif
#ifndef SPOTON_SCTP_ENABLED
  m_ui.listenerTransport->model()->setData
    (m_ui.listenerTransport->model()->index(1, 0), 0, Qt::UserRole - 1);
  m_ui.neighborTransport->model()->setData
    (m_ui.neighborTransport->model()->index(1, 0), 0, Qt::UserRole - 1);
#endif
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
#else
  m_ui.listenerTransport->model()->setData
    (m_ui.listenerTransport->model()->index(4, 0), 0, Qt::UserRole - 1);
  m_ui.neighborTransport->model()->setData
    (m_ui.neighborTransport->model()->index(4, 0), 0, Qt::UserRole - 1);
#endif
#if SPOTON_GOLDBUG == 1
  m_optionsUi.position->model()->setData
    (m_optionsUi.position->model()->index(1, 0), 0, Qt::UserRole - 1);
  m_optionsUi.position->model()->setData
    (m_optionsUi.position->model()->index(2, 0), 0, Qt::UserRole - 1);
#else
  m_ui.find->setPlaceholderText(tr("Find Text"));
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
  new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_F),
		this,
		SLOT(slotFindInSearchInitialize(void)));
#else
  new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_F),
		this,
		SLOT(slotFindInSearchInitialize(void)));
#endif
#endif
  splash->showMessage
    (tr("Connecting signals."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();

  /*
  ** Connect m_sb's items.
  */

  connect(m_sb.authentication_request,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAuthenticationRequestButtonClicked(void)));
  connect(m_sb.buzz,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.chat,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.email,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.errorlog,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(m_sb.forward_secrecy_request,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRespondToForwardSecrecy(void)));
  connect(m_sb.kernelstatus,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotKernelStatus(void)));
  connect(m_sb.listeners,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.lock,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotLock(void)));
  connect(m_sb.neighbors,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.pop_poptastic,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPopPoptastic(void)));
  connect(m_sb.status,
	  SIGNAL(linkActivated(const QString &)),
	  this,
	  SLOT(slotShareKeysWithKernel(const QString &)));
  connect(m_sb.warning,
	  SIGNAL(clicked(void)),
	  m_sb.warning,
	  SLOT(hide(void)));
  connect(m_sb.warning,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotShowNotificationsWindow(void)));

  /*
  ** Connect the object's items.
  */

  connect(this,
	  SIGNAL(dataReceived(const qint64)),
	  m_statusActivity,
	  SLOT(slotDataReceived(const qint64)));
  connect(this,
	  SIGNAL(dataSent(const qint64)),
	  m_statusActivity,
	  SLOT(slotDataSent(const qint64)));
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  &m_encryptFile,
	  SLOT(slotSetIcons(void)));
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  &m_logViewer,
	  SLOT(slotSetIcons(void)));
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  &m_rosetta,
	  SLOT(slotSetIcons(void)));
  connect(this,
	  SIGNAL(neighborsQueryReady(QSqlDatabase *,
				     QSqlQuery *,
				     const QString &,
				     const int &)),
	  this,
	  SLOT(slotPopulateNeighbors(QSqlDatabase *,
				     QSqlQuery *,
				     const QString &,
				     const int &)));
  connect(this,
	  SIGNAL(participantAdded(const QString &)),
	  &m_rosetta,
	  SLOT(slotParticipantAdded(const QString &)));
  connect(this,
	  SIGNAL(participantAdded(const QString &)),
	  m_smpWindow,
	  SLOT(slotRefresh(void)));
  connect(this,
	  SIGNAL(participantDeleted(const QString &, const QString &)),
	  m_smpWindow,
	  SLOT(slotParticipantDeleted(const QString &, const QString &)));
  connect(this,
	  SIGNAL(participantNameChanged(const QByteArray &,
					const QString &)),
	  m_smpWindow,
	  SLOT(slotParticipantNameChanged(const QByteArray &,
					  const QString &)));
  connect(this,
	  SIGNAL(participantsQueryReady(QSqlDatabase *,
					QSqlQuery *,
					const QString &)),
	  this,
	  SLOT(slotPopulateParticipants(QSqlDatabase *,
					QSqlQuery *,
					const QString &)));
  connect(this,
	  SIGNAL(pqUrlDatabaseFaulty(void)),
	  this,
	  SLOT(slotPQUrlDatabaseFaulty(void)));
  connect(this,
	  SIGNAL(smpMessageReceivedFromKernel(const QByteArrayList &)),
	  m_smpWindow,
	  SLOT(slotSMPMessageReceivedFromKernel(const QByteArrayList &)));
  m_optionsUi.guiSecureMemoryPool->setProperty
    ("original_stylesheet", m_optionsUi.guiSecureMemoryPool->styleSheet());
  m_ui.kernelSecureMemoryPool->setProperty
    ("original_stylesheet", m_ui.kernelSecureMemoryPool->styleSheet());
  statusBar()->addPermanentWidget(m_sbWidget, 100);
  statusBar()->setStyleSheet("QStatusBar::item {"
			     "border: none; "
			     "}");
  statusBar()->setMaximumHeight(m_sbWidget->height());
  m_ui.buzzTab->setStyleSheet
    ("QTabBar::tear {"
     "image: none;"
     "}"
     );
  m_ui.tab->setStyleSheet
    ("QTabBar::tear {"
     "image: none;"
     "}"
     );
  m_ui.chatSecrets->setMenu(new QMenu(this));
  m_ui.chatSecrets->menu()->setStyleSheet("QMenu {menu-scrollable: 1;}");
  m_ui.emailSecrets->setMenu(new QMenu(this));
  m_ui.emailSecrets->menu()->setStyleSheet("QMenu {menu-scrollable: 1;}");

  /*
  ** Connect the object's items.
  */

  connect(&m_chatInactivityTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotChatInactivityTimeout(void)));
  connect(&m_emailRetrievalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotRetrieveMail(void)));
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotGeneralTimerTimeout(void)));
  connect(&m_kernelSocket,
	  SIGNAL(bytesWritten(const qint64)),
	  m_statusActivity,
	  SLOT(slotDataSent(const qint64)));
  connect(&m_kernelSocket,
	  SIGNAL(connected(void)),
	  this,
	  SLOT(slotKernelSocketState(void)));
  connect(&m_kernelSocket,
	  SIGNAL(disconnected(void)),
	  this,
	  SLOT(slotKernelSocketState(void)));
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
  connect(&m_kernelSocket,
	  SIGNAL(error(QAbstractSocket::SocketError)),
	  this,
	  SLOT(slotKernelSocketError(QAbstractSocket::SocketError)));
#else
  connect(&m_kernelSocket,
	  SIGNAL(errorOccurred(QAbstractSocket::SocketError)),
	  this,
	  SLOT(slotKernelSocketError(QAbstractSocket::SocketError)));
#endif
  connect(&m_kernelSocket,
	  SIGNAL(modeChanged(QSslSocket::SslMode)),
	  this,
	  SLOT(slotModeChanged(QSslSocket::SslMode)));
  connect(&m_kernelSocket,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotReceivedKernelMessage(void)));
  connect(&m_kernelSocket,
	  SIGNAL(sslErrors(const QList<QSslError> &)),
	  this,
	  SLOT(slotKernelSocketSslErrors(const QList<QSslError> &)));
  connect(&m_kernelUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotGatherStatistics(void)));
  connect(&m_listenersUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateListeners(void)));
  connect(&m_neighborsUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateNeighbors(void)));
  connect(&m_participantsUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateParticipants(void)));
  connect(&m_rosetta,
	  SIGNAL(participantAdded(const QString &)),
	  m_smpWindow,
	  SLOT(slotRefresh(void)));
  connect(&m_rosetta,
	  SIGNAL(participantDeleted(const QString &, const QString &)),
	  m_smpWindow,
	  SLOT(slotParticipantDeleted(const QString &, const QString &)));
  connect(&m_rosetta,
	  SIGNAL(participantNameChanged(const QByteArray &,
					const QString &)),
	  m_smpWindow,
	  SLOT(slotParticipantNameChanged(const QByteArray &,
					  const QString &)));
  connect(&m_starbeamUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateEtpMagnets(void)));
  connect(&m_starbeamUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateStars(void)));
  connect(&m_tableTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateBuzzFavorites(void)));
  connect(&m_updateChatWindowsTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotUpdateChatWindows(void)));
  connect(&m_webServerInformationTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotWebServerInformationTimeout(void)));

  /*
  ** Connect m_notificationsUi's items.
  */

  connect(m_notificationsUi.action_Clear,
	  SIGNAL(triggered(void)),
	  m_notificationsUi.textBrowser,
	  SLOT(clear(void)));
  connect(m_notificationsUi.action_Clear,
	  SIGNAL(triggered(void)),
	  m_sb.warning,
	  SLOT(hide(void)));
  connect(m_notificationsUi.activate,
	  SIGNAL(toggled(bool)),
	  m_optionsUi.notifications,
	  SLOT(setChecked(bool)));
  connect(m_notificationsUi.monitor,
	  SIGNAL(toggled(bool)),
	  m_optionsUi.monitor,
	  SLOT(setChecked(bool)));
  connect(m_notificationsUi.monitor,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotMonitorEvents(bool)));

  /*
  ** Connect m_optionsUi's items.
  */

  connect(m_optionsUi.acceptBuzzMagnets,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptBuzzMagnets(bool)));
  connect(m_optionsUi.acceptChatKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptChatKeys(bool)));
  connect(m_optionsUi.acceptEmailKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptEmailKeys(bool)));
  connect(m_optionsUi.acceptGeminis,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptGeminis(bool)));
  connect(m_optionsUi.acceptPublishedConnected,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_optionsUi.acceptPublishedDisconnected,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_optionsUi.acceptPublishedLocalConnected,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_optionsUi.acceptUrlKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptUrlKeys(bool)));
  connect(m_optionsUi.action_Close,
	  SIGNAL(triggered(void)),
	  m_optionsWindow,
	  SLOT(close(void)));
  connect(m_optionsUi.apply_other,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotApplyOtherOptions(void)));
  connect(m_optionsUi.autoAddSharedSBMagnets,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAutoAddSharedSBMagnets(bool)));
  connect(m_optionsUi.autoEmailRetrieve,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAutoRetrieveEmail(bool)));
  connect(m_optionsUi.buzzAutoJoin,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveBuzzAutoJoin(bool)));
  connect(m_optionsUi.buzz_maximum_lines,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSaveLineLimits(int)));
  connect(m_optionsUi.chatAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.chatAlternatingRowColors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveAlternatingColors(bool)));
  connect(m_optionsUi.chatOpenLinks,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotOpenChatUrlChecked(bool)));
  connect(m_optionsUi.chatSendMethod,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotChatSendMethodChanged(int)));
  connect(m_optionsUi.chatSignMessages,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.chatTimestamps,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotChatTimestamps(bool)));
  connect(m_optionsUi.chatUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.chat_fs_request,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAllowFSRequest(bool)));
  connect(m_optionsUi.chat_maximum_lines,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSaveLineLimits(int)));
  connect(m_optionsUi.coAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.defaults,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTimeSliderDefaults(void)));
  connect(m_optionsUi.disable_kernel_synchronous_download,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotDisableSynchronousUrlImport(bool)));
  connect(m_optionsUi.disable_ui_synchronous_import,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotDisableSynchronousUrlImport(bool)));
  connect(m_optionsUi.displayPopups,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotDisplayPopups(bool)));
  connect(m_optionsUi.emailAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.emailAlternatingRowColors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveAlternatingColors(bool)));
  connect(m_optionsUi.emailRetrievalInterval,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMailRetrievalIntervalChanged(int)));
  connect(m_optionsUi.emailSignMessages,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.email_fs_request,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAllowFSRequest(bool)));
  connect(m_optionsUi.enableChatEmoticons,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotEnableChatEmoticons(bool)));
  connect(m_optionsUi.external_ip_url,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveExternalIPUrl(void)));
  connect(m_optionsUi.forceRegistration,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotForceKernelRegistration(bool)));
  connect(m_optionsUi.geoipPath4,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveGeoIPPath(void)));
  connect(m_optionsUi.geoipPath6,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveGeoIPPath(void)));
  connect(m_optionsUi.guiExternalIpFetch,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotExternalIp(int)));
  connect(m_optionsUi.guiSecureMemoryPool,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSecureMemoryPoolChanged(int)));
  connect(m_optionsUi.icons,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSetIcons(int)));
  connect(m_optionsUi.iconsize,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSetIconSize(int)));
  connect(m_optionsUi.ignorePublished,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_optionsUi.impersonate,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotImpersonate(bool)));
  connect(m_optionsUi.keepOnlyUserDefinedNeighbors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKeepOnlyUserDefinedNeighbors(bool)));
  connect(m_optionsUi.kernelCacheInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.kernelUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.kernel_url_batch_size,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotKernelUrlBatchSizeChanged(int)));
  connect(m_optionsUi.launchKernel,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotLaunchKernelAfterAuthentication(bool)));
  connect(m_optionsUi.limitConnections,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotLimitConnections(int)));
  connect(m_optionsUi.limit_sqlite_synchronization,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotLimitSqliteSynchronization(bool)));
  connect(m_optionsUi.listenersUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.maximumEmailFileSize,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMaximumEmailFileSizeChanged(int)));
  connect(m_optionsUi.maximum_url_keywords_interface,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMaximumUrlKeywordsChanged(int)));
  connect(m_optionsUi.maximum_url_keywords_kernel,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMaximumUrlKeywordsChanged(int)));
  connect(m_optionsUi.monitor,
	  SIGNAL(toggled(bool)),
	  m_notificationsUi.monitor,
	  SLOT(setChecked(bool)));
  connect(m_optionsUi.neighborsUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.notifications,
	  SIGNAL(toggled(bool)),
	  m_notificationsUi.activate,
	  SLOT(setChecked(bool)));
  connect(m_optionsUi.notifications,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotNotificationsEnabled(bool)));
  connect(m_optionsUi.ontopChatDialogs,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotOntopChatDialogs(bool)));
  connect(m_optionsUi.openlinks,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveOpenLinks(bool)));
  connect(m_optionsUi.play_sounds,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPlaySounds(bool)));
  connect(m_optionsUi.position,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotChangeTabPosition(int)));
  connect(m_optionsUi.postgresql_kernel_url_distribution_timeout,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotPostgreSQLKernelUrlDistributionTimeout(int)));
  connect(m_optionsUi.publishPeriodically,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPublishPeriodicallyToggled(bool)));
  connect(m_optionsUi.publishedKeySize,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotPublishedKeySizeChanged(int)));
  connect(m_optionsUi.refreshEmail,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveRefreshEmail(bool)));
  connect(m_optionsUi.remove_otm,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotRemoveOtmOnExit(bool)));
  connect(m_optionsUi.saveCopy,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKeepCopy(bool)));
  connect(m_optionsUi.saveSslControlString,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveSslControlString(void)));
  connect(m_optionsUi.scrambler,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotScramble(bool)));
  connect(m_optionsUi.searchResultsPerPage,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSearchResultsPerPage(int)));
  connect(m_optionsUi.selectGeoIP4,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectGeoIPPath(void)));
  connect(m_optionsUi.selectGeoIP6,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectGeoIPPath(void)));
  connect(m_optionsUi.sharePrivateKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveSharePrivateKeys(bool)));
  connect(m_optionsUi.sslControlString,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveSslControlString(void)));
  connect(m_optionsUi.starbeamAutoVerify,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveStarBeamAutoVerify(bool)));
  connect(m_optionsUi.starbeamUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.superEcho,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSuperEcho(int)));
  connect(m_optionsUi.tear_off_menus,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotTearOffMenusEnabled(bool)));
  connect(m_optionsUi.terminate_kernel_on_ui_exit,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotTerminateKernelOnUIExit(bool)));
  connect(m_optionsUi.testSslControlString,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestSslControlString(void)));
  connect(m_optionsUi.theme,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotStyleSheetChanged(int)));
  connect(m_optionsUi.urlAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.urlSignMessages,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.urlsAlternatingRowColors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveAlternatingColors(bool)));

  /*
  ** Connect m_ui's items.
  */

  connect(m_ui.acceptedIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddAcceptedIP(void)));
  connect(m_ui.action_About,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotAbout(void)));
#if SPOTON_GOLDBUG == 0
  connect(m_ui.action_Add_Participant,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowAddParticipant(void)));
#endif
  connect(m_ui.action_Buzz,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowPage(bool)));
  connect(m_ui.action_Clear_Clipboard_Buffer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClearClipboardBuffer(void)));
  connect(m_ui.action_Copy,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(m_ui.action_Documentation,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowDocumentation(void)));
  connect(m_ui.action_Echo_Key_Share,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewEchoKeyShare(void)));
  connect(m_ui.action_Export_Listeners,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotExportListeners(void)));
  connect(m_ui.action_Export_Public_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotExportPublicKeys(void)));
  connect(m_ui.action_File_Encryption,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowEncryptFile(void)));
  connect(m_ui.action_Import_Neighbors,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotImportNeighbors(void)));
  connect(m_ui.action_Import_Public_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotImportPublicKeys(void)));
  connect(m_ui.action_Listeners,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowPage(bool)));
  connect(m_ui.action_Log_Viewer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(m_ui.action_Minimal_Display,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowMinimalDisplay(bool)));
  connect(m_ui.action_Neighbors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowPage(bool)));
  connect(m_ui.action_New_Global_Name,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotNewGlobalName(void)));
  connect(m_ui.action_Notifications_Window,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowNotificationsWindow(void)));
  connect(m_ui.action_Options,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowOptions(void)));
  connect(m_ui.action_Paste,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(m_ui.action_Poptastic_Settings,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotConfigurePoptastic(void)));
  connect(m_ui.action_Purge_Ephemeral_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotPurgeEphemeralKeys(void)));
  connect(m_ui.action_Quit,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotQuit(void)));
  connect(m_ui.action_RSS,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowRss(void)));
  connect(m_ui.action_Release_Notes,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowReleaseNotes(void)));
  connect(m_ui.action_ResetSpotOn,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotResetAll(void)));
  connect(m_ui.action_Rosetta,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewRosetta(void)));
  connect(m_ui.action_SMP,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowSMPWindow(void)));
  connect(m_ui.action_Search,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowPage(bool)));
#if SPOTON_GOLDBUG == 0
  connect(m_ui.action_Settings,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowPage(bool)));
#endif
  connect(m_ui.action_StarBeam,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowPage(bool)));
  connect(m_ui.action_Statistics_Window,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowStatisticsWindow(void)));
  connect(m_ui.action_Urls,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowPage(bool)));
  connect(m_ui.action_Vacuum_Databases,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotVacuumDatabases(void)));
  connect(m_ui.activateKernel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotActivateKernel(void)));
  connect(m_ui.activeUrlDistribution,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotActiveUrlDistribution(bool)));
  connect(m_ui.addAEToken,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAEToken(void)));
  connect(m_ui.addAcceptedIP,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAcceptedIP(void)));
  connect(m_ui.addAccount,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAccount(void)));
  connect(m_ui.addDistiller,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddDistiller(void)));
  connect(m_ui.addFriend,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddFriendsKey(void)));
  connect(m_ui.addInstitution,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddInstitution(void)));
  connect(m_ui.addInstitutionCheckBox,
	  SIGNAL(toggled(bool)),
	  m_ui.addInstitutionLineEdit,
	  SLOT(setEnabled(bool)));
  connect(m_ui.addInstitutionCheckBox,
	  SIGNAL(toggled(bool)),
	  m_ui.institutionFrame,
	  SLOT(setDisabled(bool)));
  connect(m_ui.addInstitutionCheckBox,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAddInstitutionCheckBoxToggled(bool)));
  connect(m_ui.addInstitutionLineEdit,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddInstitution(void)));
  connect(m_ui.addListener,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddListener(void)));
  connect(m_ui.addMagnet,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddEtpMagnet(void)));
  connect(m_ui.addNeighbor,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddNeighbor(void)));
  connect(m_ui.addNova,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddReceiveNova(void)));
  connect(m_ui.add_listener_reset,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotResetAddListener(void)));
  connect(m_ui.add_neighbor_reset,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotResetAddNeighbor(void)));
  connect(m_ui.answer,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.answer_authenticate,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.attachment,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotRemoveAttachment(const QUrl &)));
  connect(m_ui.buzzActions,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotBuzzActionsActivated(int)));
  connect(m_ui.buzzName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveBuzzName(void)));
  connect(m_ui.buzzTab,
	  SIGNAL(tabCloseRequested(int)),
	  this,
	  SLOT(slotCloseBuzzTab(int)));
  connect(m_ui.buzzTools,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotBuzzTools(int)));
  connect(m_ui.buzz_details,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowBuzzDetails(bool)));
  connect(m_ui.channel,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotJoinBuzzChannel(void)));
  connect(m_ui.chatSecrets,
	  SIGNAL(clicked(void)),
	  m_ui.chatSecrets,
	  SLOT(showMenu(void)));
  connect(m_ui.chatSecrets->menu(),
	  SIGNAL(aboutToShow(void)),
	  this,
	  SLOT(slotAboutToShowChatSecretsMenu(void)));
  connect(m_ui.clearFriend,
	  SIGNAL(clicked(void)),
	  m_ui.friendInformation,
	  SLOT(clear(void)));
  connect(m_ui.clearMessages,
	  SIGNAL(clicked(void)),
	  m_ui.messages,
	  SLOT(clear(void)));
  connect(m_ui.clearOutgoing,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClearOutgoingMessage(void)));
  connect(m_ui.commonBuzzChannels,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotCommonBuzzChannelsActivated(int)));
  connect(m_ui.congestionAlgorithm,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSaveCongestionAlgorithm(int)));
  connect(m_ui.copyInstitution,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopyInstitution(void)));
  connect(m_ui.correctUrlDatabases,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCorrectUrlDatabases(void)));
  connect(m_ui.cost,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotCostChanged(int)));
  connect(m_ui.custom,
	  SIGNAL(textChanged(void)),
	  this,
	  SLOT(slotSaveCustomStatus(void)));
  connect(m_ui.days,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotDaysChanged(int)));
  connect(m_ui.deactivateKernel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeactivateKernel(void)));
  connect(m_ui.deleteAEToken,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAEToken(void)));
  connect(m_ui.deleteAcceptedIP,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAcceptedIP(void)));
  connect(m_ui.deleteAccount,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAccount(void)));
  connect(m_ui.deleteDistillers,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteUrlDistillers(void)));
  connect(m_ui.deleteEmail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteMail(void)));
  connect(m_ui.deleteInstitution,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteInstitution(void)));
  connect(m_ui.deleteNova,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteNova(void)));
  connect(m_ui.destination,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveDestination(void)));
  connect(m_ui.discover,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDiscover(void)));
  connect(m_ui.domain,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddDistiller(void)));
  connect(m_ui.dynamicdns,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.email_pages,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotEmailLettersPerPageChanged(int)));
  connect(m_ui.emailNameEditable,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveEmailName(void)));
  connect(m_ui.emailSecrets,
	  SIGNAL(clicked(void)),
	  m_ui.emailSecrets,
	  SLOT(showMenu(void)));
  connect(m_ui.emailSecrets->menu(),
	  SIGNAL(aboutToShow(void)),
	  this,
	  SLOT(slotAboutToShowEmailSecretsMenu(void)));
  connect(m_ui.email_fs_gb,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotEmailFsGb(int)));
  connect(m_ui.emptyTrash,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotEmptyTrash(void)));
  connect(m_ui.encryptionKeyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotEncryptionKeyTypeChanged(int)));
  connect(m_ui.etpMaxMosaicSize,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMaxMosaicSize(int)));
  connect(m_ui.etpSelectDestination,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectDestination(void)));
  connect(m_ui.etpSelectFile,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectTransmitFile(void)));
  connect(m_ui.favorites,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotFavoritesActivated(int)));
#if SPOTON_GOLDBUG == 0
  connect(m_ui.find,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotFindInSearch(void)));
  connect(m_ui.find,
	  SIGNAL(textChanged(const QString &)),
	  this,
	  SLOT(slotFindInSearch(void)));
#endif
  connect(m_ui.folder,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotRefreshMail(void)));
  connect(m_ui.generate,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotGenerateEtpKeys(int)));
  connect(m_ui.generateNova,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotGenerateNova(void)));
  connect(m_ui.generate_institution_key_pair,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotGenerateInstitutionKeyPair(void)));
  connect(m_ui.git_chat,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotGITChat(bool)));
  connect(m_ui.hideOfflineParticipants,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotHideOfflineParticipants(bool)));
  connect(m_ui.humanProxy,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotBehaveAsHumanProxy(bool)));
  connect(m_ui.importUrls,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotImportUrls(void)));
  connect(m_ui.ipv4Listener,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.ipv4Neighbor,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.ipv6Listener,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.ipv6Neighbor,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.join,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotJoinBuzzChannel(void)));
  connect(m_ui.kernelCipherType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotKernelCipherTypeChanged(int)));
  connect(m_ui.kernelExternalIpFetch,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotExternalIp(int)));
  connect(m_ui.kernelHashType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotKernelHashTypeChanged(int)));
  connect(m_ui.kernelKeySize,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotKernelKeySizeChanged(int)));
  connect(m_ui.kernelLogEvents,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKernelLogEvents(bool)));
  connect(m_ui.kernelPath,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveKernelPath(void)));
  connect(m_ui.kernelSecureMemoryPool,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSecureMemoryPoolChanged(int)));
  connect(m_ui.keys,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotKeysIndexChanged(int)));
  connect(m_ui.listenerIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddListener(void)));
  connect(m_ui.listenerIPCombo,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotListenerIPComboChanged(int)));
  connect(m_ui.listenerTransport,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotTransportChanged(int)));
  connect(m_ui.listeners,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotListenerSelected(void)));
  connect(m_ui.magnetRadio,
	  SIGNAL(toggled(bool)),
	  m_ui.etpMagnet,
	  SLOT(setEnabled(bool)));
  connect(m_ui.magnetRadio,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotMagnetRadioToggled(bool)));
  connect(m_ui.mail,
	  SIGNAL(itemDoubleClicked(QTableWidgetItem *)),
	  this,
	  SLOT(slotMailSelected(QTableWidgetItem *)));
  connect(m_ui.mail,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotMailSelected(void)));
  connect(m_ui.mailTab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotMailTabChanged(int)));
  connect(m_ui.message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(m_ui.messages,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotLinkClicked(const QUrl &)));
  connect(m_ui.neighborIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddNeighbor(void)));
  connect(m_ui.neighborTransport,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotTransportChanged(int)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.encryptionKeySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.encryptionKeyType,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.signatureKeySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.signatureKeyType,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotNewKeys(bool)));
  connect(m_ui.nodeName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(m_ui.pairRadio,
	  SIGNAL(toggled(bool)),
	  m_ui.generate,
	  SLOT(setEnabled(bool)));
  connect(m_ui.pairRadio,
	  SIGNAL(toggled(bool)),
	  m_ui.pairFrame,
	  SLOT(setEnabled(bool)));
  connect(m_ui.participants,
	  SIGNAL(itemChanged(QTableWidgetItem *)),
	  this,
	  SLOT(slotParticipantsItemChanged(QTableWidgetItem *)));
  connect(m_ui.participants,
	  SIGNAL(itemDoubleClicked(QTableWidgetItem *)),
	  this,
	  SLOT(slotParticipantDoubleClicked(QTableWidgetItem *)));
  connect(m_ui.passphrase,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.passphrase1,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.passphrase1,
	  SIGNAL(textChanged(const QString &)),
	  this,
	  SLOT(slotPassphraseChanged(const QString &)));
  connect(m_ui.passphrase2,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.passphraseButton,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.passphrase_rb,
	  SIGNAL(toggled(bool)),
	  m_ui.answer,
	  SLOT(setDisabled(bool)));
  connect(m_ui.passphrase_rb,
	  SIGNAL(toggled(bool)),
	  m_ui.passphrase1,
	  SLOT(setEnabled(bool)));
  connect(m_ui.passphrase_rb,
	  SIGNAL(toggled(bool)),
	  m_ui.passphrase2,
	  SLOT(setEnabled(bool)));
  connect(m_ui.passphrase_rb,
	  SIGNAL(toggled(bool)),
	  m_ui.question,
	  SLOT(setDisabled(bool)));
  connect(m_ui.passphrase_rb,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPassphraseRadioToggled(bool)));
  connect(m_ui.passphrase_rb_authenticate,
	  SIGNAL(toggled(bool)),
	  m_ui.answer_authenticate,
	  SLOT(setDisabled(bool)));
  connect(m_ui.passphrase_rb_authenticate,
	  SIGNAL(toggled(bool)),
	  m_ui.passphrase,
	  SLOT(setEnabled(bool)));
  connect(m_ui.passphrase_rb_authenticate,
	  SIGNAL(toggled(bool)),
	  m_ui.question_authenticate,
	  SLOT(setDisabled(bool)));
  connect(m_ui.passphrase_rb_authenticate,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPassphraseAuthenticateRadioToggled(bool)));
  connect(m_ui.postgresqlConnect,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPostgreSQLConnect(void)));
  connect(m_ui.postgresql_credentials,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPostgreSQLWebServerCredentials(void)));
  connect(m_ui.postofficeCheckBox,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotEnabledPostOffice(bool)));
  connect(m_ui.prepareUrlDatabases,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPrepareUrlDatabases(void)));
  connect(m_ui.proxy,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProxyChecked(bool)));
  connect(m_ui.proxyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotProxyTypeChanged(int)));
  connect(m_ui.question,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.question_authenticate,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.receiveNova,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddReceiveNova(void)));
  connect(m_ui.receivers,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotReceiversClicked(bool)));
  connect(m_ui.refreshDistillers,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshUrlDistillers(void)));
  connect(m_ui.refreshMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshMail(void)));
  connect(m_ui.refreshMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshPostOffice(void)));
  connect(m_ui.reloadEmailNames,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotReloadEmailNames(void)));
  connect(m_ui.reloadIni,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSetUrlIniPath(void)));
  connect(m_ui.reply,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotReply(void)));
  connect(m_ui.requireSsl,
	  SIGNAL(toggled(bool)),
	  m_ui.addException,
	  SLOT(setEnabled(bool)));
  connect(m_ui.requireSsl,
	  SIGNAL(toggled(bool)),
	  m_ui.neighborKeySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.requireSsl,
	  SIGNAL(toggled(bool)),
	  m_ui.neighborsSslControlString,
	  SLOT(setEnabled(bool)));
  connect(m_ui.requireSsl,
	  SIGNAL(toggled(bool)),
	  m_ui.sslKeySizeLabel,
	  SLOT(setEnabled(bool)));
  connect(m_ui.resend,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotResendMail(void)));
  connect(m_ui.reset_search_results,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotResetSearch(void)));
  connect(m_ui.retrieveMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRetrieveMail(void)));
  connect(m_ui.rewind,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRewindFile(void)));
  connect(m_ui.saveAttachment,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveAttachment(void)));
  connect(m_ui.saveBuzzName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveBuzzName(void)));
  connect(m_ui.saveCommonUrlCredentials,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveCommonUrlCredentials(void)));
  connect(m_ui.saveMOTD,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveMOTD(void)));
  connect(m_ui.saveNodeName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(m_ui.saveUrlCredentials,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveUrlCredentials(void)));
  connect(m_ui.saveUrlName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveUrlName(void)));
  connect(m_ui.search,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotDiscover(void)));
  connect(m_ui.secondary_storage,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveSecondaryStorage(bool)));
  connect(m_ui.secondary_storage_maximum_page_count,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSetCongestionMaxPageCount(int)));
  connect(m_ui.selectAttachment,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAttachment(void)));
  connect(m_ui.selectKernelPath,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectKernelPath(void)));
  connect(m_ui.selectUrlIni,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectUrlIniPath(void)));
  connect(m_ui.sendMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMail(void)));
  connect(m_ui.sendMessage,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(m_ui.setPassphrase,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.showStatistics,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotShowStatistics(void)));
  connect(m_ui.showUrlSettings,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowUrlSettings(bool)));
  connect(m_ui.signatureKeyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSignatureKeyTypeChanged(int)));
  connect(m_ui.soss_maximum_clients,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSOSSMaximumClientsChanged(int)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.days_valid,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.listenerKeySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.listenersSslControlString,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.recordIPAddress,
	  SLOT(setEnabled(bool)));
  connect(m_ui.status,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotStatusChanged(int)));
  connect(m_ui.tab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotTabChanged(int)));
  connect(m_ui.transmit,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTransmit(void)));
  connect(m_ui.transmitted,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotTransmittedSelected(void)));
  connect(m_ui.urlDistributionModel,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSaveUrlDistribution(int)));
  connect(m_ui.urlIniPath,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetUrlIniPath(void)));
  connect(m_ui.urlName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveUrlName(void)));
  connect(m_ui.url_pages,
	  SIGNAL(linkActivated(const QString &)),
	  this,
	  SLOT(slotPageClicked(const QString &)));
  connect(m_ui.urls,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotUrlLinkClicked(const QUrl &)));
  connect(m_ui.urls_db_type,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotPostgreSQLDisconnect(int)));
  connect(m_ui.verify,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotVerify(void)));
  connect(m_ui.web_server_port,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotWebServerPortChanged(int)));
  connect(m_ui.web_server_serve_local_content,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotWebServerAllowServingLocalContent(bool)));
  m_ui.passphrase_rb->setChecked(true);
  m_ui.passphrase_rb_authenticate->setChecked(true);
  m_ui.answer->setEnabled(false);
  m_ui.answer_authenticate->setEnabled(false);
  m_ui.question->setEnabled(false);
  m_ui.question_authenticate->setEnabled(false);
  m_ui.resend->setEnabled(false);
  m_sb.kernelstatus->setToolTip
    (tr("<html>The interface is not connected to the kernel. "
	"Is the kernel active?</html>"));
  m_sb.listeners->setToolTip(tr("Listeners are offline."));
  m_sb.neighbors->setToolTip(tr("Neighbors are offline."));
  menu = new QMenu(this);
  connect
    (menu->addAction(tr("Copy &Chat Public Key Pair")),
     SIGNAL(triggered(void)),
     this,
     SLOT(slotCopyMyChatPublicKey(void)));
  connect
    (menu->addAction(tr("Copy &E-Mail Public Key Pair")),
     SIGNAL(triggered(void)),
     this,
     SLOT(slotCopyMyEmailPublicKey(void)));
#ifdef SPOTON_OPEN_LIBRARY_SUPPORTED
  connect
    (menu->addAction(tr("Copy &Open Library Public Key Pair")),
     SIGNAL(triggered(void)),
     this,
     SLOT(slotCopyMyOpenLibraryPublicKey(void)));
#endif
  connect
    (menu->addAction(tr("Copy &Poptastic Public Key Pair")),
     SIGNAL(triggered(void)),
     this,
     SLOT(slotCopyMyPoptasticPublicKey(void)));
  connect
    (menu->addAction(tr("Copy &Rosetta Public Key Pair")),
     SIGNAL(triggered(void)),
     this,
     SLOT(slotCopyMyRosettaPublicKey(void)));
  connect
    (menu->addAction(tr("Copy &URL Public Key Pair")),
     SIGNAL(triggered(void)),
     this,
     SLOT(slotCopyMyURLPublicKey(void)));
  menu->addSeparator();
  connect(menu->addAction(tr("Copy &All Public Key Pairs")),
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyAllMyPublicKeys(void)));
  m_ui.commonBuzzChannels->setItemData
    (0,
     "magnet:?rn=Spot-On_Developer_Channel_Key&xf=10000&"
     "xs=Spot-On_Developer_Channel_Salt&ct=aes256&"
     "hk=Spot-On_Developer_Channel_Hash_Key&ht=sha384&xt=urn:buzz");
  m_ui.toolButtonCopyToClipboard->setMenu(menu);
  menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
  menu = new QMenu(this);
  menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
  m_ui.shareBuzzMagnet->setMenu(menu);
  m_generalTimer.start(1500);
  m_chatInactivityTimer.start(120000);
  m_updateChatWindowsTimer.start(3500);
  m_webServerInformationTimer.start(10000);
  m_ui.ipv4Listener->setChecked(true);
  m_ui.listenerIP->setInputMask("");
  m_ui.addInstitutionLineEdit->setEnabled(false);
  m_ui.listenerScopeId->setEnabled(false);
  m_ui.listenerScopeIdLabel->setEnabled(false);
  m_ui.listenerShareAddress->setEnabled(false);
  m_ui.neighborIP->setInputMask("");
  m_ui.neighborScopeId->setEnabled(false);
  m_ui.neighborScopeIdLabel->setEnabled(false);
#if defined(Q_OS_WINDOWS)
  m_ui.emailParticipants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
  m_ui.participants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
  m_ui.urlParticipants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
#endif
  splash->showMessage
    (tr("Preparing INI entries."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();

  if(!settings.contains("gui/saveCopy"))
    settings.setValue("gui/saveCopy", true);

  if(!settings.contains("gui/uuid"))
    {
      auto const uuid(QUuid::createUuid());

      settings.setValue("gui/uuid", uuid.toString());
    }

  for(int i = 0; i < settings.allKeys().size(); i++)
    m_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

  splash->showMessage
    (tr("Validating INI values."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();
  spoton_misc::correctSettingsContainer(m_settings);
  spoton_misc::setTimeVariables(m_settings);
  splash->showMessage
    (tr("Applying INI values."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();
  m_externalAddress->setUrl
    (QUrl::fromUserInput(m_settings.value("gui/external_ip_url").toString()));
  m_ui.activeUrlDistribution->setChecked
    (m_settings.value("gui/activeUrlDistribution", false).toBool());
  m_ui.action_Buzz->setChecked
    (m_settings.value("gui/showBuzzPage", true).toBool());
  m_ui.action_Listeners->setChecked
    (m_settings.value("gui/showListenersPage", true).toBool());
  m_ui.action_Neighbors->setChecked
    (m_settings.value("gui/showNeighborsPage", true).toBool());
  m_ui.action_Search->setChecked
    (m_settings.value("gui/showSearchPage", true).toBool());
  m_ui.action_StarBeam->setChecked
    (m_settings.value("gui/showStarBeamPage", true).toBool());
  m_ui.action_Urls->setChecked
    (m_settings.value("gui/showUrlsPage", true).toBool());
  m_ui.email_pages->setValue
    (m_settings.value("gui/email_letters_per_page", 500).toInt());
  m_ui.git_chat->setChecked(m_settings.value("gui/git_chat", false).toBool());
  m_ui.humanProxy->setChecked
    (m_settings.value("gui/human_proxy", false).toBool());
  m_ui.secondary_storage_maximum_page_count->setValue
    (m_settings.value("gui/congestion_control_max_page_count", 10000).toInt());
  m_ui.soss_maximum_clients->blockSignals(true);
  m_ui.soss_maximum_clients->setValue
    (m_settings.value("gui/soss_maximum_clients", 10).toInt());
  m_ui.soss_maximum_clients->blockSignals(false);
  m_ui.web_server_port->blockSignals(true);
  m_ui.web_server_port->setValue
    (m_settings.value("gui/web_server_port", 0).toInt());
  m_ui.web_server_port->blockSignals(false);
  m_ui.web_server_serve_local_content->blockSignals(true);
  m_ui.web_server_serve_local_content->setChecked
    (m_settings.value("gui/web_server_serve_local_content", false).toBool());
  m_ui.web_server_serve_local_content->blockSignals(false);

  if(m_ui.postgresqlConnect->isEnabled())
    {
      if(m_settings.value("gui/sqliteSearch", true).toBool())
	m_ui.urls_db_type->setCurrentIndex(1);
      else
	m_ui.urls_db_type->setCurrentIndex(0);
    }
  else
    m_ui.urls_db_type->setCurrentIndex(1);

  slotPostgreSQLDisconnect(m_ui.urls_db_type->currentIndex());

  if(m_ui.urls_db_type->currentIndex() == 1)
    m_ui.showUrlSettings->setChecked(false);

  m_optionsUi.buzz_maximum_lines->setValue
    (m_settings.value("gui/buzz_maximum_lines", -1).toInt());
  m_optionsUi.chatUpdateInterval->setValue
    (m_settings.value("gui/participantsUpdateTimer", 3.50).toDouble());
  m_optionsUi.chat_maximum_lines->setValue
    (m_settings.value("gui/chat_maximum_lines", -1).toInt());
  m_emailRetrievalTimer.setInterval
    (m_settings.value("gui/emailRetrievalInterval", 5 * 60 * 1000).toInt());
  m_optionsUi.kernelCacheInterval->setValue
    (m_settings.value("kernel/cachePurgeInterval", 15.00).toDouble());
  m_optionsUi.kernelUpdateInterval->setValue
    (m_settings.value("gui/kernelUpdateTimer", 3.50).toDouble());
  m_optionsUi.listenersUpdateInterval->setValue
    (m_settings.value("gui/listenersUpdateTimer", 3.50).toDouble());
  m_optionsUi.neighborsUpdateInterval->setValue
    (m_settings.value("gui/neighborsUpdateTimer", 3.50).toDouble());
  m_optionsUi.starbeamUpdateInterval->setValue
    (m_settings.value("gui/starbeamUpdateTimer", 3.50).toDouble());
  m_optionsUi.searchResultsPerPage->setValue
    (m_settings.value("gui/searchResultsPerPage", 10).toInt());
  m_optionsUi.maximum_url_keywords_interface->setValue
    (m_settings.value("gui/maximum_url_keywords_import_interface", 50).
     toInt());
  m_optionsUi.maximum_url_keywords_kernel->setValue
    (m_settings.value("gui/maximum_url_keywords_import_kernel", 50).toInt());
  m_optionsUi.kernel_url_batch_size->setValue
    (m_settings.value("gui/kernel_url_batch_size", 5).toInt());
  m_optionsUi.postgresql_kernel_url_distribution_timeout->setValue
    (m_settings.value("gui/postgresql_kernel_url_distribution_timeout", 45000).
     toInt());
  m_optionsUi.tear_off_menus->setChecked
    (m_settings.value("gui/tear_off_menus", true).toBool());
  m_optionsUi.terminate_kernel_on_ui_exit->setChecked
    (m_settings.value("gui/terminate_kernel_on_ui_exit", false).toBool());
  m_kernelUpdateTimer.start
    (static_cast<int> (1000 * m_optionsUi.kernelUpdateInterval->value()));
  m_listenersUpdateTimer.start
    (static_cast<int> (1000 * m_optionsUi.listenersUpdateInterval->value()));
  m_neighborsUpdateTimer.start
    (static_cast<int> (1000 * m_optionsUi.neighborsUpdateInterval->value()));
  m_participantsUpdateTimer.start
    (static_cast<int> (1000 * m_optionsUi.chatUpdateInterval->value()));
  m_starbeamUpdateTimer.start
    (static_cast<int> (1000 * m_optionsUi.starbeamUpdateInterval->value()));
  m_tableTimer.start(3500);

#if SPOTON_GOLDBUG == 1
  auto str(m_settings.value("gui/tabPosition", "east").toString().toLower());
#else
  auto str(m_settings.value("gui/tabPosition", "north").toString().toLower());
#endif

  if(str == "east")
    m_optionsUi.position->setCurrentIndex(0);
  else if(str == "north")
    m_optionsUi.position->setCurrentIndex(1);
  else if(str == "south")
    m_optionsUi.position->setCurrentIndex(2);
  else if(str == "west")
    m_optionsUi.position->setCurrentIndex(3);
  else
#if SPOTON_GOLDBUG == 1
    m_optionsUi.position->setCurrentIndex(0);
#else
    m_optionsUi.position->setCurrentIndex(1);
#endif

  m_sb.errorlog->setIcon
    (QIcon(QString(":/%1/information.png").
	   arg(m_settings.value("gui/iconSet", "nouve").toString().
	       toLower())));
  m_sb.kernelstatus->setIcon
    (QIcon(QString(":/%1/deactivate.png").
	   arg(m_settings.value("gui/iconSet", "nouve").toString().
	       toLower())));
  m_sb.listeners->setIcon
    (QIcon(QString(":/%1/status-offline.png").
	   arg(m_settings.value("gui/iconSet", "nouve").toString().
	       toLower())));
  m_sb.neighbors->setIcon
    (QIcon(QString(":/%1/status-offline.png").
	   arg(m_settings.value("gui/iconSet", "nouve").toString().
	       toLower())));

  if(m_settings.contains("gui/geometry"))
    restoreGeometry(m_settings.value("gui/geometry").toByteArray());

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
#if defined(Q_OS_LINUX)
  m_optionsUi.geoipPath4->setText
    (m_settings.value("gui/geoipPath4",
		      "/usr/share/GeoIP/GeoIP.dat").toString());
  m_optionsUi.geoipPath4->setCursorPosition(0);
  m_optionsUi.geoipPath6->setText
    (m_settings.value("gui/geoipPath6",
		      "/usr/share/GeoIP/GeoIP.dat").toString());
  m_optionsUi.geoipPath6->setCursorPosition(0);
#elif defined(Q_OS_WINDOWS)
  m_optionsUi.geoipPath4->setText
    (m_settings.value("gui/geoipPath4", "GeoIP.dat").toString());
  m_optionsUi.geoipPath4->setCursorPosition(0);
  m_optionsUi.geoipPath6->setText
    (m_settings.value("gui/geoipPath6", "GeoIP.dat").toString());
  m_optionsUi.geoipPath6->setCursorPosition(0);
#else
  m_optionsUi.geoipPath4->setText
    (m_settings.value("gui/geoipPath4", "GeoIP.dat").toString());
  m_optionsUi.geoipPath4->setCursorPosition(0);
  m_optionsUi.geoipPath6->setText
    (m_settings.value("gui/geoipPath6", "GeoIP.dat").toString());
  m_optionsUi.geoipPath6->setCursorPosition(0);
#endif
#endif
  m_ui.urlIniPath->setText
    (m_settings.value("gui/urlIniPath", "").toString());
  m_ui.urlIniPath->setCursorPosition(0);
  m_ui.magnetRadio->setChecked(true);
  m_ui.generate->setEnabled(false);
  m_ui.pairFrame->setEnabled(false);

#ifdef Q_OS_MACOS
  if(m_settings.contains("gui/kernelPath") &&
     QFileInfo(m_settings.value("gui/kernelPath").toString()).isBundle())
    m_ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString());
  else if(m_settings.contains("gui/kernelPath") &&
	  QFileInfo(m_settings.value("gui/kernelPath").toString()).
	  isExecutable())
    m_ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString());
  else
#if SPOTON_GOLDBUG == 0
    m_ui.kernelPath->setText("Spot-On-Kernel.app");
#else
    m_ui.kernelPath->setText("Spot-On-Kernel.app");
#endif
#else
  if(m_settings.contains("gui/kernelPath") &&
     QFileInfo(m_settings.value("gui/kernelPath").toString()).isExecutable())
    m_ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString());
  else
    {
      auto const path(QCoreApplication::applicationDirPath() +
		      QDir::separator() +
#if defined(Q_OS_WINDOWS)
		      "Spot-On-Kernel.exe"
#else
		      "Spot-On-Kernel"
#endif
		      );

      m_ui.kernelPath->setText(path);
    }
#endif

  m_ui.kernelPath->setCursorPosition(0);

  if(m_settings.value("gui/chatSendMethod", "Artificial_GET").
     toString().toLower() == "artificial_get")
    m_optionsUi.chatSendMethod->setCurrentIndex(1);
  else
    m_optionsUi.chatSendMethod->setCurrentIndex(0);

  auto keySize(m_settings.value("gui/kernelKeySize", "2048").toString());

  if(m_ui.kernelKeySize->findText(keySize) > -1)
    m_ui.kernelKeySize->setCurrentIndex(m_ui.kernelKeySize->findText(keySize));
  else
    m_ui.kernelKeySize->setCurrentIndex(4); // 2048

  m_kernelSocket.setProperty
    ("key_size", m_ui.kernelKeySize->currentText().toInt());
  keySize = m_settings.value("gui/publishedKeySize", "2048").toString();

  if(m_optionsUi.publishedKeySize->findText(keySize) > -1)
    m_optionsUi.publishedKeySize->setCurrentIndex
      (m_optionsUi.publishedKeySize->findText(keySize));
  else
    m_optionsUi.publishedKeySize->setCurrentIndex(3); // 2048

  auto const status
    (m_settings.value("gui/my_status", "Online").toByteArray().toLower());

  m_ui.custom->setText
    (QString::fromUtf8(m_settings.value("gui/customStatus", "").
		       toByteArray().constData(),
		       m_settings.value("gui/customStatus", "").
		       toByteArray().length()).trimmed());
  m_ui.custom->setVisible(false);

  if(status == "away")
    m_ui.status->setCurrentIndex(0);
  else if(status == "busy")
    m_ui.status->setCurrentIndex(1);
  else if(status == "custom")
    {
      m_ui.custom->setVisible(true);
      m_ui.status->setCurrentIndex(2);
    }
  else if(status == "offline")
    m_ui.status->setCurrentIndex(3);
  else
    m_ui.status->setCurrentIndex(4);

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  if(!m_optionsUi.geoipPath4->text().isEmpty())
    m_optionsUi.geoipPath4->setToolTip(m_optionsUi.geoipPath4->text());

  if(!m_optionsUi.geoipPath6->text().isEmpty())
    m_optionsUi.geoipPath6->setToolTip(m_optionsUi.geoipPath6->text());
#endif

  /*
  ** Please note that Spot-On supports only ciphers having 256-bit
  ** keys.
  */

  m_ui.kernelPath->setToolTip(m_ui.kernelPath->text());
  m_ui.buzzName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.buzzName->setText
    (QString::fromUtf8(m_settings.value("gui/buzzName", "unknown").
		       toByteArray().constData(),
		       m_settings.value("gui/buzzName", "unknown").
		       toByteArray().length()).trimmed());
  m_ui.buzzName->setCursorPosition(0);
  m_ui.channel->setMaxLength
    (static_cast<int> (spoton_crypt::
		       cipherKeyLength(spoton_crypt::
				       preferredCipherAlgorithm())));
  m_ui.emailName->clear();
  m_ui.emailName->addItem
    (QString::fromUtf8(m_settings.value("gui/emailName", "unknown").
		       toByteArray().constData(),
		       m_settings.value("gui/emailName", "unknown").
		       toByteArray().length()).trimmed());
  m_ui.emailNameEditable->setText(m_ui.emailName->currentText());
  m_ui.emailNameEditable->setCursorPosition(0);
  m_ui.nodeName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.nodeName->setText
    (QString::fromUtf8(m_settings.value("gui/nodeName", "unknown").
		       toByteArray().constData(),
		       m_settings.value("gui/nodeName", "unknown").
		       toByteArray().length()).trimmed());
  m_ui.nodeName->setCursorPosition(0);
  m_ui.pulseSize->setMaximum(spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE);
  m_ui.urlName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.urlName->setText
    (QString::fromUtf8(m_settings.value("gui/urlName", "unknown").
		       toByteArray().constData(),
		       m_settings.value("gui/urlName", "unknown").
		       toByteArray().length()).trimmed());
  m_ui.urlName->setCursorPosition(0);
  m_ui.username->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.receiveNova->setMaxLength
    (static_cast<int> (spoton_crypt::
		       cipherKeyLength(spoton_crypt::
				       preferredCipherAlgorithm())) + 512);
  m_optionsUi.external_ip_url->setText
    (m_settings.value("gui/external_ip_url",
		      "https://api.ipify.org").toString());
  m_optionsUi.external_ip_url->setCursorPosition(0);
  m_optionsUi.sslControlString->setText
    (m_settings.value("gui/sslControlString",
		      spoton_common::SSL_CONTROL_STRING).toString());
  m_optionsUi.sslControlString->setCursorPosition(0);
  m_ui.etpEncryptionKey->setMaxLength
    (static_cast<int> (spoton_crypt::
		       cipherKeyLength(spoton_crypt::
				       preferredCipherAlgorithm())));
  m_ui.institutionName->setMaxLength
    (static_cast<int> (spoton_crypt::
		       cipherKeyLength(spoton_crypt::
				       preferredCipherAlgorithm())));
  m_ui.transmitNova->setMaxLength
    (static_cast<int> (spoton_crypt::
		       cipherKeyLength(spoton_crypt::
				       preferredCipherAlgorithm())) + 512);
  m_ui.channelType->addItems(spoton_crypt::cipherTypes());
  m_ui.cipherType->blockSignals(true);
  m_ui.cipherType->addItems(spoton_crypt::cipherTypes());
  m_ui.cipherType->blockSignals(false);
  m_ui.commonUrlCipher->addItems(spoton_crypt::cipherTypes());
  m_ui.commonUrlHash->addItems(spoton_crypt::hashTypes());
  m_ui.congestionAlgorithm->blockSignals(true);
  m_ui.congestionAlgorithm->addItems(spoton_crypt::congestionHashAlgorithms());
  m_ui.congestionAlgorithm->blockSignals(false);
  m_ui.etpCipherType->addItems(spoton_crypt::cipherTypes());
  m_ui.ae_e_type->addItems(spoton_crypt::cipherTypes());
  m_ui.ae_h_type->addItems(spoton_crypt::hashTypes());
  m_ui.etpHashType->addItems(spoton_crypt::hashTypes());
  m_ui.buzzHashType->addItems(spoton_crypt::buzzHashTypes());
  m_ui.institutionNameType->addItems(spoton_crypt::cipherTypes());
  m_ui.institutionPostalAddressType->addItems(spoton_crypt::hashTypes());
  m_ui.kernelCipherType->blockSignals(true);
  m_ui.kernelCipherType->addItems(spoton_crypt::cipherTypes());
  m_ui.kernelCipherType->blockSignals(false);
  m_ui.kernelHashType->blockSignals(true);
  m_ui.kernelHashType->addItems(spoton_crypt::hashTypes());
  m_ui.kernelHashType->blockSignals(false);
  m_ui.urlCipher->addItems(spoton_crypt::cipherTypes());
  m_ui.urlHash->addItems(spoton_crypt::hashTypes());
  m_ui.cost->setValue(m_settings.value("gui/congestionCost", 10000).toInt());
  m_ui.days->setValue(m_settings.value("gui/postofficeDays", 1).toInt());
  m_ui.etpMaxMosaicSize->setValue
    (m_settings.value("gui/maxMosaicSize", 512).toInt());
  m_optionsUi.emailRetrievalInterval->setValue
    (m_settings.value("gui/emailRetrievalInterval", 5).toInt());
  m_optionsUi.maximumEmailFileSize->setValue
    (m_settings.value("gui/maximumEmailFileSize", 1024).toInt());

  auto const statusControl
    (m_settings.
     value("gui/acceptPublicizedListeners",
	   "localConnected").toString().toLower());

  if(statusControl == "localconnected")
    {
      m_optionsUi.acceptPublishedLocalConnected->setChecked(true);
      m_optionsUi.publishedKeySize->setEnabled(true);
    }
  else if(statusControl == "connected")
    {
      m_optionsUi.acceptPublishedConnected->setChecked(true);
      m_optionsUi.publishedKeySize->setEnabled(true);
    }
  else if(statusControl == "disconnected")
    {
      m_optionsUi.acceptPublishedDisconnected->setChecked(true);
      m_optionsUi.publishedKeySize->setEnabled(true);
    }
  else
    {
      m_optionsUi.ignorePublished->setChecked(true);
      m_optionsUi.publishedKeySize->setEnabled(false);
    }

  m_optionsUi.acceptChatKeys->setChecked
    (m_settings.value("gui/acceptChatKeys", false).toBool());
  m_optionsUi.acceptEmailKeys->setChecked
    (m_settings.value("gui/acceptEmailKeys", false).toBool());
  m_optionsUi.acceptGeminis->setChecked
    (m_settings.value("gui/acceptGeminis", true).toBool());
  m_optionsUi.acceptUrlKeys->setChecked
    (m_settings.value("gui/acceptUrlKeys", false).toBool());
  m_optionsUi.autoAddSharedSBMagnets->setChecked
    (m_settings.value("gui/autoAddSharedSBMagnets", true).toBool());
  m_optionsUi.buzzAutoJoin->setChecked
    (m_settings.value("gui/buzzAutoJoin", true).toBool());
  m_optionsUi.enableChatEmoticons->setChecked
    (m_settings.value("gui/enableChatEmoticons", false).toBool());
  m_optionsUi.forceRegistration->setChecked
    (m_settings.value("gui/forceKernelRegistration", true).toBool());
  m_optionsUi.launchKernel->setChecked
    (m_settings.value("gui/launchKernelAfterAuth", false).toBool());
  m_ui.hideOfflineParticipants->setChecked
    (m_settings.value("gui/hideOfflineParticipants", false).toBool());
  m_optionsUi.keepOnlyUserDefinedNeighbors->setChecked
    (m_settings.value("gui/keepOnlyUserDefinedNeighbors", true).toBool());
  m_ui.kernelLogEvents->setChecked
    (m_settings.value("gui/kernelLogEvents", false).toBool());
  m_optionsUi.limitConnections->setValue
    (m_settings.value("gui/limitConnections", 10).toInt());
  m_optionsUi.monitor->setChecked
    (m_settings.value("gui/monitorEvents", true).toBool());
  m_optionsUi.notifications->setChecked
    (m_settings.value("gui/automaticNotifications", false).toBool());
  m_optionsUi.openlinks->setChecked
    (m_settings.value("gui/openLinks", false).toBool());
  m_ui.postofficeCheckBox->setChecked
    (m_settings.value("gui/postoffice_enabled", false).toBool());
  m_optionsUi.publishPeriodically->setChecked
    (m_settings.value("gui/publishPeriodically", false).toBool());
  m_optionsUi.refreshEmail->setChecked
    (m_settings.value("gui/refreshEmail", false).toBool());
  m_optionsUi.chatAlternatingRowColors->setChecked
    (m_settings.value("gui/chatAlternatingRowColors", true).toBool());
  m_optionsUi.emailAlternatingRowColors->setChecked
    (m_settings.value("gui/emailAlternatingRowColors", true).toBool());
  m_optionsUi.urlsAlternatingRowColors->setChecked
    (m_settings.value("gui/urlsAlternatingRowColors", true).toBool());
  m_optionsUi.saveCopy->setChecked
    (m_settings.value("gui/saveCopy", true).toBool());
  m_ui.secondary_storage->setChecked
    (m_settings.value("gui/secondary_storage_congestion_control",
		      false).toBool());
  m_optionsUi.scrambler->setChecked
    (m_settings.value("gui/scramblerEnabled", false).toBool());
  m_optionsUi.starbeamAutoVerify->setChecked
    (m_settings.value("gui/starbeamAutoVerify", false).toBool());
  m_optionsUi.superEcho->setCurrentIndex
    (m_settings.value("gui/superEcho", 1).toInt()); // Disabled by default.

  if(m_optionsUi.superEcho->currentIndex() < 0)
    m_optionsUi.superEcho->setCurrentIndex(1); // Disabled.

  m_optionsUi.chatAcceptSigned->setChecked
    (m_settings.value("gui/chatAcceptSignedMessagesOnly", true).toBool());
  m_optionsUi.chatSignMessages->setChecked
    (m_settings.value("gui/chatSignMessages", true).toBool());
  m_optionsUi.emailAcceptSigned->setChecked
    (m_settings.value("gui/emailAcceptSignedMessagesOnly", true).toBool());
  m_optionsUi.emailSignMessages->setChecked
    (m_settings.value("gui/emailSignMessages", true).toBool());
  m_optionsUi.coAcceptSigned->setChecked
    (m_settings.value("gui/coAcceptSignedMessagesOnly", true).toBool());
  m_optionsUi.urlAcceptSigned->setChecked
    (m_settings.value("gui/urlAcceptSignedMessagesOnly", true).toBool());
  m_optionsUi.autoEmailRetrieve->setChecked
    (m_settings.value("gui/automaticallyRetrieveEmail", false).toBool());
  m_optionsUi.acceptBuzzMagnets->setChecked
    (m_settings.value("gui/acceptBuzzMagnets", false).toBool());
  m_optionsUi.impersonate->setChecked
    (m_settings.value("gui/impersonate", false).toBool());
  m_optionsUi.displayPopups->setChecked
    (m_settings.value("gui/displayPopupsAutomatically", true).toBool());
  m_optionsUi.limit_sqlite_synchronization->setChecked
    (m_settings.value("gui/limit_sqlite_synchronization", false).toBool());
  m_optionsUi.sharePrivateKeys->setChecked
    (m_settings.value("gui/sharePrivateKeysWithKernel", true).toBool());
#if defined(Q_OS_MACOS) || defined(Q_OS_WINDOWS)
  m_optionsUi.ontopChatDialogs->setChecked
    (m_settings.value("gui/ontopChatDialogs", false).toBool());
#else
  m_optionsUi.ontopChatDialogs->setChecked(false);
  m_optionsUi.ontopChatDialogs->setEnabled(false);
  settings.setValue("gui/ontopChatDialogs", false);
#endif
  m_optionsUi.urlSignMessages->setChecked
    (m_settings.value("gui/urlSignMessages", true).toBool());
  m_optionsUi.remove_otm->setChecked
    (m_settings.value("gui/removeOtmOnExit", false).toBool());
  m_optionsUi.chat_fs_request->setChecked
    (m_settings.value("gui/allowChatFSRequest", true).toBool());
  m_optionsUi.email_fs_request->setChecked
    (m_settings.value("gui/allowEmailFSRequest", true).toBool());
  m_optionsUi.disable_kernel_synchronous_download->setChecked
    (m_settings.value("gui/disable_kernel_synchronous_sqlite_url_download",
		      false).toBool());
  m_optionsUi.disable_ui_synchronous_import->setChecked
    (m_settings.value("gui/disable_ui_synchronous_sqlite_url_import", false).
     toBool());
  m_optionsUi.chatOpenLinks->setChecked
    (m_settings.value("gui/openChatUrl", false).toBool());
  m_optionsUi.chatTimestamps->setChecked
    (m_settings.value("gui/chatTimestamps", true).toBool());
  m_optionsUi.play_sounds->setChecked
    (m_settings.value("gui/play_sounds", false).toBool());
  m_optionsUi.play_sounds->setToolTip
    (tr("<html>Please place the Sounds directory in the directory which "
	"houses the %1 executable.</html>").arg(SPOTON_APPLICATION_NAME));

  /*
  ** Please don't translate n/a.
  */

  if(m_ui.ae_e_type->count() == 0)
    m_ui.ae_e_type->addItem("n/a");

  if(m_ui.ae_h_type->count() == 0)
    m_ui.ae_h_type->addItem("n/a");

  if(m_ui.channelType->count() == 0)
    m_ui.channelType->addItem("n/a");

  if(m_ui.cipherType->count() == 0)
    m_ui.cipherType->addItem("n/a");

  if(m_ui.commonUrlCipher->count() == 0)
    m_ui.commonUrlCipher->addItem("n/a");

  if(m_ui.commonUrlHash->count() == 0)
    m_ui.commonUrlHash->addItem("n/a");

  if(m_ui.congestionAlgorithm->count() == 0)
    m_ui.congestionAlgorithm->addItem("n/a");

  if(m_ui.etpCipherType->count() == 0)
    m_ui.etpCipherType->addItem("n/a");

  if(m_ui.etpHashType->count() == 0)
    m_ui.etpHashType->addItem("n/a");

  if(m_ui.institutionNameType->count() == 0)
    m_ui.institutionNameType->addItem("n/a");

  if(m_ui.institutionPostalAddressType->count() == 0)
    m_ui.institutionPostalAddressType->addItem("n/a");

  if(m_ui.kernelCipherType->count() == 0)
    m_ui.kernelCipherType->addItem("n/a");

  if(m_ui.kernelHashType->count() == 0)
    m_ui.kernelHashType->addItem("n/a");

  if(m_ui.buzzHashType->count() == 0)
    m_ui.buzzHashType->addItem("n/a");

  m_ui.hashType->blockSignals(true);
  m_ui.hashType->addItems(spoton_crypt::hashTypes());
  m_ui.hashType->blockSignals(false);

  if(m_ui.hashType->count() == 0)
    m_ui.hashType->addItem("n/a");

  if(m_ui.urlCipher->count() == 0)
    m_ui.urlCipher->addItem("n/a");

  if(m_ui.urlHash->count() == 0)
    m_ui.urlHash->addItem("n/a");

  str = m_settings.value("gui/cipherType", "aes256").toString();

  if(m_ui.cipherType->findText(str) > -1)
    m_ui.cipherType->setCurrentIndex(m_ui.cipherType->findText(str));

  str = m_settings.value("gui/kernelCipherType", "aes256").toString();

  if(m_ui.kernelCipherType->findText(str) > -1)
    m_ui.kernelCipherType->setCurrentIndex
      (m_ui.kernelCipherType->findText(str));

  str = m_settings.value("gui/kernelHashType", "sha512").toString();

  if(m_ui.kernelHashType->findText(str) > -1)
    m_ui.kernelHashType->setCurrentIndex(m_ui.kernelHashType->findText(str));

  str = m_settings.value("gui/hashType", "sha512").toString();

  if(m_ui.hashType->findText(str) > -1)
    m_ui.hashType->setCurrentIndex(m_ui.hashType->findText(str));

  str = m_settings.value("kernel/messaging_cache_algorithm", "sha224").
    toString();

  if(m_ui.congestionAlgorithm->findText(str) > -1)
    m_ui.congestionAlgorithm->setCurrentIndex
      (m_ui.congestionAlgorithm->findText(str));

  m_ui.iterationCount->setValue(m_settings.value("gui/iterationCount",
						 10000).toInt());
  str = m_settings.value("gui/guiExternalIpInterval", "-1").toString();

  if(str == "30")
    m_optionsUi.guiExternalIpFetch->setCurrentIndex(0);
  else if(str == "60")
    m_optionsUi.guiExternalIpFetch->setCurrentIndex(1);
  else
    m_optionsUi.guiExternalIpFetch->setCurrentIndex(2);

  str = m_settings.value("gui/kernelExternalIpInterval", "-1").toString();

  if(str == "30")
    m_ui.kernelExternalIpFetch->setCurrentIndex(0);
  else if(str == "60")
    m_ui.kernelExternalIpFetch->setCurrentIndex(1);
  else
    m_ui.kernelExternalIpFetch->setCurrentIndex(2);

  m_ui.saltLength->setValue(m_settings.value("gui/saltLength", 512).toInt());

  if(spoton_crypt::passphraseSet())
    {
      m_sb.frame->setEnabled(false);
      m_sb.lock->setEnabled(false);
      m_sb.pop_poptastic->setEnabled(false);
#if SPOTON_GOLDBUG == 0
      m_ui.action_Add_Participant->setEnabled(false);
#endif
      m_ui.action_Echo_Key_Share->setEnabled(false);
      m_ui.action_Export_Listeners->setEnabled(false);
      m_ui.action_Export_Public_Keys->setEnabled(false);
      m_ui.action_Import_Neighbors->setEnabled(false);
      m_ui.action_Import_Public_Keys->setEnabled(false);
      m_ui.action_New_Global_Name->setEnabled(false);
      m_ui.action_Notifications_Window->setEnabled(false);
      m_ui.action_Options->setEnabled(false);
      m_ui.action_Poptastic_Settings->setEnabled(false);
      m_ui.action_Purge_Ephemeral_Keys->setEnabled(false);
      m_ui.action_RSS->setEnabled(false);
      m_ui.action_Rosetta->setEnabled(false);
      m_ui.action_SMP->setEnabled(false);
      m_ui.action_Statistics_Window->setEnabled(false);
      m_ui.action_Vacuum_Databases->setEnabled(false);
      m_ui.delete_key->setEnabled(true);
      m_ui.encryptionKeySize->setEnabled(false);
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.keys->setEnabled(true);
      m_ui.menu_Pages->setEnabled(false);
      m_ui.regenerate->setEnabled(true);
      m_ui.signatureKeySize->setEnabled(false);
      m_ui.signatureKeyType->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	if(i == m_ui.tab->count() - 1)
	  {
	    /*
	    ** About.
	    */

	    m_ui.tab->blockSignals(true);
	    m_ui.tab->setCurrentIndex(i);
	    m_ui.tab->blockSignals(false);
	    m_ui.tab->setTabEnabled(i, true);
	  }
	else
	  m_ui.tab->setTabEnabled(i, false);

      m_ui.passphrase->setFocus();
    }
  else
    {
      m_sb.frame->setEnabled(false);
      m_sb.lock->setEnabled(false);
      m_sb.pop_poptastic->setEnabled(false);
#if SPOTON_GOLDBUG == 0
      m_ui.action_Add_Participant->setEnabled(false);
#endif
      m_ui.action_Echo_Key_Share->setEnabled(false);
      m_ui.action_Export_Listeners->setEnabled(false);
      m_ui.action_Export_Public_Keys->setEnabled(false);
      m_ui.action_Import_Neighbors->setEnabled(false);
      m_ui.action_Import_Public_Keys->setEnabled(false);
      m_ui.action_New_Global_Name->setEnabled(false);
      m_ui.action_Notifications_Window->setEnabled(false);
      m_ui.action_Options->setEnabled(false);
      m_ui.action_Poptastic_Settings->setEnabled(false);
      m_ui.action_Purge_Ephemeral_Keys->setEnabled(false);
      m_ui.action_RSS->setEnabled(false);
      m_ui.action_Rosetta->setEnabled(false);
      m_ui.action_SMP->setEnabled(false);
      m_ui.action_Statistics_Window->setEnabled(false);
      m_ui.action_Vacuum_Databases->setEnabled(false);
      m_ui.answer_authenticate->setEnabled(false);
      m_ui.delete_key->setEnabled(false);
      m_ui.encryptionKeySize->setEnabled(false);
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.kernelBox->setEnabled(false);
      m_ui.kernelBox->setVisible(false);
      m_ui.keys->setEnabled(false);
      m_ui.menu_Pages->setEnabled(false);
      m_ui.newKeys->setEnabled(true);
      m_ui.passphrase->setEnabled(false);
      m_ui.passphraseButton->setEnabled(false);
      m_ui.passphrase_rb_authenticate->setEnabled(false);
      m_ui.question_rb_authenticate->setEnabled(false);
      m_ui.regenerate->setEnabled(false);
      m_ui.showStatistics->setVisible(false);
      m_ui.signatureKeySize->setEnabled(false);
      m_ui.signatureKeyType->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	if(i == 6) // Settings
	  {
	    m_ui.tab->blockSignals(true);
	    m_ui.tab->setCurrentIndex(i);
	    m_ui.tab->blockSignals(false);
	    m_ui.tab->setTabEnabled(i, true);
	  }
	else
	  m_ui.tab->setTabEnabled(i, false);

      m_ui.username->setFocus();
      updatePublicKeysLabel();
    }

  if(m_settings.contains("gui/chatHorizontalSplitter"))
    m_ui.chatHorizontalSplitter->restoreState
      (m_settings.value("gui/chatHorizontalSplitter").toByteArray());

  if(m_settings.contains("gui/emailSplitter"))
    m_ui.emailSplitter->restoreState
      (m_settings.value("gui/emailSplitter").toByteArray());

  if(m_settings.contains("gui/listenersHorizontalSplitter"))
    m_ui.listenersHorizontalSplitter->restoreState
      (m_settings.value("gui/listenersHorizontalSplitter").toByteArray());

  if(m_settings.contains("gui/neighborsVerticalSplitter"))
    m_ui.neighborsVerticalSplitter->restoreState
      (m_settings.value("gui/neighborsVerticalSplitter").toByteArray());

  if(m_settings.contains("gui/readVerticalSplitter"))
    m_ui.readVerticalSplitter->restoreState
      (m_settings.value("gui/readVerticalSplitter").toByteArray());

  if(m_settings.contains("gui/txmSplitter"))
    m_ui.txmSplitter->restoreState
      (m_settings.value("gui/txmSplitter").toByteArray());

  if(m_settings.contains("gui/urlsVerticalSplitter"))
    m_ui.urlsVerticalSplitter->restoreState
      (m_settings.value("gui/urlsVerticalSplitter").toByteArray());

  m_ui.destination->setText(m_settings.value("gui/etpDestinationPath", "").
			    toString());
  m_ui.destination->setCursorPosition(0);
  m_optionsUi.guiSecureMemoryPool->setValue
    (m_settings.value("gui/gcryctl_init_secmem",
		      spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE).toInt());
  m_ui.kernelSecureMemoryPool->setValue
    (m_settings.value("kernel/gcryctl_init_secmem",
		      spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE).toInt());

  if(m_optionsUi.guiSecureMemoryPool->value() == 0)
    m_optionsUi.guiSecureMemoryPool->setStyleSheet
      ("QSpinBox {background-color: rgb(240, 128, 128);}"); // Light coral!

  if(m_ui.kernelSecureMemoryPool->value() == 0)
    m_ui.kernelSecureMemoryPool->setStyleSheet
      ("QSpinBox {background-color: rgb(240, 128, 128);}"); // Light coral!

  m_ui.destination->setToolTip(m_ui.destination->text());
  m_ui.emailParticipants->setAlternatingRowColors
    (m_optionsUi.emailAlternatingRowColors->isChecked());
  m_ui.participants->setAlternatingRowColors
    (m_optionsUi.chatAlternatingRowColors->isChecked());
  m_ui.urlParticipants->setAlternatingRowColors
    (m_optionsUi.urlsAlternatingRowColors->isChecked());
  connect(m_ui.buzzTab->tabBar(),
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowBuzzTabContextMenu(const QPoint &)));
  connect(m_ui.delete_key,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteKey(void)));
  connect(m_ui.emailParticipants,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.etpMagnets,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowEtpMagnetsMenu(const QPoint &)));
  connect(m_ui.listeners,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.mail,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotMailContextMenu(const QPoint &)));
  connect(m_ui.messages,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotMessagesAnchorClicked(const QUrl &)));
  connect(m_ui.neighbors,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.participants,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.received,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.regenerate,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRegenerateKey(void)));
  connect(m_ui.tab->tabBar(),
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowMainTabContextMenu(const QPoint &)));
  connect(m_ui.transmitted,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.transmittedMagnets,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.urlParticipants,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  m_ui.ae_tokens->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
  m_ui.emailParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.etpMagnets->horizontalHeader()->setSortIndicator(1, Qt::AscendingOrder);
  m_ui.addTransmittedMagnets->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.institutions->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_statisticsUi.view->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.statistics->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
  m_ui.mail->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
  m_ui.listeners->horizontalHeader()->setSortIndicator(3, Qt::AscendingOrder);
  m_ui.neighbors->horizontalHeader()->setSortIndicator(1, Qt::AscendingOrder);
  m_ui.participants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.postoffice->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
  m_ui.received->horizontalHeader()->setSortIndicator(4, Qt::AscendingOrder);
  m_ui.transmitted->horizontalHeader()->setSortIndicator(5, Qt::AscendingOrder);
  m_ui.urlParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.emailParticipants->setColumnHidden(1, true); // OID
  m_ui.emailParticipants->setColumnHidden(2, true); // neighbor_oid
  m_ui.emailParticipants->setColumnHidden(3, true); // public_key_hash
  m_ui.etpMagnets->setColumnHidden(m_ui.etpMagnets->columnCount() - 1,
				   true); // OID
  m_ui.addTransmittedMagnets->setColumnHidden
    (m_ui.addTransmittedMagnets->columnCount() - 1, true); // OID
  m_ui.mail->setColumnHidden(5, true); // goldbug
  m_ui.mail->setColumnHidden(6, true); // message
  m_ui.mail->setColumnHidden(7, true); // message_code
  m_ui.mail->setColumnHidden(8, true); // receiver_sender_hash
  m_ui.mail->setColumnHidden(9, true); // hash
  m_ui.mail->setColumnHidden(10, true); // signature
  m_ui.mail->setColumnHidden(11, true); // OID
  m_ui.listeners->setColumnHidden(m_ui.listeners->columnCount() - 1,
				  true); // OID
  m_ui.neighbors->setColumnHidden
    (m_ui.neighbors->columnCount() - 1, true); // OID
  m_ui.neighbors->setColumnHidden(29, true); // Message of the Day
  m_ui.neighbors->setColumnHidden(31, true); // certificate
  m_ui.participants->setColumnHidden(1, true); // OID
  m_ui.participants->setColumnHidden(2, true); // neighbor_oid
  m_ui.participants->setColumnHidden(3, true); // public_key_hash
  m_ui.participants->resizeColumnsToContents();
  m_ui.downDistillers->horizontalHeader()->resizeSection(0, 600);
  m_ui.sharedDistillers->horizontalHeader()->resizeSection(0, 600);
  m_ui.upDistillers->horizontalHeader()->resizeSection(0, 600);
  m_ui.received->setColumnHidden(m_ui.received->columnCount() - 1,
				 true); // OID
  m_ui.transmitted->setColumnHidden(m_ui.transmitted->columnCount() - 1,
				    true); // OID
  m_ui.urlParticipants->setColumnHidden(1, true); // OID
  m_ui.urlParticipants->setColumnHidden(2, true); // neighbor_oid
  m_ui.urlParticipants->setColumnHidden(3, true); // public_key_hash
  m_ui.emailSplitter->setStretchFactor(0, 1);
  m_ui.emailSplitter->setStretchFactor(1, 0);
  m_ui.listenersHorizontalSplitter->setStretchFactor(0, 1);
  m_ui.listenersHorizontalSplitter->setStretchFactor(1, 0);
  m_ui.neighborsVerticalSplitter->setStretchFactor(0, 1);
  m_ui.neighborsVerticalSplitter->setStretchFactor(1, 0);
  m_ui.readVerticalSplitter->setStretchFactor(0, 1);
  m_ui.readVerticalSplitter->setStretchFactor(1, 0);
  m_ui.txmSplitter->setStretchFactor(0, 1);
  m_ui.txmSplitter->setStretchFactor(1, 0);
  m_ui.urlsVerticalSplitter->setStretchFactor(0, 0);
  m_ui.urlsVerticalSplitter->setStretchFactor(1, 1);
  prepareListenerIPCombo();

  /*
  ** Not wise! We may find things we're not prepared for.
  */

  foreach(auto button,
	  m_ui.emailParticipants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  foreach(auto button, m_ui.mail->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  foreach(auto button, m_ui.participants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  foreach(auto button,
	  m_ui.urlParticipants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));

  if(m_optionsUi.guiExternalIpFetch->currentIndex() !=
     m_optionsUi.guiExternalIpFetch->count() - 1)
    {
      m_externalAddress->discover();

      if(m_optionsUi.guiExternalIpFetch->currentIndex() == 0)
	m_externalAddressDiscovererTimer.start(30000);
      else
	m_externalAddressDiscovererTimer.start(60000);
    }

  connect(&m_statisticsFutureWatcher,
	  SIGNAL(finished(void)),
	  this,
	  SLOT(slotStatisticsGathered(void)));
#if SPOTON_GOLDBUG == 0
  str = m_settings.value("gui/iconSet", "nouve").toString().toLower();
#else
  str = m_settings.value("gui/iconSet", "nuvola").toString().toLower();
#endif

  if(str == "everaldo")
    m_optionsUi.icons->setCurrentIndex(0);
  else if(str == "meego")
    m_optionsUi.icons->setCurrentIndex(1);
  else if(str == "nuvola")
    m_optionsUi.icons->setCurrentIndex(3);
  else
#if SPOTON_GOLDBUG == 0
    m_optionsUi.icons->setCurrentIndex(2);
#else
    m_optionsUi.icons->setCurrentIndex(3);
#endif

  slotSetIcons(m_optionsUi.icons->currentIndex());

#if SPOTON_GOLDBUG == 0
  auto size(m_settings.value("gui/tabIconSize", QSize(16, 16)).toSize());
#else
  auto size(m_settings.value("gui/tabIconSize", QSize(32, 32)).toSize());
#endif

  if(size == QSize(16, 16))
    m_optionsUi.iconsize->setCurrentIndex(0);
  else if(size == QSize(24, 24))
    m_optionsUi.iconsize->setCurrentIndex(1);
  else if(size == QSize(32, 32))
    m_optionsUi.iconsize->setCurrentIndex(2);
  else if(size == QSize(64, 64))
    m_optionsUi.iconsize->setCurrentIndex(3);
  else
    {
#if SPOTON_GOLDBUG == 0
      m_optionsUi.iconsize->setCurrentIndex(0);
      size = QSize(16, 16);
#else
      m_optionsUi.iconsize->setCurrentIndex(2);
      size = QSize(32, 32);
#endif
    }

  m_ui.tab->setIconSize(size);
  splash->showMessage
    (tr("Preparing widget states."),
     Qt::AlignBottom | Qt::AlignHCenter,
     QColor(Qt::white));
  splash->repaint();
  prepareContextMenuMirrors();
  prepareOtherOptions();
  prepareTearOffMenus();
  prepareTimeWidgets();

  QList<QWidget *> widgets;

  widgets << m_ui.etpMagnet
	  << m_ui.friendInformation
	  << m_ui.motd
	  << m_ui.searchfor
	  << m_ui.urls;

  for(int i = 0; i < widgets.size(); i++)
    {
      auto font(widgets.at(i)->font());

      font.setStyleHint(QFont::Monospace);
      widgets.at(i)->setFont(font);
    }

  m_ui.action_Minimal_Display->setEnabled(false);

#if SPOTON_GOLDBUG == 1
  /*
  ** Enable a minimal view after all other UI preparations.
  */

  m_ui.action_Minimal_Display->setChecked(true);
#else
  m_ui.action_Minimal_Display->blockSignals(true);
  m_ui.action_Minimal_Display->setChecked
    (m_settings.value("gui/minimal", false).toBool());
  m_ui.action_Minimal_Display->blockSignals(false);
#endif
  show();
  update();

  if(!QSqlDatabase::isDriverAvailable("QSQLITE"))
    {
      QFileInfo const fileInfo("qt.conf");
      QString str("");

      if(fileInfo.isReadable() && fileInfo.size() > 0)
	str = tr("The SQLite database driver is not available. "
		 "The file qt.conf is present in %1's "
		 "current working directory. Perhaps a conflict "
		 "exists. Please resolve!").arg(SPOTON_APPLICATION_NAME);
      else
	str = tr
	  ("The SQLite database driver is not available. Please resolve!");

      auto timer = new QTimer(this);

      connect(timer,
	      SIGNAL(timeout(void)),
	      this,
	      SLOT(slotShowErrorMessage(void)));
      timer->setProperty("text", str);
      timer->setSingleShot(true);
      timer->start(1500);
    }
  else
    {
      QFileInfo const fileInfo(spoton_misc::homePath());

      if(!fileInfo.isReadable() || !fileInfo.isWritable())
	{
	  auto const str(tr("The directory %1 must be readable and writable.").
			 arg(fileInfo.absolutePath()));
	  auto timer = new QTimer(this);

	  connect(timer,
		  SIGNAL(timeout(void)),
		  this,
		  SLOT(slotShowErrorMessage(void)));
	  timer->setProperty("text", str);
	  timer->setSingleShot(true);
	  timer->start(1500);
	}
      else if(!spoton_crypt::passphraseSet())
	QTimer::singleShot
	  (1500, this, SLOT(slotPrepareAndShowInstallationWizard(void)));

      QTimer::singleShot(2500, this, SLOT(slotAfterFirstShow(void)));
    }

#if defined(Q_OS_MACOS)
  foreach(auto toolButton, findChildren<QToolButton *> ())
#if (QT_VERSION < QT_VERSION_CHECK(5, 10, 0))
    toolButton->setStyleSheet
      ("QToolButton {border: none; padding-right: 10px;}"
       "QToolButton::menu-arrow {image: none;}"
       "QToolButton::menu-button {border: none;}");
#else
    toolButton->setStyleSheet
      ("QToolButton {border: none; padding-right: 15px;}"
       "QToolButton::menu-arrow {image: none;}"
       "QToolButton::menu-button {border: none; width: 15px;}");
#endif
#endif
  m_optionsUi.theme->setCurrentIndex(m_settings.value("gui/theme", -1).toInt());

  if(m_optionsUi.theme->currentIndex() < 0)
    m_optionsUi.theme->setCurrentIndex(3); // Default theme.

  launchKernel ?
    QTimer::singleShot(1500, this, SLOT(slotActivateKernel(void))) : (void) 0;
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  foreach(auto lineEdit, findChildren<QLineEdit *> ())
    if(!lineEdit->isReadOnly() && !lineEdit->objectName().contains("spinbox"))
      lineEdit->setClearButtonEnabled(true);

#ifdef Q_OS_MACOS
  spoton_utilities::enableTabDocumentMode(this);
#endif
  QApplication::restoreOverrideCursor();
}

spoton::~spoton()
{
}

void spoton::authenticate
(spoton_crypt *crypt, const QString &oid, const QString &message)
{
  if(!crypt)
    return;
  else if(oid.isEmpty())
    return;

  QDialog dialog(this);
  Ui_spoton_passwordprompt ui;

  ui.setupUi(&dialog);
  dialog.setWindowTitle
    (tr("%1: Authenticate Neighbor Account").arg(SPOTON_APPLICATION_NAME));

  if(!message.isEmpty())
    ui.message->setText(message);

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();

      auto const name(ui.name->text().trimmed());
      auto const password(ui.password->text());

      if(name.length() >= 32 && password.length() >= 32)
	{
	  QString connectionName("");
	  auto ok = true;

	  {
	    auto db = spoton_misc::database(connectionName);

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);

		query.prepare("UPDATE neighbors SET "
			      "account_authenticated = NULL, "
			      "account_name = ?, "
			      "account_password = ? "
			      "WHERE OID = ? AND user_defined = 1");
		query.bindValue
		  (0, crypt->encryptedThenHashed(name.toLatin1(),
						 &ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, crypt->encryptedThenHashed(password.toLatin1(),
						   &ok).toBase64());

		query.bindValue(2, oid);

		if(ok)
		  ok = query.exec();
	      }
	    else
	      ok = false;

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);

	  if(!ok)
	    QMessageBox::critical(this,
				  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				  tr("An error occurred while attempting "
				     "to record authentication "
				     "information."));
	}
      else
	QMessageBox::critical
	  (this,
	   tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	   tr("The account name and the account password "
	      "must contain at least thirty-two characters "
	      "each."));
    }

  QApplication::processEvents();
}

void spoton::changeEchoMode(const QString &mode, QTableWidget *tableWidget)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;
  else if(!tableWidget)
    return;

  QString table("");

  if(m_ui.listeners == tableWidget)
    table = "listeners";
  else
    table = "neighbors";

  QString oid("");
  int row = -1;

  if((row = tableWidget->currentRow()) >= 0)
    {
      auto item = tableWidget->item
	(row, tableWidget->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() +
       QDir::separator() +
       QString("%1.db").arg(table));

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	if(table == "listeners")
	  query.prepare("UPDATE listeners SET "
			"echo_mode = ? "
			"WHERE OID = ?");
	else
	  query.prepare("UPDATE neighbors SET "
			"echo_mode = ? "
			"WHERE OID = ?");

	query.bindValue
	  (0, crypt->encryptedThenHashed(mode.toLatin1(), &ok).
	   toBase64());
	query.bindValue(1, oid);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_ui.listeners == tableWidget)
    m_listenersLastModificationTime = QDateTime();
  else
    {
      if(m_neighborsFuture.isFinished())
	m_neighborsLastModificationTime = QDateTime();
    }
}

void spoton::cleanup(void)
{
  if(m_settings.value("gui/removeOtmOnExit", false).toBool())
    spoton_misc::removeOneTimeStarBeamMagnets();

  /*
  ** Abort timers.
  */

  m_buzzStatusTimer.stop();
  m_chatInactivityTimer.stop();
  m_emailRetrievalTimer.stop();
  m_externalAddressDiscovererTimer.stop();
  m_generalTimer.stop();
  m_kernelUpdateTimer.stop();
  m_listenersUpdateTimer.stop();
  m_neighborsUpdateTimer.stop();
  m_participantsUpdateTimer.stop();
  m_starbeamUpdateTimer.stop();
  m_tableTimer.stop();
  m_updateChatWindowsTimer.stop();
  m_webServerInformationTimer.stop();

  /*
  ** Abort threads.
  */

  m_encryptFile.abort();
  m_generalFuture.cancel();
  m_generalFuture.waitForFinished();
  m_neighborsFuture.cancel();
  m_neighborsFuture.waitForFinished();
  m_participantsFuture.cancel();
  m_participantsFuture.waitForFinished();
  m_pqUrlDatabaseFuture.cancel();
  m_pqUrlDatabaseFuture.waitForFinished();
  m_starbeamDigestInterrupt.fetchAndStoreOrdered(1);

  for(int i = 0; i < m_starbeamDigestFutures.size(); i++)
    {
      auto future(m_starbeamDigestFutures.at(i));

      future.cancel();
      future.waitForFinished();
    }

  m_statisticsFuture.cancel();
  m_statisticsFuture.waitForFinished();

  /*
  ** Close databases.
  */

  m_urlDatabase.close();
  m_urlDatabase = QSqlDatabase();

  if(QSqlDatabase::contains("URLDatabase"))
    QSqlDatabase::removeDatabase("URLDatabase");

  m_ui.url_database_connection_information->clear();
  saveSettings();
  delete m_wizardUi;
  m_wizardUi = nullptr;
#if SPOTON_GOLDBUG == 0
  m_addParticipantWindow->deleteLater();
#endif
  m_documentation->deleteLater();
  m_echoKeyShare->deleteLater();
  m_notificationsWindow->deleteLater();
  m_optionsWindow->deleteLater();
  m_releaseNotes->deleteLater();
  m_rss->close(); // Retain geometry.
  m_rss->deleteLater();
  m_smpWindow->deleteLater();
  m_statisticsWindow->deleteLater();
  delete m_urlCommonCrypt;
  m_urlCommonCrypt = nullptr;

  QMutableHashIterator<QString, spoton_crypt *> it(m_crypts);

  while(it.hasNext())
    {
      it.next();
      delete it.value();
      it.remove();
    }

  QApplication::instance()->quit();
}

void spoton::closeEvent(QCloseEvent *event)
{
  if(!m_quit && promptBeforeExit())
    {
      if(event)
	event->ignore();

      return;
    }

  m_quit = true;
  slotQuit();
}

void spoton::demagnetize(void)
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
  auto const list
    (m_ui.demagnetize->text().remove("magnet:?").
     split('&', Qt::SkipEmptyParts));
#else
  auto const list
    (m_ui.demagnetize->text().remove("magnet:?").
     split('&', QString::SkipEmptyParts));
#endif

  for(int i = 0; i < list.size(); i++)
    {
      auto str(list.at(i).trimmed());

      if(str.startsWith("rn="))
	{
	  str.remove(0, 3);
	  m_ui.channel->setText(str);
	  m_ui.channel->setCursorPosition(0);
	}
      else if(str.startsWith("xf="))
	{
	  str.remove(0, 3);
	  m_ui.buzzIterationCount->setValue(qAbs(str.toInt()));
	}
      else if(str.startsWith("xs="))
	{
	  str.remove(0, 3);
	  m_ui.channelSalt->setText(str);
	  m_ui.channelSalt->setCursorPosition(0);
	}
      else if(str.startsWith("ct="))
	{
	  str.remove(0, 3);

	  if(m_ui.channelType->findText(str) > -1)
	    m_ui.channelType->setCurrentIndex
	      (m_ui.channelType->findText(str));
	}
      else if(str.startsWith("hk="))
	{
	  str.remove(0, 3);
	  m_ui.buzzHashKey->setText(str);
	  m_ui.buzzHashKey->setCursorPosition(0);
	}
      else if(str.startsWith("ht="))
	{
	  str.remove(0, 3);

	  if(m_ui.buzzHashType->findText(str) > -1)
	    m_ui.buzzHashType->setCurrentIndex
	      (m_ui.buzzHashType->findText(str));
	}
      else if(str.startsWith("xt="))
	{
	}
    }

  slotJoinBuzzChannel();
}

void spoton::magnetize(void)
{
  if(m_ui.favorites->currentText() == "Empty") /*
                                               ** Please do not translate
                                               ** Empty.
                                               */
    return;

  QByteArray data;
  QList<QByteArray> list;
  QString error("");
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    {
      error = tr("Invalid clipboard object. This is a fatal flaw.");
      goto done_label;
    }

  list = m_ui.favorites->itemData
    (m_ui.favorites->currentIndex()).toByteArray().split('\n');

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  data.append("magnet:?");
  data.append(QString("rn=%1&").arg(list.value(0).constData()).toUtf8());
  data.append(QString("xf=%1&").arg(list.value(1).constData()).toUtf8());
  data.append(QString("xs=%1&").arg(list.value(2).constData()).toUtf8());
  data.append(QString("ct=%1&").arg(list.value(3).constData()).toUtf8());
  data.append(QString("hk=%1&").arg(list.value(4).constData()).toUtf8());
  data.append(QString("ht=%1&").arg(list.value(5).constData()).toUtf8());
  data.append("xt=urn:buzz");
  clipboard->setText(data);

 done_label:

  if(!error.isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
}

void spoton::removeFavorite(const bool removeAll)
{
  QString connectionName("");
  QString error("");
  auto crypt = m_crypts.value("chat", nullptr);
  auto ok = true;

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "buzz_channels.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");

	if(removeAll)
	  query.prepare("DELETE FROM buzz_channels");
	else
	  {
	    query.prepare("DELETE FROM buzz_channels WHERE "
			  "data_hash = ?");
	    query.bindValue
	      (0, crypt->keyedHash(m_ui.favorites->
				   itemData(m_ui.favorites->currentIndex()).
				   toByteArray(), &ok).toBase64());
	  }

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    error = tr("A database error occurred.");

 done_label:

  if(!error.isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
  else
    {
      slotPopulateBuzzFavorites();
      m_ui.buzzHashKey->clear();
      m_ui.buzzHashType->setCurrentIndex(0);
      m_ui.buzzIterationCount->setValue(m_ui.buzzIterationCount->minimum());
      m_ui.channel->clear();
      m_ui.channelSalt->clear();
      m_ui.channelType->setCurrentIndex(0);
    }
}

void spoton::saveGeoIPPath(const int version, const QString &path)
{
  if(version == 4)
    m_settings["gui/geoipPath4"] = path;
  else
    m_settings["gui/geoipPath6"] = path;

  QSettings settings;

  if(version == 4)
    settings.setValue("gui/geoipPath4", path);
  else
    settings.setValue("gui/geoipPath6", path);

  if(version == 4)
    {
      m_optionsUi.geoipPath4->setText(path);
      m_optionsUi.geoipPath4->setCursorPosition(0);
      m_optionsUi.geoipPath4->setToolTip(path);
      m_optionsUi.geoipPath4->selectAll();
    }
  else
    {
      m_optionsUi.geoipPath6->setText(path);
      m_optionsUi.geoipPath6->setCursorPosition(0);
      m_optionsUi.geoipPath6->setToolTip(path);
      m_optionsUi.geoipPath6->selectAll();
    }
}

void spoton::saveKernelPath(const QString &path)
{
  m_settings["gui/kernelPath"] = path;

  QSettings settings;

  settings.setValue("gui/kernelPath", path);
  m_ui.kernelPath->setText(path);
  m_ui.kernelPath->setCursorPosition(0);
  m_ui.kernelPath->setToolTip(path);
  m_ui.kernelPath->selectAll();
}

void spoton::saveSettings(void)
{
  QSettings settings;

  if(!isFullScreen())
    settings.setValue("gui/geometry", saveGeometry());

  settings.setValue("gui/chatHorizontalSplitter",
		    m_ui.chatHorizontalSplitter->saveState());
  settings.setValue("gui/currentTabIndex", m_ui.tab->currentIndex());
  settings.setValue("gui/emailSplitter",
		    m_ui.emailSplitter->saveState());
  settings.setValue("gui/listenersHorizontalSplitter",
		    m_ui.listenersHorizontalSplitter->saveState());
  settings.setValue("gui/neighborsVerticalSplitter",
		    m_ui.neighborsVerticalSplitter->saveState());
  settings.setValue("gui/readVerticalSplitter",
		    m_ui.readVerticalSplitter->saveState());
  settings.setValue("gui/txmSplitter",
		    m_ui.txmSplitter->saveState());
  settings.setValue("gui/urlsVerticalSplitter",
		    m_ui.urlsVerticalSplitter->saveState());
}

void spoton::sendBuzzKeysToKernel(void)
{
  auto const str(m_keysShared.value("buzz_channels_sent_to_kernel", "false"));

  if(str == "true")
    return;

  auto sent = true;

  if((sent = ((m_kernelSocket.isEncrypted() ||
	       m_ui.kernelKeySize->currentText().toInt() == 0) &&
	      m_kernelSocket.state() == QAbstractSocket::ConnectedState)))
    {
      foreach(auto page, m_buzzPages.values())
	if(page && (sent &= (m_kernelSocket.isEncrypted() ||
			     m_ui.kernelKeySize->currentText().toInt() == 0)))
	  {
	    QByteArray message;

	    message.append("addbuzz_");
	    message.append(page->key().toBase64());
	    message.append("_");
	    message.append(page->channelType().toBase64());
	    message.append("_");
	    message.append(page->hashKey().toBase64());
	    message.append("_");
	    message.append(page->hashType().toBase64());
	    message.append("\n");

	    if(!writeKernelSocketData(message))
	      {
		sent = false;
		spoton_misc::logError
		  (QString("spoton::sendBuzzKeysToKernel(): write() failure "
			   "for %1:%2.").
		   arg(m_kernelSocket.peerAddress().toString()).
		   arg(m_kernelSocket.peerPort()));
	      }
	  }
    }

  m_keysShared["buzz_channels_sent_to_kernel"] = sent ? "true" : "false";
}

void spoton::sendKeysToKernel(void)
{
  auto const str(m_keysShared.value("keys_sent_to_kernel", "false"));

  if(str == "ignore" || str == "true")
    {
      if(isKernelActive())
	if(str == "ignore")
	  m_sb.status->setText
	    (tr("<html><a href=\"authenticate\">"
		"The kernel requires your authentication "
		"and encryption keys.</a></html>"));

      return;
    }

  if(m_crypts.value("chat", nullptr))
    if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
      if(m_kernelSocket.isEncrypted() ||
	 m_ui.kernelKeySize->currentText().toInt() == 0)
	{
	  if(!m_optionsUi.sharePrivateKeys->isChecked())
	    {
	      QMessageBox mb(this);

	      mb.setIcon(QMessageBox::Question);
	      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	      mb.setText
		 (tr("The kernel process %1 requires your private "
		     "authentication and encryption keys. "
		     "Would you like to share "
		     "the keys with the kernel process?").
		  arg(m_ui.pid->text()));
	      mb.setWindowIcon(windowIcon());
	      mb.setWindowModality(Qt::ApplicationModal);
	      mb.setWindowTitle
		(tr("%1: Question").arg(SPOTON_APPLICATION_NAME));

	      if(mb.exec() != QMessageBox::Yes)
		{
		  QApplication::processEvents();
		  m_keysShared["keys_sent_to_kernel"] = "ignore";
		  return;
		}

	      QApplication::processEvents();
	    }

	  QByteArray keys("keys_");
	  auto hashKey(m_crypts.value("chat")->hashKey());
	  auto symmetricKey(m_crypts.value("chat")->symmetricKey());

	  hashKey = hashKey.toBase64();
	  symmetricKey = symmetricKey.toBase64();
	  keys.append(symmetricKey);
	  keys.append("_");
	  keys.append(hashKey);
	  keys.append("\n");

	  if(!writeKernelSocketData(keys))
	    spoton_misc::logError
	      (QString("spoton::sendKeysToKernel(): write() failure "
		       "for %1:%2.").
	       arg(m_kernelSocket.peerAddress().toString()).
	       arg(m_kernelSocket.peerPort()));
	  else
	    {
	      m_keysShared["keys_sent_to_kernel"] = "true";
	      m_sb.status->clear();
	    }
	}
}

void spoton::slotAbout(void)
{
  auto mb = findChild<QMessageBox *> ("About");

  if(!mb)
    {
      mb = new QMessageBox(this);

      QString str("");

#if SPOTON_GOLDBUG == 0
      QPixmap pixmap(":/Logo/spot-on-logo.png");

      pixmap = pixmap.scaled
	(QSize(256, 256), Qt::KeepAspectRatio, Qt::SmoothTransformation);
      str = QString
	("<html>Spot-On Version %1<br>"
	 "Made with love by textbrowser.<br>"
	 "Please visit <a href=\"https://textbrowser.github.io/spot-on\">"
	 "https://textbrowser.github.io/spot-on</a> for more information.").
	arg(SPOTON_VERSION_STR);
      mb->setIconPixmap(pixmap);
#else
      QPixmap pixmap(":/Logo/goldbug-neuland.png");

      pixmap = pixmap.scaled
	(QSize(256, 256), Qt::KeepAspectRatio, Qt::SmoothTransformation);
      str = QString("<html>GoldBug, version %1, is an open-source "
		    "application published under "
		    "the Revised BSD License.<br>"
		    "Made with love by textbrowser.<br>"
		    "Please visit <a href=\"https://goldbug.sourceforge.io\">"
		    "https://goldbug.sourceforge.io</a> for more information.").
	arg(SPOTON_VERSION_STR);
      mb->setIconPixmap(pixmap);
#endif
      str.append("</html>");
      mb->setStandardButtons(QMessageBox::Close);
      mb->setText(str);
      mb->setTextFormat(Qt::RichText);
      mb->setWindowIcon(windowIcon());
      mb->setWindowModality(Qt::NonModal);
      mb->setWindowTitle(SPOTON_APPLICATION_NAME);
      mb->button(QMessageBox::Close)->setShortcut(tr("Ctrl+W"));
    }

  mb->showNormal();
  mb->activateWindow();
  mb->raise();
  QApplication::processEvents();
}

void spoton::slotActivateKernel(void)
{
  auto const pid = m_ui.pid->text().toLongLong();

  if(pid < 0) // Error.
    return;
  else if(!m_optionsUi.forceRegistration->isChecked())
    {
      if(pid > 0)
	return;
    }
  else
    // Remove shared.db.

    QFile::remove(spoton_misc::homePath() + QDir::separator() + "shared.db");

  QFileInfo const fileInfo(m_ui.kernelPath->text());

#if defined(Q_OS_MACOS)
  if((fileInfo.isBundle() || fileInfo.isExecutable()) && fileInfo.size() > 0)
#elif defined(Q_OS_WINDOWS)
  if(fileInfo.isReadable() && fileInfo.size() > 0)
#else
  if(fileInfo.isExecutable() && fileInfo.size() > 0)
#endif
    {
    }
  else
    return; // Incorrect executable!

  m_ui.pid->setText("0");
  m_ui.pid->setCursorPosition(0);

  QColor const color(240, 128, 128); // Light coral!
  auto palette(m_ui.pid->palette());

  palette.setColor(m_ui.pid->backgroundRole(), color);
  m_ui.pid->setPalette(palette);
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText(tr("Launching the kernel. Please be patient."));
  m_sb.status->repaint();

  auto const program(m_ui.kernelPath->text());
  auto status = false;

#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
#ifdef Q_OS_MACOS
  if(QFileInfo(program).isBundle())
    {
      QStringList list;

      list << "-a" << program << "-g";
      status = QProcess::startDetached("open", list);
    }
  else
    status = QProcess::startDetached(program, QStringList());
#elif defined(Q_OS_WINDOWS)
  status = QProcess::startDetached
    (QString("\"%1\"").arg(program), QStringList());
#else
  status = QProcess::startDetached(program, QStringList());
#endif
#else
#ifdef Q_OS_MACOS
  if(QFileInfo(program).isBundle())
    {
      QStringList list;

      list << "-a" << program << "-g";
      status = QProcess::startDetached("open", list);
    }
  else
    status = QProcess::startDetached(program);
#elif defined(Q_OS_WINDOWS)
  status = QProcess::startDetached(QString("\"%1\"").arg(program));
#else
  status = QProcess::startDetached(program);
#endif
#endif

  QElapsedTimer time;

  time.start();

  do
    {
      QApplication::processEvents();

      if(m_ui.pid->text().toLongLong() > 0)
	break;
      else if(time.hasExpired(10000))
	break;
    }
  while(true);

  m_sb.status->clear();
  m_sb.status->repaint();
  QApplication::restoreOverrideCursor();

  if(status)
#if SPOTON_GOLDBUG == 1
    m_sb.kernelstatus->setIcon
      (QIcon(QString(":/%1/status-online.png").
	     arg(m_settings.value("gui/iconSet", "nouve").toString().
		 toLower())));
#else
    m_sb.kernelstatus->setIcon
      (QIcon(QString(":/%1/activate.png").
	     arg(m_settings.value("gui/iconSet", "nouve").toString().
		 toLower())));
#endif
  else
    m_sb.kernelstatus->setIcon
      (QIcon(QString(":/%1/deactivate.png").
	     arg(m_settings.value("gui/iconSet", "nouve").toString().
		 toLower())));

  if(status)
    {
      if(m_settings.value("gui/buzzAutoJoin", true).toBool())
	joinDefaultBuzzChannel();
    }
  else if(m_ui.activateKernel == sender())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The kernel process could not be started. Good luck."));
      QApplication::processEvents();
    }
}

void spoton::slotAddListener(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  if((m_ui.listenerTransport->currentIndex() == 2 ||  // TCP
      m_ui.listenerTransport->currentIndex() == 4) && // WebSocket
     m_ui.sslListener->isChecked())
    {
      QHostAddress address;

      if(m_ui.recordIPAddress->isChecked())
	address = m_externalAddress->address();
      else
	address = QHostAddress(m_ui.listenerIP->text().trimmed());

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_sb.status->setText
	(tr("Generating %1-bit SSL/TLS data. Please be patient.").
	 arg(m_ui.listenerKeySize->currentText()));
      m_sb.status->repaint();
      spoton_crypt::generateSslKeys
	(m_ui.listenerKeySize->currentText().toInt(),
	 certificate,
	 privateKey,
	 publicKey,
	 address,
	 60L * 60L * 24L * static_cast<long int> (m_ui.days_valid->value()),
	 error);
      m_sb.status->clear();
      QApplication::restoreOverrideCursor();
    }
  else if(m_ui.listenerTransport->currentIndex() == 3) // UDP
    {
      if(spoton_misc::isMulticastAddress(QHostAddress(m_ui.listenerIP->text().
						      trimmed())))
	{
	  QMessageBox::information
	    (this,
	     tr("%1: Information").arg(SPOTON_APPLICATION_NAME),
	     tr("You're attempting to create a UDP multicast listener. "
		"Please create a UDP multicast neighbor instead."));
	  QApplication::processEvents();
	  return;
	}

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      if(m_ui.sslListener->isChecked())
	{
	  QHostAddress address;

	  if(m_ui.recordIPAddress->isChecked())
	    address = m_externalAddress->address();

	  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	  m_sb.status->setText
	    (tr("Generating %1-bit SSL/TLS data. Please be patient.").
	     arg(m_ui.listenerKeySize->currentText()));
	  m_sb.status->repaint();
	  spoton_crypt::generateSslKeys
	    (m_ui.listenerKeySize->currentText().toInt(),
	     certificate,
	     privateKey,
	     publicKey,
	     address,
	     60L * 60L * 24L * static_cast<long int> (m_ui.days_valid->value()),
	     error);
	  m_sb.status->clear();
	  QApplication::restoreOverrideCursor();
	}
#endif
    }

  QString connectionName("");
  auto ok = true;

  if(!error.isEmpty())
    {
      ok = false;
      spoton_misc::logError
	(QString("spoton::slotAddListener(): "
		 "generateSslKeys() failure (%1).").arg(error));
      goto done_label;
    }

  prepareDatabasesFromUI();

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QByteArray hash;
	QString ip("");

	if(m_ui.listenerIPCombo->currentIndex() == 0)
	  ip = m_ui.listenerIP->text().toLower().trimmed();
	else
	  ip = m_ui.listenerIPCombo->currentText();

	QSqlQuery query(db);
	QString protocol("");
	QString status("online");
	QString transport("tcp");
	QString transportUniqueness("");
	auto const port(QString::number(m_ui.listenerPort->value()));
	auto scopeId(m_ui.listenerScopeId->text());
	auto sslCS(m_ui.listenersSslControlString->text().trimmed());

	if(m_ui.listenerTransport->currentIndex() == 0) // Bluetooth
	  scopeId = "";
	else
	  {
	    if(m_ui.ipv4Listener->isChecked())
	      protocol = "IPv4";
	    else
	      protocol = "IPv6";
	  }

	switch(m_ui.listenerTransport->currentIndex())
	  {
	  case 0:
	    {
	      transport = "bluetooth";
	      transportUniqueness = transport;
	      break;
	    }
	  case 1:
	    {
	      transport = "sctp";
	      transportUniqueness = transport;
	      break;
	    }
	  case 2:
	    {
	      transport = "tcp";
	      transportUniqueness = transport;
	      break;
	    }
	  case 3:
	    {
	      transport = "udp";
	      transportUniqueness = transport;
	      break;
	    }
	  case 4:
	    {
	      transport = "websocket";
	      transportUniqueness = "tcp";
	      break;
	    }
	  default:
	    {
	      break;
	    }
	  }

	if(nodeExists(db,
		      ip +
		      port +
		      scopeId +
		      transportUniqueness,
		      "listeners"))
	  {
	    error = tr("The specified listener already exists.");
	    ok = false;
	    goto close_db_label;
	  }

	query.prepare("INSERT INTO listeners "
		      "(ip_address, "
		      "port, "
		      "protocol, "
		      "scope_id, "
		      "status_control, "
		      "hash, "
		      "echo_mode, "
		      "ssl_key_size, "
		      "certificate, "
		      "private_key, "
		      "public_key, "
		      "transport, "
		      "share_udp_address, "
		      "orientation, "
		      "ssl_control_string) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	if(ip.isEmpty())
	  query.bindValue
	    (0, crypt->
	     encryptedThenHashed(QByteArray(), &ok).toBase64());
	else if(transport != "bluetooth")
	  {
	    QStringList digits;
	    QStringList list;

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
	    if(protocol == "IPv4")
	      list = ip.split(".", Qt::KeepEmptyParts);
	    else
	      list = ip.split(":", Qt::KeepEmptyParts);
#else
	    if(protocol == "IPv4")
	      list = ip.split(".", QString::KeepEmptyParts);
	    else
	      list = ip.split(":", QString::KeepEmptyParts);
#endif

	    for(int i = 0; i < list.size(); i++)
	      digits.append(list.at(i));

	    if(protocol == "IPv4")
	      {
		ip = QString::number(digits.value(0).toInt()) + "." +
		  QString::number(digits.value(1).toInt()) + "." +
		  QString::number(digits.value(2).toInt()) + "." +
		  QString::number(digits.value(3).toInt());
		ip.remove("...");
	      }
	    else
	      {
		if(m_ui.listenerIPCombo->currentIndex() == 0)
		  ip = spoton_misc::massageIpForUi(ip, protocol);
	      }

	    if(ok)
	      query.bindValue
		(0, crypt->
		 encryptedThenHashed(ip.toLatin1(), &ok).toBase64());
	  }
	else
	  {
	    if(ok)
	      query.bindValue
		(0, crypt->encryptedThenHashed(ip.toLatin1(), &ok).
		 toBase64());
	  }

	if(ok)
	  query.bindValue
	    (1, crypt->
	     encryptedThenHashed(port.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed(protocol.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->
	     encryptedThenHashed(scopeId.toLatin1(), &ok).toBase64());

	query.bindValue(4, status);

	if(ok)
	  {
	    hash = crypt->
	      keyedHash((ip + port + scopeId + transport).toLatin1(), &ok);

	    if(ok)
	      query.bindValue(5, hash.toBase64());
	  }

	if(ok)
	  {
	    if(m_ui.listenersEchoMode->currentIndex() == 0)
	      query.bindValue
		(6, crypt->encryptedThenHashed("full", &ok).toBase64());
	    else
	      query.bindValue
		(6, crypt->encryptedThenHashed("half", &ok).toBase64());
	  }

	if((m_ui.listenerTransport->currentIndex() == 2 ||  // TCP
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
	    m_ui.listenerTransport->currentIndex() == 3 ||  // UDP
#endif
	    m_ui.listenerTransport->currentIndex() == 4) && // WebSocket
	   m_ui.sslListener->isChecked())
	  query.bindValue(7, m_ui.listenerKeySize->currentText().toInt());
	else
	  query.bindValue(7, 0);

	if(ok)
	  query.bindValue
	    (8, crypt->encryptedThenHashed(certificate, &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (9, crypt->encryptedThenHashed(privateKey, &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (10, crypt->encryptedThenHashed(publicKey, &ok).
	     toBase64());

	switch(m_ui.listenerTransport->currentIndex())
	  {
	  case 0:
	    {
	      query.bindValue
		(11, crypt->encryptedThenHashed("bluetooth", &ok).toBase64());
	      break;
	    }
	  case 1:
	    {
	      query.bindValue
		(11, crypt->encryptedThenHashed("sctp", &ok).toBase64());
	      break;
	    }
	  case 2:
	    {
	      query.bindValue
		(11, crypt->encryptedThenHashed("tcp", &ok).toBase64());
	      break;
	    }
	  case 3:
	    {
	      query.bindValue
		(11, crypt->encryptedThenHashed("udp", &ok).toBase64());
	      break;
	    }
	  case 4:
	    {
	      query.bindValue
		(11, crypt->encryptedThenHashed("websocket", &ok).toBase64());
	      break;
	    }
	  default:
	    {
	      break;
	    }
	  }

	if(m_ui.listenerShareAddress->isChecked())
	  query.bindValue(12, 1);
	else
	  query.bindValue(12, 0);

	if(m_ui.listenerOrientation->currentIndex() == 0)
	  query.bindValue
	    (13, crypt->encryptedThenHashed("packet", &ok).toBase64());
	else
	  query.bindValue
	    (13, crypt->encryptedThenHashed("stream", &ok).toBase64());

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
	if(m_ui.sslListener->isChecked() && (transport == "tcp" ||
					     transport == "udp" ||
					     transport == "websocket"))
	  {
	    if(sslCS.isEmpty())
	      sslCS = spoton_common::SSL_CONTROL_STRING;
	  }
	else
	  sslCS = "N/A";
#else
	if(m_ui.sslListener->isChecked() && (transport == "tcp" ||
					     transport == "websocket"))
	  {
	    if(sslCS.isEmpty())
	      sslCS = spoton_common::SSL_CONTROL_STRING;
	  }
	else
	  sslCS = "N/A";
#endif

	query.bindValue(14, sslCS);

	if(ok)
	  ok = query.exec();

	if(ok)
	  {
	    /*
	    ** Add the default Any IP address.
	    */

	    QSqlQuery query(db);

	    query.prepare("INSERT OR REPLACE INTO listeners_allowed_ips "
			  "(ip_address, ip_address_hash, listener_oid) "
			  "VALUES (?, ?, (SELECT OID FROM listeners WHERE "
			  "hash = ?))");
	    query.bindValue
	      (0, crypt->encryptedThenHashed("Any", &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->keyedHash("Any", &ok).toBase64());

	    query.bindValue(2, hash.toBase64());

	    if(ok)
	      ok = query.exec();

	    if(query.lastError().isValid())
	      error = query.lastError().text().trimmed();
	  }
      }
    else
      {
	ok = false;

	if(db.lastError().isValid())
	  error = db.lastError().text();
      }

    db.close();
  }

 close_db_label:

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(ok)
    m_ui.listenerIP->selectAll();
  else if(error.isEmpty())
    QMessageBox::critical(this,
			  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			  tr("Unable to add the specified listener. "
			     "Please enable logging via the Log Viewer "
			     "and try again."));
  else
    QMessageBox::critical(this,
			  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			  tr("An error (%1) occurred while attempting "
			     "to add the specified listener.").arg(error));

  QApplication::processEvents();
}

void spoton::slotAddNeighbor(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
  if(m_ui.neighborTransport->currentIndex() == 3 && // UDP
     m_ui.requireSsl->isChecked() &&
     spoton_misc::
     isMulticastAddress(QHostAddress(m_ui.neighborIP->text().trimmed())))
    {
      QMessageBox::information
	(this,
	 tr("%1: Information").arg(SPOTON_APPLICATION_NAME),
	 tr("DTLS is not functional over multicast!"));
      QApplication::processEvents();
      return;
    }
#endif

  prepareDatabasesFromUI();

  QString connectionName("");
  QString error("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString port(QString::number(m_ui.neighborPort->value()));
	QString protocol("");
	QString proxyHostName("");
	QString proxyPassword("");
	QString proxyPort("1");
	QString proxyType("");
	QString proxyUsername("");
	QString status("connected");
	QString transport("tcp");
	QString transportUniqueness("");
	auto ip(m_ui.neighborIP->text().toLower().trimmed());
	auto scopeId(m_ui.neighborScopeId->text());
	auto sslCS(m_ui.neighborsSslControlString->text().trimmed());

	if(m_ui.neighborTransport->currentIndex() == 0)
	  scopeId = "";
	else
	  {
	    if(m_ui.ipv4Neighbor->isChecked())
	      protocol = "IPv4";
	    else if(m_ui.ipv6Neighbor->isChecked())
	      protocol = "IPv6";
	    else
	      protocol = "Dynamic DNS";
	  }

	switch(m_ui.neighborTransport->currentIndex())
	  {
	  case 0:
	    {
	      transport = "bluetooth";
	      transportUniqueness = transport;
	      break;
	    }
	  case 1:
	    {
	      transport = "sctp";
	      transportUniqueness = transport;
	      break;
	    }
	  case 2:
	    {
	      transport = "tcp";
	      transportUniqueness = transport;
	      break;
	    }
	  case 3:
	    {
	      transport = "udp";
	      transportUniqueness = transport;
	      break;
	    }
	  case 4:
	    {
	      transport = "websocket";
	      transportUniqueness = "tcp";
	      break;
	    }
	  default:
	    {
	      break;
	    }
	  }

	if(nodeExists(db,
		      proxyHostName +
		      proxyPort +
		      ip +
		      port +
		      scopeId +
		      transportUniqueness,
		      "neighbors"))
	  {
	    error = tr("The specified neighbor already exists.");
	    ok = false;
	    goto close_db_label;
	  }

	query.prepare("INSERT INTO neighbors "
		      "(local_ip_address, "
		      "local_port, "
		      "protocol, "
		      "remote_ip_address, "
		      "remote_port, "
		      "sticky, "
		      "scope_id, "
		      "hash, "
		      "status_control, "
		      "country, "
		      "remote_ip_address_hash, "
		      "qt_country_hash, "
		      "proxy_hostname, "
		      "proxy_password, "
		      "proxy_port, "
		      "proxy_type, "
		      "proxy_username, "
		      "uuid, "
		      "echo_mode, "
		      "ssl_key_size, "
		      "allow_exceptions, "
		      "certificate, "
		      "ssl_required, "
		      "account_name, "
		      "account_password, "
		      "transport, "
		      "orientation, "
		      "ssl_control_string, "
		      "bind_ip_address) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		      "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
	query.bindValue(0, QVariant(QMetaType(QMetaType::QString)));
	query.bindValue(1, QVariant(QMetaType(QMetaType::QString)));
#else
	query.bindValue(0, QVariant(QVariant::String));
	query.bindValue(1, QVariant(QVariant::String));
#endif
	query.bindValue
	  (2, crypt->
	   encryptedThenHashed(protocol.toLatin1(), &ok).toBase64());

	if(ip.isEmpty())
	  query.bindValue
	    (3, crypt->
	     encryptedThenHashed(QByteArray(), &ok).toBase64());
	else if(transport != "bluetooth")
	  {
	    ip = spoton_misc::massageIpForUi(ip, protocol);

	    if(ok)
	      query.bindValue
		(3, crypt->
		 encryptedThenHashed(ip.toLatin1(), &ok).toBase64());
	  }
	else
	  {
	    if(ok)
	      query.bindValue
		(3, crypt->
		 encryptedThenHashed(ip.toLatin1(), &ok).toBase64());
	  }

	if(ok)
	  query.bindValue
	    (4, crypt->
	     encryptedThenHashed(port.toLatin1(), &ok).toBase64());

	query.bindValue(5, 1); // Sticky.

	if(ok)
	  query.bindValue
	    (6, crypt->
	     encryptedThenHashed(scopeId.toLatin1(), &ok).toBase64());

	if(m_ui.proxy->isChecked() && m_ui.proxy->isEnabled())
	  {
	    proxyHostName = m_ui.proxyHostname->text().trimmed();
	    proxyPort = QString::number(m_ui.proxyPort->value());
	  }

	if(ok)
	  query.bindValue
	    (7, crypt->
	     keyedHash((proxyHostName + proxyPort + ip + port + scopeId +
			transport).toLatin1(), &ok).
	     toBase64());

	query.bindValue(8, status);

	QString country("Unknown");

	if(transport != "bluetooth")
	  country = spoton_misc::countryNameFromIPAddress(ip);

	if(ok)
	  query.bindValue
	    (9, crypt->
	     encryptedThenHashed(country.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, crypt->keyedHash(ip.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (11, crypt->
	     keyedHash(country.remove(" ").toLatin1(), &ok).
	     toBase64());

	if(m_ui.proxy->isChecked() && m_ui.proxy->isEnabled())
	  proxyPassword = m_ui.proxyPassword->text();

	if(m_ui.proxy->isChecked() && m_ui.proxy->isEnabled())
	  {
	    /*
	    ** Avoid translation mishaps.
	    */

	    if(m_ui.proxyType->currentIndex() == 0)
	      proxyType = "HTTP";
	    else if(m_ui.proxyType->currentIndex() == 1)
	      proxyType = "Socks5";
	    else
	      proxyType = "System";
	  }
	else
	  proxyType = "NoProxy";

	if(m_ui.proxy->isChecked() && m_ui.proxy->isEnabled())
	  proxyUsername = m_ui.proxyUsername->text();

	if(ok)
	  query.bindValue
	    (12, crypt->
	     encryptedThenHashed(proxyHostName.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (13, crypt->
	     encryptedThenHashed(proxyPassword.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (14, crypt->encryptedThenHashed(proxyPort.toLatin1(),
					    &ok).toBase64());

	if(ok)
	  query.bindValue
	    (15, crypt->encryptedThenHashed(proxyType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (16, crypt->encryptedThenHashed(proxyUsername.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (17, crypt->
	     encryptedThenHashed("{00000000-0000-0000-0000-000000000000}",
				 &ok).toBase64());

	if(ok)
	  {
	    if(m_ui.neighborsEchoMode->currentIndex() == 0)
	      query.bindValue
		(18, crypt->
		 encryptedThenHashed("full", &ok).toBase64());
	    else
	      query.bindValue
		(18, crypt->
		 encryptedThenHashed("half", &ok).toBase64());
	  }

	if(m_ui.neighborTransport->currentIndex() == 2 || // TCP
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
	   m_ui.neighborTransport->currentIndex() == 3 || // UDP
#endif
	   m_ui.neighborTransport->currentIndex() == 4)   // WebSocket
	  {
	    if(m_ui.requireSsl->isChecked())
	      query.bindValue(19, m_ui.neighborKeySize->currentText().toInt());
	    else
	      query.bindValue(19, 0);
	  }
	else
	  query.bindValue(19, 0);

	if(m_ui.addException->isChecked() &&
	   (m_ui.neighborTransport->currentIndex() == 2 || // TCP
	    m_ui.neighborTransport->currentIndex() == 4))  // WebSocket
	  query.bindValue(20, 1);
	else
	  query.bindValue(20, 0);

	if(ok)
	  query.bindValue
	    (21, crypt->encryptedThenHashed(QByteArray(),
					    &ok).toBase64());

	if(m_ui.neighborTransport->currentIndex() == 2 || // TCP
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
	   m_ui.neighborTransport->currentIndex() == 3 || // UDP
#endif
	   m_ui.neighborTransport->currentIndex() == 4)   // WebSocket
	  query.bindValue(22, m_ui.requireSsl->isChecked() ? 1 : 0);
	else
	  query.bindValue(22, 0);

	if(ok)
	  query.bindValue
	    (23, crypt->encryptedThenHashed(QByteArray(),
					    &ok).toBase64());

	if(ok)
	  query.bindValue
	    (24, crypt->encryptedThenHashed(QByteArray(),
					    &ok).toBase64());

	if(ok)
	  {
	    if(m_ui.neighborTransport->currentIndex() == 0)
	      query.bindValue
		(25, crypt->encryptedThenHashed("bluetooth", &ok).toBase64());
	    else if(m_ui.neighborTransport->currentIndex() == 1)
	      query.bindValue
		(25, crypt->encryptedThenHashed("sctp", &ok).toBase64());
	    else if(m_ui.neighborTransport->currentIndex() == 2)
	      query.bindValue
		(25, crypt->encryptedThenHashed("tcp", &ok).toBase64());
	    else if(m_ui.neighborTransport->currentIndex() == 3)
	      query.bindValue
		(25, crypt->encryptedThenHashed("udp", &ok).toBase64());
	    else
	      query.bindValue
		(25, crypt->encryptedThenHashed("websocket", &ok).toBase64());
	  }

	if(ok)
	  {
	    if(m_ui.neighborOrientation->currentIndex() == 0)
	      query.bindValue
		(26, crypt->encryptedThenHashed("packet", &ok).toBase64());
	    else
	      query.bindValue
		(26, crypt->encryptedThenHashed("stream", &ok).toBase64());
	  }

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
        if(m_ui.requireSsl->isChecked() && (transport == "tcp" ||
					    transport == "udp" ||
					    transport == "websocket"))
	  {
	    if(sslCS.isEmpty())
	      sslCS = spoton_common::SSL_CONTROL_STRING;
	  }
	else
	  sslCS = "N/A";
#else
        if(m_ui.requireSsl->isChecked() && (transport == "tcp" ||
					    transport == "websocket"))
	  {
	    if(sslCS.isEmpty())
	      sslCS = spoton_common::SSL_CONTROL_STRING;
	  }
	else
	  sslCS = "N/A";
#endif

	query.bindValue(27, sslCS);
	query.bindValue
	  (28,
	   crypt->encryptedThenHashed(m_ui.bind_ip->text().
				      trimmed().toLatin1(), &ok).toBase64());

	if(ok)
	  ok = query.exec();

	if(query.lastError().isValid())
	  error = query.lastError().text().trimmed();
      }
    else
      {
	ok = false;

	if(db.lastError().isValid())
	  error = db.lastError().text().trimmed();
      }

    db.close();
  }

 close_db_label:

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    m_ui.neighborIP->selectAll();
  else if(error.isEmpty())
    QMessageBox::critical(this,
			  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			  tr("Unable to add the specified neighbor. "
			     "Please enable logging via the Log Viewer "
			     "and try again."));
  else
    QMessageBox::critical(this,
			  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			  tr("An error (%1) occurred while attempting "
			     "to add the specified neighbor.").arg(error));

  QApplication::processEvents();
}

void spoton::slotAuthenticate(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  auto const list
    (m_ui.neighbors->selectionModel()->
     selectedRows(m_ui.neighbors->columnCount() - 1)); // OID

  if(list.isEmpty())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid neighbor OID. Please select a neighbor."));
      QApplication::processEvents();
      return;
    }

  authenticate(crypt, list.at(0).data().toString());
}

void spoton::slotBlockNeighbor(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QString remoteIp("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item(row, 10); // Remote IP Address

      if(item)
	remoteIp = item->text();
    }

  if(remoteIp.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	/*
	** We must block all neighbors having the given remote IP
	** address. The neighbors must be in unblocked control states.
	** Neighbors that are marked as deleted must be left as is since
	** they will be purged by either the interface or the kernel.
	*/

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, " // 0
		      "OID "                       // 1
		      "FROM neighbors WHERE status_control NOT IN "
		      "('blocked', 'deleted')"))
	  while(query.next())
	    {
	      QString ip("");
	      auto ok = true;

	      ip = crypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		if(ip == remoteIp)
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare("UPDATE neighbors SET "
					"status_control = 'blocked' WHERE "
					"OID = ? AND "
					"status_control <> 'deleted'");
		    updateQuery.bindValue(0, query.value(1));
		    updateQuery.exec();
		  }
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotBuzzTools(int index)
{
  if(index == 0)
    m_ui.demagnetize->clear();
  else if(index == 1)
    demagnetize();
  else if(index == 2)
    magnetize();
  else if(index == 3)
    removeFavorite(false);
  else if(index == 4)
    removeFavorite(true);

  m_ui.buzzTools->blockSignals(true);
  m_ui.buzzTools->setCurrentIndex(0);
  m_ui.buzzTools->blockSignals(false);
}

void spoton::slotCallParticipant(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted() &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  QString keyType("");
  QString oid("");
  auto const type(action->property("type").toString().toLower());
  auto temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      auto item = m_ui.participants->item(row, 1); // OID

      if(item)
	{
	  keyType = item->data
	    (Qt::ItemDataRole(Qt::UserRole + 1)).toString().toLower();
	  oid = item->text();
	  temporary = item->data(Qt::UserRole).toBool();
	}
    }

  if(oid.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      return;
    }
  else if(keyType == "poptastic" && type == "calling_two_way")
    {
      QApplication::restoreOverrideCursor();
      return; // Not allowed!
    }
  else if(temporary) // Temporary friend?
    {
      QApplication::restoreOverrideCursor();
      return; // Not allowed!
    }

  if(type == "calling")
    slotGenerateGeminiInChat();
  else if(type == "calling_two_way")
    generateHalfGeminis();
  else if(type == "calling_using_gemini")
    {
    }
  else
    saveGemini(QPair<QByteArray, QByteArray> (), oid);

  QByteArray message;

  if(type == "calling_using_gemini")
    message.append("call_participant_using_gemini_");
  else
    message.append("call_participant_using_public_key_");

  message.append(keyType.toUtf8());
  message.append("_");
  message.append(oid.toUtf8());
  message.append("\n");

  if(!writeKernelSocketData(message))
    spoton_misc::logError
      (QString("spoton::slotCallParticipant(): write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));

  QApplication::restoreOverrideCursor();
}

void spoton::slotChangeTabPosition(int index)
{
  if(index == 0)
    {
      m_settings["gui/tabPosition"] = "east";
      m_ui.tab->setTabPosition(QTabWidget::East);
    }
  else if(index == 1)
    {
      m_settings["gui/tabPosition"] = "north";
      m_ui.tab->setTabPosition(QTabWidget::North);
    }
  else if(index == 2)
    {
      m_settings["gui/tabPosition"] = "south";
      m_ui.tab->setTabPosition(QTabWidget::South);
    }
  else if(index == 3)
    {
      m_settings["gui/tabPosition"] = "west";
      m_ui.tab->setTabPosition(QTabWidget::West);
    }
  else
    {
#if SPOTON_GOLDBUG == 0
      m_settings["gui/tabPosition"] = "north";
      m_ui.tab->setTabPosition(QTabWidget::North);
#else
      m_settings["gui/tabPosition"] = "east";
      m_ui.tab->setTabPosition(QTabWidget::East);
#endif
    }

  prepareTabIcons();

  QSettings settings;

  settings.setValue("gui/tabPosition", m_settings.value("gui/tabPosition"));
}

void spoton::slotConnectNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "status_control = 'connected' "
		      "WHERE OID = ? AND status_control <> 'deleted'");
	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotCopyAllMyPublicKeys(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const text(copyMyChatPublicKey() + s_keyDelimiter +
		  copyMyEmailPublicKey() + s_keyDelimiter +
#ifdef SPOTON_OPEN_LIBRARY_SUPPORTED
		  copyMyOpenLibraryPublicKey() + s_keyDelimiter +
#endif
		  copyMyPoptasticPublicKey() + s_keyDelimiter +
		  copyMyRosettaPublicKey() + s_keyDelimiter +
		  copyMyUrlPublicKey());

  QApplication::restoreOverrideCursor();

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The public keys are too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  auto clipboard = QApplication::clipboard();

  if(clipboard)
    {
      m_ui.toolButtonCopyToClipboard->menu()->repaint();
      repaint();
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      clipboard->setText(spoton_misc::wrap(text));
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotCopyEmailFriendshipBundle(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  QString keyType("");
  QString oid("");
  int row = -1;

  if((row = m_ui.emailParticipants->currentRow()) >= 0)
    {
      auto item = m_ui.emailParticipants->item(row, 1); // OID

      if(item)
	{
	  keyType = item->data(Qt::ItemDataRole(Qt::UserRole + 1)).
	    toString();
	  oid = item->text();
	}
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  if(!m_crypts.value(QString("%1-signature").arg(keyType), nullptr) ||
     !m_crypts.value(keyType, nullptr))
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  /*
  ** 1. Generate some symmetric information, S.
  ** 2. Encrypt S with the participant's public key.
  ** 3. Encrypt our information (name, public keys, signatures) with the
  **    symmetric key. Call our information T.
  ** 4. Compute a keyed hash of T.
  */

  QString neighborOid("");
  QByteArray hashKey;
  QByteArray keyInformation;
  QByteArray publicKey;
  QByteArray startsWith;
  QByteArray symmetricKey;
  QPair<QByteArray, QByteArray> gemini;
  QString receiverName("");
  auto const cipherType(m_settings.value("gui/kernelCipherType", "aes256").
			toString().toLatin1());
  auto ok = true;

  if(cipherType.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     hashKey,
				     startsWith,
				     neighborOid,
				     receiverName,
				     cipherType,
				     oid,
				     m_crypts.value(keyType, nullptr),
				     &ok);

  if(!ok || hashKey.isEmpty() || publicKey.isEmpty() || symmetricKey.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (symmetricKey.toBase64() + "@" +
     cipherType.toBase64() + "@" +
     hashKey.toBase64(),
     publicKey,
     startsWith,
     &ok);

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySPublicKey
    (m_crypts.value(QString("%1-signature").arg(keyType))->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySSignature
    (m_crypts.value(QString("%1-signature").arg(keyType))->
     digitalSignature(mySPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const myPublicKey(m_crypts.value(keyType)->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySignature(m_crypts.value(keyType)->
			 digitalSignature(myPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  QByteArray myName;

  if(keyType == "email")
    myName = m_settings.value("gui/emailName", "unknown").toByteArray();
  else
    myName = poptasticNameEmail();

  if(myName.isEmpty())
    {
      if(keyType == "email")
	myName = "unknown";
      else
	myName = "unknown@unknown.org";
    }

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     spoton_crypt::preferredHashAlgorithm(),
		     QByteArray(),
		     symmetricKey,
		     hashKey,
		     0,
		     0,
		     "");

  data = crypt.encrypted(keyType.toLatin1().toBase64() + "@" +
			 myName.toBase64() + "@" +
			 qCompress(myPublicKey).toBase64() + "@" +
			 mySignature.toBase64() + "@" +
			 mySPublicKey.toBase64() + "@" +
			 mySSignature.toBase64(), &ok);

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  QByteArray hash(crypt.keyedHash(data, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const text("R" +
		  keyInformation.toBase64() + "@" +
		  data.toBase64() + "@" +
		  hash.toBase64());

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QApplication::restoreOverrideCursor();
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The e-mail bundle is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  clipboard->setText(spoton_misc::wrap(text));
  QApplication::restoreOverrideCursor();
}

void spoton::slotDeactivateKernel(void)
{
  if(isKernelActive() && m_ui.deactivateKernel == sender())
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Are you sure that you wish to deactivate the kernel?"));
      mb.setWindowIcon(windowIcon());
      mb.setWindowModality(Qt::ApplicationModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  return;
	}

      QApplication::processEvents();
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  spoton_misc::deregisterKernel(spoton_misc::kernelPid());
  m_kernelSocket.close();
#if SPOTON_GOLDBUG == 1
  m_ui.activateKernel->setStyleSheet("background-color: #ff717e;"
				     "color: white;"
				     "border-style: outset;"
				     "border-width: 2px;"
				     "border-radius: 10px;"
				     "border-color: black;"
				     "min-width: 5em;"
				     "padding: 6px");
#endif
  m_forwardSecrecyRequests.clear();
  m_sb.forward_secrecy_request->setProperty("public_key_hash", QVariant());
  m_sb.forward_secrecy_request->setToolTip("");
  m_sb.forward_secrecy_request->setVisible(false);

  QElapsedTimer time;

  time.start();

  do
    {
      QApplication::processEvents();

      auto const pid = static_cast<pid_t> (m_ui.pid->text().toLongLong());

      if(pid <= 0)
	break;
      else if(time.hasExpired(10000))
	{
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_UNIX)
	  kill(pid, SIGTERM);
#endif
	  break;
	}
    }
  while(!m_quit);

  QApplication::restoreOverrideCursor();
}

void spoton::slotDeleteAllListeners(void)
{
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  {
	    query.exec("PRAGMA secure_delete = ON");
	    query.exec("DELETE FROM listeners");
	    query.exec("DELETE FROM listeners_accounts");
	    query.exec
	      ("DELETE FROM listeners_accounts_consumed_authentications");
	    query.exec("DELETE FROM listeners_allowed_ips");
	  }
	else
	  query.exec("UPDATE listeners SET "
		     "status_control = 'deleted' WHERE "
		     "status_control <> 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  m_ui.accounts->clear();
  m_ui.ae_tokens->setRowCount(0);
}

void spoton::slotDeleteAllNeighbors(void)
{
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  {
	    query.exec("PRAGMA secure_delete = ON");
	    query.exec("DELETE FROM neighbors");
	  }
	else
	  query.exec("UPDATE neighbors SET "
		     "status_control = 'deleted' WHERE "
		     "status_control <> 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteListener(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto deleteListener = false;

	if(!isKernelActive())
	  {
	    deleteListener = true;
	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM listeners WHERE OID = ?");
	  }
	else
	  query.prepare("UPDATE listeners SET status_control = 'deleted' "
			"WHERE OID = ? AND status_control <> 'deleted'");

	query.bindValue(0, oid);
	query.exec();

	if(deleteListener)
	  {
	    query.prepare("DELETE FROM listeners_accounts WHERE "
			  "listener_oid = ?");
	    query.bindValue(0, oid);
	    query.exec();
	    query.prepare
	      ("DELETE FROM listeners_accounts_consumed_authentications "
	       "WHERE listener_oid = ?");
	    query.bindValue(0, oid);
	    query.exec();
	    query.prepare("DELETE FROM listeners_allowed_ips WHERE "
			  "listener_oid = ?");
	    query.bindValue(0, oid);
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  {
	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM neighbors WHERE OID = ?");
	  }
	else
	  query.prepare("UPDATE neighbors SET status_control = 'deleted' "
			"WHERE OID = ? AND status_control <> 'deleted'");

	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDetachListenerNeighbors(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted() ||
       m_ui.kernelKeySize->currentText().toInt() == 0)
      {
	QByteArray message;

	message.append("detach_listener_neighbors_");
	message.append(oid.toUtf8());
	message.append("\n");

	if(!writeKernelSocketData(message))
	  spoton_misc::logError
	    (QString("spoton::slotDetachListenerNeighbors(): write() "
		     "failure for %1:%2.").
	     arg(m_kernelSocket.peerAddress().toString()).
	     arg(m_kernelSocket.peerPort()));
      }
}

void spoton::slotDisconnectListenerNeighbors(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted() ||
       m_ui.kernelKeySize->currentText().toInt() == 0)
      {
	QByteArray message;

	message.append("disconnect_listener_neighbors_");
	message.append(oid.toUtf8());
	message.append("\n");

	if(!writeKernelSocketData(message))
	  spoton_misc::logError
	    (QString("spoton::slotDisconnectListenerNeighbors(): "
		     "write() failure for %1:%2.").
	     arg(m_kernelSocket.peerAddress().toString()).
	     arg(m_kernelSocket.peerPort()));
      }
}

void spoton::slotDisconnectNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "status_control = 'disconnected' "
		      "WHERE OID = ? AND status_control <> 'deleted'");
	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDiscoverExternalAddress(void)
{
  m_externalAddress->discover();
}

void spoton::slotFavoritesActivated(int index)
{
  auto const data(m_ui.favorites->itemData(index).toByteArray());
  auto list(data.split('\n'));

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  m_ui.channel->setText(list.value(0));
  m_ui.channel->setCursorPosition(0);
  m_ui.buzzIterationCount->setValue
    (static_cast<int> (list.value(1).toULong()));
  m_ui.channelSalt->setText(list.value(2));
  m_ui.channelSalt->setCursorPosition(0);

  if(m_ui.channelType->findText(list.value(3)) > -1)
    m_ui.channelType->setCurrentIndex
      (m_ui.channelType->findText(list.value(3)));
  else
    m_ui.channelType->setCurrentIndex(0);

  m_ui.buzzHashKey->setText(list.value(4));
  m_ui.buzzHashKey->setCursorPosition(0);

  if(m_ui.buzzHashType->findText(list.value(5)) > -1)
    m_ui.buzzHashType->setCurrentIndex
      (m_ui.buzzHashType->findText(list.value(5)));
  else
    m_ui.buzzHashType->setCurrentIndex(0);
}

void spoton::slotGeneralTimerTimeout(void)
{
  QColor const color(240, 128, 128); // Light coral!
  QStandardItem *item = nullptr;
  auto const list(m_statisticsModel->findItems("Kernel PID"));
  auto const text(m_ui.pid->text());
  auto pidPalette(m_ui.pid->palette());

  pidPalette.setColor(m_ui.pid->backgroundRole(), color);

  if(!list.isEmpty())
    {
      item = list.at(0);

      if(item)
	item = m_statisticsModel->item(item->row(), 1);
    }

  if(!item)
    {
      m_ui.pid->setPalette(pidPalette);
      m_ui.pid->setText("0");
      m_ui.pid->setCursorPosition(0);
    }
  else
    {
      QColor const color(144, 238, 144); // Light green!
      auto palette(m_ui.pid->palette());

      palette.setColor(m_ui.pid->backgroundRole(), color);
      m_ui.pid->setPalette(palette);
      m_ui.pid->setText(item->text());
      m_ui.pid->setCursorPosition(0);
#if SPOTON_GOLDBUG == 1
      m_ui.activateKernel->setStyleSheet("background-color: lightgreen;"
					 "border-style: outset;"
					 "border-width: 2px;"
					 "border-radius: 10px;"
					 "border-color: black;"
					 "min-width: 5em;"
					 "padding: 6px");
#endif
    }

  highlightPaths();

  if(text != m_ui.pid->text())
    {
      m_buzzFavoritesLastModificationTime = QDateTime();
      m_listenersLastModificationTime = QDateTime();
      m_magnetsLastModificationTime = QDateTime();

      if(m_neighborsFuture.isFinished())
	m_neighborsLastModificationTime = QDateTime();

      if(m_participantsFuture.isFinished())
	m_participantsLastModificationTime = QDateTime();
    }

  auto const isKernelActive = this->isKernelActive();

  if(isKernelActive)
    if(m_kernelSocket.state() == QAbstractSocket::UnconnectedState)
      {
	QString connectionName("");
	quint16 port = 0;

	{
	  auto db = spoton_misc::database(connectionName);

	  db.setDatabaseName
	    (spoton_misc::homePath() + QDir::separator() + "kernel.db");

	  if(db.open())
	    {
	      QSqlQuery query(db);

	      query.setForwardOnly(true);

	      if(query.exec("SELECT port FROM kernel_gui_server"))
		if(query.next())
		  port = query.value(0).toByteArray().toUShort();
	    }

	  db.close();
	}

	QSqlDatabase::removeDatabase(connectionName);

	if(port > 0)
	  {
	    initializeKernelSocket();

	    if(m_ui.kernelKeySize->currentText().toInt() == 0)
	      m_kernelSocket.connectToHost("127.0.0.1", port);
	    else
	      m_kernelSocket.connectToHostEncrypted("127.0.0.1", port);
	  }
      }

  slotKernelSocketState();

  if(isKernelActive)
    {
      if(!m_buzzPages.isEmpty())
	{
	  if(!m_buzzStatusTimer.isActive())
	    m_buzzStatusTimer.start();
	}
      else
	m_buzzStatusTimer.stop();
    }
  else
    {
      m_buzzStatusTimer.stop();

      if(m_ui.kernelSecureMemoryPool->value() == 0)
	m_ui.kernelSecureMemoryPool->setStyleSheet
	  ("QSpinBox {background-color: rgb(240, 128, 128);}"); // Light coral!
      else
	{
	  m_ui.kernelSecureMemoryPool->setStyleSheet
	    (m_ui.kernelSecureMemoryPool->
	     property("original_stylesheet").toString());

	  if(m_ui.kernelSecureMemoryPool->value() <
	     spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE)
	    m_ui.kernelSecureMemoryPool->setValue
	      (spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE);
	}
    }

  if(isKernelActive)
    {
      if(m_kernelSocket.isEncrypted())
	{
#if SPOTON_GOLDBUG == 1
	  m_sb.kernelstatus->setIcon
	    (QIcon(QString(":/%1/status-online.png").
		   arg(m_settings.value("gui/iconSet", "nouve").toString().
		       toLower())));
#else
	  m_sb.kernelstatus->setIcon
	    (QIcon(QString(":/%1/activate.png").
		   arg(m_settings.value("gui/iconSet", "nouve").toString().
		       toLower())));
#endif
	}
      else
	m_sb.kernelstatus->setIcon(QIcon(":/generic/kernel-warning.png"));
    }
  else
    m_sb.kernelstatus->setIcon
      (QIcon(QString(":/%1/deactivate.png").
	     arg(m_settings.value("gui/iconSet", "nouve").toString().
		 toLower())));

  if(m_optionsUi.guiSecureMemoryPool->value() == 0)
    m_optionsUi.guiSecureMemoryPool->setStyleSheet
      ("QSpinBox {background-color: rgb(240, 128, 128);}"); // Light coral!
  else
    {
      m_optionsUi.guiSecureMemoryPool->setStyleSheet
	(m_optionsUi.guiSecureMemoryPool->
	 property("original_stylesheet").toString());

      if(m_optionsUi.guiSecureMemoryPool->value() <
	 spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE)
	m_optionsUi.guiSecureMemoryPool->setValue
	  (spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE);
    }

  if(!isKernelActive ||
     m_sb.status->text() != tr("<html><a href=\"authenticate\">"
			       "The kernel requires your authentication "
			       "and encryption keys.</a></html>"))
    {
      m_sb.status->setText
	(tr("External IP: %1.").
	 arg(m_externalAddress->address().isNull() ?
	     "unknown" : m_externalAddress->address().toString()));
      m_sb.status->repaint();
    }

  for(int i = m_starbeamDigestFutures.size() - 1; i >= 0; i--)
    if(m_starbeamDigestFutures.at(i).isFinished())
      m_starbeamDigestFutures.removeAt(i);

  if(isKernelActive)
    if(m_kernelSocket.state() != QAbstractSocket::ConnectedState ||
       m_kernelSocket.write("\n", 1) != 1)
      if(!m_crypts.isEmpty())
	{
	  /*
	  ** We'll need something here.
	  */
	}

  if(m_generalFuture.isFinished())
    {
      QHash<QString, QVariant> settings;

      settings["is_kernel_active"] = isKernelActive;
      settings["keep_only_user_defined_neighbors"] = m_optionsUi.
	keepOnlyUserDefinedNeighbors->isChecked();
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
      m_generalFuture = QtConcurrent::run
	(&spoton::generalConcurrentMethod, this, settings);
#else
      m_generalFuture = QtConcurrent::run
	(this, &spoton::generalConcurrentMethod, settings);
#endif
    }

  /*
  ** Is the PostgreSQL URLs database healthy?
  */

  if(!m_ui.url_database_connection_information->text().isEmpty())
    if(m_urlDatabase.driverName() == "QPSQL")
      if(findChildren<QProgressDialog *> ().isEmpty())
	if(m_pqUrlDatabaseFuture.isFinished())
	  {
	    auto crypt = m_crypts.value("chat", nullptr);

	    if(crypt)
	      {
		QByteArray name;
		QByteArray password;
		QSettings settings;
		auto ok = true;

		name = crypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(settings.value("gui/postgresql_name", "").
			      toByteArray()), &ok);

		if(ok)
		  password = crypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(settings.value("gui/postgresql_password", "").
				toByteArray()), &ok);

		if(ok)
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		  m_pqUrlDatabaseFuture = QtConcurrent::run
		    (&spoton::inspectPQUrlDatabase, this, name, password);
#else
		  m_pqUrlDatabaseFuture = QtConcurrent::run
		    (this, &spoton::inspectPQUrlDatabase, name, password);
#endif
	      }
	  }

  /*
  ** Purge expired Forward Secrecy objects.
  */

  QMutableHashIterator<QByteArray, spoton_forward_secrecy> it
    (m_forwardSecrecyRequests);
  auto const delta1 = m_settings.value
    ("gui/forward_secrecy_time_delta", 30).toLongLong() + 5;
  auto const delta2 = m_settings.value
    ("gui/poptastic_forward_secrecy_time_delta", 60).toLongLong() + 10;

  while(it.hasNext())
    {
      it.next();

      auto const now(QDateTime::currentDateTime());
      auto const secsTo = qAbs(now.secsTo(it.value().m_date_time));

      if(it.value().m_key_type != "poptastic")
	{
	  if(secsTo >= delta1)
	    it.remove();
	}
      else
	{
	  if(secsTo >= delta2)
	    it.remove();
	}
    }

  popForwardSecrecyRequest(QByteArray());
}

void spoton::slotHideOfflineParticipants(bool state)
{
  m_participantsLastModificationTime = QDateTime();
  m_settings["gui/hideOfflineParticipants"] = state;

  QSettings settings;

  settings.setValue("gui/hideOfflineParticipants", state);
  slotPopulateParticipants();
}

void spoton::slotKernelLogEvents(bool state)
{
  m_settings["gui/kernelLogEvents"] = state;

  QSettings settings;

  settings.setValue("gui/kernelLogEvents", state);
}

void spoton::slotKernelSocketError(QAbstractSocket::SocketError error)
{
  Q_UNUSED(error);
  spoton_misc::logError
    (QString("spoton::slotKernelSocketError(): socket error (%1).").
     arg(m_kernelSocket.errorString()));
}

void spoton::slotKernelSocketSslErrors(const QList<QSslError> &errors)
{
  m_kernelSocket.ignoreSslErrors();

  for(int i = 0; i < errors.size(); i++)
    spoton_misc::logError
      (QString("spoton::slotKernelSocketSslErrors(): "
	       "error (%1) occurred for %2:%3.").
       arg(errors.at(i).errorString()).
       arg(m_kernelSocket.peerAddress().isNull() ? m_kernelSocket.peerName() :
	   m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotKernelSocketState(void)
{
  auto const state = m_kernelSocket.state();

  if(state == QAbstractSocket::ConnectedState)
    {
      m_kernelSocket.setSocketOption
	(QAbstractSocket::LowDelayOption,
	 m_settings.value("gui/tcp_nodelay", 1).toInt()); /*
							  ** Disable Nagle?
							  */
      if(m_kernelSocket.isEncrypted() ||
	 m_ui.kernelKeySize->currentText().toInt() == 0)
	{
	  sendKeysToKernel();
	  askKernelToReadStarBeamKeys();
	  sendBuzzKeysToKernel();

	  if(m_kernelSocket.isEncrypted())
	    {
	      auto const cipher(m_kernelSocket.sessionCipher());
	      auto const str(QString("%1-%2-%3-%4-%5-%6-%7").
			     arg(cipher.name()).
			     arg(cipher.authenticationMethod()).
			     arg(cipher.encryptionMethod()).
			     arg(cipher.keyExchangeMethod()).
			     arg(cipher.protocolString()).
			     arg(cipher.supportedBits()).
			     arg(cipher.usedBits()));

	      m_sb.kernelstatus->setToolTip
		(tr("<html>Connected to the kernel on port %1 "
		    "from local port %2 via cipher %3.</html>").
		 arg(m_kernelSocket.peerPort()).
		 arg(m_kernelSocket.localPort()).
		 arg(str));
	    }
	  else
	    m_sb.kernelstatus->setToolTip
	      (tr("Connected to the kernel on port %1 from local port %2.").
	       arg(m_kernelSocket.peerPort()).
	       arg(m_kernelSocket.localPort()));
	}
      else
	m_sb.kernelstatus->setToolTip
	  (tr("<html>Connected to the kernel on port %1 "
	      "from local port %2. Communications between the interface and "
	      "the kernel have been disabled.</html>").
	   arg(m_kernelSocket.peerPort()).
	   arg(m_kernelSocket.localPort()));
    }
  else if(state == QAbstractSocket::UnconnectedState)
    {
      m_keysShared["buzz_channels_sent_to_kernel"] = "false";
      m_keysShared["keys_sent_to_kernel"] = "false";

      if(isKernelActive())
	m_sb.kernelstatus->setToolTip
	  (tr("<html>The interface is not connected to the kernel. However, "
	      "the kernel appears to be active. Perhaps the kernel's "
	      "UI server has been disabled.</html>"));
      else
	m_sb.kernelstatus->setToolTip
	  (tr("<html>The interface is not connected to the kernel. "
	      "Is the kernel active?</html>"));
    }
}

void spoton::slotListenerChanged(QTableWidgetItem *item)
{
  if(!item)
    return;

  if(!(item->column() == 0 ||  // Activate
       item->column() == 12 || // Use Accounts?
       item->column() == 21))  // Passthrough
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString oid("");

	if(m_ui.listeners->item(item->row(),
				m_ui.listeners->columnCount() - 1))
	  oid = m_ui.listeners->item
	    (item->row(), m_ui.listeners->columnCount() - 1)->text();

	if(item->column() == 0)
	  {
	    query.prepare("UPDATE listeners SET "
			  "status_control = ? "
			  "WHERE OID = ? AND status_control <> 'deleted'");

	    if(item->checkState() == Qt::Checked)
	      query.bindValue(0, "online");
	    else
	      query.bindValue(0, "offline");

	    query.bindValue(1, oid);
	    query.exec();
	  }
	else if(item->column() == 12)
	  {
	    query.prepare
	      ("UPDATE listeners SET use_accounts = ? WHERE OID = ?");

	    if(item->checkState() == Qt::Checked)
	      query.bindValue(0, 1);
	    else
	      query.bindValue(0, 0);

	    query.bindValue(1, oid);
	    query.exec();
	  }
	else if(item->column() == 21)
	  {
	    query.prepare("UPDATE listeners SET passthrough = ? WHERE OID = ?");
	    query.bindValue(0, item->checkState() == Qt::Checked ? 1 : 0);
	    query.bindValue(1, oid);
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotListenerFullEcho(void)
{
  changeEchoMode("full", m_ui.listeners);
}

void spoton::slotListenerHalfEcho(void)
{
  changeEchoMode("half", m_ui.listeners);
}

void spoton::slotListenerMaximumChanged(int value)
{
  auto spinBox = qobject_cast<QSpinBox *> (sender());

  if(!spinBox)
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto const name(spinBox->property("field_name").toString().toLower());

	if(name == "maximum_buffer_size")
	  query.prepare("UPDATE listeners SET "
			"maximum_buffer_size = ? "
			"WHERE OID = ?");
	else
	  query.prepare("UPDATE listeners SET "
			"maximum_content_length = ? "
			"WHERE OID = ?");

	query.bindValue(0, value);
	query.bindValue(1, spinBox->property("oid"));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotMaximumClientsChanged(int index)
{
  auto comboBox = qobject_cast<QComboBox *> (sender());

  if(comboBox)
    {
      QString connectionName("");

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "listeners.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE listeners SET "
			  "maximum_clients = ? "
			  "WHERE OID = ?");

	    if(index != comboBox->count() - 1)
	      query.bindValue(0, comboBox->itemText(index).toInt());
	    else
	      query.bindValue(0, 0);

	    query.bindValue(1, comboBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotModeChanged(QSslSocket::SslMode mode)
{
  spoton_misc::logError(QString("spoton::slotModeChanged(): "
				"the connection mode has changed to %1 "
				"for %2:%3.").
			arg(mode).
			arg(m_kernelSocket.peerAddress().toString()).
			arg(m_kernelSocket.peerPort()));

  if(mode == QSslSocket::UnencryptedMode)
    {
      spoton_misc::logError
	(QString("spoton::slotModeChanged(): "
		 "plaintext mode. Disconnecting kernel socket for "
		 "%1:%2.").
	 arg(m_kernelSocket.peerAddress().toString()).
	 arg(m_kernelSocket.peerPort()));
      m_kernelSocket.close();
    }
}

void spoton::slotNeighborChanged(QTableWidgetItem *item)
{
  if(!item)
    return;

  if(!(item->column() == 0 || // Sticky
       item->column() == 37)) // Passthrough
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString oid("");

	if(m_ui.neighbors->item(item->row(),
				m_ui.neighbors->columnCount() - 1))
	  oid = m_ui.neighbors->item(item->row(),
				     m_ui.neighbors->columnCount() - 1)->
	    text();

	if(item->column() == 0)
	  {
	    query.prepare("UPDATE neighbors SET "
			  "sticky = ? "
			  "WHERE OID = ?");
	    query.bindValue(0, item->checkState() == Qt::Checked ? 1 : 0);
	    query.bindValue(1, oid);
	    query.exec();
	  }
	else if(item->column() == 37)
	  {
	    query.prepare("UPDATE neighbors SET "
			  "passthrough = ? "
			  "WHERE OID = ?");
	    query.bindValue(0, item->checkState() == Qt::Checked ? 1 : 0);
	    query.bindValue(1, oid);
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotNeighborFullEcho(void)
{
  changeEchoMode("full", m_ui.neighbors);
}

void spoton::slotNeighborHalfEcho(void)
{
  changeEchoMode("half", m_ui.neighbors);
}

void spoton::slotNeighborMaximumChanged(int value)
{
  auto spinBox = qobject_cast<QSpinBox *> (sender());

  if(!spinBox)
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto const name(spinBox->property("field_name").toString().toLower());

	if(name == "maximum_buffer_size")
	  query.prepare("UPDATE neighbors SET "
			"maximum_buffer_size = ? "
			"WHERE OID = ?");
	else
	  query.prepare("UPDATE neighbors SET "
			"maximum_content_length = ? "
			"WHERE OID = ?");

	query.bindValue(0, value);
	query.bindValue(1, spinBox->property("oid"));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotPopulateBuzzFavorites(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QFileInfo const fileInfo
    (spoton_misc::homePath() + QDir::separator() + "buzz_channels.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() >= m_buzzFavoritesLastModificationTime)
	{
	  if(fileInfo.lastModified() == m_buzzFavoritesLastModificationTime)
	    m_buzzFavoritesLastModificationTime = fileInfo.lastModified().
	      addMSecs(1);
	  else
	    m_buzzFavoritesLastModificationTime = fileInfo.lastModified();
	}
      else
	return;
    }
  else
    m_buzzFavoritesLastModificationTime = QDateTime();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QMap<QByteArray, QByteArray> map;
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);
	auto focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	if(query.exec("SELECT data FROM buzz_channels"))
	  while(query.next())
	    {
	      QByteArray data;
	      auto ok = true;

	      data = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		{
		  QByteArray channelName;
		  QByteArray channelSalt;
		  QByteArray channelType;
		  QByteArray hashKey;
		  QByteArray hashType;
		  auto const list(data.split('\n'));

		  channelName = QByteArray::fromBase64(list.value(0));
		  channelType = QByteArray::fromBase64(list.value(3));
		  hashKey = QByteArray::fromBase64(list.value(4));
		  hashType = QByteArray::fromBase64(list.value(5));

		  if(!channelName.isEmpty() && !channelType.isEmpty() &&
		     !hashKey.isEmpty() && !hashType.isEmpty())
		    {
		      QByteArray label;
		      unsigned long int iterationCount = 0;

		      channelSalt = QByteArray::fromBase64
			(list.value(2));
		      iterationCount = qMax
			(QByteArray::fromBase64(list.value(1)).
			 toULong(), static_cast<unsigned long int> (10000));

		      if(channelName.length() > 16)
			{
			  label.append(channelName.mid(0, 8));
			  label.append("...");
			  label.append
			    (channelName.mid(channelName.length() - 8));
			}
		      else
			label.append(channelName);

		      label.append(":");
		      label.append(QString::number(iterationCount).toUtf8());
		      label.append(":");

		      if(channelSalt.length() > 16)
			{
			  label.append(channelSalt.mid(0, 8));
			  label.append("...");
			  label.append
			    (channelSalt.mid(channelSalt.length() - 8));
			}
		      else
			label.append(channelSalt);

		      label.append(":");
		      label.append(channelType);
		      label.append(":");

		      if(hashKey.length() > 16)
			{
			  label.append(hashKey.mid(0, 8));
			  label.append("...");
			  label.append
			    (hashKey.mid(hashKey.length() - 8));
			}
		      else
			label.append(hashKey);

		      label.append(":");
		      label.append(hashType);
		      map.insert(label, data);
		    }
		}
	    }

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!map.isEmpty())
    {
      m_ui.favorites->clear();

      while(!m_ui.shareBuzzMagnet->menu()->actions().isEmpty())
	{
	  auto action = m_ui.shareBuzzMagnet->menu()->actions().first();

	  m_ui.shareBuzzMagnet->menu()->removeAction(action);
	  action->deleteLater();
	}

      for(int i = 0; i < map.keys().size(); i++)
	{
	  m_ui.favorites->addItem(map.keys().at(i));
	  m_ui.favorites->setItemData(i, map.value(map.keys().at(i)));

	  auto action = new QAction(map.keys().at(i), this);

	  action->setData(map.value(map.keys().at(i)));
	  connect(action,
		  SIGNAL(triggered(void)),
		  this,
		  SLOT(slotShareBuzzMagnet(void)));
	  m_ui.shareBuzzMagnet->menu()->addAction(action);
	}
    }
  else
    {
      m_ui.favorites->clear();
      m_ui.favorites->addItem("Empty"); // Please do not translate Empty.

      while(!m_ui.shareBuzzMagnet->menu()->actions().isEmpty())
	{
	  auto action = m_ui.shareBuzzMagnet->menu()->actions().first();

	  m_ui.shareBuzzMagnet->menu()->removeAction(action);
	  action->deleteLater();
	}
    }

  m_ui.favorites->setMinimumContentsLength(25);
  QApplication::restoreOverrideCursor();
}

void spoton::slotPopulateListeners(void)
{
#if SPOTON_GOLDBUG == 0
  if(m_ui.listenersTemporarilyPause->isChecked())
    return;
#endif

  if(currentTabName() != "listeners")
    return;

  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QFileInfo const fileInfo
    (spoton_misc::homePath() + QDir::separator() + "listeners.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() >= m_listenersLastModificationTime)
	{
	  if(fileInfo.lastModified() == m_listenersLastModificationTime)
	    m_listenersLastModificationTime = fileInfo.lastModified().
	      addMSecs(1);
	  else
	    m_listenersLastModificationTime = fileInfo.lastModified();
	}
      else
	return;
    }
  else
    m_listenersLastModificationTime = QDateTime();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	disconnect(m_ui.listeners,
		   SIGNAL(itemChanged(QTableWidgetItem *)),
		   this,
		   SLOT(slotListenerChanged(QTableWidgetItem *)));

	QModelIndexList list;
	QString ip("");
	QString port("");
	QString scopeId("");
	QString transportS("");
	auto const hval = m_ui.listeners->horizontalScrollBar()->value();
	auto const vval = m_ui.listeners->verticalScrollBar()->value();
	auto focusWidget = QApplication::focusWidget();
	int columnIP = 3;
	int columnPORT = 4;
	int columnSCOPE_ID = 5;
	int columnTRANSPORT = 15;
	int row = -1;

	list = m_ui.listeners->selectionModel()->selectedRows
	  (columnIP);

	if(!list.isEmpty())
	  ip = list.at(0).data().toString();

	list = m_ui.listeners->selectionModel()->selectedRows
	  (columnPORT);

	if(!list.isEmpty())
	  port = list.at(0).data().toString();

	list = m_ui.listeners->selectionModel()->selectedRows
	  (columnSCOPE_ID);

	if(!list.isEmpty())
	  scopeId = list.at(0).data().toString();

	list = m_ui.listeners->selectionModel()->selectedRows
	  (columnTRANSPORT);

	if(!list.isEmpty())
	  transportS = list.at(0).data().toString();

	m_ui.listeners->setUpdatesEnabled(false);
	m_ui.listeners->setSortingEnabled(false);
	m_ui.listeners->setRowCount(0);

	QSqlQuery query(db);
	int totalRows = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM listeners "
		      "WHERE status_control <> 'deleted'"))
	  if(query.next())
	    m_ui.listeners->setRowCount(query.value(0).toInt());

	if(query.exec("SELECT "
		      "status_control, "                  // 0
		      "status, "                          // 1
		      "ssl_key_size, "                    // 2
		      "ip_address, "                      // 3
		      "port, "                            // 4
		      "scope_id, "                        // 5
		      "protocol, "                        // 6
		      "external_ip_address, "             // 7
		      "external_port, "                   // 8
		      "connections, "                     // 9
		      "maximum_clients, "                 // 10
		      "echo_mode, "                       // 11
		      "use_accounts, "                    // 12
		      "maximum_buffer_size, "             // 13
		      "maximum_content_length, "          // 14
		      "transport, "                       // 15
		      "share_udp_address, "               // 16
		      "certificate, "                     // 17
		      "orientation, "                     // 18
		      "ssl_control_string, "              // 19
		      "lane_width, "                      // 20
		      "passthrough, "                     // 21
		      "source_of_randomness, "            // 22
		      "private_application_credentials, " // 23
		      "socket_options, "                  // 24
		      "OID "                              // 25
		      "FROM listeners WHERE status_control <> 'deleted'"))
	  {
	    QLocale locale;

	    row = 0;

	    while(query.next() && totalRows < m_ui.listeners->rowCount())
	      {
		totalRows += 1;

		QByteArray certificateDigest;
		QString tooltip("");
		QString transport("");
		auto ok = true;

		certificateDigest = crypt->
		  decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(17).toByteArray()),
		   &ok);

		if(!ok)
		  {
		    certificateDigest.clear();
		    certificateDigest.append(tr("error").toUtf8());
		  }

		if(ok)
		  if(!certificateDigest.isEmpty())
		    {
		      certificateDigest = spoton_crypt::
			sha512Hash(certificateDigest, &ok).toHex();

		      if(!ok)
			certificateDigest.clear();
		    }

		if(ok)
		  transport = QString
		    (crypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.value(15).
							    toByteArray()),
						 &ok)).toUpper();

		tooltip = QString
		  (tr("<html>Status: %1<br>"
		      "Bluetooth Flags / SSL Key Size: %2<br>"
		      "Local IP: %3 Local Port: %4 Scope ID: %5<br>"
		      "External IP: %6<br>"
		      "Connections: %7<br>"
		      "Echo Mode: %8<br>"
		      "Use Accounts: %9<br>"
		      "Transport: %10<br>"
		      "Share Address: %11<br>"
		      "Orientation: %12<br>"
		      "SSL Control String: %13<br>"
		      "Lane Width: %14<br>"
		      "Passthrough: %15<br>"
		      "Source of Randomness: %16<br>"
		      "Socket Options: %17</html>")).
		  arg(query.value(1).toString().toLower()).
		  arg(query.value(2).toString()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(3).
							     toByteArray()),
						  &ok).constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(4).
							     toByteArray()),
						  &ok).constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(5).
							     toByteArray()),
						  &ok).constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(7).
							     toByteArray()),
						  &ok).constData()).
		  arg(query.value(9).toString()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(11).
							     toByteArray()),
						  &ok).constData()).
		  arg(query.value(12).toLongLong() ? tr("Yes") : tr("No")).
		  arg(transport).
		  arg(query.value(16).toLongLong() ? tr("Yes") : tr("No")).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(18).
							     toByteArray()),
						  &ok).constData()).
		  arg(query.value(19).toString()).
		  arg(locale.toString(query.value(20).toInt())).
		  arg(query.value(21).toInt() ? tr("Yes") : tr("No")).
		  arg(locale.toString(query.value(22).toInt())).
		  arg(query.value(24).toString().trimmed());

		for(int i = 0; i < query.record().count(); i++)
		  {
		    spoton_table_widget_item *item = nullptr;

		    if(i == 0 || i == 12) // status_control, use_accounts
		      {
			item = new spoton_table_widget_item();
			item->setFlags(Qt::ItemIsEnabled |
				       Qt::ItemIsSelectable |
				       Qt::ItemIsUserCheckable);

			if(i == 0)
			  {
			    if(query.value(0).toString().toLower() == "online")
			      item->setCheckState(Qt::Checked);
			    else
			      item->setCheckState(Qt::Unchecked);
			  }
			else
			  {
			    if(query.value(i).toBool())
			      item->setCheckState(Qt::Checked);
			    else
			      item->setCheckState(Qt::Unchecked);
			  }
		      }
		    else if(i == 2) // ssl_key_size
		      {
			if(transport.toLower() == "bluetooth")
			  {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
			    QComboBox *box = nullptr;
			    QList<QBluetooth::Security> items;
			    QMap<QBluetooth::Security, QString> map;
			    QMap<QBluetooth::SecurityFlags,
				 QString> possibilities;
			    QMap<QString, char> values;
			    auto widget = combinationBoxForTable();

			    box = widget->findChild<QComboBox *> ();
			    items << QBluetooth::Security::Authentication
				  << QBluetooth::Security::Authorization
				  << QBluetooth::Security::Encryption
				  << QBluetooth::Security::Secure;
			    map[QBluetooth::Security::Authentication] =
			      "Authentication";
			    map[QBluetooth::Security::Authorization] =
			      "Authorization";
			    map[QBluetooth::Security::Encryption] =
			      "Encryption";
			    map[QBluetooth::Security::Secure] = "Secure";

			    for(int ii = 0; ii < items.size(); ii++)
			      {
				possibilities.insert
				  (items.at(ii), map[items.at(ii)]);

				for(int jj = 0; jj < items.size(); jj++)
				  {
				    if(ii == jj)
				      continue;

				    if(!possibilities.
				       contains((items.at(ii) | items.at(jj))))
				      possibilities.insert
					((items.at(ii) |
					  items.at(jj)),
					 map[items.at(ii)] + ", " +
					 map[items.at(jj)]);

				    for(int kk = 0; kk < items.size(); kk++)
				      {
					if(ii == kk ||
					   jj == kk)
					  continue;

					if(!possibilities.
					   contains((items.at(ii) |
						     items.at(jj) |
						     items.at(kk))))
					  possibilities.insert
					    ((items.at(ii) |
					      items.at(jj) |
					      items.at(kk)),
					     map[items.at(ii)] + ", " +
					     map[items.at(jj)] + ", " +
					     map[items.at(kk)]);

					for(int ll = 0; ll < items.size();
					    ll++)
					  {
					    if(ii == ll ||
					       jj == ll ||
					       kk == ll)
					      continue;

					    if(!possibilities.
					       contains((items.at(ii) |
							 items.at(jj) |
							 items.at(kk) |
							 items.at(ll))))
					      possibilities.insert
						((items.at(ii) |
						  items.at(jj) |
						  items.at(kk) |
						  items.at(ll)),
						 map[items.at(ii)] + ", " +
						 map[items.at(jj)] + ", " +
						 map[items.at(kk)] + ", " +
						 map[items.at(ll)]);
					  }
				      }
				  }
			      }

			    values.insert(" 0", 0);

			    for(int ii = 0; ii < possibilities.size(); ii++)
			      values.insert
				(QString::
				 number(possibilities.keys().at(ii)).
				 rightJustified(2, ' ') + " " +
				 possibilities.values().at(ii), 0);

			    box->addItems(values.keys());
			    box->setCurrentIndex
			      (query.value(i).toInt());

			    if(box->currentIndex() < 0)
			      box->setCurrentIndex(0);

			    box->setProperty
			      ("oid", query.value(query.record().count() - 1));
			    connect(box,
				    SIGNAL(currentIndexChanged(int)),
				    this,
				    SLOT(slotBluetoothSecurityChanged(int)));
			    m_ui.listeners->setCellWidget(row, i, widget);
#endif
			    item = new spoton_table_widget_item
			      (query.value(i).toString());

			    if(item->text().toInt() == 0)
			      item->setBackground
				(QBrush(QColor(240, 128, 128)));
			    else
			      item->setBackground(QBrush());
			  }
			else
			  {
			    if(query.value(i).toLongLong() == 0)
			      {
				item = new spoton_table_widget_item("0");
				item->setBackground
				  (QBrush(QColor(240, 128, 128)));
			      }
			    else
			      {
				item = new spoton_table_widget_item
				  (query.value(i).toString());
				item->setBackground(QBrush());
			      }
			  }
		      }
		    else if(i == 9) // connections
		      item = new spoton_table_widget_item
			(query.value(i).toString());
		    else if(i == 10) // maximum_clients
		      {
			QComboBox *box = nullptr;
			auto widget = combinationBoxForTable();

			box = widget->findChild<QComboBox *> ();

			if(transport != "UDP")
			  {
			    box->setProperty
			      ("oid", query.value(query.record().count() - 1));
			    box->addItem("1");

			    for(int j = 1; j <= 10; j++)
			      box->addItem(QString::number(5 * j));

			    box->addItem(tr("Unlimited"));
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
			    box->setMaximumWidth
			      (box->fontMetrics().
			       horizontalAdvance(tr("Unlimited")) + 50);
#else
			    box->setMaximumWidth
			      (box->fontMetrics().width(tr("Unlimited")) + 50);
#endif
			    m_ui.listeners->setCellWidget(row, i, widget);

			    if(query.value(i).toLongLong() <= 0)
			      box->setCurrentIndex(box->count() - 1);
			    else if(box->findText(QString::
						  number(query.
							 value(i).
							 toLongLong())) >= 0)
			      box->setCurrentIndex
				(box->findText(QString::number(query.
							       value(i).
							       toLongLong())));
			    else
			      box->setCurrentIndex(1); // Default of five.

			    connect(box,
				    SIGNAL(currentIndexChanged(int)),
				    this,
				    SLOT(slotMaximumClientsChanged(int)));
			  }
			else
			  {
			    box->addItem(tr("Unlimited"));
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
			    box->setMaximumWidth
			      (box->fontMetrics().
			       horizontalAdvance(tr("Unlimited")) + 50);
#else
			    box->setMaximumWidth
			      (box->fontMetrics().width(tr("Unlimited")) + 50);
#endif
			    box->setEnabled(false);
			    m_ui.listeners->setCellWidget(row, i, widget);
			  }

			item = new spoton_table_widget_item
			  (query.value(i).toString());
		      }
		    else if(i == 13 || i == 14)
		      {
			// maximum_buffer_size
			// maximum_content_length

			auto box = new QSpinBox();

			if(i == 13)
			  {
			    box->setMaximum
			      (spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
			    box->setMinimum
			      (spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
			  }
			else
			  box->setMaximum
			    (spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);

			box->setCorrectionMode
			  (QAbstractSpinBox::CorrectToNearestValue);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
			box->setMaximumWidth
			  (box->fontMetrics().
			   horizontalAdvance
			   (QString::
			    number(spoton_common::
				   MAXIMUM_NEIGHBOR_BUFFER_SIZE)) + 50);
#else
			box->setMaximumWidth
			  (box->fontMetrics().
			   width(QString::
				 number(spoton_common::
					MAXIMUM_NEIGHBOR_BUFFER_SIZE)) + 50);
#endif
			box->setProperty
			  ("field_name", query.record().fieldName(i));
			box->setProperty
			  ("oid", query.value(query.record().count() - 1));
			box->setToolTip
			  (QString("[%1, %2]").
			   arg(box->minimum()).arg(box->maximum()));
			box->setValue
			  (static_cast<int> (query.value(i).toLongLong()));
			box->setWrapping(true);
			item = new spoton_table_widget_item
			  (query.value(i).toString());
			connect(box,
				SIGNAL(valueChanged(int)),
				this,
				SLOT(slotListenerMaximumChanged(int)));
			m_ui.listeners->setCellWidget(row, i, box);
		      }
		    else if(i == 16) // share_udp_address
		      item = new spoton_table_widget_item
			(query.value(i).toString());
		    else if(i == 17) // certificate
		      item = new spoton_table_widget_item
			(QString(certificateDigest));
		    else if(i == 20) // lane_width
		      {
			QComboBox *box = nullptr;
			auto list(spoton_common::LANE_WIDTHS);
			auto widget = combinationBoxForTable();

			box = widget->findChild<QComboBox *> ();

			if(!list.contains(spoton_common::LANE_WIDTH_DEFAULT))
			  list << spoton_common::LANE_WIDTH_DEFAULT;

			if(!list.contains(spoton_common::LANE_WIDTH_MAXIMUM))
			  list << spoton_common::LANE_WIDTH_MAXIMUM;

			if(!list.contains(spoton_common::LANE_WIDTH_MINIMUM))
			  list << spoton_common::LANE_WIDTH_MINIMUM;

			std::sort(list.begin(), list.end());

			for(int j = 0; j < list.size(); j++)
			  box->addItem(QString::number(list.at(j)));

			box->setProperty
			  ("oid", query.value(query.record().count() - 1));
			box->setProperty("table", "listeners");
			m_ui.listeners->setCellWidget(row, i, widget);

			if(box->findText(QString::
					 number(query.
						value(i).
						toInt())) >= 0)
			  box->setCurrentIndex
			    (box->findText(QString::number(query.
							   value(i).
							   toInt())));
			else
			  box->setCurrentIndex(box->count() - 1); // Maximum.

			connect(box,
				SIGNAL(currentIndexChanged(int)),
				this,
				SLOT(slotLaneWidthChanged(int)));
			item = new spoton_table_widget_item
			  (query.value(i).toString());
		      }
		    else if(i == 21) // passthrough
		      {
			item = new spoton_table_widget_item();
			item->setFlags(Qt::ItemIsEnabled |
				       Qt::ItemIsSelectable |
				       Qt::ItemIsUserCheckable);

			if(query.value(i).toBool())
			  item->setCheckState(Qt::Checked);
			else
			  item->setCheckState(Qt::Unchecked);
		      }
		    else if(i == 22) // source_of_randomness
		      {
			auto box = new QSpinBox();

			box->setMaximum(std::numeric_limits<unsigned short>::
					max());
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
			box->setMaximumWidth
			  (box->fontMetrics().
			   horizontalAdvance(QString::
					     number(box->maximum())) + 50);
#else
			box->setMaximumWidth
			  (box->fontMetrics().
			   width(QString::
				 number(box->maximum())) + 50);
#endif
			box->setMinimum(0);
			box->setProperty
			  ("oid", query.value(query.record().count() - 1));
			box->setToolTip(tooltip);
			box->setValue(query.value(i).toInt());
			item = new spoton_table_widget_item
			  (query.value(i).toString());
			connect
			  (box,
			   SIGNAL(valueChanged(int)),
			   this,
			   SLOT(slotListenerSourceOfRandomnessChanged(int)));
			m_ui.listeners->setCellWidget(row, i, box);
		      }
		    else
		      {
			if((i >= 3 && i <= 7) ||
			   i == 11 || i == 15 || i == 18 || i == 23)
			  {
			    if(query.isNull(i))
			      item = new spoton_table_widget_item();
			    else
			      {
				switch(i)
				  {
				  case 3: // ip_address
				  case 4: // port
				  case 7: // external_ip_address
				    {
				      item = new spoton_table_widget_item
					(QString(crypt->
						 decryptedAfterAuthenticated
						 (QByteArray::
						  fromBase64(query.
							     value(i).
							     toByteArray()),
						  &ok)));
				      break;
				    }
				  default:
				    {
				      item = new spoton_table_widget_item
					(QString(crypt->
						 decryptedAfterAuthenticated
						 (QByteArray::
						  fromBase64(query.
							     value(i).
							     toByteArray()),
						  &ok)));
				      break;
				    }
				  }

				if(!ok)
				  item->setText(tr("error"));
			      }
			  }
			else
			  item = new spoton_table_widget_item
			    (query.value(i).toString());
		      }

		    if(item)
		      {
			if(!(i == 0 || i == 12 || i == 21))
			  item->setFlags
			    (Qt::ItemIsEditable |
			     Qt::ItemIsEnabled |
			     Qt::ItemIsSelectable);

			item->setToolTip(tooltip);
			m_ui.listeners->setItem(row, i, item);

			if(i == 1)
			  {
			    auto const state(query.value(i).toString());

			    if(state.contains("asleep", Qt::CaseInsensitive) ||
			       state.contains("online", Qt::CaseInsensitive))
			      item->setBackground(QBrush(QColor("lightgreen")));
			    else
			      item->setBackground(QBrush());
			  }
		      }
		  }

		QByteArray bytes1;
		QByteArray bytes2;
		QByteArray bytes3;
		QString bytes4("");

		ok = true;
		bytes1 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnIP).toByteArray()),
		   &ok);
		bytes2 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnPORT).
					  toByteArray()),
		   &ok);
		bytes3 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnSCOPE_ID).
					  toByteArray()),
		   &ok);
		bytes4 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnTRANSPORT).
					  toByteArray()),
		   &ok);

		if(bytes1 == ip &&
		   bytes2 == port &&
		   bytes3 == scopeId &&
		   bytes4 == transportS)
		  m_ui.listeners->selectRow(row);

		row += 1;
	      }
	  }

	m_ui.listeners->setRowCount(totalRows);
	m_ui.listeners->setSortingEnabled(true);

	for(int i = 0; i < m_ui.listeners->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.listeners->resizeColumnToContents(i);

	m_ui.listeners->horizontalHeader()->setStretchLastSection(true);
	m_ui.listeners->horizontalScrollBar()->setValue(hval);
	m_ui.listeners->resizeRowsToContents();
	m_ui.listeners->verticalScrollBar()->setValue(vval);
	m_ui.listeners->setUpdatesEnabled(true);
	connect(m_ui.listeners,
		SIGNAL(itemChanged(QTableWidgetItem *)),
		this,
		SLOT(slotListenerChanged(QTableWidgetItem *)));

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  populateAETokens();
}

void spoton::slotPopulateNeighbors(QSqlDatabase *db,
				   QSqlQuery *query,
				   const QString &connectionName,
				   const int &size)
{
#if SPOTON_GOLDBUG == 0
  if(m_ui.neighborsTemporarilyPause->isChecked())
    {
      delete query;

      if(db)
	db->close();

      delete db;
      QSqlDatabase::removeDatabase(connectionName);
      return;
    }
#endif

  if(currentTabName() != "neighbors")
    {
      delete query;

      if(db)
	db->close();

      delete db;
      QSqlDatabase::removeDatabase(connectionName);
      return;
    }

  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt || !db || !query)
    {
      delete query;

      if(db)
	db->close();

      delete db;
      QSqlDatabase::removeDatabase(connectionName);
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  disconnect(m_ui.neighbors,
	     SIGNAL(itemChanged(QTableWidgetItem *)),
	     this,
	     SLOT(slotNeighborChanged(QTableWidgetItem *)));
  query->seek(-1);

  QModelIndexList list;
  QString proxyIp("");
  QString proxyPort("1");
  QString remoteIp("");
  QString remotePort("");
  QString scopeId("");
  QString transport("");
  auto const hval = m_ui.neighbors->horizontalScrollBar()->value();
  auto const vval = m_ui.neighbors->verticalScrollBar()->value();
  auto focusWidget = QApplication::focusWidget();
  int const columnCOUNTRY = 9;
  int const columnPROXY_IP = 14;
  int const columnPROXY_PORT = 15;
  int const columnREMOTE_IP = 10;
  int const columnREMOTE_PORT = 11;
  int const columnSCOPE_ID = 12;
  int const columnTRANSPORT = 27;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (columnPROXY_IP);

  if(!list.isEmpty())
    proxyIp = list.at(0).data().toString();

  list = m_ui.neighbors->selectionModel()->selectedRows
    (columnPROXY_PORT);

  if(!list.isEmpty())
    proxyPort = list.at(0).data().toString();

  list = m_ui.neighbors->selectionModel()->selectedRows
    (columnREMOTE_IP);

  if(!list.isEmpty())
    remoteIp = list.at(0).data().toString();

  list = m_ui.neighbors->selectionModel()->selectedRows
    (columnREMOTE_PORT);

  if(!list.isEmpty())
    remotePort = list.at(0).data().toString();

  list = m_ui.neighbors->selectionModel()->selectedRows
    (columnSCOPE_ID);

  if(!list.isEmpty())
    scopeId = list.at(0).data().toString();

  list = m_ui.neighbors->selectionModel()->selectedRows
    (columnTRANSPORT);

  if(!list.isEmpty())
    transport = list.at(0).data().toString();

  m_neighborToOidMap.clear();
  m_ui.neighbors->setUpdatesEnabled(false);
  m_ui.neighbors->setSortingEnabled(false);
  m_ui.neighbors->setRowCount
    (m_ui.neighbors_maximum_items_displayed->currentIndex() ==
     m_ui.neighbors_maximum_items_displayed->count() - 1 ?
     size :
     qMin(m_ui.neighbors_maximum_items_displayed->currentText().toInt(), size));

  QLocale locale;
  int row = 0;
  int totalRows = 0;

  while(query->next() && totalRows < m_ui.neighbors->rowCount())
    {
      totalRows += 1;

      QByteArray certificate;
      QByteArray certificateDigest;
      QByteArray sslSessionCipher;
      QString priority("");
      QString priorityTr("");
      QString tooltip("");
      auto const isEncrypted = query->value
	(query->record().indexOf("is_encrypted")).toBool();
      auto ok = true;
      auto priorityInt = QThread::HighPriority;

      certificate = certificateDigest = crypt->
	decryptedAfterAuthenticated(QByteArray::
				    fromBase64(query->
					       value(21).
					       toByteArray()),
				    &ok);

      if(!ok)
	{
	  certificate.clear();
	  certificateDigest.clear();
	  certificateDigest.append(tr("error").toUtf8());
	}

      if(ok)
	{
	  if(!certificate.isEmpty())
	    certificate = certificate.toBase64();

	  if(!certificateDigest.isEmpty())
	    {
	      certificateDigest = spoton_crypt::
		sha512Hash(certificateDigest, &ok).toHex();

	      if(!ok)
		certificateDigest.clear();
	    }
	}

      if(!query->isNull(24))
	{
	  sslSessionCipher = crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->
						   value(24).
						   toByteArray()),
					&ok);

	  if(!ok)
	    {
	      sslSessionCipher.clear();
	      sslSessionCipher.append(tr("error").toUtf8());
	    }
	}

      priority = query->value(35).toString().trimmed();
      priorityInt = QThread::Priority(priority.toInt());

      switch(priorityInt)
	{
	case QThread::IdlePriority:
	  {
	    priority = "Idle Priority";
	    priorityTr = tr("Idle Priority");
	    break;
	  }
	case QThread::LowestPriority:
	  {
	    priority = "Lowest Priority";
	    priorityTr = tr("Lowest Priority");
	    break;
	  }
	case QThread::LowPriority:
	  {
	    priority = "Low Priority";
	    priorityTr = tr("Low Priority");
	    break;
	  }
	case QThread::NormalPriority:
	  {
	    priority = "Normal Priority";
	    priorityTr = tr("Normal Priority");
	    break;
	  }
	case QThread::HighPriority:
	  {
	    priority = "High Priority";
	    priorityTr = tr("High Priority");
	    break;
	  }
	case QThread::HighestPriority:
	  {
	    priority = "Highest Priority";
	    priorityTr = tr("Highest Priority");
	    break;
	  }
	case QThread::TimeCriticalPriority:
	  {
	    priority = "Time-Critical Priority";
	    priorityTr = tr("Time-Critical Priority");
	    break;
	  }
	default:
	  {
	    priority = "High Priority";
	    priorityTr = tr("High Priority");
	    break;
	  }
	}

      tooltip =
	(tr("<html>UUID: %1<br>"
	    "Status: %2<br>"
	    "SSL Key Size: %3<br>"
	    "Local IP: %4 Local Port: %5<br>"
	    "External IP: %6<br>"
	    "Country: %7 Remote IP: %8 Remote Port: %9 "
	    "Scope ID: %10<br>"
	    "Proxy Hostname: %11 Proxy Port: %12<br>"
	    "Echo Mode: %13<br>"
	    "Communications Mode: %14<br>"
	    "Uptime: %15 Minute(s)<br>"
	    "Allow Certificate Exceptions: %16<br>"
	    "Bytes Read: %17<br>"
	    "Bytes Written: %18<br>"
	    "SSL Session Cipher: %19<br>"
	    "Account Name: %20<br>"
	    "Account Authenticated: %21<br>"
	    "Transport: %22<br>"
	    "Orientation: %23<br>"
	    "SSL Control String: %24<br>"
	    "Priority: %25<br>"
	    "Lane Width: %26<br>"
	    "Passthrough: %27<br>"
	    "Wait-For-Bytes-Written: %28<br>"
	    "Silence Time: %29<br>"
	    "Socket Options: %30<br>"
	    "Buffered Content: %31<br>"
	    "Bind IP: %32</html>")).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(1).
						   toByteArray()),
					&ok).constData()).
	arg(query->value(2).toString().toLower()).
	arg(query->value(3).toString()).
	arg(query->value(5).toString()).
	arg(query->value(6).toString()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(7).
						   toByteArray()),
					&ok).constData()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(9).
						   toByteArray()),
					&ok).constData()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(10).
						   toByteArray()),
					&ok).constData()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(11).
						   toByteArray()),
					&ok).constData()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(12).
						   toByteArray()),
					&ok).constData()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(14).
						   toByteArray()),
					&ok).constData()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(15).
						   toByteArray()),
					&ok).constData()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(18).
						   toByteArray()),
					&ok).constData()).
	arg(isEncrypted ? "Secure" : "Insecure").
	arg(QString::
	    number(static_cast<double> (query->value(19).
					toLongLong()) /
		   60.00, 'f', 1)).
	arg(query->value(21).toLongLong() ? tr("Yes") : tr("No")).
	/*
	** Bytes read.
	*/
	arg(locale.toString(query->value(22).toULongLong())).
	/*
	** Bytes written.
	*/
	arg(locale.toString(query->value(23).toULongLong())).
	arg(sslSessionCipher.constData()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(25).
						   toByteArray()),
					&ok).constData()).
	arg(crypt->
	    decryptedAfterAuthenticated
	    (QByteArray::
	     fromBase64(query->
			value(26).
			toByteArray()),
	     &ok).toLongLong() ? tr("Yes"): tr("No")).
	arg(QString(crypt->
		    decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query->
				value(27).
				toByteArray()),
		     &ok).
		    constData()).toUpper()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(28).
						   toByteArray()),
					&ok).constData()).
	arg(query->value(34).toString()).
	arg(priority).
	arg(locale.toString(query->value(36).toInt())).
	arg(query->value(37).toInt() ? tr("Yes") : tr("No")).
	arg(locale.toString(query->value(38).toInt())).
	arg(query->value(40).toInt()).
	arg(query->value(41).toString()).
	arg(query->value(42).toInt()).
	arg(crypt->
	    decryptedAfterAuthenticated(QByteArray::
					fromBase64(query->value(43).
						   toByteArray()),
					&ok).constData());

      {
	auto item = new spoton_table_widget_item();

	if(query->value(0).toBool())
	  item->setCheckState(Qt::Checked);
	else
	  item->setCheckState(Qt::Unchecked);

	item->setFlags(Qt::ItemIsEnabled |
		       Qt::ItemIsSelectable |
		       Qt::ItemIsUserCheckable);
	item->setToolTip(tr("<html>The sticky feature enables an "
			    "indefinite lifetime for a neighbor. If "
			    "not checked, the neighbor will be "
			    "terminated after some internal "
			    "timer expires. Please note that the "
			    "neighbor may be terminated if data "
			    "has not been received for some time.</html>"));
	m_ui.neighbors->setItem(row, 0, item);
      }

      for(int i = 1; i < query->record().count(); i++)
	{
	  spoton_table_widget_item *item = nullptr;

	  if(i == 1 || i == 3 ||
	     i == 7 || (i >= 9 && i <= 13) || (i >= 14 &&
					       i <= 15) ||
	     i == 18 || i == 25 || i == 27 || i == 28 ||
	     i == 32 || i == 33 || i == 39 || i == 43)
	    {
	      if(query->isNull(i))
		item = new spoton_table_widget_item();
	      else
		{
		  QByteArray bytes;

		  if(i != 3) // ssl_key_size
		    {
		      bytes = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query->value(i).toByteArray()),
			 &ok);

		      if(!ok)
			{
			  bytes.clear();
			  bytes.append(tr("error").toUtf8());
			}
		    }

		  switch(i)
		    {
		    case 1: // uuid
		      {
			if(bytes.isEmpty())
			  bytes = "{00000000-0000-0000-0000-000000000000}";

			break;
		      }
		    case 3: // ssl_key_size
		      {
			if(query->value(i).toLongLong() == 0)
			  {
			    item = new spoton_table_widget_item("0");
			    item->setBackground(QBrush(QColor(240, 128, 128)));
			  }
			else
			  {
			    item = new spoton_table_widget_item
			      (query->value(i).toString());
			    item->setBackground(QBrush());
			  }

			break;
		      }
		    case 11: // remote_port
		    case 15: // proxy_port
		      {
			item = new spoton_table_widget_item(QString(bytes));
			break;
		      }
		    default:
		      {
			break;
		      }
		    }

		  if(i != 3) // ssl_key_size
		    if(!item)
		      item = new spoton_table_widget_item(QString(bytes));
		}
	    }
	  else if(i == 6) // local_port
	    item = new spoton_table_widget_item(query->value(i).toString());
	  else if(i >= 16 && i <= 17)
	    {
	      // maximum_buffer_size
	      // maximum_content_length

	      auto box = new QSpinBox();

	      if(i == 16)
		{
		  box->setMaximum
		    (spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
		  box->setMinimum
		    (spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
		}
	      else
		box->setMaximum
		  (spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);

	      box->setCorrectionMode
		(QAbstractSpinBox::CorrectToNearestValue);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
	      box->setMaximumWidth
		(box->fontMetrics().
		 horizontalAdvance(QString::
				   number(spoton_common::
					  MAXIMUM_NEIGHBOR_BUFFER_SIZE)) + 50);
#else
	      box->setMaximumWidth
		(box->fontMetrics().
		 width(QString::
		       number(spoton_common::
			      MAXIMUM_NEIGHBOR_BUFFER_SIZE)) + 50);
#endif
	      box->setProperty
		("field_name", query->record().fieldName(i));
	      box->setProperty
		("oid", query->value(query->record().count() - 1));
	      box->setToolTip
		(QString("[%1, %2]").arg(box->minimum()).arg(box->maximum()));
	      box->setValue
		(static_cast<int> (query->value(i).toLongLong()));
	      box->setWrapping(true);
	      connect(box,
		      SIGNAL(valueChanged(int)),
		      this,
		      SLOT(slotNeighborMaximumChanged(int)));
	      m_ui.neighbors->setCellWidget(row, i, box);

	      auto item = new spoton_table_widget_item
		(QString::number(box->value()));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      item->setToolTip(tooltip);
	      m_ui.neighbors->setItem(row, i, item);
	    }
	  else if(i == 19) // uptime
	    item = new spoton_table_widget_item
	      (locale.toString(query->value(i).toLongLong()));
	  else if(i == 20) // allow_exceptions
	    item = new spoton_table_widget_item(query->value(i).toString());
	  else if(i == 21) // Certificate Digest
	    item = new spoton_table_widget_item(QString(certificateDigest));
	  else if(i == 22 || i == 23) // bytes_read, bytes_written
	    item = new spoton_table_widget_item
	      (locale.toString(query->value(i).toLongLong()));
	  else if(i == 24) // ssl_session_cipher
	    item = new spoton_table_widget_item(QString(sslSessionCipher));
	  else if(i == 26) // account_authenticated
	    {
	      if(!query->isNull(i))
		{
		  item = new spoton_table_widget_item
		    (QString(crypt->decryptedAfterAuthenticated
			     (QByteArray::
			      fromBase64(query->
					 value(i).
					 toByteArray()),
			      &ok)));

		  if(ok)
		    {
		      if(item->text() != "0")
			item->setBackground(QBrush(QColor("lightgreen")));
		      else
			item->setBackground(QBrush(QColor(240, 128, 128)));
		    }
		  else
		    {
		      item->setText(tr("error"));
		      item->setBackground(QBrush(QColor(240, 128, 128)));
		    }
		}
	      else
		{
		  item = new spoton_table_widget_item("0");
		  item->setBackground(QBrush(QColor(240, 128, 128)));
		}
	    }
	  else if(i == 29) // motd
	    item = new spoton_table_widget_item
	      (query->value(i).toString().trimmed());
	  else if(i == 30) // is_encrypted
	    item = new spoton_table_widget_item(query->value(i).toString());
	  else if(i == 31) // certificate
	    item = new spoton_table_widget_item(QString(certificate));
	  else if(i == 35) // priority
	    {
	      item = new spoton_table_widget_item(priorityTr);
	      item->setData(Qt::UserRole, priorityInt);
	    }
	  else if(i == 36) // lane_width
	    {
	      QComboBox *box = nullptr;
	      auto list(spoton_common::LANE_WIDTHS);
	      auto widget = combinationBoxForTable();

	      box = widget->findChild<QComboBox *> ();

	      if(!list.contains(spoton_common::LANE_WIDTH_DEFAULT))
		list << spoton_common::LANE_WIDTH_DEFAULT;

	      if(!list.contains(spoton_common::LANE_WIDTH_MAXIMUM))
		list << spoton_common::LANE_WIDTH_MAXIMUM;

	      if(!list.contains(spoton_common::LANE_WIDTH_MINIMUM))
		list << spoton_common::LANE_WIDTH_MINIMUM;

	      std::sort(list.begin(), list.end());

	      for(int j = 0; j < list.size(); j++)
		box->addItem(QString::number(list.at(j)));

	      box->setProperty
		("oid", query->value(query->record().count() - 1));
	      box->setProperty("table", "neighbors");
	      box->setToolTip(tooltip);
	      m_ui.neighbors->setCellWidget(row, i, widget);

	      if(box->findText(QString::
			       number(query->
				      value(i).
				      toInt())) >= 0)
		box->setCurrentIndex
		  (box->findText(QString::number(query->
						 value(i).
						 toInt())));
	      else
		box->setCurrentIndex(box->count() - 1); // Maximum.

	      connect(box,
		      SIGNAL(currentIndexChanged(int)),
		      this,
		      SLOT(slotLaneWidthChanged(int)));

	      auto item = new spoton_table_widget_item(box->currentText());

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      item->setToolTip(tooltip);
	      m_ui.neighbors->setItem(row, i, item);
	    }
	  else if(i == 37) // passthrough
	    {
	      auto item = new spoton_table_widget_item();

	      if(query->value(i).toBool())
		item->setCheckState(Qt::Checked);
	      else
		item->setCheckState(Qt::Unchecked);

	      item->setFlags(Qt::ItemIsEnabled |
			     Qt::ItemIsSelectable |
			     Qt::ItemIsUserCheckable);
	      item->setToolTip(tooltip);
	      m_ui.neighbors->setItem(row, i, item);
	    }
	  else if(i == 38) // waitforbyteswritten_msecs
	    {
	      auto box = new QSpinBox();

	      box->setCorrectionMode
		(QAbstractSpinBox::CorrectToNearestValue);
	      box->setMaximum
		(spoton_common::
		 WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
	      box->setMaximumWidth
		(box->fontMetrics().
		 horizontalAdvance
		 (QString::
		  number(spoton_common::
			 WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM)) + 50);
#else
	      box->setMaximumWidth
		(box->fontMetrics().
		 width(QString::
		       number(spoton_common::
			      WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM)) +
		 50);
#endif
	      box->setMinimum(0);
	      box->setProperty
		("oid", query->value(query->record().count() - 1));
	      box->setToolTip
		(tr("A positive value ([%1, %2]) may pause the kernel.").
		 arg(box->minimum()).arg(box->maximum()));
	      box->setValue
		(static_cast<int> (query->value(i).toInt()));
	      box->setWrapping(true);
	      connect
		(box,
		 SIGNAL(valueChanged(int)),
		 this,
		 SLOT(slotNeighborWaitForBytesWrittenChanged(int)));
	      m_ui.neighbors->setCellWidget(row, i, box);

	      auto item = new spoton_table_widget_item
		(QString::number(box->value()));

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      item->setToolTip(tooltip);
	      m_ui.neighbors->setItem(row, i, item);
	    }
	  else if(i == 40) // silence_time
	    {
	      auto box = new QSpinBox();

	      box->setCorrectionMode
		(QAbstractSpinBox::CorrectToNearestValue);
	      box->setMaximum(999999999);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
	      box->setMaximumWidth
		(box->fontMetrics().
		 horizontalAdvance(QString::number(box->maximum())) + 50);
#else
	      box->setMaximumWidth
		(box->fontMetrics().
		 width(QString::number(box->maximum())) + 50);
#endif
	      box->setMinimum(0);
	      box->setProperty
		("oid", query->value(query->record().count() - 1));
	      box->setToolTip
		(QString("[%1, %2]").arg(box->minimum()).arg(box->maximum()));
	      box->setValue
		(static_cast<int> (query->value(i).toInt()));
	      box->setWrapping(true);
	      connect
		(box,
		 SIGNAL(valueChanged(int)),
		 this,
		 SLOT(slotNeighborSilenceTimeChanged(int)));
	      m_ui.neighbors->setCellWidget(row, i, box);

	      auto item = new spoton_table_widget_item
		(QString::number(box->value()));

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      item->setToolTip
		(tr("<html>A value of 0 will prevent the neighbor "
		    "from terminating itself if data has not "
		    "been received for some time.</html>"));
	      m_ui.neighbors->setItem(row, i, item);
	    }
	  else if(i == 42) // buffered_content
	    item = new spoton_table_widget_item(query->value(i).toString());
	  else
	    item = new spoton_table_widget_item(query->value(i).toString());

	  if(item)
	    {
	      item->setFlags(Qt::ItemIsEditable |
			     Qt::ItemIsEnabled |
			     Qt::ItemIsSelectable);

	      if(i == 2)
		{
		  auto const status(query->value(i).toString().toLower());

		  if(status == "bound" || status == "connected")
		    item->setBackground(QBrush(QColor("lightgreen")));
		  else
		    item->setBackground(QBrush());

		  if(isEncrypted && status == "connected")
		    item->setIcon
		      (QIcon(QString(":/%1/lock.png").
			     arg(m_settings.
				 value("gui/iconSet", "nouve").toString().
				 toLower())));
		  else
		    item->setIcon(QIcon());
		}

	      if(item->toolTip().isEmpty())
		item->setToolTip(tooltip);

	      m_ui.neighbors->setItem(row, i, item);
	    }
	}

      auto item1 = m_ui.neighbors->item(row, columnCOUNTRY);

      if(item1)
	{
	  QIcon icon;
	  QPixmap pixmap;
	  QString str("");
	  auto item2 = m_ui.neighbors->item(row, columnREMOTE_IP);

	  if(item2)
	    str = QString(":/Flags/%1.png").
	      arg(spoton_misc::
		  countryCodeFromIPAddress(item2->text()).
		  toLower());
	  else
	    str = ":/Flags/unknown.png";

	  pixmap = QPixmap(str);

	  if(!pixmap.isNull())
	    pixmap = pixmap.scaled(QSize(16, 16),
				   Qt::KeepAspectRatio,
				   Qt::SmoothTransformation);

	  if(!pixmap.isNull())
	    icon = QIcon(pixmap);

	  if(!icon.isNull())
	    item1->setIcon(icon);
	}

      QByteArray bytes1;
      QByteArray bytes2;
      QByteArray bytes3;
      QByteArray bytes4;
      QByteArray bytes5;
      QString bytes6;

      ok = true;
      bytes1 = crypt->decryptedAfterAuthenticated
	(QByteArray::fromBase64(query->value(columnREMOTE_IP).
				toByteArray()), &ok);
      bytes2 = crypt->decryptedAfterAuthenticated
	(QByteArray::fromBase64(query->value(columnREMOTE_PORT).
				toByteArray()), &ok);
      bytes3 = crypt->decryptedAfterAuthenticated
	(QByteArray::fromBase64(query->value(columnSCOPE_ID).
				toByteArray()), &ok);
      bytes4 = crypt->decryptedAfterAuthenticated
	(QByteArray::fromBase64(query->value(columnPROXY_IP).
				toByteArray()), &ok);
      bytes5 = crypt->decryptedAfterAuthenticated
	(QByteArray::fromBase64(query->value(columnPROXY_PORT).
				toByteArray()), &ok);
      bytes6 = crypt->decryptedAfterAuthenticated
	(QByteArray::fromBase64(query->value(columnTRANSPORT).
				toByteArray()), &ok);

      if(bytes1 == remoteIp &&
	 bytes2 == remotePort &&
	 bytes3 == scopeId &&
	 bytes4 == proxyIp &&
	 bytes5 == proxyPort &&
	 bytes6 == transport)
	m_ui.neighbors->selectRow(row);

      if(bytes3.isEmpty())
	m_neighborToOidMap.insert
	  (bytes1 + ":" + bytes2,
	   query->value(query->record().count() - 1).toString());
      else
	m_neighborToOidMap.insert
	  (bytes1 + ":" + bytes2 + ":" + bytes3,
	   query->value(query->record().count() - 1).toString());

      row += 1;
    }

  m_ui.neighbors->setRowCount(totalRows);
  m_ui.neighbors->setSortingEnabled(true);

  for(int i = 0; i < m_ui.neighbors->columnCount() - 1; i++)
    /*
    ** Ignore the OID column.
    */

    m_ui.neighbors->resizeColumnToContents(i);

  m_ui.neighbors->horizontalHeader()->setStretchLastSection(true);
  m_ui.neighbors->horizontalScrollBar()->setValue(hval);
  m_ui.neighbors->resizeRowsToContents();
  m_ui.neighbors->verticalScrollBar()->setValue(vval);
  m_ui.neighbors->setUpdatesEnabled(true);
  connect(m_ui.neighbors,
	  SIGNAL(itemChanged(QTableWidgetItem *)),
	  this,
	  SLOT(slotNeighborChanged(QTableWidgetItem *)));

  if(focusWidget)
    focusWidget->setFocus();

  delete query;

  if(db)
    db->close();

  delete db;
  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotPopulateParticipants(QSqlDatabase *db,
				      QSqlQuery *query,
				      const QString &connectionName)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt || !db || !query)
    {
      delete query;

      if(db)
	db->close();

      delete db;
      QSqlDatabase::removeDatabase(connectionName);
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  query->seek(-1);

  QList<int> rows;  // Chat
  QList<int> rowsE; // E-Mail
  QList<int> rowsU; // URLs
  QString hpData; // Human Proxy
  QStringList hashes;
  QStringList hashesE;
  QStringList hashesU;
  auto const hval = m_ui.participants->horizontalScrollBar()->value();
  auto const hvalE = m_ui.emailParticipants->horizontalScrollBar()->value();
  auto const hvalU = m_ui.urlParticipants->horizontalScrollBar()->value();
  auto const list
    (m_ui.participants->selectionModel()->
     selectedRows(3)); // public_key_hash
  auto const listE
    (m_ui.emailParticipants->selectionModel()->
     selectedRows(3)); // public_key_hash
  auto const listU
    (m_ui.urlParticipants->selectionModel()->
     selectedRows(3)); // public_key_hash
  auto const vval = m_ui.participants->verticalScrollBar()->value();
  auto const vvalE = m_ui.emailParticipants->verticalScrollBar()->value();
  auto const vvalU = m_ui.urlParticipants->verticalScrollBar()->value();
  int row = 0;
  int rowE = 0;
  int rowU = 0;

  for(int i = 0; i < list.size(); i++)
    {
      auto const data(list.at(i).data());

      if(!data.isNull() && data.isValid())
	hashes.append(data.toString());
    }

  for(int i = 0; i < listE.size(); i++)
    {
      auto const data(listE.at(i).data());

      if(!data.isNull() && data.isValid())
	hashesE.append(data.toString());
    }

  for(int i = 0; i < listU.size(); i++)
    {
      auto const data(listU.at(i).data());

      if(!data.isNull() && data.isValid())
	hashesU.append(data.toString());
    }

  for(int i = 0; i < m_ui.participants->rowCount(); i++)
    if(m_ui.participants->item(i, 0) &&
       m_ui.participants->item(i, 0)->checkState() == Qt::Checked &&
       m_ui.participants->item(i, 3))
      {
	hpData = m_ui.participants->item(i, 3)->text();
	break;
      }

  m_ui.emailParticipants->setSortingEnabled(false);
  m_ui.emailParticipants->setRowCount(0);
  m_ui.participants->setSortingEnabled(false);
  m_ui.participants->setRowCount(0);
  m_ui.urlParticipants->setSortingEnabled(false);
  m_ui.urlParticipants->setRowCount(0);
  disconnect(m_ui.participants,
	     SIGNAL(itemChanged(QTableWidgetItem *)),
	     this,
	     SLOT(slotParticipantsItemChanged(QTableWidgetItem *)));

  auto focusWidget = QApplication::focusWidget();

  while(query->next())
    {
      QIcon icon;
      QString keyType("");
      QString name("");
      QString statusText("");
      auto const oid(query->value(1).toString());
      auto const temporary = query->value(2).toLongLong() == -1 ? false : true;
      auto ok = true;
      auto publicKeyContainsPoptastic = false;
      auto status(query->value(4).toString().toLower());

      keyType = crypt->decryptedAfterAuthenticated
	(QByteArray::fromBase64(query->value(8).toByteArray()), &ok);

      if(ok)
	{
	  auto const bytes
	    (crypt->
	     decryptedAfterAuthenticated(QByteArray::
					 fromBase64(query->
						    value(0).
						    toByteArray()),
					 &ok));

	  if(ok)
	    name = QString::fromUtf8(bytes.constData(), bytes.length());
	}

      if(!ok)
	name = "";

      if(query->value(9).toByteArray().length() < 1024 * 1024)
	/*
	** Avoid McEliece keys!
	*/

	publicKeyContainsPoptastic = crypt->decryptedAfterAuthenticated
	  (QByteArray::fromBase64(query->value(9).toByteArray()), &ok).
	  contains("-poptastic");

      if(!isKernelActive())
	status = "offline";

      for(int i = 0; i < query->record().count(); i++)
	{
	  if(i == query->record().count() - 1)
	    /*
	    ** Ignore public_key.
	    */

	    continue;

	  QTableWidgetItem *item = nullptr;

	  if(keyType == "chat" || keyType == "poptastic")
	    {
	      if(i == 0)
		{
		  /*
		  ** Do not increase the table's row count
		  ** if the participant is offline and the
		  ** user wishes to hide offline participants or
		  ** if this is a Poptastic key-less participant.
		  */

		  if(!((m_ui.hideOfflineParticipants->isChecked() &&
			status == "offline") ||
		       publicKeyContainsPoptastic))
		    {
		      row += 1;
		      m_ui.participants->setRowCount(row);
		    }
		}

	      if(i == 0) // Name
		{
		  if(name.isEmpty())
		    {
		      if(keyType == "chat")
			name = "unknown";
		      else
			name = "unknown@unknown.org";
		    }

		  item = new QTableWidgetItem(name);

		  if(keyType == "poptastic")
		    item->setBackground(QBrush(QColor(137, 207, 240)));
		}
	      else if(i == 4) // Status
		{
		  auto status(query->value(i).toString().trimmed());

		  if(status.isEmpty())
		    status = "offline";

		  if(status.toLower() == "away")
		    item = new QTableWidgetItem(tr("Away"));
		  else if(status.toLower() == "busy")
		    item = new QTableWidgetItem(tr("Busy"));
		  else if(status.toLower() == "offline")
		    item = new QTableWidgetItem(tr("Offline"));
		  else if(status.toLower() == "online")
		    item = new QTableWidgetItem(tr("Online"));
		  else
		    item = new QTableWidgetItem(status);

		  item->setToolTip(item->text());
		  statusText = item->text();
		}
	      else if(i == 6 || // Gemini Encryption Key
		      i == 7)   // Gemini Hash Key
		{
		  if(query->isNull(i))
		    item = new QTableWidgetItem();
		  else
		    {
		      item = new QTableWidgetItem
			(QString(crypt->decryptedAfterAuthenticated
				 (QByteArray::fromBase64(query->
							 value(i).
							 toByteArray()),
				  &ok).toBase64()));

		      if(!ok)
			item->setText(tr("error"));
		    }
		}
	      else
		item = new QTableWidgetItem(query->value(i).toString());

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);

	      if(i == 0) // Name
		{
		  if(!temporary)
		    {
		      if(keyType == "chat")
			{
			  if(hpData == query->value(3).toString())
			    item->setCheckState(Qt::Checked);
			  else
			    item->setCheckState(Qt::Unchecked);

			  item->setFlags
			    (Qt::ItemIsEnabled |
			     Qt::ItemIsSelectable |
			     Qt::ItemIsUserCheckable);
			}

		      if(status == "away")
			item->setIcon
			  (QIcon(QString(":/%1/away.png").
				 arg(m_settings.value("gui/iconSet",
						      "nouve").
				     toString().toLower())));
		      else if(status == "busy")
			item->setIcon
			  (QIcon(QString(":/%1/busy.png").
				 arg(m_settings.value("gui/iconSet",
						      "nouve").
				     toString().toLower())));
		      else if(status == "offline")
			item->setIcon
			  (QIcon(QString(":/%1/offline.png").
				 arg(m_settings.value("gui/iconSet",
						      "nouve").
				     toString().toLower())));
		      else if(status == "online")
			item->setIcon
			  (QIcon(QString(":/%1/online.png").
				 arg(m_settings.value("gui/iconSet",
						      "nouve").
				     toString().toLower())));
		      else
			item->setIcon
			  (QIcon(QString(":/%1/chat.png").
				 arg(m_settings.value("gui/iconSet",
						      "nouve").
				     toString().toLower())));

		      item->setToolTip
			(query->value(3).toString().mid(0, 16) +
			 "..." +
			 query->value(3).toString().right(16));
		    }
		  else
		    {
		      item->setIcon
			(QIcon(QString(":/%1/add.png").
			       arg(m_settings.value("gui/iconSet",
						    "nouve").
				   toString())));
		      item->setToolTip
			(tr("User %1 requests your friendship.").
			 arg(item->text()));
		    }

		  icon = item->icon();
		}
	      else if(i == 6 ||
		      i == 7) /*
			      ** Gemini Encryption Key
			      ** Gemini Hash Key
			      */
		{
		  if(!temporary)
		    item->setFlags
		      (item->flags() | Qt::ItemIsEditable);
		}
	      else if(i == 8)
		{
		  if(!temporary)
		    {
		      /*
		      ** Forward Secrecy Information
		      */

		      QList<QByteArray> list;
		      auto ok = true;

		      list = retrieveForwardSecrecyInformation(oid, &ok);

		      if(ok)
			item->setText
			  (spoton_misc::forwardSecrecyMagnetFromList(list));
		      else
			item->setText(tr("error"));
		    }
		}

	      item->setData(Qt::ItemDataRole(Qt::UserRole + 1), keyType);
	      item->setData(Qt::UserRole, temporary);

	      /*
	      ** Delete the item if the participant is offline
	      ** and the user wishes to hide offline participants.
	      ** Please note that the e-mail participants are cloned
	      ** and do not adhere to this restriction.
	      */

	      if((m_ui.hideOfflineParticipants->isChecked() &&
		  status == "offline") ||
		 publicKeyContainsPoptastic)
		{
		  /*
		  ** This may be a plain Poptastic participant.
		  ** It will only be displayed in the E-Mail page.
		  */

		  delete item;
		  item = nullptr;
		}
	      else
		m_ui.participants->setItem(row - 1, i, item);
	    }

	  if(keyType == "email" || keyType == "poptastic")
	    {
	      if(i == 0)
		{
		  rowE += 1;
		  m_ui.emailParticipants->setRowCount(rowE);
		}

	      if(i == 0)
		{
		  if(name.isEmpty())
		    {
		      if(keyType == "email")
			name = "unknown";
		      else
			name = "unknown@unknown.org";
		    }

		  item = new QTableWidgetItem(name);

		  if(keyType == "email")
		    item->setIcon
		      (QIcon(QString(":/%1/key.png").
			     arg(m_settings.
				 value("gui/iconSet",
				       "nouve").toString())));
		  else if(keyType == "poptastic")
		    {
		      if(publicKeyContainsPoptastic)
			{
			  item->setBackground
			    (QBrush(QColor(255, 255, 224)));
			  item->setData
			    (Qt::ItemDataRole(Qt::UserRole + 2),
			     "traditional e-mail");
			}
		      else
			{
			  item->setBackground
			    (QBrush(QColor(137, 207, 240)));
			  item->setIcon
			    (QIcon(QString(":/%1/key.png").
				   arg(m_settings.
				       value("gui/iconSet",
					     "nouve").toString())));
			}
		    }
		}
	      else if(i == 1 || i == 2 || i == 3)
		item = new QTableWidgetItem(query->value(i).toString());
	      else if(i == 4)
		{
		  if(keyType == "poptastic" && publicKeyContainsPoptastic)
		    item = new QTableWidgetItem("");
		  else
		    {
		      QList<QByteArray> list;
		      auto ok = true;

		      list = retrieveForwardSecrecyInformation(oid, &ok);

		      if(ok)
			item = new QTableWidgetItem
			  (QString(spoton_misc::
				   forwardSecrecyMagnetFromList(list)));
		      else
			item = new QTableWidgetItem(tr("error"));
		    }
		}

	      if(i >= 0 && i <= 4)
		{
		  if(i == 0)
		    {
		      if(temporary)
			{
			  item->setIcon
			    (QIcon(QString(":/%1/add.png").
				   arg(m_settings.value("gui/iconSet",
							"nouve").
				       toString().toLower())));
			  item->setToolTip
			    (tr("User %1 requests your friendship.").
			     arg(item->text()));
			}
		      else
			item->setToolTip
			  (query->value(3).toString().mid(0, 16) +
			   "..." +
			   query->value(3).toString().right(16));
		    }

		  item->setData(Qt::UserRole, temporary);
		  item->setData
		    (Qt::ItemDataRole(Qt::UserRole + 1), keyType);
		  item->setFlags
		    (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		  m_ui.emailParticipants->setItem
		    (rowE - 1, i, item);
		}
	    }
	  else if(keyType == "url")
	    {
	      if(i == 0)
		{
		  rowU += 1;
		  m_ui.urlParticipants->setRowCount(rowU);
		}

	      if(i == 0)
		{
		  if(name.isEmpty())
		    name = "unknown";

		  item = new QTableWidgetItem(name);
		}
	      else if(i == 1 || i == 2 || i == 3)
		item = new QTableWidgetItem
		  (query->value(i).toString());

	      if(item)
		{
		  if(i == 0)
		    {
		      if(temporary)
			{
			  item->setIcon
			    (QIcon(QString(":/%1/add.png").
				   arg(m_settings.value("gui/iconSet",
							"nouve").
				       toString().toLower())));
			  item->setToolTip
			    (tr("User %1 requests your friendship.").
			     arg(item->text()));
			}
		      else
			item->setToolTip
			  (query->value(3).toString().mid(0, 16) +
			   "..." +
			   query->value(3).toString().right(16));
		    }

		  item->setData(Qt::UserRole, temporary);
		  item->setFlags
		    (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		  m_ui.urlParticipants->setItem
		    (rowU - 1, i, item);
		}
	    }

	  if(item)
	    if(!item->tableWidget())
	      {
		spoton_misc::logError
		  ("spoton::slotPopulateParticipants(): "
		   "QTableWidgetItem does not have a parent "
		   "table. Deleting.");
		delete item;
		item = nullptr;
	      }
	}

      if(keyType == "chat" || keyType == "poptastic")
	emit statusChanged(icon, name, oid, statusText);

      if(hashes.contains(query->value(3).toString()))
	rows.append(row - 1);

      if(hashesE.contains(query->value(3).toString()) ||
	 m_emailAddressAdded == name)
	{
	  if(m_emailAddressAdded == name)
	    m_emailAddressAdded.clear();

	  rowsE.append(rowE - 1);
	}

      if(hashesU.contains(query->value(3).toString()))
	rowsU.append(rowU - 1);
    }

  connect(m_ui.participants,
	  SIGNAL(itemChanged(QTableWidgetItem *)),
	  this,
	  SLOT(slotParticipantsItemChanged(QTableWidgetItem *)));
  m_ui.emailParticipants->setSelectionMode(QAbstractItemView::MultiSelection);
  m_ui.participants->setSelectionMode(QAbstractItemView::MultiSelection);
  m_ui.urlParticipants->setSelectionMode(QAbstractItemView::MultiSelection);

  for(int i = 0; i < rows.size(); i++)
    m_ui.participants->selectRow(rows.at(i));

  for(int i = 0; i < rowsE.size(); i++)
    m_ui.emailParticipants->selectRow(rowsE.at(i));

  for(int i = 0; i < rowsU.size(); i++)
    m_ui.urlParticipants->selectRow(rowsU.at(i));

  m_ui.emailParticipants->setSelectionMode
    (QAbstractItemView::ExtendedSelection);
  m_ui.emailParticipants->setSortingEnabled(true);
  m_ui.emailParticipants->resizeColumnToContents(0);
  m_ui.emailParticipants->horizontalHeader()->setStretchLastSection(true);
  m_ui.emailParticipants->horizontalScrollBar()->setValue(hvalE);
  m_ui.emailParticipants->verticalScrollBar()->setValue(vvalE);
  m_ui.participants->resizeColumnToContents(0); // Participant.
  m_ui.participants->resizeColumnToContents
    (m_ui.participants->columnCount() - 3); // Gemini Encryption Key.
  m_ui.participants->resizeColumnToContents
    (m_ui.participants->columnCount() - 2); // Gemini Hash Key.
  m_ui.participants->setSelectionMode(QAbstractItemView::ExtendedSelection);
  m_ui.participants->setSortingEnabled(true);
  m_ui.participants->horizontalHeader()->setStretchLastSection(true);
  m_ui.participants->horizontalScrollBar()->setValue(hval);
  m_ui.participants->verticalScrollBar()->setValue(vval);
  m_ui.urlParticipants->setSelectionMode(QAbstractItemView::ExtendedSelection);
  m_ui.urlParticipants->setSortingEnabled(true);
  m_ui.urlParticipants->resizeColumnToContents(0);
  m_ui.urlParticipants->horizontalHeader()->setStretchLastSection(true);
  m_ui.urlParticipants->horizontalScrollBar()->setValue(hvalU);
  m_ui.urlParticipants->verticalScrollBar()->setValue(vvalU);

  if(focusWidget)
    focusWidget->setFocus();

  delete query;

  if(db)
    db->close();

  delete db;
  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotProtocolRadioToggled(bool state)
{
  Q_UNUSED(state);

  auto radio = qobject_cast<QRadioButton *> (sender());

  if(!radio)
    return;

  if(radio == m_ui.dynamicdns)
    {
      m_ui.neighborIP->clear();
      m_ui.neighborIP->setInputMask("");
      m_ui.neighborScopeId->setEnabled(true);
      m_ui.neighborScopeIdLabel->setEnabled(true);
    }
  else if(radio == m_ui.ipv4Listener || radio == m_ui.ipv4Neighbor)
    {
      if(radio == m_ui.ipv4Listener)
	{
	  m_ui.listenerIP->clear();
	  m_ui.listenerIP->setInputMask("");
	  m_ui.listenerScopeId->setEnabled(false);
	  m_ui.listenerScopeIdLabel->setEnabled(false);
	}
      else
	{
	  m_ui.neighborIP->clear();
	  m_ui.neighborIP->setInputMask("");
	  m_ui.neighborScopeId->setEnabled(false);
	  m_ui.neighborScopeIdLabel->setEnabled(false);
	}
    }
  else
    {
      if(radio == m_ui.ipv6Listener)
	{
	  m_ui.listenerIP->clear();
	  m_ui.listenerIP->setInputMask("");
	  m_ui.listenerScopeId->setEnabled(true);
	  m_ui.listenerScopeIdLabel->setEnabled(true);
	}
      else
	{
	  m_ui.neighborIP->clear();
	  m_ui.neighborIP->setInputMask("");
	  m_ui.neighborScopeId->setEnabled(true);
	  m_ui.neighborScopeIdLabel->setEnabled(true);
	}
    }

  prepareListenerIPCombo();
}

void spoton::slotProxyChecked(bool state)
{
  m_ui.proxyHostname->clear();
  m_ui.proxyHostname->setEnabled(state);
  m_ui.proxyPassword->clear();
  m_ui.proxyPort->setEnabled(state);
  m_ui.proxyPort->setValue(m_ui.proxyPort->minimum());
  disconnect(m_ui.proxyType,
	     SIGNAL(currentIndexChanged(int)),
	     this,
	     SLOT(slotProxyTypeChanged(int)));
  m_ui.proxyType->setCurrentIndex(0);
  connect(m_ui.proxyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotProxyTypeChanged(int)));
  m_ui.proxyUsername->clear();
#if SPOTON_GOLDBUG == 0
  m_ui.proxy_frame->setVisible(state);
#endif
}

void spoton::slotProxyTypeChanged(int index)
{
  m_ui.proxyHostname->clear();
  m_ui.proxyHostname->setEnabled(index != 2);
  m_ui.proxyPassword->clear();
  m_ui.proxyPort->setEnabled(index != 2);
  m_ui.proxyPort->setValue(m_ui.proxyPort->minimum());
  m_ui.proxyUsername->clear();
}

void spoton::slotQuit(void)
{
  /*
  ** closeEvent() calls slotQuit().
  */

  if(!m_quit && sender())
    if(promptBeforeExit())
      return;

  if(m_optionsUi.terminate_kernel_on_ui_exit->isChecked())
    {
      QString connectionName("");
      int count = 0; // Terminate the kernel on database errors.

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "kernel.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);

	    if(query.exec("SELECT value FROM kernel_statistics "
			  "WHERE statistic = 'Attached User Interfaces'") &&
	       query.next())
	      count = query.value(0).toInt();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      if(count <= 1)
	slotDeactivateKernel();
    }

  m_quit = true;
  cleanup();
}

void spoton::slotResetAccountInformation(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  auto const list
    (m_ui.neighbors->selectionModel()->
     selectedRows(m_ui.neighbors->columnCount() - 1)); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	query.prepare("UPDATE neighbors SET "
		      "account_authenticated = NULL, "
		      "account_name = ?, "
		      "account_password = ? "
		      "WHERE OID = ? AND user_defined = 1");
	query.bindValue
	  (0, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	query.bindValue(2, list.at(0).data());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSaveGeoIPPath(void)
{
  if(m_optionsUi.geoipPath4 == sender())
    saveGeoIPPath(4, m_optionsUi.geoipPath4->text());
  else
    saveGeoIPPath(6, m_optionsUi.geoipPath6->text());
}

void spoton::slotSaveKernelPath(void)
{
  saveKernelPath(m_ui.kernelPath->text());
}

void spoton::slotSaveSslControlString(void)
{
  auto str(m_optionsUi.sslControlString->text());

  if(str.trimmed().isEmpty())
    str = spoton_common::SSL_CONTROL_STRING;

  m_ui.listenersSslControlString->setText(str.trimmed());
  m_ui.listenersSslControlString->setCursorPosition(0);
  m_ui.neighborsSslControlString->setText(str.trimmed());
  m_ui.neighborsSslControlString->setCursorPosition(0);
  m_optionsUi.sslControlString->setText(str.trimmed());
  m_optionsUi.sslControlString->setCursorPosition(0);
  m_optionsUi.sslControlString->selectAll();
  m_settings["gui/sslControlString"] = str;

  QSettings settings;

  settings.setValue("gui/sslControlString", str);
}

void spoton::slotScramble(bool state)
{
  m_settings["gui/scramblerEnabled"] = state;

  QSettings settings;

  settings.setValue("gui/scramblerEnabled", state);
}

void spoton::slotSelectGeoIPPath(void)
{
  QFileDialog dialog(m_optionsWindow);

  dialog.setWindowTitle
    (tr("%1: Select GeoIP Data Path").arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();

      if(m_optionsUi.selectGeoIP4 == sender())
	saveGeoIPPath(4, dialog.selectedFiles().value(0));
      else
	saveGeoIPPath(6, dialog.selectedFiles().value(0));
    }

  QApplication::processEvents();
}

void spoton::slotSelectKernelPath(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select Kernel Path").arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      saveKernelPath(dialog.selectedFiles().value(0));
    }

  QApplication::processEvents();
}

void spoton::slotSetPassphrase(void)
{
  if(m_wizardHash.value("shown", false))
    return;
  else if(!verifyInitializationPassphrase(this))
    return;

  auto const str3(m_ui.username->text());
  auto const wizardAccepted = m_wizardHash.value("accepted", false);
  auto reencode = false;
  auto str1(m_ui.passphrase1->text());
  auto str2(m_ui.passphrase2->text());

  if(spoton_crypt::passphraseSet())
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);

      if(m_ui.passphrase_rb->isChecked())
	mb.setText(tr("Are you sure that you wish to replace the "
		      "existing passphrase? Please note that URL data must "
		      "be re-encoded via a separate tool. Please see "
		      "the future Re-Encode URLs option. The RSS mechanism "
		      "and the kernel will be deactivated."));
      else
	mb.setText(tr("Are you sure that you wish to replace the "
		      "existing answer/question? Please note that URL "
		      "data must "
		      "be re-encoded via a separate tool. Please see "
		      "the future Re-Encode URLs option. The RSS mechanism "
		      "and the kernel will be deactivated."));

      mb.setWindowIcon(windowIcon());
      mb.setWindowModality(Qt::ApplicationModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  m_ui.answer->clear();
	  m_ui.passphrase1->clear();
	  m_ui.passphrase2->clear();
	  m_ui.question->clear();
	  return;
	}
      else
	{
	  repaint();
	  QApplication::processEvents();
	  m_rss->deactivate();
	  slotDeactivateKernel();
	  reencode = true;
	}
    }
  else
    {
      repaint();
      QApplication::processEvents();

      /*
      ** Deactivate machines before preparing keys.
      */

      m_rss->deactivate();
      slotDeactivateKernel();
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText
    (tr("Generating derived keys. Please be patient."));
  m_sb.status->repaint();

  QByteArray salt;
  QByteArray saltedPassphraseHash;
  QString error1("");
  QString error2("");
  QString error3("");

  salt.resize(m_ui.saltLength->value());
  salt = spoton_crypt::strongRandomBytes(static_cast<size_t> (salt.length()));

  QPair<QByteArray, QByteArray> derivedKeys;

  if(m_ui.passphrase_rb->isChecked())
    derivedKeys = spoton_crypt::derivedKeys
      (m_ui.cipherType->currentText(),
       m_ui.hashType->currentText(),
       static_cast<unsigned long int> (m_ui.iterationCount->value()),
       str1,
       salt,
       false,
       error1);
  else
    {
      str1 = m_ui.question->text();
      str2 = m_ui.answer->text();
      derivedKeys = spoton_crypt::derivedKeys
	(m_ui.cipherType->currentText(),
	 m_ui.hashType->currentText(),
	 static_cast<unsigned long int> (m_ui.iterationCount->value()),
	 str1 + str2,
	 salt,
	 false,
	 error1);
    }

  m_sb.status->clear();
  QApplication::restoreOverrideCursor();

  if(error1.isEmpty())
    {
      if(!m_ui.newKeys->isChecked() && reencode)
	{
	  if(m_crypts.value("chat", nullptr))
	    {
	      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	      QScopedPointer<spoton_crypt> crypt
		(new
		 spoton_crypt(m_ui.cipherType->currentText(),
			      m_ui.hashType->currentText(),
			      QByteArray(),
			      derivedKeys.first,
			      derivedKeys.second,
			      m_ui.saltLength->value(),
			      static_cast<unsigned long int> (m_ui.
							      iterationCount->
							      value()),
			      "chat"));
	      auto list(spoton_common::SPOTON_ENCRYPTION_KEY_NAMES +
			spoton_common::SPOTON_SIGNATURE_KEY_NAMES);

	      std::sort(list.begin(), list.end());

	      for(int i = 0; i < list.size(); i++)
		{
		  m_sb.status->setText
		    (tr("Re-encoding public key pair %1 of %2. "
			"Please be patient.").
		     arg(i + 1).
		     arg(list.size()));
		  m_sb.status->repaint();

		  /*
		  ** All m_crypts values have identical symmetric keys.
		  */

		  spoton_crypt::reencodePrivatePublicKeys
		    (crypt.data(),
		     m_crypts.value("chat", nullptr), list.at(i), error2);
		  m_sb.status->clear();

		  if(!error2.isEmpty())
		    break;
		}

	      QApplication::restoreOverrideCursor();
	    }
	}
      else
	{
	  auto proceed = false;

	  if(!wizardAccepted)
	    {
	      QMessageBox mb(this);

	      mb.setIcon(QMessageBox::Question);
	      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	      mb.setText(tr("Would you like to generate public key pairs?"));
	      mb.setWindowIcon(windowIcon());
	      mb.setWindowModality(Qt::ApplicationModal);
	      mb.setWindowTitle
		(tr("%1: Question").arg(SPOTON_APPLICATION_NAME));

	      if(mb.exec() == QMessageBox::Yes)
		proceed = true;

	      QApplication::processEvents();
	    }
	  else
	    proceed = m_wizardHash.value("initialize_public_keys", true);

	  if(proceed)
	    if(m_ui.encryptionKeyType->currentIndex() == 1)
	      {
		QMessageBox mb(this);

		mb.setIcon(QMessageBox::Question);
		mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
		mb.setText
		  (tr("McEliece key pairs require a significant amount of "
		      "storage memory. As %1 prefers secure memory, "
		      "the gcrypt library may fail if it's unable to "
		      "reserve the required amount of memory. Some "
		      "operating systems require configuration in order "
		      "to support large amounts of locked memory. "
		      "You may disable secure memory by setting the "
		      "secure memory pools of the interface and the kernel "
		      "to zero. Continue with the key-generation process?").
		   arg(SPOTON_APPLICATION_NAME));
		mb.setWindowIcon(windowIcon());
		mb.setWindowModality(Qt::ApplicationModal);
		mb.setWindowTitle
		  (tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

		if(mb.exec() != QMessageBox::Yes)
		  proceed = false;

		QApplication::processEvents();
	      }

	  if(proceed)
	    {
	      repaint();
	      QApplication::processEvents();

	      QString encryptionKeyType("");
	      QString signatureKeyType("");
	      QStringList list;

	      if(m_ui.encryptionKeyType->currentIndex() == 0)
		encryptionKeyType = "elg";
	      else if(m_ui.encryptionKeyType->currentIndex() == 1)
		encryptionKeyType = "mceliece";
	      else if(m_ui.encryptionKeyType->currentIndex() == 2)
		encryptionKeyType = "ntru";
	      else
		encryptionKeyType = "rsa";

	      if(m_ui.signatureKeyType->currentIndex() == 0)
		signatureKeyType = "dsa";
	      else if(m_ui.signatureKeyType->currentIndex() == 1)
		signatureKeyType = "ecdsa";
	      else if(m_ui.signatureKeyType->currentIndex() == 2)
		signatureKeyType = "eddsa";
	      else if(m_ui.signatureKeyType->currentIndex() == 3)
		signatureKeyType = "elg";
	      else
		signatureKeyType = "rsa";

	      list << spoton_common::SPOTON_ENCRYPTION_KEY_NAMES
		   << spoton_common::SPOTON_SIGNATURE_KEY_NAMES;
	      std::sort(list.begin(), list.end());

	      QProgressDialog progress(this);

	      progress.setLabelText
		(tr("Generating key pairs. Please be patient."));
	      progress.setMaximum(list.size());
	      progress.setMinimum(0);
	      progress.setModal(true);
	      progress.setWindowTitle
		(tr("%1: Generating Key Pairs").arg(SPOTON_APPLICATION_NAME));
	      progress.show();
	      progress.repaint();
	      QApplication::processEvents();

	      for(int i = 0; i < list.size() && !progress.wasCanceled(); i++)
		{
		  if(i + 1 <= progress.maximum())
		    progress.setValue(i + 1);

		  progress.repaint();
		  QApplication::processEvents();

		  spoton_crypt crypt
		    (m_ui.cipherType->currentText(),
		     m_ui.hashType->currentText(),
		     str1.toUtf8(), // Passphrase.
		     derivedKeys.first,
		     derivedKeys.second,
		     m_ui.saltLength->value(),
		     static_cast<unsigned long int> (m_ui.iterationCount->
						     value()),
		     list.at(i));

		  if(!list.at(i).contains("signature"))
		    crypt.generatePrivatePublicKeys
		      (m_ui.encryptionKeySize->currentText(),
		       encryptionKeyType,
		       error2);
		  else
		    crypt.generatePrivatePublicKeys
		      (m_ui.signatureKeySize->currentText(),
		       signatureKeyType,
		       error2);

		  if(!error2.isEmpty())
		    break;
		}

	      progress.close();
	    }
	}
    }

  if(error1.isEmpty() && error2.isEmpty())
    {
      if(m_ui.passphrase_rb->isChecked())
	saltedPassphraseHash = spoton_crypt::saltedPassphraseHash
	  (m_ui.hashType->currentText(), str1, salt, error3);
      else
	{
	  auto ok = true;

	  saltedPassphraseHash = spoton_crypt::keyedHash
	    (str1.toUtf8(), str2.toUtf8(),
	     m_ui.hashType->currentText().toLatin1(), &ok);

	  if(!ok)
	    error3 = "keyed hash failure";
	}
    }

  if(!error1.trimmed().isEmpty())
    {
      spoton_crypt::purgeDatabases();
      updatePublicKeysLabel();
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("An error (%1) occurred with spoton_crypt::derivedKeys().").
	 arg(error1.trimmed()));
      QApplication::processEvents();
    }
  else if(!error2.trimmed().isEmpty())
    {
      spoton_crypt::purgeDatabases();
      updatePublicKeysLabel();
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error (%1) occurred with "
			       "spoton_crypt::"
			       "generatePrivatePublicKeys() or "
			       "spoton_crypt::"
			       "reencodePrivatePublicKeys().").
			    arg(error2.trimmed()));
      QApplication::processEvents();
    }
  else if(!error3.trimmed().isEmpty())
    {
      spoton_crypt::purgeDatabases();
      updatePublicKeysLabel();
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error (%1) occurred with "
			       "spoton_crypt::"
			       "keyedHash() or "
			       "spoton_crypt::"
			       "saltedPassphraseHash().").
			    arg(error3.trimmed()));
      QApplication::processEvents();
    }
  else
    {
      if(!m_crypts.value("chat", nullptr) || reencode)
	{
	  if(reencode)
	    {
	      QScopedPointer<spoton_crypt> crypt
		(new
		 spoton_crypt(m_ui.cipherType->currentText(),
			      m_ui.hashType->currentText(),
			      QByteArray(),
			      derivedKeys.first,
			      derivedKeys.second,
			      m_ui.saltLength->value(),
			      static_cast<unsigned long int> (m_ui.
							      iterationCount->
							      value()),
			      "chat"));
	      spoton_reencode reencode;

	      QApplication::setOverrideCursor(Qt::WaitCursor);
	      reencode.reencode
		(m_sb, crypt.data(), m_crypts.value("chat", nullptr));
	      spoton_crypt::removeFlawedEntries(crypt.data());
	      QApplication::restoreOverrideCursor();
	    }

	  QHashIterator<QString, spoton_crypt *> it(m_crypts);

	  while(it.hasNext())
	    {
	      it.next();
	      delete it.value();
	    }

	  m_crypts.clear();

	  auto list(spoton_common::SPOTON_ENCRYPTION_KEY_NAMES +
		    spoton_common::SPOTON_SIGNATURE_KEY_NAMES);

	  std::sort(list.begin(), list.end());

	  for(int i = 0; i < list.size(); i++)
	    m_crypts.insert
	      (list.at(i),
	       new spoton_crypt(m_ui.cipherType->currentText(),
				m_ui.hashType->currentText(),
				QByteArray(),
				derivedKeys.first,
				derivedKeys.second,
				m_ui.saltLength->value(),
				static_cast<unsigned long int> (m_ui.
								iterationCount->
								value()),
				list.at(i)));

	  spoton_misc::prepareAuthenticationHint
	    (m_crypts.value("chat", nullptr));

	  if(!reencode)
	    {
	      auto proceed = false;

	      if(!wizardAccepted)
		{
		  QMessageBox mb(this);

		  mb.setIcon(QMessageBox::Question);
		  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
		  mb.setText(tr("Would you like to exercise your new "
				"credentials as URL Common Credentials?"));
		  mb.setWindowIcon(windowIcon());
		  mb.setWindowTitle
		    (tr("%1: Question").arg(SPOTON_APPLICATION_NAME));

		  if(mb.exec() == QMessageBox::Yes)
		    proceed = true;

		  QApplication::processEvents();
		}
	      else
		proceed = m_wizardHash.value("url_credentials", true);

	      if(proceed)
		{
		  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
		  spoton_misc::prepareUrlKeysDatabase();

		  if(saveCommonUrlCredentials(derivedKeys,
					      m_ui.cipherType->currentText(),
					      m_ui.hashType->currentText(),
					      m_crypts.value("chat", nullptr)).
		     isEmpty())
		    {
		      prepareUrlContainers();
		      prepareUrlLabels();
		    }

		  QApplication::restoreOverrideCursor();
		}

	      if(wizardAccepted)
		m_ui.activeUrlDistribution->setChecked
		  (m_wizardHash.value("url_distribution", false));
	    }

	  QApplication::setOverrideCursor(Qt::WaitCursor);
	  m_smpWindow->populateSecrets();
	  sendKeysToKernel();
	  askKernelToReadStarBeamKeys();
	  populateNovas();
	  sendBuzzKeysToKernel();
	  updatePublicKeysLabel();
	  QApplication::restoreOverrideCursor();

	  if(!reencode)
	    {
	      QApplication::setOverrideCursor(Qt::WaitCursor);
	      m_echoKeyShare->createDefaultUrlCommunity();
	      QApplication::restoreOverrideCursor();
	    }
	  else
	    prepareUrlContainers();
	}

      m_sb.frame->setEnabled(true);
      m_sb.lock->setEnabled(true);
#ifdef SPOTON_POPTASTIC_SUPPORTED
      m_sb.pop_poptastic->setEnabled(true);
#endif
#if SPOTON_GOLDBUG == 0
      m_ui.action_Add_Participant->setEnabled(true);
#endif
      m_ui.action_Echo_Key_Share->setEnabled(true);
      m_ui.action_Export_Listeners->setEnabled(true);
      m_ui.action_Export_Public_Keys->setEnabled(true);
      m_ui.action_Import_Neighbors->setEnabled(true);
      m_ui.action_Import_Public_Keys->setEnabled(true);
      m_ui.action_Minimal_Display->setEnabled(true);
      m_ui.action_New_Global_Name->setEnabled(true);
      m_ui.action_Notifications_Window->setEnabled(true);
      m_ui.action_Options->setEnabled(true);
#ifdef SPOTON_POPTASTIC_SUPPORTED
      m_ui.action_Poptastic_Settings->setEnabled(true);
#endif
      m_ui.action_Purge_Ephemeral_Keys->setEnabled(true);
      m_ui.action_RSS->setEnabled(true);
      m_ui.action_Rosetta->setEnabled(true);
      m_ui.action_SMP->setEnabled(true);
      m_ui.action_Statistics_Window->setEnabled(true);
      m_ui.action_Vacuum_Databases->setEnabled(true);
      m_ui.answer->clear();
      m_ui.delete_key->setEnabled(true);
      m_ui.encryptionKeySize->setEnabled(false);
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.kernelBox->setEnabled(true);
      m_ui.kernelBox->setVisible(true);
      m_ui.keys->setEnabled(true);
      m_ui.menu_Pages->setEnabled(true);
      m_ui.newKeys->setChecked(false);
      m_ui.newKeys->setEnabled(true);
      m_ui.passphrase1->clear();
      m_ui.passphrase2->clear();
      m_ui.passphrase_strength_indicator->setVisible(false);
      m_ui.publicKeysBox->setVisible(true);
      m_ui.question->clear();
      m_ui.regenerate->setEnabled(true);
      m_ui.showStatistics->setVisible(true);
      m_ui.signatureKeyType->setEnabled(false);
      m_ui.signatureKeyType->setEnabled(false);
      repaint();
      QApplication::processEvents();

      for(int i = 0; i < m_ui.tab->count(); i++)
	{
	  m_ui.tab->setTabEnabled(i, true);

	  auto hash(m_tabWidgetsProperties[i]);

	  hash["enabled"] = true;
	  m_tabWidgetsProperties[i] = hash;
	}

      /*
      ** Save the various entities.
      */

      m_settings["gui/buzzName"] = str3.toUtf8();
      m_settings["gui/cipherType"] = m_ui.cipherType->currentText();
      m_settings["gui/emailName"] = str3.toUtf8();
      m_settings["gui/hashType"] = m_ui.hashType->currentText();
      m_settings["gui/iterationCount"] = m_ui.iterationCount->value();
      m_settings["gui/kernelCipherType"] =
	m_ui.kernelCipherType->currentText();
      m_settings["gui/kernelHashType"] =
	m_ui.kernelHashType->currentText();
      m_settings["gui/nodeName"] = str3.toUtf8();
      m_settings["gui/rosettaName"] = str3.toUtf8();
      m_settings["gui/salt"] = salt;
      m_settings["gui/saltLength"] = m_ui.saltLength->value();
      m_settings["gui/saltedPassphraseHash"] = saltedPassphraseHash;
      m_settings["gui/urlName"] = str3.toUtf8();

      QSettings settings;

      settings.setValue("gui/buzzName", m_settings["gui/buzzName"]);
      settings.setValue("gui/cipherType", m_settings["gui/cipherType"]);
      settings.setValue("gui/emailName", m_settings["gui/emailName"]);
      settings.setValue("gui/hashType", m_settings["gui/hashType"]);
      settings.setValue("gui/iterationCount",
			m_settings["gui/iterationCount"]);
      settings.setValue("gui/kernelCipherType",
			m_settings["gui/kernelCipherType"]);
      settings.setValue("gui/kernelHashType",
			m_settings["gui/kernelHashType"]);
      settings.setValue("gui/nodeName", m_settings["gui/nodeName"]);
      settings.setValue("gui/rosettaName", m_settings["gui/rosettaName"]);
      settings.setValue("gui/salt", m_settings["gui/salt"]);
      settings.setValue("gui/saltLength", m_settings["gui/saltLength"]);
      settings.setValue
	("gui/saltedPassphraseHash", m_settings["gui/saltedPassphraseHash"]);
      settings.setValue("gui/spot_on_neighbors_txt_processed", true);
      settings.setValue("gui/urlName", m_settings["gui/urlName"]);
      m_ui.buzzName->setText(m_ui.username->text());
      m_ui.buzzName->setCursorPosition(0);
      m_ui.emailName->clear();
      m_ui.emailName->addItem(m_ui.username->text());
      m_ui.emailNameEditable->setText(m_ui.emailName->currentText());
      m_ui.emailNameEditable->setCursorPosition(0);
      m_ui.nodeName->setText(m_ui.username->text());
      m_ui.nodeName->setCursorPosition(0);
      m_ui.urlName->setText(m_ui.username->text());
      m_ui.urlName->setCursorPosition(0);

      if(!m_settings.value("gui/initial_url_distillers_defined",
			   false).toBool())
	{
	  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	  m_sb.status->setText
	    (tr("Initializing URL distillers. Please be patient."));
	  m_sb.status->repaint();
	  initializeUrlDistillers();

	  QSettings settings;

	  settings.setValue("gui/initial_url_distillers_defined",
			    true);
	  m_settings["gui/initial_url_distillers_defined"] = true;
	  populateUrlDistillers();
	  m_sb.status->clear();
	  QApplication::restoreOverrideCursor();
	}

      if(!m_settings.value("gui/spot_on_neighbors_txt_processed",
			   false).toBool())
	{
	  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	  m_sb.status->setText
	    (tr("Importing spot-on-neighbors.txt. Please be patient."));
	  m_sb.status->repaint();
	  importNeighbors(":/Data/spot-on-neighbors.txt");

	  QSettings settings;

	  settings.setValue("gui/spot_on_neighbors_txt_processed",
			    true);
	  m_settings["gui/spot_on_neighbors_txt_processed"] = true;
	  m_sb.status->clear();
	  QApplication::restoreOverrideCursor();
	}

      slotApplyOtherOptions(); // Initialize miscellaneous options.
      QMessageBox::information
	(this,
	 tr("%1: Information").arg(SPOTON_APPLICATION_NAME),
	 tr("Your confidential information has been saved. Enjoy!"));
      QApplication::processEvents();

      if(m_ui.pid->text() == "0")
	if(QFileInfo(m_ui.kernelPath->text()).isExecutable())
	  {
	    auto proceed = false;

	    if(!wizardAccepted)
	      {
		QMessageBox mb(this);

		mb.setIcon(QMessageBox::Question);
		mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
		mb.setText(tr("Would you like the kernel to be activated?"));
		mb.setWindowIcon(windowIcon());
		mb.setWindowModality(Qt::ApplicationModal);
		mb.setWindowTitle
		  (tr("%1: Question").arg(SPOTON_APPLICATION_NAME));

		if(mb.exec() == QMessageBox::Yes)
		  proceed = true;

		QApplication::processEvents();
	      }
	    else
	      proceed = m_wizardHash.value("launch_kernel", true);

	    if(proceed)
	      slotActivateKernel();
	  }

#if SPOTON_GOLDBUG == 1
      slotConnectAllNeighbors();
#endif
      playSound("login.wav");

#if SPOTON_GOLDBUG == 0
      if(m_settings.contains("gui/minimal"))
	slotShowMinimalDisplay
	  (m_settings.value("gui/minimal", false).toBool());
#endif
    }
}

void spoton::slotShowContextMenu(const QPoint &point)
{
  if(m_ui.emailParticipants == sender())
    {
      QAction *action = nullptr;
      QMenu menu(this);

      menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add Participant As Friend"),
	 this,
	 SLOT(slotShareEmailPublicKeyWithParticipant(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/copy.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Copy Keys (Clipboard Buffer)"),
		     this,
		     SLOT(slotCopyEmailKeys(void)));
      menu.addAction(QIcon(":/generic/repleo-email.png"),
		     tr("&Copy Repleo (Clipboard Buffer)"),
		     this,
		     SLOT(slotCopyEmailFriendshipBundle(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Remove Participant(s)"),
		     this,
		     SLOT(slotRemoveEmailParticipants(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Rename Participant..."),
			      this,
			      SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "email");
      menu.addSeparator();
      action = menu.addAction
	(tr("Initiate Forward &Secrecy Exchange(s)..."),
	 this,
	 SLOT(slotEstablishForwardSecrecy(void)));
      action->setProperty("type", "email");
      action = menu.addAction
	(tr("Purge Forward &Secrecy Key Pair"),
	 this,
	 SLOT(slotPurgeEphemeralKeyPair(void)));
      action->setProperty("type", "email");
      action = menu.addAction
	(tr("Reset Forward &Secrecy Information of Selected Participant(s)"),
	 this,
	 SLOT(slotResetForwardSecrecyInformation(void)));
      action->setProperty("type", "email");
      menu.setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu.exec(m_ui.emailParticipants->mapToGlobal(point));
    }
  else if(m_ui.listeners == sender())
    {
      QAction *action = nullptr;
      QMenu menu(this);

      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"),
		     this,
		     SLOT(slotDeleteListener(void)));
      menu.addAction(tr("Delete &All"),
		     this,
		     SLOT(slotDeleteAllListeners(void)));
      menu.addSeparator();
      menu.addAction(tr("Detach &Neighbors"),
		     this,
		     SLOT(slotDetachListenerNeighbors(void)));
      menu.addAction(tr("Disconnect &Neighbors"),
		     this,
		     SLOT(slotDisconnectListenerNeighbors(void)));
      menu.addSeparator();
      menu.addAction(tr("&Publish Information (Plaintext)"),
		     this,
		     SLOT(slotPublicizeListenerPlaintext(void)));
      menu.addAction(tr("Publish &All (Plaintext)"),
		     this,
		     SLOT(slotPublicizeAllListenersPlaintext(void)));
      menu.addSeparator();
      menu.addAction(tr("&Full Echo"),
		     this,
		     SLOT(slotListenerFullEcho(void)));
      menu.addAction(tr("&Half Echo"),
		     this,
		     SLOT(slotListenerHalfEcho(void)));
      menu.addSeparator();
      action = menu.addAction
	(tr("&Copy Private Application Magnet"),
	 this,
	 SLOT(slotCopyPrivateApplicationMagnet(void)));
      action->setProperty("type", "listeners");
      action = menu.addAction
	(tr("&Set Private Application Information..."),
	 this,
	 SLOT(slotSetPrivateApplicationInformation(void)));
      action->setProperty("type", "listeners");
      action = menu.addAction
	(tr("&Reset Private Application Information"),
	 this,
	 SLOT(slotResetPrivateApplicationInformation(void)));
      action->setProperty("type", "listeners");
      menu.addSeparator();
      menu.addAction(tr("&Prepare New One-Year Certificate"),
		     this,
		     SLOT(slotGenerateOneYearListenerCertificate(void)))->
	setEnabled(listenerSupportsSslTls());
      menu.addAction(tr("Set &SSL Control String..."),
		     this,
		     SLOT(slotSetListenerSSLControlString(void)))->
	setEnabled(listenerSupportsSslTls());
      menu.addSeparator();
      action = menu.addAction(tr("Set Socket &Options..."),
			      this,
			      SLOT(slotSetSocketOptions(void)));
      action->setEnabled(listenerTransport() > "bluetooth");
      action->setProperty("type", "listeners");
      menu.setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu.exec(m_ui.listeners->mapToGlobal(point));
    }
  else if(m_ui.neighbors == sender())
    {
      QAction *action = nullptr;
      QMenu menu(this);
      auto const neighborSpecialClient = this->neighborSpecialClient();
      auto const neighborSupportsSslTls = this->neighborSupportsSslTls();

      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &Chat Public Key Pair"),
		     this,
		     SLOT(slotShareChatPublicKey(void)));
      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &E-Mail Public Key Pair"),
		     this,
		     SLOT(slotShareEmailPublicKey(void)));
#ifdef SPOTON_OPEN_LIBRARY_SUPPORTED
      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &Open Library Public Key Pair"),
		     this,
		     SLOT(slotShareOpenLibraryPublicKey(void)));
#endif
      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &Poptastic Public Key Pair"),
		     this,
		     SLOT(slotSharePoptasticPublicKey(void)));
      menu.addAction(QIcon(QString(":%1//share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &URL Public Key Pair"),
		     this,
		     SLOT(slotShareURLPublicKey(void)));
      menu.addSeparator();
      menu.addAction(tr("&Assign New Remote IP Information..."),
		     this,
		     SLOT(slotAssignNewIPToNeighbor(void)));
      menu.addAction(tr("&Connect"),
		     this,
		     SLOT(slotConnectNeighbor(void)));
      menu.addAction(tr("&Disconnect"),
		     this,
		     SLOT(slotDisconnectNeighbor(void)));
      menu.addSeparator();
      menu.addAction(tr("&Connect All"),
		     this,
		     SLOT(slotConnectAllNeighbors(void)));
      menu.addAction(tr("&Disconnect All"),
		     this,
		     SLOT(slotDisconnectAllNeighbors(void)));
      menu.addSeparator();
      menu.addAction
	(tr("&Authenticate Account..."),
	 this,
	 SLOT(slotAuthenticate(void)));
      menu.addAction(tr("&Reset Account Information"),
		     this,
		     SLOT(slotResetAccountInformation(void)));
      menu.addSeparator();
      menu.addAction(tr("&Reset Certificate"),
		     this,
		     SLOT(slotResetCertificate(void)))->
	setEnabled(neighborSupportsSslTls);
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"),
		     this,
		     SLOT(slotDeleteNeighbor(void)));
      menu.addAction(tr("Delete &All"),
		     this,
		     SLOT(slotDeleteAllNeighbors(void)));
      menu.addAction(tr("Delete All Non-Unique &Blocked"),
		     this,
		     SLOT(slotDeleteAllBlockedNeighbors(void)));
      menu.addAction(tr("Delete All Non-Unique &UUIDs"),
		     this,
		     SLOT(slotDeleteAllUuids(void)));
      menu.addSeparator();
      menu.addAction(tr("B&lock"),
		     this,
		     SLOT(slotBlockNeighbor(void)));
      menu.addAction(tr("U&nblock"),
		     this,
		     SLOT(slotUnblockNeighbor(void)));
      menu.addSeparator();
      menu.addAction(tr("&Full Echo"),
		     this,
		     SLOT(slotNeighborFullEcho(void)));
      menu.addAction(tr("&Half Echo"),
		     this,
		     SLOT(slotNeighborHalfEcho(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Copy Adaptive Echo Magnet"),
			      this,
			      SLOT(slotCopyAEMagnet(void)));
      action->setProperty("from", "neighbors");
      menu.addAction(tr("&Set Adaptive Echo Token Information..."),
		     this,
		     SLOT(slotSetAETokenInformation(void)));
      menu.addAction(tr("&Reset Adaptive Echo Token Information"),
		     this,
		     SLOT(slotResetAETokenInformation(void)));
      menu.addSeparator();
      action = menu.addAction
	(tr("&Copy Private Application Magnet"),
	 this,
	 SLOT(slotCopyPrivateApplicationMagnet(void)));
      action->setProperty("type", "neighbors");
      action = menu.addAction
	(tr("&Set Private Application Information..."),
	 this,
	 SLOT(slotSetPrivateApplicationInformation(void)));
      action->setProperty("type", "neighbors");
      action = menu.addAction
	(tr("&Reset Private Application Information"),
	 this,
	 SLOT(slotResetPrivateApplicationInformation(void)));
      action->setProperty("type", "neighbors");
      menu.addSeparator();
      menu.addAction(tr("Set &SSL Control String..."),
		     this,
		     SLOT(slotSetNeighborSSLControlString(void)))->
	setEnabled(neighborSupportsSslTls);
      menu.addSeparator();
      action = menu.addAction(tr("Set Socket &Options..."),
			      this,
			      SLOT(slotSetSocketOptions(void)));
      action->setEnabled(neighborTransport() > "bluetooth");
      action->setProperty("type", "neighbors");
      menu.addSeparator();

      QList<QPair<QString, QThread::Priority> > list;
      QPair<QString, QThread::Priority> pair;
      auto actionGroup = new QActionGroup(&menu);
      auto subMenu = menu.addMenu(tr("Priority"));

      pair.first = tr("High Priority");
      pair.second = QThread::HighPriority;
      list << pair;
      pair.first = tr("Highest Priority");
      pair.second = QThread::HighestPriority;
      list << pair;
      pair.first = tr("Idle Priority");
      pair.second = QThread::IdlePriority;
      list << pair;
      pair.first = tr("Low Priority");
      pair.second = QThread::LowPriority;
      list << pair;
      pair.first = tr("Lowest Priority");
      pair.second = QThread::LowestPriority;
      list << pair;
      pair.first = tr("Normal Priority");
      pair.second = QThread::NormalPriority;
      list << pair;
      pair.first = tr("Time-Critical Priority");
      pair.second = QThread::TimeCriticalPriority;
      list << pair;

      auto const priority = neighborThreadPriority();

      for(int i = 0; i < list.size(); i++)
	{
	  action = subMenu->addAction
	    (list.at(i).first,
	     this,
	     SLOT(slotSetNeighborPriority(void)));
	  action->setCheckable(true);
	  action->setProperty("priority", list.at(i).second);
	  actionGroup->addAction(action);

	  if(list.at(i).second == priority)
	    action->setChecked(true);
	}

      if(actionGroup->actions().isEmpty())
	actionGroup->deleteLater();

#if SPOTON_GOLDBUG == 0
      menu.addSeparator();
      menu.addAction("&Statistics...",
		     this,
		     SLOT(slotShowNeighborStatistics(void)));
#endif
      menu.addSeparator();
      action = menu.addAction
	(tr("Initiate SSL/TLS Client Session"),
	 this,
	 SLOT(slotInitiateSSLTLSSession(void)));
      action->setEnabled(neighborSpecialClient && neighborSupportsSslTls);
      action->setProperty("mode", "client");
      action = menu.addAction
	(tr("Initiate SSL/TLS Server Session"),
	 this,
	 SLOT(slotInitiateSSLTLSSession(void)));
      action->setEnabled(neighborSpecialClient && neighborSupportsSslTls);
      action->setProperty("mode", "server");
      menu.setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu.exec(m_ui.neighbors->mapToGlobal(point));
    }
  else if(m_ui.participants == sender())
    {
      QAction *action = nullptr;
      QMenu menu(this);

      menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add Participant As Friend"),
	 this,
	 SLOT(slotShareChatPublicKeyWithParticipant(void)));
      menu.addSeparator();
      menu.addAction(tr("Chat &Popup..."),
		     this,
		     SLOT(slotChatPopup(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/generic/repleo-chat.png"),
		     tr("&Copy Repleo (Clipboard Buffer)"),
		     this,
		     SLOT(slotCopyFriendshipBundle(void)));
      menu.addSeparator();
#if SPOTON_GOLDBUG == 1
      action = menu.addAction(QIcon(QString(":/%1/melodica.png").
				    arg(m_settings.value("gui/iconSet",
							 "nouve").
					toString().toLower())),
			      tr("MELODICA: &Call Friend (New Gemini Pair)"),
			      this,
			      SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu.addAction(QIcon(QString(":/%1/melodica.png").
				    arg(m_settings.value("gui/iconSet",
							 "nouve").
					toString().toLower())),
			      tr("MELODICA: &Call Friend "
				 "(New Gemini Pair Using "
				 "Existing Gemini Pair)"),
			      this,
			      SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_using_gemini");
      action = menu.addAction(QIcon(QString(":/%1/melodica.png").
				    arg(m_settings.value("gui/iconSet",
							 "nouve").
					toString().toLower())),
			      tr("MELODICA Two-Way: &Call Friend (New "
				 "Gemini Pair)"),
			      this,
			      SLOT(slotCallParticipant(void)));
      action->setEnabled
	("chat" == participantKeyType(m_ui.participants));
      action->setProperty("type", "calling_two_way");
#else
      action = menu.addAction(tr("&Call Participant"),
			      this,
			      SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu.addAction
	(tr("&Call Participant (Existing Gemini Pair)"),
	 this,
	 SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_using_gemini");
      action = menu.addAction(tr("&Two-Way Calling"),
			      this,
			      SLOT(slotCallParticipant(void)));
      action->setEnabled
	("chat" == participantKeyType(m_ui.participants));
      action->setProperty("type", "calling_two_way");
#endif
      action = menu.addAction(tr("&Terminate Call"),
			      this,
			      SLOT(slotCallParticipant(void)));
      action->setProperty("type", "terminating");
      menu.addSeparator();
#if SPOTON_GOLDBUG == 1
      menu.addAction
	(tr("&Generate Random Gemini Pair (Without Call)"),
	 this,
	 SLOT(slotGenerateGeminiInChat(void)));
#else
      menu.addAction(tr("&Generate Random Gemini Pair"),
		     this,
		     SLOT(slotGenerateGeminiInChat(void)));
#endif
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Remove Participant(s)"),
		     this,
		     SLOT(slotRemoveParticipants(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Rename Participant..."),
			      this,
			      SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "chat");
      menu.addSeparator();
      menu.addAction(tr("&Derive Gemini Pair From SMP Secret"),
		     this,
		     SLOT(slotDeriveGeminiPairViaSMP(void)));
      menu.addAction(tr("&Reset SMP Machine's Internal State (S0)"),
		     this,
		     SLOT(slotInitializeSMP(void)));
      menu.addAction(tr("&Set SMP Secret..."),
		     this,
		     SLOT(slotPrepareSMP(void)));
      menu.addAction(tr("&Verify SMP Secret"),
		     this,
		     SLOT(slotVerifySMPSecret(void)));
      menu.addSeparator();
      menu.addAction(tr("Replay &Last %1 Messages").
		     arg(spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE),
		     this,
		     SLOT(slotReplayMessages(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/starbeam.png").
			   arg(m_settings.value("gui/iconSet",
						"nouve").
			       toString().toLower())),
		     tr("Share &StarBeam With "
			"Selected Participant(s)..."),
		     this,
		     SLOT(slotShareStarBeam(void)))->setEnabled
	("chat" == participantKeyType(m_ui.participants));
      menu.addSeparator();
      menu.addAction
	(tr("Call Via Forward &Secrecy Credentials"),
	 this,
	 SLOT(slotCallParticipantViaForwardSecrecy(void)));
      action = menu.addAction
	(tr("Initiate Forward &Secrecy Exchange(s)..."),
	 this,
	 SLOT(slotEstablishForwardSecrecy(void)));
      action->setProperty("type", "chat");
      action = menu.addAction
	(tr("Purge Forward &Secrecy Key Pair"),
	 this,
	 SLOT(slotPurgeEphemeralKeyPair(void)));
      action->setProperty("type", "chat");
      action = menu.addAction
	(tr("Reset Forward &Secrecy Information of Selected Participant(s)"),
	 this,
	 SLOT(slotResetForwardSecrecyInformation(void)));
      action->setProperty("type", "chat");
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/buzz.png").
			   arg(m_settings.value("gui/iconSet",
						"nouve").
			       toString().toLower())),
		     tr("Invite Selected Participant(s) "
			"(Anonymous Buzz Channel)..."),
		     this,
		     SLOT(slotBuzzInvite(void)))->setEnabled
	("chat" == participantKeyType(m_ui.participants));
      menu.setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu.exec(m_ui.participants->mapToGlobal(point));
    }
  else if(m_ui.received == sender())
    {
      QAction *action = nullptr;
      QMenu menu(this);

      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"),
		     this,
		     SLOT(slotDeleteReceived(void)));
      menu.addAction(tr("Delete &All"),
		     this,
		     SLOT(slotDeleteAllReceived(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Compute SHA-1 Hash"),
			      this,
			      SLOT(slotComputeFileHash(void)));
      action->setProperty("hash", "sha-1");
      action->setProperty("widget_of", "received");
      action = menu.addAction(tr("&Compute SHA3-512 Hash"),
			      this,
			      SLOT(slotComputeFileHash(void)));
#if QT_VERSION < 0x050100
      action->setEnabled(false);
#endif
      action->setProperty("hash", "sha3-512");
      action->setProperty("widget_of", "received");
      menu.addSeparator();
      action = menu.addAction(tr("&Copy SHA-1 Hash"),
			      this,
			      SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "received");
      menu.setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu.exec(m_ui.received->mapToGlobal(point));
    }
  else if(m_ui.transmitted == sender())
    {
      QAction *action = nullptr;
      QMenu menu(this);

      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"),
		     this,
		     SLOT(slotDeleteTransmitted(void)));
      menu.addAction(tr("Delete &All"),
		     this,
		     SLOT(slotDeleteAllTransmitted(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Compute SHA-1 Hash"),
			      this,
			      SLOT(slotComputeFileHash(void)));
      action->setProperty("widget_of", "transmitted");
      action = menu.addAction(tr("&Compute SHA3-512 Hash"),
			      this,
			      SLOT(slotComputeFileHash(void)));
#if QT_VERSION < 0x050100
      action->setEnabled(false);
#endif
      action->setProperty("hash", "sha3-512");
      action->setProperty("widget_of", "transmitted");
      menu.addSeparator();
      action = menu.addAction(tr("&Copy SHA-1 Hash"),
			      this,
			      SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "transmitted");
      menu.addSeparator();
      menu.addAction(tr("Set &Pulse Size..."),
		     this,
		     SLOT(slotSetSBPulseSize(void)));
      menu.addAction(tr("Set &Read Interval..."),
		     this,
		     SLOT(slotSetSBReadInterval(void)));
      menu.setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu.exec(m_ui.transmitted->mapToGlobal(point));
    }
  else if(m_ui.transmittedMagnets == sender())
    {
      QMenu menu(this);

      menu.addAction(tr("Copy &Magnet"),
		     this,
		     SLOT(slotCopyTransmittedMagnet(void)));
      menu.addAction(tr("&Duplicate Magnet"),
		     this,
		     SLOT(slotDuplicateTransmittedMagnet(void)));
      menu.exec(m_ui.transmittedMagnets->mapToGlobal(point));
    }
  else if(m_ui.urlParticipants == sender())
    {
      QAction *action = nullptr;
      QMenu menu(this);

      menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add Participant As Friend"),
	 this,
	 SLOT(slotShareUrlPublicKeyWithParticipant(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/copy.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Copy Keys (Clipboard Buffer)"),
		     this,
		     SLOT(slotCopyUrlKeys(void)));
      menu.addAction(QIcon(":/generic/repleo-url.png"),
		     tr("&Copy Repleo (Clipboard Buffer)"),
		     this,
		     SLOT(slotCopyUrlFriendshipBundle(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Remove Participant(s)"),
		     this,
		     SLOT(slotRemoveUrlParticipants(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Rename Participant..."),
			      this,
			      SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "url");
      menu.setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu.exec(m_ui.urlParticipants->mapToGlobal(point));
    }
}

void spoton::slotSignatureCheckBoxToggled(bool state)
{
  QString str("");
  auto checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox == m_optionsUi.chatAcceptSigned)
    str = "chatAcceptSignedMessagesOnly";
  else if(checkBox == m_optionsUi.chatSignMessages)
    str = "chatSignMessages";
  else if(checkBox == m_optionsUi.coAcceptSigned)
    str = "coAcceptSignedMessagesOnly";
  else if(checkBox == m_optionsUi.emailAcceptSigned)
    str = "emailAcceptSignedMessagesOnly";
  else if(checkBox == m_optionsUi.emailSignMessages)
    str = "emailSignMessages";
  else if(checkBox == m_optionsUi.urlAcceptSigned)
    str = "urlAcceptSignedMessagesOnly";
  else if(checkBox == m_optionsUi.urlSignMessages)
    str = "urlSignMessages";

  if(!str.isEmpty())
    {
      m_settings[QString("gui/%1").arg(str)] = state;

      QSettings settings;

      settings.setValue(QString("gui/%1").arg(str), state);
    }
}

void spoton::slotTabChanged(int index)
{
  Q_UNUSED(index);

  auto const tabName(currentTabName());

  if(tabName == "buzz")
    m_sb.buzz->setVisible(false);
  else if(tabName == "chat")
    {
      if(m_participantsFuture.isFinished())
	m_participantsLastModificationTime = QDateTime();

      m_sb.chat->setVisible(false);
    }
  else if(tabName == "listeners")
    m_listenersLastModificationTime = QDateTime();
  else if(tabName == "neighbors")
    {
      if(m_neighborsFuture.isFinished())
	m_neighborsLastModificationTime = QDateTime();
    }
  else if(tabName == "starbeam")
    {
      m_magnetsLastModificationTime = QDateTime();
      m_starsLastModificationTime = QDateTime();
    }
}

void spoton::slotUnblockNeighbor(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QString remoteIp("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item(row, 10); // Remote IP Address

      if(item)
	remoteIp = item->text();
    }

  if(remoteIp.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	/*
	** We must unblock all neighbors having the given remote IP
	** address. The neighbors must be in blocked control states. We shall
	** place the unblocked neighbors in disconnected control states.
	*/

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, " // 0
		      "OID "                       // 1
		      "FROM neighbors WHERE status_control = 'blocked'"))
	  while(query.next())
	    {
	      auto ok = true;
	      auto const ip
		(crypt->
		 decryptedAfterAuthenticated(QByteArray::
					     fromBase64(query.
							value(0).
							toByteArray()),
					     &ok));

	      if(ok)
		if(ip == remoteIp)
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare("UPDATE neighbors SET "
					"status_control = 'disconnected' "
					"WHERE OID = ? AND "
					"status_control <> 'deleted'");
		    updateQuery.bindValue(0, query.value(1));
		    updateQuery.exec();
		  }
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotValidatePassphrase(void)
{
  QByteArray computedHash;
  QString error("");
  auto authenticated = false;
  auto const salt(m_settings.value("gui/salt", "").toByteArray());
  auto const saltedPassphraseHash
    (m_settings.value("gui/saltedPassphraseHash", "").toByteArray());

  if(m_ui.passphrase_rb_authenticate->isChecked())
    computedHash = spoton_crypt::saltedPassphraseHash
      (m_ui.hashType->currentText(), m_ui.passphrase->text(), salt, error);
  else
    {
      auto ok = true;

      computedHash = spoton_crypt::keyedHash
	(m_ui.question_authenticate->text().toUtf8(),
	 m_ui.answer_authenticate->text().toUtf8(),
	 m_ui.hashType->currentText().toLatin1(), &ok);

      if(!ok)
	error = "keyed hash failure";
    }

  if(!computedHash.isEmpty() &&
     !saltedPassphraseHash.isEmpty() &&
     spoton_crypt::memcmp(computedHash, saltedPassphraseHash))
    if(error.isEmpty())
      {
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	QPair<QByteArray, QByteArray> keys;

	if(m_ui.passphrase_rb_authenticate->isChecked())
	  keys = spoton_crypt::derivedKeys
	    (m_ui.cipherType->currentText(),
	     m_ui.hashType->currentText(),
	     static_cast<unsigned long int> (m_ui.iterationCount->value()),
	     m_ui.passphrase->text(),
	     salt,
	     false,
	     error);
	else
	  keys = spoton_crypt::derivedKeys
	    (m_ui.cipherType->currentText(),
	     m_ui.hashType->currentText(),
	     static_cast<unsigned long int> (m_ui.iterationCount->value()),
	     m_ui.question_authenticate->text() +
	     m_ui.answer_authenticate->text(),
	     salt,
	     false,
	     error);

	QApplication::restoreOverrideCursor();

	if(error.isEmpty())
	  {
	    authenticated = true;

	    QHashIterator<QString, spoton_crypt *> it(m_crypts);

	    while(it.hasNext())
	      {
		it.next();
		delete it.value();
	      }

	    m_crypts.clear();

	    auto list(spoton_common::SPOTON_ENCRYPTION_KEY_NAMES +
		      spoton_common::SPOTON_SIGNATURE_KEY_NAMES);

	    std::sort(list.begin(), list.end());

	    for(int i = 0; i < list.size(); i++)
	      m_crypts.insert
		(list.at(i),
		 new spoton_crypt
		 (m_ui.cipherType->currentText(),
		  m_ui.hashType->currentText(),
		  QByteArray(),
		  keys.first,
		  keys.second,
		  m_ui.saltLength->value(),
		  static_cast<unsigned long int> (m_ui.
						  iterationCount->
						  value()),
		  list.at(i)));

	    QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	    spoton_misc::alterDatabasesAfterAuthentication
	      (m_crypts.value("chat", nullptr));
	    spoton_misc::prepareAuthenticationHint
	      (m_crypts.value("chat", nullptr));
	    spoton_crypt::removeFlawedEntries(m_crypts.value("chat", nullptr));
	    QApplication::restoreOverrideCursor();

	    if(m_optionsUi.launchKernel->isChecked())
	      slotActivateKernel();

	    m_sb.frame->setEnabled(true);
	    m_sb.lock->setEnabled(true);
#ifdef SPOTON_POPTASTIC_SUPPORTED
	    m_sb.pop_poptastic->setEnabled(true);
#endif
#if SPOTON_GOLDBUG == 0
	    m_ui.action_Add_Participant->setEnabled(true);
#endif
	    m_ui.action_Echo_Key_Share->setEnabled(true);
	    m_ui.action_Export_Listeners->setEnabled(true);
	    m_ui.action_Export_Public_Keys->setEnabled(true);
	    m_ui.action_Import_Neighbors->setEnabled(true);
	    m_ui.action_Import_Public_Keys->setEnabled(true);
	    m_ui.action_Minimal_Display->setEnabled(true);
	    m_ui.action_New_Global_Name->setEnabled(true);
	    m_ui.action_Notifications_Window->setEnabled(true);
	    m_ui.action_Options->setEnabled(true);
#ifdef SPOTON_POPTASTIC_SUPPORTED
	    m_ui.action_Poptastic_Settings->setEnabled(true);
#endif
	    m_ui.action_Purge_Ephemeral_Keys->setEnabled(true);
	    m_ui.action_RSS->setEnabled(true);
	    m_ui.action_Rosetta->setEnabled(true);
	    m_ui.action_SMP->setEnabled(true);
	    m_ui.action_Statistics_Window->setEnabled(true);
	    m_ui.action_Vacuum_Databases->setEnabled(true);
	    m_ui.answer->clear();
	    m_ui.answer_authenticate->clear();
	    m_ui.delete_key->setEnabled(true);
	    m_ui.encryptionKeySize->setEnabled(false);
	    m_ui.encryptionKeyType->setEnabled(false);
	    m_ui.kernelBox->setEnabled(true);
	    m_ui.kernelBox->setVisible(true);
	    m_ui.keys->setEnabled(true);
	    m_ui.menu_Pages->setEnabled(true);
	    m_ui.newKeys->setEnabled(true);
	    m_ui.passphrase->clear();
	    m_ui.passphrase->clear();
	    m_ui.passphrase->setEnabled(false);
	    m_ui.passphrase1->clear();
	    m_ui.passphrase2->clear();
	    m_ui.passphraseButton->setEnabled(false);
	    m_ui.passphrase_rb_authenticate->setChecked(true);
	    m_ui.passphrase_rb_authenticate->setEnabled(false);
	    m_ui.publicKeysBox->setVisible(true);
	    m_ui.question->clear();
	    m_ui.question_authenticate->clear();
	    m_ui.question_rb_authenticate->setEnabled(false);
	    m_ui.regenerate->setEnabled(true);
	    m_ui.showStatistics->setVisible(true);
	    m_ui.signatureKeySize->setEnabled(false);
	    m_ui.signatureKeyType->setEnabled(false);

	    for(int i = 0; i < m_ui.tab->count(); i++)
	      {
		m_ui.tab->setTabEnabled(i, true);

		auto hash(m_tabWidgetsProperties[i]);

		hash["enabled"] = true;
		m_tabWidgetsProperties[i] = hash;
	      }

	    {
	      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	      auto const list
		(spoton_misc::
		 poptasticSettings("",
				   m_crypts.value("chat", nullptr),
				   nullptr));

	      for(int i = 0; i < list.size(); i++)
		{
		  if(i == 0)
		    m_ui.emailName->insertSeparator(1);

		  m_ui.emailName->addItem
		    (list.at(i).value("in_username").toString());
		}

	      QApplication::restoreOverrideCursor();
	    }

	    QApplication::setOverrideCursor(Qt::WaitCursor);
	    sendKeysToKernel();
	    askKernelToReadStarBeamKeys();
	    populateNovas();
	    populateUrlDistillers();
	    prepareUrlContainers();
	    prepareUrlLabels();
	    prepareVisiblePages();
	    sendBuzzKeysToKernel();
	    QApplication::restoreOverrideCursor();
	    m_rss->prepareAfterAuthentication();
	    m_smpWindow->populateSecrets();

	    QString name("");
	    QString nameEmail("");

	    if(m_crypts.value("chat", nullptr))
	      {
		QByteArray bytes;
		QSettings settings;
		auto ok = true;

		bytes = m_crypts.value("chat")->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(settings.
					  value("gui/poptasticName").
					  toByteArray()), &ok).trimmed();

		if(ok)
		  name = bytes;

		bytes = m_crypts.value("chat")->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(settings.
					  value("gui/poptasticNameEmail").
					  toByteArray()), &ok).trimmed();

		if(ok)
		  nameEmail = bytes;
	      }

	    if(name.isEmpty())
	      name = "unknown@unknown.org";

	    if(nameEmail.isEmpty())
	      {
		/*
		** Leave gui/poptasticNameEmail empty.
		** If Poptastic e-mail is written, the user will be required
		** to provide Poptastic information.
		*/
	      }

	    m_settings["gui/poptasticName"] = name.toLatin1();
	    m_settings["gui/poptasticNameEmail"] = nameEmail.toLatin1();

	    if(!m_settings.value("gui/initial_url_distillers_defined",
				 false).toBool())
	      {
		QApplication::setOverrideCursor(Qt::WaitCursor);
		initializeUrlDistillers();

		QSettings settings;

		settings.setValue("gui/initial_url_distillers_defined",
				  true);
		m_settings["gui/initial_url_distillers_defined"] = true;
		populateUrlDistillers();
		QApplication::restoreOverrideCursor();
	      }

	    if(!m_settings.value("gui/spot_on_neighbors_txt_processed",
				 false).toBool())
	      {
		importNeighbors(":/Data/spot-on-neighbors.txt");

		QSettings settings;

		settings.setValue("gui/spot_on_neighbors_txt_processed",
				  true);
		m_settings["gui/spot_on_neighbors_txt_processed"] = true;
	      }

	    if(m_optionsUi.refreshEmail->isChecked())
	      {
		populateMail();
		refreshInstitutions();
	      }

	    QApplication::setOverrideCursor(Qt::WaitCursor);
	    m_echoKeyShare->createDefaultUrlCommunity();
	    QApplication::restoreOverrideCursor();
	  }
      }

  m_ui.answer->clear();
  m_ui.passphrase->clear();
  m_ui.question->clear();

  if(!authenticated)
    m_ui.passphrase->selectAll();
  else
    {
#if SPOTON_GOLDBUG == 1
      slotConnectAllNeighbors();
#endif
      playSound("login.wav");
      updatePublicKeysLabel();

#if SPOTON_GOLDBUG == 0
      if(m_settings.contains("gui/minimal"))
	slotShowMinimalDisplay
	  (m_settings.value("gui/minimal", false).toBool());
#endif

      m_ui.tab->setCurrentIndex
	(m_settings.value("gui/currentTabIndex", m_ui.tab->count() - 1).
	 toInt());
      m_ui.tab->widget(m_ui.tab->currentIndex())->setFocus();
    }
}
