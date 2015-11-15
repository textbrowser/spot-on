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

#ifdef ANDROID
extern void _Exit(int status);
#endif

extern "C"
{
#include <curl/curl.h>
}

#include <iostream>

#include <QProgressDialog>
#include <QScopedPointer>
#include <QStandardItemModel>
#include <QThread>
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
#include <qbluetooth.h>
#endif
#include "spot-on.h"
#include "spot-on-defines.h"
#include "spot-on-buzzpage.h"
#include "ui_passwordprompt.h"

/*
** Not pleasant! Please avoid this solution!
*/

QList<int> spoton_common::LANE_WIDTHS = QList<int> () << 20000
                                                      << 25000
                                                      << 50000
                                                      << 75000;
QStringList spoton_common::ACCEPTABLE_URL_SCHEMES =
  QStringList() << "ftp" << "gopher" << "http" << "https";
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
const int spoton_common::KERNEL_URLS_BATCH_SIZE;
const int spoton_common::LANE_WIDTH_DEFAULT;
const int spoton_common::LANE_WIDTH_MAXIMUM;
const int spoton_common::LANE_WIDTH_MINIMUM;
const int spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::MAXIMUM_ATTEMPTS_PER_POPTASTIC_POST;
const int spoton_common::MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS;
const int spoton_common::MAXIMUM_KEYWORDS_IN_URL_DESCRIPTION;
const int spoton_common::MOSAIC_SIZE;
const int spoton_common::NAME_MAXIMUM_LENGTH;
const int spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::POPTASTIC_MAXIMUM_EMAIL_SIZE;
const int spoton_common::POPTASTIC_STATUS_INTERVAL;
const int spoton_common::REAP_POST_OFFICE_LETTERS_INTERVAL;
const int spoton_common::SEND_QUEUED_EMAIL_INTERVAL;
const int spoton_common::SPOTON_HOME_MAXIMUM_PATH_LENGTH;
const int spoton_common::STATUS_INTERVAL;
const int spoton_common::STATUS_TEXT_MAXIMUM_LENGTH;
const qint64 spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE;
const qint64 spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH;
const qint64 spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE;
const qint64 spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH;
const unsigned long spoton_common::GEMINI_ITERATION_COUNT;
int spoton_common::CACHE_TIME_DELTA_MAXIMUM =
  spoton_common::CACHE_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::CHAT_TIME_DELTA_MAXIMUM =
  spoton_common::CHAT_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
  spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::GEMINI_TIME_DELTA_MAXIMUM =
  spoton_common::GEMINI_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::MAIL_TIME_DELTA_MAXIMUM =
  spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
  spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
static QPointer<spoton> s_gui = 0;

#if QT_VERSION >= 0x050000
static void qt_message_handler(QtMsgType type,
			       const QMessageLogContext &context,
			       const QString &msg)
{
  Q_UNUSED(type);
  Q_UNUSED(context);
  spoton_misc::logError(QString("An error (%1) occurred.").arg(msg));
}
#else
static void qt_message_handler(QtMsgType type, const char *msg)
{
  Q_UNUSED(type);
  spoton_misc::logError(QString("An error (%1) occurred.").arg(msg));
}
#endif

static void signal_handler(int signal_number)
{
  static int fatal_error = 0;

  if(fatal_error)
    _Exit(signal_number);

  fatal_error = 1;
  spoton_crypt::terminate();

  /*
  ** _Exit() and _exit() may be safely called from signal handlers.
  */

  _Exit(signal_number);
}

int main(int argc, char *argv[])
{
  curl_global_init(CURL_GLOBAL_ALL);
  libspoton_enable_sqlite_cache();
  spoton_misc::prepareSignalHandler(signal_handler);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  QMacStyle *style = new (std::nothrow) QMacStyle();

  if(style)
    QApplication::setStyle(style);
#endif
#endif
#if QT_VERSION >= 0x050000
#ifdef Q_OS_WIN32
  QApplication::addLibraryPath("plugins");
  QApplication::setStyle("fusion");
#endif
  qInstallMessageHandler(qt_message_handler);
#else
  qInstallMsgHandler(qt_message_handler);
#endif

  QApplication qapplication(argc, argv);
  QThread *thread = qapplication.thread();

  if(!thread)
    thread = QThread::currentThread();

  if(thread)
    thread->setPriority(QThread::HighPriority);
  else
    qDebug() << "Cannot set the main thread's priority because "
      "the main thread does not exist.";

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
  /*
  ** Eliminate pool errors on OS X.
  */

  CocoaInitializer ci;
#endif
#endif

  /*
  ** Configure translations.
  */

  QTranslator qtTranslator;

  qtTranslator.load("qt_" + QLocale::system().name(), "Translations");
  qapplication.installTranslator(&qtTranslator);

  QTranslator myappTranslator;

  myappTranslator.load("spot-on_" + QLocale::system().name(),
		       "Translations");
  qapplication.installTranslator(&myappTranslator);
  QCoreApplication::setApplicationName("SpotOn");
  QCoreApplication::setOrganizationName("SpotOn");
  QCoreApplication::setOrganizationDomain("spot-on.sf.net");
  QCoreApplication::setApplicationVersion(SPOTON_VERSION_STR);
  QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                     spoton_misc::homePath());
  QSettings::setDefaultFormat(QSettings::IniFormat);

  QSettings settings;

#ifdef Q_OS_WIN32
  if(!settings.contains("gui/etpDestinationPath"))
    {
      QDir dir(QDir::currentPath());

      dir.mkdir("Mosaics");
      dir.cd("Mosaics");
      settings.setValue("gui/etpDestinationPath", dir.absolutePath());
    }
#else
  if(!settings.contains("gui/etpDestinationPath"))
    settings.setValue("gui/etpDestinationPath", QDir::homePath());
#endif

  if(!settings.contains("gui/gcryctl_init_secmem"))
    settings.setValue("gui/gcryctl_init_secmem", 262144);

  if(!settings.contains("gui/tcp_nodelay"))
    settings.setValue("gui/tcp_nodelay", 1);

  bool ok = true;
  int integer = settings.value("gui/gcryctl_init_secmem", 262144).
    toInt(&ok);

  if(integer < 131072 || integer > 999999999 || !ok)
    integer = 262144;

  spoton_crypt::init(integer);

  try
    {
      s_gui = new spoton();
      qapplication.exec();
      curl_global_cleanup();
      return EXIT_SUCCESS;
    }
  catch(const std::bad_alloc &exception)
    {
      std::cerr << "Critical memory failure. Exiting." << std::endl;
      curl_global_cleanup();
      return EXIT_FAILURE;
    }
}

spoton::spoton(void):QMainWindow()
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

	m_urlPrefixes << QString("%1%2").arg(c1).arg(c2);
      }

  m_locked = false;
  qsrand(static_cast<uint> (QTime(0, 0, 0).secsTo(QTime::currentTime())));
  spoton_smp::test1();
  spoton_smp::test2();
  spoton_smp::test3();
  QDir().mkdir(spoton_misc::homePath());
  m_keysShared["buzz_channels_sent_to_kernel"] = "false";
  m_keysShared["keys_sent_to_kernel"] = "false";
  m_buzzStatusTimer.setInterval(15000);
  m_buzzFavoritesLastModificationTime = QDateTime();
  m_kernelStatisticsLastModificationTime = QDateTime();
  m_magnetsLastModificationTime = QDateTime();
  m_listenersLastModificationTime = QDateTime();
  m_neighborsLastModificationTime = QDateTime();
  m_participantsLastModificationTime = QDateTime();
  m_echoKeyShare = new spoton_echo_key_share(&m_kernelSocket, this);
  m_starbeamAnalyzer = new spoton_starbeamanalyzer(this);
  m_starbeamReceivedModel = new QStandardItemModel(this);

  QStringList list;

  list << tr("Percent Received") << tr("File");
  m_starbeamReceivedModel->setHorizontalHeaderLabels(list);
  m_starsLastModificationTime = QDateTime();
  m_urlCommonCrypt = 0;
  m_ui.setupUi(this);
#if SPOTON_GOLDBUG == 0
  m_ui.version->setText
    (QString("<html><head/><body><p><a href=\"https://github.com/textbrowser/"
	     "spot-on/blob/master/branches/Documentation/RELEASE-NOTES.html\">"
	     "<span style=\" text-decoration: underline; color:#0000ff;\">"
	     "Spot-On Version %1</span></a></p></body></html>").
     arg(SPOTON_VERSION_STR));
#else
  m_ui.version->setText
    (QString("<html><head/><body><p><a href=\"https://github.com/textbrowser/"
	     "spot-on/blob/master/branches/Documentation/RELEASE-NOTES.html\">"
	     "<span style=\" text-decoration: underline; color:#0000ff;\">"
	     "%1</span></a></p></body></html>").
     arg(SPOTON_GOLDBUG_VERSION_STR));
#endif
  setWindowTitle
    (tr("%1").arg(SPOTON_APPLICATION_NAME));
  m_ui.listenerOrientation->model()->setData
    (m_ui.listenerOrientation->model()->index(1, 0), 0, Qt::UserRole - 1);
  m_ui.neighborOrientation->model()->setData
    (m_ui.neighborOrientation->model()->index(1, 0), 0, Qt::UserRole - 1);

  bool sslSupported = QSslSocket::supportsSsl();

  m_ui.buildInformation->setText
    (QString("Compiled on %1, %2.\n"
	     "%3.\n"
	     "Qt %4, %5-bit.\n"
	     "%6.\n"
	     "libgcrypt %7.\n"
	     "libspoton %8.").
     arg(__DATE__).
     arg(__TIME__).
     arg(sslSupported ?
	 SSLeay_version(SSLEAY_VERSION) :
	 "OpenSSL is not supported, according to Qt").
     arg(QT_VERSION_STR).arg(sizeof(void *) * 8).
     arg(curl_version()).
     arg(GCRYPT_VERSION).
     arg(LIBSPOTON_VERSION_STR));
  m_ui.statisticsBox->setVisible(false);
  m_ui.urlSettings->setVisible(true);
  m_ui.urlsBox->setVisible(false);
  m_ui.showUrlSettings->setChecked(true);
  m_ui.urls_db_type->model()->setData
    (m_ui.urls_db_type->model()->index(0, 0), 0, Qt::UserRole - 1);
  m_ui.goldbug->setEnabled(false);
  m_ui.postgresqlConnect->setEnabled(false);
  m_ui.postgresqlConnect->setVisible(false);

  foreach(QString driver, QSqlDatabase::drivers())
    if(driver.toLower().contains("qpsql"))
      {
	m_ui.postgresqlConnect->setEnabled(true);
	m_ui.urls_db_type->model()->setData
	  (m_ui.urls_db_type->model()->index(0, 0), QVariant(1 | 32),
	   Qt::UserRole - 1);
	break;
      }

#ifndef SPOTON_LINKED_WITH_LIBGEOIP
  m_ui.geoipPath4->setEnabled(false);
  m_ui.geoipPath4->setToolTip
    (tr("%1 was configured without "
	"libGeoIP.").arg(SPOTON_APPLICATION_NAME));
  m_ui.geoipPath6->setEnabled(false);
  m_ui.geoipPath6->setToolTip
    (tr("%1 was configured without "
	"libGeoIP.").arg(SPOTON_APPLICATION_NAME));
  m_ui.selectGeoIP4->setEnabled(false);
  m_ui.selectGeoIP4->setToolTip
    (tr("%1 was configured without "
	"libGeoIP.").arg(SPOTON_APPLICATION_NAME));
  m_ui.selectGeoIP6->setEnabled(false);
  m_ui.selectGeoIP6->setToolTip
    (tr("%1 was configured without "
	"libGeoIP.").arg(SPOTON_APPLICATION_NAME));
#endif
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
#if QT_VERSION >= 0x040700
  m_ui.search->setPlaceholderText(tr("Search"));
#endif
  m_optionsWindow = new QMainWindow(this);
  m_optionsUi.setupUi(m_optionsWindow);
  m_optionsWindow->setWindowTitle
    (tr("%1: Options").arg(SPOTON_APPLICATION_NAME));
  m_poptasticRetroPhoneDialog = new QDialog(this);
  m_poptasticRetroPhoneSettingsUi.setupUi(m_poptasticRetroPhoneDialog);
  m_sbWidget = new QWidget(this);
  m_sb.setupUi(m_sbWidget);
  m_sb.authentication_request->setVisible(false);
  m_sb.buzz->setVisible(false);
  m_sb.chat->setVisible(false);
  m_sb.email->setVisible(false);
  m_sb.forward_secrecy_request->setVisible(false);
  m_sb.status->setTextFormat(Qt::RichText);
#ifdef Q_OS_MAC
  foreach(QToolButton *toolButton, m_sbWidget->findChildren<QToolButton *> ())
    toolButton->setStyleSheet
    ("QToolButton {border: none;}"
     "QToolButton::menu-button {border: none;}");
#endif
#ifndef SPOTON_LINKED_WITH_LIBBOTAN
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
#if QT_VERSION < 0x050200 || !defined(SPOTON_BLUETOOTH_ENABLED)
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
#if SPOTON_GOLDBUG == 1
  m_optionsUi.position->model()->setData
    (m_optionsUi.position->model()->index(1, 0), 0, Qt::UserRole - 1);
  m_optionsUi.position->model()->setData
    (m_optionsUi.position->model()->index(2, 0), 0, Qt::UserRole - 1);
#endif
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
	  SIGNAL(iconsChanged(void)),
	  m_starbeamAnalyzer,
	  SLOT(slotSetIcons(void)));
  connect(this,
	  SIGNAL(starBeamReceivedAndVerified(const QString &)),
	  this,
	  SLOT(slotStarBeamReceivedAndVerified(const QString &)));
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
  connect(m_sb.forward_secrecy_request,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRespondToForwardSecrecy(void)));
  connect(m_sb.listeners,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.neighbors,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.errorlog,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(m_sb.kernelstatus,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotKernelStatus(void)));
  connect(m_sb.lock,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotLock(void)));
  connect(m_sb.status,
	  SIGNAL(linkActivated(const QString &)),
	  this,
	  SLOT(slotShareKeysWithKernel(const QString &)));
  statusBar()->addPermanentWidget(m_sbWidget, 100);
  statusBar()->setStyleSheet("QStatusBar::item {"
			     "border: none; "
			     "}");
  statusBar()->setMaximumHeight(m_sbWidget->height());
  connect(m_ui.action_About,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotAbout(void)));
  connect(m_ui.activeUrlDistribution,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotActiveUrlDistribution(bool)));
  connect(m_ui.actionClear_Clipboard_Buffer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClearClipboardBuffer(void)));
  connect(m_ui.action_Copy,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(m_ui.action_File_Encryption,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowEncryptFile(void)));
  connect(m_ui.action_Paste,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(m_ui.action_Purge_Ephemeral_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotPurgeEphemeralKeys(void)));
  connect(m_ui.copyInstitution,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopyInstitution(void)));
  connect(m_ui.action_Quit,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotQuit(void)));
  connect(m_optionsUi.action_Close,
	  SIGNAL(triggered(void)),
	  m_optionsWindow,
	  SLOT(close(void)));
  connect(m_ui.action_Options,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowOptions(void)));
  connect(m_ui.action_Echo_Key_Share,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewEchoKeyShare(void)));
  connect(m_ui.action_Log_Viewer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(m_ui.action_Rosetta,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewRosetta(void)));
  connect(m_ui.action_Minimal_Display,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowMinimalDisplay(bool)));
  connect(m_ui.addInstitution,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddInstitution(void)));
  connect(m_ui.addListener,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddListener(void)));
  connect(m_ui.addNeighbor,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddNeighbor(void)));
  connect(m_optionsUi.autoAddSharedSBMagnets,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAutoAddSharedSBMagnets(bool)));
  connect(m_optionsUi.buzzAutoJoin,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveBuzzAutoJoin(bool)));
  connect(m_optionsUi.refreshEmail,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveRefreshEmail(bool)));
  connect(m_ui.saveAttachment,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveAttachment(void)));
  connect(m_ui.dynamicdns,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
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
  connect(m_optionsUi.launchKernel,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotLaunchKernelAfterAuthentication(bool)));
  connect(m_optionsUi.limitConnections,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotLimitConnections(int)));
  connect(m_ui.ipv6Neighbor,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.activateKernel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotActivateKernel(void)));
  connect(m_ui.deactivateKernel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeactivateKernel(void)));
  connect(m_ui.etpSelectDestination,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectDestination(void)));
  connect(m_ui.selectGeoIP4,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectGeoIPPath(void)));
  connect(m_ui.selectGeoIP6,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectGeoIPPath(void)));
  connect(m_ui.selectKernelPath,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectKernelPath(void)));
  connect(m_ui.etpSelectFile,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectTransmitFile(void)));
  connect(m_ui.selectUrlIni,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectUrlIniPath(void)));
  connect(m_ui.setPassphrase,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.custom,
	  SIGNAL(textChanged(void)),
	  this,
	  SLOT(slotSaveCustomStatus(void)));
  connect(m_ui.passphrase1,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.passphrase2,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.destination,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveDestination(void)));
  connect(m_ui.geoipPath4,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveGeoIPPath(void)));
  connect(m_ui.geoipPath6,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveGeoIPPath(void)));
  connect(m_ui.kernelPath,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveKernelPath(void)));
  connect(m_ui.passphrase,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.answer_authenticate,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.question_authenticate,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.passphraseButton,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.tab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotTabChanged(int)));
  connect(m_ui.sendMessage,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(m_ui.message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(m_ui.clearMessages,
	  SIGNAL(clicked(void)),
	  m_ui.messages,
	  SLOT(clear(void)));
  connect(m_ui.saveBuzzName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveBuzzName(void)));
  connect(m_ui.saveNodeName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(m_ui.saveUrlName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveUrlName(void)));
  connect(m_ui.saveEmailName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveEmailName(void)));
  connect(m_ui.buzzName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveBuzzName(void)));
  connect(m_ui.guiExternalIpFetch,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotExternalIp(int)));
  connect(m_ui.kernelExternalIpFetch,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotExternalIp(int)));
  connect(m_ui.favorites,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotFavoritesActivated(int)));
  connect(m_ui.buzzActions,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotBuzzActionsActivated(int)));
  connect(m_ui.nodeName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(m_ui.emailName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveEmailName(void)));
  connect(m_ui.email_fs_gb,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotEmailFsGb(int)));
  connect(m_ui.urlName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveUrlName(void)));
  connect(m_optionsUi.scrambler,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotScramble(bool)));
  connect(m_optionsUi.impersonate,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotImpersonate(bool)));
  connect(m_ui.listenerIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddListener(void)));
  connect(m_ui.neighborIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddNeighbor(void)));
  connect(m_ui.listenerIPCombo,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotListenerIPComboChanged(int)));
  connect(m_ui.transmit,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTransmit(void)));
  connect(m_ui.listenerTransport,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotTransportChanged(int)));
  connect(m_ui.neighborTransport,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotTransportChanged(int)));
  connect(m_ui.folder,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotRefreshMail(void)));
  connect(m_optionsUi.chatSendMethod,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotChatSendMethodChanged(int)));
  connect(m_ui.status,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotStatusChanged(int)));
  connect(m_ui.kernelCipherType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotKernelCipherTypeChanged(int)));
  connect(m_ui.kernelHashType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotKernelHashTypeChanged(int)));
  connect(m_ui.addFriend,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddFriendsKey(void)));
  connect(m_ui.clearFriend,
	  SIGNAL(clicked(void)),
	  m_ui.friendInformation,
	  SLOT(clear(void)));
  connect(m_ui.action_ResetSpotOn,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotResetAll(void)));
  connect(m_ui.showStatistics,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotShowStatistics(void)));
  connect(m_ui.showUrlSettings,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotShowUrlSettings(bool)));
  connect(m_ui.sendMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMail(void)));
  connect(m_ui.resend,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotResendMail(void)));
  connect(m_ui.participants,
	  SIGNAL(itemChanged(QTableWidgetItem *)),
	  this,
	  SLOT(slotGeminiChanged(QTableWidgetItem *)));
  connect(m_ui.participants,
	  SIGNAL(itemDoubleClicked(QTableWidgetItem *)),
	  this,
	  SLOT(slotParticipantDoubleClicked(QTableWidgetItem *)));
  connect(m_ui.commonBuzzChannels,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotCommonBuzzChannelsActivated(int)));
  connect(m_optionsUi.acceptPublishedConnected,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_optionsUi.acceptPublishedDisconnected,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_optionsUi.ignorePublished,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_optionsUi.keepOnlyUserDefinedNeighbors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKeepOnlyUserDefinedNeighbors(bool)));
  connect(m_ui.clearOutgoing,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClearOutgoingMessage(void)));
  connect(m_ui.deleteInstitution,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteInstitution(void)));
  connect(m_ui.deleteEmail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteMail(void)));
  connect(m_ui.refreshMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshMail(void)));
  connect(m_ui.refreshMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshPostOffice(void)));
  connect(m_ui.mail,
	  SIGNAL(itemDoubleClicked(QTableWidgetItem *)),
	  this,
	  SLOT(slotMailSelected(QTableWidgetItem *)));
  connect(m_ui.mail,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotMailSelected(void)));
  connect(m_ui.neighbors,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotNeighborSelected(void)));
  connect(m_ui.listeners,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotListenerSelected(void)));
  connect(m_ui.transmitted,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotTransmittedSelected(void)));
  connect(m_ui.emptyTrash,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotEmptyTrash(void)));
  connect(m_ui.retrieveMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRetrieveMail(void)));
  connect(m_ui.mailTab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotMailTabChanged(int)));
  connect(m_optionsUi.enableChatEmoticons,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotEnableChatEmoticons(bool)));
  connect(m_ui.postofficeCheckBox,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotEnabledPostOffice(bool)));
  connect(m_ui.saveCopy,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKeepCopy(bool)));
  connect(m_optionsUi.icons,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSetIcons(int)));
  connect(m_optionsUi.iconsize,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSetIconSize(int)));
  connect(m_optionsUi.position,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotChangeTabPosition(int)));
  connect(m_ui.action_Export_Listeners,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotExportListeners(void)));
  connect(m_ui.action_Export_Public_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotExportPublicKeys(void)));
  connect(m_ui.action_Import_Neighbors,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotImportNeighbors(void)));
  connect(m_ui.action_Import_Public_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotImportPublicKeys(void)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.encryptionKeySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.signatureKeySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.encryptionKeyType,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.signatureKeyType,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotNewKeys(bool)));
  connect(m_ui.encryptionKeyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotEncryptionKeyTypeChanged(int)));
  connect(m_ui.signatureKeyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSignatureKeyTypeChanged(int)));
  connect(m_ui.cost,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotCostChanged(int)));
  connect(m_ui.days,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotDaysChanged(int)));
  connect(m_optionsUi.maximumEmailFileSize,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMaximumEmailFileSizeChanged(int)));
  connect(m_ui.etpMaxMosaicSize,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMaxMosaicSize(int)));
  connect(m_optionsUi.emailRetrievalInterval,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMailRetrievalIntervalChanged(int)));
  connect(m_ui.guiSecureMemoryPool,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSecureMemoryPoolChanged(int)));
  connect(m_ui.kernelSecureMemoryPool,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSecureMemoryPoolChanged(int)));
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
	  m_ui.sslKeySizeLabel,
	  SLOT(setEnabled(bool)));
  connect(m_ui.requireSsl,
	  SIGNAL(toggled(bool)),
	  m_ui.neighborsSslControlString,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.listenerKeySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.permanentCertificate,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.recordIPAddress,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.listenersSslControlString,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.days_valid,
	  SLOT(setEnabled(bool)));
  connect(m_optionsUi.publishPeriodically,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPublishPeriodicallyToggled(bool)));
  connect(m_ui.hideOfflineParticipants,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotHideOfflineParticipants(bool)));
  connect(m_ui.proxyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotProxyTypeChanged(int)));
  connect(m_optionsUi.publishedKeySize,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotPublishedKeySizeChanged(const QString &)));
  connect(m_ui.congestionAlgorithm,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotSaveCongestionAlgorithm(const QString &)));
  connect(m_ui.kernelKeySize,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotKernelKeySizeChanged(const QString &)));
  connect(m_optionsUi.superEcho,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSuperEcho(int)));
  connect(m_ui.kernelLogEvents,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKernelLogEvents(bool)));
  connect(m_ui.proxy,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProxyChecked(bool)));
  connect(m_ui.channel,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotJoinBuzzChannel(void)));
  connect(m_ui.acceptedIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddAcceptedIP(void)));
  connect(m_ui.addAEToken,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAEToken(void)));
  connect(m_ui.deleteAEToken,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAEToken(void)));
  connect(m_ui.sslControlString,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveSslControlString(void)));
  connect(m_ui.addNova,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddReceiveNova(void)));
  connect(m_ui.receiveNova,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddReceiveNova(void)));
  connect(m_ui.answer,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.question,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.urlIniPath,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSetUrlIniPath(void)));
  connect(m_ui.reloadIni,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSetUrlIniPath(void)));
  connect(m_ui.search,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotDiscover(void)));
  connect(m_ui.saveSslControlString,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveSslControlString(void)));
  connect(m_ui.join,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotJoinBuzzChannel(void)));
  connect(m_ui.buzzTab,
	  SIGNAL(tabCloseRequested(int)),
	  this,
	  SLOT(slotCloseBuzzTab(int)));
  connect(m_optionsUi.chatAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.acceptChatKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptChatKeys(bool)));
  connect(m_optionsUi.acceptEmailKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptEmailKeys(bool)));
  connect(m_optionsUi.acceptUrlKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptUrlKeys(bool)));
  connect(m_optionsUi.chatSignMessages,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.emailAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.emailSignMessages,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.urlSignMessages,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.coAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_optionsUi.urlAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_ui.addAcceptedIP,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAcceptedIP(void)));
  connect(m_ui.testSslControlString,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestSslControlString(void)));
  connect(m_ui.addAccount,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAccount(void)));
  connect(m_ui.deleteAccount,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAccount(void)));
  connect(m_ui.deleteAcceptedIP,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAccepedIP(void)));
  connect(m_ui.saveMOTD,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveMOTD(void)));
  connect(m_ui.deleteNova,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteNova(void)));
  connect(m_ui.buzzTools,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotBuzzTools(int)));
  connect(m_ui.magnetRadio,
	  SIGNAL(toggled(bool)),
	  m_ui.etpMagnet,
	  SLOT(setEnabled(bool)));
  connect(m_ui.magnetRadio,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotMagnetRadioToggled(bool)));
  connect(m_ui.pairRadio,
	  SIGNAL(toggled(bool)),
	  m_ui.pairFrame,
	  SLOT(setEnabled(bool)));
  connect(m_ui.pairRadio,
	  SIGNAL(toggled(bool)),
	  m_ui.generate,
	  SLOT(setEnabled(bool)));
  connect(m_optionsUi.autoEmailRetrieve,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAutoRetrieveEmail(bool)));
  connect(m_ui.generate,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotGenerateEtpKeys(int)));
  connect(m_ui.generateNova,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotGenerateNova(void)));
  connect(m_ui.addMagnet,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddEtpMagnet(void)));
  connect(m_ui.receivers,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotReceiversClicked(bool)));
  connect(m_ui.rewind,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRewindFile(void)));
  connect(m_optionsUi.acceptBuzzMagnets,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptBuzzMagnets(bool)));
  connect(m_optionsUi.forceRegistration,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotForceKernelRegistration(bool)));
  connect(m_ui.action_StarBeam_Analyzer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotShowStarBeamAnalyzer(void)));
  connect(m_ui.demagnetizeMissingLinks,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDemagnetizeMissingLinks(void)));
  connect(m_ui.missingLinksCheckBox,
	  SIGNAL(clicked(void)),
	  m_ui.missingLinks,
	  SLOT(clear(void)));
  connect(m_ui.missingLinksCheckBox,
	  SIGNAL(toggled(bool)),
	  m_ui.demagnetizeMissingLinks,
	  SLOT(setEnabled(bool)));
  connect(m_ui.missingLinksCheckBox,
	  SIGNAL(toggled(bool)),
	  m_ui.missingLinks,
	  SLOT(setEnabled(bool)));
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
  connect(m_optionsUi.displayPopups,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotDisplayPopups(bool)));
  connect(m_optionsUi.openlinks,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveOpenLinks(bool)));
  connect(m_ui.selectAttachment,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAttachment(void)));
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
	  m_ui.answer,
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
	  m_ui.answer_authenticate,
	  SLOT(setDisabled(bool)));
  connect(m_ui.passphrase_rb,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPassphraseRadioToggled(bool)));
  connect(m_ui.passphrase_rb_authenticate,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPassphraseAuthenticateRadioToggled(bool)));
  connect(m_ui.prepareUrlDatabases,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPrepareUrlDatabases(void)));
  connect(m_ui.deleteAllUrls,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAllUrls(void)));
  connect(m_ui.importUrls,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotImportUrls(void)));
  connect(m_ui.verify,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotVerify(void)));
  connect(m_ui.saveUrlCredentials,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveUrlCredentials(void)));
  connect(m_ui.saveCommonUrlCredentials,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveCommonUrlCredentials(void)));
  connect(m_ui.postgresqlConnect,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPostgreSQLConnect(void)));
  connect(m_optionsUi.chatUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.kernelUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.listenersUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.neighborsUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.starbeamUpdateInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_optionsUi.kernelCacheInterval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotUpdateSpinBoxChanged(double)));
  connect(m_ui.discover,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDiscover(void)));
  connect(m_ui.url_pages, SIGNAL(linkActivated(const QString &)),
	  this, SLOT(slotPageClicked(const QString &)));
  connect(m_ui.urls_db_type, SIGNAL(currentIndexChanged(int)),
	  this, SLOT(slotPostgreSQLDisconnect(int)));
  connect(m_optionsUi.acceptGeminis, SIGNAL(toggled(bool)),
	  this, SLOT(slotAcceptGeminis(bool)));
  connect(m_ui.action_Poptastic_Settings, SIGNAL(triggered(void)),
	  this, SLOT(slotConfigurePoptastic(void)));
  connect(m_ui.addDistiller,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddDistiller(void)));
  connect(m_ui.domain,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddDistiller(void)));
  connect(m_ui.refreshDistillers,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshUrlDistillers(void)));
  connect(m_ui.deleteDistillers,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteUrlDistillers(void)));
  connect(m_ui.urls,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotUrlLinkClicked(const QUrl &)));
  connect(m_ui.urlDistributionModel,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotSaveUrlDistribution(int)));
  connect(m_ui.correctUrlDatabases,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCorrectUrlDatabases(void)));
  connect(m_optionsUi.sharePrivateKeys,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveSharePrivateKeys(bool)));
  connect(m_optionsUi.starbeamAutoVerify,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveStarBeamAutoVerify(bool)));
  connect(m_optionsUi.chatAlternatingRowColors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveAlternatingColors(bool)));
  connect(m_optionsUi.emailAlternatingRowColors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveAlternatingColors(bool)));
  connect(m_optionsUi.urlsAlternatingRowColors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSaveAlternatingColors(bool)));
  connect(m_optionsUi.ontopChatDialogs,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotOntopChatDialogs(bool)));
  connect(m_optionsUi.remove_otm,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotRemoveOtmOnExit(bool)));
  connect(m_optionsUi.searchResultsPerPage,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSearchResultsPerPage(int)));
  connect(m_optionsUi.chat_fs_request,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAllowFSRequest(bool)));
  connect(m_optionsUi.email_fs_request,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAllowFSRequest(bool)));
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
  connect(&m_chatInactivityTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotChatInactivityTimeout(void)));
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotGeneralTimerTimeout(void)));
  connect(&m_updateChatWindowsTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotUpdateChatWindows(void)));
  connect(&m_tableTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateBuzzFavorites(void)));
  connect(&m_starbeamUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateEtpMagnets(void)));
  connect(&m_kernelUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateKernelStatistics(void)));
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
  connect(&m_starbeamUpdateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateStars(void)));
  connect(&m_emailRetrievalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotRetrieveMail(void)));
  connect(&m_kernelSocket,
	  SIGNAL(connected(void)),
	  this,
	  SLOT(slotKernelSocketState(void)));
  connect(&m_kernelSocket,
	  SIGNAL(disconnected(void)),
	  this,
	  SLOT(slotKernelSocketState(void)));
  connect(&m_kernelSocket,
	  SIGNAL(error(QAbstractSocket::SocketError)),
	  this,
	  SLOT(slotKernelSocketError(QAbstractSocket::SocketError)));
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
#ifdef Q_OS_OS2
  m_ui.ipv6Listener->setEnabled(false);
  m_ui.ipv6Neighbor->setEnabled(false);
#endif
  m_ui.passphrase_rb->setChecked(true);
  m_ui.passphrase_rb_authenticate->setChecked(true);
  m_ui.answer->setEnabled(false);
  m_ui.answer_authenticate->setEnabled(false);
  m_ui.question->setEnabled(false);
  m_ui.question_authenticate->setEnabled(false);
  m_ui.resend->setEnabled(false);
  m_sb.kernelstatus->setToolTip
    (tr("Not connected to the kernel. Is the kernel "
	"active?"));
  m_sb.listeners->setToolTip(tr("Listeners are offline."));
  m_sb.neighbors->setToolTip(tr("Neighbors are offline."));

  QMenu *menu = new QMenu(this);

  connect
    (menu->addAction(tr("Copy &Chat Public Key Pair")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyMyChatPublicKey(void)));
  connect
    (menu->addAction(tr("Copy &E-Mail Public Key Pair")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyMyEmailPublicKey(void)));
  connect
    (menu->addAction(tr("Copy &Poptastic Public Key Pair")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyMyPoptasticPublicKey(void)));
  connect
    (menu->addAction(tr("Copy &Rosetta Public Key Pair")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyMyRosettaPublicKey(void)));
  connect
    (menu->addAction(tr("Copy &URL Public Key Pair")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyMyURLPublicKey(void)));
  /*
  ** menu->addSeparator();
  ** connect(menu->addAction(tr("Copy &All Public Key Pairs")),
  ** SIGNAL(triggered(void)), this, SLOT(slotCopyAllMyPublicKeys(void)));
  */
  m_ui.commonBuzzChannels->setItemData
    (0,
     "magnet:?rn=Spot-On_Developer_Channel_Key&xf=10000&"
     "xs=Spot-On_Developer_Channel_Salt&ct=aes256&"
     "hk=Spot-On_Developer_Channel_Hash_Key&ht=sha512&xt=urn:buzz");
  m_ui.toolButtonCopyToClipboard->setMenu(menu);
  menu = new QMenu(this);
  m_ui.shareBuzzMagnet->setMenu(menu);
  m_generalTimer.start(3500);
  m_chatInactivityTimer.start(120000);
  m_updateChatWindowsTimer.start(3500);
  m_ui.ipv4Listener->setChecked(true);
  m_ui.listenerIP->setInputMask("");
  m_ui.addInstitutionLineEdit->setEnabled(false);
  m_ui.listenerScopeId->setEnabled(false);
  m_ui.listenerScopeIdLabel->setEnabled(false);
  m_ui.listenerShareAddress->setEnabled(false);
  m_ui.missingLinks->setEnabled(false);
  m_ui.neighborIP->setInputMask("");
  m_ui.neighborScopeId->setEnabled(false);
  m_ui.neighborScopeIdLabel->setEnabled(false);
#ifdef Q_OS_WIN32
  m_ui.emailParticipants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
  m_ui.participants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
  m_ui.urlParticipants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
#endif

  QSettings settings;

  settings.remove("gui/acceptUrlDL");
  settings.remove("gui/acceptUrlUL");
  settings.remove("gui/acceptedIPs");
  settings.remove("gui/applyPolarizers");
  settings.remove("gui/disable_kernel_synchronous_sqlite_url_download");
  settings.remove("gui/enableCongestionControl");
  settings.remove("gui/encryptionKey");
  settings.remove("gui/geoipPath");
  settings.remove("gui/keySize");
  settings.remove("gui/my_poptasticStatus");
  settings.remove("gui/poptasticName");
  settings.remove("gui/poptasticVerifyPopHostPeer");
  settings.remove("gui/poptasticVerifySmtpHostPeer");
  settings.remove("gui/rsaKeySize");
  settings.remove("gui/signatureKey");

  if(!settings.contains("gui/saveCopy"))
    settings.setValue("gui/saveCopy", true);

  if(!settings.contains("gui/uuid"))
    {
      QUuid uuid(QUuid::createUuid());

      settings.setValue("gui/uuid", uuid.toString());
    }

  for(int i = 0; i < settings.allKeys().size(); i++)
    m_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

  spoton_misc::correctSettingsContainer(m_settings);
  spoton_misc::setTimeVariables(m_settings);
  m_ui.activeUrlDistribution->setChecked
    (m_settings.value("gui/activeUrlDistribution", true).toBool());

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

  m_optionsUi.chatUpdateInterval->setValue
    (m_settings.value("gui/participantsUpdateTimer", 3.50).toDouble());
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
  QString str(m_settings.value("gui/tabPosition", "east").toString().
	      toLower());
#else
  QString str(m_settings.value("gui/tabPosition", "north").toString().
	      toLower());
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
  m_ui.geoipPath4->setText
    (m_settings.value("gui/geoipPath4",
		      "/usr/share/GeoIP/GeoIP.dat").toString());
  m_ui.geoipPath6->setText
    (m_settings.value("gui/geoipPath6",
		      "/usr/share/GeoIP/GeoIP.dat").toString());
#elif defined(Q_OS_WIN32)
  m_ui.geoipPath4->setText
    (m_settings.value("gui/geoipPath4", "GeoIP.dat").toString());
  m_ui.geoipPath6->setText
    (m_settings.value("gui/geoipPath6", "GeoIP.dat").toString());
#else
  m_ui.geoipPath4->setText
    (m_settings.value("gui/geoipPath4", "GeoIP.dat").toString());
  m_ui.geoipPath6->setText
    (m_settings.value("gui/geoipPath6", "GeoIP.dat").toString());
#endif
#endif
  m_ui.urlIniPath->setText
    (m_settings.value("gui/urlIniPath", "").toString());
  m_ui.magnetRadio->setChecked(true);
  m_ui.generate->setEnabled(false);
  m_ui.pairFrame->setEnabled(false);

#ifdef Q_OS_MAC
  if(m_settings.contains("gui/kernelPath") &&
     QFileInfo(m_settings.value("gui/kernelPath").toString()).
     isBundle())
    m_ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString());
  else if(m_settings.contains("gui/kernelPath") &&
	  QFileInfo(m_settings.value("gui/kernelPath").toString()).
	  isExecutable())
    m_ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString());
  else
    m_ui.kernelPath->setText
      ("/Applications/Spot-On.d/Spot-On-Kernel.app");
#else
  if(m_settings.contains("gui/kernelPath") &&
     QFileInfo(m_settings.value("gui/kernelPath").toString()).isExecutable())
    m_ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString());
  else
    {
      QString path(QCoreApplication::applicationDirPath() +
		   QDir::separator() +
#if defined(Q_OS_WIN32)
		   "Spot-On-Kernel.exe"
#else
		   "Spot-On-Kernel"
#endif
		   );

      m_ui.kernelPath->setText(path);
    }
#endif

  if(m_settings.value("gui/chatSendMethod", "Artificial_GET").
     toString().toLower() == "artificial_get")
    m_optionsUi.chatSendMethod->setCurrentIndex(1);
  else
    m_optionsUi.chatSendMethod->setCurrentIndex(0);

  QString keySize
    (m_settings.value("gui/kernelKeySize", "2048").toString());

  if(m_ui.kernelKeySize->findText(keySize) > -1)
    m_ui.kernelKeySize->setCurrentIndex
      (m_ui.kernelKeySize->findText(keySize));
  else
    m_ui.kernelKeySize->setCurrentIndex(0);

  keySize = m_settings.value("gui/publishedKeySize", "2048").toString();

  if(m_optionsUi.publishedKeySize->findText(keySize) > -1)
    m_optionsUi.publishedKeySize->setCurrentIndex
      (m_optionsUi.publishedKeySize->findText(keySize));
  else
    m_optionsUi.publishedKeySize->setCurrentIndex(0);

  QByteArray status
    (m_settings.value("gui/my_status", "Online").toByteArray().toLower());

  m_ui.custom->setText
    (QString::fromUtf8(m_settings.value("gui/customStatus", "").
		       toByteArray().trimmed()));
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
  if(!m_ui.geoipPath4->text().isEmpty())
    m_ui.geoipPath4->setToolTip(m_ui.geoipPath4->text());

  if(!m_ui.geoipPath6->text().isEmpty())
    m_ui.geoipPath6->setToolTip(m_ui.geoipPath6->text());
#endif

  /*
  ** Please note that Spot-On supports only ciphers having 256-bit
  ** keys.
  */

  m_ui.kernelPath->setToolTip(m_ui.kernelPath->text());
  m_ui.buzzName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.buzzName->setText
    (QString::fromUtf8(m_settings.value("gui/buzzName", "unknown").
		       toByteArray()).trimmed());
  m_ui.channel->setMaxLength
    (static_cast<int> (spoton_crypt::cipherKeyLength("aes256")));
  m_ui.emailName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.emailName->setText
    (QString::fromUtf8(m_settings.value("gui/emailName", "unknown").
		       toByteArray()).trimmed());
  m_ui.nodeName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.nodeName->setText
    (QString::fromUtf8(m_settings.value("gui/nodeName", "unknown").
		       toByteArray()).trimmed());
  m_ui.pulseSize->setMaximum(spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE);
  m_ui.urlName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.urlName->setText
    (QString::fromUtf8(m_settings.value("gui/urlName", "unknown").
		       toByteArray()).trimmed());
  m_ui.username->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.receiveNova->setMaxLength
    (static_cast<int> (spoton_crypt::cipherKeyLength("aes256")) + 512);
  m_ui.sslControlString->setText
    (m_settings.value("gui/sslControlString",
		      "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH").
     toString());
  m_ui.etpEncryptionKey->setMaxLength
    (static_cast<int> (spoton_crypt::cipherKeyLength("aes256")));
  m_ui.institutionName->setMaxLength
    (static_cast<int> (spoton_crypt::cipherKeyLength("aes256")));
  m_ui.transmitNova->setMaxLength
    (static_cast<int> (spoton_crypt::cipherKeyLength("aes256")) + 512);
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
  m_ui.buzzHashType->addItems(spoton_crypt::hashTypes());
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
  m_ui.etpMaxMosaicSize->setValue(m_settings.value("gui/maxMosaicSize",
						   512).toInt());
  m_optionsUi.emailRetrievalInterval->setValue
    (m_settings.value("gui/emailRetrievalInterval", 5).toInt());
  m_optionsUi.maximumEmailFileSize->setValue
    (m_settings.value("gui/maximumEmailFileSize", 100).toInt());

  QString statusControl
    (m_settings.
     value("gui/acceptPublicizedListeners",
	   "ignored").toString().toLower());

  if(statusControl == "connected")
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
  m_ui.saveCopy->setChecked
    (m_settings.value("gui/saveCopy", true).toBool());
  m_optionsUi.scrambler->setChecked
    (m_settings.value("gui/scramblerEnabled", false).toBool());
  m_optionsUi.starbeamAutoVerify->setChecked
    (m_settings.value("gui/starbeamAutoVerify", false).toBool());
  m_optionsUi.superEcho->setCurrentIndex
    (m_settings.value("gui/superEcho", 1).toInt());

  if(m_optionsUi.superEcho->currentIndex() < 0)
    m_optionsUi.superEcho->setCurrentIndex(1);

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
  m_ui.receivers->setChecked(m_settings.value("gui/etpReceivers",
					      false).toBool());
  m_optionsUi.autoEmailRetrieve->setChecked
    (m_settings.value("gui/automaticallyRetrieveEmail", false).toBool());
  m_optionsUi.acceptBuzzMagnets->setChecked
    (m_settings.value("gui/acceptBuzzMagnets", false).toBool());
  m_optionsUi.impersonate->setChecked
    (m_settings.value("gui/impersonate", false).toBool());
  m_optionsUi.displayPopups->setChecked
    (m_settings.value("gui/displayPopupsAutomatically", true).toBool());
  m_optionsUi.sharePrivateKeys->setChecked
    (m_settings.value("gui/sharePrivateKeysWithKernel", true).toBool());
  m_optionsUi.ontopChatDialogs->setChecked
    (m_settings.value("gui/ontopChatDialogs", false).toBool());
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
    m_ui.kernelHashType->setCurrentIndex
      (m_ui.kernelHashType->findText(str));

  str = m_settings.value("gui/hashType", "sha512").toString();

  if(m_ui.hashType->findText(str) > -1)
    m_ui.hashType->setCurrentIndex(m_ui.hashType->findText(str));

  str = m_settings.value("kernel/messaging_cache_algorithm",
			 "sha224").toString();

  if(m_ui.congestionAlgorithm->findText(str) > -1)
    m_ui.congestionAlgorithm->setCurrentIndex
      (m_ui.congestionAlgorithm->findText(str));

  m_ui.iterationCount->setValue(m_settings.value("gui/iterationCount",
						 10000).toInt());
  str = m_settings.value("gui/guiExternalIpInterval", "-1").toString();

  if(str == "30")
    m_ui.guiExternalIpFetch->setCurrentIndex(0);
  else if(str == "60")
    m_ui.guiExternalIpFetch->setCurrentIndex(1);
  else
    m_ui.guiExternalIpFetch->setCurrentIndex(2);

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
      m_ui.action_Echo_Key_Share->setEnabled(false);
      m_ui.action_Export_Listeners->setEnabled(false);
      m_ui.action_Import_Neighbors->setEnabled(false);
      m_ui.action_Export_Public_Keys->setEnabled(false);
      m_ui.action_Import_Public_Keys->setEnabled(false);
      m_ui.action_Options->setEnabled(false);
      m_ui.action_Poptastic_Settings->setEnabled(false);
      m_ui.action_Purge_Ephemeral_Keys->setEnabled(false);
      m_ui.action_Rosetta->setEnabled(false);
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.encryptionKeySize->setEnabled(false);
      m_ui.signatureKeySize->setEnabled(false);
      m_ui.keys->setEnabled(true);
      m_ui.regenerate->setEnabled(true);
      m_ui.signatureKeyType->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	if(i == m_ui.tab->count() - 1)
	  {
	    m_ui.tab->blockSignals(true);
	    m_ui.tab->setCurrentIndex(i);
	    m_ui.tab->blockSignals(false);
	    m_ui.tab->setTabEnabled(i, true);
	  }
	else
	  /*
	  ** About.
	  */

	  m_ui.tab->setTabEnabled(i, false);

      m_ui.passphrase->setFocus();
    }
  else
    {
      m_sb.frame->setEnabled(false);
      m_ui.action_Echo_Key_Share->setEnabled(false);
      m_ui.action_Export_Listeners->setEnabled(false);
      m_ui.action_Import_Neighbors->setEnabled(false);
      m_ui.action_Export_Public_Keys->setEnabled(false);
      m_ui.action_Import_Public_Keys->setEnabled(false);
      m_ui.action_Options->setEnabled(false);
      m_ui.action_Poptastic_Settings->setEnabled(false);
      m_ui.action_Purge_Ephemeral_Keys->setEnabled(false);
      m_ui.action_Rosetta->setEnabled(false);
      m_ui.answer_authenticate->setEnabled(false);
      m_ui.encryptionKeySize->setEnabled(false);
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.keys->setEnabled(false);
      m_ui.newKeys->setEnabled(true);
      m_ui.passphrase->setEnabled(false);
      m_ui.passphraseButton->setEnabled(false);
      m_ui.passphrase_rb_authenticate->setEnabled(false);
      m_ui.question_rb_authenticate->setEnabled(false);
      m_ui.regenerate->setEnabled(false);
      m_ui.signatureKeySize->setEnabled(false);
      m_ui.signatureKeyType->setEnabled(false);
      m_ui.kernelBox->setEnabled(false);

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

#if SPOTON_GOLDBUG == 1
  m_ui.action_Minimal_Display->setChecked(true);
#endif

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
  m_ui.guiSecureMemoryPool->setValue
    (m_settings.value("gui/gcryctl_init_secmem", 262144).toInt());
  m_ui.kernelSecureMemoryPool->setValue
    (m_settings.value("kernel/gcryctl_init_secmem", 262144).toInt());
  m_ui.destination->setToolTip(m_ui.destination->text());
  m_ui.emailParticipants->setAlternatingRowColors
    (m_optionsUi.emailAlternatingRowColors->isChecked());
  m_ui.participants->setAlternatingRowColors
    (m_optionsUi.chatAlternatingRowColors->isChecked());
  m_ui.urlParticipants->setAlternatingRowColors
    (m_optionsUi.urlsAlternatingRowColors->isChecked());
  m_ui.emailParticipants->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.etpMagnets->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.listeners->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.neighbors->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.participants->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.received->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.transmitted->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.transmittedMagnets->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.urlParticipants->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(m_ui.emailParticipants,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.urlParticipants,
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
  connect(m_ui.transmitted,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.transmittedMagnets,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.delete_key,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteKey(void)));
  connect(m_ui.regenerate,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRegenerateKey(void)));
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
  m_ui.mail->setColumnHidden(10, true); // OID
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
  m_ui.ae_tokens->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.emailParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.etpMagnets->horizontalHeader()->setSortIndicator
    (1, Qt::AscendingOrder);
  m_ui.addTransmittedMagnets->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.institutions->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.kernelStatistics->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.mail->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.listeners->horizontalHeader()->setSortIndicator
    (3, Qt::AscendingOrder);
  m_ui.neighbors->horizontalHeader()->setSortIndicator
    (1, Qt::AscendingOrder);
  m_ui.participants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.postoffice->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.received->horizontalHeader()->setSortIndicator
    (4, Qt::AscendingOrder);
  m_ui.transmitted->horizontalHeader()->setSortIndicator
    (5, Qt::AscendingOrder);
  m_ui.urlParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
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

  foreach(QAbstractButton *button,
	  m_ui.emailParticipants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  foreach(QAbstractButton *button,
	  m_ui.participants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  foreach(QAbstractButton *button,
	  m_ui.urlParticipants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));

  if(m_ui.guiExternalIpFetch->currentIndex() !=
     m_ui.guiExternalIpFetch->count() - 1)
    {
      m_externalAddress.discover();

      if(m_ui.guiExternalIpFetch->currentIndex() == 0)
	m_externalAddressDiscovererTimer.start(30000);
      else
	m_externalAddressDiscovererTimer.start(60000);
    }

#if SPOTON_GOLDBUG == 0
  str = m_settings.value("gui/iconSet", "nouve").toString().toLower();
#else
  str = m_settings.value("gui/iconSet", "nuvola").toString().toLower();
#endif

  if(str == "everaldo")
    m_optionsUi.icons->setCurrentIndex(0);
  else if(str == "nuvola")
    m_optionsUi.icons->setCurrentIndex(2);
  else
#if SPOTON_GOLDBUG == 0
    m_optionsUi.icons->setCurrentIndex(1);
#else
    m_optionsUi.icons->setCurrentIndex(2);
#endif

  slotSetIcons(m_optionsUi.icons->currentIndex());

#if SPOTON_GOLDBUG == 0
  QSize size(m_settings.value("gui/tabIconSize", QSize(24, 24)).toSize());
#else
  QSize size(m_settings.value("gui/tabIconSize", QSize(32, 32)).toSize());
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
      m_optionsUi.iconsize->setCurrentIndex(1);
      size = QSize(24, 24);
#else
      m_optionsUi.iconsize->setCurrentIndex(2);
      size = QSize(32, 32);
#endif
    }

  m_ui.tab->setIconSize(size);
  prepareContextMenuMirrors();
  prepareTimeWidgets();

  QList<QWidget *> widgets;

  widgets << m_ui.etpMagnet
	  << m_ui.friendInformation
	  << m_ui.motd
	  << m_ui.neighborSummary
	  << m_ui.searchfor
	  << m_ui.urls;

  for(int i = 0; i < widgets.size(); i++)
    {
      QFont font(widgets.at(i)->font());

      font.setStyleHint(QFont::Monospace);
      widgets.at(i)->setFont(font);
    }

  show();
  update();

  if(!QSqlDatabase::isDriverAvailable("QSQLITE"))
    QMessageBox::critical
      (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
       tr("The SQLite database driver QSQLITE is not available. "
	  "This is a fatal flaw."));
  else
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_sb.status->setText(tr("Preparing databases. Please be patient."));
      m_sb.status->repaint();
      spoton_misc::prepareDatabases();
      spoton_misc::prepareUrlDistillersDatabase();
      spoton_misc::prepareUrlKeysDatabase();
      m_sb.status->clear();
      QApplication::restoreOverrideCursor();
    }
}

spoton::~spoton()
{
}

void spoton::slotQuit(void)
{
  /*
  ** closeEvent() calls slotQuit().
  */

  if(sender())
    if(promptBeforeExit())
      return;

  cleanup();
}

void spoton::cleanup(void)
{
  if(m_settings.value("gui/removeOtmOnExit", false).toBool())
    spoton_misc::removeOneTimeStarBeamMagnets();

  m_starbeamDigestInterrupt.fetchAndStoreOrdered(1);

  while(!m_starbeamDigestFutures.isEmpty())
    {
      QFuture<void> future(m_starbeamDigestFutures.takeFirst());

      future.waitForFinished();
    }

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
  m_urlDatabase.close();
  m_urlDatabase = QSqlDatabase();

  if(QSqlDatabase::contains("URLDatabase"))
    QSqlDatabase::removeDatabase("URLDatabase");

  m_ui.url_database_connection_information->clear();
  saveSettings();
  delete m_urlCommonCrypt;

  QHashIterator<QString, spoton_crypt *> it(m_crypts);

  while(it.hasNext())
    {
      it.next();
      delete it.value();
    }

  m_crypts.clear();
  m_starbeamAnalyzer->deleteLater();
  spoton_crypt::terminate();
  QApplication::instance()->quit();
}

void spoton::slotAddListener(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  if(m_ui.listenerTransport->currentIndex() == 2 &&
     m_ui.permanentCertificate->isChecked() &&
     m_ui.sslListener->isChecked())
    {
      QHostAddress address;

      if(m_ui.recordIPAddress->isChecked())
	address = m_externalAddress.address();

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_sb.status->setText
	(tr("Generating SSL data. Please be patient."));
      m_sb.status->repaint();
      spoton_crypt::generateSslKeys
	(m_ui.listenerKeySize->currentText().toInt(),
	 certificate,
	 privateKey,
	 publicKey,
	 address,
	 60L * 60L * 24L * static_cast<long> (m_ui.days_valid->value()),
	 error);
      m_sb.status->clear();
      QApplication::restoreOverrideCursor();
    }

  QString connectionName("");
  bool ok = true;

  if(!error.isEmpty())
    {
      ok = false;
      spoton_misc::logError
	(QString("spoton::"
		 "slotAddListener(): "
		 "generateSslKeys() failure (%1).").arg(error));
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QByteArray hash;
	QString ip("");

	if(m_ui.listenerIPCombo->currentIndex() == 0)
	  ip = m_ui.listenerIP->text().trimmed();
	else
	  ip = m_ui.listenerIPCombo->currentText();

	QString port(QString::number(m_ui.listenerPort->value()));
	QString protocol("");
	QString scopeId(m_ui.listenerScopeId->text());
	QString sslCS(m_ui.listenersSslControlString->text().trimmed());
	QString status("online");
	QString transport("");
	QSqlQuery query(db);

	if(m_ui.listenerTransport->currentIndex() == 0)
	  scopeId = "";
	else
	  {
	    if(m_ui.ipv4Listener->isChecked())
	      protocol = "IPv4";
	    else
	      protocol = "IPv6";
	  }

	if(m_ui.listenerTransport->currentIndex() == 0)
	  transport = "bluetooth";
	else if(m_ui.listenerTransport->currentIndex() == 1)
	  transport = "sctp";
	else if(m_ui.listenerTransport->currentIndex() == 2)
	  transport = "tcp";
	else
	  transport = "udp";

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

	    if(protocol == "IPv4")
	      list = ip.split(".", QString::KeepEmptyParts);
	    else
	      list = ip.split(":", QString::KeepEmptyParts);

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

	if(m_ui.listenerTransport->currentIndex() == 2 &&
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

	if(m_ui.listenerTransport->currentIndex() == 0)
	  query.bindValue
	    (11, crypt->encryptedThenHashed("bluetooth", &ok).toBase64());
	else if(m_ui.listenerTransport->currentIndex() == 1)
	  query.bindValue
	    (11, crypt->encryptedThenHashed("sctp", &ok).toBase64());
	else if(m_ui.listenerTransport->currentIndex() == 2)
	  query.bindValue
	    (11, crypt->encryptedThenHashed("tcp", &ok).toBase64());
	else
	  query.bindValue
	    (11, crypt->encryptedThenHashed("udp", &ok).toBase64());

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

	if(sslCS.isEmpty())
	  sslCS = "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";

	if(!m_ui.sslListener->isChecked() || transport != "tcp")
	  sslCS = "N/A";

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

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(ok)
    m_ui.listenerIP->selectAll();
  else if(error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("Unable to add the specified listener. "
			     "Please enable logging via the Log Viewer "
			     "and try again."));
  else
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("An error (%1) occurred while attempting "
			     "to add the specified listener. "
			     "Please enable logging via the Log Viewer "
			     "and try again.").arg(error));
}

void spoton::slotAddNeighbor(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QString connectionName("");
  QString error("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QString ip(m_ui.neighborIP->text().trimmed());
	QString port(QString::number(m_ui.neighborPort->value()));
	QString protocol("");
	QString proxyHostName("");
	QString proxyPassword("");
	QString proxyPort("1");
	QString proxyType("");
	QString proxyUsername("");
	QString scopeId(m_ui.neighborScopeId->text());
	QString sslCS(m_ui.neighborsSslControlString->text().trimmed());
	QString status("connected");
	QString transport("");
	QSqlQuery query(db);

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

	if(m_ui.neighborTransport->currentIndex() == 0)
	  transport = "bluetooth";
	else if(m_ui.neighborTransport->currentIndex() == 1)
	  transport = "sctp";
	else if(m_ui.neighborTransport->currentIndex() == 2)
	  transport = "tcp";
	else
	  transport = "udp";

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
		      "ssl_control_string) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		      "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	query.bindValue(0, QVariant(QVariant::String));
	query.bindValue(1, QVariant(QVariant::String));
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

	QString country(spoton_misc::countryNameFromIPAddress(ip));

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

	if(m_ui.neighborTransport->currentIndex() == 2)
	  {
	    if(m_ui.requireSsl->isChecked())
	      query.bindValue
		(19, m_ui.neighborKeySize->currentText().toInt());
	    else
	      query.bindValue(19, 0);
	  }
	else
	  query.bindValue(19, 0);

	if(m_ui.addException->isChecked() &&
	   m_ui.neighborTransport->currentIndex() == 2)
	  query.bindValue(20, 1);
	else
	  query.bindValue(20, 0);

	if(ok)
	  query.bindValue
	    (21, crypt->encryptedThenHashed(QByteArray(),
					    &ok).toBase64());

	if(m_ui.neighborTransport->currentIndex() == 2)
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
	    else
	      query.bindValue
		(25, crypt->encryptedThenHashed("udp", &ok).toBase64());
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

	if(sslCS.isEmpty())
	  sslCS = "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";

	if(!m_ui.requireSsl->isChecked() || transport != "tcp")
	  sslCS = "N/A";

	query.bindValue(27, sslCS);

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

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    m_ui.neighborIP->selectAll();
  else if(error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("Unable to add the specified neighbor. "
			     "Please enable logging via the Log Viewer "
			     "and try again."));
  else
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("An error (%1) occurred while attempting "
			     "to add the specified neighbor. "
			     "Please enable logging via the Log Viewer "
			     "and try again.").arg(error));
}

void spoton::slotHideOfflineParticipants(bool state)
{
  m_settings["gui/hideOfflineParticipants"] = state;

  QSettings settings;

  settings.setValue("gui/hideOfflineParticipants", state);
  m_participantsLastModificationTime = QDateTime();
}

void spoton::slotProtocolRadioToggled(bool state)
{
  Q_UNUSED(state);

  QRadioButton *radio = qobject_cast<QRadioButton *> (sender());

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

void spoton::slotScramble(bool state)
{
  m_settings["gui/scramblerEnabled"] = state;

  QSettings settings;

  settings.setValue("gui/scramblerEnabled", state);
}

void spoton::slotPopulateListeners(void)
{
  if(currentTabName() != "listeners")
    return;

  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "listeners.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() > m_listenersLastModificationTime)
	m_listenersLastModificationTime = fileInfo.lastModified();
      else
	return;
    }
  else
    m_listenersLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateListenersTable(db);

	QModelIndexList list;
	QString ip("");
	QString port("");
	QString scopeId("");
	QString transportS("");
	QWidget *focusWidget = QApplication::focusWidget();
	int columnIP = 3;
	int columnPORT = 4;
	int columnSCOPE_ID = 5;
	int columnTRANSPORT = 15;
	int hval = m_ui.listeners->horizontalScrollBar()->value();
	int row = -1;
	int vval = m_ui.listeners->verticalScrollBar()->value();

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

	m_ui.listeners->setSortingEnabled(false);
	m_ui.listeners->clearContents();
	m_ui.listeners->setRowCount(0);

	QSqlQuery query(db);
	int totalRows = 0;

	query.setForwardOnly(true);
	query.exec("PRAGMA read_uncommitted = True");

	if(query.exec("SELECT COUNT(*) FROM listeners "
		      "WHERE status_control <> 'deleted'"))
	  if(query.next())
	    m_ui.listeners->setRowCount(query.value(0).toInt());

	if(query.exec("SELECT "
		      "status_control, "
		      "status, "
		      "ssl_key_size, "
		      "ip_address, "
		      "port, "
		      "scope_id, "
		      "protocol, "
		      "external_ip_address, "
		      "external_port, "
		      "connections, "
		      "maximum_clients, "
		      "echo_mode, "
		      "use_accounts, "
		      "maximum_buffer_size, "
		      "maximum_content_length, "
		      "transport, "
		      "share_udp_address, "
		      "certificate, "
		      "orientation, "
		      "ssl_control_string, "
		      "lane_width, "
		      "OID "
		      "FROM listeners WHERE status_control <> 'deleted'"))
	  {
	    row = 0;

	    while(query.next() && totalRows < m_ui.listeners->rowCount())
	      {
		totalRows += 1;

		QByteArray certificateDigest;
		QString tooltip("");
		QString transport("");
		bool ok = true;

		certificateDigest = crypt->
		  decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(17).toByteArray()),
		   &ok);

		if(!ok)
		  {
		    certificateDigest.clear();
		    certificateDigest.append(tr("error"));
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
		  transport = QString(crypt->
				      decryptedAfterAuthenticated
				      (QByteArray::
				       fromBase64(query.
						  value(15).
						  toByteArray()),
				       &ok).
				      constData()).toUpper();

		tooltip = QString
		  (tr("Status: %1\n"
		      "Bluetooth Flags / SSL Key Size: %2\n"
		      "Local IP: %3 Local Port: %4 Scope ID: %5\n"
		      "External IP: %6\n"
		      "Connections: %7\n"
		      "Echo Mode: %8\n"
		      "Use Accounts: %9\n"
		      "Transport: %10\n"
		      "Share Address: %11\n"
		      "Orientation: %12\n"
		      "SSL Control String: %13\n"
		      "Lane Width: %14")).
		  arg(query.value(1).toString().toLower()).
		  arg(query.value(2).toString()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(3).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(4).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(5).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(7).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(query.value(9).toString()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(11).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(query.value(12).toLongLong() ? "Yes" : "No").
		  arg(transport).
		  arg(query.value(16).toLongLong() ? "Yes" : "No").
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(18).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(query.value(19).toString()).
		  arg(query.value(20).toInt());

		for(int i = 0; i < query.record().count(); i++)
		  {
		    QTableWidgetItem *item = 0;

		    if(i == 0 || i == 12)
		      {
			QCheckBox *check = new QCheckBox();

			if(i == 0)
			  {
			    if(query.value(0).toString().
			       toLower() == "online")
			      check->setChecked(true);
			  }
			else
			  {
			    if(query.value(15).toString().toLower() == "tcp")
			      {
				if(query.value(2).toLongLong() > 0)
				  {
				    if(query.value(i).toLongLong())
				      check->setChecked(true);
				  }
				else
				  check->setEnabled(false);
			      }
			    else
			      {
				if(query.value(i).toLongLong())
				  check->setChecked(true);
			      }
			  }

			check->setProperty
			  ("oid", query.value(query.record().count() - 1));
			check->setToolTip(tooltip);

			if(i == 0)
			  connect(check,
				  SIGNAL(toggled(bool)),
				  this,
				  SLOT(slotListenerCheckChange(bool)));
			else
			  connect(check,
				  SIGNAL(toggled(bool)),
				  this,
				  SLOT(slotListenerUseAccounts(bool)));

			m_ui.listeners->setCellWidget(row, i, check);
		      }
		    else if(i == 2)
		      {
			if(transport.toLower() == "bluetooth")
			  {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
			    QComboBox *box = new QComboBox();
			    QList<QBluetooth::Security> items;
			    QMap<QBluetooth::Security, QString> map;
			    QMap<QBluetooth::SecurityFlags,
				 QString> possibilities;
			    QMap<QString, char> values;

			    items << QBluetooth::Authentication
				  << QBluetooth::Authorization
				  << QBluetooth::Encryption
				  << QBluetooth::Secure;
			    map[QBluetooth::Authentication] = "Authentication";
			    map[QBluetooth::Authorization] = "Authorization";
			    map[QBluetooth::Encryption] = "Encryption";
			    map[QBluetooth::Secure] = "Secure";

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
			    m_ui.listeners->setCellWidget(row, i, box);
#else
			    item = new QTableWidgetItem
			      (query.value(i).toString());

			    if(item->text().toInt() == 0)
			      item->setBackground
				(QBrush(QColor(240, 128, 128)));
			    else
			      item->setBackground(QBrush());
#endif
			  }
			else
			  {
			    if(query.value(i).toLongLong() == 0)
			      {
				item = new QTableWidgetItem("0");
				item->setBackground
				  (QBrush(QColor(240, 128, 128)));
			      }
			    else
			      {
				item = new QTableWidgetItem
				  (query.value(i).toString());
				item->setBackground(QBrush());
			      }
			  }
		      }
		    else if(i == 10)
		      {
			QComboBox *box = new QComboBox();

			if(transport != "UDP")
			  {
			    box->setProperty
			      ("oid", query.value(query.record().count() - 1));
			    box->addItem("1");

			    for(int j = 1; j <= 10; j++)
			      box->addItem(QString::number(5 * j));

			    box->addItem(tr("Unlimited"));
			    box->setMaximumWidth
			      (box->fontMetrics().width(tr("Unlimited")) + 50);
			    box->setToolTip
			      (tr("Please deactivate the listener before "
				  "changing the maximum connections value."));
			    m_ui.listeners->setCellWidget(row, i, box);

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
			    box->addItem("1");
			    box->setEnabled(false);
			    m_ui.listeners->setCellWidget(row, i, box);
			  }
		      }
		    else if(i == 13 || i == 14)
		      {
			// maximum_buffer_size
			// maximum_content_length

			QSpinBox *box = new QSpinBox();

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
			box->setWrapping(true);
			box->setMaximumWidth
			  (box->fontMetrics().
			   width(QString::
				 number(spoton_common::
					MAXIMUM_NEIGHBOR_BUFFER_SIZE)) + 50);
			box->setProperty
			  ("field_name", query.record().fieldName(i));
			box->setProperty
			  ("oid", query.value(query.record().count() - 1));
			box->setToolTip(tooltip);
			box->setValue
			  (static_cast<int> (query.value(i).toLongLong()));
			connect(box,
				SIGNAL(valueChanged(int)),
				this,
				SLOT(slotListenerMaximumChanged(int)));
			m_ui.listeners->setCellWidget(row, i, box);
		      }
		    else if(i == 17) // Certificate Digest
		      item = new QTableWidgetItem
			(certificateDigest.constData());
		    else if(i == 20) // Lane Width
		      {
			QComboBox *box = new QComboBox();
			QList<int> list;
			QSet<int> set;

			for(int j = 0;
			    j < spoton_common::LANE_WIDTHS.size(); j++)
			  set << spoton_common::LANE_WIDTHS.at(j);

			set << spoton_common::LANE_WIDTH_MINIMUM
			    << spoton_common::LANE_WIDTH_DEFAULT
			    << spoton_common::LANE_WIDTH_MAXIMUM;
			list = set.toList();
			qSort(list);

			while(!list.isEmpty())
			  box->addItem(QString::number(list.takeFirst()));

			box->setProperty
			  ("oid", query.value(query.record().count() - 1));
			box->setProperty("table", "listeners");
			m_ui.listeners->setCellWidget(row, i, box);

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
		      }
		    else
		      {
			if((i >= 3 && i <= 7) ||
			   i == 11 || i == 15 || i == 18)
			  {
			    if(query.isNull(i))
			      item = new QTableWidgetItem();
			    else
			      {
				item = new QTableWidgetItem
				  (crypt->
				   decryptedAfterAuthenticated
				   (QByteArray::
				    fromBase64(query.
					       value(i).
					       toByteArray()),
				    &ok).
				   constData());

				if(!ok)
				  item->setText(tr("error"));
			      }
			  }
			else
			  item = new QTableWidgetItem
			    (query.value(i).toString());
		      }

		    if(item)
		      {
			item->setFlags
			  (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
			item->setToolTip(tooltip);
			m_ui.listeners->setItem(row, i, item);

			if(i == 1)
			  {
			    if(query.value(i).toString().
			       toLower() == "online")
			      item->setBackground
				(QBrush(QColor("lightgreen")));
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
		   &ok).constData();

		if(ip == bytes1 && port == bytes2 && scopeId == bytes3 &&
		   transportS == bytes4)
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
	m_ui.listeners->verticalScrollBar()->setValue(vval);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  populateAETokens();
}

void spoton::slotPopulateNeighbors(void)
{
  if(currentTabName() != "neighbors")
    return;

  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "neighbors.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() > m_neighborsLastModificationTime)
	m_neighborsLastModificationTime = fileInfo.lastModified();
      else
	return;
    }
  else
    m_neighborsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateNeighborsTable(db);

	QModelIndexList list;
	QString proxyIp("");
	QString proxyPort("1");
	QString remoteIp("");
	QString remotePort("");
	QString scopeId("");
	QString transport("");
	QWidget *focusWidget = QApplication::focusWidget();
	int columnCOUNTRY = 9;
	int columnPROXY_IP = 14;
	int columnPROXY_PORT = 15;
	int columnREMOTE_IP = 10;
	int columnREMOTE_PORT = 11;
	int columnSCOPE_ID = 12;
	int columnTRANSPORT = 27;
	int hval = m_ui.neighbors->horizontalScrollBar()->value();
	int row = -1;
	int vval = m_ui.neighbors->verticalScrollBar()->value();

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
	m_ui.neighbors->setSortingEnabled(false);
	m_ui.neighbors->clearContents();
	m_ui.neighbors->setRowCount(0);

	QSqlQuery query(db);
	int totalRows = 0;

	query.setForwardOnly(true);
	query.exec("PRAGMA read_uncommitted = True");

	if(query.exec("SELECT COUNT(*) "
		      "FROM neighbors WHERE status_control <> 'deleted'"))
	  if(query.next())
	    m_ui.neighbors->setRowCount(query.value(0).toInt());

	if(query.exec("SELECT sticky, "
		      "uuid, "
		      "status, "
		      "ssl_key_size, "
		      "status_control, "
		      "local_ip_address, "
		      "local_port, "
		      "external_ip_address, "
		      "external_port, "
		      "country, "
		      "remote_ip_address, "
		      "remote_port, "
		      "scope_id, "
		      "protocol, "
		      "proxy_hostname, "
		      "proxy_port, "
		      "maximum_buffer_size, "
		      "maximum_content_length, "
		      "echo_mode, "
		      "uptime, "
		      "allow_exceptions, "
		      "certificate, "
		      "bytes_read, "
		      "bytes_written, "
		      "ssl_session_cipher, "
		      "account_name, "
		      "account_authenticated, "
		      "transport, "
		      "orientation, "
		      "motd, "
		      "is_encrypted, "
		      "0, " // Certificate
		      "ae_token, "
		      "ae_token_type, "
		      "ssl_control_string, "
		      "priority, "
		      "lane_width, "
		      "OID "
		      "FROM neighbors WHERE status_control <> 'deleted'"))
	  {
	    QString localIp("");
	    QString localPort("");

	    row = 0;

	    while(query.next() && totalRows < m_ui.neighbors->rowCount())
	      {
		totalRows += 1;

		QByteArray certificate;
		QByteArray certificateDigest;
		QByteArray sslSessionCipher;
		QLocale locale;
		QString priority("");
		QString tooltip("");
		bool isEncrypted = query.value
		  (query.record().indexOf("is_encrypted")).toBool();
		bool ok = true;

		certificate = certificateDigest = crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(21).
							 toByteArray()),
					      &ok);

		if(!ok)
		  {
		    certificate.clear();
		    certificateDigest.clear();
		    certificateDigest.append(tr("error"));
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

		if(!query.isNull(24))
		  {
		    sslSessionCipher = crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(24).
							     toByteArray()),
						  &ok);

		    if(!ok)
		      {
			sslSessionCipher.clear();
			sslSessionCipher.append(tr("error"));
		      }
		  }

		priority = query.value(35).toString().trimmed();

		if(priority.toInt() == 0)
		  priority = "Idle Priority";
		else if(priority.toInt() == 1)
		  priority = "Lowest Priority";
		else if(priority.toInt() == 2)
		  priority = "Low Priority";
		else if(priority.toInt() == 3)
		  priority = "Normal Priority";
		else if(priority.toInt() == 4)
		  priority = "High Priority";
		else if(priority.toInt() == 5)
		  priority = "Highest Priority";
		else if(priority.toInt() == 6)
		  priority = "Time-Critical Priority";
		else if(priority.toInt() == 7)
		  priority = "Inherit Priority";
		else
		  priority = "High Priority";

		tooltip =
		  (tr("UUID: %1\n"
		      "Status: %2\n"
		      "SSL Key Size: %3\n"
		      "Local IP: %4 Local Port: %5\n"
		      "External IP: %6\n"
		      "Country: %7 Remote IP: %8 Remote Port: %9 "
		      "Scope ID: %10\n"
		      "Proxy HostName: %11 Proxy Port: %12\n"
		      "Echo Mode: %13\n"
		      "Communications Mode: %14\n"
		      "Uptime: %15 Minutes\n"
		      "Allow Certificate Exceptions: %16\n"
		      "Bytes Read: %17\n"
		      "Bytes Written: %18\n"
		      "SSL Session Cipher: %19\n"
		      "Account Name: %20\n"
		      "Account Authenticated: %21\n"
		      "Transport: %22\n"
		      "Orientation: %23\n"
		      "SSL Control String: %24\n"
		      "Priority: %25\n"
		      "Lane Width: %26")).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(1).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(query.value(2).toString().toLower()).
		  arg(query.value(3).toString()).
		  arg(query.value(5).toString()).
		  arg(query.value(6).toString()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(7).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(9).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(10).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(11).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(12).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(14).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(15).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(18).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(isEncrypted ? "Secure" : "Insecure").
		  arg(QString::
		      number(static_cast<double> (query.value(19).
						  toLongLong()) /
			     60.00, 'f', 1)).
		  arg(query.value(21).toLongLong() ? "Yes" : "No").
		  arg(locale.toString(query.value(22).toULongLong())).
		  arg(locale.toString(query.value(23).toULongLong())).
		  arg(sslSessionCipher.constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(25).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(crypt->
		      decryptedAfterAuthenticated
		      (QByteArray::
		       fromBase64(query.
				  value(26).
				  toByteArray()),
		       &ok).toLongLong() ? "Yes": "No").
		  arg(QString(crypt->
			      decryptedAfterAuthenticated
			      (QByteArray::
			       fromBase64(query.
					  value(27).
					  toByteArray()),
			       &ok).
			      constData()).toUpper()).
		  arg(crypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(query.
							     value(28).
							     toByteArray()),
						  &ok).
		      constData()).
		  arg(query.value(34).toString()).
		  arg(priority).
		  arg(locale.toString(query.value(36).toInt()));

		QCheckBox *check = 0;

		check = new QCheckBox();
		check->setToolTip(tr("The sticky feature enables an "
				     "indefinite lifetime for a neighbor.\n"
				     "If "
				     "not checked, the neighbor will be "
				     "terminated after some internal "
				     "timer expires."));

		if(query.value(0).toLongLong())
		  check->setChecked(true);
		else
		  check->setChecked(false);

		check->setProperty
		  ("oid", query.value(query.record().count() - 1));
		connect(check,
			SIGNAL(toggled(bool)),
			this,
			SLOT(slotNeighborCheckChange(bool)));
		m_ui.neighbors->setCellWidget(row, 0, check);

		for(int i = 1; i < query.record().count(); i++)
		  {
		    QTableWidgetItem *item = 0;

		    if(i == 1 || i == 3 ||
		       i == 7 || (i >= 9 && i <= 13) || (i >= 14 &&
							 i <= 15) ||
		       i == 18 || i == 25 || i == 27 || i == 28 ||
		       i == 32 || i == 33)
		      {
			if(query.isNull(i))
			  item = new QTableWidgetItem();
			else
			  {
			    QByteArray bytes;

			    if(i != 3) // SSL Key Size
			      {
				bytes = crypt->decryptedAfterAuthenticated
				  (QByteArray::
				   fromBase64(query.
					      value(i).
					      toByteArray()),
				   &ok);

				if(!ok)
				  {
				    bytes.clear();
				    bytes.append(tr("error"));
				  }
			      }

			    if(i == 1) // uuid
			      {
				if(bytes.isEmpty())
				  bytes =
				    "{00000000-0000-0000-0000-000000000000}";
			      }
			    else if(i == 3) // SSL Key Size
			      {
				if(query.value(i).toLongLong() == 0)
				  {
				    item = new QTableWidgetItem("0");
				    item->setBackground
				      (QBrush(QColor(240, 128, 128)));
				  }
				else
				  {
				    item = new QTableWidgetItem
				      (query.value(i).toString());
				    item->setBackground(QBrush());
				  }
			      }

			    if(i != 3) // SSL Key Size
			      item = new QTableWidgetItem(bytes.constData());
			  }
		      }
		    else if(i >= 16 && i <= 17)
		      {
			// maximum_buffer_size
			// maximum_content_length

			QSpinBox *box = new QSpinBox();

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
			box->setWrapping(true);
			box->setMaximumWidth
			  (box->fontMetrics().
			   width(QString::
				 number(spoton_common::
					MAXIMUM_NEIGHBOR_BUFFER_SIZE)) + 50);
			box->setProperty
			  ("field_name", query.record().fieldName(i));
			box->setProperty
			  ("oid", query.value(query.record().count() - 1));
			box->setToolTip(tooltip);
			box->setValue
			  (static_cast<int> (query.value(i).toLongLong()));
			connect(box,
				SIGNAL(valueChanged(int)),
				this,
				SLOT(slotNeighborMaximumChanged(int)));
			m_ui.neighbors->setCellWidget(row, i, box);
		      }
		    else if(i == 19) // uptime
		      item = new QTableWidgetItem
			(locale.toString(query.value(i).toLongLong()));
		    else if(i == 21) // Certificate Digest
		      item = new QTableWidgetItem
			(certificateDigest.constData());
		    else if(i == 22 || i == 23) // bytes_read, bytes_written
		      item = new QTableWidgetItem
			(locale.toString(query.value(i).toLongLong()));
		    else if(i == 24) // SSL Session Cipher
		      item = new QTableWidgetItem
			(sslSessionCipher.constData());
		    else if(i == 26) // Account Authenticated
		      {
			if(!query.isNull(i))
			  {
			    item = new QTableWidgetItem
			      (crypt->decryptedAfterAuthenticated
			       (QByteArray::
				fromBase64(query.
					   value(i).
					   toByteArray()),
				&ok).constData());

			    if(ok)
			      {
				if(item->text() != "0")
				  item->setBackground
				    (QBrush(QColor("lightgreen")));
				else
				  item->setBackground
				    (QBrush(QColor(240, 128, 128)));
			      }
			    else
			      {
				item->setText(tr("error"));
				item->setBackground
				  (QBrush(QColor(240, 128, 128)));
			      }
			  }
			else
			  {
			    item = new QTableWidgetItem("0");
			    item->setBackground
			      (QBrush(QColor(240, 128, 128)));
			  }
		      }
		    else if(i == 29) // MOTD
		      item = new QTableWidgetItem
			(query.value(i).toString().trimmed());
		    else if(i == 31) // Certificate
		      item = new QTableWidgetItem(certificate.constData());
		    else if(i == 35) // Priority
		      item = new QTableWidgetItem(priority);
		    else if(i == 36) // Lane Width
		      {
			QComboBox *box = new QComboBox();
			QList<int> list;
			QSet<int> set;

			for(int j = 0;
			    j < spoton_common::LANE_WIDTHS.size(); j++)
			  set << spoton_common::LANE_WIDTHS.at(j);

			set << spoton_common::LANE_WIDTH_MINIMUM
			    << spoton_common::LANE_WIDTH_DEFAULT
			    << spoton_common::LANE_WIDTH_MAXIMUM;
			list = set.toList();
			qSort(list);

			while(!list.isEmpty())
			  box->addItem(QString::number(list.takeFirst()));

			box->setProperty
			  ("oid", query.value(query.record().count() - 1));
			box->setProperty("table", "neighbors");
			m_ui.neighbors->setCellWidget(row, i, box);

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
		      }
		    else
		      item = new QTableWidgetItem
			(query.value(i).toString());

		    if(item)
		      {
			item->setFlags
			  (Qt::ItemIsEnabled | Qt::ItemIsSelectable);

			if(i == 2)
			  {
			    if(query.value(i).toString().
			       toLower() == "connected")
			      item->setBackground
				(QBrush(QColor("lightgreen")));
			    else
			      item->setBackground(QBrush());

			    if(isEncrypted)
			      item->setIcon
				(QIcon(QString(":/%1/lock.png").
				       arg(m_settings.
					   value("gui/iconSet",
						 "nouve").toString().
					   toLower())));
			  }

			item->setToolTip(tooltip);
			m_ui.neighbors->setItem(row, i, item);
		      }
		  }

		QTableWidgetItem *item1 = m_ui.neighbors->item
		  (row, columnCOUNTRY);

		if(item1)
		  {
		    QIcon icon;
		    QPixmap pixmap;
		    QString str("");
		    QTableWidgetItem *item2 = m_ui.neighbors->item
		      (row, columnREMOTE_IP);

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
		  (QByteArray::fromBase64(query.value(columnREMOTE_IP).
					  toByteArray()), &ok);
		bytes2 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnREMOTE_PORT).
					  toByteArray()), &ok);
		bytes3 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnSCOPE_ID).
					  toByteArray()), &ok);
		bytes4 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnPROXY_IP).
					  toByteArray()), &ok);
		bytes5 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnPROXY_PORT).
					  toByteArray()), &ok);
		bytes6 = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(columnTRANSPORT).
					  toByteArray()), &ok);

		if(remoteIp == bytes1 && remotePort == bytes2 &&
		   scopeId == bytes3 && proxyIp == bytes4 &&
		   proxyPort == bytes5 && transport == bytes6)
		  m_ui.neighbors->selectRow(row);

		if(bytes3.isEmpty())
		  m_neighborToOidMap.insert
		    (bytes1 + ":" + bytes2,
		     query.value(query.record().count() - 1).toString());
		else
		  m_neighborToOidMap.insert
		    (bytes1 + ":" + bytes2 + ":" + bytes3,
		     query.value(query.record().count() - 1).toString());

		row += 1;
	      }

	    if(m_ui.neighbors->currentRow() == -1 || row == 0)
	      m_ui.neighborSummary->clear();
	  }
	else
	  m_ui.neighborSummary->clear();

	m_ui.neighbors->setRowCount(totalRows);
	m_ui.neighbors->setSortingEnabled(true);

	for(int i = 0; i < m_ui.neighbors->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.neighbors->resizeColumnToContents(i);

	m_ui.neighbors->horizontalHeader()->setStretchLastSection(true);
	m_ui.neighbors->horizontalScrollBar()->setValue(hval);
	m_ui.neighbors->verticalScrollBar()->setValue(vval);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotActivateKernel(void)
{
  QString program(m_ui.kernelPath->text());
  bool status = false;

#ifdef Q_OS_MAC
  if(QFileInfo(program).isBundle())
    {
      QStringList list;

      list << "-a" << program << "-g"
	   << "--args" << "--vacuum";

      status = QProcess::startDetached("open", list);
    }
  else
    status = QProcess::startDetached(program,
				     QStringList("--vacuum"));
#elif defined(Q_OS_WIN32)
  status = QProcess::startDetached(QString("\"%1\"").arg(program),
				   QStringList("--vacuum"));
#else
  status = QProcess::startDetached(program, QStringList("--vacuum"));
#endif

  if(status)
    if(m_settings.value("gui/buzzAutoJoin", true).toBool())
      joinDefaultBuzzChannel();
}

void spoton::slotDeactivateKernel(void)
{
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_handle_t libspotonHandle;

  if(libspoton_init_b(sharedPath.toStdString().c_str(),
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      &libspotonHandle,
		      m_settings.value("gui/gcryctl_init_secmem",
				       262144).
		      toInt()) == LIBSPOTON_ERROR_NONE)
    libspoton_deregister_kernel
      (libspoton_registered_kernel_pid(&libspotonHandle, 0),
       &libspotonHandle);

  libspoton_close(&libspotonHandle);
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
}

void spoton::slotGeneralTimerTimeout(void)
{
  QColor color(240, 128, 128); // Light coral!
  QPalette pidPalette(m_ui.pid->palette());
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  QString text(m_ui.pid->text());
  libspoton_handle_t libspotonHandle;

  pidPalette.setColor(m_ui.pid->backgroundRole(), color);

  if(libspoton_init_b(sharedPath.toStdString().c_str(),
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      &libspotonHandle,
		      m_settings.value("gui/gcryctl_init_secmem",
				       262144).
		      toInt()) == LIBSPOTON_ERROR_NONE)
    {
      libspoton_create_urls_table(&libspotonHandle);

      libspoton_error_t err = LIBSPOTON_ERROR_NONE;
      pid_t pid = 0;

      pid = libspoton_registered_kernel_pid(&libspotonHandle, &err);

      if(err == LIBSPOTON_ERROR_SQLITE_DATABASE_LOCKED || pid == 0)
	{
	  /*
	  ** Try next time.
	  */

	  m_ui.pid->setPalette(pidPalette);

	  if(pid == 0)
	    m_ui.pid->setText("0");
	  else
	    m_ui.pid->setText("-1");
	}
      else
	{
	  QColor color(144, 238, 144); // Light green!
	  QPalette palette(m_ui.pid->palette());

	  palette.setColor(m_ui.pid->backgroundRole(), color);
	  m_ui.pid->setPalette(palette);
	  m_ui.pid->setText(QString::number(pid));
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
    }
  else
    {
      m_ui.pid->setPalette(pidPalette);
      m_ui.pid->setText("-1");
    }

  libspoton_close(&libspotonHandle);
  highlightPaths();

  if(text != m_ui.pid->text())
    {
      m_buzzFavoritesLastModificationTime = QDateTime();
      m_kernelStatisticsLastModificationTime = QDateTime();
      m_magnetsLastModificationTime = QDateTime();
      m_listenersLastModificationTime = QDateTime();
      m_neighborsLastModificationTime = QDateTime();
      m_participantsLastModificationTime = QDateTime();
    }

  if(isKernelActive())
    if(m_kernelSocket.state() == QAbstractSocket::UnconnectedState)
      {
	QString connectionName("");
	quint16 port = 0;

	{
	  QSqlDatabase db = spoton_misc::database(connectionName);

	  db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			     "kernel.db");

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
	    m_kernelSocket.connectToHostEncrypted
	      ("127.0.0.1", port);
	  }
      }

  slotKernelSocketState();

  if(isKernelActive())
    {
      if(m_ui.buzzTab->count() > 0)
	{
	  if(!m_buzzStatusTimer.isActive())
	    m_buzzStatusTimer.start();
	}
      else
	m_buzzStatusTimer.stop();
    }
  else
    m_buzzStatusTimer.stop();

  if(!isKernelActive() ||
     m_sb.status->text() != tr("<html><a href=\"authenticate\">"
			       "The kernel requires your authentication "
			       "and encryption keys.</a></html>"))
    {
      m_sb.status->setText
	(tr("External IP: %1.").
	 arg(m_externalAddress.address().isNull() ?
	     "unknown" : m_externalAddress.address().toString()));
      m_sb.status->repaint();
    }

  for(int i = m_starbeamDigestFutures.size() - 1; i >= 0; i--)
    if(m_starbeamDigestFutures.at(i).isFinished())
      m_starbeamDigestFutures.removeAt(i);
}

void spoton::slotSelectGeoIPPath(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select GeoIP Data Path").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    {
      if(m_ui.selectGeoIP4 == sender())
	saveGeoIPPath(4, dialog.selectedFiles().value(0));
      else
	saveGeoIPPath(6, dialog.selectedFiles().value(0));
    }
}

void spoton::slotSelectKernelPath(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select Kernel Path").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    saveKernelPath(dialog.selectedFiles().value(0));
}

void spoton::slotSaveGeoIPPath(void)
{
  if(m_ui.geoipPath4 == sender())
    saveGeoIPPath(4, m_ui.geoipPath4->text());
  else
    saveGeoIPPath(6, m_ui.geoipPath6->text());
}

void spoton::slotSaveKernelPath(void)
{
  saveKernelPath(m_ui.kernelPath->text());
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
      m_ui.geoipPath4->setText(path);
      m_ui.geoipPath4->setToolTip(path);
      m_ui.geoipPath4->selectAll();
    }
  else
    {
      m_ui.geoipPath6->setText(path);
      m_ui.geoipPath6->setToolTip(path);
      m_ui.geoipPath6->selectAll();
    }
}

void spoton::saveKernelPath(const QString &path)
{
  m_settings["gui/kernelPath"] = path;

  QSettings settings;

  settings.setValue("gui/kernelPath", path);
  m_ui.kernelPath->setText(path);
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

void spoton::closeEvent(QCloseEvent *event)
{
  if(promptBeforeExit())
    {
      if(event)
	event->ignore();

      return;
    }

  slotQuit();
}

void spoton::slotDeleteListener(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool deleteListener = false;

	if(!isKernelActive())
	  {
	    deleteListener = true;
	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM listeners WHERE "
			  "OID = ?");
	  }
	else
	  query.prepare("UPDATE listeners SET status_control = 'deleted' "
			"WHERE "
			"OID = ? AND status_control <> 'deleted'");

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
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  {
	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM neighbors WHERE "
			  "OID = ?");
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
  m_ui.neighborSummary->clear();
}

void spoton::slotListenerCheckChange(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "listeners.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE listeners SET "
			  "status_control = ? "
			  "WHERE OID = ? AND status_control <> 'deleted'");

	    if(state)
	      query.bindValue(0, "online");
	    else
	      query.bindValue(0, "offline");

	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotListenerUseAccounts(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "listeners.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE listeners SET "
			  "use_accounts = ? WHERE OID = ?");

	    if(state)
	      query.bindValue(0, 1);
	    else
	      query.bindValue(0, 0);

	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::updateListenersTable(const QSqlDatabase &db)
{
  if(!isKernelActive())
    if(db.isOpen())
      {
	QSqlQuery query(db);

	/*
	** OK, so the kernel is inactive. Discover the
	** listeners that have not been deleted and update some of their
	** information.
	*/

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM listeners WHERE "
		   "status_control = 'deleted'");
	query.exec("DELETE FROM listeners_accounts WHERE "
		   "listener_oid NOT IN "
		   "(SELECT OID FROM listeners)");
	query.exec("DELETE FROM listeners_accounts_consumed_authentications "
		   "WHERE listener_oid >= 0");
	query.exec("DELETE FROM listeners_allowed_ips WHERE "
		   "listener_oid NOT IN "
		   "(SELECT OID FROM listeners)");
	query.exec("UPDATE listeners SET connections = 0, "
		   "external_ip_address = NULL, "
		   "status = 'offline' WHERE "
		   "status = 'online' OR connections > 0");
      }
}

void spoton::updateNeighborsTable(const QSqlDatabase &db)
{
  if(m_optionsUi.keepOnlyUserDefinedNeighbors->isChecked())
    if(db.isOpen())
      {
	/*
	** Delete random, disconnected peers.
	*/

	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM neighbors WHERE "
		   "status <> 'connected' AND "
		   "status_control <> 'blocked' AND "
		   "user_defined = 0");
      }

  if(!isKernelActive())
    if(db.isOpen())
      {
	QSqlQuery query(db);

	/*
	** OK, so the kernel is inactive. Discover the
	** neighbors that have not been deleted and not disconnected
	** and update some of their information.
	*/

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM neighbors WHERE "
		   "status_control = 'deleted'");
	query.exec("UPDATE neighbors SET "
		   "account_authenticated = NULL, "
		   "bytes_read = 0, "
		   "bytes_written = 0, "
		   "external_ip_address = NULL, "
		   "is_encrypted = 0, "
		   "local_ip_address = NULL, "
		   "local_port = NULL, "
		   "ssl_session_cipher = NULL, "
		   "status = 'disconnected', "
		   "uptime = 0 WHERE "
		   "local_ip_address IS NOT NULL OR local_port IS NOT NULL "
		   "OR status <> 'disconnected'");
      }
}

void spoton::updateParticipantsTable(const QSqlDatabase &db)
{
  if(!isKernelActive())
    if(db.isOpen())
      {
	QSqlQuery query(db);

	/*
	** OK, so the kernel is inactive. All participants are offline.
	*/

	query.exec("UPDATE friends_public_keys SET status = 'offline' WHERE "
		   "status <> 'offline'");
	spoton_misc::purgeSignatureRelationships
	  (db, m_crypts.value("chat", 0));
      }
}

void spoton::slotSetPassphrase(void)
{
  bool reencode = false;
  QString str1(m_ui.passphrase1->text());
  QString str2(m_ui.passphrase2->text());
  QString str3(m_ui.username->text());

  if(str3.trimmed().isEmpty())
    {
      str3 = "unknown";
      m_ui.username->setText(str3);
    }
  else
    m_ui.username->setText(str3.trimmed());

  if(!m_ui.passphrase_rb->isChecked())
    {
      str1 = m_ui.question->text();
      str2 = m_ui.answer->text();
    }

  if(str1.length() < 16 || str2.length() < 16)
    {
      if(m_ui.passphrase_rb->isChecked())
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("The passphrases must contain at least "
				 "sixteen characters each."));
      else
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("The answer and question must contain "
				 "at least sixteen characters each."));

      if(m_ui.passphrase_rb->isChecked())
	{
	  m_ui.passphrase1->selectAll();
	  m_ui.passphrase1->setFocus();
	}
      else
	{
	  m_ui.question->selectAll();
	  m_ui.question->setFocus();
	}

      return;
    }

  if(m_ui.passphrase_rb->isChecked() &&
     str1 != str2)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("The passphrases are not identical."));
      m_ui.passphrase1->selectAll();
      m_ui.passphrase1->setFocus();
      return;
    }

  if(str3.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Please provide a name."));
      m_ui.username->selectAll();
      m_ui.username->setFocus();
      return;
    }

  if(spoton_crypt::passphraseSet())
    {
      QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      mb.setIcon(QMessageBox::Question);
      mb.setWindowTitle(tr("%1: Confirmation").
			arg(SPOTON_APPLICATION_NAME));
      mb.setWindowModality(Qt::WindowModal);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);

      if(m_ui.passphrase_rb->isChecked())
	mb.setText(tr("Are you sure that you wish to replace the "
		      "existing passphrase? Please note that URL data must "
		      "be re-encoded via a separate tool. Please see "
		      "the future Re-Encode URLs option."));
      else
	mb.setText(tr("Are you sure that you wish to replace the "
		      "existing answer/question? Please note that URL "
		      "data must "
		      "be re-encoded via a separate tool. Please see "
		      "the future Re-Encode URLs option."));

      if(mb.exec() != QMessageBox::Yes)
	{
	  m_ui.answer->clear();
	  m_ui.passphrase1->clear();
	  m_ui.passphrase2->clear();
	  m_ui.question->clear();
	  return;
	}
      else
	reencode = true;
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
       static_cast<unsigned long> (m_ui.iterationCount->value()),
       str1,
       salt,
       error1);
  else
    derivedKeys = spoton_crypt::derivedKeys
      (m_ui.cipherType->currentText(),
       m_ui.hashType->currentText(),
       static_cast<unsigned long> (m_ui.iterationCount->value()),
       str1 + str2,
       salt,
       error1);

  m_sb.status->clear();
  QApplication::restoreOverrideCursor();

  if(error1.isEmpty())
    {
      slotDeactivateKernel();

      if(!m_ui.newKeys->isChecked() && reencode)
	{
	  if(m_crypts.value("chat", 0))
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
			      static_cast<unsigned long> (m_ui.
							  iterationCount->
							  value()),
			      "chat"));
	      QStringList list;

	      list << "chat"
		   << "chat-signature"
		   << "email"
		   << "email-signature"
		   << "poptastic"
		   << "poptastic-signature"
		   << "rosetta"
		   << "rosetta-signature"
	           << "url"
		   << "url-signature";

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
		     m_crypts.value("chat", 0), list.at(i), error2);
		  m_sb.status->clear();

		  if(!error2.isEmpty())
		    break;
		}

	      QApplication::restoreOverrideCursor();
	    }
	}
      else
	{
	  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	  mb.setIcon(QMessageBox::Question);
	  mb.setWindowTitle(tr("%1: Question").
			    arg(SPOTON_APPLICATION_NAME));
	  mb.setWindowModality(Qt::WindowModal);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText
	    (tr("Would you like to generate private and public keys?"));

	  if(mb.exec() == QMessageBox::Yes)
	    {
#ifndef Q_OS_MAC
	      QApplication::processEvents();
#endif

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

	      list << "chat"
		   << "chat-signature"
		   << "email"
		   << "email-signature"
		   << "poptastic"
		   << "poptastic-signature"
		   << "rosetta"
		   << "rosetta-signature"
		   << "url"
		   << "url-signature";

	      QProgressDialog progress(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	      progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	      progress.setLabelText(tr("Generating key pairs. "
				       "Please be patient."));
	      progress.setMaximum(list.size());
	      progress.setMinimum(0);
	      progress.setWindowModality(Qt::ApplicationModal);
	      progress.setWindowTitle(tr("%1: Generating Key Pairs").
				      arg(SPOTON_APPLICATION_NAME));
	      progress.show();
#ifndef Q_OS_MAC
	      QApplication::processEvents();
#endif

	      for(int i = 0; i < list.size() && !progress.wasCanceled(); i++)
		{
		  if(i + 1<= progress.maximum())
		    progress.setValue(i + 1);

#ifndef Q_OS_MAC
		  QApplication::processEvents();
#endif

		  spoton_crypt crypt
		    (m_ui.cipherType->currentText(),
		     m_ui.hashType->currentText(),
		     str1.toUtf8(), // Passphrase.
		     derivedKeys.first,
		     derivedKeys.second,
		     m_ui.saltLength->value(),
		     static_cast<unsigned long> (m_ui.iterationCount->
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
	  bool ok = true;

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
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("An error (%1) occurred with spoton_crypt::"
	    "derivedKeys().").arg(error1.trimmed()));
    }
  else if(!error2.trimmed().isEmpty())
    {
      spoton_crypt::purgeDatabases();
      updatePublicKeysLabel();
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("An error (%1) occurred with "
			       "spoton_crypt::"
			       "generatePrivatePublicKeys() or "
			       "spoton_crypt::"
			       "reencodePrivatePublicKeys().").
			    arg(error2.trimmed()));
    }
  else if(!error3.trimmed().isEmpty())
    {
      spoton_crypt::purgeDatabases();
      updatePublicKeysLabel();
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("An error (%1) occurred with "
			       "spoton_crypt::"
			       "keyedHash() or "
			       "spoton_crypt::"
			       "saltedPassphraseHash().").
			    arg(error3.trimmed()));
    }
  else
    {
      if(!m_crypts.value("chat", 0) || reencode)
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
			      static_cast<unsigned long> (m_ui.
							  iterationCount->
							  value()),
			      "chat"));

	      spoton_reencode reencode;

	      reencode.reencode
		(m_sb, crypt.data(), m_crypts.value("chat", 0));
	    }

	  QHashIterator<QString, spoton_crypt *> it(m_crypts);

	  while(it.hasNext())
	    {
	      it.next();
	      delete it.value();
	    }

	  m_crypts.clear();

	  QStringList list;

	  list << "chat"
	       << "chat-signature"
	       << "email"
	       << "email-signature"
	       << "poptastic"
	       << "poptastic-signature"
	       << "rosetta"
	       << "rosetta-signature"
	       << "url"
	       << "url-signature";

	  for(int i = 0; i < list.size(); i++)
	    m_crypts.insert
	      (list.at(i),
	       new spoton_crypt(m_ui.cipherType->currentText(),
				m_ui.hashType->currentText(),
				QByteArray(),
				derivedKeys.first,
				derivedKeys.second,
				m_ui.saltLength->value(),
				static_cast<unsigned long> (m_ui.
							    iterationCount->
							    value()),
				list.at(i)));

	  if(!reencode)
	    {
	      QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	      mb.setIcon(QMessageBox::Question);
	      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	      mb.setText(tr("Would you like to use your new "
			    "credentials as URL Common Credentials?"));

	      if(mb.exec() == QMessageBox::Yes)
		{
		  spoton_misc::prepareUrlKeysDatabase();

		  if(saveCommonUrlCredentials(derivedKeys,
					      m_ui.cipherType->currentText(),
					      m_ui.hashType->currentText(),
					      m_crypts.value("chat", 0)).
		     isEmpty())
		    {
		      prepareUrlContainers();
		      prepareUrlLabels();
		    }
		}
	    }

	  askKernelToReadStarBeamKeys();
	  populateNovas();
	  sendBuzzKeysToKernel();
	  sendKeysToKernel();
	  updatePublicKeysLabel();

	  if(!reencode)
	    {
	      QApplication::setOverrideCursor(Qt::WaitCursor);
	      m_echoKeyShare->createDefaultUrlCommunity();
	      QApplication::restoreOverrideCursor();
	    }
	}

      m_sb.frame->setEnabled(true);
      m_ui.action_Echo_Key_Share->setEnabled(true);
      m_ui.action_Export_Listeners->setEnabled(true);
      m_ui.action_Import_Neighbors->setEnabled(true);
      m_ui.action_Export_Public_Keys->setEnabled(true);
      m_ui.action_Import_Public_Keys->setEnabled(true);
      m_ui.action_Options->setEnabled(true);
      m_ui.action_Poptastic_Settings->setEnabled(true);
      m_ui.action_Purge_Ephemeral_Keys->setEnabled(true);
      m_ui.action_Rosetta->setEnabled(true);
      m_ui.answer->clear();
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.kernelBox->setEnabled(true);
      m_ui.encryptionKeySize->setEnabled(false);
      m_ui.signatureKeyType->setEnabled(false);
      m_ui.keys->setEnabled(true);
      m_ui.newKeys->setEnabled(true);
      m_ui.passphrase1->clear();
      m_ui.passphrase2->clear();
      m_ui.question->clear();
      m_ui.regenerate->setEnabled(true);
      m_ui.signatureKeyType->setEnabled(false);
      m_ui.newKeys->setChecked(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	m_ui.tab->setTabEnabled(i, true);

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
      m_ui.emailName->setText(m_ui.username->text());
      m_ui.nodeName->setText(m_ui.username->text());
      m_ui.urlName->setText(m_ui.username->text());

      if(!m_settings.value("gui/initial_url_distillers_defined",
			   false).toBool())
	{
	  initializeUrlDistillers();

	  QSettings settings;

	  settings.setValue("gui/initial_url_distillers_defined",
			    true);
	  m_settings["gui/initial_url_distillers_defined"] = true;
	  populateUrlDistillers();
	}

      if(!m_settings.value("gui/spot_on_neighbors_txt_processed",
			   false).toBool())
	{
	  importNeighbors("spot-on-neighbors.txt");

	  QSettings settings;

	  settings.setValue("gui/spot_on_neighbors_txt_processed",
			    true);
	  m_settings["gui/spot_on_neighbors_txt_processed"] = true;
	}

      QMessageBox::information
	(this, tr("%1: Information").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Your confidential information has been saved. "
	    "You are now ready to use the full power of %1. Enjoy!").
	 arg(SPOTON_APPLICATION_NAME));

      if(m_ui.pid->text() == "0")
	if(QFileInfo(m_ui.kernelPath->text()).isExecutable())
	  {
	    QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	    mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	    mb.setIcon(QMessageBox::Question);
	    mb.setWindowTitle(tr("%1: Question").
			      arg(SPOTON_APPLICATION_NAME));
	    mb.setWindowModality(Qt::WindowModal);
	    mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	    mb.setText(tr("Would you like the kernel to be activated?"));

	    if(mb.exec() == QMessageBox::Yes)
	      slotActivateKernel();
	  }

#if SPOTON_GOLDBUG == 1
      slotConnectAllNeighbors();
#endif
      playSong("login.wav");
    }
}

void spoton::slotValidatePassphrase(void)
{
  QByteArray computedHash;
  QByteArray salt(m_settings.value("gui/salt", "").toByteArray());
  QByteArray saltedPassphraseHash
    (m_settings.value("gui/saltedPassphraseHash", "").toByteArray());
  QString error("");
  bool authenticated = false;

  if(m_ui.passphrase_rb_authenticate->isChecked())
    computedHash = spoton_crypt::saltedPassphraseHash
      (m_ui.hashType->currentText(), m_ui.passphrase->text(), salt, error);
  else
    {
      bool ok = true;

      computedHash = spoton_crypt::keyedHash
	(m_ui.question_authenticate->text().toUtf8(),
	 m_ui.answer_authenticate->text().toUtf8(),
	 m_ui.hashType->currentText().toLatin1(), &ok);

      if(!ok)
	error = "keyed hash failure";
    }

  if(!computedHash.isEmpty() && !saltedPassphraseHash.isEmpty() &&
     spoton_crypt::memcmp(computedHash, saltedPassphraseHash))
    if(error.isEmpty())
      {
	authenticated = true;
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	QPair<QByteArray, QByteArray> keys;

	if(m_ui.passphrase_rb_authenticate->isChecked())
	  keys = spoton_crypt::derivedKeys
	    (m_ui.cipherType->currentText(),
	     m_ui.hashType->currentText(),
	     static_cast<unsigned long> (m_ui.iterationCount->value()),
	     m_ui.passphrase->text(),
	     salt,
	     error);
	else
	  keys = spoton_crypt::derivedKeys
	    (m_ui.cipherType->currentText(),
	     m_ui.hashType->currentText(),
	     static_cast<unsigned long> (m_ui.iterationCount->value()),
	     m_ui.question_authenticate->text() +
	     m_ui.answer_authenticate->text(),
	     salt,
	     error);

	QApplication::restoreOverrideCursor();

	if(error.isEmpty())
	  {
	    QHashIterator<QString, spoton_crypt *> it(m_crypts);

	    while(it.hasNext())
	      {
		it.next();
		delete it.value();
	      }

	    m_crypts.clear();

	    QStringList list;

	    list << "chat"
		 << "chat-signature"
		 << "email"
		 << "email-signature"
		 << "poptastic"
		 << "poptastic-signature"
		 << "rosetta"
		 << "rosetta-signature"
		 << "url"
		 << "url-signature";

	    for(int i = 0; i < list.size(); i++)
	      m_crypts.insert
		(list.at(i),
		 new spoton_crypt(m_ui.cipherType->currentText(),
				  m_ui.hashType->currentText(),
				  QByteArray(),
				  keys.first,
				  keys.second,
				  m_ui.saltLength->value(),
				  static_cast<unsigned long> (m_ui.
							      iterationCount->
							      value()),
				  list.at(i)));

	    if(m_optionsUi.launchKernel->isChecked())
	      slotActivateKernel();

	    m_sb.frame->setEnabled(true);
	    m_ui.passphrase_rb_authenticate->setChecked(true);
	    m_ui.action_Echo_Key_Share->setEnabled(true);
	    m_ui.action_Export_Listeners->setEnabled(true);
	    m_ui.action_Import_Neighbors->setEnabled(true);
	    m_ui.action_Export_Public_Keys->setEnabled(true);
	    m_ui.action_Import_Public_Keys->setEnabled(true);
	    m_ui.action_Options->setEnabled(true);
	    m_ui.action_Poptastic_Settings->setEnabled(true);
	    m_ui.action_Purge_Ephemeral_Keys->setEnabled(true);
	    m_ui.action_Rosetta->setEnabled(true);
	    m_ui.answer->clear();
	    m_ui.answer_authenticate->clear();
	    m_ui.encryptionKeyType->setEnabled(false);
	    m_ui.kernelBox->setEnabled(true);
	    m_ui.encryptionKeySize->setEnabled(false);
	    m_ui.signatureKeySize->setEnabled(false);
	    m_ui.keys->setEnabled(true);
	    m_ui.newKeys->setEnabled(true);
	    m_ui.passphrase->clear();
	    m_ui.passphrase->clear();
	    m_ui.passphrase1->clear();
	    m_ui.passphrase2->clear();
	    m_ui.passphrase->setEnabled(false);
	    m_ui.passphraseButton->setEnabled(false);
	    m_ui.passphrase_rb_authenticate->setEnabled(false);
	    m_ui.question->clear();
	    m_ui.question_authenticate->clear();
	    m_ui.question_rb_authenticate->setEnabled(false);
	    m_ui.regenerate->setEnabled(true);
	    m_ui.signatureKeyType->setEnabled(false);

	    for(int i = 0; i < m_ui.tab->count(); i++)
	      m_ui.tab->setTabEnabled(i, true);

	    askKernelToReadStarBeamKeys();
	    populateNovas();
	    populateUrlDistillers();
	    prepareUrlContainers();
	    prepareUrlLabels();
	    sendBuzzKeysToKernel();
	    m_ui.tab->setCurrentIndex
	      (m_settings.value("gui/currentTabIndex", m_ui.tab->count() - 1).
	       toInt());

	    QHash<QString, QVariant> hash;
	    bool ok = true;

	    hash = spoton_misc::poptasticSettings
	      (m_crypts.value("chat", 0), &ok);

	    if(ok)
	      m_poptasticRetroPhoneSettingsUi.in_username->setText
		(hash["in_username"].toString().trimmed());
	    else
	      m_poptasticRetroPhoneSettingsUi.in_username->setText
		("unknown@unknown.org");

	    m_settings["gui/poptasticName"] =
	      m_poptasticRetroPhoneSettingsUi.in_username->text().toUtf8();

	    if(!m_settings.value("gui/initial_url_distillers_defined",
				 false).toBool())
	      {
		initializeUrlDistillers();

		QSettings settings;

		settings.setValue("gui/initial_url_distillers_defined",
				  true);
		m_settings["gui/initial_url_distillers_defined"] = true;
	      }

	    if(!m_settings.value("gui/spot_on_neighbors_txt_processed",
				 false).toBool())
	      {
		importNeighbors("spot-on-neighbors.txt");

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
      playSong("login.wav");
      m_ui.passphrase->setFocus();
      updatePublicKeysLabel();
    }
}

void spoton::slotTabChanged(int index)
{
  if(currentTabName() == "listeners")
    m_listenersLastModificationTime = QDateTime();
  else if(currentTabName() == "neighbors")
    m_neighborsLastModificationTime = QDateTime();
  else if(currentTabName() == "starbeam")
    {
      m_magnetsLastModificationTime = QDateTime();
      m_starsLastModificationTime = QDateTime();
    }

  if(index == 0)
    m_sb.buzz->setVisible(false);
  else if(index == 1)
    m_sb.chat->setVisible(false);
}

void spoton::slotNeighborCheckChange(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE neighbors SET "
			  "sticky = ? "
			  "WHERE OID = ?");
	    query.bindValue(0, state ? 1 : 0);
	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotMaximumClientsChanged(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(comboBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "listeners.db");

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

void spoton::slotShowContextMenu(const QPoint &point)
{
  if(m_ui.emailParticipants == sender())
    {
      QAction *action = 0;
      QMenu menu(this);

      menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareEmailPublicKeyWithParticipant(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/generic/repleo-email.png"),
		     tr("&Copy Repleo to the clipboard buffer."),
		     this, SLOT(slotCopyEmailFriendshipBundle(void)));
      menu.addAction(QIcon(QString(":/%1/copy.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Copy keys to the clipboard buffer."),
		     this, SLOT(slotCopyEmailKeys(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Remove participant(s)."),
		     this, SLOT(slotRemoveEmailParticipants(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Rename participant."),
			      this, SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "email");
      menu.addSeparator();
      action = menu.addAction
	(tr("Initiate Forward &Secrecy exchange(s)."),
	 this, SLOT(slotEstablishForwardSecrecy(void)));
      action->setProperty("type", "email");
      action = menu.addAction
	(tr("Purge Forward &Secrecy key pair."),
	 this, SLOT(slotPurgeEphemeralKeyPair(void)));
      action->setProperty("type", "email");
      action = menu.addAction
	(tr("Reset Forward &Secrecy information."),
	 this, SLOT(slotResetForwardSecrecyInformation(void)));
      action->setProperty("type", "email");
      menu.exec(m_ui.emailParticipants->mapToGlobal(point));
    }
  else if(m_ui.listeners == sender())
    {
      QMenu menu(this);

      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"),
		     this, SLOT(slotDeleteListener(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteAllListeners(void)));
      menu.addSeparator();
      menu.addAction(tr("Detach &Neighbors"),
		     this, SLOT(slotDetachListenerNeighbors(void)));
      menu.addAction(tr("Disconnect &Neighbors"),
		     this, SLOT(slotDisconnectListenerNeighbors(void)));
      menu.addSeparator();
      menu.addAction(tr("&Publish Information (Plaintext)"),
		     this, SLOT(slotPublicizeListenerPlaintext(void)));
      menu.addAction(tr("Publish &All (Plaintext)"),
		     this, SLOT(slotPublicizeAllListenersPlaintext(void)));
      menu.addSeparator();
      menu.addAction(tr("&Full Echo"),
		     this, SLOT(slotListenerFullEcho(void)));
      menu.addAction(tr("&Half Echo"),
		     this, SLOT(slotListenerHalfEcho(void)));
      menu.addSeparator();
      menu.addAction(tr("Set &SSL Control String"),
		     this, SLOT(slotSetListenerSSLControlString(void)));
      menu.exec(m_ui.listeners->mapToGlobal(point));
    }
  else if(m_ui.neighbors == sender())
    {
      QAction *action = 0;
      QMenu menu(this);

      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &Chat Public Key Pair"),
		     this, SLOT(slotShareChatPublicKey(void)));
      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &E-Mail Public Key Pair"),
		     this, SLOT(slotShareEmailPublicKey(void)));
      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &Poptastic Public Key Pair"),
		     this, SLOT(slotSharePoptasticPublicKey(void)));
      menu.addAction(QIcon(QString(":%1//share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("Share &URL Public Key Pair"),
		     this, SLOT(slotShareURLPublicKey(void)));
      menu.addSeparator();
      menu.addAction(tr("&Assign New Remote IP Information"),
		     this, SLOT(slotAssignNewIPToNeighbor(void)));
      menu.addAction(tr("&Connect"),
		     this, SLOT(slotConnectNeighbor(void)));
      menu.addAction(tr("&Disconnect"),
		     this, SLOT(slotDisconnectNeighbor(void)));
      menu.addSeparator();
      menu.addAction(tr("&Connect All"),
		     this, SLOT(slotConnectAllNeighbors(void)));
      menu.addAction(tr("&Disconnect All"),
		     this, SLOT(slotDisconnectAllNeighbors(void)));
      menu.addSeparator();
      menu.addAction
	(tr("&Authenticate"),
	 this,
	 SLOT(slotAuthenticate(void)));
      menu.addAction(tr("&Reset Account Information"),
		     this,
		     SLOT(slotResetAccountInformation(void)));
      menu.addSeparator();
      menu.addAction(tr("&Reset Certificate"),
		     this,
		     SLOT(slotResetCertificate(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"),
		     this, SLOT(slotDeleteNeighbor(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteAllNeighbors(void)));
      menu.addAction(tr("Delete All Non-Unique &Blocked"),
		     this, SLOT(slotDeleteAllBlockedNeighbors(void)));
      menu.addAction(tr("Delete All Non-Unique &UUIDs"),
		     this, SLOT(slotDeleteAllUuids(void)));
      menu.addSeparator();
      menu.addAction(tr("B&lock"),
		     this, SLOT(slotBlockNeighbor(void)));
      menu.addAction(tr("U&nblock"),
		     this, SLOT(slotUnblockNeighbor(void)));
      menu.addSeparator();
      menu.addAction(tr("&Full Echo"),
		     this, SLOT(slotNeighborFullEcho(void)));
      menu.addAction(tr("&Half Echo"),
		     this, SLOT(slotNeighborHalfEcho(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Copy Adaptive Echo Magnet"),
			      this, SLOT(slotCopyAEMagnet(void)));
      action->setProperty("from", "neighbors");
      menu.addAction(tr("&Set Adaptive Echo Token Information"),
		     this, SLOT(slotSetAETokenInformation(void)));
      menu.addAction(tr("&Reset Adaptive Echo Token Information"),
		     this, SLOT(slotResetAETokenInformation(void)));
      menu.addSeparator();
      menu.addAction(tr("Set &SSL Control String"),
		     this, SLOT(slotSetNeighborSSLControlString(void)));
      menu.addSeparator();

      QList<QPair<QString, QThread::Priority> > list;
      QMenu *subMenu = menu.addMenu(tr("Priority"));
      QPair<QString, QThread::Priority> pair;

      pair.first = tr("High Priority");
      pair.second = QThread::HighPriority;
      list << pair;
      pair.first = tr("Highest Priority");
      pair.second = QThread::HighestPriority;
      list << pair;
      pair.first = tr("Idle Priority");
      pair.second = QThread::IdlePriority;
      list << pair;
      pair.first = tr("Inherit Priority");
      pair.second = QThread::InheritPriority;
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

      for(int i = 0; i < list.size(); i++)
	{
	  action = subMenu->addAction
	    (list.at(i).first,
	     this,
	     SLOT(slotSetNeighborPriority(void)));
	  action->setProperty("priority", list.at(i).second);
	}

      menu.exec(m_ui.neighbors->mapToGlobal(point));
    }
  else if(m_ui.participants == sender())
    {
      QAction *action = 0;
      QMenu menu(this);

      menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareChatPublicKeyWithParticipant(void)));
      menu.addSeparator();
      menu.addAction(tr("Chat &popup."), this,
		      SLOT(slotChatPopup(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/generic/repleo-chat.png"),
		     tr("&Copy Repleo to the clipboard buffer."),
		     this, SLOT(slotCopyFriendshipBundle(void)));
      menu.addSeparator();
#if SPOTON_GOLDBUG == 1
      action = menu.addAction(QIcon(QString(":/%1/melodica.png").
				    arg(m_settings.value("gui/iconSet",
							 "nouve").
					toString().toLower())),
			      tr("MELODICA: &Call friend with new "
				 "Gemini pair."),
			      this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu.addAction(QIcon(QString(":/%1/melodica.png").
				    arg(m_settings.value("gui/iconSet",
							 "nouve").
					toString().toLower())),
			      tr("MELODICA: &Call friend with new "
				 "Gemini pair using the "
				 "existing Gemini pair."),
			      this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_using_gemini");
      action = menu.addAction(QIcon(QString(":/%1/melodica.png").
				    arg(m_settings.value("gui/iconSet",
							 "nouve").
					toString().toLower())),
			      tr("MELODICA Two-Way: &Call friend with new "
				 "Gemini pair."),
			      this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_two_way");
#else
      action = menu.addAction(tr("&Call participant."),
			      this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu.addAction
	(tr("&Call participant using the existing Gemini pair."),
	 this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_using_gemini");
      action = menu.addAction(tr("&Two-way calling."),
			      this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_two_way");
#endif
      action = menu.addAction(tr("&Terminate call."),
			      this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "terminating");
      menu.addSeparator();
#if SPOTON_GOLDBUG == 1
      menu.addAction
	(tr("&Generate random Gemini pair "
	    "(AES-256 Key, SHA-512 Key) (without a call)."),
	 this, SLOT(slotGenerateGeminiInChat(void)));
#else
      menu.addAction(tr("&Generate random Gemini pair "
			"(AES-256 Key, SHA-512 Key)."),
		     this, SLOT(slotGenerateGeminiInChat(void)));
#endif
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Remove participant(s)."),
		     this, SLOT(slotRemoveParticipants(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Rename participant."),
			      this, SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "chat");
      menu.addSeparator();
      menu.addAction(tr("&Derive Gemini pair from SMP secret."),
		     this,
		     SLOT(slotDeriveGeminiPairViaSMP(void)));
      menu.addAction(tr("&Reset the SMP machine's internal state to s0."),
		     this,
		     SLOT(slotInitializeSMP(void)));
      menu.addAction(tr("&Set an SMP secret."),
		     this,
		     SLOT(slotPrepareSMP(void)));
      menu.addAction(tr("&Verify the SMP secret."),
		     this,
		     SLOT(slotVerifySMPSecret(void)));
      menu.addSeparator();
      menu.addAction(tr("Replay &last %1 messages.").
		     arg(spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE),
		     this,
		     SLOT(slotReplayMessages(void)));
      menu.addAction(tr("Share a &StarBeam."),
		     this,
		     SLOT(slotShareStarBeam(void)));
      menu.addSeparator();
      menu.addAction
	(tr("Call via Forward &Secrecy credentials."),
	 this, SLOT(slotCallParticipantViaForwardSecrecy(void)));
      action = menu.addAction
	(tr("Initiate Forward &Secrecy exchange(s)."),
	 this, SLOT(slotEstablishForwardSecrecy(void)));
      action->setProperty("type", "chat");
      action = menu.addAction
	(tr("Purge Forward &Secrecy key pair."),
	 this, SLOT(slotPurgeEphemeralKeyPair(void)));
      action->setProperty("type", "chat");
      action = menu.addAction
	(tr("Reset Forward &Secrecy information."),
	 this, SLOT(slotResetForwardSecrecyInformation(void)));
      action->setProperty("type", "chat");
      menu.exec(m_ui.participants->mapToGlobal(point));
    }
  else if(m_ui.received == sender())
    {
      QAction *action = 0;
      QMenu menu(this);

      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"), this,
		     SLOT(slotDeleteReceived(void)));
      menu.addAction(tr("Delete &All"), this,
		     SLOT(slotDeleteAllReceived(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Compute SHA-1 Hash"), this,
			      SLOT(slotComputeFileHash(void)));
      action->setProperty("widget_of", "received");
      menu.addSeparator();
      action = menu.addAction(tr("&Copy File Hash"), this,
			      SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "received");
      menu.addSeparator();
      menu.addAction(tr("Discover &Missing Links"), this,
		     SLOT(slotDiscoverMissingLinks(void)));
      menu.exec(m_ui.received->mapToGlobal(point));
    }
  else if(m_ui.transmitted == sender())
    {
      QAction *action = 0;
      QMenu menu(this);

      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"), this,
		     SLOT(slotDeleteTransmitted(void)));
      menu.addAction(tr("Delete &All"), this,
		     SLOT(slotDeleteAllTransmitted(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Compute SHA-1 Hash"), this,
			      SLOT(slotComputeFileHash(void)));
      action->setProperty("widget_of", "transmitted");
      menu.addSeparator();
      action = menu.addAction(tr("&Copy File Hash"), this,
			      SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "transmitted");
      menu.addSeparator();
      menu.addAction(tr("Set &Pulse Size"), this,
		     SLOT(slotSetSBPulseSize(void)));
      menu.addAction(tr("Set &Read Interval"), this,
		     SLOT(slotSetSBReadInterval(void)));
      menu.exec(m_ui.transmitted->mapToGlobal(point));
    }
  else if(m_ui.transmittedMagnets == sender())
    {
      QMenu menu(this);

      menu.addAction(tr("Copy &Magnet"),
		     this, SLOT(slotCopyTransmittedMagnet(void)));
      menu.addAction(tr("&Duplicate Magnet"),
		     this, SLOT(slotDuplicateTransmittedMagnet(void)));
      menu.exec(m_ui.transmittedMagnets->mapToGlobal(point));
    }
  else if(m_ui.urlParticipants == sender())
    {
      QAction *action = 0;
      QMenu menu(this);

      menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareUrlPublicKeyWithParticipant(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/generic/repleo-url.png"),
		     tr("&Copy Repleo to the clipboard buffer."),
		     this, SLOT(slotCopyUrlFriendshipBundle(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Remove participant(s)."),
		     this, SLOT(slotRemoveUrlParticipants(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Rename participant."),
			      this, SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "url");
      menu.exec(m_ui.urlParticipants->mapToGlobal(point));
    }
}

void spoton::slotKernelSocketState(void)
{
  QAbstractSocket::SocketState state = m_kernelSocket.state();

  if(state == QAbstractSocket::ConnectedState)
    {
      m_kernelSocket.setSocketOption
	(QAbstractSocket::LowDelayOption,
	 m_settings.value("gui/tcp_nodelay", 1).toInt()); /*
							  ** Disable Nagle?
							  */
      if(m_kernelSocket.isEncrypted())
	{
	  askKernelToReadStarBeamKeys();
	  sendBuzzKeysToKernel();
	  sendKeysToKernel();

	  QSslCipher cipher(m_kernelSocket.sessionCipher());
	  QString str(QString("%1-%2-%3-%4-%5-%6-%7").
		      arg(cipher.name()).
		      arg(cipher.authenticationMethod()).
		      arg(cipher.encryptionMethod()).
		      arg(cipher.keyExchangeMethod()).
		      arg(cipher.protocolString()).
		      arg(cipher.supportedBits()).
		      arg(cipher.usedBits()));

	  m_sb.kernelstatus->setToolTip
	    (tr("Connected securely to the kernel on port %1 "
		"from local port %2 via cipher %3.").
	     arg(m_kernelSocket.peerPort()).
	     arg(m_kernelSocket.localPort()).
	     arg(str));
	}
      else
	m_sb.kernelstatus->setToolTip
	  (tr("Connected insecurely to the kernel on port %1 "
	      "from local port %2. Communications between the interface and "
	      "the kernel have been disabled.").
	   arg(m_kernelSocket.peerPort()).
	   arg(m_kernelSocket.localPort()));

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
  else if(state == QAbstractSocket::UnconnectedState)
    {
      m_keysShared["buzz_channels_sent_to_kernel"] = "false";
      m_keysShared["keys_sent_to_kernel"] = "false";
      m_sb.kernelstatus->setIcon
	(QIcon(QString(":/%1/deactivate.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())));
      m_sb.kernelstatus->setToolTip
	(tr("Not connected to the kernel. Is the kernel "
	    "active?"));
    }
}

void spoton::sendBuzzKeysToKernel(void)
{
  QString str(m_keysShared.value("buzz_channels_sent_to_kernel", "false"));

  if(str == "true")
    return;

  bool sent = true;

  if((sent = (m_kernelSocket.state() == QAbstractSocket::ConnectedState)))
    if((sent = m_kernelSocket.isEncrypted()))
      foreach(spoton_buzzpage *page,
	      m_ui.tab->findChildren<spoton_buzzpage *> ())
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

	  if(m_kernelSocket.write(message.constData(), message.length()) !=
	     message.length())
	    {
	      sent = false;
	      spoton_misc::logError
		(QString("spoton::sendBuzzKeysToKernel(): write() failure "
			 "for %1:%2.").
		 arg(m_kernelSocket.peerAddress().toString()).
		 arg(m_kernelSocket.peerPort()));
	    }
	}

  m_keysShared["buzz_channels_sent_to_kernel"] = sent ? "true" : "false";
}

void spoton::sendKeysToKernel(void)
{
  QString str(m_keysShared.value("keys_sent_to_kernel", "false"));

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

  if(m_crypts.value("chat", 0))
    if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
      if(m_kernelSocket.isEncrypted())
	{
	  if(!m_optionsUi.sharePrivateKeys->isChecked())
	    {
	      QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	      mb.setIcon(QMessageBox::Question);
	      mb.setWindowTitle(tr("%1: Question").
				arg(SPOTON_APPLICATION_NAME));
	      mb.setWindowModality(Qt::WindowModal);
	      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	      mb.setText
		 (tr("The kernel process %1 requires your private "
		     "authentication "
		     "and encryption keys. Would you like to share the keys?").
		  arg(m_ui.pid->text()));

	      if(mb.exec() != QMessageBox::Yes)
		{
		  m_keysShared["keys_sent_to_kernel"] = "ignore";
		  return;
		}
	    }

	  QByteArray hashKey(m_crypts.value("chat")->hashKey());
	  QByteArray keys("keys_");
	  QByteArray symmetricKey(m_crypts.value("chat")->symmetricKey());

	  hashKey = hashKey.toBase64();
	  symmetricKey = symmetricKey.toBase64();
	  keys.append(symmetricKey);
	  keys.append("_");
	  keys.append(hashKey);
	  keys.append("\n");

	  if(m_kernelSocket.write(keys.constData(), keys.length()) !=
	     keys.length())
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

void spoton::slotConnectNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

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

void spoton::slotDisconnectNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

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

void spoton::slotBlockNeighbor(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString remoteIp("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, 10); // Remote IP Address

      if(item)
	remoteIp = item->text();
    }

  if(remoteIp.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

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

	if(query.exec("SELECT remote_ip_address, OID "
		      "FROM neighbors WHERE status_control NOT IN "
		      "('blocked', 'deleted')"))
	  while(query.next())
	    {
	      QString ip("");
	      bool ok = true;

	      ip = crypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok).constData();

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

void spoton::slotUnblockNeighbor(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString remoteIp("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, 10); // Remote IP Address

      if(item)
	remoteIp = item->text();
    }

  if(remoteIp.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	/*
	** We must unblock all neighbors having the given remote IP
	** address. The neighbors must be in blocked control states. We shall
	** place the unblocked neighbors in disconnected control states.
	*/

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, OID "
		      "FROM neighbors WHERE status_control = 'blocked'"))
	  while(query.next())
	    {
	      bool ok = true;

	      QString ip
		(crypt->
		 decryptedAfterAuthenticated(QByteArray::
					     fromBase64(query.
							value(0).
							toByteArray()),
					     &ok).
		 constData());

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

void spoton::slotDeleteAllListeners(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

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
  m_ui.ae_tokens->clearContents();
}

void spoton::slotDeleteAllNeighbors(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

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
  m_ui.neighborSummary->clear();
}

void spoton::slotPopulateParticipants(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "friends_public_keys.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() > m_participantsLastModificationTime)
	m_participantsLastModificationTime = fileInfo.lastModified();
      else
	return;
    }
  else
    m_participantsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateParticipantsTable(db);

	QList<int> rows;  // Chat
	QList<int> rowsE; // E-Mail
	QList<int> rowsU; // URLs
	QModelIndexList list
	  (m_ui.participants->selectionModel()->
	   selectedRows(3)); // public_key_hash
	QModelIndexList listE
	  (m_ui.emailParticipants->selectionModel()->
	   selectedRows(3)); // public_key_hash
	QModelIndexList listU
	  (m_ui.urlParticipants->selectionModel()->
	   selectedRows(3)); // public_key_hash
	QStringList hashes;
	QStringList hashesE;
	QStringList hashesU;
	int hval = m_ui.participants->horizontalScrollBar()->value();
	int hvalE = m_ui.emailParticipants->horizontalScrollBar()->value();
	int hvalU = m_ui.urlParticipants->horizontalScrollBar()->value();
	int row = 0;
	int rowE = 0;
	int rowU = 0;
	int vval = m_ui.participants->verticalScrollBar()->value();
	int vvalE = m_ui.emailParticipants->verticalScrollBar()->value();
	int vvalU = m_ui.urlParticipants->verticalScrollBar()->value();

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      hashes.append(data.toString());
	  }

	while(!listE.isEmpty())
	  {
	    QVariant data(listE.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      hashesE.append(data.toString());
	  }

	while(!listU.isEmpty())
	  {
	    QVariant data(listU.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      hashesU.append(data.toString());
	  }

	m_ui.emailParticipants->setSortingEnabled(false);
	m_ui.emailParticipants->clearContents();
	m_ui.emailParticipants->setRowCount(0);
	m_ui.participants->setSortingEnabled(false);
	m_ui.participants->clearContents();
	m_ui.participants->setRowCount(0);
	m_ui.urlParticipants->setSortingEnabled(false);
	m_ui.urlParticipants->clearContents();
	m_ui.urlParticipants->setRowCount(0);
	disconnect(m_ui.participants,
		   SIGNAL(itemChanged(QTableWidgetItem *)),
		   this,
		   SLOT(slotGeminiChanged(QTableWidgetItem *)));

	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();
	bool ok = true;

	query.setForwardOnly(true);
	query.exec("PRAGMA read_uncommitted = True");
	query.prepare("SELECT "
		      "name, "               // 0
		      "OID, "                // 1
		      "neighbor_oid, "       // 2
		      "public_key_hash, "    // 3
		      "status, "             // 4
		      "last_status_update, " // 5
		      "gemini, "             // 6
		      "gemini_hash_key, "    // 7
		      "key_type, "           // 8
		      "public_key "          // 9
		      "FROM friends_public_keys "
		      "WHERE key_type_hash IN (?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->keyedHash(QByteArray("chat"), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->keyedHash(QByteArray("email"), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->keyedHash(QByteArray("poptastic"), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->keyedHash(QByteArray("url"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray publicKey;
	      QIcon icon;
	      QString keyType("");
	      QString name("");
	      QString oid(query.value(1).toString());
	      QString status(query.value(4).toString().toLower());
	      QString statusText("");
	      bool ok = true;
	      bool temporary =
		query.value(2).toLongLong() == -1 ? false : true;

	      keyType = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(8).toByteArray()),
		 &ok).constData();

	      if(ok)
		name = QString::fromUtf8
		  (crypt->
		   decryptedAfterAuthenticated(QByteArray::
					       fromBase64(query.
							  value(0).
							  toByteArray()),
					       &ok).constData());

	      if(!ok)
		name = "";

	      publicKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(9).toByteArray()), &ok);

	      if(!isKernelActive())
		status = "offline";

	      for(int i = 0; i < query.record().count(); i++)
		{
		  if(i == query.record().count() - 1)
		    /*
		    ** Ignore public_key.
		    */

		    continue;

		  QTableWidgetItem *item = 0;

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
			       publicKey.contains("-poptastic")))
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
			    item->setBackground
			      (QBrush(QColor(137, 207, 240)));
			}
		      else if(i == 4) // Status
			{
			  QString status(query.value(i).toString().
					 trimmed());

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
		      else if(i == 6 ||
			      i == 7) /*
				      ** Gemini Encryption Key
				      ** Gemini Hash Key
				      */
			{
			  if(query.isNull(i))
			    item = new QTableWidgetItem();
			  else
			    {
			      item = new QTableWidgetItem
				(crypt->decryptedAfterAuthenticated
				 (QByteArray::fromBase64(query.
							 value(i).
							 toByteArray()),
				  &ok).toBase64().constData());

			      if(!ok)
				item->setText(tr("error"));
			    }
			}
		      else
			item = new QTableWidgetItem
			  (query.value(i).toString());

		      item->setFlags
			(Qt::ItemIsEnabled | Qt::ItemIsSelectable);

		      if(i == 0) // Name
			{
			  if(!temporary)
			    {
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
				(query.value(3).toString().mid(0, 16) +
				 "..." +
				 query.value(3).toString().right(16));
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
			  /*
			  ** Forward Secrecy Information
			  */

			  QList<QByteArray> list;
			  bool ok = true;

			  list = retrieveForwardSecrecyInformation
			    (db, oid, &ok);

			  if(ok)
			    item->setText
			      (spoton_misc::
			       forwardSecrecyMagnetFromList(list).
			       constData());
			  else
			    item->setText(tr("error"));
			}

		      item->setData(Qt::UserRole, temporary);
		      item->setData
			(Qt::ItemDataRole(Qt::UserRole + 1), keyType);

		      /*
		      ** Delete the item if the participant is offline
		      ** and the user wishes to hide offline participants.
		      ** Please note that the e-mail participants are cloned
		      ** and are not subjected to this restriction.
		      */

		      if((m_ui.hideOfflineParticipants->isChecked() &&
			  status == "offline") ||
			 publicKey.contains("-poptastic"))
			{
			  /*
			  ** This may be a plain Poptastic participant.
			  ** It will only be displayed in the E-Mail tab.
			  */

			  delete item;
			  item = 0;
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
			      if(keyType == "email" ||
				 keyType == "email-signature")
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
			      if(publicKey.contains("-poptastic"))
				item->setBackground
				  (QBrush(QColor(255, 255, 224)));
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
			item = new QTableWidgetItem
			  (query.value(i).toString());
		      else if(i == 4)
			{
			  QList<QByteArray> list;
			  bool ok = true;

			  list = retrieveForwardSecrecyInformation
			    (db, oid, &ok);

			  if(ok)
			    item = new QTableWidgetItem
			      (spoton_misc::
			       forwardSecrecyMagnetFromList(list).
			       constData());
			  else
			    item = new QTableWidgetItem(tr("error"));
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
				  (query.value(3).toString().mid(0, 16) +
				   "..." +
				   query.value(3).toString().right(16));
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
			  (query.value(i).toString());

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
				  (query.value(3).toString().mid(0, 16) +
				   "..." +
				   query.value(3).toString().right(16));
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
			item = 0;
		      }
		}

	      if(keyType == "chat" || keyType == "poptastic")
		emit statusChanged(icon, name, oid, statusText);

	      if(hashes.contains(query.value(3).toString()))
		rows.append(row - 1);

	      if(hashesE.contains(query.value(3).toString()))
		rowsE.append(rowE - 1);

	      if(hashesU.contains(query.value(3).toString()))
		rowsU.append(rowU - 1);
	    }

	connect(m_ui.participants,
		SIGNAL(itemChanged(QTableWidgetItem *)),
		this,
		SLOT(slotGeminiChanged(QTableWidgetItem *)));
	m_ui.emailParticipants->setSelectionMode
	  (QAbstractItemView::MultiSelection);
	m_ui.participants->setSelectionMode
	  (QAbstractItemView::MultiSelection);
	m_ui.urlParticipants->setSelectionMode
	  (QAbstractItemView::MultiSelection);

	while(!rows.isEmpty())
	  m_ui.participants->selectRow(rows.takeFirst());

	while(!rowsE.isEmpty())
	  m_ui.emailParticipants->selectRow(rowsE.takeFirst());

	while(!rowsU.isEmpty())
	  m_ui.urlParticipants->selectRow(rowsU.takeFirst());

	m_ui.emailParticipants->setSelectionMode
	  (QAbstractItemView::ExtendedSelection);
	m_ui.emailParticipants->setSortingEnabled(true);
	m_ui.emailParticipants->resizeColumnToContents(0);
	m_ui.emailParticipants->horizontalHeader()->
	  setStretchLastSection(true);
	m_ui.emailParticipants->horizontalScrollBar()->setValue(hvalE);
	m_ui.emailParticipants->verticalScrollBar()->setValue(vvalE);
	m_ui.participants->resizeColumnToContents
	  (m_ui.participants->columnCount() - 3); // Gemini Encryption Key.
	m_ui.participants->resizeColumnToContents
	  (m_ui.participants->columnCount() - 2); // Gemini Hash Key.
	m_ui.participants->setSelectionMode
	  (QAbstractItemView::ExtendedSelection);
	m_ui.participants->setSortingEnabled(true);
	m_ui.participants->horizontalHeader()->setStretchLastSection(true);
	m_ui.participants->horizontalScrollBar()->setValue(hval);
	m_ui.participants->verticalScrollBar()->setValue(vval);
	m_ui.urlParticipants->setSelectionMode
	  (QAbstractItemView::ExtendedSelection);
	m_ui.urlParticipants->setSortingEnabled(true);
	m_ui.urlParticipants->resizeColumnsToContents();
	m_ui.urlParticipants->horizontalHeader()->
	  setStretchLastSection(true);
	m_ui.urlParticipants->horizontalScrollBar()->setValue(hvalU);
	m_ui.urlParticipants->verticalScrollBar()->setValue(vvalU);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
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

void spoton::changeEchoMode(const QString &mode, QTableWidget *tableWidget)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

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
      QTableWidgetItem *item = tableWidget->item
	(row, tableWidget->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       QString("%1.db").arg(table));

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

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
    m_neighborsLastModificationTime = QDateTime();
}

void spoton::slotListenerFullEcho(void)
{
  changeEchoMode("full", m_ui.listeners);
}

void spoton::slotListenerHalfEcho(void)
{
  changeEchoMode("half", m_ui.listeners);
}

void spoton::slotNeighborFullEcho(void)
{
  changeEchoMode("full", m_ui.neighbors);
}

void spoton::slotNeighborHalfEcho(void)
{
  changeEchoMode("half", m_ui.neighbors);
}

void spoton::slotKernelLogEvents(bool state)
{
  m_settings["gui/kernelLogEvents"] = state;

  QSettings settings;

  settings.setValue("gui/kernelLogEvents", state);
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

void spoton::slotListenerMaximumChanged(int value)
{
  QSpinBox *spinBox = qobject_cast<QSpinBox *> (sender());

  if(!spinBox)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString name(spinBox->property("field_name").toString().toLower());

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

void spoton::slotNeighborMaximumChanged(int value)
{
  QSpinBox *spinBox = qobject_cast<QSpinBox *> (sender());

  if(!spinBox)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString name(spinBox->property("field_name").toString().toLower());

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

void spoton::slotDetachListenerNeighbors(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted())
      {
	QByteArray message;

	message.append("detach_listener_neighbors_");
	message.append(oid);
	message.append("\n");

	if(m_kernelSocket.write(message.constData(), message.length()) !=
	   message.length())
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
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted())
      {
	QByteArray message;

	message.append("disconnect_listener_neighbors_");
	message.append(oid);
	message.append("\n");

	if(m_kernelSocket.write(message.constData(), message.length()) !=
	   message.length())
	  spoton_misc::logError
	    (QString("spoton::slotDisconnectListenerNeighbors(): "
		     "write() failure for %1:%2.").
	     arg(m_kernelSocket.peerAddress().toString()).
	     arg(m_kernelSocket.peerPort()));
      }
}

void spoton::slotCallParticipant(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString keyType("");
  QString oid("");
  QString type(action->property("type").toString().toLower());
  bool temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item(row, 1); // OID

      if(item)
	{
	  keyType = item->data
	    (Qt::ItemDataRole(Qt::UserRole + 1)).toString().toLower();
	  oid = item->text();
	  temporary = item->data(Qt::UserRole).toBool();
	}
    }

  if(oid.isEmpty())
    return;
  else if(keyType == "poptastic" && type == "calling_two_way")
    return; // Not allowed!
  else if(temporary) // Temporary friend?
    return; // Not allowed!

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

  message.append(keyType);
  message.append("_");
  message.append(oid);
  message.append("\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotCallParticipant(): write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotSignatureCheckBoxToggled(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());
  QString str("");

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

void spoton::slotCopyEmailFriendshipBundle(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  if(!m_crypts.value("email", 0) ||
     !m_crypts.value("email-signature", 0))
    {
      clipboard->clear();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.emailParticipants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.emailParticipants->item
	(row, 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
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
  QByteArray cipherType(m_settings.value("gui/kernelCipherType",
					 "aes256").toString().
			toLatin1());
  QByteArray hashKey;
  QByteArray keyInformation;
  QByteArray publicKey;
  QByteArray symmetricKey;
  QPair<QByteArray, QByteArray> gemini;
  QString receiverName("");
  bool ok = true;

  if(cipherType.isEmpty())
    {
      clipboard->clear();
      return;
    }

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     hashKey,
				     neighborOid,
				     receiverName,
				     cipherType,
				     oid,
				     m_crypts.value("email", 0),
				     &ok);

  if(!ok || publicKey.isEmpty() || symmetricKey.isEmpty())
    {
      clipboard->clear();
      return;
    }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (symmetricKey.toBase64() + "@" +
     cipherType.toBase64() + "@" +
     hashKey.toBase64(), publicKey, &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySPublicKey(m_crypts.value("email-signature")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySSignature
    (m_crypts.value("email-signature")->digitalSignature(mySPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myPublicKey(m_crypts.value("email")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySignature(m_crypts.value("email")->
			 digitalSignature(myPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myName
    (m_settings.value("gui/emailName", "unknown").toByteArray());

  if(myName.isEmpty())
    myName = "unknown";

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     "sha512",
		     QByteArray(),
		     symmetricKey,
		     hashKey,
		     0,
		     0,
		     "");

  data = crypt.encrypted(QByteArray("email").toBase64() + "@" +
			 myName.toBase64() + "@" +
			 myPublicKey.toBase64() + "@" +
			 mySignature.toBase64() + "@" +
			 mySPublicKey.toBase64() + "@" +
			 mySSignature.toBase64(), &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray hash(crypt.keyedHash(data, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  clipboard->setText("R" +
		     keyInformation.toBase64() + "@" +
		     data.toBase64() + "@" +
		     hash.toBase64());
}

void spoton::slotCopyAllMyPublicKeys(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      clipboard->setText(copyMyChatPublicKey() + "\n" +
			 copyMyEmailPublicKey() + "\n" +
			 copyMyPoptasticPublicKey() + "\n" +
			 copyMyRosettaPublicKey() + "\n" +
			 copyMyUrlPublicKey());
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotSaveSslControlString(void)
{
  QString str(m_ui.sslControlString->text());

  if(str.trimmed().isEmpty())
    str = "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";

  m_ui.listenersSslControlString->setText(str.trimmed());
  m_ui.neighborsSslControlString->setText(str.trimmed());
  m_ui.sslControlString->setText(str.trimmed());
  m_ui.sslControlString->selectAll();
  m_settings["gui/sslControlString"] = str;

  QSettings settings;

  settings.setValue("gui/sslControlString", str);
}

void spoton::slotDiscoverExternalAddress(void)
{
  m_externalAddress.discover();
}

void spoton::slotNeighborSelected(void)
{
  QTableWidgetItem *item = m_ui.neighbors->selectedItems().value(0);

  if(item)
    {
      QSslCertificate certificate;
      QString label("<html>");
      int row = item->row();

      if(m_ui.neighbors->item(row, 31)) // certificate
	certificate = QSslCertificate
	  (QByteArray::fromBase64(m_ui.neighbors->
				  item(row, 31)->text().toLatin1()));

      for(int i = 0; i < m_ui.neighbors->columnCount() - 1; i++)
	{
	  QTableWidgetItem *h = m_ui.neighbors->horizontalHeaderItem(i);

	  if(!h)
	    continue;
	  else if(!(h->text().length() > 0 && h->text().at(0).isUpper()))
	    continue;

	  QTableWidgetItem *item = m_ui.neighbors->item(row, i);

	  if(item)
	    label.append
	      (QString("<b>" +
		       m_ui.neighbors->horizontalHeaderItem(i)->
		       text() +
		       ":</b> %1" + "<br>").arg(spoton_misc::
						htmlEncode(item->text())));
	}

      int h = m_ui.neighborSummary->horizontalScrollBar()->value();
      int v = m_ui.neighborSummary->verticalScrollBar()->value();

      if(!certificate.isNull())
	label.append
	  (tr("<b>Cert. Effective Date:</b> %1<br>"
	      "<b>Cert. Expiration Date:</b> %2<br>"
	      "<b>Cert. Issuer Organization:</b> %3<br>"
	      "<b>Cert. Issuer Common Name:</b> %4<br>"
	      "<b>Cert. Issuer Locality Name:</b> %5<br>"
	      "<b>Cert. Issuer Organizational Unit Name:</b> %6<br>"
	      "<b>Cert. Issuer Country Name:</b> %7<br>"
	      "<b>Cert. Issuer State or Province Name:</b> %8<br>"
	      "<b>Cert. Serial Number:</b> %9<br>"
	      "<b>Cert. Subject Organization:</b> %10<br>"
	      "<b>Cert. Subject Common Name:</b> %11<br>"
	      "<b>Cert. Subject Locality Name:</b> %12<br>"
	      "<b>Cert. Subject Organizational Unit Name:</b> %13<br>"
	      "<b>Cert. Subject Country Name:</b> %14<br>"
	      "<b>Cert. Subject State or Province Name:</b> %15<br>"
	      "<b>Cert. Version:</b> %16<br>").
	   arg(certificate.effectiveDate().toString("MM/dd/yyyy")).
	   arg(certificate.expiryDate().toString("MM/dd/yyyy")).
#if QT_VERSION < 0x050000
	   arg(certificate.issuerInfo(QSslCertificate::Organization)).
	   arg(certificate.issuerInfo(QSslCertificate::CommonName)).
	   arg(certificate.issuerInfo(QSslCertificate::LocalityName)).
	   arg(certificate.
	       issuerInfo(QSslCertificate::OrganizationalUnitName)).
	   arg(certificate.issuerInfo(QSslCertificate::CountryName)).
	   arg(certificate.
	       issuerInfo(QSslCertificate::StateOrProvinceName)).
#else
	   arg(certificate.issuerInfo(QSslCertificate::Organization).
	       value(0)).
	   arg(certificate.issuerInfo(QSslCertificate::CommonName).
	       value(0)).
	   arg(certificate.issuerInfo(QSslCertificate::LocalityName).
	       value(0)).
	   arg(certificate.
	       issuerInfo(QSslCertificate::OrganizationalUnitName).value(0)).
	   arg(certificate.issuerInfo(QSslCertificate::CountryName).value(0)).
	   arg(certificate.
	       issuerInfo(QSslCertificate::StateOrProvinceName).value(0)).
#endif
	   arg(certificate.serialNumber().constData()).
#if QT_VERSION < 0x050000
	   arg(certificate.subjectInfo(QSslCertificate::Organization)).
	   arg(certificate.subjectInfo(QSslCertificate::CommonName)).
	   arg(certificate.subjectInfo(QSslCertificate::LocalityName)).
	   arg(certificate.
	       subjectInfo(QSslCertificate::OrganizationalUnitName)).
	   arg(certificate.subjectInfo(QSslCertificate::CountryName)).
	   arg(certificate.
	       subjectInfo(QSslCertificate::StateOrProvinceName)).
#else
	   arg(certificate.subjectInfo(QSslCertificate::Organization).
	       value(0)).
	   arg(certificate.subjectInfo(QSslCertificate::CommonName).
	       value(0)).
	   arg(certificate.subjectInfo(QSslCertificate::LocalityName).
	       value(0)).
	   arg(certificate.
	       subjectInfo(QSslCertificate::OrganizationalUnitName).
	       value(0)).
	   arg(certificate.subjectInfo(QSslCertificate::CountryName).
	       value(0)).
	   arg(certificate.
	       subjectInfo(QSslCertificate::StateOrProvinceName).
	       value(0)).
#endif
	   arg(certificate.version().constData()));
      label.append("</html>");
      m_ui.neighborSummary->setText(label);
      m_ui.neighborSummary->horizontalScrollBar()->setValue(h);
      m_ui.neighborSummary->verticalScrollBar()->setValue(v);
    }
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

void spoton::slotResetAccountInformation(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

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

void spoton::slotAuthenticate(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid neighbor OID. "
			       "Please select a neighbor."));
      return;
    }

  authenticate(crypt, list.at(0).data().toString());
}

void spoton::authenticate(spoton_crypt *crypt, const QString &oid,
			  const QString &message)
{
  if(!crypt)
    return;
  else if(oid.isEmpty())
    return;

  QDialog dialog(this);
  Ui_passwordprompt ui;

  ui.setupUi(&dialog);
  dialog.setWindowTitle
    (tr("%1: Please Authenticate").
     arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif

  if(!message.isEmpty())
    ui.message->setText(message);

  if(dialog.exec() == QDialog::Accepted)
    {
      QString name(ui.name->text().trimmed());
      QString password(ui.password->text());

      if(name.length() >= 32 && password.length() >= 32)
	{
	  QString connectionName("");
	  bool ok = true;

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			       "neighbors.db");

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
	    QMessageBox::critical(this, tr("%1: Error").
				  arg(SPOTON_APPLICATION_NAME),
				  tr("An error occurred while attempting "
				     "to record authentication "
				     "information."));
	}
      else
	QMessageBox::critical
	  (this, tr("%1: Error").
	   arg(SPOTON_APPLICATION_NAME),
	   tr("The account name and the account password "
	      "must contain at least thirty-two characters "
	      "each."));
    }
}

void spoton::slotPopulateBuzzFavorites(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "buzz_channels.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() > m_buzzFavoritesLastModificationTime)
	m_buzzFavoritesLastModificationTime = fileInfo.lastModified();
      else
	return;
    }
  else
    m_buzzFavoritesLastModificationTime = QDateTime();

  QMap<QByteArray, QByteArray> map;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	if(query.exec("SELECT data FROM buzz_channels"))
	  while(query.next())
	    {
	      QByteArray data;
	      bool ok = true;

	      data = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		{
		  QByteArray channelName;
		  QByteArray channelSalt;
		  QByteArray channelType;
		  QByteArray hashKey;
		  QByteArray hashType;
		  QList<QByteArray> list(data.split('\n'));

		  channelName = QByteArray::fromBase64(list.value(0));
		  channelType = QByteArray::fromBase64(list.value(3));
		  hashKey = QByteArray::fromBase64(list.value(4));
		  hashType = QByteArray::fromBase64(list.value(5));

		  if(!channelName.isEmpty() && !channelType.isEmpty() &&
		     !hashKey.isEmpty() && !hashType.isEmpty())
		    {
		      QByteArray label;
		      unsigned long iterationCount = 0;

		      channelSalt = QByteArray::fromBase64
			(list.value(2));
		      iterationCount = qMax
			(QByteArray::fromBase64(list.value(1)).
			 toULong(), static_cast<unsigned long> (10000));

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
		      label.append(QString::number(iterationCount));
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
	  QAction *action = m_ui.shareBuzzMagnet->menu()->actions().first();

	  m_ui.shareBuzzMagnet->menu()->removeAction(action);
	  action->deleteLater();
	}

      for(int i = 0; i < map.keys().size(); i++)
	{
	  m_ui.favorites->addItem(map.keys().at(i));
	  m_ui.favorites->setItemData(i, map.value(map.keys().at(i)));

	  QAction *action = new QAction
	    (map.keys().at(i), this);

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
      m_ui.favorites->addItem("Empty");

      while(!m_ui.shareBuzzMagnet->menu()->actions().isEmpty())
	{
	  QAction *action = m_ui.shareBuzzMagnet->menu()->actions().first();

	  m_ui.shareBuzzMagnet->menu()->removeAction(action);
	  action->deleteLater();
	}
    }

  m_ui.favorites->setMinimumContentsLength
    (m_ui.favorites->itemText(0).length());
}

void spoton::slotFavoritesActivated(int index)
{
  QByteArray data(m_ui.favorites->itemData(index).toByteArray());
  QList<QByteArray> list(data.split('\n'));

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  m_ui.channel->setText(list.value(0));
  m_ui.buzzIterationCount->setValue
    (static_cast<int> (list.value(1).toULong()));
  m_ui.channelSalt->setText(list.value(2));

  if(m_ui.channelType->findText(list.value(3)) > -1)
    m_ui.channelType->setCurrentIndex
      (m_ui.channelType->findText(list.value(3)));
  else
    m_ui.channelType->setCurrentIndex(0);

  m_ui.buzzHashKey->setText(list.value(4));

  if(m_ui.buzzHashType->findText(list.value(5)) > -1)
    m_ui.buzzHashType->setCurrentIndex
      (m_ui.buzzHashType->findText(list.value(5)));
  else
    m_ui.buzzHashType->setCurrentIndex(0);
}

void spoton::removeFavorite(const bool removeAll)
{
  QString connectionName("");
  QString error("");
  bool ok = true;
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "buzz_channels.db");

    if(db.open())
      {
	QByteArray data;
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
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error);
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

void spoton::magnetize(void)
{
  if(m_ui.favorites->currentText() == "Empty")
    return;

  QByteArray data;
  QList<QByteArray> list;
  QClipboard *clipboard = QApplication::clipboard();
  QString error("");

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
  data.append(QString("rn=%1&").arg(list.value(0).constData()));
  data.append(QString("xf=%1&").arg(list.value(1).constData()));
  data.append(QString("xs=%1&").arg(list.value(2).constData()));
  data.append(QString("ct=%1&").arg(list.value(3).constData()));
  data.append(QString("hk=%1&").arg(list.value(4).constData()));
  data.append(QString("ht=%1&").arg(list.value(5).constData()));
  data.append("xt=urn:buzz");
  clipboard->setText(data);

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error);
}

void spoton::demagnetize(void)
{
  QStringList list
    (m_ui.demagnetize->text().remove("magnet:?").split("&"));

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(str.startsWith("rn="))
	{
	  str.remove(0, 3);
	  m_ui.channel->setText(str);
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

  disconnect(m_ui.buzzTools,
	     SIGNAL(activated(int)),
	     this,
	     SLOT(slotFavoritesActivated(int)));
  m_ui.buzzTools->setCurrentIndex(0);
  connect(m_ui.buzzTools,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotFavoritesActivated(int)));
}

void spoton::slotAbout(void)
{
  QMessageBox mb(this);
  QString str("");

#if SPOTON_GOLDBUG == 0
  QPixmap pixmap(":/Logo/spot-on-logo.png");

  pixmap = pixmap.scaled
    (QSize(250, 250), Qt::KeepAspectRatio, Qt::SmoothTransformation);
  str = "Please visit <a href=\"http://spot-on.sourceforge.net\">"
    "spot-on.sourceforge.net</a> for more information.";
  mb.setIconPixmap(pixmap);
#else
  str = "Please visit <a href=\"http://goldbug.sourceforge.net\">"
    "goldbug.sourceforge.net</a> for more information.";
  mb.setIconPixmap(*m_ui.logo->pixmap());
#endif
  str.append("<br><br>");
  str.append(m_ui.buildInformation->text());
  mb.setStandardButtons(QMessageBox::Ok);
  mb.setText(str);
  mb.setTextFormat(Qt::RichText);
  mb.setWindowTitle(SPOTON_APPLICATION_NAME);
  mb.exec();
}

QPointer<spoton> spoton::instance(void)
{
  return s_gui;
}
