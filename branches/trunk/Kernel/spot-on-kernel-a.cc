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

#ifdef SPOTON_USE_HIDDEN_KERNEL_WINDOW
#include <QApplication>
#else
#include <QCoreApplication>
#endif
#include <QDir>
#ifdef SPOTON_USE_HIDDEN_KERNEL_WINDOW
#include <QMainWindow>
#endif
#include <QNetworkProxy>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QtCore/qmath.h>

#include <limits>
#include <iostream>

extern "C"
{
#include "libSpotOn/libspoton.h"
}

extern "C"
{
#include <libpq-fe.h>
}

extern "C"
{
#include <fcntl.h>
#ifdef Q_OS_WIN32
#include <process.h>
#endif
#include <signal.h>
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_OS2) ||	\
  defined(Q_OS_UNIX)
#include <termios.h>
#include <unistd.h>
#else
#if QT_VERSION >= 0x050000
#include <winsock2.h>
#endif
#include <windows.h>
#endif
}

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-fireshare.h"
#include "spot-on-gui-server.h"
#include "spot-on-kernel.h"
#include "spot-on-listener.h"
#include "spot-on-mailer.h"
#include "spot-on-neighbor.h"
#include "spot-on-starbeam-reader.h"
#include "spot-on-starbeam-writer.h"
#include "spot-on-urldistribution.h"

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
#include "Common/CocoaInitializer.h"
#endif
#endif

QByteArray spoton_kernel::s_messagingCacheKey;
QDateTime spoton_kernel::s_institutionLastModificationTime;
QHash<QByteArray, QList<QByteArray> > spoton_kernel::s_buzzKeys;
QHash<QByteArray, char> spoton_kernel::s_messagingCache;
QHash<QByteArray, uint> spoton_kernel::s_emailRequestCache;
QHash<QByteArray, uint> spoton_kernel::s_geminisCache;
QHash<QString, QVariant> spoton_kernel::s_settings;
QHash<QString, spoton_crypt *> spoton_kernel::s_crypts;
QMultiHash<qint64,
	   QPointer<spoton_neighbor> > spoton_kernel::s_connectionCounts;
QMultiMap<uint, QByteArray> spoton_kernel::s_messagingCacheLookup;
QList<QList<QByteArray> > spoton_kernel::s_institutionKeys;
QList<QPair<QByteArray, QByteArray> > spoton_kernel::s_adaptiveEchoPairs;
QReadWriteLock spoton_kernel::s_adaptiveEchoPairsMutex;
QReadWriteLock spoton_kernel::s_buzzKeysMutex;
QReadWriteLock spoton_kernel::s_emailRequestCacheMutex;
QReadWriteLock spoton_kernel::s_geminisCacheMutex;
QReadWriteLock spoton_kernel::s_institutionKeysMutex;
QReadWriteLock spoton_kernel::s_institutionLastModificationTimeMutex;
QReadWriteLock spoton_kernel::s_messagingCacheMutex;
QReadWriteLock spoton_kernel::s_settingsMutex;

/*
** Not pleasant! Please avoid this solution!
*/

int spoton_common::CACHE_TIME_DELTA_MAXIMUM = CACHE_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::CHAT_TIME_DELTA_MAXIMUM = CHAT_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
  FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::GEMINI_TIME_DELTA_MAXIMUM =
  GEMINI_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::MAIL_TIME_DELTA_MAXIMUM = MAIL_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
  POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
static QPointer<spoton_kernel> s_kernel = 0;
static int s_exit_code = EXIT_SUCCESS;

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

  /*
  ** Resume console input echo.
  */

#ifdef Q_OS_WIN32
  DWORD mode = 0;
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

  GetConsoleMode(hStdin, &mode);
  SetConsoleMode(hStdin, mode | ENABLE_ECHO_INPUT);
#else
  termios oldt;

  tcgetattr(STDIN_FILENO, &oldt);
  oldt.c_lflag |= ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

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
		      262144) == LIBSPOTON_ERROR_NONE) /*
						       ** We don't need
						       ** the official secure
						       ** memory size here.
						       */
#ifdef Q_OS_WIN32
    libspoton_deregister_kernel(_getpid(), &libspotonHandle);
#else
    libspoton_deregister_kernel(getpid(), &libspotonHandle);
#endif

  libspoton_close(&libspotonHandle);
  QFile::remove(spoton_misc::homePath() + QDir::separator() + "kernel.db");
  spoton_crypt::terminate();

  /*
  ** _Exit() and _exit() may be safely called from signal handlers.
  */

  _Exit(signal_number);
}

int main(int argc, char *argv[])
{
  PQinitOpenSSL(0, 0); // We will initialize OpenSSL and libcrypto.

  for(int i = 1; i < argc; i++)
    if(argv[i] && qstrcmp(argv[i], "--version") == 0)
      {
	fprintf(stdout, "Compiled on %s, %s. Version %s.\n",
		__DATE__, __TIME__, SPOTON_VERSION_STR);
	exit(EXIT_SUCCESS);
      }

  curl_global_init(CURL_GLOBAL_ALL);
  libspoton_enable_sqlite_cache();
  spoton_misc::prepareSignalHandler(signal_handler);

#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
  struct sigaction act;

  /*
  ** Ignore SIGHUP.
  */

  act.sa_handler = SIG_IGN;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  sigaction(SIGHUP, &act, 0);

  /*
  ** Ignore SIGPIPE.
  */

  act.sa_handler = SIG_IGN;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  sigaction(SIGPIPE, &act, 0);
#if QT_VERSION >= 0x050000
  qInstallMessageHandler(qt_message_handler);
#else
  qInstallMsgHandler(qt_message_handler);
#endif
#endif
#ifdef SPOTON_USE_HIDDEN_KERNEL_WINDOW
  QApplication qapplication(argc, argv);
#else
  QCoreApplication qapplication(argc, argv);
#endif
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
  /*
  ** Eliminate pool errors on OS X.
  */

  CocoaInitializer ci;
#endif
#endif

  QCoreApplication::setApplicationName("Spot-On");
  QCoreApplication::setOrganizationName("Spot-On");
  QCoreApplication::setOrganizationDomain("spot-on.sf.net");
  QCoreApplication::setApplicationVersion(SPOTON_VERSION_STR);
  QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
		     spoton_misc::homePath());
  QSettings::setDefaultFormat(QSettings::IniFormat);

  QSettings settings;

  for(int i = 1; i < argc; i++)
    if(argv[i] && qstrcmp(argv[i], "--vacuum") == 0)
      spoton_misc::vacuumAllDatabases();

  if(!settings.contains("kernel/gcryctl_init_secmem"))
    settings.setValue("kernel/gcryctl_init_secmem", 262144);

  if(!settings.contains("kernel/sctp_nodelay"))
    settings.setValue("kernel/sctp_nodelay", 1);

  if(!settings.contains("kernel/server_account_verification_window_msecs"))
    settings.setValue("kernel/server_account_verification_window_msecs",
		      15000);

  if(!settings.contains("kernel/tcp_nodelay"))
    settings.setValue("kernel/tcp_nodelay", 1);

  bool ok = true;
  int integer = settings.value("kernel/gcryctl_init_secmem", 262144).
    toInt(&ok);

  if(integer < 131072 || integer > 999999999 || !ok)
    integer = 262144;

  spoton_crypt::init(integer);

  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_error_t err = LIBSPOTON_ERROR_NONE;
  libspoton_handle_t libspotonHandle;

  if((err = libspoton_init_b(sharedPath.toStdString().c_str(),
			     0,
			     0,
			     0,
			     0,
			     0,
			     0,
			     0,
			     &libspotonHandle,
			     integer)) == LIBSPOTON_ERROR_NONE)
    err = libspoton_register_kernel
      (static_cast<pid_t> (QCoreApplication::applicationPid()),
       settings.value("gui/forceKernelRegistration", true).toBool(),
       &libspotonHandle);

  libspoton_close(&libspotonHandle);

  if(err == LIBSPOTON_ERROR_NONE)
    {
      try
	{
	  s_kernel = new spoton_kernel();

#ifdef SPOTON_USE_HIDDEN_KERNEL_WINDOW
	  QMainWindow window;

	  window.showMinimized();
	  QObject::connect(&qapplication,
			   SIGNAL(lastWindowClosed(void)),
			   s_kernel,
			   SLOT(deleteLater(void)));
#endif

	  int rc = qapplication.exec();

	  curl_global_cleanup();
	  return rc;
	}
      catch(const std::bad_alloc &exception)
	{
	  std::cerr << "Critical memory failure. Exiting kernel."
		    << std::endl;
	  curl_global_cleanup();
	  return EXIT_FAILURE;
	}
      catch(...)
	{
	  std::cerr << "Critical failure. Exiting kernel."
		    << std::endl;
	  curl_global_cleanup();
	  return EXIT_FAILURE;
	}
    }
  else
    {
      std::cerr << "Critical kernel error ("
		<< libspoton_strerror(err)
		<< ") with libspoton_init_b()."
		<< std::endl;
      curl_global_cleanup();
      return EXIT_FAILURE;
    }
}

spoton_kernel::spoton_kernel(void):QObject(0)
{
  qRegisterMetaType<QAbstractSocket::SocketError>
    ("QAbstractSocket::SocketError");
  qRegisterMetaType<QByteArrayList> ("QByteArrayList");
  qRegisterMetaType<QHostAddress> ("QHostAddress");
  qRegisterMetaType<QPairByteArrayByteArray> ("QPairByteArrayByteArray");
  qRegisterMetaType<QPairByteArrayInt64List> ("QPairByteArrayInt64List");
  qRegisterMetaType<QStringByteArrayHash> ("QStringByteArrayHash");
#if QT_VERSION >= 0x050000
  qRegisterMetaType<qintptr> ("qintptr");
#endif
  qRegisterMetaType<spoton_sctp_socket::SocketError>
    ("spoton_sctp_socket::SocketError");
  m_activeListeners = 0;
  m_activeNeighbors = 0;
  m_activeStarbeams = 0;
  m_guiServer = 0;
  m_mailer = 0;
  m_starbeamWriter = 0;
  m_urlsProcessed = 0;
  m_lastPoptasticStatus = QDateTime::currentDateTime();
  m_uptime = QDateTime::currentDateTime();
  s_institutionLastModificationTime = QDateTime();
  s_messagingCacheKey = spoton_crypt::weakRandomBytes
    (static_cast<size_t> (spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES));
  qsrand(static_cast<uint> (QTime(0, 0, 0).secsTo(QTime::currentTime())));
  QDir().mkdir(spoton_misc::homePath());

  /*
  ** The user interface doesn't yet have a means of preparing advanced
  ** options.
  */

  QSettings settings;
  bool disable_ui_server = false;

  settings.remove("kernel/neighbor_thread_priority");

  for(int i = 0; i < settings.allKeys().size(); i++)
    s_settings.insert(settings.allKeys().at(i),
		      settings.value(settings.allKeys().at(i)));

  spoton_misc::correctSettingsContainer(s_settings);
  spoton_misc::setTimeVariables(s_settings);
  spoton_misc::enableLog
    (setting("gui/kernelLogEvents", false).toBool());

  QStringList arguments(QCoreApplication::arguments());

  for(int i = 1; i < arguments.size(); i++)
    if(arguments.at(i) == "--disable-ui-server")
      disable_ui_server = true;
    else if(arguments.at(i) == "--passphrase" ||
	  arguments.at(i) == "--question-answer")
      {
	/*
	** Attempt to disable input echo.
	*/

	bool error = false;

#ifdef Q_OS_WIN32
	DWORD mode = 0;
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

	if(GetConsoleMode(hStdin, &mode) == 0)
	  {
	    s_exit_code = EXIT_FAILURE;
	    std::cerr << "Unable to retrieve the terminal's mode. Exiting."
		      << std::endl;
	    deleteLater();
	    break;
	  }

	if(SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT)) == 0)
	  error = true;
#else
	termios newt;
	termios oldt;

	if(tcgetattr(STDIN_FILENO, &oldt) != 0)
	  {
	    s_exit_code = EXIT_FAILURE;
	    std::cerr << "Unable to retrieve the terminal's mode. Exiting."
		      << std::endl;
	    deleteLater();
	    break;
	  }

	newt = oldt;
	newt.c_lflag &= ~ECHO;

	if(tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0)
	  error = true;
#endif
	QString input1("");
	QString input2("");

	if(!error)
	  {
	    QTextStream cin(stdin);
	    QTextStream cout(stdout);

	    if(arguments.at(i) == "--passphrase")
	      {
		cout << "Passphrase, please: ";
		cout.flush();
		input1 = cin.readLine(std::numeric_limits<int>::max());
	      }
	    else
	      {
		cout << "Question, please: ";
		cout.flush();
		input1 = cin.readLine(std::numeric_limits<int>::max());
		cout << endl;
		cout << "Answer, please: ";
		cout.flush();
		input2 = cin.readLine(std::numeric_limits<int>::max());
	      }
	  }

#ifdef Q_OS_WIN32
	SetConsoleMode(hStdin, mode);
#else
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

	if(!error)
	  {
	    std::cout << "\n";
	    std::cout << "Validating the input... Please remain calm.\n";

	    if(!initializeSecurityContainers(input1, input2))
	      {
		s_exit_code = EXIT_FAILURE;
		std::cerr << "Invalid input?" << std::endl;
		deleteLater();
	      }
	    else
	      {
		std::cout << "Input validated.\n";
		spoton_misc::cleanupDatabases(s_crypts.value("chat", 0));
	      }

	    break;
	  }
	else
	  {
	    s_exit_code = EXIT_FAILURE;
	    std::cerr << "Unable to silence the terminal's echo. Exiting."
		      << std::endl;
	    deleteLater();
	    break;
	  }
      }
    else if(arguments.at(i) == "--vacuum")
      {
      }
    else
      {
	s_exit_code = EXIT_FAILURE;
	std::cerr << "Invalid option: " << arguments.at(i).constData()
		  << ". Exiting." << std::endl;
	deleteLater();
	break;
      }

  connect(this,
	  SIGNAL(poppedMessage(const QByteArray &)),
	  this,
	  SLOT(slotPoppedMessage(const QByteArray &)));
  connect(&m_controlDatabaseTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPollDatabase(void)));
  connect(&m_impersonateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotImpersonateTimeout(void)));
  connect(&m_messagingCachePurgeTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotMessagingCachePurge(void)));
  connect(&m_poptasticPopTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPoptasticPop(void)));
  connect(&m_poptasticPostTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPoptasticPost(void)));
  connect(&m_publishAllListenersPlaintextTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPublicizeAllListenersPlaintext(void)));
  connect(&m_scramblerTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotScramble(void)));
  connect(&m_settingsTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotUpdateSettings(void)));
  connect(&m_statusTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotStatusTimerExpired(void)));
  connect(&m_urlImportTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotUrlImportTimerExpired(void)));
  m_controlDatabaseTimer.start(2500);
  m_impersonateTimer.setInterval(2500);
  m_messagingCachePurgeTimer.setInterval
    (static_cast<int> (1000 * setting("kernel/cachePurgeInterval", 15.00).
		       toDouble()));

  if(!setting("gui/disablePop3", true).toBool())
    m_poptasticPopTimer.start
      (static_cast<int> (1000 * setting("gui/poptasticRefreshInterval",
					5.00).toDouble()));

  if(!setting("gui/disableSmtp", true).toBool())
    m_poptasticPostTimer.start(2500);

  m_publishAllListenersPlaintextTimer.setInterval(10 * 60 * 1000);
  m_settingsTimer.setInterval(1500);
  m_scramblerTimer.setSingleShot(true);
  m_settingsTimer.setSingleShot(true);
  m_statusTimer.start(1000 * spoton_common::STATUS_INTERVAL);
  m_urlImportFutures.resize
    (qCeil(2.5 * qMax(1, QThread::idealThreadCount())));

  for(int i = 0; i < m_urlImportFutures.size(); i++)
    m_urlImportFutures.replace(i, QFuture<void> ());

  m_urlImportTimer.start(500);
  m_fireShare = new spoton_fireshare(this);

  if(!disable_ui_server)
    m_guiServer = new spoton_gui_server(this);

  m_mailer = new spoton_mailer(this);
  m_starbeamWriter = new spoton_starbeam_writer(this);
  m_urlDistribution = new spoton_urldistribution(this);

  if(m_guiServer)
    {
      connect(m_guiServer,
	      SIGNAL(buzzMagnetReceivedFromUI(const qint64,
					      const QByteArray &)),
	      this,
	      SLOT(slotBuzzMagnetReceivedFromUI(const qint64,
						const QByteArray &)));
      connect(m_guiServer,
	      SIGNAL(buzzReceivedFromUI(const QByteArray &,
					const QByteArray &,
					const QByteArray &,
					const QByteArray &,
					const QByteArray &,
					const QByteArray &,
					const QString &,
					const QByteArray &,
					const QByteArray &)),
	      this,
	      SLOT(slotBuzzReceivedFromUI(const QByteArray &,
					  const QByteArray &,
					  const QByteArray &,
					  const QByteArray &,
					  const QByteArray &,
					  const QByteArray &,
					  const QString &,
					  const QByteArray &,
					  const QByteArray &)));
      connect(m_guiServer,
	      SIGNAL(callParticipant(const QByteArray &,
				     const qint64)),
	      this,
	      SLOT(slotCallParticipant(const QByteArray &,
				       const qint64)));
      connect(m_guiServer,
	      SIGNAL(callParticipantUsingForwardSecrecy(const QByteArray &,
							const qint64)),
	      this,
	      SLOT(slotCallParticipantUsingForwardSecrecy(const QByteArray &,
							  const qint64)));
      connect(m_guiServer,
	      SIGNAL(callParticipantUsingGemini(const QByteArray &,
						const qint64)),
	      this,
	      SLOT(slotCallParticipantUsingGemini(const QByteArray &,
						  const qint64)));
      connect(m_guiServer,
	      SIGNAL(detachNeighbors(const qint64)),
	      this,
	      SLOT(slotDetachNeighbors(const qint64)));
      connect(m_guiServer,
	      SIGNAL(disconnectNeighbors(const qint64)),
	      this,
	      SLOT(slotDisconnectNeighbors(const qint64)));
      connect
	(m_guiServer,
	 SIGNAL(forwardSecrecyInformationReceivedFromUI(const
							QByteArrayList &)),
	 this,
	 SLOT(slotForwardSecrecyInformationReceivedFromUI(const
							  QByteArrayList &)));
      connect
	(m_guiServer,
	 SIGNAL(forwardSecrecyResponseReceivedFromUI(const
						     QByteArrayList &)),
	 this,
	 SLOT(slotForwardSecrecyResponseReceivedFromUI(const
						       QByteArrayList &)));
      connect(m_guiServer,
	      SIGNAL(messageReceivedFromUI(const qint64,
					   const QByteArray &,
					   const QByteArray &,
					   const QByteArray &,
					   const QByteArray &,
					   const QString &)),
	      this,
	      SLOT(slotMessageReceivedFromUI(const qint64,
					     const QByteArray &,
					     const QByteArray &,
					     const QByteArray &,
					     const QByteArray &,
					     const QString &)));
      connect
	(m_guiServer,
	 SIGNAL(publicKeyReceivedFromUI(const qint64,
					const QByteArray &,
					const QByteArray &,
					const QByteArray &,
					const QByteArray &,
					const QByteArray &,
					const QByteArray &,
					const QString &)),
	 this,
	 SLOT(slotPublicKeyReceivedFromUI(const qint64,
					  const QByteArray &,
					  const QByteArray &,
					  const QByteArray &,
					  const QByteArray &,
					  const QByteArray &,
					  const QByteArray &,
					  const QString &)));
      connect(m_guiServer,
	      SIGNAL(populateStarBeamKeys(void)),
	      m_starbeamWriter,
	      SLOT(slotReadKeys(void)));
      connect(m_guiServer,
	      SIGNAL(publicizeAllListenersPlaintext(void)),
	      this,
	      SLOT(slotPublicizeAllListenersPlaintext(void)));
      connect(m_guiServer,
	      SIGNAL(publicizeListenerPlaintext(const qint64)),
	      this,
	      SLOT(slotPublicizeListenerPlaintext(const qint64)));
      connect(m_guiServer,
	      SIGNAL(purgeEphemeralKeyPair(const QByteArray &)),
	      this,
	      SLOT(slotPurgeEphemeralKeyPair(const QByteArray &)));
      connect(m_guiServer,
	      SIGNAL(purgeEphemeralKeys(void)),
	      this,
	      SLOT(slotPurgeEphemeralKeys(void)));
      connect(m_guiServer,
	      SIGNAL(retrieveMail(void)),
	      this,
	      SLOT(slotRetrieveMail(void)));
      connect(m_guiServer,
	      SIGNAL(shareLink(const QByteArray &)),
	      m_fireShare,
	      SLOT(slotShareLink(const QByteArray &)));
    }

  connect(m_mailer,
	  SIGNAL(sendMail(const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const QByteArray &,
			  const qint64)),
	  this,
	  SLOT(slotSendMail(const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const QByteArray &,
			    const qint64)));

  if(m_guiServer)
    {
      connect(this,
	      SIGNAL(forwardSecrecyRequest(const QByteArrayList &)),
	      m_guiServer,
	      SLOT(slotForwardSecrecyRequest(const QByteArrayList &)));
      connect(this,
	      SIGNAL(forwardSecrecyResponseReceived(const QByteArrayList &)),
	      m_guiServer,
	      SLOT(slotForwardSecrecyResponse(const QByteArrayList &)));
      connect(this,
	      SIGNAL(newEMailArrived(void)),
	      m_guiServer,
	      SLOT(slotNewEMailArrived(void)));
      connect(this,
	      SIGNAL(receivedChatMessage(const QByteArray &)),
	      m_guiServer,
	      SLOT(slotReceivedChatMessage(const QByteArray &)));
      connect(this,
	      SIGNAL(statusMessageReceived(const QByteArray &,
					   const QString &)),
	      m_guiServer,
	      SLOT(slotStatusMessageReceived(const QByteArray &,
					     const QString &)));
    }

  connect(&m_settingsWatcher,
	  SIGNAL(fileChanged(const QString &)),
	  this,
	  SLOT(slotSettingsChanged(const QString &)));
  m_settingsWatcher.addPath(settings.fileName());
  m_fireShare->start();
  m_messagingCachePurgeTimer.start();

  if(setting("gui/etpReceivers", false).toBool())
    m_starbeamWriter->start();

  if(setting("gui/impersonate", false).toBool())
    m_impersonateTimer.start();

  if(setting("gui/activeUrlDistribution", true).toBool())
    m_urlDistribution->start();
  else
    {
      m_urlDistribution->quit();
      m_urlDistribution->wait();
    }

  spoton_misc::prepareDatabases();
}

spoton_kernel::~spoton_kernel()
{
  m_controlDatabaseTimer.stop();
  m_impersonateTimer.stop();
  m_messagingCachePurgeTimer.stop();
  m_poptasticPopTimer.stop();
  m_poptasticPostTimer.stop();
  m_publishAllListenersPlaintextTimer.stop();
  m_scramblerTimer.stop();
  m_settingsTimer.stop();
  m_statusTimer.stop();
  m_urlImportTimer.stop();

  QWriteLocker locker1(&s_messagingCacheMutex);

  s_messagingCache.clear();
  s_messagingCacheLookup.clear();
  locker1.unlock();

  QWriteLocker locker2(&m_poptasticCacheMutex);

  m_poptasticCache.clear();
  locker2.unlock();
  m_future.cancel();
  m_poptasticPopFuture.cancel();
  m_poptasticPostFuture.cancel();
  m_urlImportFutureInterrupt.fetchAndStoreOrdered(1);

  for(int i = 0; i < m_urlImportFutures.size(); i++)
    m_urlImportFutures[i].cancel();

  m_future.waitForFinished();
  m_poptasticPopFuture.waitForFinished();
  m_poptasticPostFuture.waitForFinished();
  m_statisticsFuture.waitForFinished();
  m_fireShare->quit();
  m_fireShare->wait();
  m_urlDistribution->quit();
  m_urlDistribution->wait();

  for(int i = 0; i < m_urlImportFutures.size(); i++)
    m_urlImportFutures[i].waitForFinished();

  cleanup();
  spoton_misc::cleanupDatabases(s_crypts.value("chat", 0));

  QHashIterator<QString, spoton_crypt *> it(s_crypts);

  while(it.hasNext())
    {
      it.next();
      delete it.value();
    }

  s_crypts.clear();
  spoton_misc::logError(QString("Kernel %1 about to exit.").
			arg(QCoreApplication::applicationPid()));
  spoton_crypt::terminate();
  QCoreApplication::exit(s_exit_code);
}

void spoton_kernel::cleanup(void)
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
		      setting("kernel/gcryctl_init_secmem", 262144).
		      toInt()) == LIBSPOTON_ERROR_NONE)
    libspoton_deregister_kernel
      (static_cast<pid_t> (QCoreApplication::applicationPid()),
			   &libspotonHandle);

  libspoton_close(&libspotonHandle);
}

void spoton_kernel::slotPollDatabase(void)
{
  spoton_misc::prepareDatabases();
  prepareListeners();
  prepareNeighbors();
  prepareStarbeamReaders();

  if(m_statisticsFuture.isFinished())
    m_statisticsFuture = QtConcurrent::run
      (this, &spoton_kernel::updateStatistics,
       m_uptime, interfaces(), m_activeListeners, m_activeNeighbors,
       m_activeStarbeams);

  checkForTermination();
}

void spoton_kernel::prepareListeners(void)
{
  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT token, token_type FROM "
		      "listeners_adaptive_echo_tokens"))
	  {
	    QWriteLocker locker(&s_adaptiveEchoPairsMutex);

	    s_adaptiveEchoPairs.clear();

	    while(query.next())
	      {
		QPair<QByteArray, QByteArray> pair;

		pair.first = QByteArray::fromBase64
		  (query.value(0).toByteArray());
		pair.second = QByteArray::fromBase64
		  (query.value(1).toByteArray());

		if(!s_adaptiveEchoPairs.contains(pair))
		  s_adaptiveEchoPairs.append(pair);
	      }
	  }

	if(query.exec("SELECT "
		      "ip_address, "             // 0
		      "port, "                   // 1
		      "scope_id, "               // 2
		      "echo_mode, "              // 3
		      "status_control, "         // 4
		      "maximum_clients, "        // 5
		      "ssl_key_size, "           // 6
		      "certificate, "            // 7
		      "private_key, "            // 8
		      "public_key, "             // 9
		      "use_accounts, "           // 10
		      "maximum_buffer_size, "    // 11
		      "maximum_content_length, " // 12
		      "transport, "              // 13
		      "share_udp_address, "      // 14
		      "orientation, "            // 15
		      "motd, "                   // 16
		      "ssl_control_string, "     // 17
		      "lane_width, "             // 18
		      "OID "                     // 19
		      "FROM listeners"))
	  while(query.next())
	    {
	      QPointer<spoton_listener> listener = 0;
	      QString status(query.value(4).toString().toLower());
	      qint64 id = query.value(query.record().count() - 1).
		toLongLong();

	      /*
	      ** We're only interested in creating objects for
	      ** listeners that will listen.
	      */

	      if(status == "deleted" || status == "offline")
		{
		  listener = m_listeners.value(id);

		  if(listener)
		    {
		      listener->close();
		      listener->deleteLater();
		    }

		  m_listeners.remove(id);
		  s_connectionCounts.remove(id);

		  if(status == "deleted")
		    cleanupListenersDatabase(db);
		}
	      else if(status == "online")
		{
		  if(!m_listeners.contains(id))
		    {
		      QByteArray certificate;
		      QByteArray orientation;
		      QByteArray privateKey;
		      QByteArray publicKey;
		      QByteArray transport;
		      QList<QByteArray> list;
		      bool ok = true;

		      for(int i = 0; i < 4; i++)
			{
			  QByteArray bytes;

			  bytes = s_crypt->
			    decryptedAfterAuthenticated
			    (QByteArray::fromBase64(query.
						    value(i).
						    toByteArray()),
			     &ok);

			  if(ok)
			    list.append(bytes);
			  else
			    break;
			}

		      if(ok)
			certificate = s_crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.
						  value(7).
						  toByteArray()),
			   &ok);

		      if(ok)
			privateKey = s_crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.
						  value(8).
						  toByteArray()),
			   &ok);

		      if(ok)
			publicKey = s_crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.
						  value(9).
						  toByteArray()),
			   &ok);

		      if(ok)
			transport =  s_crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.
						  value(13).
						  toByteArray()),
			   &ok);

		      if(ok)
			orientation =  s_crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.
						  value(15).
						  toByteArray()),
			   &ok);

		      if(ok)
			{
			  int maximumClients =
			    static_cast<int> (query.value(5).toLongLong());

			  if(maximumClients > 0)
			    {
			      if(maximumClients % 5 != 0)
				maximumClients = 1;
			    }
			  else
			    maximumClients = 0;

			  try
			    {
			      listener = new spoton_listener
				(list.value(0).constData(),
				 list.value(1).constData(),
				 list.value(2).constData(),
				 maximumClients,
				 id,
				 list.value(3).constData(),
				 static_cast<int> (query.value(6).
						   toLongLong()),
				 certificate,
				 privateKey,
				 publicKey,
				 static_cast<int> (query.value(10).
						   toLongLong()),
				 query.value(11).toLongLong(),
				 query.value(12).toLongLong(),
				 transport.constData(),
				 static_cast<int> (query.value(14).
						   toLongLong()),
				 orientation.constData(),
				 QString::fromUtf8(query.value(16).
						   toByteArray()).trimmed(),
				 query.value(17).toString(),
				 query.value(18).toInt(),
				 this);
			    }
			  catch(const std::bad_alloc &exception)
			    {
			      listener = 0;
			      s_connectionCounts.remove(id);
			      spoton_misc::logError
				("spoton_kernel::prepareListeners(): "
				 "memory failure.");
			    }
			  catch(...)
			    {
			      if(listener)
				listener->deleteLater();

			      s_connectionCounts.remove(id);
			      spoton_misc::logError
				("spoton_kernel::prepareListeners(): "
				 "critical failure.");
			    }
			}

		      if(listener)
			{
			  connect
			    (listener,
			     SIGNAL(newNeighbor(QPointer<spoton_neighbor>)),
			     this,
			     SLOT(slotNewNeighbor(QPointer<spoton_neighbor>)));
			  m_listeners.insert(id, listener);
			}
		    }
		  else
		    {
		      listener = m_listeners.value(id);

		      /*
		      ** We must also be careful if we've never listened
		      ** before because serverAddress() and serverPort()
		      ** may not be defined properly. Please notice
		      ** that both aforementioned methods return the values
		      ** that were provided to the listener's constructor.
		      */

		      if(listener)
			if(!listener->isListening())
			  listener->listen(listener->serverAddress(),
					   listener->serverPort());
		    }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  QMutableHashIterator<qint64, QPointer<spoton_listener> > it
    (m_listeners);

  m_activeListeners = 0;

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	{
	  spoton_misc::logError
	    (QString("spoton_kernel::prepareListeners(): "
		     "listener %1 "
		     "may have been deleted from the listeners table by an "
		     "external event. Purging listener from the listeners "
		     "container.").
	     arg(it.key()));
	  it.remove();
	}
      else if(it.value()->isListening())
	m_activeListeners += 1;
    }

  if(m_listeners.isEmpty())
    s_connectionCounts.clear();
}

void spoton_kernel::prepareNeighbors(void)
{
  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, "
		      "remote_port, "
		      "scope_id, "
		      "status_control, "
		      "proxy_hostname, "
		      "proxy_password, "
		      "proxy_port, "
		      "proxy_type, "
		      "proxy_username, "
		      "user_defined, "
		      "ssl_key_size, "
		      "maximum_buffer_size, "
		      "maximum_content_length, "
		      "echo_mode, "
		      "certificate, "
		      "allow_exceptions, "
		      "protocol, "
		      "ssl_required, "
		      "account_name, "
		      "account_password, "
		      "transport, "
		      "orientation, "
		      "motd, "
		      "ssl_control_string, "
		      "priority, "
		      "lane_width, "
		      "OID FROM neighbors"))
	  while(query.next())
	    {
	      QPointer<spoton_neighbor> neighbor = 0;
	      qint64 id = query.value(query.record().count() - 1).
		toLongLong();

	      if(query.value(3).toString().toLower() == "connected")
		{
		  if(!m_neighbors.contains(id))
		    {
		      QList<QVariant> list;
		      bool userDefined = query.value
			(query.record().indexOf("user_defined")).toBool();

		      for(int i = 0; i < query.record().count() - 1; i++)
			if(i == 3) // status_control
			  list.append(query.value(i).toString().toLower());
			else if(i == 9) // user_defined
			  list.append(userDefined);
			else if(i == 10) // ssl_key_size
			  list.append(query.value(i).toLongLong());
			else if(i == 11 || // maximum_buffer_size
				i == 12)   // maximum_content_length
			  list.append(query.value(i).toLongLong());
			else if(i == 15) // allow_exceptions
			  list.append(query.value(i).toLongLong());
			else if(i == 17) // ssl_required
			  list.append(query.value(i).toLongLong());
			else if(i == 18) // account_name
			  list.append(QByteArray::fromBase64(query.value(i).
							     toByteArray()));
			else if(i == 19) // account_password
			  list.append(QByteArray::fromBase64(query.value(i).
							     toByteArray()));
			else if(i == 22) // motd
			  list.append
			    (QString::fromUtf8(query.value(i).toByteArray()).
			     trimmed());
			else if(i == 23) // ssl_control_string
			  list.append(query.value(i).toString());
			else if(i == 24) // priority
			  list.append(query.value(i).toInt());
			else if(i == 25) // lane_width
			  list.append(query.value(i).toInt());
			else
			  {
			    QByteArray bytes;
			    bool ok = true;

			    bytes = s_crypt->
			      decryptedAfterAuthenticated
			      (QByteArray::fromBase64(query.
						      value(i).
						      toByteArray()),
			       &ok);

			    if(ok)
			      list.append(bytes);
			    else
			      break;
			  }

		      if(list.size() == query.record().count() - 1)
			{
			  QNetworkProxy proxy;

			  /*
			  ** The indices of the list do not correspond
			  ** with the indices of the query container.
			  **
			  ** list[4] - Proxy HostName
			  ** list[5] - Proxy Password
			  ** list[6] - Proxy Port
			  ** list[7] - Proxy Type
			  ** list[8] - Proxy Username
			  */

			  if(list.value(7) == "HTTP" ||
			     list.value(7) == "Socks5")
			    {
			      proxy.setCapabilities
				(QNetworkProxy::HostNameLookupCapability |
				 QNetworkProxy::TunnelingCapability);
			      proxy.setHostName(list.value(4).toByteArray().
						constData());
			      proxy.setPassword(list.value(5).toByteArray().
						constData());
			      proxy.setPort(list.value(6).toByteArray().
					    toUShort()); /*
							 ** toUShort()
							 ** returns zero
							 ** on failure.
							 */

			      if(list.value(7) == "HTTP")
				proxy.setType(QNetworkProxy::HttpProxy);
			      else
				proxy.setType(QNetworkProxy::Socks5Proxy);

			      proxy.setUser(list.value(8).toByteArray().
					    constData());
			    }
			  else if(list.value(7) == "System")
			    {
			      QNetworkProxyQuery proxyQuery;

			      proxyQuery.setQueryType
				(QNetworkProxyQuery::TcpSocket);

			      QList<QNetworkProxy> proxies
				(QNetworkProxyFactory::
				 systemProxyForQuery(proxyQuery));

			      if(!proxies.isEmpty())
				{
				  proxy = proxies.at(0);
				  proxy.setPassword
				    (list.value(5).toByteArray().
				     constData());
				  proxy.setUser(list.value(8).toByteArray().
						constData());
				}
			    }
			  else
			    proxy.setType(QNetworkProxy::NoProxy);

			  try
			    {
			      neighbor = new spoton_neighbor
				(proxy,
				 list.value(0).toByteArray().constData(),
				 list.value(1).toByteArray().constData(),
				 list.value(2).toByteArray().constData(),
				 id,
				 userDefined,
				 static_cast<int> (list.value(10).
						   toLongLong()),
				 list.value(11).toLongLong(),
				 list.value(12).toLongLong(),
				 list.value(13).toByteArray().constData(),
				 list.value(14).toByteArray(),
				 list.value(15).toBool(),
				 list.value(16).toByteArray().constData(),
				 list.value(17).toBool(),
				 list.value(18).toByteArray(),
				 list.value(19).toByteArray(),
				 list.value(20).toString(),
				 list.value(21).toString(),
				 list.value(22).toString(),
				 list.value(3).toString(),
				 list.value(23).toString(),
				 QThread::Priority(list.value(24).toInt()),
				 list.value(25).toInt(),
				 this);
			    }
			  catch(const std::bad_alloc &exception)
			    {
			      neighbor = 0;
			      spoton_misc::logError
				("spoton_kernel::prepareNeighbors(): "
				 "memory failure.");
			    }
			  catch(...)
			    {
			      if(neighbor)
				neighbor->deleteLater();

			      spoton_misc::logError
				("spoton_kernel::prepareNeighbors(): "
				 "critical failure.");
			    }
			}

		      if(neighbor)
			{
			  connectSignalsToNeighbor(neighbor);
			  m_neighbors.insert(id, neighbor);
			}
		    }
		}
	      else
		{
		  neighbor = m_neighbors.value(id, 0);

		  if(neighbor)
		    neighbor->deleteLater();

		  m_neighbors.remove(id);
		  cleanupNeighborsDatabase(db);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  QMutableHashIterator<qint64, QPointer<spoton_neighbor> > it
    (m_neighbors);
  int disconnected = 0;

  m_activeNeighbors = 0;

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	{
	  spoton_misc::logError
	    (QString("spoton_kernel::prepareNeighbors(): "
		     "neighbor %1 "
		     "may have been deleted from the neighbors table by an "
		     "external event. Purging neighbor from the neighbors "
		     "container.").arg(it.key()));
	  it.remove();
	}
      else if(it.value()->state() == QAbstractSocket::UnconnectedState)
	disconnected += 1;
      else if(it.value()->state() == QAbstractSocket::ConnectedState)
	m_activeNeighbors += 1;
    }

  if(disconnected == m_neighbors.size() || m_neighbors.isEmpty())
    {
      QWriteLocker locker(&s_messagingCacheMutex);

      s_messagingCache.clear();
      s_messagingCacheLookup.clear();
      locker.unlock();
    }
}

void spoton_kernel::prepareStarbeamReaders(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT "
		      "read_interval, "
		      "status_control, "
		      "OID "
		      "FROM transmitted"))
	  while(query.next())
	    {
	      QString status(query.value(1).toString().toLower());
	      QPointer<spoton_starbeam_reader> starbeam = 0;
	      double readInterval = query.value(0).toDouble();
	      qint64 id = query.value(query.record().count() - 1).
		toLongLong();

	      if(status == "transmitting")
		{
		  QPointer<spoton_starbeam_reader> starbeam = 0;

		  if(!m_starbeamReaders.contains(id))
		    {
		      try
			{
			  starbeam = new spoton_starbeam_reader
			    (id, readInterval, this);
			}
		      catch(const std::bad_alloc &exception)
			{
			  starbeam = 0;
			}
		      catch(...)
			{
			  if(starbeam)
			    starbeam->deleteLater();

			  spoton_misc::logError
			    ("spoton_misc::prepareStarbeamReaders(): "
			     "critical failure.");
			}

		      if(starbeam)
			m_starbeamReaders.insert(id, starbeam);
		      else
			{
			  m_starbeamReaders.remove(id);
			  spoton_misc::logError
			    ("spoton_misc::prepareStarbeamReaders(): "
			     "memory failure.");
			}
		    }
		  else
		    {
		      starbeam = m_starbeamReaders.value(id, 0);

		      if(starbeam)
			starbeam->setReadInterval(readInterval);
		    }
		}
	      else
		{
		  starbeam = m_starbeamReaders.value(id, 0);

		  if(starbeam)
		    starbeam->deleteLater();

		  m_starbeamReaders.remove(id);

		  if(status == "deleted")
		    cleanupStarbeamsDatabase(db);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  QMutableHashIterator<qint64, QPointer<spoton_starbeam_reader> > it
    (m_starbeamReaders);

  m_activeStarbeams = 0;

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	{
	  spoton_misc::logError
	    (QString("spoton_kernel::prepareStarbeamReaders(): "
		     "starbeam %1 "
		     "may have been deleted from the starbeam table by an "
		     "external event. Purging starbeam reader from the "
		     "starbeam container.").
	     arg(it.key()));
	  it.remove();
	}
      else
	m_activeStarbeams += 1;
    }
}

void spoton_kernel::checkForTermination(void)
{
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  bool registered = false;
  libspoton_error_t err = LIBSPOTON_ERROR_NONE;

  if(QFileInfo(sharedPath).exists())
    {
      libspoton_handle_t libspotonHandle;

      if((err = libspoton_init_b(sharedPath.toStdString().c_str(),
				 0,
				 0,
				 0,
				 0,
				 0,
				 0,
				 0,
				 &libspotonHandle,
				 setting("kernel/gcryctl_init_secmem",
					 262144).toInt())) ==
	 LIBSPOTON_ERROR_NONE)
	registered = QCoreApplication::applicationPid() ==
	  libspoton_registered_kernel_pid(&libspotonHandle, &err);

      libspoton_close(&libspotonHandle);

      if(err == LIBSPOTON_ERROR_SQLITE_DATABASE_LOCKED)
	/*
	** Let's try next time.
	*/

	registered = true;
    }

  if(!registered)
    {
      for(int i = 0; i < m_listeners.keys().size(); i++)
	{
	  QPointer<spoton_listener> listener = m_listeners.take
	    (m_listeners.keys().at(i));

	  if(listener)
	    {
	      listener->close();
	      listener->deleteLater();
	    }
	}

      for(int i = 0; i < m_neighbors.keys().size(); i++)
	{
	  QPointer<spoton_neighbor> neighbor = m_neighbors.take
	    (m_neighbors.keys().at(i));

	  if(neighbor)
	    neighbor->deleteLater();
	}

      for(int i = 0; i < m_starbeamReaders.keys().size(); i++)
	{
	  QPointer<spoton_starbeam_reader> starbeam =
	    m_starbeamReaders.take(m_starbeamReaders.keys().at(i));

	  if(starbeam)
	    starbeam->deleteLater();
	}

      if(err != LIBSPOTON_ERROR_NONE)
	spoton_misc::logError
	  (QString("spoton_kernel::checkForTermination(): "
		   "an error occurred (%1) with libspoton.").
	   arg(err));

      deleteLater();
    }
}

void spoton_kernel::slotNewNeighbor(QPointer<spoton_neighbor> neighbor)
{
  if(neighbor)
    {
      qint64 id = neighbor->id();

      if(m_neighbors.contains(id) && !m_neighbors.value(id, 0))
	m_neighbors.remove(id);

      if(!m_neighbors.contains(id))
	{
	  connectSignalsToNeighbor(neighbor);
	  m_neighbors.insert(id, neighbor);
	}
      else
	spoton_misc::logError
	  (QString("spoton_kernel::slotNewNeighbor(): "
		   "neighbor %1 already exists in m_neighbors. This is "
		   "a serious problem!").
	   arg(id));
    }
}

void spoton_kernel::slotMessageReceivedFromUI
(const qint64 oid,
 const QByteArray &name,
 const QByteArray &message,
 const QByteArray &sequenceNumber,
 const QByteArray &utcDate,
 const QString &keyType)
{
  spoton_crypt *s_crypt1 = s_crypts.value(keyType, 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value
    (QString("%1-signature").arg(keyType), 0);

  if(!s_crypt2)
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  QByteArray myPublicKeyHash;

  myPublicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  QByteArray cipherType(setting("gui/kernelCipherType",
				"aes256").toString().toLatin1());
  QByteArray data;
  QByteArray hashKey;
  QByteArray hashType(setting("gui/kernelHashType",
			      "sha512").toString().toLatin1());
  QByteArray keyInformation;
  QByteArray symmetricKey;
  QDataStream stream(&keyInformation, QIODevice::WriteOnly);
  QPair<QByteArray, QByteArray> gemini;
  QString neighborOid("");
  QString receiverName("");

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     hashKey,
				     neighborOid,
				     receiverName,
				     cipherType,
				     QString::number(oid),
				     s_crypt1,
				     &ok);

  if(!ok || cipherType.isEmpty() || hashKey.isEmpty() ||
     symmetricKey.isEmpty())
    return;

  stream << QByteArray("0000")
	 << symmetricKey
	 << hashKey
	 << cipherType
	 << hashType;

  if(stream.status() != QDataStream::Ok)
    ok = false;

  if(ok)
    keyInformation = spoton_crypt::publicKeyEncrypt
      (keyInformation, publicKey, &ok);

  if(ok)
    {
      {
	/*
	** We would like crypt to be destroyed as soon as possible.
	*/

	QByteArray signature;
	spoton_crypt crypt(cipherType,
			   hashType,
			   QByteArray(),
			   symmetricKey,
			   hashKey,
			   0,
			   0,
			   "");

	if(setting("gui/chatSignMessages", true).toBool())
	  signature = s_crypt2->digitalSignature
	    ("0000" +
	     symmetricKey +
	     hashKey +
	     cipherType +
	     hashType +
	     myPublicKeyHash +
	     name +
	     message +
	     sequenceNumber +
	     utcDate, &ok);

	if(ok)
	  {
	    QDataStream stream(&data, QIODevice::WriteOnly);

	    stream << myPublicKeyHash
		   << name
		   << message
		   << sequenceNumber
		   << utcDate
		   << signature;

	    if(stream.status() != QDataStream::Ok)
	      ok = false;

	    if(ok)
	      data = crypt.encrypted(data, &ok);
	  }

	if(ok)
	  {
	    QByteArray messageCode
	      (crypt.keyedHash(keyInformation + data, &ok));

	    if(ok)
	      data = keyInformation.toBase64() + "\n" +
		data.toBase64() + "\n" +
		messageCode.toBase64();
	  }
      }

      if(ok)
	if(!gemini.first.isEmpty() &&
	   !gemini.second.isEmpty())
	  {
	    QByteArray bytes;
	    QByteArray messageCode;
	    QDataStream stream(&bytes, QIODevice::WriteOnly);
	    spoton_crypt crypt("aes256",
			       "sha512" ,
			       QByteArray(),
			       gemini.first,
			       gemini.second,
			       0,
			       0,
			       "");

	    stream << QByteArray("0000")
		   << data;

	    if(stream.status() != QDataStream::Ok)
	      ok = false;

	    if(ok)
	      data = crypt.encrypted(bytes, &ok);

	    if(ok)
	      messageCode = crypt.keyedHash(data, &ok);

	    if(ok)
	      {
		data = data.toBase64();
		data.append("\n");
		data.append(messageCode.toBase64());
	      }
	  }

      if(ok)
	{
	  if(keyType == "poptastic")
	    {
	      QByteArray message(spoton_send::message0000(data));

	      postPoptasticMessage(receiverName, message);
	    }
	  else
	    {
	      if(setting("gui/chatSendMethod",
			 "Artificial_GET").toString().
		 toLower() == "artificial_get")
		emit sendMessage(data, spoton_send::ARTIFICIAL_GET);
	      else
		emit sendMessage(data, spoton_send::NORMAL_POST);
	    }
	}
    }
}

void spoton_kernel::slotPublicKeyReceivedFromUI(const qint64 oid,
						const QByteArray &keyType,
						const QByteArray &name,
						const QByteArray &publicKey,
						const QByteArray &signature,
						const QByteArray &sPublicKey,
						const QByteArray &sSignature,
						const QString &messageType)
{
  QPointer<spoton_neighbor> neighbor = 0;

  if(m_neighbors.contains(oid))
    neighbor = m_neighbors[oid];

  if(!neighbor)
    {
      spoton_misc::logError
	(QString("spoton_kernel::slotPublicKeyReceivedFromUI(): "
		 "neighbor %1 not found in m_neighbors.").arg(oid));
      return;
    }

  if(messageType == "0011")
    {
      QByteArray data
	(spoton_send::message0011(keyType, name,
				  publicKey, signature,
				  sPublicKey, sSignature));

      if(neighbor->write(data.constData(), data.length()) != data.length())
	spoton_misc::logError
	  (QString("spoton_kernel::slotPublicKeyReceivedFromUI(): "
		   "write() failure for %1:%2.").
	   arg(neighbor->peerAddress().toString()).
	   arg(neighbor->peerPort()));
      else
	{
	  neighbor->addToBytesWritten(data.length());

	  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

	  if(!s_crypt)
	    return;

	  /*
	  ** Now let's update friends_public_keys if the peer also
	  ** shared their key.
	  */

	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			       "friends_public_keys.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		bool ok = true;

		query.prepare("UPDATE friends_public_keys SET "
			      "neighbor_oid = -1 "
			      "WHERE key_type_hash = ? AND "
			      "neighbor_oid = ?");
		query.bindValue
		  (0, s_crypt->keyedHash(keyType, &ok).toBase64());
		query.bindValue(1, oid);

		if(ok)
		  query.exec();

		query.prepare("UPDATE friends_public_keys SET "
			      "neighbor_oid = -1 "
			      "WHERE key_type_hash = ? AND "
			      "neighbor_oid = ?");

		if(ok)
		  query.bindValue
		    (0, s_crypt->keyedHash(keyType + "-signature",
					   &ok).toBase64());

		query.bindValue(1, oid);

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }
  else
    neighbor->slotSharePublicKey
      (keyType, name, publicKey, signature, sPublicKey, sSignature);
}

void spoton_kernel::slotSettingsChanged(const QString &path)
{
  /*
  ** Method may be issued several times per change.
  */

  m_settingsTimer.start();
  m_settingsWatcher.addPath(path);
}

void spoton_kernel::slotUpdateSettings(void)
{
  QSettings settings;
  QWriteLocker locker(&s_settingsMutex);

  for(int i = 0; i < settings.allKeys().size(); i++)
    if(settings.value(settings.allKeys().at(i)) !=
       s_settings.value(settings.allKeys().at(i)))
      s_settings.insert(settings.allKeys().at(i),
			settings.value(settings.allKeys().at(i)));

  spoton_misc::correctSettingsContainer(s_settings);
  spoton_misc::setTimeVariables(s_settings);
  locker.unlock();
  spoton_misc::enableLog
    (setting("gui/kernelLogEvents", false).toBool());

  if(setting("gui/etpReceivers", false).toBool())
    {
      if(!m_starbeamWriter->isActive())
	m_starbeamWriter->start();
    }
  else
    m_starbeamWriter->stop();

  if(setting("gui/impersonate", false).toBool())
    {
      if(!m_impersonateTimer.isActive())
	m_impersonateTimer.start();
    }
  else
    m_impersonateTimer.stop();

  int integer = static_cast<int>
    (1000 * setting("gui/poptasticRefreshInterval", 5.00).toDouble());

  if(!setting("gui/disablePop3", true).toBool())
    {
      if(!m_poptasticPopTimer.isActive())
	m_poptasticPopTimer.start(integer);
      else if(integer != m_poptasticPopTimer.interval())
	m_poptasticPopTimer.start(integer);
    }
  else
    m_poptasticPopTimer.stop();

  if(!setting("gui/disableSmtp", true).toBool())
    {
      if(!m_poptasticPostTimer.isActive())
	m_poptasticPostTimer.start(2500);
    }
  else
    {
      m_poptasticPostTimer.stop();

      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
    }

  if(setting("gui/publishPeriodically", false).toBool())
    {
      if(!m_publishAllListenersPlaintextTimer.isActive())
	m_publishAllListenersPlaintextTimer.start();
    }
  else
    m_publishAllListenersPlaintextTimer.stop();

  integer = static_cast<int>
    (1000 * setting("kernel/cachePurgeInterval", 15.00).toDouble());

  if(integer != m_messagingCachePurgeTimer.interval())
    m_messagingCachePurgeTimer.start(integer);

  if(setting("gui/activeUrlDistribution", true).toBool())
    {
      if(!m_urlDistribution->isRunning())
	m_urlDistribution->start();
    }
  else
    {
      m_urlDistribution->quit();
      m_urlDistribution->wait();
    }
}

void spoton_kernel::connectSignalsToNeighbor
(QPointer<spoton_neighbor> neighbor)
{
  if(!neighbor)
    return;

  connect(m_fireShare,
	  SIGNAL(sendURLs(const QByteArray &)),
	  neighbor,
	  SLOT(slotWriteURLs(const QByteArray &)),
	  Qt::UniqueConnection);

  if(m_guiServer)
    connect(m_guiServer,
	    SIGNAL(echoKeyShare(const QByteArrayList &)),
	    neighbor,
	    SLOT(slotEchoKeyShare(const QByteArrayList &)),
	    Qt::UniqueConnection);

  connect(m_mailer,
	  SIGNAL(sendMailFromPostOffice(const QByteArray &,
					const QPairByteArrayByteArray &)),
	  neighbor,
	  SLOT(slotSendMailFromPostOffice(const QByteArray &,
					  const QPairByteArrayByteArray &)),
	  Qt::UniqueConnection);
  connect(m_urlDistribution,
	  SIGNAL(sendURLs(const QByteArray &)),
	  neighbor,
	  SLOT(slotWriteURLs(const QByteArray &)),
	  Qt::UniqueConnection);

  if(m_guiServer)
    connect(neighbor,
	    SIGNAL(authenticationRequested(const QString &)),
	    m_guiServer,
	    SLOT(slotAuthenticationRequested(const QString &)),
	    Qt::UniqueConnection);

  connect(neighbor,
	  SIGNAL(callParticipant(const QByteArray &,
				 const QByteArray &,
				 const QByteArray &)),
	  this,
	  SLOT(slotCallParticipant(const QByteArray &,
				   const QByteArray &,
				   const QByteArray &)),
	  Qt::UniqueConnection);

  if(m_guiServer)
    {
      connect(neighbor,
	      SIGNAL(forwardSecrecyRequest(const QByteArrayList &)),
	      m_guiServer,
	      SLOT(slotForwardSecrecyRequest(const QByteArrayList &)),
	      Qt::UniqueConnection);
      connect(neighbor,
	      SIGNAL(newEMailArrived(void)),
	      m_guiServer,
	      SLOT(slotNewEMailArrived(void)),
	      Qt::UniqueConnection);
      connect
	(neighbor,
	 SIGNAL(receivedBuzzMessage(const QByteArrayList &,
				    const QByteArrayList &)),
	 m_guiServer,
	 SLOT(slotReceivedBuzzMessage(const QByteArrayList &,
				      const QByteArrayList &)),
	 Qt::UniqueConnection);
      connect(neighbor,
	      SIGNAL(receivedChatMessage(const QByteArray &)),
	      m_guiServer,
	      SLOT(slotReceivedChatMessage(const QByteArray &)),
	      Qt::UniqueConnection);
    }

  connect(neighbor,
	  SIGNAL(receivedMessage(const QByteArray &,
				 const qint64,
				 const QPairByteArrayByteArray &)),
	  this,
	  SIGNAL(write(const QByteArray &,
		       const qint64,
		       const QPairByteArrayByteArray &)),
	  Qt::UniqueConnection);

  if(m_guiServer)
    connect(neighbor,
	    SIGNAL(statusMessageReceived(const QByteArray &,
					 const QString &)),
	    m_guiServer,
	    SLOT(slotStatusMessageReceived(const QByteArray &,
					   const QString &)),
	    Qt::UniqueConnection);

  connect(neighbor,
	  SIGNAL(saveForwardSecrecySessionKeys(const QByteArrayList &)),
	  this,
	  SLOT(slotSaveForwardSecrecySessionKeys(const QByteArrayList &)),
	  Qt::UniqueConnection);
  connect(neighbor,
	  SIGNAL(scrambleRequest(void)),
	  this,
	  SLOT(slotRequestScramble(void)),
	  Qt::UniqueConnection);
  connect(neighbor,
	  SIGNAL(publicizeListenerPlaintext(const QByteArray &,
					    const qint64)),
	  this,
	  SIGNAL(publicizeListenerPlaintext(const QByteArray &,
					    const qint64)),
	  Qt::UniqueConnection);
  connect(neighbor,
	  SIGNAL(retrieveMail(const QByteArray &,
			      const QByteArray &,
			      const QByteArray &,
			      const QByteArray &,
			      const QPairByteArrayByteArray &)),
	  m_mailer,
	  SLOT(slotRetrieveMail(const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QPairByteArrayByteArray &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(callParticipant(const QByteArray &,
				 const QString &)),
	  neighbor,
	  SLOT(slotCallParticipant(const QByteArray &,
				   const QString &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(publicizeListenerPlaintext(const QByteArray &,
					    const qint64)),
	  neighbor,
	  SLOT(slotPublicizeListenerPlaintext(const QByteArray &,
					      const qint64)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(publicizeListenerPlaintext(const QHostAddress &,
					    const quint16,
					    const QString &,
					    const QString &)),
	  neighbor,
	  SLOT(slotPublicizeListenerPlaintext(const QHostAddress &,
					      const quint16,
					      const QString &,
					      const QString &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(retrieveMail(const QByteArrayList &,
			      const QString &)),
	  neighbor,
	  SLOT(slotRetrieveMail(const QByteArrayList &,
				const QString &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(sendBuzz(const QByteArray &)),
	  neighbor,
	  SLOT(slotSendBuzz(const QByteArray &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(sendForwardSecrecyPublicKey(const QByteArray &)),
	  neighbor,
	  SLOT(slotSendForwardSecrecyPublicKey(const QByteArray &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(sendForwardSecrecySessionKeys(const QByteArray &)),
	  neighbor,
	  SLOT(slotSendForwardSecrecySessionKeys(const QByteArray &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(sendMail(const QPairByteArrayInt64List &,
			  const QString &)),
	  neighbor,
	  SLOT(slotSendMail(const QPairByteArrayInt64List &,
			    const QString &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(sendMessage(const QByteArray &,
			     const spoton_send::spoton_send_method)),
	  neighbor,
	  SLOT(slotSendMessage(const QByteArray &,
			       const spoton_send::spoton_send_method)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(sendStatus(const QByteArrayList &)),
	  neighbor,
	  SLOT(slotSendStatus(const QByteArrayList &)),
	  Qt::UniqueConnection);
  connect(this,
	  SIGNAL(write(const QByteArray &, const qint64,
		       const QPairByteArrayByteArray &)),
	  neighbor,
	  SLOT(slotWrite(const QByteArray &, const qint64,
			 const QPairByteArrayByteArray &)),
	  Qt::UniqueConnection);
}

void spoton_kernel::slotStatusTimerExpired(void)
{
  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");

	for(int i = 1; i <= 2; i++)
	  {
	    bool ok = true;

	    query.prepare("UPDATE friends_public_keys SET "
			  "status = 'offline' WHERE "
			  "key_type_hash = ? AND "
			  "neighbor_oid = -1 AND "
			  "status <> 'offline' AND "
			  "strftime('%s', ?) - "
			  "strftime('%s', last_status_update) > ?");

	    if(i == 1)
	      query.bindValue
		(0, s_crypt->keyedHash(QByteArray("chat"), &ok).toBase64());
	    else
	      query.bindValue
		(0, s_crypt->keyedHash(QByteArray("poptastic"), &ok).
		 toBase64());

	    query.bindValue
	      (1, QDateTime::currentDateTime().toString(Qt::ISODate));

	    if(i == 1)
	      query.bindValue
		(2, 2.5 * spoton_common::STATUS_INTERVAL);
	    else
	      query.bindValue
		(2, 2.5 * spoton_common::POPTASTIC_STATUS_INTERVAL);

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(interfaces() <= 0)
    return;

  QByteArray status
    (setting("gui/my_status", "Online").toByteArray().toLower());

  if(status == "offline")
    return;

  prepareStatus("chat");

  if(m_lastPoptasticStatus.secsTo(QDateTime::currentDateTime()) >=
     spoton_common::POPTASTIC_STATUS_INTERVAL)
    prepareStatus("poptastic");
}

void spoton_kernel::prepareStatus(const QString &keyType)
{
  spoton_crypt *s_crypt1 = s_crypts.value(keyType, 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value
    (QString("%1-signature").arg(keyType), 0);

  if(!s_crypt2)
    return;

  QByteArray publicKey;
  QByteArray myPublicKeyHash;
  bool ok = true;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  myPublicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  QByteArray status(setting("gui/my_status", "Online").
		    toByteArray().toLower());

  if(status == "custom")
    status = setting("gui/customStatus", "").toByteArray().trimmed();

  QHash<QString, QVariant> hash;
  QList<QByteArray> list;
  QString connectionName("");
  QStringList receiverNames;

  if(keyType == "poptastic")
    hash = spoton_misc::poptasticSettings(s_crypt1, &ok);

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT gemini, public_key, "
		      "gemini_hash_key, name "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND "
		      "strftime('%s', ?) - "
		      "strftime('%s', last_status_update) <= ? AND "
		      "neighbor_oid = -1");
	query.bindValue(0, s_crypt1->keyedHash(keyType.toLatin1(),
					       &ok).toBase64());
	query.bindValue
	  (1, QDateTime::currentDateTime().toString(Qt::ISODate));

	if(keyType == "chat")
	  query.bindValue
	    (2, 2.5 * spoton_common::STATUS_INTERVAL);
	else
	  query.bindValue
	    (2, 2.5 * spoton_common::POPTASTIC_STATUS_INTERVAL);

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray data;
	      QByteArray publicKey;
	      QByteArray receiverName;
	      QPair<QByteArray, QByteArray> gemini;
	      bool ok = true;

	      if(!query.isNull(0))
		gemini.first = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.
					  value(0).
					  toByteArray()),
		   &ok);

	      if(ok)
		publicKey = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.
					  value(1).
					  toByteArray()),
		   &ok);

	      if(ok)
		if(!query.isNull(2))
		  gemini.second = s_crypt1->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.
					    value(2).
					    toByteArray()),
		     &ok);

	      if(ok)
		receiverName = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.
					  value(3).
					  toByteArray()),
		   &ok).constData();

	      if(!ok)
		continue;

	      QByteArray cipherType
		(setting("gui/kernelCipherType", "aes256").
		 toString().toLatin1());
	      QByteArray hashKey;
	      QByteArray hashType(setting("gui/kernelHashType",
					  "sha512").toString().toLatin1());
	      QByteArray keyInformation;
	      QByteArray name;

	      if(keyType == "chat")
		name = setting("gui/nodeName", "unknown").
		  toByteArray();
	      else
		name = hash["in_username"].toByteArray();

	      if(name.isEmpty())
		{
		  if(keyType == "chat")
		    name = "unknown";
		  else
		    name = "unknown@unknown.org";
		}

	      QByteArray symmetricKey;
	      size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		(cipherType);

	      if(symmetricKeyLength > 0)
		{
		  hashKey.resize(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		  hashKey = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (hashKey.length()));
		  symmetricKey.resize(static_cast<int> (symmetricKeyLength));
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (symmetricKey.length()));
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotStatusTimerExpired(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      if(ok)
		{
		  QDataStream stream(&keyInformation, QIODevice::WriteOnly);

		  stream << QByteArray("0013")
			 << symmetricKey
			 << hashKey
			 << cipherType
			 << hashType;

		  if(stream.status() != QDataStream::Ok)
		    ok = false;

		  if(ok)
		    keyInformation = spoton_crypt::publicKeyEncrypt
		      (keyInformation, publicKey, &ok);
		}

	      if(ok)
		{
		  {
		    /*
		    ** We would like crypt to be destroyed as
		    ** soon as possible.
		    */

		    QByteArray signature;
		    QDateTime dateTime(QDateTime::currentDateTime());
		    spoton_crypt crypt(cipherType,
				       hashType,
				       QByteArray(),
				       symmetricKey,
				       hashKey,
				       0,
				       0,
				       "");

		    if(setting("gui/chatSignMessages", true).toBool())
		      signature = s_crypt2->digitalSignature
			("0013" +
			 symmetricKey +
			 hashKey +
			 cipherType +
			 hashType +
			 myPublicKeyHash +
			 name +
			 status +
			 dateTime.toUTC().toString("MMddyyyyhhmmss").
			 toLatin1(), &ok);

		    if(ok)
		      {
			QDataStream stream(&data, QIODevice::WriteOnly);

			stream << myPublicKeyHash
			       << name
			       << status
			       << dateTime.toUTC().toString("MMddyyyyhhmmss").
			          toLatin1()
			       << signature;

			if(stream.status() != QDataStream::Ok)
			  ok = false;

			if(ok)
			  data = crypt.encrypted(data, &ok);
		      }

		    if(ok)
		      {
			QByteArray messageCode
			  (crypt.keyedHash(keyInformation + data, &ok));

			if(ok)
			  data = keyInformation.toBase64() + "\n" +
			    data.toBase64() + "\n" +
			    messageCode.toBase64();
		      }
		  }

		  if(ok)
		    if(!gemini.first.isEmpty() &&
		       !gemini.second.isEmpty())
		      {
			QByteArray bytes;
			QByteArray messageCode;
			QDataStream stream(&bytes, QIODevice::WriteOnly);
			spoton_crypt crypt("aes256",
					   "sha512" ,
					   QByteArray(),
					   gemini.first,
					   gemini.second,
					   0,
					   0,
					   "");

			stream << QByteArray("0013")
			       << data;

			if(stream.status() != QDataStream::Ok)
			  ok = false;

			if(ok)
			  data = crypt.encrypted(bytes, &ok);

			if(ok)
			  messageCode = crypt.keyedHash(data, &ok);

			if(ok)
			  {
			    data = data.toBase64();
			    data.append("\n");
			    data.append(messageCode.toBase64());
			  }
		      }

		  if(ok)
		    {
		      list.append(data);
		      receiverNames.append(receiverName);
		    }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!list.isEmpty())
    {
      if(keyType == "chat")
	emit sendStatus(list);
      else
	while(!list.isEmpty())
	  {
	    QByteArray message(spoton_send::message0013(list.takeFirst()));

	    postPoptasticMessage(receiverNames.takeFirst(), message);
	  }
    }
}

void spoton_kernel::slotScramble(void)
{
  QByteArray cipherType(setting("gui/kernelCipherType",
				"aes256").toString().toLatin1());
  QByteArray data;
  QByteArray hashType(setting("gui/kernelHashType",
			      "sha512").toString().toLatin1());
  QByteArray message(qrand() % 1024 + 512, 0);
  QByteArray messageCode;
  QByteArray symmetricKey;
  bool ok = true;
  size_t symmetricKeyLength = spoton_crypt::cipherKeyLength(cipherType);

  if(symmetricKeyLength > 0)
    {
      symmetricKey.resize(static_cast<int> (symmetricKeyLength));
      symmetricKey = spoton_crypt::strongRandomBytes
	(static_cast<size_t> (symmetricKey.length()));
    }
  else
    ok = false;

  if(ok)
    {
      spoton_crypt crypt
	(cipherType,
	 hashType,
	 QByteArray(),
	 symmetricKey,
	 spoton_crypt::
	 strongRandomBytes(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES),
	 0,
	 0,
	 "");

      data = crypt.encrypted(message, &ok);

      if(ok)
	messageCode = crypt.keyedHash(data, &ok);

      if(ok)
	{
	  data = data.toBase64();
	  data.append("\n");
	  data.append(messageCode.toBase64());
	}
    }

  if(ok)
    {
      if(setting("gui/chatSendMethod",
		 "Artificial_GET").toString().toLower() == "artificial_get")
	emit sendMessage(data, spoton_send::ARTIFICIAL_GET);
      else
	emit sendMessage(data, spoton_send::NORMAL_POST);
    }
}

void spoton_kernel::slotRetrieveMail(void)
{
  if(m_poptasticPopFuture.isFinished())
    m_poptasticPopFuture =
      QtConcurrent::run(this, &spoton_kernel::popPoptastic);

  spoton_crypt *s_crypt = s_crypts.value("email-signature", 0);

  if(!s_crypt)
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = s_crypt->publicKey(&ok); /*
				       ** Signature public key.
				       */

  if(!ok)
    return;

  QByteArray myPublicKeyHash(spoton_crypt::sha512Hash(publicKey, &ok));

  if(!ok)
    return;

  QList<QByteArray> list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	/*
	** Much of this is duplicated in the below branch.
	*/

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT cipher_type, hash_type, "
		      "name, postal_address FROM institutions"))
	  while(query.next())
	    {
	      QByteArray data;
	      QByteArray hashType;
	      QByteArray institutionName;
	      QByteArray institutionPostalAddress;
	      QByteArray message1(spoton_crypt::strongRandomBytes(64));
	      QByteArray message2(spoton_crypt::strongRandomBytes(64));
	      QByteArray requesterHashInformation;
	      QByteArray signature;
	      QString cipherType("");
	      bool ok = true;

	      cipherType = s_crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok).constData();

	      if(ok)
		hashType = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		institutionName = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		institutionPostalAddress = s_crypt->
		  decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(ok)
		requesterHashInformation = spoton_crypt::keyedHash
		  (message1 + publicKey,
		   institutionPostalAddress, hashType, &ok);

	      QDateTime dateTime(QDateTime::currentDateTime());

	      if(ok)
		signature = s_crypt->digitalSignature
		  (QByteArray("0002b") +
		   message1 + requesterHashInformation + message2 +
		   dateTime.toUTC().toString("MMddyyyyhhmmss").
		   toLatin1(), &ok);

	      if(!ok)
		continue;

	      spoton_crypt crypt(cipherType,
				 hashType,
				 QByteArray(),
				 institutionName,
				 institutionPostalAddress,
				 0,
				 0,
				 "");

	      data = crypt.encrypted
		(QByteArray("0002b").toBase64() + "\n" +
		 message1.toBase64() + "\n" +
		 requesterHashInformation.toBase64() + "\n" +
		 message2.toBase64() + "\n" +
		 dateTime.toUTC().toString("MMddyyyyhhmmss").
		 toLatin1().toBase64() + "\n" +
		 signature.toBase64(), &ok);

	      if(ok)
		{
		  QByteArray messageCode(crypt.keyedHash(data, &ok));

		  if(ok)
		    data = data.toBase64() + "\n" +
		      messageCode.toBase64();
		}

	      if(ok)
		list.append(data);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!list.isEmpty())
    emit retrieveMail(list, "0002b");

  list.clear();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND neighbor_oid = -1");
	query.bindValue(0, s_crypt->keyedHash(QByteArray("email"), &ok).
			toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray cipherType
		(setting("gui/kernelCipherType", "aes256").
		 toString().toLatin1());
	      QByteArray data;
	      QByteArray hashKey;
	      QByteArray hashType(setting("gui/kernelHashType",
					  "sha512").toString().toLatin1());
	      QByteArray keyInformation;
	      QByteArray message(spoton_crypt::strongRandomBytes(64));
	      QByteArray publicKey;
	      QByteArray signature;
	      QByteArray symmetricKey;
	      bool ok = true;
	      size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		(cipherType);

	      publicKey = s_crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(symmetricKeyLength > 0)
		{
		  hashKey.resize(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		  hashKey = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (hashKey.length()));
		  symmetricKey.resize(static_cast<int> (symmetricKeyLength));
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (symmetricKey.length()));
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotRetrieveMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      if(ok)
		keyInformation = spoton_crypt::publicKeyEncrypt
		  (QByteArray("0002a").toBase64() + "\n" +
		   symmetricKey.toBase64() + "\n" +
		   hashKey.toBase64() + "\n" +
		   cipherType.toBase64() + "\n" +
		   hashType.toBase64(),
		   publicKey, &ok);

	      if(ok)
		{
		  data.append
		    (spoton_crypt::publicKeyEncrypt(myPublicKeyHash,
						    publicKey, &ok).
		     toBase64());
		  data.append("\n");
		}

	      QDateTime dateTime(QDateTime::currentDateTime());

	      if(ok)
		signature = s_crypt->digitalSignature
		  ("0002a" +
		   symmetricKey +
		   hashKey +
		   cipherType +
		   hashType +
		   myPublicKeyHash +
		   message +
		   dateTime.toUTC().toString("MMddyyyyhhmmss").toLatin1(),
		   &ok);

	      if(ok)
		{
		  spoton_crypt crypt(cipherType,
				     hashType,
				     QByteArray(),
				     symmetricKey,
				     hashKey,
				     0,
				     0,
				     "");

		  data = crypt.encrypted
		    (myPublicKeyHash.toBase64() + "\n" +
		     message.toBase64() + "\n" +
		     dateTime.toUTC().toString("MMddyyyyhhmmss").
		     toLatin1().toBase64() + "\n" +
		     signature.toBase64(), &ok);

		  if(ok)
		    {
		      QByteArray messageCode
			(crypt.keyedHash(keyInformation + data, &ok));

		      if(ok)
			data = keyInformation.toBase64() + "\n" +
			  data.toBase64() + "\n" +
			  messageCode.toBase64();
		    }
		}

	      if(ok)
		list.append(data);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!list.isEmpty())
    emit retrieveMail(list, "0002a");
}

void spoton_kernel::slotSendMail(const QByteArray &goldbug,
				 const QByteArray &message,
				 const QByteArray &name,
				 const QByteArray &publicKey,
				 const QByteArray &subject,
				 const QByteArray &attachment,
				 const QByteArray &attachmentName,
				 const QByteArray &keyType,
				 const QByteArray &receiverName,
				 const QByteArray &mode,
				 const qint64 mailOid)
{
  if(keyType == "poptastic" && publicKey.contains("-poptastic"))
    {
      postPoptasticMessage
	(attachment, attachmentName, message, receiverName, subject, mode,
	 mailOid);
      return;
    }

  if(mode == "pure-forward-secrecy")
    {
      QByteArray data;

      if(prepareAlmostAnonymousEmail(attachment,
				     attachmentName,
				     goldbug,
				     keyType,
				     message,
				     name,
				     receiverName,
				     subject,
				     mailOid,
				     data))
	{
	  QPair<QByteArray, qint64> pair(data, mailOid);

	  emit sendMail
	    (QList<QPair<QByteArray, qint64> > () << pair, "0001c");
	  return;
	}
    }

  spoton_crypt *s_crypt1 = s_crypts.value(keyType, 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value
    (QString("%1-signature").arg(keyType.constData()), 0);

  if(!s_crypt2)
    return;

  /*
  ** name: my name
  ** publicKey: recipient's public key
  ** mode: forward-secrecy, normal, pure-forward-secrecy
  */

  QByteArray myPublicKey;
  bool ok = true;

  myPublicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  QByteArray myPublicKeyHash(spoton_crypt::sha512Hash(myPublicKey, &ok));

  if(!ok)
    return;

  QByteArray recipientHash;

  recipientHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  QList<QPair<QByteArray, qint64> > list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open() || keyType == "poptastic")
      {
	/*
	** Much of this is duplicated in the below branch.
	*/

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(keyType == "poptastic" ||
	   query.exec("SELECT cipher_type, "
		      "hash_type, name, postal_address FROM institutions"))
	  while(keyType == "poptastic" || query.next())
	    {
	      QByteArray cipherType
		(setting("gui/kernelCipherType", "aes256").
		 toString().toLatin1());
	      QByteArray data;
	      QByteArray hashKey;
	      QByteArray hashType(setting("gui/kernelHashType",
					  "sha512").toString().toLatin1());
	      QByteArray institutionHashType;
	      QByteArray institutionName;
	      QByteArray institutionPostalAddress;
	      QByteArray keyInformation;
	      QByteArray messageCode1;
	      QByteArray messageCode2;
	      QByteArray randomBytes(spoton_crypt::strongRandomBytes(64));
	      QByteArray recipientHashInformation;
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm;
	      QString institutionCipherType;
	      bool goldbugUsed = false;
	      bool ok = true;

	      if(keyType == "email")
		{
		  institutionCipherType = s_crypt1->
		    decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(0).toByteArray()),
		     &ok).constData();

		  if(ok)
		    institutionHashType = s_crypt1->
		      decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(1).toByteArray()),
		       &ok);

		  if(ok)
		    institutionName = s_crypt1->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(2).toByteArray()),
		       &ok);

		  if(ok)
		    institutionPostalAddress = s_crypt1->
		      decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(3).toByteArray()),
		       &ok);
		}
	      else
		{
		  /*
		  ** Artificial credentials.
		  */

		  institutionCipherType = "aes256";
		  institutionHashType = "sha512";
		  institutionName = spoton_crypt::weakRandomBytes
		    (spoton_crypt::cipherKeyLength("aes256"));
		  institutionPostalAddress =
		    spoton_crypt::weakRandomBytes
		    (spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		}

	      if(!ok)
		{
		  if(keyType == "poptastic")
		    break;

		  continue;
		}

	      symmetricKeyAlgorithm = cipherType;

	      size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		(symmetricKeyAlgorithm);

	      if(symmetricKeyLength > 0)
		{
		  hashKey.resize(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		  hashKey = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (hashKey.length()));
		  symmetricKey.resize(static_cast<int> (symmetricKeyLength));
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (symmetricKey.length()));
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotSendMail(): "
		     "cipherKeyLength() failure.");

		  if(keyType == "poptastic")
		    break;

		  continue;
		}

	      keyInformation = spoton_crypt::publicKeyEncrypt
		(QByteArray("0001b").toBase64() + "\n" +
		 symmetricKey.toBase64() + "\n" +
		 hashKey.toBase64() + "\n" +
		 symmetricKeyAlgorithm.toBase64() + "\n" +
		 hashType.toBase64(),
		 publicKey, &ok);

	      QList<QByteArray> items;

	      if(ok)
		{
		  if(attachment.isEmpty() || attachmentName.isEmpty())
		    items << name
			  << subject
			  << message
			  << QByteArray()
			  << QByteArray();
		  else
		    items << name
			  << subject
			  << message
			  << qCompress(attachment, 9)
			  << attachmentName;
		}

	      if(ok)
		if(!goldbug.isEmpty())
		  {
		    spoton_crypt *crypt = spoton_misc::
		      cryptFromForwardSecrecyMagnet(goldbug);

		    if(crypt)
		      for(int i = 0; i < items.size(); i++)
			{
			  if(ok)
			    items.replace
			      (i, crypt->encryptedThenHashed(items.at(i),
							     &ok));
			  else
			    break;
			}

		    if(crypt && ok)
		      goldbugUsed = true;

		    delete crypt;
		  }

	      if(ok)
		{
		  QByteArray signature;
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     hashType,
				     QByteArray(),
				     symmetricKey,
				     hashKey,
				     0,
				     0,
				     "");

		  if(setting("gui/emailSignMessages",
			     true).toBool())
		    signature = s_crypt2->digitalSignature
		      ("0001b" +
		       symmetricKey +
		       hashKey +
		       symmetricKeyAlgorithm +
		       hashType +
		       myPublicKeyHash +
		       items.value(0) + // Name
		       items.value(1) + // Subject
		       items.value(2) + // Message
		       items.value(3) + // Attachment
		       items.value(4),  // Attachment Name
		       &ok);

		  if(ok)
		    data = crypt.encrypted
		      (myPublicKeyHash.toBase64() + "\n" +
		       items.value(0).toBase64() + "\n" + // Name
		       items.value(1).toBase64() + "\n" + // Subject
		       items.value(2).toBase64() + "\n" + // Message
		       items.value(3).toBase64() + "\n" + // Attachment
		       items.value(4).toBase64() + "\n" + // Attachment Name
		       signature.toBase64() + "\n" +
		       QVariant(goldbugUsed).toByteArray().toBase64(),
		       &ok);

		  if(ok)
		    messageCode1 = crypt.keyedHash
		      (keyInformation + data, &ok);

		  if(ok)
		    recipientHashInformation = spoton_crypt::keyedHash
		      (randomBytes + publicKey, institutionPostalAddress,
		       institutionHashType, &ok);

		  if(ok)
		    messageCode2 = spoton_crypt::keyedHash
		      (keyInformation + data +
		       messageCode1 + randomBytes + recipientHashInformation,
		       institutionPostalAddress, institutionHashType, &ok);

		  if(ok)
		    data = keyInformation.toBase64() + "\n" +
		      data.toBase64() + "\n" +
		      messageCode1.toBase64() + "\n" +
		      randomBytes.toBase64() + "\n" +
		      recipientHashInformation.toBase64() + "\n" +
		      messageCode2.toBase64();
		}

	      if(ok)
		{
		  QPair<QByteArray, qint64> pair(data, mailOid);

		  list.append(pair);
		}

	      if(keyType == "poptastic")
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!list.isEmpty())
    {
      if(keyType == "email")
	emit sendMail(list, "0001b");
      else
	{
	  QByteArray message(spoton_send::message0001b(list.first().first));

	  postPoptasticMessage(receiverName, message, mailOid);
	  return;
	}
    }

  list.clear();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	/*
	** Use all of our participants, including the recipients,
	** as mail carriers unless we're sending data
	** to one or more institutions.
	*/

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND neighbor_oid = -1");
	query.bindValue(0, s_crypt1->keyedHash(QByteArray("email"),
					       &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray cipherType
		(setting("gui/kernelCipherType", "aes256").
		 toString().toLatin1());
	      QByteArray data;
	      QByteArray data1;
	      QByteArray data2;
	      QByteArray hashKey1;
	      QByteArray hashKey2;
	      QByteArray hashType(setting("gui/kernelHashType",
					  "sha512").toString().toLatin1());
	      QByteArray keyInformation1;
	      QByteArray keyInformation2;
	      QByteArray messageCode1;
	      QByteArray messageCode2;
	      QByteArray participantPublicKey;
	      QByteArray symmetricKey;
	      bool goldbugUsed = false;
	      bool ok = true;
	      size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		(cipherType);

	      participantPublicKey = s_crypt1->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(!ok)
		continue;

	      if(symmetricKeyLength > 0)
		{
		  hashKey1.resize(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		  hashKey1 = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (hashKey1.length()));
		  symmetricKey.resize(static_cast<int> (symmetricKeyLength));
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (symmetricKey.length()));
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotSendMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      if(ok)
		keyInformation1 = spoton_crypt::publicKeyEncrypt
		  (QByteArray("0001a").toBase64() + "\n" +
		   symmetricKey.toBase64() + "\n" +
		   hashKey1.toBase64() + "\n" +
		   cipherType.toBase64() + "\n" +
		   hashType.toBase64(),
		   participantPublicKey, &ok);

	      if(ok)
		{
		  QByteArray signature;
		  spoton_crypt crypt(cipherType,
				     hashType,
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     "");

		  if(setting("gui/emailSignMessages",
			     true).toBool())
		    signature = s_crypt2->digitalSignature
		      ("0001a" +
		       symmetricKey +
		       hashKey1 +
		       cipherType +
		       hashType +
		       myPublicKeyHash +
		       recipientHash, &ok);

		  if(ok)
		    data1 = crypt.encrypted
		      (myPublicKeyHash.toBase64() + "\n" +
		       recipientHash.toBase64() + "\n" +
		       signature.toBase64(), &ok);
		}

	      if(!ok)
		continue;

	      symmetricKeyLength = spoton_crypt::cipherKeyLength(cipherType);

	      if(symmetricKeyLength > 0)
		{
		  hashKey2.resize(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		  hashKey2 = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (hashKey2.length()));
		  symmetricKey.resize(static_cast<int> (symmetricKeyLength));
		  symmetricKey = spoton_crypt::strongRandomBytes
		    (static_cast<size_t> (symmetricKey.length()));
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotSendMail(): "
		     "cipherKeyLength() failure.");
		  continue;
		}

	      keyInformation2 = spoton_crypt::publicKeyEncrypt
		/*
		** We need to store the message type 0001b here as
		** the data may be stored in a post office.
		*/

		(QByteArray("0001b").toBase64() + "\n" +
		 symmetricKey.toBase64() + "\n" +
		 hashKey2.toBase64() + "\n" +
		 cipherType.toBase64() + "\n" +
		 hashType.toBase64(),
		 publicKey, &ok);

	      QList<QByteArray> items;

	      if(ok)
		{
		  if(attachment.isEmpty() || attachmentName.isEmpty())
		    items << name
			  << subject
			  << message
			  << QByteArray()
			  << QByteArray();
		  else
		    items << name
			  << subject
			  << message
			  << qCompress(attachment, 9)
			  << attachmentName;
		}

	      if(ok)
		if(!goldbug.isEmpty())
		  {
		    spoton_crypt *crypt = spoton_misc::
		      cryptFromForwardSecrecyMagnet(goldbug);

		    if(crypt)
		      for(int i = 0; i < items.size(); i++)
			{
			  if(ok)
			    items.replace
			      (i,
			       crypt->encryptedThenHashed(items.at(i), &ok));
			  else
			    break;
			}

		    if(crypt && ok)
		      goldbugUsed = true;

		    delete crypt;
		  }

	      if(ok)
		{
		  QByteArray signature;
		  spoton_crypt crypt(cipherType,
				     hashType,
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     "");

		  if(setting("gui/emailSignMessages",
			     true).toBool())
		    signature = s_crypt2->digitalSignature
		      ("0001b" +
		       symmetricKey +
		       hashKey2 +
		       cipherType +
		       hashType +
		       myPublicKeyHash +
		       items.value(0) + // Name
		       items.value(1) + // Subject
		       items.value(2) + // Message
		       items.value(3) + // Attachment
		       items.value(4),  // Attachment Name
		       &ok);

		  if(ok)
		    data2 = crypt.encrypted
		      (myPublicKeyHash.toBase64() + "\n" +
		       items.value(0).toBase64() + "\n" + // Name
		       items.value(1).toBase64() + "\n" + // Subject
		       items.value(2).toBase64() + "\n" + // Message
		       items.value(3).toBase64() + "\n" + // Attachment
		       items.value(4).toBase64() + "\n" + // Attachment Name
		       signature.toBase64() + "\n" +
		       QVariant(goldbugUsed).toByteArray().toBase64(),
		       &ok);

		  if(ok)
		    messageCode1 = spoton_crypt::keyedHash
		      (keyInformation1 + data1 + keyInformation2 + data2,
		       hashKey1, hashType, &ok);

		  if(ok)
		    messageCode2 = spoton_crypt::keyedHash
		      (keyInformation2 + data2, hashKey2, hashType, &ok);
		}

	      if(ok)
		{
		  data = keyInformation1.toBase64() + "\n" +
		    data1.toBase64() + "\n" +
		    keyInformation2.toBase64() + "\n" +
		    data2.toBase64() + "\n" +
		    messageCode2.toBase64() + "\n" +
		    messageCode1.toBase64();

		  QPair<QByteArray, qint64> pair(data, mailOid);

		  list.append(pair);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!list.isEmpty())
    emit sendMail(list, "0001a");
}

bool spoton_kernel::initializeSecurityContainers(const QString &passphrase,
						 const QString &answer)
{
  QByteArray computedHash;
  QByteArray salt(setting("gui/salt", "").toByteArray());
  QByteArray saltedPassphraseHash
    (setting("gui/saltedPassphraseHash", "").toByteArray());
  QString error("");
  bool ok = false;

  if(answer.isEmpty())
    computedHash = spoton_crypt::saltedPassphraseHash
      (setting("gui/hashType", "sha512").toString(), passphrase, salt, error);
  else
    {
      bool ok = true;

      computedHash = spoton_crypt::keyedHash
	(passphrase.toUtf8(), answer.toUtf8(),
	 setting("gui/hashType", "sha512").toByteArray(), &ok);

      if(!ok)
	error = "keyed hash failure";
    }

  if(!computedHash.isEmpty() && !saltedPassphraseHash.isEmpty() &&
     spoton_crypt::memcmp(computedHash, saltedPassphraseHash))
    if(error.isEmpty())
      {
	QPair<QByteArray, QByteArray> keys
	  (spoton_crypt::
	   derivedKeys(setting("gui/cipherType",
			       "aes256").toString(),
		       setting("gui/hashType",
			       "sha512").toString(),
		       static_cast<unsigned long> (setting("gui/"
							   "iterationCount",
							   10000).toInt()),
		       passphrase,
		       salt,
		       error));

	if(error.isEmpty())
	  {
	    ok = true;

	    QStringList list;

	    list << "chat"
		 << "chat-signature"
		 << "email"
		 << "email-signature"
		 << "poptastic"
		 << "poptastic-signature"
		 << "url"
		 << "url-signature";

	    for(int i = 0; i < list.size(); i++)
	      if(!s_crypts.contains(list.at(i)))
		{
		  spoton_crypt *crypt = 0;

		  try
		    {
		      crypt = new spoton_crypt
			(setting("gui/cipherType",
				 "aes256").toString(),
			 setting("gui/hashType",
				 "sha512").toString(),
			 QByteArray(),
			 keys.first,
			 keys.second,
			 setting("gui/saltLength", 512).toInt(),
			 static_cast<unsigned long> (setting("gui/"
							     "iterationCount",
							     10000).
						     toInt()),
			 list.at(i));
		    }
		  catch(const std::bad_alloc &exception)
		    {
		      crypt = 0;
		    }
		  catch(...)
		    {
		      if(crypt)
			{
			  delete crypt;
			  crypt = 0;
			}
		    }

		  if(crypt)
		    s_crypts.insert(list.at(i), crypt);
		  else
		    s_crypts.remove(list.at(i));
		}

	    for(int i = 0; i < list.size(); i++)
	      if(!s_crypts.value(list.at(i), 0))
		spoton_misc::logError
		  ("spoton_kernel::initializeSecurityContainers(): "
		   "potential memory failure. Critical!");
	  }
      }

  return ok;
}

void spoton_kernel::cleanupListenersDatabase(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QSqlQuery query(db);

  query.exec("PRAGMA secure_delete = ON");
  query.exec("DELETE FROM listeners WHERE "
	     "status_control = 'deleted'");
  query.exec("DELETE FROM listeners_accounts WHERE "
	     "listener_oid NOT IN "
	     "(SELECT OID FROM listeners)");
  query.exec("DELETE FROM listeners_accounts_consumed_authentications WHERE "
	     "listener_oid NOT IN "
	     "(SELECT OID FROM listeners)");
  query.exec("DELETE FROM listeners_allowed_ips WHERE "
	     "listener_oid NOT IN "
	     "(SELECT OID FROM listeners)");
}

void spoton_kernel::cleanupNeighborsDatabase(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QSqlQuery query(db);

  query.exec("PRAGMA secure_delete = ON");
  query.exec("DELETE FROM neighbors WHERE "
	     "status_control = 'deleted'");
}

void spoton_kernel::cleanupStarbeamsDatabase(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QSqlQuery query(db);

  query.exec("PRAGMA secure_delete = ON");
  query.exec("DELETE FROM transmitted WHERE "
	     "status = 'deleted'");
  query.exec("DELETE FROM transmitted_magnets WHERE "
	     "transmitted_oid NOT IN "
	     "(SELECT OID FROM transmitted)");
  query.exec("DELETE FROM transmitted_scheduled_pulses WHERE "
	     "transmitted_oid NOT IN "
	     "(SELECT OID FROM transmitted)");
}

void spoton_kernel::slotPublicizeAllListenersPlaintext(void)
{
  QHashIterator<qint64, QPointer<spoton_listener> > it(m_listeners);

  while(it.hasNext())
    {
      it.next();

      QPointer<spoton_listener> listener = it.value();

      if(listener)
	if(!listener->externalAddress().isNull())
	  emit publicizeListenerPlaintext(listener->externalAddress(),
					  listener->externalPort(),
					  listener->transport(),
					  listener->orientation());
    }
}

void spoton_kernel::slotPublicizeListenerPlaintext(const qint64 oid)
{
  QPointer<spoton_listener> listener = m_listeners.value(oid, 0);

  if(listener)
    if(!listener->externalAddress().isNull())
      emit publicizeListenerPlaintext(listener->externalAddress(),
				      listener->externalPort(),
				      listener->transport(),
				      listener->orientation());
}

void spoton_kernel::slotRequestScramble(void)
{
  /*
  ** Send a scrambled message in proximity of a received message.
  */

  if(setting("gui/scramblerEnabled", false).toBool())
    {
      if(!m_scramblerTimer.isActive())
	m_scramblerTimer.start(qrand() % 5000 + 10000);
    }
  else
    m_scramblerTimer.stop();
}

void spoton_kernel::slotBuzzReceivedFromUI(const QByteArray &key,
					   const QByteArray &channelType,
					   const QByteArray &name,
					   const QByteArray &id,
					   const QByteArray &message,
					   const QByteArray &sendMethod,
					   const QString &messageType,
					   const QByteArray &hashKey,
					   const QByteArray &hashType)
{
  QByteArray data;
  QByteArray messageCode;
  QDataStream stream(&data, QIODevice::WriteOnly);
  bool ok = true;
  spoton_crypt crypt(channelType,
		     hashType,
		     QByteArray(),
		     key,
		     hashKey,
		     0,
		     0,
		     "");

  stream << messageType.toLatin1();

  if(stream.status() != QDataStream::Ok)
    ok = false;

  if(ok)
    {
      if(messageType == "0040a")
	stream << name
	       << id;
      else
	stream << name
	       << id
	       << message;

      if(stream.status() != QDataStream::Ok)
	ok = false;
    }

  if(ok)
    data = crypt.encrypted(data, &ok);

  if(ok)
    messageCode = crypt.keyedHash(data, &ok);

  if(ok)
    data = data.toBase64() + "\n" + messageCode.toBase64();

  if(ok)
    {
      if(messageType == "0040a")
	emit sendBuzz(spoton_send::message0040a(data));
      else
	{
	  if(sendMethod.toLower() == "artificial_get")
	    emit sendBuzz
	      (spoton_send::message0040b(data,
					 spoton_send::ARTIFICIAL_GET));
	  else
	    emit sendBuzz
	      (spoton_send::message0040b(data,
					 spoton_send::NORMAL_POST));
	}
    }
}

void spoton_kernel::slotMessagingCachePurge(void)
{
  if(m_future.isFinished())
    m_future = QtConcurrent::run
      (this, &spoton_kernel::purgeMessagingCache);
}

void spoton_kernel::purgeMessagingCache(void)
{
  /*
  ** Remove expired e-mail requests.
  */

  QWriteLocker locker1(&s_emailRequestCacheMutex);
  QMutableHashIterator<QByteArray, uint> it1(s_emailRequestCache);

  while(it1.hasNext())
    {
      it1.next();

      uint now = QDateTime::currentDateTime().toTime_t();

      if(now > it1.value())
	if(now - it1.value() > static_cast<uint> (spoton_common::
						  MAIL_TIME_DELTA_MAXIMUM))
	  it1.remove();

      if(m_future.isCanceled())
	return;
    }

  locker1.unlock();

  /*
  ** Remove expired geminis.
  */

  QWriteLocker locker2(&s_geminisCacheMutex);
  QMutableHashIterator<QByteArray, uint> it2(s_geminisCache);

  while(it2.hasNext())
    {
      it2.next();

      uint now = QDateTime::currentDateTime().toTime_t();

      if(now > it2.value())
	if(now - it2.value() > static_cast<uint> (spoton_common::
						  GEMINI_TIME_DELTA_MAXIMUM))
	  it2.remove();

      if(m_future.isCanceled())
	return;
    }

  locker2.unlock();

  /*
  ** Remove expired cache items.
  */

  QWriteLocker locker3(&s_messagingCacheMutex);
  QMutableMapIterator<uint, QByteArray> it3(s_messagingCacheLookup);
  int i = 0;
  int maximum = qMax(250, qCeil(0.15 * s_messagingCacheLookup.size()));

  while(it3.hasNext())
    {
      i += 1;

      if(i >= maximum)
	break;

      it3.next();

      uint now = QDateTime::currentDateTime().toTime_t();

      if(now > it3.key())
	if(now - it3.key() > static_cast<uint> (spoton_common::
						CACHE_TIME_DELTA_MAXIMUM))
	  {
	    QList<QByteArray> values
	      (s_messagingCacheLookup.values(it3.key()));

	    while(!values.isEmpty())
	      {
		s_messagingCache.remove(values.takeFirst());

		if(m_future.isCanceled())
		  return;
	      }

	    it3.remove();
	  }

      if(m_future.isCanceled())
	return;
    }
}

bool spoton_kernel::messagingCacheContains(const QByteArray &data,
					   const bool do_not_hash)
{
  QByteArray hash;

  if(!do_not_hash)
    {
      bool ok = true;

      hash = spoton_crypt::keyedHash
	(data, s_messagingCacheKey,
	 setting("kernel/messaging_cache_algorithm", "sha224").
	 toString().toLatin1(), &ok);

      if(!ok)
	return false;
    }
  else
    hash = data;

  QReadLocker locker(&s_messagingCacheMutex);

  return s_messagingCache.contains(hash);
}

void spoton_kernel::messagingCacheAdd(const QByteArray &data,
				      const bool do_not_hash,
				      const int add_msecs)
{
  QByteArray hash;

  if(!do_not_hash)
    {
      bool ok = true;

      hash = spoton_crypt::keyedHash
	(data, s_messagingCacheKey,
	 setting("kernel/messaging_cache_algorithm", "sha224").
	 toString().toLatin1(), &ok);

      if(!ok)
	return;
    }
  else
    hash = data;

  int cost = setting("gui/congestionCost", 10000).toInt();

  QWriteLocker locker(&s_messagingCacheMutex);

  if(!s_messagingCache.contains(hash))
    {
      if(cost <= s_messagingCache.size())
	return;

      s_messagingCache.insert(hash, 0);
      s_messagingCacheLookup.insert
	(QDateTime::currentDateTime().addMSecs(add_msecs).toTime_t(), hash);
    }
}

void spoton_kernel::slotDetachNeighbors(const qint64 listenerOid)
{
  QPointer<spoton_listener> listener = 0;

  if(m_listeners.contains(listenerOid))
    listener = m_listeners.value(listenerOid, 0);
  else
    spoton_misc::logError(QString("spoton_kernel::slotDetachNeighbors(): "
				  "listener %1 not found.").
			  arg(listenerOid));

  if(listener)
    {
      foreach(spoton_neighbor *socket,
	      listener->findChildren<spoton_neighbor *> ())
	socket->setParent(this);

      listener->updateConnectionCount();
    }
}

void spoton_kernel::slotDisconnectNeighbors(const qint64 listenerOid)
{
  QPointer<spoton_listener> listener = 0;

  if(m_listeners.contains(listenerOid))
    listener = m_listeners.value(listenerOid, 0);

  if(listener)
    foreach(spoton_neighbor *socket,
	    listener->findChildren<spoton_neighbor *> ())
      socket->deleteLater();
}

void spoton_kernel::addBuzzKey(const QByteArray &key,
			       const QByteArray &channelType,
			       const QByteArray &hashKey,
			       const QByteArray &hashType)
{
  if(key.isEmpty() || channelType.isEmpty() ||
     hashKey.isEmpty() || hashType.isEmpty())
    return;

  QList<QByteArray> list;

  list << key << channelType << hashKey << hashType;

  QWriteLocker locker(&s_buzzKeysMutex);

  s_buzzKeys.insert(key, list);
}

void spoton_kernel::removeBuzzKey(const QByteArray &key)
{
  QWriteLocker locker(&s_buzzKeysMutex);

  s_buzzKeys.remove(key);
}

QList<QByteArray> spoton_kernel::findBuzzKey
(const QByteArray &data, const QByteArray &hash)
{
  if(hash.isEmpty())
    return QList<QByteArray> ();

  QReadLocker locker(&s_buzzKeysMutex);

  if(s_buzzKeys.isEmpty())
    return QList<QByteArray> ();

  QHashIterator<QByteArray, QList<QByteArray> > it(s_buzzKeys);
  QList<QByteArray> list;

  while(it.hasNext())
    {
      it.next();

      QByteArray computedHash;
      bool ok = true;

      computedHash = spoton_crypt::keyedHash
	(data, it.value().value(2), it.value().value(3), &ok);

      if(ok)
	if(!computedHash.isEmpty() && !hash.isEmpty() &&
	   spoton_crypt::memcmp(computedHash, hash))
	  {
	    list = it.value();
	    break;
	  }
    }

  return list;
}

void spoton_kernel::clearBuzzKeysContainer(void)
{
  QWriteLocker locker(&s_buzzKeysMutex);

  s_buzzKeys.clear();
}

int spoton_kernel::interfaces(void)
{
  if(instance())
    {
      if(!instance()->m_guiServer)
	return 0;

      int count = 0;

      foreach(QSslSocket *socket, instance()->m_guiServer->
	      findChildren<QSslSocket *> ())
	count += socket->isEncrypted();

      return count;
    }
  else
    return 0;
}

void spoton_kernel::slotCallParticipant(const QByteArray &keyType,
					const qint64 oid)
{
  spoton_crypt *s_crypt1 = s_crypts.value(keyType, 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value
    (QString("%1-signature").arg(keyType.constData()), 0);

  if(!s_crypt2)
    return;

  QByteArray publicKey;
  QByteArray myPublicKeyHash;
  bool ok = false;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  myPublicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;
  else
    ok = false;

  QByteArray data;
  QString connectionName("");
  QString receiverName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT gemini, public_key, "
		      "gemini_hash_key, name "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash IN (?, ?) AND neighbor_oid = -1 AND "
		      "OID = ?");
	query.bindValue(0, s_crypt1->keyedHash(QByteArray("chat"),
					       &ok).toBase64());

	if(ok)
	  query.bindValue(1, s_crypt1->keyedHash(QByteArray("poptastic"),
						 &ok).toBase64());

	query.bindValue(2, oid);

	if(ok && query.exec())
	  if(query.next())
	    {
	      QByteArray publicKey;
	      QPair<QByteArray, QByteArray> gemini;

	      if(!query.isNull(0))
		gemini.first = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.
					  value(0).
					  toByteArray()),
		   &ok);

	      if(ok)
		publicKey = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		if(!query.isNull(2))
		  gemini.second = s_crypt1->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.
					    value(2).
					    toByteArray()),
		     &ok);

	      if(ok)
		receiverName = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.
					  value(3).
					  toByteArray()),
		   &ok);

	      QByteArray hashKey;
	      QByteArray hashType(setting("gui/kernelHashType",
					  "sha512").toString().toLatin1());
	      QByteArray keyInformation;
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm
		(setting("gui/kernelCipherType", "aes256").toString().
		 toLatin1());
	      size_t symmetricKeyLength = 0;

	      if(ok)
		{
		  symmetricKeyLength = spoton_crypt::cipherKeyLength
		    (symmetricKeyAlgorithm);

		  if(symmetricKeyLength > 0)
		    {
		      hashKey.resize
			(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		      hashKey = spoton_crypt::strongRandomBytes
			(static_cast<size_t> (hashKey.length()));
		      symmetricKey.resize
			(static_cast<int> (symmetricKeyLength));
		      symmetricKey = spoton_crypt::strongRandomBytes
			(static_cast<size_t> (symmetricKey.length()));
		    }
		  else
		    {
		      ok = false;
		      spoton_misc::logError
			("spoton_kernel::slotCallParticipant(): "
			 "cipherKeyLength() failure.");
		    }
		}

	      if(ok)
		{
		  QDataStream stream(&keyInformation, QIODevice::WriteOnly);

		  stream << QByteArray("0000a")
			 << symmetricKey
			 << hashKey
			 << symmetricKeyAlgorithm
			 << hashType;

		  if(stream.status() != QDataStream::Ok)
		    ok = false;

		  if(ok)
		    keyInformation = spoton_crypt::publicKeyEncrypt
		      (keyInformation, publicKey, &ok);
		}

	      if(ok)
		{
		  {
		    /*
		    ** We would like crypt to be destroyed as
		    ** soon as possible.
		    */

		    QByteArray signature;
		    QDateTime dateTime(QDateTime::currentDateTime());
		    spoton_crypt crypt(symmetricKeyAlgorithm,
				       hashType,
				       QByteArray(),
				       symmetricKey,
				       hashKey,
				       0,
				       0,
				       "");

		    if(setting("gui/chatSignMessages", true).toBool())
		      signature = s_crypt2->digitalSignature
			("0000a" +
			 symmetricKey +
			 hashKey +
			 symmetricKeyAlgorithm +
			 hashType +
			 myPublicKeyHash +
			 gemini.first +
			 gemini.second +
			 dateTime.toUTC().toString("MMddyyyyhhmmss").
			 toLatin1(), &ok);

		    if(ok)
		      {
			QDataStream stream(&data, QIODevice::WriteOnly);

			stream << myPublicKeyHash
			       << gemini.first
			       << gemini.second
			       << dateTime.toUTC().toString("MMddyyyyhhmmss").
			          toLatin1()
			       << signature;

			if(stream.status() != QDataStream::Ok)
			  ok = false;

			if(ok)
			  data = crypt.encrypted(data, &ok);
		      }

		    if(ok)
		      {
			QByteArray messageCode
			  (crypt.keyedHash(keyInformation + data, &ok));

			if(ok)
			  data = keyInformation.toBase64() + "\n" +
			    data.toBase64() + "\n" +
			    messageCode.toBase64();
		      }
		  }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      if(keyType == "poptastic")
	{
	  QByteArray message(spoton_send::message0000a(data));

	  postPoptasticMessage(receiverName, message);
	}
      else
	emit callParticipant(data, "0000a");
    }
}

void spoton_kernel::slotCallParticipantUsingGemini(const QByteArray &keyType,
						   const qint64 oid)
{
  spoton_crypt *s_crypt1 = s_crypts.value(keyType, 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value
    (QString("%1-signature").arg(keyType.constData()), 0);

  if(!s_crypt2)
    return;

  QByteArray publicKey;
  QByteArray myPublicKeyHash;
  bool ok = false;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  myPublicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;
  else
    ok = false;

  QByteArray data;
  QByteArray hashKey;
  QByteArray symmetricKey;
  QString connectionName("");
  QString receiverName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT gemini, public_key, "
		      "gemini_hash_key, name "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash IN (?, ?) AND neighbor_oid = -1 AND "
		      "OID = ?");
	query.bindValue(0, s_crypt1->keyedHash(QByteArray("chat"),
					       &ok).toBase64());

	if(ok)
	  query.bindValue(1, s_crypt1->keyedHash(QByteArray("poptastic"),
						 &ok).toBase64());

	query.bindValue(2, oid);

	if(ok && query.exec())
	  if(query.next())
	    {
	      QByteArray publicKey;
	      QPair<QByteArray, QByteArray> gemini;

	      if(!query.isNull(0))
		gemini.first = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.
					  value(0).
					  toByteArray()),
		   &ok);

	      if(ok)
		publicKey = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		if(!query.isNull(2))
		  gemini.second = s_crypt1->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.
					    value(2).
					    toByteArray()),
		     &ok);

	      if(ok)
		receiverName = s_crypt1->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.
					  value(3).
					  toByteArray()),
		   &ok);

	      QByteArray symmetricKeyAlgorithm("aes256");
	      size_t symmetricKeyLength = 0;

	      if(ok)
		{
		  symmetricKeyLength = spoton_crypt::cipherKeyLength
		    (symmetricKeyAlgorithm);

		  if(symmetricKeyLength > 0)
		    {
		      hashKey.resize
			(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		      hashKey = spoton_crypt::strongRandomBytes
			(static_cast<size_t> (hashKey.length()));
		      symmetricKey.resize
			(static_cast<int> (symmetricKeyLength));
		      symmetricKey = spoton_crypt::strongRandomBytes
			(static_cast<size_t> (symmetricKey.length()));
		    }
		  else
		    {
		      ok = false;
		      spoton_misc::logError
			("spoton_kernel::slotCallParticipantUsingGemini(): "
			 "cipherKeyLength() failure.");
		    }
		}

	      if(ok)
		{
		  {
		    /*
		    ** We would like crypt to be destroyed as
		    ** soon as possible.
		    */

		    QByteArray signature;
		    QDateTime dateTime(QDateTime::currentDateTime());
		    spoton_crypt crypt(symmetricKeyAlgorithm,
				       "sha512",
				       QByteArray(),
				       gemini.first,
				       gemini.second,
				       0,
				       0,
				       "");

		    if(setting("gui/chatSignMessages", true).toBool())
		      signature = s_crypt2->digitalSignature
			("0000b" + myPublicKeyHash + symmetricKey + hashKey +
			 dateTime.toUTC().toString("MMddyyyyhhmmss").
			 toLatin1(), &ok);

		    if(ok)
		      {
			QDataStream stream(&data, QIODevice::WriteOnly);

			stream << QByteArray("0000b")
			       << myPublicKeyHash
			       << symmetricKey
			       << hashKey
			       << dateTime.toUTC().toString("MMddyyyyhhmmss").
			          toLatin1()
			       << signature;

			if(stream.status() != QDataStream::Ok)
			  ok = false;

			if(ok)
			  data = crypt.encrypted(data, &ok);
		      }

		    if(ok)
		      {
			QByteArray messageCode
			  (crypt.keyedHash(data, &ok));

			if(ok)
			  data = data.toBase64() + "\n" +
			    messageCode.toBase64();
		      }
		  }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      QPair<QByteArray, QByteArray> gemini;

      gemini.first = symmetricKey;
      gemini.second = hashKey;

      if(spoton_misc::saveGemini(gemini, QString::number(oid), s_crypt1))
	{
	  if(keyType == "poptastic")
	    {
	      QByteArray message(spoton_send::message0000b(data));

	      postPoptasticMessage(receiverName, message);
	    }
	  else
	    emit callParticipant(data, "0000b");
	}
    }
}

QVariant spoton_kernel::setting(const QString &name,
				const QVariant &defaultValue)
{
  QReadLocker locker(&s_settingsMutex);

  return s_settings.value(name, defaultValue);
}

void spoton_kernel::updateStatistics(const QDateTime &uptime,
				     const int interfaces,
				     const int listeners,
				     const int neighbors,
				     const int starbeams)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QLocale locale;
	QSqlQuery query(db);
	int size = 0;
	qint64 v1 = 0;
	qint64 v2 = 0;

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Active Buzz Channels', ?)");

	QReadLocker locker1(&s_buzzKeysMutex);

	v1 = s_buzzKeys.size();
	locker1.unlock();
	query.bindValue(0, v1);
	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Active StarBeam Readers', ?)");
	query.bindValue(0, starbeams);
	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Active Threads', ?)");

	if(QThreadPool::globalInstance())
	  query.bindValue(0, QThreadPool::globalInstance()->
			  activeThreadCount());
	else
	  query.bindValue(0, -1);

	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Attached User Interfaces', ?)");
	query.bindValue(0, interfaces);
	query.exec();

	QReadLocker locker2(&s_messagingCacheMutex);

	size = s_messagingCache.size() *
	  (2 * s_messagingCache.keys().value(0).length() +
	   static_cast<int> (sizeof(char)) +
	   static_cast<int> (sizeof(uint)));
	v1 = s_messagingCache.size() + s_messagingCacheLookup.size();
	locker2.unlock();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Congestion Container(s) Approximate "
		      "MiB Consumed', ?)");
	query.bindValue
	  (0, QString("%1 MiB").arg(locale.toString(size / 1024)));
	query.exec();
	v2 = 2 * qMax(1, setting("gui/congestionCost", 10000).toInt());
	query.prepare
	  ("INSERT OR REPLACE INTO kernel_statistics "
	   "(statistic, value) "
	   "VALUES ('Congestion Container(s) Percent Consumed', ?)");
	query.bindValue
	  (0,
	   QString::number(100.00 * static_cast<double> (v1) /
			   static_cast<double> (v2), 'f', 2).append("%"));
	query.exec();
	query.prepare("INSERT OR REPLACE INTO KERNEL_STATISTICS "
		      "(statistic, value) "
		      "VALUES ('Database Accesses', ?)");
	query.bindValue
	  (0, locale.toString(spoton_misc::databaseAccesses()));
	query.exec();
	query.prepare("INSERT OR REPLACE INTO KERNEL_STATISTICS "
		      "(statistic, value) "
		      "VALUES ('Ephemeral Key Pairs', ?)");

	QReadLocker locker3(&m_forwardSecrecyKeysMutex);

	query.bindValue(0, locale.toString(m_forwardSecrecyKeys.size()));
	locker3.unlock();
	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Live Listeners', ?)");
	query.bindValue(0, listeners);
	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Live Neighbors', ?)");
	query.bindValue(0, locale.toString(neighbors));
	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Open Database Connections', ?)");
	query.bindValue
	  (0, locale.toString(QSqlDatabase::connectionNames().size()));
	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Total URLs Processed', ?)");

	QReadLocker locker4(&m_urlsProcessedMutex);

	query.bindValue
	  (0, QString("%1 URLs").arg(locale.toString(m_urlsProcessed)));
	locker4.unlock();
	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('URL Container Size', ?)");

	QReadLocker locker5(&m_urlListMutex);

	query.bindValue(0, locale.toString(m_urlList.size()));
	locker5.unlock();
	query.exec();
	query.prepare("INSERT OR REPLACE INTO kernel_statistics "
		      "(statistic, value) "
		      "VALUES ('Uptime', ?)");
	query.bindValue
	  (0, QString("%1 Minutes").
	   arg(QString::number(uptime.
			       secsTo(QDateTime::currentDateTime()) / 60.0,
			       'f', 1)));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_kernel::slotBuzzMagnetReceivedFromUI(const qint64 oid,
						 const QByteArray &magnet)
{
  QPointer<spoton_neighbor> neighbor = 0;

  if(m_neighbors.contains(oid))
    neighbor = m_neighbors[oid];

  if(!neighbor)
    {
      spoton_misc::logError
	(QString("spoton_kernel::slotBuzzMagnetReceivedFromUI(): "
		 "neighbor %1 not found in m_neighbors.").arg(oid));
      return;
    }
  else if(!neighbor->isEncrypted())
    {
      spoton_misc::logError
	(QString("spoton_kernel::slotBuzzMagnetReceivedFromUI(): "
		 "neighbor %1 is not encrypted.").arg(oid));
      return;
    }

  QByteArray data(spoton_send::message0065(magnet));

  if(neighbor->write(data.constData(), data.length()) != data.length())
    spoton_misc::logError
      (QString("spoton_kernel::slotBuzzMagnetReceivedFromUI(): "
	       "write() failure for %1:%2.").
       arg(neighbor->peerAddress().toString()).
       arg(neighbor->peerPort()));
  else
    neighbor->addToBytesWritten(data.length());
}

void spoton_kernel::writeMessage0060(const QByteArray &data, bool *ok)
{
  if(*ok)
    *ok = false;

  QHashIterator<qint64, QPointer<spoton_neighbor> > it(m_neighbors);

  while(it.hasNext())
    {
      it.next();

      if(it.value())
	if(it.value()->writeMessage0060(data))
	  {
	    if(ok)
	      *ok = true;
	  }
    }
}

bool spoton_kernel::processPotentialStarBeamData
(const QByteArray &data,
 QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair)
{
  return m_starbeamWriter->append(data, discoveredAdaptiveEchoPair);
}

void spoton_kernel::slotImpersonateTimeout(void)
{
  slotScramble();
  m_impersonateTimer.setInterval(qrand() % 30000 + 10);
}

QList<QByteArray> spoton_kernel::findInstitutionKey
(const QByteArray &data, const QByteArray &hash)
{
  if(hash.isEmpty())
    return QList<QByteArray> ();

  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return QList<QByteArray> ();

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "email.db");

  if(fileInfo.exists())
    {
      QDateTime dateTime;
      QReadLocker locker(&s_institutionLastModificationTimeMutex);

      dateTime = s_institutionLastModificationTime;
      locker.unlock();

      if(fileInfo.lastModified() < dateTime)
	{
	  /*
	  ** Locate the institution keys in our container.
	  */

	  QList<QByteArray> list;
	  QReadLocker locker(&s_institutionKeysMutex);

	  for(int i = 0; i < s_institutionKeys.size(); i++)
	    {
	      QByteArray cipherType;
	      QByteArray hashType;
	      QByteArray name;
	      QByteArray postalAddress;
	      bool ok = true;

	      cipherType = s_crypt->decryptedAfterAuthenticated
		(s_institutionKeys.at(i).value(0), &ok);

	      if(ok)
		hashType = s_crypt->decryptedAfterAuthenticated
		  (s_institutionKeys.at(i).value(1), &ok);

	      if(ok)
		name = s_crypt->decryptedAfterAuthenticated
		  (s_institutionKeys.at(i).value(2), &ok);

	      if(ok)
		postalAddress = s_crypt->decryptedAfterAuthenticated
		  (s_institutionKeys.at(i).value(3), &ok);

	      if(ok)
		{
		  QByteArray computedHash;

		  computedHash = spoton_crypt::keyedHash
		    (data, postalAddress, hashType, &ok);

		  if(ok)
		    if(!computedHash.isEmpty() && !hash.isEmpty() &&
		       spoton_crypt::memcmp(computedHash, hash))
		      {
			list << name << cipherType
			     << postalAddress << hashType;
			break;
		      }
		}
	    }

	  return list;
	}
      else
	{
	  QWriteLocker locker(&s_institutionLastModificationTimeMutex);

	  s_institutionLastModificationTime = fileInfo.lastModified();
	}
    }
  else
    {
      QWriteLocker locker(&s_institutionLastModificationTimeMutex);

      s_institutionLastModificationTime = QDateTime();
    }

  QList<QByteArray> list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	QWriteLocker locker(&s_institutionKeysMutex);

	s_institutionKeys.clear();
	locker.unlock();

	if(query.exec("SELECT cipher_type, hash_type, "
		      "name, postal_address FROM institutions"))
	  while(query.next())
	    {
	      QByteArray cipherType;
	      QByteArray hashType;
	      QByteArray name;
	      QByteArray postalAddress;
	      bool ok = true;

	      cipherType = s_crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		hashType = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		name = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		postalAddress = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(!ok)
		continue;

	      QList<QByteArray> temp;

	      temp << QByteArray::fromBase64(query.value(0).toByteArray())
		   << QByteArray::fromBase64(query.value(1).toByteArray())
		   << QByteArray::fromBase64(query.value(2).toByteArray())
		   << QByteArray::fromBase64(query.value(3).toByteArray());

	      QWriteLocker locker(&s_institutionKeysMutex);

	      if(!s_institutionKeys.contains(temp))
		s_institutionKeys.append(temp);

	      locker.unlock();

	      QByteArray computedHash;

	      computedHash = spoton_crypt::keyedHash
		(data, postalAddress, hashType, &ok);

	      if(ok)
		if(list.isEmpty())
		  if(!computedHash.isEmpty() && !hash.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, hash))
		    list << name << cipherType << postalAddress << hashType;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return list;
}

void spoton_kernel::discoverAdaptiveEchoPair
(const QByteArray &data,
 QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair)
{
  QReadLocker locker(&s_adaptiveEchoPairsMutex);

  QList<QPair<QByteArray, QByteArray> > adaptiveEchoPairs
    (s_adaptiveEchoPairs);

  locker.unlock();

  if(adaptiveEchoPairs.isEmpty())
    return;

  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray d(data.mid(0, data.lastIndexOf('\n')));

  if(d.isEmpty())
    return;

  QList<QByteArray> list(data.split('\n'));

  if(list.isEmpty())
    return;

  QByteArray last(QByteArray::fromBase64(list.last()));

  if(last.isEmpty())
    return;

  /*
  ** H(E(x) + E(timestamp)) + E(timestamp).
  */

  QByteArray messageCode
    (last.mid(0,
	      spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES)); /*
							   ** SHA-512, etc.,
							   ** output size.
							   */

  if(messageCode.size() < spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES)
    return;

  for(int i = 0; i < adaptiveEchoPairs.size(); i++)
    {
      QByteArray token(adaptiveEchoPairs.at(i).first);
      QByteArray tokenType(adaptiveEchoPairs.at(i).second);
      bool ok = true;

      token = s_crypt->decryptedAfterAuthenticated(token, &ok);

      if(ok)
	tokenType = s_crypt->decryptedAfterAuthenticated(tokenType, &ok);

      if(!ok)
	continue;

      QByteArray computedHash;
      int length = static_cast<int>
	(spoton_crypt::cipherKeyLength("aes256"));
      spoton_crypt crypt(tokenType.split('\n').value(0),
			 tokenType.split('\n').value(1),
			 QByteArray(),
			 token.mid(0, length),
			 token.mid(length),
			 0,
			 0,
			 "");

      /*
      ** d = E(x)
      ** last.mid(64) = E(timestamp)
      */

      /*
      ** 64 = SHA-512, etc., output size.
      */

      computedHash = crypt.keyedHash
	(d + last.mid(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES), &ok);

      if(!ok)
	continue;

      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	 spoton_crypt::memcmp(computedHash, messageCode))
	{
	  /*
	  ** 64 = SHA-512, etc., output size.
	  */

	  QByteArray timestamp
	    (crypt.decrypted(last.
			     mid(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES),
			     &ok));

	  if(!ok)
	    continue;

	  QDateTime dateTime
	    (QDateTime::fromString(timestamp.constData(),
				   "MMddyyyyhhmmss"));

	  if(!dateTime.isValid())
	    continue;

	  QDateTime now(QDateTime::currentDateTimeUtc());

	  dateTime.setTimeSpec(Qt::UTC);
	  now.setTimeSpec(Qt::UTC);

	  int secsTo = qAbs(now.secsTo(dateTime));

	  if(secsTo <= 5)
	    {
	      discoveredAdaptiveEchoPair = adaptiveEchoPairs.at(i);
	      break;
	    }
	}
    }
}

bool spoton_kernel::acceptRemoteConnection(const QHostAddress &localAddress,
					   const QHostAddress &peerAddress)
{
  if(peerAddress.isNull() || peerAddress.toString().isEmpty())
    return false;
  else if(localAddress == peerAddress)
    {
      if(localAddress.isNull() || localAddress.toString().isEmpty() ||
	 peerAddress.isNull() || peerAddress.toString().isEmpty())
	return false;
      else if(spoton_misc::isPrivateNetwork(localAddress))
	return true;
      else
	return false;
    }
  else
    {
      QHashIterator<qint64, QPointer<spoton_neighbor> > it
	(m_neighbors);
      int count = 0;
      int value = setting("gui/limitConnections", 10).toInt();

      while(it.hasNext())
	{
	  it.next();

	  if(it.value() &&
	     it.value()->state() == QAbstractSocket::ConnectedState)
	    if(it.value()->peerAddress() == peerAddress)
	      count += 1;
	}

      if(count >= value)
	return false;
      else
	return true;
    }
}

int spoton_kernel::buzzKeyCount(void)
{
  QReadLocker locker(&s_buzzKeysMutex);

  return s_buzzKeys.size();
}

bool spoton_kernel::duplicateEmailRequests(const QByteArray &data)
{
  QByteArray hash;
  bool ok = true;

  hash = spoton_crypt::keyedHash
    (data, s_messagingCacheKey,
     setting("kernel/messaging_cache_algorithm", "sha224").
     toString().toLatin1(), &ok);

  if(!ok)
    return false;

  QReadLocker locker(&s_emailRequestCacheMutex);

  return s_emailRequestCache.contains(hash);
}

bool spoton_kernel::duplicateGeminis(const QByteArray &data)
{
  QByteArray hash;
  bool ok = true;

  hash = spoton_crypt::keyedHash
    (data, s_messagingCacheKey,
     setting("kernel/messaging_cache_algorithm", "sha224").
     toString().toLatin1(), &ok);

  if(!ok)
    return false;

  QReadLocker locker(&s_geminisCacheMutex);

  return s_geminisCache.contains(hash);
}

void spoton_kernel::emailRequestCacheAdd(const QByteArray &data)
{
  QByteArray hash;
  bool ok = true;

  hash = spoton_crypt::keyedHash
    (data, s_messagingCacheKey,
     setting("kernel/messaging_cache_algorithm", "sha224").
     toString().toLatin1(), &ok);

  if(!ok)
    return;

  QWriteLocker locker(&s_emailRequestCacheMutex);

  s_emailRequestCache.insert(hash, QDateTime::currentDateTime().toTime_t());
}

void spoton_kernel::geminisCacheAdd(const QByteArray &data)
{
  QByteArray hash;
  bool ok = true;

  hash = spoton_crypt::keyedHash
    (data, s_messagingCacheKey,
     setting("kernel/messaging_cache_algorithm", "sha224").
     toString().toLatin1(), &ok);

  if(!ok)
    return;

  QWriteLocker locker(&s_geminisCacheMutex);

  s_geminisCache.insert(hash, QDateTime::currentDateTime().toTime_t());
}

void spoton_kernel::slotCallParticipant(const QByteArray &publicKeyHash,
					const QByteArray &gemini,
					const QByteArray &geminiHashKey)
{
  spoton_crypt *s_crypt1 = s_crypts.value("chat", 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = s_crypts.value("chat-signature", 0);

  if(!s_crypt2)
    return;

  QByteArray publicKey;
  QByteArray myPublicKeyHash;
  bool ok = false;

  publicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  myPublicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;
  else
    ok = false;

  QByteArray data;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND neighbor_oid = -1 AND "
		      "public_key_hash = ?");
	query.bindValue(0, s_crypt1->keyedHash("chat",
					       &ok).toBase64());
	query.bindValue(1, publicKeyHash.toBase64());

	if(ok && query.exec())
	  if(query.next())
	    {
	      QByteArray publicKey;
	      QPair<QByteArray, QByteArray> geminis(gemini,
						    geminiHashKey);

	      publicKey = s_crypt1->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      QByteArray hashKey;
	      QByteArray hashType(setting("gui/kernelHashType",
					  "sha512").toString().toLatin1());
	      QByteArray keyInformation;
	      QByteArray symmetricKey;
	      QByteArray symmetricKeyAlgorithm
		(setting("gui/kernelCipherType", "aes256").toString().
		 toLatin1());
	      size_t symmetricKeyLength = 0;

	      if(ok)
		{
		  symmetricKeyLength = spoton_crypt::cipherKeyLength
		    (symmetricKeyAlgorithm);

		  if(symmetricKeyLength > 0)
		    {
		      hashKey.resize
			(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		      hashKey = spoton_crypt::strongRandomBytes
			(static_cast<size_t> (hashKey.length()));
		      symmetricKey.resize
			(static_cast<int> (symmetricKeyLength));
		      symmetricKey = spoton_crypt::strongRandomBytes
			(static_cast<size_t> (symmetricKey.length()));
		    }
		  else
		    {
		      ok = false;
		      spoton_misc::logError
			("spoton_kernel::slotCallParticipant(): "
			 "cipherKeyLength() failure.");
		    }
		}

	      if(ok)
		{
		  QDataStream stream(&keyInformation, QIODevice::WriteOnly);

		  stream << QByteArray("0000c")
			 << symmetricKey
			 << hashKey
			 << symmetricKeyAlgorithm
			 << hashType;

		  if(stream.status() != QDataStream::Ok)
		    ok = false;

		  if(ok)
		    keyInformation = spoton_crypt::publicKeyEncrypt
		      (keyInformation, publicKey, &ok);
		}

	      if(ok)
		{
		  {
		    /*
		    ** We would like crypt to be destroyed as
		    ** soon as possible.
		    */

		    QByteArray signature;
		    QDateTime dateTime(QDateTime::currentDateTime());
		    spoton_crypt crypt(symmetricKeyAlgorithm,
				       hashType,
				       QByteArray(),
				       symmetricKey,
				       hashKey,
				       0,
				       0,
				       "");

		    if(setting("gui/chatSignMessages", true).toBool())
		      signature = s_crypt2->digitalSignature
			("0000c" +
			 symmetricKey +
			 hashKey +
			 symmetricKeyAlgorithm +
			 hashType +
			 myPublicKeyHash +
			 geminis.first +
			 geminis.second +
			 dateTime.toUTC().toString("MMddyyyyhhmmss").
			 toLatin1(), &ok);

		    if(ok)
		      {
			QDataStream stream(&data, QIODevice::WriteOnly);

			stream << myPublicKeyHash
			       << geminis.first
			       << geminis.second
			       << dateTime.toUTC().toString("MMddyyyyhhmmss").
			          toLatin1()
			       << signature;

			if(stream.status() != QDataStream::Ok)
			  ok = false;

			if(ok)
			  data = crypt.encrypted(data, &ok);
		      }

		    if(ok)
		      {
			QByteArray messageCode
			  (crypt.keyedHash(keyInformation + data, &ok));

			if(ok)
			  data = keyInformation.toBase64() + "\n" +
			    data.toBase64() + "\n" +
			    messageCode.toBase64();
		      }
		  }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    emit callParticipant(data, "0000c");
}

void spoton_kernel::postPoptasticMessage(const QString &receiverName,
					 const QByteArray &message)
{
  postPoptasticMessage(receiverName, message, -1);
}

void spoton_kernel::postPoptasticMessage(const QString &receiverName,
					 const QByteArray &message,
					 const qint64 mailOid)
{
  if(receiverName.isEmpty())
    return;
  else if(setting("gui/disableSmtp", true).toBool())
    {
      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
      return;
    }

  QWriteLocker locker(&m_poptasticCacheMutex);

  m_lastPoptasticStatus = QDateTime::currentDateTime();
  m_poptasticCache.enqueue(QList<QVariant> () << receiverName
			                      << message
			                      << mailOid);
}

void spoton_kernel::postPoptasticMessage(const QByteArray &attachment,
					 const QByteArray &attachmentName,
					 const QByteArray &message,
					 const QByteArray &name,
					 const QByteArray &subject,
					 const QByteArray &mode,
					 const qint64 mailOid)
{
  if(setting("gui/disableSmtp", true).toBool())
    {
      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
      return;
    }

  QWriteLocker locker(&m_poptasticCacheMutex);

  m_lastPoptasticStatus = QDateTime::currentDateTime();
  m_poptasticCache.enqueue(QList<QVariant> () << name
			                      << message
			                      << subject
			                      << attachment
			                      << attachmentName
			                      << mode
			                      << mailOid);
}

QList<QPair<QByteArray, QByteArray> > spoton_kernel::adaptiveEchoTokens(void)
{
  QReadLocker locker(&s_adaptiveEchoPairsMutex);

  return s_adaptiveEchoPairs;
}

QPointer<spoton_kernel> spoton_kernel::instance(void)
{
  return s_kernel;
}
