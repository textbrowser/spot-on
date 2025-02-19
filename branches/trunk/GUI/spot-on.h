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

#ifndef _spoton_h_
#define _spoton_h_

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDir>
#include <QElapsedTimer>
#include <QFileDialog>
#include <QFuture>
#include <QFutureWatcher>
#include <QHash>
#include <QInputDialog>
#include <QLineEdit>
#include <QLocale>
#include <QMainWindow>
#include <QMediaPlayer>
#include <QMessageBox>
#include <QMouseEvent>
#ifdef Q_OS_WINDOWS
#include <qt_windows.h>
#include <QNetworkInterface>
#else
#include <QNetworkInterface>
#endif
#include <QPointer>
#include <QProcess>
#include <QQueue>
#include <QScrollBar>
#include <QSet>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QSslSocket>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QThread>
#include <QTimer>
#include <QTranslator>
#include <QUuid>
#if QT_VERSION >= 0x050600 && defined(SPOTON_WEBENGINE_ENABLED)
#include <QWebEngineUrlRequestInterceptor>
#endif
#include <QtDebug>

#include <limits>

#ifdef Q_OS_MACOS
#include "Common/CocoaInitializer.h"
#endif

#include "spot-on-buzzpage.h"
#include "spot-on-defines.h"
#include "ui_spot-on-keyboard.h"

class QStandardItemModel;

class spoton_table_item_delegate: public QStyledItemDelegate
{
  Q_OBJECT

 public:
  spoton_table_item_delegate(QObject *parent):QStyledItemDelegate(parent)
  {
  }

  QWidget *createEditor(QWidget *parent,
			const QStyleOptionViewItem &option,
			const QModelIndex &index) const
  {
    Q_UNUSED(option);

    auto lineEdit = new QLineEdit(parent);

    lineEdit->setReadOnly(true);
    lineEdit->setText(index.data().toString());
    lineEdit->setCursorPosition(0);
    return lineEdit;
  }
};

class spoton_virtual_keyboard: public QDialog
{
  Q_OBJECT

 public:
  spoton_virtual_keyboard(QWidget *parent):QDialog(parent)
  {
    m_ui.setupUi(this);
    m_ui.passphrase->clear();
    m_ui.passphrase->setEchoMode(QLineEdit::Password);
    connect(m_ui.back,
	    SIGNAL(clicked(void)),
	    this,
	    SLOT(slotBack(void)));
    connect(m_ui.shift,
	    SIGNAL(clicked(void)),
	    this,
	    SLOT(slotShift(void)));
    connect(m_ui.show,
	    SIGNAL(toggled(bool)),
	    this,
	    SLOT(slotShow(bool)));

#if (QT_VERSION < QT_VERSION_CHECK(6, 6, 0))
    auto const country = QLocale::system().country();
#else
    auto const country = QLocale::system().territory();
#endif
    QStringList row;

    if(country == QLocale::Germany)
      row << "°\n^"
	  << "!\n1"
	  << "\"\n2"
	  << "§\n3"
	  << "$\n4"
	  << "%\n5"
	  << "&&\n6"
	  << "/\n7"
	  << "(\n8"
	  << ")\n9"
	  << "=\n0"
	  << "?\nß"
	  << "`\n´";
    else
      row << "~\n`"
	  << "!\n1"
	  << "@\n2"
	  << "#\n3"
	  << "$\n4"
	  << "%\n5"
	  << "^\n6"
	  << "&&\n7"
	  << "*\n8"
	  << "(\n9"
	  << ")\n0"
	  << "_\n-"
	  << "+\n=";

    for(int i = 0; i < row.size(); i++)
      {
	auto button = new QToolButton(this);

	button->setMinimumSize(45, 45);
	button->setText(row.at(i));
	m_ui.number_layout->addWidget(button);
      }

    row.clear();

    if(country == QLocale::Germany)
      row << "q"
	  << "w"
	  << "e"
	  << "r"
	  << "t"
	  << "z"
	  << "u"
	  << "i"
	  << "o"
	  << "p"
	  << "ü"
	  << "*\n+"
	  << "'\n#";
    else
      row << "q"
	  << "w"
	  << "e"
	  << "r"
	  << "t"
	  << "y"
	  << "u"
	  << "i"
	  << "o"
	  << "p"
	  << "{\n["
	  << "}\n]"
	  << "|\n\\";

    for(int i = 0; i < row.size(); i++)
      {
	auto button = new QToolButton(this);

	button->setMinimumSize(45, 45);
	button->setText(row.at(i));
	m_ui.row1->addWidget(button);
      }

    row.clear();

    if(country == QLocale::Germany)
      row << "a"
	  << "s"
	  << "d"
	  << "f"
	  << "g"
	  << "h"
	  << "j"
	  << "k"
	  << "l"
	  << "ö"
	  << "ä";
    else
      row << "a"
	  << "s"
	  << "d"
	  << "f"
	  << "g"
	  << "h"
	  << "j"
	  << "k"
	  << "l"
	  << ":\n;"
	  << "\"\n'";

    for(int i = 0; i < row.size(); i++)
      {
	auto button = new QToolButton(this);

	button->setMinimumSize(45, 45);
	button->setText(row.at(i));
	m_ui.row2->addWidget(button);
      }

    row.clear();

    if(country == QLocale::Germany)
      row << "y"
	  << "x"
	  << "c"
	  << "v"
	  << "b"
	  << "n"
	  << "m"
	  << ";\n,"
	  << ":\n."
	  << "_\n-";
    else
      row << "z"
	  << "x"
	  << "c"
	  << "v"
	  << "b"
	  << "n"
	  << "m"
	  << "<\n,"
	  << ">\n."
	  << "?\n/";

    for(int i = 0; i < row.size(); i++)
      {
	auto button = new QToolButton(this);

	button->setMinimumSize(45, 45);
	button->setText(row.at(i));
	m_ui.row3->addWidget(button);
      }

    foreach(auto button, findChildren<QToolButton *> ())
      if(button != m_ui.back && button != m_ui.shift)
	connect(button,
		SIGNAL(clicked(void)),
		this,
		SLOT(slotKeyPressed(void)));

    setWindowTitle(tr("%1: Virtual Keyboard").arg(SPOTON_APPLICATION_NAME));
  }

  ~spoton_virtual_keyboard()
  {
  }

  Ui_spoton_keyboard m_ui;

 private slots:
  void slotBack(void)
  {
    m_ui.passphrase->backspace();
  }

  void slotKeyPressed(void)
  {
    auto button = qobject_cast<QToolButton *> (sender());

    if(!button)
      return;

    auto text(m_ui.passphrase->text());

    if(button == m_ui.space)
      text.append(" ");
    else if(m_ui.shift->isChecked())
      text.append(button->text().split('\n').value(0).mid(0, 1).toUpper());
    else if(button->text().contains('\n'))
      text.append(button->text().split('\n').value(1));
    else
      text.append(button->text());

    m_ui.passphrase->setText(text);
  }

  void slotShow(bool state)
  {
    if(state)
      m_ui.passphrase->setEchoMode(QLineEdit::Normal);
    else
      m_ui.passphrase->setEchoMode(QLineEdit::Password);
  }

 public slots:
  void slotShift(void)
  {
    foreach(auto button, findChildren<QToolButton *> ())
      if(button != m_ui.back && button != m_ui.shift)
	{
	  if(m_ui.shift->isChecked())
	    button->setText(button->text().toUpper());
	  else
	    button->setText(button->text().toLower());
	}
  }
};

class spoton_lineedit: public QLineEdit
{
  Q_OBJECT

 public:
  spoton_lineedit(QWidget *parent):QLineEdit(parent)
  {
    m_dialog = new spoton_virtual_keyboard(this);
  }

  ~spoton_lineedit()
  {
  }

 private:
  void mouseDoubleClickEvent(QMouseEvent *event)
  {
    if(event)
      if(event->type() == QEvent::MouseButtonDblClick)
	{
	  m_dialog->m_ui.shift->setChecked(false);
	  m_dialog->m_ui.show->setChecked(false);
	  m_dialog->slotShift();
	  m_dialog->m_ui.passphrase->setFocus();

	  if(m_dialog->exec() == QDialog::Accepted)
	    {
	      QApplication::processEvents();
	      setText(m_dialog->m_ui.passphrase->text());
	    }

	  QApplication::processEvents();
	  m_dialog->m_ui.passphrase->clear();
	}

    QLineEdit::mouseDoubleClickEvent(event);
  }

 private:
  spoton_virtual_keyboard *m_dialog;
};

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-external-address.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-chatwindow.h"
#include "spot-on-encryptfile.h"
#include "spot-on-logviewer.h"
#include "spot-on-rosetta.h"
#include "spot-on-smpwindow.h"
#include "ui_spot-on-controlcenter.h"
#include "ui_spot-on-notificationswindow.h"
#include "ui_spot-on-options.h"
#include "ui_spot-on-poptastic-retrophone-settings.h"
#include "ui_spot-on-statisticswindow.h"
#include "ui_spot-on-statusbar.h"
#include "ui_spot-on-wizard.h"

class QProgressDialog;
class QSplashScreen;
class spoton_documentation;
class spoton_echo_key_share;
class spoton_rss;
class spoton_smp;
class spoton_status_activity;

class spoton_forward_secrecy
{
 public:
  QByteArray m_public_key;
  QByteArray m_public_key_hash;
  QDateTime m_date_time;
  QString m_key_type;
};

class spoton: public QMainWindow
{
  Q_OBJECT

 public:
  spoton(QSplashScreen *splash, const bool launchKernel);
  ~spoton();
  QHash<QString, QPair<QQueue<QString>, QQueue<QByteArray> > > m_chatQueues;
  QHash<QString, QVariant> m_settings;
  QHash<QString, quint64> m_chatSequenceNumbers;
  QList<QFileInfo> prisonBluesDirectories(void) const;
  static char s_keyDelimiter;
  QHash<QString, spoton_crypt *> crypts(void) const;
  QMap<QString, QByteArray> SMPWindowStreams
    (const QStringList &keyTypes) const;
  QList<QByteArray> retrieveForwardSecrecyInformation
    (const QString &oid, bool *ok) const;
  QSqlDatabase urlDatabase(void) const;

  QSslSocket *kernelSocket(void)
  {
    return &m_kernelSocket;
  }

  QStandardItemModel *starbeamReceivedModel(void) const;
  Ui_spoton_mainwindow ui(void) const;
  bool isKernelActive(void) const;
  qint64 selectedHumanProxyOID(void) const;
  spoton_crypt *urlCommonCrypt(void) const;
  static QHash<QString, QStringList> s_publicKeySizes;
  static QList<QTableWidgetItem *> findItems(QTableWidget *table,
					     const QString &text,
					     const int column);
  static QString mapIconToEmoticon(const QString &content);
  static QString optionsEnabled(void);
  static void prepareDatabasesFromUI(void);
  void addMessageToReplayQueue(const QString &message1,
			       const QByteArray &message2,
			       const QString &publicKeyHash);
  void launchPrisonBluesProcesses(void);

 private:
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_ATTACHMENTS = 1;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_DATABASE = 2;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_GENERAL = 3;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_MEMORY = 4;
  QAtomicInt m_pqUrlFaultyCounter;
  QAtomicInt m_starbeamDigestInterrupt;
  QByteArray m_kernelSocketData;
  QDateTime m_buzzFavoritesLastModificationTime;
  QDateTime m_listenersLastModificationTime;
  QDateTime m_magnetsLastModificationTime;
  QDateTime m_neighborsLastModificationTime;
  QDateTime m_participantsLastModificationTime;
  QDateTime m_starsLastModificationTime;
  QDialog *m_poptasticRetroPhoneDialog;
  QElapsedTimer m_urlQueryElapsedTimer;
  QFuture<QList<QPair<QString, QVariant> > > m_statisticsFuture;
  QFuture<void> m_generalFuture;
  QFuture<void> m_neighborsFuture;
  QFuture<void> m_participantsFuture;
  QFuture<void> m_pqUrlDatabaseFuture;
  QFutureWatcher<QList<QPair<QString, QVariant> > > m_statisticsFutureWatcher;
  QHash<QByteArray, QPointer<spoton_buzzpage> > m_buzzPages;
  QHash<QByteArray, QString> m_neighborToOidMap;
  QHash<QByteArray, quint64> m_receivedChatSequenceNumbers;
  QHash<QByteArray, spoton_forward_secrecy> m_forwardSecrecyRequests;
  QHash<QString, QByteArray> m_buzzIds;
  QHash<QString, QPointer<spoton_chatwindow> > m_chatWindows;
  QHash<QString, QString> m_keysShared;
  QHash<QString, bool> m_wizardHash;
  QHash<QString, spoton_crypt *> m_crypts;
  QHash<QString, spoton_smp *> m_smps; /*
				       ** The objects contained within
				       ** m_smps are destroyed whenever
				       ** participants are removed or
				       ** whenever the UI process terminates.
				       ** Unlike m_chatWindows, m_smps
				       ** purging is less rigid.
				       */
  QIcon m_careOfPageIcon;
  QList<QFuture<void> > m_starbeamDigestFutures;
  QMainWindow *m_addParticipantWindow;
  QMainWindow *m_notificationsWindow;
  QMainWindow *m_optionsWindow;
  QMainWindow *m_statisticsWindow;
  QMap<int, QHash<QString, QVariant> > m_tabWidgetsProperties;
  QMap<int, QWidget *> m_tabWidgets; /*
				     ** QTabWidget does not provide
				     ** a method for hiding individual pages.
				     */
  QPointer<QWidget> m_careOfPage;
  QPointer<spoton_status_activity> m_statusActivity;
  QSet<QString> m_urlPrefixes;
  QSqlDatabase m_urlDatabase;
  QSslSocket m_kernelSocket;
  QStandardItemModel *m_starbeamReceivedModel;
  QStandardItemModel *m_statisticsModel;
  QString m_defaultStyleSheet;
  QString m_emailAddressAdded;
  QString m_urlQuery;
  QTimer m_buzzStatusTimer;
  QTimer m_chatInactivityTimer;
  QTimer m_emailRetrievalTimer;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_generalTimer;
  QTimer m_kernelUpdateTimer;
  QTimer m_listenersUpdateTimer;
  QTimer m_neighborsUpdateTimer;
  QTimer m_participantsUpdateTimer;
  QTimer m_starbeamUpdateTimer;
  QTimer m_tableTimer;
  QTimer m_updateChatWindowsTimer;
  QTimer m_webServerInformationTimer;
  QTimer m_webServerValueChangedTimer;
  QVector<QPointer<QProcess> > m_prisonBluesProcesses;
  QWidget *m_sbWidget;
  Ui_spoton_mainwindow m_ui;
  Ui_spoton_notifications_window m_notificationsUi;
  Ui_spoton_options m_optionsUi;
  Ui_spoton_poptasticretrophonesettings m_poptasticRetroPhoneSettingsUi;
  Ui_spoton_statistics_window m_statisticsUi;
  Ui_spoton_statusbar m_sb;
  Ui_spoton_wizard *m_wizardUi;
  bool m_locked;
  bool m_quit;
  mutable QList<QFileInfo> m_prisonBluesDirectoriesCache;
  quint64 m_urlCurrentPage;
  quint64 m_urlLimit;
  quint64 m_urlOffset;
  quint64 m_urlPages;
  spoton_crypt *m_urlCommonCrypt;
  spoton_documentation *m_documentation;
  spoton_documentation *m_releaseNotes;
  spoton_echo_key_share *m_echoKeyShare;
  spoton_encryptfile m_encryptFile;
  spoton_external_address *m_externalAddress;
  spoton_logviewer m_logViewer;
  spoton_rosetta m_rosetta;
  spoton_rss *m_rss;
  spoton_smpwindow *m_smpWindow;
  QByteArray copiedPublicKeyPairToMagnet(const QByteArray &data) const;
  QByteArray copyMyChatPublicKey(void) const;
  QByteArray copyMyEmailPublicKey(void) const;
  QByteArray copyMyOpenLibraryPublicKey(void) const;
  QByteArray copyMyPoptasticPublicKey(void) const;
  QByteArray copyMyRosettaPublicKey(void) const;
  QByteArray copyMyUrlPublicKey(void) const;
  QByteArray poptasticName(void) const;
  QByteArray poptasticNameEmail(void) const;
  QList<QPair<QString, QVariant> > gatherStatistics(void) const;
  QPixmap pixmapForCountry(const QString &country) const;
  QString currentTabName(void) const;
  QString listenerTransport(void) const;
  QString neighborTransport(void) const;
  QString participantKeyType(QTableWidget *table) const;
  QString saveCommonUrlCredentials(const QPair<QByteArray, QByteArray> &keys,
				   const QString &cipherType,
				   const QString &hashType,
				   spoton_crypt *crypt) const;
  QString savePoptasticAccount(void);
  QStringList parseAEMagnet(const QString &magnet) const;
  QThread::Priority neighborThreadPriority(void) const;
  QWidget *combinationBoxForTable(void) const;
  bool addFriendsKey(const QByteArray &key,
		     const QString &type,
		     QWidget *parent);
  bool deleteAllUrls(void);
  bool listenerSupportsSslTls(void) const;
  bool neighborSpecialClient(void) const;
  bool neighborSupportsSslTls(void) const;
  bool nodeExists(const QSqlDatabase &db,
		  const QString &identifier,
		  const QString &table) const;
  bool promptBeforeExit(void);
  bool saveGemini(const QPair<QByteArray, QByteArray> &gemini,
		  const QString &oid);
  bool updateMailStatus(const QString &oid, const QString &status);
  bool verifyInitializationPassphrase(QWidget *parent);
  bool writeKernelSocketData(const QByteArray &bytes);
  int applyGoldBugToLetter(const QByteArray &goldbug, const int row);
  int tabIndexFromName(const QString &name) const;
  void applyGoldBugToAttachments(const QString &folderOid,
				 const QSqlDatabase &db,
				 int *count,
				 spoton_crypt *crypt,
				 bool *ok);
  void askKernelToReadStarBeamKeys(void);
  void authenticate(spoton_crypt *crypt,
		    const QString &oid,
		    const QString &message = "");
  void authenticationRequested(const QByteArray &data);
  void cancelUrlQuery(void);
  void changeEchoMode(const QString &mode, QTableWidget *tableWidget);
  void cleanup(void);
  void closeEvent(QCloseEvent *event);
  void computeFileDigests(const QString &fileName,
			  const QString &oid,
			  spoton_crypt *crypt);
  void demagnetize(void);
  void derivativeUpdates(void);
  void discoverUrls(void);
  void displayUrlImportResults(const QDateTime &then,
			       const quint64 imported,
			       const quint64 not_imported,
			       const quint64 declined);
  void forwardSecrecyRequested(const QList<QByteArray> &list);
  void generalConcurrentMethod(const QHash<QString, QVariant> &settings);
  void generateHalfGeminis(void);
  void highlightPaths(void);
  void importNeighbors(const QString &filePath);
  void initializeKernelSocket(void);
  void initializeSMP(const QString &hash);
  void initializeUrlDistillers(void);
  void inspectPQUrlDatabase(const QByteArray &name,
			    const QByteArray &password);
  void joinBuzzChannel(const QUrl &url);
  void joinDefaultBuzzChannel(void);
  void magnetize(void);
  void notify(const QString &text);
  void playSound(const QString &name);
  void popForwardSecrecyRequest(const QByteArray &publicKeyHash);
  void populateAETokens(void);
  void populateAccounts(const QString &listenerOid);
  void populateGITTable(void);
  void populateListenerIps(const QString &listenerOid);
  void populateMOTD(const QString &listenerOid);
  void populateMail(void);
  void populateNovas(void);
  void populatePoptasticWidgets(const QHash<QString, QVariant> &hash);
  void populateStatistics(const QList<QPair<QString, QVariant> > &list);
  void populateUrlDistillers();
  void prepareAndShowInstallationWizard(void);
  void prepareContextMenuMirrors(void);
  void prepareListenerIPCombo(void);
  void prepareOtherOptions(void);
  void prepareSMP(const QString &hash);
  void prepareStyleSheet(void);
  void prepareTabIcons(void);
  void prepareTearOffMenus(void);
  void prepareTimeWidgets(void);
  void prepareUrlContainers(void);
  void prepareUrlLabels(void);
  void prepareVisiblePages(void);
  void refreshInstitutions(void);
  void removeFavorite(const bool removeAll);
  void resizeEvent(QResizeEvent *event);
  void retrieveNeighbors(void);
  void retrieveParticipants(spoton_crypt *crypt);
  void saveDestination(const QString &path);
  void saveGeoIPPath(const int version, const QString &path);
  void saveKernelPath(const QString &path);
  void saveSettings(void);
  void saveUrlIniPath(const QString &path);
  void sendBuzzKeysToKernel(void);
  void sendKeysToKernel(void);
  void sendMessage(bool *ok);
  void sendSMPLinkToKernel(const QList<QByteArray> &list,
			   const QString &keyType,
			   const QString &oid);
  void setSBField(const QString &oid,
		  const QVariant &value,
		  const QString &field);
  void sharePublicKeyWithParticipant(const QString &keyType);
  void showError(const QString &error);
  void showUrls(const QString &link, const QString &querystr);
  void updatePoptasticNameSettingsFromWidgets(spoton_crypt *crypt);
  void updatePublicKeysLabel(void);
  void verifySMPSecret
    (const QString &hash, const QString &keyType, const QString &oid);

 private slots:
  void slotAbout(void);
  void slotAboutToShowChatSecretsMenu(void);
  void slotAboutToShowEmailSecretsMenu(void);
  void slotAcceptBuzzMagnets(bool state);
  void slotAcceptChatKeys(bool state);
  void slotAcceptEmailKeys(bool state);
  void slotAcceptGeminis(bool state);
  void slotAcceptPublicizedListeners(void);
  void slotAcceptUrlKeys(bool state);
  void slotActivateKernel(void);
  void slotActiveUrlDistribution(bool state);
  void slotAddAEToken(void);
  void slotAddAcceptedIP(void);
  void slotAddAccount(void);
  void slotAddAttachment(void);
  void slotAddDistiller(void);
  void slotAddEtpMagnet(const QString &text = "",
			const bool displayError = true);
  void slotAddFriendsKey(void);
  void slotAddInstitution(const QString &text = "");
  void slotAddInstitutionCheckBoxToggled(bool state);
  void slotAddListener(void);
  void slotAddMagnet(void);
  void slotAddNeighbor(void);
  void slotAddReceiveNova(void);
  void slotAfterFirstShow(void);
  void slotAllowFSRequest(bool state);
  void slotApplyOtherOptions(void);
  void slotAssignNewIPToNeighbor(void);
  void slotAuthenticate(void);
  void slotAuthenticationRequestButtonClicked(void);
  void slotAutoAddSharedSBMagnets(bool state);
  void slotAutoRetrieveEmail(bool state);
  void slotBlockNeighbor(void);
  void slotBluetoothSecurityChanged(int index);
  void slotBehaveAsHumanProxy(bool state);
  void slotBuzzActionsActivated(int index);
  void slotBuzzChanged(void);
  void slotBuzzInvite(void);
  void slotBuzzPageDestroyed(QObject *object);
  void slotBuzzTools(int index);
  void slotCallParticipant(void);
  void slotCallParticipantViaForwardSecrecy(void);
  void slotChangeTabPosition(int index);
  void slotChatInactivityTimeout(void);
  void slotChatPopup(void);
  void slotChatSecretsActionSelected(void);
  void slotChatSendMethodChanged(int index);
  void slotChatTimestamps(bool state);
  void slotChatWindowDestroyed(void);
  void slotChatWindowMessageSent(void);
  void slotClearClipboardBuffer(void);
  void slotClearOutgoingMessage(void);
  void slotCloseBuzzTab(int index);
  void slotCloseTab(void);
  void slotCommonBuzzChannelsActivated(int index);
  void slotComputeFileHash(void);
  void slotConfigurePoptastic(void);
  void slotConnectAllNeighbors(void);
  void slotConnectNeighbor(void);
  void slotCopyAEMagnet(void);
  void slotCopyAllMyPublicKeys(void);
  void slotCopyEmailFriendshipBundle(void);
  void slotCopyEmailKeys(void);
  void slotCopyEtpMagnet(void);
  void slotCopyFileHash(void);
  void slotCopyFriendshipBundle(void);
  void slotCopyInstitution(void);
  void slotCopyMyChatPublicKey(void);
  void slotCopyMyEmailPublicKey(void);
  void slotCopyMyOpenLibraryPublicKey(void);
  void slotCopyMyPoptasticPublicKey(void);
  void slotCopyMyRosettaPublicKey(void);
  void slotCopyMyURLPublicKey(void);
  void slotCopyOrPaste(void);
  void slotCopyPrivateApplicationMagnet(void);
  void slotCopyStyleSheet(void);
  void slotCopyTransmittedMagnet(void);
  void slotCopyUrlFriendshipBundle(void);
  void slotCopyUrlKeys(void);
  void slotCorrectUrlDatabases(void);
  void slotCostChanged(int value);
  void slotDaysChanged(int value);
  void slotDeactivateKernel(void);
  void slotDeleteAEToken(void);
  void slotDeleteAcceptedIP(void);
  void slotDeleteAccount(void);
  void slotDeleteAllBlockedNeighbors(void);
  void slotDeleteAllListeners(void);
  void slotDeleteAllNeighbors(void);
  void slotDeleteAllReceived(void);
  void slotDeleteAllTransmitted(void);
  void slotDeleteAllUrls(void);
  void slotDeleteAllUuids(void);
  void slotDeleteEtpAllMagnets(void);
  void slotDeleteEtpMagnet(void);
  void slotDeleteInstitution(void);
  void slotDeleteKey(void);
  void slotDeleteListener(void);
  void slotDeleteMail(void);
  void slotDeleteNeighbor(void);
  void slotDeleteNova(void);
  void slotDeletePoptasticAccount(void);
  void slotDeleteReceived(void);
  void slotDeleteTransmitted(void);
  void slotDeleteUrlDistillers(void);
  void slotDeriveGeminiPairViaSMP(const QString &publicKeyHash,
				  const QString &oid);
  void slotDeriveGeminiPairViaSMP(void);
  void slotDetachListenerNeighbors(void);
  void slotDisableSynchronousUrlImport(bool state);
  void slotDisconnectAllNeighbors(void);
  void slotDisconnectListenerNeighbors(void);
  void slotDisconnectNeighbor(void);
  void slotDiscover(void);
  void slotDiscoverExternalAddress(void);
  void slotDisplayPopups(bool state);
  void slotDropUrlTables(void);
  void slotDuplicateTransmittedMagnet(void);
  void slotEmailFsGb(int index);
  void slotEmailLettersPerPageChanged(int value);
  void slotEmailPageChanged(int value);
  void slotEmailSecretsActionSelected(void);
  void slotEmptyTrash(void);
  void slotEnableChatEmoticons(bool state);
  void slotEnableRetrieveMail(void);
  void slotEnabledPostOffice(bool state);
  void slotEncryptionKeyTypeChanged(int index);
  void slotEstablishForwardSecrecy(void);
  void slotExportListeners(void);
  void slotExportPublicKeys(void);
  void slotExternalIp(int index);
  void slotFavoritesActivated(int index);
  void slotFindInSearch(void);
  void slotFindInSearchInitialize(void);
  void slotForceKernelRegistration(bool state);
  void slotForwardSecrecyEncryptionKeyChanged(int index);
  void slotGITChat(bool state);
  void slotGatherStatistics(void);
  void slotGatherUrlStatistics(void);
  void slotGeneralTimerTimeout(void);
  void slotGenerateEtpKeys(int index);
  void slotGenerateGeminiInChat(void);
  void slotGenerateInstitutionKeyPair(void);
  void slotGenerateNova(void);
  void slotGenerateOneYearListenerCertificate(void);
  void slotGoldBugDialogActionSelected(void);
  void slotHideOfflineParticipants(bool state);
  void slotImpersonate(bool state);
  void slotImportNeighbors(void);
  void slotImportPublicKeys(void);
  void slotImportUrls(void);
  void slotInitializeSMP(const QString &hash);
  void slotInitializeSMP(void);
  void slotInitiateSSLTLSSession(void);
  void slotJoinBuzzChannel(void);
  void slotKeepCopy(bool state);
  void slotKeepOnlyUserDefinedNeighbors(bool state);
  void slotKernelCipherTypeChanged(int index);
  void slotKernelHashTypeChanged(int index);
  void slotKernelKeySizeChanged(int index);
  void slotKernelLogEvents(bool state);
  void slotKernelSocketError(QAbstractSocket::SocketError error);
  void slotKernelSocketSslErrors(const QList<QSslError> &errors);
  void slotKernelSocketState(void);
  void slotKernelStatus(void);
  void slotKernelUrlBatchSizeChanged(int value);
  void slotKeysIndexChanged(int index);
  void slotLaneWidthChanged(int index);
  void slotLaunchKernelAfterAuthentication(bool state);
  void slotLimitConnections(int value);
  void slotLimitSqliteSynchronization(bool state);
  void slotLinkClicked(const QUrl &url);
  void slotListenerChanged(QTableWidgetItem *item);
  void slotListenerFullEcho(void);
  void slotListenerHalfEcho(void);
  void slotListenerIPComboChanged(int index);
  void slotListenerMaximumChanged(int value);
  void slotListenerSelected(void);
  void slotListenerSourceOfRandomnessChanged(int value);
  void slotLock(void);
  void slotMagnetRadioToggled(bool state);
  void slotMailContextMenu(const QPoint &point);
  void slotMailRetrievalIntervalChanged(int value);
  void slotMailSelected(QTableWidgetItem *item);
  void slotMailSelected(void);
  void slotMailTabChanged(int index);
  void slotMaxMosaicSize(int value);
  void slotMaximumClientsChanged(int index);
  void slotMaximumEmailFileSizeChanged(int value);
  void slotMaximumUrlKeywordsChanged(int value);
  void slotMediaError(QMediaPlayer::Error error);
  void slotMediaError(QMediaPlayer::Error error, const QString &errorString);
  void slotMediaStatusChanged(QMediaPlayer::MediaStatus status);
  void slotMessagesAnchorClicked(const QUrl &link);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotMonitorEvents(bool state);
  void slotNeighborChanged(QTableWidgetItem *item);
  void slotNeighborFullEcho(void);
  void slotNeighborHalfEcho(void);
  void slotNeighborMaximumChanged(int value);
  void slotNeighborSilenceTimeChanged(int value);
  void slotNeighborWaitForBytesWrittenChanged(int value);
  void slotNewEmailWindow(void);
  void slotNewGlobalName(void);
  void slotNewKeys(bool state);
  void slotNotificationsEnabled(bool state);
  void slotOntopChatDialogs(bool state);
  void slotOpenChatUrlChecked(bool state);
  void slotPQUrlDatabaseFaulty(void);
  void slotPageClicked(const QString &link);
  void slotParticipantDoubleClicked(QTableWidgetItem *item);
  void slotParticipantsItemChanged(QTableWidgetItem *item);
  void slotPassphraseAuthenticateRadioToggled(bool state);
  void slotPassphraseChanged(const QString &text);
  void slotPassphraseRadioToggled(bool state);
  void slotPlaySounds(bool state);
  void slotPopPoptastic(void);
  void slotPoptasticAccountChanged(int index);
  void slotPoptasticSettingsReset(bool state);
  void slotPoptasticSettingsReset(void);
  void slotPopulateBuzzFavorites(void);
  void slotPopulateEtpMagnets(void);
  void slotPopulateListeners(void);
  void slotPopulateNeighbors(QSqlDatabase *db,
			     QSqlQuery *query,
			     const QString &connectionName,
			     const int &size);
  void slotPopulateNeighbors(void);
  void slotPopulateParticipants(QSqlDatabase *db,
				QSqlQuery *query,
				const QString &connectionName);
  void slotPopulateParticipants(void);
  void slotPopulateStars(void);
  void slotPostgreSQLConnect(void);
  void slotPostgreSQLDisconnect(int index);
  void slotPostgreSQLKernelUrlDistributionTimeout(int value);
  void slotPostgreSQLWebServerCredentials(void);
  void slotPrepareAndShowInstallationWizard(void);
  void slotPrepareContextMenuMirrors(void);
  void slotPrepareSMP(const QString &hash);
  void slotPrepareSMP(void);
  void slotPrepareUrlDatabases(void);
  void slotPreviewStyleSheet(void);
  void slotProtocolRadioToggled(bool state);
  void slotProxyChecked(bool state);
  void slotProxyTypeChanged(int index);
  void slotPublicizeAllListenersPlaintext(void);
  void slotPublicizeListenerPlaintext(void);
  void slotPublishPeriodicallyToggled(bool state);
  void slotPublishedKeySizeChanged(int index);
  void slotPurgeEphemeralKeyPair(void);
  void slotPurgeEphemeralKeys(void);
  void slotQuit(void);
  void slotReceivedKernelMessage(void);
  void slotReceiversChanged(QTableWidgetItem *item);
  void slotReceiversClicked(bool state);
  void slotRefreshMail(void);
  void slotRefreshPostOffice(void);
  void slotRefreshUrlDistillers(void);
  void slotRegenerateKey(void);
  void slotReloadEmailNames(void);
  void slotRemoveAttachment(const QUrl &url);
  void slotRemoveEmailParticipants(void);
  void slotRemoveOtmOnExit(bool state);
  void slotRemoveParticipants(void);
  void slotRemoveUrlParticipants(void);
  void slotRenameParticipant(void);
  void slotReplayMessages(void);
  void slotReply(void);
  void slotResendMail(void);
  void slotResetAETokenInformation(void);
  void slotResetAccountInformation(void);
  void slotResetAddListener(void);
  void slotResetAddNeighbor(void);
  void slotResetAll(void);
  void slotResetAllStyleSheets(void);
  void slotResetCertificate(void);
  void slotResetForwardSecrecyInformation(void);
  void slotResetPrivateApplicationInformation(void);
  void slotResetSearch(void);
  void slotResetStyleSheet(void);
  void slotRespondToForwardSecrecy(void);
  void slotRetrieveMail(void);
  void slotRewindFile(void);
  void slotSOSSMaximumClientsChanged(int value);
  void slotSaveAlternatingColors(bool state);
  void slotSaveAttachment(void);
  void slotSaveBuzzAutoJoin(bool state);
  void slotSaveBuzzName(void);
  void slotSaveCommonUrlCredentials(void);
  void slotSaveCongestionAlgorithm(int index);
  void slotSaveCustomStatus(void);
  void slotSaveDestination(void);
  void slotSaveEmailName(void);
  void slotSaveExternalIPUrl(void);
  void slotSaveGITEnvironment(void);
  void slotSaveGeoIPPath(void);
  void slotSaveKernelPath(void);
  void slotSaveLineLimits(int value);
  void slotSaveMOTD(void);
  void slotSaveNodeName(void);
  void slotSaveOpenLinks(bool state);
  void slotSavePoptasticAccount(void);
  void slotSaveRefreshEmail(bool state);
  void slotSaveSecondaryStorage(bool state);
  void slotSaveSharePrivateKeys(bool state);
  void slotSaveSslControlString(void);
  void slotSaveStarBeamAutoVerify(bool state);
  void slotSaveUrlCredentials(void);
  void slotSaveUrlDistribution(int index);
  void slotSaveUrlName(void);
  void slotScramble(bool state);
  void slotSearchResultsPerPage(int value);
  void slotSecureMemoryPoolChanged(int value);
  void slotSelectCAPath(void);
  void slotSelectDestination(void);
  void slotSelectGeoIPPath(void);
  void slotSelectKernelPath(void);
  void slotSelectTransmitFile(void);
  void slotSelectUrlIniPath(void);
  void slotSendMail(void);
  void slotSendMessage(void);
  void slotSeparateBuzzPage(void);
  void slotSetAETokenInformation(void);
  void slotSetCongestionMaxPageCount(int value);
  void slotSetIconSize(int index);
  void slotSetIcons(int index);
  void slotSetListenerSSLControlString(void);
  void slotSetNeighborPriority(void);
  void slotSetNeighborSSLControlString(void);
  void slotSetPassphrase(void);
  void slotSetPrivateApplicationInformation(void);
  void slotSetSBPulseSize(void);
  void slotSetSBReadInterval(void);
  void slotSetSocketOptions(void);
  void slotSetStyleSheet(void);
  void slotSetUrlIniPath(void);
  void slotSetWidgetStyleSheet(const QPoint &point);
  void slotShareBuzzMagnet(void);
  void slotShareChatPublicKey(void);
  void slotShareChatPublicKeyWithParticipant(void);
  void slotShareEmailPublicKey(void);
  void slotShareEmailPublicKeyWithParticipant(void);
  void slotShareKeysWithKernel(const QString &link);
  void slotShareOpenLibraryPublicKey(void);
  void slotSharePoptasticPublicKey(void);
  void slotShareStarBeam(void);
  void slotShareURLPublicKey(void);
  void slotShareUrlPublicKeyWithParticipant(void);
  void slotShowAddParticipant(void);
  void slotShowBuzzDetails(bool state);
  void slotShowBuzzTabContextMenu(const QPoint &point);
  void slotShowContextMenu(const QPoint &point);
  void slotShowDocumentation(void);
  void slotShowEncryptFile(void);
  void slotShowErrorMessage(void);
  void slotShowEtpMagnetsMenu(const QPoint &point);
  void slotShowMainTabContextMenu(const QPoint &point);
  void slotShowMinimalDisplay(bool state);
  void slotShowNeighborStatistics(void);
  void slotShowNotificationsWindow(void);
  void slotShowOptions(void);
  void slotShowPage(bool state);
  void slotShowReleaseNotes(void);
  void slotShowRss(void);
  void slotShowSMPWindow(void);
  void slotShowStatistics(void);
  void slotShowStatisticsWindow(void);
  void slotShowUrlSettings(bool state);
  void slotSignatureCheckBoxToggled(bool state);
  void slotSignatureKeyTypeChanged(int index);
  void slotStarBeamFragmented(bool state);
  void slotStarOTMCheckChange(bool state);
  void slotStatisticsGathered(void);
  void slotStatusButtonClicked(void);
  void slotStatusChanged(int index);
  void slotStyleSheetChanged(int index);
  void slotSuperEcho(int index);
  void slotTabChanged(int index);
  void slotTearOffMenusEnabled(bool state);
  void slotTerminateKernelOnUIExit(bool state);
  void slotTestPoptasticPop3Settings(void);
  void slotTestPoptasticSmtpSettings(void);
  void slotTestSslControlString(void);
  void slotTimeSliderDefaults(void);
  void slotTimeSliderValueChanged(int value);
  void slotTransmit(void);
  void slotTransmittedPaused(bool state);
  void slotTransmittedSelected(void);
  void slotTransportChanged(int index);
  void slotUnblockNeighbor(void);
  void slotUnifyBuzz(void);
  void slotUpdateChatWindows(void);
  void slotUpdateSpinBoxChanged(double value);
  void slotUrlLinkClicked(const QUrl &u);
  void slotUrlPolarizerTypeChange(int index);
  void slotVacuumDatabases(void);
  void slotValidatePassphrase(void);
  void slotVerify(void);
  void slotVerifySMPSecret(const QString &hash,
			   const QString &keyType,
			   const QString &oid);
  void slotVerifySMPSecret(void);
  void slotViewEchoKeyShare(void);
  void slotViewLog(void);
  void slotViewRosetta(void);
  void slotWebServerAllowServingLocalContent(bool state);
  void slotWebServerInformationTimeout(void);
  void slotWebServerPortChanged(int value);
  void slotWebServerValueChangedTimeout(void);
  void slotWizardButtonClicked(void);
  void slotWizardCheckClicked(void);

 signals:
  void buzzNameChanged(const QByteArray &name);
  void dataReceived(const qint64 size);
  void dataSent(const qint64 size);
  void iconsChanged(void);
  void minimal(const bool state);
  void neighborsQueryReady(QSqlDatabase *db,
			   QSqlQuery *query,
			   const QString &connectionName,
			   const int &size);
  void newEmailName(const QString &text);
  void newGlobalName(const QString &text);
  void participantAdded(const QString &type);
  void participantDeleted(const QString &oid, const QString &type);
  void participantNameChanged(const QByteArray &publicKeyHash,
			      const QString &name);
  void participantsQueryReady(QSqlDatabase *db,
			      QSqlQuery *query,
			      const QString &connectionName);
  void pqUrlDatabaseFaulty(void);
  void smpMessageReceivedFromKernel(const QByteArrayList &list);
  void statusChanged(const QIcon &icon,
		     const QString &name,
		     const QString &id,
		     const QString &toolTip);
  void updateEmailWindows(void);
};

class spoton_table_widget_item: public QTableWidgetItem
{
 public:
  spoton_table_widget_item(const QString &text):QTableWidgetItem(text)
  {
  }

  spoton_table_widget_item(void):QTableWidgetItem()
  {
  }

  bool operator < (const QTableWidgetItem &other) const
  {
    static QRegularExpression s_regexp("[!+.:=@A-Za-z]");

    if(Qt::ItemIsUserCheckable & flags())
      return checkState() < other.checkState();
    else if(other.text().contains(s_regexp) || text().contains(s_regexp))
      return other.text() > text();
    else
      return other.text().remove(",").toLongLong() >
        text().remove(",").toLongLong();
  }
};

#if QT_VERSION >= 0x050600 && defined(SPOTON_WEBENGINE_ENABLED)
class spoton_webengine_url_request_interceptor:
  public QWebEngineUrlRequestInterceptor
{
  Q_OBJECT

 public:
  spoton_webengine_url_request_interceptor(QObject *parent):
  QWebEngineUrlRequestInterceptor(parent)
  {
  }

  ~spoton_webengine_url_request_interceptor()
  {
  }

  void interceptRequest(QWebEngineUrlRequestInfo &info)
  {
    info.block(true);
  }
};
#endif
#endif
