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
#include <QFileDialog>
#include <QFuture>
#include <QHash>
#include <QInputDialog>
#include <QLocale>
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
#include <QMacStyle>
#endif
#endif
#include <QMainWindow>
#if QT_VERSION >= 0x050000
#include <QMediaPlayer>
#endif
#include <QMessageBox>
#include <QMouseEvent>
#ifdef Q_OS_WIN32
#include <qt_windows.h>
#include <QtNetwork>
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
#include <QTimer>
#include <QTranslator>
#include <QUuid>
#include <QtDebug>

#include <limits>

extern "C"
{
#include "libSpotOn/libspoton.h"
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
#include "Common/CocoaInitializer.h"
#endif
#endif

#include "spot-on-defines.h"
#include "ui_keyboard.h"

class QStandardItemModel;

class spoton_virtual_keyboard: public QDialog
{
  Q_OBJECT

 public:
  spoton_virtual_keyboard(QWidget *parent):QDialog(parent)
  {
    m_ui.setupUi(this);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
    setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
    setWindowTitle
      (tr("%1: Virtual Keyboard").arg(SPOTON_APPLICATION_NAME));
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

    QLocale::Country country = QLocale::system().country();
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
	QToolButton *button = new QToolButton(this);

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
	QToolButton *button = new QToolButton(this);

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
	QToolButton *button = new QToolButton(this);

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
	QToolButton *button = new QToolButton(this);

	button->setMinimumSize(45, 45);
	button->setText(row.at(i));
	m_ui.row3->addWidget(button);
      }

    foreach(QToolButton *button, findChildren<QToolButton *> ())
      if(button != m_ui.back && button != m_ui.shift)
	connect(button,
		SIGNAL(clicked(void)),
		this,
		SLOT(slotKeyPressed(void)));
  }

  ~spoton_virtual_keyboard()
  {
  }

  Ui_keyboard m_ui;

 private slots:
  void slotBack(void)
  {
    m_ui.passphrase->backspace();
  }

  void slotKeyPressed(void)
  {
    QToolButton *button = qobject_cast<QToolButton *> (sender());

    if(!button)
      return;

    QString text(m_ui.passphrase->text());

    if(button == m_ui.space)
      text.append(" ");
    else if(m_ui.shift->isChecked())
      text.append(button->text().split('\n').value(0).toUpper());
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
    foreach(QToolButton *button, findChildren<QToolButton *> ())
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
	    setText(m_dialog->m_ui.passphrase->text());

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
#include "spot-on-echo-key-share.h"
#include "spot-on-encryptfile.h"
#include "spot-on-logviewer.h"
#include "spot-on-reencode.h"
#include "spot-on-rosetta.h"
#include "spot-on-smp.h"
#include "spot-on-starbeamanalyzer.h"
#include "ui_controlcenter.h"
#include "ui_options.h"
#include "ui_poptastic-retrophone-settings.h"
#include "ui_statusbar.h"

class QProgressDialog;

class spoton_forward_secrecy
{
 public:
  QByteArray public_key;
  QByteArray public_key_hash;
  QString key_type;
};

class spoton: public QMainWindow
{
  Q_OBJECT

 public:
  spoton(void);
  ~spoton();
  QHash<QString, QPair<QQueue<QString>, QQueue<QByteArray> > >
    m_chatQueues;
  QHash<QString, QVariant> m_settings;
  QHash<QString, quint64> m_chatSequenceNumbers;
  QHash<QString, spoton_crypt *> crypts(void) const;
  QStandardItemModel *starbeamReceivedModel(void) const;
  Ui_spoton_mainwindow ui(void) const;
  static QList<QTableWidgetItem *> findItems(QTableWidget *table,
					     const QString &text,
					     const int column);
  static QPointer<spoton> instance(void);
  static QString mapIconToEmoticon(const QString &content);
  void addMessageToReplayQueue(const QString &message1,
			       const QByteArray &message2,
			       const QString &publicKeyHash);

 private:
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_ATTACHMENTS = 1;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_DATABASE = 2;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_GENERAL = 3;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_MEMORY = 4;
  QAtomicInt m_starbeamDigestInterrupt;
  QByteArray m_kernelSocketData;
  QDateTime m_buzzFavoritesLastModificationTime;
  QDateTime m_magnetsLastModificationTime;
  QDateTime m_kernelStatisticsLastModificationTime;
  QDateTime m_listenersLastModificationTime;
  QDateTime m_neighborsLastModificationTime;
  QDateTime m_participantsLastModificationTime;
  QDateTime m_starsLastModificationTime;
  QDialog *m_poptasticRetroPhoneDialog;
  QHash<QByteArray, QString> m_neighborToOidMap;
  QHash<QByteArray, quint64> m_receivedChatSequenceNumbers;
  QHash<QByteArray, spoton_forward_secrecy> m_forwardSecrecyRequests;
  QHash<QString, QByteArray> m_buzzIds;
  QHash<QString, QPointer<spoton_chatwindow> > m_chatWindows;
  QHash<QString, QString> m_keysShared;
  QHash<QString, spoton_crypt *> m_crypts;
  QHash<QString, spoton_smp *> m_smps; /*
				       ** The objects contained within
				       ** m_smps are destroyed whenever
				       ** participants are removed or
				       ** whenever the UI process terminates.
				       ** Unlike m_chatWindows, m_smps
				       ** purging is less rigid.
				       */
  QList<QFuture<void> > m_starbeamDigestFutures;
  QMainWindow *m_optionsWindow;
  QSet<QString> m_urlPrefixes;
  QSqlDatabase m_urlDatabase;
  QSslSocket m_kernelSocket;
  QStandardItemModel *m_starbeamReceivedModel;
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
  QWidget *m_sbWidget;
  Ui_poptasticretrophonesettings m_poptasticRetroPhoneSettingsUi;
  Ui_spoton_mainwindow m_ui;
  Ui_spoton_options m_optionsUi;
  Ui_statusbar m_sb;
  bool m_locked;
  quint64 m_urlCurrentPage;
  quint64 m_urlLimit;
  quint64 m_urlOffset;
  quint64 m_urlPages;
  spoton_crypt *m_urlCommonCrypt;
  spoton_echo_key_share *m_echoKeyShare;
  spoton_encryptfile m_encryptFile;
  spoton_external_address m_externalAddress;
  spoton_logviewer m_logViewer;
  spoton_rosetta m_rosetta;
  spoton_starbeamanalyzer *m_starbeamAnalyzer;
  QByteArray copiedPublicKeyPairToMagnet(const QByteArray &data) const;
  QByteArray copyMyChatPublicKey(void) const;
  QByteArray copyMyEmailPublicKey(void) const;
  QByteArray copyMyPoptasticPublicKey(void) const;
  QByteArray copyMyRosettaPublicKey(void) const;
  QByteArray copyMyUrlPublicKey(void) const;
  QByteArray poptasticName(void) const;
  QList<QByteArray> retrieveForwardSecrecyInformation
    (const QSqlDatabase &db, const QString &oid, bool *ok) const;
  QPixmap pixmapForCountry(const QString &country) const;
  QString currentTabName(void) const;
  QString saveCommonUrlCredentials
    (const QPair<QByteArray, QByteArray> &keys,
     const QString &cipherType, const QString &hashType,
     spoton_crypt *crypt) const;
  QStringList parseAEMagnet(const QString &magnet) const;
  bool deleteAllUrls(void);
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
  bool event(QEvent *event);
#endif
#endif
  bool importUrl(const QByteArray &description,
		 const QByteArray &title,
		 const QByteArray &url);
  bool isKernelActive(void) const;
  bool promptBeforeExit(void);
  bool saveGemini(const QPair<QByteArray, QByteArray> &gemini,
		  const QString &oid);
  bool updateMailStatus(const QString &oid, const QString &status);
  int applyGoldBugToLetter(const QByteArray &goldbug,
			   const int row);
  void addFriendsKey(const QByteArray &key, const QString &type);
  void applyGoldBugToAttachments(const QString &folderOid,
				 const QSqlDatabase &db,
				 int *count,
				 spoton_crypt *crypt,
				 bool *ok);
  void askKernelToReadStarBeamKeys(void);
  void authenticate(spoton_crypt *crypt, const QString &oid,
		    const QString &message = "");
  void authenticationRequested(const QByteArray &data);
  void changeEchoMode(const QString &mode, QTableWidget *tableWidget);
  void cleanup(void);
  void closeEvent(QCloseEvent *event);
  void computeFileDigest(const QByteArray &expectedFileHash,
			 const QString &fileName,
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
  void generateHalfGeminis(void);
  void highlightPaths(void);
  void importNeighbors(const QString &filePath);
  void initializeKernelSocket(void);
  void initializeSMP(const QString &hash);
  void initializeUrlDistillers(void);
  void joinDefaultBuzzChannel(void);
  void magnetize(void);
  void playSong(const QString &name);
  void popForwardSecrecyRequest(const QByteArray &publicKeyHash);
  void populateAETokens(void);
  void populateAccounts(const QString &listenerOid);
  void populateListenerIps(const QString &listenerOid);
  void populateMOTD(const QString &listenerOid);
  void populateMail(void);
  void populateNovas(void);
  void populateUrlDistillers(void);
  void prepareContextMenuMirrors(void);
  void prepareListenerIPCombo(void);
  void prepareSMP(const QString &hash);
  void prepareTabIcons(void);
  void prepareTimeWidgets(void);
  void prepareUrlContainers(void);
  void prepareUrlLabels(void);
  void refreshInstitutions(void);
  void removeFavorite(const bool removeAll);
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
  void setSBField(const QString &oid, const QVariant &value,
		  const QString &field);
  void sharePublicKeyWithParticipant(const QString &keyType);
  void showError(const QString &error);
  void showUrls(const QString &link, const QString &querystr);
  void updateListenersTable(const QSqlDatabase &db);
  void updateNeighborsTable(const QSqlDatabase &db);
  void updateParticipantsTable(const QSqlDatabase &db);
  void updatePublicKeysLabel(void);
  void verifySMPSecret(const QString &hash, const QString &keyType,
		       const QString &oid);

 private slots:
  void slotAbout(void);
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
  void slotAddBootstrapper(void);
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
  void slotAllowFSRequest(bool state);
  void slotAssignNewIPToNeighbor(void);
  void slotAuthenticate(void);
  void slotAuthenticationRequestButtonClicked(void);
  void slotAutoAddSharedSBMagnets(bool state);
  void slotAutoRetrieveEmail(bool state);
  void slotBlockNeighbor(void);
  void slotBluetoothSecurityChanged(int index);
  void slotBuzzActionsActivated(int index);
  void slotBuzzChanged(void);
  void slotBuzzTools(int index);
  void slotCallParticipant(void);
  void slotCallParticipantViaForwardSecrecy(void);
  void slotChangeTabPosition(int index);
  void slotChatInactivityTimeout(void);
  void slotChatPopup(void);
  void slotChatSendMethodChanged(int index);
  void slotChatWindowDestroyed(void);
  void slotChatWindowMessageSent(void);
  void slotClearClipboardBuffer(void);
  void slotClearOutgoingMessage(void);
  void slotCloseBuzzTab(int index);
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
  void slotCopyMyPoptasticPublicKey(void);
  void slotCopyMyRosettaPublicKey(void);
  void slotCopyMyURLPublicKey(void);
  void slotCopyOrPaste(void);
  void slotCopyTransmittedMagnet(void);
  void slotCopyUrlFriendshipBundle(void);
  void slotCorrectUrlDatabases(void);
  void slotCostChanged(int value);
  void slotDaysChanged(int value);
  void slotDeactivateKernel(void);
  void slotDeleteAEToken(void);
  void slotDeleteAccepedIP(void);
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
  void slotDeleteReceived(void);
  void slotDeleteTransmitted(void);
  void slotDeleteUrlDistillers(void);
  void slotDemagnetizeMissingLinks(void);
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
  void slotDiscoverMissingLinks(void);
  void slotDisplayLocalSearchResults(void);
  void slotDisplayPopups(bool state);
  void slotDoSearch(void);
  void slotDuplicateTransmittedMagnet(void);
  void slotEmailFsGb(int index);
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
  void slotFetchMoreAlgo(void);
  void slotFetchMoreButton(void);
  void slotForceKernelRegistration(bool state);
  void slotForwardSecrecyEncryptionKeyChanged(int index);
  void slotGatherUrlStatistics(void);
  void slotGeminiChanged(QTableWidgetItem *item);
  void slotGenerateEtpKeys(int index);
  void slotGeneralTimerTimeout(void);
  void slotGenerateGeminiInChat(void);
  void slotGenerateNova(void);
  void slotKeepCopy(bool state);
  void slotKeepOnlyUserDefinedNeighbors(bool state);
  void slotKernelCipherTypeChanged(int index);
  void slotKernelHashTypeChanged(int index);
  void slotKernelKeySizeChanged(const QString &text);
  void slotKernelLogEvents(bool state);
  void slotKernelSocketError(QAbstractSocket::SocketError error);
  void slotKernelSocketSslErrors(const QList<QSslError> &errors);
  void slotKernelSocketState(void);
  void slotKernelStatus(void);
  void slotHideOfflineParticipants(bool state);
  void slotImpersonate(bool state);
  void slotImportNeighbors(void);
  void slotImportPublicKeys(void);
  void slotImportUrls(void);
  void slotInitializeSMP(const QString &hash);
  void slotInitializeSMP(void);
  void slotJoinBuzzChannel(void);
  void slotLaneWidthChanged(int index);
  void slotLaunchKernelAfterAuthentication(bool state);
  void slotLimitConnections(int value);
  void slotLinkClicked(const QUrl &url);
  void slotListenerCheckChange(bool state);
  void slotListenerFullEcho(void);
  void slotListenerHalfEcho(void);
  void slotListenerIPComboChanged(int index);
  void slotListenerMaximumChanged(int value);
  void slotListenerSelected(void);
  void slotListenerUseAccounts(bool state);
  void slotLock(void);
  void slotMagnetRadioToggled(bool state);
  void slotMailRetrievalIntervalChanged(int value);
  void slotMailSelected(QTableWidgetItem *item);
  void slotMailSelected(void);
  void slotMailTabChanged(int index);
  void slotMaxMosaicSize(int value);
  void slotMaximumClientsChanged(int index);
  void slotMaximumEmailFileSizeChanged(int value);
#if QT_VERSION >= 0x050000
  void slotMediaError(QMediaPlayer::Error error);
  void slotMediaStatusChanged(QMediaPlayer::MediaStatus status);
#endif
  void slotMessagesAnchorClicked(const QUrl &url);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotMosaicLocked(bool state);
  void slotNeighborCheckChange(bool state);
  void slotNeighborFullEcho(void);
  void slotNeighborHalfEcho(void);
  void slotNeighborMaximumChanged(int value);
  void slotNeighborSelected(void);
  void slotNewKeys(bool state);
  void slotOntopChatDialogs(bool state);
  void slotPageClicked(const QString &link);
  void slotParticipantDoubleClicked(QTableWidgetItem *item);
  void slotPassphraseAuthenticateRadioToggled(bool state);
  void slotPassphraseRadioToggled(bool state);
  void slotPoptasticSettingsReset(bool state);
  void slotPoptasticSettingsReset(void);
  void slotPopulateBuzzFavorites(void);
  void slotPopulateEtpMagnets(void);
  void slotPopulateKernelStatistics(void);
  void slotPopulateListeners(void);
  void slotPopulateNeighbors(void);
  void slotPopulateParticipants(void);
  void slotPopulateStars(void);
  void slotPostgreSQLConnect(void);
  void slotPostgreSQLDisconnect(int index);
  void slotPrepareSMP(const QString &hash);
  void slotPrepareSMP(void);
  void slotPrepareUrlDatabases(void);
  void slotProtocolRadioToggled(bool state);
  void slotProxyChecked(bool state);
  void slotProxyTypeChanged(int index);
  void slotPublicizeAllListenersPlaintext(void);
  void slotPublicizeListenerPlaintext(void);
  void slotPublishPeriodicallyToggled(bool sate);
  void slotPublishedKeySizeChanged(const QString &text);
  void slotPurgeEphemeralKeyPair(void);
  void slotPurgeEphemeralKeys(void);
  void slotQuit(void);
  void slotReceivedKernelMessage(void);
  void slotReceiversClicked(bool state);
  void slotRefreshMail(void);
  void slotRefreshPostOffice(void);
  void slotRefreshUrlDistillers(void);
  void slotRegenerateKey(void);
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
  void slotResetAll(void);
  void slotResetCertificate(void);
  void slotResetForwardSecrecyInformation(void);
  void slotRespondToForwardSecrecy(void);
  void slotRetrieveMail(void);
  void slotRewindFile(void);
  void slotSaveAlternatingColors(bool state);
  void slotSaveAttachment(void);
  void slotSaveBuzzAutoJoin(bool state);
  void slotSaveBuzzName(void);
  void slotSaveCommonUrlCredentials(void);
  void slotSaveCongestionAlgorithm(const QString &text);
  void slotSaveCustomStatus(void);
  void slotSaveDestination(void);
  void slotSaveEmailName(void);
  void slotSaveGeoIPPath(void);
  void slotSaveKernelPath(void);
  void slotSaveMOTD(void);
  void slotSaveNodeName(void);
  void slotSaveOpenLinks(bool state);
  void slotSaveRefreshEmail(bool state);
  void slotSaveSharePrivateKeys(bool state);
  void slotSaveSslControlString(void);
  void slotSaveStarBeamAutoVerify(bool state);
  void slotSaveUrlCredentials(void);
  void slotSaveUrlName(void);
  void slotSaveUrlDistribution(int index);
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
  void slotSetAETokenInformation(void);
  void slotSetIconSize(int index);
  void slotSetIcons(int index);
  void slotSetListenerSSLControlString(void);
  void slotSetNeighborPriority(void);
  void slotSetNeighborSSLControlString(void);
  void slotSetPassphrase(void);
  void slotSetSBPulseSize(void);
  void slotSetSBReadInterval(void);
  void slotSetUrlIniPath(void);
  void slotShareBuzzMagnet(void);
  void slotShareChatPublicKey(void);
  void slotShareChatPublicKeyWithParticipant(void);
  void slotShareEmailPublicKey(void);
  void slotShareEmailPublicKeyWithParticipant(void);
  void slotShareKeysWithKernel(const QString &link);
  void slotSharePoptasticPublicKey(void);
  void slotShareStarBeam(void);
  void slotShareUrlPublicKeyWithParticipant(void);
  void slotShareURLPublicKey(void);
  void slotShowContextMenu(const QPoint &point);
  void slotShowEncryptFile(void);
  void slotShowEtpMagnetsMenu(const QPoint &point);
  void slotShowMinimalDisplay(bool state);
  void slotShowOptions(void);
  void slotShowStarBeamAnalyzer(void);
  void slotShowStatistics(void);
  void slotShowUrlSettings(bool state);
  void slotSignatureCheckBoxToggled(bool state);
  void slotSignatureKeyTypeChanged(int index);
  void slotStarBeamReceivedAndVerified(const QString &fileName);
  void slotStarOTMCheckChange(bool state);
  void slotStatusButtonClicked(void);
  void slotStatusChanged(int index);
  void slotSuperEcho(int index);
  void slotTabChanged(int index);
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
  void slotUpdateChatWindows(void);
  void slotUpdateSpinBoxChanged(double value);
  void slotUrlLinkClicked(const QUrl &u);
  void slotUrlPolarizerTypeChange(int index);
  void slotValidatePassphrase(void);
  void slotVerify(void);
  void slotVerifySMPSecret(const QString &hash, const QString &keyType,
			   const QString &oid);
  void slotVerifySMPSecret(void);
  void slotViewEchoKeyShare(void);
  void slotViewLog(void);
  void slotViewRosetta(void);

 signals:
  void buzzNameChanged(const QByteArray &name);
  void iconsChanged(void);
  void starBeamReceivedAndVerified(const QString &fileName);
  void statusChanged(const QIcon &icon,
		     const QString &name,
		     const QString &id,
		     const QString &toolTip);
};

#endif
