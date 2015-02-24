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
#include <QDir>
#include <QFileDialog>
#include <QFuture>
#include <QHash>
#include <QInputDialog>
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
#include <QMacStyle>
#endif
#endif
#include <QMainWindow>
#include <QMessageBox>
#ifdef Q_OS_WIN32
#include <qt_windows.h>
#include <QtNetwork>
#else
#include <QNetworkInterface>
#endif
#include <QPointer>
#include <QProcess>
#include <QScrollBar>
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
#ifdef SPOTON_LINKED_WITH_LIBPHONON
#if 0
#include <phonon/AudioOutput>
#include <phonon/MediaObject>
#endif
#endif

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

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-external-address.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-chatwindow.h"
#include "spot-on-encryptfile.h"
#include "spot-on-logviewer.h"
#include "spot-on-reencode.h"
#include "spot-on-rosetta.h"
#include "spot-on-smp.h"
#include "spot-on-starbeamanalyzer.h"
#include "ui_controlcenter.h"
#include "ui_options.h"
#include "ui_poptasticsettings.h"
#include "ui_statusbar.h"

class QProgressDialog;

class spoton: public QMainWindow
{
  Q_OBJECT

 public:
  spoton(void);
  ~spoton();
  QHash<QString, QVariant> m_settings;
  QHash<QString, quint64> m_chatSequenceNumbers;
  Ui_spoton_mainwindow ui(void) const;
  static QPointer<spoton> s_gui;
  static QString mapIconToEmoticon(const QString &content);

 private:
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_ATTACHMENTS = 1;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_DATABASE = 2;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_GENERAL = 3;
  static const int APPLY_GOLDBUG_TO_LETTER_ERROR_MEMORY = 4;
  QByteArray m_kernelSocketData;
  QDateTime m_buzzFavoritesLastModificationTime;
  QDateTime m_magnetsLastModificationTime;
  QDateTime m_kernelStatisticsLastModificationTime;
  QDateTime m_listenersLastModificationTime;
  QDateTime m_neighborsLastModificationTime;
  QDateTime m_participantsLastModificationTime;
  QDateTime m_starsLastModificationTime;
  QDialog *m_poptasticDialog;
  QHash<QByteArray, QString> m_neighborToOidMap;
  QHash<QByteArray, quint64> m_receivedChatSequenceNumbers;
  QHash<QString, QByteArray> m_buzzIds;
  QHash<QString, QPointer<spoton_chatwindow> > m_chatWindows;
  QHash<QString, QString> m_keysShared;
  QHash<QString, spoton_crypt *> m_crypts;
  QHash<QString, spoton_smp *> m_smps;
#ifdef SPOTON_LINKED_WITH_LIBPHONON
#endif
  QMainWindow *m_optionsWindow;
  QSqlDatabase m_urlDatabase;
  QSslSocket m_kernelSocket;
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
  Ui_poptasticsettings m_poptasticSettingsUi;
  Ui_spoton_mainwindow m_ui;
  Ui_spoton_options m_optionsUi;
  Ui_statusbar m_sb;
  quint64 m_urlCurrentPage;
  quint64 m_urlLimit;
  quint64 m_urlOffset;
  quint64 m_urlPages;
  spoton_crypt *m_urlCommonCrypt;
  spoton_encryptfile m_encryptFile;
  spoton_external_address m_externalAddress;
  spoton_logviewer m_logViewer;
  spoton_rosetta m_rosetta;
  spoton_starbeamanalyzer *m_starbeamAnalyzer;
  QByteArray copyMyChatPublicKey(void) const;
  QByteArray copyMyEmailPublicKey(void) const;
  QByteArray copyMyPoptasticPublicKey(void) const;
  QByteArray copyMyRosettaPublicKey(void) const;
  QByteArray copyMyUrlPublicKey(void) const;
  QPixmap pixmapForCountry(const QString &country) const;
  QString currentTabName(void) const;
  QStringList parseAEMagnet(const QString &magnet) const;
  bool deleteAllUrls(void);
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
  bool event(QEvent *event);
#endif
#endif
  bool isKernelActive(void) const;
  bool promptBeforeExit(void);
  bool saveGemini(const QPair<QByteArray, QByteArray> &gemini,
		  const QString &oid);
  bool updateMailStatus(const QString &oid, const QString &status);
  int applyGoldbugToLetter(const QByteArray &goldbug,
			   const int row);
  void addFriendsKey(const QByteArray &key);
  void applyGoldbugToAttachments(const QString &folderOid,
				 const QSqlDatabase &db,
				 int *count,
				 spoton_crypt *crypt,
				 bool *ok);
  void askKernelToReadStarBeamKeys(void);
  void authenticate(spoton_crypt *crypt, const QString &oid,
		    const QString &message = QString(""));
  void authenticationRequested(const QByteArray &data);
  void changeEchoMode(const QString &mode, QTableWidget *tableWidget);
  void cleanup(void);
  void closeEvent(QCloseEvent *event);
  void demagnetize(void);
  void derivativeUpdates(void);
  void discoverUrls(void);
  void generateHalfGeminis(void);
  void highlightPaths(void);
  void importNeighbors(const QString &filePath);
  void importUrl(const QByteArray &description,
		 const QByteArray &title,
		 const QByteArray &url);
  void initializeKernelSocket(void);
  void joinDefaultBuzzChannel(void);
  void magnetize(void);
  void playSong(const QString &name);
  void populateAETokens(void);
  void populateAccounts(const QString &listenerOid);
  void populateListenerIps(const QString &listenerOid);
  void populateMOTD(const QString &listenerOid);
  void populateMail(void);
  void populateNovas(void);
  void populateUrlDistillers(void);
  void prepareContextMenuMirrors(void);
  void prepareListenerIPCombo(void);
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
  void sendSMPLinkToKernel(const QList<QByteArray> &list,
			   const QString &keyType,
			   const QString &oid);
  void sharePublicKeyWithParticipant(const QString &keyType);
  void showUrls(const QString &link, const QString &querystr);
  void updateListenersTable(const QSqlDatabase &db);
  void updateNeighborsTable(const QSqlDatabase &db);
  void updateParticipantsTable(const QSqlDatabase &db);
  void updatePublicKeysLabel(void);

 private slots:
  void slotAcceptBuzzMagnets(bool state);
  void slotAcceptChatKeys(bool state);
  void slotAcceptEmailKeys(bool state);
  void slotAcceptGeminis(bool state);
  void slotAcceptPublicizedListeners(void);
  void slotAcceptUrlKeys(bool state);
  void slotActivateKernel(void);
  void slotAddAEToken(void);
  void slotAddAcceptedIP(void);
  void slotAddAccount(void);
  void slotAddAttachment(void);
  void slotAddBootstrapper(void);
  void slotAddDistiller(void);
  void slotAddEtpMagnet(const QString &text = QString(),
			const bool displayError = true);
  void slotAddFriendsKey(void);
  void slotAddInstitution(const QString &text = QString());
  void slotAddInstitutionCheckBoxToggled(bool state);
  void slotAddListener(void);
  void slotAddMagnet(void);
  void slotAddNeighbor(void);
  void slotAddReceiveNova(void);
  void slotAssignNewIPToNeighbor(void);
  void slotAuthenticate(void);
  void slotAuthenticationRequestButtonClicked(void);
  void slotAutoAddSharedSBMagnets(bool state);
  void slotAutoRetrieveEmail(bool state);
  void slotBlockNeighbor(void);
  void slotBuzzActionsActivated(int index);
  void slotBuzzChanged(void);
  void slotBuzzTools(int index);
  void slotCallParticipant(void);
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
  void slotDeleteLink(const QUrl &u);
  void slotDeleteListener(void);
  void slotDeleteMail(void);
  void slotDeleteNeighbor(void);
  void slotDeleteNova(void);
  void slotDeleteReceived(void);
  void slotDeleteTransmitted(void);
  void slotDeleteUrlDistillers(void);
  void slotDemagnetizeMissingLinks(void);
  void slotDetachListenerNeighbors(void);
  void slotDisconnectAllNeighbors(void);
  void slotDisconnectListenerNeighbors(void);
  void slotDisconnectNeighbor(void);
  void slotDiscover(void);
  void slotDiscoverExternalAddress(void);
  void slotDiscoverMissingLinks(void);
  void slotDisplayLocalSearchResults(void);
  void slotDisplayPopups(bool state);
  void slotDoSearch(void);
  void slotEmptyTrash(void);
  void slotEnableChatEmoticons(bool state);
  void slotEnableRetrieveMail(void);
  void slotEnabledPostOffice(bool state);
  void slotEncryptionKeyTypeChanged(int index);
  void slotExportListeners(void);
  void slotExportPublicKeys(void);
  void slotExternalIp(int index);
  void slotFavoritesActivated(int index);
  void slotFetchMoreAlgo(void);
  void slotFetchMoreButton(void);
  void slotForceKernelRegistration(bool state);
  void slotGatherUrlStatistics(void);
  void slotGeminiChanged(QTableWidgetItem *item);
  void slotGenerateEtpKeys(int index);
  void slotGeneralTimerTimeout(void);
  void slotGenerateGoldBug(void);
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
  void slotInitializeSMP(void);
  void slotJoinBuzzChannel(void);
  void slotLaunchKernelAfterAuthentication(bool state);
  void slotLimitConnections(int value);
  void slotListenerCheckChange(bool state);
  void slotListenerFullEcho(void);
  void slotListenerHalfEcho(void);
  void slotListenerIPComboChanged(int index);
  void slotListenerMaximumChanged(int value);
  void slotListenerSelected(void);
  void slotListenerUseAccounts(bool state);
  void slotMagnetRadioToggled(bool state);
  void slotMailRetrievalIntervalChanged(int value);
  void slotMailSelected(QTableWidgetItem *item);
  void slotMailSelected(void);
  void slotMailTabChanged(int index);
  void slotMaxMosaicSize(int value);
  void slotMaximumClientsChanged(int index);
  void slotMaximumEmailFileSizeChanged(int value);
  void slotMessagesAnchorClicked(const QUrl &url);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotMosaicLocked(bool state);
  void slotNeighborCheckChange(bool state);
  void slotNeighborFullEcho(void);
  void slotNeighborHalfEcho(void);
  void slotNeighborMaximumChanged(int value);
  void slotNeighborSelected(void);
  void slotNewKeys(bool state);
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
  void slotPostgreSQLDisconnect(bool state);
  void slotPrepareSMP(void);
  void slotPrepareUrlDatabases(void);
  void slotProtocolRadioToggled(bool state);
  void slotProxyChecked(bool state);
  void slotProxyTypeChanged(int index);
  void slotPublicizeAllListenersPlaintext(void);
  void slotPublicizeListenerPlaintext(void);
  void slotPublishPeriodicallyToggled(bool sate);
  void slotPublishedKeySizeChanged(const QString &text);
  void slotQuit(void);
  void slotReceivedKernelMessage(void);
  void slotReceiversClicked(bool state);
  void slotRefreshMail(void);
  void slotRefreshPostOffice(void);
  void slotRefreshUrlDistillers(void);
  void slotRegenerateKey(void);
  void slotRemoveEmailParticipants(void);
  void slotRemoveParticipants(void);
  void slotRemoveUrlParticipants(void);
  void slotRenameParticipant(void);
  void slotReply(void);
  void slotResendMail(void);
  void slotResetAETokenInformation(void);
  void slotResetAccountInformation(void);
  void slotResetAll(void);
  void slotResetCertificate(void);
  void slotRetrieveMail(void);
  void slotRewindFile(void);
  void slotSaveAttachment(void);
  void slotSaveBuzzAutoJoin(bool state);
  void slotSaveBuzzName(void);
  void slotSaveCommonUrlCredentials(void);
  void slotSaveDestination(void);
  void slotSaveEmailName(void);
  void slotSaveGeoIPPath(void);
  void slotSaveKernelPath(void);
  void slotSaveMOTD(void);
  void slotSaveNodeName(void);
  void slotSaveOpenLinks(bool state);
  void slotSaveSharePrivateKeys(bool state);
  void slotSaveSslControlString(void);
  void slotSaveUrlCredentials(void);
  void slotSaveUrlName(void);
  void slotSaveUrlDistribution(int index);
  void slotScramble(bool state);
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
  void slotSetUrlIniPath(void);
  void slotShareBuzzMagnet(void);
  void slotShareChatPublicKey(void);
  void slotShareChatPublicKeyWithParticipant(void);
  void slotShareEmailPublicKey(void);
  void slotShareEmailPublicKeyWithParticipant(void);
  void slotShareKeysWithKernel(const QString &link);
  void slotSharePoptasticPublicKey(void);
  void slotShareUrlPublicKeyWithParticipant(void);
  void slotShareURLPublicKey(void);
  void slotShowContextMenu(const QPoint &point);
  void slotShowEncryptFile(void);
  void slotShowEtpMagnetsMenu(const QPoint &point);
  void slotShowMinimalDisplay(bool state);
  void slotShowOptions(void);
  void slotShowStarBeamAnalyzer(void);
  void slotShowStatistics(void);
  void slotShowUrlSettings(void);
  void slotSignatureCheckBoxToggled(bool state);
  void slotSignatureKeyTypeChanged(int index);
  void slotStarOTMCheckChange(bool state);
  void slotStatusButtonClicked(void);
  void slotStatusChanged(int index);
  void slotSuperEcho(int index);
  void slotTabChanged(int index);
  void slotTestPoptasticPop3Settings(void);
  void slotTestPoptasticSmtpSettings(void);
  void slotTestSslControlString(void);
  void slotTransmit(void);
  void slotTransmittedPaused(bool state);
  void slotTransmittedSelected(void);
  void slotTransportChanged(int index);
  void slotUnblockNeighbor(void);
  void slotUpdateChatWindows(void);
  void slotUpdateSpinBoxChanged(double value);
  void slotUrlDistillersRadioButton(bool state);
  void slotValidatePassphrase(void);
  void slotVerify(void);
  void slotVerifySMPSecret(void);
  void slotViewLog(void);
  void slotViewRosetta(void);

 signals:
  void buzzNameChanged(const QByteArray &name);
  void iconsChanged(void);
  void statusChanged(const QIcon &icon,
		     const QString &name,
		     const QString &id);
};

#endif
