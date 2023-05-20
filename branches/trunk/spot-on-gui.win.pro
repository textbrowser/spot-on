cache()
include(spot-on-gui-source.windows.pro)
libntru.commands = $(MAKE) -C ..\\..\\libNTRU
libntru.depends =
libntru.target = libntru.dll
mceliece_supported = "false"

CONFIG		+= qt release warn_on
CONFIG		-= debug
LANGUAGE	= C++
QT		+= concurrent \
                   gui \
                   multimedia \
                   network \
                   printsupport \
                   sql \
                   websockets \
                   widgets

DEFINES         += LIBSPOTON_OS_WINDOWS \
                   SPOTON_DATELESS_COMPILATION \
		   SPOTON_GPGME_ENABLED \
                   SPOTON_LINKED_WITH_LIBNTRU \
                   SPOTON_LINKED_WITH_LIBPTHREAD \
                   SPOTON_POSTGRESQL_DISABLED \
		   SPOTON_WEBSOCKETS_ENABLED

equals(mceliece_supported, "true") {
DEFINES         += SPOTON_MCELIECE_ENABLED
}

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ..\\..\\libNTRU\\libntru.dll \
                          ..\\..\\libNTRU\\src\\*.o \
                          ..\\..\\libNTRU\\src\\*.s \
                          Spot-On
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wextra \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstrict-overflow=5 \
                          -fwrapv \
                          -pedantic \
                          -pie \
                          -std=c++17
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_DISTCLEAN        += -r debug \
                          .qmake.cache \
                          .qmake.stash \
                          object_script.Spot-On.Debug \
                          object_script.Spot-On.Release
QMAKE_EXTRA_TARGETS    = libntru purge

INCLUDEPATH	+= . \
                   ..\\..\\. \
                   ..\\..\\libGPGME\\Win64.d \
                   ..\\..\\libOpenSSL\\Include.win64 \
                   ..\\..\\libSpotOn\\Include.win64 \
                   GUI

equals(mceliece_supported, "true") {
INCLUDEPATH     += ..\\..\\libNTL\\windows.d\\include
}

LIBS		+= -L..\\..\\libGPGME\\Win64.d \
		   -L..\\..\\libNTRU \
		   -L..\\..\\libOpenSSL\\Libraries.win64 \
                   -L..\\..\\libSpotOn\\Libraries.win64 \
                   -lcrypto-3-x64 \
                   -lgcrypt-20 \
                   -lgpg-error-0 \
                   -lgpgme-11 \
                   -lntru \
                   -lpthread \
                   -lsqlite3 \
                   -lssl-3-x64 \
                   -lws2_64

equals(mceliece_supported, "true") {
LIBS            += -L..\\..\\libNTL\\windows.d\\libraries.d -lntl
}

PRE_TARGETDEPS  = libntru.dll
PROJECTNAME	= Spot-On
RC_FILE		= Icons\\Resources\\spot-on.rc
TARGET		= Spot-On
TEMPLATE        = app

data.files = Data\\*.txt
data.path = release\\.
documentation.files = Documentation
documentation.path = release\\.
executables.files = ..\\..\\Windows\\*.exe
executables.path = release\\.
libgpgme1.files = ..\\..\\libGPGME\\Win64.d\\*.dll
libgpgme1.path = release\\.
libgpgme2.files = ..\\..\\libGPGME\\Win64.d\\*.exe
libgpgme2.path = release\\.

equals(mceliece_supported, "true") {
libntl.files = ..\\..\\libNTL\\windows.d\\libraries.d\\*.dll
libntl.path = release\\.
}

libntrudll.files = ..\\..\\libNTRU\\*.dll
libntrudll.path = release\\.
libopenssl.files = ..\\..\\libOpenSSL\\Libraries.win64\\*.dll
libopenssl.path = release\\.
libspoton1.files = ..\\..\\libSpotOn\\Libraries.win64\\*.dll
libspoton1.path = release\\.
libspoton2.files = ..\\..\\libSpotOn\\Libraries.win64\\thread.d\\*.dll
libspoton2.path = release\\.
plugins1.files = $$[QT_INSTALL_PLUGINS]\\*
plugins1.path = release\\plugins\\.
plugins2.files = $$[QT_INSTALL_PLUGINS]\\gamepads\\xinputgamepad.dll
plugins2.path = release\\plugins\\gamepads\\.
plugins3.files = $$[QT_INSTALL_PLUGINS]\\platforms\\qdirect2d.dll
plugins3.path = release\\plugins\\platforms\\.
plugins4.files = $$[QT_INSTALL_PLUGINS]\\renderplugins\\scene2d.dll
plugins4.path = release\\plugins\\renderplugins\\.
pluginspurge.extra = del /q /s *d.dll
pluginspurge.path = release\\plugins\\.
qt.files = Qt\\qt.conf
qt.path = release\\.
qtlibraries.files = $$[QT_INSTALL_BINS]\\Qt5Core.dll \
                    $$[QT_INSTALL_BINS]\\Qt5Gui.dll \
                    $$[QT_INSTALL_BINS]\\Qt5Multimedia.dll \
                    $$[QT_INSTALL_BINS]\\Qt5Network.dll \
                    $$[QT_INSTALL_BINS]\\Qt5PrintSupport.dll \
                    $$[QT_INSTALL_BINS]\\Qt5Sql.dll \
                    $$[QT_INSTALL_BINS]\\Qt5WebSockets.dll \
                    $$[QT_INSTALL_BINS]\\Qt5Widgets.dll \
                    $$[QT_INSTALL_BINS]\\libgcc_s_dw2-1.dll \
                    $$[QT_INSTALL_BINS]\\libstdc++-6.dll \
                    $$[QT_INSTALL_BINS]\\libwinpthread-1.dll
qtlibraries.path = release\\.
sounds.files = Sounds
sounds.path = release\\.
spotonbat.files = Shell\\*.bat
spotonbat.path = release\\.
sql1.files = SQL\\README*
sql1.path = release\\SQL\\.
sql2.files = SQL\\*.sql
sql2.path = release\\SQL\\.
translations.files = Translations\\*.qm
translations.path = release\\Translations\\.

INSTALLS = plugins1 \
           pluginspurge \
           data \
           documentation \
           executables \
           libgpgme1 \
           libgpgme2 \
           libntl \
           libntrudll \
           libopenssl \
           libspoton1 \
           libspoton2 \
           plugins2 \
           plugins3 \
           plugins4 \
           qt \
           qtlibraries \
           sounds \
           spotonbat \
           sql1 \
           sql2 \
           translations
