cache()
include(spot-on-gui-source.windows.pro)
libntru.commands = $(MAKE) -C ..\\libNTRU
libntru.depends =
libntru.target = libntru.dll
mceliece_supported = "false"

CONFIG		+= qt release warn_on
CONFIG		-= debug
LANGUAGE	= C++
QMAKE_STRIP	=
QT		+= concurrent \
                   gui \
                   multimedia \
                   network \
                   printsupport \
                   sql \
                   websockets \
                   widgets

DEFINES         += SPOTON_DATELESS_COMPILATION \
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

QMAKE_CLEAN            += ..\\libNTRU\\libntru.dll \
                          ..\\libNTRU\\src\\*.o \
                          ..\\libNTRU\\src\\*.s \
                          Spot-On
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wextra \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstrict-overflow=1 \
                          -funroll-loops \
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
                   ..\\. \
                   ..\\libGCrypt\\Include.win64 \
                   ..\\libGPGME\\Include.win64 \
                   ..\\libOpenSSL\\Include.win64 \
                   GUI

equals(mceliece_supported, "true") {
INCLUDEPATH     += ..\\libNTL\\windows.d\\include
}

LIBS		+= -L..\\libNTRU \
                   -L..\\libGCrypt\\Libraries.win64 \
                   -L..\\libGPGME\\Libraries.win64 \
		   -L..\\libOpenSSL\\Libraries.win64 \
                   -lcrypto-3-x64 \
                   -lgcrypt-20 \
                   -lgpg-error-0 \
                   -lgpgme-11 \
                   -lntru \
                   -lpthread \
                   -lssl-3-x64 \
                   -lws2_32

equals(mceliece_supported, "true") {
LIBS            += -L..\\libNTL\\windows.d\\libraries.d -lntl
}

PRE_TARGETDEPS  = libntru.dll
PROJECTNAME	= Spot-On
RC_FILE		= Icons\\Resources\\spot-on.rc
TARGET		= Spot-On
TEMPLATE        = app

data.files = Data\\*.txt
data.path = release\\.
documentation.files = Documentation\\*.pdf
documentation.path = release\\.
gpgmeexecutables.files = ..\\libGPGME\\Executables.win64\\*.exe
gpgmeexecutables.path = release\\.
libassuan.files = ..\\libAssuan\\Libraries.win64\\*.dll
libassuan.path = release\\.
libgcrypt.files = ..\\libGCrypt\\Libraries.win64\\*.dll
libgcrypt.path = release\\.
libgpgme.files = ..\\libGPGME\\Libraries.win64\\*
libgpgme.path = release\\.

equals(mceliece_supported, "true") {
libntl.files = ..\\libNTL\\windows.d\\libraries.d\\*.dll
libntl.path = release\\.
}

libntrudll.files = ..\\libNTRU\\*.dll
libntrudll.path = release\\.
libopenssl.files = ..\\libOpenSSL\\Libraries.win64\\*.dll
libopenssl.path = release\\.
opensslexecutables.files = ..\\libOpenSSL\\Executables.win64\\*.exe
opensslexecutables.path = release\\.
plugins.files = $$[QT_INSTALL_PLUGINS]\\*
plugins.path = release\\plugins\\.
qt.files = Qt\\qt.conf
qt.path = release\\.
qtlibraries.files = $$[QT_INSTALL_BINS]\\Qt*Core.dll \
                    $$[QT_INSTALL_BINS]\\Qt*Gui.dll \
                    $$[QT_INSTALL_BINS]\\Qt*Multimedia.dll \
                    $$[QT_INSTALL_BINS]\\Qt*Network.dll \
                    $$[QT_INSTALL_BINS]\\Qt*PrintSupport.dll \
                    $$[QT_INSTALL_BINS]\\Qt*Sql.dll \
                    $$[QT_INSTALL_BINS]\\Qt*WebSockets.dll \
                    $$[QT_INSTALL_BINS]\\Qt*Widgets.dll \
                    $$[QT_INSTALL_BINS]\\libgcc_s_dw2-*.dll \
                    $$[QT_INSTALL_BINS]\\libgcc_s_seh-*.dll \
                    $$[QT_INSTALL_BINS]\\libstdc++-*.dll \
                    $$[QT_INSTALL_BINS]\\libwinpthread-*.dll
qtlibraries.path = release\\.
sounds.files = Sounds
sounds.path = release\\.
spotonbat.files = Shell\\*.bat
spotonbat.path = release\\.
translations.files = Translations\\*.qm
translations.path = release\\Translations\\.

INSTALLS = data \
           documentation \
           gpgmeexecutables \
           libassuan \
           libgcrypt \
           libgpgme \
           libntrudll \
           libopenssl \
           opensslexecutables \
           plugins \
           qt \
           qtlibraries \
           sounds \
           spotonbat \
           translations

equals(mceliece_supported, "true") {
INSTALLS += libntl
}
