cache()
include(spot-on-gui-source.windows.pro)
libntru.commands = $(MAKE) -C ..\\..\\libNTRU
libntru.depends =
libntru.target = libntru.dll
libspoton.commands = $(MAKE) -C ..\\..\\libSpotOn library
libspoton.depends =
libspoton.target = libspoton.dll

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

DEFINES         += SPOTON_GPGME_ENABLED \
                   SPOTON_LINKED_WITH_LIBGEOIP \
                   SPOTON_LINKED_WITH_LIBNTRU \
		   SPOTON_LINKED_WITH_LIBPTHREAD \
                   SPOTON_MCELIECE_ENABLED \
                   SPOTON_POPTASTIC_SUPPORTED \
		   SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN            += ..\\..\\libNTRU.dll \
                          ..\\..\\libNTRU\\src\\*.o \
                          ..\\..\\libNTRU\\src\\*.s \
                          ..\\..\\libSpotOn\\*.o \
                          ..\\..\\libSpotOn\\libspoton.dll \
                          ..\\..\\libSpotOn\\test.exe \
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
                          -mtune=generic \
                          -pedantic \
                          -pie \
                          -std=c++11
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_DISTCLEAN        += -r debug \
                          .qmake.cache \
                          .qmake.stash \
                          object_script.Spot-On.Debug \
                          object_script.Spot-On.Release
QMAKE_EXTRA_TARGETS    = libntru libspoton purge

INCLUDEPATH	+= . \
                   ..\\..\\. \
                   ..\\..\\PostgreSQL\\Include.win32 \
                   ..\\..\\libGPGME\\Win32.d \
                   ..\\..\\libGeoIP\\Include.win32 \
                   ..\\..\\libNTL\\windows.d\\include \
                   ..\\..\\libOpenSSL\\Include.win32 \
                   ..\\..\\libSpotOn\\Include.win32 \
                   ..\\..\\libcURL\\Win32.d\\include \
                   GUI
LIBS		+= -L..\\..\\PostgreSQL\\Libraries.win32 \
                   -L..\\..\\libGPGME\\Win32.d \
		   -L..\\..\\libGeoIP\\Libraries.win32 \
		   -L..\\..\\libNTL\\windows.d\\libraries.d \
		   -L..\\..\\libNTRU \
		   -L..\\..\\libOpenSSL\\Libraries.win32 \
                   -L..\\..\\libSpotOn \
                   -L..\\..\\libSpotOn\\Libraries.win32 \
                   -L..\\..\\libcURL\\Win32.d\\bin \
                   -lGeoIP-1 \
                   -lcrypto-1_1 \
                   -lcurl \
                   -lgcrypt-20 \
                   -lgpg-error-0 \
                   -lgpgme-11 \
                   -lntl \
                   -lntru \
                   -lpq \
                   -lspoton \
                   -lssl-1_1 \
                   -lws2_32
PRE_TARGETDEPS  = libntru.dll libspoton.dll
PROJECTNAME	= Spot-On
RC_FILE		= Icons\\Resources\\spot-on.rc
TARGET		= Spot-On
TEMPLATE        = app

data.files = Data\\*.txt
data.path = release\\.
documentation.files = Documentation
documentation.path = release\\.
libcurl1.files = ..\\..\\libcURL\\*.crt
libcurl1.path = release\\.
libcurl2.files = ..\\..\\libcURL\\Win32.d\\bin\\*.dll
libcurl2.path = release\\.
libgeoip1.files = ..\\..\\GeoIP\\Data\\*.dat
libgeoip1.path = release\\.
libgeoip2.files = ..\\..\\libGeoIP\\Libraries.win32\\*.dll
libgeoip2.path = release\\.
libgpgme1.files = ..\\..\\libGPGME\\*.dll
libgpgme1.path = release\\.
libgpgme2.files = ..\\..\\libGPGME\\.*exe
libgpgme2.path = release\\.
libntl.files = ..\\..\\libNTL\\windows.d\\libraries.d\\*.dll
libntl.path = release\\.
libntru.files = ..\\..\\libNTRU\\*.dll
libntru.path = release\\.
libopenssl.files = ..\\..\\libOpenSSL\\Libraries.win32\\*.dll
libopenssl.path = release\\.
libspoton.files = ..\\..\\libSpotOn\\*.dll
libspoton.path = release\\.
postgresql1.files = ..\\..\\PostgreSQL\\Libraries.win32\\*.dll
postgresql1.path = release\\.
postgresql2.files = ..\\..\\PostgreSQL\\Libraries.win32\\*.manifest
postgresql2.path= release\\.
qt.files = Qt\\qt.conf
qt.path = release\\.
qtlibraries.files = $$[QT_INSTALL_LIBS]\\Qt5Core.dll \
                    $$[QT_INSTALL_LIBS]\\Qt5Gui.dll \
                    $$[QT_INSTALL_LIBS]\\Qt5Multimedia.dll \
                    $$[QT_INSTALL_LIBS]\\Qt5Network.dll \
                    $$[QT_INSTALL_LIBS]\\Qt5PrintSupport.dll \
                    $$[QT_INSTALL_LIBS]\\Qt5Sql.dll \
                    $$[QT_INSTALL_LIBS]\\Qt5WebSockets.dll \
                    $$[QT_INSTALL_LIBS]\\Qt5Widgets.dll \
                    $$[QT_INSTALL_LIBS]\\libgcc_s_dw2-1.dll \
                    $$[QT_INSTALL_LIBS]\\libstdc++-6.dll \
                    $$[QT_INSTALL_LIBS]\\libwinpthread-1.dll
qtlibraries.path = release\\.
sounds.files = Sounds
sounds.path = release\\.
sql1.files = SQL\\README*
sql1.path = release\\SQL\\.
sql2.files = SQL\\*.sql
sql2.path = release\\SQL\\.
translations.files = Translations\\*.qm
translations.path = release\\Translations\\.

INSTALLS = data \
           documentation \
           libcurl1 \
           libcurl2 \
           libgeoip1 \
           libgeoip2 \
           libgpgme1 \
           libgpgme2 \
           libntl \
           libntru \
           libopenssl \
           libspoton \
           postgresql1 \
           postgresql2 \
           qt \
           qtlibraries \
           sounds \
           sql1 \
           sql2 \
           translations
