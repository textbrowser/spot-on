cache()
include(spot-on-gui-source.pro)
libntl.target = libntl.dylib
libntl.commands = cd ../../libNTL/unix.d/src && ./configure \
CXX=clang++ CXXFLAGS=\'-std=c++11 -stdlib=libc++\' \
DEF_PREFIX= LIBTOOL=/usr/local/bin/glibtool && $(MAKE)
libntl.depends =
libntru.target = libntru.dylib
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libspoton.target = libspoton.dylib
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= bluetooth concurrent multimedia network printsupport \
		   sql widgets
CONFIG		+= app_bundle qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES += SPOTON_BLUETOOTH_ENABLED \
           SPOTON_LINKED_WITH_LIBGEOIP \
           SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
	   SPOTON_MCELIECE_ENABLED \
           SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN     += Spot-On \
                   ../../libNTL/unix.d/src/*.o ../../libNTL/unix.d/src/*.lo \
                   ../../libNTRU/*.dylib ../../libNTRU/src/*.o \
                   ../../libNTRU/src/*.s \
                   ../../libSpotOn/*.dylib ../../libSpotOn/*.o \
		   ../../libSpotOn/test
QMAKE_CXX = clang++
QMAKE_DISTCLEAN += -r temp .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
			  -mtune=generic \
			  -Wall -Wcast-align -Wcast-qual \
                          -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstack-protector -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libntl libntru libspoton purge
QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.7
INCLUDEPATH	+= . ../../. ../../libNTL/unix.d/include GUI \
                   /usr/local/include /usr/local/opt
ICON		= Icons/Logo/spot-on-logo.icns
LIBS		+= -L../../libNTL/unix.d/src/.libs -lntl \
                   -L../../libNTRU -lntru \
                   -L../../libSpotOn -lspoton \
                   -L/usr/local/lib -L/usr/local/opt/curl/lib \
                   -L/usr/local/opt/openssl/lib -lGeoIP \
                   -lcrypto -lcurl -lgcrypt \
		   -lgpg-error -lntl -lpq -lssl \
                   -framework AppKit -framework Cocoa
PRE_TARGETDEPS = libntl.dylib libntru.dylib libspoton.dylib
OBJECTS_DIR = temp/obj
UI_DIR = temp/ui
MOC_DIR = temp/moc
RCC_DIR = temp/rcc

OBJECTIVE_HEADERS += Common/CocoaInitializer.h
OBJECTIVE_SOURCES += Common/CocoaInitializer.mm

TARGET		= Spot-On
PROJECTNAME	= Spot-On

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

install1.path           = /Applications/Spot-On_Qt5.d
install1.files          = ./Data/spot-on-neighbors.txt
libgeoip_data_install.path = /Applications/Spot-On_Qt5.d/GeoIP
libgeoip_data_install.files = ../../GeoIP/Data/GeoIP.dat
libntru_install.path  = .
libntru_install.extra = cp ../../libNTRU/libntru.dylib ./Spot-On.app/Contents/Frameworks/libntru.dylib && install_name_tool -change ../../libNTRU/libntru.dylib @executable_path/../Frameworks/libntru.dylib ./Spot-On.app/Contents/MacOS/Spot-On
libspoton_install.path  = .
libspoton_install.extra = cp ../../libSpotOn/libspoton.dylib ./Spot-On.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change /usr/local/opt/libgcrypt/lib/libgcrypt.20.dylib @loader_path/libgcrypt.20.dylib ./Spot-On.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change ../../libSpotOn/libspoton.dylib @executable_path/../Frameworks/libspoton.dylib ./Spot-On.app/Contents/MacOS/Spot-On
lrelease.extra          = $$[QT_INSTALL_BINS]/lrelease spot-on-gui.osx.qt5.pro
lrelease.path           = .
lupdate.extra           = $$[QT_INSTALL_BINS]/lupdate spot-on-gui.osx.qt5.pro
lupdate.path            = .
macdeployqt.path        = ./Spot-On.app
macdeployqt.extra       = $$[QT_INSTALL_BINS]/macdeployqt ./Spot-On.app -verbose=0
preinstall.path         = /Applications/Spot-On_Qt5.d
preinstall.extra        = rm -rf /Applications/Spot-On_Qt5.d/Spot-On.app/*
postinstall.path	= /Applications/Spot-On_Qt5.d
postinstall.extra	= find /Applications/Spot-On_Qt5.d -name .svn -exec rm -rf {} \\; 2>/dev/null; echo
sounds.path             = /Applications/Spot-On_Qt5.d/Spot-On.app/Contents/MacOS/Sounds
sounds.files            = Sounds/*.wav
spoton.path		= /Applications/Spot-On_Qt5.d/Spot-On.app
spoton.files		= Spot-On.app/*
translations.path 	= /Applications/Spot-On_Qt5.d/Translations
translations.files	= Translations/*.qm

INSTALLS	= macdeployqt \
                  preinstall \
                  install1 \
                  libgeoip_data_install \
                  libntru_install \
                  libspoton_install \
                  lupdate \
                  lrelease \
                  sounds \
                  spoton \
                  translations \
                  postinstall
