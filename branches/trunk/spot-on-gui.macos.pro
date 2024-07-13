cache()
dmg.commands = hdiutil create Spot-On.d.dmg -srcfolder Spot-On.d
include(spot-on-gui-source.pro)
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libntru.target = libntru.dylib

CONFIG		+= app_bundle qt release warn_on
LANGUAGE	= C++
QT		+= bluetooth \
                   concurrent \
                   gui \
                   multimedia \
                   network \
                   printsupport \
                   sql \
                   webenginewidgets \
                   websockets \
                   widgets

DEFINES += SPOTON_BLUETOOTH_ENABLED \
	   SPOTON_DATELESS_COMPILATION \
           SPOTON_DTLS_DISABLED \
           SPOTON_LINKED_WITH_LIBGEOIP \
           SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
           SPOTON_POSTGRESQL_DISABLED \
           SPOTON_WEBENGINE_ENABLED \
	   SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ../../libNTRU/*.dylib \
                          ../../libNTRU/src/*.o \
                          ../../libNTRU/src/*.s \
                          Spot-On
QMAKE_CXX              = clang++
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-qual \
                          -Wextra \
                          -Wno-cast-align \
                          -Wno-deprecated \
                          -Wno-unused-parameter \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstack-protector \
                          -Wstrict-overflow=5 \
                          -fPIE \
                          -fstack-protector-all \
                          -funroll-loops \
                          -fwrapv \
                          -pedantic \
                          -std=c++20
QMAKE_EXTRA_TARGETS    = dmg libntru purge
QMAKE_MACOSX_DEPLOYMENT_TARGET = 11.0

# Removed.
# /usr/local/opt/postgresql/include/postgresql@14

INCLUDEPATH	  += . \
                     ../../. \
		     /opt/homebrew/include \
		     /opt/homebrew/ntl \
                     /opt/homebrew/openssl \
                     GUI
ICON		  = Icons/Logo/spot-on-logo.icns

# Removed.
# -lpq

LIBS		  += -L../../libNTRU \
                     -L/usr/local/lib \
                     -L/usr/local/opt/openssl/lib \
                     -framework AppKit \
                     -framework Cocoa \
                     -lGeoIP \
                     -lcrypto \
                     -lgcrypt \
                     -lgmp \
                     -lgpg-error \
                     -lntl \
                     -lntru \
                     -lpthread \
                     -lssl
MOC_DIR           = temp/moc
OBJECTIVE_HEADERS += Common/CocoaInitializer.h
OBJECTIVE_SOURCES += Common/CocoaInitializer.mm
OBJECTS_DIR       = temp/obj
PRE_TARGETDEPS    = libntru.dylib
PROJECTNAME	  = Spot-On
RCC_DIR           = temp/rcc
TARGET		  = Spot-On
TEMPLATE          = app
UI_DIR            = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

copyspoton.extra            = cp -r ./Spot-On.app ./Spot-On.d/.
copyspoton.path             = ./Spot-On.d
copyssl.extra               = cp /usr/local/opt/openssl@1.1/lib/*.dylib ./Spot-On.d/Spot-On.app/Contents/Frameworks/.
copyssl.path                = ./Spot-On.d
install1.files              = ./Data/spot-on-neighbors.txt
install1.path               = ./Spot-On.d
install_name_tool.extra     = install_name_tool -change /usr/local/Cellar/openssl@1.1/1.1.1w/lib/libcrypto.1.1.dylib @executable_path/../Frameworks/libcrypto.1.1.dylib ./Spot-On.d/Spot-On.app/Contents/Frameworks/libssl.1.1.dylib
install_name_tool.path      = .
libgeoip_data_install.files = ../../GeoIP/Data/GeoIP.dat
libgeoip_data_install.path  = ./Spot-On.d/GeoIP
libntru_install.extra       = cp ../../libNTRU/libntru.dylib ./Spot-On.d/Spot-On.app/Contents/Frameworks/libntru.dylib && install_name_tool -change libntru.dylib @executable_path/../Frameworks/libntru.dylib ./Spot-On.d/Spot-On.app/Contents/MacOS/Spot-On
libntru_install.path        = .
lrelease.extra              = $$[QT_INSTALL_BINS]/lrelease spot-on-gui.macos.pro
lrelease.path               = .
lupdate.extra               = $$[QT_INSTALL_BINS]/lupdate spot-on-gui.macos.pro
lupdate.path                = .
macdeployqt.extra           = $$[QT_INSTALL_BINS]/macdeployqt ./Spot-On.d/Spot-On.app -executable=./Spot-On.d/Spot-On.app/Contents/MacOS/Spot-On
macdeployqt.path            = Spot-On.app
other_libraries1.extra      = cp /usr/local/Cellar/brotli/1.1.0/lib/libbrotlicommon.1.dylib ./Spot-On.d/Spot-On.app/Contents/Frameworks/.
other_libraries1.path       = .
preinstall.extra            = rm -rf ./Spot-On.d/Spot-On.app/*
preinstall.path             = ./Spot-On.d
sounds.files                = Sounds/*.wav
sounds.path                 = ./Spot-On.d/Spot-On.app/Contents/MacOS/Sounds
translations.files	    = Translations/*.qm
translations.path	    = ./Spot-On.d/Translations

# Order is important.

INSTALLS	= preinstall \
                  copyspoton \
                  install1 \
                  libgeoip_data_install \
                  sounds \
                  translations \
                  macdeployqt \
                  copyssl \
                  install_name_tool \
                  libntru_install \
                  other_libraries1
