cache()
include(spot-on-gui-source.pro)
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libntru.target = libntru.dylib

CONFIG		+= app_bundle qt release warn_on
LANGUAGE	= C++
QT		+= bluetooth \
                   concurrent \
                   multimedia \
                   network \
                   printsupport \
                   sql \
                   websockets \
                   widgets

DEFINES += LIBSPOTON_OS_MAC \
           SPOTON_BLUETOOTH_ENABLED \
	   SPOTON_DATELESS_COMPILATION \
           SPOTON_DTLS_DISABLED \
           SPOTON_LINKED_WITH_LIBGEOIP \
           SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
           SPOTON_POPTASTIC_SUPPORTED \
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
                          -Wdouble-promotion \
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
                          -fwrapv \
                          -mtune=generic \
                          -pedantic \
                          -std=c++11
QMAKE_EXTRA_TARGETS    = libntru purge
QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.12

INCLUDEPATH	  += . \
                     ../../. \
                     /usr/local/Cellar/openssl@1.1/1.1.1i/include \
                     /usr/local/include \
                     /usr/local/opt \
                     /usr/local/opt/curl/include \
                     GUI
ICON		  = Icons/Logo/spot-on-logo.icns
LIBS		  += -L../../libNTRU \
                     -L/usr/local/Cellar/openssl@1.1/1.1.1i/lib \
                     -L/usr/local/lib \
                     -L/usr/local/opt/curl/lib \
                     -framework AppKit \
                     -framework Cocoa \
                     -lGeoIP \
                     -lcrypto \
                     -lcurl \
                     -lgcrypt \
                     -lgmp \
                     -lgpg-error \
                     -lntl \
                     -lntru \
                     -lpq \
                     -lpthread \
                     -lsqlite3 \
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

copyspoton.extra            = cp -r ./Spot-On.app /Applications/Spot-On.d/.
copyspoton.path             = /Applications/Spot-On.d
copyssl.extra               = cp /usr/local/Cellar/openssl@1.1/1.1.1i/lib/*.dylib /Applications/Spot-On.d/Spot-On.app/Contents/Frameworks/.
copyssl.path                = /Applications/Spot-On.d
install1.files              = ./Data/spot-on-neighbors.txt
install1.path               = /Applications/Spot-On.d
install_name_tool.extra     = install_name_tool -change /usr/local/Cellar/openssl@1.1/1.1.1i/lib/libcrypto.1.1.dylib @executable_path/../Frameworks/libcrypto.1.1.dylib /Applications/Spot-On.d/Spot-On.app/Contents/Frameworks/libssl.1.1.dylib
install_name_tool.path      = .
libgeoip_data_install.files = ../../GeoIP/Data/GeoIP.dat
libgeoip_data_install.path  = /Applications/Spot-On.d/GeoIP
libntru_install.extra       = cp ../../libNTRU/libntru.dylib /Applications/Spot-On.d/Spot-On.app/Contents/Frameworks/libntru.dylib && install_name_tool -change libntru.dylib @executable_path/../Frameworks/libntru.dylib /Applications/Spot-On.d/Spot-On.app/Contents/MacOS/Spot-On
libntru_install.path        = .
lrelease.extra              = $$[QT_INSTALL_BINS]/lrelease spot-on-gui.osx.pro
lrelease.path               = .
lupdate.extra               = $$[QT_INSTALL_BINS]/lupdate spot-on-gui.osx.pro
lupdate.path                = .
macdeployqt.extra           = $$[QT_INSTALL_BINS]/macdeployqt /Applications/Spot-On.d/Spot-On.app -executable=/Applications/Spot-On.d/Spot-On.app/Contents/MacOS/Spot-On
macdeployqt.path            = Spot-On.app
preinstall.extra            = rm -rf /Applications/Spot-On.d/Spot-On.app/*
preinstall.path             = /Applications/Spot-On.d
sounds.files                = Sounds/*.wav
sounds.path                 = /Applications/Spot-On.d/Spot-On.app/Contents/MacOS/Sounds
translations.files	    = Translations/*.qm
translations.path	    = /Applications/Spot-On.d/Translations
zzz.extra		    = chown -Rh root:wheel /Applications/Spot-On.d
zzz.path		    = /Applications/Spot-On.d

# Order is important.

INSTALLS	= preinstall \
                  copyspoton \
                  install1 \
                  libgeoip_data_install \
                  lupdate \
                  lrelease \
                  sounds \
                  translations \
                  macdeployqt \
                  copyssl \
                  install_name_tool \
                  libntru_install \
                  zzz
