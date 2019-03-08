cache()
include(spot-on-gui-source.pro)
libntru.target = libntru.dylib
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libspoton.target = libspoton.dylib
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =

CONFIG		+= app_bundle qt release warn_on
LANGUAGE	= C++
QT		+= bluetooth concurrent multimedia network printsupport \
		   sql widgets

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

QMAKE_CLEAN            += Spot-On ../../libNTRU/*.dylib ../../libNTRU/src/*.o \
                          ../../libNTRU/src/*.s \
                          ../../libSpotOn/*.dylib ../../libSpotOn/*.o \
                          ../../libSpotOn/test
QMAKE_CXX              = clang++
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
			  -mtune=generic -O3 \
			  -Wall -Wcast-align -Wcast-qual \
                          -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstack-protector -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS    = libntru libspoton purge
QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.12

INCLUDEPATH	  += . ../../. GUI \
                     /usr/local/include /usr/local/opt \
                     /usr/local/opt/curl/include \
                     /usr/local/opt/openssl/include
ICON		  = Icons/Logo/spot-on-logo.icns
LIBS		  += -L../../libNTRU -lntru \
                     -L../../libSpotOn -lspoton \
                     -L/usr/local/lib \
                     -L/usr/local/opt/curl/lib \
                     -L/usr/local/opt/openssl/lib -lGeoIP \
                     -lcrypto -lcurl -lgcrypt -lgmp \
                     -lgpg-error -lntl -lpq -lssl \
                     -framework AppKit -framework Cocoa
MOC_DIR           = temp/moc
OBJECTIVE_HEADERS += Common/CocoaInitializer.h
OBJECTIVE_SOURCES += Common/CocoaInitializer.mm
OBJECTS_DIR       = temp/obj
PRE_TARGETDEPS    = libntru.dylib libspoton.dylib
PROJECTNAME	  = Spot-On
RCC_DIR           = temp/rcc
TARGET		  = Spot-On
TEMPLATE          = app
UI_DIR            = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

copyspoton.path             = /Applications/Spot-On_Qt5.d
copyspoton.extra            = cp -r ./Spot-On.app /Applications/Spot-On_Qt5.d/.
install1.files              = ./Data/spot-on-neighbors.txt
install1.path               = /Applications/Spot-On_Qt5.d
install_name_tool.path      = .
install_name_tool.extra     = install_name_tool -change /usr/local/Cellar/openssl/1.0.2m/lib/libcrypto.1.0.0.dylib @executable_path/../Frameworks/libcrypto.1.0.0.dylib /Applications/Spot-On_Qt5.d/Spot-On.app/Contents/Frameworks/libssl.1.0.0.dylib
libgeoip_data_install.path  = /Applications/Spot-On_Qt5.d/GeoIP
libgeoip_data_install.files = ../../GeoIP/Data/GeoIP.dat
libntru_install.path        = .
libntru_install.extra       = cp ../../libNTRU/libntru.dylib /Applications/Spot-On_Qt5.d/Spot-On.app/Contents/Frameworks/libntru.dylib && install_name_tool -change libntru.dylib @executable_path/../Frameworks/libntru.dylib /Applications/Spot-On_Qt5.d/Spot-On.app/Contents/MacOS/Spot-On
libspoton_install.path      = .
libspoton_install.extra     = cp ../../libSpotOn/libspoton.dylib /Applications/Spot-On_Qt5.d/Spot-On.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change /usr/local/opt/libgcrypt/lib/libgcrypt.20.dylib @loader_path/libgcrypt.20.dylib /Applications/Spot-On_Qt5.d/Spot-On.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change libspoton.dylib @executable_path/../Frameworks/libspoton.dylib /Applications/Spot-On_Qt5.d/Spot-On.app/Contents/MacOS/Spot-On
lrelease.extra              = $$[QT_INSTALL_BINS]/lrelease spot-on-gui.osx.qt5.pro
lrelease.path               = .
lupdate.extra               = $$[QT_INSTALL_BINS]/lupdate spot-on-gui.osx.qt5.pro
lupdate.path                = .
macdeployqt.path            = Spot-On.app
macdeployqt.extra           = $$[QT_INSTALL_BINS]/macdeployqt /Applications/Spot-On_Qt5.d/Spot-On.app -executable=/Applications/Spot-On_Qt5.d/Spot-On.app/Contents/MacOS/Spot-On
preinstall.path             = /Applications/Spot-On_Qt5.d
preinstall.extra            = rm -rf /Applications/Spot-On_Qt5.d/Spot-On.app/*
sounds.path                 = /Applications/Spot-On_Qt5.d/Spot-On.app/Contents/MacOS/Sounds
sounds.files                = Sounds/*.wav
translations.path	    = /Applications/Spot-On_Qt5.d/Translations
translations.files	    = Translations/*.qm

INSTALLS	= preinstall \
                  copyspoton \
                  install1 \
                  libgeoip_data_install \
                  lupdate \
                  lrelease \
                  sounds \
                  translations \
                  macdeployqt \
                  install_name_tool \
                  libntru_install \
                  libspoton_install
