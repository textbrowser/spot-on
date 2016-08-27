include(spot-on-gui-source.pro)
libntru.target = libntru.dylib
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libspoton.target = libspoton.dylib
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= gui network sql
CONFIG		+= app_bundle qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES += SPOTON_LINKED_WITH_LIBGEOIP \
           SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN     += Spot-On ../../libNTRU/*.dylib ../../libNTRU/src/*.o \
                   ../../libNTRU/src/*.s \
                   ../../libSpotOn/*.dylib ../../libSpotOn/*.o \
		   ../../libSpotOn/test
QMAKE_DISTCLEAN += -r temp
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
			  -mtune=generic -pie \
			  -Wall -Wcast-align -Wcast-qual \
                          -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstack-protector -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libntru libspoton purge
QMAKE_LFLAGS_RELEASE =
QMAKE_LFLAGS_RPATH =
INCLUDEPATH	+= . ../../. GUI \
                   /usr/local/include /usr/local/opt
ICON		= Icons/Logo/spot-on-logo.icns
LIBS		+= -L../../libNTRU -lntru \
                   -L../../libSpotOn -lspoton \
                   -L/usr/local/lib -L/usr/local/opt/curl/lib \
                   -L/usr/local/opt/openssl/lib -lGeoIP \
                   -lcrypto -lcurl -lgcrypt \
		   -lgpg-error -lpq -lssl
PRE_TARGETDEPS = libntru.dylib libspoton.dylib
OBJECTS_DIR = temp/obj
UI_DIR = temp/ui
MOC_DIR = temp/moc
RCC_DIR = temp/rcc

TARGET		= Spot-On
PROJECTNAME	= Spot-On

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

spoton.path		= /Applications/Spot-On.d/Spot-On.app
spoton.files		= Spot-On.app/*
install1.path           = /Applications/Spot-On.d
install1.files          = ./Data/spot-on-neighbors.txt
libgeoip_data_install.path = /Applications/Spot-On.d/GeoIP
libgeoip_data_install.files = ../../GeoIP/Data/GeoIP.dat
libntru_install.path  = .
libntru_install.extra = cp ../../libNTRU/libntru.dylib ./Spot-On.app/Contents/Frameworks/libntru.dylib && install_name_tool -change ../../libNTRU/libntru.dylib @executable_path/../Frameworks/libntru.dylib ./Spot-On.app/Contents/MacOS/Spot-On
libspoton_install.path  = .
libspoton_install.extra = cp ../../libSpotOn/libspoton.dylib ./Spot-On.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change /usr/local/opt/libgcrypt/lib/libgcrypt.20.dylib @loader_path/libgcrypt.20.dylib ./Spot-On.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change ../../libSpotOn/libspoton.dylib @executable_path/../Frameworks/libspoton.dylib ./Spot-On.app/Contents/MacOS/Spot-On
lrelease.extra          = $$[QT_INSTALL_BINS]/lrelease spot-on-gui.osx.pro
lrelease.path           = .
lupdate.extra           = $$[QT_INSTALL_BINS]/lupdate spot-on-gui.osx.pro
lupdate.path            = .
macdeployqt.path        = ./Spot-On.app
macdeployqt.extra       = $$[QT_INSTALL_BINS]/macdeployqt ./Spot-On.app -verbose=0
preinstall.path         = /Applications/Spot-On.d
preinstall.extra        = rm -rf /Applications/Spot-On.d/Spot-On.app/*
postinstall.path	= /Applications/Spot-On.d
postinstall.extra	= find /Applications/Spot-On.d -name .svn -exec rm -rf {} \\; 2>/dev/null; echo
translations.path 	= /Applications/Spot-On.d/Translations
translations.files	= Translations/*.qm

INSTALLS	= macdeployqt \
                  preinstall \
                  install1 \
                  libgeoip_data_install \
                  libntru_install \
                  libspoton_install \
                  lupdate \
                  lrelease \
                  translations \
                  spoton \
                  postinstall
