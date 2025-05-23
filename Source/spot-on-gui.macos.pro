cache()
include(spot-on-gui-source.pro)

libntru.commands = $(MAKE) -C ../libNTRU
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
           SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
           SPOTON_POSTGRESQL_DISABLED \
           SPOTON_WEBENGINE_ENABLED \
	   SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ../libNTRU/*.dylib \
                          ../libNTRU/src/*.o \
                          ../libNTRU/src/*.s \
                          Spot-On
QMAKE_DISTCLEAN        += -r Temporary .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-qual \
                          -Wextra \
                          -Wno-c++20-attribute-extensions \
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
                          -std=c++17
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_EXTRA_TARGETS    = libntru purge
QMAKE_MACOSX_DEPLOYMENT_TARGET = 12.0

exists(/opt/homebrew/include) {
INCLUDEPATH += /opt/homebrew/include
}

exists(/opt/homebrew/lib) {
LIBS += -L/opt/homebrew/lib
}

INCLUDEPATH	  += . ../. GUI
ICON		  = Icons/Logo/spot-on-logo.icns
LIBS		  += -L../libNTRU \
                     -framework AppKit \
                     -framework Cocoa \
                     -lcrypto \
                     -lgcrypt \
                     -lgmp \
                     -lgpg-error \
                     -lntl \
                     -lntru \
                     -lpthread \
                     -lssl
MOC_DIR           = Temporary/moc
OBJECTIVE_HEADERS += Common/CocoaInitializer.h
OBJECTIVE_SOURCES += Common/CocoaInitializer.mm
OBJECTS_DIR       = Temporary/obj
PRE_TARGETDEPS    = libntru.dylib
PROJECTNAME	  = Spot-On
RCC_DIR           = Temporary/rcc
TARGET		  = Spot-On
TEMPLATE          = app
UI_DIR            = Temporary/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

copyspoton.extra   = cp -r ./Spot-On.app ./Spot-On.d/.
copyspoton.path    = ./Spot-On.d
libntru.extra      = cp ../libNTRU/libntru.dylib \
 ./Spot-On.d/Spot-On.app/Contents/Frameworks/libntru.dylib && \
 install_name_tool -change libntru.dylib \
 @executable_path/../Frameworks/libntru.dylib \
 ./Spot-On.d/Spot-On.app/Contents/MacOS/Spot-On
libntru.path       = .
macdeployqt.extra  = $$[QT_INSTALL_BINS]/macdeployqt ./Spot-On.d/Spot-On.app \
                     -executable=./Spot-On.d/Spot-On.app/Contents/MacOS/Spot-On
macdeployqt.path   = Spot-On.app
preinstall.extra   = rm -rf ./Spot-On.d/Spot-On.app/*
preinstall.path    = ./Spot-On.d
sounds.files       = Sounds/*.wav
sounds.path        = ./Spot-On.d/Spot-On.app/Contents/MacOS/Sounds
translations.files = Translations/*.qm
translations.path  = ./Spot-On.d/Translations

INSTALLS = preinstall \
           copyspoton \
           sounds \
           translations \
           macdeployqt \
           libntru
