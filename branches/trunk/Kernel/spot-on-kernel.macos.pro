cache()
include(spot-on-kernel-source.pro)
libntru.commands = $(MAKE) -C ../../../libNTRU
libntru.depends =
libntru.target = libntru.dylib
purge.commands = rm -f *~

CONFIG		+= qt release warn_on app_bundle
LANGUAGE	= C++
QT		+= bluetooth concurrent network sql websockets
QT              -= gui

DEFINES += SPOTON_BLUETOOTH_ENABLED \
	   SPOTON_DATELESS_COMPILATION \
           SPOTON_DTLS_DISABLED \
           SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
           SPOTON_POSTGRESQL_DISABLED \
	   SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ../../../libNTRU/*.dylib \
                          ../../../libNTRU/src/*.o \
                          ../../../libNTRU/src/*.s \
                          ../Spot-On-Kernel
QMAKE_CXX              = clang++
QMAKE_CXXFLAGS_RELEASE -= -O2
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
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntru purge
QMAKE_MACOSX_DEPLOYMENT_TARGET = 12.0
ICON		  =
INCLUDEPATH	  += . \
                     ../. ../../../.

exists(/opt/homebrew) {
INCLUDEPATH       += /opt/homebrew/include
LIBS              += -L/opt/homebrew/lib
} else {
INCLUDEPATH       += /usr/local/include
LIBS              += -L/usr/local/lib
}

LIBS		  += -L../../../libNTRU \
                     -framework Cocoa \
                     -lcrypto \
                     -lgcrypt \
                     -lgmp \
                     -lgpg-error \
                     -lntl \
                     -lntru \
		     -lpthread \
                     -lssl

MOC_DIR           = temp/moc
OBJECTIVE_HEADERS += ../Common/CocoaInitializer.h
OBJECTIVE_SOURCES += ../Common/CocoaInitializer.mm
OBJECTS_DIR       = temp/obj
PRE_TARGETDEPS    = libntru.dylib
PROJECTNAME	  = Spot-On-Kernel
RCC_DIR           = temp/rcc
TARGET		  = ../Spot-On-Kernel
TEMPLATE          = app
UI_DIR            = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

copyspoton.extra  = cp -r ../Spot-On-Kernel.app ../Spot-On.d/.
copyspoton.path   = ../Spot-On.d
macdeployqt.extra = $$[QT_INSTALL_BINS]/macdeployqt \
                    ../Spot-On.d/Spot-On-Kernel.app \
                    -executable=../Spot-On.d/Spot-On-Kernel.app/\
                    Contents/MacOS/Spot-On-Kernel
macdeployqt.path  = Spot-On-Kernel.app
preinstall.extra  = rm -rf ../Spot-On.d/Spot-On-Kernel.app/*
preinstall.path   = ../Spot-On.d

INSTALLS = preinstall \
           copyspoton \
           macdeployqt
