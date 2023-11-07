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
           SPOTON_LINKED_WITH_LIBGEOIP \
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
                          -pedantic \
                          -std=c++17
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntru purge
QMAKE_MACOSX_DEPLOYMENT_TARGET = 11.0

ICON		  =

# Removed.
# /usr/local/opt/postgresql/include/postgresql@14

INCLUDEPATH	  += . \
                     ../. ../../../. \
                     /usr/local/opt \
                     /usr/local/opt/geoip/include \
                     /usr/local/opt/libgcrypt/include \
                     /usr/local/opt/libgpg-error/include \
                     /usr/local/opt/ntl/include \
                     /usr/local/opt/openssl/include

# Removed.
# -lpq

LIBS		  += -L../../../libNTRU \
                     -L/usr/local/lib \
                     -L/usr/local/opt/openssl/lib \
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

copyspoton.extra            = cp -r ../Spot-On-Kernel.app ../Spot-On.d/.
copyspoton.path             = ../Spot-On.d
copyssl.extra               = cp /usr/local/opt/openssl@1.1/lib/*.dylib ../Spot-On.d/Spot-On-Kernel.app/Contents/Frameworks/.
copyssl.path                = ../Spot-On.d
install_name_tool.extra     = install_name_tool -change /usr/local/Cellar/openssl@1.1/1.1.1v/lib/libcrypto.1.1.dylib @executable_path/../Frameworks/libcrypto.1.1.dylib ../Spot-On.d/Spot-On-Kernel.app/Contents/Frameworks/libssl.1.1.dylib
install_name_tool.path      = .
libgeoip_data_install.files = ../../../GeoIP/Data/GeoIP.dat
libgeoip_data_install.path  = ../Spot-On.d/GeoIP
libntru_install.extra       = cp ../../../libNTRU/libntru.dylib ../Spot-On.d/Spot-On-Kernel.app/Contents/Frameworks/libntru.dylib && install_name_tool -change libntru.dylib @executable_path/../Frameworks/libntru.dylib ../Spot-On.d/Spot-On-Kernel.app/Contents/MacOS/Spot-On-Kernel
libntru_install.path        = .
macdeployqt.extra           = $$[QT_INSTALL_BINS]/macdeployqt ../Spot-On.d/Spot-On-Kernel.app -executable=../Spot-On.d/Spot-On-Kernel.app/Contents/MacOS/Spot-On-Kernel
macdeployqt.path            = Spot-On-Kernel.app
other_libraries1.extra      = cp /usr/local/Cellar/brotli/1.0.9/lib/libbrotlicommon.1.dylib ../Spot-On.d/Spot-On-Kernel.app/Contents/Frameworks/.
other_libraries1.path       = .
preinstall.extra            = rm -rf ../Spot-On.d/Spot-On-Kernel.app/*
preinstall.path             = ../Spot-On.d

# Order is important.

INSTALLS	= preinstall \
                  copyspoton \
                  macdeployqt \
                  copyssl \
                  install_name_tool \
                  libgeoip_data_install \
                  libntru_install \
                  other_libraries1
