cache()
include(spot-on-kernel-source.windows.pro)
libntru.commands = $(MAKE) -C ..\\..\\..\\libNTRU
libntru.depends =
libntru.target = libntru.dll
libspoton.commands = $(MAKE) -C ..\\..\\..\\libSpotOn library
libspoton.depends =
libspoton.target = libspoton.dll
purge.commands = del /F *~

CONFIG		+= qt release warn_on
CONFIG		-= debug
LANGUAGE	= C++
QT		+= concurrent network sql websockets
QT              -= gui

DEFINES         += SPOTON_LINKED_WITH_LIBGEOIP \
                   SPOTON_LINKED_WITH_LIBNTRU \
                   SPOTON_LINKED_WITH_LIBPTHREAD \
                   SPOTON_MCELIECE_ENABLED \
		   SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN            += ..\\..\\..\\libNTRU\\libntru.dll \
                          ..\\..\\..\\libNTRU\\src\\*.o \
                          ..\\..\\..\\libNTRU\\src\\*.s \
                          ..\\..\\..\\libSpotOn\\*.o \
                          ..\\..\\..\\libSpotOn\\libspoton.dll \
                          ..\\..\\..\\libSpotOn\\test.exe \
                          ..\\..\\release\\Spot-On-Kernel
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wdouble-promotion \
                          -Wextra \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstrict-overflow=5 \
                          -fwrapv \
                          -mtune=generic \
                          -pedantic \
                          -pie \
                          -std=c++11
QMAKE_DISTCLEAN        += -r debug \
                          -r release \
                          .qmake.cache \
                          .qmake.stash \
                          object_script.Spot-On-Kernel.Debug \
                          object_script.Spot-On-Kernel.Release
QMAKE_EXTRA_TARGETS    = libntru libspoton purge

INCLUDEPATH	+= . \
                   ..\\. \
                   ..\\..\\..\\. \
                   ..\\..\\..\\PostgreSQL\Include.win32 \
                   ..\\..\\..\\libGeoIP\\Include.win32 \
                   ..\\..\\..\\libNTL\\windows.d\\include \
                   ..\\..\\..\\libOpenSSL\\Include.win32 \
                   ..\\..\\..\\libSpotOn\\Include.win32 \
                   ..\\..\\..\\libcURL\\Win32.d\include
LIBS		+= -L..\\..\\..\\PostgreSQL\\Libraries.win32 \
                   -L..\\..\\..\\libNTL\\windows.d\\libraries.d \
                   -L..\\..\\..\\libNTRU \
                   -L..\\..\\..\\libSpotOn \
		   -L..\\..\\..\\libSpotOn\\Libraries.win32 \
                   -L..\\..\\..\\libGeoIP\\Libraries.win32 \
		   -L..\\..\\..\\libOpenSSL\\Libraries.win32 \
                   -L..\\..\\..\\libcURL\\Win32.d\bin \
                   -lGeoIP-1 \
                   -lcrypto-1_1 \
                   -lcurl \
                   -lgcrypt-20 \
                   -lgpg-error-0 \
                   -lntl \
                   -lntru \
                   -lpq \
                   -lspoton \
                   -lssl-1_1 \
                   -lws2_32
PRE_TARGETDEPS  = libntru.dll libspoton.dll
PROJECTNAME	= Spot-On-Kernel
TARGET		= ..\\..\\release\\Spot-On-Kernel
TEMPLATE        = app
