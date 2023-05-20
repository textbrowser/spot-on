cache()
include(spot-on-kernel-source.windows.pro)
libntru.commands = $(MAKE) -C ..\\..\\..\\libNTRU
libntru.depends =
libntru.target = libntru.dll
mceliece_supported = "false"
purge.commands = del /F *~

CONFIG		+= qt release warn_on
CONFIG		-= debug
LANGUAGE	= C++
QT		+= concurrent network sql websockets
QT              -= gui

DEFINES         += LIBSPOTON_OS_WINDOWS \
                   SPOTON_DATELESS_COMPILATION \
                   SPOTON_LINKED_WITH_LIBNTRU \
                   SPOTON_LINKED_WITH_LIBPTHREAD \
                   SPOTON_POSTGRESQL_DISABLED \
		   SPOTON_WEBSOCKETS_ENABLED

equals(mceliece_supported, "true") {
DEFINES         += SPOTON_MCELIECE_ENABLED
}

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ..\\..\\..\\libNTRU\\libntru.dll \
                          ..\\..\\..\\libNTRU\\src\\*.o \
                          ..\\..\\..\\libNTRU\\src\\*.s \
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
                          -pedantic \
                          -pie \
                          -std=c++17
QMAKE_DISTCLEAN        += -r debug \
                          -r release \
                          .qmake.cache \
                          .qmake.stash \
                          object_script.Spot-On-Kernel.Debug \
                          object_script.Spot-On-Kernel.Release
QMAKE_EXTRA_TARGETS    = libntru purge

INCLUDEPATH	+= . \
                   ..\\. \
                   ..\\..\\..\\. \
                   ..\\..\\..\\libOpenSSL\\Include.win64 \
                   ..\\..\\..\\libSpotOn\\Include.win64 \
LIBS		+= -L..\\..\\..\\libNTRU \
		   -L..\\..\\..\\libSpotOn\\Libraries.win64 \
		   -L..\\..\\..\\libOpenSSL\\Libraries.win64 \
                   -lcrypto-3-x64 \
                   -lgcrypt-20 \
                   -lgpg-error-0 \
                   -lntru \
                   -lpthread \
                   -lsqlite3 \
                   -lssl-3-x64 \
                   -lws2_64

equals(mceliece_supported, "true") {
INCLUDEPATH     += ..\\..\\..\\libNTL\\windows.d\\include
LIBS            += -L..\\..\\..\\libNTL\\windows.d\\libraries.d -lntl
}

PRE_TARGETDEPS  = libntru.dll
PROJECTNAME	= Spot-On-Kernel
TARGET		= ..\\..\\release\\Spot-On-Kernel
TEMPLATE        = app
