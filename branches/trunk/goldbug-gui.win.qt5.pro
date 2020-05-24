cache()
include(goldbug-gui-source.windows.pro)
libntru.commands = $(MAKE) -C ..\\..\\libNTRU
libntru.depends =
libntru.target = libntru.dll
libspoton.commands = $(MAKE) -C ..\\..\\libSpotOn library
libspoton.depends =
libspoton.target = libspoton.dll

TEMPLATE	= app
LANGUAGE	= C++
QT		+= concurrent \
                   gui \
                   multimedia \
                   network \
                   printsupport \
                   sql \
                   websockets \
                   widgets
CONFIG		+= qt release warn_on

DEFINES         += SPOTON_GOLDBUG \
		   SPOTON_LINKED_WITH_LIBGEOIP \
                   SPOTON_LINKED_WITH_LIBNTRU \
		   SPOTON_LINKED_WITH_LIBPTHREAD \
		   SPOTON_MCELIECE_ENABLED \
		   SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN     += ..\\..\\libNTRU.dll \
                   ..\\..\\libNTRU\\src\\*.o \
                   ..\\..\\libNTRU\\src\\*.s \
                   ..\\..\\libSpotOn\\*.o \
                   ..\\..\\libSpotOn\\libspoton.dll \
                   ..\\..\\libSpotOn\\test.exe \
                   GoldBug
QMAKE_CXXFLAGS_RELEASE += -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wextra \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstrict-overflow=5 \
                          -fwrapv \
                          -mtune=generic \
                          -pie
QMAKE_DISTCLEAN        += -r debug \
                          .qmake.cache \
                          .qmake.stash \
                          object_script.GoldBug.Debug \
                          object_script.GoldBug.Release
QMAKE_EXTRA_TARGETS = libntru libspoton purge
INCLUDEPATH	+= . \
                   ..\\..\\. \
                   ..\\..\\PostgreSQL\\Include.win32 \
                   ..\\..\\libGeoIP\\Include.win32 \
                   ..\\..\\libNTL\\windows.d\\include \
                   ..\\..\\libOpenSSL\\Include.win32 \
                   ..\\..\\libSpotOn\\Include.win32 \
                   ..\\..\\libcURL\\Win32.d\include \
                   GUI
LIBS		+= -L..\\..\\PostgreSQL\\Libraries.win32 \
                   -L..\\..\\libGeoIP\\Libraries.win32 \
                   -L..\\..\\libNTL\\windows.d\\libraries.d \
                   -L..\\..\\libNTRU \
                   -L..\\..\\libOpenSSL\\Libraries.win32 \
                   -L..\\..\\libSpotOn \
                   -L..\\..\\libSpotOn\\Libraries.win32 \
                   -L..\\..\\libcURL\\Win32.d\bin \
                   -lGeoIP-1 \
                   -lcrypto-1_1 \
                   -lcurl \
                   -lgcrypt-20 \
                   -lgpg-error-0 \-lntl \
                   -lntru \
                   -lpq -lpthread \
                   -lspoton \
                   -lssl-1_1 \
                   -lws2_32
PRE_TARGETDEPS = libntru.dll libspoton.dll

RC_FILE		= Icons\\Resources\\goldbug.rc

TARGET		= GoldBug
PROJECTNAME	= GoldBug
