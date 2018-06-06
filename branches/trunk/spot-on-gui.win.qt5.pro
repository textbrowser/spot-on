cache()
include(spot-on-gui-source.windows.pro)
libntru.target = libntru.dll
libntru.commands = $(MAKE) -C ..\\..\\libNTRU
libntru.depends =
libspoton.target = libspoton.dll
libspoton.commands = $(MAKE) -C ..\\..\\libSpotOn library
libspoton.depends =

CONFIG		+= qt release warn_on
CONFIG		-= debug
LANGUAGE	= C++
QT		+= concurrent gui multimedia network printsupport sql \
		   widgets

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         += SPOTON_LINKED_WITH_LIBGEOIP \
                   SPOTON_LINKED_WITH_LIBNTRU \
		   SPOTON_LINKED_WITH_LIBPTHREAD \
		   SPOTON_MCELIECE_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN            += Spot-On ..\\..\\libNTRU.dll \
                          ..\\..\\libNTRU\\src\\*.o \
                          ..\\..\\libNTRU\\src\\*.s \
                          ..\\..\\libSpotOn\\libspoton.dll \
                          ..\\..\\libSpotOn\\*.o \
                          ..\\..\\libSpotOn\\test.exe \
                          .qmake.cache .qmake.stash \
                          object_script.Spot-On.Debug \
                          object_script.Spot-On.Release
QMAKE_CXXFLAGS_RELEASE += -fwrapv -mtune=generic -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstrict-overflow=5
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_DISTCLEAN        += .qmake.cache .qmake.stash \
                          object_script.Spot-On.Debug \
                          object_script.Spot-On.Release
QMAKE_EXTRA_TARGETS    = libntru libspoton purge

INCLUDEPATH	+= . ..\\..\\. GUI \
		   ..\\..\\PostgreSQL\\Include.win32 \
		   ..\\..\\libSpotOn\\Include.win32 \
		   ..\\..\\libGeoIP\\Include.win32 \
		   ..\\..\\libOpenSSL\\Include.win32 \
		   ..\\..\\libNTL\\windows.d\\include \
                   ..\\..\\libcURL\\Win32.d\\include
LIBS		+= -L..\\..\\PostgreSQL\\Libraries.win32 \
		   -L..\\..\\libNTL\\windows.d\\libraries.d \
		   -L..\\..\\libNTRU \
                   -L..\\..\\libSpotOn -L..\\..\\libSpotOn\\Libraries.win32 \
		   -L..\\..\\libGeoIP\\Libraries.win32 \
		   -L..\\..\\libOpenSSL\\Libraries.win32 \
                   -L..\\..\\libcURL\\Win32.d\\bin \
		   -lGeoIP-1 -lcrypto-1_1 -lcurl -lgcrypt-20 \
		   -lgpg-error-0 -lntl \
		   -lntru -lpq -lpthread -lspoton -lssl-1_1 -lws2_32
PRE_TARGETDEPS  = libntru.dll libspoton.dll
PROJECTNAME	= Spot-On
RC_FILE		= Icons\\Resources\\spot-on.rc
TARGET		= Spot-On
TEMPLATE        = app
