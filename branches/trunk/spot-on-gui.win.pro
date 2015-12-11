include(spot-on-gui-source.windows.pro)
libntru.target = libntru.dll
libntru.commands = $(MAKE) -C ..\\..\\libNTRU
libntru.depends =
libspoton.target = libspoton.dll
libspoton.commands = $(MAKE) -C ..\\..\\libSpotOn library
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         += SPOTON_LINKED_WITH_LIBGEOIP \
                   SPOTON_LINKED_WITH_LIBNTRU \
		   SPOTON_LINKED_WITH_LIBPTHREAD \
                   SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN     += Spot-On ..\\..\\libNTRU.dll ..\\..\\libNTRU\\src\\*.o \
                   ..\\..\\libNTRU\\src\\*.s \
                   ..\\..\\libSpotOn\\libspoton.dll \
		   ..\\..\\libSpotOn\\*.o \
		   ..\\..\\libSpotOn\\test.exe
QMAKE_CXXFLAGS_RELEASE += -fwrapv -mtune=generic -pie \
			  -Wall -Wcast-align -Wcast-qual \
			  -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libntru libspoton purge
INCLUDEPATH	+= . ..\\..\\. GUI ..\\..\\libSpotOn\\Include.win32 \
		   ..\\..\\libGeoIP\\Include.win32 \
		   ..\\..\\libOpenSSL\\Include.win32 \
		   ..\\..\\libcURL\\Win32.d\include
LIBS		+= -L..\\..\\libNTRU \
                   -L..\\..\\libSpotOn -L..\\..\\libSpotOn\\Libraries.win32 \
		   -L..\\..\\libGeoIP\\Libraries.win32 \
		   -L..\\..\\libOpenSSL\\Libraries.win32 \
		   -L..\\..\\libcURL\\Win32.d\\bin \
		   -lGeoIP-1 -lcurl -leay32 -lgcrypt-20 -lgpg-error-0 \
		   -lntru -lpthread -lspoton -lssl32 -lws2_32
PRE_TARGETDEPS = libntru.dll libspoton.dll

RC_FILE		= Icons\\Resources\\spot-on.rc

TARGET		= Spot-On
PROJECTNAME	= Spot-On
