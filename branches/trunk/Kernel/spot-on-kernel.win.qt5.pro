cache()
libntru.target = libntru.dll
libntru.commands = $(MAKE) -C ..\\..\\..\\libNTRU
libntru.depends =
libspoton.target = libspoton.dll
libspoton.commands = $(MAKE) -C ..\\..\\..\\libSpotOn library
libspoton.depends =
purge.commands = del /F *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= concurrent core network sql
QT		-= gui
CONFIG		+= qt release warn_on
CONFIG          -= debug

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         += SPOTON_LINKED_WITH_LIBGEOIP \
                   SPOTON_LINKED_WITH_LIBNTRU \
		   SPOTON_LINKED_WITH_LIBPTHREAD \
                   SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN     += ..\\..\\release\\Spot-On-Kernel \
                   ..\\..\\..\\libNTRU\\libntru.dll \
                   ..\\..\\..\\libNTRU\\src\\*.o \
		   ..\\..\\..\\libSpotOn\\libspoton.dll \
		   ..\\..\\..\\libSpotOn\\*.o ..\\..\\..\\libSpotOn\\test.exe
                   .qmake.cache
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -fwrapv -mtune=generic -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libntru libspoton purge
INCLUDEPATH	+= . ..\\. ..\\..\\..\\. ..\\..\\..\\libSpotOn\\Include.win32 \
                   ..\\..\\..\\libGeoIP\\Include.win32 \
		   ..\\..\\..\\libOpenSSL\\Include.win32 \
                   ..\\..\\..\\libSCTP\\SctpDrv.win32\\inc \
                   ..\\..\\..\\libcURL\\Win32.d\include
LIBS		+= -L..\\..\\..\\libNTRU -L..\\..\\..\\libSpotOn \
		   -L..\\..\\..\\libSpotOn\\Libraries.win32 \
                   -L..\\..\\..\\libGeoIP\\Libraries.win32 \
		   -L..\\..\\..\\libOpenSSL\\Libraries.win32 \
                   -L..\\..\\..\\libSCTP\\SctpDrv.win32\\lib \
                   -L..\\..\\..\\libcURL\\Win32.d\bin \
		   -lGeoIP-1 -lcurl -leay32 -lgcrypt-20 -lgpg-error-0 \
		   -lntru -lpthread -lsctpsp -lspoton -lssl32 -lws2_32
PRE_TARGETDEPS = libntru.dll libspoton.dll

HEADERS		= ..\\Common\\spot-on-external-address.h \
		  spot-on-gui-server.h \
		  spot-on-kernel.h \
		  spot-on-listener.h \
		  spot-on-mailer.h \
		  spot-on-neighbor.h \
		  spot-on-sctp-server.h \
		  spot-on-sctp-socket.h \
		  spot-on-starbeam-reader.h \
		  spot-on-starbeam-writer.h \
		  spot-on-urldistribution.h

SOURCES		= ..\\Common\\spot-on-crypt.cc \
		  ..\\Common\\spot-on-crypt-ntru.cc \
		  ..\\Common\\spot-on-external-address.cc \
		  ..\\Common\\spot-on-misc.cc \
                  ..\\Common\\spot-on-receive.cc \
		  ..\\Common\\spot-on-send.cc \
		  spot-on-gui-server.cc \
		  spot-on-kernel-a.cc \
		  spot-on-kernel-b.cc \
		  spot-on-listener.cc \
		  spot-on-mailer.cc \
		  spot-on-neighbor.cc \
		  spot-on-sctp-server.cc \
		  spot-on-sctp-socket.cc \
		  spot-on-starbeam-reader.cc \
		  spot-on-starbeam-writer.cc \
		  spot-on-urldistribution.cc

TRANSLATIONS    =

TARGET		= ..\\..\\release\\Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel
