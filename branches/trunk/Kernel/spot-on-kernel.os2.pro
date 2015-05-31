libspoton.target = libspotn.dll
libspoton.commands = $(MAKE) -C ../../../libSpotOn library
libspoton.depends =
purge.commands = del /F *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
QT		-= gui
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         -= SPOTON_LINKED_WITH_LIBGEOIP
DEFINES		+= SPOTON_LINKED_WITH_LIBPTHREAD

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += ../../release/Spot-On-Kernel \
		   ../../../libSpotOn/libspotn.dll \
		   ../../../libSpotOn/*.o ../../../libSpotOn/test.exe
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -mtune=generic -fwrapv -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libspoton purge
INCLUDEPATH	+= . ../. ../../../. ../../../libSpotOn/Include.win32 \
		   u:/usr/local473/include
LIBS		+= -L../../../libSpotOn \
		   -L../../../libSpotOn/Libraries.win32 \
		   -Lu:/usr/local473/lib \
		   -lcrypto -lcurl -lgcrypt -lgpg-error -lmmap -lpthread \
		   -lspoton -lssl -lssp_s
PRE_TARGETDEPS = libspotn.dll

HEADERS		= ../Common/spot-on-external-address.h \
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

SOURCES		= ../Common/spot-on-crypt.cc \
		  ../Common/spot-on-crypt-mceliece.cc \
		  ../Common/spot-on-crypt-ntru.cc \
		  ../Common/spot-on-external-address.cc \
		  ../Common/spot-on-misc.cc \
                  ../Common/spot-on-receive.cc \
		  ../Common/spot-on-send.cc \
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

TARGET		= Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel
