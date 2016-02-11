cache()
include(spot-on-kernel-source.pro)
libntru.target = libntru.so
libntru.commands = gmake -C ../../../libNTRU
libntru.depends =
libspoton.target = libspoton.so
libspoton.commands = gmake -C ../../../libSpotOn library
libspoton.depends =
purge.commands = rm -f *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= concurrent core network sql
QT              -= gui
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES += SPOTON_LINKED_WITH_LIBGEOIP \
   	   SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN     += ../Spot-On-Kernel ../../../libNTRU/*.so \
		   ../../../libNTRU/src/*.o ../../../libNTRU/src/*.s \
		   ../../../libSpotOn/*.o \
		   ../../../libSpotOn/*.so ../../../libSpotOn/test
QMAKE_CXX = clang++
QMAKE_DISTCLEAN += -r temp .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
			  -mtune=generic -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstack-protector -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libntru libspoton purge
INCLUDEPATH	+= . ../. ../../../. /usr/local/include/postgresql
LIBS		+= -L../../../libNTRU -L../../../libSpotOn \
		   -L/usr/local/lib -lGeoIP \
		   -lcrypto -lcurl -lgcrypt -lgpg-error -lntru -lpq \
		   -lspoton -lssl
PRE_TARGETDEPS = libntru.so libspoton.so purge
OBJECTS_DIR = temp/obj
UI_DIR = temp/ui
MOC_DIR = temp/moc
RCC_DIR = temp/rcc

TARGET		= ../Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
