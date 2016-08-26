include(spot-on-gui-source.pro)
libntru.target = libntru.so
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libspoton.target = libspoton.so
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES	+= SPOTON_LINKED_WITH_LIBGEOIP \
	   SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
	   SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTL, libNTRU, and libSpotOn.

QMAKE_CLEAN     += Spot-On ../../libNTL/unix.d/src/*.o \
		   ../../libNTRU/*.so ../../libNTRU/src/*.o \
                   ../../libNTRU/src/*.s \
		   ../../libSpotOn/*.o ../../libSpotOn/*.so \
		   ../../libSpotOn/test
QMAKE_DISTCLEAN += -r temp
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
                          -mtune=native -pie \
			  -Wall -Wcast-align -Wcast-qual \
			  -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
                          -Wstack-protector -Wstrict-overflow=5
QMAKE_LFLAGS_RELEASE += -Wl,-rpath,/usr/local/spot-on/Lib
QMAKE_EXTRA_TARGETS = libntru libspoton ntl purge
QMAKE_LFLAGS_RPATH =
INCLUDEPATH	+= . ../../. GUI /usr/include/postgresql
LIBS		+= -L../../libNTRU -L../../libSpotOn \
		   -lGeoIP -lcrypto -lcurl \
                   -lgcrypt -lgpg-error -lntru -lpq -lspoton -lssl
PRE_TARGETDEPS = libntru.so libspoton.so ntl.a
OBJECTS_DIR = temp/obj
UI_DIR = temp/ui
MOC_DIR = temp/moc
RCC_DIR = temp/rcc

TARGET		= Spot-On
PROJECTNAME	= Spot-On

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
