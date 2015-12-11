cache()
include(goldbug-gui-source.pro)
libntru.target = libntru.so
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libspoton.target = libspoton.so
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= bluetooth concurrent gui multimedia network \
		   printsupport sql widgets
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES	+= SPOTON_BLUETOOTH_ENABLED \
           SPOTON_GOLDBUG \
	   SPOTON_LINKED_WITH_LIBGEOIP \
	   SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
	   SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN     += GoldBug ../../libNTRU/*.so ../../libNTRU/src/*.o \
                   ../../libNTRU/src/*.s \
		   ../../libSpotOn/*.o ../../libSpotOn/*.so \
		   ../../libSpotOn/test
QMAKE_DISTCLEAN += -r temp .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
                          -mtune=generic -pie \
			  -Wall -Wcast-align -Wcast-qual \
			  -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
                          -Wstack-protector -Wstrict-overflow=5
QMAKE_LFLAGS_RELEASE += -Wl,-rpath,/usr/local/spot-on/Lib
QMAKE_EXTRA_TARGETS = libntru libspoton purge
QMAKE_LFLAGS_RPATH =
INCLUDEPATH	+= . ../../. GUI
LIBS		+= -L../../libNTRU -L../../libSpotOn \
		   -lGeoIP -lcrypto -lcurl -lgcrypt \
		   -lgpg-error -lntru -lspoton -lssl
PRE_TARGETDEPS = libntru.so libspoton.so
OBJECTS_DIR = temp/obj
UI_DIR = temp/ui
MOC_DIR = temp/moc
RCC_DIR = temp/rcc

TARGET		= GoldBug
PROJECTNAME	= GoldBug

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
