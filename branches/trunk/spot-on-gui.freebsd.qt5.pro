cache()
include(spot-on-gui-source.pro)
libntru.target = libntru.so
libntru.commands = gmake -C ../../libNTRU
libntru.depends =
libspoton.target = libspoton.so
libspoton.commands = gmake -C ../../libSpotOn library
libspoton.depends =

CONFIG		+= qt release warn_on
LANGUAGE	= C++
QT		+= concurrent gui multimedia network printsupport sql \
		   websockets widgets

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES	+= SPOTON_LINKED_WITH_LIBGEOIP \
	   SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
	   SPOTON_SCTP_ENABLED \
	   SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN            += Spot-On \
		          ../../libNTRU/*.so ../../libNTRU/src/*.o \
                          ../../libNTRU/src/*.s \
                          ../../libSpotOn/*.o ../../libSpotOn/*.so \
                          ../../libSpotOn/test
QMAKE_CXX              = clang++
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
                          -mtune=native -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
                          -Wstack-protector -Wstrict-overflow=5
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntru libspoton purge

INCLUDEPATH	+= . ../../. GUI /usr/local/include/postgresql
LIBS		+= -L../../libNTRU -L../../libSpotOn \
		   -lGeoIP -lcrypto -lcurl -lgcrypt \
		   -lgpg-error -lgmp -lntl -lntru -lpq -lspoton -lssl
MOC_DIR         = temp/moc
OBJECTS_DIR     = temp/obj
PRE_TARGETDEPS  = libntru.so libspoton.so
PROJECTNAME	= Spot-On
RCC_DIR         = temp/rcc
TARGET		= Spot-On
TEMPLATE        = app
UI_DIR          = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
