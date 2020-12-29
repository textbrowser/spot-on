cache()
include(spot-on-gui-source.pro)
libntl.commands = echo
libntl.depends =
libntl.target = libntl.so
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libntru.target = libntru.so
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =
libspoton.target = libspoton.so

CONFIG		+= qt release warn_on
LANGUAGE	= C++
QT		+= bluetooth \
                   concurrent \
                   gui \
                   multimedia \
                   network \
                   printsupport \
                   sql \
                   websockets \
                   widgets

DEFINES	+= SPOTON_BLUETOOTH_ENABLED \
           SPOTON_LINKED_WITH_LIBGEOIP \
	   SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
           SPOTON_POPTASTIC_SUPPORTED \
           SPOTON_SCTP_ENABLED \
           SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTL, libNTRU, and libSpotOn.

QMAKE_CLEAN            += ../../libNTL/unix.d/src/*.lo \
                          ../../libNTL/unix.d/src/*.o \
                          ../../libNTRU/*.so \
                          ../../libNTRU/src/*.o \
                          ../../libNTRU/src/*.s \
                          ../../libSpotOn/*.o \
                          ../../libSpotOn/*.so \
                          ../../libSpotOn/test \
                          Spot-On
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wdouble-promotion \
                          -Wextra \
                          -Wfloat-equal \
                          -Wformat=2 \
                          -Wformat-overflow=2 \
                          -Wl,-z,relro \
                          -Wlogical-op \
                          -Wno-deprecated-copy \
                          -Wno-expansion-to-defined \
                          -Wno-unused \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wredundant-decls \
                          -Wstack-protector \
                          -Wstrict-overflow=5 \
                          -fPIE \
                          -fstack-protector-all \
                          -fwrapv \
                          -mtune=native \
                          -pedantic \
                          -pie \
                          -std=c++11
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntl libntru libspoton purge
QMAKE_LFLAGS_RELEASE   = -Wl,-rpath,/usr/local/spot-on/Lib
QMAKE_LFLAGS_RPATH     =

INCLUDEPATH	+= . \
                   ../../. \
                   ../../libNTL/unix.d/include \
                   /usr/include/postgresql \
                   GUI
LIBS		+= -L../../libNTL/unix.d/src/.libs \
                   -L../../libNTRU \
                   -L../../libSpotOn \
                   -lGeoIP \
                   -lcrypto \
                   -lcurl \
                   -lgcrypt \
                   -lgpg-error \
                   -lntl \
                   -lntru \
                   -lpq \
                   -lspoton \
                   -lssl
MOC_DIR         = temp/moc
OBJECTS_DIR     = temp/obj
PRE_TARGETDEPS  = libntl.so libntru.so libspoton.so
PROJECTNAME	= Spot-On
RCC_DIR         = temp/rcc
TARGET		= Spot-On
TEMPLATE	= app
UI_DIR          = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
