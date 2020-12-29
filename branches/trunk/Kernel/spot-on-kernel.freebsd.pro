cache()
include(spot-on-kernel-source.pro)
libntru.commands = gmake -C ../../../libNTRU
libntru.depends =
libntru.target = libntru.so
libspoton.commands = gmake -C ../../../libSpotOn library
libspoton.depends =
libspoton.target = libspoton.so
purge.commands = rm -f *~

CONFIG		+= qt release warn_on
LANGUAGE	= C++
QT		+= bluetooth concurrent network sql websockets
QT              -= gui

DEFINES += SPOTON_BLUETOOTH_ENABLED \
	   SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
           SPOTON_POPTASTIC_SUPPORTED \
           SPOTON_SCTP_ENABLED \
	   SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN            += ../../../libNTRU/*.so \
                          ../../../libNTRU/src/*.o \
                          ../../../libNTRU/src/*.s \
                          ../../../libSpotOn/*.o \
                          ../../../libSpotOn/*.so \
                          ../../../libSpotOn/test \
                          ../Spot-On-Kernel
QMAKE_CXX              = clang++
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wdouble-promotion \
                          -Wextra \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstack-protector \
                          -Wstrict-overflow=5 \
                          -fPIE \
                          -fstack-protector-all \
                          -fwrapv \
                          -pedantic \
                          -std=c++17
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntru libspoton purge

INCLUDEPATH	+= . \
                   ../. \
                   ../../../. \
                   /usr/local/include/postgresql
LIBS		+= -L../../../libNTRU \
                   -L../../../libSpotOn \
                   -L/usr/local/lib \
                   -lcrypto \
                   -lcurl \
                   -lgcrypt \
                   -lgmp \
                   -lgpg-error \
                   -lntl \
                   -lntru \
                   -lpq \
                   -lspoton \
                   -lssl
MOC_DIR         = temp/moc
OBJECTS_DIR     = temp/obj
PRE_TARGETDEPS  = libntru.so libspoton.so
PROJECTNAME	= Spot-On-Kernel
RCC_DIR         = temp/rcc
TARGET		= ../Spot-On-Kernel
TEMPLATE        = app
UI_DIR          = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
