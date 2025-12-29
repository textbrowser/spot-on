cache()
include(spot-on-gui-source.pro)
libntru.commands = $(MAKE) -C ../libNTRU
libntru.depends =
libntru.target = libntru.so

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
	   SPOTON_DATELESS_COMPILATION \
	   SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_POPTASTIC_SUPPORTED \
	   SPOTON_SCTP_ENABLED \
	   SPOTON_WEBSOCKETS_ENABLED

exists(/usr/include/NTL) {
DEFINES += SPOTON_MCELIECE_ENABLED
message("McEliece enabled!")
} else {
warning("McEliece disabled!")
}

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ../libNTRU/*.so \
                          ../libNTRU/src/*.o \
                          ../libNTRU/src/*.s \
                          Spot-On
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wdouble-promotion \
                          -Wextra \
                          -Wl,-z,relro \
                          -Wno-unused-parameter \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstack-protector \
                          -Wstrict-overflow=5 \
                          -fPIE \
                          -fstack-protector-all \
                          -funroll-loops \
                          -fwrapv \
                          -mabi=altivec \
                          -mcpu=powerpc \
                          -mtune=powerpc \
                          -pedantic \
                          -pie \
                          -std=c++11
QMAKE_DISTCLEAN        += -r Temporary .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntru purge
QMAKE_LFLAGS_RELEASE   += -Wl,-rpath,/opt/spot-on/Lib

INCLUDEPATH	+= . \
                   ../. \
                   /usr/include/postgresql \
                   GUI
LIBS		+= -L../libNTRU \
                   -lcrypto \
                   -lcurl \
                   -lgcrypt \
                   -lgpg-error \
                   -lntru \
                   -lpq \
                   -lpthread \
                   -lssl

exists(/usr/include/NTL) {
LIBS += -lgmp -lntl
}

MOC_DIR         = Temporary/moc
OBJECTS_DIR     = Temporary/obj
PRE_TARGETDEPS  = libntru.so
PROJECTNAME	= Spot-On
RCC_DIR         = Temporary/rcc
TARGET		= Spot-On
TEMPLATE        = app
UI_DIR          = Temporary/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
