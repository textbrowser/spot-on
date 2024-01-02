cache()
include(spot-on-kernel-source.pro)
libntl.commands = echo
libntl.depends =
libntl.target = libntl.so
libntru.commands = $(MAKE) -C ../../../libNTRU
libntru.depends =
libntru.target = libntru.so
purge.commands = rm -f *~

CONFIG		+= qt release warn_on
LANGUAGE	= C++
QT		+= concurrent network sql
QT              -= gui

qtHaveModule(bluetooth) {
DEFINES += SPOTON_BLUETOOTH_ENABLED
QT += bluetooth
}

qtHaveModule(websockets) {
DEFINES += SPOTON_WEBSOCKETS_ENABLED
QT += websockets
}

DEFINES += QT_DEPRECATED_WARNINGS \
	   SPOTON_DATELESS_COMPILATION \
           SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD

exists(../../../libNTL/unix.d/src/.libs/libntl.so) {
DEFINES += SPOTON_MCELIECE_ENABLED
}

exists(/usr/include/GeoIP.h) {
DEFINES += SPOTON_LINKED_WITH_LIBGEOIP
}

exists(/usr/include/netinet/sctp.h) {
DEFINES += SPOTON_SCTP_ENABLED
}

exists(/usr/include/postgresql/libpq-fe.h) {
} else {
DEFINES += SPOTON_POSTGRESQL_DISABLED
}

exists(/usr/include/x86_64-linux-gnu/curl/curl.h) {
DEFINES += SPOTON_POPTASTIC_SUPPORTED
}

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTL, and libNTRU.

QMAKE_CLEAN            += ../../../libNTL/unix.d/src/*.lo \
                          ../../../libNTL/unix.d/src/*.o \
                          ../../../libNTRU/*.so \
                          ../../../libNTRU/src/*.o \
                          ../../../libNTRU/src/*.s \
                          ../Spot-On-Kernel
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
                          -Wno-deprecated-copy \
                          -Wno-expansion-to-defined \
                          -Wno-unused \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstack-protector \
                          -Wstrict-overflow=5 \
                          -Wstringop-overflow=4 \
                          -Wundef \
                          -fPIE \
                          -fstack-protector-all \
                          -fwrapv \
                          -pedantic \
                          -pie \
                          -std=c++17
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntl libntru purge
QMAKE_LFLAGS_RELEASE   = -Wl,-rpath,/opt/spot-on/Lib
QMAKE_LFLAGS_RPATH     =

greaterThan(QT_MAJOR_VERSION, 5) {
QMAKE_CXXFLAGS_RELEASE += -Wstrict-overflow=1
QMAKE_CXXFLAGS_RELEASE -= -Wstrict-overflow=5
}

INCLUDEPATH	+= . ../. ../../../.
LIBS		+= -L../../../libNTRU \
                   -lcrypto \
                   -lgcrypt \
                   -lgpg-error \
                   -lntru \
                   -lpthread \
                   -lssl

exists(../../../libNTL/unix.d/src/.libs/libntl.so) {
INCLUDEPATH     += ../../../libNTL/unix.d/include
LIBS            += -L../../../libNTL/unix.d/src/.libs -lntl
}

exists(/usr/include/GeoIP.h) {
LIBS            += -lGeoIP
}

exists(/usr/include/postgresql/libpq-fe.h) {
INCLUDEPATH     += /usr/include/postgresql
LIBS            += -lpq
}

exists(/usr/include/x86_64-linux-gnu/curl/curl.h) {
LIBS            += -lcurl
}

MOC_DIR         = temp/moc
OBJECTS_DIR     = temp/obj
PRE_TARGETDEPS  = libntru.so

exists(../../../libNTL/unix.d/src/.libs/libntl.so) {
PRE_TARGETDEPS  += libntl.so
}

PROJECTNAME	= Spot-On-Kernel
RCC_DIR         = temp/rcc
TARGET		= ../Spot-On-Kernel
TEMPLATE        = app
UI_DIR          = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
