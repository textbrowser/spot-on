cache()
include(spot-on-kernel-source.pro)
libntl.commands  = echo
libntl.depends   =
libntl.target    = libntl.so
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends  =
libntru.target   = libntru.so
purge.commands   = rm -f *~

CONFIG	 += qt release warn_on
LANGUAGE = C++
QT	 += bluetooth concurrent network sql websockets widgets

DEFINES += SPOTON_BLUETOOTH_ENABLED \
	   SPOTON_DATELESS_COMPILATION \
           SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
           SPOTON_POPTASTIC_SUPPORTED \
           SPOTON_SCTP_ENABLED \
           SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTL and libNTRU.

QMAKE_CLEAN            += ../../libNTL/unix.d/src/*.lo \
                          ../../libNTL/unix.d/src/*.o \
                          ../../libNTRU/*.so \
                          ../../libNTRU/src/*.o \
                          ../../libNTRU/src/*.s \
                          ../Spot-On-Kernel
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wdouble-promotion \
                          -Wextra \
                          -Wl,-z,relro \
                          -Wno-unused \
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
QMAKE_EXTRA_TARGETS    = libntl libntru purge
QMAKE_LFLAGS_RELEASE   = -Wl,-rpath,/opt/spot-on/Lib
QMAKE_LFLAGS_RPATH     =

INCLUDEPATH	+= . \
                   ../. \
                   ../../. \
                   ../../libNTL/unix.d/include \
                   /usr/include/postgresql
LIBS		+= -L../../libNTL/unix.d/src/.libs \
                   -L../../libNTRU \
                   -lcrypto \
                   -lcurl \
                   -lgcrypt \
                   -lgpg-error \
                   -lntl \
                   -lntru \
                   -lpq \
                   -lpthread \
                   -lssl
MOC_DIR         = Temporary/moc
OBJECTS_DIR     = Temporary/obj
PRE_TARGETDEPS  = libntl.so libntru.so
PROJECTNAME	= Spot-On-Kernel
RCC_DIR         = Temporary/rcc
TARGET		= ../Spot-On-Kernel
TEMPLATE        = app
UI_DIR          = Temporary/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP = echo
