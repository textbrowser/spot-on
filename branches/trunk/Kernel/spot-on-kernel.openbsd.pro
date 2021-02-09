include(spot-on-kernel-source.pro)
libntru.commands = gmake -C ../../../libNTRU
libntru.depends =
libntru.target = libntru.so
purge.commands = rm -f *~

CONFIG		+= qt release warn_on
LANGUAGE	= C++
QT		+= concurrent network sql websockets
QT		-= gui

DEFINES += LIBSPOTON_IGNORE_GCRY_CONTROL_GCRYCTL_INIT_SECMEM_RETURN_VALUE \
           LIBSPOTON_OS_OPENBSD \
	   SPOTON_DATELESS_COMPILATION \
           SPOTON_DTLS_DISABLED \
	   SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_POPTASTIC_SUPPORTED \
           SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ../../../libNTRU/*.so \
                          ../../../libNTRU/src/*.o \
                          ../../../libNTRU/src/*.s \
                          ../Spot-On-Kernel
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
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
                          -std=c++11
QMAKE_DISTCLEAN        += -r temp
QMAKE_EXTRA_TARGETS    = libntru purge

INCLUDEPATH	+= . \
                   ../. \
                   ../../../. \
                   /usr/local/include/postgresql
LIBS		+= -L../../../libNTRU \
                   -L/usr/local/lib \
                   -lcrypto \
                   -lcurl \
                   -lgcrypt \
                   -lgpg-error \
                   -lntru \
                   -lpq \
                   -lpthread \
                   -lsqlite3 \
                   -lssl
MOC_DIR         = temp/moc
OBJECTS_DIR     = temp/obj
PRE_TARGETDEPS  = libntru.so
PROJECTNAME	= Spot-On-Kernel
RCC_DIR         = temp/rcc
TARGET		= ../Spot-On-Kernel
TEMPLATE        = app
UI_DIR          = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
