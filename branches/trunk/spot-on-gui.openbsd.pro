include(spot-on-gui-source.pro)
libntru.commands = gmake -C ../../libNTRU
libntru.depends =
libntru.target = libntru.so

CONFIG		+= qt release warn_on
LANGUAGE	= C++
QT		+= concurrent \
                   gui \
                   multimedia \
                   network \
                   printsupport \
                   sql \
                   websockets \
                   widgets

DEFINES	+= LIBSPOTON_IGNORE_GCRY_CONTROL_GCRYCTL_INIT_SECMEM_RETURN_VALUE \
           LIBSPOTON_OS_OPENBSD \
           SPOTON_DTLS_DISABLED \
	   SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_POPTASTIC_SUPPORTED \
           SPOTON_WEBSOCKETS_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ../../libNTRU/*.so \
                          ../../libNTRU/src/*.o \
                          ../../libNTRU/src/*.s \
                          Spot-On
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-qual \
                          -Wdouble-promotion \
                          -Wextra \
                          -Wl,-z,relro \
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

INCLUDEPATH	       += . \
                          ../../. \
                          /usr/local/include/postgresql \
                          GUI
LIBS		       += -L../../libNTRU \
                          -lcrypto \
                          -lcurl \
                          -lgcrypt \
                          -lgpg-error \
                          -lntru \
                          -lpq \
                          -lpthread \
                          -lsqlite3 \
                          -lssl
MOC_DIR                = temp/moc
OBJECTS_DIR            = temp/obj
PRE_TARGETDEPS         = libntru.so
PROJECTNAME	       = Spot-On
RCC_DIR                = temp/rcc
TARGET		       = Spot-On
TEMPLATE               = app
UI_DIR                 = temp/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
