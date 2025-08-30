cache()
include(spot-on-kernel-source.pro)
libntru.commands = gmake -C ../../libNTRU
libntru.depends  =
libntru.target   = libntru.so
purge.commands   = rm -f *~

CONFIG	 += qt release warn_on
LANGUAGE = C++
QT	 += concurrent network sql widgets

qtHaveModule(bluetooth) {
DEFINES += SPOTON_BLUETOOTH_ENABLED
QT      += bluetooth
}

qtHaveModule(websockets) {
DEFINES += SPOTON_WEBSOCKETS_ENABLED
QT      += websockets
}

DEFINES += SPOTON_DATELESS_COMPILATION \
	   SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_MCELIECE_ENABLED \
           SPOTON_POPTASTIC_SUPPORTED \
           SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ../../libNTRU/*.so \
                          ../../libNTRU/src/*.o \
                          ../../libNTRU/src/*.s \
                          ../Spot-On-Kernel
QMAKE_CXX              = clang++
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wextra \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstack-protector \
                          -Wstrict-overflow=5 \
                          -fPIE \
                          -fstack-protector-all \
                          -funroll-loops \
                          -fwrapv \
                          -pedantic \
                          -std=c++17
QMAKE_DISTCLEAN        += -r Temporary .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntru purge

INCLUDEPATH    += . \
                  ../. \
                  ../../. \
                  /usr/local/include/postgresql
LIBS	       += -L../../libNTRU \
                  -L/usr/local/lib \
                  -lcrypto \
                  -lcurl \
                  -lgcrypt \
                  -lgmp \
                  -lgpg-error \
                  -lntl \
                  -lntru \
                  -lpq \
                  -lpthread \
                  -lssl
MOC_DIR        = Temporary/moc
OBJECTS_DIR    = Temporary/obj
PRE_TARGETDEPS = libntru.so
PROJECTNAME    = Spot-On-Kernel
RCC_DIR        = Temporary/rcc
TARGET	       = ../Spot-On-Kernel
TEMPLATE       = app
UI_DIR         = Temporary/ui

# Prevent qmake from stripping everything.

QMAKE_STRIP = echo
