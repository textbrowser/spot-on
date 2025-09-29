cache()
include(spot-on-kernel-source.pro)
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends  =
libntru.target   = libntru.so
purge.commands   = rm -f *~

CONFIG	 += qt release warn_on
LANGUAGE = C++
QT	 += concurrent network sql widgets

qtHaveModule(websockets) {
DEFINES += SPOTON_WEBSOCKETS_ENABLED
QT      += websockets
}

qtHaveModule(bluetooth) {
DEFINES += SPOTON_BLUETOOTH_ENABLED
QT      += bluetooth
message("Bluetooth enabled!")
}

DEFINES += QT_DEPRECATED_WARNINGS \
	   SPOTON_DATELESS_COMPILATION \
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
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-qual \
                          -Wdouble-promotion \
                          -Wextra \
                          -Wl,-z,relro \
                          -Wno-deprecated-copy \
                          -Wno-expansion-to-defined \
                          -Wno-unused \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstack-protector \
                          -Wstrict-overflow=1 \
                          -fPIE \
                          -fstack-protector-all \
                          -funroll-loops \
                          -fwrapv \
                          -pedantic \
                          -pie \
                          -std=c++17
QMAKE_DISTCLEAN        += -r Temporary .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntru purge
QMAKE_LFLAGS_RELEASE   = -Wl,-rpath,/opt/spot-on/Lib
QMAKE_LFLAGS_RPATH     =

INCLUDEPATH    += . \
                   ../. \
                   ../../. \
                   /usr/include/postgresql
LIBS	       += -L../../libNTRU \
                  -lcrypto \
                  -lcurl \
                  -lgcrypt \
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
