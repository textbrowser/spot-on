cache()
include(spot-on-gui-source.pro)
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libntru.target = libntru.so

CONFIG		+= qt release warn_on
LANGUAGE	= C++
QMAKE_STRIP	= echo
QT		+= concurrent \
                   gui \
                   multimedia \
                   network \
                   printsupport \
                   sql \
                   webenginewidgets \
                   widgets

qtHaveModule(bluetooth) {
DEFINES += SPOTON_BLUETOOTH_ENABLED
QT += bluetooth
message("Bluetooth enabled!")
}

qtHaveModule(websockets) {
DEFINES += SPOTON_WEBSOCKETS_ENABLED
QT += websockets
message("WebSockets enabled!")
}

DEFINES	+= QT_DEPRECATED_WARNINGS \
	   SPOTON_DATELESS_COMPILATION \
	   SPOTON_LINKED_WITH_LIBNTRU \
           SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_WEBENGINE_ENABLED

exists(/usr/include/NTL) {
DEFINES += SPOTON_MCELIECE_ENABLED
message("McEliece enabled!")
} else {
warning("McEliece disabled!")
}

exists(/usr/include/GeoIP.h) {
DEFINES += SPOTON_LINKED_WITH_LIBGEOIP
message("GeoIP enabled!")
}

exists(/usr/include/netinet/sctp.h) {
DEFINES += SPOTON_SCTP_ENABLED
message("SCTP enabled!")
}

exists(/usr/include/postgresql/libpq-fe.h) {
message("PostgreSQL enabled!")
} else {
DEFINES += SPOTON_POSTGRESQL_DISABLED
}

exists(/usr/include/x86_64-linux-gnu/curl/curl.h) {
DEFINES += SPOTON_POPTASTIC_SUPPORTED
message("Poptastic enabled!")
}

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU.

QMAKE_CLEAN            += ../../libNTRU/*.so \
                          ../../libNTRU/src/*.o \
                          ../../libNTRU/src/*.s \
                          Spot-On
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wdangling-reference \
                          -Wdouble-promotion \
                          -Werror \
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
                          -Wstringop-overflow=4 \
                          -Wunused \
                          -Wzero-as-null-pointer-constant \
                          -fPIE \
                          -fstack-protector-all \
                          -funroll-loops \
                          -fwrapv \
                          -pedantic \
                          -pie \
                          -std=c++17
QMAKE_DISTCLEAN        += -r temp .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = libntru purge
QMAKE_LFLAGS_RELEASE   = -Wl,-rpath,/opt/spot-on/Lib
QMAKE_LFLAGS_RPATH     =

greaterThan(QT_MAJOR_VERSION, 5) {
QMAKE_CXXFLAGS_RELEASE += -Wstrict-overflow=1
QMAKE_CXXFLAGS_RELEASE -= -Wredundant-decls \
                          -Wstrict-overflow=5
}

INCLUDEPATH	+= . ../../. GUI
LIBS		+= -L../../libNTRU \
                   -lcrypto \
                   -lgcrypt \
                   -lgpg-error \
                   -lntru \
                   -lpthread \
                   -lssl

exists(/usr/include/GeoIP.h) {
LIBS            += -lGeoIP
}

exists(/usr/include/NTL) {
LIBS            += -lntl
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
PROJECTNAME	= Spot-On
RCC_DIR         = temp/rcc
TARGET		= Spot-On
TEMPLATE	= app
UI_DIR          = temp/ui
