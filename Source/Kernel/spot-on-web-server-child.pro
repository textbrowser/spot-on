cache()
purge.commands = rm -f *~

CONFIG		+= qt release warn_on
LANGUAGE	= C++
QT		+= network sql widgets

DEFINES += QT_DEPRECATED_WARNINGS \
           SPOTON_LINKED_WITH_LIBPTHREAD

exists(/usr/include/postgresql/libpq-fe.h) {
INCLUDEPATH     += /usr/include/postgresql
LIBS            += -lpq
} else {
DEFINES += SPOTON_POSTGRESQL_DISABLED
}

QMAKE_CLEAN            += ../Spot-On-Web-Server-Child-Main
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
                          -Wno-deprecated-copy \
                          -Wno-expansion-to-defined \
                          -Wno-unused \
                          -Wold-style-cast \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstack-protector \
                          -Wstrict-overflow=5 \
                          -Wstringop-overflow=4 \
                          -Wundef \
                          -Wunused \
                          -fPIE \
                          -fstack-protector-all \
                          -funroll-loops \
                          -fwrapv \
                          -pedantic \
                          -pie \
                          -std=c++17
QMAKE_DISTCLEAN        += -r Temporary .qmake.cache .qmake.stash
QMAKE_EXTRA_TARGETS    = purge

greaterThan(QT_MAJOR_VERSION, 5) {
QMAKE_CXXFLAGS_RELEASE += -Wstrict-overflow=1
QMAKE_CXXFLAGS_RELEASE -= -Wstrict-overflow=5
}

INCLUDEPATH	+= . ../.
LIBS		+= -lcrypto \
                   -lgcrypt \
                   -lgpg-error \
                   -lssl

HEADERS         = spot-on-web-server-child-main.h
MOC_DIR         = Temporary/moc
OBJECTS_DIR     = Temporary/obj
PROJECTNAME	= Spot-On-Web-Server-Child
QMAKE_STRIP	= echo
RESOURCES	= ../HTML/html.qrc
SOURCES         = ../Common/spot-on-crypt.cc \
                  ../Common/spot-on-crypt-mceliece.cc \
                  ../Common/spot-on-crypt-ntru.cc \
                  ../Common/spot-on-misc.cc \
                  ../Common/spot-on-threefish.cc \
                  spot-on-web-server-child-main.cc
TARGET		= ../Spot-On-Web-Server-Child
TEMPLATE        = app
