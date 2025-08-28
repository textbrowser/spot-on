cache()

unix {
purge.commands = rm -f *~
} else {
purge.commands = del /F *~
}

CONFIG	 += qt release warn_on
CONFIG   -= debug
LANGUAGE = C++
QT	 += network sql widgets

DEFINES += QT_DEPRECATED_WARNINGS \
           SPOTON_DATELESS_COMPILATION \
           SPOTON_LINKED_WITH_LIBPTHREAD

exists(/usr/include/postgresql/libpq-fe.h) {
INCLUDEPATH += /usr/include/postgresql
LIBS        += -lpq
} else:exists(/usr/local/include/postgresql/libpq-fe.h) {
INCLUDEPATH += /usr/local/include/postgresql
LIBS        += -L/usr/local/lib \
               -lpq
} else {
DEFINES += SPOTON_POSTGRESQL_DISABLED
}

unix {
QMAKE_CLEAN += ../Spot-On-Web-Server-Child-Main
} else {
QMAKE_CLEAN += ..\\..\\release\\Spot-On-Web-Server-Child-Main
}

QMAKE_CXXFLAGS_RELEASE -= -O2

contains(QMAKE_HOST.arch, ppc) {
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
} else:linux-* {
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
} else:macx {
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-qual \
                          -Wextra \
                          -Wno-c++20-attribute-extensions \
                          -Wno-cast-align \
                          -Wno-deprecated \
                          -Wno-unused-parameter \
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
} else:win32 {
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O3 \
                          -Wall \
                          -Wcast-align \
                          -Wcast-qual \
                          -Wdouble-promotion \
                          -Wextra \
                          -Woverloaded-virtual \
                          -Wpointer-arith \
                          -Wstrict-overflow=1 \
                          -funroll-loops \
                          -fwrapv \
                          -pedantic \
                          -pie \
                          -std=c++17
}

QMAKE_DISTCLEAN        += -r Temporary-Web-Server \
                          -r debug \
                          -r release \
                          .qmake.cache \
                          .qmake.stash \
                          object_script.*
QMAKE_EXTRA_TARGETS    = purge

greaterThan(QT_MAJOR_VERSION, 5) {
QMAKE_CXXFLAGS_RELEASE += -Wstrict-overflow=1
QMAKE_CXXFLAGS_RELEASE -= -Wstrict-overflow=5
}

unix {
INCLUDEPATH += . ../.
} else {
INCLUDEPATH += . \
               ..\\. \
               ..\\..\\libGCrypt\\Include.win64 \
               ..\\..\\libOpenSSL\\Include.win64
}

linux-* {
LIBS += -lcrypto \
        -lgcrypt \
        -lgpg-error \
        -lpthread \
        -lssl
} else:freebsd-* {
LIBS += -L/usr/local/lib \
        -lcrypto \
        -lgcrypt \
        -lgpg-error \
        -lpthread \
        -lssl
} else {
LIBS += -L..\\..\\libGCrypt\\Libraries.win64 \
        -L..\\..\\libOpenSSL\\Libraries.win64 \
        -lcrypto-3-x64 \
        -lgcrypt-20 \
        -lgpg-error-0 \
        -lpthread \
        -lssl-3-x64 \
        -lws2_32
}

HEADERS = spot-on-web-server-child-main.h

unix {
MOC_DIR     = Temporary-Web-Server/moc
OBJECTS_DIR = Temporary-Web-Server/obj
} else {
MOC_DIR     = Temporary-Web-Server\\moc
OBJECTS_DIR = Temporary-Web-Server\\obj
}

PROJECTNAME = Spot-On-Web-Server-Child
QMAKE_STRIP = echo

unix {
RESOURCES = ../HTML/html.qrc
} else {
RESOURCES = ..\\HTML\\html.qrc
}

unix {
SOURCES = ../Common/spot-on-crypt.cc \
          ../Common/spot-on-crypt-mceliece.cc \
          ../Common/spot-on-crypt-ntru.cc \
          ../Common/spot-on-misc.cc \
          ../Common/spot-on-threefish.cc \
          spot-on-web-server-child-main.cc
} else {
SOURCES = ..\\Common\\spot-on-crypt.cc \
          ..\\Common\\spot-on-crypt-mceliece.cc \
          ..\\Common\\spot-on-crypt-ntru.cc \
          ..\\Common\\spot-on-misc.cc \
          ..\\Common\\spot-on-threefish.cc \
          spot-on-web-server-child-main.cc
}

unix {
TARGET = ../Spot-On-Web-Server-Child
} else {
TARGET = ..\\..\\release\\Spot-On-Web-Server-Child
}

TEMPLATE = app

macx {
copy.extra        = cp -r ../Spot-On-Web-Server-Child.app ../Spot-On.d/.
copy.path         = ../Spot-On.d
macdeployqt.extra = $$[QT_INSTALL_BINS]/macdeployqt \
                    ../Spot-On.d/Spot-On-Web-Server-Child.app \
                    -executable=../Spot-On.d/Spot-On-Web-Server-Child.app/Contents/MacOS/Spot-On-Web-Server-Child
macdeployqt.path  = Spot-On-Web-Server-Child.app
preinstall.extra  = rm -rf ../Spot-On.d/Spot-On-Web-Server-Child.app/*
preinstall.path   = ../Spot-On.d

INSTALLS = preinstall \
           copy \
           macdeployqt
}
