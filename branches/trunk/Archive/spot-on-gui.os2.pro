include(spot-on-gui-source.pro)
libspoton.target = libspotn.dll
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql webkit
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         -= SPOTON_LINKED_WITH_LIBGEOIP
DEFINES		+= SPOTON_LINKED_WITH_LIBPTHREAD

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += Spot-On ../../libSpotOn/libspotn.dll \
                   ../../libNTRU/src/*.s \
		   ../../libSpotOn/*.o \
		   ../../libSpotOn/test.exe
QMAKE_CXXFLAGS_RELEASE += -fwrapv -mtune=generic -pie \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libspoton purge
INCLUDEPATH	+= . ../../. GUI \
		   ../../PostgreSQL/Include.win32 \
		   ../../libSpotOn/Include.win32 \
		   u:/usr/local473/include
LIBS		+= -L../../libSpotOn -L../../libSpotOn/Libraries.win32 \
		   -Lu:/usr/local473/lib \
		   -lcrypto -lcurl -lgcrypt \
		   -lgpg-error -lmmap -lpq -lpthread -lspoton -lssl -lssp_s
PRE_TARGETDEPS = libspotn.dll

win32:RC_FILE	= Icons/Resources/spot-on.rc

TARGET		= Spot-On
PROJECTNAME	= Spot-On
