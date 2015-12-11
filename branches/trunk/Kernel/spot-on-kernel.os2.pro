include(spot-on-kernel-source.pro)
libspoton.target = libspotn.dll
libspoton.commands = $(MAKE) -C ../../../libSpotOn library
libspoton.depends =
purge.commands = del /F *~

TEMPLATE	= app
LANGUAGE	= C++
QT		+= network sql
QT		-= gui
CONFIG		+= qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES         -= SPOTON_LINKED_WITH_LIBGEOIP
DEFINES		+= SPOTON_LINKED_WITH_LIBPTHREAD

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libSpotOn.

QMAKE_CLEAN     += ../../release/Spot-On-Kernel \
		   ../../../libSpotOn/libspotn.dll \
		   ../../../libSpotOn/*.o ../../../libSpotOn/test.exe
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -mtune=generic -fwrapv -pie -O3 \
			  -Wall -Wcast-align -Wcast-qual \
			  -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libspoton purge
INCLUDEPATH	+= . ../. ../../../. ../../../libSpotOn/Include.win32 \
		   u:/usr/local473/include
LIBS		+= -L../../../libSpotOn \
		   -L../../../libSpotOn/Libraries.win32 \
		   -Lu:/usr/local473/lib \
		   -lcrypto -lcurl -lgcrypt -lgpg-error -lmmap -lpq \
		   -lpthread -lspoton -lssl -lssp_s
PRE_TARGETDEPS = libspotn.dll

TARGET		= Spot-On-Kernel
PROJECTNAME	= Spot-On-Kernel
