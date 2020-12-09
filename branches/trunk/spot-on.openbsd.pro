purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.openbsd.qt5.pro \
			Kernel/spot-on-kernel.openbsd.qt5.pro
TEMPLATE	=	subdirs
