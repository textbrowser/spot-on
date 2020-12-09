cache()
purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.freebsd.qt5.pro \
			Kernel/spot-on-kernel.freebsd.qt5.pro
TEMPLATE	=	subdirs
