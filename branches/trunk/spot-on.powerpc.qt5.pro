cache()
purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.powerpc.qt5.pro \
			Kernel/spot-on-kernel.powerpc.qt5.pro
TEMPLATE	=	subdirs
