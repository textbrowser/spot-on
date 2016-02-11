purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.powerpc.pro \
			Kernel/spot-on-kernel.powerpc.pro
TEMPLATE	=	subdirs
