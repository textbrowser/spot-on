purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.sparc64.pro \
			Kernel/spot-on-kernel.sparc64.pro
TEMPLATE	=	subdirs
