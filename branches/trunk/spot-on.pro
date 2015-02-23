purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.pro \
			Kernel/spot-on-kernel.pro
TEMPLATE	=	subdirs
