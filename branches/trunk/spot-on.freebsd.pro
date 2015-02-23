purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.freebsd.pro \
			Kernel/spot-on-kernel.freebsd.pro
TEMPLATE	=	subdirs
