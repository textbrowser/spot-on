purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.arm.pro \
			Kernel/spot-on-kernel.arm.pro
TEMPLATE	=	subdirs
