purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	goldbug-gui.arm.pro \
			Kernel/spot-on-kernel.arm.pro
TEMPLATE	=	subdirs
