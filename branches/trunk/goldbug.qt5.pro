cache()
purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	goldbug-gui.qt5.pro \
			Kernel/spot-on-kernel.qt5.pro
TEMPLATE	=	subdirs
