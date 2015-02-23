cache()
purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	spot-on-gui.osx.qt5.pro \
			Kernel/spot-on-kernel.osx.qt5.pro
TEMPLATE	=	subdirs
