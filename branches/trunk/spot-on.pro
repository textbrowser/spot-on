cache()
doxygen.commands = doxygen spot-on.doxygen
purge.commands = rm -f */*~ *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = doxygen purge
SUBDIRS		=	spot-on-gui.pro \
			Kernel/spot-on-kernel.pro
TEMPLATE	=	subdirs
