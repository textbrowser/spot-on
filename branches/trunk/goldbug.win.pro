cache()
purge.commands = del /F *\\*~ && del /F *~

CONFIG		+=	ordered
QMAKE_EXTRA_TARGETS = purge
SUBDIRS		=	goldbug-gui.win.pro \
			Kernel\\spot-on-kernel.win.pro
TEMPLATE	=	subdirs
