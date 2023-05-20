cache()
purge.commands = del /F *\\*~ && del /F *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = goldbug-gui.win.pro \
		      Kernel\\spot-on-kernel.win.pro
TEMPLATE	    = subdirs
