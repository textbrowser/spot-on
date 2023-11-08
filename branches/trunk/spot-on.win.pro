cache()
purge.commands = del /F *\\*~ && del /F *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel\\spot-on-kernel.win.pro spot-on-gui.win.pro
TEMPLATE	    = subdirs
