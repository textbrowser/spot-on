cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel/spot-on-kernel.freebsd.pro spot-on-gui.freebsd.pro
TEMPLATE	    = subdirs
