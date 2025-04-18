cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel/spot-on-kernel.powerpc.pro spot-on-gui.powerpc.pro
TEMPLATE	    = subdirs
