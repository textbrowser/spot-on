cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel/spot-on-kernel.arm.pro spot-on-gui.arm.pro
TEMPLATE	    = subdirs
