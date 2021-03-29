cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS	   	    = spot-on-gui.arm.pro \
		      Kernel/spot-on-kernel.arm.pro
TEMPLATE	    = subdirs
