cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel/spot-on-kernel.macos.pro spot-on-gui.macos.pro
TEMPLATE	    = subdirs
