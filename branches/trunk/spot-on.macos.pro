cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel/spot-on-kernel.osx.pro spot-on-gui.osx.pro
TEMPLATE	    = subdirs
