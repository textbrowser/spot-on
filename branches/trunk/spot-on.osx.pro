cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = spot-on-gui.osx.pro \
		      Kernel/spot-on-kernel.osx.pro
TEMPLATE	    = subdirs
