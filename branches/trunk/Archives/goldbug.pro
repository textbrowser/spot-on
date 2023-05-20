cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = goldbug-gui.pro \
		      Kernel/spot-on-kernel.pro
TEMPLATE	    = subdirs
