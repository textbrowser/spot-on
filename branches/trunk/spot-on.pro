cache()
doxygen.commands = doxygen spot-on.doxygen
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = doxygen purge
SUBDIRS		    = Kernel/spot-on-kernel.pro spot-on-gui.pro
TEMPLATE	    = subdirs
