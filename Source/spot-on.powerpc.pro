cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel/spot-on-kernel.powerpc.pro \
                      Kernel/spot-on-web-server-child.pro \
                      spot-on-gui.powerpc.pro
TEMPLATE	    = subdirs
