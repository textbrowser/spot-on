cache()
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel/spot-on-kernel.freebsd.pro \
                      Kernel/spot-on-web-server-child.pro \
                      spot-on-gui.freebsd.pro
TEMPLATE	    = subdirs
