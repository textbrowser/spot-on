cache()
purge.commands = del /F *\\*~ && del /F *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel\\spot-on-kernel.windows.pro \
                      Kernel\\spot-on-web-server-child.pro \
                      spot-on-gui.windows.pro
TEMPLATE	    = subdirs
