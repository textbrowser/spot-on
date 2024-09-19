cache()
purge.commands = del /F *\\*~ && del /F *~

QMAKE_EXTRA_TARGETS = purge
SUBDIRS		    = Kernel\\spot-on-kernel.windows.pro \
                      spot-on-gui.windows.pro
TEMPLATE	    = subdirs
