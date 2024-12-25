cache()
dmg.commands = make install && hdiutil create Spot-On.d.dmg \
               -srcfolder Spot-On.d
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = dmg purge
SUBDIRS		    = Kernel/spot-on-kernel.macos.pro spot-on-gui.macos.pro
TEMPLATE	    = subdirs
