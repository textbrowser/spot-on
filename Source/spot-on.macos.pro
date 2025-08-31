cache()
dmg.commands   = make install && \
                 hdiutil create Spot-On.d.dmg -srcfolder Spot-On.d
purge.commands = rm -f */*~ *~

QMAKE_EXTRA_TARGETS = dmg purge

# Order of project files is important. For example, the dmg target
# expects some order.

SUBDIRS	 = spot-on-gui.macos.pro \
           Kernel/spot-on-kernel.macos.pro \
           Kernel/spot-on-web-server-child.pro
TEMPLATE = subdirs
