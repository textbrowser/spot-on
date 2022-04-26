include(spot-on-gui.win.pro)

DEFINES         += SPOTON_GOLDBUG
PROJECTNAME	= GoldBug
QMAKE_CLEAN     += GoldBug
QMAKE_DISTCLEAN += -r debug \
                   object_script.GoldBug.Debug \
                   object_script.GoldBug.Release
RC_FILE		= Icons\\Resources\\goldbug.rc
TARGET		= GoldBug
