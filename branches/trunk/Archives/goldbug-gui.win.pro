include(spot-on-gui.win.pro)
include(goldbug-gui-source.windows.pro)

DEFINES         += SPOTON_GOLDBUG
DEFINES         -= SPOTON_GPGME_ENABLED
INSTALLS        -= libgpgme1 \
                   libgpgme2
PROJECTNAME	= GoldBug
QMAKE_CLEAN     += GoldBug
QMAKE_DISTCLEAN += -r debug \
                   object_script.GoldBug.Debug \
                   object_script.GoldBug.Release
RC_FILE		= Icons\\Resources\\goldbug.rc
TARGET		= GoldBug