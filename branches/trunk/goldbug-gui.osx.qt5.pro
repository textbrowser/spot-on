cache()
libntru.target = libntru.dylib
libntru.commands = $(MAKE) -C ../../libNTRU
libntru.depends =
libspoton.target = libspoton.dylib
libspoton.commands = $(MAKE) -C ../../libSpotOn library
libspoton.depends =

TEMPLATE	= app
LANGUAGE	= C++
QT		+= concurrent core gui multimedia network sql widgets
CONFIG		+= app_bundle qt release warn_on

# The function gcry_kdf_derive() is available in version
# 1.5.0 of the gcrypt library.

DEFINES += SPOTON_GOLDBUG \
           SPOTON_LINKED_WITH_LIBGEOIP \
           SPOTON_LINKED_WITH_LIBNTRU \
	   SPOTON_LINKED_WITH_LIBPTHREAD \
           SPOTON_SCTP_ENABLED

# Unfortunately, the clean target assumes too much knowledge
# about the internals of libNTRU and libSpotOn.

QMAKE_CLEAN     += GoldBug ../../libNTRU/*.dylib ../../libNTRU/src/*.o \
                   ../../libNTRU/src/*.s \
                   ../../libSpotOn/*.dylib ../../libSpotOn/*.o \
		   ../../libSpotOn/test
QMAKE_CXX = clang++
QMAKE_DISTCLEAN += -r temp .qmake.cache .qmake.stash
QMAKE_CXXFLAGS_RELEASE += -fPIE -fstack-protector-all -fwrapv \
			  -mtune=generic \
			  -Wall -Wcast-align -Wcast-qual \
                          -Werror -Wextra \
			  -Woverloaded-virtual -Wpointer-arith \
			  -Wstack-protector -Wstrict-overflow=5
QMAKE_EXTRA_TARGETS = libntru libspoton purge
QMAKE_LFLAGS_RELEASE =
QMAKE_LFLAGS_RPATH =
INCLUDEPATH	+= . ../../. GUI \
                   /usr/local/include /usr/local/opt
ICON		= Icons/Logo/goldbug.icns
LIBS		+= -L../../libNTRU -lntru \
                   -L../../libSpotOn -lspoton \
                   -L/usr/local/lib -L/usr/local/opt/curl/lib \
                   -L/usr/local/opt/openssl/lib -lGeoIP \
                   -lcrypto -lcurl -lgcrypt -lgpg-error -lssl \
                   -framework AppKit -framework Cocoa
PRE_TARGETDEPS = libntru.dylib libspoton.dylib
OBJECTS_DIR = temp/obj
UI_DIR = temp/ui
MOC_DIR = temp/moc
RCC_DIR = temp/rcc

FORMS           = GoldBug-UI/adaptiveechoprompt.ui \
		  GoldBug-UI/buzzpage.ui \
		  GoldBug-UI/chatwindow.ui \
		  GoldBug-UI/controlcenter.ui \
		  GoldBug-UI/encryptfile.ui \
		  GoldBug-UI/ipinformation.ui \
		  GoldBug-UI/keyboard.ui \
                  GoldBug-UI/logviewer.ui \
		  GoldBug-UI/options.ui \
                  GoldBug-UI/passwordprompt.ui \
		  GoldBug-UI/poptastic-retrophone-settings.ui \
		  GoldBug-UI/postgresqlconnect.ui \
		  GoldBug-UI/rosetta.ui \
                  GoldBug-UI/starbeamanalyzer.ui \
		  GoldBug-UI/statusbar.ui

UI_HEADERS_DIR  = GUI

HEADERS		= Common/spot-on-external-address.h \
		  GUI/spot-on.h \
		  GUI/spot-on-buzzpage.h \
		  GUI/spot-on-chatwindow.h \
		  GUI/spot-on-encryptfile.h \
		  GUI/spot-on-logviewer.h \
		  GUI/spot-on-rosetta.h \
                  GUI/spot-on-starbeamanalyzer.h \
		  GUI/spot-on-tabwidget.h \
		  GUI/spot-on-textedit.h

SOURCES		= Common/spot-on-crypt.cc \
		  Common/spot-on-crypt-ntru.cc \
		  Common/spot-on-external-address.cc \
		  Common/spot-on-misc.cc \
		  GUI/spot-on-a.cc \
		  GUI/spot-on-b.cc \
		  GUI/spot-on-buzzpage.cc \
		  GUI/spot-on-c.cc \
		  GUI/spot-on-chatwindow.cc \
		  GUI/spot-on-d.cc \
		  GUI/spot-on-e.cc \
		  GUI/spot-on-encryptfile.cc \
		  GUI/spot-on-logviewer.cc \
		  GUI/spot-on-reencode.cc \
		  GUI/spot-on-rosetta.cc \
		  GUI/spot-on-smp.cc \
                  GUI/spot-on-starbeamanalyzer.cc \
		  GUI/spot-on-tabwidget.cc \
		  GUI/spot-on-textedit.cc \
		  GUI/spot-on-urls.cc \
		  GUI/spot-on-urls-search.cc

OBJECTIVE_HEADERS += Common/CocoaInitializer.h
OBJECTIVE_SOURCES += Common/CocoaInitializer.mm

TRANSLATIONS    = Translations/spot-on_af.ts \
                  Translations/spot-on_al.ts \
                  Translations/spot-on_am.ts \
                  Translations/spot-on_ar.ts \
                  Translations/spot-on_as.ts \
                  Translations/spot-on_az.ts \
                  Translations/spot-on_be.ts \
                  Translations/spot-on_bd.ts \
                  Translations/spot-on_bg.ts \
                  Translations/spot-on_ca.ts \
                  Translations/spot-on_cr.ts \
                  Translations/spot-on_cz.ts \
                  Translations/spot-on_de.ts \
                  Translations/spot-on_dk.ts \
                  Translations/spot-on_ee.ts \
                  Translations/spot-on_es.ts \
                  Translations/spot-on_eo.ts \
                  Translations/spot-on_et.ts \
                  Translations/spot-on_eu.ts \
                  Translations/spot-on_fi.ts \
                  Translations/spot-on_fr.ts \
                  Translations/spot-on_gl.ts \
                  Translations/spot-on_gr.ts \
                  Translations/spot-on_hb.ts \
                  Translations/spot-on_hi.ts \
                  Translations/spot-on_hr.ts \
                  Translations/spot-on_hu.ts \
                  Translations/spot-on_it.ts \
                  Translations/spot-on_il.ts \
                  Translations/spot-on_ie.ts \
                  Translations/spot-on_id.ts \
                  Translations/spot-on_ja.ts \
                  Translations/spot-on_kk.ts \
                  Translations/spot-on_kn.ts \
                  Translations/spot-on_ko.ts \
                  Translations/spot-on_ky.ts \
                  Translations/spot-on_ku.ts \
                  Translations/spot-on_lt.ts \
                  Translations/spot-on_lk.ts \
                  Translations/spot-on_lv.ts \
                  Translations/spot-on_ml.ts \
                  Translations/spot-on_mk.ts \
                  Translations/spot-on_mn.ts \
                  Translations/spot-on_ms.ts \
                  Translations/spot-on_my.ts \
                  Translations/spot-on_mr.ts \
                  Translations/spot-on_mt.ts \
                  Translations/spot-on_nl.ts \
                  Translations/spot-on_no.ts \
                  Translations/spot-on_np.ts \
                  Translations/spot-on_pl.ts \
                  Translations/spot-on_pa.ts \
                  Translations/spot-on_pt.ts \
                  Translations/spot-on_ps.ts \
                  Translations/spot-on_ro.ts \
                  Translations/spot-on_ru.ts \
                  Translations/spot-on_rw.ts \
                  Translations/spot-on_sv.ts \
                  Translations/spot-on_sk.ts \
                  Translations/spot-on_sl.ts \
                  Translations/spot-on_sr.ts \
                  Translations/spot-on_sq.ts \
                  Translations/spot-on_sw.ts \
                  Translations/spot-on_th.ts \
                  Translations/spot-on_tr.ts \
                  Translations/spot-on_vn.ts \
                  Translations/spot-on_zh.ts \
                  Translations/spot-on_zh_TW.ts \
                  Translations/spot-on_zh_HK.ts

RESOURCES	= Icons/icons.qrc \
		  Sounds/sounds.qrc \
		  Translations/translations.qrc

TARGET		= GoldBug
PROJECTNAME	= GoldBug

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo

goldbug.path		= /Applications/GoldBug.d/GoldBug.app
goldbug.files		= GoldBug.app/*
install1.path           = /Applications/GoldBug.d
install1.files          = spot-on-neighbors.txt
libgeoip_data_install.path = /Applications/GoldBug.d/GeoIP
libgeoip_data_install.files = ../../GeoIP/Data/GeoIP.dat
libntru_install.path  = .
libntru_install.extra = cp ../../libNTRU/libntru.dylib ./GoldBug.app/Contents/Frameworks/libntru.dylib && install_name_tool -change ../../libNTRU/libntru.dylib @executable_path/../Frameworks/libntru.dylib ./GoldBug.app/Contents/MacOS/GoldBug
libspoton_install.path  = .
libspoton_install.extra = cp ../../libSpotOn/libspoton.dylib ./GoldBug.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change /usr/local/lib/libgcrypt.20.dylib @loader_path/libgcrypt.20.dylib ./GoldBug.app/Contents/Frameworks/libspoton.dylib && install_name_tool -change ../../libSpotOn/libspoton.dylib @executable_path/../Frameworks/libspoton.dylib ./GoldBug.app/Contents/MacOS/GoldBug
lrelease.extra          = $$[QT_INSTALL_BINS]/lrelease goldbug-gui.osx.qt5.pro
lrelease.path           = .
lupdate.extra           = $$[QT_INSTALL_BINS]/lupdate goldbug-gui.osx.qt5.pro
lupdate.path            = .
macdeployqt.path        = ./GoldBug.app
macdeployqt.extra       = $$[QT_INSTALL_BINS]/macdeployqt ./GoldBug.app -verbose=0
preinstall.path         = /Applications/GoldBug.d
preinstall.extra        = rm -rf /Applications/GoldBug.d/GoldBug.app/*
postinstall.path	= /Applications/GoldBug.d
postinstall.extra	= find /Applications/GoldBug.d -name .svn -exec rm -rf {} \\; 2>/dev/null; echo
translations.path 	= /Applications/GoldBug.d/Translations
translations.files	= Translations/*.qm

# Prevent qmake from stripping everything.

QMAKE_STRIP	= echo
INSTALLS	= macdeployqt \
                  preinstall \
                  install1 \
                  libgeoip_data_install \
                  libntru_install \
                  libspoton_install \
                  lupdate \
                  lrelease \
                  translations \
                  goldbug \
                  postinstall
