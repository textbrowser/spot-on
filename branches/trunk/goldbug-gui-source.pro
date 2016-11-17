FORMS           = GoldBug-UI/spot-on-adaptive-echo-prompt.ui \
		  GoldBug-UI/spot-on-buzzpage.ui \
		  GoldBug-UI/spot-on-chatwindow.ui \
		  GoldBug-UI/spot-on-controlcenter.ui \
		  GoldBug-UI/spot-on-documentation.ui \
		  GoldBug-UI/spot-on-echo-key-share.ui \
		  GoldBug-UI/spot-on-encryptfile.ui \
		  GoldBug-UI/spot-on-encryptfile-page.ui \
		  GoldBug-UI/spot-on-forward-secrecy-algorithms-selection.ui \
		  GoldBug-UI/spot-on-ipinformation.ui \
		  GoldBug-UI/spot-on-keyboard.ui \
		  GoldBug-UI/spot-on-listener-socket-options.ui \
                  GoldBug-UI/spot-on-logviewer.ui \
		  GoldBug-UI/spot-on-notificationswindow.ui \
		  GoldBug-UI/spot-on-options.ui \
		  GoldBug-UI/spot-on-pageviewer.ui \
                  GoldBug-UI/spot-on-password-prompt.ui \
		  GoldBug-UI/spot-on-poptastic-retrophone-settings.ui \
		  GoldBug-UI/spot-on-postgresql-connect.ui \
		  GoldBug-UI/spot-on-private-application-credentials.ui \
		  GoldBug-UI/spot-on-rosetta.ui \
		  GoldBug-UI/spot-on-rss.ui \
		  GoldBug-UI/spot-on-smpwindow.ui \
                  GoldBug-UI/spot-on-starbeamanalyzer.ui \
		  GoldBug-UI/spot-on-statisticswindow.ui \
		  GoldBug-UI/spot-on-statusbar.ui \
		  GoldBug-UI/spot-on-unlock.ui \
		  GoldBug-UI/spot-on-wizard.ui

HEADERS		= Common/spot-on-external-address.h \
		  GUI/spot-on.h \
		  GUI/spot-on-buzzpage.h \
		  GUI/spot-on-chatwindow.h \
		  GUI/spot-on-documentation.h \
		  GUI/spot-on-echo-key-share.h \
		  GUI/spot-on-encryptfile.h \
		  GUI/spot-on-encryptfile-page.h \
		  GUI/spot-on-logviewer.h \
		  GUI/spot-on-pageviewer.h \
		  GUI/spot-on-rosetta.h \
		  GUI/spot-on-rss.h \
		  GUI/spot-on-smpwindow.h \
                  GUI/spot-on-starbeamanalyzer.h \
                  GUI/spot-on-tabwidget.h \
		  GUI/spot-on-textbrowser.h \
		  GUI/spot-on-textedit.h

RESOURCES	= Documentation/documentation.qrc \
		  Icons/icons.qrc \
		  Translations/translations.qrc

SOURCES		= Common/spot-on-crypt.cc \
		  Common/spot-on-crypt-mceliece.cc \
		  Common/spot-on-crypt-ntru.cc \
		  Common/spot-on-external-address.cc \
		  Common/spot-on-mceliece.cc \
		  Common/spot-on-misc.cc \
                  Common/spot-on-send.cc \
		  Common/spot-on-threefish.cc \
		  GUI/spot-on-a.cc \
		  GUI/spot-on-b.cc \
		  GUI/spot-on-buzzpage.cc \
		  GUI/spot-on-c.cc \
		  GUI/spot-on-chatwindow.cc \
		  GUI/spot-on-d.cc \
		  GUI/spot-on-documentation.cc \
		  GUI/spot-on-e.cc \
		  GUI/spot-on-echo-key-share.cc \
		  GUI/spot-on-encryptfile.cc \
		  GUI/spot-on-encryptfile-page.cc \
		  GUI/spot-on-f.cc \
		  GUI/spot-on-g.cc \
		  GUI/spot-on-logviewer.cc \
		  GUI/spot-on-pageviewer.cc \
		  GUI/spot-on-reencode.cc \
		  GUI/spot-on-rosetta.cc \
		  GUI/spot-on-rss.cc \
		  GUI/spot-on-smp.cc \
		  GUI/spot-on-smpwindow.cc \
                  GUI/spot-on-starbeamanalyzer.cc \
		  GUI/spot-on-tabwidget.cc \
		  GUI/spot-on-textbrowser.cc \
		  GUI/spot-on-textedit.cc \
		  GUI/spot-on-urls.cc \
		  GUI/spot-on-urls-search.cc

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

UI_HEADERS_DIR  = GUI
