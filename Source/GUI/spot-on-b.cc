/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from Spot-On without specific prior written permission.
**
** SPOT-ON IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** SPOT-ON, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <QSslKey>
#include <QtMath>
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#include <qbluetoothhostinfo.h>
#include <qbluetoothlocaldevice.h>
#endif

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_UNIX)
extern "C"
{
#include <signal.h>
}
#endif

#include "spot-on-defines.h"
#include "spot-on-smp.h"
#include "spot-on.h"
#include "ui_spot-on-goldbug.h"

QByteArray spoton::copyMyChatPublicKey(void) const
{
  if(!m_crypts.value("chat", nullptr) ||
     !m_crypts.value("chat-signature", nullptr))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  auto ok = true;

  name = m_settings.value("gui/nodeName", "unknown").toByteArray();
  mPublicKey = m_crypts.value("chat")->publicKey(&ok);

  if(ok)
    mSignature = m_crypts.value("chat")->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("chat-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("chat-signature")->digitalSignature
      (sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("chat").toBase64() + "@" +
      name.toBase64() + "@" +
      qCompress(mPublicKey).toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

QByteArray spoton::copyMyEmailPublicKey(void) const
{
  if(!m_crypts.value("email", nullptr) ||
     !m_crypts.value("email-signature", nullptr))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  auto ok = true;

  mPublicKey = m_crypts.value("email")->publicKey(&ok);
  name = m_settings.value("gui/emailName", "unknown").toByteArray();

  if(ok)
    mSignature = m_crypts.value("email")->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("email-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("email-signature")->digitalSignature
      (sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("email").toBase64() + "@" +
      name.toBase64() + "@" +
      qCompress(mPublicKey).toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

QByteArray spoton::copyMyPoptasticPublicKey(void) const
{
  if(!m_crypts.value("poptastic", nullptr) ||
     !m_crypts.value("poptastic-signature", nullptr))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  auto ok = true;

  name = poptasticName();

  if(name.isEmpty())
    name = "unknown@unknown.org";

  mPublicKey = m_crypts.value("poptastic")->publicKey(&ok);

  if(ok)
    mSignature = m_crypts.value("poptastic")->digitalSignature
      (mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("poptastic-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("poptastic-signature")->digitalSignature
      (sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("poptastic").toBase64() + "@" +
      name.toBase64() + "@" +
      qCompress(mPublicKey).toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

QByteArray spoton::copyMyRosettaPublicKey(void) const
{
  if(!m_crypts.value("rosetta", nullptr) ||
     !m_crypts.value("rosetta-signature", nullptr))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  auto ok = true;

  name = m_settings.value("gui/rosettaName", "unknown").toByteArray();
  mPublicKey = m_crypts.value("rosetta")->publicKey(&ok);

  if(ok)
    mSignature = m_crypts.value("rosetta")->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("rosetta-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("rosetta-signature")->digitalSignature
      (sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("rosetta").toBase64() + "@" +
      name.toBase64() + "@" +
      qCompress(mPublicKey).toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

QByteArray spoton::copyMyUrlPublicKey(void) const
{
  if(!m_crypts.value("url", nullptr) ||
     !m_crypts.value("url-signature", nullptr))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  auto ok = true;

  mPublicKey = m_crypts.value("url")->publicKey(&ok);
  name = m_settings.value("gui/urlName", "unknown").toByteArray();

  if(ok)
    mSignature = m_crypts.value("url")->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("url-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("url-signature")->digitalSignature
      (sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("url").toBase64() + "@" +
      name.toBase64() + "@" +
      qCompress(mPublicKey).toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

QPixmap spoton::pixmapForCountry(const QString &country) const
{
  if(country == "Afghanistan")
    return QPixmap(":/Flags/af.png");
  else if(country == "Albania")
    return QPixmap(":/Flags/al.png");
  else if(country == "Algeria")
    return QPixmap(":/Flags/dz.png");
  else if(country == "AmericanSamoa")
    return QPixmap(":/Flags/as.png");
  else if(country == "Angola")
    return QPixmap(":/Flags/ao.png");
  else if(country == "Argentina")
    return QPixmap(":/Flags/ar.png");
  else if(country == "Armenia")
    return QPixmap(":/Flags/am.png");
  else if(country == "Aruba")
    return QPixmap(":/Flags/aw.png");
  else if(country == "Australia")
    return QPixmap(":/Flags/au.png");
  else if(country == "Austria")
    return QPixmap(":/Flags/at.png");
  else if(country == "Azerbaijan")
    return QPixmap(":/Flags/az.png");
  else if(country == "Bahrain")
    return QPixmap(":/Flags/bh.png");
  else if(country == "Bangladesh")
    return QPixmap(":/Flags/bd.png");
  else if(country == "Barbados")
    return QPixmap(":/Flags/bb.png");
  else if(country == "Belarus")
    return QPixmap(":/Flags/by.png");
  else if(country == "Belgium")
    return QPixmap(":/Flags/be.png");
  else if(country == "Belize")
    return QPixmap(":/Flags/bz.png");
  else if(country == "Benin")
    return QPixmap(":/Flags/bj.png");
  else if(country == "Bermuda")
    return QPixmap(":/Flags/bm.png");
  else if(country == "Bhutan")
    return QPixmap(":/Flags/bt.png");
  else if(country == "Bolivia")
    return QPixmap(":/Flags/bo.png");
  else if(country == "BosniaAndHerzegowina")
    return QPixmap(":/Flags/ba.png");
  else if(country == "Botswana")
    return QPixmap(":/Flags/bw.png");
  else if(country == "Brazil")
    return QPixmap(":/Flags/br.png");
  else if(country == "BruneiDarussalam")
    return QPixmap(":/Flags/bn.png");
  else if(country == "Bulgaria")
    return QPixmap(":/Flags/bg.png");
  else if(country == "BurkinaFaso")
    return QPixmap(":/Flags/bf.png");
  else if(country == "Burundi")
    return QPixmap(":/Flags/bi.png");
  else if(country == "Cambodia")
    return QPixmap(":/Flags/kh.png");
  else if(country == "Cameroon")
    return QPixmap(":/Flags/cm.png");
  else if(country == "Canada")
    return QPixmap(":/Flags/ca.png");
  else if(country == "CapeVerde")
    return QPixmap(":/Flags/cv.png");
  else if(country == "CentralAfricanRepublic")
    return QPixmap(":/Flags/cf.png");
  else if(country == "Chad")
    return QPixmap(":/Flags/td.png");
  else if(country == "Chile")
    return QPixmap(":/Flags/cl.png");
  else if(country == "China")
    return QPixmap(":/Flags/cn.png");
  else if(country == "Colombia")
    return QPixmap(":/Flags/co.png");
  else if(country == "Comoros")
    return QPixmap(":/Flags/km.png");
  else if(country == "CostaRica")
    return QPixmap(":/Flags/cr.png");
  else if(country == "Croatia")
    return QPixmap(":/Flags/hr.png");
  else if(country == "Cyprus")
    return QPixmap(":/Flags/cy.png");
  else if(country == "CzechRepublic")
    return QPixmap(":/Flags/cz.png");
  else if(country == "Default")
    return QPixmap(":/Flags/us.png");
  else if(country == "DemocraticRepublicOfCongo")
    return QPixmap(":/Flags/cd.png");
  else if(country == "Denmark")
    return QPixmap(":/Flags/dk.png");
  else if(country == "Djibouti")
    return QPixmap(":/Flags/dj.png");
  else if(country == "DominicanRepublic")
    return QPixmap(":/Flags/do.png");
  else if(country == "Ecuador")
    return QPixmap(":/Flags/ec.png");
  else if(country == "Egypt")
    return QPixmap(":/Flags/eg.png");
  else if(country == "ElSalvador")
    return QPixmap(":/Flags/sv.png");
  else if(country == "EquatorialGuinea")
    return QPixmap(":/Flags/gq.png");
  else if(country == "Eritrea")
    return QPixmap(":/Flags/er.png");
  else if(country == "Estonia")
    return QPixmap(":/Flags/ee.png");
  else if(country == "Ethiopia")
    return QPixmap(":/Flags/et.png");
  else if(country == "FaroeIslands")
    return QPixmap(":/Flags/fo.png");
  else if(country == "Finland")
    return QPixmap(":/Flags/fi.png");
  else if(country == "France")
    return QPixmap(":/Flags/fr.png");
  else if(country == "FrenchGuiana")
    return QPixmap(":/Flags/gy.png");
  else if(country == "Gabon")
    return QPixmap(":/Flags/ga.png");
  else if(country == "Georgia")
    return QPixmap(":/Flags/ge.png");
  else if(country == "Germany")
    return QPixmap(":/Flags/de.png");
  else if(country == "Ghana")
    return QPixmap(":/Flags/gh.png");
  else if(country == "Greece")
    return QPixmap(":/Flags/gr.png");
  else if(country == "Greenland")
    return QPixmap(":/Flags/gl.png");
  else if(country == "Guadeloupe")
    return QPixmap(":/Flags/fr.png");
  else if(country == "Guam")
    return QPixmap(":/Flags/gu.png");
  else if(country == "Guatemala")
    return QPixmap(":/Flags/gt.png");
  else if(country == "Guinea")
    return QPixmap(":/Flags/gn.png");
  else if(country == "GuineaBissau")
    return QPixmap(":/Flags/gw.png");
  else if(country == "Guyana")
    return QPixmap(":/Flags/gy.png");
  else if(country == "Honduras")
    return QPixmap(":/Flags/hn.png");
  else if(country == "HongKong")
    return QPixmap(":/Flags/hk.png");
  else if(country == "Hungary")
    return QPixmap(":/Flags/hu.png");
  else if(country == "Iceland")
    return QPixmap(":/Flags/is.png");
  else if(country == "India")
    return QPixmap(":/Flags/in.png");
  else if(country == "Indonesia")
    return QPixmap(":/Flags/id.png");
  else if(country == "Iran")
    return QPixmap(":/Flags/ir.png");
  else if(country == "Iraq")
    return QPixmap(":/Flags/iq.png");
  else if(country == "Ireland")
    return QPixmap(":/Flags/ie.png");
  else if(country == "Israel")
    return QPixmap(":/Flags/il.png");
  else if(country == "Italy")
    return QPixmap(":/Flags/it.png");
  else if(country == "IvoryCoast")
    return QPixmap(":/Flags/ci.png");
  else if(country == "Jamaica")
    return QPixmap(":/Flags/jm.png");
  else if(country == "Japan")
    return QPixmap(":/Flags/jp.png");
  else if(country == "Jordan")
    return QPixmap(":/Flags/jo.png");
  else if(country == "Kazakhstan")
    return QPixmap(":/Flags/kz.png");
  else if(country == "Kenya")
    return QPixmap(":/Flags/ke.png");
  else if(country == "Kuwait")
    return QPixmap(":/Flags/kw.png");
  else if(country == "Kyrgyzstan")
    return QPixmap(":/Flags/kg.png");
  else if(country == "Lao")
    return QPixmap(":/Flags/la.png");
  else if(country == "LatinAmericaAndTheCaribbean")
    return QPixmap(":/Flags/mx.png");
  else if(country == "Latvia")
    return QPixmap(":/Flags/lv.png");
  else if(country == "Lebanon")
    return QPixmap(":/Flags/lb.png");
  else if(country == "Lesotho")
    return QPixmap(":/Flags/ls.png");
  else if(country == "Liberia")
    return QPixmap(":/Flags/lr.png");
  else if(country == "LibyanArabJamahiriya")
    return QPixmap(":/Flags/ly.png");
  else if(country == "Liechtenstein")
    return QPixmap(":/Flags/li.png");
  else if(country == "Lithuania")
    return QPixmap(":/Flags/lt.png");
  else if(country == "Luxembourg")
    return QPixmap(":/Flags/lu.png");
  else if(country == "Macau")
    return QPixmap(":/Flags/mo.png");
  else if(country == "Macedonia")
    return QPixmap(":/Flags/mk.png");
  else if(country == "Madagascar")
    return QPixmap(":/Flags/mg.png");
  else if(country == "Malaysia")
    return QPixmap(":/Flags/my.png");
  else if(country == "Mali")
    return QPixmap(":/Flags/ml.png");
  else if(country == "Malta")
    return QPixmap(":/Flags/mt.png");
  else if(country == "MarshallIslands")
    return QPixmap(":/Flags/mh.png");
  else if(country == "Martinique")
    return QPixmap(":/Flags/fr.png");
  else if(country == "Mauritius")
    return QPixmap(":/Flags/mu.png");
  else if(country == "Mayotte")
    return QPixmap(":/Flags/yt.png");
  else if(country == "Mexico")
    return QPixmap(":/Flags/mx.png");
  else if(country == "Moldova")
    return QPixmap(":/Flags/md.png");
  else if(country == "Monaco")
    return QPixmap(":/Flags/mc.png");
  else if(country == "Mongolia")
    return QPixmap(":/Flags/mn.png");
  else if(country == "Montenegro")
    return QPixmap(":/Flags/me.png");
  else if(country == "Morocco")
    return QPixmap(":/Flags/ma.png");
  else if(country == "Mozambique")
    return QPixmap(":/Flags/mz.png");
  else if(country == "Myanmar")
    return QPixmap(":/Flags/mm.png");
  else if(country == "Namibia")
    return QPixmap(":/Flags/na.png");
  else if(country == "Nepal")
    return QPixmap(":/Flags/np.png");
  else if(country == "Netherlands")
    return QPixmap(":/Flags/nl.png");
  else if(country == "NewZealand")
    return QPixmap(":/Flags/nz.png");
  else if(country == "Nicaragua")
    return QPixmap(":/Flags/ni.png");
  else if(country == "Niger")
    return QPixmap(":/Flags/ne.png");
  else if(country == "Nigeria")
    return QPixmap(":/Flags/ng.png");
  else if(country == "NorthernMarianaIslands")
    return QPixmap(":/Flags/mp.png");
  else if(country == "Norway")
    return QPixmap(":/Flags/no.png");
  else if(country == "Oman")
    return QPixmap(":/Flags/om.png");
  else if(country == "Pakistan")
    return QPixmap(":/Flags/pk.png");
  else if(country == "Panama")
    return QPixmap(":/Flags/pa.png");
  else if(country == "Paraguay")
    return QPixmap(":/Flags/py.png");
  else if(country == "PeoplesRepublicOfCongo")
    return QPixmap(":/Flags/cg.png");
  else if(country == "Peru")
    return QPixmap(":/Flags/pe.png");
  else if(country == "Philippines")
    return QPixmap(":/Flags/ph.png");
  else if(country == "Poland")
    return QPixmap(":/Flags/pl.png");
  else if(country == "Portugal")
    return QPixmap(":/Flags/pt.png");
  else if(country == "PuertoRico")
    return QPixmap(":/Flags/pr.png");
  else if(country == "Qatar")
    return QPixmap(":/Flags/qa.png");
  else if(country == "RepublicOfKorea")
    return QPixmap(":/Flags/kr.png");
  else if(country == "Reunion")
    return QPixmap(":/Flags/fr.png");
  else if(country == "Romania")
    return QPixmap(":/Flags/ro.png");
  else if(country == "RussianFederation")
    return QPixmap(":/Flags/ru.png");
  else if(country == "Rwanda")
    return QPixmap(":/Flags/rw.png");
  else if(country == "Saint Barthelemy")
    return QPixmap(":/Flags/bl.png");
  else if(country == "Saint Martin")
    return QPixmap(":/Flags/fr.png");
  else if(country == "SaoTomeAndPrincipe")
    return QPixmap(":/Flags/st.png");
  else if(country == "SaudiArabia")
    return QPixmap(":/Flags/sa.png");
  else if(country == "Senegal")
    return QPixmap(":/Flags/sn.png");
  else if(country == "Serbia")
    return QPixmap(":/Flags/rs.png");
  else if(country == "SerbiaAndMontenegro")
    return QPixmap(":/Flags/rs.png");
  else if(country == "Singapore")
    return QPixmap(":/Flags/sg.png");
  else if(country == "Slovakia")
    return QPixmap(":/Flags/sk.png");
  else if(country == "Slovenia")
    return QPixmap(":/Flags/si.png");
  else if(country == "Somalia")
    return QPixmap(":/Flags/so.png");
  else if(country == "SouthAfrica")
    return QPixmap(":/Flags/za.png");
  else if(country == "Spain")
    return QPixmap(":/Flags/es.png");
  else if(country == "SriLanka")
    return QPixmap(":/Flags/lk.png");
  else if(country == "Sudan")
    return QPixmap(":/Flags/sd.png");
  else if(country == "Swaziland")
    return QPixmap(":/Flags/sz.png");
  else if(country == "Sweden")
    return QPixmap(":/Flags/se.png");
  else if(country == "Switzerland")
    return QPixmap(":/Flags/ch.png");
  else if(country == "SyrianArabRepublic")
    return QPixmap(":/Flags/sy.png");
  else if(country == "Taiwan")
    return QPixmap(":/Flags/tw.png");
  else if(country == "Tajikistan")
    return QPixmap(":/Flags/tj.png");
  else if(country == "Tanzania")
    return QPixmap(":/Flags/tz.png");
  else if(country == "Thailand")
    return QPixmap(":/Flags/th.png");
  else if(country == "Togo")
    return QPixmap(":/Flags/tg.png");
  else if(country == "Tonga")
    return QPixmap(":/Flags/to.png");
  else if(country == "TrinidadAndTobago")
    return QPixmap(":/Flags/tt.png");
  else if(country == "Tunisia")
    return QPixmap(":/Flags/tn.png");
  else if(country == "Turkey")
    return QPixmap(":/Flags/tr.png");
  else if(country == "USVirginIslands")
    return QPixmap(":/Flags/vi.png");
  else if(country == "Uganda")
    return QPixmap(":/Flags/ug.png");
  else if(country == "Ukraine")
    return QPixmap(":/Flags/ua.png");
  else if(country == "UnitedArabEmirates")
    return QPixmap(":/Flags/ae.png");
  else if(country == "UnitedKingdom")
    return QPixmap(":/Flags/gb.png");
  else if(country == "UnitedStates")
    return QPixmap(":/Flags/us.png");
  else if(country == "UnitedStatesMinorOutlyingIslands")
    return QPixmap(":/Flags/us.png");
  else if(country == "Uruguay")
    return QPixmap(":/Flags/uy.png");
  else if(country == "Uzbekistan")
    return QPixmap(":/Flags/uz.png");
  else if(country == "Venezuela")
    return QPixmap(":/Flags/ve.png");
  else if(country == "VietNam")
    return QPixmap(":/Flags/vn.png");
  else if(country == "Yemen")
    return QPixmap(":/Flags/ye.png");
  else if(country == "Yugoslavia")
    return QPixmap(":/Flags/yu.png");
  else if(country == "Zambia")
    return QPixmap(":/Flags/zm.png");
  else if(country == "Zimbabwe")
    return QPixmap(":/Flags/zw.png");
  else
    return QPixmap(":/Flags/unknown.png");
}

Ui_spoton_mainwindow spoton::ui(void) const
{
  return m_ui;
}

bool spoton::addFriendsKey(const QByteArray &k,
			   const QString &type,
			   QWidget *parent)
{
  auto const key(k.trimmed());

  if(!parent)
    parent = this;

  if(type == "E")
    {
      if(!m_crypts.value("chat", nullptr))
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Invalid spoton_crypt object. This is a fatal flaw."));
	  QApplication::processEvents();
	  return false;
	}
      else if(!key.contains("@"))
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Please provide a normal e-mail address."));
	  QApplication::processEvents();
	  return false;
	}
      else if(key.isEmpty())
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Empty e-mail address. Really?"));
	  QApplication::processEvents();
	  return false;
	}

      QByteArray keyType("poptastic");
      QString connectionName("");
      auto const name(key.trimmed());
      auto ok = true;

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() +
	   QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    if((ok = spoton_misc::
		saveFriendshipBundle(keyType,
				     name,
				     name + "-poptastic",
				     QByteArray(),
				     -1,
				     db,
				     m_crypts.value("chat", nullptr))))
	      m_ui.friendInformation->selectAll();
	  }
	else
	  ok = false;

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      if(!ok)
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("An error occurred while attempting "
				   "to save the friendship bundle."));
	  QApplication::processEvents();
	  return false;
	}
    }
  else if(type == "K")
    {
      if(!m_crypts.value("chat", nullptr) ||
	 !m_crypts.value("email", nullptr) ||
	 !m_crypts.value("open-library", nullptr) ||
	 !m_crypts.value("poptastic", nullptr) ||
	 !m_crypts.value("rosetta", nullptr) ||
	 !m_crypts.value("url", nullptr))
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("Invalid spoton_crypt object(s). This is "
				   "a fatal flaw."));
	  QApplication::processEvents();
	  return false;
	}
      else if(key.isEmpty())
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("Empty key(s). Really?"));
	  QApplication::processEvents();
	  return false;
	}

      if(!(key.startsWith("K") || key.startsWith("k")))
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Invalid key(s). The provided text must start with either "
		"the letter K or the letter k."));
	  QApplication::processEvents();
	  return false;
	}

      auto const list(key.mid(1).split('@'));

      if(list.size() != 6)
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Irregular data. Expecting 6 entries, received %1.").
	     arg(list.size()));
	  QApplication::processEvents();
	  return false;
	}

      auto keyType(list.value(0));

      keyType = QByteArray::fromBase64(keyType);

      if(!spoton_common::SPOTON_ENCRYPTION_KEY_NAMES.contains(keyType))
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Invalid key type. Expecting 'chat', 'email', "
		"'open-library', 'poptastic', 'rosetta', or 'url'."));
	  QApplication::processEvents();
	  return false;
	}

      QByteArray myPublicKey;
      auto ok = true;

      myPublicKey = m_crypts.value(keyType)->publicKey(&ok);

      if(!ok)
	{
	  QMessageBox mb(parent);

	  mb.setIcon(QMessageBox::Question);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Unable to retrieve your %1 "
			"public key for comparison. Are you sure "
			"that you wish to accept the foreign key pair?").
		     arg(keyType.constData()));
	  mb.setWindowIcon(windowIcon());
	  mb.setWindowModality(Qt::ApplicationModal);
	  mb.setWindowTitle
	    (tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

	  if(mb.exec() != QMessageBox::Yes)
	    {
	      QApplication::processEvents();
	      return false;
	    }

	  QApplication::processEvents();
	}

      QByteArray mySPublicKey;

      mySPublicKey = m_crypts.value
	(QString("%1-signature").arg(keyType.constData()))->publicKey(&ok);

      if(!ok)
	{
	  QMessageBox mb(parent);

	  mb.setIcon(QMessageBox::Question);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Unable to retrieve your %1 signature "
			"public key for comparison. Are you sure "
			"that you wish to accept the foreign key pair?").
		     arg(keyType.constData()));
	  mb.setWindowIcon(windowIcon());
	  mb.setWindowModality(Qt::ApplicationModal);
	  mb.setWindowTitle
	    (tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

	  if(mb.exec() != QMessageBox::Yes)
	    {
	      QApplication::processEvents();
	      return false;
	    }

	  QApplication::processEvents();
	}

      auto mPublicKey(list.value(2));
      auto mSignature(list.value(3));
      auto sPublicKey(list.value(4));
      auto sSignature(list.value(5));

      mPublicKey = qUncompress(QByteArray::fromBase64(mPublicKey));
      sPublicKey = QByteArray::fromBase64(sPublicKey);

      if((mPublicKey == myPublicKey && !myPublicKey.isEmpty()) ||
	 (sPublicKey == mySPublicKey && !mySPublicKey.isEmpty()))
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("You're attempting to add your own '%1' keys. "
		"Please do not do this!").arg(keyType.constData()));
	  QApplication::processEvents();
	  return false;
	}

      mSignature = QByteArray::fromBase64(mSignature);

      if(!spoton_crypt::isValidSignature(mPublicKey, mPublicKey, mSignature))
	{
	  QMessageBox mb(parent);

	  mb.setIcon(QMessageBox::Question);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Invalid %1 public key signature. Accept?").
		     arg(keyType.constData()));
	  mb.setWindowIcon(windowIcon());
	  mb.setWindowModality(Qt::ApplicationModal);
	  mb.setWindowTitle
	    (tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

	  if(mb.exec() != QMessageBox::Yes)
	    {
	      QApplication::processEvents();
	      return false;
	    }
	}

      sSignature = QByteArray::fromBase64(sSignature);

      if(!spoton_crypt::isValidSignature(sPublicKey, sPublicKey, sSignature))
	{
	  QMessageBox mb(parent);

	  mb.setIcon(QMessageBox::Question);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Invalid %1 signature public key signature. Accept?").
		     arg(keyType.constData()));
	  mb.setWindowIcon(windowIcon());
	  mb.setWindowModality(Qt::ApplicationModal);
	  mb.setWindowTitle
	    (tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

	  if(mb.exec() != QMessageBox::Yes)
	    {
	      QApplication::processEvents();
	      return false;
	    }

	  QApplication::processEvents();
	}

      QString connectionName("");

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() +
	   QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    auto name(list.value(1));

	    name = QByteArray::fromBase64(name);

	    if((ok = spoton_misc::
		saveFriendshipBundle(keyType,
				     name,
				     mPublicKey,
				     sPublicKey,
				     -1,
				     db,
				     m_crypts.value("chat", nullptr))))
	      if((ok = spoton_misc::
		  saveFriendshipBundle(keyType + "-signature",
				       name,
				       sPublicKey,
				       QByteArray(),
				       -1,
				       db,
				       m_crypts.value("chat", nullptr))))
		m_ui.friendInformation->selectAll();
	  }
	else
	  ok = false;

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      if(!ok)
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("An error occurred while attempting "
				   "to save the friendship bundle."));
	  QApplication::processEvents();
	  return false;
	}
      else
	emit participantAdded(keyType);
    }
  else if(type == "R")
    {
      /*
      ** Now we have to perform the inverse of slotCopyFriendshipBundle().
      ** Have fun!
      */

      if(!m_crypts.value("chat", nullptr) ||
	 !m_crypts.value("email", nullptr) ||
	 !m_crypts.value("open-library", nullptr) ||
	 !m_crypts.value("poptastic", nullptr) ||
	 !m_crypts.value("rosetta", nullptr) ||
	 !m_crypts.value("url", nullptr))
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("Invalid spoton_crypt object(s). This is "
				   "a fatal flaw."));
	  QApplication::processEvents();
	  return false;
	}
      else if(key.isEmpty())
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("Empty key(s). Really?"));
	  QApplication::processEvents();
	  return false;
	}

      if(!(key.startsWith("R") || key.startsWith("r")))
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Invalid repleo(s). The provided text must start with "
		"either the letter R or the letter r."));
	  QApplication::processEvents();
	  return false;
	}

      auto list(key.mid(1).split('@'));

      if(list.size() != 3)
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Irregular data. Expecting 3 entries, received %1.").
	     arg(list.size()));
	  QApplication::processEvents();
	  return false;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      auto const hash(list.value(2));
      auto data(list.value(1));
      auto keyInformation(list.value(0));
      auto ok = true;

      keyInformation = m_crypts.value("chat")->
	publicKeyDecrypt(list.value(0), &ok);

      if(!ok)
	{
	  keyInformation = m_crypts.value("email")->
	    publicKeyDecrypt(list.value(0), &ok);

	  if(!ok)
	    {
	      keyInformation = m_crypts.value("open-library")->
		publicKeyDecrypt(list.value(0), &ok);

	      if(!ok)
		{
		  keyInformation = m_crypts.value("poptastic")->
		    publicKeyDecrypt(list.value(0), &ok);

		  if(!ok)
		    {
		      keyInformation = m_crypts.value("rosetta")->
			publicKeyDecrypt(list.value(0), &ok);

		      if(!ok)
			{
			  keyInformation = m_crypts.value("url")->
			    publicKeyDecrypt(list.value(0), &ok);

			  if(!ok)
			    {
			      QMessageBox::critical
				(parent,
				 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				 tr("Asymmetric decryption failure. "
				    "Are you attempting "
				    "to add a repleo that you gathered?"));
			      QApplication::processEvents();
			      return false;
			    }
			}
		    }
		}
	    }
	}

      list = keyInformation.split('@');

      if(list.size() != 3)
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Irregular data. Expecting 3 entries, received %1.").
	     arg(list.size()));
	  QApplication::processEvents();
	  return false;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray computedHash;
      spoton_crypt crypt(list.value(1), // Cipher Type
			 spoton_crypt::preferredHashAlgorithm(),
			 QByteArray(),
			 list.value(0), // Symmetric Key
			 list.value(2), // Hash Key
			 0,
			 0,
			 "");

      computedHash = crypt.keyedHash(data, &ok);

      if(!ok)
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("Unable to compute a keyed hash."));
	  QApplication::processEvents();
	  return false;
	}

      if(computedHash.isEmpty() || hash.isEmpty() ||
	 !spoton_crypt::memcmp(computedHash, hash))
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("The computed hash does not match "
				   "the provided hash."));
	  QApplication::processEvents();
	  return false;
	}

      data = crypt.decrypted(data, &ok);

      if(!ok)
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Symmetric decryption failure. Serious!"));
	  QApplication::processEvents();
	  return false;
	}

      list = data.split('@');

      if(list.size() != 6)
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Irregular data. Expecting 6 entries, received %1.").
	     arg(list.size()));
	  QApplication::processEvents();
	  return false;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(!spoton_common::SPOTON_ENCRYPTION_KEY_NAMES.contains(list.value(0)))
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Invalid key type. Expecting 'chat', 'email', "
		"'open-library', 'poptastic', "
		"'rosetta', or 'url'."));
	  QApplication::processEvents();
	  return false;
	}

      list.replace(2, qUncompress(list.at(2))); // Public Key

      QByteArray myPublicKey;
      QByteArray mySPublicKey;

      if(list.value(0) == "chat")
	{
	  myPublicKey = m_crypts.value("chat")->publicKey(&ok);

	  if(ok)
	    mySPublicKey = m_crypts.value("chat-signature")->
	      publicKey(&ok);
	}
      else if(list.value(0) == "email")
	{
	  myPublicKey = m_crypts.value("email")->publicKey(&ok);

	  if(ok)
	    mySPublicKey = m_crypts.value("email-signature")->
	      publicKey(&ok);
	}
      else if(list.value(0) == "open-library")
	{
	  myPublicKey = m_crypts.value("open-library")->publicKey(&ok);

	  if(ok)
	    mySPublicKey = m_crypts.value("open-library-signature")->
	      publicKey(&ok);
	}
      else if(list.value(0) == "poptastic")
	{
	  myPublicKey = m_crypts.value("poptastic")->publicKey(&ok);

	  if(ok)
	    mySPublicKey = m_crypts.value("poptastic-signature")->
	      publicKey(&ok);
	}
      else if(list.value(0) == "rosetta")
	{
	  myPublicKey = m_crypts.value("rosetta")->publicKey(&ok);

	  if(ok)
	    mySPublicKey = m_crypts.value("rosetta-signature")->
	      publicKey(&ok);
	}
      else if(list.value(0) == "url")
	{
	  myPublicKey = m_crypts.value("url")->publicKey(&ok);

	  if(ok)
	    mySPublicKey = m_crypts.value("url-signature")->
	      publicKey(&ok);
	}

      if(ok)
	if((list.value(2) == myPublicKey && !myPublicKey.isEmpty()) ||
	   (list.value(4) == mySPublicKey && !mySPublicKey.isEmpty()))
	  ok = false;

      if(!ok)
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("You're attempting to add your own keys or "
		"%1 was not able to retrieve your keys for "
		"comparison.").
	     arg(SPOTON_APPLICATION_NAME));
	  QApplication::processEvents();
	  return false;
	}

      if(!spoton_crypt::isValidSignature(list.value(2),  // Data
					 list.value(2),  // Public Key
					 list.value(3))) // Signature
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Invalid 'chat', 'email', 'open-library', 'poptastic', "
		"'rosetta', or 'url' "
		"public key signature."));
	  QApplication::processEvents();
	  return false;
	}

      if(!spoton_crypt::
	 isValidSignature(list.value(4),  // Data
			  list.value(4),  // Signature Public Key
			  list.value(5))) // Signature
	{
	  QMessageBox::critical
	    (parent,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Invalid 'chat', 'email', 'open-library', 'poptastic', "
		"'rosetta', or 'url' "
		"signature public key signature."));
	  QApplication::processEvents();
	  return false;
	}

      QString connectionName("");

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() +
	   QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    if((ok = spoton_misc::
		saveFriendshipBundle(list.value(0), // Key Type
				     list.value(1), // Name
				     list.value(2), // Public Key
				     list.value(4), // Signature
				                    // Public Key
				     -1,            // Neighbor OID
				     db,
				     m_crypts.value("chat", nullptr))))
	      if((ok = spoton_misc::
		  saveFriendshipBundle(list.value(0) + "-signature",
				       list.value(1), // Name
				       list.value(4), // Signature Public Key
				       QByteArray(),  // Signature Public Key
				       -1,            // Neighbor OID
				       db,
				       m_crypts.value("chat", nullptr))))
		m_ui.friendInformation->selectAll();
	  }
	else
	  ok = false;

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      if(!ok)
	{
	  QMessageBox::critical(parent,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("An error occurred while attempting "
				   "to save the friendship bundle."));
	  QApplication::processEvents();
	  return false;
	}
    }

  return true;
}

bool spoton::isKernelActive(void) const
{
  auto const pid = spoton_misc::kernelPid();

  if(pid > 0)
    {
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_UNIX)
      return kill(pid, 0) == 0;
#elif defined(Q_OS_WINDOWS)
      auto handle = OpenProcess
	(PROCESS_ALL_ACCESS, false, static_cast<DWORD> (pid));

      if(handle)
	{
	  DWORD exitCode {};

	  if(!GetExitCodeProcess(handle, &exitCode))
	    {
	      CloseHandle(handle);
	      return false;
	    }

	  CloseHandle(handle);
	  return exitCode == STILL_ACTIVE;
	}
      else
	return false;
#else
      return true;
#endif
    }
  else
    return false;
}

bool spoton::saveGemini(const QPair<QByteArray, QByteArray> &gemini,
			const QString &oid)
{
  return spoton_misc::saveGemini(gemini, oid, m_crypts.value("chat", nullptr));
}

bool spoton::updateMailStatus(const QString &oid, const QString &status)
{
  if(!m_crypts.value("email", nullptr))
    return false;

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare("UPDATE folders SET status = ? WHERE OID = ?");
	query.bindValue
	  (0, m_crypts.value("email")->
	   encryptedThenHashed(status.toUtf8(), &ok).toBase64());
	query.bindValue(1, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

int spoton::applyGoldBugToLetter(const QByteArray &goldbug,
				 const int row)
{
  if(!m_crypts.value("email", nullptr))
    return APPLY_GOLDBUG_TO_LETTER_ERROR_MEMORY;

  auto item = m_ui.mail->item(row, m_ui.mail->columnCount() - 1); // OID

  if(!item)
    return APPLY_GOLDBUG_TO_LETTER_ERROR_MEMORY;

  QString connectionName("");
  auto const oid(item->text());
  auto ok = true;
  int rc = 0;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if((ok = db.open()))
      {
	QList<QByteArray> list;
	QSqlQuery query(db);
	int attachmentsCount = 0;

	query.setForwardOnly(true);
	query.prepare("SELECT date, "          // 0
		      "message, "              // 1
		      "message_code, "         // 2
		      "receiver_sender, "      // 3
		      "receiver_sender_hash, " // 4
		      "subject, "              // 5
		      "(SELECT COUNT(*) FROM folders_attachment WHERE "
		      "folders_oid = ?), "     // 6
		      "signature "             // 7
		      "FROM folders "
		      "WHERE OID = ?");
	query.bindValue(0, oid);
	query.bindValue(1, oid);

	if((ok = query.exec()))
	  if((ok = query.next()))
	    for(int i = 0; i < query.record().count(); i++)
	      {
		if(i == 2 || i == 4)
		  list.append
		    (QByteArray::fromBase64(query.value(i).
					    toByteArray()));
		else if(i == 6) // attachment(s)
		  list.append(query.value(i).toString().toLatin1());
		else
		  list.append
		    (m_crypts.value("email")->
		     decryptedAfterAuthenticated
		     (QByteArray::fromBase64(query.value(i).
					     toByteArray()),
		      &ok));

		if(!ok)
		  {
		    if(rc == 0)
		      rc = APPLY_GOLDBUG_TO_LETTER_ERROR_GENERAL;

		    break;
		  }
	      }

	if(!ok)
	  if(rc == 0)
	    rc = APPLY_GOLDBUG_TO_LETTER_ERROR_DATABASE;

	if(ok)
	  {
	    auto crypt = spoton_misc::cryptFromForwardSecrecyMagnet(goldbug);

	    if(!crypt)
	      ok = false;
	    else
	      for(int i = 0; i < list.size(); i++)
		{
		  if(i == 2 || i == 4 || i == 6)
		    /*
		    ** Ignore the message_code,
		    ** receiver_sender_hash, and attachment(s) count columns.
		    */

		    continue;

		  list.replace
		    (i, crypt->decryptedAfterAuthenticated(list.at(i), &ok));

		  if(!ok)
		    {
		      if(rc == 0)
			rc = APPLY_GOLDBUG_TO_LETTER_ERROR_GENERAL;

		      break;
		    }
		}

	    if(ok)
	      {
		/*
		** Let's prepare the attachments.
		*/

		QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
		applyGoldBugToAttachments
		  (oid, db, &attachmentsCount, crypt, &ok);
		QApplication::restoreOverrideCursor();

		if(!ok)
		  if(rc == 0)
		    rc = APPLY_GOLDBUG_TO_LETTER_ERROR_ATTACHMENTS;
	      }

	    delete crypt;
	  }

	if(ok)
	  {
	    /*
	    ** list[0]: date
	    ** list[1]: message
	    ** list[2]: message_code
	    ** list[3]: receiver_sender
	    ** list[4]: receiver_sender_hash
	    ** list[5]: subject
	    ** list[6]: attachment(s) count
	    ** list[7]: signature
	    */

	    QSqlQuery updateQuery(db);

	    updateQuery.prepare("UPDATE folders SET "
				"date = ?, "
				"goldbug = ?, "
				"hash = ?, "
				"message = ?, "
				"message_code = ?, "
				"receiver_sender = ?, "
				"signature = ?, "
				"subject = ? "
				"WHERE OID = ?");
	    updateQuery.bindValue
	      (0, m_crypts.value("email")->
	       encryptedThenHashed(list.value(0), &ok).toBase64());

	    if(ok)
	      updateQuery.bindValue
		(1, m_crypts.value("email")->
		 encryptedThenHashed(QByteArray::number(0), &ok).
		 toBase64());

	    if(ok)
	      updateQuery.bindValue
		(2, m_crypts.value("email")->
		 keyedHash(list.value(0) + list.value(1) + list.value(5), &ok).
		 toBase64());

	    if(!list.value(1).isEmpty())
	      if(ok)
		updateQuery.bindValue
		  (3, m_crypts.value("email")->
		   encryptedThenHashed(list.value(1), &ok).toBase64());

	    if(!list.value(2).isEmpty())
	      if(ok)
		updateQuery.bindValue
		  (4, m_crypts.value("email")->
		   encryptedThenHashed(QByteArray(), &ok).toBase64());

	    if(!list.value(3).isEmpty())
	      if(ok)
		updateQuery.bindValue
		  (5, m_crypts.value("email")->
		   encryptedThenHashed(list.value(3), &ok).toBase64());

	    if(ok)
	      updateQuery.bindValue
		(6, m_crypts.value("email")->
		 encryptedThenHashed(list.value(7), &ok).toBase64());

	    if(ok)
	      updateQuery.bindValue
		(7, m_crypts.value("email")->
		 encryptedThenHashed(list.value(5), &ok).toBase64());

	    updateQuery.bindValue(8, oid);

	    if(ok)
	      {
		ok = updateQuery.exec();

		if(!ok)
		  {
		    if(updateQuery.lastError().text().
		       toLower().contains("unique"))
		      ok = true;

		    if(!ok)
		      if(rc == 0)
			rc = APPLY_GOLDBUG_TO_LETTER_ERROR_DATABASE;
		  }
	      }
	    else if(rc == 0)
	      rc = APPLY_GOLDBUG_TO_LETTER_ERROR_GENERAL;
	  }

	if(ok)
	  {
	    m_ui.mail->setSortingEnabled(false);

	    auto item = m_ui.mail->item(row, 0); // Date

	    if(item)
	      item->setText(list.value(0));

	    item = m_ui.mail->item(row, 1); // From / To

	    if(item)
	      {
		auto const items
		  (findItems(m_ui.emailParticipants,
			     list.value(4).toBase64(),
			     3));

		if(!items.isEmpty() && items.at(0))
		  {
		    QTableWidgetItem *it =
		      m_ui.emailParticipants->
		      item(items.at(0)->row(), 0);

		    if(it)
		      item->setText(it->text());
		  }
		else
		  item->setText(list.value(3));
	      }

	    item = m_ui.mail->item(row, 3); // Subject

	    if(item)
	      item->setText(list.value(5));

	    item = m_ui.mail->item(row, 4); // Attachment(s)

	    if(item)
	      {
		if(attachmentsCount > 0)
		  {
		    item->setData(Qt::UserRole, 1);
		    item->setIcon(QIcon(":/generic/attach.png"));
		  }
		else
		  item->setData(Qt::UserRole, 0);

		item->setText(QString::number(attachmentsCount));
	      }

	    item = m_ui.mail->item(row, 5); // Gold Bug

	    if(item)
	      item->setText("0");

	    item = m_ui.mail->item(row, 6); // Message

	    if(item)
	      item->setText(list.value(1));

	    item = m_ui.mail->item(row, 10); // Signature

	    if(item)
	      item->setText(list.value(7));

	    m_ui.mail->setSortingEnabled(true);
	  }
      }
    else if(rc == 0)
      rc = APPLY_GOLDBUG_TO_LETTER_ERROR_DATABASE;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    if(rc == 0)
      rc = APPLY_GOLDBUG_TO_LETTER_ERROR_GENERAL;

  return rc;
}

void spoton::authenticationRequested(const QByteArray &data)
{
  if(!data.isEmpty())
    if(!m_sb.authentication_request->isVisible())
      {
	m_sb.authentication_request->setProperty
	  ("data", data);
	m_sb.authentication_request->
	  setToolTip(tr("<html>Remote peer %1 is requesting authentication "
			"credentials.</html>").arg(data.constData()));
	m_sb.authentication_request->setVisible(true);
	QTimer::singleShot(7500, m_sb.authentication_request,
			   SLOT(hide(void)));
      }
}

void spoton::highlightPaths(void)
{
  QList<QLineEdit *> list;

  list << m_optionsUi.geoipPath4
       << m_optionsUi.geoipPath6
       << m_optionsUi.openssl
       << m_poptasticRetroPhoneSettingsUi.capath
       << m_rosetta->attachmentsGPGPath()
       << m_ui.destination
       << m_ui.kernelPath
       << m_ui.urlIniPath
       << m_ui.webServerProcessName;

  foreach(auto widget, list)
    {
      QColor color;
      QFileInfo const fileInfo(widget->text());

      if(m_optionsUi.geoipPath4 == widget || m_optionsUi.geoipPath6 == widget)
	{
#ifdef SPOTON_LINKED_WITH_LIBGEOIP
	  fileInfo.setFile(widget->text());

	  if(fileInfo.isReadable() && fileInfo.size() > 0)
	    color = QColor(144, 238, 144);
	  else
	    color = QColor(240, 128, 128); // Light coral!
#else
	  color = QColor(240, 128, 128); // Light coral!
#endif
	}
      else if(m_optionsUi.openssl == widget)
	{
	  if(fileInfo.isExecutable())
	    color = QColor(144, 238, 144);
	  else
	    color = QColor(240, 128, 128); // Light coral!
	}
      else if(m_poptasticRetroPhoneSettingsUi.capath == widget)
	{
	  if(fileInfo.isReadable())
	    color = QColor(144, 238, 144);
	  else
	    color = QColor(240, 128, 128); // Light coral!
	}
      else if(m_rosetta->attachmentsGPGPath() == widget)
	{
	  if(fileInfo.isExecutable())
	    color = QColor(144, 238, 144);
	  else
	    color = QColor(240, 128, 128); // Light coral!
	}
      else if(m_ui.destination == widget)
	{
	  if(fileInfo.isReadable() && fileInfo.isWritable())
	    color = QColor(144, 238, 144);
	  else
	    color = QColor(240, 128, 128); // Light coral!
	}
      else if(m_ui.kernelPath == widget ||
	      m_ui.webServerProcessName == widget)
	{
#if defined(Q_OS_MACOS)
	  if((fileInfo.isBundle() ||
	      fileInfo.isExecutable()) &&
	     (fileInfo.size() > 0))
#elif defined(Q_OS_WINDOWS)
	  if(fileInfo.isReadable() && fileInfo.size() > 0)
#else
	  if(fileInfo.isExecutable() && fileInfo.size() > 0)
#endif
	    color = QColor(144, 238, 144);
	  else
	    color = QColor(240, 128, 128); // Light coral!
	}
      else if(m_ui.urlIniPath == widget)
	{
	  if(fileInfo.isReadable() && fileInfo.size() > 0)
	    color = QColor(144, 238, 144);
	  else
	    color = QColor(240, 128, 128); // Light coral!
	}

      auto palette(widget->palette());

      palette.setColor(widget->backgroundRole(), color);
      widget->setPalette(palette);
    }
}

void spoton::initializeKernelSocket(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::UnconnectedState)
    return;

  auto const keySize = m_ui.kernelKeySize->currentText().toInt();

  if(keySize > 0)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_sb.status->setText
	(tr("Generating SSL/TLS %1-bit kernel socket credentials.").
	 arg(keySize));
      m_sb.status->repaint();

      QByteArray certificate;
      QByteArray privateKey;
      QByteArray publicKey;
      QString error("");

      spoton_crypt::generateSslKeys
	(keySize,
	 certificate,
	 privateKey,
	 publicKey,
	 m_kernelSocket.peerAddress(),
	 0,
	 error);
      m_sb.status->clear();
      QApplication::restoreOverrideCursor();

      if(error.isEmpty())
	{
	  QSslConfiguration configuration;
	  QSslKey key;
	  auto const sslCS
	    (m_settings.value("gui/sslControlString",
			      spoton_common::SSL_CONTROL_STRING).toString());

	  configuration.setPeerVerifyMode(QSslSocket::VerifyNone);

	  if(keySize < 1024)
	    key = QSslKey(privateKey, QSsl::Ec);
	  else
	    key = QSslKey(privateKey, QSsl::Rsa);

	  configuration.setPrivateKey(key);
	  configuration.setSslOption(QSsl::SslOptionDisableCompression, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableEmptyFragments, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableLegacyRenegotiation, true);
#if QT_VERSION >= 0x050501
	  configuration.setSslOption
	    (QSsl::SslOptionDisableSessionPersistence, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableSessionSharing, true);
#endif
	  configuration.setSslOption
	    (QSsl::SslOptionDisableSessionTickets, true);
#if QT_VERSION >= 0x050501
	  spoton_crypt::setSslCiphers
	    (QSslConfiguration::supportedCiphers(), sslCS, configuration);
#else
	  spoton_crypt::setSslCiphers
	    (m_kernelSocket.supportedCiphers(), sslCS, configuration);
#endif
	  m_kernelSocket.ignoreSslErrors();
	  m_kernelSocket.setSslConfiguration(configuration);
	}
      else
	spoton_misc::logError
	  (QString("spoton::"
		   "initializeKernelSocket(): "
		   "generateSslKeys() failure (%1).").arg(error));
    }
  else
    m_kernelSocket.ignoreSslErrors();
}

void spoton::populateAccounts(const QString &listenerOid)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QString account("");
	auto const index =
	  m_ui.accounts->selectionModel()->selectedRows().value(0);

	if(index.isValid())
	  account = index.data().toString();

	m_ui.accounts->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT account_name FROM listeners_accounts "
		      "WHERE listener_oid = ? AND "
		      "listener_oid IN (SELECT OID FROM listeners WHERE "
		      "status_control <> 'deleted' AND OID = ?)");
	query.bindValue(0, listenerOid);
	query.bindValue(1, listenerOid);

	if(query.exec())
	  {
	    QStringList names;

	    while(query.next())
	      {
		QString name("");
		auto ok = true;

		name = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()),
		   &ok);

		if(!name.isEmpty())
		  names.append(name);
	      }

	    std::sort(names.begin(), names.end());

	    if(!names.isEmpty())
	      m_ui.accounts->addItems(names);
	  }

	auto item = m_ui.accounts->findItems
	  (account, Qt::MatchExactly).value(0);

	if(item)
	  item->setSelected(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::populateListenerIps(const QString &listenerOid)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QString ip("");
	auto const index = m_ui.acceptedIPList->
	  selectionModel()->selectedRows().value(0);

	if(index.isValid())
	  ip = index.data().toString();

	m_ui.acceptedIPList->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT ip_address FROM listeners_allowed_ips "
		      "WHERE listener_oid = ? AND listener_oid IN "
		      "(SELECT OID FROM listeners WHERE status_control <> "
		      "'deleted' AND OID = ?)");
	query.bindValue(0, listenerOid);
	query.bindValue(1, listenerOid);

	if(query.exec())
	  {
	    QStringList ips;

	    while(query.next())
	      {
		QString ip("");
		auto ok = true;

		ip = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()),
		   &ok);

		if(!ip.isEmpty())
		  ips.append(ip);
	      }

	    std::sort(ips.begin(), ips.end());

	    if(!ips.isEmpty())
	      m_ui.acceptedIPList->addItems(ips);
	  }

	auto item = m_ui.acceptedIPList->findItems
	  (ip, Qt::MatchExactly).value(0);

	if(item)
	  item->setSelected(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::populateMail(void)
{
  if(!m_crypts.value("email", nullptr))
    return;

  if(m_ui.folder->currentIndex() == 0 || m_ui.folder->currentIndex() == 2)
    m_ui.reply->setEnabled(true);
  else
    m_ui.reply->setEnabled(false);

  m_ui.resend->setEnabled(m_ui.folder->currentIndex() == 1);

  if(m_ui.folder->currentIndex() == 0) // Inbox
    {
      if(currentTabName() == "email")
	if(m_ui.mailTab->currentIndex() == 0)
	  m_sb.email->setVisible(false);

      m_ui.mail->horizontalHeaderItem(1)->setText(tr("From"));
    }
  else if(m_ui.folder->currentIndex() == 1) // Sent
    m_ui.mail->horizontalHeaderItem(1)->setText(tr("To"));
  else
    m_ui.mail->horizontalHeaderItem(1)->setText(tr("From/To")); // Trash

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  slotPopulateParticipants();

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QHash<QString, bool> cRow; // OID, bool.
	QList<int> rows;
	QSqlQuery query(db);
	QStringList oids;
	auto const html
	  (m_ui.email_plain->isChecked() ?
	   m_ui.mailMessage->toPlainText() : m_ui.mailMessage->toHtml());
	auto const list
	  (m_ui.mail->selectionModel()->
	   selectedRows(m_ui.mail->columnCount() - 1)); // OID
	auto const vValue = m_ui.mail->verticalScrollBar()->value();
	auto emailPage = m_ui.email_page->currentIndex();
	int totalRows = 0;

	for(int i = 0; i < list.size(); i++)
	  {
	    if(list.at(i).row() == m_ui.mail->currentRow())
	      cRow[list.at(i).data().toString()] = false;

	    auto const data(list.at(i).data());

	    if(!data.isNull() && data.isValid())
	      oids.append(data.toString());
	  }

	disconnect(m_ui.email_page,
		   SIGNAL(currentIndexChanged(int)),
		   this,
		   SLOT(slotEmailPageChanged(int)));
	disconnect(m_ui.mail,
		   SIGNAL(itemSelectionChanged(void)),
		   this,
		   SLOT(slotMailSelected(void)));
	m_ui.email_page->clear();
	m_ui.mail->setRowCount(0);
	m_ui.mail->setSortingEnabled(false);
	m_ui.mailMessage->clear();
	query.setForwardOnly(true);

	if(query.exec(QString("SELECT COUNT(*) FROM folders WHERE "
			      "folder_index = %1").
		      arg(m_ui.folder->currentIndex())))
	  if(query.next())
	    {
	      auto const pages = qCeil
		(query.value(0).toDouble() /
		 static_cast<double> (m_ui.email_pages->value()));

	      for(int i = 0; i < pages; i++)
		m_ui.email_page->addItem(QString::number(i + 1));

	      m_ui.mail->setRowCount(query.value(0).toInt());
	    }

	if(m_ui.email_page->count() == 0)
	  m_ui.email_page->addItem("1");

	emailPage = qBound(0, emailPage, m_ui.email_page->count() - 1);
	m_ui.email_page->setCurrentIndex(emailPage);
	connect(m_ui.email_page,
		SIGNAL(currentIndexChanged(int)),
		this,
		SLOT(slotEmailPageChanged(int)));

	if(query.exec(QString("SELECT f.date, "          // 0
			      "f.receiver_sender, "      // 1
			      "f.status, "               // 2
			      "f.subject, "              // 3
			      "COUNT(a.OID), "           // 4
			      "f.goldbug, "              // 5
			      "f.message, "              // 6
			      "f.message_code, "         // 7
			      "f.receiver_sender_hash, " // 8
			      "f.hash, "                 // 9
			      "f.signature, "            // 10
			      "f.OID "                   // 11
			      "FROM folders f "
			      "LEFT JOIN folders_attachment a "
			      "ON a.folders_oid = f.OID "
			      "WHERE f.folder_index = %1 "
			      "GROUP BY f.OID "
			      "LIMIT %2 OFFSET %3").
		      arg(m_ui.folder->currentIndex()).
		      arg(m_ui.email_pages->value()).
		      arg(m_ui.email_page->currentIndex() *
			  m_ui.email_pages->value())))
	  {
	    int row = 0;

	    while(query.next() && totalRows < m_ui.mail->rowCount())
	      {
		totalRows += 1;

		QByteArray goldbug;
		QString tooltip("<html>");
		auto ok = true;

		goldbug = m_crypts.value("email")->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(5).
							 toByteArray()),
					      &ok);

		if(goldbug.isEmpty())
		  goldbug = "0";

		for(int i = 0; i < query.record().count(); i++)
		  {
		    QTableWidgetItem *item = nullptr;

		    if(i == 0)
		      row += 1;

		    if(i == 0 ||
		       i == 1 ||
		       i == 2 ||
		       i == 3 ||
		       i == 6 ||
		       i == 7 ||
		       i == 10)
		      {
			if(i == 1 || i == 2 || i == 3 || i == 6 || i == 10)
			  {
			    if(goldbug == "0")
			      {
				if(i == 3) // subject
				  {
				    auto const bytes
				      (m_crypts.value("email")->
				       decryptedAfterAuthenticated
				       (QByteArray::fromBase64
					(query.value(i).toByteArray()),
					&ok));

				    item = new QTableWidgetItem
				      (QString::fromUtf8(bytes.constData(),
							 bytes.length()).
				       trimmed());
				    tooltip.append
				      (m_ui.mail->
				       horizontalHeaderItem(i)->text());
				    tooltip.append(": ");
				    tooltip.append(item->text());
				    tooltip.append("<br>");
				  }
				else
				  {
				    auto const bytes
				      (m_crypts.value("email")->
				       decryptedAfterAuthenticated
				       (QByteArray::
					fromBase64
					(query.value(i).toByteArray()),
					&ok));

				    item = new QTableWidgetItem
				      (QString::fromUtf8(bytes.constData(),
							 bytes.length()).
				       trimmed());

				    if(i != 2 && i <= 3)
				      {
					tooltip.append
					  (m_ui.mail->
					   horizontalHeaderItem(i)->text());
					tooltip.append(": ");
					tooltip.append(item->text());
					tooltip.append("<br>");
				      }

				    if(i == 6)
				      {
					tooltip.append
					  (m_ui.mail->
					   horizontalHeaderItem(i)->text());
					tooltip.append("<br>");
				      }
				  }

				if(!ok)
				  item->setText(tr("error"));
				else if(i == 1) // receiver_sender
				  {
				    auto const items
				      (findItems(m_ui.emailParticipants,
						 query.value(8).
						 toByteArray(),
						 3));

				    if(!items.isEmpty() && items.at(0))
				      {
					auto it =
					  m_ui.emailParticipants->
					  item(items.at(0)->row(), 0);

					if(it)
					  {
					    item->setBackground
					      (QBrush(QColor("lightgreen")));
					    item->setText(it->text());
					  }
				      }
				  }
			      }
			    else
			      item = new QTableWidgetItem("#####");
			  }
			else
			  {
			    if(goldbug == "0")
			      {
				item = new QTableWidgetItem
				  (QString(m_crypts.value("email")->
					   decryptedAfterAuthenticated
					   (QByteArray::
					    fromBase64(query.value(i).
						       toByteArray()),
					    &ok)));

				if(!ok)
				  item->setText(tr("error"));
				else if(i == 0) // date
				  {
				    if(QDateTime::currentDateTime().date() ==
				       QDateTime::fromString(item->text(),
							     Qt::ISODate).
				       date() ||
				       QDateTime::currentDateTime().date() ==
				       QDateTime::fromString(item->text(),
							     Qt::RFC2822Date).
				       date())
				      item->setBackground
					(QBrush(QColor("lightgreen")));

				    tooltip.append
				      (m_ui.mail->
				       horizontalHeaderItem(i)->text());
				    tooltip.append(": ");
				    tooltip.append(item->text());
				    tooltip.append("<br>");
				  }
			      }
			    else
			      item = new QTableWidgetItem("#####");
			  }
		      }
		    else if(i == 4) // attachment(s) count
		      {
			if(goldbug == "0")
			  {
			    if(query.value(i).toLongLong() > 0)
			      {
				item = new spoton_table_widget_item
				  (QString::
				   number(query.value(i).toLongLong()));
				item->setData(Qt::UserRole, 1);
				item->setIcon(QIcon(":/generic/attach.png"));
			      }
			    else
			      {
				item = new spoton_table_widget_item("0");
				item->setData(Qt::UserRole, 0);
			      }

			    tooltip.append
			      (m_ui.mail->horizontalHeaderItem(i)->text());
			    tooltip.append(": ");
			    tooltip.append(item->text());
			    tooltip.append("<br>");
			  }
			else
			  {
			    item = new QTableWidgetItem("#####");
			    item->setData(Qt::UserRole, 0);
			  }
		      }
		    else if(i == 5) // goldbug
		      item = new QTableWidgetItem(QString(goldbug));
		    else
		      item = new QTableWidgetItem(query.value(i).toString());

		    item->setFlags
		      (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		    m_ui.mail->setItem(row - 1, i, item);
		  }

		if(tooltip.endsWith("<br>"))
		  tooltip = tooltip.mid(0, tooltip.length() - 4);

		tooltip.append("</html>");

		if(tooltip != "<html></html>")
		  for(int i = 0; i < 5; i++)
		    {
		      auto item = m_ui.mail->item(row - 1, i);

		      if(!item)
			continue;

		      item->setToolTip(tooltip);
		    }

		if(cRow.contains(query.value(11).toString()))
		  cRow[query.value(11).toString()] = true;

		if(oids.contains(query.value(11).toString()))
		  rows.append(row - 1);
	      }
	  }

	m_ui.mail->setRowCount(totalRows);
	m_ui.mail->setSelectionMode(QAbstractItemView::MultiSelection);

	if(cRow.values().value(0))
	  {
	    if(m_ui.email_plain->isChecked())
	      m_ui.mailMessage->setPlainText(html);
	    else
	      m_ui.mailMessage->setHtml(html);
	  }

	for(int i = 0; i < rows.size(); i++)
	  m_ui.mail->selectRow(rows.at(i));

	m_ui.mail->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_ui.mail->setSortingEnabled(true);
	m_ui.mail->verticalScrollBar()->setValue(vValue);
	m_ui.mail->resizeColumnsToContents();
	connect(m_ui.mail,
		SIGNAL(itemSelectionChanged(void)),
		this,
		SLOT(slotMailSelected(void)));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::prepareListenerIPCombo(void)
{
  m_ui.listenerIPCombo->clear();
  m_ui.listenerTransport->repaint();
  repaint();

  QHash<QString, char> hash;
  QStringList list;

  if(m_ui.listenerTransport->currentIndex() == 0)
    {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      auto const devices(QBluetoothLocalDevice::allDevices());

      for(int i = 0; i < devices.size(); i++)
	{
	  auto const hostInfo(devices.at(i));
	  auto const string(hostInfo.address().toString());

	  if(hash.contains(string))
	    continue;
	  else
	    hash[string] = 0;

	  list.append(string);
	}

      QApplication::restoreOverrideCursor();
#endif
    }
  else
    {
      QHash<QString, char> hash;
      auto const interfaces(QNetworkInterface::allInterfaces());

      for(int i = 0; i < interfaces.size(); i++)
	{
	  if(!interfaces.at(i).isValid() ||
	     !(interfaces.at(i).flags() & QNetworkInterface::IsUp))
	    continue;

	  auto const addresses(interfaces.at(i).addressEntries());

	  for(int i = 0; i < addresses.size(); i++)
	    {
	      QHostAddress address;
	      auto const entry(addresses.at(i));

	      address = entry.ip();

	      if(m_ui.ipv4Listener->isChecked())
		{
		  if(address.protocol() == QAbstractSocket::IPv4Protocol)
		    {
		      auto const str(address.toString());

		      if(!hash.contains(str))
			{
			  hash[str] = 0;
			  list.append(address.toString());
			}
		    }
		}
	      else
		{
		  if(address.protocol() == QAbstractSocket::IPv6Protocol)
		    {
		      auto const str
			(QHostAddress(address.toIPv6Address()).toString());

		      if(!hash.contains(str))
			{
			  hash[str] = 0;
			  list.append(str);
			}
		    }
		}
	    }
	}
    }

  if(!list.isEmpty())
    {
      std::sort(list.begin(), list.end());
      m_ui.listenerIPCombo->addItem(tr("Custom"));
      m_ui.listenerIPCombo->insertSeparator(1);
      m_ui.listenerIPCombo->addItems(list);
    }
  else
    m_ui.listenerIPCombo->addItem(tr("Custom"));
}

void spoton::sendMessage(bool *ok)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString error("");
  QString msg("");
  QString to("");
  auto const gitMessages
    (m_ui.participants->selectionModel()->
     selectedRows(9)); // GIT Messages (Boolean)
  auto const list
    (m_ui.participants->selectionModel()->selectedRows(1)); // OID
  auto const names
    (m_ui.participants->selectionModel()->selectedRows(0)); // Participant
  auto const now(QDateTime::currentDateTime());
  auto const publicKeyHashes
    (m_ui.participants->selectionModel()->selectedRows(3)); // public_key_hash

  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    {
      error = tr("The interface is not connected to the kernel.");
      goto done_label;
    }
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    {
      error = tr("The connection to the kernel is not encrypted. "
		 "A secure connection is requested.");
      goto done_label;
    }
  else if(m_ui.message->toPlainText().trimmed().isEmpty())
    {
      error = tr("Please provide a real message.");
      goto done_label;
    }

  if(!m_ui.participants->selectionModel()->hasSelection())
    {
      /*
      ** We need at least one participant.
      */

      error = tr("Please select at least one participant.");
      goto done_label;
    }

  for(int i = 0; i < names.size(); i++)
    to.append(names.at(i).data().toString()).append(", ");

  msg.append
    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
     arg(now.toString("MM")).
     arg(now.toString("dd")).
     arg(now.toString("yyyy")).
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  msg.append
    (tr("<b>me</b> (<font color=gray>%1</font>)<b>:</b> ").
     arg(to.mid(0, to.length() - 2)));

  if(m_settings.value("gui/enableChatEmoticons", false).toBool())
    msg.append(mapIconToEmoticon(m_ui.message->toPlainText().trimmed()));
  else
    msg.append(m_ui.message->toPlainText().trimmed());

  m_ui.messages->append(msg);
  m_ui.messages->verticalScrollBar()->setValue
    (m_ui.messages->verticalScrollBar()->maximum());

  for(int i = 0; i < list.size(); i++)
    {
      auto const data(list.at(i).data());
      auto const gitMessage(gitMessages.value(i).data(Qt::CheckStateRole));
      auto const keyType
	(list.at(i).data(Qt::ItemDataRole(Qt::UserRole + 1)).toString());
      auto const publicKeyHash(publicKeyHashes.value(i).data().toString());

      if(!data.isNull() && data.isValid())
	{
	  QByteArray message;
	  QByteArray name;

	  if(keyType == "chat")
	    name = m_settings.value("gui/nodeName", "unknown").toByteArray();
	  else
	    name = poptasticName();

	  if(name.isEmpty())
	    {
	      if(keyType == "chat")
		name = "unknown";
	      else
		name = "unknown@unknown.org";
	    }

	  if(!m_chatSequenceNumbers.contains(data.toString()))
	    m_chatSequenceNumbers[data.toString()] = 0;

	  m_chatSequenceNumbers[data.toString()] += 1;

	  if(keyType == "chat")
	    message.append("message_");
	  else
	    message.append("poptasticmessage_");

	  message.append(QString("%1_").arg(data.toString()).toUtf8());
	  message.append(name.toBase64());
	  message.append("_");
	  message.append
	    (m_ui.message->toPlainText().trimmed().toUtf8().toBase64());
	  message.append("_");
	  message.append
	    (QByteArray::number(m_chatSequenceNumbers[data.toString()]).
	     toBase64());
	  message.append("_");
	  message.append(QDateTime::currentDateTimeUtc().
			 toString("MMddyyyyhhmmss").toLatin1().toBase64());
	  message.append("_");
	  message.append(QByteArray::number(selectedHumanProxyOID()));
	  message.append("_");
	  message.append(QByteArray::number(gitMessage.toBool()));
	  message.append("\n");
	  addMessageToReplayQueue(msg, message, publicKeyHash);

	  auto chat = m_chatWindows.value(publicKeyHash, nullptr);

	  if(chat)
	    chat->append(msg);

	  if(!writeKernelSocketData(message))
	    spoton_misc::logError
	      (QString("spoton::sendMessage(): write() failure for %1:%2.").
	       arg(m_kernelSocket.peerAddress().toString()).
	       arg(m_kernelSocket.peerPort()));
	  else
	    m_chatInactivityTimer.start();
	}
    }

  m_ui.message->clear();

 done_label:

  QApplication::restoreOverrideCursor();

  if(error.isEmpty())
    playSound("qrc:/Sounds/send.wav");

  if(!error.isEmpty())
    {
      if(ok)
	*ok = false;
      else
	{
	  QMessageBox::critical
	    (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
	  QApplication::processEvents();
	}
    }
}

void spoton::slotAcceptPublicizedListeners(void)
{
  auto radioButton = qobject_cast<QRadioButton *> (sender());

  if(!radioButton)
    return;

  if(m_optionsUi.acceptPublishedLocalConnected == radioButton)
    {
      m_settings["gui/acceptPublicizedListeners"] = "localConnected";
      m_optionsUi.publishedKeySize->setEnabled(true);
    }
  else if(m_optionsUi.acceptPublishedConnected == radioButton)
    {
      m_settings["gui/acceptPublicizedListeners"] = "connected";
      m_optionsUi.publishedKeySize->setEnabled(true);
    }
  else if(m_optionsUi.acceptPublishedDisconnected == radioButton)
    {
      m_settings["gui/acceptPublicizedListeners"] = "disconnected";
      m_optionsUi.publishedKeySize->setEnabled(true);
    }
  else
    {
      m_settings["gui/acceptPublicizedListeners"] = "ignored";
      m_optionsUi.publishedKeySize->setEnabled(false);
    }

  QSettings settings;

  settings.setValue("gui/acceptPublicizedListeners",
		    m_settings.value("gui/acceptPublicizedListeners"));
}

void spoton::slotAddAcceptedIP(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid listener OID. Please select a listener."));
      QApplication::processEvents();
      return;
    }

  QHostAddress ip(m_ui.acceptedIP->text().trimmed());

  if(m_ui.acceptedIP->text().trimmed() != "Any")
    if(ip.isNull())
      {
	QMessageBox::critical(this,
			      tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			      tr("Please provide an IP address or "
				 "the keyword Any."));
	QApplication::processEvents();
	return;
      }

  prepareDatabasesFromUI();

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO listeners_allowed_ips "
	   "(ip_address, ip_address_hash, "
	   "listener_oid) "
	   "VALUES (?, ?, ?)");

	if(m_ui.acceptedIP->text().trimmed() == "Any")
	  {
	    query.bindValue
	      (0, crypt->encryptedThenHashed("Any", &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->keyedHash("Any", &ok).
		 toBase64());
	  }
	else
	  {
	    query.bindValue
	      (0, crypt->encryptedThenHashed(ip.toString().toLatin1(),
					     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->keyedHash(ip.toString().
				     toLatin1(), &ok).
		 toBase64());
	  }

	query.bindValue(2, oid);

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    m_ui.acceptedIP->clear();
  else
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Unable to record the IP address."));
      QApplication::processEvents();
    }
}

void spoton::slotAddAccount(void)
{
  QString connectionName("");
  QString error("");
  QString oid("");
  auto const name(m_ui.accountName->text().trimmed());
  auto const password(m_ui.accountPassword->text().trimmed());
  auto crypt = m_crypts.value("chat", nullptr);
  auto ok = true;
  int row = -1;

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      error = tr("Invalid listener OID. Please select a listener.");
      goto done_label;
    }

  if(name.length() < 32)
    {
      error = tr("Please provide an account name that contains at "
		 "least thirty-two characters.");
      goto done_label;
    }
  else if(password.length() < 32)
    {
      error = tr("Please provide an account password that contains at "
		 "least thirty-two characters.");
      goto done_label;
    }

  prepareDatabasesFromUI();

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO listeners_accounts "
		      "(account_name, "
		      "account_name_hash, "
		      "account_password, "
		      "listener_oid, "
		      "one_time_account) "
		      "VALUES (?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(name.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->keyedHash(name.toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->encryptedThenHashed(password.toLatin1(),
					   &ok).toBase64());

	query.bindValue(3, oid);
	query.bindValue(4, m_ui.ota->isChecked() ? 1 : 0);

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    error = tr("A database error has occurred.");

 done_label:

  if(!error.isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
  else
    {
      m_ui.accountName->clear();
      m_ui.accountPassword->clear();
      m_ui.ota->setChecked(false);
      populateAccounts(oid);
    }
}

void spoton::slotAddFriendsKey(void)
{
  auto const key
    (m_ui.friendInformation->toPlainText().remove("\n").remove("\r\n").
     toLatin1().trimmed());
#if SPOTON_GOLDBUG == 0
  auto parent = m_addParticipantWindow;
#else
  auto parent = this;
#endif

  if(m_ui.addFriendEmail->isChecked())
    addFriendsKey(key, "E", parent);
  else if(key.startsWith("K") || key.startsWith("k"))
    {
      auto const list(key.split(s_keyDelimiter));

      for(int i = 0; i < list.size(); i++)
	{
	  QByteArray bytes("K");

	  bytes.append(list.at(i));
	  bytes.remove(0, 1);
	  addFriendsKey(bytes, "K", parent);
	}
    }
  else
    addFriendsKey(key, "R", parent);
}

void spoton::slotAuthenticationRequestButtonClicked(void)
{
  m_sb.authentication_request->setVisible(false);
  m_ui.tab->setCurrentIndex(tabIndexFromName("neighbors")); // Neighbors

  if(m_neighborToOidMap.contains(m_sb.authentication_request->
				 property("data").toByteArray()))
    authenticate
      (m_crypts.value("chat", nullptr),
       m_neighborToOidMap.value(m_sb.authentication_request->
				property("data").toByteArray()),
       m_sb.authentication_request->toolTip());

  m_sb.authentication_request->setProperty("data", QVariant());
}

void spoton::slotBuzzChanged(void)
{
  if(currentTabName() != "buzz")
    m_sb.buzz->setVisible(true);

  playSound("qrc:/Sounds/buzz.wav");
}

void spoton::slotChatInactivityTimeout(void)
{
  if(m_ui.status->currentIndex() == 4) // Online
    m_ui.status->setCurrentIndex(0); // Away
}

void spoton::slotChatSendMethodChanged(int index)
{
  if(index == 0)
    m_settings["gui/chatSendMethod"] = "Normal_POST";
  else
    m_settings["gui/chatSendMethod"] = "Artificial_GET";

  QSettings settings;

  settings.setValue
    ("gui/chatSendMethod",
     m_settings.value("gui/chatSendMethod").toString());
}

void spoton::slotChatWindowDestroyed(void)
{
  QMutableHashIterator<QString, QPointer<spoton_chatwindow> > it
    (m_chatWindows);

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	it.remove();
    }
}

void spoton::slotChatWindowMessageSent(void)
{
  m_chatInactivityTimer.start();
}

void spoton::slotClearOutgoingMessage(void)
{
  m_ui.attachment->clear();
  m_ui.emailName->setCurrentIndex(0);
  m_ui.emailParticipants->selectionModel()->clear();
  m_ui.email_fs_gb->setCurrentIndex(2);
  m_ui.goldbug->clear();
  m_ui.outgoingMessage->clear();
  m_ui.outgoingMessage->setCurrentCharFormat(QTextCharFormat());
  m_ui.outgoingSubject->clear();
  m_ui.richtext->setChecked(true);
  m_ui.sign_this_email->setChecked(m_optionsUi.emailSignMessages->isChecked());
  m_ui.outgoingSubject->setFocus();
}

void spoton::slotCloseBuzzTab(int index)
{
  auto page = qobject_cast<spoton_buzzpage *> (m_ui.buzzTab->widget(index));

  if(page)
    {
      m_buzzPages.remove(page->key());
      page->deleteLater();
    }

  m_ui.buzzTab->removeTab(index);

  if(m_buzzPages.isEmpty())
    m_buzzStatusTimer.stop();
}

void spoton::slotCopyFriendshipBundle(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  QString keyType("");
  QString oid("");
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      auto item = m_ui.participants->item(row, 1); // OID

      if(item)
	{
	  keyType = item->data(Qt::ItemDataRole(Qt::UserRole + 1)).
	    toString();
	  oid = item->text();
	}
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  if(!m_crypts.value(QString("%1-signature").arg(keyType), nullptr) ||
     !m_crypts.value(keyType, nullptr))
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  /*
  ** 1. Generate some symmetric information, S.
  ** 2. Encrypt S with the participant's public key.
  ** 3. Encrypt our information (name, public keys, signatures) with the
  **    symmetric key. Call our information T.
  ** 4. Compute a keyed hash of T.
  */

  QString neighborOid("");
  QByteArray hashKey;
  QByteArray keyInformation;
  QByteArray publicKey;
  QByteArray startsWith;
  QByteArray symmetricKey;
  QPair<QByteArray, QByteArray> gemini;
  QString receiverName("");
  auto const cipherType(m_settings.value("gui/kernelCipherType", "aes256").
			toString().toLatin1());
  auto ok = true;

  if(cipherType.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     hashKey,
				     startsWith,
				     neighborOid,
				     receiverName,
				     cipherType,
				     oid,
				     m_crypts.value(keyType, nullptr),
				     &ok);

  if(!ok || hashKey.isEmpty() || publicKey.isEmpty() || symmetricKey.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (symmetricKey.toBase64() + "@" +
     cipherType.toBase64() + "@" +
     hashKey.toBase64(),
     publicKey,
     startsWith,
     &ok);

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySPublicKey
    (m_crypts.value(QString("%1-signature").arg(keyType))->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySSignature
    (m_crypts.value(QString("%1-signature").arg(keyType))->digitalSignature
     (mySPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const myPublicKey(m_crypts.value(keyType)->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySignature
    (m_crypts.value(keyType)->digitalSignature(myPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  QByteArray myName;

  if(keyType == "chat")
    myName = m_settings.value("gui/nodeName", "unknown").toByteArray();
  else
    myName = poptasticName();

  if(myName.isEmpty())
    {
      if(keyType == "chat")
	myName = "unknown";
      else
	myName = "unknown@unknown.org";
    }

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     spoton_crypt::preferredHashAlgorithm(),
		     QByteArray(),
		     symmetricKey,
		     hashKey,
		     0,
		     0,
		     "");

  data = crypt.encrypted(keyType.toLatin1().toBase64() + "@" +
			 myName.toBase64() + "@" +
			 qCompress(myPublicKey).toBase64() + "@" +
			 mySignature.toBase64() + "@" +
			 mySPublicKey.toBase64() + "@" +
			 mySSignature.toBase64(), &ok);

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const hash(crypt.keyedHash(data, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const text("R" +
		  keyInformation.toBase64() + "@" +
		  data.toBase64() + "@" +
		  hash.toBase64());

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QApplication::restoreOverrideCursor();
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The chat bundle is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  clipboard->setText(spoton_misc::wrap(text));
  QApplication::restoreOverrideCursor();
}

void spoton::slotCopyMyChatPublicKey(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const text(copyMyChatPublicKey());

  QApplication::restoreOverrideCursor();

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The chat public key is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  auto clipboard = QApplication::clipboard();

  if(clipboard)
    {
      m_ui.toolButtonCopyToClipboard->menu()->repaint();
      repaint();
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      clipboard->setText(spoton_misc::wrap(text));
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotCopyMyEmailPublicKey(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const text(copyMyEmailPublicKey());

  QApplication::restoreOverrideCursor();

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The e-mail public key is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  auto clipboard = QApplication::clipboard();

  if(clipboard)
    {
      m_ui.toolButtonCopyToClipboard->menu()->repaint();
      repaint();
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      clipboard->setText(spoton_misc::wrap(text));
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotCopyMyPoptasticPublicKey(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const text(copyMyPoptasticPublicKey());

  QApplication::restoreOverrideCursor();

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The poptastic public key is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  auto clipboard = QApplication::clipboard();

  if(clipboard)
    {
      m_ui.toolButtonCopyToClipboard->menu()->repaint();
      repaint();
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      clipboard->setText(spoton_misc::wrap(text));
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotCopyMyRosettaPublicKey(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const text(copyMyRosettaPublicKey());

  QApplication::restoreOverrideCursor();

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The rosetta public key is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  auto clipboard = QApplication::clipboard();

  if(clipboard)
    {
      m_ui.toolButtonCopyToClipboard->menu()->repaint();
      repaint();
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      clipboard->setText(spoton_misc::wrap(text));
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotCopyMyURLPublicKey(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const text(copyMyUrlPublicKey());

  QApplication::restoreOverrideCursor();

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The URL public key is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  auto clipboard = QApplication::clipboard();

  if(clipboard)
    {
      m_ui.toolButtonCopyToClipboard->menu()->repaint();
      repaint();
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      clipboard->setText(spoton_misc::wrap(text));
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotCostChanged(int value)
{
  m_settings["gui/congestionCost"] = value;

  QSettings settings;

  settings.setValue("gui/congestionCost", value);
}

void spoton::slotDaysChanged(int value)
{
  m_settings["gui/postofficeDays"] = value;

  QSettings settings;

  settings.setValue("gui/postofficeDays", value);
}

void spoton::slotDeleteAcceptedIP(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid listener OID. "
			       "Please select a listener."));
      QApplication::processEvents();
      return;
    }

  QString ip("");

  if((row = m_ui.acceptedIPList->currentRow()) >= 0)
    {
      auto item = m_ui.acceptedIPList->item(row);

      if(item)
	ip = item->text();
    }

  if(ip.isEmpty())
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Please select an address to delete."));
      QApplication::processEvents();
      return;
    }

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM listeners_allowed_ips WHERE "
		      "ip_address_hash = ? AND listener_oid = ?");
	query.bindValue
	  (0, crypt->keyedHash(ip.toLatin1(), &ok).toBase64());
	query.bindValue(1, oid);

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(ip == "Any")
	  query.exec
	    ("UPDATE neighbors SET status_control = 'disconnected' "
	     "WHERE status_control <> 'deleted' AND user_defined = 0");
	else
	  {
	    query.prepare("UPDATE neighbors SET "
			  "status_control = 'disconnected' "
			  "WHERE remote_ip_address_hash = ? AND "
			  "status_control <> 'deleted' AND "
			  "user_defined = 0");

	    if(ok)
	      query.bindValue
		(0,
		 crypt->keyedHash(ip.toLatin1(), &ok).toBase64());

	    if(ok)
	      ok = query.exec();
	  }
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    delete m_ui.acceptedIPList->takeItem(row);
  else
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error occurred while attempting "
			       "to delete the specified IP."));
      QApplication::processEvents();
    }
}

void spoton::slotDeleteAccount(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid listener OID. Please select a listener."));
      QApplication::processEvents();
      return;
    }

  auto const list(m_ui.accounts->selectionModel()->selectedRows());

  if(list.isEmpty() || list.value(0).isValid() == false)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Please select an account to delete."));
      QApplication::processEvents();
      return;
    }

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM listeners_accounts WHERE "
		      "account_name_hash = ? AND listener_oid = ?");
	query.addBindValue
	  (crypt->keyedHash(list.at(0).data().toString().toLatin1(), &ok).
	   toBase64());
	query.addBindValue(oid);

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error occurred while attempting "
			       "to delete the specified account."));
      QApplication::processEvents();
    }
  else
    populateAccounts(oid);
}

void spoton::slotDeleteAllBlockedNeighbors(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Delete all non-unique blocked neighbors.
  ** Do remember that remote_ip_address contains encrypted data.
  */

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QMultiHash<QByteArray, qint64> hash;
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, " // 0
		      "OID "                       // 1
		      "FROM neighbors "
		      "WHERE status_control = 'blocked' ORDER BY OID"))
	  while(query.next())
	    {
	      QByteArray ip;
	      auto ok = true;

	      ip = crypt->
		decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).
					toByteArray()),
		 &ok);

	      if(ok)
		hash.insert(ip, query.value(1).toLongLong());
	    }

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM neighbors WHERE OID = ?");

	for(int i = 0; i < hash.keys().size(); i++)
	  {
	    auto list(hash.values(hash.keys().at(i)));

	    std::sort(list.begin(), list.end());

	    for(int j = 1; j < list.size(); j++) // Delete all but one.
	      {
		query.bindValue(0, list.at(j));
		query.exec();
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotDeleteAllUuids(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Delete all non-unique uuids.
  ** Do remember that uuid contains encrypted data.
  */

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QMultiHash<QByteArray, qint64> hash;
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT uuid, " // 0
		      "OID "          // 1
		      "FROM neighbors ORDER BY OID"))
	  while(query.next())
	    {
	      QByteArray uuid;
	      auto ok = true;

	      uuid = crypt->
		decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).
					toByteArray()),
		 &ok);

	      if(ok)
		hash.insert(uuid, query.value(1).toLongLong());
	    }

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM neighbors WHERE OID = ?");

	for(int i = 0; i < hash.keys().size(); i++)
	  {
	    auto list(hash.values(hash.keys().at(i)));

	    std::sort(list.begin(), list.end());

	    for(int j = 1; j < list.size(); j++) // Delete all but one.
	      {
		query.bindValue(0, list.at(j));
		query.exec();
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotDeleteMail(void)
{
  auto const list
    (m_ui.mail->selectionModel()->
     selectedRows(m_ui.mail->columnCount() - 1)); // OID

  if(list.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	for(int i = 0; i < list.size(); i++)
	  {
	    auto const oid(list.at(i).data().toString());
	    auto ok = true;

	    if(m_ui.folder->currentIndex() == 2) // Trash
	      {
		query.exec("PRAGMA secure_delete = ON");
		query.prepare("DELETE FROM folders WHERE OID = ?");
		query.bindValue(0, oid);
	      }
	    else
	      {
		query.prepare("UPDATE folders SET folder_index = 2, "
			      "status = ? WHERE "
			      "OID = ?");

		if(m_crypts.value("email", nullptr))
		  query.bindValue
		    (0, m_crypts.value("email")->
		     encryptedThenHashed(QByteArray("Deleted"), &ok).
		     toBase64());
		else
		  ok = false;

		query.bindValue(1, oid);
	      }

	    if(ok)
	      {
		if(!query.exec())
		  {
		    /*
		    ** We may be attempting to delete a letter from the
		    ** inbox that also exists in the trash. This can occur
		    ** whenever we request e-mail from other offices that was
		    ** also delivered to us.
		    ** The letter's date in the trash folder will be stale.
		    */

		    if(query.lastError().text().toLower().contains("unique"))
		      {
			QSqlQuery query(db);

			query.exec("PRAGMA secure_delete = ON");
			query.prepare("DELETE FROM folders WHERE OID = ?");
			query.bindValue(0, oid);
			query.exec();
			query.prepare("DELETE FROM folders_attachment "
				      "WHERE folders_oid = ?");
			query.bindValue(0, oid);
			query.exec();
		      }
		  }
		else if(m_ui.folder->currentIndex() == 2) // Trash
		  {
		    QSqlQuery query(db);

		    query.exec("PRAGMA secure_delete = ON");
		    query.prepare("DELETE FROM folders_attachment "
				  "WHERE folders_oid = ?");
		    query.bindValue(0, oid);
		    query.exec();
		  }
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  slotRefreshMail();
}

void spoton::slotEmptyTrash(void)
{
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to empty the Trash folder?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM folders WHERE folder_index = 2");
	query.exec("DELETE FROM folders_attachment WHERE folders_oid "
		   "NOT IN (SELECT OID FROM folders)");
	query.exec("VACUUM");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();

  if(m_ui.folder->currentIndex() == 2)
    {
      m_ui.mail->setRowCount(0);
      m_ui.mailMessage->clear();
    }
}

void spoton::slotEnableRetrieveMail(void)
{
  m_ui.retrieveMail->setEnabled(true);
}

void spoton::slotEnabledPostOffice(bool state)
{
  m_settings["gui/postoffice_enabled"] = state;

  QSettings settings;

  settings.setValue("gui/postoffice_enabled", state);
}

void spoton::slotGenerateGeminiInChat(void)
{
  auto const row = m_ui.participants->currentRow();

  if(row < 0)
    return;

  auto item1 = m_ui.participants->item(row, 1); // OID
  auto item2 = m_ui.participants->item(row, 6); // Gemini Encryption Key
  auto item3 = m_ui.participants->item(row, 7); // Gemini Hash Key

  if(!item1 || !item2 || !item3)
    return;
  else if(item1->data(Qt::UserRole).toBool()) // Temporary friend?
    return; // Temporary!

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QPair<QByteArray, QByteArray> gemini;

  gemini.first = spoton_crypt::
    strongRandomBytes(spoton_crypt::
		      cipherKeyLength(spoton_crypt::
				      preferredCipherAlgorithm()));
  gemini.second = spoton_crypt::strongRandomBytes
    (spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);

  if(saveGemini(gemini, item1->text()))
    {
      disconnect(m_ui.participants,
		 SIGNAL(itemChanged(QTableWidgetItem *)),
		 this,
		 SLOT(slotParticipantsItemChanged(QTableWidgetItem *)));
      item2->setText(gemini.first.toBase64());
      item3->setText(gemini.second.toBase64());
      connect(m_ui.participants,
	      SIGNAL(itemChanged(QTableWidgetItem *)),
	      this,
	      SLOT(slotParticipantsItemChanged(QTableWidgetItem *)));
    }

  QApplication::restoreOverrideCursor();
}

void spoton::slotJoinBuzzChannel(void)
{
  QByteArray id;
  QPair<QByteArray, QByteArray> keys;
  QPointer<spoton_buzzpage> page;
  QString error("");
  auto const channel(m_ui.channel->text().toLatin1());
  auto const channelSalt(m_ui.channelSalt->text().toLatin1());
  auto const channelType(m_ui.channelType->currentText().toLatin1());
  auto const hashKey(m_ui.buzzHashKey->text().toLatin1());
  auto const hashType(m_ui.buzzHashType->currentText().toLatin1());
  auto const iterationCount = static_cast<unsigned long int>
    (m_ui.buzzIterationCount->value());

  if(channel.isEmpty())
    {
      error = tr("Please provide a channel key.");
      goto done_label;
    }

  if(channelSalt.isEmpty())
    {
      error = tr("Please provide a channel salt.");
      goto done_label;
    }

  if(hashKey.isEmpty())
    {
      error = tr("Please provide a hash key.");
      goto done_label;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  keys = spoton_crypt::derivedKeys(channelType,
				   "sha1", // PBKDF2.
				   iterationCount,
				   channel + channelType + hashType,
				   channelSalt,
				   true,
				   error);
  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    goto done_label;

  if((page = m_buzzPages.value(keys.first, nullptr)))
    {
      if(m_ui.buzzTab->indexOf(page) != -1)
	m_ui.buzzTab->setCurrentWidget(page);

      goto done_label;
    }

  if(m_buzzIds.contains(keys.first))
    id = m_buzzIds.value(keys.first);
  else
    {
      id = spoton_crypt::strongRandomBytes
	(spoton_common::BUZZ_MAXIMUM_ID_LENGTH / 2).toHex();
      m_buzzIds[keys.first] = id;
    }

  m_ui.channel->clear();
  m_ui.channelSalt->clear();
  m_ui.channelType->setCurrentIndex(0);
  m_ui.buzzIterationCount->setValue(m_ui.buzzIterationCount->minimum());
  m_ui.buzzHashKey->clear();
  m_ui.buzzHashType->setCurrentIndex(0);
  page = new spoton_buzzpage
    (&m_kernelSocket,
     channel,
     channelSalt,
     channelType,
     id,
     iterationCount,
     hashKey,
     hashType,
     keys.first,
     this);
  m_buzzPages[page->key()] = page;
  connect(&m_buzzStatusTimer,
	  SIGNAL(timeout(void)),
	  page,
	  SLOT(slotSendStatus(void)));
  connect(page,
	  SIGNAL(changed(void)),
	  this,
	  SLOT(slotBuzzChanged(void)));
  connect(page,
	  SIGNAL(channelSaved(void)),
	  this,
	  SLOT(slotPopulateBuzzFavorites(void)));
  connect(page,
	  SIGNAL(destroyed(QObject *)),
	  this,
	  SLOT(slotBuzzPageDestroyed(QObject *)));
  connect(page,
	  SIGNAL(unify(void)),
	  this,
	  SLOT(slotUnifyBuzz(void)));
  connect(this,
	  SIGNAL(buzzNameChanged(const QByteArray &)),
	  page,
	  SLOT(slotBuzzNameChanged(const QByteArray &)));
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  page,
	  SLOT(slotSetIcons(void)));
  connect(this,
	  SIGNAL(minimal(const bool)),
	  page,
	  SLOT(slotMinimal(const bool)));
  emit minimal(m_ui.action_Minimal_Display->isChecked());
  m_ui.buzzTab->addTab
    (page, QString::fromUtf8(channel.constData(), channel.length()));
  m_ui.buzzTab->setCurrentIndex(m_ui.buzzTab->count() - 1);

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted() ||
       m_ui.kernelKeySize->currentText().toInt() == 0)
      {
	QByteArray message("addbuzz_");

	message.append(page->key().toBase64());
	message.append("_");
	message.append(page->channelType().toBase64());
	message.append("_");
	message.append(page->hashKey().toBase64());
	message.append("_");
	message.append(page->hashType().toBase64());
	message.append("\n");

	if(!writeKernelSocketData(message))
	  spoton_misc::logError
	    (QString("spoton::slotJoinBuzzChannel(): "
		     "write() failure for %1:%2.").
	     arg(m_kernelSocket.peerAddress().toString()).
	     arg(m_kernelSocket.peerPort()));
      }

 done_label:

  if(!error.isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
}

void spoton::slotKeepCopy(bool state)
{
  m_settings["gui/saveCopy"] = state;

  QSettings settings;

  settings.setValue("gui/saveCopy", state);
}

void spoton::slotKeepOnlyUserDefinedNeighbors(bool state)
{
  m_settings["gui/keepOnlyUserDefinedNeighbors"] = state;

  QSettings settings;

  settings.setValue("gui/keepOnlyUserDefinedNeighbors", state);

  if(m_neighborsFuture.isFinished() && state)
    m_neighborsLastModificationTime = QDateTime();
}

void spoton::slotKernelCipherTypeChanged(int index)
{
  Q_UNUSED(index);
  m_settings["gui/kernelCipherType"] =
    m_ui.kernelCipherType->currentText().toLower();

  QSettings settings;

  settings.setValue
    ("gui/kernelCipherType", m_settings.value("gui/kernelCipherType"));
}

void spoton::slotKernelHashTypeChanged(int index)
{
  Q_UNUSED(index);
  m_settings["gui/kernelHashType"] =
    m_ui.kernelHashType->currentText().toLower();

  QSettings settings;

  settings.setValue
    ("gui/kernelHashType", m_settings.value("gui/kernelHashType"));
}

void spoton::slotKernelKeySizeChanged(int index)
{
  auto const text(m_ui.kernelKeySize->itemText(index));

  m_kernelSocket.setProperty("key_size", text.toInt());
  m_settings["gui/kernelKeySize"] = text.toInt();
  QSettings().setValue
    ("gui/kernelKeySize", m_settings.value("gui/kernelKeySize"));
}

void spoton::slotKernelStatus(void)
{
  if(isKernelActive() && m_sb.kernelstatus == sender())
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Are you sure that you wish to deactivate the kernel?"));
      mb.setWindowIcon(windowIcon());
      mb.setWindowModality(Qt::ApplicationModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  return;
	}

      QApplication::processEvents();
      slotDeactivateKernel();
    }
  else
    {
      slotDeactivateKernel();
      slotActivateKernel();
    }
}

void spoton::slotListenerIPComboChanged(int index)
{
  /*
  ** Method will be called because of activity in prepareListenerIPCombo().
  */

  if(index == 0)
    {
      m_ui.listenerIP->clear();
      m_ui.listenerScopeId->clear();
      m_ui.listenerIP->setEnabled(true);
    }
  else
    {
      m_ui.listenerIP->setText(m_ui.listenerIPCombo->currentText());
      m_ui.listenerIP->setCursorPosition(0);
      m_ui.listenerIP->setEnabled(false);
    }
}

void spoton::slotListenerSelected(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  populateAccounts(oid);
  populateListenerIps(oid);
  populateMOTD(oid);
}

void spoton::slotMailSelected(QTableWidgetItem *item)
{
  if(!item)
    {
      m_ui.mailMessage->clear();
      return;
    }

  int row = item->row();

  if(row < 0)
    {
      m_ui.mailMessage->clear();
      return;
    }

  {
    QString goldbug("");
    auto item = m_ui.mail->item(row, 5); // Gold Bug

    if(item)
      goldbug = item->text();

    if(goldbug == "1")
      {
	QDialog dialog(this);
	Ui_spoton_goldbug ui;

	ui.setupUi(&dialog);
	ui.secrets->setMenu(new QMenu(this));
	ui.secrets->menu()->setStyleSheet("QMenu {menu-scrollable: 1;}");
	connect(ui.secrets,
		SIGNAL(clicked(void)),
		ui.secrets,
		SLOT(showMenu(void)));
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	QMapIterator<QString, QByteArray> it
	  (m_smpWindow->streams(QStringList() << "email" << "poptastic"));

	while(it.hasNext())
	  {
	    it.next();

	    auto action = ui.secrets->menu()->addAction
	      (it.key(),
	       this,
	       SLOT(slotGoldBugDialogActionSelected(void)));

	    action->setProperty
	      ("pointer", QVariant::fromValue<QWidget *> (ui.goldbug));
	    action->setProperty("stream", it.value());
	  }

	if(ui.secrets->menu()->actions().isEmpty())
	  {
	    /*
	    ** Please do not translate Empty.
	    */

	    auto action = ui.secrets->menu()->addAction("Empty");

	    action->setEnabled(false);
	  }

	QApplication::restoreOverrideCursor();
	dialog.setWindowTitle(tr("%1: Gold Bug").arg(SPOTON_APPLICATION_NAME));

	if(dialog.exec() != QDialog::Accepted)
	  {
	    QApplication::processEvents();
	    return;
	  }
	else
	  {
	    QApplication::processEvents();
	    goldbug = ui.goldbug->text().trimmed();
	  }

	if(goldbug.isEmpty())
	  return;

	QByteArray magnet;
	auto const bytes(goldbug.toUtf8());
	auto const size = static_cast<int>
	  (spoton_crypt::cipherKeyLength(spoton_crypt::
					 preferredCipherAlgorithm()));

	magnet.append("magnet:?aa=");
	magnet.append(spoton_crypt::preferredHashAlgorithm());
	magnet.append("&ak=");
	magnet.append
	  (bytes.mid(size, spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES));
	magnet.append("&ea=");
	magnet.append(spoton_crypt::preferredCipherAlgorithm());
	magnet.append("&ek=");
	magnet.append(bytes.mid(0, size));
	magnet.append("&xt=urn:forward-secrecy");

	auto const rc = applyGoldBugToLetter(magnet, row);

	if(rc == APPLY_GOLDBUG_TO_LETTER_ERROR_ATTACHMENTS)
	  {
	    QMessageBox::critical(this,
				  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				  tr("An error occurred while processing "
				     "the attachment(s)."));
	    QApplication::processEvents();
	    return;
	  }
	else if(rc == APPLY_GOLDBUG_TO_LETTER_ERROR_DATABASE)
	  {
	    QMessageBox::critical(this,
				  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				  tr("A database error occurred."));
	    QApplication::processEvents();
	    return;
	  }
	else if(rc == APPLY_GOLDBUG_TO_LETTER_ERROR_GENERAL)
	  {
	    QMessageBox::critical(this,
				  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				  tr("The provided Gold Bug may be "
				     "incorrect."));
	    QApplication::processEvents();
	    return;
	  }
	else if(rc == APPLY_GOLDBUG_TO_LETTER_ERROR_MEMORY)
	  {
	    QMessageBox::critical(this,
				  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				  tr("A severe memory issue occurred."));
	    QApplication::processEvents();
	    return;
	  }
	else if(item)
	  row = item->row(); // Sorting.
      }
  }

  QString date("");
  QString fromTo("");
  QString message("");
  QString signature("");
  QString status("");
  QString subject("");
  QString text("");

  {
    auto item = m_ui.mail->item(row, 0); // Date

    if(item)
      date = item->text();

    item = m_ui.mail->item(row, 1); // From / To

    if(item)
      fromTo = item->text();

    item = m_ui.mail->item(row, 2); // Status

    if(item)
      status = item->text();

    item = m_ui.mail->item(row, 3); // Subject

    if(item)
      subject = item->text();

    item = m_ui.mail->item(row, 6); // Message

    if(item)
      message = item->text();

    item = m_ui.mail->item(row, 10); // Signature

    if(item)
      signature = item->text();
  }

  if(m_ui.folder->currentIndex() == 0) // Inbox
    {
      if(signature.isEmpty())
	{
	  text.append(tr("<font color=#9F6000><b>"
			 "The message was not digitally signed "
			 "or digital signatures are not supported."
			 "</b></font>"));
	  text.append("<br><br>");
	}
      else
	{
	  text.append(tr("<font color=#4F8A10><b>"
			 "The message appears to have been digitally signed."
			 "</b></font>"));
	  text.append("<br><br>");
	}

      text.append(tr("<b>From:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>To:</b> me"));
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<hr>");
      text.append("<span style=\"font-size:large;\">");
      text.append(message);
      text.append("</span>");

      if(status != "Read")
	{
	  QTableWidgetItem *item = nullptr;

	  if((item = m_ui.mail->
	      item(row, m_ui.mail->columnCount() - 1))) // OID
	    if(updateMailStatus(item->text(), "Read"))
	      if((item = m_ui.mail->item(row, 2))) // Status
		item->setText("Read");
	}
    }
  else if(m_ui.folder->currentIndex() == 1) // Sent
    {
      text.append(tr("<b>From:</b> me"));
      text.append("<br>");
      text.append(tr("<b>To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<hr>");
      text.append(message);
    }
  else // Trash
    {
      text.append(tr("<b>From/To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>From/To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<hr>");
      text.append(message);

      if(status != "Deleted")
	{
	  QTableWidgetItem *item = nullptr;

	  if((item = m_ui.mail->
	      item(row, m_ui.mail->columnCount() - 1))) // OID
	    if(updateMailStatus(item->text(), "Deleted"))
	      if((item = m_ui.mail->item(row, 2))) // Status
		item->setText("Deleted");
	}
    }

  m_ui.mailMessage->clear();
  m_ui.email_plain->isChecked() ?
    m_ui.mailMessage->setPlainText(text) : m_ui.mailMessage->setHtml(text);
  m_ui.mailMessage->horizontalScrollBar()->setValue(0);
  m_ui.mailMessage->verticalScrollBar()->setValue(0);
}

void spoton::slotMailSelected(void)
{
  if(!m_ui.mail->selectionModel()->hasSelection())
    m_ui.mailMessage->clear();
  else
    slotMailSelected(m_ui.mail->currentItem());
}

void spoton::slotMailTabChanged(int index)
{
  Q_UNUSED(index);
}

void spoton::slotMaximumEmailFileSizeChanged(int value)
{
  m_settings["gui/maximumEmailFileSize"] = value;

  QSettings settings;

  settings.setValue("gui/maximumEmailFileSize", value);
}

void spoton::slotParticipantDoubleClicked(QTableWidgetItem *item)
{
  if(!item)
    return;

  if(item->data(Qt::UserRole).toBool()) // Temporary friend?
    return;
  else if(item->column() == 6 ||
	  item->column() == 7) // Gemini Encryption Key, Gemini Hash Key
    return;

  QIcon icon;
  QString keyType("");
  QString oid("");
  QString participant("");
  QString publicKeyHash("");
  QString status("");
  auto const row = item->row();
  auto gitMessage = false;

  item = m_ui.participants->item(row, 0); // Participant

  if(!item)
    return;

  icon = item->icon();
  participant = item->text();
  item = m_ui.participants->item(row, 1); // OID

  if(!item)
    return;

  keyType = item->data(Qt::ItemDataRole(Qt::UserRole + 1)).toString();
  oid = item->text();
  item = m_ui.participants->item(row, 3); // public_key_hash

  if(!item)
    return;

  publicKeyHash = item->text();
  item = m_ui.participants->item(row, 4); // Status

  if(item)
    status = item->text();

  item = m_ui.participants->item(row, 9); // GIT Messages (Boolean)

  if(item)
    gitMessage = item->checkState() == Qt::Checked;

  auto smp = m_smps.value(publicKeyHash, nullptr);

  if(m_chatWindows.contains(publicKeyHash))
    {
      auto chat = m_chatWindows.value(publicKeyHash);

      if(chat)
	{
	  m_starsLastModificationTime = QDateTime();

	  if(smp)
	    chat->setSMPVerified(smp->passed());

	  chat->showNormal();
	  chat->activateWindow();
	  chat->raise();
	  return;
	}
      else
	m_chatWindows.remove(publicKeyHash);
    }

  auto chat = new spoton_chatwindow
    (icon,
     oid,
     keyType,
     participant,
     publicKeyHash,
     status,
     gitMessage,
     &m_kernelSocket,
     this);

  connect(chat,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotMessagesAnchorClicked(const QUrl &)));
  connect(chat,
	  SIGNAL(deriveGeminiPairViaSMP(const QString &, const QString &)),
	  this,
	  SLOT(slotDeriveGeminiPairViaSMP(const QString &,
					  const QString &)));
  connect(chat,
	  SIGNAL(destroyed(void)),
	  this,
	  SLOT(slotChatWindowDestroyed(void)));
  connect(chat,
	  SIGNAL(initializeSMP(const QString &)),
	  this,
	  SLOT(slotInitializeSMP(const QString &)));
  connect(chat,
	  SIGNAL(messageSent(void)),
	  this,
	  SLOT(slotChatWindowMessageSent(void)));
  connect(chat,
	  SIGNAL(prepareSMP(const QString &)),
	  this,
	  SLOT(slotPrepareSMP(const QString &)));
  connect(chat,
	  SIGNAL(verifySMPSecret(const QString &,
				 const QString &,
				 const QString &)),
	  this,
	  SLOT(slotVerifySMPSecret(const QString &,
				   const QString &,
				   const QString &)));
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  chat,
	  SLOT(slotSetIcons(void)));
  connect(this,
	  SIGNAL(statusChanged(const QIcon &,
			       const QString &,
			       const QString &,
			       const QString &,
			       const bool)),
	  chat,
	  SLOT(slotSetStatus(const QIcon &,
			     const QString &,
			     const QString &,
			     const QString &,
			     const bool)));
  m_chatWindows[publicKeyHash] = chat;
  m_starsLastModificationTime = QDateTime();
  chat->center(this);
  chat->showNormal(); // Custom.
  chat->activateWindow();
  chat->raise();

  if(smp)
    chat->setSMPVerified(smp->passed());
}

void spoton::slotParticipantsItemChanged(QTableWidgetItem *item)
{
  if(!item)
    return;
  else if(!(item->column() == 0 || // Participant
	    item->column() == 6 || // Gemini Encryption Key
	    item->column() == 7))  // Gemini Hash Key
    return;
  else if(!m_ui.participants->item(item->row(), 1)) // OID
    return;

  if(item->column() == 0)
    {
      /*
      ** Uncheck all other items.
      */

      disconnect(m_ui.participants,
		 SIGNAL(itemChanged(QTableWidgetItem *)),
		 this,
		 SLOT(slotParticipantsItemChanged(QTableWidgetItem *)));

      for(int i = 0; i < m_ui.participants->rowCount(); i++)
	if(i != item->row() && m_ui.participants->item(i, 0))
	  if(Qt::ItemIsUserCheckable & m_ui.participants->item(i, 0)->flags())
	    m_ui.participants->item(i, 0)->setCheckState(Qt::Unchecked);

      connect(m_ui.participants,
	      SIGNAL(itemChanged(QTableWidgetItem *)),
	      this,
	      SLOT(slotParticipantsItemChanged(QTableWidgetItem *)));
      return;
    }

  QTableWidgetItem *item1 = nullptr;
  QTableWidgetItem *item2 = nullptr;

  if(item->column() == 6)
    {
      item1 = item;
      item2 = m_ui.participants->item(item->row(), 7);
    }
  else
    {
      item1 = m_ui.participants->item(item->row(), 6);
      item2 = item;
    }

  if(!item1 || !item2)
    return;

  QPair<QByteArray, QByteArray> gemini;

  gemini.first = item1->text().toLatin1();
  gemini.second = item2->text().toLatin1();
  saveGemini(gemini, m_ui.participants->item(item->row(), 1)->text()); // OID
}

void spoton::slotPublicizeAllListenersPlaintext(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  QByteArray message;

  message.append("publicizealllistenersplaintext\n");

  if(!writeKernelSocketData(message))
    spoton_misc::logError
      (QString("spoton::slotPublicizeAllListenersPlaintext(): "
	       "write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotPublicizeListenerPlaintext(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray message;

  message.append("publicizelistenerplaintext_");
  message.append(oid.toUtf8());
  message.append("\n");

  if(!writeKernelSocketData(message))
    spoton_misc::logError
      (QString("spoton::slotPublicizeListenerPlaintext(): "
	       "write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotPublishPeriodicallyToggled(bool state)
{
  m_settings["gui/publishPeriodically"] = state;

  QSettings settings;

  settings.setValue("gui/publishPeriodically", state);
}

void spoton::slotPublishedKeySizeChanged(int index)
{
  auto const text(m_optionsUi.publishedKeySize->itemText(index));

  m_settings["gui/publishedKeySize"] = text.toInt();

  QSettings settings;

  settings.setValue
    ("gui/publishedKeySize",
     m_settings.value("gui/publishedKeySize"));
}

void spoton::slotReceivedKernelMessage(void)
{
  while(m_kernelSocket.bytesAvailable() > 0 &&
	m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    {
      auto const data(m_kernelSocket.readAll());

      if(!data.isEmpty())
	emit dataReceived(static_cast<qint64> (data.length()));

      m_kernelSocketData.append(data);
    }

  if(m_kernelSocketData.endsWith("\n"))
    {
      auto const list
	(m_kernelSocketData.mid(0, m_kernelSocketData.lastIndexOf("\n")).
	 split('\n'));

      m_kernelSocketData.remove(0, m_kernelSocketData.lastIndexOf("\n"));

      for(int i = 0; i < list.size(); i++)
	{
	  auto data(list.at(i));

	  if(data.startsWith("authentication_requested_"))
	    {
	      data.remove
		(0, static_cast<int> (qstrlen("authentication_requested_")));

	      if(!data.isEmpty())
		authenticationRequested(data);
	    }
	  else if(data.startsWith("buzz_"))
	    {
	      data.remove
		(0, static_cast<int> (qstrlen("buzz_")));

	      auto list(data.split('_'));

	      if(list.size() != 2)
		continue;

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      auto const key(list.value(1));

	      /*
	      ** Find the channel(s)!
	      */

	      auto page = m_buzzPages.value(key, nullptr);

	      if(!page)
		continue;

	      list = list.value(0).split('\n');

	      if(!list.isEmpty())
		list.replace
		  (list.size() - 1,
		   QByteArray::fromBase64(list.at(list.size() - 1)));
	      else
		continue;

	      auto dateTime
		(QDateTime::fromString(list.at(list.size() - 1).constData(),
				       "MMddyyyyhhmmss"));

	      if(!spoton_misc::
		 acceptableTimeSeconds(dateTime,
				       spoton_common::BUZZ_TIME_DELTA))
		continue;

	      for(int i = 0; i < list.size() - 1; i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      list.removeAt(0); // Message Type

	      if(list.size() == 3)
		page->userStatus(list);
	      else if(list.size() == 4)
		page->appendMessage(list);
	    }
	  else if(data.startsWith("bytes_received_"))
	    emit dataReceived(data.mid(15).toLongLong());
	  else if(data.startsWith("bytes_sent_"))
	    emit dataSent(data.mid(11).toLongLong());
	  else if(data.startsWith("chat_status_"))
	    {
	      data.remove
		(0, static_cast<int> (qstrlen("chat_status_")));

	      if(!data.isEmpty())
		{
		  auto list(data.split('_'));

		  if(list.size() != 2)
		    continue;

		  for(int i = 0; i < list.size() - 1; i++)
		    /*
		    ** We'll ignore the status message.
		    */

		    list.replace(i, QByteArray::fromBase64(list.at(i)));

		  QString msg("");
		  auto const now(QDateTime::currentDateTime());

		  msg.append
		    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
		     arg(now.toString("MM")).
		     arg(now.toString("dd")).
		     arg(now.toString("yyyy")).
		     arg(now.toString("hh")).
		     arg(now.toString("mm")).
		     arg(now.toString("ss")));
		  msg.append(QString("<i>%1</i>").arg(list.at(1).constData()));

		  if(m_chatWindows.contains(list.value(0).toBase64()))
		    {
		      auto chat = m_chatWindows.value(list.value(0).toBase64());

		      if(chat)
			{
			  chat->append(msg);
#if defined(Q_OS_WINDOWS)
			  if(chat->isVisible())
			    chat->activateWindow();
#endif
			}
		    }

		  auto const lines = m_settings.value
		    ("gui/chat_maximum_lines", -1).toInt();

		  if(lines >= 0)
		    if(lines <= m_ui.messages->document()->blockCount())
		      m_ui.messages->clear();

		  m_ui.messages->append(msg);
		  m_ui.messages->verticalScrollBar()->setValue
		    (m_ui.messages->verticalScrollBar()->maximum());

		  if(currentTabName() != "chat")
		    m_sb.chat->setVisible(true);

		  playSound("qrc:/Sounds/receive.wav");
		}
	    }
	  else if(data.startsWith("forward_secrecy_request_"))
	    {
	      data.remove
		(0, static_cast<int> (qstrlen("forward_secrecy_request_")));
	      forwardSecrecyRequested(data.split('_'));
	    }
	  else if(data.startsWith("forward_secrecy_response_"))
	    {
	      data.remove
		(0, static_cast<int> (qstrlen("forward_secrecy_response_")));

	      auto list(data.split('_'));

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      if(!list.isEmpty())
		{
		  auto const keyType = spoton_misc::keyTypeFromPublicKeyHash
		    (list.value(0), m_crypts.value("chat", nullptr));
		  auto name = spoton_misc::nameFromPublicKeyHash
		    (list.value(0), m_crypts.value("chat", nullptr));

		  if(name.isEmpty())
		    {
		      if(keyType == "poptastic")
			name = "unknown@unknown.org";
		      else
			name = "unknown";
		    }

		  QString const str(list.value(0).toBase64());

		  notify(QDateTime::currentDateTime().toString());
		  notify
		    (tr("Participant <b>%1</b> (%2) "
			"has completed a Forward Secrecy exchange.<br>").
		     arg(name).
		     arg(str.mid(0, 16) + "..." + str.right(16)));
		}
	    }
	  else if(data.startsWith("gpg_message_"))
	    {
#ifdef SPOTON_GPGME_ENABLED
	      data.remove(0, static_cast<int> (qstrlen("gpg_message_")));

	      auto list(data.split('_'));

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      if(list.size() == 2)
		m_rosetta->processGPGMessage(list.at(0), list.at(1));
#endif
	    }
	  else if(data.startsWith("message_"))
	    {
	      data.remove
		(0, static_cast<int> (qstrlen("message_")));

	      if(!data.isEmpty())
		{
		  auto list(data.split('_'));

		  if(list.size() != 7)
		    continue;

		  for(int i = 0; i < list.size() - 1; i++)
		    /*
		    ** We'll ignore the message authentication
		    ** code.
		    */

		    list.replace(i, QByteArray::fromBase64(list.at(i)));

		  QList<QByteArray> values;
		  QPointer<spoton_chatwindow> chat;
		  QString notsigned(tr(" "));

		  if(list.value(5).isEmpty())
		    notsigned = tr(" unsigned ");

		  if(m_chatWindows.contains(list.value(0).toBase64()))
		    chat = m_chatWindows.value
		      (list.value(0).toBase64(), nullptr);

		  if(spoton_misc::isValidBuzzMagnet(list.value(2)))
		    {
		      QString msg("");
		      auto const hash
			(list.at(0)); /*
				      ** SHA-512 hash of the sender's
				      ** public key.
				      */
		      auto const now(QDateTime::currentDateTime());

		      msg.append
			(QString("[%1/%2/%3 %4:%5<font color=gray>:%6"
				 "</font>] ").
			 arg(now.toString("MM")).
			 arg(now.toString("dd")).
			 arg(now.toString("yyyy")).
			 arg(now.toString("hh")).
			 arg(now.toString("mm")).
			 arg(now.toString("ss")));
		      msg.append
			(tr("<i>%2...%3 cordially invites you to "
			    "join a Buzz channel. Please <a href='%1'>"
			    "accept</a> the invitation. If accepted, a new "
			    "window will be displayed.</i>").
			 arg(list.value(2).constData()).
			 arg(hash.toBase64().mid(0, 16).constData()).
			 arg(hash.toBase64().right(16).constData()));

		      if(chat)
			{
			  chat->append(msg);
#if defined(Q_OS_WINDOWS)
			  if(chat->isVisible())
			    chat->activateWindow();
#endif
			}

		      auto const lines = m_settings.value
			("gui/chat_maximum_lines", -1).toInt();

		      if(lines >= 0)
			if(lines <= m_ui.messages->document()->blockCount())
			  m_ui.messages->clear();

		      m_ui.messages->append(msg);
		      m_ui.messages->verticalScrollBar()->setValue
			(m_ui.messages->verticalScrollBar()->maximum());

		      if(currentTabName() != "chat")
			m_sb.chat->setVisible(true);

		      playSound("qrc:/Sounds/receive.wav");
		      continue;
		    }
		  else if(spoton_misc::isValidSMPMagnet(list.value(2), values))
		    {
		      QList<QTableWidgetItem *> items;
		      QString keyType("");
		      QString msg("");
		      QString smpName("");
		      auto const hash
			(list.at(0)); /*
				      ** SHA-512 hash of the sender's
				      ** public key.
				      */
		      auto const now(QDateTime::currentDateTime());

		      items = findItems(m_ui.participants, hash.toBase64(), 3);

		      if(!items.isEmpty() && items.at(0))
			{
			  auto item = m_ui.participants->
			    item(items.at(0)->row(), 0); // Name

			  if(item)
			    {
			      keyType = item->data
				(Qt::ItemDataRole(Qt::UserRole + 1)).
				toString();
			      smpName = item->text();
			    }
			}

		      if(smpName.isEmpty())
			{
			  if(keyType == "poptastic")
			    smpName = "unknown@unknown.org";
			  else
			    smpName = "unknown";
			}

		      auto smp = m_smps.value(hash.toBase64(), nullptr);

		      if(!smp)
			{
			  initializeSMP(hash.toBase64());
			  smp = m_smps.value(hash.toBase64(), nullptr);
			}

		      msg.append
			(QString("[%1/%2/%3 %4:%5<font color=gray>:%6"
				 "</font>] ").
			 arg(now.toString("MM")).
			 arg(now.toString("dd")).
			 arg(now.toString("yyyy")).
			 arg(now.toString("hh")).
			 arg(now.toString("mm")).
			 arg(now.toString("ss")));
		      msg.append
			(tr("<i>Received an%1SMP message "
			    "from <b>%2</b> (%3...%4). We're at step %5.</i>").
			 arg(notsigned).
			 arg(smpName).
			 arg(hash.toBase64().mid(0, 16).constData()).
			 arg(hash.toBase64().right(16).constData()).
			 arg(smp ? smp->step() : -1));

		      if(chat)
			{
			  chat->append(msg);
#if defined(Q_OS_WINDOWS)
			  if(chat->isVisible())
			    chat->activateWindow();
#endif
			}

		      auto const lines = m_settings.value
			("gui/chat_maximum_lines", -1).toInt();

		      if(lines >= 0)
			if(lines <= m_ui.messages->document()->blockCount())
			  m_ui.messages->clear();

		      m_ui.messages->append(msg);
		      m_ui.messages->verticalScrollBar()->setValue
			(m_ui.messages->verticalScrollBar()->maximum());

		      if(m_ui.status->currentIndex() == 3) // Away
			{
			  if(currentTabName() != "chat")
			    m_sb.chat->setVisible(true);

			  playSound("qrc:/Sounds/receive.wav");
			  continue;
			}

		      if(!smp)
			{
			  QString msg("");
			  auto const now(QDateTime::currentDateTime());

			  msg.append
			    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6"
				     "</font>] ").
			     arg(now.toString("MM")).
			     arg(now.toString("dd")).
			     arg(now.toString("yyyy")).
			     arg(now.toString("hh")).
			     arg(now.toString("mm")).
			     arg(now.toString("ss")));
			  msg.append(tr("<i>Unable to respond because "
					"an SMP object is not defined for "
					"%1 (%2...%3).</i>").
				     arg(smpName).
				     arg(hash.toBase64().mid(0, 16).
					 constData()).
				     arg(hash.toBase64().right(16).
					 constData()));

			  if(chat)
			    {
			      chat->append(msg);
#if defined(Q_OS_WINDOWS)
			      if(chat->isVisible())
				chat->activateWindow();
#endif
			    }

			  auto const lines = m_settings.value
			    ("gui/chat_maximum_lines", -1).toInt();

			  if(lines >= 0)
			    if(lines <= m_ui.messages->document()->blockCount())
			      m_ui.messages->clear();

			  m_ui.messages->append(msg);
			  m_ui.messages->verticalScrollBar()->setValue
			    (m_ui.messages->verticalScrollBar()->maximum());
			}

		      items = findItems(m_ui.participants, hash.toBase64(), 3);

		      QString oid("");
		      auto ok = true;
		      auto passed = false;

		      if(!items.isEmpty() && items.at(0))
			{
			  auto item = m_ui.participants->
			    item(items.at(0)->row(), 1); // OID

			  if(item)
			    {
			      keyType = item->data
				(Qt::ItemDataRole(Qt::UserRole + 1)).
				toString();
			      oid = item->text();
			    }
			}

		      if(chat)
			chat->setSMPVerified(false);

		      if(smp)
			values = smp->nextStep(values, &ok, &passed);

		      if(smp && (!ok || smp->step() == 4 || smp->step() == 5))
			{
			  msg.clear();
			  msg.append
			    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6"
				     "</font>] ").
			     arg(now.toString("MM")).
			     arg(now.toString("dd")).
			     arg(now.toString("yyyy")).
			     arg(now.toString("hh")).
			     arg(now.toString("mm")).
			     arg(now.toString("ss")));

			  if(smp->step() == 4 || smp->step() == 5)
			    {
			      if(passed)
				msg.append
				  (tr("<font color=green>"
				      "<i>SMP verification with "
				      "<b>%1</b> (%2...%3) "
				      "has succeeded.</i></font>").
				   arg(smpName).
				   arg(hash.toBase64().mid(0, 16).
				       constData()).
				   arg(hash.toBase64().right(16).
				       constData()));
			      else
				msg.append
				  (tr("<font color=red>"
				      "<i>SMP verification with "
				      "<b>%1</b> (%2...%3) "
				      "has failed.</i></font>").
				   arg(smpName).
				   arg(hash.toBase64().mid(0, 16).constData()).
				   arg(hash.toBase64().right(16).constData()));

			      /*
			      ** Set the SMP's state to the first stage.
			      ** Messaging popups may be displayed after
			      ** a successful SMP execution.
			      */

			      smp->setStep0();
			    }
			  else
			    msg.append
			      (tr("<font color=red>"
				  "<i>SMP verification with "
				  "<b>%1</b> (%2...%3) has "
				  "experienced a protocol failure. "
				  "The respective state machine has been reset."
				  "</i></font>").
			       arg(smpName).
			       arg(hash.toBase64().mid(0, 16).constData()).
			       arg(hash.toBase64().right(16).constData()));

			  auto const lines = m_settings.value
			    ("gui/chat_maximum_lines", -1).toInt();

			  if(lines >= 0)
			    if(lines <= m_ui.messages->document()->blockCount())
			      m_ui.messages->clear();

			  m_ui.messages->append(msg);
			  m_ui.messages->verticalScrollBar()->setValue
			    (m_ui.messages->verticalScrollBar()->maximum());

			  if(chat)
			    {
			      chat->append(msg);
			      chat->setSMPVerified(passed);
#if defined(Q_OS_WINDOWS)
			      if(chat->isVisible())
				chat->activateWindow();
#endif
			    }

			  /*
			  ** Let's reset the SMP state to s0.
			  */

			  if(!ok)
			    smp->initialize();
			}

		      if(ok)
			sendSMPLinkToKernel(values, keyType, oid, true);

		      if(currentTabName() != "chat")
			m_sb.chat->setVisible(true);

		      playSound("qrc:/Sounds/receive.wav");
		      continue;
		    }

		  QString msg("");
		  auto const utcDate(list.value(4));
		  auto const dateTime
		    (QDateTime::fromString(utcDate.constData(),
					   "MMddyyyyhhmmss"));
		  auto const hash(list.at(0)); /*
					       ** SHA-512 hash of the sender's
					       ** public key.
					       */
		  auto const items
		    (findItems(m_ui.participants, hash.toBase64(), 3));
		  auto const message(list.value(2));
		  auto const now(QDateTime::currentDateTime());
		  auto content
		    (QString::fromUtf8(message.constData(), message.length()));
		  auto name(list.value(1).trimmed());
		  auto ok = true;
		  auto sequenceNumber(list.value(3));

		  if(!items.isEmpty() && items.at(0))
		    {
		      auto item = m_ui.participants->
			item(items.at(0)->row(), 0); // Participant

		      if(item)
			name = item->text().toUtf8().trimmed();
		    }

		  if(name.isEmpty())
		    name = "unknown";

		  if(message.isEmpty())
		    content = "unknown";

		  sequenceNumber.toULongLong(&ok);

		  if(!ok || sequenceNumber == "0")
		    sequenceNumber = "1";

		  msg.append
		    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>]:").
		     arg(now.toString("MM")).
		     arg(now.toString("dd")).
		     arg(now.toString("yyyy")).
		     arg(now.toString("hh")).
		     arg(now.toString("mm")).
		     arg(now.toString("ss")));

		  if(m_settings.value("gui/chatTimestamps", true).toBool())
		    {
		      if(dateTime.isValid())
			{
			  auto const n(QDateTime::currentDateTimeUtc());
			  auto d(dateTime);
			  QString str("green");

#if (QT_VERSION >= QT_VERSION_CHECK(6, 8, 0))
			  d.setTimeZone(QTimeZone(QTimeZone::UTC));
#else
			  d.setTimeSpec(Qt::UTC);
#endif

			  if(qAbs(d.secsTo(n)) >
			     static_cast<qint64> (spoton_common::
						  CHAT_TIME_DELTA_MAXIMUM))
			    str = "#ff8c00";

			  if(str == "green")
			    msg.append
			      (QString("[%1/%2/%3 "
				       "<font color=%4>%5:%6:%7</font>]").
			       arg(dateTime.toString("MM")).
			       arg(dateTime.toString("dd")).
			       arg(dateTime.toString("yyyy")).
			       arg(str).
			       arg(dateTime.toString("hh")).
			       arg(dateTime.toString("mm")).
			       arg(dateTime.toString("ss")));
			  else
			    msg.append
			      (QString("[<font color=%1>%2/%3/%4 "
				       "%5:%6:%7</font>]").
			       arg(str).
			       arg(dateTime.toString("MM")).
			       arg(dateTime.toString("dd")).
			       arg(dateTime.toString("yyyy")).
			       arg(dateTime.toString("hh")).
			       arg(dateTime.toString("mm")).
			       arg(dateTime.toString("ss")));
			}
		      else
			msg.append
			  ("[00/00/0000 <font color=red>00:00:00</font>]");
		    }

		  auto first = false;
		  quint64 previousSequenceNumber = 1;

		  if(m_receivedChatSequenceNumbers.contains(hash))
		    previousSequenceNumber =
		      m_receivedChatSequenceNumbers[hash];
		  else
		    {
		      first = true;
		      previousSequenceNumber =
			sequenceNumber.toULongLong() - 1;
		    }

		  m_receivedChatSequenceNumbers[hash] =
		    sequenceNumber.toULongLong();

		  if(sequenceNumber.toULongLong() !=
		     previousSequenceNumber + 1)
		    msg.append(QString(":<font color=red>%1</font>: ").
			       arg(sequenceNumber.constData()));
		  else
		    msg.append(QString(":%1: ").
			       arg(sequenceNumber.constData()));

		  msg.append
		    (QString("<font color=blue>%1: </font>").
		     arg(QString::fromUtf8(name.constData(), name.length())));

		  if(notsigned != tr(" "))
		    msg.append
		      (tr("<font color=orange>unsigned: </font>"));

		  if(spoton_misc::isValidInstitutionMagnet(content.toLatin1()))
		    {
		      QString str("");

		      str.prepend("<a href='");
		      str.append(content);
		      str.append("'>");
		      str.append(content);
		      str.append("</a>");
		      content = str;
		    }
		  else if(spoton_misc::
			  isValidStarBeamMagnet(content.toLatin1()))
		    {
		      if(m_settings.value("gui/autoAddSharedSBMagnets",
					  true).toBool())
			slotAddEtpMagnet(content, false);

		      QString str("");

		      str.prepend("<a href='");
		      str.append(content);
		      str.append("'>");
		      str.append(content);
		      str.append("</a>");
		      content = str;
		    }

		  if(m_settings.value("gui/enableChatEmoticons",
				      false).toBool())
		    content = mapIconToEmoticon(content);

		  msg.append(content);

		  if(!m_locked)
		    if(m_optionsUi.displayPopups->isChecked())
		      if(first)
			if(!m_chatWindows.contains(hash.toBase64()))
			  {
			    slotParticipantDoubleClicked(items.at(0));
			    chat = m_chatWindows.value
			      (list.value(0).toBase64(), nullptr);
			  }

		  if(chat)
		    {
		      chat->append(msg);
#if defined(Q_OS_WINDOWS)
		      if(chat->isVisible())
			chat->activateWindow();
#endif
		    }

		  auto const lines = m_settings.value
		    ("gui/chat_maximum_lines", -1).toInt();

		  if(lines >= 0)
		    if(lines <= m_ui.messages->document()->blockCount())
		      m_ui.messages->clear();

		  m_ui.messages->append(msg);
		  m_ui.messages->verticalScrollBar()->setValue
		    (m_ui.messages->verticalScrollBar()->maximum());

		  if(currentTabName() != "chat")
		    m_sb.chat->setVisible(true);

		  playSound("qrc:/Sounds/receive.wav");
		}
	    }
	  else if(data == "newmail")
	    {
	      m_sb.email->setVisible(true);
#if SPOTON_GOLDBUG == 1
	      populateMail();
#endif
	      playSound("qrc:/Sounds/echo.wav");
	    }
	  else if(data.startsWith("notification_"))
	    {
	      data.remove(0, static_cast<int> (qstrlen("notification_")));

	      if(!data.isEmpty())
		{
		  notify(QDateTime::currentDateTime().toString());
		  notify(data + "<br>");
		}
	    }
	  else if(data.startsWith("smp_"))
	    {
	      data.remove(0, static_cast<int> (qstrlen("smp_")));

	      auto list(data.split('_'));

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      if(!list.isEmpty())
		emit smpMessageReceivedFromKernel(list);
	    }
	}
    }
  else if(m_kernelSocketData.length() >
	  static_cast<int> (spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH))
    {
      m_kernelSocketData.clear();
      spoton_misc::logError
	(QString("spoton::slotReceivedKernelMessage(): "
		 "unable to detect an EOL in m_kernelSocketData for %1:%2. "
		 "The container is bloated! Purging.").
	 arg(m_kernelSocket.peerAddress().toString()).
	 arg(m_kernelSocket.peerPort()));
    }
}

void spoton::slotRefreshMail(void)
{
  if(m_ui.mailTab->currentIndex() == 1)
    {
      refreshInstitutions();
      return;
    }

  populateMail();
}

void spoton::slotRefreshPostOffice(void)
{
  if(!m_crypts.value("email", nullptr))
    return;
  else if(m_ui.mailTab->currentIndex() != 1)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	m_ui.postoffice->setRowCount(0);
	m_ui.postoffice->setSortingEnabled(false);

	QSqlQuery query(db);
	int totalRows = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM post_office"))
	  if(query.next())
	    m_ui.postoffice->setRowCount(query.value(0).toInt());

	if(query.exec("SELECT date_received, " // 0
		      "message_bundle, "       // 1
		      "recipient_hash "        // 2
		      "FROM post_office"))
	  {
	    int row = 0;

	    while(query.next() && totalRows < m_ui.postoffice->rowCount())
	      {
		totalRows += 1;

		for(int i = 0; i < query.record().count(); i++)
		  {
		    QTableWidgetItem *item = nullptr;
		    auto ok = true;

		    if(i == 0)
		      row += 1;

		    if(i == 0)
		      {
			item = new QTableWidgetItem
			  (m_crypts.value("email")->
			   decryptedAfterAuthenticated
			   (QByteArray::fromBase64(query.value(i).
						   toByteArray()),
			    &ok).constData());

			if(!ok)
			  item->setText(tr("error"));
		      }
		    else if(i == 1)
		      {
			auto const bytes
			  (m_crypts.value("email")->
			   decryptedAfterAuthenticated
			   (QByteArray::fromBase64(query.value(i).
						   toByteArray()),
			    &ok));

			if(ok)
			  item = new spoton_table_widget_item
			    (QString::number(bytes.length()));
			else
			  item = new QTableWidgetItem(tr("error"));
		      }
		    else
		      item = new QTableWidgetItem(query.value(i).toString());

		    item->setFlags
		      (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		    m_ui.postoffice->setItem(row - 1, i, item);
		  }
	      }
	  }

	m_ui.postoffice->setRowCount(totalRows);
	m_ui.postoffice->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotRemoveEmailParticipants(void)
{
  if(!m_ui.emailParticipants->selectionModel()->hasSelection())
    return;

  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"E-Mail participant(s)?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto const list
	  (m_ui.emailParticipants->selectionModel()->
	   selectedRows(1)); // OID

	for(int i = 0; i < list.size(); i++)
	  {
	    auto const data(list.at(i).data());

	    if(!data.isNull() && data.isValid())
	      {
		query.exec("PRAGMA secure_delete = ON");
		query.prepare("DELETE FROM friends_public_keys WHERE "
			      "OID = ?");
		query.bindValue(0, data.toString());

		if(query.exec())
		  emit participantDeleted(data.toString(), "email");
	      }
	  }

	spoton_misc::purgeSignatureRelationships
	  (db, m_crypts.value("chat", nullptr));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotRemoveParticipants(void)
{
  if(!m_ui.participants->selectionModel()->hasSelection())
    return;

  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"Chat participant(s)?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto list
	  (m_ui.participants->selectionModel()->selectedRows(1)); // OID
	auto listHashes
	  (m_ui.participants->selectionModel()->
	   selectedRows(3)); // public_key_hash

	while(!list.isEmpty() && !listHashes.isEmpty())
	  {
	    auto const data(list.takeFirst().data());
	    auto const hash(listHashes.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      {
		query.exec("PRAGMA secure_delete = ON");
		query.prepare("DELETE FROM friends_public_keys WHERE "
			      "OID = ?");
		query.bindValue(0, data.toString());

		if(query.exec())
		  emit participantDeleted(data.toString(), "chat");
	      }

	    if(m_chatSequenceNumbers.contains(data.toString()))
	      m_chatSequenceNumbers.remove(data.toString());

	    if(m_receivedChatSequenceNumbers.contains
	       (QByteArray::fromBase64(hash.toByteArray())))
	      m_receivedChatSequenceNumbers.
		remove(QByteArray::fromBase64(hash.toByteArray()));

	    m_chatQueues.remove(hash.toString());

	    if(m_chatWindows.contains(hash.toString()))
	      {
		auto chat = m_chatWindows.value(hash.toString(), nullptr);

		m_chatWindows.remove(hash.toString());

		if(chat)
		  chat->deleteLater();
	      }

	    if(m_smps.contains(hash.toString()))
	      {
		auto smp = m_smps.value(hash.toString(), nullptr);

		m_smps.remove(hash.toString());
		delete smp;
	      }
	  }

	spoton_misc::purgeSignatureRelationships
	  (db, m_crypts.value("chat", nullptr));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotReply(void)
{
  auto const row = m_ui.mail->currentRow();

  if(row < 0)
    return;

  auto item = m_ui.mail->item(row, 5); // Gold Bug

  if(!item)
    return;

  if(item->text() != "0")
    {
      /*
      ** How can we reply to an encrypted message?
      */

      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Cannot reply to an encrypted message. "
			       "Please decrypt the message by providing "
			       "the correct Gold Bug."));
      QApplication::processEvents();
      return;
    }

  item = m_ui.mail->item(row, 6); // Message

  if(!item)
    return;

  auto message(item->text());

  item = m_ui.mail->item(row, 8); // receiver_sender_hash

  if(!item)
    return;

  auto const receiverSenderHash(item->text());

  item = m_ui.mail->item(row, 3); // Subject

  if(!item)
    return;

  if(m_ui.emailSplitter->sizes().at(1) == 0)
    m_ui.emailSplitter->setSizes(QList<int> () << width() / 2 << width() / 2);

#if SPOTON_GOLDBUG == 1
  m_ui.mailTab->setCurrentIndex(2); // Write panel.
#endif

  auto const subject(item->text());

  if(m_ui.richtext->isChecked())
    {
      message = "<br><span style=\"font-size:large;\">" + message + "</span>";
      m_ui.outgoingMessage->setHtml(message);
    }
  else
    m_ui.outgoingMessage->setPlainText("\n\n" + message);

  m_ui.outgoingSubject->setText(tr("Re: ") + subject);
  m_ui.outgoingSubject->setCursorPosition(0);

  /*
  ** The original author may have vanished.
  */

  m_ui.emailParticipants->selectionModel()->clear();

  auto found = false;

  for(int i = 0; i < m_ui.emailParticipants->rowCount(); i++)
    {
      auto item = m_ui.emailParticipants->item(i, 3); // public_key_hash

      if(item && item->text() == receiverSenderHash)
	{
	  found = true;
	  m_ui.emailParticipants->selectRow(i);
	  break;
	}
    }

  if(!found)
    {
      auto item = m_ui.mail->item(row, 1); // From / To

      if(item)
	{
	  auto const str(item->text());
	  auto const index1 = str.indexOf('.');
	  auto const index2 = str.indexOf('@');

	  if(index1 > 0 &&
	     index1 < str.length() - 1 &&
	     index2 > 0 &&
	     index2 < str.length() - 1)
	    {
	      QMessageBox mb(this);

	      mb.setIcon(QMessageBox::Question);
	      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	      mb.setText
		(tr("Would you like to save the e-mail address %1?").arg(str));
	      mb.setWindowIcon(windowIcon());
	      mb.setWindowModality(Qt::ApplicationModal);
	      mb.setWindowTitle
		(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

	      if(mb.exec() == QMessageBox::Yes)
		{
		  QApplication::processEvents();
		  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
		  addFriendsKey(str.toLatin1(), "E", this);
		  m_emailAddressAdded = str;
		  slotPopulateParticipants();
		  QApplication::restoreOverrideCursor();
		}
	      else
		QApplication::processEvents();
	    }
	}
    }

  m_ui.outgoingMessage->moveCursor(QTextCursor::Start);
  m_ui.outgoingMessage->setFocus();
}

void spoton::slotResetAll(void)
{
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setDefaultButton(QMessageBox::No); // After setStandardButtons().
  mb.setText(tr("Are you sure that you wish to reset %1? All "
		"data will be lost. PostgreSQL databases must be "
		"removed separately. %1 will be restarted.").
	     arg(SPOTON_APPLICATION_NAME));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();
  slotDeactivateKernel();

  QStringList list;

  list << "buzz_channels.db"
       << "congestion_control.db"
       << "echo_key_sharing_secrets.db"
       << "email.db"
       << "error_log.dat"
       << "friends_public_keys.db"
       << "gpg.db"
       << "idiotes.db"
       << "kernel.db"
       << "kernel_web_server.db"
       << "listeners.db"
       << "neighbors.db"
       << "poptastic.db"
       << "rss.db"
       << "secrets.db"
       << "shared.db"
       << "starbeam.db"
       << "urls.db"
       << "urls_distillers_information.db"
       << "urls_key_information.db";

  for(int i = 0; i < list.size(); i++)
    QFile::remove(spoton_misc::homePath() + QDir::separator() + list.at(i));

  deleteAllUrls();

  QSettings settings;

  for(int i = settings.allKeys().size() - 1; i >= 0; i--)
    settings.remove(settings.allKeys().at(i));

  restart();
}

void spoton::slotRetrieveMail(void)
{
  QString error("");

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    {
      if(m_kernelSocket.isEncrypted() ||
	 m_ui.kernelKeySize->currentText().toInt() == 0)
	{
	  QByteArray message("retrievemail\n");

	  if(!writeKernelSocketData(message))
	    spoton_misc::logError
	      (QString("spoton::slotRetrieveMail(): write() failure "
		       "for %1:%2.").
	       arg(m_kernelSocket.peerAddress().toString()).
	       arg(m_kernelSocket.peerPort()));
	  else
	    {
	      m_ui.retrieveMail->setEnabled(false);
	      QTimer::singleShot
		(5000, this, SLOT(slotEnableRetrieveMail(void)));
	    }
	}
      else if(m_ui.kernelKeySize->currentText().toInt() > 0)
	error = tr("The connection to the kernel is not encrypted.");
    }
  else
    error = tr("The interface is not connected to the kernel.");

  if(m_ui.retrieveMail == sender())
    if(!error.isEmpty())
      {
	QMessageBox::critical
	  (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
	QApplication::processEvents();
      }
}

void spoton::slotSaveBuzzName(void)
{
  auto str(m_ui.buzzName->text());

  if(str.trimmed().isEmpty())
    {
      str = "unknown";
      m_ui.buzzName->setText(str);
    }
  else
    m_ui.buzzName->setText(str.trimmed());

  m_ui.buzzName->setCursorPosition(0);
  m_settings["gui/buzzName"] = str.toUtf8();

  QSettings settings;

  settings.setValue("gui/buzzName", str.toUtf8());
  m_ui.buzzName->selectAll();
  emit buzzNameChanged(str.toUtf8());
}

void spoton::slotSaveEmailName(void)
{
  auto str(m_ui.emailNameEditable->text());

  if(str.trimmed().isEmpty())
    {
      str = "unknown";
      m_ui.emailName->setItemText(0, str);
      m_ui.emailNameEditable->setText(str);
    }
  else
    {
      m_ui.emailName->setItemText(0, str.trimmed());
      m_ui.emailNameEditable->setText(str.trimmed());
    }

  m_ui.emailNameEditable->setCursorPosition(0);
  m_settings["gui/emailName"] = str.toUtf8();

  QSettings settings;

  settings.setValue("gui/emailName", str.toUtf8());
  m_ui.emailNameEditable->selectAll();
  emit newEmailName(str);
}

void spoton::slotSaveNodeName(void)
{
  auto str(m_ui.nodeName->text());

  if(str.trimmed().isEmpty())
    {
      str = "unknown";
      m_ui.nodeName->setText(str);
    }
  else
    m_ui.nodeName->setText(str.trimmed());

  m_ui.nodeName->setCursorPosition(0);
  m_settings["gui/nodeName"] = str.toUtf8();

  QSettings settings;

  settings.setValue("gui/nodeName", str.toUtf8());
  m_ui.nodeName->selectAll();
}

void spoton::slotSendMail(void)
{
  QFileInfo const fileInfo
    (spoton_misc::homePath() + QDir::separator() + "email.db");
  auto const maximumSize = 1048576 *
    m_settings.value("gui/maximumEmailFileSize", 1024).toLongLong();

  if(fileInfo.size() >= maximumSize)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The file email.db has exceeded the defined limit. Please "
	    "remove some entries and/or increase the limit "
	    "via the Permissions section in Options."));
      QApplication::processEvents();
      return;
    }

  QList<QPair<QByteArray, QByteArray> > attachments;

  if(!m_ui.attachment->toPlainText().isEmpty())
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
      auto const files
	(m_ui.attachment->toPlainText().split('\n', Qt::SkipEmptyParts));
#else
      auto const files
	(m_ui.attachment->toPlainText().split('\n', QString::SkipEmptyParts));
#endif

      for(int i = 0; i < files.size(); i++)
	{
	  auto fileName(files.at(i));

	  fileName = fileName.mid(0, fileName.lastIndexOf(' '));
	  fileName = fileName.mid(0, fileName.lastIndexOf(' '));

	  QFileInfo const fileInfo(fileName);

	  if(!fileInfo.exists() || !fileInfo.isReadable())
	    {
	      QApplication::restoreOverrideCursor();

	      if(fileName.trimmed().isEmpty())
		QMessageBox::critical
		  (this,
		   tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
		   tr("The attachment cannot be accessed."));
	      else
		QMessageBox::critical
		  (this,
		   tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
		   tr("The attachment %1 cannot be accessed.").
		   arg(fileName));

	      QApplication::processEvents();
	      return;
	    }
	  else if(fileInfo.size() >
		  spoton_common::EMAIL_ATTACHMENT_MAXIMUM_SIZE)
	    {
	      QApplication::restoreOverrideCursor();
	      QMessageBox::critical
		(this,
		 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
		 tr("The attachment %1 is too large. The maximum size "
		    "of an attachment is %2 byte(s).").arg(fileName).
		 arg(QLocale().toString(spoton_common::
					EMAIL_ATTACHMENT_MAXIMUM_SIZE)));
	      QApplication::processEvents();
	      return;
	    }

	  QByteArray attachment;

	  if(fileName.trimmed().length() > 0)
	    {
	      QFile file(fileName);

	      if(file.open(QIODevice::ReadOnly))
		attachment = file.readAll();

	      file.close();
	    }

	  if(attachment.isEmpty() ||
	     attachment.length() != static_cast<int> (fileInfo.size()))
	    {
	      QApplication::restoreOverrideCursor();
	      QMessageBox::critical
		(this,
		 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
		 tr("An error occurred while reading the attachment %1.").
		 arg(fileName));
	      QApplication::processEvents();
	      return;
	    }

	  attachments << QPair<QByteArray, QByteArray>
	    (attachment, fileInfo.fileName().toUtf8());
	}

      QApplication::restoreOverrideCursor();
    }

  auto crypt = m_crypts.value("email", nullptr);

  if(!crypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  /*
  ** Why would you send an empty message?
  */

  if(!m_ui.emailParticipants->selectionModel()->hasSelection())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please select at least one participant."));
      QApplication::processEvents();
      m_ui.emailParticipants->setFocus();
      return;
    }
  else if(m_ui.outgoingMessage->toPlainText().isEmpty())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please compose an actual letter."));
      QApplication::processEvents();
      m_ui.outgoingMessage->setFocus();
      return;
    }
  else if(m_ui.email_fs_gb->currentIndex() == 1)
    {
      if(m_ui.goldbug->text().size() < 96)
	{
	  QMessageBox::critical
	    (this,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Please provide a Gold Bug that contains at least ninety-six "
		"characters."));
	  QApplication::processEvents();
	  return;
	}
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const list
    (m_ui.emailParticipants->selectionModel()->selectedRows(0)); // Participant
  auto mixed = false;
  auto temporary = false;

  for(int i = 0; i < list.size(); i++)
    {
      if(list.at(i).data(Qt::UserRole).toBool())
	temporary = true;
      else
	{
	  auto const keyType
	    (list.at(i).data(Qt::ItemDataRole(Qt::UserRole + 1)).toString());

	  if(m_ui.emailName->currentIndex() == 0)
	    {
	      if(keyType == "poptastic")
		mixed = true;
	    }
	  else
	    {
	      if(keyType != "poptastic")
		mixed = true;
	    }
	}

      if(mixed || temporary)
	break;
    }

  QApplication::restoreOverrideCursor();

  if(temporary)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("At least one of the selected e-mail recipients is temporary. "
	    "Please correct."));
      QApplication::processEvents();
      return;
    }

  if(mixed)
    {
      if(m_settings.value("gui/poptasticNameEmail").isNull())
	{
	  QMessageBox::information
	    (this,
	     tr("%1: Information").arg(SPOTON_APPLICATION_NAME),
	     tr("The Poptastic & RetroPhone Settings window will be "
		"displayed. Please prepare at least one Poptastic account."));
	  QApplication::processEvents();
	  slotConfigurePoptastic();
	}

      if(m_settings.value("gui/poptasticNameEmail").isNull())
	return;
    }

  prepareDatabasesFromUI();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Bundle the love letter and send it to the email.db file. The
  ** kernel shall do the rest.
  */

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QList<bool> isTraditionalEmailAccounts;
	QModelIndexList list;
	QStringList forwardSecrecyCredentials;
	QStringList keyTypes;
	QStringList names;
	QStringList oids;
	QStringList publicKeyHashes;

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(4); // Forward Secrecy Information

	for(int i = 0; i < list.size(); i++)
	  forwardSecrecyCredentials.append(list.at(i).data().toString());

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(0); // Participant

	for(int i = 0; i < list.size(); i++)
	  {
	    auto const index(list.at(i));

	    isTraditionalEmailAccounts.append
	      (index.data(Qt::ItemDataRole(Qt::UserRole + 2)).
	       toString() == "traditional e-mail" ? true : false);
	    keyTypes.append(index.data(Qt::ItemDataRole(Qt::UserRole + 1)).
			    toString());
	    names.append(index.data().toString());
	  }

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(1); // OID

	for(int i = 0; i < list.size(); i++)
	  oids.append(list.at(i).data().toString());

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(3); // public_key_hash

	for(int i = 0; i < list.size(); i++)
	  publicKeyHashes.append(list.at(i).data().toString());

	while(!forwardSecrecyCredentials.isEmpty() &&
	      !isTraditionalEmailAccounts.isEmpty() &&
	      !keyTypes.isEmpty() &&
	      !names.isEmpty() &&
	      !publicKeyHashes.isEmpty() &&
	      !oids.isEmpty())
	  {
	    QByteArray goldbug;
	    QByteArray mode;
	    QSqlQuery query(db);
	    auto const isTraditionalEmailAccount =
	      isTraditionalEmailAccounts.takeFirst();
	    auto const keyType(keyTypes.takeFirst());
	    auto const name(names.takeFirst().toUtf8());
	    auto const now(QDateTime::currentDateTime());
	    auto const oid(oids.takeFirst());
	    auto const publicKeyHash(publicKeyHashes.takeFirst().toLatin1());
	    auto const subject(m_ui.outgoingSubject->text().toUtf8());
	    auto ok = true;

	    if(m_ui.email_fs_gb->currentIndex() == 0 ||
	       m_ui.email_fs_gb->currentIndex() == 3)
	      {
		if(m_ui.email_fs_gb->currentIndex() == 0)
		  mode = "forward-secrecy";
		else
		  mode = "pure-forward-secrecy";

		goldbug = forwardSecrecyCredentials.first().toLatin1();
	      }
	    else if(m_ui.email_fs_gb->currentIndex() == 1)
	      {
		mode = "forward-secrecy";

		auto const bytes(m_ui.goldbug->text().toUtf8());
		auto const size = static_cast<int>
		  (spoton_crypt::
		   cipherKeyLength(spoton_crypt::
				   preferredCipherAlgorithm()));

		goldbug.append("magnet:?aa=");
		goldbug.append(spoton_crypt::preferredHashAlgorithm());
		goldbug.append("&ak=");
		goldbug.append
		  (bytes.mid(size,
			     spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES));
		goldbug.append("&ea=");
		goldbug.append(spoton_crypt::preferredCipherAlgorithm());
		goldbug.append("&ek=");
		goldbug.append(bytes.mid(0, size));
		goldbug.append("&xt=urn:forward-secrecy");
	      }
	    else
	      mode = "normal";

	    forwardSecrecyCredentials.removeFirst();

	    {
	      QList<QByteArray> list;

	      if(!spoton_misc::isValidForwardSecrecyMagnet(goldbug, list))
		{
		  goldbug.clear();
		  mode = "normal";
		}
	    }

	    query.prepare("INSERT INTO folders "
			  "(date, folder_index, from_account, goldbug, hash, "
			  "message, message_code, mode, "
			  "receiver_sender, receiver_sender_hash, "
			  "sign, signature, "
			  "status, subject, participant_oid) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, "
			  "?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, crypt->
	       encryptedThenHashed(now.toString(Qt::RFC2822Date).
				   toLatin1(), &ok).toBase64());
	    query.bindValue(1, 1); // Sent Folder

	    /*
	    ** If the destination account is a Spot-On account, let's
	    ** use the Spot-On e-mail name. Otherwise, we'll use
	    ** the primary Poptastic e-mail account.
	    */

	    if(keyType != "email")
	      {
		if(ok)
		  query.bindValue
		    (2,
		     crypt->encryptedThenHashed(poptasticNameEmail(), &ok).
		     toBase64());
	      }
	    else
	      {
		if(ok)
		  query.bindValue
		    (2,
		     crypt->encryptedThenHashed(m_ui.emailNameEditable->
						text().toUtf8(), &ok).
		     toBase64());
	      }

	    if(ok)
	      query.bindValue
		(3, crypt->
		 encryptedThenHashed(goldbug, &ok).toBase64());

	    QByteArray message;

	    if(m_ui.richtext->isChecked())
	      {
		if(isTraditionalEmailAccount)
		  message = m_ui.outgoingMessage->toPlainText().toUtf8();
		else
		  message = m_ui.outgoingMessage->toHtml().toUtf8();
	      }
	    else
	      message = m_ui.outgoingMessage->toPlainText().toUtf8();

	    if(ok)
	      query.bindValue
		(4, crypt->
		 keyedHash(now.toString(Qt::RFC2822Date).toLatin1() +
			   message + subject, &ok).toBase64());

	    if(ok)
	      query.bindValue(5, crypt->
			      encryptedThenHashed(message, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(6, crypt->
		 encryptedThenHashed(QByteArray(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(7, crypt->encryptedThenHashed(mode, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(8, crypt->
		 encryptedThenHashed(name, &ok).toBase64());

	    query.bindValue
	      (9, publicKeyHash);

	    if(ok)
	      query.bindValue
		(10, crypt->
		 encryptedThenHashed(QByteArray::
				     number(m_ui.sign_this_email->
					    isChecked()), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(11, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(12, crypt->
		 encryptedThenHashed(QByteArray("Queued"), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(13, crypt->
		 encryptedThenHashed(subject, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(14, crypt->
		 encryptedThenHashed(oid.toLatin1(), &ok).toBase64());

	    if(ok)
	      if(query.exec())
		{
		  auto const variant(query.lastInsertId());
		  auto const id = query.lastInsertId().toLongLong();

		  for(int i = 0; i < attachments.size(); i++)
		    {
		      auto const attachment(attachments.at(i).first);
		      auto const fileName(attachments.at(i).second);

		      if(variant.isValid())
			{
			  QSqlQuery query(db);

			  query.prepare("INSERT INTO folders_attachment "
					"(data, folders_oid, name) "
					"VALUES (?, ?, ?)");
			  query.bindValue
			    (0, crypt->encryptedThenHashed(attachment,
							   &ok).toBase64());
			  query.bindValue(1, id);

			  if(ok)
			    query.bindValue
			      (2, crypt->encryptedThenHashed(fileName,
							     &ok).toBase64());

			  if(ok)
			    query.exec();
			}
		    }
		}
	  }

	m_ui.attachment->clear();
	m_ui.emailName->setCurrentIndex(0);
	m_ui.emailParticipants->selectionModel()->clear();
	m_ui.email_fs_gb->setCurrentIndex(2);
	m_ui.goldbug->clear();
	m_ui.outgoingMessage->clear();
	m_ui.outgoingMessage->setCurrentCharFormat(QTextCharFormat());
	m_ui.outgoingSubject->clear();
	m_ui.richtext->setChecked(true);
	m_ui.sign_this_email->setChecked
	  (m_optionsUi.emailSignMessages->isChecked());

#if SPOTON_GOLDBUG == 1
	QApplication::restoreOverrideCursor();

	QMessageBox mb(this);

	mb.setIcon(QMessageBox::Information);
	mb.setText(tr("E-mail has been queued."));
	mb.setWindowIcon(windowIcon());
	mb.setWindowModality(Qt::ApplicationModal);
	mb.setWindowTitle(tr("GoldBug: Confirmation"));
	mb.exec();
	QApplication::processEvents();
#endif
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(QApplication::overrideCursor()->shape() != Qt::ArrowCursor)
    QApplication::restoreOverrideCursor();

  m_ui.outgoingSubject->setFocus();
}

void spoton::slotSendMessage(void)
{
  sendMessage(nullptr);
}

void spoton::slotSetIcons(int index)
{
  QSettings settings;
  QString iconSet("nouve");

  if(index == 0)
    iconSet = "everaldo";
  else if(index == 1)
    iconSet = "meego";
  else if(index == 2)
    iconSet = "nouve";
  else
    iconSet = "nuvola";

  m_settings["gui/iconSet"] = iconSet;
  settings.setValue("gui/iconSet", iconSet);

  /*
  ** Kernel, listeners, and neighbors status icons are prepared elsewhere.
  */

  // Generic

  m_ui.action_Echo_Key_Share->setIcon
    (QIcon(QString(":/%1/share.png").arg(iconSet)));
  m_ui.action_File_Encryption->setIcon
    (QIcon(QString(":/%1/lock.png").arg(iconSet)));
  m_ui.action_Log_Viewer->setIcon
    (QIcon(QString(":/%1/information.png").arg(iconSet)));
#if SPOTON_GOLDBUG == 1
  m_ui.action_Quit->setIcon
    (QIcon(QString(":/%1/quit.png").arg(iconSet)));
#endif
  m_ui.action_Rosetta->setIcon
    (QIcon(QString(":/%1/lock.png").arg(iconSet)));

  QStringList list;

  // Buzz

  m_ui.join->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.saveBuzzName->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));

  // Chat

  if(m_ui.chatActionMenu->menu())
    {
      m_ui.chatActionMenu->menu()->deleteLater();
      m_ui.chatActionMenu->setMenu(nullptr);
    }

  m_ui.clearMessages->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  m_ui.saveNodeName->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  m_ui.sendMessage->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  list.clear();
  list << "away.png" << "busy.png" << "chat.png"
       << "offline.png" << "online.png";

  for(int i = 0; i < list.size(); i++)
    m_ui.status->setItemIcon
      (i, QIcon(QString(":/%1/%2").arg(iconSet).arg(list.at(i))));

  // Email

  if(m_ui.emailWriteActionMenu->menu())
    {
      m_ui.emailWriteActionMenu->menu()->deleteLater();
      m_ui.emailWriteActionMenu->setMenu(nullptr);
    }

  m_ui.refreshMail->setIcon(QIcon(QString(":/%1/refresh.png").arg(iconSet)));
  m_ui.reply->setIcon(QIcon(QString(":/%1/reply.png").arg(iconSet)));
  m_ui.retrieveMail->setIcon(QIcon(QString(":/%1/down.png").arg(iconSet)));
  m_ui.emptyTrash->setIcon
    (QIcon(QString(":/%1/empty-trash.png").arg(iconSet)));
  m_ui.resend->setIcon(QIcon(QString(":/%1/reply.png").arg(iconSet)));
  m_ui.sendMail->setIcon(QIcon(QString(":/%1/email.png").arg(iconSet)));
  list.clear();
  list << "inbox.png" << "outbox.png" << "full-trash.png";

  for(int i = 0; i < list.size(); i++)
    m_ui.folder->setItemIcon
      (i, QIcon(QString(":/%1/%2").arg(iconSet).arg(list.at(i))));

  list.clear();
  list << "email.png" << "database.png";

  for(int i = 0; i < list.size(); i++)
    {
      m_ui.mailTab->setTabIcon
	(i, QIcon(QString(":/%1/%2").arg(iconSet).arg(list.at(i))));

      if(i == 1)
	m_careOfPageIcon = QIcon
	  (QString(":/%1/%2").arg(iconSet).arg(list.at(i)));
    }

  // Listeners

  if(m_ui.listenersActionMenu->menu())
    {
      m_ui.listenersActionMenu->menu()->deleteLater();
      m_ui.listenersActionMenu->setMenu(nullptr);
    }

  m_ui.addAEToken->setIcon(QIcon(QString(":/%1/add.png").
				 arg(iconSet)));
  m_ui.addAcceptedIP->setIcon(QIcon(QString(":/%1/add.png").
				    arg(iconSet)));
  m_ui.addAccount->setIcon(QIcon(QString(":/%1/add.png").
				 arg(iconSet)));
  m_ui.addListener->setIcon(QIcon(QString(":/%1/add-listener.png").
				  arg(iconSet)));
  m_ui.deleteAEToken->setIcon(QIcon(QString(":/%1/clear.png").
				    arg(iconSet)));
  m_ui.deleteAccount->setIcon(QIcon(QString(":/%1/clear.png").
				    arg(iconSet)));
  m_ui.deleteAcceptedIP->setIcon(QIcon(QString(":/%1/clear.png").
				       arg(iconSet)));
  m_ui.saveMOTD->setIcon(QIcon(QString(":/%1/ok.png").
			       arg(iconSet)));

  // Login

  m_ui.passphraseButton->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  m_listenersLastModificationTime = QDateTime();

  if(m_neighborsFuture.isFinished())
    m_neighborsLastModificationTime = QDateTime();

  if(m_participantsFuture.isFinished())
    m_participantsLastModificationTime = QDateTime();

  // Neighbors

  if(m_ui.neighborsActionMenu->menu())
    {
      m_ui.neighborsActionMenu->menu()->deleteLater();
      m_ui.neighborsActionMenu->setMenu(nullptr);
    }

  m_ui.toolButtonCopyToClipboard->setIcon
    (QIcon(QString(":/%1/copy.png").arg(iconSet)));
  m_ui.shareBuzzMagnet->setIcon
    (QIcon(QString(":/%1/share.png").arg(iconSet)));
  m_ui.addNeighbor->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.addFriend->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.clearFriend->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
#if SPOTON_GOLDBUG == 1
  m_ui.addFriendPublicKeyRadio->setIcon
    (QIcon(QString(":/%1/key.png").arg(iconSet)));
#endif

  // Search

  if(m_ui.deleteAllUrls->menu())
    {
      m_ui.deleteAllUrls->menu()->deleteLater();
      m_ui.deleteAllUrls->setMenu(nullptr);
    }

  m_ui.discover->setIcon(QIcon(QString(":/%1/search.png").arg(iconSet)));

  // Settings

  m_ui.activateKernel->setIcon
    (QIcon(QString(":/%1/activate.png").arg(iconSet)));
  m_ui.deactivateKernel->setIcon
    (QIcon(QString(":/%1/deactivate.png").arg(iconSet)));
  m_ui.setPassphrase->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));

  // StarBeam

  if(m_ui.magnetsActionMenu->menu())
    {
      m_ui.magnetsActionMenu->menu()->deleteLater();
      m_ui.magnetsActionMenu->setMenu(nullptr);
    }

  if(m_ui.receivedActionMenu->menu())
    {
      m_ui.receivedActionMenu->menu()->deleteLater();
      m_ui.receivedActionMenu->setMenu(nullptr);
    }

  if(m_ui.transmittedActionMenu->menu())
    {
      m_ui.transmittedActionMenu->menu()->deleteLater();
      m_ui.transmittedActionMenu->setMenu(nullptr);
    }

  m_ui.addMagnet->setIcon(QIcon(QString(":/%1/add.png").
				arg(iconSet)));
  m_ui.addNova->setIcon(QIcon(QString(":/%1/add.png").
			      arg(iconSet)));
  m_ui.deleteNova->setIcon(QIcon(QString(":/%1/clear.png").
				 arg(iconSet)));
  m_ui.generateNova->setIcon
    (QIcon(QString(":/%1/lock.png").arg(iconSet)));

  // Status

  m_sb.authentication_request->setIcon
    (QIcon(QString(":/%1/lock.png").arg(iconSet)));
  m_sb.buzz->setIcon(QIcon(QString(":/%1/buzz.png").arg(iconSet)));
  m_sb.chat->setIcon(QIcon(QString(":/%1/chat.png").arg(iconSet)));
  m_sb.email->setIcon(QIcon(QString(":/%1/email.png").arg(iconSet)));
  m_sb.errorlog->setIcon(QIcon(QString(":/%1/information.png").arg(iconSet)));
  m_sb.forward_secrecy_request->setIcon
    (QIcon(QString(":/%1/key.png").arg(iconSet)));
  m_sb.lock->setIcon(QIcon(QString(":/%1/lock.png").arg(iconSet)));

  // Tab

  list.clear();
  prepareTabIcons();

  // URLs

  if(m_ui.urlActionMenu->menu())
    {
      m_ui.urlActionMenu->menu()->deleteLater();
      m_ui.urlActionMenu->setMenu(nullptr);
    }

  m_ui.addDistiller->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  m_ui.deleteDistillers->setIcon
    (QIcon(QString(":/%1/delete.png").arg(iconSet)));
  m_ui.refreshDistillers->setIcon
    (QIcon(QString(":/%1/refresh.png").arg(iconSet)));
  m_ui.urlTab->setTabIcon
    (0, QIcon(QString(":/%1/down.png").arg(iconSet)));
  m_ui.urlTab->setTabIcon
    (1, QIcon(QString(":/%1/share.png").arg(iconSet)));
  m_ui.urlTab->setTabIcon
    (2, QIcon(QString(":/%1/up.png").arg(iconSet)));
  prepareContextMenuMirrors();
  emit iconsChanged();
}

void spoton::slotShareChatPublicKey(void)
{
  if(!m_crypts.value("chat", nullptr) ||
     !m_crypts.value("chat-signature", nullptr))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  if(m_ui.neighborsActionMenu->menu())
    m_ui.neighborsActionMenu->menu()->repaint();

  repaint();
  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      return;
    }

  QByteArray publicKey;
  QByteArray signature;
  auto ok = true;

  publicKey = m_crypts.value("chat")->publicKey(&ok);

  if(ok)
    signature = m_crypts.value("chat")->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value("chat-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("chat-signature")->digitalSignature
      (sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      auto name(m_settings.value("gui/nodeName", "unknown").toByteArray());

      if(name.isEmpty())
	name = "unknown";

      message.append("sharepublickey_");
      message.append(oid.toUtf8());
      message.append("_");
      message.append(QByteArray("chat").toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(qCompress(publicKey).toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append("\n");

      if(!writeKernelSocketData(message))
	spoton_misc::logError
	  (QString("spoton::slotShareChatPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }

  QApplication::restoreOverrideCursor();
}

void spoton::slotShareChatPublicKeyWithParticipant(void)
{
  auto item = m_ui.participants->item
    (m_ui.participants->currentRow(), 1); // OID

  if(item)
    sharePublicKeyWithParticipant
      (item->data(Qt::ItemDataRole(Qt::UserRole + 1)).toString());
}

void spoton::slotShareEmailPublicKey(void)
{
  if(!m_crypts.value("email", nullptr) ||
     !m_crypts.value("email-signature", nullptr))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  if(m_ui.neighborsActionMenu->menu())
    m_ui.neighborsActionMenu->menu()->repaint();

  repaint();
  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      return;
    }

  QByteArray publicKey;
  QByteArray signature;
  auto ok = true;

  publicKey = m_crypts.value("email")->publicKey(&ok);

  if(ok)
    signature = m_crypts.value("email")->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value("email-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("email-signature")->digitalSignature
      (sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      auto name(m_settings.value("gui/emailName", "unknown").toByteArray());

      if(name.isEmpty())
	name = "unknown";

      message.append("sharepublickey_");
      message.append(oid.toUtf8());
      message.append("_");
      message.append(QByteArray("email").toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(qCompress(publicKey).toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append("\n");

      if(!writeKernelSocketData(message))
	spoton_misc::logError
	  (QString("spoton::slotShareEmailPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }

  QApplication::restoreOverrideCursor();
}

void spoton::slotShareEmailPublicKeyWithParticipant(void)
{
  auto item = m_ui.emailParticipants->item
    (m_ui.emailParticipants->currentRow(), 1); // OID

  if(item)
    sharePublicKeyWithParticipant
      (item->data(Qt::ItemDataRole(Qt::UserRole + 1)).toString());
}

void spoton::slotShareURLPublicKey(void)
{
  if(!m_crypts.value("url", nullptr) ||
     !m_crypts.value("url-signature", nullptr))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  if(m_ui.neighborsActionMenu->menu())
    m_ui.neighborsActionMenu->menu()->repaint();

  repaint();
  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      return;
    }

  QByteArray publicKey;
  QByteArray signature;
  auto ok = true;

  publicKey = m_crypts.value("url")->publicKey(&ok);

  if(ok)
    signature = m_crypts.value("url")->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value("url-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("url-signature")->digitalSignature
      (sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      auto name(m_settings.value("gui/urlName", "unknown").toByteArray());

      if(name.isEmpty())
	name = "unknown";

      message.append("sharepublickey_");
      message.append(oid.toUtf8());
      message.append("_");
      message.append(QByteArray("url").toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(qCompress(publicKey).toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append("\n");

      if(!writeKernelSocketData(message))
	spoton_misc::logError
	  (QString("spoton::slotShareURLPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }

  QApplication::restoreOverrideCursor();
}

void spoton::slotShareUrlPublicKeyWithParticipant(void)
{
  sharePublicKeyWithParticipant("url");
}

void spoton::slotStatusButtonClicked(void)
{
  auto toolButton = qobject_cast<QToolButton *> (sender());

  if(toolButton == m_sb.buzz)
    {
      m_sb.buzz->setVisible(false);
      m_ui.tab->setCurrentIndex(tabIndexFromName("buzz"));
    }
  else if(toolButton == m_sb.chat)
    {
      m_sb.chat->setVisible(false);
      m_ui.tab->setCurrentIndex(tabIndexFromName("chat"));
    }
  else if(toolButton == m_sb.email)
    {
      m_sb.email->setVisible(false);
      m_ui.folder->setCurrentIndex(0);
      m_ui.mailTab->setCurrentIndex(0);
      m_ui.tab->setCurrentIndex(tabIndexFromName("email"));
      slotRefreshMail();
    }
  else if(toolButton == m_sb.listeners)
    m_ui.tab->setCurrentIndex(tabIndexFromName("listeners"));
  else if(toolButton == m_sb.neighbors)
    m_ui.tab->setCurrentIndex(tabIndexFromName("neighbors"));
}

void spoton::slotStatusChanged(int index)
{
  m_ui.custom->setVisible(false);

  if(index == 0)
    m_settings["gui/my_status"] = "Away";
  else if(index == 1)
    m_settings["gui/my_status"] = "Busy";
  else if(index == 2)
    {
      m_settings["gui/my_status"] = "Custom";
      m_ui.custom->setVisible(true);
    }
  else if(index == 3)
    m_settings["gui/my_status"] = "Offline";
  else
    m_settings["gui/my_status"] = "Online";

  QSettings settings;

  settings.setValue("gui/my_status", m_settings.value("gui/my_status"));
}

void spoton::slotSuperEcho(int index)
{
  m_settings["gui/superEcho"] = index;

  QSettings settings;

  settings.setValue("gui/superEcho", index);
}

void spoton::slotTestSslControlString(void)
{
  QMessageBox mb(m_optionsWindow);
  QString str("");
  auto const ciphers
    (spoton_crypt::defaultSslCiphers(m_optionsUi.sslControlString->text()));

  for(int i = 0; i < ciphers.size(); i++)
    str.append(QString("%1-%2").arg(ciphers.at(i).name()).
	       arg(ciphers.at(i).protocolString()) + "\n");

  if(!str.isEmpty())
    {
      mb.setDetailedText(str);
      mb.setText
	(tr("The following ciphers are supported by your OpenSSL library. "
	    "Please note that %1 may neglect discovered ciphers "
	    "if the ciphers are not also understood by Qt.").
	 arg(SPOTON_APPLICATION_NAME));
    }
  else
    mb.setText(tr("Empty cipher list."));

  mb.setStandardButtons(QMessageBox::Ok);
  mb.setWindowIcon(windowIcon());
  mb.setWindowTitle(tr("%1: Information").arg(SPOTON_APPLICATION_NAME));
  mb.exec();
  QApplication::processEvents();
}

void spoton::slotViewLog(void)
{
  m_logViewer.property("resized").toBool() ?
    (void) 0:
    m_logViewer.resize
    (m_logViewer.size().width(),
     qMax(-100 + size().height(), m_logViewer.size().height())),
    m_logViewer.setProperty("resized", true);
  m_logViewer.show(this);
}
