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

#include "spot-on-crypt.h"
#ifdef SPOTON_MCELIECE_ENABLED
#include "spot-on-mceliece.h"
#endif
#include "spot-on-misc.h"

void spoton_crypt::generateMcElieceKeys(const QString &keySize,
					QByteArray &privateKey,
					QByteArray &publicKey,
					bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_MCELIECE_ENABLED
  size_t m = 0;
  size_t t = 0;

  if(keySize == "m12t66")
    {
      m = 12;
      t = 66;
    }
  else if(keySize == "m13t119")
    {
      m = 13;
      t = 119;
    }
  else
    return;

  spoton_mceliece *mceliece = new (std::nothrow) spoton_mceliece(m, t);

  if(mceliece)
    if(mceliece->generatePrivatePublicKeys())
      {
      }

  delete mceliece;
  Q_UNUSED(privateKey);
  Q_UNUSED(publicKey);
#else
  Q_UNUSED(keySize);
  Q_UNUSED(privateKey);
  Q_UNUSED(publicKey);
#endif
}

QByteArray spoton_crypt::publicKeyDecryptMcEliece
(const QByteArray &data, bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_MCELIECE_ENABLED
  Q_UNUSED(data);
  return QByteArray();
#else
  Q_UNUSED(data);
  return QByteArray();
#endif
}

QByteArray spoton_crypt::publicKeyEncryptMcEliece(const QByteArray &data,
						  const QByteArray &publicKey,
						  bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_MCELIECE_ENABLED
  Q_UNUSED(data);
  Q_UNUSED(publicKey);
  return QByteArray();
#else
  Q_UNUSED(data);
  Q_UNUSED(publicKey);
  return QByteArray();
#endif
}

QString spoton_crypt::publicKeySizeMcEliece(const QByteArray &data)
{
  Q_UNUSED(data);

  QString keySize("");

  return keySize;
}

QString spoton_crypt::publicKeySizeMcEliece(void)
{
#ifdef SPOTON_MCELIECE_ENABLED
  bool ok = true;

  publicKey(&ok);

  if(!ok)
    {
      spoton_misc::logError
	("spoton_crypt::publicKeySizeMcEliece(): publicKey() failure.");
      return "";
    }

  return publicKeySizeMcEliece(m_publicKey);
#else
  return publicKeySizeMcEliece(QByteArray());
#endif
}
