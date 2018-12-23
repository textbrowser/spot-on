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

QByteArray spoton_crypt::publicKeyDecryptMcEliece
(const QByteArray &data, bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_MCELIECE_ENABLED
  QWriteLocker locker(&m_privateKeyMutex); /*
					   ** NTL is not necessarily
					   ** thread-safe.
					   */

  if(!m_mceliece)
    {
      m_mceliece = new (std::nothrow) spoton_mceliece
	(m_privateKey, m_privateKeyLength, m_publicKey);

      if(!m_mceliece->ok())
	{
	  delete m_mceliece;
	  m_mceliece = 0;
	}
      else
	{
	  if(s_hasSecureMemory.fetchAndAddOrdered(0))
	    gcry_free(m_privateKey);
	  else
	    free(m_privateKey);

	  m_privateKey = 0; // Do not reset m_privateKeyLength.
	}
    }

  if(!m_mceliece)
    return QByteArray();

  QByteArray bytes;
  std::stringstream ciphertext;
  std::stringstream plaintext;

  ciphertext.write(data.constData(), static_cast<size_t> (data.length()));

  if(m_mceliece->decrypt(ciphertext, plaintext))
    {
      locker.unlock();
      bytes = QByteArray // A deep copy is required.
	(plaintext.str().c_str(),
	 static_cast<int> (plaintext.str().size()));

      if(!bytes.isEmpty())
	if(ok)
	  *ok = true;
    }
  else
    locker.unlock();

  if(bytes.isEmpty())
    spoton_misc::logError("spoton_crypt::publicKeyDecryptMcEliece(): "
			  "failure.");

  return bytes;
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
  if(data.isEmpty())
    return QByteArray();

  QByteArray bytes;
  QByteArray hash(sha512Hash(publicKey, 0));
  spoton_mceliece *mceliece = 0;

  {
    QWriteLocker locker(&s_mceliecePeersMutex);

    if(s_mceliecePeers.contains(hash))
      mceliece = s_mceliecePeers.value(hash);
    else
      {
	mceliece = new (std::nothrow) spoton_mceliece(publicKey);

	if(mceliece)
	  s_mceliecePeers[hash] = mceliece;
      }
  }

  std::stringstream ciphertext;

  if(mceliece)
    if(mceliece->encrypt(data.constData(),
			 static_cast<size_t> (data.length()),
			 ciphertext))
      {
	bytes = QByteArray // A deep copy is required.
	  (ciphertext.str().c_str(),
	   static_cast<int> (ciphertext.str().size()));

	if(!bytes.isEmpty())
	  if(ok)
	    *ok = true;
      }

  if(bytes.isEmpty())
    spoton_misc::logError("spoton_crypt::publicKeyEncryptMcEliece(): "
			  "failure.");

  return bytes;
#else
  Q_UNUSED(data);
  Q_UNUSED(publicKey);
  return QByteArray();
#endif
}

QString spoton_crypt::publicKeySizeMcEliece(const QByteArray &data)
{
  QString keySize("");

#ifdef SPOTON_MCELIECE_ENABLED
  if(!data.startsWith("mceliece-public-key-"))
    return keySize;

  spoton_mceliece *mceliece = new (std::nothrow) spoton_mceliece
    (qCompress(data)); // A compressed key is expected.

  if(mceliece)
    {
      if(data.startsWith("mceliece-public-key-000"))
	keySize = QString("m%1t%2").arg(mceliece->m()).arg(mceliece->t());
      else if(data.startsWith("mceliece-public-key-foa"))
	keySize = QString("m%1t%2-fujisaki-okamoto-a").
	  arg(mceliece->m()).arg(mceliece->t());
      else
	keySize = QString("m%1t%2-fujisaki-okamoto-b").
	  arg(mceliece->m()).arg(mceliece->t());
    }

  delete mceliece;
#else
  Q_UNUSED(data);
#endif
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

void spoton_crypt::generateMcElieceKeys(const QString &keySize,
					QByteArray &privateKey,
					QByteArray &publicKey,
					bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_MCELIECE_ENABLED
  QByteArray conversion("");
  QByteArray prefix("");
  size_t m = 0;
  size_t t = 0;

  if(keySize == "m11t51")
    {
      conversion = "000";
      m = 11;
      prefix = "000-m11t51";
      t = 51;
    }
  else if(keySize == "m11t51-fujisaki-okamoto-a")
    {
      conversion = "foa";
      m = 11;
      prefix = "foa-m11t51";
      t = 51;
    }
  else if(keySize == "m11t51-fujisaki-okamoto-b")
    {
      conversion = "fob";
      m = 11;
      prefix = "fob-m11t51";
      t = 51;
    }
  else if(keySize == "m12t68")
    {
      conversion = "000";
      m = 12;
      prefix = "000-m12t68";
      t = 68;
    }
  else if(keySize == "m12t68-fujisaki-okamoto-a")
    {
      conversion = "foa";
      m = 12;
      prefix = "foa-m12t68";
      t = 68;
    }
  else if(keySize == "m12t68-fujisaki-okamoto-b")
    {
      conversion = "fob";
      m = 12;
      prefix = "fob-m12t68";
      t = 68;
    }
  else
    return;

  spoton_mceliece *mceliece = new (std::nothrow) spoton_mceliece
    (conversion, m, t);

  if(mceliece)
    if(mceliece->generatePrivatePublicKeys())
      {
	mceliece->privateKeyParameters(privateKey);

	if(!privateKey.isEmpty())
	  {
	    privateKey.prepend(prefix);
	    privateKey.prepend("mceliece-private-key-");
	  }

	mceliece->publicKeyParameters(publicKey);

	if(!publicKey.isEmpty())
	  {
	    publicKey.prepend(prefix);
	    publicKey.prepend("mceliece-public-key-");
	  }

	if(!publicKey.isEmpty() && !privateKey.isEmpty())
	  if(ok)
	    *ok = true;
      }

  delete mceliece;
#else
  Q_UNUSED(keySize);
  Q_UNUSED(privateKey);
  Q_UNUSED(publicKey);
#endif
}
