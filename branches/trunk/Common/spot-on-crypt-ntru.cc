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
#include "spot-on-misc.h"

void spoton_crypt::generateNTRUKeys(const QString &keySize,
				    QByteArray &privateKey,
				    QByteArray &publicKey,
				    bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_LINKED_WITH_LIBNTRU
  int index = 0;
  struct NtruEncParams parameters[] = {EES1087EP2,
				       EES1171EP1,
				       EES1499EP1};

  if(keySize == "EES1087EP2")
    index = 0;
  else if(keySize == "EES1171EP1")
    index = 1;
  else if(keySize == "EES1499EP1")
    index = 2;
  else
    {
      spoton_misc::logError
	("spoton_crypt::generateNTRUKeys(): parameter is not supported.");
      return;
    }

  NtruEncKeyPair kp;
  NtruRandContext rand_ctx_def;
#ifdef Q_OS_WIN32
  NtruRandGen rng_def = NTRU_RNG_DEFAULT;
#else
  NtruRandGen rng_def = NTRU_RNG_DEVURANDOM;
#endif

  ntru_rand_init(&rand_ctx_def, &rng_def);

  if(ntru_gen_key_pair(&parameters[index], &kp,
		       &rand_ctx_def) == NTRU_SUCCESS)
    {
      uint8_t *privateKey_array = 0;
      uint8_t *publicKey_array = 0;
      uint16_t length1 = ntru_priv_len(&parameters[index]);
      uint16_t length2 = ntru_pub_len(&parameters[index]);

      privateKey_array = new (std::nothrow) uint8_t[length1];
      publicKey_array = new (std::nothrow) uint8_t[length2];

      if(privateKey_array && publicKey_array)
	{
	  if(ok)
	    *ok = true;

	  ntru_export_priv(&kp.priv, privateKey_array);
	  ntru_export_pub(&kp.pub, publicKey_array);
	  privateKey.resize(length1);
	  memcpy(privateKey.data(), privateKey_array, length1);
	  privateKey.prepend("ntru-private-key-");
	  publicKey.resize(length2);
	  memcpy(publicKey.data(), publicKey_array, length2);
	  publicKey.prepend("ntru-public-key-");
	  memset(privateKey_array, 0, length1);
	  memset(publicKey_array, 0, length2);
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::generateNTRUKeys(): memory failure.");

      delete []privateKey_array;
      delete []publicKey_array;
    }

  ntru_rand_release(&rand_ctx_def);
#else
  Q_UNUSED(keySize);
  Q_UNUSED(privateKey);
  Q_UNUSED(publicKey);
#endif
}

QByteArray spoton_crypt::publicKeyDecryptNTRU
(const QByteArray &data, bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_LINKED_WITH_LIBNTRU
  if(data.isEmpty() || !m_privateKey || m_privateKeyLength <= 0 ||
     m_privateKeyLength <=
     static_cast<size_t> (qstrlen("ntru-private-key-")) ||
     static_cast<uint> (m_publicKey.length()) <= qstrlen("ntru-public-key-"))
    {
      spoton_misc::logError
	("spoton_crypt::publicKeyDecryptNTRU(): something peculiar!");
      return QByteArray();
    }

  QByteArray decrypted;
  size_t length1 = 0;
  size_t length2 = 0;
  uint8_t *d = 0;
  uint8_t *encrypted = 0;
  uint8_t *privateKey_array = 0;
  uint8_t *publicKey_array = 0;

  length1 = m_privateKeyLength -
    static_cast<size_t> (qstrlen("ntru-private-key-"));
  length2 = static_cast<size_t>
    (static_cast<uint> (m_publicKey.length()) - qstrlen("ntru-public-key-"));
  encrypted = new (std::nothrow) uint8_t[data.size()];
  privateKey_array = new (std::nothrow) uint8_t[length1];
  publicKey_array = new (std::nothrow) uint8_t[length2];

  if(encrypted && privateKey_array && publicKey_array)
    {
      NtruEncKeyPair kp;
      QByteArray privateKey;
      QByteArray publicKey;

      privateKey.append
	(m_privateKey, static_cast<int> (m_privateKeyLength));
      privateKey.remove
	(0, static_cast<int> (qstrlen("ntru-private-key-")));
      memcpy(privateKey_array, privateKey.constData(), length1);
      ntru_import_priv(privateKey_array, &kp.priv);
      privateKey.replace
	(0, privateKey.length(), QByteArray(privateKey.length(), 0));
      publicKey.append(m_publicKey, m_publicKey.length());
      publicKey.remove
	(0, static_cast<int> (qstrlen("ntru-public-key-")));
      memcpy(publicKey_array, publicKey.constData(), length2);
      ntru_import_pub(publicKey_array, &kp.pub);
      publicKey.replace
	(0, publicKey.length(), QByteArray(publicKey.length(), 0));
      memcpy(encrypted, data.constData(),
	     static_cast<size_t> (data.length()));
      memset(privateKey_array, 0, length1);
      privateKey.clear();
      memset(publicKey_array, 0, length2);
      publicKey.clear();

      int index = 0;
      struct NtruEncParams parameters[] = {EES1087EP2,
					   EES1171EP1,
					   EES1499EP1};
      uint8_t err = 0;
      uint8_t length = 0;
      uint16_t decrypted_len = 0;

      if(kp.pub.h.N == parameters[0].N)
	index = 0;
      else if(kp.pub.h.N == parameters[1].N)
	index = 1;
      else if(kp.pub.h.N == parameters[2].N)
	index = 2;
      else
	{
	  spoton_misc::logError
	    ("spoton_crypt::publicKeyDecryptNTRU(): unable to "
	     "determine index.");
	  goto done_label;
	}

      length = ntru_max_msg_len(&parameters[index]);

      if(length <= 0)
	{
	  spoton_misc::logError
	    ("spoton_crypt::publicKeyDecryptNTRU(): ntru_max_msg_len() "
	     "failure.");
	  goto done_label;
	}

      d = new (std::nothrow) uint8_t[length];

      if(!d)
	{
	  spoton_misc::logError
	    ("spoton_crypt::publicKeyDecryptNTRU(): memory failure.");
	  goto done_label;
	}

      if((err = ntru_decrypt(encrypted, &kp, &parameters[index],
			     d, &decrypted_len)) == NTRU_SUCCESS)
	{
	  if(ok)
	    *ok = true;

	  decrypted.resize(decrypted_len);
	  memcpy(decrypted.data(), d, decrypted_len);
	}
      else
	spoton_misc::logError
	  (QString("spoton_crypt::publicKeyDecryptNTRU(): "
		   "ntru_decrypt() failure (%1).").arg(err));
    }
  else
    spoton_misc::logError
      ("spoton_crypt::publicKeyDecryptNTRU(): memory failure.");

 done_label:
  delete []d;
  delete []encrypted;
  delete []privateKey_array;
  delete []publicKey_array;
  return decrypted;
#else
  Q_UNUSED(data);
  return QByteArray();
#endif
}

QByteArray spoton_crypt::publicKeyEncryptNTRU(const QByteArray &data,
					      const QByteArray &publicKey,
					      bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_LINKED_WITH_LIBNTRU
  if(data.isEmpty() ||
     static_cast<uint> (publicKey.length()) <= qstrlen("ntru-public-key-"))
    {
      spoton_misc::logError
	("spoton_crypt::publicKeyEncryptNTRU(): something peculiar!");
      return QByteArray();
    }

  NtruRandContext rand_ctx_def;
#ifdef Q_OS_WIN32
  NtruRandGen rng_def = NTRU_RNG_DEFAULT;
#else
  NtruRandGen rng_def = NTRU_RNG_DEVURANDOM;
#endif
  QByteArray encrypted;
  uint8_t *data_array = 0;
  uint8_t *e = 0;
  uint8_t *publicKey_array = 0;

  ntru_rand_init(&rand_ctx_def, &rng_def);
  data_array = new (std::nothrow) uint8_t[data.length()];
  publicKey_array = new (std::nothrow)
    uint8_t[publicKey.mid(static_cast<int> (qstrlen("ntru-public-key-"))).
	    length()];

  if(data_array && publicKey_array)
    {
      NtruEncPubKey pk;

      memcpy(data_array, data.constData(),
	     static_cast<size_t> (data.length()));
      memcpy
	(publicKey_array,
	 publicKey.
	 mid(static_cast<int> (qstrlen("ntru-public-key-"))).constData(),
	 static_cast<size_t> (publicKey.length() -
			      static_cast<int> (qstrlen("ntru-"
							"public-key-"))));
      ntru_import_pub(publicKey_array, &pk);
      memset
	(publicKey_array, 0,
	 static_cast<size_t> (publicKey.
			      mid(static_cast<int> (qstrlen("ntru-"
							    "public-"
							    "key-"))).
			      length()));

      int index = 0;
      struct NtruEncParams parameters[] = {EES1087EP2,
					   EES1171EP1,
					   EES1499EP1};
      uint16_t length = 0;

      if(pk.h.N == parameters[0].N)
	index = 0;
      else if(pk.h.N == parameters[1].N)
	index = 1;
      else if(pk.h.N == parameters[2].N)
	index = 2;
      else
	goto done_label;

      length = ntru_enc_len(&parameters[index]);

      if(length <= 0)
	{
	  spoton_misc::logError
	    ("spoton_crypt::publicKeyEncryptNTRU(): ntru_enc_len() "
	     "failure.");
	  goto done_label;
	}

      e = new (std::nothrow) uint8_t[length];

      if(!e)
	{
	  spoton_misc::logError
	    ("spoton_crypt::publicKeyEncryptNTRU(): memory failure.");
	  goto done_label;
	}

      if(ntru_encrypt(data_array,
		      static_cast<uint16_t> (data.length()),
		      &pk, &parameters[index],
		      &rand_ctx_def,
		      e) == NTRU_SUCCESS)
	{
	  if(ok)
	    *ok = true;

	  encrypted.resize(length);
	  memcpy(encrypted.data(), e, length);
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::publicKeyEncryptNTRU(): ntru_encrypt() "
	   "failure.");
    }
  else
    spoton_misc::logError
      ("spoton_crypt::publicKeyEncryptNTRU(): memory failure.");

 done_label:
  delete []data_array;
  delete []e;
  delete []publicKey_array;
  ntru_rand_release(&rand_ctx_def);
  return encrypted;
#else
  Q_UNUSED(data);
  Q_UNUSED(publicKey);
  return QByteArray();
#endif
}
