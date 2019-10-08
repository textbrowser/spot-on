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

#include <QDataStream>
#include <QDir>
#include <QElapsedTimer>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QtCore/qmath.h>

#include <bitset>
#include <iostream>
#include <limits>

#include "spot-on-common.h"
#include "spot-on-crypt.h"
#ifdef SPOTON_MCELIECE_ENABLED
#include "spot-on-mceliece.h"
#endif
#include "spot-on-misc.h"
#include "spot-on-threefish.h"

extern "C"
{
#ifdef SPOTON_LINKED_WITH_LIBPTHREAD
#if !defined(GCRYPT_VERSION_NUMBER) || GCRYPT_VERSION_NUMBER < 0x010600
  GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif
#endif
#include "libSpotOn/libspoton.h"
#include <openssl/opensslv.h>
}

#ifndef SPOTON_LINKED_WITH_LIBPTHREAD
#include <QMutex>
extern "C"
{
  int gcry_qmutex_destroy(void **mutex)
  {
    delete static_cast<QMutex *> (*mutex);
    return 0;
  }

  int gcry_qmutex_init(void **mutex)
  {
    *mutex = static_cast<void *> (new QMutex());
    return 0;
  }

  int gcry_qmutex_lock(void **mutex)
  {
    QMutex *m = static_cast<QMutex *> (*mutex);

    if(m)
      {
	m->lock();
	return 0;
      }
    else
      return -1;
  }

  int gcry_qmutex_unlock(void **mutex)
  {
    QMutex *m = static_cast<QMutex *> (*mutex);

    if(m)
      {
	m->unlock();
	return 0;
      }
    else
      return -1;
  }

  int gcry_qthread_init(void)
  {
    return 0;
  }
}

struct gcry_thread_cbs gcry_threads_qt =
  {
    GCRY_THREAD_OPTION_USER, gcry_qthread_init, gcry_qmutex_init,
    gcry_qmutex_destroy, gcry_qmutex_lock, gcry_qmutex_unlock,
    0, 0, 0, 0, 0, 0, 0, 0
  };
#endif

QAtomicInt spoton_crypt::s_hasSecureMemory = 0;
bool spoton_crypt::s_cbc_cts_enabled = true;
static bool gcryctl_set_thread_cbs_set = false;
static bool ssl_library_initialized = false;

spoton_crypt::spoton_crypt(const QByteArray &privateKey,
			   const QByteArray &publicKey)
{
  init("", "", QByteArray(), QByteArray(), QByteArray(), 0, 0, "", "cbc");
  m_privateKeyLength = static_cast<size_t> (privateKey.length());

  if(privateKey.startsWith("mceliece-") || publicKey.startsWith("mceliece-"))
    m_isMcEliece.fetchAndStoreOrdered(1);

  if(s_hasSecureMemory.fetchAndAddOrdered(0))
    {
      if(m_privateKeyLength == 0 ||
	 (m_privateKey =
	  static_cast<char *> (gcry_calloc_secure(m_privateKeyLength,
						  sizeof(char)))) == 0)
	{
	  m_privateKeyLength = 0;
	  spoton_misc::logError
	    (QString("spoton_crypt::spoton_crypt(): "
		     "gcry_calloc_secure() "
		     "failure or m_privateKeyLength is zero (%1).").arg(m_id));
	}
    }
  else
    {
      if(m_privateKeyLength == 0 ||
	 (m_privateKey = static_cast<char *> (calloc(m_privateKeyLength,
						     sizeof(char)))) == 0)
	{
	  m_privateKeyLength = 0;
	  spoton_misc::logError
	    (QString("spoton_crypt::spoton_crypt(): calloc() "
		     "failure or m_privateKeyLength is zero (%1).").arg(m_id));
	}
    }

  if(m_privateKey && m_privateKeyLength > 0)
    memcpy(m_privateKey,
	   privateKey.constData(),
	   m_privateKeyLength);

  m_publicKey = publicKey;
}

spoton_crypt::spoton_crypt(const QString &cipherType,
			   const QString &hashType,
			   const QByteArray &passphrase,
			   const QByteArray &symmetricKey,
			   const QByteArray &hashKey,
			   const int saltLength,
			   const unsigned long int iterationCount,
			   const QString &id)
{
  init(cipherType,
       hashType,
       passphrase,
       symmetricKey,
       hashKey,
       saltLength,
       iterationCount,
       id,
       "cbc");
}

spoton_crypt::spoton_crypt(const QString &cipherType,
			   const QString &hashType,
			   const QByteArray &passphrase,
			   const QByteArray &symmetricKey,
			   const QByteArray &hashKey,
			   const int saltLength,
			   const unsigned long int iterationCount,
			   const QString &id,
			   const QString &modeOfOperation)
{
  init(cipherType,
       hashType,
       passphrase,
       symmetricKey,
       hashKey,
       saltLength,
       iterationCount,
       id,
       modeOfOperation);
}

spoton_crypt::spoton_crypt(const QString &cipherType,
			   const QString &hashType,
			   const QByteArray &passphrase,
			   const QByteArray &symmetricKey,
			   const int saltLength,
			   const unsigned long int iterationCount,
			   const QString &id)
{
  init(cipherType,
       hashType,
       passphrase,
       symmetricKey,
       QByteArray(),
       saltLength,
       iterationCount,
       id,
       "cbc");
}

spoton_crypt::~spoton_crypt()
{
#ifdef SPOTON_MCELIECE_ENABLED
  delete m_mceliece;
#endif
  delete m_threefish;
  m_publicKey.clear();
  gcry_cipher_close(m_cipherHandle);
  gcry_free(m_hashKey);

  if(s_hasSecureMemory.fetchAndAddOrdered(0))
    gcry_free(m_privateKey);
  else
    free(m_privateKey);

  gcry_free(m_symmetricKey);
}

QByteArray spoton_crypt::decrypted(const QByteArray &data, bool *ok)
{
  if(data.isEmpty())
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  if(m_threefish)
    return m_threefish->decrypted(data, ok);

  if(m_cipherAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError("spoton_crypt::decrypted(): m_cipherAlgorithm "
			    "is zero.");
      return QByteArray();
    }

  if(!m_cipherHandle)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::decrypted(): m_cipherHandle is zero.");
      return QByteArray();
    }

  QByteArray decrypted(data);
  QMutexLocker locker(&m_cipherMutex);

  if(!setInitializationVector(decrypted, m_cipherAlgorithm, m_cipherHandle))
    {
      if(ok)
	*ok = false;

      decrypted.clear();
      spoton_misc::logError
	("spoton_crypt::decrypted(): setInitializationVector() failure.");
    }
  else
    {
      gcry_error_t err = 0;

      if((err = gcry_cipher_decrypt(m_cipherHandle,
				    decrypted.data(),
				    static_cast<size_t> (decrypted.length()),
				    0,
				    0)) == 0)
	{
	  QByteArray originalLength;
	  int s = 0;

	  if(decrypted.length() > static_cast<int> (sizeof(int)))
	    originalLength = decrypted.mid
	      (decrypted.length() - static_cast<int> (sizeof(int)),
	       static_cast<int> (sizeof(int)));

	  if(!originalLength.isEmpty())
	    {
	      QDataStream in(&originalLength, QIODevice::ReadOnly);

	      in >> s;

	      if(in.status() != QDataStream::Ok)
		{
		  if(ok)
		    *ok = false;

		  decrypted.clear();
		  return decrypted;
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      decrypted.clear();
	      return decrypted;
	    }

	  if(s >= 0 && s <= decrypted.length())
	    {
	      if(ok)
		*ok = true;

	      decrypted = decrypted.mid(0, s);
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      decrypted.clear();
	    }
	}
      else
	{
	  if(ok)
	    *ok = false;

	  decrypted.clear();
	}
    }

  return decrypted;
}

QByteArray spoton_crypt::decryptedAfterAuthenticated(const QByteArray &data,
						     bool *ok)
{
  if(data.isEmpty())
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  unsigned int length = gcry_md_get_algo_dlen(m_hashAlgorithm);

  if(length == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::decryptedAfterAuthenticated(): "
	 "gcry_md_get_algo_dlen() failure.");
      return QByteArray();
    }

  if(data.mid(static_cast<int> (length)).isEmpty())
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  QByteArray computedHash(keyedHash(data.mid(static_cast<int> (length)), ok));
  QByteArray hash(data.mid(0, static_cast<int> (length)));

  if(!computedHash.isEmpty() && !hash.isEmpty() && memcmp(computedHash, hash))
    return decrypted(data.mid(static_cast<int> (length)), ok);
  else
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }
}

QByteArray spoton_crypt::derivedSha1Key
(const QByteArray &salt,
 const QString &passphrase,
 const int hashKeySize,
 const unsigned long int iterationCount)
{
  if(gcry_md_test_algo(gcry_md_map_name("sha1")) != 0 || salt.isEmpty())
    return QByteArray();
  else
    gcry_fast_random_poll();

  QByteArray key(qAbs(hashKeySize), 0);
  int hashAlgorithm = gcry_md_map_name("sha1");

  if(gcry_kdf_derive(passphrase.toUtf8().constData(),
		     static_cast<size_t> (passphrase.toUtf8().length()),
		     GCRY_KDF_PBKDF2,
		     hashAlgorithm,
		     salt.constData(),
		     static_cast<size_t> (salt.length()),
		     iterationCount,
		     static_cast<size_t> (key.length()),
		     key.data()) != 0)
    return QByteArray();

  return key;
}

QByteArray spoton_crypt::digitalSignature(const QByteArray &data, bool *ok)
{
  {
    bool ok = true;

    initializePrivateKeyContainer(&ok);

    if(!ok)
      return QByteArray();
  }

  QReadLocker locker1(&m_privateKeyMutex);

  if(!m_privateKey || m_privateKeyLength == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::digitalSignature(): m_privateKey or "
	         "m_privateKeyLength is zero (%1).").arg(m_id));
      return QByteArray();
    }

  QByteArray array;

  array.append(m_privateKey, static_cast<int> (m_privateKeyLength));

  if(array.startsWith("mceliece-") ||
     array.startsWith("ntru-private-key-"))
    {
      if(ok)
	*ok = true;

      array.replace(0, array.length(), QByteArray(array.length(), 0));
      array.clear();
      return QByteArray();
    }

  array.replace(0, array.length(), QByteArray(array.length(), 0));
  array.clear();

  QByteArray hash(XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES, 0);
  QByteArray random(20, 0);
  QByteArray signature;
  QString keyType("");
  QStringList list;
  gcry_error_t err = 0;
  gcry_mpi_t hash_t = 0;
  gcry_sexp_t data_t = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t signature_t = 0;
  unsigned char *hash_p = 0;

  if((err = gcry_sexp_new(&key_t,
			  m_privateKey,
			  m_privateKeyLength, 1)) != 0 || !key_t)
    {
      locker1.unlock();

      if(ok)
	*ok = false;

      QWriteLocker locker2(&m_privateKeyMutex);

      if(s_hasSecureMemory.fetchAndAddOrdered(0))
	gcry_free(m_privateKey);
      else
	free(m_privateKey);

      m_privateKey = 0;
      m_privateKeyLength = 0;
      locker2.unlock();

      QWriteLocker locker3(&m_publicKeyMutex);

      m_publicKey.clear();
      locker3.unlock();

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::digitalSignature(): gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::digitalSignature(): gcry_sexp_new() failure.");

      goto done_label;
    }

  if((err = gcry_pk_testkey(key_t)) != 0)
    {
      locker1.unlock();

      if(ok)
	*ok = false;

      QByteArray buffer(64, 0);

      gpg_strerror_r(err, buffer.data(),
		     static_cast<size_t> (buffer.length()));
      spoton_misc::logError
	(QString("spoton_crypt::digitalSignature(): gcry_pk_testkey() "
		 "failure (%1).").arg(buffer.constData()));

      QWriteLocker locker2(&m_privateKeyMutex);

      if(s_hasSecureMemory.fetchAndAddOrdered(0))
	gcry_free(m_privateKey);
      else
	free(m_privateKey);

      m_privateKey = 0;
      m_privateKeyLength = 0;
      locker2.unlock();

      QWriteLocker locker3(&m_publicKeyMutex);

      m_publicKey.clear();
      locker3.unlock();
      goto done_label;
    }

  list << "dsa"
       << "ecc"
       << "elg"
       << "rsa";

  for(int i = 0; i < list.size(); i++)
    if(strstr(m_privateKey,
	      QString("(%1").arg(list.at(i)).toLatin1().constData()))
      {
	if(list.at(i) == "ecc")
	  {
	    if(!strstr(m_privateKey, "(flags eddsa)"))
	      keyType = "ecdsa";
	    else
	      keyType = "eddsa";

	    break;
	  }

	keyType = list.at(i);
	break;
      }

  locker1.unlock();
  gcry_md_hash_buffer
    (GCRY_MD_SHA512,
     hash.data(),
     data.constData(),
     static_cast<size_t> (data.length()));

  if(keyType == "dsa" || keyType == "ecdsa" || keyType == "elg")
    {
      if(hash.length() > 0)
	hash_p = static_cast<unsigned char *>
	  (malloc(static_cast<size_t> (hash.length())));
      else
	hash_p = 0;

      if(!hash_p)
	{
	  if(ok)
	    *ok = false;

	  spoton_misc::logError("spoton_crypt::digitalSignature(): "
				"hash is empty or malloc() failure.");
	  goto done_label;
	}
      else
	memcpy(hash_p, hash.constData(),
	       static_cast<size_t> (hash.length()));

      err = gcry_mpi_scan
	(&hash_t, GCRYMPI_FMT_USG, hash_p,
	 static_cast<size_t> (hash.length()), 0);

      if(err != 0 || !hash_t)
	{
	  if(ok)
	    *ok = false;

	  if(err != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(),
			     static_cast<size_t> (buffer.length()));
	      spoton_misc::logError
		(QString("spoton_crypt::digitalSignature(): "
			 "gcry_mpi_scan() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else
	    spoton_misc::logError
	      ("spoton_crypt::digitalSignature(): "
	       "gcry_mpi_scan() "
	       "failure.");

	  goto done_label;
	}

      err = gcry_sexp_build(&data_t, 0,
			    "(data (flags raw)(value %m))",
			    hash_t);
    }
  else if(keyType == "eddsa")
    err = gcry_sexp_build(&data_t, 0,
			  "(data (flags eddsa)(hash-algo sha512)"
			  "(value %b))",
			  hash.length(),
			  hash.constData());
  else if(keyType == "rsa")
    {
      random = strongRandomBytes(static_cast<size_t> (random.length()));
      err = gcry_sexp_build(&data_t, 0,
			    "(data (flags pss)(hash sha512 %b)"
			    "(random-override %b))",
			    hash.length(),
			    hash.constData(),
			    random.length(),
			    random.constData());
    }
  else
    {
      if(ok)
	*ok = false;

      spoton_misc::logError("spoton_crypt::digitalSignature(): "
			    "unable to determine the private key's type.");
      goto done_label;
    }

  if(err == 0 && data_t)
    {
      if((err = gcry_pk_sign(&signature_t, data_t,
			     key_t)) == 0 && signature_t)
	{
	  size_t length = gcry_sexp_sprint
	    (signature_t, GCRYSEXP_FMT_ADVANCED, 0, 0);

	  if(length > 0)
	    {
	      char *buffer = static_cast<char *> (malloc(length));

	      if(buffer)
		{
		  if(gcry_sexp_sprint(signature_t,
				      GCRYSEXP_FMT_ADVANCED,
				      buffer,
				      length) != 0)
		    {
		      if(ok)
			*ok = true;

		      signature.append
			(QByteArray(buffer, static_cast<int> (length)));
		    }
		  else
		    {
		      if(ok)
			*ok = false;

		      spoton_misc::logError
			("spoton_crypt::digitalSignature(): "
			 "gcry_sexp_sprint() failure.");
		    }
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    ("spoton_crypt::digitalSignature(): malloc() "
		     "failure.");
		}

	      if(buffer)
		memset(buffer, 0, length);

	      free(buffer);
	      buffer = 0;
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError
		("spoton_crypt::digitalSignature(): "
		 "gcry_sexp_sprint() failure.");
	    }
	}
      else
	{
	  if(ok)
	    *ok = false;

	  if(err != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(),
			     static_cast<size_t> (buffer.length()));
	      spoton_misc::logError
		(QString("spoton_crypt::digitalSignature(): "
			 "gcry_pk_sign() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else
	    spoton_misc::logError
	      ("spoton_crypt::digitalSignature(): gcry_pk_sign() "
	       "failure.");

	  goto done_label;
	}
    }
  else
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::digitalSignature(): "
		     "gcry_sexp_build() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::digitalSignature(): gcry_sexp_build() "
	   "failure.");

      goto done_label;
    }

 done_label:
  free(hash_p);
  gcry_mpi_release(hash_t);
  gcry_sexp_release(data_t);
  gcry_sexp_release(key_t);
  gcry_sexp_release(signature_t);
  return signature;
}

QByteArray spoton_crypt::encrypted(const QByteArray &data, bool *ok)
{
  if(m_threefish)
    return m_threefish->encrypted(data, ok);

  if(m_cipherAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::encrypted(): m_cipherAlgorithm is zero.");
      return QByteArray();
    }

  if(!m_cipherHandle)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::encrypted(): m_cipherHandle is zero.");
      return QByteArray();
    }

  QByteArray encrypted(data);
  QByteArray iv;
  QMutexLocker locker(&m_cipherMutex);

  if(!setInitializationVector(iv, m_cipherAlgorithm, m_cipherHandle))
    {
      if(ok)
	*ok = false;

      encrypted.clear();
      spoton_misc::logError
	("spoton_crypt::encrypted(): setInitializationVector() failure.");
    }
  else
    {
      size_t blockLength = gcry_cipher_get_algo_blklen(m_cipherAlgorithm);

      if(blockLength == 0)
	{
	  if(ok)
	    *ok = false;

	  encrypted.clear();
	  spoton_misc::logError
	    (QString("spoton_crypt::encrypted(): "
		     "gcry_cipher_get_algo_blklen() "
		     "failure for %1.").arg(m_cipherType));
	}
      else
	{
	  if(encrypted.isEmpty())
	    encrypted = encrypted.leftJustified
	      (static_cast<int> (blockLength), 0);
	  else if(static_cast<size_t> (encrypted.length()) < blockLength)
	    encrypted = encrypted.leftJustified
	      (static_cast<int> (blockLength) *
	       static_cast<int> (qCeil(static_cast<qreal> (encrypted.
							   length()) /
				       static_cast<qreal> (blockLength))),
	       0);

	  QByteArray originalLength;
	  QDataStream out(&originalLength, QIODevice::WriteOnly);

	  out << data.length();

	  if(out.status() != QDataStream::Ok)
	    {
	      if(ok)
		*ok = false;

	      encrypted.clear();
	      spoton_misc::logError
		(QString("spoton_crypt::encrypted(): "
			 "QDataStream failure (%1).").arg(out.status()));
	    }
	  else
	    {
	      encrypted.append(originalLength);

	      gcry_error_t err = 0;

	      if((err =
		  gcry_cipher_encrypt(m_cipherHandle,
				      encrypted.data(),
				      static_cast<size_t> (encrypted.
							   length()),
				      0,
				      0)) == 0)
		{
		  if(ok)
		    *ok = true;

		  encrypted = iv + encrypted;
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  encrypted.clear();

		  QByteArray buffer(64, 0);

		  gpg_strerror_r(err, buffer.data(),
				 static_cast<size_t> (buffer.length()));
		  spoton_misc::logError
		    (QString("spoton_crypt::encrypted(): "
			     "gcry_cipher_encrypt() failure (%1).").
		     arg(buffer.constData()));
		}
	    }
	}
    }

  return encrypted;
}

QByteArray spoton_crypt::encryptedThenHashed(const QByteArray &data, bool *ok)
{
  QByteArray bytes1(encrypted(data, ok));
  QByteArray bytes2;

  if(!bytes1.isEmpty())
    bytes2 = keyedHash(bytes1, ok);

  if(bytes1.isEmpty() || bytes2.isEmpty())
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }
  else
    return bytes2 + bytes1; // HMAC(E(Data)) || E(Data)
}

QByteArray spoton_crypt::hashKey(void)
{
  QReadLocker locker(&m_hashKeyMutex);

  if(m_hashKey)
    return QByteArray(m_hashKey, static_cast<int> (m_hashKeyLength));
  else
    return QByteArray();
}

QByteArray spoton_crypt::keyedHash(const QByteArray &data,
				   const QByteArray &key,
				   const QByteArray &hashType,
				   bool *ok)
{
  QByteArray hash;
  gcry_error_t err = 0;
  gcry_md_hd_t hd = 0;
  int hashAlgorithm = gcry_md_map_name(hashType.constData());

  if(hashAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::keyedHash(): hashAlgorithm is zero.");
      return hash;
    }
  else if(key.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::keyedHash(): key is empty.");
      return hash;
    }

  if((err = gcry_md_open(&hd, hashAlgorithm,
			 GCRY_MD_FLAG_HMAC)) != 0 || !hd)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::keyedHash(): gcry_md_open() "
		     "failure (%1).").
	     arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::keyedHash(): gcry_md_open() failure.");
    }
  else
    {
      if((err = gcry_md_setkey(hd,
			       key.constData(),
			       static_cast<size_t> (key.length()))) != 0)
	{
	  if(ok)
	    *ok = false;

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::keyedHash(): gcry_md_setkey() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	{
	  gcry_md_write
	    (hd,
	     data.constData(),
	     static_cast<size_t> (data.length()));

	  unsigned char *buffer = gcry_md_read(hd, hashAlgorithm);

	  if(buffer)
	    {
	      unsigned int length = gcry_md_get_algo_dlen(hashAlgorithm);

	      if(length > 0)
		{
		  if(ok)
		    *ok = true;

		  hash.resize(static_cast<int> (length));
		  memcpy(hash.data(),
			 buffer,
			 static_cast<size_t> (hash.length()));
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    (QString("spoton_crypt::keyedHash(): "
			     "gcry_md_get_algo_dlen() "
			     "failure for %1.").arg(hashType.constData()));
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError("spoton_crypt::keyedHash(): "
				    "gcry_md_read() returned zero.");
	    }
	}
    }

  gcry_md_close(hd);
  return hash;
}

QByteArray spoton_crypt::keyedHash(const QByteArray &data, bool *ok)
{
  if(m_hashAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::keyedHash(): m_hashAlgorithm is zero.");
      return QByteArray();
    }

  QReadLocker locker(&m_hashKeyMutex);

  if(!m_hashKey || m_hashKeyLength == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::keyedHash(): m_hashKey is not defined or "
	         "m_hashKeyLength is zero (%1).").arg(m_id));
      return QByteArray();
    }

  locker.unlock();

  QByteArray hash;
  gcry_error_t err = 0;
  gcry_md_hd_t hd = 0;

  if((err = gcry_md_open(&hd, m_hashAlgorithm,
			 GCRY_MD_FLAG_HMAC)) != 0 || !hd)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::keyedHash(): "
		     "gcry_md_open() failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::keyedHash(): gcry_md_open() failure.");
    }
  else
    {
      QReadLocker locker(&m_hashKeyMutex);

      if((err = gcry_md_setkey(hd,
			       m_hashKey,
			       m_hashKeyLength)) != 0)
	{
	  locker.unlock();

	  if(ok)
	    *ok = false;

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::keyedHash(): gcry_md_setkey() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	{
	  locker.unlock();
	  gcry_md_write
	    (hd,
	     data.constData(),
	     static_cast<size_t> (data.length()));

	  unsigned char *buffer = gcry_md_read(hd, m_hashAlgorithm);

	  if(buffer)
	    {
	      unsigned int length = gcry_md_get_algo_dlen(m_hashAlgorithm);

	      if(length > 0)
		{
		  if(ok)
		    *ok = true;

		  hash.resize(static_cast<int> (length));
		  memcpy(hash.data(),
			 buffer,
			 static_cast<size_t> (hash.length()));
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    (QString("spoton_crypt::keyedHash(): "
			     "gcry_md_get_algo_dlen() "
			     "failure for %1.").arg(m_hashType));
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError("spoton_crypt::keyedHash(): "
				    "gcry_md_read() returned zero.");
	    }
	}
    }

  gcry_md_close(hd);
  return hash;
}

QByteArray spoton_crypt::publicKey(bool *ok)
{
  QReadLocker locker(&m_publicKeyMutex);

  if(!m_publicKey.isEmpty())
    {
      if(ok)
	*ok = true;

      return m_publicKey;
    }

  locker.unlock();

  /*
  ** Returns the correct public key from idiotes.db.
  */

  QByteArray data;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key FROM idiotes WHERE id_hash = ?");
	query.bindValue(0, keyedHash(m_id.toLatin1(), &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    data = QByteArray::fromBase64(query.value(0).toByteArray());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    bool ok = true;

    data = decryptedAfterAuthenticated(data, &ok);

    if(!ok)
      data.clear();
  }

  if(data.isEmpty())
    {
      if(ok)
	*ok = false;

      QWriteLocker locker(&m_publicKeyMutex);

      m_publicKey.clear();
      return QByteArray();
    }

  if(data.contains("(public-key") ||
     data.startsWith("mceliece-") ||
     data.startsWith("ntru-public-key-"))
    {
      if(ok)
	*ok = true;

      QWriteLocker locker(&m_publicKeyMutex);

      m_publicKey = data;
    }
  else
    {
      if(ok)
	*ok = false;

      data.clear();

      QWriteLocker locker(&m_publicKeyMutex);

      m_publicKey.clear();
    }

  return data;
}

QByteArray spoton_crypt::publicKeyDecrypt(const QByteArray &data, bool *ok)
{
  {
    bool ok = true;

    initializePrivateKeyContainer(&ok);

    if(!ok)
      return QByteArray();
  }

  if(m_isMcEliece.fetchAndAddOrdered(0))
    return publicKeyDecryptMcEliece(data, ok);

  QReadLocker locker1(&m_privateKeyMutex);

  if(!m_privateKey || m_privateKeyLength == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::publicKeyDecrypt(): m_privateKey or "
	         "m_privateKeyLength is zero (%1).").arg(m_id));
      return QByteArray();
    }

  if(::memcmp(m_privateKey,
	      "ntru-private-key-",
	      qMin(m_privateKeyLength, strlen("ntru-private-key-"))) == 0)
    {
      locker1.unlock();

      /*
      ** NTRU requires knowledge of the public key.
      */

      {
	bool ok = true;

	publicKey(&ok);
      }

      return publicKeyDecryptNTRU(data, ok);
    }

  QByteArray decrypted;
  QByteArray random;
  QString keyType("");
  const char *buffer = 0;
  gcry_error_t err = 0;
  gcry_sexp_t data_t = 0;
  gcry_sexp_t decrypted_t = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t raw_t = 0;
  size_t length = 0;

  if((err = gcry_sexp_new(&key_t,
			  m_privateKey,
			  m_privateKeyLength, 1)) != 0 || !key_t)
    {
      locker1.unlock();

      if(ok)
	*ok = false;

      QWriteLocker locker2(&m_privateKeyMutex);

      if(s_hasSecureMemory.fetchAndAddOrdered(0))
	gcry_free(m_privateKey);
      else
	free(m_privateKey);

      m_privateKey = 0;
      m_privateKeyLength = 0;
      locker2.unlock();

      QWriteLocker locker3(&m_publicKeyMutex);

      m_publicKey.clear();
      locker3.unlock();

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::publicKeyDecrypt(): gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::publicKeyDecrypt(): gcry_sexp_new() failure.");

      goto done_label;
    }

  locker1.unlock();

  if((err = gcry_pk_testkey(key_t)) != 0)
    {
      if(ok)
	*ok = false;

      QByteArray buffer(64, 0);

      gpg_strerror_r(err, buffer.data(),
		     static_cast<size_t> (buffer.length()));
      spoton_misc::logError
	(QString("spoton_crypt::publicKeyDecrypt(): gcry_pk_testkey() "
		 "failure (%1).").arg(buffer.constData()));

      QWriteLocker locker1(&m_privateKeyMutex);

      if(s_hasSecureMemory.fetchAndAddOrdered(0))
	gcry_free(m_privateKey);
      else
	free(m_privateKey);

      m_privateKey = 0;
      m_privateKeyLength = 0;
      locker1.unlock();

      QWriteLocker locker2(&m_publicKeyMutex);

      m_publicKey.clear();
      locker2.unlock();
      goto done_label;
    }

  if((err = gcry_sexp_new(&data_t,
			  data.constData(),
			  static_cast<size_t> (data.length()),
			  1)) != 0 || !data_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  raw_t = gcry_sexp_find_token(key_t, "elg", 0);

  if(raw_t)
    keyType = "elg";
  else
    {
      raw_t = gcry_sexp_find_token(key_t, "rsa", 0);

      if(raw_t)
	keyType = "rsa";
    }

  if(!raw_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  gcry_sexp_release(raw_t);
  raw_t = gcry_sexp_find_token(data_t, keyType.toLatin1().constData(), 0);
  gcry_sexp_release(data_t);
  data_t = 0;

  if(!raw_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if(keyType == "elg")
    err = gcry_sexp_build(&data_t, 0,
			  "(enc-val (flags raw) %S)",
			  raw_t);
  else
    {
      unsigned int nbits = gcry_pk_get_nbits(key_t);

      if(nbits == 2048) // We do not support 2048-bit keys.
	{
	  random.resize(SHA384_OUTPUT_SIZE_IN_BYTES);
	  err = gcry_sexp_build(&data_t, 0,
				"(enc-val (flags oaep)"
				"(hash-algo sha384)(random-override %b) %S)",
				random.length(),
				random.constData(),
				raw_t);
	}
      else
	{
	  random.resize(XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
	  err = gcry_sexp_build(&data_t, 0,
				"(enc-val (flags oaep)"
				"(hash-algo sha512)(random-override %b) %S)",
				random.length(),
				random.constData(),
				raw_t);
	}
    }

  if(err != 0 || !data_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if((err = gcry_pk_decrypt(&decrypted_t,
			    data_t, key_t)) != 0 || !decrypted_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  buffer = gcry_sexp_nth_data(decrypted_t, 1, &length);

  if(!buffer || length == 0)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  decrypted = QByteArray(buffer, static_cast<int> (length));

  if(keyType == "elg")
    decrypted = QByteArray::fromBase64(decrypted);

  if(ok)
    *ok = true;

 done_label:
  gcry_sexp_release(data_t);
  gcry_sexp_release(decrypted_t);
  gcry_sexp_release(key_t);
  gcry_sexp_release(raw_t);
  return decrypted;
}

QByteArray spoton_crypt::publicKeyEncrypt(const QByteArray &data,
					  const QByteArray &pk,
					  const QByteArray &startsWith,
					  bool *ok)
{
  if(startsWith.startsWith("mceliece-"))
    return publicKeyEncryptMcEliece(data, pk, ok);
  else if(startsWith.startsWith("ntru-public-key-"))
    return publicKeyEncryptNTRU(data, qUncompress(pk), ok);
  else if(!startsWith.startsWith("(public-key"))
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  QByteArray encrypted;
  QByteArray publicKey(qUncompress(pk));
  gcry_error_t err = 0;
  gcry_sexp_t key_t = 0;

  if((err = gcry_sexp_new(&key_t,
			  publicKey.constData(),
			  static_cast<size_t> (publicKey.length()),
			  1)) == 0 && key_t)
    {
      QString keyType("");
      gcry_sexp_t data_t = 0;
      gcry_sexp_t encodedData_t = 0;
      gcry_sexp_t raw_t = 0;

      raw_t = gcry_sexp_find_token(key_t, "elg", 0);

      if(raw_t)
	keyType = "elg";
      else
	{
	  raw_t = gcry_sexp_find_token(key_t, "rsa", 0);

	  if(raw_t)
	    keyType = "rsa";
	}

      gcry_sexp_release(raw_t);

      if(keyType == "elg")
	err = gcry_sexp_build(&data_t, 0,
			      "(data (flags raw)(value %b))",
			      data.toBase64().length(),
			      data.toBase64().constData());
      else
	{
	  QByteArray random;
	  unsigned int nbits = gcry_pk_get_nbits(key_t);

	  if(nbits == 2048) // We do not support 2048-bit keys.
	    {
	      random.resize(SHA384_OUTPUT_SIZE_IN_BYTES);
	      random = strongRandomBytes
		(static_cast<size_t> (random.length()));
	      err = gcry_sexp_build(&data_t, 0,
				    "(data (flags oaep)(hash-algo sha384)"
				    "(value %b)(random-override %b))",
				    data.length(),
				    data.constData(),
				    random.length(),
				    random.constData());
	    }
	  else
	    {
	      random.resize(XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
	      random = strongRandomBytes
		(static_cast<size_t> (random.length()));
	      err = gcry_sexp_build(&data_t, 0,
				    "(data (flags oaep)(hash-algo sha512)"
				    "(value %b)(random-override %b))",
				    data.length(),
				    data.constData(),
				    random.length(),
				    random.constData());
	    }
	}

      if(err == 0 && data_t)
	{
	  if((err = gcry_pk_encrypt(&encodedData_t, data_t,
				    key_t)) == 0 && encodedData_t)
	    {
	      size_t length = gcry_sexp_sprint
		(encodedData_t, GCRYSEXP_FMT_ADVANCED, 0, 0);

	      if(length > 0)
		{
		  char *buffer = static_cast<char *> (malloc(length));

		  if(buffer)
		    {
		      if(gcry_sexp_sprint(encodedData_t,
					  GCRYSEXP_FMT_ADVANCED,
					  buffer,
					  length) != 0)
			{
			  if(ok)
			    *ok = true;

			  encrypted.append
			    (QByteArray(buffer, static_cast<int> (length)));
			}
		      else
			{
			  if(ok)
			    *ok = false;

			  spoton_misc::logError
			    ("spoton_crypt::publicKeyEncrypt(): "
			     "gcry_sexp_sprint() failure.");
			}
		    }
		  else
		    {
		      if(ok)
			*ok = false;

		      spoton_misc::logError
			("spoton_crypt::publicKeyEncrypt(): malloc() "
			 "failure.");
		    }

		  if(buffer)
		    memset(buffer, 0, length);

		  free(buffer);
		  buffer = 0;
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    ("spoton_crypt::publicKeyEncrypt(): "
		     "gcry_sexp_sprint() failure.");
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      if(err != 0)
		{
		  QByteArray buffer(64, 0);

		  gpg_strerror_r(err, buffer.data(),
				 static_cast<size_t> (buffer.length()));
		  spoton_misc::logError
		    (QString("spoton_crypt::publicKeyEncrypt(): "
			     "gcry_pk_encrypt() "
			     "failure (%1).").arg(buffer.constData()));
		}
	      else
		spoton_misc::logError
		  ("spoton_crypt::publicKeyEncrypt(): "
		   "gcry_pk_encrypt() failure.");
	    }
	}
      else
	{
	  if(ok)
	    *ok = false;

	  if(err != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(),
			     static_cast<size_t> (buffer.length()));
	      spoton_misc::logError
		(QString("spoton_crypt::publicKeyEncrypt(): "
			 "gcry_sexp_build() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else if(keyType.isEmpty())
	    spoton_misc::logError
	      ("spoton_crypt::publicKeyEncrypt(): gcry_sexp_find_token() "
	       "failure.");
	  else
	    spoton_misc::logError
	      ("spoton_crypt::publicKeyEncrypt(): gcry_sexp_build() "
	       "failure.");
	}

      gcry_sexp_release(data_t);
      gcry_sexp_release(encodedData_t);
    }
  else
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::publicKeyEncrypt(): gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::publicKeyEncrypt(): gcry_sexp_new() failure.");
    }

  gcry_sexp_release(key_t);
  return encrypted;
}

QByteArray spoton_crypt::publicKeyHash(bool *ok)
{
  QByteArray hash;

  {
    bool ok = true;

    publicKey(&ok);
  }

  QReadLocker locker(&m_publicKeyMutex);

  if(!m_publicKey.isEmpty())
    {
      bool ok = true;

      hash = shaXHash(m_hashAlgorithm, m_publicKey, &ok);

      if(!ok)
	hash.clear();
    }

  locker.unlock();

  if(hash.isEmpty())
    if(ok)
      *ok = false;

  return hash;
}

QByteArray spoton_crypt::randomBytes(const size_t size,
				     const enum gcry_random_level level)
{
  QByteArray random;

  if(size == 0)
    return random;

  char *buffer = static_cast<char *> (malloc(size));

  if(!buffer)
    return random;

  gcry_randomize(buffer, size, level);
  random = QByteArray(buffer, static_cast<int> (size));
  free(buffer);
  return random;
}

QByteArray spoton_crypt::saltedPassphraseHash(const QString &hashType,
					      const QString &passphrase,
					      const QByteArray &salt,
					      QString &error)
{
  QByteArray saltedPassphraseHash;
  QByteArray saltedPassphrase;
  int hashAlgorithm = 0;
  unsigned int length = 0;

  if(hashType.isEmpty())
    {
      error = QObject::tr("empty hashType");
      spoton_misc::logError("spoton_crypt::saltedPassphrase(): "
			    "empty hashType.");
      goto done_label;
    }

  if(passphrase.isEmpty())
    {
      error = QObject::tr("empty passphrase");
      spoton_misc::logError("spoton_crypt::saltedPassphrase(): "
			    "empty passphrase.");
      goto done_label;
    }

  if(salt.isEmpty())
    {
      error = QObject::tr("empty salt");
      spoton_misc::logError("spoton_crypt::saltedPassphrase(): "
			    "empty salt.");
      goto done_label;
    }

  hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());

  if(hashAlgorithm == 0)
    {
      error = QObject::tr("gcry_md_map_name() returned zero");
      spoton_misc::logError
	(QString("spoton_crypt::saltedPassphraseHash(): "
		 "gcry_md_map_name() "
		 "returned zero for %1.").arg(hashType));
      goto done_label;
    }

  length = gcry_md_get_algo_dlen(hashAlgorithm);

  if(length == 0)
    {
      error = QObject::tr("gcry_md_get_algo_dlen() returned zero");
      spoton_misc::logError
	(QString("spoton_crypt::saltedPassphraseHash(): "
		 "gcry_md_get_algo_dlen() "
		 "returned zero for %1.").arg(hashType));
      goto done_label;
    }

  saltedPassphrase.append(passphrase).append(salt);
  saltedPassphraseHash.resize(static_cast<int> (length));
  gcry_md_hash_buffer(hashAlgorithm,
		      saltedPassphraseHash.data(),
		      saltedPassphrase.constData(),
		      static_cast<size_t> (saltedPassphrase.length()));

 done_label:
  return saltedPassphraseHash;
}

QByteArray spoton_crypt::sha1FileHash(const QString &fileName)
{
  QAtomicInt atomic;

  return sha1FileHash(fileName, atomic);
}

QByteArray spoton_crypt::sha1FileHash(const QString &fileName,
				      QAtomicInt &atomic)
{
  QByteArray buffer(4096, 0);
  QCryptographicHash hash(QCryptographicHash::Sha1);
  QFile file(fileName);

  if(file.open(QIODevice::ReadOnly))
    {
      qint64 rc = 0;

      while((rc = file.read(buffer.data(), buffer.length())) > 0)
	{
	  if(atomic.fetchAndAddOrdered(0))
	    break;

	  hash.addData(buffer, static_cast<int> (rc));
	}
    }

  file.close();
  return hash.result();
}

QByteArray spoton_crypt::sha1Hash(const QByteArray &data, bool *ok)
{
  return shaXHash(GCRY_MD_SHA1, data, ok);
}

QByteArray spoton_crypt::sha256Hash(const QByteArray &data, bool *ok)
{
  return shaXHash(GCRY_MD_SHA256, data, ok);
}

QByteArray spoton_crypt::sha3_512FileHash(const QString &fileName)
{
  QAtomicInt atomic;

  return sha3_512FileHash(fileName, atomic);
}

QByteArray spoton_crypt::sha3_512FileHash(const QString &fileName,
					  QAtomicInt &atomic)
{
#if QT_VERSION >= 0x050100
  QByteArray buffer(4096, 0);
  QCryptographicHash hash(QCryptographicHash::Sha3_512);
  QFile file(fileName);

  if(file.open(QIODevice::ReadOnly))
    {
      qint64 rc = 0;

      while((rc = file.read(buffer.data(), buffer.length())) > 0)
	{
	  if(atomic.fetchAndAddOrdered(0))
	    break;

	  hash.addData(buffer, static_cast<int> (rc));
	}
    }

  file.close();
  return hash.result();
#else
  Q_UNUSED(atomic);
  Q_UNUSED(fileName);
  return QByteArray();
#endif
}

QByteArray spoton_crypt::sha512Hash(const QByteArray &data, bool *ok)
{
  return shaXHash(GCRY_MD_SHA512, data, ok);
}

QByteArray spoton_crypt::shaXHash(const int algorithm,
				  const QByteArray &data,
				  bool *ok)
{
  QByteArray hash;
  unsigned int length = gcry_md_get_algo_dlen(algorithm);

  if(length > 0)
    {
      if(ok)
	*ok = true;

      hash.resize(static_cast<int> (length));
      gcry_md_hash_buffer
	(algorithm,
	 hash.data(),
	 data.constData(),
	 static_cast<size_t> (data.length()));
    }
  else
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::shaXHash(): "
		 "gcry_md_get_algo_dlen() "
		 "failure for %1.").arg(algorithm));
    }

  return hash;
}

QByteArray spoton_crypt::shake256(const QByteArray &buffer,
				  const size_t length,
				  bool *ok)
{
#if !defined(GCRYPT_VERSION_NUMBER) || GCRYPT_VERSION_NUMBER < 0x010700
  Q_UNUSED(buffer);
  Q_UNUSED(length);

  if(ok)
    *ok = false;

  return QByteArray();
#else
  gcry_error_t err = 0;
  gcry_md_hd_t hd = 0;

  if((err = gcry_md_open(&hd, GCRY_MD_SHAKE256, 0)) != 0 || !hd)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::shake256(): gcry_md_open() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::shake256(): gcry_md_open() failure.");

      return QByteArray();
    }

  gcry_md_write(hd, buffer.constData(), static_cast<size_t> (buffer.length()));

  QByteArray bytes(static_cast<int> (length), 0);

  if((err = gcry_md_extract(hd, GCRY_MD_SHAKE256, bytes.data(), length)) != 0)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::shake256(): gcry_md_extract() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::shake256(): gcry_md_extract() failure.");

      gcry_md_close(hd);
      return QByteArray();
    }

  if(ok)
    *ok = true;

  gcry_md_close(hd);
  return bytes;
#endif
}

QByteArray spoton_crypt::strongRandomBytes(const size_t size)
{
  return randomBytes(size, GCRY_STRONG_RANDOM);
}

QByteArray spoton_crypt::symmetricKey(void)
{
  QReadLocker locker(&m_symmetricKeyMutex);

  if(m_symmetricKey && m_symmetricKeyLength > 0)
    return QByteArray
      (m_symmetricKey, static_cast<int> (m_symmetricKeyLength));
  else
    return QByteArray();
}

QByteArray spoton_crypt::veryStrongRandomBytes(const size_t size)
{
  return randomBytes(size, GCRY_VERY_STRONG_RANDOM);
}

QByteArray spoton_crypt::weakRandomBytes(const size_t size)
{
  return randomBytes(size, GCRY_WEAK_RANDOM);
}

QByteArray spoton_crypt::whirlpoolHash(const QByteArray &data, bool *ok)
{
  QByteArray hash;
  unsigned int length = gcry_md_get_algo_dlen(GCRY_MD_WHIRLPOOL);

  if(length > 0)
    {
      if(ok)
	*ok = true;

      hash.resize(static_cast<int> (length));
      gcry_md_hash_buffer
	(GCRY_MD_WHIRLPOOL,
	 hash.data(),
	 data.constData(),
	 static_cast<size_t> (data.length()));
    }
  else
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::whirlpool(): "
		 "gcry_md_get_algo_dlen() "
		 "failure for %1.").arg(GCRY_MD_WHIRLPOOL));
    }

  return hash;
}

QList<QSslCipher> spoton_crypt::defaultSslCiphers(const QString &scs)
{
  QList<QSslCipher> list;
  QString controlString(scs.trimmed());
  QStringList protocols;
  SSL *ssl = 0;
  SSL_CTX *ctx = 0;
  const char *next = 0;
  int index = 0;

  if(controlString.isEmpty())
    {
      QSettings settings;

      controlString = settings.value
	("gui/sslControlString",
	 spoton_common::SSL_CONTROL_STRING).toString().trimmed();
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  protocols << "TlsV1_2"
	    << "TlsV1_1"
	    << "TlsV1_0";

  if(!controlString.toLower().contains("!sslv3"))
    protocols << "SslV3";
#else
  protocols << "TlsV1_3"
            << "TlsV1_2"
	    << "TlsV1_1"
	    << "TlsV1_0";
#endif

  while(!protocols.isEmpty())
    {
      QString protocol(protocols.takeFirst());

      index = 0;
      next = 0;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      ctx = SSL_CTX_new(TLS_client_method());
#else
      if(protocol == "TlsV1_2")
	{
#ifdef TLS1_2_VERSION
	  if(!(ctx = SSL_CTX_new(TLSv1_2_client_method())))
	    {
	      spoton_misc::logError
		("spoton_crypt::defaultSslCiphers(): "
		 "SSL_CTX_new(TLSv1_2_client_method()) failure.");
	      goto done_label;
	    }
#endif
	}
      else if(protocol == "TlsV1_1")
	{
#ifdef TLS1_1_VERSION
	  if(!(ctx = SSL_CTX_new(TLSv1_1_method())))
	    {
	      spoton_misc::logError
		("spoton_crypt::defaultSslCiphers(): "
		 "SSL_CTX_new(TLSv1_1_method()) failure.");
	      goto done_label;
	    }
#endif
	}
      else if(protocol == "TlsV1_0")
	{
	  if(!(ctx = SSL_CTX_new(TLSv1_method())))
	    {
	      spoton_misc::logError
		("spoton_crypt::defaultSslCiphers(): "
		 "SSL_CTX_new(TLSv1_method()) failure.");
	      goto done_label;
	    }
	}
      else
	{
#ifndef OPENSSL_NO_SSL3_METHOD
	  if(!(ctx = SSL_CTX_new(SSLv3_method())))
	    {
	      spoton_misc::logError
		("spoton_crypt::defaultSslCiphers(): "
		 "SSL_CTX_new(SSLv3_method()) failure.");
	      goto done_label;
	    }
#endif
	}
#endif

      if(!ctx)
	{
	  spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				"ctx is zero!");
	  continue;
	}

      if(SSL_CTX_set_cipher_list(ctx,
				 controlString.toLatin1().constData()) == 0)
	{
	  spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				"SSL_CTX_set_cipher_list() failure.");
	  goto done_label;
	}

      if(!(ssl = SSL_new(ctx)))
	{
	  spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				"SSL_new() failure.");
	  goto done_label;
	}

      do
	{
	  if((next = SSL_get_cipher_list(ssl, index)))
	    {
#if QT_VERSION < 0x050000
	      QSslCipher cipher;

	      if(protocol == "SslV3")
		cipher = QSslCipher(next, QSsl::SslV3);
	      else if(protocol == "TlsV1_0")
		cipher = QSslCipher(next, QSsl::TlsV1);
	      else
		cipher = QSslCipher(next, QSsl::UnknownProtocol);
#else
	      QSslCipher cipher;

	      if(protocol == "SslV3")
		cipher = QSslCipher(next, QSsl::SslV3);
	      else if(protocol == "TlsV1_0")
		cipher = QSslCipher(next, QSsl::TlsV1_0);
	      else if(protocol == "TlsV1_1")
		cipher = QSslCipher(next, QSsl::TlsV1_1);
	      else if(protocol == "TlsV1_2")
		cipher = QSslCipher(next, QSsl::TlsV1_2);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0))
	      else if(protocol == "TlsV1_3")
		cipher = QSslCipher(next, QSsl::TlsV1_3OrLater);
#endif
#endif

	      if(cipher.isNull())
		cipher = QSslCipher(next, QSsl::UnknownProtocol);

	      if(!cipher.isNull())
		list.append(cipher);
	    }

	  index += 1;
	}
      while(next);

    done_label:
      SSL_CTX_free(ctx);
      SSL_free(ssl);
      ctx = 0;
      ssl = 0;
    }

  if(list.isEmpty())
    spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
			  "empty cipher list.");

  return list;
}

QPair<QByteArray, QByteArray> spoton_crypt::derivedKeys
(const QString &cipherType,
 const QString &hashType,
 const unsigned long int iterationCount,
 const QString &passphrase,
 const QByteArray &salt,
 const bool singleIteration,
 QString &error)
{
  return derivedKeys
    (cipherType,
     hashType,
     iterationCount,
     passphrase,
     salt,
     256,
     singleIteration,
     error);
}

QPair<QByteArray, QByteArray> spoton_crypt::derivedKeys
(const QString &cipherType,
 const QString &hashType,
 const unsigned long int iterationCount,
 const QString &passphrase,
 const QByteArray &salt,
 const int hashKeySize,
 const bool singleIteration,
 QString &error)
{
  if(salt.isEmpty())
    {
      error = QObject::tr("empty salt");
      spoton_misc::logError("spoton_crypt::derivedKeys(): empty salt.");
      return QPair<QByteArray, QByteArray> ();
    }

  QByteArray key;
  QByteArray temporaryKey;
  QPair<QByteArray, QByteArray> keys;
  gcry_error_t err = 0;
  int cipherAlgorithm = (cipherType == "threefish") ? -1 :
    gcry_cipher_map_name(cipherType.toLatin1().constData());
  int hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  size_t keyLength = 0;

  if(cipherAlgorithm > 0 && gcry_cipher_test_algo(cipherAlgorithm) != 0)
    {
      error = QObject::tr("gcry_cipher_test_algo() returned non-zero");
      spoton_misc::logError
	(QString("spoton_crypt::derivedKeys(): gcry_cipher_test_algo() "
		 "failure for %1.").arg(cipherType));
      goto done_label;
    }

  if(gcry_md_test_algo(hashAlgorithm) != 0)
    {
      error = QObject::tr("gcry_md_test_algo() returned non-zero");
      spoton_misc::logError
	(QString("spoton_crypt::derivedKeys(): gcry_md_test_algo() "
		 "failure for %1.").arg(hashType));
      goto done_label;
    }

  if(cipherAlgorithm > 0)
    {
      if((keyLength = gcry_cipher_get_algo_keylen(cipherAlgorithm)) == 0)
	{
	  error = QObject::tr("gcry_cipher_get_algo_keylen() failed");
	  spoton_misc::logError
	    (QString("spoton_crypt::derivedKeys(): "
		     "gcry_cipher_get_algo_keylen() "
		     "failure for %1.").arg(cipherType));
	  goto done_label;
	}
    }
  else if(cipherType == "threefish")
    keyLength = cipherKeyLength(cipherType.toLatin1());
  else
    {
      error = QObject::tr("unsupported cipher");
      spoton_misc::logError
	(QString("spoton_crypt::derivedKeys(): "
		 "unsupported cipher %1.").arg(cipherType));
      goto done_label;
    }

  /*
  ** keys.first: encryption key.
  ** keys.second: hash key.
  */

  key.resize(static_cast<int> (keyLength) + qAbs(hashKeySize));
  keys.first.resize(static_cast<int> (keyLength));
  keys.second.resize(key.length() - static_cast<int> (keyLength));
  temporaryKey.resize(key.length());

  /*
  ** temporary = PBKDF2(passphrase, ...)
  ** (keys.first, keys.second) = PBKDF2(temporary, ...)
  */

  for(int i = 1; i <= 2; i++)
    {
      gcry_fast_random_poll();

      if(i == 1)
	err = gcry_kdf_derive
	  (passphrase.toUtf8().constData(),
	   static_cast<size_t> (passphrase.toUtf8().length()),
	   GCRY_KDF_PBKDF2,
	   hashAlgorithm,
	   salt.constData(),
	   static_cast<size_t> (salt.length()),
	   iterationCount,
	   static_cast<size_t> (temporaryKey.length()),
	   temporaryKey.data());
      else if(i == 2)
	{
	  if(singleIteration)
	    {
	      keys.first = temporaryKey.mid(0, keys.first.length());
	      keys.second = temporaryKey.mid(keys.first.length());
	    }
	  else
	    {
	      err = gcry_kdf_derive
		(temporaryKey.constData(),
		 static_cast<size_t> (temporaryKey.length()),
		 GCRY_KDF_PBKDF2,
		 hashAlgorithm,
		 salt.constData(),
		 static_cast<size_t> (salt.length()),
		 iterationCount,
		 static_cast<size_t> (key.length()),
		 key.data());

	      if(err == 0)
		{
		  keys.first = key.mid(0, keys.first.length());
		  keys.second = key.mid(keys.first.length());
		}
	    }

	  temporaryKey.replace
	    (0, temporaryKey.length(), QByteArray(temporaryKey.length(), 0));
	  temporaryKey.clear();
	}

      if(err != 0)
	{
	  error = QObject::tr("gcry_kdf_derive() returned non-zero");

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::derivedKeys(): gcry_kdf_derive() "
		     "returned non-zero (%1).").arg(buffer.constData()));
	  break;
	}
    }

 done_label:

  if(!error.isEmpty())
    {
      keys.first.replace
	(0, keys.first.length(), QByteArray(keys.first.length(), 0));
      keys.first.clear();
      keys.second.replace
	(0, keys.second.length(), QByteArray(keys.second.length(), 0));
      keys.second.clear();
    }

  temporaryKey.replace
    (0, temporaryKey.length(), QByteArray(temporaryKey.length(), 0));
  temporaryKey.clear();
  return keys;
}

QPair<QByteArray, QByteArray> spoton_crypt::generatePrivatePublicKeys
(const QString &keySize,
 const QString &keyType,
 QString &error,
 const bool save_keys)
{
  QByteArray privateKey;
  QByteArray publicKey;
  QPair<QByteArray, QByteArray> keys;
  QString connectionName("");
  QString genkey("");
  char *buffer = 0;
  gcry_error_t err = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t keyPair_t = 0;
  gcry_sexp_t parameters_t = 0;
  int ks = keySize.toInt();
  size_t length = 0;

  m_isMcEliece.fetchAndStoreOrdered(0);

  /*
  ** Use lock guards.
  */

  QWriteLocker locker1(&m_privateKeyMutex);

  if(s_hasSecureMemory.fetchAndAddOrdered(0))
    gcry_free(m_privateKey);
  else
    free(m_privateKey);

  m_privateKey = 0;
  m_privateKeyLength = 0;
  locker1.unlock();

  QWriteLocker locker2(&m_publicKeyMutex);

  m_publicKey.clear();
  locker2.unlock();

  if(ks <= 0 || ks > 15360)
    ks = 3072;

  if(keyType.toLower() == "dsa")
    genkey = QString("(genkey (dsa (nbits %1:%2)))").
      arg(qFloor(log10(ks)) + 1).
      arg(ks);
  else if(keyType.toLower() == "ecdsa")
    {
      if(ks <= 0 || ks > 521)
	ks = 521;

      genkey = QString("(genkey (ecc (nbits %1:%2)))").
	arg(qFloor(log10(ks)) + 1).
	arg(ks);
    }
  else if(keyType.toLower() == "eddsa")
    genkey = "(genkey (ecc (curve \"Ed25519\")(flags eddsa)))";
  else if(keyType.toLower() == "elg")
    genkey = QString("(genkey (elg (nbits %1:%2)))").
      arg(qFloor(log10(ks)) + 1).
      arg(ks);
  else if(keyType.toLower() == "mceliece")
    {
      bool ok = true;

      generateMcElieceKeys(keySize, privateKey, publicKey, &ok);

      if(ok)
	goto save_keys_label;
      else
	{
	  error = QObject::tr("generateMcElieceKeys() failure");
	  spoton_misc::logError
	    ("spoton_crypt::generatePrivatePublicKeys(): "
	     "generateMcElieceKeys() failure.");
	  goto done_label;
	}
    }
  else if(keyType.toLower() == "ntru")
    {
      bool ok = true;

      generateNTRUKeys(keySize, privateKey, publicKey, &ok);

      if(ok)
	goto save_keys_label;
      else
	{
	  error = QObject::tr("generateNTRUKeys() failure");
	  spoton_misc::logError
	    ("spoton_crypt::generatePrivatePublicKeys(): "
	     "generateNTRUKeys() failure.");
	  goto done_label;
	}
    }
  else if(keyType.toLower() == "rsa")
    genkey = QString("(genkey (rsa (nbits %1:%2)))").
      arg(qFloor(log10(ks)) + 1).
      arg(ks);
  else
    {
      error = QObject::tr("key type is not supported");
      spoton_misc::logError
	("spoton_crypt::generatePrivatePublicKeys(): "
	 "key type is not supported.");
      goto done_label;
    }

  if((err = gcry_sexp_build(&parameters_t, 0,
			    genkey.toLatin1().constData())) != 0 ||
     !parameters_t)
    {
      error = QObject::tr("gcry_sexp_build() failure");

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::generatePrivatePublicKeys(): "
		     "gcry_sexp_build() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::generatePrivatePublicKeys(): gcry_sexp_build() "
	   "failure.");

      goto done_label;
    }

  gcry_fast_random_poll();

  if((err = gcry_pk_genkey(&keyPair_t, parameters_t)) != 0 || !keyPair_t)
    {
      error = QObject::tr("gcry_pk_genkey() failure");

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::generatePrivatePublicKeys(): "
		     "gcry_pk_genkey() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::generatePrivatePublicKeys(): gcry_pk_genkey() "
	   "failure.");

      goto done_label;
    }

  for(int i = 1; i <= 2; i++)
    {
      if(i == 1)
	key_t = gcry_sexp_find_token(keyPair_t, "private-key", 0);
      else
	key_t = gcry_sexp_find_token(keyPair_t, "public-key", 0);

      if(!key_t)
	{
	  error = QObject::tr("gcry_sexp_find_token() failure");
	  spoton_misc::logError
	    ("spoton_crypt::generatePrivatePublicKeys(): "
	     "gcry_sexp_find_token() failure.");
	  goto done_label;
	}

      length = gcry_sexp_sprint(key_t, GCRYSEXP_FMT_ADVANCED, 0, 0);

      if(length == 0)
	{
	  error = QObject::tr("gcry_sexp_sprint() failure");
	  spoton_misc::logError
	    ("spoton_crypt::generatePrivatePublicKeys(): gcry_sexp_sprint() "
	     "failure.");
	  goto done_label;
	}
      else
	{
	  buffer = static_cast<char *> (malloc(length));

	  if(buffer)
	    {
	      if(gcry_sexp_sprint(key_t, GCRYSEXP_FMT_ADVANCED,
				  buffer, length) == 0)
		{
		  error = QObject::tr("gcry_sexp_sprint() failure");
		  spoton_misc::logError
		    ("spoton_crypt::generatePrivatePublicKeys(): "
		     "gcry_sexp_sprint() "
		     "failure.");
		  goto done_label;
		}

	      if(i == 1)
		privateKey = QByteArray(buffer, static_cast<int> (length));
	      else
		publicKey = QByteArray(buffer, static_cast<int> (length));

	      memset(buffer, 0, length);
	      free(buffer);
	      buffer = 0;
	    }
	  else
	    {
	      error = QObject::tr("malloc() failure");
	      spoton_misc::logError
		("spoton_crypt::generatePrivatePublicKeys(): "
		 "malloc() failure.");
	      goto done_label;
	    }
	}

      gcry_free(key_t);
      key_t = 0;
    }

 save_keys_label:

  if(!save_keys)
    {
      keys.first = privateKey;
      keys.second = publicKey;
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("INSERT OR REPLACE INTO idiotes (id, id_hash, "
	   "private_key, public_key) "
	   "VALUES (?, ?, ?, ?)");
	query.bindValue(0, encryptedThenHashed(m_id.toLatin1(),
					       &ok).toBase64());

	if(ok)
	  query.bindValue(1, keyedHash(m_id.toLatin1(), &ok).toBase64());

	if(ok)
	  if(!privateKey.isEmpty())
	    query.bindValue
	      (2, encryptedThenHashed(privateKey, &ok).toBase64());

	if(ok)
	  if(!publicKey.isEmpty())
	    query.bindValue
	      (3, encryptedThenHashed(publicKey, &ok).toBase64());

	if(ok)
	  {
	    if(!query.exec())
	      {
		error = QObject::tr("QSqlQuery::exec() failure");
		spoton_misc::logError
		  (QString("spoton_crypt::generatePrivatePublicKeys(): "
			   "QSqlQuery::exec() failure (%1).").
		   arg(query.lastError().text()));
	      }
	  }
	else
	  {
	    error = QObject::tr("encryptedThenHashed() failure");
	    spoton_misc::logError
	      ("spoton_crypt::generatePrivatePublicKeys(): "
	       "encryptedThenHashed() failure.");
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:
  privateKey.replace
    (0, privateKey.length(), QByteArray(privateKey.length(), 0));
  privateKey.clear();
  publicKey.replace
    (0, publicKey.length(), QByteArray(publicKey.length(), 0));
  publicKey.clear();
  free(buffer);
  gcry_free(key_t);
  gcry_free(keyPair_t);
  gcry_free(parameters_t);
  return keys;
}

QString spoton_crypt::cipherType(void) const
{
  return m_cipherType;
}

QString spoton_crypt::publicKeyAlgorithm(const QByteArray &data)
{
  QString keyType("");
  QStringList list;

  list << "dsa"
       << "ecc"
       << "elg"
       << "rsa";

  for(int i = 0; i < list.size(); i++)
    if(data.contains(QString("(%1").arg(list.at(i)).toLatin1()))
      {
	if(list.at(i) == "ecc")
	  {
	    if(!data.contains("(flags eddsa)"))
	      keyType = "ECDSA";
	    else
	      keyType = "EdDSA";

	    break;
	  }
	else if(list.at(i) == "elg")
	  {
	    keyType = "ElGamal";
	    break;
	  }

	keyType = list.at(i).toUpper();
	break;
      }

  if(keyType.isEmpty())
    {
      if(data.startsWith("mceliece"))
	keyType = "McEliece";
      else if(data.startsWith("ntru"))
	keyType = "NTRU";
    }

  return keyType;
}

QString spoton_crypt::publicKeyAlgorithm(void)
{
  bool ok = true;

  publicKey(&ok);

  if(!ok)
    {
      spoton_misc::logError
	("spoton_crypt::publicKeyAlgorithm(): publicKey() failure.");
      return "";
    }

  return publicKeyAlgorithm(m_publicKey);
}

QString spoton_crypt::publicKeySize(const QByteArray &data)
{
  QString algorithm(publicKeyAlgorithm(data).toLower().trimmed());

  if(algorithm.isEmpty())
    {
      spoton_misc::logError
	("spoton_crypt::publicKeySize(): publicKeyAlgorithm() failure.");
      return "";
    }

  QString keySize("");

  if(algorithm == "mceliece")
    keySize = publicKeySizeMcEliece(data);
  else if(algorithm == "ntru")
    keySize = publicKeySizeNTRU(data);
  else
    {
      gcry_sexp_t key_t = 0;

      if(gcry_sexp_new(&key_t,
		       data.constData(),
		       static_cast<size_t> (data.length()),
		       1) == 0 && key_t)
	keySize = QString::number(gcry_pk_get_nbits(key_t));

      gcry_sexp_release(key_t);
    }

  return keySize;
}

QString spoton_crypt::publicKeySize(void)
{
  bool ok = true;

  publicKey(&ok);

  if(!ok)
    {
      spoton_misc::logError
	("spoton_crypt::publicKeySize(): publicKey() failure.");
      return "";
    }

  return publicKeySize(m_publicKey);
}

QStringList spoton_crypt::buzzHashTypes(void)
{
  QStringList types;

  types << "blake2b_512"
	<< "sha3-512"
	<< "sha384"
	<< "sha512"
	<< "stribog512"
	<< "whirlpool";

  for(int i = types.size() - 1; i >= 0; i--)
    {
      int algorithm = gcry_md_map_name(types.at(i).toLatin1().constData());

      if(!(algorithm != 0 && gcry_md_test_algo(algorithm) == 0))
	types.removeAt(i);
    }

  return types;
}

QStringList spoton_crypt::cipherTypes(void)
{
  QStringList types;

  types << "aes256"
	<< "camellia256"
	<< "gost28147"
	<< "serpent256"
	<< "twofish";

  for(int i = types.size() - 1; i >= 0; i--)
    {
      int algorithm = gcry_cipher_map_name(types.at(i).toLatin1().constData());

      if(!(algorithm != 0 && gcry_cipher_test_algo(algorithm) == 0))
	types.removeAt(i);
    }

  types << "threefish";
  std::sort(types.begin(), types.end());
  return types;
}

QStringList spoton_crypt::congestionHashAlgorithms(void)
{
  QStringList types;

  types << "blake2b_160"
	<< "blake2b_256"
	<< "blake2b_384"
	<< "blake2b_512"
	<< "blake2s_128"
	<< "blake2s_224"
	<< "sha1"
	<< "sha224"
	<< "sha3-224"
	<< "sha3-256"
	<< "sha3-384"
	<< "sha3-512"
	<< "sha384"
	<< "sha512"
	<< "stribog256"
	<< "stribog512"
	<< "tiger"
	<< "tiger1"
	<< "tiger2";

  for(int i = types.size() - 1; i >= 0; i--)
    {
      int algorithm = gcry_md_map_name(types.at(i).toLatin1().constData());

      if(!(algorithm != 0 && gcry_md_test_algo(algorithm) == 0))
	types.removeAt(i);
    }

  return types;
}

QStringList spoton_crypt::hashTypes(void)
{
  QStringList types;

  types << "blake2b_512"
	<< "sha3-512"
	<< "sha512"
	<< "stribog512"
	<< "whirlpool";

  for(int i = types.size() - 1; i >= 0; i--)
    {
      int algorithm = gcry_md_map_name(types.at(i).toLatin1().constData());

      if(!(algorithm != 0 && gcry_md_test_algo(algorithm) == 0))
	types.removeAt(i);
    }

  return types;
}

bool spoton_crypt::exists(const QByteArray &publicKey, spoton_crypt *crypt)
{
  if(!crypt)
    return false;

  QString connectionName("");
  bool exists = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT public_key FROM idiotes"))
	  while(query.next())
	    {
	      QByteArray data;
	      bool ok = true;

	      data = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		if(data == publicKey)
		  {
		    exists = true;
		    break;
		  }
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return exists;
}

bool spoton_crypt::hasShake(void)
{
#if !defined(GCRYPT_VERSION_NUMBER) || GCRYPT_VERSION_NUMBER < 0x010700
  return false;
#else
  return true;
#endif
}

bool spoton_crypt::isAuthenticated(void)
{
  QString connectionName("");
  bool authenticated = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key FROM idiotes WHERE id_hash = ?");
	query.bindValue(0, keyedHash(m_id.toLatin1(), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray data;
	      bool ok = true;

	      data = decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(!data.isEmpty() && ok)
		authenticated = true;
	      else
		spoton_misc::logError
		  ("spoton_crypt::isAuthenticated(): "
		   "data is empty or ok is false.");

	      break;
	    }

	if(query.lastError().isValid())
	  spoton_misc::logError
	    (QString("spoton_crypt::isAuthenticated(): "
		     "QSqlQuery::exec() failure (%1).").
	     arg(query.lastError().text()));
	else
	  authenticated = true; // We know very little.
      }

    if(db.lastError().isValid())
      spoton_misc::logError
	(QString("spoton_crypt::isAuthenticated(): "
		 "database error (%1).").arg(db.lastError().text()));

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return authenticated;
}

bool spoton_crypt::isValidSignature(const QByteArray &data,
				    const QByteArray &publicKey,
				    const QByteArray &signature)
{
  QByteArray hash(XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES, 0);
  QByteArray random(20, 0);
  QString keyType("");
  QStringList list;
  bool ok = true;
  gcry_error_t err = 0;
  gcry_mpi_t hash_t = 0;
  gcry_sexp_t data_t = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t signature_t = 0;
  unsigned char *hash_p = 0;

  if(data.isEmpty() || publicKey.isEmpty() || signature.isEmpty())
    {
      ok = false;
      spoton_misc::logError
	("spoton_crypt::isValidSignature(): data, publicKey, or "
	 "signature is empty.");
      goto done_label;
    }

  if((err = gcry_sexp_new(&key_t,
			  publicKey.constData(),
			  static_cast<size_t> (publicKey.length()),
			  1)) != 0 || !key_t)
    {
      ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::isValidSignature(): gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::isValidSignature(): gcry_sexp_new() failure.");

      goto done_label;
    }

  if((err = gcry_sexp_new(&signature_t,
			  signature.constData(),
			  static_cast<size_t> (signature.length()),
			  1)) != 0 || !signature_t)
    {
      ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::isValidSignature(): "
		     "gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::isValidSignature(): gcry_sexp_new() "
	   "failure.");

      goto done_label;
    }

  list << "dsa"
       << "ecc"
       << "elg"
       << "rsa";

  for(int i = 0; i < list.size(); i++)
    if(publicKey.contains(QString("(%1").arg(list.at(i)).toLatin1()))
      {
	if(list.at(i) == "ecc")
	  {
	    if(!publicKey.contains("(flags eddsa)"))
	      keyType = "ecdsa";
	    else
	      keyType = "eddsa";

	    break;
	  }

	keyType = list.at(i);
	break;
      }

  gcry_md_hash_buffer
    (GCRY_MD_SHA512,
     hash.data(),
     data.constData(),
     static_cast<size_t> (data.length()));

  if(keyType == "dsa" || keyType == "ecdsa" || keyType == "elg")
    {
      if(hash.length() > 0)
	hash_p = static_cast<unsigned char *>
	  (malloc(static_cast<size_t> (hash.length())));
      else
	hash_p = 0;

      if(!hash_p)
	{
	  ok = false;
	  spoton_misc::logError("spoton_crypt::isValidSignature(): "
				"hash is empty or malloc() failure.");
	  goto done_label;
	}
      else
	memcpy(hash_p, hash.constData(),
	       static_cast<size_t> (hash.length()));

      err = gcry_mpi_scan
	(&hash_t, GCRYMPI_FMT_USG, hash_p,
	 static_cast<size_t> (hash.length()), 0);

      if(err != 0 || !hash_t)
	{
	  ok = false;

	  if(err != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(),
			     static_cast<size_t> (buffer.length()));
	      spoton_misc::logError
		(QString("spoton_crypt::isValidSignature(): "
			 "gcry_mpi_scan() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else
	    spoton_misc::logError
	      ("spoton_crypt::isValidSignature(): "
	       "gcry_mpi_scan() "
	       "failure.");

	  goto done_label;
	}

      err = gcry_sexp_build(&data_t, 0,
			    "(data (flags raw)(value %m))",
			    hash_t);
    }
  else if(keyType == "eddsa")
    err = gcry_sexp_build(&data_t, 0,
			  "(data (flags eddsa)(hash-algo sha512)"
			  "(value %b))",
			  hash.length(),
			  hash.constData());
  else if(keyType == "rsa")
    err = gcry_sexp_build(&data_t, 0,
			  "(data (flags pss)(hash sha512 %b)"
			  "(random-override %b))",
			  hash.length(),
			  hash.constData(),
			  random.length(),
			  random.constData());
  else
    {
      ok = false;
      spoton_misc::logError("spoton_crypt::isValidSignature(): "
			    "unable to determine the public key's type.");
      goto done_label;
    }

  if(err != 0 || !data_t)
    {
      ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(),
			 static_cast<size_t> (buffer.length()));
	  spoton_misc::logError
	    (QString("spoton_crypt::isValidSignature(): "
		     "gcry_sexp_build() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::isValidSignature(): gcry_sexp_build() "
	   "failure.");

      goto done_label;
    }

  if((err = gcry_pk_verify(signature_t, data_t, key_t)) != 0)
    {
      ok = false;

      QByteArray buffer(64, 0);

      gpg_strerror_r(err, buffer.data(),
		     static_cast<size_t> (buffer.length()));
      spoton_misc::logError
	(QString("spoton_crypt::isValidSignature(): "
		 "gcry_pk_verify() "
		 "failure (%1).").arg(buffer.constData()));
    }

 done_label:
  free(hash_p);
  gcry_mpi_release(hash_t);
  gcry_sexp_release(data_t);
  gcry_sexp_release(key_t);
  gcry_sexp_release(signature_t);
  return ok;
}

bool spoton_crypt::memcmp(const QByteArray &bytes1, const QByteArray &bytes2)
{
  QByteArray a;
  QByteArray b;
  int length = qMax(bytes1.length(), bytes2.length());
  unsigned long int rc = 0;

  a = bytes1.leftJustified(length, 0);
  b = bytes2.leftJustified(length, 0);

  /*
  ** x ^ y returns zero if x and y are identical.
  */

  for(int i = 0; i < length; i++)
    {
      std::bitset<CHAR_BIT * sizeof(unsigned long int)> ba1
	(static_cast<unsigned long int> (a.at(i)));
      std::bitset<CHAR_BIT * sizeof(unsigned long int)> ba2
	(static_cast<unsigned long int> (b.at(i)));

      for(size_t j = 0; j < ba1.size(); j++)
	rc |= static_cast<unsigned long int> (ba1[j]) ^
	  static_cast<unsigned long int> (ba2[j]);
    }

  return rc == 0; /*
		  ** Return true if bytes1 and bytes2 are identical or
		  ** if both bytes1 and bytes2 are empty.
		  ** Perhaps this final comparison can be enhanced.
		  */
}

bool spoton_crypt::passphraseSet(void)
{
  QSettings settings;

  return settings.contains("gui/saltedPassphraseHash") &&
    !settings.value("gui/saltedPassphraseHash",
		    "").toByteArray().isEmpty();
}

bool spoton_crypt::setInitializationVector(QByteArray &bytes,
					   const int algorithm,
					   gcry_cipher_hd_t cipherHandle)
{
  if(algorithm == 0)
    {
      spoton_misc::logError("spoton_crypt::setInitializationVector(): "
			    "algorithm is zero.");
      return false;
    }

  if(!cipherHandle)
    {
      spoton_misc::logError("spoton_crypt::setInitializationVector(): "
			    "cipherHandle is zero.");
      return false;
    }

  bool ok = true;
  size_t ivLength = 0;

  if((ivLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
    {
      ok = false;
      spoton_misc::logError
	(QString("spoton_crypt::setInitializationVector(): "
		 "gcry_cipher_get_algo_blklen() "
		 "failure for cipher algorithm %1.").arg(algorithm));
    }
  else
    {
      char *iv = static_cast<char *> (gcry_calloc(ivLength, sizeof(char)));

      if(Q_LIKELY(iv))
	{
	  if(bytes.isEmpty())
	    {
	      gcry_fast_random_poll();
	      gcry_create_nonce(iv, ivLength);
	      bytes.append(iv, static_cast<int> (ivLength));
	    }
	  else
	    {
	      memcpy
		(iv,
		 bytes.constData(),
		 qMin(ivLength, static_cast<size_t> (bytes.length())));
	      bytes.remove(0, static_cast<int> (ivLength));
	    }

	  gcry_cipher_reset(cipherHandle);

	  gcry_error_t err = 0;

	  if((err = gcry_cipher_setiv(cipherHandle,
				      iv,
				      ivLength)) != 0)
	    {
	      ok = false;

	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(),
			     static_cast<size_t> (buffer.length()));
	      spoton_misc::logError
		(QString("spoton_crypt::setInitializationVector(): "
			 "gcry_cipher_setiv() failure (%1).").
		 arg(buffer.constData()));
	    }

	  gcry_free(iv);
	}
      else
	{
	  ok = false;
	  spoton_misc::logError("spoton_crypt::setInitializationVector(): "
				"gcry_calloc() failed.");
	}
    }

  return ok;
}

qint64 spoton_crypt::publicKeyCount(void)
{
  QString connectionName("");
  qint64 count = 0;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) "
		      "FROM idiotes WHERE id_hash = ?");
	query.bindValue(0, keyedHash(m_id.toLatin1(), &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count;
}

size_t spoton_crypt::cipherKeyLength(const QByteArray &cipherType)
{
  int cipherAlgorithm = (cipherType == "threefish") ? -1 :
    gcry_cipher_map_name(cipherType.constData());
  size_t keyLength = 0;

  if(cipherAlgorithm > 0)
    {
      if((keyLength = gcry_cipher_get_algo_keylen(cipherAlgorithm)) == 0)
	spoton_misc::logError("spoton_crypt::cipherKeyLength(): "
			      "gcry_cipher_get_algo_keylen() "
			      "failed.");
    }
  else if(cipherType == "threefish")
    keyLength = 32;
  else
    spoton_misc::logError("spoton_crypt::cipherKeyLength(): "
			  "gcry_cipher_map_name() failure or unsupported "
			  "cipher.");

  return keyLength;
}

size_t spoton_crypt::ivLength(const QString &cipherType)
{
  return gcry_cipher_get_algo_blklen
    (gcry_cipher_map_name(cipherType.toLatin1().constData()));
}

void spoton_crypt::generateCertificate(RSA *rsa,
				       QByteArray &certificate,
				       const QHostAddress &address,
				       const long int days,
				       QString &error)
{
  BIO *memory = 0;
  BUF_MEM *bptr;
  EVP_PKEY *pk = 0;
  QString addressString(address.toString().trimmed());
  X509 *x509 = 0;
  X509_NAME *name = 0;
  X509_NAME *subject = 0;
  X509_NAME_ENTRY *commonNameEntry = 0;
  char *buffer = 0;
  int length = 0;
  static const unsigned char *organization =
    reinterpret_cast<const unsigned char *>
    ("Spot-On Origami Self-Signed Certificate");
  unsigned char *commonName = 0;

  if(!error.isEmpty())
    goto done_label;

  if(!rsa)
    {
      error = QObject::tr("rsa container is zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "rsa container is zero.");
      goto done_label;
    }

  if(!(pk = EVP_PKEY_new()))
    {
      error = QObject::tr("EVP_PKEY_new() failure");
      spoton_misc::logError
	("spoton_crypt::generateCertificate(): "
	 "EVP_PKEY_new() failure.");
      goto done_label;
    }

  if(!(x509 = X509_new()))
    {
      error = QObject::tr("X509_new() failure");
      spoton_misc::logError
	("spoton_crypt::generateCertificate(): "
	 "X509_new() failure.");
      goto done_label;
    }

  if(EVP_PKEY_assign_RSA(pk, rsa) == 0)
    {
      error = QObject::tr("EVP_PKEY_assign_RSA() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "EVP_PKEY_assign_RSA() failure.");
      goto done_label;
    }

  /*
  ** Set some attributes.
  */

  if(X509_set_version(x509, 3) == 0)
    {
      error = QObject::tr("X509_set_version() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_set_version() failure.");
      goto done_label;
    }

  if(X509_gmtime_adj(X509_get_notBefore(x509), 0) == 0)
    {
      error = QObject::tr("X509_gmtime_adj() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_gmtime_adj() failure.");
      goto done_label;
    }

  if(X509_gmtime_adj(X509_get_notAfter(x509), days) == 0)
    {
      error = QObject::tr("X509_gmtime_adj() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_gmtime_adj() failure.");
      goto done_label;
    }

  if(addressString.isEmpty() || address == QHostAddress::LocalHost)
    addressString = "Spot-On-" + weakRandomBytes(10).toHex();

  if(std::numeric_limits<int>::max() - addressString.toLatin1().length() < 1)
    commonName = 0;
  else
    commonName = static_cast<unsigned char *>
      (calloc(static_cast<size_t> (addressString.toLatin1().length() + 1),
	      sizeof(unsigned char)));

  if(!commonName)
    {
      error = QObject::tr("calloc() returned zero or irregular address");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "calloc() failure or irregular address.");
      goto done_label;
    }

  length = addressString.toLatin1().length();
  memcpy(commonName,
	 addressString.toLatin1().constData(),
	 static_cast<size_t> (length));
  commonNameEntry = X509_NAME_ENTRY_create_by_NID
    (0,
     NID_commonName, V_ASN1_PRINTABLESTRING,
     commonName, length);

  if(!commonNameEntry)
    {
      error = QObject::tr("X509_NAME_ENTRY_create_by_NID() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_NAME_ENTRY_create_by_NID() failure.");
      goto done_label;
    }

  subject = X509_NAME_new();

  if(!subject)
    {
      error = QObject::tr("X509_NAME_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_NAME_new() failure.");
      goto done_label;
    }

  if(X509_NAME_add_entry_by_txt(subject,
				"O",
				MBSTRING_ASC,
				organization,
				-1,
				-1,
				0) != 1)
    {
      error = QObject::tr("X509_NAME_add_entry_by_txt() failure");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_NAME_add_entry_by_txt() failure.");
      goto done_label;
    }

  if(X509_NAME_add_entry(subject, commonNameEntry, -1, 0) != 1)
    {
      error = QObject::tr("X509_NAME_add_entry() failure");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_NAME_add_entry() failure.");
      goto done_label;
    }

  if(X509_set_subject_name(x509, subject) != 1)
    {
      error = QObject::tr("X509_set_subject_name() failed");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_set_subject_name() failure.");
      goto done_label;
    }

  if((name = X509_get_subject_name(x509)) == 0)
    {
      error = QObject::tr("X509_get_subject_name() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_get_subject_name() failure.");
      goto done_label;
    }

  if(X509_set_issuer_name(x509, name) == 0)
    {
      error = QObject::tr("X509_set_issuer_name() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_set_issuer_name() failure.");
      goto done_label;
    }

  if(X509_set_pubkey(x509, pk) == 0)
    {
      error = QObject::tr("X509_set_pubkey() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_set_pubkey() failure.");
      goto done_label;
    }

  if(X509_sign(x509, pk, EVP_sha512()) == 0)
    {
      error = QObject::tr("X509_sign() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_sign() failure.");
      goto done_label;
    }

  /*
  ** Write the certificate to memory.
  */

  if(!(memory = BIO_new(BIO_s_mem())))
    {
      error = QObject::tr("BIO_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "BIO_new() failure.");
      goto done_label;
    }

  if(PEM_write_bio_X509(memory, x509) == 0)
    {
      error = QObject::tr("PEM_write_bio_X509() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "PEM_write_bio_X509() failure.");
      goto done_label;
    }

  BIO_get_mem_ptr(memory, &bptr);

  if(bptr->length + 1 <= 0 ||
     std::numeric_limits<size_t>::max() - bptr->length < 1 ||
     !(buffer = static_cast<char *> (calloc(bptr->length + 1,
					    sizeof(char)))))
    {
      error = QObject::tr("calloc() failure or bptr->length + 1 is "
			  "irregular");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "calloc() failure or bptr->length + 1 is "
			    "irregular.");
      goto done_label;
    }

  memcpy(buffer, bptr->data, bptr->length);
  buffer[bptr->length] = 0;
  certificate = buffer;

 done_label:
  BIO_free(memory);

  if(!error.isEmpty())
    {
      certificate.replace
	(0, certificate.length(), QByteArray(certificate.length(), 0));
      certificate.clear();
    }

  if(rsa)
    RSA_up_ref(rsa); // Reference counter.

  EVP_PKEY_free(pk);
  X509_NAME_ENTRY_free(commonNameEntry);
  X509_NAME_free(subject);
  X509_free(x509);
  free(buffer);
  free(commonName);
}

void spoton_crypt::generateSslKeys(const int rsaKeySize,
				   QByteArray &certificate,
				   QByteArray &privateKey,
				   QByteArray &publicKey,
				   const QHostAddress &address,
				   const long int days,
				   QString &error)
{
  BIGNUM *f4 = 0;
  BIO *privateMemory = 0;
  BIO *publicMemory = 0;
  BUF_MEM *bptr;
  RSA *rsa = 0;
  char *privateBuffer = 0;
  char *publicBuffer = 0;

  if(rsaKeySize <= 0)
    {
      error = QObject::tr("rsaKeySize is less than or equal to zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "rsaKeySize is less than or equal to zero.");
      goto done_label;
    }
  else if(rsaKeySize > 4096)
    {
      error = QObject::tr("rsaKeySize is greater than 4096");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "rsaKeySize is greater than 4096.");
      goto done_label;
    }

  if(!(f4 = BN_new()))
    {
      error = QObject::tr("BN_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "BN_new() failure.");
      goto done_label;
    }

  if(BN_set_word(f4, RSA_F4) != 1)
    {
      error = QObject::tr("BN_set_word() failure");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "BN_set_word() failure.");
      goto done_label;
    }

  if(!(rsa = RSA_new()))
    {
      error = QObject::tr("RSA_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "RSA_new() failure.");
      goto done_label;
    }

  if(RSA_generate_key_ex(rsa, rsaKeySize, f4, 0) == -1)
    {
      error = QObject::tr("RSA_generate_key_ex() returned negative one");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "RSA_generate_key_ex() failure.");
      goto done_label;
    }

  if(!(privateMemory = BIO_new(BIO_s_mem())))
    {
      error = QObject::tr("BIO_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "BIO_new() failure.");
      goto done_label;
    }

  if(!(publicMemory = BIO_new(BIO_s_mem())))
    {
      error = QObject::tr("BIO_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "BIO_new() failure.");
      goto done_label;
    }

  if(PEM_write_bio_RSAPrivateKey(privateMemory, rsa, 0, 0, 0, 0, 0) == 0)
    {
      error = QObject::tr("PEM_write_bio_RSAPrivateKey() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "PEM_write_bio_RSAPrivateKey() failure.");
      goto done_label;
    }

  if(PEM_write_bio_RSAPublicKey(publicMemory, rsa) == 0)
    {
      error = QObject::tr("PEM_write_bio_RSAPublicKey() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "PEM_write_bio_RSAPublicKey() failure.");
      goto done_label;
    }

  BIO_get_mem_ptr(privateMemory, &bptr);

  if(bptr->length + 1 <= 0 ||
     std::numeric_limits<size_t>::max() - bptr->length < 1 ||
     !(privateBuffer = static_cast<char *> (calloc(bptr->length + 1,
						   sizeof(char)))))
    {
      error = QObject::tr("calloc() failure or bptr->length + 1 is "
			  "irregular");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "calloc() failure or bptr->length + 1 is "
			    "irregular.");
      goto done_label;
    }

  memcpy(privateBuffer, bptr->data, bptr->length);
  privateBuffer[bptr->length] = 0;
  privateKey = privateBuffer;
  BIO_get_mem_ptr(publicMemory, &bptr);

  if(bptr->length + 1 <= 0 ||
     std::numeric_limits<size_t>::max() - bptr->length < 1 ||
     !(publicBuffer = static_cast<char *> (calloc(bptr->length + 1,
						  sizeof(char)))))
    {
      error = QObject::tr("calloc() failure or bptr->length + 1 is "
			  "irregular");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "calloc() failure or bptr->length + 1 is "
			    "irregular.");
      goto done_label;
    }

  memcpy(publicBuffer, bptr->data, bptr->length);
  publicBuffer[bptr->length] = 0;
  publicKey = publicBuffer;

  if(days > 0)
    generateCertificate(rsa, certificate, address, days, error);

 done_label:

  if(!error.isEmpty())
    {
      certificate.replace
	(0, certificate.length(), QByteArray(certificate.length(), 0));
      certificate.clear();
      privateKey.replace
	(0, privateKey.length(), QByteArray(privateKey.length(), 0));
      privateKey.clear();
      publicKey.replace
	(0, publicKey.length(), QByteArray(publicKey.length(), 0));
      publicKey.clear();
    }

  BIO_free(privateMemory);
  BIO_free(publicMemory);
  BN_free(f4);
  RSA_free(rsa);
  free(privateBuffer);
  free(publicBuffer);
}

void spoton_crypt::init(const QString &cipherType,
			const QString &hashType,
			const QByteArray &passphrase,
			const QByteArray &symmetricKey,
			const QByteArray &hashKey,
			const int saltLength,
			const unsigned long int iterationCount,
			const QString &id,
			const QString &modeOfOperation)
{
  Q_UNUSED(passphrase);
  m_cipherAlgorithm = (cipherType == "threefish") ? -1 :
    gcry_cipher_map_name(cipherType.toLatin1().constData());
  m_cipherHandle = 0;
  m_cipherType = cipherType;
  m_hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  m_hashKey = 0;
  m_hashKeyLength = 0;
  m_hashType = hashType;
  m_id = id;
  m_isMcEliece.fetchAndStoreOrdered(0);
  m_iterationCount = iterationCount;
#ifdef SPOTON_MCELIECE_ENABLED
  m_mceliece = 0;
#endif
  m_privateKey = 0;
  m_privateKeyLength = 0;
  m_saltLength = saltLength;
  m_symmetricKey = 0;
  m_threefish = 0;

  if(m_cipherAlgorithm > 0)
    m_symmetricKeyLength = gcry_cipher_get_algo_keylen(m_cipherAlgorithm);
  else if(m_cipherType == "threefish")
    m_symmetricKeyLength = cipherKeyLength(m_cipherType.toLatin1());
  else
    m_symmetricKeyLength = 0;

  setHashKey(hashKey);

  if(m_symmetricKeyLength > 0)
    m_symmetricKey = static_cast<char *>
      (gcry_calloc_secure(m_symmetricKeyLength, sizeof(char)));
  else
    spoton_misc::logError("spoton_crypt::init(): "
			  "gcry_cipher_get_algo_keylen() failed.");

  if(m_symmetricKey && m_symmetricKeyLength > 0)
    {
      memcpy(m_symmetricKey,
	     symmetricKey.constData(),
	     qMin(m_symmetricKeyLength,
		  static_cast<size_t> (symmetricKey.length())));

      gcry_error_t err = 0;

      if(m_cipherAlgorithm > 0)
	{
	  if(modeOfOperation.toLower() == "cbc")
	    {
	      unsigned int flags = GCRY_CIPHER_SECURE;

	      if(s_cbc_cts_enabled)
		flags |= GCRY_CIPHER_CBC_CTS;

	      err = gcry_cipher_open(&m_cipherHandle, m_cipherAlgorithm,
				     GCRY_CIPHER_MODE_CBC,
				     flags);
	    }
#if GCRYPT_VERSION_NUMBER >= 0x010600
	  else if(modeOfOperation.toLower() == "gcm")
	    err = gcry_cipher_open(&m_cipherHandle, m_cipherAlgorithm,
				   GCRY_CIPHER_MODE_GCM,
				   GCRY_CIPHER_SECURE);
#endif
	  else
	    spoton_misc::logError
	      ("spoton_crypt::init(): mode of operation is not supported.");

	  if(err != 0 || !m_cipherHandle)
	    {
	      if(err != 0)
		{
		  QByteArray buffer(64, 0);

		  gpg_strerror_r(err, buffer.data(),
				 static_cast<size_t> (buffer.length()));
		  spoton_misc::logError
		    (QString("spoton_crypt::init(): "
			     "gcry_cipher_open() failure (%1).").
		     arg(buffer.constData()));
		}
	      else
		spoton_misc::logError("spoton_crypt::init(): "
				      "gcry_cipher_open() failure.");
	    }
	}
      else if(m_cipherType == "threefish")
	{
	  bool ok = true;

	  m_threefish = new spoton_threefish();
	  m_threefish->setKey(m_symmetricKey, m_symmetricKeyLength, &ok);

	  if(ok)
	    m_threefish->setTweak("76543210fedcba98", &ok);

	  if(!ok)
	    {
	      delete m_threefish;
	      m_threefish = 0;
	    }
	}
      else
	spoton_misc::logError("spoton_crypt::init(): "
			      "m_cipherAlgorithm is zero or unsupported "
			      "cipher.");

      if(err == 0)
	{
	  if(m_cipherHandle)
	    {
	      if((err = gcry_cipher_setkey(m_cipherHandle,
					   m_symmetricKey,
					   m_symmetricKeyLength)) != 0)
		{
		  QByteArray buffer(64, 0);

		  gpg_strerror_r(err, buffer.data(),
				 static_cast<size_t> (buffer.length()));
		  spoton_misc::logError
		    (QString("spoton_crypt::init(): "
			     "gcry_cipher_setkey() "
			     "failure (%1).").arg(buffer.constData()));
		}
	    }
	  else if(m_cipherType == "threefish")
	    {
	      if(!m_threefish)
		spoton_misc::logError("spoton_crypt::init(): "
				      "m_threefish is zero.");
	    }
	  else
	    spoton_misc::logError("spoton_crypt::init(): "
				  "m_cipherHandle is zero or unsupported "
				  "cipher.");
	}
    }
  else if(m_symmetricKeyLength > 0)
    {
      m_symmetricKeyLength = 0;
      spoton_misc::logError("spoton_crypt::init(): "
			    "gcry_calloc_secure() failed.");
    }
}

void spoton_crypt::init(const int secureMemorySize, const bool cbc_cts_enabled)
{
  if(!gcryctl_set_thread_cbs_set)
    {
      gcry_error_t err = 0;

#ifdef SPOTON_LINKED_WITH_LIBPTHREAD
      /*
      ** libgcrypt 1.6.x compatibility.
      */
#if !defined(GCRYPT_VERSION_NUMBER) || GCRYPT_VERSION_NUMBER < 0x010600
      err = gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread, 0);
#endif
#else
      err = gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_qt, 0);
#endif

      if(err == 0)
	gcryctl_set_thread_cbs_set = true;
      else
	std::cerr << "spoton_crypt::init(): gcry_control() "
		  << "failed while initializing threads. Proceeding."
		  << std::endl;
    }

  if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    {
      s_cbc_cts_enabled = cbc_cts_enabled;
      s_hasSecureMemory.fetchAndStoreOrdered(0);
      gcry_control(GCRYCTL_ENABLE_M_GUARD);

      if(!gcry_check_version(GCRYPT_VERSION))
	{
	  std::cerr << "spoton_crypt::init(): gcry_check_version() "
		    << "failure. Perhaps you should verify some "
		    << "settings."
		    << std::endl;
	  spoton_misc::logError
	    ("spoton_crypt::init(): gcry_check_version() "
	     "failure. Perhaps you should verify some "
	     "settings.");
	}

      if(secureMemorySize == 0)
	{
	  std::cerr << "spoton_crypt::init(): disabling secure memory."
		    << std::endl;
	  spoton_misc::logError
	    ("spoton_crypt::init(): disabling secure memory.");
	  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
      else
	{
	  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
#ifdef Q_OS_FREEBSD
	  gcry_control(GCRYCTL_INIT_SECMEM, qAbs(secureMemorySize), 0);
	  s_hasSecureMemory.fetchAndStoreOrdered(1);
#else
	  gcry_error_t err = 0;

	  if((err = gcry_control(GCRYCTL_INIT_SECMEM, qAbs(secureMemorySize),
				 0)) != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(),
			     static_cast<size_t> (buffer.length()));
	      spoton_misc::logError
		(QString("spoton_crypt::init(): initializing "
			 "secure memory failure (%1).").
		 arg(buffer.constData()));
	    }
	  else
	    s_hasSecureMemory.fetchAndStoreOrdered(1);
#endif

	  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
    }
  else
    spoton_misc::logError
      ("spoton_crypt::init(): libgcrypt is already initialized.");

  if(!ssl_library_initialized)
    {
      ssl_library_initialized = true;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      SSL_library_init(); // Always returns 1.
#else
#ifdef Q_OS_OPENBSD
      SSL_library_init(); // Always returns 1.
#else
      OPENSSL_init_ssl(0, NULL);
#endif
#endif
    }
}

void spoton_crypt::initializePrivateKeyContainer(bool *ok)
{
  QReadLocker locker1(&m_privateKeyMutex);

  if(m_privateKey || m_privateKeyLength > 0)
    {
      if(ok)
	*ok = true;

      return;
    }

  locker1.unlock();

  QByteArray keyData;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT private_key FROM idiotes WHERE id_hash = ?");
	query.bindValue(0, keyedHash(m_id.toLatin1(), &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    keyData = QByteArray::fromBase64
	      (query.value(0).toByteArray());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(keyData.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::initializePrivateKeyContainer(): "
	         "empty %1 private key.").arg(m_id));
      return;
    }

  {
    bool ok = true;

    keyData = this->decryptedAfterAuthenticated(keyData, &ok);

    if(!ok)
      keyData.clear();
  }

  if(keyData.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::initializePrivateKeyContainer(): "
	 "decryptedAfterAuthenticated() failure.");
      return;
    }

  if(keyData.contains("(private-key") ||
     keyData.startsWith("mceliece-") ||
     keyData.startsWith("ntru-private-key-"))
    {
      if(keyData.startsWith("mceliece-"))
	m_isMcEliece.fetchAndStoreOrdered(1);
    }
  else
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::initializePrivateKeyContainer(): "
	 "keyData does not contain private-key.");
      return;
    }

  QWriteLocker locker2(&m_privateKeyMutex);

  m_privateKeyLength = static_cast<size_t> (keyData.length());

  if(s_hasSecureMemory.fetchAndAddOrdered(0))
    {
      if(m_privateKeyLength == 0 ||
	 (m_privateKey =
	  static_cast<char *> (gcry_calloc_secure(m_privateKeyLength,
						  sizeof(char)))) == 0)
	{
	  if(ok)
	    *ok = false;

	  m_isMcEliece.fetchAndAddOrdered(0);
	  m_privateKeyLength = 0;
	  spoton_misc::logError
	    (QString("spoton_crypt::initializePrivateKeyContainer(): "
		     "gcry_calloc_secure() "
		     "failure or m_privateKeyLength is zero (%1).").
	     arg(m_id));
	  return;
	}
    }
  else
    {
      if(m_privateKeyLength == 0 ||
	 (m_privateKey = static_cast<char *> (calloc(m_privateKeyLength,
						     sizeof(char)))) == 0)
	{
	  if(ok)
	    *ok = false;

	  m_isMcEliece.fetchAndStoreOrdered(0);
	  m_privateKeyLength = 0;
	  spoton_misc::logError
	    (QString("spoton_crypt::initializePrivateKeyContainer(): calloc() "
		     "failure or m_privateKeyLength is zero (%1).").
	     arg(m_id));
	  return;
	}
    }

  memcpy(m_privateKey, keyData.constData(), m_privateKeyLength);
  locker2.unlock();
  keyData.replace(0, keyData.length(), QByteArray(keyData.length(), 0));
  keyData.clear();

  if(ok)
    *ok = true;
}

void spoton_crypt::memcmp_test(void)
{
  QByteArray a;
  QByteArray b;
  QElapsedTimer timer;

  for(int i = 0; i < 10; i++)
    {
      a = "This is a test.";
      b = "This is another test.";
      timer.restart();
      memcmp(a, b);
#if QT_VERSION >= 0x040806
      qDebug() << "memcmp_test():" << timer.nsecsElapsed();
#else
      qDebug() << "memcmp_test():" << timer.elapsed();
#endif
      a = "This is another test.";
      b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      timer.restart();
      memcmp(a, b);
#if QT_VERSION >= 0x040806
      qDebug() << "memcmp_test():" << timer.nsecsElapsed();
#else
      qDebug() << "memcmp_test():" << timer.elapsed();
#endif
    }
}

void spoton_crypt::purgeDatabases(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM idiotes");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_crypt::purgePrivatePublicKeys(void)
{
  m_isMcEliece.fetchAndStoreOrdered(0);

  QWriteLocker locker1(&m_privateKeyMutex);

  if(s_hasSecureMemory.fetchAndAddOrdered(0))
    gcry_free(m_privateKey);
  else
    free(m_privateKey);

  m_privateKey = 0;
  m_privateKeyLength = 0;
  locker1.unlock();

  QWriteLocker locker2(&m_publicKeyMutex);

  m_publicKey.clear();
  locker2.unlock();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM idiotes WHERE id_hash = ?");
	query.bindValue(0, keyedHash(m_id.toLatin1(), &ok).toBase64());
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_crypt::reencodePrivatePublicKeys(spoton_crypt *newCrypt,
					     spoton_crypt *oldCrypt,
					     const QString &id,
					     QString &error)
{
  if(!newCrypt)
    {
      error = QObject::tr("newCrypt is zero");
      spoton_misc::logError("spoton_crypt::reencodePrivatePublicKeys(): "
			    "newCrypt is zero.");
      return;
    }

  if(!oldCrypt)
    {
      error = QObject::tr("oldCrypt is zero");
      spoton_misc::logError("spoton_crypt::reencodePrivatePublicKeys(): "
			    "oldCrypt is zero.");
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT id, private_key, public_key FROM idiotes "
		      "WHERE id_hash = ?");
	query.bindValue
	  (0, oldCrypt->keyedHash(id.toLatin1(), &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    {
	      QByteArray id
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      QByteArray idHash;
	      QByteArray privateKey
		(QByteArray::fromBase64(query.value(1).toByteArray()));
	      QByteArray publicKey
		(QByteArray::fromBase64(query.value(2).toByteArray()));
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.exec("PRAGMA secure_delete = ON");
	      id = oldCrypt->decryptedAfterAuthenticated
		(id, &ok);

	      if(ok)
		{
		  privateKey = oldCrypt->decryptedAfterAuthenticated
		    (privateKey, &ok);

		  if(ok)
		    {
		      if(privateKey.contains("(private-key") ||
			 privateKey.startsWith("mceliece-") ||
			 privateKey.startsWith("ntru-private-key-"))
			{
			}
		      else
			ok = false;
		    }
		}

	      if(ok)
		{
		  publicKey = oldCrypt->decryptedAfterAuthenticated
		    (publicKey, &ok);

		  if(ok)
		    {
		      if(publicKey.contains("(public-key") ||
			 publicKey.startsWith("mceliece") ||
			 publicKey.startsWith("ntru-public-key-"))
			{
			}
		      else
			ok = false;
		    }
		}

	      if(ok)
		idHash = newCrypt->keyedHash(id, &ok);

	      if(ok)
		id = newCrypt->encryptedThenHashed(id, &ok);

	      if(ok)
		privateKey = newCrypt->encryptedThenHashed
		  (privateKey, &ok);

	      if(ok)
		publicKey = newCrypt->encryptedThenHashed
		  (publicKey, &ok);

	      if(ok)
		{
		  updateQuery.prepare("UPDATE idiotes SET "
				      "id = ?, "
				      "id_hash = ?, "
				      "private_key = ?, "
				      "public_key = ? "
				      "WHERE id = ?");
		  updateQuery.bindValue(0, id.toBase64());
		  updateQuery.bindValue(1, idHash.toBase64());
		  updateQuery.bindValue(2, privateKey.toBase64());
		  updateQuery.bindValue(3, publicKey.toBase64());
		  updateQuery.bindValue(4, query.value(0));
		}
	      else
		{
		  updateQuery.prepare("DELETE FROM idiotes "
				      "WHERE id = ?");
		  updateQuery.bindValue(0, query.value(0));
		}

	      if(!ok)
		{
		  error = QObject::tr("decryption or encryption failure, or "
				      "the keys are malformed");
		  spoton_misc::logError
		    ("spoton_crypt::reencodePrivatePublicKeys(): "
		     "decryption or encryption failure, or the keys "
		     "are malformed.");
		}

	      updateQuery.exec();
	      privateKey.replace
		(0, privateKey.length(), QByteArray(privateKey.length(), 0));
	      privateKey.clear();
	      publicKey.replace
		(0, publicKey.length(), QByteArray(publicKey.length(), 0));
	      publicKey.clear();
	    }

	if(error.isEmpty())
	  if(query.lastError().isValid())
	    {
	      error = query.lastError().text();
	      spoton_misc::logError
		(QString("spoton_crypt::reencodePrivatePublicKeys(): "
			 "database error (%1).").arg(error));
	    }
      }

    if(error.isEmpty())
      if(db.lastError().isValid())
	{
	  error = db.lastError().text();
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodePrivatePublicKeys(): "
		     "database error (%1).").arg(error));
	}

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_crypt::removeFlawedEntries(spoton_crypt *crypt)
{
  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT id FROM idiotes"))
	  while(query.next())
	    {
	      QByteArray data;
	      bool ok = true;

	      data = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(!ok)
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM idiotes WHERE id = ?");
		  deleteQuery.addBindValue(query.value(0).toByteArray());
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_crypt::setHashKey(const QByteArray &hashKey)
{
  QWriteLocker locker(&m_hashKeyMutex);

  gcry_free(m_hashKey);
  m_hashKey = 0;
  m_hashKeyLength = static_cast<size_t> (hashKey.length());

  if(m_hashKeyLength > 0 &&
     (m_hashKey =
      static_cast<char *> (gcry_calloc_secure(m_hashKeyLength,
					      sizeof(char)))) != 0)
    memcpy(m_hashKey,
	   hashKey.constData(),
	   qMin(m_hashKeyLength,
		static_cast<size_t> (hashKey.length())));
  else
    m_hashKeyLength = 0;
}

void spoton_crypt::setSslCiphers(const QList<QSslCipher> &ciphers,
				 const QString &sslControlString,
				 QSslConfiguration &configuration)
{
  QList<QSslCipher> preferred(defaultSslCiphers(sslControlString));

  for(int i = preferred.size() - 1; i >= 0; i--)
    if(!ciphers.contains(preferred.at(i)))
      preferred.removeAt(i);

  if(preferred.isEmpty())
    configuration.setCiphers(ciphers);
  else
    configuration.setCiphers(preferred);
}

void spoton_crypt::terminate(void)
{
  gcry_control(GCRYCTL_TERM_SECMEM);
}
