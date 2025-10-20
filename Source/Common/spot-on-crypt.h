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

#ifndef _spoton_crypt_h_
#define _spoton_crypt_h_

#ifdef SPOTON_LINKED_WITH_LIBNTRU
extern "C"
{
#include "../../libNTRU/src/ntru.h"
}
#endif

extern "C"
{
#include <errno.h>
#include <gcrypt.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#ifdef SPOTON_LINKED_WITH_LIBPTHREAD
#endif
}

#include <QAtomicInt>
#include <QByteArray>
#include <QFileInfo>
#include <QHostAddress>
#include <QMutex>
#include <QReadWriteLock>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QStringList>

#include "spot-on-fortuna.h"

#ifdef SPOTON_MCELIECE_ENABLED
class spoton_mceliece;
#endif
class spoton_threefish;

class spoton_crypt
{
 public:
  static QByteArray derivedSha1Key
    (const QByteArray &salt,
     const QString &passphrase,
     const int hashKeySize,
     const unsigned long int iterationCount);
  static QByteArray fingerprint(const QByteArray &publicKey);
  static QByteArray gpgInformation(const QByteArray &publicKey);
  static QByteArray hash(const QByteArray &algorithm,
			 const QByteArray &data,
			 bool *ok);
  static QByteArray identity(spoton_crypt *eCrypt, spoton_crypt *sCrypt);
  static QByteArray keyedHash(const QByteArray &data,
			      const QByteArray &key,
			      const QByteArray &hashType,
			      bool *ok);
  static QByteArray preferredHMAC(const QByteArray &data,
				  const QByteArray &key);
  static QByteArray preferredHash(const QByteArray &data);
  static QByteArray preferredHashAlgorithm(void);
  static QByteArray publicGPG(spoton_crypt *crypt);
  static QByteArray publicKeyEncrypt(const QByteArray &data,
				     const QByteArray &pk,
				     const QByteArray &startsWith,
				     bool *ok);
  static QByteArray saltedPassphraseHash(const QString &hashType,
					 const QString &passphrase,
					 const QByteArray &salt,
					 QString &error);
  static QByteArray sha1FileHash(const QString &fileName);
  static QByteArray sha1FileHash(const QString &fileName,
				 QAtomicInt &atomic);
  static QByteArray sha1Hash(const QByteArray &data, bool *ok);
  static QByteArray sha256Hash(const QByteArray &data, bool *ok);
  static QByteArray sha3_512FileHash(const QString &fileName);
  static QByteArray sha3_512FileHash(const QString &fileName,
				     QAtomicInt &atomic);
  static QByteArray sha512Hash(const QByteArray &data, bool *ok);
  static QByteArray shaXHash(const int algorithm,
			     const QByteArray &data,
			     bool *ok);
  static QByteArray shake256(const QByteArray &buffer,
			     const size_t length,
			     bool *ok);
  static QByteArray strongRandomBytes(const size_t size);
  static QByteArray veryStrongRandomBytes(const size_t size);
  static QByteArray weakRandomBytes(const size_t size);
  static QByteArray whirlpoolHash(const QByteArray &data, bool *ok);
  static QList<QSslCipher> defaultSslCiphers(const QString &sslControlString);
  static QPair<QByteArray, QByteArray> derivedKeys
    (const QString &cipherType,
     const QString &hashType,
     const unsigned long int iterationCount,
     const QString &passphrase,
     const QByteArray &salt,
     const bool singleIteration,
     QString &error);
  static QPair<QByteArray, QByteArray> derivedKeys
    (const QString &cipherType,
     const QString &hashType,
     const unsigned long int iterationCount,
     const QString &passphrase,
     const QByteArray &salt,
     const int hashKeySize,
     const bool singleIteration,
     QString &error);
  static QString publicKeyAlgorithm(const QByteArray &data);
  static QString publicKeySize(const QByteArray &data);
  static QString publicKeySizeMcEliece(const QByteArray &data);
  static QString publicKeySizeNTRU(const QByteArray &data);
  static QStringList buzzHashTypes(void);
  static QStringList cipherTypes(void);
  static QStringList congestionHashAlgorithms(void);
  static QStringList hashTypes(void);
  static bool exists(const QByteArray &publicKey, spoton_crypt *crypt);
  static bool hasShake(void);
  static bool isValidSignature(const QByteArray &data,
			       const QByteArray &publicKey,
			       const QByteArray &signature);
  static bool memcmp(const QByteArray &bytes1, const QByteArray &bytes);
  static bool passphraseSet(void);
  static int gpgFingerprintLength(void);
  static const char *preferredCipherAlgorithm(void);
  static const int SHA224_OUTPUT_SIZE_IN_BYTES = 28;
  static const int SHA384_OUTPUT_SIZE_IN_BYTES = 48;
  static const int XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES = 64; /*
							 ** The preferred
							 ** digest algorithm's
							 ** output size.
							 */
  static size_t cipherKeyLength(const QByteArray &cipherType);
  static size_t ivLength(const QString &cipherType);

  static void destroyFortuna(void)
  {
    QWriteLocker locker(&s_fortunaMutex);

    delete s_fortuna;
    s_fortuna = nullptr;
  }

  static void generateECCKeys(QByteArray &certificate,
			      QByteArray &privateKey,
			      QByteArray &publicKey,
			      QString &error,
			      const QHostAddress &address,
			      const int keySize,
			      const long int days);
  static void generateMcElieceKeys(const QString &keySize,
				   QByteArray &privateKey,
				   QByteArray &publicKey,
				   bool *ok);
  static void generateNTRUKeys(const QString &keySize,
			       QByteArray &privateKey,
			       QByteArray &publicKey,
			       bool *ok);
  static void generateSslKeys(const int keySize,
			      QByteArray &certificate,
			      QByteArray &privateKey,
			      QByteArray &publicKey,
			      const QHostAddress &address,
			      const long int days,
			      QString &error);
  static void init(const int secureMemorySize, const bool cbc_cts_enabled);
  static void memcmp_test(void);

  static void memset_s(void *s, int c, size_t n)
  {
    if(!n || !s)
      return;

    volatile auto v = static_cast<unsigned char *> (s);

    while(n--)
      *v++ = static_cast<unsigned char> (c);
  }

  static void memzero(QByteArray &bytes);
  static void memzero(QString &str);

  static void prepareFortuna
    (const QFileInfo &fileInfo,
     const QString &ipAddress,
     const bool tls,
     const int interval,
     const quint16 port)
  {
    QWriteLocker locker(&s_fortunaMutex);

    if(!s_fortuna)
      s_fortuna = new fortunate_q(nullptr);

    s_fortuna->set_file_peer(fileInfo.absoluteFilePath());
    s_fortuna->set_send_byte(0, interval);
    s_fortuna->set_tcp_peer(ipAddress, tls, port);
  }

  static void purgeDatabases(void);
  static void reencodePrivatePublicKeys
    (spoton_crypt *newCrypt,
     spoton_crypt *oldCrypt,
     const QString &id,
     QString &error);
  static void removeFlawedEntries(spoton_crypt *crypt);
  static void setGcrySexpBuildHashAlgorithm(const QByteArray &algorithm);

  static void setPreferredHashAlgorithm(const char *algorithm)
  {
    if(algorithm)
      s_preferredHashAlgorithm = algorithm;

    if(!hashTypes().contains(s_preferredHashAlgorithm))
      s_preferredHashAlgorithm = "sha512";
  }

  static void setSslCiphers(const QList<QSslCipher> &ciphers,
			    const QString &sslControlString,
			    QSslConfiguration &configuration);
  static void terminate(void);
  spoton_crypt(const QByteArray &privateKey,
	       const QByteArray &publicKey);
  spoton_crypt(const QString &cipherType,
	       const QString &hashType,
	       const QByteArray &passphrase,
	       const QByteArray &symmetricKey,
	       const QByteArray &hashKey,
	       const int saltLength,
	       const unsigned long int iterationCount,
	       const QString &id);
  spoton_crypt(const QString &cipherType,
	       const QString &hashType,
	       const QByteArray &passphrase,
	       const QByteArray &symmetricKey,
	       const QByteArray &hashKey,
	       const int saltLength,
	       const unsigned long int iterationCount,
	       const QString &id,
	       const QString &modeOfOperation);
  spoton_crypt(const QString &cipherType,
	       const QString &hashType,
	       const QByteArray &passphrase,
	       const QByteArray &symmetricKey,
	       const int saltLength,
	       const unsigned long int iterationCount,
	       const QString &id);
  ~spoton_crypt();
  QByteArray decrypted(const QByteArray &data, bool *ok);
  QByteArray decryptedAfterAuthenticated(const QByteArray &data, bool *ok);
  QByteArray digitalSignature(const QByteArray &data, bool *ok);
  QByteArray encrypted(const QByteArray &data, bool *ok);
  QByteArray encryptedThenHashed(const QByteArray &data, bool *ok);
  QByteArray hashKey(void);
  QByteArray keyedHash(const QByteArray &data, bool *ok);
  QByteArray publicKey(bool *ok);
  QByteArray publicKeyDecrypt(const QByteArray &data, bool *ok);
  QByteArray publicKeyHash(bool *ok);
  QByteArray symmetricKey(void);
  QPair<QByteArray, QByteArray> generatePrivatePublicKeys
    (const QString &keySize,
     const QString &keyType,
     QString &error,
     const bool save_keys = true);
  QString cipherType(void) const;
  QString publicKeyAlgorithm(void);
  QString publicKeySize(void);
  QString publicKeySizeMcEliece(void);
  QString publicKeySizeNTRU(void);
  bool isAuthenticated(void);
  qint64 publicKeyCount(void);
  void purgePrivatePublicKeys(void);

 private:
  QAtomicInt m_isMcEliece;
  QByteArray m_publicKey;
  QMutex m_cipherMutex;
  QReadWriteLock m_hashKeyMutex;
  QReadWriteLock m_privateKeyMutex;
  QReadWriteLock m_publicKeyMutex;
  QReadWriteLock m_symmetricKeyMutex;
  QString m_cipherType;
  QString m_hashType;
  QString m_id;
  char *m_hashKey; // Stored in secure memory.
  char *m_privateKey; // Stored in secure memory.
  char *m_symmetricKey; // Stored in secure memory.
  gcry_cipher_hd_t m_cipherHandle;
  int m_cipherAlgorithm;
  int m_hashAlgorithm;
  int m_saltLength;
  size_t m_hashKeyLength;
  size_t m_privateKeyLength;
  size_t m_symmetricKeyLength;
#ifdef SPOTON_MCELIECE_ENABLED
  spoton_mceliece *m_mceliece;
#endif
  spoton_threefish *m_threefish;
  static QAtomicInt s_hasSecureMemory;
  static QAtomicInteger<quint64> s_openSSLIdentifier;
  static QByteArray s_preferredHashAlgorithm;
  static QPointer<fortunate_q> s_fortuna;
  static QReadWriteLock s_fortunaMutex;
  static bool s_cbc_cts_enabled;
  unsigned long int m_iterationCount;
  QByteArray publicKeyDecryptMcEliece(const QByteArray &data, bool *ok);
  QByteArray publicKeyDecryptNTRU(const QByteArray &data, bool *ok);
  void freeHashKey(void);
  void freePrivateKey(void);
  void freeSymmetricKey(void);
  void init(const QString &cipherType,
	    const QString &hashType,
	    const QByteArray &passphrase,
	    const QByteArray &symmetricKey,
	    const QByteArray &hashKey,
	    const int saltLength,
	    const unsigned long int iterationCount,
	    const QString &id,
	    const QString &modeOfOperation);
  void initializePrivateKeyContainer(bool *ok);
  void setHashKey(const QByteArray &hashKey);
  static QByteArray publicKeyEncryptMcEliece(const QByteArray &data,
					     const QByteArray &publicKey,
					     bool *ok);
  static QByteArray publicKeyEncryptNTRU(const QByteArray &data,
					 const QByteArray &publicKey,
					 bool *ok);
  static QByteArray randomBytes(const size_t size,
				const enum gcry_random_level level);
  static bool setInitializationVector(QByteArray &iv,
				      const int algorithm,
				      gcry_cipher_hd_t cipherHandle);
  static void generateCertificate(const int keySize,
				  void *key,
				  QByteArray &certificate,
				  const QHostAddress &address,
				  const long int days,
				  QString &error);
};

#endif
