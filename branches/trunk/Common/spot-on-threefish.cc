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
#include <QtCore/qmath.h>

#include "spot-on-crypt.h"
#include "spot-on-misc.h"
#include "spot-on-threefish.h"

extern "C"
{
#include <gcrypt.h>
}

/*
** Threefish 256-bit only!
*/

static const size_t Nr = 72;
static const size_t Nw = 4;
static const uint8_t Pi_4[4] = {0, 3, 2, 1};
static const uint8_t RPi_4[4] = {0, 3, 2, 1};
static const uint8_t R_4[8][2] = {{14, 16},
				  {52, 57},
				  {23, 40},
				  {5, 37},
				  {25, 33},
				  {46, 12},
				  {58, 22},
				  {32, 32}};
static void bytesToWords(uint64_t *W,
			 const char *bytes,
			 const size_t bytes_size);
static void threefish_decrypt(char *D,
			      const char *K,
			      const char *T,
			      const char *C,
			      const size_t C_size,
			      const size_t block_size,
			      bool *ok);
static void threefish_decrypt_implementation(char *D,
					     const char *K,
					     const char *T,
					     const char *C,
					     const size_t C_size,
					     const size_t block_size,
					     bool *ok);
static void threefish_encrypt(char *E,
			      const char *K,
			      const char *T,
			      const char *P,
			      const size_t P_size,
			      const size_t block_size,
			      bool *ok);
static void threefish_encrypt_implementation(char *E,
					     const char *K,
					     const char *T,
					     const char *P,
					     const size_t P_size,
					     const size_t block_size,
					     bool *ok);
static void wordsToBytes(char *B,
			 const uint64_t *words,
			 const size_t words_size);

static void bytesToWords(uint64_t *W,
			 const char *bytes,
			 const size_t bytes_size)
{
  if(Q_UNLIKELY(!W || !bytes || bytes_size == 0))
    return;

  char b[8];

  for(size_t i = 0; i < bytes_size / 8; i++)
    {
      b[0] = bytes[i * 8];
      b[1] = bytes[i * 8 + 1];
      b[2] = bytes[i * 8 + 2];
      b[3] = bytes[i * 8 + 3];
      b[4] = bytes[i * 8 + 4];
      b[5] = bytes[i * 8 + 5];
      b[6] = bytes[i * 8 + 6];
      b[7] = bytes[i * 8 + 7];
      W[i] = static_cast<uint64_t> (b[0] & 0xff) |
	(static_cast<uint64_t> (b[1] & 0xff) << 8) |
	(static_cast<uint64_t> (b[2] & 0xff) << 16) |
	(static_cast<uint64_t> (b[3] & 0xff) << 24) |
	(static_cast<uint64_t> (b[4] & 0xff) << 32) |
	(static_cast<uint64_t> (b[5] & 0xff) << 40) |
	(static_cast<uint64_t> (b[6] & 0xff) << 48) |
	(static_cast<uint64_t> (b[7] & 0xff) << 56);
    }
}

static void mix(const uint64_t x0,
		const uint64_t x1,
		const size_t d,
		const size_t i,
		uint64_t *y0,
		uint64_t *y1,
		const size_t block_size)
{
  Q_UNUSED(block_size);

  if(Q_UNLIKELY(!y0 || !y1))
    return;

  /*
  ** Section 3.3.1.
  */

  auto const r = static_cast<uint64_t> (R_4[d % 8][i]);

  *y0 = x0 + x1;

  /*
  ** Please see https://en.wikipedia.org/wiki/Circular_shift.
  */

  *y1 = ((x1 << r) | (x1 >> (64 - r))) ^ *y0;
}

static void mix_inverse(const uint64_t y0,
			const uint64_t y1,
			const size_t d,
			const size_t i,
			uint64_t *x0,
			uint64_t *x1,
			const size_t block_size)
{
  Q_UNUSED(block_size);

  if(Q_UNLIKELY(!x0 || !x1))
    return;

  /*
  ** Section 3.3.1.
  */

  auto const r = static_cast<uint64_t> (R_4[d % 8][i]);

  /*
  ** Please see https://en.wikipedia.org/wiki/Circular_shift.
  */

  *x1 = ((y1 ^ y0) >> r) | ((y1 ^ y0) << (64 - r));
  *x0 = y0 - *x1;
}

static void threefish_decrypt(char *D,
			      const char *K,
			      const char *T,
			      const char *C,
			      const size_t C_size,
			      const size_t block_size,
			      bool *ok)
{
  if(Q_UNLIKELY(!C || C_size == 0 || !D || !K || !T || block_size == 0))
    {
      if(ok)
	*ok = false;

      return;
    }

  threefish_decrypt_implementation(D, K, T, C, C_size, block_size, ok);
}

static void threefish_decrypt_implementation(char *D,
					     const char *K,
					     const char *T,
					     const char *C,
					     const size_t C_size,
					     const size_t block_size,
					     bool *ok)
{
  if(Q_UNLIKELY(!C || C_size == 0 || !D || !K || !T || block_size == 0))
    {
      if(ok)
	*ok = false;

      return;
    }

  /*
  ** The inverse of section 3.3.
  */

  auto error = false;
  auto f = new (std::nothrow) uint64_t[Nw];
  auto k = new (std::nothrow) uint64_t[Nw + 1];
  auto s = new (std::nothrow) uint64_t*[Nr / 4 + 1];
  auto v = new (std::nothrow) uint64_t[Nw];
  const uint64_t C240 = 0x1bd11bdaa9fc1a22;
  uint64_t kNw = C240; // Section 3.3.2.
  uint64_t t[3];
  uint64_t x0 = 0;
  uint64_t x1 = 0;

  if(Q_UNLIKELY(!f || !k || !s || !v))
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  for(size_t i = 0; i < Nr / 4 + 1; i++)
    {
      s[i] = new (std::nothrow) uint64_t[Nw];

      if(Q_UNLIKELY(!s[i]))
	error = true; // Do not break.
      else
	memset(s[i], 0, sizeof(*s[i]) * static_cast<size_t> (Nw));
    }

  if(Q_UNLIKELY(error))
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  bytesToWords(k, K, C_size);
  bytesToWords(t, T, 16);
  bytesToWords(v, C, C_size);

  /*
  ** Section 3.3.2.
  */

  kNw ^= k[0];
  kNw ^= k[1];
  kNw ^= k[2];
  kNw ^= k[3];
  k[Nw] = kNw;
  t[2] = t[0] ^ t[1];

  /*
  ** Prepare the key schedule, section 3.3.2.
  */

  for(size_t d = 0; d < Nr / 4 + 1; d++)
    for(size_t i = 0; i < Nw; i++)
      {
	s[d][i] = k[(d + i) % (Nw + 1)];

	if(i == Nw - 1)
	  s[d][i] += d;
	else if(i == Nw - 2)
	  s[d][i] += t[(d + 1) % 3];
	else if(i == Nw - 3)
	  s[d][i] += t[d % 3];
      }

  v[0] -= s[Nr / 4][0];
  v[1] -= s[Nr / 4][1];
  v[2] -= s[Nr / 4][2];
  v[3] -= s[Nr / 4][3];

  for(size_t d = Nr - 1;; d--)
    {
      f[0] = v[RPi_4[0]];
      f[1] = v[RPi_4[1]];
      f[2] = v[RPi_4[2]];
      f[3] = v[RPi_4[3]];
      mix_inverse(f[0], f[1], d, 0, &x0, &x1, block_size);
      v[0] = x0;
      v[1] = x1;
      mix_inverse(f[2], f[3], d, 1, &x0, &x1, block_size);
      v[2] = x0;
      v[3] = x1;
      memset(f, 0, sizeof(*f) * static_cast<size_t> (Nw));

      if(d % 4 == 0)
	{
	  v[0] -= s[d / 4][0];
	  v[1] -= s[d / 4][1];
	  v[2] -= s[d / 4][2];
	  v[3] -= s[d / 4][3];
	}

      if(d == 0)
	break;
    }

  wordsToBytes(D, v, Nw);

  if(ok)
    *ok = true;

 done_label:
  delete []f;

  if(Q_LIKELY(k))
    memset(k, 0, sizeof(*k) * static_cast<size_t> (Nw + 1));

  spoton_crypt::memset_s(t, 0, sizeof(t));

  if(Q_LIKELY(v))
    memset(v, 0, sizeof(*v) * static_cast<size_t> (Nw));

  delete []k;

  if(Q_LIKELY(s))
    for(size_t i = 0; i < Nr / 4 + 1; i++)
      {
	if(Q_LIKELY(s[i]))
	  memset(s[i], 0, sizeof(*s[i]) * static_cast<size_t> (Nw));

	delete []s[i];
      }

  delete []s;
  delete []v;
}

static void threefish_encrypt(char *E,
			      const char *K,
			      const char *T,
			      const char *P,
			      const size_t P_size,
			      const size_t block_size,
			      bool *ok)
{
  if(Q_UNLIKELY(!E || !K || !P || P_size == 0 || !T || block_size == 0))
    {
      if(ok)
	*ok = false;

      return;
    }

  threefish_encrypt_implementation(E, K, T, P, P_size, block_size, ok);
}

static void threefish_encrypt_implementation(char *E,
					     const char *K,
					     const char *T,
					     const char *P,
					     const size_t P_size,
					     const size_t block_size,
					     bool *ok)
{
  if(Q_UNLIKELY(!E || !K || !T || !P || P_size == 0 || block_size == 0))
    {
      if(ok)
	*ok = false;

      return;
    }

  /*
  ** Section 3.3.
  */

  auto error = false;
  auto f = new (std::nothrow) uint64_t[Nw];
  auto k = new (std::nothrow) uint64_t[Nw + 1];
  auto s = new (std::nothrow) uint64_t*[Nr / 4 + 1];
  auto v = new (std::nothrow) uint64_t[Nw];
  const uint64_t C240 = 0x1bd11bdaa9fc1a22;
  uint64_t kNw = C240; // Section 3.3.2.
  uint64_t t[3];
  uint64_t y0 = 0;
  uint64_t y1 = 0;

  if(Q_UNLIKELY(!f || !k || !s || !v))
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  for(size_t i = 0; i < Nr / 4 + 1; i++)
    {
      s[i] = new (std::nothrow) uint64_t[Nw];

      if(Q_UNLIKELY(!s[i]))
	error = true; // Do not break.
      else
	memset(s[i], 0, sizeof(*s[i]) * static_cast<size_t> (Nw));
    }

  if(Q_UNLIKELY(error))
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  bytesToWords(k, K, P_size);
  bytesToWords(t, T, 16);
  bytesToWords(v, P, P_size);

  /*
  ** Section 3.3.2.
  */

  kNw ^= k[0];
  kNw ^= k[1];
  kNw ^= k[2];
  kNw ^= k[3];
  k[Nw] = kNw;
  t[2] = t[0] ^ t[1];

  /*
  ** Prepare the key schedule, section 3.3.2.
  */

  for(size_t d = 0; d < Nr / 4 + 1; d++)
    for(size_t i = 0; i < Nw; i++)
      {
	s[d][i] = k[(d + i) % (Nw + 1)];

	if(i == Nw - 1)
	  s[d][i] += d;
	else if(i == Nw - 2)
	  s[d][i] += t[(d + 1) % 3];
	else if(i == Nw - 3)
	  s[d][i] += t[d % 3];
      }

  for(size_t d = 0; d < Nr; d++)
    {
      if(d % 4 == 0)
	{
	  v[0] += s[d / 4][0];
	  v[1] += s[d / 4][1];
	  v[2] += s[d / 4][2];
	  v[3] += s[d / 4][3];
	}

      mix(v[0], v[1], d, 0, &y0, &y1, block_size);
      f[0] = y0;
      f[1] = y1;
      mix(v[2], v[3], d, 1, &y0, &y1, block_size);
      f[2] = y0;
      f[3] = y1;
      v[0] = f[Pi_4[0]];
      v[1] = f[Pi_4[1]];
      v[2] = f[Pi_4[2]];
      v[3] = f[Pi_4[3]];
      memset(f, 0, sizeof(*f) * static_cast<size_t> (Nw));
    }

  v[0] += s[Nr / 4][0];
  v[1] += s[Nr / 4][1];
  v[2] += s[Nr / 4][2];
  v[3] += s[Nr / 4][3];
  wordsToBytes(E, v, Nw);

  if(ok)
    *ok = true;

 done_label:
  delete []f;

  if(Q_LIKELY(k))
    memset(k, 0, sizeof(*k) * static_cast<size_t> (Nw + 1));

  spoton_crypt::memset_s(t, 0, sizeof(t));

  if(Q_LIKELY(v))
    memset(v, 0, sizeof(*v) * static_cast<size_t> (Nw));

  delete []k;

  if(Q_LIKELY(s))
    for(size_t i = 0; i < Nr / 4 + 1; i++)
      {
	if(Q_LIKELY(s[i]))
	  memset(s[i], 0, sizeof(*s[i]) * static_cast<size_t> (Nw));

	delete []s[i];
      }

  delete []s;
  delete []v;
}

static void wordsToBytes(char *B,
			 const uint64_t *words,
			 const size_t words_size)
{
  if(Q_UNLIKELY(!B || !words || words_size == 0))
    return;

  for(size_t i = 0; i < words_size; i++)
    {
      B[i * 8] = static_cast<char> (words[i] & 0xff);
      B[i * 8 + 1] = static_cast<char> ((words[i] >> 8) & 0xff);
      B[i * 8 + 2] = static_cast<char> ((words[i] >> 16) & 0xff);
      B[i * 8 + 3] = static_cast<char> ((words[i] >> 24) & 0xff);
      B[i * 8 + 4] = static_cast<char> ((words[i] >> 32) & 0xff);
      B[i * 8 + 5] = static_cast<char> ((words[i] >> 40) & 0xff);
      B[i * 8 + 6] = static_cast<char> ((words[i] >> 48) & 0xff);
      B[i * 8 + 7] = static_cast<char> ((words[i] >> 56) & 0xff);
    }
}

spoton_threefish::spoton_threefish(void)
{
  m_blockSize = 0;
  m_key = 0;
  m_keyLength = 0;
  m_tweak = 0;
  m_tweakLength = 0;
}

spoton_threefish::~spoton_threefish()
{
  delete []m_tweak;

  if(m_key)
    for(size_t i = 0; i < m_keyLength; i++)
      m_key[i] = 0;

  gcry_free(m_key);
}

QByteArray spoton_threefish::decrypted(const QByteArray &bytes, bool *ok) const
{
  QReadLocker locker(&m_locker);

  if(Q_UNLIKELY(!m_key || !m_tweak))
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  auto const &iv(bytes.mid(0, static_cast<int> (m_keyLength)));

  if(Q_UNLIKELY(iv.length() != static_cast<int> (m_keyLength)))
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  QByteArray block(static_cast<int> (m_blockSize), 0);
  QByteArray c;
  QByteArray decrypted;
  auto const &ciphertext(bytes.mid(iv.length()));
  auto const iterations = ciphertext.length() / static_cast<int> (m_blockSize);

  for(int i = 0; i < iterations; i++)
    {
      auto const position = i * static_cast<int> (m_blockSize);
      auto ok = true;

      threefish_decrypt
	(block.data(),
	 m_key,
	 m_tweak,
	 ciphertext.mid(position, static_cast<int> (m_blockSize)).constData(),
	 m_blockSize,
	 8 * m_blockSize,
	 &ok);

      if(!ok)
	{
	  decrypted.clear();
	  break;
	}

      if(i == 0)
	block = spoton_misc::xor_arrays(block, iv);
      else
	block = spoton_misc::xor_arrays(block, c);

      c = ciphertext.mid(position, static_cast<int> (m_blockSize));
      decrypted.append(block);
    }

  if(decrypted.isEmpty())
    {
      if(ok)
	*ok = false;

      return decrypted;
    }

  QByteArray originalLength;

  if(decrypted.length() > static_cast<int> (sizeof(int)))
    originalLength = decrypted.mid
      (decrypted.length() - static_cast<int> (sizeof(int)),
       static_cast<int> (sizeof(int)));

  if(!originalLength.isEmpty())
    {
      QDataStream in(&originalLength, QIODevice::ReadOnly);
      int s = 0;

      in >> s;

      if(in.status() != QDataStream::Ok)
	{
	  if(ok)
	    *ok = false;

	  decrypted.clear();
	}
      else
	{
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
    }
  else
    {
      if(ok)
	*ok = false;

      decrypted.clear();
    }

  return decrypted;
}

QByteArray spoton_threefish::encrypted(const QByteArray &bytes, bool *ok) const
{
  QReadLocker locker(&m_locker);

  if(Q_UNLIKELY(!m_key || !m_tweak))
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  locker.unlock();

  QByteArray iv;

  setInitializationVector(iv, ok);

  if(Q_UNLIKELY(iv.isEmpty()))
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  locker.relock();

  /*
  ** Let's resize the container to the block size.
  */

  QByteArray block(iv.length(), 0);
  QByteArray encrypted;
  auto plaintext(bytes);

  if(plaintext.isEmpty())
    plaintext = plaintext.leftJustified(static_cast<int> (m_blockSize), 0);
  else
    plaintext = plaintext.leftJustified
      (static_cast<int> (m_blockSize) *
       static_cast<int> (qCeil(static_cast<qreal> (plaintext.length()) /
			       static_cast<qreal> (m_blockSize)) + 1), 0);

  QByteArray originalLength;
  QDataStream out(&originalLength, QIODevice::WriteOnly);

  out << bytes.length();

  if(out.status() != QDataStream::Ok)
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  plaintext.replace
    (plaintext.length() - static_cast<int> (sizeof(int)),
     static_cast<int> (sizeof(int)), originalLength);

  auto const iterations = plaintext.length() / static_cast<int> (m_blockSize);

  for(int i = 0; i < iterations; i++)
    {
      QByteArray p;
      auto const position = i * static_cast<int> (m_blockSize);
      auto ok = true;

      p = plaintext.mid(position, static_cast<int> (m_blockSize));

      if(i == 0)
	block = spoton_misc::xor_arrays(iv, p);
      else
	block = spoton_misc::xor_arrays(block, p);

      threefish_encrypt(block.data(),
			m_key,
			m_tweak,
			block,
			m_blockSize,
			8 * m_blockSize,
			&ok);

      if(!ok)
	{
	  encrypted.clear();
	  break;
	}

      encrypted.append(block);
    }

  if(encrypted.isEmpty())
    {
      if(ok)
	*ok = false;

      return encrypted;
    }

  return iv + encrypted;
}

void spoton_threefish::setInitializationVector
(QByteArray &bytes, bool *ok) const
{
  QReadLocker locker(&m_locker);
  auto const ivLength = m_keyLength;

  locker.unlock();

  if(ok)
    *ok = false;

  if(Q_UNLIKELY(ivLength == 0))
    return;

  auto iv = static_cast<char *> (gcry_calloc(ivLength, sizeof(char)));

  if(Q_LIKELY(iv))
    {
      if(ok)
	*ok = true;

      gcry_fast_random_poll();
      gcry_create_nonce(iv, ivLength);
      bytes = QByteArray(iv, static_cast<int> (ivLength));
    }

  gcry_free(iv);
}

void spoton_threefish::setKey(const QByteArray &key, bool *ok)
{
  setKey(key.constData(), static_cast<size_t> (key.length()), ok);
}

void spoton_threefish::setKey(const char *key, const size_t keyLength, bool *ok)
{
  QWriteLocker locker(&m_locker);

  if(keyLength != 32)
    {
      if(ok)
	*ok = false;

      return;
    }

  gcry_free(m_key);
  m_key = static_cast<char *> (gcry_calloc_secure(keyLength, sizeof(char)));

  if(Q_UNLIKELY(!m_key))
    {
      m_blockSize = 0;
      m_keyLength = 0;

      if(ok)
	*ok = false;

      return;
    }

  if(ok)
    *ok = true;

  m_blockSize = keyLength;
  m_keyLength = keyLength;
  memcpy(m_key, key, m_keyLength);
}

void spoton_threefish::setTweak(const QByteArray &tweak, bool *ok)
{
  QWriteLocker locker(&m_locker);

  if(tweak.length() != 16)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  delete []m_tweak;
  m_tweak = new (std::nothrow) char[static_cast<size_t> (tweak.length())];

  if(!m_tweak)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  m_tweakLength = static_cast<size_t> (tweak.length());
  memcpy(m_tweak, tweak.constData(), m_tweakLength);

  if(ok)
    *ok = true;

  return;

 done_label:
  delete []m_tweak;
  m_tweak = 0;
  m_tweakLength = 0;
}

void spoton_threefish::test1(void)
{
  auto s = new (std::nothrow) spoton_threefish();

  if(!s)
    return;

  QByteArray c;
  QByteArray p;
  auto ok = true;

  s->setKey(spoton_crypt::strongRandomBytes(32), &ok);

  if(ok)
    s->setTweak("76543210fedcba98", &ok);

  p = "The pink duck visited the Soap Queen. A happy moment indeed.";

  if(ok)
    c = s->encrypted(p, &ok);

  if(ok)
    p = s->decrypted(c, &ok);

  qDebug() << ok << p;
  delete s;
}

void spoton_threefish::test2(void)
{
  auto s = new (std::nothrow) spoton_threefish();

  if(!s)
    return;

  QByteArray c;
  QByteArray p;
  auto ok = true;

  s->setKey(spoton_crypt::strongRandomBytes(32), &ok);

  if(ok)
    s->setTweak("76543210fedcba98", &ok);

  p = "If you wish to glimpse inside a human soul "
    "and get to know a man, don't bother analyzing "
    "his ways of being silent, of talking, of weeping, "
    "of seeing how much he is moved by noble ideas; you "
    "will get better results if you just watch him laugh. "
    "If he laughs well, he's a good man.";

  if(ok)
    c = s->encrypted(p, &ok);

  if(ok)
    p = s->decrypted(c, &ok);

  qDebug() << ok << p;
  delete s;
}

void spoton_threefish::test3(void)
{
  auto s = new (std::nothrow) spoton_threefish();

  if(!s)
    return;

  QByteArray c;
  QByteArray p;
  auto ok = true;

  s->setKey(spoton_crypt::strongRandomBytes(32), &ok);

  if(ok)
    s->setTweak("76543210fedcba98", &ok);

  p = "The truth is always an abyss. One must - as in a swimming pool "
    "- dare to dive from the quivering springboard of trivial "
    "everyday experience and sink into the depths, in order to "
    "later rise again - laughing and fighting for breath - to "
    "the now doubly illuminated surface of things.";

  if(ok)
    c = s->encrypted(p, &ok);

  if(ok)
    p = s->decrypted(c, &ok);

  qDebug() << ok << p;
  delete s;
}
