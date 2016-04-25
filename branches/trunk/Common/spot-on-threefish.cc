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

#include "Common/spot-on-crypt.h"
#include "spot-on-misc.h"
#include "spot-on-threefish.h"

extern "C"
{
#include <gcrypt.h>
}

static const uint8_t *Pi = 0;
static const uint8_t *RPi = 0;
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
static size_t Nr = 0;
static size_t Nw = 0;
static void bytesToWords(uint64_t *W,
			 const char *bytes,
			 const size_t bytes_size);
static void purge(void *buffer, const size_t buffer_size);
static void threefish_decrypt(char *D,
			      const char *K,
			      const char *T,
			      const char *C,
			      const size_t C_size,
			      const size_t block_size);
static void threefish_decrypt_implementation(char *D,
					     const char *K,
					     const char *T,
					     const char *C,
					     const size_t C_size,
					     const size_t block_size);
static void threefish_encrypt(char *E,
			      const char *K,
			      const char *T,
			      const char *P,
			      const size_t P_size,
			      const size_t block_size);
static void threefish_encrypt_implementation(char *E,
					     const char *K,
					     const char *T,
					     const char *P,
					     const size_t P_size,
					     const size_t block_size);
static void wordsToBytes(char *B,
			 const uint64_t *words,
			 const size_t words_size);

static void bytesToWords(uint64_t *W,
			 const char *bytes,
			 const size_t bytes_size)
{
  if(!W || !bytes || bytes_size <= 0)
    return;

  for(size_t i = 0; i < bytes_size / 8; i++)
    {
      char b[8];

      for(size_t j = 0; j < 8; j++)
	b[j] = bytes[i * 8 + j];

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

  if(!y0 || !y1)
    return;

  /*
  ** Section 3.3.1.
  */

  uint64_t r = R_4[d % 8][i];

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

  if(!x0 || !x1)
    return;

  /*
  ** Section 3.3.1.
  */

  uint64_t r = R_4[d % 8][i];

  /*
  ** Please see https://en.wikipedia.org/wiki/Circular_shift.
  */

  *x1 = ((y1 ^ y0) >> r) | ((y1 ^ y0) << (64 - r));
  *x0 = y0 - *x1;
}

static void purge(void *buffer,
		  const size_t buffer_size)
{
  if(!buffer || buffer_size <= 0)
    return;

  char *b = static_cast<char *> (buffer);

  for(size_t i = 0; i < buffer_size; i++)
    {
      *b = 0;
      b += 1;
    }
}

static void threefish_decrypt(char *D,
			      const char *K,
			      const char *T,
			      const char *C,
			      const size_t C_size,
			      const size_t block_size)
{
  if(!C || C_size <= 0 || !D || !K || !T || block_size <= 0)
    return;

  Nr = 72;
  Nw = 4;
  RPi = RPi_4;
  threefish_decrypt_implementation(D, K, T, C, C_size, block_size);
}

static void threefish_decrypt_implementation(char *D,
					     const char *K,
					     const char *T,
					     const char *C,
					     const size_t C_size,
					     const size_t block_size)
{
  if(!C || C_size <= 0 || !D || !K || !T || block_size <= 0)
    return;

  /*
  ** The inverse of section 3.3.
  */

  uint64_t C240 = 0x1bd11bdaa9fc1a22;
  uint64_t k[Nw + 1];
  uint64_t kNw = C240; // Section 3.3.2.
  uint64_t s[Nr / 4 + 1][Nw];
  uint64_t t[3];
  uint64_t v[Nw];

  bytesToWords(k, K, C_size);
  bytesToWords(t, T, 16);
  bytesToWords(v, C, C_size);

  for(size_t i = 0; i < Nw; i++)
    kNw ^= k[i]; // Section 3.3.2.

  k[Nw] = kNw;
  t[2] = t[0] ^ t[1]; // Section 3.3.2.

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

  for(size_t i = 0; i < Nw; i++)
    v[i] -= s[Nr / 4][i];

  for(size_t d = Nr - 1;; d--)
    {
      uint64_t f[Nw];

      for(size_t i = 0; i < Nw; i++)
	f[i] = v[RPi[i]];

      for(size_t i = 0; i < Nw / 2; i++)
	{
	  uint64_t x0 = 0;
	  uint64_t x1 = 0;
	  uint64_t y0 = f[i * 2];
	  uint64_t y1 = f[i * 2 + 1];

	  mix_inverse(y0, y1, d, i, &x0, &x1, block_size);
	  v[i * 2] = x0;
	  v[i * 2 + 1] = x1;
	}

      purge(f, sizeof(f));

      if(d % 4 == 0)
	for(size_t i = 0; i < Nw; i++)
	  v[i] -= s[d / 4][i];

      if(d == 0)
	break;
    }

  wordsToBytes(D, v, Nw);
  purge(k, sizeof(k));
  purge(s, sizeof(s));
  purge(t, sizeof(t));
  purge(v, sizeof(v));
}

static void threefish_encrypt(char *E,
			      const char *K,
			      const char *T,
			      const char *P,
			      const size_t P_size,
			      const size_t block_size)
{
  if(!E || !K || !P || P_size <= 0 || !T || block_size <= 0)
    return;

  Nr = 72;
  Nw = 4;
  Pi = Pi_4;
  threefish_encrypt_implementation(E, K, T, P, P_size, block_size);
}

static void threefish_encrypt_implementation(char *E,
					     const char *K,
					     const char *T,
					     const char *P,
					     const size_t P_size,
					     const size_t block_size)
{
  if(!E || !K || !T || !P || P_size <= 0 || block_size <= 0)
    return;

  /*
  ** Section 3.3.
  */

  uint64_t C240 = 0x1bd11bdaa9fc1a22;
  uint64_t k[Nw + 1];
  uint64_t kNw = C240; // Section 3.3.2.
  uint64_t s[Nr / 4 + 1][Nw];
  uint64_t t[3];
  uint64_t v[Nw];

  bytesToWords(k, K, P_size);
  bytesToWords(t, T, 16);
  bytesToWords(v, P, P_size);

  for(size_t i = 0; i < Nw; i++)
    kNw ^= k[i]; // Section 3.3.2.

  k[Nw] = kNw;
  t[2] = t[0] ^ t[1]; // Section 3.3.2.

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
	for(size_t i = 0; i < Nw; i++)
	  v[i] += s[d / 4][i];

      uint64_t f[Nw];

      for(size_t i = 0; i < Nw / 2; i++)
	{
	  uint64_t x0 = v[i * 2];
	  uint64_t x1 = v[i * 2 + 1];
	  uint64_t y0 = 0;
	  uint64_t y1 = 0;

	  mix(x0, x1, d, i, &y0, &y1, block_size);
	  f[i * 2] = y0;
	  f[i * 2 + 1] = y1;
	}

      for(size_t i = 0; i < Nw; i++)
	v[i] = f[Pi[i]];

      purge(f, sizeof(f));
    }

  for(size_t i = 0; i < Nw; i++)
    v[i] += s[Nr / 4][i];

  wordsToBytes(E, v, Nw);
  purge(k, sizeof(k));
  purge(s, sizeof(s));
  purge(t, sizeof(t));
  purge(v, sizeof(v));
}

static void wordsToBytes(char *B,
			 const uint64_t *words,
			 const size_t words_size)
{
  if(!B || !words || words_size <= 0)
    return;

  for(size_t i = 0; i < words_size; i++)
    {
      B[i * 8 + 0] = static_cast<char> (words[i]);
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
  gcry_free(m_key);
  gcry_free(m_tweak);
}

QByteArray spoton_threefish::decrypted(const QByteArray &bytes, bool *ok) const
{
  QReadLocker locker(&m_locker);

  if(!m_key || !m_tweak)
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  QByteArray iv(bytes.mid(0, static_cast<int> (m_keyLength)));

  if(iv.length() != static_cast<int> (m_keyLength))
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  QByteArray block(static_cast<int> (m_blockSize), 0);
  QByteArray c;
  QByteArray ciphertext(bytes.mid(iv.length()));
  QByteArray decrypted;
  int iterations = ciphertext.length() / static_cast<int> (m_blockSize);

  for(int i = 0; i < iterations; i++)
    {
      int position = i * static_cast<int> (m_blockSize);

      threefish_decrypt
	(block.data(),
	 m_key,
	 m_tweak,
	 ciphertext.mid(position,static_cast<int> (m_blockSize)).constData(),
	 m_blockSize,
	 8 * m_blockSize);

      if(i == 0)
	block = spoton_misc::xor_arrays(block, iv);
      else
	block = spoton_misc::xor_arrays(block, c);

      c = ciphertext.mid(position, static_cast<int> (m_blockSize));
      decrypted.append(block);
    }

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

  return decrypted;
}

QByteArray spoton_threefish::encrypted(const QByteArray &bytes, bool *ok) const
{
  QReadLocker locker(&m_locker);

  if(!m_key || !m_tweak)
    {
      if(ok)
	*ok = false;

      return QByteArray();
    }

  locker.unlock();

  QByteArray iv;

  setInitializationVector(iv, ok);

  if(iv.isEmpty())
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
  QByteArray plaintext(bytes);

  if(plaintext.isEmpty())
    plaintext = plaintext.leftJustified
      (static_cast<int> (m_blockSize), 0);
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
    (plaintext.length() - sizeof(int), sizeof(int), originalLength);

  int iterations = plaintext.length() / static_cast<int> (m_blockSize);

  for(int i = 0; i < iterations; i++)
    {
      QByteArray p;
      int position = i * static_cast<int> (m_blockSize);

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
			8 * m_blockSize);
      encrypted.append(block);
    }

  return iv + encrypted;
}

void spoton_threefish::setInitializationVector
(QByteArray &bytes, bool *ok) const
{
  QReadLocker locker(&m_locker);
  size_t ivLength = m_keyLength;

  locker.unlock();

  if(ok)
    *ok = false;

  if(ivLength <= 0)
    return;

  char *iv = static_cast<char *> (gcry_calloc(ivLength, sizeof(char)));

  if(iv)
    {
      if(ok)
	*ok = true;

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
    }

  gcry_free(iv);
}

void spoton_threefish::setKey(const QByteArray &key, bool *ok)
{
  QWriteLocker locker(&m_locker);

  if(key.size() != 32)
    {
      if(*ok)
	*ok = false;

      goto done_label;
    }

  gcry_free(m_key);
  m_key = static_cast<char *>
    (gcry_calloc_secure(static_cast<size_t> (key.length()), sizeof(char)));
  m_keyLength = static_cast<size_t> (key.length());

  if(!m_key)
    {
      m_blockSize = 0;
      m_keyLength = 0;

      if(ok)
	*ok = false;

      goto done_label;
    }

  if(*ok)
    *ok = true;

  m_blockSize = m_keyLength;
  return;

 done_label:
  gcry_free(m_key);
  m_blockSize = 0;
  m_key = 0;
  m_keyLength = 0;
}

void spoton_threefish::setTweak(const QByteArray &tweak, bool *ok)
{
  QWriteLocker locker(&m_locker);

  if(tweak.size() != 16)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  gcry_free(m_tweak);
  m_tweak = static_cast<char *>
    (calloc(static_cast<size_t> (tweak.length()), sizeof(char)));
  m_tweakLength = static_cast<size_t> (tweak.length());

  if(!m_tweak)
    {
      m_tweakLength = 0;

      if(ok)
	*ok = false;

      goto done_label;
    }

  if(*ok)
    *ok = true;

  return;

 done_label:
  gcry_free(m_tweak);
  m_tweak = 0;
  m_tweakLength = 0;
}

void spoton_threefish::test1(void)
{
  QByteArray c;
  QByteArray p;
  bool ok = true;
  spoton_threefish *s = new spoton_threefish();

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
  QByteArray c;
  QByteArray p;
  bool ok = true;
  spoton_threefish *s = new spoton_threefish();

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
  QByteArray c;
  QByteArray p;
  bool ok = true;
  spoton_threefish *s = new spoton_threefish();

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
