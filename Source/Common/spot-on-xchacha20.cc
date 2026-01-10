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

#include <QtDebug>
#include <QtMath>

#include "spot-on-crypt.h"
#include "spot-on-misc.h"
#include "spot-on-xchacha20.h"

/*
** Read https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha,
** https://datatracker.ietf.org/doc/html/rfc7539,
** https://www.rfc-editor.org/rfc/rfc8439.
*/

spoton_xchacha20::spoton_xchacha20(const QByteArray &key)
{
  m_key = key.mid(0, 32);
  m_keyLength = 32; // Or, 256 bits.

  if(m_key.length() < m_keyLength)
    m_key.append(m_keyLength - m_key.length(), 0);
  else
    m_key.resize(m_keyLength);
}

spoton_xchacha20::~spoton_xchacha20()
{
  spoton_crypt::memzero(m_key);
}

QByteArray spoton_xchacha20::chacha20Block
(const QByteArray &key, const QByteArray &nonce, const uint32_t counter)
{
  /*
  ** ChaCha20 Block
  */

  QVector<uint32_t> initialState(16);
  QVector<uint32_t> state(16);

  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  state[4] = extract4Bytes(key, 0);
  state[5] = extract4Bytes(key, 4);
  state[6] = extract4Bytes(key, 8);
  state[7] = extract4Bytes(key, 12);
  state[8] = extract4Bytes(key, 16);
  state[9] = extract4Bytes(key, 20);
  state[10] = extract4Bytes(key, 24);
  state[11] = extract4Bytes(key, 28);
  state[12] = counter;
  state[13] = extract4Bytes(nonce, 0);
  state[14] = extract4Bytes(nonce, 4);
  state[15] = extract4Bytes(nonce, 8);

  for(int i = 0; i < initialState.size(); i++)
    initialState[i] = state[i];

  for(int i = 1; i <= 10; i++)
    {
      quarterRound(state[0], state[4], state[8], state[12]);
      quarterRound(state[1], state[5], state[9], state[13]);
      quarterRound(state[2], state[6], state[10], state[14]);
      quarterRound(state[3], state[7], state[11], state[15]);
      quarterRound(state[0], state[5], state[10], state[15]);
      quarterRound(state[1], state[6], state[11], state[12]);
      quarterRound(state[2], state[7], state[8], state[13]);
      quarterRound(state[3], state[4], state[9], state[14]);
    }

  for(int i = 0; i < initialState.size(); i++)
    state[i] += initialState[i];

  spoton_crypt::memzero(initialState);

  QByteArray data(64, '0');

  for(int i = 0; i < state.size(); i++)
    infuse4Bytes(data, i * 4, state[i]);

  spoton_crypt::memzero(state);
  return data;
}

QByteArray spoton_xchacha20::chacha20Encrypt(const QByteArray &key,
					     const QByteArray &nonce,
					     const QByteArray &plaintext,
					     const uint32_t counter)
{
  QByteArray encrypted;

  for(int i = 0; i <= qFloor(plaintext.length() / 64.0) - 1; i++)
    {
      auto const block(plaintext.mid(i * 64, 64));
      auto const stream(chacha20Block(key, nonce, counter + i));

      encrypted.append(spoton_misc::xor_arrays(block, stream));
    }

  if(plaintext.length() % 64 != 0)
    {
      QByteArray block;
      auto const i = qFloor(plaintext.length() / 64.0);
      auto const stream(chacha20Block(key, nonce, counter + i));

      block = plaintext.mid(i * 64);
      encrypted.append
	(spoton_misc::
	 xor_arrays(block, stream).mid(0, plaintext.length() % 64));
    }

  return encrypted;
}

QByteArray spoton_xchacha20::encrypt(const QByteArray &data)
{
  auto const nonce(spoton_crypt::strongRandomBytes(24));
  auto const static counter = static_cast<uint32_t> (1);

  return nonce + xchacha20Encrypt(m_key, nonce, data, counter);
}

QByteArray spoton_xchacha20::decrypt(const QByteArray &data)
{
  auto const nonce(data.mid(0, 24));
  auto const static counter = static_cast<uint32_t> (1);

  return xchacha20Encrypt(m_key, nonce, data.mid(24), counter);
}

QByteArray spoton_xchacha20::hchacha20Block
(const QByteArray &key, const QByteArray &nonce)
{
  /*
  ** HChaCha20 Block
  */

  QVector<uint32_t> state(16);

  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  state[4] = extract4Bytes(key, 0);
  state[5] = extract4Bytes(key, 4);
  state[6] = extract4Bytes(key, 8);
  state[7] = extract4Bytes(key, 12);
  state[8] = extract4Bytes(key, 16);
  state[9] = extract4Bytes(key, 20);
  state[10] = extract4Bytes(key, 24);
  state[11] = extract4Bytes(key, 28);
  state[12] = extract4Bytes(nonce, 0);
  state[13] = extract4Bytes(nonce, 4);
  state[14] = extract4Bytes(nonce, 8);
  state[15] = extract4Bytes(nonce, 12);

  for(int i = 0; i < 10; i++)
    {
      quarterRound(state[0], state[4], state[8], state[12]);
      quarterRound(state[1], state[5], state[9], state[13]);
      quarterRound(state[2], state[6], state[10], state[14]);
      quarterRound(state[3], state[7], state[11], state[15]);
      quarterRound(state[0], state[5], state[10], state[15]);
      quarterRound(state[1], state[6], state[11], state[12]);
      quarterRound(state[2], state[7], state[8], state[13]);
      quarterRound(state[3], state[4], state[9], state[14]);
    }

  QByteArray data(32, '0');

  infuse4Bytes(data, 0, state[0]);
  infuse4Bytes(data, 4, state[1]);
  infuse4Bytes(data, 8, state[2]);
  infuse4Bytes(data, 12, state[3]);
  infuse4Bytes(data, 16, state[12]);
  infuse4Bytes(data, 20, state[13]);
  infuse4Bytes(data, 24, state[14]);
  infuse4Bytes(data, 28, state[15]);
  spoton_crypt::memzero(state);
  return data;
}

QByteArray spoton_xchacha20::xchacha20Encrypt
(const QByteArray &key,
 const QByteArray &nonce,
 const QByteArray &plaintext,
 const uint32_t counter)
{
  /*
  ** XChaCha20 Encrypt
  */

  auto const chacha20_nonce(QByteArray::fromHex("00000000") + nonce.mid(16));
  auto const stream(hchacha20Block(key, nonce.mid(0, 16)));

  return chacha20Encrypt(stream, chacha20_nonce, plaintext, counter);
}

uint32_t spoton_xchacha20::extract4Bytes
(const QByteArray &bytes, const int offset)
{
  uint32_t value = 0;

  if(bytes.length() > offset + 3 && offset >= 0)
    {
      for(int i = 0; i < 4; i++)
	value |= static_cast<uint32_t>
	  (static_cast<uint8_t> (bytes[i + offset]) << i * 8);
    }
  else
    qDebug() << "Error!";

  return value;
}

void spoton_xchacha20::infuse4Bytes
(QByteArray &bytes, const int offset, const uint32_t value)
{
  if(bytes.length() > offset + 3 && offset >= 0)
    {
      for(int i = 0; i < 4; i++)
	bytes[i + offset] = static_cast<char> ((value >> i * 8) & 0xff);
    }
  else
    qDebug() << "Error!";
}

void spoton_xchacha20::quarterRound
(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d)
{
  a += b;
  d ^= a;
  rotate(d, 16);
  c += d;
  b ^= c;
  rotate(b, 12);
  a += b;
  d ^= a;
  rotate(d, 8);
  c += d;
  b ^= c;
  rotate(b, 7);
}

void spoton_xchacha20::rotate(uint32_t &x, const uint32_t n)
{
  x = (x << n) | (x >> (32 - n));
}

void spoton_xchacha20::setKey(const QByteArray &key)
{
  spoton_crypt::memzero(m_key);
  m_key = key.mid(0, 32);

  if(m_key.length() < m_keyLength)
    m_key.append(m_keyLength - m_key.length(), 0);
  else
    m_key.resize(m_keyLength);
}
