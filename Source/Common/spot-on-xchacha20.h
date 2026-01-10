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

#ifndef _spoton_xchacha20_h_
#define _spoton_xchacha20_h_

#include <QByteArray>

class spoton_xchacha20
{
 public:
  spoton_xchacha20(const QByteArray &key);
  ~spoton_xchacha20();
  QByteArray decrypt(const QByteArray &data);
  QByteArray encrypt(const QByteArray &data);
  static QByteArray chacha20Block(const QByteArray &key,
				  const QByteArray &nonce,
				  const uint32_t counter);
  static QByteArray chacha20Encrypt(const QByteArray &key,
				    const QByteArray &nonce,
				    const QByteArray &plaintext,
				    const uint32_t counter);
  static QByteArray hchacha20Block(const QByteArray &key,
				   const QByteArray &nonce);
  static QByteArray xchacha20Encrypt(const QByteArray &key,
				     const QByteArray &nonce,
				     const QByteArray &plaintext,
				     const uint32_t counter);
  static uint32_t extract4Bytes(const QByteArray &bytes, const int offset);
  static void infuse4Bytes(QByteArray &bytes,
			     const int offset,
			     const uint32_t value);
  static void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d);
  static void rotate(uint32_t &x, const uint32_t n);
  void setKey(const QByteArray &key);

 private:
  QByteArray m_key;
  int m_keyLength;
};

#endif
