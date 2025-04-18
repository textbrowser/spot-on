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

#ifndef _spoton_threefish_h_
#define _spoton_threefish_h_

#include <QByteArray>
#include <QReadWriteLock>

class spoton_threefish
{
 public:
  spoton_threefish(void);
  ~spoton_threefish();
  QByteArray decrypted(const QByteArray &bytes, bool *ok) const;
  QByteArray encrypted(const QByteArray &bytes, bool *ok) const;
  static void test1(void);
  static void test2(void);
  static void test3(void);
  void setKey(const QByteArray &key, bool *ok);
  void setKey(const char *key, const size_t keyLength, bool *ok);
  void setTweak(const QByteArray &tweak, bool *ok);

 private:
  char *m_key; // Stored in secure memory.
  char *m_tweak;
  mutable QReadWriteLock m_locker;
  size_t m_blockSize;
  size_t m_keyLength;
  size_t m_tweakLength;
  void setInitializationVector(QByteArray &bytes, bool *ok) const;
};

#endif
