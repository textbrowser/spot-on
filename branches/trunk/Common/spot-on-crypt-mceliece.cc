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

void spoton_crypt::generateMcElieceKeys(const QString &keySize,
					QByteArray &privateKey,
					QByteArray &publicKey,
					bool *ok)
{
  if(ok)
    *ok = false;

#ifdef SPOTON_LINKED_WITH_LIBBOTAN
  Q_UNUSED(keySize);
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

#ifdef SPOTON_LINKED_WITH_LIBBOTAN
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

#ifdef SPOTON_LINKED_WITH_LIBBOTAN
  Q_UNUSED(data);
  Q_UNUSED(publicKey);
  return QByteArray();
#else
  Q_UNUSED(data);
  Q_UNUSED(publicKey);
  return QByteArray();
#endif
}
