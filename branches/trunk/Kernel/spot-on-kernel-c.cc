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

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"

bool spoton_kernel::prepareAlmostAnonymousEmail
(const QByteArray &attachment,
 const QByteArray &attachmentName,
 const QByteArray &goldbug,
 const QByteArray &keyType,
 const QByteArray &message,
 const QByteArray &name,
 const QByteArray &receiverName,
 const QByteArray &subject,
 QByteArray &data)
{
  data.clear();

  spoton_crypt *s_crypt = s_crypts.value(keyType, 0);

  if(!s_crypt)
    return false;

  QByteArray dispatcherPublicKey;
  QByteArray dispatcherPublicKeyHash;
  bool ok = true;

  dispatcherPublicKey = s_crypt->publicKey(&ok);

  if(!ok)
    return false;

  dispatcherPublicKeyHash = spoton_crypt::sha512Hash
    (dispatcherPublicKey, &ok);

  if(!ok)
    return false;

  spoton_crypt *crypt = spoton_misc::cryptFromForwardSecrecyMagnet(goldbug);

  if(!crypt)
    return false;

  QByteArray group1;
  QByteArray group2;
  QDataStream stream(&data, QIODevice::WriteOnly);

  if(!ok)
    goto done_label;

  stream << QByteArray("0001c")
	 << dispatcherPublicKeyHash
	 << name
	 << subject
	 << message
	 << attachment
	 << attachmentName;

  if(stream.status() != QDataStream::Ok)
    {
      ok = false;
      goto done_label;
    }

  group1 = crypt->encrypted(data, &ok);

  if(!ok)
    goto done_label;

  group2 = crypt->keyedHash(group1, &ok);

  if(!ok)
    goto done_label;

  data = group1.toBase64() + "\n" + group2.toBase64();

  if(keyType == "poptastic")
    {
      QByteArray message(spoton_send::message0001c(data));

      postPoptasticMessage(receiverName, message);
    }

 done_label:
  delete crypt;

  if(!ok)
    data.clear();

  return ok;
}
