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

#include "Kernel/spot-on-kernel.h"
#include "spot-on-crypt.h"
#include "spot-on-misc.h"
#include "spot-on-receive.h"

QList<QByteArray> spoton_receive::process0000
(int length,
 const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const bool acceptSignedMessagesOnly,
 const QString &address,
 const quint16 port,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0000(): "
	 "s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));
      bool ok = true;

      if(list.size() == 3)
	{
	  /*
	  ** Gemini?
	  */

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QPair<QByteArray, QByteArray> gemini;

	  if(symmetricKeys.value(0).isEmpty() ||
	     symmetricKeys.value(2).isEmpty())
	    gemini = spoton_misc::findGeminiInCosmos(list.value(0),
						     list.value(1),
						     s_crypt);
	  else
	    {
	      gemini.first = symmetricKeys.value(0);
	      gemini.second = symmetricKeys.value(2);
	    }

	  if(!gemini.first.isEmpty() && !gemini.second.isEmpty())
	    {
	      QByteArray computedHash;
	      QByteArray message(list.value(0));
	      spoton_crypt crypt("aes256",
				 "sha512",
				 QByteArray(),
				 gemini.first,
				 gemini.second,
				 0,
				 0,
				 "");

	      computedHash = crypt.keyedHash(message, &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(1));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      list.clear();
		      message = crypt.decrypted(message, &ok);

		      if(ok)
			{
			  QByteArray a;
			  QDataStream stream(&message, QIODevice::ReadOnly);

			  stream >> a; // Message Type

			  if(stream.status() == QDataStream::Ok)
			    {
			      stream >> a; // Message

			      if(stream.status() == QDataStream::Ok)
				list = a.split('\n');
			    }
			}

		      if(list.size() != 3)
			{
			  spoton_misc::logError
			    (QString("spoton_receive::process0000(): "
				     "received irregular data. "
				     "Expecting 3 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return QList<QByteArray> ();
			}
		    }
		  else
		    {
		      spoton_misc::logError("spoton_receive::"
					    "process0000(): "
					    "computed message code does "
					    "not match provided code.");
		      return QList<QByteArray> ();
		    }
		}
	    }
	  else
	    return QList<QByteArray> (); /*
					 ** A gemini was not discovered.
					 ** We need to echo.
					 */
	}
      else if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0000(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hashKey;
      QByteArray hashKeyAlgorithm;
      QByteArray keyInformation(list.value(0));
      QByteArray originalKeyInformation(keyInformation);
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QDataStream stream(&keyInformation, QIODevice::ReadOnly);
	  QList<QByteArray> list;

	  for(int i = 0; i < 5; i++)
	    {
	      QByteArray a;

	      stream >> a;

	      if(stream.status() != QDataStream::Ok)
		{
		  list.clear();
		  break;
		}
	      else
		list << a;
	    }

	  if(!list.isEmpty())
	    list.removeAt(0); // Message Type

	  if(list.size() == 4)
	    {
	      hashKey = list.value(1);
	      hashKeyAlgorithm = list.value(3);
	      symmetricKey = list.value(0);
	      symmetricKeyAlgorithm = list.value(2);
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_receive::process0000(): "
			 "received irregular data. "
			 "Expecting 4 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return QList<QByteArray> ();
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash
	    (originalKeyInformation + data,
	     hashKey,
	     hashKeyAlgorithm,
	     &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     hashKeyAlgorithm,
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     "");

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QDataStream stream(&data, QIODevice::ReadOnly);
		      QList<QByteArray> list;

		      for(int i = 0; i < 6; i++)
			{
			  QByteArray a;

			  stream >> a;

			  if(stream.status() != QDataStream::Ok)
			    {
			      list.clear();
			      break;
			    }
			  else
			    list << a;
			}

		      if(list.size() == 6)
			{
			  if(spoton_misc::
			     isAcceptedParticipant(list.value(0), "chat",
						   s_crypt) ||
			     spoton_misc::
			     isAcceptedParticipant(list.value(0), "poptastic",
						   s_crypt))
			    {
			      if(acceptSignedMessagesOnly)
				{
				  QByteArray recipientDigest;
				  bool ok = true;

				  recipientDigest = s_crypt->publicKey(&ok);

				  if(ok)
				    recipientDigest = spoton_crypt::
				      sha512Hash(recipientDigest, &ok);

				  if(!ok ||
				     !spoton_misc::
				     isValidSignature("0000" +
						      symmetricKey +
						      hashKey +
						      symmetricKeyAlgorithm +
						      hashKeyAlgorithm +
						      list.value(0) +
						      list.value(1) +
						      list.value(2) +
						      list.value(3) +
						      list.value(4) +
						      recipientDigest,
						      list.value(0),
						      list.value(5),
						      s_crypt))
				    {
				      spoton_misc::logError
					("spoton_receive::"
					 "process0000(): invalid "
					 "signature.");
				      return QList<QByteArray> ();
				    }
				}

			      if(!list.value(0).isEmpty() &&
				 !list.value(1).isEmpty() &&
				 !list.value(2).isEmpty() &&
				 !list.value(3).isEmpty() &&
				 !list.value(4).isEmpty())
				{
				  list.append(messageCode);
				  return list;
				}
			    }
			}
		      else
			spoton_misc::logError
			  (QString("spoton_receive::process0000(): "
				   "received irregular data. "
				   "Expecting 6 "
				   "entries, "
				   "received %1.").arg(list.size()));
		    }
		}
	      else
		spoton_misc::logError("spoton_receive::"
				      "process0000(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0000(): 0000 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0000a
(int length,
 const QByteArray &dataIn,
 const bool acceptSignedMessagesOnly,
 const QString &address,
 const quint16 port,
 const QString &messageType,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0000a(): "
	 "s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0000a(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hashKey;
      QByteArray hashKeyAlgorithm;
      QByteArray keyInformation(list.value(0));
      QByteArray originalKeyInformation(keyInformation);
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QDataStream stream(&keyInformation, QIODevice::ReadOnly);
	  QList<QByteArray> list;

	  for(int i = 0; i < 5; i++)
	    {
	      QByteArray a;

	      stream >> a;

	      if(stream.status() != QDataStream::Ok)
		{
		  list.clear();
		  break;
		}
	      else
		list << a;
	    }

	  if(!list.isEmpty())
	    list.removeAt(0); // Message Type

	  if(list.size() == 4)
	    {
	      hashKey = list.value(1);
	      hashKeyAlgorithm = list.value(3);
	      symmetricKey = list.value(0);
	      symmetricKeyAlgorithm = list.value(2);
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_receive::process0000a(): "
			 "received irregular data. "
			 "Expecting 4 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return QList<QByteArray> ();
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash
	    (originalKeyInformation + data, hashKey, hashKeyAlgorithm, &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     hashKeyAlgorithm,
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     "");

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QDataStream stream(&data, QIODevice::ReadOnly);
		      QList<QByteArray> list;

		      for(int i = 0; i < 5; i++)
			{
			  QByteArray a;

			  stream >> a;

			  if(stream.status() != QDataStream::Ok)
			    {
			      list.clear();
			      break;
			    }
			  else
			    list << a;
			}

		      if(list.size() == 5)
			{
			  if(spoton_misc::
			     isAcceptedParticipant(list.value(0),
						   "chat",
						   s_crypt) ||
			     spoton_misc::
			     isAcceptedParticipant(list.value(0),
						   "poptastic",
						   s_crypt))
			    {
			      if(acceptSignedMessagesOnly)
				{
				  QByteArray recipientDigest;
				  bool ok = true;

				  recipientDigest = s_crypt->publicKey(&ok);

				  if(ok)
				    recipientDigest = spoton_crypt::
				      sha512Hash(recipientDigest, &ok);

				  if(!ok ||
				     !spoton_misc::
				     /*
				     ** 0 - Sender's SHA-512 Hash
				     ** 1 - Gemini Encryption Key
				     ** 2 - Gemini Hash Key
				     ** 3 - Timestamp
				     ** 4 - Signature
				     */

				     isValidSignature(messageType.toLatin1() +
						      symmetricKey +
						      hashKey +
						      symmetricKeyAlgorithm +
						      hashKeyAlgorithm +
						      list.value(0) +
						      list.value(1) +
						      list.value(2) +
						      list.value(3) +
						      recipientDigest,
						      list.value(0),
						      list.value(4),
						      s_crypt))
				    {
				      spoton_misc::logError
					("spoton_receive::"
					 "process0000a(): invalid "
					 "signature.");
				      return QList<QByteArray> ();
				    }
				}

			      return list;
			    }
			}
		      else
			spoton_misc::logError
			  (QString("spoton_receive::process0000a(): "
				   "received irregular data. "
				   "Expecting 5 "
				   "entries, "
				   "received %1.").arg(list.size()));
		    }
		}
	      else
		spoton_misc::logError("spoton_receive::process0000a(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0000a(): 0000a "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0000b
(int length,
 const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const bool acceptSignedMessagesOnly,
 const QString &address,
 const quint16 port,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0000b(): "
	 "s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_receivet::process0000b(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      /*
      ** The method findMessageType() verified that the computed
      ** hash is identical to the provided hash during the
      ** discovery of the gemini pair. Other
      ** process() methods perform redundant tests.
      */

      spoton_crypt crypt("aes256",
			 "sha512",
			 QByteArray(),
			 symmetricKeys.value(0),
			 0,
			 0,
			 "");

      data = crypt.decrypted(list.value(0), &ok);

      if(ok)
	{
	  QDataStream stream(&data, QIODevice::ReadOnly);
	  QList<QByteArray> list;

	  for(int i = 0; i < 6; i++)
	    {
	      QByteArray a;

	      stream >> a;

	      if(stream.status() != QDataStream::Ok)
		{
		  list.clear();
		  break;
		}
	      else
		list << a;
	    }

	  if(list.size() == 6)
	    {
	      if(spoton_misc::isAcceptedParticipant(list.value(1),
						    "chat",
						    s_crypt) ||
		 spoton_misc::isAcceptedParticipant(list.value(1),
						    "poptastic",
						    s_crypt))
		{
		  if(acceptSignedMessagesOnly)
		    {
		      QByteArray recipientDigest;
		      bool ok = true;

		      recipientDigest = s_crypt->publicKey(&ok);

		      if(ok)
			recipientDigest = spoton_crypt::
			  sha512Hash(recipientDigest, &ok);

		      if(!ok ||
			 !spoton_misc::
			 /*
			 ** 0 - 0000b
			 ** 1 - Sender's SHA-512 Hash
			 ** 2 - Gemini Encryption Key
			 ** 3 - Gemini Hash Key
			 ** 4 - Timestamp
			 ** 5 - Signature
			 */

			 isValidSignature(list.value(0) +
					  list.value(1) +
					  list.value(2) +
					  list.value(3) +
					  list.value(4) +
					  recipientDigest,
					  list.value(1),
					  list.value(5),
					  s_crypt))
			{
			  spoton_misc::logError
			    ("spoton_receive::"
			     "process0000b(): invalid "
			     "signature.");
			  return QList<QByteArray> ();
			}
		    }

		  return list;
		}
	    }
	  else
	    spoton_misc::logError
	      (QString("spoton_receive::process0000b(): "
		       "received irregular data. "
		       "Expecting 6 "
		       "entries, "
		       "received %1.").arg(list.size()));
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0000b(): 0000b "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0000d
(int length,
 const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const QString &address,
 const quint16 port,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0000d(): "
	 "s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_receivet::process0000d(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      /*
      ** The method findMessageType() verified that the computed
      ** hash is identical to the provided hash during the
      ** discovery of the Forward Secrecy pair. Other
      ** process() methods perform redundant tests.
      */

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      ** symmetricKeys[4]: Dispatcher's Digest
      */

      bool ok = true;
      spoton_crypt crypt(symmetricKeys.value(1).constData(),
			 symmetricKeys.value(3).constData(),
			 QByteArray(),
			 symmetricKeys.value(0),
			 symmetricKeys.value(2),
			 0,
			 0,
			 "");

      data = crypt.decrypted(list.value(0), &ok);

      if(ok)
	{
	  QDataStream stream(&data, QIODevice::ReadOnly);
	  QList<QByteArray> list;

	  for(int i = 0; i < 4; i++)
	    {
	      QByteArray a;

	      stream >> a;

	      if(stream.status() != QDataStream::Ok)
		{
		  list.clear();
		  break;
		}
	      else
		list << a;
	    }

	  if(list.size() == 4)
	    {
	      if(spoton_misc::isAcceptedParticipant(symmetricKeys.value(4),
						    "chat",
						    s_crypt) ||
		 spoton_misc::isAcceptedParticipant(symmetricKeys.value(4),
						    "poptastic",
						    s_crypt))
		{
		  list.removeAt(0); // Message Type
		  list.prepend(symmetricKeys.value(4)); // public_key_hash
		  return list;
		}
	    }
	  else
	    spoton_misc::logError
	      (QString("spoton_receive::process0000d(): "
		       "received irregular data. "
		       "Expecting 4 "
		       "entries, "
		       "received %1.").arg(list.size()));
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0000d(): 0000d "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0001b
(int length,
 const QByteArray &dataIn,
 const QString &address,
 const quint16 port,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0001b(): "
	 "s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 7)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0001b(): "
		     "received irregular data. Expecting 7 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hashKey;
      QByteArray hashKeyAlgorithm;
      QByteArray keyInformation(list.value(0));
      QByteArray originalKeyInformation(keyInformation);
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;
      bool ok = true;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation.split('\n'));

	  if(!list.isEmpty())
	    list.removeAt(0); // Message Type

	  if(list.size() == 4)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      hashKeyAlgorithm = QByteArray::fromBase64(list.value(3));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_receive::0001b(): "
			 "received irregular data. "
			 "Expecting 4 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return QList<QByteArray> ();
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash
	    (originalKeyInformation + data, hashKey, hashKeyAlgorithm, &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     hashKeyAlgorithm,
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     "");

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(data.split('\n'));

		      if(list.size() == 8)
			{
			  for(int i = 0; i < list.size(); i++)
			    list.replace
			      (i, QByteArray::fromBase64(list.at(i)));

			  return list;
			}
		      else
			{
			  spoton_misc::logError
			    (QString("spoton_receive::process0001b(): "
				     "received irregular data. "
				     "Expecting 8 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return QList<QByteArray> ();
			}
		    }
		}
	      else
		{
		  spoton_misc::logError
		    ("spoton_receive::process0001b(): "
		     "computed message code does "
		     "not match provided code.");
		  return QList<QByteArray> ();
		}
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0001b(): 0001b "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0001c
(int length,
 const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const QString &address,
 const quint16 port,
 const QString &keyType,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0001c(): "
	 "s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length != data.length())
    {
      spoton_misc::logError
      (QString("spoton_receive::process0001c(): 0001c "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address).
       arg(port));
      return QList<QByteArray> ();
    }

  data = data.trimmed();

  QList<QByteArray> list(data.split('\n'));

  if(list.size() != 3)
    {
      spoton_misc::logError
	(QString("spoton_receivet::process0001c(): "
		 "received irregular data. Expecting 3 "
		 "entries, "
		 "received %1.").arg(list.size()));
      return QList<QByteArray> ();
    }

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  /*
  ** The message digest was verified.
  */

  /*
  ** symmetricKeys[0]: Encryption Key
  ** symmetricKeys[1]: Encryption Type
  ** symmetricKeys[2]: Hash Key
  ** symmetricKeys[3]: Hash Type
  ** symmetricKeys[4]: Owner's Digest
  */

  bool ok = true;
  spoton_crypt crypt(symmetricKeys.value(1).constData(),
		     symmetricKeys.value(3).constData(),
		     QByteArray(),
		     symmetricKeys.value(0),
		     symmetricKeys.value(2),
		     0,
		     0,
		     "");

  data = crypt.decrypted(list.value(0), &ok);

  if(ok)
    {
      QDataStream stream(&data, QIODevice::ReadOnly);
      QList<QByteArray> list;

      for(int i = 0; i < 5; i++)
	{
	  QByteArray a;

	  stream >> a;

	  if(stream.status() != QDataStream::Ok)
	    {
	      list.clear();
	      break;
	    }
	  else
	    list << a;
	}

      if(list.isEmpty())
	return QList<QByteArray> ();

      if(!spoton_misc::isAcceptedParticipant(symmetricKeys.value(4),
					     keyType, s_crypt))
	return QList<QByteArray> ();

      QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
			 "email.db");
      qint64 maximumSize = 1048576 * spoton_kernel::setting
	("gui/maximumEmailFileSize", 1024).toLongLong();

      if(fileInfo.size() >= maximumSize)
	{
	  spoton_misc::logError("spoton_receive::process0001c(): "
				"email.db has exceeded the specified limit.");
	  return QList<QByteArray> ();
	}

      list.prepend(symmetricKeys.value(4)); /*
					    ** The dispatcher's digest.
					    */

      if(spoton_misc::storeAlmostAnonymousLetter(list, s_crypt))
	return list;
    }

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0013
(int length,
 const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const bool acceptSignedMessagesOnly,
 const QString &address,
 const quint16 port,
 spoton_crypt *s_crypt)
{
  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0013(): "
	 "s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));
      bool ok = true;

      if(list.size() == 3)
	{
	  /*
	  ** Gemini?
	  */

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QPair<QByteArray, QByteArray> gemini;

	  if(symmetricKeys.value(0).isEmpty() ||
	     symmetricKeys.value(2).isEmpty())
	    gemini = spoton_misc::findGeminiInCosmos
	      (list.value(0), list.value(1), s_crypt);
	  else
	    {
	      gemini.first = symmetricKeys.value(0);
	      gemini.second = symmetricKeys.value(2);
	    }

	  if(!gemini.first.isEmpty() && !gemini.second.isEmpty())
	    {
	      QByteArray computedHash;
	      QByteArray message(list.value(0));
	      spoton_crypt crypt("aes256",
				 "sha512",
				 QByteArray(),
				 gemini.first,
				 gemini.second,
				 0,
				 0,
				 "");

	      computedHash = crypt.keyedHash(message, &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(1));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      list.clear();
		      message = crypt.decrypted(message, &ok);

		      if(ok)
			{
			  QByteArray a;
			  QDataStream stream(&message, QIODevice::ReadOnly);

			  stream >> a; // Message Type

			  if(stream.status() == QDataStream::Ok)
			    {
			      stream >> a; // Message

			      if(stream.status() == QDataStream::Ok)
				list = a.split('\n');
			    }
			}

		      if(list.size() != 3)
			{
			  spoton_misc::logError
			    (QString("spoton_receive::process0013(): "
				     "received irregular data. "
				     "Expecting 3 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return QList<QByteArray> ();
			}
		    }
		  else
		    {
		      spoton_misc::logError("spoton_receive::"
					    "process0013(): "
					    "computed message code does "
					    "not match provided code.");
		      return QList<QByteArray> ();
		    }
		}
	    }
	  else
	    return QList<QByteArray> (); /*
					 ** A gemini was not discovered.
					 ** We need to echo.
					 */
	}
      else if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0013(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hashKey;
      QByteArray hashKeyAlgorithm;
      QByteArray keyInformation(list.value(0));
      QByteArray originalKeyInformation(keyInformation);
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QDataStream stream(&keyInformation, QIODevice::ReadOnly);
	  QList<QByteArray> list;

	  for(int i = 0; i < 5; i++)
	    {
	      QByteArray a;

	      stream >> a;

	      if(stream.status() != QDataStream::Ok)
		{
		  list.clear();
		  break;
		}
	      else
		list << a;
	    }

	  if(!list.isEmpty())
	    list.removeAt(0); // Message Type

	  if(list.size() == 4)
	    {
	      hashKey = list.value(1);
	      hashKeyAlgorithm = list.value(3);
	      symmetricKey = list.value(0);
	      symmetricKeyAlgorithm = list.value(2);
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_receive::process0013(): "
			 "received irregular data. "
			 "Expecting 4 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return QList<QByteArray> ();
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash
	    (originalKeyInformation + data, hashKey, hashKeyAlgorithm, &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     hashKeyAlgorithm,
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     "");

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QDataStream stream(&data, QIODevice::ReadOnly);
		      QList<QByteArray> list;

		      for(int i = 0; i < 5; i++)
			{
			  QByteArray a;

			  stream >> a;

			  if(stream.status() != QDataStream::Ok)
			    {
			      list.clear();
			      break;
			    }
			  else
			    list << a;
			}

		      if(list.size() == 5)
			{
			  if(spoton_misc::
			     isAcceptedParticipant(list.value(0),
						   "chat",
						   s_crypt) ||
			     spoton_misc::
			     isAcceptedParticipant(list.value(0),
						   "poptastic",
						   s_crypt))
			    {
			      if(acceptSignedMessagesOnly)
				{
				  QByteArray recipientDigest;
				  bool ok = true;

				  recipientDigest = s_crypt->publicKey(&ok);

				  if(ok)
				    recipientDigest = spoton_crypt::
				      sha512Hash(recipientDigest, &ok);

				  if(!ok ||
				     !spoton_misc::
				     isValidSignature("0013" +
						      symmetricKey +
						      hashKey +
						      symmetricKeyAlgorithm +
						      hashKeyAlgorithm +
						      list.value(0) +
						      list.value(1) +
						      list.value(2) +
						      list.value(3) +
						      recipientDigest,
						      list.value(0),
						      list.value(4),
						      s_crypt))
				    {
				      spoton_misc::logError
					("spoton_receive::"
					 "process0013(): invalid "
					 "signature.");
				      return QList<QByteArray> ();
				    }
				}

			      return list;
			    }
			}
		      else
			spoton_misc::logError
			  (QString("spoton_receive::process0013(): "
				   "received irregular data. "
				   "Expecting 5 "
				   "entries, "
				   "received %1.").arg(list.size()));
		    }
		}
	      else
		spoton_misc::logError("spoton_receive::process0013(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0013(): 0013 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(address).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0091
(int length,
 const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const QString &address,
 const quint16 port,
 const QString &messageType)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0091(): s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0091(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      bool ok = true;
      spoton_crypt crypt(symmetricKeys.value(1).constData(),
			 symmetricKeys.value(3).constData(),
			 QByteArray(),
			 symmetricKeys.value(0),
			 symmetricKeys.value(2),
			 0,
			 0,
			 "");

      computedHash = spoton_crypt::keyedHash
	(list.value(0) + list.value(1),
	 symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(2));

	  if(computedHash.isEmpty() || messageCode.isEmpty() ||
	     !spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      spoton_misc::logError
		("spoton_receive::"
		 "process0091(): "
		 "computed message code does "
		 "not match provided code.");
	      return QList<QByteArray> ();
	    }
	}
      else
	return QList<QByteArray> ();

      data = crypt.decrypted(list.value(1), &ok);

      if(!ok)
	return QList<QByteArray> ();

      QDataStream stream(&data, QIODevice::ReadOnly);

      list.clear();

      for(int i = 0; i < 4; i++)
	{
	  QByteArray a;

	  stream >> a;

	  if(stream.status() != QDataStream::Ok)
	    {
	      list.clear();
	      break;
	    }
	  else
	    list << a;
	}

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0091(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      QString keyType
	(spoton_misc::keyTypeFromPublicKeyHash(list.value(0), s_crypt));

      if(!(keyType == "chat" || keyType == "email" ||
	   keyType == "open-library" || keyType == "poptastic" ||
	   keyType == "url"))
	{
	  spoton_misc::logError("spoton_receive::process0091(): "
				"unexpected key type.");
	  return QList<QByteArray> ();
	}

      if(messageType == "0091a")
	{
	  if(keyType == "chat")
	    {
	      if(!spoton_kernel::setting("gui/allowChatFSRequest",
					 true).toBool())
		return QList<QByteArray> ();
	    }
	  else if(keyType == "email")
	    {
	      if(!spoton_kernel::setting("gui/allowEmailFSRequest",
					 true).toBool())
		return QList<QByteArray> ();
	    }
	  else if(keyType == "poptastic")
	    {
	      if(!(spoton_kernel::setting("gui/allowChatFSRequest",
					  true).toBool() ||
		   spoton_kernel::setting("gui/allowEmailFSRequest",
					  true).toBool()))
		return QList<QByteArray> ();
	    }
	}

      if(!spoton_misc::isAcceptedParticipant(list.value(0), keyType,
					     s_crypt))
	return QList<QByteArray> ();

      bool signatureRequired = true;

      /*
      ** Poptastic messages? Signatures are required!
      */

      if((keyType == "chat" &&
	  !spoton_kernel::setting("gui/chatAcceptSignedMessagesOnly",
				  true).toBool()) ||
	 (keyType == "email" &&
	  !spoton_kernel::setting("gui/emailAcceptSignedMessagesOnly",
				  true).toBool()) ||
	 (keyType == "url" &&
	  !spoton_kernel::setting("gui/urlAcceptSignedMessagesOnly",
				  true).toBool()))
	signatureRequired = false;

      if(signatureRequired)
	{
	  QByteArray recipientDigest;
	  bool ok = true;

	  if(spoton_kernel::s_crypts.value(keyType, 0))
	    recipientDigest = spoton_kernel::s_crypts.value(keyType)->
	      publicKey(&ok);
	  else
	    ok = false;

	  if(ok)
	    recipientDigest = spoton_crypt::sha512Hash(recipientDigest, &ok);

	  if(messageType == "0091a")
	    {
	      if(!ok ||
		 !spoton_misc::isValidSignature("0091a" +
						symmetricKeys.value(0) +
						symmetricKeys.value(2) +
						symmetricKeys.value(1) +
						symmetricKeys.value(3) +
						list.value(0) +
						list.value(1) +
						list.value(2) +
						recipientDigest,
						list.value(0),
						list.value(3), // Signature
						spoton_kernel::s_crypts.
						value(keyType, 0)))
		{
		  spoton_misc::logError
		    ("spoton_receive::process0091(): invalid signature.");
		  return QList<QByteArray> ();
		}
	    }
	  else
	    {
	      if(!ok ||
		 !spoton_misc::isValidSignature("0091b" +
						symmetricKeys.value(0) +
						symmetricKeys.value(2) +
						symmetricKeys.value(1) +
						symmetricKeys.value(3) +
						list.value(0) +
						list.value(1) +
						list.value(2) +
						recipientDigest,
						list.value(0),
						list.value(3), // Signature
						spoton_kernel::s_crypts.
						value(keyType, 0)))
		{
		  spoton_misc::logError
		    ("spoton_receive::process0091(): invalid signature.");
		  return QList<QByteArray> ();
		}
	    }
	}

      QDateTime dateTime
	(QDateTime::fromString(list.value(2).constData(), "MMddyyyyhhmmss"));
      QDateTime now(QDateTime::currentDateTimeUtc());

      dateTime.setTimeSpec(Qt::UTC);
      now.setTimeSpec(Qt::UTC);

      int timeDelta = 0;
      qint64 secsTo = qAbs(now.secsTo(dateTime));

      if(keyType == "chat" || keyType == "email" || keyType == "url")
	timeDelta = spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM;
      else
	timeDelta =
	  spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM;

      if(!(secsTo <= static_cast<qint64> (timeDelta)))
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0091(): "
		     "large time delta (%1).").arg(secsTo));
	  return QList<QByteArray> ();
	}

      if(messageType == "0091a")
	return QList<QByteArray> () << keyType.toLatin1()
				    << list.value(0)
				    << list.value(1);
      else
	return QList<QByteArray> () << list.value(0)
				    << list.value(1);
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0091(): %1 "
	       "Content-Length mismatch (advertised: %2, received: %3) "
	       "for %4:%5.").
       arg(messageType).
       arg(length).arg(data.length()).
       arg(address).
       arg(port));

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_receive::process0092
(int length,
 const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const QString &address,
 const quint16 port)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::process0092(): s_crypt is zero.");
      return QList<QByteArray> ();
    }

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0092(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      bool ok = true;
      spoton_crypt crypt(symmetricKeys.value(1).constData(),
			 symmetricKeys.value(3).constData(),
			 QByteArray(),
			 symmetricKeys.value(0),
			 symmetricKeys.value(2),
			 0,
			 0,
			 "");

      computedHash = spoton_crypt::keyedHash
	(list.value(0) + list.value(1),
	 symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(2));

	  if(computedHash.isEmpty() || messageCode.isEmpty() ||
	     !spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      spoton_misc::logError
		("spoton_receive::"
		 "process0092(): "
		 "computed message code does "
		 "not match provided code.");
	      return QList<QByteArray> ();
	    }
	}
      else
	return QList<QByteArray> ();

      data = crypt.decrypted(list.value(1), &ok);

      if(!ok)
	return QList<QByteArray> ();

      QDataStream stream(&data, QIODevice::ReadOnly);

      list.clear();

      for(int i = 0; i < 4; i++)
	{
	  QByteArray a;

	  stream >> a;

	  if(stream.status() != QDataStream::Ok)
	    {
	      list.clear();
	      break;
	    }
	  else
	    list << a;
	}

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0092(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return QList<QByteArray> ();
	}

      QString keyType
	(spoton_misc::keyTypeFromPublicKeyHash(list.value(0), s_crypt));

      if(!(keyType == "chat" || keyType == "email" ||
	   keyType == "open-library" || keyType == "poptastic" ||
	   keyType == "rosetta" || keyType == "url"))
	{
	  spoton_misc::logError
	    ("spoton_receive::process0092(): unexpected key type.");
	  return QList<QByteArray> ();
	}

      if(!spoton_misc::isAcceptedParticipant(list.value(0), keyType, s_crypt))
	return QList<QByteArray> ();

      QByteArray recipientDigest;

      if(spoton_kernel::s_crypts.value(keyType, 0))
	recipientDigest = spoton_kernel::s_crypts.value(keyType)->
	  publicKey(&ok);
      else
	ok = false;

      if(ok)
	recipientDigest = spoton_crypt::sha512Hash(recipientDigest, &ok);

      if(!ok ||
	 !spoton_misc::isValidSignature("0092" +
					symmetricKeys.value(0) +
					symmetricKeys.value(2) +
					symmetricKeys.value(1) +
					symmetricKeys.value(3) +
					list.value(0) +
					list.value(1) +
					list.value(2) +
					recipientDigest,
					list.value(0),
					list.value(3), // Signature
					spoton_kernel::s_crypts.
					value(keyType, 0)))
	{
	  spoton_misc::logError
	    ("spoton_receive::process0092(): invalid signature.");
	  return QList<QByteArray> ();
	}

      QDateTime dateTime
	(QDateTime::fromString(list.value(2).constData(), "MMddyyyyhhmmss"));
      QDateTime now(QDateTime::currentDateTimeUtc());

      dateTime.setTimeSpec(Qt::UTC);
      now.setTimeSpec(Qt::UTC);

      int timeDelta = spoton_common::SMP_TIME_DELTA_MAXIMUM;
      qint64 secsTo = qAbs(now.secsTo(dateTime));

      if(!(secsTo <= static_cast<qint64> (timeDelta)))
	{
	  spoton_misc::logError
	    (QString("spoton_receive::process0092(): "
		     "large time delta (%1).").arg(secsTo));
	  return QList<QByteArray> ();
	}

      return QList<QByteArray> () << list.value(0)
				  << list.value(1);
    }
  else
    spoton_misc::logError
      (QString("spoton_receive::process0092(): "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).
       arg(data.length()).
       arg(address).
       arg(port));

  return QList<QByteArray> ();
}

QString spoton_receive::findMessageType
(const QByteArray &data,
 QList<QByteArray> &symmetricKeys,
 const int interfaces,
 const QString &keyType,
 spoton_crypt *s_crypt)
{
  Q_UNUSED(interfaces);

  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_receive::findMessageType(): s_crypt is zero.");
      return "";
    }

  QList<QByteArray> list(data.trimmed().split('\n'));
  QString type("");

  /*
  ** list[0]: Data
  ** ...
  ** list[list.size - 1]: Adaptive Echo Data
  ** symmetricKeys[0]: Encryption Key
  ** symmetricKeys[1]: Encryption Type
  ** symmetricKeys[2]: Hash Key
  ** symmetricKeys[3]: Hash Type
  */

  if(list.size() == 4)
    {
      QByteArray data;
      bool ok = true;

      data = s_crypt->publicKeyDecrypt
	(QByteArray::fromBase64(list.value(0)), &ok);

      if(ok)
	{
	  QByteArray a;
	  QDataStream stream(&data, QIODevice::ReadOnly);

	  stream >> a;

	  if(stream.status() == QDataStream::Ok)
	    type = a;

	  if(type == "0091a" || type == "0091b" || type == "0092")
	    {
	      QList<QByteArray> list;

	      for(int i = 0; i < 4; i++)
		{
		  stream >> a;

		  if(stream.status() != QDataStream::Ok)
		    {
		      list.clear();
		      type.clear();
		      break;
		    }
		  else
		    list.append(a);
		}

	      if(!type.isEmpty())
		{
		  symmetricKeys.append(list.value(0));
		  symmetricKeys.append(list.value(2));
		  symmetricKeys.append(list.value(1));
		  symmetricKeys.append(list.value(3));
		  goto done_label;
		}
	    }
	  else
	    type.clear();
	}
    }

  if(list.size() == 3 &&
     spoton_misc::participantCount("poptastic", s_crypt) > 0)
    {
      QPair<QByteArray, QByteArray> gemini;

      gemini = spoton_misc::findGeminiInCosmos
	(QByteArray::fromBase64(list.value(0)),
	 QByteArray::fromBase64(list.value(1)),
	 s_crypt);

      if(!gemini.first.isEmpty())
	{
	  QByteArray data;
	  bool ok = true;
	  spoton_crypt crypt("aes256",
			     "sha512",
			     QByteArray(),
			     gemini.first,
			     0,
			     0,
			     "");

	  data = crypt.decrypted
	    (QByteArray::fromBase64(list.value(0)), &ok);

	  if(ok)
	    {
	      QByteArray a;
	      QDataStream stream(&data, QIODevice::ReadOnly);

	      stream >> a;

	      if(stream.status() == QDataStream::Ok)
		type = a;
	    }

	  if(!type.isEmpty())
	    {
	      symmetricKeys.append(gemini.first);
	      symmetricKeys.append("aes256");
	      symmetricKeys.append(gemini.second);
	      symmetricKeys.append("sha512");
	      goto done_label;
	    }
	  else
	    symmetricKeys.clear();
	}
      else
	symmetricKeys.clear();
    }

  if(list.size() == 4)
    if(!spoton_misc::allParticipantsHaveGeminis())
      if(spoton_misc::participantCount("poptastic", s_crypt) > 0)
	{
	  QByteArray data;
	  bool ok = true;

	  data = s_crypt->publicKeyDecrypt
	    (QByteArray::fromBase64(list.value(0)), &ok);

	  if(ok)
	    {
	      QByteArray a;
	      QDataStream stream(&data, QIODevice::ReadOnly);

	      stream >> a;

	      if(stream.status() == QDataStream::Ok)
		type = a;
	      else
		type.clear();
	    }

	  if(!type.isEmpty())
	    goto done_label;
	}

  if(list.size() == 4 || list.size() == 7)
    if(spoton_misc::participantCount(keyType, s_crypt) > 0)
      {
	QByteArray data;
	bool ok = true;

	data = s_crypt->publicKeyDecrypt
	  (QByteArray::fromBase64(list.value(0)), &ok);

	if(ok)
	  type = QByteArray::fromBase64(data.split('\n').value(0));

	if(!type.isEmpty())
	  {
	    if(type == "0001b")
	      {
		QList<QByteArray> list(data.split('\n'));

		for(int i = 0; i < list.size(); i++)
		  list.replace(i, QByteArray::fromBase64(list.at(i)));

		symmetricKeys.append(list.value(1));
		symmetricKeys.append(list.value(3));
		symmetricKeys.append(list.value(2));
		symmetricKeys.append(list.value(4));
	      }
	    else
	      symmetricKeys.clear();

	    goto done_label;
	  }
	else
	  symmetricKeys.clear();
      }

  if(list.size() == 3 && (s_crypt =
			  spoton_kernel::s_crypts.value(keyType, 0)))
    symmetricKeys = spoton_misc::findForwardSecrecyKeys
      (QByteArray::fromBase64(list.value(0)),
       QByteArray::fromBase64(list.value(1)),
       type,
       s_crypt);

 done_label:
  return type;
}
