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

#include <QDir>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlRecord>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-reencode.h"

spoton_reencode::spoton_reencode(void)
{
}

spoton_reencode::~spoton_reencode()
{
}

void spoton_reencode::reencode(Ui_spoton_statusbar sb,
			       spoton_crypt *newCrypt,
			       spoton_crypt *oldCrypt)
{
  if(!newCrypt || !oldCrypt)
    return;

  QString connectionName("");

  sb.status->setText(QObject::tr("Re-encoding buzz_channels.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "buzz_channels.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT data, " // 0
		      "data_hash "    // 1
		      "FROM buzz_channels"))
	  while(query.next())
	    {
	      QByteArray data;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE buzz_channels "
				  "SET data = ?, "
				  "data_hash = ? WHERE "
				  "data_hash = ?");
	      data = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(data, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(data, &ok).toBase64());

	      updateQuery.bindValue(2, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding buzz_channels error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM buzz_channels WHERE "
				      "data_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding echo_key_sharing_secrets.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() +
       QDir::separator() +
       "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT "
		      "category, " // 0
		      "OID "       // 1
		      "FROM categories"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      bytes = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
	      updateQuery.prepare("UPDATE categories "
				  "SET category = ?, "
				  "category_hash = ? "
				  "WHERE OID = ?");

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(bytes, &ok).toBase64());

	      updateQuery.bindValue
		(2, query.value(query.record().count() - 1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding categories error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM categories WHERE OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT "
		      "accept, "              // 0
		      "authentication_key, "  // 1
		      "cipher_type, "         // 2
		      "encryption_key, "      // 3
		      "hash_type, "           // 4
		      "iteration_count, "     // 5
		      "name, "                // 6
		      "share, "               // 7
		      "signatures_required, " // 8
		      "category_oid, "        // 9
		      "OID "                  // 10
		      "FROM echo_key_sharing_secrets"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      auto ok = true;

	      for(int i = 0; i < query.record().count() - 2; i++)
		{
		  QByteArray bytes;

		  bytes = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(i).toByteArray()), &ok);

		  if(ok)
		    list.append(bytes);
		  else
		    break;
		}

	      if(ok)
		if(!list.isEmpty())
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare
		      ("UPDATE echo_key_sharing_secrets SET "
		       "accept = ?, "
		       "authentication_key = ?, "
		       "cipher_type = ?, "
		       "encryption_key = ?, "
		       "hash_type = ?, "
		       "iteration_count = ?, "
		       "name = ?, "
		       "share = ?, "
		       "signatures_required = ?, "
		       "name_hash = ? "
		       "WHERE OID = ?");

		    for(int i = 0; i < list.size(); i++)
		      if(ok)
			updateQuery.bindValue
			  (i, newCrypt->
			   encryptedThenHashed(list.value(i), &ok).
			   toBase64());

		    if(ok)
		      updateQuery.bindValue
			(9, newCrypt->keyedHash(list.value(6), &ok).
			 toBase64());

		    updateQuery.bindValue
		      (10, query.value(query.record().count() - 1));

		    if(ok)
		      updateQuery.exec();
		  }

	      if(!ok)
		{
		  spoton_misc::logError
		    ("Re-encoding echo_key_sharing_secrets error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM echo_key_sharing_secrets "
				      "WHERE category_oid = ? AND "
				      "OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 2));
		  deleteQuery.bindValue
		    (1, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding email.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT date, "     // 0
		      "from_account, "    // 1
		      "goldbug, "         // 2
		      "message, "         // 3
		      "message_code, "    // 4
		      "mode, "            // 5
		      "participant_oid, " // 6
		      "receiver_sender, " // 7
		      "sign, "            // 8
		      "signature, "       // 9
		      "status, subject, " // 10
		      "OID "              // 11
		      "FROM folders"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      auto ok = true;

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  QByteArray bytes;

		  if(!query.isNull(i))
		    bytes = oldCrypt->decryptedAfterAuthenticated
		      (QByteArray::
		       fromBase64(query.value(i).toByteArray()), &ok);

		  if(ok)
		    list.append(bytes);
		  else
		    break;
		}

	      if(ok)
		if(!list.isEmpty())
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare("UPDATE folders SET "
					"date = ?, "            // 0
					"from_account = ?, "    // 1
					"goldbug = ?, "         // 2
					"message = ?, "         // 3
					"message_code = ?, "    // 4
					"mode = ?, "            // 5
					"participant_oid = ?, " // 6
					"receiver_sender = ?, " // 7
					"sign = ?, "            // 8
					"signature = ?, "       // 9
					"status = ?, "          // 10
					"subject = ?, "         // 11
					"hash = ? "             // 12
					"WHERE OID = ?");       // 13

		    for(int i = 0; i < list.size(); i++)
		      if(ok)
			updateQuery.bindValue
			  (i, newCrypt->encryptedThenHashed(list.at(i),
							    &ok).
			   toBase64());
		      else
			break;

		    if(ok)
		      updateQuery.bindValue
			/*
			** date + message + subject
			*/

			(12, newCrypt->keyedHash(list.value(0) +
						 list.value(3) +
						 list.value(11), &ok).
			 toBase64());

		    if(ok)
		      {
			updateQuery.bindValue
			  (13, query.value(query.record().count() - 1));
			updateQuery.exec();
		      }
		    else
		      {
			spoton_misc::logError
			  ("Re-encoding folders error.");

			QSqlQuery deleteQuery(db);

			deleteQuery.exec("PRAGMA secure_delete = ON");
			deleteQuery.prepare("DELETE FROM folders WHERE "
					    "OID = ?");
			deleteQuery.bindValue
			  (0, query.value(query.record().count() - 1));
			deleteQuery.exec();
			deleteQuery.prepare
			  ("DELETE FROM folders_attachment WHERE "
			   "folders_oid = ?");
			deleteQuery.bindValue
			  (0, query.value(query.record().count() - 1));
			deleteQuery.exec();
		      }
		  }
	    }

	if(query.exec("SELECT data, " // 0
		      "name, "        // 1
		      "OID "          // 2
		      "FROM folders_attachment"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      auto ok = true;

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  QByteArray bytes;

		  bytes = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.value(i).toByteArray()), &ok);

		  if(ok)
		    list.append(bytes);
		  else
		    break;
		}

	      if(ok)
		if(!list.isEmpty())
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare("UPDATE folders_attachment SET "
					"data = ?, "
					"name = ? "
					"WHERE OID = ?");

		    for(int i = 0; i < list.size(); i++)
		      if(ok)
			updateQuery.bindValue
			  (i, newCrypt->encryptedThenHashed(list.at(i),
							    &ok).
			   toBase64());
		      else
			break;

		    updateQuery.bindValue
		      (2, query.value(2));

		    if(ok)
		      updateQuery.exec();
		    else
		      {
			spoton_misc::logError
			  ("Re-encoding folders_attachment error.");

			QSqlQuery deleteQuery(db);

			deleteQuery.exec("PRAGMA secure_delete = ON");
			deleteQuery.prepare
			  ("DELETE FROM folders_attachment WHERE OID = ?");
			deleteQuery.bindValue
			  (0, query.value(query.record().count() - 1));
			deleteQuery.exec();
		      }
		  }
	    }

	if(query.exec("SELECT cipher_type, " // 0
		      "hash_type, "          // 1
		      "name, "               // 2
		      "postal_address, "     // 3
		      "OID "                 // 4
		      "FROM institutions"))
	  while(query.next())
	    {
	      QByteArray cipherType;
	      QByteArray hashType;
	      QByteArray name;
	      QByteArray postalAddress;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE institutions "
				  "SET "
				  "cipher_type = ?, "
				  "hash_type = ?, "
				  "name = ?, "
				  "postal_address = ?, "
				  "hash = ? "
				  "WHERE "
				  "OID = ?");
	      cipherType = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		hashType = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		name = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		postalAddress = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(cipherType,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(hashType,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(name,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(postalAddress,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->keyedHash(name,
					  &ok).toBase64());

	      updateQuery.bindValue(5, query.value(4));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding institutions error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM institutions WHERE OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT date_received, " // 0
		      "message_bundle, "       // 1
		      "participant_hash, "     // 2
		      "OID "                   // 3
		      "FROM post_office"))
	  while(query.next())
	    {
	      QByteArray dateReceived;
	      QByteArray messageBundle;
	      QByteArray participantHash;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE post_office "
				  "SET date_received = ?, "
				  "message_bundle = ?, "
				  "message_bundle_hash = ?, "
				  "participant_hash = ? "
				  "WHERE "
				  "OID = ?");
	      dateReceived = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		messageBundle = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		participantHash = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(dateReceived,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(messageBundle,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->keyedHash(messageBundle,
					  &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(participantHash,
						    &ok).toBase64());

	      updateQuery.bindValue(4, query.value(3));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding post_office error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM post_office WHERE OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding friends_public_keys.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT gemini, gemini_hash_key, "
		      "public_key_hash, "
		      "public_key, key_type, name, "
		      "forward_secrecy_authentication_algorithm, "
		      "forward_secrecy_authentication_key, "
		      "forward_secrecy_encryption_algorithm, "
		      "forward_secrecy_encryption_key "
		      "FROM "
		      "friends_public_keys WHERE neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray fsAuthAlg;
	      QByteArray fsAuthKey;
	      QByteArray fsEncAlg;
	      QByteArray fsEncKey;
	      QByteArray gemini;
	      QByteArray geminiHashKey;
	      QByteArray keyType;
	      QByteArray name;
	      QByteArray publicKey;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare
		("UPDATE friends_public_keys "
		 "SET gemini = ?, "
		 "gemini_hash_key = ?, "
		 "public_key = ?, "
		 "key_type = ?, "
		 "key_type_hash = ?, "
		 "name = ?, "
		 "forward_secrecy_authentication_algorithm = ?, "
		 "forward_secrecy_authentication_key = ?, "
		 "forward_secrecy_encryption_algorithm = ?, "
		 "forward_secrecy_encryption_key = ? "
		 "WHERE public_key_hash = ?");

	      if(!query.isNull(0))
		gemini = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()),
		   &ok);

	      if(ok)
		if(!query.isNull(1))
		  geminiHashKey = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(1).toByteArray()),
		     &ok);

	      if(ok)
		publicKey = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(ok)
		keyType = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(4).toByteArray()),
		   &ok);

	      if(ok)
		name = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(5).toByteArray()),
		   &ok);

	      if(ok)
		if(!query.isNull(6))
		  fsAuthAlg = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(6).toByteArray()),
		     &ok);

	      if(ok)
		if(!query.isNull(7))
		  fsAuthKey = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(7).toByteArray()),
		     &ok);

	      if(ok)
		if(!query.isNull(8))
		  fsEncAlg = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(8).toByteArray()),
		     &ok);

	      if(ok)
		if(!query.isNull(9))
		  fsEncKey = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(9).toByteArray()),
		     &ok);

	      if(ok)
		{
		  if(query.isNull(0))
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (0, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(0, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (0, newCrypt->encryptedThenHashed(gemini,
							&ok).toBase64());
		}

	      if(ok)
		{
		  if(query.isNull(1))
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (1, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(1, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (1,
		       newCrypt->encryptedThenHashed(geminiHashKey,
						     &ok).toBase64());
		}

	      if(ok)
		updateQuery.bindValue
		  (2,
		   newCrypt->encryptedThenHashed(publicKey,
						 &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3,
		   newCrypt->encryptedThenHashed(keyType,
						 &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4,
		   newCrypt->keyedHash(keyType, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (5, newCrypt->encryptedThenHashed(name, &ok).toBase64());

	      if(ok)
		{
		  if(query.isNull(6))
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (6, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(6, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (6, newCrypt->encryptedThenHashed(fsAuthAlg, &ok).
		       toBase64());
		}

	      if(ok)
		{
		  if(query.isNull(7))
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (7, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(7, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (7, newCrypt->encryptedThenHashed(fsAuthKey, &ok).
		       toBase64());
		}

	      if(ok)
		{
		  if(query.isNull(8))
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (8, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(8, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (8, newCrypt->encryptedThenHashed(fsEncAlg, &ok).
		       toBase64());
		}

	      if(ok)
		{
		  if(query.isNull(9))
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (9, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(9, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (9, newCrypt->encryptedThenHashed(fsEncKey, &ok).
		       toBase64());
		}

	      updateQuery.bindValue
		(10, query.value(2));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError
		    ("Re-encoding friends_public_keys error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM friends_public_keys "
				      "WHERE public_key_hash = ?");
		  deleteQuery.bindValue(0, query.value(2));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT email, "     // 0
		      "public_keys, "      // 1
		      "public_keys_hash, " // 2
		      "OID "               // 3
		      "FROM gpg"))
	  while(query.next())
	    {
	      QByteArray email;
	      QByteArray fingerprint;
	      QByteArray publicKeys;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      email = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		publicKeys = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()), &ok);

	      if(ok)
		fingerprint = spoton_crypt::fingerprint(publicKeys);

	      updateQuery.prepare
		("UPDATE gpg SET "
		 "email = ?, "
		 "public_keys = ?, "
		 "public_keys_hash = ? "
		 "WHERE public_keys_hash = ?");

	      if(ok)
		updateQuery.addBindValue
		  (newCrypt->encryptedThenHashed(email, &ok).toBase64());

	      if(ok)
		updateQuery.addBindValue
		  (newCrypt->encryptedThenHashed(publicKeys, &ok).toBase64());

	      if(ok)
		updateQuery.addBindValue
		  (newCrypt->keyedHash(fingerprint, &ok).toBase64());

	      if(ok)
		updateQuery.addBindValue(query.value(2));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding gpg error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM gpg WHERE OID = ?");
		  deleteQuery.bindValue(0, query.value(3));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding kernel_web_server.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() +
		       QDir::separator() +
		       "kernel_web_server.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT certificate, "
		      "private_key, "
		      "OID "
		      "FROM kernel_web_server"))
	  while(query.next())
	    {
	      QByteArray data;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE kernel_web_server "
				  "SET certificate = ?, "
				  "private_key = ? WHERE "
				  "OID = ?");
	      data = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(data, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(data, &ok).toBase64());

	      updateQuery.bindValue
		(2, query.value(2));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError
		    ("Re-encoding kernel_web_server error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare
		    ("DELETE FROM kernel_web_server WHERE OID = ?");
		  deleteQuery.bindValue(0, query.value(2));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding listeners.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT ip_address, "
		      "port, "
		      "scope_id, "
		      "protocol, "
		      "echo_mode, "
		      "certificate, "
		      "private_key, "
		      "public_key, "
		      "transport, "
		      "orientation, "
		      "private_application_credentials, "
		      "hash FROM listeners"))
	  while(query.next())
	    {
	      QByteArray certificate;
	      QByteArray privateKey;
	      QByteArray publicKey;
	      QSqlQuery updateQuery(db);
	      QString echoMode("");
	      QString ipAddress("");
	      QString orientation("");
	      QString port("");
	      QString privateApplicationCredentials("");
	      QString protocol("");
	      QString scopeId("");
	      QString transport("");
	      auto ok = true;

	      updateQuery.prepare("UPDATE listeners "
				  "SET ip_address = ?, "
				  "port = ?, "
				  "scope_id = ?, "
				  "protocol = ?, "
				  "hash = ?, "
				  "echo_mode = ?, "
				  "certificate = ?, "
				  "private_key = ?, "
				  "public_key = ?, "
				  "transport = ?, "
				  "orientation = ?, "
				  "private_application_credentials = ? "
				  "WHERE hash = ?");
	      ipAddress = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		port = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()), &ok);

	      if(ok)
		scopeId = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()), &ok);

	      if(ok)
		protocol = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()), &ok);

	      if(ok)
		echoMode = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(4).toByteArray()), &ok);

	      if(ok)
		certificate = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(5).toByteArray()), &ok);

	      if(ok)
		privateKey = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(6).toByteArray()), &ok);

	      if(ok)
		publicKey = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(7).toByteArray()), &ok);

	      if(ok)
		transport = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(8).toByteArray()), &ok);

	      if(ok)
		orientation = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(9).toByteArray()), &ok);

	      if(ok)
		if(!query.isNull(10))
		  privateApplicationCredentials = oldCrypt->
		    decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(10).toByteArray()),
		     &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed
		   (ipAddress.
		    toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(port.toLatin1(),
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(scopeId.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(protocol.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->keyedHash((ipAddress + port + scopeId +
					   transport).
					  toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (5, newCrypt->
		   encryptedThenHashed(echoMode.toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (6, newCrypt->encryptedThenHashed(certificate,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (7, newCrypt->encryptedThenHashed(privateKey,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (8, newCrypt->encryptedThenHashed(publicKey,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (9, newCrypt->encryptedThenHashed(transport.toLatin1(),
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (10, newCrypt->encryptedThenHashed(orientation.toLatin1(),
						     &ok).toBase64());

	      if(ok)
		{
		  if(privateApplicationCredentials.isEmpty())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (11, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(11, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (11, newCrypt->
		       encryptedThenHashed(privateApplicationCredentials.
					   toLatin1(), &ok).toBase64());
		}

	      updateQuery.bindValue(12, query.value(11));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding listeners error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM listeners WHERE "
				      "hash = ?");
		  deleteQuery.bindValue(0, query.value(11));
		  deleteQuery.exec();
		  deleteQuery.exec("DELETE FROM listeners_accounts "
				   "WHERE listener_oid NOT IN "
				   "(SELECT OID FROM listeners)");
		  deleteQuery.exec("DELETE FROM listeners_allowed_ips "
				   "WHERE listener_oid NOT IN "
				   "(SELECT OID FROM listeners)");
		}
	    }

	if(query.exec("SELECT account_name, account_name_hash, "
		      "account_password, listener_oid "
		      "FROM listeners_accounts"))
	  while(query.next())
	    {
	      QByteArray name;
	      QByteArray password;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE listeners_accounts "
				  "SET account_name = ?, "
				  "account_name_hash = ?, "
				  "account_password = ? "
				  "WHERE account_name_hash = ? AND "
				  "listener_oid = ?");
	      name = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		password = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()), &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(name, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(name, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(password, &ok).toBase64());

	      updateQuery.bindValue(3, query.value(1));
	      updateQuery.bindValue(4, query.value(3));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError
		    ("Re-encoding listeners_accounts error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM listeners_accounts WHERE "
				      "account_name_hash = ? AND "
				      "listener_oid = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.bindValue(1, query.value(3));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT token, token_hash, token_type "
		      "FROM listeners_adaptive_echo_tokens"))
	  while(query.next())
	    {
	      QByteArray token;
	      QByteArray tokenType;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE listeners_adaptive_echo_tokens "
				  "SET token = ?, "
				  "token_hash = ?, "
				  "token_type = ? "
				  "WHERE token_hash = ?");
	      token = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		tokenType = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()), &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(token, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(token + tokenType,
					  &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(tokenType,
						    &ok).toBase64());

	      updateQuery.bindValue(3, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError
		    ("Re-encoding listeners_adaptive_echo_tokens error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare
		    ("DELETE FROM listeners_adaptive_echo_tokens WHERE "
		     "token_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT ip_address, ip_address_hash, "
		      "listener_oid "
		      "FROM listeners_allowed_ips"))
	  while(query.next())
	    {
	      QByteArray ip;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE listeners_allowed_ips "
				  "SET ip_address = ?, "
				  "ip_address_hash = ? "
				  "WHERE ip_address_hash = ? AND "
				  "listener_oid = ?");
	      ip = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(ip, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(ip, &ok).toBase64());

	      updateQuery.bindValue(2, query.value(1));
	      updateQuery.bindValue(3, query.value(2));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError
		    ("Re-encoding listeners_allowed_ips error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM listeners_allowed_ips "
				      "WHERE "
				      "ip_address_hash = ? AND "
				      "listener_oid = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.bindValue(1, query.value(2));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding neighbors.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, remote_port, "
		      "scope_id, country, hash, proxy_hostname, "
		      "proxy_password, proxy_port, proxy_type, "
		      "proxy_username, uuid, "
		      "echo_mode, certificate, protocol, "
		      "account_name, account_password, transport, "
		      "orientation, ae_token, ae_token_type, "
		      "private_application_credentials, bind_ip_address "
		      "FROM neighbors"))
	  while(query.next())
	    {
	      QByteArray peerCertificate;
	      QByteArray uuid;
	      QSqlQuery updateQuery(db);
	      QString accountName("");
	      QString accountPassword("");
	      QString aeToken("");
	      QString aeTokenType("");
	      QString bindIpAddress("");
	      QString country("");
	      QString echoMode("");
	      QString ipAddress("");
	      QString orientation("");
	      QString port("");
	      QString privateApplicationCredentials("");
	      QString protocol("");
	      QString proxyHostName("");
	      QString proxyPassword("");
	      QString proxyPort("1");
	      QString proxyType("");
	      QString proxyUsername("");
	      QString scopeId("");
	      QString transport("");
	      auto ok = true;

	      updateQuery.prepare("UPDATE neighbors "
				  "SET remote_ip_address = ?, "
				  "remote_port = ?, "
				  "scope_id = ?, "
				  "country = ?, "
				  "hash = ?, "
				  "remote_ip_address_hash = ?, "
				  "qt_country_hash = ?, "
				  "proxy_hostname = ?, "
				  "proxy_password = ?, "
				  "proxy_port = ?, "
				  "proxy_type = ?, "
				  "proxy_username = ?, "
				  "uuid = ?, "
				  "echo_mode = ?, "
				  "certificate = ?, "
				  "protocol = ?, "
				  "ssl_session_cipher = NULL, "
				  "account_name = ?, "
				  "account_password = ?, "
				  "account_authenticated = NULL, "
				  "transport = ?, "
				  "orientation = ?, "
				  "ae_token = ?, "
				  "ae_token_type = ?, "
				  "private_application_credentials = ?, "
				  "bind_ip_address = ? "
				  "WHERE hash = ?");
	      ipAddress = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		port = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()), &ok);

	      if(ok)
		scopeId = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()), &ok);

	      if(ok)
		country = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()), &ok);

	      if(ok)
		proxyHostName = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(5).toByteArray()), &ok);

	      if(ok)
		proxyPassword = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(6).toByteArray()), &ok);

	      if(ok)
		proxyPort = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(7).toByteArray()), &ok);

	      if(ok)
		proxyType = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(8).toByteArray()), &ok);

	      if(ok)
		proxyUsername = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(9).
			      toByteArray()),
		   &ok);

	      if(ok)
		uuid = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(10).
			      toByteArray()),
		   &ok);

	      if(ok)
		echoMode = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(11).toByteArray()),
		   &ok);

	      if(ok)
		peerCertificate = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(12).
			      toByteArray()),
		   &ok);

	      if(ok)
		protocol = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(13).
			      toByteArray()),
		   &ok);

	      if(ok)
		accountName = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(14).
			      toByteArray()),
		   &ok);

	      if(ok)
		accountPassword = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(15).
			      toByteArray()),
		   &ok);

	      if(ok)
		transport = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(16).
			      toByteArray()),
		   &ok);

	      if(ok)
		orientation = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(17).
			      toByteArray()),
		   &ok);

	      if(ok)
		if(!query.isNull(18))
		  aeToken = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.
				value(18).
				toByteArray()),
		     &ok);

	      if(ok)
		if(!query.isNull(19))
		  aeTokenType = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.
				value(19).
				toByteArray()),
		     &ok);

	      if(ok)
		if(!query.isNull(20))
		  privateApplicationCredentials = oldCrypt->
		    decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(20).toByteArray()),
		     &ok);

	      if(ok)
		if(!query.isNull(21))
		  bindIpAddress = oldCrypt->
		    decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(21).toByteArray()),
		     &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(ipAddress.
						    toLatin1(),
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(port.toLatin1(),
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(scopeId.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(country.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->keyedHash((ipAddress + port + scopeId +
					   transport).toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (5, newCrypt->keyedHash(ipAddress.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (6, newCrypt->keyedHash(country.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (7, newCrypt->
		   encryptedThenHashed(proxyHostName.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (8, newCrypt->encryptedThenHashed(proxyPassword.toUtf8(),
						    &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (9, newCrypt->
		   encryptedThenHashed(proxyPort.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (10, newCrypt->
		   encryptedThenHashed(proxyType.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (11, newCrypt->
		   encryptedThenHashed(proxyUsername.toUtf8(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (12, newCrypt->encryptedThenHashed(uuid, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (13, newCrypt->encryptedThenHashed(echoMode.toLatin1(),
						     &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (14, newCrypt->encryptedThenHashed(peerCertificate, &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (15, newCrypt->
		   encryptedThenHashed(protocol.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (16, newCrypt->encryptedThenHashed
		   (accountName.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (17, newCrypt->
		   encryptedThenHashed(accountPassword.toLatin1(),
				       &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (18, newCrypt->encryptedThenHashed(transport.toLatin1(),
						     &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (19, newCrypt->
		   encryptedThenHashed(orientation.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		{
		  if(aeToken.isEmpty())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (20, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(20, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (20, newCrypt->
		       encryptedThenHashed(aeToken.toLatin1(), &ok).
		       toBase64());
		}

	      if(ok)
		{
		  if(aeTokenType.isEmpty())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (21, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(21, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (21, newCrypt->
		       encryptedThenHashed(aeTokenType.toLatin1(), &ok).
		       toBase64());
		}

	      if(ok)
		{
		  if(privateApplicationCredentials.isEmpty())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (22, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(22, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (22, newCrypt->
		       encryptedThenHashed(privateApplicationCredentials.
					   toLatin1(), &ok).toBase64());
		}

	      if(ok)
		{
		  if(bindIpAddress.isEmpty())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    updateQuery.bindValue
		      (23, QVariant(QMetaType(QMetaType::QString)));
#else
		    updateQuery.bindValue(23, QVariant::String);
#endif
		  else
		    updateQuery.bindValue
		      (23, newCrypt->
		       encryptedThenHashed(bindIpAddress.toLatin1(), &ok).
		       toBase64());
		}

	      updateQuery.bindValue
		(24, query.value(4));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding neighbors error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM neighbors WHERE hash = ?");
		  deleteQuery.bindValue(0, query.value(4));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding poptastic.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT in_method, in_password, in_server_address, "
		      "in_server_port, in_ssltls, in_username, "
		      "in_username_hash, "
		      "in_verify_host, in_verify_peer, "
		      "out_method, out_password, out_server_address, "
		      "out_server_port, out_ssltls, out_username, "
		      "out_verify_host, out_verify_peer, "
		      "proxy_enabled, proxy_password, "
		      "proxy_server_address, proxy_server_port, "
		      "proxy_username, smtp_localname "
		      "FROM poptastic"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      QList<QByteArray> list;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE poptastic "
				  "SET in_method = ?, "
				  "in_password = ?, "
				  "in_server_address = ?, "
				  "in_server_port = ?, "
				  "in_ssltls = ?, "
				  "in_username = ?, "
				  "in_username_hash = ?, "
				  "in_verify_host = ?, "
				  "in_verify_peer = ?, "
				  "out_method = ?, "
				  "out_password = ?, "
				  "out_server_address = ?, "
				  "out_server_port = ?, "
				  "out_ssltls = ?, "
				  "out_username = ?, "
				  "out_verify_host = ?, "
				  "out_verify_peer = ?, "
				  "proxy_enabled = ?, "
				  "proxy_password = ?, "
				  "proxy_server_address = ?, "
				  "proxy_server_port = ?, "
				  "proxy_username = ?, "
				  "smtp_localname = ? WHERE "
				  "in_username_hash = ?");

	      for(int i = 0; i < query.record().count(); i++)
		{
		  if(i == 6)
		    {
		      list << QByteArray::fromBase64(query.value(i).
						     toByteArray());
		      continue;
		    }

		  bytes = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.
				value(i).
				toByteArray()),
		     &ok);

		  if(ok)
		    list << bytes;
		  else
		    {
		      list.clear();
		      break;
		    }
		}

	      for(int i = 0; i < list.size(); i++)
		{
		  if(ok)
		    {
		      if(i == 6) // in_username_hash
			updateQuery.bindValue
			  (i, newCrypt->keyedHash(list.at(i - 1), &ok).
			   toBase64());
		      else
			updateQuery.bindValue
			  (i, newCrypt->encryptedThenHashed(list.at(i), &ok).
			   toBase64());
		    }
		  else
		    break;
		}

	      updateQuery.bindValue(23, query.value(6));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding poptastic error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.exec("DELETE FROM poptastic");
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding rss.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT feed, feed_description, "
		      "feed_image, feed_title, OID FROM rss_feeds"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      auto ok = true;

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  auto const bytes
		    (oldCrypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.value(i).
							    toByteArray()),
						 &ok));

		  if(ok)
		    list << bytes;
		  else
		    break;
		}

	      if(ok)
		{
		  QSqlQuery updateQuery(db);

		  updateQuery.prepare("UPDATE rss_feeds SET "
				      "feed = ?, "
				      "feed_description = ?, "
				      "feed_hash = ?, "
				      "feed_image = ?, "
				      "feed_title = ? WHERE "
				      "OID = ?");
		  updateQuery.bindValue
		    (0, newCrypt->encryptedThenHashed(list.value(0),
						      &ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (1, newCrypt->encryptedThenHashed(list.value(1),
							&ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (2, newCrypt->keyedHash(list.value(0), &ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (3, newCrypt->encryptedThenHashed(list.value(2),
							&ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (4, newCrypt->encryptedThenHashed(list.value(3),
							&ok).toBase64());

		  updateQuery.bindValue
		    (5, query.value(query.record().count() - 1));

		  if(ok)
		    updateQuery.exec();
		}

	      if(!ok)
		{
		  spoton_misc::logError("Re-encoding rss_feeds error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM rss_feeds WHERE OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT content, description, title, url, "
		      "url_redirected, OID FROM rss_feeds_links"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      auto ok = true;

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  auto const bytes
		    (oldCrypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.value(i).
							    toByteArray()),
						 &ok));

		  if(ok)
		    list << bytes;
		  else
		    break;
		}

	      if(ok)
		{
		  QSqlQuery updateQuery(db);

		  updateQuery.prepare("UPDATE rss_feeds_links SET "
				      "content = ?, "
				      "description = ?, "
				      "title = ?, "
				      "url = ?, "
				      "url_hash = ?, "
				      "url_redirected = ? "
				      "WHERE OID = ?");
		  updateQuery.bindValue
		    (0, newCrypt->encryptedThenHashed(list.value(0),
						      &ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (1, newCrypt->encryptedThenHashed(list.value(1),
							&ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (2, newCrypt->encryptedThenHashed(list.value(2),
							&ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (3, newCrypt->encryptedThenHashed(list.value(3),
							&ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (4, newCrypt->keyedHash(list.value(3), &ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (5, newCrypt->encryptedThenHashed(list.value(4), &ok).
		       toBase64());

		  updateQuery.bindValue
		    (6, query.value(query.record().count() - 1));

		  if(ok)
		    updateQuery.exec();
		}

	      if(!ok)
		{
		  spoton_misc::logError("Re-encoding rss_feeds_links error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM rss_feeds_links WHERE "
				      "OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT enabled, hostname, password, port, "
		      "type, username FROM rss_proxy"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      auto ok = true;

	      for(int i = 0; i < query.record().count(); i++)
		{
		  auto const bytes
		    (oldCrypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.value(i).
							    toByteArray()),
						 &ok));

		  if(ok)
		    list << bytes;
		  else
		    break;
		}

	      if(ok)
		{
		  QSqlQuery updateQuery(db);

		  updateQuery.prepare("UPDATE rss_proxy SET "
				      "enabled = ?, "
				      "hostname = ?, "
				      "password = ?, "
				      "port = ?, "
				      "type = ?, "
				      "username = ?");

		  for(int i = 0; i < list.size(); i++)
		    if(ok)
		      updateQuery.bindValue
			(i, newCrypt->encryptedThenHashed(list.value(i),
							  &ok).toBase64());
		    else
		      break;

		  if(ok)
		    updateQuery.exec();
		}

	      if(!ok)
		{
		  spoton_misc::logError("Re-encoding rss_proxy error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.exec("DELETE FROM rss_proxy");
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding secrets.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT generated_data, "
		      "hint, "
		      "key_type, OID FROM secrets"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      auto ok = true;

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  auto const bytes
		    (oldCrypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.value(i).
							    toByteArray()),
						 &ok));

		  if(ok)
		    list << bytes;
		  else
		    break;
		}

	      if(ok)
		{
		  QSqlQuery updateQuery(db);

		  updateQuery.prepare("UPDATE secrets SET "
				      "generated_data = ?, "
				      "generated_data_hash = ?, "
				      "hint = ?, "
				      "key_type = ? "
				      "WHERE OID = ?");
		  updateQuery.bindValue
		    (0, newCrypt->encryptedThenHashed(list.value(0),
						      &ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (1, newCrypt->keyedHash(list.value(0),
					      &ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (2, newCrypt->encryptedThenHashed(list.value(1),
							&ok).toBase64());

		  if(ok)
		    updateQuery.bindValue
		      (3, newCrypt->encryptedThenHashed(list.value(2),
							&ok).toBase64());

		  updateQuery.bindValue
		    (4, query.value(query.record().count() - 1));

		  if(ok)
		    updateQuery.exec();
		}

	      if(!ok)
		{
		  spoton_misc::logError("Re-encoding secrets error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM secrets WHERE OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding starbeam.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT magnet, magnet_hash, origin FROM magnets"))
	  while(query.next())
	    {
	      QByteArray magnet;
	      QByteArray origin;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE magnets "
				  "SET magnet = ?, "
				  "magnet_hash = ?, "
				  "origin = ? "
				  "WHERE magnet_hash = ?");
	      magnet = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		origin = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()), &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(magnet, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(magnet, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(origin, &ok).toBase64());

	      updateQuery.bindValue
		(3, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding magnets error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM magnets WHERE "
				      "magnet_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT "
		      "estimated_time_arrival, " // 0
		      "expected_file_hash, "     // 1
		      "expected_sha3_512_hash, " // 2
		      "file, "                   // 3
		      "file_hash, "              // 4
		      "hash, "                   // 5
		      "pulse_size, "             // 6
		      "sha3_512_hash, "          // 7
		      "total_size, "             // 8
		      "OID "                     // 9
		      "FROM received"))
	  while(query.next())
	    {
	      QByteArray file;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE received SET "
				  "estimated_time_arrival = ?, "
				  "expected_file_hash = ?, "
				  "expected_sha3_512_hash = ?, "
				  "file = ?, "
				  "file_hash = ?, "
				  "hash = ?, "
				  "pulse_size = ?, "
				  "sha3_512_hash = ?, "
				  "total_size = ? "
				  "WHERE OID = ?");

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  QByteArray bytes;

		  if(i != 4 && !query.isNull(i))
		    bytes = oldCrypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(i).toByteArray()),
		       &ok);

		  if(ok)
		    {
		      if(i == 3)
			file = bytes;
		      else if(i == 4)
			updateQuery.addBindValue
			  (newCrypt->keyedHash(file, &ok).toBase64());
		      else
			{
			  if(query.isNull(i))
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
			    updateQuery.addBindValue
			      (QVariant(QMetaType(QMetaType::QString)));
#else
			    updateQuery.addBindValue(QVariant::String);
#endif
			  else
			    updateQuery.addBindValue
			      (newCrypt->
			       encryptedThenHashed(bytes, &ok).toBase64());
			}
		    }
		}

	      updateQuery.addBindValue
		(query.value(query.record().count() - 1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding received error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM received WHERE "
				      "file_hash = ?");
		  deleteQuery.bindValue(0, query.value(4));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT nova, nova_hash FROM received_novas"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE received_novas "
				  "SET nova = ?, "
				  "nova_hash = ? "
				  "WHERE nova_hash = ?");
	      bytes = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(bytes, &ok).toBase64());

	      updateQuery.bindValue(2, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding received_novas error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM received_novas WHERE "
				      "nova_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT "
		      "estimated_time_arrival, " // 0
		      "file, "                   // 1
		      "hash, "                   // 2
		      "mosaic, "                 // 3
		      "nova, "                   // 4
		      "position, "               // 5
		      "pulse_size, "             // 6
		      "sha3_512_hash, "          // 7
		      "total_size, "             // 8
		      "OID "                     // 9
		      "FROM transmitted"))
	  while(query.next())
	    {
	      QByteArray file;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE transmitted SET "
				  "estimated_time_arrival = ?, "
				  "file = ?, "
				  "hash = ?, "
				  "mosaic = ?, "
				  "nova = ?, "
				  "position = ?, "
				  "pulse_size = ?, "
				  "sha3_512_hash = ?, "
				  "total_size = ? "
				  "WHERE OID = ?");

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  QByteArray bytes;

		  if(i != 2 && !query.isNull(i))
		    bytes = oldCrypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(i).toByteArray()),
		       &ok);

		  if(ok)
		    {
		      if(i == 1)
			file = bytes;
		      else if(i == 2)
			updateQuery.addBindValue
			  (newCrypt->keyedHash(file, &ok).toBase64());
		      else
			{
			  if(query.isNull(i))
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
			    updateQuery.addBindValue
			      (QVariant(QMetaType(QMetaType::QString)));
#else
			    updateQuery.addBindValue(QVariant::String);
#endif
			  else
			    updateQuery.addBindValue
			      (newCrypt->
			       encryptedThenHashed(bytes, &ok).toBase64());
			}
		    }
		}

	      updateQuery.addBindValue
		(query.value(query.record().count() - 1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding transmitted error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM transmitted WHERE "
				      "mosaic = ?");
		  deleteQuery.bindValue(0, query.value(2));
		  deleteQuery.exec();
		  deleteQuery.exec
		    ("DELETE FROM transmitted_magnets WHERE "
		     "transmitted_oid NOT IN "
		     "(SELECT OID FROM transmitted)");
		  deleteQuery.exec
		    ("DELETE FROM transmitted_scheduled_pulses WHERE "
		     "transmitted_oid NOT IN "
		     "(SELECT OID FROM transmitted)");
		}
	    }

	if(query.exec("SELECT magnet, magnet_hash, transmitted_oid "
		      "FROM transmitted_magnets"))
	  while(query.next())
	    {
	      QByteArray magnet;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE transmitted_magnets "
				  "SET magnet = ?, "
				  "magnet_hash = ? "
				  "WHERE magnet_hash = ? AND "
				  "transmitted_oid = ?");
	      magnet = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(magnet,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1,
		   newCrypt->keyedHash(magnet,
				       &ok).toBase64());

	      updateQuery.bindValue
		(2, query.value(1));
	      updateQuery.bindValue
		(3, query.value(2));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError
		    ("Re-encoding transmitted_magnets error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare
		    ("DELETE FROM transmitted_magnets WHERE "
		     "magnet_hash = ? AND transmitted_oid = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.bindValue(0, query.value(2));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText
    (QObject::tr("Re-encoding urls_distillers_information.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() +
       QDir::separator() +
       "urls_distillers_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT direction, domain, "
		      "permission, OID FROM distillers"))
	  while(query.next())
	    {
	      QByteArray direction;
	      QByteArray domain;
	      QByteArray permission;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE distillers "
				  "SET direction = ?, "
				  "direction_hash = ?, "
				  "domain = ?, "
				  "domain_hash = ?, "
				  "permission = ? WHERE "
				  "OID = ?");
	      direction = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->
		   encryptedThenHashed(direction, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1,
		   newCrypt->keyedHash(direction,
				       &ok).toBase64());

	      if(ok)
		domain = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(domain, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->keyedHash(domain, &ok).toBase64());

	      if(ok)
		permission = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->encryptedThenHashed(permission, &ok).
		   toBase64());

	      updateQuery.bindValue
		(5, query.value(query.record().count() - 1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError("Re-encoding distillers error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM distillers WHERE OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText(QObject::tr("Re-encoding urls_key_information.db."));
  sb.status->repaint();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() +
       QDir::separator() +
       "urls_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT cipher_type, symmetric_key, OID "
		      "FROM import_key_information"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE import_key_information "
				  "SET cipher_type = ?, "
				  "symmetric_key = ? WHERE "
				  "OID = ?");
	      bytes = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		bytes = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      updateQuery.bindValue
		(2, query.value(2));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError
		    ("Re-encoding import_key_information error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM import_key_information "
				      "WHERE OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT cipher_type, encryption_key, "
		      "hash_key, hash_type, OID "
		      "FROM remote_key_information"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      QSqlQuery updateQuery(db);
	      auto ok = true;

	      updateQuery.prepare("UPDATE remote_key_information "
				  "SET cipher_type = ?, "
				  "encryption_key = ?, "
				  "hash_key = ?, "
				  "hash_type = ? WHERE "
				  "OID = ?");

	      for(int i = 0; i < 4; i++)
		{
		  auto const bytes
		    (oldCrypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.
							    value(i).
							    toByteArray()),
						 &ok));

		  if(ok)
		    list.append(bytes);
		  else
		    break;
		}

	      for(int i = 0; i < list.size(); i++)
		{
		  if(ok)
		    updateQuery.bindValue
		      (i, newCrypt->encryptedThenHashed(list.at(i),
							&ok).toBase64());

		  if(!ok)
		    break;
		}

	      updateQuery.bindValue
		(4, query.value(4));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  spoton_misc::logError
		    ("Re-encoding remote_key_information error.");

		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM remote_key_information "
				      "WHERE OID = ?");
		  deleteQuery.bindValue
		    (0, query.value(query.record().count() - 1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->clear();

  QByteArray bytes;
  QSettings settings;
  auto ok = true;

  bytes = oldCrypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.value("gui/authenticationHint", "").
			    toByteArray()), &ok);

  if(ok)
    settings.setValue("gui/authenticationHint",
		      newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

  if(!ok)
    settings.remove("gui/authenticationHint");

  bytes = oldCrypt->decryptedAfterAuthenticated
    (settings.value("gui/git_table").toByteArray(), &ok);

  if(ok)
    settings.setValue
      ("gui/git_table", newCrypt->encryptedThenHashed(bytes, &ok));

  if(!ok)
    settings.remove("gui/git_table");

  settings.remove("gui/gpg_passphrase");
  bytes = oldCrypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.value("gui/poptasticName", "").
			    toByteArray()), &ok);

  if(ok)
    settings.setValue
      ("gui/poptasticName", newCrypt->encryptedThenHashed(bytes, &ok).
       toBase64());

  if(!ok)
    settings.remove("gui/poptasticName");

  bytes = oldCrypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.value("gui/poptasticNameEmail", "").
			    toByteArray()), &ok);

  if(ok)
    settings.setValue
      ("gui/poptasticNameEmail", newCrypt->encryptedThenHashed(bytes, &ok).
       toBase64());

  if(!ok)
    settings.remove("gui/poptasticNameEmail");

  bytes = oldCrypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.value("gui/postgresql_name", "").
			    toByteArray()), &ok);

  if(ok)
    settings.setValue
      ("gui/postgresql_name",
       newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

  if(!ok)
    settings.remove("gui/postgresql_name");

  bytes = oldCrypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.value("gui/postgresql_password", "").
			    toByteArray()), &ok);

  if(ok)
    settings.setValue
      ("gui/postgresql_password",
       newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

  if(!ok)
    settings.remove("gui/postgresql_password");

  bytes = oldCrypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.value("gui/postgresql_web_name", "").
			    toByteArray()), &ok);

  if(ok)
    settings.setValue
      ("gui/postgresql_web_name",
       newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

  if(!ok)
    settings.remove("gui/postgresql_web_name");

  bytes = oldCrypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.value("gui/postgresql_web_password", "").
			    toByteArray()), &ok);

  if(ok)
    settings.setValue
      ("gui/postgresql_web_password",
       newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

  if(!ok)
    settings.remove("gui/postgresql_web_password");
}
