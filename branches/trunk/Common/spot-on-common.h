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

#include <QHash>
#include <QStringList>

#ifndef _spoton_common_h_
#define _spoton_common_h_

#define SPOTON_VERSION_STR "2015.09.25"

typedef QHash<QString, QByteArray> QStringByteArrayHash;
typedef QList<QByteArray> QByteArrayList;
typedef QList<QPair<QByteArray, qint64> > QPairByteArrayInt64List;
typedef QPair<QByteArray, QByteArray> QPairByteArrayByteArray;

namespace spoton_common
{
  static const QStringList ACCEPTABLE_URL_SCHEMES =
    QStringList() << "ftp" << "gopher" << "http" << "https";
  static const int ACCOUNTS_RANDOM_BUFFER_SIZE = 64;
  static const int BUZZ_MAXIMUM_ID_LENGTH = 256; /*
						 ** Please use a number
						 ** that's divisible by two.
						 ** The number of random bytes
						 ** to be used is half of this
						 ** number. The actual ID
						 ** will be represented in
						 ** base sixteen.
						 */
  static const int CACHE_TIME_DELTA_MAXIMUM_STATIC = 30;
  static const int CHAT_MAXIMUM_REPLAY_QUEUE_SIZE = 15;
  static const int CHAT_TIME_DELTA_MAXIMUM_STATIC = 30;
  static const int FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC = 30;
  static const int GEMINI_TIME_DELTA_MAXIMUM_STATIC = 90;
  static const int HARVEST_POST_OFFICE_LETTERS_INTERVAL = 5;
  static const int KERNEL_CERTIFICATE_DAYS_VALID = 7;
  static const int KERNEL_URLS_BATCH_SIZE = 25;
  static const int MAIL_TIME_DELTA_MAXIMUM_STATIC = 90;
  static const int MAXIMUM_ATTEMPTS_PER_POPTASTIC_POST = 2;
  static const int MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS = 500;
  static const int MAXIMUM_KEYWORDS_IN_URL_DESCRIPTION = 50;
  static const int MOSAIC_SIZE = 64;
  static const int NAME_MAXIMUM_LENGTH = 64;
  static const int POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC = 60;
  static const int POPTASTIC_STATUS_INTERVAL = 60;
  static const int REAP_POST_OFFICE_LETTERS_INTERVAL = 60;
  static const int SEND_QUEUED_EMAIL_INTERVAL = 15;
  static const int SPOTON_HOME_MAXIMUM_PATH_LENGTH = 256;
  static const int STATUS_INTERVAL = 15;
  static const int STATUS_TEXT_MAXIMUM_LENGTH = 64;
  static const qint64 MAXIMUM_NEIGHBOR_BUFFER_SIZE =
    20971520; /*
	      ** The buffer size must be greater than the content length.
	      */
  static const qint64 MAXIMUM_NEIGHBOR_CONTENT_LENGTH = 10485760;
  static const qint64 MAXIMUM_STARBEAM_PULSE_SIZE = 250000;
  static const qint64 MINIMUM_NEIGHBOR_CONTENT_LENGTH = 256;
  static const unsigned long GEMINI_ITERATION_COUNT = 100000;

  /*
  ** Dynamic values. Not a pleasant solution.
  */

  extern int CACHE_TIME_DELTA_MAXIMUM;
  extern int CHAT_TIME_DELTA_MAXIMUM;
  extern int FORWARD_SECRECY_TIME_DELTA_MAXIMUM;
  extern int GEMINI_TIME_DELTA_MAXIMUM;
  extern int MAIL_TIME_DELTA_MAXIMUM;
  extern int POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM;
}

#endif
