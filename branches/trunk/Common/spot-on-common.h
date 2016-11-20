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

#ifndef _spoton_common_h_
#define _spoton_common_h_

#include <QHash>
#include <QStringList>

#define SPOTON_VERSION_STR "2016.11.19"

typedef QHash<QString, QByteArray> QStringByteArrayHash;
typedef QList<QByteArray> QByteArrayList;
typedef QList<QPair<QByteArray, qint64> > QPairByteArrayInt64List;
typedef QPair<QByteArray, QByteArray> QPairByteArrayByteArray;

class spoton_common
{
 public:
  static QList<int> LANE_WIDTHS;
  static QString SSL_CONTROL_STRING;
  static QStringList ACCEPTABLE_URL_SCHEMES;
  static QStringList SPOTON_ENCRYPTION_KEY_NAMES;
  static QStringList SPOTON_SIGNATURE_KEY_NAMES;
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
  static const int ELEGANT_STARBEAM_SIZE = 15000;
  static const int EMAIL_ATTACHMENT_MAXIMUM_SIZE = 10 * 1024 * 1024;
  static const int FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC = 30;
  static const int GEMINI_TIME_DELTA_MAXIMUM_STATIC = 90;
  static const int HARVEST_POST_OFFICE_LETTERS_INTERVAL = 5;
  static const int KERNEL_CERTIFICATE_DAYS_VALID = 7;
  static const int KERNEL_URL_DISPATCHER_INTERVAL_STATIC = 60;
  static const int LANE_WIDTH_DEFAULT = 104857600;
  static const int LANE_WIDTH_MAXIMUM = LANE_WIDTH_DEFAULT;
  static const int LANE_WIDTH_MINIMUM =
    4096 < LANE_WIDTH_DEFAULT ? 4096 : LANE_WIDTH_DEFAULT; /*
							   ** Must be smaller
							   ** than the
							   ** default.
							   */
  static const int LOG_FILE_MAXIMUM_SIZE = 8 * 1024 * 1024;
  static const int MAIL_TIME_DELTA_MAXIMUM_STATIC = 90;
  static const int MAXIMUM_ATTEMPTS_PER_POPTASTIC_POST = 2;
  static const int MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS = 500;
  static const int MAXIMUM_KERNEL_GUI_SERVER_SINGLE_SOCKET_BUFFER_SIZE =
#ifdef SPOTON_MCELIECE_ENABLED
    INT_MAX;
#else
    CHAR_BIT * 1024 * 1024;
#endif
  static const int MAXIMUM_UDP_DATAGRAM_SIZE = 508;
  static const int MINIMUM_SECURE_MEMORY_POOL_SIZE = 262144;
  static const int MINIMUM_STARBEAM_PULSE_SIZE = 1024;
  static const int MOSAIC_SIZE = 64;
  static const int NAME_MAXIMUM_LENGTH = 64;
  static const int NEIGHBOR_LIFETIME_MS = 10 * 60 * 1000;
  static const int NEIGHBOR_SILENCE_TIME = 90;
  static const int POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC = 60;
  static const int POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM_STATIC = 90;
  static const int POPTASTIC_MAXIMUM_EMAIL_SIZE = 50 * 1024 * 1024;
  static const int POPTASTIC_STATUS_INTERVAL = 60;
  static const int REAP_POST_OFFICE_LETTERS_INTERVAL = 60;
  static const int RSS_IMPORTS_PER_THREAD = 5;
  static const int SEND_QUEUED_EMAIL_INTERVAL = 5;
  static const int SMP_TIME_DELTA_MAXIMUM = 90;
  static const int SPOTON_HOME_MAXIMUM_PATH_LENGTH = 256;
  static const int STATUS_INTERVAL = 15;
  static const int STATUS_TEXT_MAXIMUM_LENGTH = 64;
  static const int URL_CONTENT_SHARE_MAXIMUM_SIZE = 5 * 1024 * 1024;
  static const int WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM = 60000;
  static const qint64 MAXIMUM_NEIGHBOR_BUFFER_SIZE =
    static_cast<qint64> (LANE_WIDTH_MAXIMUM); /*
					      ** The buffer size must be greater
					      ** than the content length.
					      */
  static const qint64 MAXIMUM_NEIGHBOR_CONTENT_LENGTH =
    104856576 < MAXIMUM_NEIGHBOR_BUFFER_SIZE ?
    104856576 : MAXIMUM_NEIGHBOR_BUFFER_SIZE;
  static const qint64 MAXIMUM_STARBEAM_PULSE_SIZE = 2500000;
  static const qint64 MINIMUM_NEIGHBOR_CONTENT_LENGTH =
    256 < MAXIMUM_NEIGHBOR_CONTENT_LENGTH ?
    256 : MAXIMUM_NEIGHBOR_CONTENT_LENGTH;
  static const unsigned long int GEMINI_ITERATION_COUNT = 25000;

  /*
  ** Dynamic values. Not a pleasant solution.
  */

  static int CACHE_TIME_DELTA_MAXIMUM;
  static int CHAT_TIME_DELTA_MAXIMUM;
  static int FORWARD_SECRECY_TIME_DELTA_MAXIMUM;
  static int GEMINI_TIME_DELTA_MAXIMUM;
  static int KERNEL_URL_DISPATCHER_INTERVAL;
  static int MAIL_TIME_DELTA_MAXIMUM;
  static int POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM;
  static int POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM;

 private:
  spoton_common(void);
  ~spoton_common();
};

#endif
