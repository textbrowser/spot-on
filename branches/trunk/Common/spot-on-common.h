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

#ifndef _spoton_common_h_
#define _spoton_common_h_

#define SPOTON_VERSION_STR "0.23"

typedef QHash<QString, QByteArray> QStringByteArrayHash;
typedef QList<QByteArray> QByteArrayList;
typedef QList<QPair<QByteArray, qint64> > QPairByteArrayInt64List;
typedef QPair<QByteArray, QByteArray> QPairByteArrayByteArray;

namespace spoton_common
{
  static const int BUZZ_MAXIMUM_ID_LENGTH = 256; /*
						 ** Please use a number
						 ** that's divisible by two.
						 ** The number of random bytes
						 ** to be used is half of this
						 ** number. The actual ID
						 ** will be represented in
						 ** base sixteen.
						 */
  static const int CHAT_TIME_DELTA_MAXIMUM = 30;
  static const int NAME_MAXIMUM_LENGTH = 64;
  static const int STATUS_MAXIMUM_LENGTH = 64;
  static const qint64 MAXIMUM_NEIGHBOR_BUFFER_SIZE =
    20971520; /*
	      ** The buffer size must be greater than the content length.
	      */
  static const qint64 MAXIMUM_NEIGHBOR_CONTENT_LENGTH = 10485760;
  static const qint64 MAXIMUM_STARBEAM_PULSE_SIZE = 250000;
  static const qint64 MINIMUM_NEIGHBOR_CONTENT_LENGTH = 256;
}

#endif
