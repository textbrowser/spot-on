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

#include "spot-on-skein.h"

extern "C"
{
#include <gcrypt.h>
}

spoton_skein::spoton_skein(void)
{
  m_key = 0;
  m_keyLength = 0;
}

spoton_skein::~spoton_skein()
{
  gcry_free(m_key);
  gcry_free(m_tweak);
}

void spoton_skein::setKey(const QByteArray &key, bool *ok)
{
  if(key.size() != 32)
    {
      if(*ok)
	*ok = false;

      goto done_label;
    }

  gcry_free(m_key);
  m_key = static_cast<char *> (gcry_calloc_secure(key.length(), sizeof(char)));
  m_keyLength = key.length();

  if(!m_key)
    {
      m_keyLength = 0;

      if(ok)
	*ok = false;

      goto done_label;
    }

  if(*ok)
    *ok = true;

  return;

 done_label:
  gcry_free(m_key);
  m_key = 0;
  m_keyLength = 0;
}

void spoton_skein::setTweak(const QByteArray &tweak, bool *ok)
{
  if(tweak.size() != 16)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  gcry_free(m_tweak);
  m_tweak = static_cast<char *> (calloc(tweak.length(), sizeof(char)));
  m_tweakLength = tweak.length();

  if(!m_tweak)
    {
      m_tweakLength = 0;

      if(ok)
	*ok = false;

      goto done_label;
    }

  if(*ok)
    *ok = true;

  return;

 done_label:
  gcry_free(m_tweak);
  m_tweak = 0;
  m_tweakLength = 0;
}
