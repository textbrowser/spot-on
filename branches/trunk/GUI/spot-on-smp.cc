/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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

/*
** The following is adapted from
** https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html.
*/

#include <QtDebug>

#include "Common/spot-on-crypt.h"
#include "spot-on-smp.h"

#define GOTO_DONE_LABEL ({if(ok) *ok = false; list.clear(); goto done_label;})

spoton_smp::spoton_smp(void)
{
  gcry_mpi_scan(&m_generator, GCRYMPI_FMT_HEX, "0x02", 0, 0);
  gcry_mpi_scan(&m_modulus, GCRYMPI_FMT_HEX,
		"0x"
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
		0, 0);
  m_a2 = 0;
  m_a3 = 0;
  m_b2 = 0;
  m_b3 = 0;
  m_guess = 0;
  m_pa = 0;
  m_passed = false;
  m_pb = 0;
  m_qb = 0;
  m_step = 0;
}

spoton_smp::~spoton_smp()
{
  gcry_mpi_release(m_generator);
  gcry_mpi_release(m_modulus);
  reset();
}

QByteArray spoton_smp::guessWhirlpool(void) const
{
  QByteArray bytes;
  bool ok = true;
  size_t size = 0;
  unsigned char *buffer = 0;

  if(!m_guess)
    goto done_label;

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, m_guess) != 0)
    goto done_label;
  else
    bytes = QByteArray
      (reinterpret_cast<char *> (buffer), static_cast<int> (size));

  bytes = spoton_crypt::whirlpoolHash(bytes, &ok);

 done_label:
  gcry_free(buffer);
  return bytes;
}

QList<QByteArray> spoton_smp::nextStep(const QList<QByteArray> &other,
				       bool *ok, bool *passed)
{
  /*
  ** A submits the first exchange and transitions to the first state.
  ** B receives A's information and transitions to the second state.
  ** A receives B's information and transitions to the third state.
  ** B receives A's information and transitions to the fourth state.
  ** A receives B's information and transitions to the fifth state.
  */

  if(m_step == 0)
    return step2(other, ok);
  else if(m_step == 1)
    return step3(other, ok);
  else if(m_step == 2)
    return step4(other, ok, passed);
  else if(m_step == 3)
    step5(other, ok, passed);
  else
    {
      if(ok)
	*ok = false;

      if(passed)
	*passed = false;
    }

  return QList<QByteArray> ();
}

QList<QByteArray> spoton_smp::step1(bool *ok)
{
  QList<QByteArray> list;
  gcry_mpi_t g2a = 0;
  gcry_mpi_t g3a = 0;
  size_t size = 0;
  unsigned char *buffer = 0;

  /*
  ** Generate a2 and a3.
  */

  if(m_a2)
    {
      gcry_mpi_release(m_a2);
      m_a2 = 0;
    }

  if(m_a3)
    {
      gcry_mpi_release(m_a3);
      m_a3 = 0;
    }

  m_a2 = generateRandomExponent(ok);

  if(!m_a2)
    GOTO_DONE_LABEL;

  m_a3 = generateRandomExponent(ok);

  if(!m_a3)
    GOTO_DONE_LABEL;

  /*
  ** Calculate g2a and g3a and store the results in the list.
  */

  g2a = gcry_mpi_new(BITS);
  g3a = gcry_mpi_new(BITS);

  if(!g2a || !g3a)
    GOTO_DONE_LABEL;

  if(!m_generator || !m_modulus)
    GOTO_DONE_LABEL;

  gcry_mpi_powm(g2a, m_generator, m_a2, m_modulus);
  gcry_mpi_powm(g3a, m_generator, m_a3, m_modulus);

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, g2a) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, g3a) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;
  m_step = 1;

 done_label:
  gcry_free(buffer);
  gcry_mpi_release(g2a);
  gcry_mpi_release(g3a);
  return list;
}

QList<QByteArray> spoton_smp::step2(const QList<QByteArray> &other,
				    bool *ok)
{
  QByteArray bytes;
  QList<QByteArray> list;
  gcry_mpi_t g2 = 0;
  gcry_mpi_t g2a = 0;
  gcry_mpi_t g2b = 0;
  gcry_mpi_t g3 = 0;
  gcry_mpi_t g3a = 0;
  gcry_mpi_t g3b = 0;
  gcry_mpi_t qb1 = 0;
  gcry_mpi_t qb2 = 0;
  gcry_mpi_t r = 0;
  size_t size = 0;
  unsigned char *buffer = 0;

  /*
  ** Extract g2a and g3a.
  */

  if(other.size() != 2)
    GOTO_DONE_LABEL;

  if(m_pb)
    {
      gcry_mpi_release(m_pb);
      m_pb = 0;
    }

  if(m_qb)
    {
      gcry_mpi_release(m_qb);
      m_qb = 0;
    }

  m_pb = gcry_mpi_new(BITS);
  m_qb = gcry_mpi_new(BITS);
  g2 = gcry_mpi_new(BITS);
  g2b = gcry_mpi_new(BITS);
  g3 = gcry_mpi_new(BITS);
  g3b = gcry_mpi_new(BITS);
  qb1 = gcry_mpi_new(BITS);
  qb2 = gcry_mpi_new(BITS);

  if(!m_pb || !m_qb || !g2 || !g2b || !g3 || !g3b || !qb1 || !qb2)
    GOTO_DONE_LABEL;

  bytes = other.at(0).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&g2a, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  bytes = other.at(1).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&g3a, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  /*
  ** Generate b2 and b3.
  */

  if(m_b2)
    {
      gcry_mpi_release(m_b2);
      m_b2 = 0;
    }

  if(m_b3)
    {
      gcry_mpi_release(m_b3);
      m_b3 = 0;
    }

  m_b2 = generateRandomExponent(ok);

  if(!m_b2)
    GOTO_DONE_LABEL;

  m_b3 = generateRandomExponent(ok);

  if(!m_b3)
    GOTO_DONE_LABEL;

  /*
  ** Calculate g2b and g3b and store the results in the list.
  */

  if(!m_generator || !m_modulus)
    GOTO_DONE_LABEL;

  gcry_mpi_powm(g2b, m_generator, m_b2, m_modulus);
  gcry_mpi_powm(g3b, m_generator, m_b3, m_modulus);

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, g2b) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, g3b) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;

  /*
  ** Calculate g2 and g3.
  */

  gcry_mpi_powm(g2, g2a, m_b2, m_modulus);
  gcry_mpi_powm(g3, g3a, m_b3, m_modulus);

  /*
  ** Generate r.
  */

  r = generateRandomExponent(ok);

  if(!r)
    GOTO_DONE_LABEL;

  /*
  ** Calculate pb and qb and store the results in the list.
  */

  if(!m_guess)
    GOTO_DONE_LABEL;

  gcry_mpi_powm(m_pb, g3, r, m_modulus);
  gcry_mpi_powm(qb1, m_generator, r, m_modulus);
  gcry_mpi_powm(qb2, g2, m_guess, m_modulus);
  gcry_mpi_mulm(m_qb, qb1, qb2, m_modulus);

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, m_pb) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, m_qb) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;
  m_step = 2;

 done_label:
  gcry_free(buffer);
  gcry_mpi_release(g2);
  gcry_mpi_release(g2a);
  gcry_mpi_release(g2b);
  gcry_mpi_release(g3);
  gcry_mpi_release(g3a);
  gcry_mpi_release(g3b);
  gcry_mpi_release(qb1);
  gcry_mpi_release(qb2);
  gcry_mpi_release(r);
  return list;
}

QList<QByteArray> spoton_smp::step3(const QList<QByteArray> &other,
				    bool *ok)
{
  QByteArray bytes;
  QList<QByteArray> list;
  gcry_mpi_t g2 = 0;
  gcry_mpi_t g2b = 0;
  gcry_mpi_t g3 = 0;
  gcry_mpi_t g3b = 0;
  gcry_mpi_t qa = 0;
  gcry_mpi_t qa1 = 0;
  gcry_mpi_t qa2 = 0;
  gcry_mpi_t qb = 0;
  gcry_mpi_t qbinv = 0;
  gcry_mpi_t ra = 0;
  gcry_mpi_t ra1 = 0;
  gcry_mpi_t s = 0;
  size_t size = 0;
  unsigned char *buffer = 0;

  /*
  ** Extract g2b, g3b, pb, and qb.
  */

  if(other.size() != 4)
    GOTO_DONE_LABEL;

  bytes = other.at(0).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&g2b, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  bytes = other.at(1).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&g3b, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  bytes = other.at(2).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&m_pb, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  bytes = other.at(3).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&qb, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  /*
  ** Calculate g2 and g3.
  */

  g2 = gcry_mpi_new(BITS);
  g3 = gcry_mpi_new(BITS);

  if(!g2 || !g3)
    GOTO_DONE_LABEL;

  if(!m_a2 || !m_a3 || !m_modulus)
    GOTO_DONE_LABEL;

  gcry_mpi_powm(g2, g2b, m_a2, m_modulus);
  gcry_mpi_powm(g3, g3b, m_a3, m_modulus);

  /*
  ** Generate s.
  */

  s = generateRandomExponent(ok);

  if(!s)
    GOTO_DONE_LABEL;

  /*
  ** Calculate pa and qa and store the results in the list.
  */

  if(m_pa)
    {
      gcry_mpi_release(m_pa);
      m_pa = 0;
    }

  m_pa = gcry_mpi_new(BITS);
  qa = gcry_mpi_new(BITS);
  qa1 = gcry_mpi_new(BITS);
  qa2 = gcry_mpi_new(BITS);

  if(!m_pa || !qa || !qa1 || !qa2)
    GOTO_DONE_LABEL;

  if(!m_generator || !m_guess)
    GOTO_DONE_LABEL;

  gcry_mpi_powm(m_pa, g3, s, m_modulus);
  gcry_mpi_powm(qa1, m_generator, s, m_modulus);
  gcry_mpi_powm(qa2, g2, m_guess, m_modulus);
  gcry_mpi_mulm(qa, qa1, qa2, m_modulus);

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, m_pa) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, qa) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;

  /*
  ** Calculate ra and store the results in the list.
  */

  qbinv = gcry_mpi_new(BITS);

  if(!qbinv)
    GOTO_DONE_LABEL;

  if(!gcry_mpi_invm(qbinv, qb, m_modulus))
    GOTO_DONE_LABEL;

  ra = gcry_mpi_new(BITS);
  ra1 = gcry_mpi_new(BITS);

  if(!ra || !ra1)
    GOTO_DONE_LABEL;

  gcry_mpi_mulm(ra1, qa, qbinv, m_modulus);
  gcry_mpi_powm(ra, ra1, m_a3, m_modulus);

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, ra) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;
  m_step = 3;

 done_label:
  gcry_free(buffer);
  gcry_mpi_release(g2);
  gcry_mpi_release(g2b);
  gcry_mpi_release(g3);
  gcry_mpi_release(g3b);
  gcry_mpi_release(qa);
  gcry_mpi_release(qa1);
  gcry_mpi_release(qa2);
  gcry_mpi_release(qb);
  gcry_mpi_release(qbinv);
  gcry_mpi_release(ra);
  gcry_mpi_release(ra1);
  gcry_mpi_release(s);
  return list;
}

QList<QByteArray> spoton_smp::step4(const QList<QByteArray> &other,
				    bool *ok, bool *passed)
{
  QByteArray bytes;
  QList<QByteArray> list;
  gcry_mpi_t pa = 0;
  gcry_mpi_t papb = 0;
  gcry_mpi_t pbinv = 0;
  gcry_mpi_t qa = 0;
  gcry_mpi_t qbinv = 0;
  gcry_mpi_t ra = 0;
  gcry_mpi_t rab = 0;
  gcry_mpi_t rb = 0;
  gcry_mpi_t rb1 = 0;
  size_t size = 0;
  unsigned char *buffer = 0;

  m_passed = false;

  if(passed)
    *passed = false;

  /*
  ** Extract pa, qa, and ra.
  */

  if(other.size() != 3)
    GOTO_DONE_LABEL;

  bytes = other.at(0).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&pa, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  bytes = other.at(1).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&qa, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  bytes = other.at(2).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&ra, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    GOTO_DONE_LABEL;

  /*
  ** Calculate rb and store the results in the list.
  */

  qbinv = gcry_mpi_new(BITS);

  if(!qbinv)
    GOTO_DONE_LABEL;

  if(!m_modulus || !m_qb)
    GOTO_DONE_LABEL;

  if(!gcry_mpi_invm(qbinv, m_qb, m_modulus))
    GOTO_DONE_LABEL;

  rb = gcry_mpi_new(BITS);
  rb1 = gcry_mpi_new(BITS);

  if(!rb || !rb1)
    GOTO_DONE_LABEL;

  if(!m_b3)
    GOTO_DONE_LABEL;

  gcry_mpi_mulm(rb1, qa, qbinv, m_modulus);
  gcry_mpi_powm(rb, rb1, m_b3, m_modulus);

  if(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &size, rb) != 0)
    GOTO_DONE_LABEL;
  else
    list.append(QByteArray(reinterpret_cast<char *> (buffer),
			   static_cast<int> (size)));

  gcry_free(buffer);
  buffer = 0;

  /*
  ** Calculate rab.
  */

  rab = gcry_mpi_new(BITS);

  if(!rab)
    GOTO_DONE_LABEL;

  gcry_mpi_powm(rab, ra, m_b3, m_modulus);

  /*
  ** Calculate pa / pb.
  */

  pbinv = gcry_mpi_new(BITS);

  if(!pbinv)
    GOTO_DONE_LABEL;

  if(!m_pb)
    GOTO_DONE_LABEL;

  if(!gcry_mpi_invm(pbinv, m_pb, m_modulus))
    GOTO_DONE_LABEL;

  papb = gcry_mpi_new(BITS);

  if(!papb)
    GOTO_DONE_LABEL;

  gcry_mpi_mulm(papb, pa, pbinv, m_modulus);

  if(gcry_mpi_cmp(rab, papb) == 0)
    {
      m_passed = true;

      if(passed)
	*passed = true;
    }

  m_step = 4;

 done_label:
  gcry_free(buffer);
  gcry_mpi_release(pa);
  gcry_mpi_release(papb);
  gcry_mpi_release(pbinv);
  gcry_mpi_release(qa);
  gcry_mpi_release(qbinv);
  gcry_mpi_release(ra);
  gcry_mpi_release(rab);
  gcry_mpi_release(rb);
  gcry_mpi_release(rb1);
  return list;
}

bool spoton_smp::passed(void) const
{
  return m_passed;
}

gcry_mpi_t spoton_smp::generateRandomExponent(bool *ok)
{
  gcry_mpi_t exponent = 0;
  unsigned char *buffer = (unsigned char *) gcry_random_bytes_secure
    (BITS / 8, GCRY_STRONG_RANDOM);

  if(!buffer)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if(gcry_mpi_scan(&exponent, GCRYMPI_FMT_USG, buffer, BITS / 8, 0) != 0)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

 done_label:
  gcry_free(buffer);
  return exponent;
}

int spoton_smp::step(void) const
{
  return m_step;
}

void spoton_smp::initialize(void)
{
  gcry_mpi_t g = 0;

  if(m_guess)
    g = gcry_mpi_set(0, m_guess);

  reset();

  if(g)
    m_guess = gcry_mpi_set(0, g);
}

void spoton_smp::reset(void)
{
  gcry_mpi_release(m_a2);
  gcry_mpi_release(m_a3);
  gcry_mpi_release(m_b2);
  gcry_mpi_release(m_b3);
  gcry_mpi_release(m_guess);
  gcry_mpi_release(m_pa);
  gcry_mpi_release(m_pb);
  gcry_mpi_release(m_qb);
  m_a2 = 0;
  m_a3 = 0;
  m_b2 = 0;
  m_b3 = 0;
  m_guess = 0;
  m_pa = 0;
  m_passed = false;
  m_pb = 0;
  m_qb = 0;
  m_step = 0;
}

void spoton_smp::setGuess(const QString &guess)
{
  if(m_guess)
    {
      gcry_mpi_release(m_guess);
      m_guess = 0;
    }

  QByteArray hash;
  bool ok = true;

  hash = spoton_crypt::sha512Hash(guess.toUtf8(), &ok);

  if(ok)
    gcry_mpi_scan
      (&m_guess, GCRYMPI_FMT_USG,
       reinterpret_cast<const unsigned char *> (hash.constData()),
       hash.length(), 0);
}

void spoton_smp::step5(const QList<QByteArray> &other, bool *ok,
		       bool *passed)
{
  QByteArray bytes;
  gcry_mpi_t papb = 0;
  gcry_mpi_t pbinv = 0;
  gcry_mpi_t rab = 0;
  gcry_mpi_t rb = 0;

  m_passed = false;

  if(passed)
    *passed = false;

  /*
  ** Extract rb.
  */

  if(other.size() != 1)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  bytes = other.at(0).mid(0, static_cast<int> (BITS / 8));

  if(gcry_mpi_scan(&rb, GCRYMPI_FMT_USG,
		   reinterpret_cast<const unsigned char *> (bytes.
							    constData()),
		   bytes.length(), 0) != 0)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  /*
  ** Calculate rab.
  */

  rab = gcry_mpi_new(BITS);

  if(!rab)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if(!m_a3 || !m_modulus)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  gcry_mpi_powm(rab, rb, m_a3, m_modulus);

  /*
  ** Calculate pa / pb.
  */

  pbinv = gcry_mpi_new(BITS);

  if(!pbinv)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if(!m_modulus || !m_pb)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if(!gcry_mpi_invm(pbinv, m_pb, m_modulus))
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  papb = gcry_mpi_new(BITS);

  if(!papb)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if(!m_pa)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  gcry_mpi_mulm(papb, m_pa, pbinv, m_modulus);

  if(gcry_mpi_cmp(rab, papb) == 0)
    {
      m_passed = true;

      if(passed)
	*passed = true;
    }

  m_step = 5;

 done_label:
  gcry_mpi_release(papb);
  gcry_mpi_release(pbinv);
  gcry_mpi_release(rab);
  gcry_mpi_release(rb);
}

void spoton_smp::test(void)
{
  QList<QByteArray> list;
  bool ok = true;
  bool passed = false;
  spoton_smp a;
  spoton_smp b;

  a.setGuess("This is a test.");
  b.setGuess("This is a test.");
  list = a.step1(&ok);

  if(!ok)
    {
      qDebug() << "SMP step 1 failure.";
      return;
    }

  list = b.nextStep(list, &ok, &passed);

  if(!ok)
    {
      qDebug() << "SMP step 2 failure.";
      return;
    }

  list = a.nextStep(list, &ok, &passed);

  if(!ok)
    {
      qDebug() << "SMP step 3 failure.";
      return;
    }

  list = b.nextStep(list, &ok, &passed);

  if(!ok)
    {
      qDebug() << "SMP step 4 failure.";
      return;
    }

  if(passed)
    qDebug() << "Secrets are identical from b's perspective.";
  else
    qDebug() << "Secrets are different from b's perspective.";

  a.nextStep(list, &ok, &passed);

  if(!ok)
    {
      qDebug() << "SMP step 5 failure.";
      return;
    }

  if(passed)
    qDebug() << "Secrets are identical from a's perspective.";
  else
    qDebug() << "Secrets are different from a's perspective.";
}
