/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Software based on specifications provided by Antoon Bosselaers,
** René Govaerts, Robert McEliece, Bart Preneel, Marek Repka,
** Christopher Roering, Joos Vandewalle.
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
**    derived from skein without specific prior written permission.
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

#ifndef _spoton_mceliece_h_
#define _spoton_mceliece_h_

#ifdef SPOTON_MCELIECE_ENABLED
extern "C"
{
#include <limits.h>
#include <string.h>
}

#include <NTL/GF2E.h>
#include <NTL/GF2EX.h>
#include <NTL/GF2EXFactoring.h>
#include <NTL/GF2X.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/mat_GF2.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_GF2E.h>

#include <limits>
#include <sstream>
#include <vector>

class spoton_mceliece_private_key
{
 public:
  spoton_mceliece_private_key(const char *privateKey,
			      const size_t privateKeyLength);
  spoton_mceliece_private_key(const size_t m, const size_t t);
  ~spoton_mceliece_private_key();

  NTL::GF2EX X(void) const
  {
    return m_X;
  }

  NTL::GF2EX gZ(void) const
  {
    return m_gZ;
  }

  NTL::mat_GF2 G(void) const
  {
    return m_G;
  }

  NTL::mat_GF2 P(void) const
  {
    return m_P;
  }

  NTL::mat_GF2 Pinv(void) const
  {
    return m_Pinv;
  }

  NTL::mat_GF2 S(void) const
  {
    return m_S;
  }

  NTL::mat_GF2 Sinv(void) const
  {
    return m_Sinv;
  }

  NTL::vec_GF2E L(void) const
  {
    return m_L;
  }

  QByteArray conversion(void) const
  {
    return m_conversion;
  }

  bool ok(void) const
  {
    return m_ok;
  }

  bool prepareG(const NTL::mat_GF2 &R);

  size_t k(void) const
  {
    return m_k;
  }

  size_t m(void) const
  {
    return m_m;
  }

  size_t n(void) const
  {
    return m_n;
  }

  size_t preSynTabSize(void) const
  {
    return m_preSynTab.size();
  }

  size_t t(void) const
  {
    return m_t;
  }

  std::vector<NTL::GF2EX> preSynTab(void) const
  {
    return m_preSynTab;
  }

  std::vector<long int> swappingColumns(void) const
  {
    return m_swappingColumns;
  }

  void swapSwappingColumns(const long int i, const long int j);

 private:
  NTL::GF2EX m_X;
  NTL::GF2EX m_gZ;
  NTL::mat_GF2 m_G;
  NTL::mat_GF2 m_P;
  NTL::mat_GF2 m_Pinv;
  NTL::mat_GF2 m_S;
  NTL::mat_GF2 m_Sinv;
  NTL::vec_GF2E m_L;
  QByteArray m_conversion;
  bool m_ok;
  size_t m_k;
  size_t m_m;
  size_t m_n;
  size_t m_t;
  std::vector<NTL::GF2EX> m_preSynTab;
  std::vector<long int> m_swappingColumns;
  bool prepareP(void);
  bool preparePreSynTab(void);
  bool prepareS(void);
  bool prepare_gZ(void);
  void prepareSwappingColumns(void);
  void reset(const bool ok);
};

class spoton_mceliece_public_key
{
 public:
  spoton_mceliece_public_key(const size_t m, const size_t t);
  spoton_mceliece_public_key(const size_t t, const NTL::mat_GF2 &Gcar);
  ~spoton_mceliece_public_key();

  NTL::mat_GF2 Gcar(void) const
  {
    return m_Gcar;
  }

  bool ok(void) const
  {
    return m_ok;
  }

  bool prepareGcar(const NTL::mat_GF2 &G,
		   const NTL::mat_GF2 &P,
		   const NTL::mat_GF2 &S);

  size_t k(void) const
  {
    return static_cast<size_t> (m_Gcar.NumRows());
  }

  size_t n(void) const
  {
    return static_cast<size_t> (m_Gcar.NumCols());
  }

  size_t t(void) const
  {
    return m_t;
  }

 private:
  NTL::mat_GF2 m_Gcar;
  bool m_ok;
  size_t m_t;
  void reset(const bool ok);
};

class spoton_mceliece
{
 public:
  explicit spoton_mceliece(const QByteArray &publicKey);
  spoton_mceliece(const char *privateKey,
		  const size_t privateKeyLength,
		  const QByteArray &publicKey);
  spoton_mceliece(const QByteArray &conversion,
		  const size_t m,
		  const size_t t);
  ~spoton_mceliece();
  bool decrypt(const std::stringstream &ciphertext,
	       std::stringstream &plaintext) const;
  bool encrypt(const char *plaintext,
	       const size_t plaintext_size,
	       std::stringstream &ciphertext) const;
  bool generatePrivatePublicKeys(void);

  bool ok(void) const
  {
    if(m_privateKey && m_publicKey)
      return m_privateKey->ok() && m_publicKey->ok();
    else
      return false;
  }

  size_t m(void) const
  {
    return m_m;
  }

  size_t t(void) const
  {
    return m_t;
  }

  static double expansion(const size_t m, const size_t t)
  {
    size_t k = 0;
    size_t n = 1 << m; // 2^m

    if(m * t < n)
      k = n - m * t;

    if(k > 0)
      return static_cast<double> (n) / static_cast<double> (k);
    else
      return 0.0;
  }

  void initializeSystemParameters(const size_t m, const size_t t)
  {
    m_m = m;
    m_n = 1 << m_m; // 2^m
    m_t = t;

    /*
    ** Some calculations.
    */

    if(m_m * m_t < m_n)
      m_k = m_n - m_m * m_t;
    else
      m_k = 0;
  }

  void privateKeyParameters(QByteArray &privateKey) const;
  void publicKeyParameters(QByteArray &publicKey) const;

 private:
  QByteArray m_conversion; /*
			   ** 000 - None
			   ** foa - Fujisaki-Okamoto Model A
			   ** fob - Fujisaki-Okamoto Model B
			   */
  spoton_mceliece_private_key *m_privateKey;
  spoton_mceliece_public_key *m_publicKey;
  size_t m_k;
  size_t m_m;
  size_t m_n;
  size_t m_t;
};

#endif
#endif
