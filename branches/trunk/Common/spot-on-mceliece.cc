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

#ifdef SPOTON_MCELIECE_ENABLED
#include <QByteArray>
#include <QtMath>

#include <bitset>
#include <cmath>
#include <map>
#include <stdexcept>

#include "spot-on-crypt.h"
#include "spot-on-mceliece.h"
#include "spot-on-misc.h"

spoton_mceliece_private_key::spoton_mceliece_private_key
(const char *privateKey, const size_t privateKeyLength)
{
  m_conversion = ZZZ;
  m_k = 0;
  m_m = 0;
  m_n = 0;
  m_ok = true;
  m_t = 0;

  if(!privateKey || privateKeyLength == 0)
    {
      reset(false);
      return;
    }

  char *c = 0;

  try
    {
      size_t offset = static_cast<size_t>
	(qstrlen("mceliece-private-key-000-m00t00"));

      if(privateKeyLength > offset)
	{
	  if((c = new (std::nothrow) char[privateKeyLength - offset + 1]))
	    {
	      int m = 11;

	      if(memcmp(privateKey,
			"mceliece-private-key-foa-m12t68",
			offset) == 0 ||
		 memcmp(privateKey,
			"mceliece-private-key-fob-m12t68",
			offset) == 0)
		m = 12;

	      NTL::GF2E::init
		(NTL::
		 BuildIrred_GF2X(static_cast<long int> (m))); /*
							      ** Initialize
							      ** some NTL
							      ** internal
							      ** object(s).
							      */

	      if(memcmp(privateKey,
			"mceliece-private-key-foa",
			offset - 7) == 0)
		m_conversion = FOA;
	      else if(memcmp(privateKey,
			     "mceliece-private-key-fob",
			     offset - 7) == 0)
		m_conversion = FOB;

	      memset(c, 0, privateKeyLength - offset + 1);
	      memcpy(c, privateKey + offset, privateKeyLength - offset);

	      NTL::vec_long v;
	      std::stringstream s;

	      s << c;
	      s >> m_L;
	      s >> m_Pinv;
	      s >> m_Sinv;
	      s >> m_gZ;
	      s >> v;

	      for(long int i = 0; i < v.length(); i++)
		m_swappingColumns.push_back(v[i]);

	      m_k = static_cast<size_t> (m_Sinv.NumRows());
	      m_n = static_cast<size_t> (m_L.length());
	      m_t = static_cast<size_t> (NTL::deg(m_gZ));

	      /*
	      ** Some calculations.
	      */

	      if(m_n > 0)
		m_m = static_cast<size_t> (::log2(m_n));

	      preparePreSynTab();
	    }
	  else
	    reset(false);
	}
      else
	reset(false);
    }
  catch(...)
    {
      spoton_misc::logError("spoton_mceliece_private_key::"
			    "spoton_mceliece_private_key(): failure.");
      reset(false);
    }

  delete []c;

  if(!(m_n > m_k && m_t > 0 && m_m * m_t == m_n - m_k))
    reset(false);
}

spoton_mceliece_private_key::spoton_mceliece_private_key(const size_t m,
							 const size_t t)
{
  m_k = 0;
  m_m = m;
  m_n = 1 << m_m; // 2^m
  m_ok = true;
  m_t = t;

  /*
  ** Some calculations.
  */

  if(m_m * m_t < m_n)
    m_k = m_n - m_m * m_t;

  /*
  ** Prepare important containers.
  */

  prepare_gZ();
  prepareP();
  prepareS();
  prepareSwappingColumns();

  long int n = static_cast<long int> (m_n);
  std::vector<long int> dividers;

  for(long int i = 2; i < (n - 1) / 2 + 1; i++)
    if((n - 1) % i == 0)
      dividers.push_back(i);

  try
    {
    repeat_label:

      NTL::GF2E A = NTL::GF2E::zero();

      for(long int i = 2; i < n; i++)
	{
	  NTL::GF2E gf2e;
	  NTL::GF2X gf2x;
	  bool found = true;

	  gf2x.SetLength(static_cast<long int> (m));
	  gf2x = NTL::GF2X::zero();

	  for(long int j = 0; j < static_cast<long int> (m); j++)
	    /*
	    ** 0 or 1, selected randomly.
	    */

	    NTL::SetCoeff(gf2x, j, NTL::RandomBnd(2));

	  A = gf2e = NTL::to_GF2E(gf2x);

	  for(int long j = 0; j < static_cast<long int> (dividers.size()); j++)
	    if(NTL::power(gf2e, dividers[j]) == NTL::to_GF2E(1))
	      {
		found = false;
		break;
	      }

	  if(found)
	    {
	      A = gf2e;
	      break;
	    }
	}

      NTL::GF2EX X;

      X.SetLength(2);
      NTL::SetCoeff(X, 0, 0);
      NTL::SetCoeff(X, 1, 1);
      m_L.SetLength(n);

      for(long int i = 0; i < n; i++)
	{
	  if(i == 0)
	    m_L[i] = NTL::GF2E::zero(); // Lambda-0 is always zero.
	  else if(i == 1)
	    m_L[i] = A; // Discovered generator.
	  else
	    m_L[i] = A * m_L[i - 1];

	  if(NTL::IsZero(X - m_L[i]))
	    goto repeat_label;
	}

      preparePreSynTab();
    }
  catch(...)
    {
      reset(false);
    }
}

spoton_mceliece_private_key::~spoton_mceliece_private_key()
{
  try
    {
      reset(true);
    }
  catch(...)
    {
    }
}

bool spoton_mceliece_private_key::prepareG(const NTL::mat_GF2 &R)
{
  try
    {
      if(m_n != m_swappingColumns.size())
	throw std::runtime_error("m_swappingColumns().size() mismatch");

      long int k = static_cast<long int> (m_k);
      long int n = static_cast<long int> (m_n);

      m_G.SetDims(k, n);

      for(long int i = 0; i < k; i++)
	{
	  for(long int j = 0; j < n - k; j++)
	    m_G[i][j] = R[i][j];

	  m_G[i][n - k + i] = 1;
	}

      NTL::mat_GF2 mat_GF2;

      mat_GF2.SetDims(k, n);

      for(long int i = 0; i < n; i++)
	for(long int j = 0; j < k; j++)
	  mat_GF2[j][m_swappingColumns[i]] = m_G[j][i];

      m_G = mat_GF2;
    }
  catch(const std::runtime_error &exception)
    {
      spoton_misc::logError(QString("spoton_mceliece_private_key::"
				    "prepareG(): failure (%1).").
			    arg(exception.what()));
      reset(false);
      return false;
    }
  catch(...)
    {
      spoton_misc::logError("spoton_mceliece_private_key::"
			    "prepareG(): failure.");
      reset(false);
      return false;
    }

  m_ok &= true;
  return true;
}

bool spoton_mceliece_private_key::prepareP(void)
{
  try
    {
      long int n = static_cast<long int> (m_n);
      std::map<long int, char> indexes;

      /*
      ** 0 ... 1 ... 0 ... 0 ...
      ** 1 ... 0 ... 0 ... 0 ...
      ** 0 ... 0 ... 1 ... 0 ...
      ** 0 ... 0 ... 0 ... 0 ...
      ** 0 ... 0 ... 0 ... 1 ...
      ** ...
      */

      m_P.SetDims(n, n);

      for(long int i = 0; i < m_P.NumRows(); i++)
	do
	  {
	    long int j = NTL::RandomBnd(m_P.NumCols());

	    if(indexes.find(j) == indexes.end())
	      {
		indexes[j] = 0;
		m_P[i][j] = 1;
		break;
	      }
	  }
	while(true);

      /*
      ** A permutation matrix always has an inverse.
      */

      /*
      ** (PP^T)ij = Sum(Pik(P^T)kj, k = 1..n) = Sum(PikPjk, k = 1..n).
      ** Sum(PikPjk, k = 1..n) = 1 if i = j, and 0 otherwise (I).
      ** That is, PP^T = I or the inverse of P is equal to P's transpose.
      */

      m_Pinv = NTL::transpose(m_P);
    }
  catch(...)
    {
      reset(false);
      return false;
    }

  m_ok &= true;
  return true;
}

bool spoton_mceliece_private_key::preparePreSynTab(void)
{
  try
    {
      if(NTL::IsZero(m_gZ))
	throw std::runtime_error("m_gZ is zero");
      else if(!NTL::deg(m_gZ))
	throw std::runtime_error("m_gZ has a degree of zero");

      long int n = static_cast<long int> (m_n);

      if(m_L.length() != n)
	throw std::runtime_error("m_L.length() mismatch");

      m_X.SetLength(2);
      NTL::SetCoeff(m_X, 0, 0);
      NTL::SetCoeff(m_X, 1, 1);
      m_preSynTab.clear();

      for(long int i = 0; i < n; i++)
	{
	  NTL::GF2EX gf2ex = m_X - m_L[i];

	  if(!NTL::IsZero(gf2ex)) // Should always be true.
	    m_preSynTab.push_back(NTL::InvMod(gf2ex, m_gZ));
	  else
	    m_preSynTab.push_back(m_X);
	}
    }
  catch(const std::runtime_error &exception)
    {
      spoton_misc::logError(QString("spoton_mceliece_private_key::"
				    "preparePreSynTab(): failure (%1).").
			    arg(exception.what()));
      reset(false);
      return false;
    }
  catch(...)
    {
      spoton_misc::logError("spoton_mceliece_private_key::"
			    "preparePreSynTab(): failure.");
      reset(false);
      return false;
    }

  m_ok &= true;
  return true;
}

bool spoton_mceliece_private_key::prepareS(void)
{
  try
    {
      int long k = static_cast<long int> (m_k);

      m_S.SetDims(k, k);

      do
	{
	  for(long int i = 0; i < k; i++)
	    m_S[i] = NTL::random_vec_GF2(k);
	}
      while(NTL::determinant(m_S) == 0);

      m_Sinv = NTL::inv(m_S);
    }
  catch(...)
    {
      reset(false);
      return false;
    }

  m_ok &= true;
  return true;
}

bool spoton_mceliece_private_key::prepare_gZ(void)
{
  try
    {
      NTL::GF2E::init
	(NTL::BuildIrred_GF2X(static_cast<long int> (m_m))); /*
							     ** Initialize
							     ** some NTL
							     ** internal
							     ** object(s).
							     */
      m_gZ = NTL::BuildRandomIrred
	(NTL::BuildIrred_GF2EX(static_cast<long int> (m_t)));
    }
  catch(...)
    {
      reset(false);
      return false;
    }

  m_ok &= true;
  return true;
}

void spoton_mceliece_private_key::prepareSwappingColumns(void)
{
  m_swappingColumns.clear();

  long int n = static_cast<long int> (m_n);

  for(long int i = 0; i < n; i++)
    m_swappingColumns.push_back(i);
}

void spoton_mceliece_private_key::reset(const bool ok)
{
  NTL::clear(m_G);
  NTL::clear(m_L);
  NTL::clear(m_P);
  NTL::clear(m_Pinv);
  NTL::clear(m_S);
  NTL::clear(m_Sinv);
  NTL::clear(m_X);
  NTL::clear(m_gZ);
  m_conversion = ZZZ;
  m_k = 0;
  m_m = 0;
  m_n = 0;
  m_ok = ok;
  m_preSynTab.clear();
  m_swappingColumns.clear();
  m_t = 0;
}

void spoton_mceliece_private_key::swapSwappingColumns(const long int i,
						      const long int j)
{
  if(i < 0 || i >= static_cast<long int> (m_swappingColumns.size()) ||
     j < 0 || j >= static_cast<long int> (m_swappingColumns.size()))
    {
      m_ok = false;
      return;
    }

  long int t = m_swappingColumns[i];

  m_swappingColumns[i] = m_swappingColumns[j];
  m_swappingColumns[j] = t;
}

spoton_mceliece_public_key::spoton_mceliece_public_key(const size_t m,
						       const size_t t)
{
  m_ok = true;
  m_t = t;

  /*
  ** Some calculations.
  */

  long int k = 0;
  long int n = 1 << static_cast<long int> (m);

  k = n - static_cast<long int> (m) * static_cast<long int> (m_t);

  try
    {
      m_Gcar.SetDims(k, n);
    }
  catch(...)
    {
      NTL::clear(m_Gcar);
      m_ok = false;
    }
}

spoton_mceliece_public_key::spoton_mceliece_public_key
(const size_t t, const NTL::mat_GF2 &Gcar)
{
  m_Gcar = Gcar;
  m_ok = true;
  m_t = t;
}

spoton_mceliece_public_key::~spoton_mceliece_public_key()
{
  reset(true);
}

bool spoton_mceliece_public_key::prepareGcar(const NTL::mat_GF2 &G,
					     const NTL::mat_GF2 &P,
					     const NTL::mat_GF2 &S)
{
  try
    {
      m_Gcar = S * G * P;
    }
  catch(...)
    {
      reset(false);
      return false;
    }

  m_ok &= true;
  return true;
}

void spoton_mceliece_public_key::reset(const bool ok)
{
  NTL::clear(m_Gcar);
  m_ok = ok;
  m_t = 0;
}

spoton_mceliece::spoton_mceliece(const QByteArray &pk)
{
  m_conversion = spoton_mceliece_private_key::ZZZ;
  m_k = 0;
  m_m = 0;
  m_n = 0;
  m_privateKey = 0;
  m_publicKey = 0;
  m_t = 0;

  QByteArray publicKey(qUncompress(pk)); // Key is compressed.
  size_t offset = static_cast<size_t>
    (qstrlen("mceliece-public-key-000-m00t00"));

  if(publicKey.length() > static_cast<int> (offset))
    {
      NTL::mat_GF2 Gcar;

      try
	{
	  std::stringstream s;

	  s << publicKey.mid(static_cast<int> (offset)).constData();
	  s >> Gcar; // ~500 ms.
	  s >> m_t;
	  m_publicKey = new (std::nothrow)
	    spoton_mceliece_public_key(m_t, Gcar);
	}
      catch(...)
	{
	  NTL::clear(Gcar);
	  delete m_publicKey;
	  m_publicKey = 0;
	  m_t = 0;
	}
    }

  if(m_publicKey && m_publicKey->ok())
    {
      if(publicKey.startsWith("mceliece-public-key-foa"))
	m_conversion = spoton_mceliece_private_key::FOA;
      else if(publicKey.startsWith("mceliece-public-key-fob"))
	m_conversion = spoton_mceliece_private_key::FOB;

      m_k = m_publicKey->k();
      m_n = m_publicKey->n();

      /*
      ** Calculate m.
      */

      if(m_n > 0)
	m_m = ::log2(m_n);
    }
  else
    {
      delete m_publicKey;
      m_publicKey = 0;
    }

  if(!m_publicKey)
    spoton_misc::logError("spoton_mceliece::spoton_mceliece(): "
			  "m_publicKey is zero!");
}

spoton_mceliece::spoton_mceliece(const QByteArray &conversion,
				 const size_t m,
				 const size_t t)
{
  QByteArray c(conversion.mid(0, 3).toLower());

  if(c == "foa")
    m_conversion = spoton_mceliece_private_key::FOA;
  else if(c == "fob")
    m_conversion = spoton_mceliece_private_key::FOB;
  else
    m_conversion = spoton_mceliece_private_key::ZZZ;

  m_privateKey = 0;
  m_publicKey = 0;

  try
    {
      initializeSystemParameters(m, t);
    }
  catch(...)
    {
    }
}

spoton_mceliece::spoton_mceliece(const char *privateKey,
				 const size_t privateKeyLength,
				 const QByteArray &publicKey)
{
  m_privateKey = new (std::nothrow) spoton_mceliece_private_key
    (privateKey, privateKeyLength);
  m_publicKey = 0;

  if(m_privateKey && m_privateKey->ok())
    {
      m_conversion = m_privateKey->conversion();
      m_k = m_privateKey->k();
      m_m = m_privateKey->m();
      m_n = m_privateKey->n();
      m_t = m_privateKey->t();
    }
  else
    {
      delete m_privateKey;
      m_privateKey = 0;
    }

  size_t offset = static_cast<size_t>
    (qstrlen("mceliece-public-key-000-m00t00"));

  if(publicKey.length() > static_cast<int> (offset))
    {
      NTL::mat_GF2 Gcar;

      try
	{
	  size_t t = 0;
	  std::stringstream s;

	  s << publicKey.mid(static_cast<int> (offset)).constData();
	  s >> Gcar; // ~500 ms.
	  s >> t;
	  m_publicKey = new (std::nothrow) spoton_mceliece_public_key(t, Gcar);
	}
      catch(...)
	{
	  NTL::clear(Gcar);
	  delete m_publicKey;
	  m_publicKey = 0;
	}
    }

  if(!(m_privateKey && m_privateKey->ok() && m_publicKey && m_publicKey->ok()))
    {
      delete m_privateKey;
      m_privateKey = 0;
      delete m_publicKey;
      m_publicKey = 0;
    }

  if(!m_privateKey)
    spoton_misc::logError("spoton_mceliece::spoton_mceliece(): "
			  "m_privateKey is zero!");

  if(!m_publicKey)
    spoton_misc::logError("spoton_mceliece::spoton_mceliece(): "
			  "m_publicKey is zero!");
}

spoton_mceliece::~spoton_mceliece()
{
  delete m_privateKey;
  delete m_publicKey;
}

bool spoton_mceliece::decrypt(const std::stringstream &ciphertext,
			      std::stringstream &plaintext) const
{
  if(!m_privateKey || !m_privateKey->ok() || !m_publicKey || !m_publicKey->ok())
    return false;

  size_t plaintext_size = static_cast<size_t>
    (std::ceil(m_k / CHAR_BIT)); /*
				 ** m_k is not necessarily
				 ** a multiple of CHAR_BIT.
				 ** It may be, however.
				 */

  if(Q_UNLIKELY(plaintext_size == 0))
    return false;

  char *p = new (std::nothrow) char[plaintext_size];

  if(!p)
    {
      spoton_misc::logError("spoton_mceliece::decrypt(): p is zero!");
      return false;
    }

  try
    {
      NTL::GF2E::init
	(NTL::BuildIrred_GF2X(static_cast<long int> (m_m))); /*
							     ** Initialize
							     ** some NTL
							     ** internal
							     ** object(s).
							     */

      NTL::vec_GF2 c1;
      NTL::vec_GF2 c2;
      QByteArray salt1;
      QByteArray salt2;
      std::stringstream s;

      s << ciphertext.rdbuf();
      s >> c1;

      if(c1.length() != static_cast<long int> (m_n))
	throw std::runtime_error("c1.length() mismatch");

      switch(m_conversion)
	{
	case spoton_mceliece_private_key::FOA:
	  {
	    s >> c2;

	    if(c2.length() != static_cast<long int> (m_k))
	      throw std::runtime_error("c2.length() mismatch");

	    std::string string;

	    s >> string;
	    salt1 = QByteArray::fromBase64(string.c_str());

	    if(salt1.length() != 32)
	      throw std::runtime_error("salt1.length() mismatch");

	    s >> string;
	    salt2 = QByteArray::fromBase64(string.c_str());

	    if(salt2.length() != 32)
	      throw std::runtime_error("salt2.length() mismatch");
	    break;
	  }
	case spoton_mceliece_private_key::FOB:
	  {
	    s >> c2;

	    if(c2.length() != static_cast<long int> (m_k))
	      throw std::runtime_error("c2.length() mismatch");

	    break;
	  }
	default:
	  {
	    break;
	  }
	}

      NTL::vec_GF2 ccar = c1 * m_privateKey->Pinv();

      if(ccar.length() != static_cast<long int> (m_n))
	throw std::runtime_error("ccar.length() mismatch");
      else if(m_n != m_privateKey->preSynTabSize())
	throw std::runtime_error("preSynTabSize() mismatch");

      /*
      ** Patterson.
      */

      NTL::GF2EX syndrome = NTL::GF2EX::zero();
      long int n = static_cast<long int> (m_n);
      std::vector<NTL::GF2EX> v(m_privateKey->preSynTab());

      for(long int i = 0; i < n; i++)
	if(ccar[i] != 0)
	  syndrome += v[i];

      NTL::GF2EX sigma = NTL::GF2EX::zero();

      if(!NTL::IsZero(syndrome))
	{
	  NTL::GF2EX T = NTL::InvMod(syndrome, m_privateKey->gZ()) +
	    m_privateKey->X();
	  NTL::GF2EX tau = NTL::GF2EX::zero();
	  NTL::ZZ exponent = NTL::power
	    (NTL::power2_ZZ(static_cast<long int> (m_t)),
	     static_cast<long int> (m_m)) / 2;

	  if(NTL::IsZero(T))
	    sigma = m_privateKey->X();
	  else
	    {
	      tau = NTL::PowerMod(T, exponent, m_privateKey->gZ());

	      NTL::GF2E c1;
	      NTL::GF2E c2;
	      NTL::GF2E c3;
	      NTL::GF2E c4;
	      NTL::GF2EX gf2ex = NTL::GF2EX::zero();
	      NTL::GF2EX r0 = m_privateKey->gZ();
	      NTL::GF2EX r1 = tau;
	      NTL::GF2EX u0 = NTL::GF2EX::zero();
	      NTL::GF2EX u1;
	      long int dr = NTL::deg(r1);
	      long int dt = NTL::deg(r0) - dr;
	      long int du = 0;
	      long int t = static_cast<long int> (m_t / 2);

	      u1.SetLength(1);
	      NTL::SetCoeff(u1, 0, 1);

	      while(dr >= t + 1)
		{
		  for(long int j = dt; j >= 0; j--)
		    {
		      NTL::GetCoeff(c1, r0, dr + j);
		      NTL::GetCoeff(c2, r1, dr);
		      c3 = c1 * NTL::inv(c2);
		      c1 = c3;

		      if(!NTL::IsZero(c1))
			{
			  for(long int i = 0; i <= du; i++)
			    {
			      NTL::GetCoeff(c3, u0, i + j);
			      NTL::GetCoeff(c4, u1, i);
			      c3 = c3 + c1 * c4;
			      NTL::SetCoeff(u0, i + j, c3);
			    }

			  for(long int i = 0; i <= dr; i++)
			    {
			      NTL::GetCoeff(c3, r0, i + j);
			      NTL::GetCoeff(c4, r1, i);
			      c3 = c3 + c1 * c4;
			      NTL::SetCoeff(r0, i + j, c3);
			    }
			}
		    }

		  gf2ex = r0;
		  r0 = r1;
		  r1 = gf2ex;
		  gf2ex = u0;
		  u0 = u1;
		  u1 = gf2ex;
		  du += dt;
		  dt = 1;
		  NTL::GetCoeff(c3, r1, dr - dt);

		  while(NTL::IsZero(c3))
		    {
		      dt++;
		      NTL::GetCoeff(c3, r1, dr - dt);
		    }

		  dr -= dt;
		}

	      NTL::GF2EX alpha = NTL::GF2EX::zero();

	      NTL::rem(alpha, r1, m_privateKey->gZ());
	      sigma = NTL::power(alpha, 2) +
		NTL::power(u1, 2) * m_privateKey->X();
	    }
	}

      NTL::vec_GF2 e;
      NTL::vec_GF2E L = m_privateKey->L();

      e.SetLength(n);

      for(long int i = 0; i < n; i++)
	if(NTL::IsZero(NTL::eval(sigma, L[i])))
	  e[i] = 1;

      ccar += e;

      NTL::vec_GF2 m;
      NTL::vec_GF2 mcar;
      NTL::vec_GF2 vec_GF2;
      std::vector<long int> swappingColumns(m_privateKey->swappingColumns());

      vec_GF2.SetLength(n);

      for(long int i = 0; i < n; i++)
	vec_GF2[i] = ccar[swappingColumns[i]];

      long int k = static_cast<long int> (m_k);

      mcar.SetLength(k);

      for(long int i = 0; i < k; i++)
	mcar[i] = vec_GF2[i + n - k];

      m = mcar * m_privateKey->Sinv();

      switch(m_conversion)
	{
	case spoton_mceliece_private_key::FOA:
	  {
	    NTL::vec_GF2 ecar;
	    std::stringstream stream1;

	    ecar = c1 - m * m_publicKey->Gcar(); // Original error vector.
	    stream1 << ecar;

	    QByteArray bytes
	      (stream1.str().c_str(), static_cast<int> (stream1.str().size()));
	    bool ok = true;

	    bytes = spoton_crypt::sha256Hash(bytes, &ok);

	    if(!ok)
	      throw std::runtime_error("spoton_crypt::sha256Hash() failure");

	    /*
	    ** Generate a key stream via PBKDF2 from SHA-256(m).
	    */

	    QByteArray keyStream2
	      (static_cast<int> (qCeil(static_cast<double> (m.length()) /
				       CHAR_BIT)), 0);

	    if(gcry_kdf_derive(bytes.constData(),
			       static_cast<size_t> (bytes.length()),
			       GCRY_KDF_PBKDF2,
			       gcry_md_map_name("sha256"),
			       salt2.constData(),
			       static_cast<size_t> (salt2.length()),
			       1,
			       static_cast<size_t> (keyStream2.length()),
			       keyStream2.data()) != 0)
	      throw std::runtime_error("gcry_kdf_derive() failure");

	    NTL::vec_GF2 h;

	    h.SetLength(c2.length());

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (keyStream2.size()); i++)
	      {
		std::bitset<CHAR_BIT> b(keyStream2[static_cast<int> (i)]);

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < h.length(); j++, k++)
		  h[k] = b[static_cast<size_t> (j)];
	      }

	    for(long int i = 0; i < c2.length(); i++)
	      mcar[i] = (c2[i] == 0 ? 0 : 1) ^ (h[i] == 0 ? 0 : 1);

	    std::stringstream stream2;

	    stream2 << ecar << mcar;
	    bytes = QByteArray
	      (stream2.str().c_str(), static_cast<int> (stream2.str().size()));
	    bytes = spoton_crypt::sha256Hash(bytes, &ok);

	    if(!ok)
	      throw std::runtime_error("spoton_crypt::sha256Hash() failure");

	    /*
	    ** Generate a key stream via PBKDF2 from SHA-256(e || mcar).
	    */

	    QByteArray keyStream1
	      (static_cast<int> (qCeil(static_cast<double> (m.length()) /
				       CHAR_BIT)), 0);

	    if(gcry_kdf_derive(bytes.constData(),
			       static_cast<size_t> (bytes.length()),
			       GCRY_KDF_PBKDF2,
			       gcry_md_map_name("sha256"),
			       salt1.constData(),
			       static_cast<size_t> (salt1.length()),
			       1,
			       static_cast<size_t> (keyStream1.length()),
			       keyStream1.data()) != 0)
	      throw std::runtime_error("gcry_kdf_derive() failure");

	    NTL::vec_GF2 rcar;

	    rcar.SetLength(m.length());

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (keyStream1.size()); i++)
	      {
		std::bitset<CHAR_BIT> b(keyStream1[static_cast<int> (i)]);

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < rcar.length(); j++, k++)
		  rcar[k] = b[static_cast<size_t> (j)];
	      }

	    if(c1 != (rcar * m_publicKey->Gcar() + ecar))
	      throw std::runtime_error("c1 is not equal to E(rcar, ecar)");

	    memset(p, 0, plaintext_size);

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (plaintext_size);
		i++)
	      {
		std::bitset<CHAR_BIT> b;

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < mcar.length(); j++, k++)
		  b[static_cast<size_t> (j)] = mcar[k] == 0 ? 0 : 1;

		p[static_cast<size_t> (i)] = static_cast<char> (b.to_ulong());
	      }

	    plaintext.write(p, plaintext_size);
	    break;
	  }
	case spoton_mceliece_private_key::FOB:
	  {
	    NTL::vec_GF2 ecar;
	    std::stringstream stream1;

	    ecar = c1 - m * m_publicKey->Gcar(); // Original error vector.
	    stream1 << ecar;

	    QByteArray keyStream2
	      (stream1.str().c_str(), static_cast<int> (stream1.str().size()));
	    bool ok = true;

	    keyStream2 = spoton_crypt::shake256
	      (keyStream2,
	       qCeil(static_cast<double> (m.length()) / CHAR_BIT),
	       &ok);

	    if(!ok)
	      throw std::runtime_error("spoton_crypt::shake256() failure");

	    NTL::vec_GF2 h;

	    h.SetLength(c2.length());

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (keyStream2.size()); i++)
	      {
		std::bitset<CHAR_BIT> b(keyStream2[static_cast<int> (i)]);

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < h.length(); j++, k++)
		  h[k] = b[static_cast<size_t> (j)];
	      }

	    for(long int i = 0; i < c2.length(); i++)
	      mcar[i] = (c2[i] == 0 ? 0 : 1) ^ (h[i] == 0 ? 0 : 1);

	    std::stringstream stream2;

	    stream2 << ecar << mcar;

	    QByteArray keyStream1
	      (stream2.str().c_str(), static_cast<int> (stream2.str().size()));

	    keyStream1 = spoton_crypt::shake256
	      (keyStream1,
	       qCeil(static_cast<double> (m.length()) / CHAR_BIT),
	       &ok);

	    if(!ok)
	      throw std::runtime_error("spoton_crypt::shake256() failure");

	    NTL::vec_GF2 rcar;

	    rcar.SetLength(m.length());

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (keyStream1.size()); i++)
	      {
		std::bitset<CHAR_BIT> b(keyStream1[static_cast<int> (i)]);

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < rcar.length(); j++, k++)
		  rcar[k] = b[static_cast<size_t> (j)];
	      }

	    if(c1 != (rcar * m_publicKey->Gcar() + ecar))
	      throw std::runtime_error("c1 is not equal to E(rcar, ecar)");

	    memset(p, 0, plaintext_size);

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (plaintext_size);
		i++)
	      {
		std::bitset<CHAR_BIT> b;

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < mcar.length(); j++, k++)
		  b[static_cast<size_t> (j)] = mcar[k] == 0 ? 0 : 1;

		p[static_cast<size_t> (i)] = static_cast<char> (b.to_ulong());
	      }

	    plaintext.write(p, plaintext_size);
	    break;
	  }
	case spoton_mceliece_private_key::ZZZ:
	  {
	    memset(p, 0, plaintext_size);

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (plaintext_size);
		i++)
	      {
		std::bitset<CHAR_BIT> b;

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < m.length(); j++, k++)
		  b[static_cast<size_t> (j)] = m[k] == 0 ? 0 : 1;

		p[static_cast<size_t> (i)] = static_cast<char> (b.to_ulong());
	      }

	    plaintext.write(p, plaintext_size);
	    break;
	  }
	default:
	  {
	    break;
	  }
	}
    }
  catch(const std::runtime_error &exception)
    {
      spoton_misc::logError
	(QString("spoton_mceliece::decrypt(): failure (%1).").
	 arg(exception.what()));
      delete []p;
      plaintext.clear();
      return false;
    }
  catch(...)
    {
      spoton_misc::logError("spoton_mceliece::decrypt(): failure.");
      delete []p;
      plaintext.clear();
      return false;
    }

  delete []p;
  return true;
}

bool spoton_mceliece::encrypt(const char *plaintext,
			      const size_t plaintext_size,
			      std::stringstream &ciphertext) const
{
  if(!m_publicKey || !m_publicKey->ok() || !plaintext || plaintext_size == 0)
    return false;

  if(CHAR_BIT * plaintext_size > static_cast<size_t> (m_k))
    return false;

  try
    {
      /*
      ** Represent the message as a binary vector of length k.
      */

      NTL::vec_GF2 m;

      m.SetLength(static_cast<long int> (m_k));

      for(size_t i = 0, k = 0; i < plaintext_size; i++)
	{
	  std::bitset<CHAR_BIT> b(plaintext[i]);

	  for(long int j = 0; j < static_cast<long int> (b.size()) && k < m_k;
	      j++, k++)
	    m[static_cast<long int> (k)] = b[static_cast<size_t> (j)];
	}

      /*
      ** Create the random vector e. It will contain at most t ones.
      */

      NTL::vec_GF2 e;
      long int t = static_cast<long int> (m_t);
      long int ts = 0;

      e.SetLength(static_cast<long int> (m_n));

      do
	{
	  long int i = NTL::RandomBnd(e.length());

	  if(e[i] == 0)
	    {
	      e[i] = 1;
	      ts += 1;
	    }
	}
      while(t > ts);

      switch(m_conversion)
	{
	case spoton_mceliece_private_key::FOA:
	  {
	    std::stringstream stream1;

	    stream1 << e << m;

	    QByteArray bytes
	      (stream1.str().c_str(), static_cast<int> (stream1.str().size()));
	    bool ok = true;

	    bytes = spoton_crypt::sha256Hash(bytes, &ok);

	    if(!ok)
	      throw std::runtime_error("spoton_crypt::sha256Hash() failure");

	    /*
	    ** Generate a key stream via PBKDF2 from SHA-256(e || m).
	    */

	    QByteArray keyStream1
	      (static_cast<int> (qCeil(static_cast<double> (m.length()) /
				       CHAR_BIT)), 0);
	    QByteArray salt1(spoton_crypt::weakRandomBytes(32));

	    if(gcry_kdf_derive(bytes.constData(),
			       static_cast<size_t> (bytes.length()),
			       GCRY_KDF_PBKDF2,
			       gcry_md_map_name("sha256"),
			       salt1.constData(),
			       static_cast<size_t> (salt1.length()),
			       1,
			       static_cast<size_t> (keyStream1.length()),
			       keyStream1.data()) != 0)
	      throw std::runtime_error("gcry_kdf_derive() failure");

	    NTL::vec_GF2 r;

	    r.SetLength(m.length());

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (keyStream1.size()); i++)
	      {
		std::bitset<CHAR_BIT> b(keyStream1[static_cast<int> (i)]);

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < r.length(); j++, k++)
		  r[k] = b[static_cast<size_t> (j)];
	      }

	    ciphertext << r * m_publicKey->Gcar() + e;

	    std::stringstream stream2;

	    stream2 << e;
	    bytes = QByteArray
	      (stream2.str().c_str(), static_cast<int> (stream2.str().size()));
	    bytes = spoton_crypt::sha256Hash(bytes, &ok);

	    if(!ok)
	      throw std::runtime_error("spoton_crypt::sha256Hash() failure");

	    /*
	    ** Generate a key stream via PBKDF2 from SHA-256(e).
	    */

	    QByteArray keyStream2
	      (static_cast<int> (qCeil(static_cast<double> (m.length()) /
				       CHAR_BIT)), 0);
	    QByteArray salt2(spoton_crypt::weakRandomBytes(32));

	    if(gcry_kdf_derive(bytes.constData(),
			       static_cast<size_t> (bytes.length()),
			       GCRY_KDF_PBKDF2,
			       gcry_md_map_name("sha256"),
			       salt2.constData(),
			       static_cast<size_t> (salt2.length()),
			       1,
			       static_cast<size_t> (keyStream2.length()),
			       keyStream2.data()) != 0)
	      throw std::runtime_error("gcry_kdf_derive() failure");

	    NTL::vec_GF2 h;

	    h.SetLength(m.length());

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (keyStream2.size()); i++)
	      {
		std::bitset<CHAR_BIT> b(keyStream2[static_cast<int> (i)]);

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < h.length(); j++, k++)
		  h[k] = b[static_cast<size_t> (j)];
	      }

	    for(long int i = 0; i < m.length(); i++)
	      m[i] = (h[i] == 0 ? 0 : 1) ^ (m[i] == 0 ? 0 : 1);

	    ciphertext << m
		       << salt1.toBase64().constData()
		       << " "
		       << salt2.toBase64().constData();
	    break;
	  }
	case spoton_mceliece_private_key::FOB:
	  {
	    std::stringstream stream1;

	    stream1 << e << m;

	    QByteArray keyStream1
	      (stream1.str().c_str(), static_cast<int> (stream1.str().size()));
	    bool ok = true;

	    keyStream1 = spoton_crypt::shake256
	      (keyStream1,
	       static_cast<size_t> (qCeil(static_cast<double> (m.length()) /
					  CHAR_BIT)),
	       &ok);

	    if(!ok)
	      throw std::runtime_error("spoton_crypt::shake256() failure");

	    NTL::vec_GF2 r;

	    r.SetLength(m.length());

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (keyStream1.size()); i++)
	      {
		std::bitset<CHAR_BIT> b(keyStream1[static_cast<int> (i)]);

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < r.length(); j++, k++)
		  r[k] = b[static_cast<size_t> (j)];
	      }

	    ciphertext << r * m_publicKey->Gcar() + e;

	    std::stringstream stream2;

	    stream2 << e;

	    QByteArray keyStream2
	      (stream2.str().c_str(), static_cast<int> (stream2.str().size()));

	    keyStream2 = spoton_crypt::shake256
	      (keyStream2,
	       static_cast<size_t> (qCeil(static_cast<double> (m.length()) /
					  CHAR_BIT)),
	       &ok);

	    if(!ok)
	      throw std::runtime_error("spoton_crypt::shake256 failure");

	    NTL::vec_GF2 h;

	    h.SetLength(m.length());

	    for(long int i = 0, k = 0;
		i < static_cast<long int> (keyStream2.size()); i++)
	      {
		std::bitset<CHAR_BIT> b(keyStream2[static_cast<int> (i)]);

		for(long int j = 0; j < static_cast<long int> (b.size()) &&
		      k < h.length(); j++, k++)
		  h[k] = b[static_cast<size_t> (j)];
	      }

	    for(long int i = 0; i < m.length(); i++)
	      m[i] = (h[i] == 0 ? 0 : 1) ^ (m[i] == 0 ? 0 : 1);

	    ciphertext << m;
	    break;
	  }
	default:
	  {
	    ciphertext << m * m_publicKey->Gcar() + e;
	    break;
	  }
	}
    }
  catch(...)
    {
      ciphertext.clear();
      return false;
    }

  return true;
}

bool spoton_mceliece::generatePrivatePublicKeys(void)
{
  delete m_privateKey;
  m_privateKey = 0;
  delete m_publicKey;
  m_publicKey = 0;
  m_privateKey = new (std::nothrow) spoton_mceliece_private_key(m_m, m_t);

  if(!m_privateKey)
    return false;

  m_publicKey = new (std::nothrow) spoton_mceliece_public_key(m_m, m_t);

  if(!m_publicKey)
    {
      delete m_privateKey;
      m_privateKey = 0;
      return false;
    }

  try
    {
      if(!m_privateKey->ok())
	throw std::runtime_error("private key error");
      else if(!m_publicKey->ok())
	throw std::runtime_error("public key error");

      /*
      ** Create the parity-check matrix H.
      */

      NTL::GF2EX gZ = m_privateKey->gZ();
      NTL::mat_GF2 H;
      NTL::vec_GF2E L = m_privateKey->L();
      long int m = static_cast<long int> (m_m);
      long int n = static_cast<long int> (m_n);
      long int t = static_cast<long int> (m_t);

      H.SetDims(m * t, n);

      for(long int i = 0; i < t; i++)
	for(long int j = 0; j < n; j++)
	  {
	    NTL::GF2E gf2e = NTL::inv(NTL::eval(gZ, L[j])) *
	      NTL::power(L[j], i);
	    NTL::vec_GF2 v = NTL::to_vec_GF2(gf2e._GF2E__rep);

	    for(long int k = 0; k < v.length(); k++)
	      H[i * m + k][j] = v[k];
	  }

      NTL::gauss(H);

      /*
      ** Reduced row echelon form.
      */

      long int lead = 0;

      for(long int r = 0; r < H.NumRows(); r++)
	{
	  if(H.NumCols() <= lead)
	    break;

	  long int i = r;

	  while(H[i][lead] == 0)
	    {
	      i += 1;

	      if(H.NumRows() == i)
		{
		  i = r;
		  lead += 1;

		  if(H.NumCols() == lead)
		    goto done_label;
		}
	    }

	  NTL::swap(H[i], H[r]);

	  if(H[r][lead] != 0)
	    for(long int j = 0; j < H.NumCols(); j++)
	      H[r][j] /= H[r][lead];

	  for(long int j = 0; j < H.NumRows(); j++)
	    if(j != r)
	      H[j] = H[j] - H[j][lead] * H[r];

	  lead += 1;
	}

    done_label:

      /*
      ** H = [I|R], systematic form.
      ** More information at https://en.wikipedia.org/wiki/Generator_matrix.
      */

      for(long int i = 0; i < H.NumRows(); i++)
	if(H[i][i] == 0)
	  {
	    bool pivot = true;

	    for(long int j = i + 1; j < H.NumCols(); j++)
	      {
		if(H[i][j] == 1)
		  {
		    for(long int k = i + 1; k < H.NumRows(); k++)
		      if(H[k][j] == 1)
			{
			  pivot = false;
			  break;
			}

		    if(!pivot)
		      break;

		    for(long int k = i - 1; k >= 0; k--)
		      if(H[k][j] == 1)
			{
			  pivot = false;
			  break;
			}
		  }
		else
		  continue;

		if(pivot)
		  {
		    m_privateKey->swapSwappingColumns(i, j);
		    break;
		  }
	      }
	  }

      NTL::mat_GF2 mat_GF2;
      std::vector<long int> swappingColumns(m_privateKey->swappingColumns());

      mat_GF2.SetDims(H.NumRows(), H.NumCols());

      for(long int i = 0; i < n; i++)
	for(long int j = 0; j < m * t; j++)
	  mat_GF2[j][i] = H[j][swappingColumns[i]];

      H = mat_GF2;

      NTL::mat_GF2 R;

      R.SetDims(m * t, n - m * t); // R^T has n - mt rows and mt columns.

      for(long int i = 0; i < R.NumRows(); i++)
	for(long int j = 0; j < R.NumCols(); j++)
	  R[i][j] = H[i][j + m * t];

      R = NTL::transpose(R);
      m_privateKey->prepareG(R);
      m_publicKey->prepareGcar
	(m_privateKey->G(), m_privateKey->P(), m_privateKey->S());
    }
  catch(const std::runtime_error &exception)
    {
      spoton_misc::logError(QString("spoton_mceliece::"
				    "generatePrivatePublicKeys(): "
				    "failure (%1).").
			    arg(exception.what()));
      delete m_privateKey;
      m_privateKey = 0;
      delete m_publicKey;
      m_publicKey = 0;
      return false;
    }
  catch(...)
    {
      spoton_misc::logError("spoton_mceliece::"
			    "generatePrivatePublicKeys(): "
			    "failure.");
      delete m_privateKey;
      m_privateKey = 0;
      delete m_publicKey;
      m_publicKey = 0;
      return false;
    }

  return true;
}

void spoton_mceliece::privateKeyParameters(QByteArray &privateKey) const
{
  privateKey.clear();

  if(!m_privateKey)
    return;

  try
    {
      std::stringstream s;

      s << m_privateKey->L()
	<< m_privateKey->Pinv()
	<< m_privateKey->Sinv()
	<< m_privateKey->gZ();

      NTL::vec_long v;

      v.SetLength
	(static_cast<long int> (m_privateKey->swappingColumns().size()));

      std::vector<long int> swappingColumns(m_privateKey->swappingColumns());

      for(size_t i = 0; i < m_privateKey->swappingColumns().size(); i++)
	v[static_cast<long int> (i)] = swappingColumns[i];

      s << v;

      /*
      ** A deep copy is required.
      */

      privateKey = QByteArray
	(s.str().c_str(), static_cast<int> (s.str().size()));
    }
  catch(...)
    {
      privateKey.clear();
    }
}

void spoton_mceliece::publicKeyParameters(QByteArray &publicKey) const
{
  publicKey.clear();

  if(!m_publicKey)
    return;

  try
    {
      std::stringstream s;

      s << m_publicKey->Gcar() << m_publicKey->t();

      /*
      ** A deep copy is required.
      */

      publicKey = QByteArray
	(s.str().c_str(), static_cast<int> (s.str().size()));
    }
  catch(...)
    {
      publicKey.clear();
    }
}

#endif
