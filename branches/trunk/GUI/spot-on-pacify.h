/*
** Copyright (c) 2011 - 10^10^10, Mattias Andrée, Alexis Megas.
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

#ifndef _spoton_pacify_h_
#define _spoton_pacify_h_

#include <algorithm>
#include <cmath>
#include <map>
#include <string>

class spoton_pacify
{
 public:
  spoton_pacify(const std::string &passphrase)
  {
    size_t n = passphrase.length();

    // Convert from UTF-8 to UTF-32.
    //   Note this is not an attack-safe implementation,
    //   this implementation allows characters that are
    //   encoded with an excessive number of bytes.

    // Count the number of characters.
    //   Byte      Datum
    //   0.......  Single-byte character                   (Count these.)
    //   11......  Initial byte in multibyte character     (Count these.)
    //   10......  Non-initial byte in multibyte character (Do not count these.)

    m_passphrase = 0;
    m_passphrase_length = 0;

    for(size_t i = 0; i < n; i++)
      if((static_cast<int> (passphrase.at(i)) & 0xc0) != 0x80)
	m_passphrase_length += 1;

    if(m_passphrase_length > 0)
      m_passphrase = new long int[m_passphrase_length];

    // Convert.
    //   0.......
    //   110..... 10......
    //   1110.... 10...... 10......
    //   11110... 10...... 10...... 10......
    //   111110.. 10...... 10...... 10...... 10......
    //   1111110. 10...... 10...... 10...... 10...... 10......

    for(size_t i = 0, j = 0; i < n; j++)
      {
	int c = static_cast<int> (passphrase.at(i++));

	if((c & 0x80) == 0)
	  {
	    // Single-byte character.

	    if(m_passphrase)
	      m_passphrase[j] = static_cast<long int> (c);
	  }
	else if((c & 0xc0) == 0xc0)
	  {
	    // Initial byte in multibyte-character.

	    int b = 0;

	    // Get width of character.
	    //   110.....  2-byte character  11-bit character
	    //   1110....  3-byte character  16-bit character
	    //   11110...  4-byte character  21-bit character (New UTF-8 Limit)
	    //   111110..  5-byte character  26-bit character
	    //   1111110.  6-byte character  31-bit character (Old UTF-8 Limit)

	    while(c & 0x80)
	      b++, c <<= 1;

	    if(b > 6)
	      {
		if(m_passphrase)
		  m_passphrase[j] = 0; /* XXX invalid input. */

		break;
	      }

	    // Get bits (represented by dots in the table above)
	    // stored in the start byte.

	    c = (c & 0xff) >> b;

	    if(m_passphrase)
	      m_passphrase[j] = static_cast<long int> (c);

	    // We have read one of the bytes.

	    b--;

	    // Get bits stored in the continuation bytes.
	    //   10......

	    while(b--)
	      {
		if(i == n)
		  {
		    // Premature end of string.

		    if(m_passphrase)
		      m_passphrase[j] = 0; /* XXX invalid input. */

		    break;
		  }

		c = static_cast<int> (passphrase.at(i++));

		if((c & 0xc0) != 0x80)
		  {
		    // Premature end of multibyte-character byte sequence.

		    if(m_passphrase)
		      m_passphrase[j] = 0; /* XXX invalid input. */

		    i--;
		    break;
		  }
		else
		  {
		    // Store the six lowest bits.

		    if(m_passphrase)
		      {
			m_passphrase[j] <<= 6;
			m_passphrase[j] |= static_cast<long int> (c & 0x3f);
		      }
		  }
	      }
	  }
	else
	  // Non-initial byte in multibyte-character at beginning of character.
	  // (Unexpected continuation byte.)

	  j--; /* XXX invalid input. */
      }
  }

  ~spoton_pacify()
  {
    if(m_passphrase)
      delete []m_passphrase;
  }

  double evaluate(void) const
  {
    double rc = 0.0;
    long int last = -1;
    std::map<long int, int> used;
    std::map<double, int> classes;

    classes[2.5] = 0;
    classes[3.5] = 0;

    for(int i = 1; i <= 10; i++)
      classes[i] = 0;

    for(size_t i = 0; i < m_passphrase_length; i++)
      {
	double r = 0.0;
	long int c = m_passphrase ? m_passphrase[i] : 0;

	r = char_class(c);

	if(used.end() == used.find(c))
	  used[c] = 1;
	else
	  used[c] += 1;

	rc += std::pow(r, 2);
	rc += 5.0 / used[c];

	if(r >= 4.0)
	  r += 2.0;
	else if(r > 3.0)
	  r = 5.0;
	else if(r == 3.0)
	  r = 4.0;
	else if(r > 2.0)
	  r = 3.0;

	if(classes.end() == classes.find(r - 1.0))
	  classes[r - 1.0] = 0;

	classes[r - 1.0] += 1;

	if(i > 0)
	  {
	    if(c > 127 || last > 127)
	      r = distance('\0', '\0');
	    else
	      r = distance(static_cast<char> (c), static_cast<char> (last));

	    rc += std::pow(r, 0.5);
	  }

	last = c;
      }

    if(rc >= 0.0)
      rc += 30.0;

    double a = 0.0;
    double b = 0.0;
    double c = 0.0;
    double d = 0.0;
    int i = 0;

    for(std::map<double, int>::iterator it = classes.begin();
	it != classes.end(); i++, it++)
      if(i == 0)
	a = it->second;
      else if(i == 1)
	b = it->second;
      else if(i == 2)
	c = it->second;
      else if(i == 3)
	d = it->second;
      else
	break;

    if(a + b + c + d == 0.0)
      rc += 30.0;
    else
      {
	double r = std::pow(a, 2) + std::pow(b, 2) + std::pow(c, 3) +
	  std::pow(d, 2);

	rc += 30.0 * static_cast<double> (m_passphrase_length) /
	  std::pow(r, 0.5);
      }

    return std::floor(rc + 0.5);
  }

 private:
  long int *m_passphrase;
  size_t m_passphrase_length;

  double char_class(const long int c) const
  {
    if(static_cast<long int> ('0') <= c && c <= static_cast<long int> ('9'))
      return 1.0;
    else if(static_cast<long int> ('a') <= c &&
	    c <= static_cast<long int> ('z'))
      return 2.0;
    else if(static_cast<long int> ('A') <= c &&
	    c <= static_cast<long int> ('Z'))
      return 2.5;
    else if(c < (1 << 7))
      return 3.0;
    else if(c < (1 << 8))
      return 3.5;
    else if(c < (1 << 10))
      return 4.0;
    else if(c < (1 << 14))
      return 5.0;
    else if(c < (1 << 16))
      return 6.0;
    else if(c < (1 << 18))
      return 7.0;
    else if(c < (1 << 22))
      return 8.0;
    else if(c < (1 << 26))
      return 9.0;
    else
      return 10.0;
  }

  double distance(const char a, const char b) const
  {
    std::string _a_;
    std::string _b_;

    _a_.append(1, a);
    _b_.append(1, b);
    std::transform(_a_.begin(), _a_.end(), _a_.begin(), ::tolower);
    std::transform(_b_.begin(), _b_.end(), _b_.begin(), ::tolower);

    if(_a_ == _b_)
      return 0.0;

    std::map<char, std::pair<double, double> > keys;
    std::string L1("1234567890");
    std::string L2("qwertyuiop");
    std::string L3("asdfghjkl");
    std::string L4("zxcvbnm");
    std::string _a_b_(_a_ + _b_);

    for(size_t i = 0; i < L1.length(); i++)
      keys[L1[i]] = std::pair<double, double> (static_cast<double> (i), 0.0);

    for(size_t i = 0; i < L2.length(); i++)
      keys[L2[i]] = std::pair<double, double> (static_cast<double> (i) + 0.5,
					       1.0);

    for(size_t i = 0; i < L3.length(); i++)
      keys[L3[i]] = std::pair<double, double> (static_cast<double> (i) + 0.75,
					       2.0);

    for(size_t i = 0; i < L4.length(); i++)
      keys[L4[i]] = std::pair<double, double> (static_cast<double> (i) + 1.0,
					       3.0);

    for(size_t i = 0; i < _a_b_.length(); i++)
      if(keys.end() == keys.find(_a_b_[i]))
	return 15.0;

    return std::pow(std::pow(keys[_a_.at(0)].first -
			     keys[_b_.at(0)].first, 2) +
		    std::pow(keys[_a_.at(0)].second -
			     keys[_b_.at(0)].second, 2), 0.5);
  }
};

#endif
