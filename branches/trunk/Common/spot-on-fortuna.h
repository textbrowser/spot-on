/*
** Copyright (c) 2023, Alexis Megas.
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
**    derived from FortunateQ without specific prior written permission.
**
** FORTUNATEQ IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** FORTUNATEQ, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _fortunate_q_h_
#define _fortunate_q_h_

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static uint8_t s_rcon[][11] = {{0x00, 0x00, 0x00, 0x00},
			       {0x01, 0x00, 0x00, 0x00},
			       {0x02, 0x00, 0x00, 0x00},
			       {0x04, 0x00, 0x00, 0x00},
			       {0x08, 0x00, 0x00, 0x00},
			       {0x10, 0x00, 0x00, 0x00},
			       {0x20, 0x00, 0x00, 0x00},
			       {0x40, 0x00, 0x00, 0x00},
			       {0x80, 0x00, 0x00, 0x00},
			       {0x1b, 0x00, 0x00, 0x00},
			       {0x36, 0x00, 0x00, 0x00}};

static uint8_t s_inv_sbox[256] =
{
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
  0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
  0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
  0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
  0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
  0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
  0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
  0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
  0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
  0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
  0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
  0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
  0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
  0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
  0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
  0x55, 0x21, 0x0c, 0x7d
};

static uint8_t s_sbox[256] =
{
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
  0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
  0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
  0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
  0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
  0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
  0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
  0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
  0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16
};

class aes256
{
 public:
  aes256(const std::string &key)
  {
    m_Nb = 4;
    m_Nk = 8;
    m_Nr = 14;
    m_block_length = 16; // Or, 128 bits.
    m_key = from_hex(key);
    m_key_length = 32; // Or, 256 bits.
    m_state[0][0] = m_state[0][1] = m_state[0][2] = m_state[0][3] = 0;
    m_state[1][0] = m_state[1][1] = m_state[1][2] = m_state[1][3] = 0;
    m_state[2][0] = m_state[2][1] = m_state[2][2] = m_state[2][3] = 0;
    m_state[3][0] = m_state[3][1] = m_state[3][2] = m_state[3][3] = 0;
    memset(m_round_key, 0, 4 * 60 * sizeof(m_round_key[0][0]));
    key_expansion();
  }

  ~aes256()
  {
    for(size_t i = 0, size = m_key.size(); i < size; i++)
      m_key[i] = 0;

    m_key.clear();
    memset(m_round_key, 0, 4 * 60 * sizeof(m_round_key[0][0]));
    memset(m_state, 0, 4 * 4 * sizeof(m_state[0][0]));
  }

  static std::string to_hex(const std::vector<uint8_t> &vector)
  {
    std::stringstream stream;

    stream << std::hex;

    for(size_t i = 0, size = vector.size(); i < size; i += 1)
      stream << std::setw(2)
	     << std::setfill('0')
	     << static_cast<int> (vector[i]);

    return stream.str();
  }

  static std::vector<uint8_t> from_hex(const std::string &string)
  {
    std::vector<uint8_t> vector;

    for(size_t i = 0, length = string.length(); i < length; i += 2)
      {
	auto byte = static_cast<uint8_t>
	  (strtol(string.substr(i, 2).c_str(), nullptr, 16));

        vector.push_back(byte);
      }

    return vector;
  }

  std::vector<uint8_t> decrypt_block(const std::vector<uint8_t> &block)
  {
    std::vector<uint8_t> b;

    if(block.size() != 16)
      return b;

    b.resize(16);
    m_state[0][0] = block[0 + 4 * 0];
    m_state[0][1] = block[0 + 4 * 1];
    m_state[0][2] = block[0 + 4 * 2];
    m_state[0][3] = block[0 + 4 * 3];
    m_state[1][0] = block[1 + 4 * 0];
    m_state[1][1] = block[1 + 4 * 1];
    m_state[1][2] = block[1 + 4 * 2];
    m_state[1][3] = block[1 + 4 * 3];
    m_state[2][0] = block[2 + 4 * 0];
    m_state[2][1] = block[2 + 4 * 1];
    m_state[2][2] = block[2 + 4 * 2];
    m_state[2][3] = block[2 + 4 * 3];
    m_state[3][0] = block[3 + 4 * 0];
    m_state[3][1] = block[3 + 4 * 1];
    m_state[3][2] = block[3 + 4 * 2];
    m_state[3][3] = block[3 + 4 * 3];
    add_round_key(m_Nr);

    for(size_t i = m_Nr - 1; i > 0; i--)
      {
	inv_shift_rows();
	inv_sub_bytes();
	add_round_key(i);
	inv_mix_columns();
      }

    inv_shift_rows();
    inv_sub_bytes();
    add_round_key(0);
    b[0 + 4 * 0] = m_state[0][0];
    b[0 + 4 * 1] = m_state[0][1];
    b[0 + 4 * 2] = m_state[0][2];
    b[0 + 4 * 3] = m_state[0][3];
    b[1 + 4 * 0] = m_state[1][0];
    b[1 + 4 * 1] = m_state[1][1];
    b[1 + 4 * 2] = m_state[1][2];
    b[1 + 4 * 3] = m_state[1][3];
    b[2 + 4 * 0] = m_state[2][0];
    b[2 + 4 * 1] = m_state[2][1];
    b[2 + 4 * 2] = m_state[2][2];
    b[2 + 4 * 3] = m_state[2][3];
    b[3 + 4 * 0] = m_state[3][0];
    b[3 + 4 * 1] = m_state[3][1];
    b[3 + 4 * 2] = m_state[3][2];
    b[3 + 4 * 3] = m_state[3][3];
    return b;
  }

  std::vector<uint8_t> encrypt_block(const std::vector<uint8_t> &block)
  {
    std::vector<uint8_t> b;

    if(block.size() != 16)
      return b;

    b.resize(16);
    m_state[0][0] = block[0 + 4 * 0];
    m_state[0][1] = block[0 + 4 * 1];
    m_state[0][2] = block[0 + 4 * 2];
    m_state[0][3] = block[0 + 4 * 3];
    m_state[1][0] = block[1 + 4 * 0];
    m_state[1][1] = block[1 + 4 * 1];
    m_state[1][2] = block[1 + 4 * 2];
    m_state[1][3] = block[1 + 4 * 3];
    m_state[2][0] = block[2 + 4 * 0];
    m_state[2][1] = block[2 + 4 * 1];
    m_state[2][2] = block[2 + 4 * 2];
    m_state[2][3] = block[2 + 4 * 3];
    m_state[3][0] = block[3 + 4 * 0];
    m_state[3][1] = block[3 + 4 * 1];
    m_state[3][2] = block[3 + 4 * 2];
    m_state[3][3] = block[3 + 4 * 3];
    add_round_key(0);

    for(size_t i = 1; i < m_Nr; i++)
      {
	sub_bytes();
	shift_rows();
	mix_columns();
	add_round_key(i);
      }

    sub_bytes();
    shift_rows();
    add_round_key(m_Nr);
    b[0 + 4 * 0] = m_state[0][0];
    b[0 + 4 * 1] = m_state[0][1];
    b[0 + 4 * 2] = m_state[0][2];
    b[0 + 4 * 3] = m_state[0][3];
    b[1 + 4 * 0] = m_state[1][0];
    b[1 + 4 * 1] = m_state[1][1];
    b[1 + 4 * 2] = m_state[1][2];
    b[1 + 4 * 3] = m_state[1][3];
    b[2 + 4 * 0] = m_state[2][0];
    b[2 + 4 * 1] = m_state[2][1];
    b[2 + 4 * 2] = m_state[2][2];
    b[2 + 4 * 3] = m_state[2][3];
    b[3 + 4 * 0] = m_state[3][0];
    b[3 + 4 * 1] = m_state[3][1];
    b[3 + 4 * 2] = m_state[3][2];
    b[3 + 4 * 3] = m_state[3][3];
    return b;
  }

 private:
  int m_block_length;
  int m_key_length;
  size_t m_Nb;
  size_t m_Nk;
  size_t m_Nr;
  std::vector<uint8_t> m_key;
  uint8_t m_round_key[60][4] {};
  uint8_t m_state[4][4] {}; // 4 rows, Nb columns.

  uint8_t xtime(uint8_t x)
  {
    return static_cast<uint8_t> ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
  }

  uint8_t xtime_special(uint8_t x, uint8_t y)
  {
    auto xtime_y = xtime(y);

    return static_cast<uint8_t>
      (((x & 1) * y) ^
       (((x >> 1) & 1) * xtime_y) ^
       (((x >> 2) & 1) * xtime(xtime_y)) ^
       (((x >> 3) & 1) * xtime(xtime(xtime_y))) ^
       (((x >> 4) & 1) * xtime(xtime(xtime(xtime_y)))));
  }

  void add_round_key(size_t c)
  {
    auto product = c * m_Nb;

    m_state[0][0] ^= m_round_key[product + 0][0];
    m_state[0][1] ^= m_round_key[product + 1][0];
    m_state[0][2] ^= m_round_key[product + 2][0];
    m_state[0][3] ^= m_round_key[product + 3][0];
    m_state[1][0] ^= m_round_key[product + 0][1];
    m_state[1][1] ^= m_round_key[product + 1][1];
    m_state[1][2] ^= m_round_key[product + 2][1];
    m_state[1][3] ^= m_round_key[product + 3][1];
    m_state[2][0] ^= m_round_key[product + 0][2];
    m_state[2][1] ^= m_round_key[product + 1][2];
    m_state[2][2] ^= m_round_key[product + 2][2];
    m_state[2][3] ^= m_round_key[product + 3][2];
    m_state[3][0] ^= m_round_key[product + 0][3];
    m_state[3][1] ^= m_round_key[product + 1][3];
    m_state[3][2] ^= m_round_key[product + 2][3];
    m_state[3][3] ^= m_round_key[product + 3][3];
  }

  void inv_mix_columns(void)
  {
    uint8_t a[4];

    a[0] = m_state[0][0];
    a[1] = m_state[1][0];
    a[2] = m_state[2][0];
    a[3] = m_state[3][0];
    m_state[0][0] = xtime_special(0x0e, a[0]) ^ xtime_special(0x0b, a[1]) ^
      xtime_special(0x0d, a[2]) ^ xtime_special(0x09, a[3]);
    m_state[1][0] = xtime_special(0x09, a[0]) ^ xtime_special(0x0e, a[1]) ^
      xtime_special(0x0b, a[2]) ^ xtime_special(0x0d, a[3]);
    m_state[2][0] = xtime_special(0x0d, a[0]) ^ xtime_special(0x09, a[1]) ^
      xtime_special(0x0e, a[2]) ^ xtime_special(0x0b, a[3]);
    m_state[3][0] = xtime_special(0x0b, a[0]) ^ xtime_special(0x0d, a[1]) ^
      xtime_special(0x09, a[2]) ^ xtime_special(0x0e, a[3]);
    a[0] = m_state[0][1];
    a[1] = m_state[1][1];
    a[2] = m_state[2][1];
    a[3] = m_state[3][1];
    m_state[0][1] = xtime_special(0x0e, a[0]) ^ xtime_special(0x0b, a[1]) ^
      xtime_special(0x0d, a[2]) ^ xtime_special(0x09, a[3]);
    m_state[1][1] = xtime_special(0x09, a[0]) ^ xtime_special(0x0e, a[1]) ^
      xtime_special(0x0b, a[2]) ^ xtime_special(0x0d, a[3]);
    m_state[2][1] = xtime_special(0x0d, a[0]) ^ xtime_special(0x09, a[1]) ^
      xtime_special(0x0e, a[2]) ^ xtime_special(0x0b, a[3]);
    m_state[3][1] = xtime_special(0x0b, a[0]) ^ xtime_special(0x0d, a[1]) ^
      xtime_special(0x09, a[2]) ^ xtime_special(0x0e, a[3]);
    a[0] = m_state[0][2];
    a[1] = m_state[1][2];
    a[2] = m_state[2][2];
    a[3] = m_state[3][2];
    m_state[0][2] = xtime_special(0x0e, a[0]) ^ xtime_special(0x0b, a[1]) ^
      xtime_special(0x0d, a[2]) ^ xtime_special(0x09, a[3]);
    m_state[1][2] = xtime_special(0x09, a[0]) ^ xtime_special(0x0e, a[1]) ^
      xtime_special(0x0b, a[2]) ^ xtime_special(0x0d, a[3]);
    m_state[2][2] = xtime_special(0x0d, a[0]) ^ xtime_special(0x09, a[1]) ^
      xtime_special(0x0e, a[2]) ^ xtime_special(0x0b, a[3]);
    m_state[3][2] = xtime_special(0x0b, a[0]) ^ xtime_special(0x0d, a[1]) ^
      xtime_special(0x09, a[2]) ^ xtime_special(0x0e, a[3]);
    a[0] = m_state[0][3];
    a[1] = m_state[1][3];
    a[2] = m_state[2][3];
    a[3] = m_state[3][3];
    m_state[0][3] = xtime_special(0x0e, a[0]) ^ xtime_special(0x0b, a[1]) ^
      xtime_special(0x0d, a[2]) ^ xtime_special(0x09, a[3]);
    m_state[1][3] = xtime_special(0x09, a[0]) ^ xtime_special(0x0e, a[1]) ^
      xtime_special(0x0b, a[2]) ^ xtime_special(0x0d, a[3]);
    m_state[2][3] = xtime_special(0x0d, a[0]) ^ xtime_special(0x09, a[1]) ^
      xtime_special(0x0e, a[2]) ^ xtime_special(0x0b, a[3]);
    m_state[3][3] = xtime_special(0x0b, a[0]) ^ xtime_special(0x0d, a[1]) ^
      xtime_special(0x09, a[2]) ^ xtime_special(0x0e, a[3]);
    memset(a, 0, 4 * sizeof(a[0]));
  }

  void inv_shift_rows(void)
  {
    uint8_t temp[4];

    temp[0] = m_state[1][0];
    temp[1] = m_state[1][1];
    temp[2] = m_state[1][2];
    temp[3] = m_state[1][3];
    m_state[1][(1 + 0) % m_Nb] = temp[0];
    m_state[1][(1 + 1) % m_Nb] = temp[1];
    m_state[1][(1 + 2) % m_Nb] = temp[2];
    m_state[1][(1 + 3) % m_Nb] = temp[3];
    temp[0] = m_state[2][0];
    temp[1] = m_state[2][1];
    temp[2] = m_state[2][2];
    temp[3] = m_state[2][3];
    m_state[2][(2 + 0) % m_Nb] = temp[0];
    m_state[2][(2 + 1) % m_Nb] = temp[1];
    m_state[2][(2 + 2) % m_Nb] = temp[2];
    m_state[2][(2 + 3) % m_Nb] = temp[3];
    temp[0] = m_state[3][0];
    temp[1] = m_state[3][1];
    temp[2] = m_state[3][2];
    temp[3] = m_state[3][3];
    m_state[3][(3 + 0) % m_Nb] = temp[0];
    m_state[3][(3 + 1) % m_Nb] = temp[1];
    m_state[3][(3 + 2) % m_Nb] = temp[2];
    m_state[3][(3 + 3) % m_Nb] = temp[3];
    memset(temp, 0, 4 * sizeof(temp[0]));
  }

  void inv_sub_bytes(void)
  {
    m_state[0][0] = s_inv_sbox[static_cast<size_t> (m_state[0][0])];
    m_state[0][1] = s_inv_sbox[static_cast<size_t> (m_state[0][1])];
    m_state[0][2] = s_inv_sbox[static_cast<size_t> (m_state[0][2])];
    m_state[0][3] = s_inv_sbox[static_cast<size_t> (m_state[0][3])];
    m_state[1][0] = s_inv_sbox[static_cast<size_t> (m_state[1][0])];
    m_state[1][1] = s_inv_sbox[static_cast<size_t> (m_state[1][1])];
    m_state[1][2] = s_inv_sbox[static_cast<size_t> (m_state[1][2])];
    m_state[1][3] = s_inv_sbox[static_cast<size_t> (m_state[1][3])];
    m_state[2][0] = s_inv_sbox[static_cast<size_t> (m_state[2][0])];
    m_state[2][1] = s_inv_sbox[static_cast<size_t> (m_state[2][1])];
    m_state[2][2] = s_inv_sbox[static_cast<size_t> (m_state[2][2])];
    m_state[2][3] = s_inv_sbox[static_cast<size_t> (m_state[2][3])];
    m_state[3][0] = s_inv_sbox[static_cast<size_t> (m_state[3][0])];
    m_state[3][1] = s_inv_sbox[static_cast<size_t> (m_state[3][1])];
    m_state[3][2] = s_inv_sbox[static_cast<size_t> (m_state[3][2])];
    m_state[3][3] = s_inv_sbox[static_cast<size_t> (m_state[3][3])];
  }

  void key_expansion(void)
  {
    size_t i = 0;

    while(i < m_Nk)
      {
	auto product = 4 * i;

	if(m_key.size() > product)
	  m_round_key[i][0] = m_key[product + 0];

	if(m_key.size() > product + 1)
	  m_round_key[i][1] = m_key[product + 1];

	if(m_key.size() > product + 2)
	  m_round_key[i][2] = m_key[product + 2];

	if(m_key.size() > product + 3)
	  m_round_key[i][3] = m_key[product + 3];

	i += 1;
      }

    auto iterations = m_Nb * (m_Nr + 1);
    uint8_t temp[4];

    while(i < iterations)
      {
	auto difference = i - 1;

	temp[0] = m_round_key[difference][0];
	temp[1] = m_round_key[difference][1];
	temp[2] = m_round_key[difference][2];
	temp[3] = m_round_key[difference][3];

	if(m_Nk > 0 && i % m_Nk == 0)
	  {
	    auto quotient = i / m_Nk;
	    uint8_t t = temp[0];

	    temp[0] = temp[1];
	    temp[1] = temp[2];
	    temp[2] = temp[3];
	    temp[3] = t;
	    temp[0] = s_sbox[static_cast<size_t> (temp[0])] ^
	      s_rcon[quotient][0];
	    temp[1] = s_sbox[static_cast<size_t> (temp[1])] ^
	      s_rcon[quotient][1];
	    temp[2] = s_sbox[static_cast<size_t> (temp[2])] ^
	      s_rcon[quotient][2];
	    temp[3] = s_sbox[static_cast<size_t> (temp[3])] ^
	      s_rcon[quotient][3];
	    t = 0;
	  }
	else if(m_Nk > 0 && i % m_Nk == 4)
	  {
	    temp[0] = s_sbox[static_cast<size_t> (temp[0])];
	    temp[1] = s_sbox[static_cast<size_t> (temp[1])];
	    temp[2] = s_sbox[static_cast<size_t> (temp[2])];
	    temp[3] = s_sbox[static_cast<size_t> (temp[3])];
	  }

	difference = i - m_Nk;
	m_round_key[i][0] = m_round_key[difference][0] ^ temp[0];
	m_round_key[i][1] = m_round_key[difference][1] ^ temp[1];
	m_round_key[i][2] = m_round_key[difference][2] ^ temp[2];
	m_round_key[i][3] = m_round_key[difference][3] ^ temp[3];
	memset(temp, 0, 4 * sizeof(temp[0]));
	i += 1;
      }
  }

  void memset(void *s, int c, size_t n)
  {
    if(!n || !s)
      return;

    volatile auto v = static_cast<unsigned char *> (s);

    while(n--)
      *v++ = static_cast<unsigned char> (c);
  }

  void mix_columns(void)
  {
    uint8_t a[4];
    uint8_t b[4];

    a[0] = m_state[0][0];
    a[1] = m_state[1][0];
    a[2] = m_state[2][0];
    a[3] = m_state[3][0];
    b[0] = xtime(m_state[0][0]);
    b[1] = xtime(m_state[1][0]);
    b[2] = xtime(m_state[2][0]);
    b[3] = xtime(m_state[3][0]);
    m_state[0][0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    m_state[1][0] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    m_state[2][0] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    m_state[3][0] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    a[0] = m_state[0][1];
    a[1] = m_state[1][1];
    a[2] = m_state[2][1];
    a[3] = m_state[3][1];
    b[0] = xtime(m_state[0][1]);
    b[1] = xtime(m_state[1][1]);
    b[2] = xtime(m_state[2][1]);
    b[3] = xtime(m_state[3][1]);
    m_state[0][1] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    m_state[1][1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    m_state[2][1] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    m_state[3][1] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    a[0] = m_state[0][2];
    a[1] = m_state[1][2];
    a[2] = m_state[2][2];
    a[3] = m_state[3][2];
    b[0] = xtime(m_state[0][2]);
    b[1] = xtime(m_state[1][2]);
    b[2] = xtime(m_state[2][2]);
    b[3] = xtime(m_state[3][2]);
    m_state[0][2] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    m_state[1][2] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    m_state[2][2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    m_state[3][2] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    a[0] = m_state[0][3];
    a[1] = m_state[1][3];
    a[2] = m_state[2][3];
    a[3] = m_state[3][3];
    b[0] = xtime(m_state[0][3]);
    b[1] = xtime(m_state[1][3]);
    b[2] = xtime(m_state[2][3]);
    b[3] = xtime(m_state[3][3]);
    m_state[0][3] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    m_state[1][3] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    m_state[2][3] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    m_state[3][3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    memset(a, 0, 4 * sizeof(a[0]));
    memset(b, 0, 4 * sizeof(b[0]));
  }

  void shift_rows(void)
  {
    uint8_t temp[4];

    temp[0] = m_state[1][(1 + 0) % m_Nb];
    temp[1] = m_state[1][(1 + 1) % m_Nb];
    temp[2] = m_state[1][(1 + 2) % m_Nb];
    temp[3] = m_state[1][(1 + 3) % m_Nb];
    m_state[1][0] = temp[0];
    m_state[1][1] = temp[1];
    m_state[1][2] = temp[2];
    m_state[1][3] = temp[3];
    temp[0] = m_state[2][(2 + 0) % m_Nb];
    temp[1] = m_state[2][(2 + 1) % m_Nb];
    temp[2] = m_state[2][(2 + 2) % m_Nb];
    temp[3] = m_state[2][(2 + 3) % m_Nb];
    m_state[2][0] = temp[0];
    m_state[2][1] = temp[1];
    m_state[2][2] = temp[2];
    m_state[2][3] = temp[3];
    temp[0] = m_state[3][(3 + 0) % m_Nb];
    temp[1] = m_state[3][(3 + 1) % m_Nb];
    temp[2] = m_state[3][(3 + 2) % m_Nb];
    temp[3] = m_state[3][(3 + 3) % m_Nb];
    m_state[3][0] = temp[0];
    m_state[3][1] = temp[1];
    m_state[3][2] = temp[2];
    m_state[3][3] = temp[3];
    memset(temp, 0, 4 * sizeof(temp[0]));
  }

  void sub_bytes(void)
  {
    m_state[0][0] = s_sbox[static_cast<size_t> (m_state[0][0])];
    m_state[0][1] = s_sbox[static_cast<size_t> (m_state[0][1])];
    m_state[0][2] = s_sbox[static_cast<size_t> (m_state[0][2])];
    m_state[0][3] = s_sbox[static_cast<size_t> (m_state[0][3])];
    m_state[1][0] = s_sbox[static_cast<size_t> (m_state[1][0])];
    m_state[1][1] = s_sbox[static_cast<size_t> (m_state[1][1])];
    m_state[1][2] = s_sbox[static_cast<size_t> (m_state[1][2])];
    m_state[1][3] = s_sbox[static_cast<size_t> (m_state[1][3])];
    m_state[2][0] = s_sbox[static_cast<size_t> (m_state[2][0])];
    m_state[2][1] = s_sbox[static_cast<size_t> (m_state[2][1])];
    m_state[2][2] = s_sbox[static_cast<size_t> (m_state[2][2])];
    m_state[2][3] = s_sbox[static_cast<size_t> (m_state[2][3])];
    m_state[3][0] = s_sbox[static_cast<size_t> (m_state[3][0])];
    m_state[3][1] = s_sbox[static_cast<size_t> (m_state[3][1])];
    m_state[3][2] = s_sbox[static_cast<size_t> (m_state[3][2])];
    m_state[3][3] = s_sbox[static_cast<size_t> (m_state[3][3])];
  }
};

#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFile>
#include <QHostAddress>
#include <QPointer>
#include <QSocketNotifier>
#include <QSslSocket>
#include <QTimer>
#include <QtDebug>
#include <QtMath>

static qsizetype MIN_POOL_SIZE = 64;
static qsizetype POOLS = 32;

class counter_q
{
 public:
  counter_q(void)
  {
    m_l = m_r = 0;
  }

  QByteArray value(void) const
  {
    QByteArray value(16, 0);

    memcpy(value.data(), &m_l, 8);
    memcpy(value.data() + 8, &m_r, 8);
    return value;
  }

  bool is_zero(void) const
  {
    return m_l == 0 && m_r == 0;
  }

  void increment(void)
  {
    m_r += 1;

    if(m_r == 0)
      m_l += 1;
  }

 private:
  quint64 m_l;
  quint64 m_r;
};

class fortunate_q: public QObject
{
  Q_OBJECT

 public:
  fortunate_q(QObject *parent):QObject(parent)
  {
    m_R = initialize_prng();
    m_source_indices.resize(POOLS);
    m_tcp_socket_connection_timer.setInterval(500);
  }

  ~fortunate_q()
  {
    m_periodic_write_timer.stop();
    m_tcp_socket_connection_timer.stop();
  }

  QByteArray random_data(const int n)
  {
    return random_data(n, m_R);
  }

  void set_file_peer(const QString &file_name)
  {
    m_file.close();
    m_file.setFileName(file_name);
    m_file.open(QIODevice::ReadOnly | QIODevice::Unbuffered);
    m_file_notifier = m_file_notifier ?
      (m_file_notifier->deleteLater(),
       new QSocketNotifier(m_file.handle(), QSocketNotifier::Read, this)) :
      (new QSocketNotifier(m_file.handle(), QSocketNotifier::Read, this));
    connect(m_file_notifier,
	    SIGNAL(activated(QSocketDescriptor, QSocketNotifier::Type)),
	    this,
	    SLOT(slot_file_ready_read(void)));
  }

  void set_send_byte(const char byte, const int interval)
  {
    /*
    ** Some devices require periodic data.
    */

    connect(&m_periodic_write_timer,
	    &QTimer::timeout,
	    this,
	    &fortunate_q::slot_send_byte,
	    Qt::UniqueConnection);
    m_periodic_write_timer.start(interval);
    m_send_byte[0] = byte;
  }

  void set_tcp_peer(const QString &address, const bool tls, const quint16 port)
  {
    connect(&m_tcp_socket,
	    &QSslSocket::connected,
	    this,
	    &fortunate_q::slot_tcp_socket_connected,
	    Qt::UniqueConnection);
    connect(&m_tcp_socket,
	    &QSslSocket::disconnected,
	    this,
	    &fortunate_q::slot_tcp_socket_disconnected,
	    Qt::UniqueConnection);
    connect(&m_tcp_socket,
	    &QSslSocket::readyRead,
	    this,
	    &fortunate_q::slot_tcp_socket_ready_read,
	    Qt::UniqueConnection);
    connect(&m_tcp_socket,
	    SIGNAL(sslErrors(const QList<QSslError> &)),
	    this,
	    SLOT(slot_tcp_socket_ssl_erros(const QList<QSslError> &)),
	    Qt::UniqueConnection);
    connect(&m_tcp_socket_connection_timer,
	    &QTimer::timeout,
	    this,
	    &fortunate_q::slot_tcp_socket_disconnected,
	    Qt::UniqueConnection);
    m_tcp_address = address;
    m_tcp_port = port;
    m_tcp_socket.abort();
    m_tcp_socket_tls = tls;
    m_tcp_socket_connection_timer.start();
  }

 private:
  enum class Devices
  {
    FILE = 0,
    TCP = 1
  };

  struct generator_state
  {
    QByteArray m_key;
    counter_q m_counter;
  };

  struct prng_state
  {
    QElapsedTimer m_lastReseed;
    QVector<QByteArray> m_P;
    generator_state m_G;
#ifndef __SIZEOF_INT128__
    quint64 m_reseedCnt;
#else
    unsigned __int128 m_reseedCnt;
#endif
  };

  QFile m_file;
  QPointer<QSocketNotifier> m_file_notifier;
  QSslSocket m_tcp_socket;
  QString m_tcp_address;
  QTimer m_periodic_write_timer;
  QTimer m_tcp_socket_connection_timer;
  QVector<int> m_source_indices;
  bool m_tcp_socket_tls;
  char m_send_byte[1];
  prng_state m_R; // The magic pseudo-random number generator.
  quint16 m_tcp_port;

  static QByteArray E(const QByteArray &C, const QByteArray &K)
  {
    aes256 aes(K.constData());
    auto string(std::string(C.toHex().constData()));

    return QByteArray::fromHex
      (aes256::to_hex(aes.encrypt_block(aes256::from_hex(string))).data());
  }

  static QByteArray generate_blocks(const int k, generator_state &G)
  {
    QByteArray r;

    if(!G.m_counter.is_zero())
      for(int i = 1; i <= k; i++)
	{
	  r = r + E(G.m_counter.value(), G.m_key);
	  G.m_counter.increment();
	}

    return r;
  }

  static QByteArray pseudo_random_data(const int n, generator_state &G)
  {
    QByteArray r;

    if(0 <= n && 1048576 >= n)
      {
	r = generate_blocks(qCeil(n / 16.0), G).mid(0, n);
	G.m_key = generate_blocks(2, G);
      }

    return r;
  }

  static QByteArray random_data(const int n, prng_state &R)
  {
    if(MIN_POOL_SIZE <= R.m_P.value(0).size() ||
       R.m_lastReseed.elapsed() > 100 ||
       R.m_lastReseed.isValid() == false)
      {
	QByteArray s;

	R.m_reseedCnt += 1;

	for(int i = 0; i < static_cast<int> (R.m_P.size()); i++)
	  if(R.m_reseedCnt % static_cast<int> (qPow(2.0, i)) == 0)
	    {
	      s = s + QCryptographicHash::hash
		(R.m_P[i], QCryptographicHash::Sha256);
	      R.m_P[i].clear();
	    }

	reseed(s, R.m_G);
	R.m_lastReseed.start();
      }

    if(R.m_reseedCnt == 0)
      return QByteArray(); // Error!
    else
      return pseudo_random_data(n, R.m_G);
  }

  static generator_state initialize_generator(void)
  {
    /*
    ** What is a zero key?
    */

    return generator_state{QByteArray(32, '0'), counter_q()};
  }

  static prng_state initialize_prng(void)
  {
    prng_state R;

    R.m_G = initialize_generator();
    R.m_P.resize(POOLS);
    R.m_reseedCnt = 0;
    return R;
  }

  static void reseed(const QByteArray &s, generator_state &G)
  {
    G.m_counter.increment();
    G.m_key = QCryptographicHash::hash
      (G.m_key + s, QCryptographicHash::Sha256);
  }

  void process_device(QIODevice *device, const int i, const int s)
  {
    if(device && device->isOpen())
      do
	{
	  auto e(device->read(32));

	  if(!e.isEmpty() && i < m_R.m_P.size())
	    {
	      m_R.m_P[i] = m_R.m_P[i] +
		QByteArray::number(s) +
		QByteArray::number(e.size()) +
		e;
	      emit pool_filled(i, s);
	    }
	}
      while(device->bytesAvailable() > 0);
  }

 private slots:
  void slot_file_ready_read(void)
  {
    auto s = static_cast<int> (Devices::FILE);

    m_source_indices[s] = (m_source_indices[s] + 1) % POOLS;
    process_device(&m_file, m_source_indices[s], s);
  }

  void slot_send_byte(void)
  {
    if(m_tcp_socket.state() == QAbstractSocket::ConnectedState)
      m_tcp_socket.write(m_send_byte, static_cast<qsizetype> (1));
  }

  void slot_tcp_socket_connected(void)
  {
    m_tcp_socket_connection_timer.stop();
  }

  void slot_tcp_socket_disconnected(void)
  {
    if(m_tcp_socket.state() == QAbstractSocket::UnconnectedState)
      {
	if(m_tcp_socket_tls)
	  m_tcp_socket.connectToHostEncrypted(m_tcp_address, m_tcp_port);
	else
	  m_tcp_socket.connectToHost(m_tcp_address, m_tcp_port);

	m_tcp_socket.ignoreSslErrors();
	m_tcp_socket_connection_timer.start();
      }
  }

  void slot_tcp_socket_ready_read(void)
  {
    auto s = static_cast<int> (Devices::TCP);

    m_source_indices[s] = (m_source_indices[s] + 1) % POOLS;
    process_device(&m_tcp_socket, m_source_indices[s], s);
  }

  void slot_tcp_socket_ssl_erros(const QList<QSslError> &errors)
  {
    Q_UNUSED(errors);
    m_tcp_socket.ignoreSslErrors();
  }

 signals:
  void pool_filled(const int index, const int source);
};

#endif
