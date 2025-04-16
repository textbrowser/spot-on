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

#include "spot-on-sqlquery.h"

spoton_sqlquery::spoton_sqlquery(void)
{
}

spoton_sqlquery::~spoton_sqlquery()
{
}

QString spoton_sqlquery::fieldName(const int index) const
{
  return m_fields.value(index);
}

QVariant spoton_sqlquery::value(const int index) const
{
  return m_current.value(index).first;
}

bool spoton_sqlquery::isNull(const int index) const
{
  if(m_current.contains(index))
    return m_current.value(index).second;
  else
    return true;
}

bool spoton_sqlquery::next(void)
{
  if(m_queue.isEmpty())
    return false;

  m_current = m_queue.dequeue();
  return true;
}

int spoton_sqlquery::indexOfField(const QString &field) const
{
  return m_fields.key(field, -1);
}

int spoton_sqlquery::recordCount(void) const
{
  return m_current.size();
}

int spoton_sqlquery::size(void) const
{
  return m_queue.size();
}

void spoton_sqlquery::enqueue(const QHash<int, QPair<QVariant, bool> > &hash)
{
  m_queue.enqueue(hash);
}

void spoton_sqlquery::setField(const int index, const QString &field)
{
  if(index >= 0)
    m_fields[index] = field;
}
