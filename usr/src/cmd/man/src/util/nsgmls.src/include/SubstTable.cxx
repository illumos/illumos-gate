// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef SubstTable_DEF_INCLUDED
#define SubstTable_DEF_INCLUDED 1

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

template<class T>
SubstTable<T>::SubstTable()
: pairsValid_(1)
{
}

template<class T>
void SubstTable<T>::addSubst(T from, T to)
{
  if (table_.size() == 0) {
    table_.resize(T(-1) + 1);
#if _MSC_VER == 1100
    // Workaround for Visual C++ 5.0 bug.
    T n = 0;
    int i = 0;
    while (i < T(-1) + 1)
      table_[i++] = n++;
#else
    for (int i = 0; i < T(-1) + 1; i++)
      table_[i] = i;
#endif
  }
  if (table_[from] != to)
    pairsValid_ = 0;
  table_[from] = to;
}

template<class T>
String<T> SubstTable<T>::inverse(T ch) const
{
  if (!pairsValid_) {
    const T *p = table_.data();
    size_t length = table_.size();
    for (size_t i = 0; i < length; i++)
      if (p[i] != i) {
	// FIXME use mutable if available
	((SubstTable<T> *)this)->pairs_ += T(i);
	((SubstTable<T> *)this)->pairs_ += p[i];
      }
    ((SubstTable<T> *)this)->pairsValid_ = 1;
  }
  const T *p = pairs_.data();
  if (!p)
    return String<T>(&ch, 1);
  String<T> result;
  if (table_[ch] == ch)
    result += ch;
  for (size_t n = pairs_.size(); n > 0; n -= 2, p += 2)
    if (p[1] == ch)
      result += p[0];
  return result;
}

template<class T>
void SubstTable<T>::inverseTable(SubstTable<T> &inv) const
{
  if (table_.size() == 0) {
    inv.table_.resize(0);
    inv.pairs_.resize(0);
    inv.pairsValid_ = 1;
  }
  else {
    if (inv.table_.size() == 0)
      inv.table_.resize(T(-1) + 1);
    int i;
    for (i = 0; i < T(-1) + 1; i++)
      inv.table_[i] = i;
    inv.pairs_.resize(0);
    inv.pairsValid_ = 0;
    for (i = 0; i < T(-1) + 1; i++)
      if (table_[i] != i)
	inv.table_[table_[i]] = i;
  }
}

template<class T>
void SubstTable<T>::subst(String<T> &str) const
{
  for (size_t i = 0; i < str.size(); i++)
    subst(str[i]);
}

#ifdef SP_NAMESPACE
}
#endif

#endif /* not SubstTable_DEF_INCLUDED */
