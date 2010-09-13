// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef SubstTable_INCLUDED
#define SubstTable_INCLUDED

#include <limits.h>
#include "StringOf.h"
#include "Boolean.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

template<class T>
class SubstTable {
public:
  SubstTable();
  void addSubst(T from, T to);
  void subst(T &c) const { if (table_.size() > 0) c = table_[c]; }
  void subst(String<T> &) const;
  T operator[](T c) const { return table_.size() > 0 ? table_[c] : c; }
  String<T> inverse(T) const;
  void inverseTable(SubstTable<T> &) const;
private:
  String<T> table_;
  String<T> pairs_;		// mutable
  Boolean pairsValid_;		// mutable
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* SubstTable_INCLUDED */

#ifdef SP_DEFINE_TEMPLATES
#include "SubstTable.cxx"
#endif
