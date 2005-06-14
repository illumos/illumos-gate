// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef XcharMap_INCLUDED
#define XcharMap_INCLUDED 1

#include "types.h"
#include "Resource.h"
#include "Ptr.h"
#include "constant.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

template<class T>
class SharedXcharMap : public Resource {
public:
  SharedXcharMap();
  SharedXcharMap(T defaultValue);
  T *ptr() { return v + 1; }
private:
  T v[2 + charMax];
};

template<class T>
class XcharMap {
public:
  XcharMap();
  XcharMap(T defaultValue);
  T operator[](Xchar c) const { return ptr_[c]; }
  void setRange(Char min, Char max, T val);
  void setChar(Char c, T val) { ptr_[c] = val; }
  void setEe(T val) { ptr_[-1] = val; }
  void clear() { ptr_ = 0; sharedMap_.clear(); }
private:
  T *ptr_;
  Ptr<SharedXcharMap<T> > sharedMap_;
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* not XcharMap_INCLUDED */

#ifdef SP_DEFINE_TEMPLATES
#include "XcharMap.cxx"
#endif
