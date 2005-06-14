// Copyright (c) 1997 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef CharMap_INCLUDED
#define CharMap_INCLUDED 1

#include "types.h"
#include "Resource.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

#ifdef SP_MULTI_BYTE
template<class T>
class CharMapColumn {
public:
  enum { level3bits = 4 };
  CharMapColumn();
  CharMapColumn(const CharMapColumn<T> &);
  void operator=(const CharMapColumn<T> &);
  ~CharMapColumn();
  T *values;
  T value;
};

template<class T>
class CharMapPage {
public:
  enum { level2bits = 4 };
  CharMapPage();
  CharMapPage(const CharMapPage<T> &);
  void operator=(const CharMapPage<T> &);
  ~CharMapPage();
  void swap(CharMapPage<T> &);
  CharMapColumn<T> *values;
  T value;
};
#endif /* SP_MULTI_BYTE */

template<class T>
class CharMap {
public:
  CharMap();
  CharMap(T);
  T operator[](Char) const;
  T getRange(Char from, Char &to) const;
  void swap(CharMap<T> &);
  void setChar(Char, T);
  void setRange(Char from, Char to, T val);
  void setAll(T);
private:
#ifdef SP_MULTI_BYTE
  enum { level1bits = 8, level2bits = 4, level3bits = 4 };
  CharMapPage<T> pages_[1 << level1bits];
#else
  T values_[256];
#endif
};

template<class T>
class CharMapResource : public CharMap<T>, public Resource {
public:
  CharMapResource() { }
  CharMapResource(T t) : CharMap<T>(t) { }
};

#ifdef SP_MULTI_BYTE

template<class T>
inline
T CharMap<T>::operator[](Char c) const
{
  const CharMapPage<T> &pg = pages_[c >> (level2bits + level3bits)];
  if (pg.values) {
    const CharMapColumn<T> &column = pg.values[(c >> level3bits) & ((1 << level2bits) - 1)];
    if (column.values)
      return column.values[c & ((1 << level3bits) - 1)];
    else
      return column.value;
  }
  else
    return pg.value;
}

template<class T>
inline
T CharMap<T>::getRange(Char c, Char &max) const
{
  const CharMapPage<T> &pg = pages_[c >> (level2bits + level3bits)];
  if (pg.values) {
    const CharMapColumn<T> &column = pg.values[(c >> level3bits) & ((1 << level2bits) - 1)];
    if (column.values) {
      max = c;
      return column.values[c & ((1 << level3bits) - 1)];
    }
    else {
      max = (c & ~((1 << level3bits) - 1)) + ((1 << level3bits) - 1);
      return column.value;
    }
  }
  else {
    max = (c & ~((1 << (level2bits + level3bits)) - 1)) + ((1 << (level2bits + level2bits)) - 1);
    return pg.value;
  }
}

#else

template<class T>
inline
T CharMap<T>::operator[](Char c) const
{
  return values_[c];
}

template<class T>
inline
T CharMap<T>::getRange(Char c, Char &max) const
{
  max = c;
  return values_[c];
}

template<class T>
inline
void CharMap<T>::setChar(Char c, T val)
{
  values_[c] = val;
}

#endif

#ifdef SP_NAMESPACE
}
#endif

#endif /* not CharMap_INCLUDED */

#ifdef SP_DEFINE_TEMPLATES
#include "CharMap.cxx"
#endif
