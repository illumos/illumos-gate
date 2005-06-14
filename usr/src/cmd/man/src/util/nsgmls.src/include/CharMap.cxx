// Copyright (c) 1997 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef CharMap_DEF_INCLUDED
#define CharMap_DEF_INCLUDED 1

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

#ifdef SP_MULTI_BYTE

template<class T>
CharMap<T>::CharMap()
{
}

template<class T>
CharMap<T>::CharMap(T dflt)
{
  for (size_t i = 0; i < (1 << level1bits); i++)
    pages_[i].value = dflt;
}

template<class T>
void CharMap<T>::setAll(T val)
{
  for (size_t i = 0; i < (1 << level1bits); i++) {
    pages_[i].value = val;
    delete [] pages_[i].values;
    pages_[i].values = 0;
  }
}

template<class T>
void CharMap<T>::swap(CharMap<T> &map)
{
  for (size_t i = 0; i < (1 << level1bits); i++)
    pages_[i].swap(map.pages_[i]);
}

template<class T>
void CharMap<T>::setChar(Char c, T val)
{
  CharMapPage<T> &pg = pages_[c >> (level2bits + level3bits)];
  if (pg.values) {
    CharMapColumn<T> &column = pg.values[(c >> level3bits) & ((1 << level2bits) - 1)];
    if (column.values)
      column.values[c & ((1 << level3bits) - 1)] = val;
    else if (val != column.value) {
      column.values = new T[1 << level3bits];
      for (size_t i = 0; i < (1 << level3bits); i++)
	column.values[i] = column.value;
      column.values[c & ((1 << level3bits) - 1)] = val;
    }
  }
  else if (val != pg.value) {
    pg.values = new CharMapColumn<T>[1 << level2bits];
    for (size_t i = 0; i < (1 << level2bits); i++)
      pg.values[i].value = pg.value;
    CharMapColumn<T> &column = pg.values[(c >> level3bits) & ((1 << level2bits) - 1)];
    column.values = new T[1 << level3bits];
    for (size_t i = 0; i < (1 << level3bits); i++)
      column.values[i] = column.value;
    column.values[c & ((1 << level3bits) - 1)] = val;
  }
}

template<class T>
void CharMap<T>::setRange(Char from, Char to, T val)
{
  do {
    if ((from & ((1 << level3bits) - 1)) == 0
        && to - from >= (1 << level3bits) - 1) {
      if ((from & ((1 << (level2bits + level3bits)) - 1)) == 0
	  && to - from >= (1 << (level2bits + level3bits)) - 1) {
	// Set a complete page.
	CharMapPage<T> &pg = pages_[from >> (level2bits + level3bits)];
	pg.value = val;
	delete pg.values;
	pg.values = 0;
	from += (1 << (level2bits + level3bits)) - 1;
      }
      else {
	// Set a complete column.
	CharMapPage<T> &pg = pages_[from >> (level2bits + level3bits)];
	if (pg.values) {
	  CharMapColumn<T> &column = pg.values[(from >> level3bits) & ((1 << level2bits) - 1)];
	  column.value = val;
	  delete column.values;
	  column.values = 0;
	}
	else if (val != pg.value) {
	  // split the page
	  pg.values = new CharMapColumn<T>[1 << level2bits];
          for (size_t i = 0; i < (1 << level2bits); i++)
	    pg.values[i].value = pg.value;
	  CharMapColumn<T> &column = pg.values[(from >> level3bits) & ((1 << level2bits) - 1)];
	  column.value = val;
	}
	from += (1 << level2bits) - 1;
      }
    }
    else
      setChar(from, val);
  } while (from++ != to);
}

template<class T>
CharMapPage<T>::CharMapPage()
: values(0)
{
}

template<class T>
CharMapPage<T>::CharMapPage(const CharMapPage<T> &pg)
{
  if (pg.values) {
    values = new CharMapColumn<T>[1 << level2bits];
    for (size_t i = 0; i < (1 << level2bits); i++)
      values[i] = pg.values[i];
  }
  else {
    value = pg.value;
    values = 0;
  }
}

template<class T>
void CharMapPage<T>::operator=(const CharMapPage<T> &pg)
{
  if (pg.values) {
    if (!values)
      values = new CharMapColumn<T>[1 << level2bits];
    for (size_t i = 0; i < (1 << level2bits); i++)
      values[i] = pg.values[i];
  }
  else {
    if (values) {
      delete [] values;
      values = 0;
    }
    value = pg.value;
  }
}

template<class T>
CharMapPage<T>::~CharMapPage()
{
  delete [] values;
}

template<class T>
void CharMapPage<T>::swap(CharMapPage<T> &pg)
{
  {
    CharMapColumn<T> *tem = values;
    values = pg.values;
    pg.values = tem;
  }
  {
    T tem(value);
    value = pg.value;
    pg.value = tem;
  }
}

template<class T>
CharMapColumn<T>::CharMapColumn()
: values(0)
{
}

template<class T>
CharMapColumn<T>::CharMapColumn(const CharMapColumn<T> &col)
{
  if (col.values) {
    values = new T[1 << level3bits];
    for (size_t i = 0; i < (1 << level3bits); i++)
      values[i] = col.values[i];
  }
  else {
    values = 0;
    value = col.value;
  }
}

template<class T>
void CharMapColumn<T>::operator=(const CharMapColumn<T> &col)
{
  if (col.values) {
    if (!values)
      values = new T[1 << level3bits];
    for (size_t i = 0; i < (1 << level3bits); i++)
      values[i] = col.values[i];
  }
  else {
    if (values) {
      delete [] values;
      values = 0;
    }
    value = col.value;
  }
}

template<class T>
CharMapColumn<T>::~CharMapColumn()
{
  delete [] values;
}

#else /* not SP_MULTI_BYTE */

template<class T>
CharMap<T>::CharMap()
{
}

template<class T>
CharMap<T>::CharMap(T dflt)
{
  for (int i = 0; i < 256; i++)
    values_[i] = dflt;
}

template<class T>
void CharMap<T>::setAll(T val)
{
  for (size_t i = 0; i < 256; i++)
    values_[i] = val;
}

template<class T>
void CharMap<T>::setRange(Char from, Char to, T val)
{
  do {
    values_[from] = val;
  } while (from++ != to);
}

template<class T>
void CharMap<T>::swap(CharMap<T> &map)
{
  for (size_t i = 0; i < 256; i++) {
    T tem(values_[i]);
    values_[i] = map.values_[i];
    map.values_[i] = tem;
  }
}

#endif /* not SP_MULTI_BYTE */

#ifdef SP_NAMESPACE
}
#endif

#endif /* not CharMap_DEF_INCLUDED */
