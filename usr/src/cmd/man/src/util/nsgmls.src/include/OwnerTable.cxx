// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef OwnerTable_DEF_INCLUDED
#define OwnerTable_DEF_INCLUDED 1

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

template<class T, class K, class HF, class KF>
OwnerTable<T, K, HF, KF>::~OwnerTable()
{
  for (size_t i = 0; i < vec_.size(); i++)
    delete vec_[i];
}

template<class T, class K, class HF, class KF>
void OwnerTable<T, K, HF, KF>::clear()
{
  for (size_t i = 0; i < vec_.size(); i++)
    delete vec_[i];
  PointerTable<T *, K, HF, KF>::clear();
}

template<class T, class K, class HF, class KF>
void
CopyOwnerTable<T, K, HF, KF>::operator=(const CopyOwnerTable<T, K, HF, KF> &t)
{
  clear();
  PointerTable<T *, K, HF, KF>::operator=(t);
  // FIXME This isn't exception safe.
  for (size_t i = 0; i < vec_.size(); i++)
    if (vec_[i])
      vec_[i] = vec_[i]->copy();
}

#ifdef SP_NAMESPACE
}
#endif

#endif /* not OwnerTable_DEF_INCLUDED */
