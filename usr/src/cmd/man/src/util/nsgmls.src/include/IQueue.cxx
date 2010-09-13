// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef IQueue_DEF_INCLUDED
#define IQueue_DEF_INCLUDED 1

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

template<class T>
void IQueue<T>::clear()
{
  while (!empty())
    delete get();
}

#ifdef SP_NAMESPACE
}
#endif

#endif /* not IQueue_DEF_INCLUDED */
