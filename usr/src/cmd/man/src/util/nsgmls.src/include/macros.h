// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef macros_INCLUDED
#define macros_INCLUDED 1

#ifndef __GNUG__
#define __attribute__(args) /* as nothing */
#endif

#ifdef NDEBUG

#include <stdlib.h>
#define ASSERT(expr) ((void)0)
#define CANNOT_HAPPEN() ((void)abort())

#else /* not NDEBUG */

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif
extern SP_API void assertionFailed(const char *, const char *, int)
     __attribute__((noreturn));
#ifdef SP_NAMESPACE
}
#endif

#define ASSERT(expr) \
  ((void)((expr) || \
  (::SP_NAMESPACE_SCOPE assertionFailed(# expr, __FILE__, __LINE__), 0)))
#define CANNOT_HAPPEN() ASSERT(0)

#endif /* not NDEBUG */

#define SIZEOF(v) (sizeof(v)/sizeof(v[0]))

#endif /* not macros_INCLUDED */
