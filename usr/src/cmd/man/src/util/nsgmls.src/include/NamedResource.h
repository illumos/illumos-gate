// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef NamedResource_INCLUDED
#define NamedResource_INCLUDED 1

#include "Named.h"
#include "Resource.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

class SP_API NamedResource : public Named, public Resource {
public:
  NamedResource(const StringC &str) : Named(str) { }
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* not NamedResource_INCLUDED */
