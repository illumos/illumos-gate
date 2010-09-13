// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef MarkupScan_INCLUDED
#define MarkupScan_INCLUDED 1

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct MarkupScan {
  enum Type {
    normal,
    in,
    out,
    suppress
    };
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* not MarkupScan_INCLUDED */
