// Copyright (c) 1996 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef MessageTable_INCLUDED
#define MessageTable_INCLUDED 1

#ifdef __GNUG__
#pragma interface
#endif

#include "Message.h"
#include "Boolean.h"
#include "StringC.h"
#include "sptchar.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

class SP_API MessageTable {
public:
  static const MessageTable *instance();
  virtual Boolean getText(const MessageFragment &,
			  String<SP_TCHAR> &) const = 0;
private:
  static MessageTable *instance_;
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* not MessageTable_INCLUDED */
