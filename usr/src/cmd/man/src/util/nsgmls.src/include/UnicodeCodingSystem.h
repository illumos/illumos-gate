// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef UnicodeCodingSystem_INCLUDED
#define UnicodeCodingSystem_INCLUDED 1

#include "CodingSystem.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

class SP_API UnicodeCodingSystem : public CodingSystem {
public:
  UnicodeCodingSystem(const InputCodingSystem *sub = 0);
  Decoder *makeDecoder() const;
  Encoder *makeEncoder() const;
  unsigned fixedBytesPerChar() const;
private:
  const InputCodingSystem *sub_;
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* not UnicodeCodingSystem_INCLUDED */
