// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __GNUG__
#pragma implementation
#endif
#include "splib.h"
#include "MessageArg.h"
#include "MessageBuilder.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

MessageArg::MessageArg()
{
}

MessageArg::~MessageArg()
{
}

StringMessageArg::StringMessageArg(const StringC &s)
: s_(s)
{
}

MessageArg *StringMessageArg::copy() const
{
  return new StringMessageArg(*this);
}

void StringMessageArg::append(MessageBuilder &builder) const
{
  builder.appendChars(s_.data(), s_.size());
}

NumberMessageArg::NumberMessageArg(unsigned long n)
: n_(n)
{
}

MessageArg *NumberMessageArg::copy() const
{
  return new NumberMessageArg(*this);
}

void NumberMessageArg::append(MessageBuilder &builder) const
{
  builder.appendNumber(n_);
}


OrdinalMessageArg::OrdinalMessageArg(unsigned long n)
: n_(n)
{
}

MessageArg *OrdinalMessageArg::copy() const
{
  return new OrdinalMessageArg(*this);
}

void OrdinalMessageArg::append(MessageBuilder &builder) const
{
  builder.appendOrdinal(n_);
}

RTTI_DEF0(OtherMessageArg)

OtherMessageArg::OtherMessageArg()
{
}

void OtherMessageArg::append(MessageBuilder &builder) const
{
  builder.appendOther(this);
}

#ifdef SP_NAMESPACE
}
#endif
