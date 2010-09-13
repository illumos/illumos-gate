// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __GNUG__
#pragma implementation
#endif
#include "splib.h"
#include "ExternalId.h"
#include "CharsetInfo.h"
#include "macros.h"
#include "ParserMessages.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

ExternalId::ExternalId()
: haveSystem_(0), havePublic_(0)
{
}

void ExternalId::setSystem(Text &text)
{
  text.swap(system_);
  haveSystem_ = 1;
}

Boolean ExternalId::setPublic(Text &text, const CharsetInfo &charset,
			      Char space, const MessageType1 *&error)
{
  havePublic_ = 1;
  return public_.init(text, charset, space, error);
}

void ExternalId::setLocation(const Location &loc)
{
  loc_ = loc;
}

PublicId::PublicId()
: formal_(0)
{
}

Boolean PublicId::init(Text &text, const CharsetInfo &charset,
		       Char space, const MessageType1 *&error)
{
  text.swap(text_);
  const StringC &str = text_.string();
  formal_ = 0;
  const Char *next = str.data();
  const Char *lim = str.data() + str.size();
  Char solidus = charset.execToDesc('/');
  Char minus = charset.execToDesc('-');
  Char plus = charset.execToDesc('+');
  const Char *fieldStart;
  size_t fieldLength;
  if (!nextField(solidus, next, lim, fieldStart, fieldLength)) {
    error = &ParserMessages::fpiMissingField;
    return 0;
  }
  if (fieldLength == 1 && (*fieldStart == minus || *fieldStart == plus)) {
    ownerType_ = (*fieldStart == plus ? registered : unregistered);
    if (!nextField(solidus, next, lim, fieldStart, fieldLength)) {
      error = &ParserMessages::fpiMissingField;
      return 0;
    }
  }
  else
    ownerType_ = ISO;
  owner_.assign(fieldStart, fieldLength);
  if (!nextField(solidus, next, lim, fieldStart, fieldLength)) {
    error = &ParserMessages::fpiMissingField;
    return 0;
  }
  size_t i;
  for (i = 0; i < fieldLength; i++)
    if (fieldStart[i] == space)
      break;
  if (i >= fieldLength) {
    error = &ParserMessages::fpiMissingTextClassSpace;
    return 0;
  }
  StringC textClassString(fieldStart, i);
  if (!lookupTextClass(textClassString, charset, textClass_)) {
    error = &ParserMessages::fpiInvalidTextClass;
    return 0;
  }
  i++;				// skip the space
  fieldStart += i;
  fieldLength -= i;
  if (fieldLength  == 1 && *fieldStart == minus) {
    unavailable_ = 1;
    if (!nextField(solidus, next, lim, fieldStart, fieldLength)) {
      error = &ParserMessages::fpiMissingField;
      return 0;
    }
  }
  else
    unavailable_ = 0;
  description_.assign(fieldStart, fieldLength);
  if (!nextField(solidus, next, lim, fieldStart, fieldLength)) {
    error = &ParserMessages::fpiMissingField;
    return 0;
  }
  if (textClass_ != CHARSET) {
    for (i = 0; i < fieldLength; i++) {
      UnivChar c;
      if (!charset.descToUniv(fieldStart[i], c)
	  || c < UnivCharsetDesc::A || c >= UnivCharsetDesc::A + 26) {
	error = &ParserMessages::fpiInvalidLanguage;
	return 0;
      }
    }
    // The public text language must be a name.
    // Names cannot be empty.
    if (fieldLength == 0) {
      error = &ParserMessages::fpiInvalidLanguage;
      return 0;
    }
  }
  languageOrDesignatingSequence_.assign(fieldStart, fieldLength);
  if (nextField(solidus, next, lim, fieldStart, fieldLength)) {
    switch (textClass_) {
    case CAPACITY:
    case CHARSET:
    case NOTATION:
    case SYNTAX:
      error = &ParserMessages::fpiIllegalDisplayVersion;
      return 0;
    default:
      break;
    }
    haveDisplayVersion_ = 1;
    displayVersion_.assign(fieldStart, fieldLength);
  }
  else
    haveDisplayVersion_ = 0;
  if (next != 0) {
    error = &ParserMessages::fpiExtraField;
    return 0;
  }
  formal_ = 1;
  return 1;
}

Boolean PublicId::nextField(Char solidus,
				  const Char *&next,
				  const Char *lim,
				  const Char *&fieldStart,
				  size_t &fieldLength)

{
  if (next == 0)
    return 0;
  fieldStart = next;
  for (; next < lim; next++) {
    if (next[0] == solidus && next + 1 < lim && next[1] == solidus) {
      fieldLength = next - fieldStart;
      next += 2;
      return 1;
    }
  }
  fieldLength = lim - fieldStart;
  next = 0;
  return 1;
}

const char *const PublicId::textClasses[] = {
  "CAPACITY",
  "CHARSET",
  "DOCUMENT",
  "DTD",
  "ELEMENTS",
  "ENTITIES",
  "LPD",
  "NONSGML",
  "NOTATION",
  "SD",
  "SHORTREF",
  "SUBDOC",
  "SYNTAX",
  "TEXT",
};

Boolean PublicId::lookupTextClass(const StringC &str,
					const CharsetInfo &charset,
					TextClass &textClass)
{
  for (size_t i = 0; i < SIZEOF(textClasses); i++)
    if (str == charset.execToDesc(textClasses[i])) {
      textClass = TextClass(i);
      return 1;
    }
  return 0;
}

Boolean PublicId::getOwnerType(OwnerType &result) const
{
  if (!formal_)
    return 0;
  result = ownerType_;
  return 1;
}

Boolean PublicId::getOwner(StringC &result) const
{
  if (!formal_)
    return 0;
  result = owner_;
  return 1;
}

Boolean PublicId::getTextClass(TextClass &result) const
{
  if (!formal_)
    return 0;
  result = textClass_;
  return 1;
}

Boolean PublicId::getUnavailable(Boolean &result) const
{
  if (!formal_)
    return 0;
  result = unavailable_;
  return 1;
}

Boolean PublicId::getDescription(StringC &result) const
{
  if (!formal_)
    return 0;
  result = description_;
  return 1;
}

Boolean PublicId::getLanguage(StringC &result) const
{
  if (!formal_ || textClass_ == CHARSET)
    return 0;
  result = languageOrDesignatingSequence_;
  return 1;
}

Boolean PublicId::getDesignatingSequence(StringC &result) const
{
  if (!formal_ || textClass_ != CHARSET)
    return 0;
  result = languageOrDesignatingSequence_;
  return 1;
}

Boolean PublicId::getDisplayVersion(StringC &result) const
{
  if (!formal_)
    return 0;
  if (haveDisplayVersion_)
    result = displayVersion_;
  return 1;
}

#ifdef SP_NAMESPACE
}
#endif
