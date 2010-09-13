// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "splib.h"

#ifdef SP_MULTI_BYTE

#include "UnicodeCodingSystem.h"
#include "macros.h"
#include "Owner.h"

#include <stddef.h>
#include <string.h>
#ifdef DECLARE_MEMMOVE
extern "C" {
  void *memmove(void *, const void *, size_t);
}
#endif

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

const unsigned short byteOrderMark = 0xfeff;
const unsigned short swappedByteOrderMark = 0xfffe;

class UnicodeDecoder : public Decoder {
public:
  UnicodeDecoder(const InputCodingSystem *sub);
  size_t decode(Char *to, const char *from, size_t fromLen,
		const char **rest);
  Boolean convertOffset(unsigned long &offset) const;
private:
  PackedBoolean hadFirstChar_;
  PackedBoolean hadByteOrderMark_;
  PackedBoolean swapBytes_;
  Owner<Decoder> subDecoder_;
  const InputCodingSystem *subCodingSystem_;
};

class UnicodeEncoder : public Encoder {
public:
  UnicodeEncoder();
  ~UnicodeEncoder();
  void output(Char *, size_t, OutputByteStream *);
  void output(const Char *, size_t, OutputByteStream *);
  void startFile(OutputByteStream *);
private:
  void allocBuf(size_t);
  unsigned short *buf_;
  size_t bufSize_;
};

UnicodeCodingSystem::UnicodeCodingSystem(const InputCodingSystem *sub)
: sub_(sub)
{
}

Decoder *UnicodeCodingSystem::makeDecoder() const
{
  return new UnicodeDecoder(sub_);
}

Encoder *UnicodeCodingSystem::makeEncoder() const
{
  return new UnicodeEncoder;
}

unsigned UnicodeCodingSystem::fixedBytesPerChar() const
{
  return 2;
}

UnicodeDecoder::UnicodeDecoder(const InputCodingSystem *subCodingSystem)
: Decoder(subCodingSystem ? 1 : 2), subCodingSystem_(subCodingSystem),
  hadByteOrderMark_(0), hadFirstChar_(0), swapBytes_(0)
{
}


size_t UnicodeDecoder::decode(Char *to, const char *from, size_t fromLen,
			      const char **rest)
{
  union U {
    unsigned short word;
    char bytes[2];
  };
    
  if (subDecoder_)
    return subDecoder_->decode(to, from, fromLen, rest);
  if (!hadFirstChar_) {
    if (fromLen < 2) {
      *rest = from;
      return 0;
    }
    hadFirstChar_ = 1;
    minBytesPerChar_ = 2;
    U u;
    u.bytes[0] = from[0];
    u.bytes[1] = from[1];
    if (u.word == byteOrderMark) {
      hadByteOrderMark_ = 1;
      from += 2;
      fromLen -= 2;
    }
    else if (u.word == swappedByteOrderMark) {
      hadByteOrderMark_ = 1;
      from += 2;
      fromLen -= 2;
      swapBytes_ = 1;
    }
    else if (subCodingSystem_) {
      subDecoder_ = subCodingSystem_->makeDecoder();
      minBytesPerChar_ = subDecoder_->minBytesPerChar();
      return subDecoder_->decode(to, from, fromLen, rest);
    }
  }
  fromLen &= ~1;
  *rest = from + fromLen;
  if (sizeof(Char) == 2) {
    if (!swapBytes_) {
      if (from != (char *)to)
	memmove(to, from, fromLen);
      return fromLen/2;
    }
  }
  if (swapBytes_) {
    for (size_t n = fromLen; n > 0; n -= 2) {
      U u;
      u.bytes[1] = *from++;
      u.bytes[0] = *from++;
      *to++ = u.word;
    }
  }
  else  {
    for (size_t n = fromLen; n > 0; n -= 2) {
      U u;
      u.bytes[0] = *from++;
      u.bytes[1] = *from++;
      *to++ = u.word;
    }
  }
  return fromLen/2;
}

Boolean UnicodeDecoder::convertOffset(unsigned long &n) const
{
  if (subDecoder_)
    return subDecoder_->convertOffset(n);
  if (hadByteOrderMark_)
    n += 1;
  n *= 2;
  return true;
}

UnicodeEncoder::UnicodeEncoder()
: buf_(0), bufSize_(0)
{
}

UnicodeEncoder::~UnicodeEncoder()
{
  delete [] buf_;
}

void UnicodeEncoder::allocBuf(size_t n)
{
  if (bufSize_ < n) {
    delete [] buf_;
    buf_ = new unsigned short[bufSize_ = n];
  }
}

void UnicodeEncoder::startFile(OutputByteStream *sb)
{
  const unsigned short n = byteOrderMark;
  sb->sputn((char *)&n, 2);
}

void UnicodeEncoder::output(Char *s, size_t n, OutputByteStream *sb)
{
  if (sizeof(Char) == 2) {
    sb->sputn((char *)s, n*2);
    return;
  }
  ASSERT(sizeof(Char) >= 2);
  unsigned short *p = (unsigned short *)s;
  for (size_t i = 0; i < n; i++)
    p[i] = s[i] & 0xffff;
  sb->sputn((char *)s, n*2);
}

void UnicodeEncoder::output(const Char *s, size_t n, OutputByteStream *sb)
{
  if (sizeof(Char) == 2) {
    sb->sputn((char *)s, n*2);
    return;
  }
  allocBuf(n);
  for (size_t i = 0; i < n; i++)
    buf_[i] = s[i] & 0xffff;
  sb->sputn((char *)buf_, n*2);
}

#ifdef SP_NAMESPACE
}
#endif

#else /* not SP_MULTI_BYTE */

#ifndef __GNUG__
static char non_empty_translation_unit;	// sigh
#endif

#endif /* not SP_MULTI_BYTE */
