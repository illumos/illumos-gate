// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

// This uses a big endian byte order irrespective of host byte order.
// Nothing special is done with FEFF/FFFE.

#include "splib.h"

#ifdef SP_MULTI_BYTE

#include "Fixed2CodingSystem.h"
#include "macros.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

class Fixed2Decoder : public Decoder {
public:
  Fixed2Decoder();
  size_t decode(Char *to, const char *from, size_t fromLen,
		const char **rest);
  Boolean convertOffset(unsigned long &offset) const;
};

class Fixed2Encoder : public Encoder {
public:
  Fixed2Encoder();
  ~Fixed2Encoder();
  void output(Char *, size_t, OutputByteStream *);
  void output(const Char *, size_t, OutputByteStream *);
private:
  void allocBuf(size_t);
  char *buf_;
  size_t bufSize_;
};

Decoder *Fixed2CodingSystem::makeDecoder() const
{
  return new Fixed2Decoder;
}

Encoder *Fixed2CodingSystem::makeEncoder() const
{
  return new Fixed2Encoder;
}

unsigned Fixed2CodingSystem::fixedBytesPerChar() const
{
  return 2;
}

Fixed2Decoder::Fixed2Decoder()
: Decoder(2)
{
}

size_t Fixed2Decoder::decode(Char *to, const char *from, size_t fromLen,
			   const char **rest)
{
#ifdef SP_BIG_ENDIAN
  if (sizeof(Char) == 2 && from == (char *)to) {
    *rest = from + (fromLen & ~1);
    return fromLen/2;
  }
#endif
  fromLen &= ~1;
  *rest = from + fromLen;
  for (size_t n = fromLen; n > 0; n -= 2) {
    *to++ = ((unsigned char)from[0] << 8) + (unsigned char)from[1];
    from += 2;
  }
  return fromLen/2;
}

Boolean Fixed2Decoder::convertOffset(unsigned long &n) const
{
  n *= 2;
  return true;
}

Fixed2Encoder::Fixed2Encoder()
: buf_(0), bufSize_(0)
{
}

Fixed2Encoder::~Fixed2Encoder()
{
  delete [] buf_;
}

void Fixed2Encoder::allocBuf(size_t n)
{
  if (bufSize_ < n) {
    delete [] buf_;
    buf_ = new char[bufSize_ = n];
  }
}

void Fixed2Encoder::output(Char *s, size_t n, OutputByteStream *sb)
{
#ifdef SP_BIG_ENDIAN
  if (sizeof(Char) == 2) {
    sb->sputn((char *)s, n*2);
    return;
  }
#endif
  ASSERT(sizeof(Char) >= 2);
  char *p = (char *)s;
  for (size_t i = 0; i < n; i++) {
    Char c = s[i];
    *p++ = (c >> 8) & 0xff;
    *p++ = c & 0xff;
  }
  sb->sputn((char *)s, n*2);
}

void Fixed2Encoder::output(const Char *s, size_t n, OutputByteStream *sb)
{
#ifdef SP_BIG_ENDIAN
  if (sizeof(Char) == 2) {
    sb->sputn((char *)s, n*2);
    return;
  }
#endif
  allocBuf(n*2);
  for (size_t i = 0; i < n; i++) {
    buf_[i*2] = (s[i] >> 8) & 0xff;
    buf_[i*2 + 1] = s[i] & 0xff;
  }
  sb->sputn(buf_, n*2);
}

#ifdef SP_NAMESPACE
}
#endif

#else /* not SP_MULTI_BYTE */

#ifndef __GNUG__
static char non_empty_translation_unit;	// sigh
#endif

#endif /* not SP_MULTI_BYTE */
