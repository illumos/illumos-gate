/*
 * src/lib/krb5/asn.1/asn1_decode.c
 * 
 * Copyright 1994, 2003 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/* ASN.1 primitive decoders */
#include "asn1_decode.h"
#include "asn1_get.h"
#include <stdio.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif

#define setup()\
asn1_error_code retval;\
taginfo tinfo

#define asn1class	(tinfo.asn1class)
#define construction	(tinfo.construction)
#define tagnum		(tinfo.tagnum)
#define length		(tinfo.length)

#define tag(type)\
retval = asn1_get_tag_2(buf,&tinfo);\
if(retval) return retval;\
if(asn1class != UNIVERSAL || construction != PRIMITIVE || tagnum != type)\
  return ASN1_BAD_ID
  
#define cleanup()\
return 0

extern time_t krb5int_gmt_mktime (struct tm *);

asn1_error_code asn1_decode_integer(asn1buf *buf, long int *val)
{
  setup();
  asn1_octet o;
  long n = 0; /* initialize to keep gcc happy */
  int i;

  tag(ASN1_INTEGER);

  for (i = 0; i < length; i++) {
    retval = asn1buf_remove_octet(buf, &o);
    if (retval) return retval;
    if (!i) {
      n = (0x80 & o) ? -1 : 0;	/* grab sign bit */
      if (n < 0 && length > sizeof (long))
	return ASN1_OVERFLOW;
      else if (length > sizeof (long) + 1) /* allow extra octet for positive */
	return ASN1_OVERFLOW;
    }
    n = (n << 8) | o;
  }
  *val = n;
  cleanup();
}

asn1_error_code asn1_decode_unsigned_integer(asn1buf *buf, long unsigned int *val)
{
  setup();
  asn1_octet o;
  unsigned long n;
  int i;

  tag(ASN1_INTEGER);

  for (i = 0, n = 0; i < length; i++) {
    retval = asn1buf_remove_octet(buf, &o);
    if(retval) return retval;
    if (!i) {
      if (0x80 & o)
	return ASN1_OVERFLOW;
      else if (length > sizeof (long) + 1)
	return ASN1_OVERFLOW;
    }
    n = (n << 8) | o;
  }
  *val = n;
  cleanup();
}

/*
 * asn1_decode_maybe_unsigned
 *
 * This is needed because older releases of MIT krb5 have signed
 * sequence numbers.  We want to accept both signed and unsigned
 * sequence numbers, in the range -2^31..2^32-1, mapping negative
 * numbers into their positive equivalents in the same way that C's
 * normal integer conversions do, i.e., would preserve bits on a
 * two's-complement architecture.
 */
asn1_error_code asn1_decode_maybe_unsigned(asn1buf *buf, unsigned long *val)
{
  setup();
  asn1_octet o;
  unsigned long n, bitsremain;
  unsigned int i;

  tag(ASN1_INTEGER);
  o = 0;
  n = 0;
  bitsremain = ~0UL;
  for (i = 0; i < length; i++) {
    /* Accounts for u_long width not being a multiple of 8. */
    if (bitsremain < 0xff) return ASN1_OVERFLOW;
    retval = asn1buf_remove_octet(buf, &o);
    if (retval) return retval;
    if (bitsremain == ~0UL) {
      if (i == 0)
	n = (o & 0x80) ? ~0UL : 0UL; /* grab sign bit */
      /*
       * Skip leading zero or 0xFF octets to humor non-compliant encoders.
       */
      if (n == 0 && o == 0)
	continue;
      if (n == ~0UL && o == 0xff)
	continue;
    }
    n = (n << 8) | o;
    bitsremain >>= 8;
  }
  *val = n;
  cleanup();
}

asn1_error_code asn1_decode_oid(asn1buf *buf, unsigned int *retlen, asn1_octet **val)
{
  setup();
  tag(ASN1_OBJECTIDENTIFIER);
  retval = asn1buf_remove_octetstring(buf, length, val);
  if (retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_octetstring(asn1buf *buf, unsigned int *retlen, asn1_octet **val)
{
  setup();
  tag(ASN1_OCTETSTRING);
  retval = asn1buf_remove_octetstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_charstring(asn1buf *buf, unsigned int *retlen, char **val)
{
  setup();
  tag(ASN1_OCTETSTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}


asn1_error_code asn1_decode_generalstring(asn1buf *buf, unsigned int *retlen, char **val)
{
  setup();
  tag(ASN1_GENERALSTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}


asn1_error_code asn1_decode_null(asn1buf *buf)
{
  setup();
  tag(ASN1_NULL);
  if(length != 0) return ASN1_BAD_LENGTH;
  cleanup();
}

asn1_error_code asn1_decode_printablestring(asn1buf *buf, int *retlen, char **val)
{
  setup();
  tag(ASN1_PRINTABLESTRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_ia5string(asn1buf *buf, int *retlen, char **val)
{
  setup();
  tag(ASN1_IA5STRING);
  retval = asn1buf_remove_charstring(buf,length,val);
  if(retval) return retval;
  *retlen = length;
  cleanup();
}

asn1_error_code asn1_decode_generaltime(asn1buf *buf, time_t *val)
{
  setup();
  char *s;
  struct tm ts;
  time_t t;

  tag(ASN1_GENERALTIME);

  if(length != 15) return ASN1_BAD_LENGTH;
  retval = asn1buf_remove_charstring(buf,15,&s);
  if (retval) return retval;
  /* Time encoding: YYYYMMDDhhmmssZ */
  if(s[14] != 'Z') {
      free(s);
      return ASN1_BAD_FORMAT;
  }
  if(s[0] == '1' && !memcmp("19700101000000Z", s, 15)) {
      t = 0;
      free(s);
      goto done;
  }
#define c2i(c) ((c)-'0')
  ts.tm_year = 1000*c2i(s[0]) + 100*c2i(s[1]) + 10*c2i(s[2]) + c2i(s[3])
    - 1900;
  ts.tm_mon = 10*c2i(s[4]) + c2i(s[5]) - 1;
  ts.tm_mday = 10*c2i(s[6]) + c2i(s[7]);
  ts.tm_hour = 10*c2i(s[8]) + c2i(s[9]);
  ts.tm_min = 10*c2i(s[10]) + c2i(s[11]);
  ts.tm_sec = 10*c2i(s[12]) + c2i(s[13]);
  ts.tm_isdst = -1;
  t = krb5int_gmt_mktime(&ts);
  free(s);

  if(t == -1) return ASN1_BAD_TIMEFORMAT;

done:
  *val = t;
  cleanup();
}
