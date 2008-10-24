/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * src/lib/krb5/asn.1/asn1_encode.c
 * 
 * Copyright 1994 by the Massachusetts Institute of Technology.
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

/* ASN.1 primitive encoders */

#include "asn1_encode.h"
#include "asn1_make.h"

static asn1_error_code asn1_encode_integer_internal(asn1buf *buf,  long val,
						    unsigned int *retlen)
{
  asn1_error_code retval;
  unsigned int length = 0;
  long valcopy;
  int digit;
  
  valcopy = val;
  do {
    digit = (int) (valcopy&0xFF);
    retval = asn1buf_insert_octet(buf,(asn1_octet) digit);
    if(retval) return retval;
    length++;
    valcopy = valcopy >> 8;
  } while (valcopy != 0 && valcopy != ~0);

  if((val > 0) && ((digit&0x80) == 0x80)) { /* make sure the high bit is */
    retval = asn1buf_insert_octet(buf,0); /* of the proper signed-ness */
    if(retval) return retval;
    length++;
  }else if((val < 0) && ((digit&0x80) != 0x80)){
    retval = asn1buf_insert_octet(buf,0xFF);
    if(retval) return retval;
    length++;
  }


  *retlen = length;
  return 0;
}

asn1_error_code asn1_encode_integer(asn1buf * buf,  long val,
 unsigned int *retlen)
{
  asn1_error_code retval;
  unsigned int length = 0;
  unsigned  int partlen;
  retval = asn1_encode_integer_internal(buf, val, &partlen);
  if (retval) return retval;

  length = partlen;
    retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_INTEGER,length, &partlen); 
  if(retval) return retval;
  length += partlen;

  *retlen = length;
  return 0;
}

asn1_error_code
asn1_encode_enumerated(asn1buf * buf, const long val,
		       unsigned int *retlen)
{
  asn1_error_code retval;
  unsigned int length = 0;
  unsigned  int partlen;
  retval = asn1_encode_integer_internal(buf, val, &partlen);
  if (retval) return retval;

  length = partlen;
    retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_ENUMERATED,length, &partlen); 
  if(retval) return retval;
  length += partlen;

  *retlen = length;
  return 0;
}

asn1_error_code asn1_encode_unsigned_integer(asn1buf *buf, unsigned long val,
					     unsigned int *retlen)
{
  asn1_error_code retval;
  unsigned int length = 0;
  unsigned int partlen;
  unsigned long valcopy;
  int digit;
  
  valcopy = val;
  do {
    digit = (int) (valcopy&0xFF);
    retval = asn1buf_insert_octet(buf,(asn1_octet) digit);
    if(retval) return retval;
    length++;
    valcopy = valcopy >> 8;
  } while (valcopy != 0 && valcopy != ~0);

  if(digit&0x80) {		          /* make sure the high bit is */
    retval = asn1buf_insert_octet(buf,0); /* of the proper signed-ness */
    if(retval) return retval;
    length++;
  }

  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_INTEGER,length, &partlen); 
  if(retval) return retval;
  length += partlen;

  *retlen = length;
  return 0;
}

asn1_error_code asn1_encode_oid(asn1buf *buf, unsigned int len,
				const asn1_octet *val,
				unsigned int *retlen)
{
  asn1_error_code retval;
  unsigned int length;

  retval = asn1buf_insert_octetstring(buf, len, val);
  if (retval) return retval;
  retval = asn1_make_tag(buf, UNIVERSAL, PRIMITIVE, ASN1_OBJECTIDENTIFIER,
			 len, &length);
  if (retval) return retval;

  *retlen = len + length;
  return 0;
}

asn1_error_code asn1_encode_octetstring(asn1buf *buf, unsigned int len,
					const asn1_octet *val,
					unsigned int *retlen)
{
  asn1_error_code retval;
  unsigned int length;

  retval = asn1buf_insert_octetstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_OCTETSTRING,len,&length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}

asn1_error_code asn1_encode_charstring(asn1buf *buf, unsigned int len,
				       const char *val, unsigned int *retlen)
{
  asn1_error_code retval;
  unsigned int length;

  retval = asn1buf_insert_charstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_OCTETSTRING,len,&length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}

asn1_error_code asn1_encode_null(asn1buf *buf, int *retlen)
{
  asn1_error_code retval;
  
  retval = asn1buf_insert_octet(buf,0x00);
  if(retval) return retval;
  retval = asn1buf_insert_octet(buf,0x05);
  if(retval) return retval;

  *retlen = 2;
  return 0;
}

asn1_error_code asn1_encode_printablestring(asn1buf *buf, unsigned int len,
					    const char *val, int *retlen)
{
  asn1_error_code retval;
  unsigned int length;

  retval = asn1buf_insert_charstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_PRINTABLESTRING,len,			 &length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}

asn1_error_code asn1_encode_ia5string(asn1buf *buf, unsigned int len,
				      const char *val, int *retlen)
{
  asn1_error_code retval;
  unsigned int length;

  retval = asn1buf_insert_charstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_IA5STRING,len,			 &length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}

asn1_error_code asn1_encode_generaltime(asn1buf *buf, time_t val,
					unsigned int *retlen)
{
  asn1_error_code retval;
  struct tm *gtime, gtimebuf;
  char s[16], *sp;
  unsigned int length, sum=0;
  time_t gmt_time = val;

  /*
   * Time encoding: YYYYMMDDhhmmssZ
   */
  if (gmt_time == 0) {
      sp = "19700101000000Z";
  } else {

      /*
       * Sanity check this just to be paranoid, as gmtime can return NULL,
       * and some bogus implementations might overrun on the sprintf.
       */
#ifdef HAVE_GMTIME_R
# ifdef GMTIME_R_RETURNS_INT
      if (gmtime_r(&gmt_time, &gtimebuf) != 0)
	  return ASN1_BAD_GMTIME;
# else
      if (gmtime_r(&gmt_time, &gtimebuf) == NULL)
	  return ASN1_BAD_GMTIME;
# endif
#else
      gtime = gmtime(&gmt_time);
      if (gtime == NULL)
	  return ASN1_BAD_GMTIME;
      memcpy(&gtimebuf, gtime, sizeof(gtimebuf));
#endif
      gtime = &gtimebuf;

      if (gtime->tm_year > 8099 || gtime->tm_mon > 11 ||
	  gtime->tm_mday > 31 || gtime->tm_hour > 23 ||
	  gtime->tm_min > 59 || gtime->tm_sec > 59)
	  return ASN1_BAD_GMTIME;
      sprintf(s, "%04d%02d%02d%02d%02d%02dZ",
	      1900+gtime->tm_year, gtime->tm_mon+1, gtime->tm_mday,
	      gtime->tm_hour, gtime->tm_min, gtime->tm_sec);
      sp = s;
  }

  retval = asn1buf_insert_charstring(buf,15,sp);
  if(retval) return retval;
  sum = 15;

  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_GENERALTIME,sum,&length);
  if(retval) return retval;
  sum += length;

  *retlen = sum;
  return 0;
}

asn1_error_code asn1_encode_generalstring(asn1buf *buf, unsigned int len,
					  const char *val,
					  unsigned int *retlen)
{
  asn1_error_code retval;
  unsigned int length;

  retval = asn1buf_insert_charstring(buf,len,val);
  if(retval) return retval;
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_GENERALSTRING,len,
			 &length);
  if(retval) return retval;

  *retlen = len + length;
  return 0;
}
