#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * src/lib/krb5/asn.1/asn1_make.h
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

#ifndef __ASN1_MAKE_H__
#define __ASN1_MAKE_H__

#include "k5-int.h"
#include "krbasn1.h"
#include "asn1buf.h"

/*
   Overview

     Each of these procedures constructs a subpart of an ASN.1
     primitive in a coding buffer.

    Operations

      asn1_make_etag
      asn1_make_sequence
      asn1_make_set
      asn1_make_tag
      asn1_make_string
*/

asn1_error_code asn1_make_etag
	(asn1buf *buf,
		   const asn1_class asn1class,
		   const asn1_tagnum tagnum,
		   const unsigned int in_len,
		   unsigned int *retlen);
/* requires  *buf is allocated, in_len is the length of an ASN.1 encoding
             which has just been inserted in *buf
   modifies  *buf, *retlen
   effects   Inserts an explicit tag with class = asn1class, id# = tag
              length = in_len into *buf.
	     Returns the length of this encoding in *retlen.
	     Returns ENOMEM if memory runs out. */

asn1_error_code asn1_make_tag
	(asn1buf *buf, const asn1_class asn1class,
		   const asn1_construction construction,
		   const asn1_tagnum tagnum,
		   const unsigned int in_len,
		   unsigned int *retlen);
/* requires  *buf is allocated, in_len is the length of an ASN.1 encoding
             which has just been inserted in *buf
   modifies  *buf, *retlen
   effects   Inserts the encoding of a tag with class = asn1class,
              primitive/constructed staus = construction,
	      id# = tag and length = in_len into *buf.
	     Returns the length of this encoding in *retlen.
	     Returns ENOMEM if memory runs out.
	     Returns ASN1_OVERFLOW if tagnum exceeds the limits of
	      the implementation. */

asn1_error_code asn1_make_sequence
	(asn1buf *buf, const unsigned int seq_len, unsigned int *len);
/* requires  *buf is allocated, seq_len is the length of a series of
             sequence components which have just been inserted in *buf
   modifies  *buf, *retlen
   effects   Inserts the sequence header for a sequence of length seq_len
              in *buf.  Returns the length of this encoding in *retlen.
             Returns ENOMEM if memory runs out. */

asn1_error_code asn1_make_set
	(asn1buf *buf, const unsigned int set_len, 
		   unsigned int *retlen);
/* requires  *buf is allocated, seq_len is the length of a series of
             sequence components which have just been inserted in *buf
   modifies  *buf, *retlen
   effects   Inserts the set header for a set of length set_len in *buf.
             Returns the length of this encoding in *retlen.
             Returns ENOMEM if memory runs out. */

asn1_error_code asn1_make_string
	(asn1buf *buf,
		   const unsigned int len, const char *string,
		   int *retlen);
/* requires  *buf is allocated, len is the length of *string
   effects   Inserts the encoding of *string (a series of octets) in *buf.
             Returns the length of this encoding in *retlen.
             Returns ENOMEM if memory runs out. */


/****************************************************************/
/* Private procedures */

/* "helper" procedure for asn1_make_tag */
asn1_error_code asn1_make_length
	(asn1buf *buf, const unsigned int in_len, 
		   unsigned int *retlen);
/* requires  *buf is allocated, in_len is the length of an ASN.1 encoding
             which has just been inserted in *buf
   modifies  *buf, *retlen
   effects   inserts length octet(s) for in_len into *buf */

/* "helper" procedure for asn1_make_tag */
asn1_error_code asn1_make_id
	(asn1buf *buf,
		   const asn1_class asn1class,
		   const asn1_construction construction,
		   const asn1_tagnum tagnum,
		   unsigned int *retlen);
/* requires  *buf is allocated, asn1class and tagnum are appropriate for
             the ASN.1 encoding which has just been inserted in *buf
   modifies  *buf, *retlen
   effects   Inserts id octet(s) of class asn1class and tag number tagnum
             into *buf */

#endif
