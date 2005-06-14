#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * src/lib/krb5/asn.1/asn1_encode.h
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

#ifndef __ASN1_ENCODE_H__
#define __ASN1_ENCODE_H__

#include "k5-int.h"
#include "krbasn1.h"
#include "asn1buf.h"
#include <time.h>

/*
   Overview

     Each of these procedures inserts the encoding of an ASN.1
     primitive in a coding buffer.

   Operations

     asn1_encode_integer
     asn1_encode_octetstring
     asn1_encode_null
     asn1_encode_printablestring
     asn1_encode_ia5string
     asn1_encode_generaltime
     asn1_encode_generalstring
*/

asn1_error_code asn1_encode_integer
	(asn1buf *buf, const long val, unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_enumerated
(asn1buf *buf, const long val, unsigned int *retlen);

asn1_error_code asn1_encode_unsigned_integer
	(asn1buf *buf, const unsigned long val, 
		   unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_octetstring
	(asn1buf *buf,
		   const unsigned int len, const asn1_octet *val,
		   unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_oid
	(asn1buf *buf,
		   const unsigned int len, const asn1_octet *val,
		   unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_charstring
	(asn1buf *buf,
		   const unsigned int len, const char *val,
		   unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_null
	(asn1buf *buf, int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of NULL into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_printablestring
	(asn1buf *buf,
		   const unsigned int len, const char *val,
		   int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_ia5string
	(asn1buf *buf,
		   const unsigned int len, const char *val,
		   int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

asn1_error_code asn1_encode_generaltime
	(asn1buf *buf, const time_t val, unsigned int *retlen);
/* requires  *buf is allocated
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer.
   Note: The encoding of GeneralizedTime is YYYYMMDDhhmmZ */

asn1_error_code asn1_encode_generalstring
	(asn1buf *buf,
		   const unsigned int len, const char *val,
		   unsigned int *retlen);
/* requires  *buf is allocated,  val has a length of len characters
   modifies  *buf, *retlen
   effects   Inserts the encoding of val into *buf and returns 
              the length of the encoding in *retlen.
             Returns ENOMEM to signal an unsuccesful attempt
              to expand the buffer. */

#endif
