#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * src/lib/krb5/asn.1/asn1_misc.c
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

#include "asn1_misc.h"

asn1_error_code asn1_krb5_realm_copy(krb5_principal target, krb5_principal source)
{
  target->realm.length = source->realm.length;
  target->realm.data = (char*)malloc(target->realm.length); /* copy realm */
  if (target->realm.data == NULL) return ENOMEM;
  memcpy(target->realm.data,source->realm.data, /* to client */
	 target->realm.length);
  return 0;
}
