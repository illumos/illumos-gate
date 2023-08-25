/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright (C) 2001 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 * Section 6 (Encryption) of the Kerberos revisions document defines
 * cipher states to be used to chain encryptions and decryptions
 * together.  Examples of cipher states include initialization vectors
 * for CBC encription.  Most Kerberos encryption systems can share
 * code for initializing and freeing cipher states.  This file
 * contains that default code.
 */

#include "k5-int.h"

/* ARGSUSED */
krb5_error_code krb5int_des_init_state
(krb5_context context, const krb5_keyblock *key,
	krb5_keyusage usage, krb5_data *new_state )
{
  new_state->length = 8;
  new_state->data = (void *) MALLOC(8);
  if (new_state->data) {
    /* Solaris Kerberos */
    (void) memset (new_state->data, 0, new_state->length);
    /* We need to copy in the key for des-cbc-cr--ick, but that's how it works*/
    if (key->enctype == ENCTYPE_DES_CBC_CRC) {
      /* Solaris Kerberos */
      (void) memcpy (new_state->data, key->contents, new_state->length);
  }
  } else {
    return ENOMEM;
  }
  return 0;
}

/* ARGSUSED */
krb5_error_code krb5int_default_free_state
(krb5_context context, krb5_data *state)
{
  if (state->data) {
    FREE (state->data, state->length);
    state-> data = NULL;
    state->length = 0;
  }
  return 0;
}



