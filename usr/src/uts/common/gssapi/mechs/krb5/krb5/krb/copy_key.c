/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/copy_key.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 *
 *
 * krb5_copy_keyblock()
 */

#include "k5-int.h"

/*
 * krb5_copy_keyblock_data
 *
 * Utility for copying keyblock data structures safely.
 * This assumes that the necessary storage areas are
 * already allocated.
 */
krb5_error_code
krb5_copy_keyblock_data(krb5_context context,
			const krb5_keyblock *from, krb5_keyblock *to)
{
	krb5_error_code ret = 0;

	/* If nothing to copy, return no error */
	if (from == NULL || to == NULL)
		return (0);

	if ((to->contents == NULL || from->contents == NULL) &&
		from->length > 0)
		return (ENOMEM);

	to->magic       = from->magic;
	to->enctype     = from->enctype;
	to->length      = from->length;
	to->dk_list     = NULL;

	if (from->length > 0)
		(void) memcpy(to->contents, from->contents, from->length);

#ifdef _KERNEL
	to->kef_mt		= from->kef_mt;
	to->kef_key.ck_data	= NULL;
	to->key_tmpl		= NULL;
	if ((ret = init_key_kef(context->kef_cipher_mt, to))) {
		return (ret);
	}
#else
	/*
	 * Don't copy or try to initialize crypto framework
	 * data.  This data gets initialized the first time it is
	 * used.
	 */
	to->hKey	= CK_INVALID_HANDLE;
#endif /* _KERNEL */
	return (ret);
}


/*
 * Copy a keyblock, including alloc'ed storage.
 */
/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_copy_keyblock(context, from, to)
    krb5_context context;
    const krb5_keyblock *from;
    krb5_keyblock 	**to;
{
	krb5_keyblock	*new_key;
	krb5_error_code ret = 0;
	if (!(new_key = (krb5_keyblock *) MALLOC(sizeof(krb5_keyblock))))
		return (ENOMEM);

	if (!(new_key->contents = (krb5_octet *)MALLOC(from->length))) {
		FREE(new_key, sizeof(krb5_keyblock));
		return (ENOMEM);
	}

	ret = krb5_copy_keyblock_data(context, from, new_key);
	if (ret) {
		krb5_free_keyblock(context, new_key);
		return (ret);
	}

	*to = new_key;
	return (ret);
}
