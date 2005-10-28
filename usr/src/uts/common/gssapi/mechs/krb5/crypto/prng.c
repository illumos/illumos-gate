/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include <k5-int.h>

#ifdef _KERNEL
#include <sys/random.h>
#endif

#ifndef _KERNEL

/*
 * Solaris kerberos:  we don't need a random number generator
 * for the /dev/[u]random, as it uses entropy in the kernel.
 * Keep this function as some apps might call it directly.
 */

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_c_random_seed(krb5_context context, krb5_data *data)
{
	/*
	 * We can't do much if this fails, so ignore the
	 * return code.  /dev/urandom has its own entropy
	 * source, so seeding it from here is of questionable 
	 * value in the first place.
	 */
	(void) C_SeedRandom(krb_ctx_hSession(context),
		(CK_BYTE_PTR)data->data,
		(CK_ULONG)data->length);

	return(0);
}
#endif /* !_KERNEL */

/*
 * krb5_get_random_octets
 *   New for Solaris 9.  This routine takes advantage of the new
 * /dev/[u]random interface provided in Solaris 9 for getting random
 * bytes generated from the kernel.  The entropy produced there is generally
 * considered better than the current MIT PRNG code that we are replacing.
 *
 * This func is visible so that it can be used to generate a
 * random confounder.
 */

#ifndef _KERNEL

#endif /* ! _KERNEL */

/*
 * We can assume that the memory for data is already malloc'd.
 * Return an error if there is an error, but don't clear the data->length
 * or free data->data.  This will be done by the calling function.
 */

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_c_random_make_octets(krb5_context context, krb5_data *data)
{
/*
 * Solaris kerberos uses /dev/[u]random
 */
#ifndef _KERNEL /* User space code */

    krb5_error_code err = 0;
    CK_RV rv;

    KRB5_LOG0(KRB5_INFO, "krb5_c_random_make_octets() start, user space using "
	"krb5_get_random_octets()\n");

    rv = C_GenerateRandom(krb_ctx_hSession(context), (CK_BYTE_PTR)data->data,
		(CK_ULONG)data->length);

    if (rv != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_GenerateRandom failed in "
		"krb5_c_random_make_octets: rv = 0x%x.", rv);
	err = PKCS_ERR;
    }
    if (err != 0) {
	KRB5_LOG0(KRB5_ERR, "krb5_c_random_make_octets() end, error");
	return (err);
    }

#else  /* Kernel code section */

    /*
     * Solaris Kerberos: for kernel code we use the randomness generator native
     * to Solaris 9.  We avoid global variables and other nastiness this way.
     *
     * Using random_get_pseudo_bytes() instead of random_get_bytes() because it
     * will not return an error code if there isn't enough entropy but will use
     * a pseudo random algorithm to produce randomness.  Most of the time it
     * should be as good as random_get_bytes() and we don't have to worry about
     * dealing with a non-fatal error.
     */
    KRB5_LOG0(KRB5_INFO, "krb5_c_random_make_octets() start, kernel using "
	    "random_get_pseudo_bytes()\n ");

    if(random_get_pseudo_bytes((uint8_t *)data->data, data->length) != 0) {
	KRB5_LOG0(KRB5_ERR, "krb5_c_random_make_octets() end, "
		"random_get_pseudo_bytes() error.\n");
	return(KRB5_CRYPTO_INTERNAL);
    }

#endif /* !_KERNEL */

    KRB5_LOG0(KRB5_INFO, "krb5_c_random_make_octets() end\n");
    return(0);
}
