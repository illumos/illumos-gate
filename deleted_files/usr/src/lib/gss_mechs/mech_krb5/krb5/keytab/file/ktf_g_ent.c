/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/keytab/file/ktf_get_en.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This is the get_entry routine for the file based keytab implementation.
 * It opens the keytab file, and either retrieves the entry or returns
 * an error.
 */

#include <k5-int.h>
#include "ktfile.h"

krb5_error_code KRB5_CALLCONV
krb5_ktfile_get_entry(context, id, principal, kvno, enctype, entry)
   krb5_context context;
   krb5_keytab id;
   krb5_const_principal principal;
   krb5_kvno kvno;
   krb5_enctype enctype;
   krb5_keytab_entry * entry;
{
    krb5_keytab_entry cur_entry, new_entry;
    krb5_error_code kerror = 0;
    int found_wrong_kvno = 0;
    krb5_boolean similar;
    int kvno_offset = 0;

    KRB5_LOG0(KRB5_INFO, "krb5_ktfile_get_entry() start\n");

    /* Open the keyfile for reading */
    if ((kerror = krb5_ktfileint_openr(context, id))){
	KRB5_LOG(KRB5_ERR, "krb5_ktfile_get_entry() end, krb5_ktfileint_openr() "
		"kerror= %d\n", kerror);
	return(kerror);
    }

    /*
     * For efficiency and simplicity, we'll use a while true that
     * is exited with a break statement.
     */
    cur_entry.principal = 0;
    cur_entry.vno = 0;
    cur_entry.key.contents = 0;
    /*CONSTCOND*/
    while (TRUE) {
	if ((kerror = krb5_ktfileint_read_entry(context, id, &new_entry)))
	    break;

	/* by the time this loop exits, it must either free cur_entry,
	   and copy new_entry there, or free new_entry.  Otherwise, it
	   leaks. */

	/* if the principal isn't the one requested, free new_entry
	   and continue to the next. */

	if (!krb5_principal_compare(context, principal, new_entry.principal)) {
	    krb5_kt_free_entry(context, &new_entry);
	    continue;
	}

	/* if the enctype is not ignored and doesn't match, free new_entry
	   and continue to the next */

	if (enctype != IGNORE_ENCTYPE) {
	    if ((kerror = krb5_c_enctype_compare(context, enctype,
						 new_entry.key.enctype,
						 &similar))) {
		krb5_kt_free_entry(context, &new_entry);
		break;
	    }

	    if (!similar) {
		krb5_kt_free_entry(context, &new_entry);
		continue;
	    }
	    /*
	     * Coerce the enctype of the output keyblock in case we
	     * got an inexact match on the enctype.
	     */
	    new_entry.key.enctype = enctype;
	}

	if (kvno == IGNORE_VNO) {
	    /* if this is the first match, or if the new vno is
	       bigger, free the current and keep the new.  Otherwise,
	       free the new. */
	    /* A 1.2.x keytab contains only the low 8 bits of the key
	       version number.  Since it can be much bigger, and thus
	       the 8-bit value can wrap, we need some heuristics to
	       figure out the "highest" numbered key if some numbers
	       close to 255 and some near 0 are used.

	       The heuristic here:

	       If we have any keys with versions over 240, then assume
	       that all version numbers 0-127 refer to 256+N instead.
	       Not perfect, but maybe good enough?  */

#define M(VNO) (((VNO) - kvno_offset + 256) % 256)

	    if (new_entry.vno > 240)
		kvno_offset = 128;
	    if (! cur_entry.principal ||
		M(new_entry.vno) > M(cur_entry.vno)) {
		krb5_kt_free_entry(context, &cur_entry);
		cur_entry = new_entry;
	    } else {
		krb5_kt_free_entry(context, &new_entry);
	    }
	} else {
	    /* if this kvno matches, free the current (will there ever
	       be one?), keep the new, and break out.  Otherwise, remember
	       that we were here so we can return the right error, and
	       free the new */
	    /* Yuck.  The krb5-1.2.x keytab format only stores one byte
	       for the kvno, so we're toast if the kvno requested is
	       higher than that.  Short-term workaround: only compare
	       the low 8 bits.  */

	    if (new_entry.vno == (kvno & 0xff)) {
		krb5_kt_free_entry(context, &cur_entry);
		cur_entry = new_entry;
		break;
	    } else {
		found_wrong_kvno++;
		krb5_kt_free_entry(context, &new_entry);
	    }
	}
    }

    if (kerror == KRB5_KT_END) {
	 if (cur_entry.principal)
	      kerror = 0;
	 else if (found_wrong_kvno)
	      kerror = KRB5_KT_KVNONOTFOUND;
	 else
	      kerror = KRB5_KT_NOTFOUND;
    }
    if (kerror) {
	(void) krb5_ktfileint_close(context, id);
	krb5_kt_free_entry(context, &cur_entry);
	KRB5_LOG(KRB5_ERR,"krb5_ktfile_get_entry() end, kerror="
		    "%d\n", kerror);
	return kerror;
    }
    if ((kerror = krb5_ktfileint_close(context, id)) != 0) {
	krb5_kt_free_entry(context, &cur_entry);
	KRB5_LOG(KRB5_ERR,"krb5_ktfile_get_entry() end, krb5_ktfileint_close() "
	       "kerror= %d\n", kerror);
	return kerror;
    }
    *entry = cur_entry;

    /* Let us close the file before we leave */
    (void) krb5_ktfileint_close(context, id);

    KRB5_LOG0(KRB5_INFO, "krb5_ktfile_get_entry() end");

    return 0;
}
