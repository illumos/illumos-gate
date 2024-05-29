/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * Solaris Kerberos:
 * Iterate through a keytab (keytab) looking for an entry which matches
 * the components of a principal (princ) but match on any realm. When a
 * suitable entry is found return the entry's realm.
 */

#include "k5-int.h"

krb5_error_code krb5_kt_find_realm(krb5_context context, krb5_keytab keytab,
    krb5_principal princ, krb5_data *realm) {

	krb5_kt_cursor cur;
	krb5_keytab_entry ent;
	krb5_boolean match;
	krb5_data tmp_realm;
	krb5_error_code ret, ret2;

	ret = krb5_kt_start_seq_get(context, keytab, &cur);
	if (ret != 0) {
		return (ret);
	}

	while ((ret = krb5_kt_next_entry(context, keytab, &ent, &cur)) == 0) {
		/* For the comparison the realms should be the same. */
		memcpy(&tmp_realm, &ent.principal->realm, sizeof (krb5_data));
		memcpy(&ent.principal->realm, &princ->realm,
		    sizeof (krb5_data));

		match = krb5_principal_compare(context, ent.principal, princ);

		/* Copy the realm back */
		memcpy(&ent.principal->realm, &tmp_realm, sizeof (krb5_data));

		if (match) {
			/*
			 * A suitable entry was found in the keytab.
			 * Copy its realm
			 */
			ret = krb5int_copy_data_contents_add0(context,
			    &ent.principal->realm, realm);
			if (ret) {
				krb5_kt_free_entry(context, &ent);
				krb5_kt_end_seq_get(context, keytab, &cur);
				return (ret);
			}

			krb5_kt_free_entry(context, &ent);
			break;
		}

		krb5_kt_free_entry(context, &ent);
	}

	ret2 = krb5_kt_end_seq_get(context, keytab, &cur);

	if (ret == KRB5_KT_END) {
		return (KRB5_KT_NOTFOUND);
	}

	return (ret ? ret : ret2);
}
