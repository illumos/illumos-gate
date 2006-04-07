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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "k5-int.h"


krb5_enctype
krb5_get_key_enctype(krb5_keyblock *kb)
{
	return (kb->enctype);
}

unsigned int
krb5_get_key_length(krb5_keyblock *kb)
{
	return (kb->length);
}

krb5_octet *
krb5_get_key_data(krb5_keyblock *kb)
{
	return (kb->contents);
}

void
krb5_set_key_enctype(krb5_keyblock *kb, krb5_enctype enctype)
{
	kb->enctype = enctype;
}

void
krb5_set_key_length(krb5_keyblock *kb, unsigned int len)
{
	kb->length = len;
}

void
krb5_set_key_data(krb5_keyblock *kb, krb5_octet *data)
{
	kb->contents = data;
}
