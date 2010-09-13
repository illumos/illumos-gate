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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Core KCF (Kernel Cryptographic Framework). This file implements
 * the crypto (/dev/crypto) supporting functions.
 */

#include <sys/kmem.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>

/* called from CRYPTO_GET_PROVIDER_LIST ioctl */
void
crypto_free_provider_list(crypto_provider_entry_t *array, uint_t count)
{
	if (count ==  0 || array == NULL)
		return;

	kmem_free(array, count * sizeof (crypto_provider_entry_t));
}

/* called from CRYPTO_GET_PROVIDER_MECHANISMS ioctl */
int
crypto_get_provider_mechanisms(crypto_minor_t *cm, crypto_provider_id_t id,
    uint_t *count, crypto_mech_name_t **array)
{
	if (id >= cm->cm_provider_count)
		return (CRYPTO_ARGUMENTS_BAD);

	return (crypto_build_permitted_mech_names(cm->cm_provider_array[id],
	    array, count, KM_SLEEP));
}
