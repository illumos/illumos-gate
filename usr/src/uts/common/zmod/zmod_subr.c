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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <zlib.h>

struct zchdr {
	uint_t zch_magic;
	uint_t zch_size;
};

#define	ZCH_MAGIC	0x3cc13cc1

void *
zcalloc(void *opaque __unused, uint_t items, uint_t size)
{
	size_t nbytes = sizeof (struct zchdr) + items * size;
	struct zchdr *z = kobj_zalloc(nbytes, KM_NOWAIT|KM_TMP);

	if (z == NULL)
		return (NULL);

	z->zch_magic = ZCH_MAGIC;
	z->zch_size = nbytes;

	return (z + 1);
}

void
zcfree(void *opaque __unused, void *ptr)
{
	struct zchdr *z = ((struct zchdr *)ptr) - 1;

	if (z->zch_magic != ZCH_MAGIC)
		panic("zcfree region corrupt: hdr=%p ptr=%p", (void *)z, ptr);

	kobj_free(z, z->zch_size);
}
