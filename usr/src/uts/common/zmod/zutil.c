/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>

/*
 * This module is used both during the normal operation of the kernel (i.e.
 * after kmem has been initialized) and during boot (before unix`_start has
 * been called).  kobj_alloc is able to tell the difference between the two
 * cases, and as such must be used instead of kmem_alloc.
 */

void
zmemcpy(uchar_t *dest, const uchar_t *source, uint_t len)
{
	bcopy(source, dest, len);
}

struct zchdr {
	uint_t zch_magic;
	uint_t zch_size;
};

#define	ZCH_MAGIC	0x3cc13cc1

/*ARGSUSED*/
void *
zcalloc(void *opaque, uint_t items, uint_t size)
{
	size_t nbytes = sizeof (struct zchdr) + items * size;
	struct zchdr *z = kobj_zalloc(nbytes, KM_NOWAIT|KM_TMP);

	if (z == NULL)
		return (NULL);

	z->zch_magic = ZCH_MAGIC;
	z->zch_size = nbytes;

	return (z + 1);
}

/*ARGSUSED*/
void
zcfree(void *opaque, void *ptr)
{
	struct zchdr *z = ((struct zchdr *)ptr) - 1;

	if (z->zch_magic != ZCH_MAGIC)
		panic("zcfree region corrupt: hdr=%p ptr=%p", (void *)z, ptr);

	kobj_free(z, z->zch_size);
}
