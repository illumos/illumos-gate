/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <libintl.h>
#include <string.h>
#include <stdlib.h>
#include <libuutil.h>

#include "idtab.h"

#define	IDTAB_GROW	2	/* Table size multiplier on grow */
#define	IDTAB_DEFSIZE	16	/* Starting table size */

void
idtab_create(idtab_t *idt)
{
	(void) memset(idt, 0, sizeof (idtab_t));
}

void
idtab_destroy(idtab_t *idt)
{
	if (idt->id_data) {
		free(idt->id_data);
		idt->id_data = NULL;
		idt->id_nelems = idt->id_size = 0;
	}
}

void
idtab_append(idtab_t *idt, idkey_t id)
{
	size_t size;
	void *data;

	if (idt->id_nelems >= idt->id_size) {
		size = idt->id_size ? idt->id_size * IDTAB_GROW : IDTAB_DEFSIZE;

		if ((data = realloc(idt->id_data,
		    sizeof (idkey_t) * size)) != NULL) {
			idt->id_data = data;
			idt->id_size = size;
		} else {
			uu_die(gettext("Failed to grow table"));
		}
	}

	idt->id_data[idt->id_nelems++] = id;
}

static int
idtab_compare(const void *lhsp, const void *rhsp)
{
	idkey_t lhs = *((idkey_t *)lhsp);
	idkey_t rhs = *((idkey_t *)rhsp);

	if (lhs == rhs)
		return (0);

	return (lhs > rhs ? 1 : -1);
}

void
idtab_sort(idtab_t *idt)
{
	if (idt->id_data) {
		qsort(idt->id_data, idt->id_nelems,
		    sizeof (idkey_t), idtab_compare);
	}
}

int
idtab_search(idtab_t *idt, idkey_t id)
{
	return (bsearch(&id, idt->id_data, idt->id_nelems,
	    sizeof (idkey_t), idtab_compare) != NULL);
}
