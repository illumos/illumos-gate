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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * krtld link maps
 */

#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/modctl.h>
#include <sys/types.h>

#pragma weak primaries = kobj_linkmaps	/* backwards compatibility */
struct modctl_list *kobj_linkmaps[] = {
	NULL,
	NULL,
	NULL
};

#define	KOBJ_LM_NENT	(sizeof (kobj_linkmaps) / sizeof (struct modctl *) - 1)

struct modctl_list *
kobj_lm_lookup(int lmid)
{
	if (lmid < 0 || lmid >= KOBJ_LM_NENT)
		return (NULL);

	return (kobj_linkmaps[lmid]);
}

void
kobj_lm_append(int lmid, struct modctl *modp)
{
	struct modctl_list **lpp, *lp;

	if (lmid < 0 || lmid >= KOBJ_LM_NENT)
		return;

	lpp = &kobj_linkmaps[lmid];

	lp = kobj_zalloc(sizeof (struct modctl_list), KM_WAIT);
	lp->modl_modp = modp;

	if (*lpp == NULL) {
		*lpp = lp;
	} else {
		struct modctl_list *last;

		for (last = *lpp; last->modl_next != NULL;
		    last = last->modl_next)
			/* */;

		last->modl_next = lp;
	}
}

void
kobj_lm_dump(int lmid)
{
	struct modctl_list *lp;

	for (lp = kobj_lm_lookup(lmid); lp; lp = lp->modl_next) {
		struct module *mp = lp->modl_modp->mod_mp;

		_kobj_printf(ops, "module %s: ", mp->filename);
		_kobj_printf(ops, "text at [0x%p, ", mp->text);
		_kobj_printf(ops, "0x%lx] ", (uintptr_t)mp->text +
		    mp->text_size - 1);
		_kobj_printf(ops, "data at 0x%p\n", mp->data);
	}
}
