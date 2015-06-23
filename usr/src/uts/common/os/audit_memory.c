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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <c2/audit.h>
#include <c2/audit_kernel.h>


/* process audit data (pad) cache */
kmem_cache_t *au_pad_cache;

/*
 * increment audit path reference count
 */
void
au_pathhold(struct audit_path *app)
{
	atomic_inc_32(&app->audp_ref);
}

/*
 * decrement audit path reference count
 */
void
au_pathrele(struct audit_path *app)
{
	if (atomic_dec_32_nv(&app->audp_ref) > 0)
		return;
	kmem_free(app, app->audp_size);
}

/*
 * allocate a new auditpath
 *	newsect = increment sections count,
 *	charincr = change in strings storage
 */

struct audit_path *
au_pathdup(const struct audit_path *oldapp, int newsect, int charincr)
{
	struct audit_path	*newapp;
	int	i, alloc_size, oldlen;
	char	*oldcp, *newcp;

	newsect = (newsect != 0);
	oldcp = oldapp->audp_sect[0];
	oldlen = (oldapp->audp_sect[oldapp->audp_cnt] - oldcp);
	alloc_size = sizeof (struct audit_path) +
	    (oldapp->audp_cnt + newsect) * sizeof (char *) +
	    oldlen + charincr;

	newapp = kmem_alloc(alloc_size, KM_SLEEP);
	newapp->audp_ref = 1;
	newapp->audp_size = alloc_size;

	newapp->audp_cnt = oldapp->audp_cnt + newsect;
	newcp = (char *)(&newapp->audp_sect[newapp->audp_cnt + 1]);
	for (i = 0; i <= oldapp->audp_cnt; i++) {
		newapp->audp_sect[i] = newcp +
		    (oldapp->audp_sect[i] - oldcp);
	}
	/*
	 * if this is a new section, set its end
	 * if this is an extended section, reset its end
	 */
	newapp->audp_sect[newapp->audp_cnt] = newcp + oldlen + charincr;
	/* copy all of the old strings */
	bcopy(oldcp, newcp, oldlen);

	return (newapp);
}

/*ARGSUSED1*/
static int
au_pad_const(void *vpad, void *priv, int flags)
{
	p_audit_data_t *pad = vpad;

	mutex_init(&pad->pad_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED1*/
static void
au_pad_destr(void *vpad, void *priv)
{
	p_audit_data_t *pad = vpad;

	mutex_destroy(&pad->pad_lock);
}

void
au_pad_init()
{
	au_pad_cache = kmem_cache_create("audit_proc",
	    sizeof (p_audit_data_t), 0, au_pad_const, au_pad_destr,
	    NULL, NULL, NULL, 0);
}
