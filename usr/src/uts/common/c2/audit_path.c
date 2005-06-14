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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * @(#)audit_path.c 2.7 92/02/16 SMI; SunOS CMW
 * @(#)audit_path.c 4.2.1.2 91/05/08 SMI; BSM Module
 *
 * This code does the audit path processes. Part of this is still in
 * audit.c and will be moved here when time permits.
 *
 * Note that audit debuging is enabled here. We will turn it off at
 * beta shipment.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/kmem.h>		/* for KM_SLEEP */
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/pathname.h>
#include <sys/acct.h>
#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_record.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>

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

/*
 * increment audit path reference count
 */
void
au_pathhold(struct audit_path *app)
{
	atomic_add_32(&app->audp_ref, 1);
}

/*
 * decrement audit path reference count
 */
void
au_pathrele(struct audit_path *app)
{
	if (atomic_add_32_nv(&app->audp_ref, -1) > 0)
		return;
	kmem_free(app, app->audp_size);
}


int
au_token_size(m)
	token_t *m;
{
	int i;

	if (m == (token_t *)0)
		return (0);

	for (i = 0; m != (token_t *)0; m = m->next_buf)
		i += m->len;
	return (i);
}

token_t *
au_set(cp, size)
	caddr_t  cp;
	uint_t    size;
{
	au_buff_t *head;
	au_buff_t *tail;
	au_buff_t *m;
	uint_t	l;

	head = NULL;
	tail = NULL;	/* only to satisfy lint */

	while (size) {
		m = au_get_buff();
		l = MIN(size, AU_BUFSIZE);
		bcopy(cp, memtod(m, char *), l);
		m->len = l;

		if (head)
			tail->next_buf = m;	/* tail set if head set */
		else
			head = m;
		tail = m;
		size -= l;
		cp += l;
	}

	return (head);
}

token_t *
au_append_token(chain, m)
	token_t *chain;
	token_t *m;
{
	token_t *mbp;

	if (chain == (token_t *)0)
		return (m);

	if (m == (token_t *)0)
		return (chain);

	for (mbp = chain; mbp->next_buf != (token_t *)0; mbp = mbp->next_buf)
		;
	mbp->next_buf = m;
	return (chain);
}


void
audit_fixpath(struct audit_path *app, int len)
{
	int id;		/* index of where we are in destination string */
	int is;		/* index of where we are in source string */
	int cnt;	/* # of levels in audit_path */
	int slashseen;	/* have we seen a slash */
	char *s;	/* start of top-level string */
	char c;

	cnt = app->audp_cnt;
	s = app->audp_sect[cnt - 1];
	is = (app->audp_sect[cnt] - s) - len;
	if (is <= 2)
		is = 0;	/* catch leading // or ./ */
	slashseen = (is > 0);
	for (id = is; ; is++) {
		if ((c = s[is]) == '\0') {
			/* that's all folks, we've reached the end of input */
			if (id > 1 && s[id-1] == '/') {
				/* remove terminating / */
				--id;
			}
			s[id++] = '\0';
			break;
		}
		if (slashseen) {
			/* previous character was a / */
			if (c == '/') {
				/* another slash, ignore it */
				continue;
			}
		} else if (c == '/') {
			/* we see a /, just copy it and try again */
			slashseen = 1;
			s[id++] = c;
			continue;
		}
		if (c == '.') {
			if ((c = s[is+1]) == '\0') {
				/* XXX/. seen */
				if (id > 1)
					id--;
				continue;
			}
			if (c == '/') {
				/* XXX/./ seen */
				is += 1;
				continue;
			}
			if (c == '.' && (s[is+2] == '\0' || s[is+2] == '/')) {
				/* XXX/.. or XXX/../ seen */
				is++;
				if (id == 0 && cnt > 1) {
					char	*s_attr;
					/* .. refers to attributed object */
					app->audp_cnt = --cnt;
					s_attr = s;
					s = app->audp_sect[cnt - 1];
					id = s_attr - s;
					is += id;
					id--;
					slashseen = 0;
					continue;
				}
				/* backup over previous component */
				if (id > 0)
					id--;
				while (id > 0 && s[id - 1] != '/')
					id--;
				continue;
			}
		}
		/* copy component name and terminating /, if any */
		for (;;) {
			c = s[is++];
			if (c == '\0' || c == '/')
				break;
			s[id++] = c;
		}
		/* back up to before terminating '\0' or / */
		slashseen = 0;
		is -= 2;
	}
	/* fill empty attribute directory reference */
	if (id == 1 && cnt > 1) {
		s[0] = '.';
		s[1] = '\0';
		id = 2;
	}
	/* correct end pointer */
	app->audp_sect[cnt] = s + id;
}
