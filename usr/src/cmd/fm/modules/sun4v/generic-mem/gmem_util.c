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

#include <gmem.h>
#include <gmem_util.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

int
gmem_set_errno(int err)
{
	errno = err;
	return (-1);
}

void *
gmem_buf_read(fmd_hdl_t *hdl, fmd_case_t *cp, const char *bufname, size_t bufsz)
{
	void *buf;
	size_t sz;

	if ((sz = fmd_buf_size(hdl, cp, bufname)) == 0) {
		(void) gmem_set_errno(ENOENT);
		return (NULL);
	} else if (sz != bufsz) {
		(void) gmem_set_errno(EINVAL);
		return (NULL);
	}

	buf = fmd_hdl_alloc(hdl, bufsz, FMD_SLEEP);
	fmd_buf_read(hdl, cp, bufname, buf, bufsz);

	return (buf);
}

void
gmem_vbufname(char *buf, size_t bufsz, const char *fmt, va_list ap)
{
	char *c;

	(void) vsnprintf(buf, bufsz, fmt, ap);

	for (c = buf; *c != '\0'; c++) {
		if (*c == ' ' || *c == '/' || *c == ':')
			*c = '_';
	}
}

void
gmem_bufname(char *buf, size_t bufsz, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	gmem_vbufname(buf, bufsz, fmt, ap);
	va_end(ap);
}

void
gmem_list_append(gmem_list_t *lp, void *new)
{
	gmem_list_t *p = lp->l_prev;	/* p = tail list element */
	gmem_list_t *q = new;		/* q = new list element */

	lp->l_prev = q;
	q->l_prev = p;
	q->l_next = NULL;

	if (p != NULL)
		p->l_next = q;
	else
		lp->l_next = q;
}

void
gmem_list_prepend(gmem_list_t *lp, void *new)
{
	gmem_list_t *p = new;		/* p = new list element */
	gmem_list_t *q = lp->l_next;	/* q = head list element */

	lp->l_next = p;
	p->l_prev = NULL;
	p->l_next = q;

	if (q != NULL)
		q->l_prev = p;
	else
		lp->l_prev = p;
}

void
gmem_list_insert_before(gmem_list_t *lp, void *before_me, void *new)
{
	gmem_list_t *p = before_me;
	gmem_list_t *q = new;

	if (p == NULL || p->l_prev == NULL) {
		gmem_list_prepend(lp, new);
		return;
	}

	q->l_prev = p->l_prev;
	q->l_next = p;
	p->l_prev = q;
	q->l_prev->l_next = q;
}

void
gmem_list_insert_after(gmem_list_t *lp, void *after_me, void *new)
{
	gmem_list_t *p = after_me;
	gmem_list_t *q = new;

	if (p == NULL || p->l_next == NULL) {
		gmem_list_append(lp, new);
		return;
	}

	q->l_next = p->l_next;
	q->l_prev = p;
	p->l_next = q;
	q->l_next->l_prev = q;
}

void
gmem_list_delete(gmem_list_t *lp, void *existing)
{
	gmem_list_t *p = existing;

	if (p->l_prev != NULL)
		p->l_prev->l_next = p->l_next;
	else
		lp->l_next = p->l_next;

	if (p->l_next != NULL)
		p->l_next->l_prev = p->l_prev;
	else
		lp->l_prev = p->l_prev;
}
