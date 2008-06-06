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
 * catgets.c
 */

#pragma weak _catgets = catgets

#include "lint.h"
#include <sys/types.h>
#include <nl_types.h>
#include <errno.h>
#include "nlspath_checks.h"

char *
catgets(nl_catd catd_st, int set_id, int msg_id, const char *def_str)
{
	int			hi, lo, mid;
	struct	_cat_hdr 	*p;
	struct	_cat_set_hdr	*q;
	struct	_cat_msg_hdr	*r;
	void			*catd;

	if ((catd_st == NULL) || (catd_st == (nl_catd)-1)) {
		/* invalid message catalog descriptor */
		errno = EBADF;
		return ((char *)def_str);
	}

	if ((catd_st->__content == NULL) &&
	    (catd_st->__size == 0) && (catd_st->__trust == 1)) {
		/* special message catalog descriptor for C locale */
		return ((char *)def_str);
	} else if ((catd_st->__content == NULL) || (catd_st->__size == 0)) {
		/* invalid message catalog descriptor */
		errno = EBADF;
		return ((char *)def_str);
	}

	catd = catd_st->__content;
	p = (struct _cat_hdr *)catd_st->__content;
	hi = p->__nsets - 1;
	lo = 0;
	/*
	 * Two while loops will perform binary search.
	 * Outer loop searches the set and inner loop searches
	 * message id
	 */
	while (hi >= lo) {
		mid = (hi + lo) / 2;
		q = (struct _cat_set_hdr *)
		    ((uintptr_t)catd
		    + _CAT_HDR_SIZE
		    + _CAT_SET_HDR_SIZE * mid);
		if (q->__set_no == set_id) {
			lo = q->__first_msg_hdr;
			hi = lo + q->__nmsgs - 1;
			while (hi >= lo) {
				mid = (hi + lo) / 2;
				r = (struct _cat_msg_hdr *)
				    ((uintptr_t)catd
				    + _CAT_HDR_SIZE
				    + p->__msg_hdr_offset
				    + _CAT_MSG_HDR_SIZE * mid);
				if (r->__msg_no == msg_id) {
					char *msg = (char *)catd
					    + _CAT_HDR_SIZE
					    + p->__msg_text_offset
					    + r->__msg_offset;

					if (!catd_st->__trust) {
						int errno_save = errno;
						char *cmsg = check_format(
						    def_str, msg, 0);
						if (cmsg == def_str) {
							/* security */
							return ((char *)
							    def_str);
						} else {
							errno = errno_save;
							return (msg);
						}
					} else {
						return (msg);
					}
				} else if (r->__msg_no < msg_id)
					lo = mid + 1;
				else
					hi = mid - 1;
			} /* while */

			/* In case set number not found */
			errno = ENOMSG;
			return ((char *)def_str);
		} else if (q->__set_no < set_id)
			lo = mid + 1;
		else
			hi = mid - 1;
	} /* while */

	/* In case msg_id not found. */
	errno = ENOMSG;
	return ((char *)def_str);
}
