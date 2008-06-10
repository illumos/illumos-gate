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
 * Copyright 1992,1997-1998,2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AFLT_H
#define	_SYS_AFLT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dditypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Possible values of fault type
 */
#define	AFLT_ECC	1
#define	AFLT_SX		2
#define	AFLT_SX_VRFY	3

/*
 * Arg which is passed to an ECC async handler to specify the error
 * (For fault type AFLT_ECC)
 */
struct ecc_handler_args {
	uint_t e_uncorrectable;	/* true if uncorrectable error */
	uint_t e_addrhi;	/* most significant bits of address */
	uint_t e_addrlo;	/* least significant bits of address */
};


/*
 * Structure to hold state about each registered handler.
 */
struct aflt_cookie {
	int handler_type;
	void *cookie;
};

/*
 * Return values for asynchronous fault support routines
 */

#define	AFLT_SUCCESS		0
#define	AFLT_NOTSUPPORTED	1
#define	AFLT_FAILURE		2

/*
 * Return values for async fault handler
 */

#define	AFLT_HANDLED	0
#define	AFLT_NOTHANDLED	1

#ifdef	__STDC__

extern int aflt_get_iblock_cookie(dev_info_t *, int, ddi_iblock_cookie_t *);
extern int aflt_add_handler(dev_info_t *, int, void **,
    int (*)(void *, void *), void *);
extern int aflt_remove_handler(void *);

#else	/* __STDC__ */

extern int aflt_get_iblock_cookie();
extern int aflt_add_handler();
extern int aflt_remove_handler();

#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AFLT_H */
