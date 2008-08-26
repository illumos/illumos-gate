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

#ifndef _LIBDLADM_IMPL_H
#define	_LIBDLADM_IMPL_H

#include <libdladm.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXLINELEN		1024
#define	BUFLEN(lim, ptr)	(((lim) > (ptr)) ? ((lim) - (ptr)) : 0)

typedef struct val_desc {
	char		*vd_name;
	uintptr_t	vd_val;
} val_desc_t;

#define	VALCNT(vals)	(sizeof ((vals)) / sizeof (val_desc_t))

extern dladm_status_t	dladm_errno2status(int);
extern dladm_status_t   i_dladm_rw_db(const char *, mode_t,
			    dladm_status_t (*)(void *, FILE *, FILE *),
			    void *, boolean_t);

/*
 * Link attributes persisted by dlmgmtd.
 */
/*
 * Set for VLANs only
 */
#define	FVLANID		"vid"		/* uint64_t */
#define	FLINKOVER	"linkover"	/* uint64_t */

/*
 * Set for AGGRs only
 */
#define	FKEY		"key"		/* uint64_t */
#define	FNPORTS		"nports"	/* uint64_t */
#define	FPORTS		"portnames"	/* string */
#define	FPOLICY		"policy"	/* uint64_t */
#define	FFIXMACADDR	"fix_macaddr"	/* boolean_t */
#define	FMACADDR	"macaddr"	/* string */
#define	FFORCE		"force"		/* boolean_t */
#define	FLACPMODE	"lacp_mode"	/* uint64_t */
#define	FLACPTIMER	"lacp_timer"	/* uint64_t */

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_IMPL_H */
