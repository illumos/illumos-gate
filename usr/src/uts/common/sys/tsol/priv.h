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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_TSOL_PRIV_H
#define	_SYS_TSOL_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/priv.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum priv_ftype {
	PRIV_ALLOWED,
	PRIV_FORCED
} priv_ftype_t;

/*
 * Privilege macros.
 */

/*
 * PRIV_ASSERT(a, b) setst.privilege "b" in privilege set "a".
 */
#define	PRIV_ASSERT(a, b) (priv_addset(a, b))

/*
 * PRIV_CLEAR(a,b) clearst.privilege "b" in privilege set "a".
 */
#define	PRIV_CLEAR(a, b) (priv_delset(a, b))

/*
 * PRIV_EQUAL(set_a, set_b) is true if set_a and set_b are identical.
 */
#define	PRIV_EQUAL(a, b) (priv_isequalset(a, b))
#define	PRIV_EMPTY(a) (priv_emptyset(a))
#define	PRIV_FILL(a) (priv_fillset(a))

/*
 * PRIV_ISASSERT tests if privilege 'b' is asserted in privilege set 'a'.
 */
#define	PRIV_ISASSERT(a, b) (priv_ismember(a, b))
#define	PRIV_ISEMPTY(a) (priv_isemptyset(a))
#define	PRIV_ISFULL(a) (priv_isfullset(a))

/*
 * This macro returns 1 if all privileges asserted in privilege set "a"
 * are also asserted in privilege set "b" (i.e. if a is a subset of b)
 */
#define	PRIV_ISSUBSET(a, b) (priv_issubset(a, b))

/*
 * Takes intersection of "a" and "b" and stores in "b".
 */
#define	PRIV_INTERSECT(a, b) (priv_intersect(a, b))

/*
 * Replaces "a" with inverse of "a".
 */
#define	PRIV_INVERSE(a)  (priv_inverse(a))

/*
 * Takes union of "a" and "b" and stores in "b".
 */
#define	PRIV_UNION(a, b) (priv_union(a, b))


#define	PRIV_FILE_UPGRADE_SL	((const char *)"file_upgrade_sl")
#define	PRIV_FILE_DOWNGRADE_SL	((const char *)"file_downgrade_sl")
#
#define	PRIV_PROC_AUDIT_TCB	((const char *)"proc_audit")
#define	PRIV_PROC_AUDIT_APPL	((const char *)"proc_audit")
#
#define	PRIV_SYS_TRANS_LABEL	((const char *)"sys_trans_label")
#define	PRIV_WIN_COLORMAP	((const char *)"win_colormap")
#define	PRIV_WIN_CONFIG		((const char *)"win_config")
#define	PRIV_WIN_DAC_READ	((const char *)"win_dac_read")
#define	PRIV_WIN_DAC_WRITE	((const char *)"win_dac_write")
#define	PRIV_WIN_DGA		((const char *)"win_dga")
#define	PRIV_WIN_DEVICES	((const char *)"win_devices")
#define	PRIV_WIN_DOWNGRADE_SL	((const char *)"win_downgrade_sl")
#define	PRIV_WIN_FONTPATH	((const char *)"win_fontpath")
#define	PRIV_WIN_MAC_READ	((const char *)"win_mac_read")
#define	PRIV_WIN_MAC_WRITE	((const char *)"win_mac_write")
#define	PRIV_WIN_SELECTION	((const char *)"win_selection")
#define	PRIV_WIN_UPGRADE_SL	((const char *)"win_upgrade_sl")

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TSOL_PRIV_H */
