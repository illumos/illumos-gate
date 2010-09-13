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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDINCLUDE_H
#define	_MDINCLUDE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <mdb/mdb_modapi.h>

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/condvar.h>

#include <sys/lvm/md_crc.h>
#include <sys/lvm/md_basic.h>
#include <sys/lvm/md_names.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_mdiox.h>

#include <sys/lvm/md_mirror.h>
#include <sys/lvm/md_raid.h>
#include <sys/lvm/md_sp.h>
#include <sys/lvm/md_stripe.h>
#include <sys/lvm/md_trans.h>
#include <sys/lvm/md_hotspares.h>

/* these are defined in snarf.c and md.c */
extern md_set_t	mdset[MD_MAXSETS];
extern set_t	md_nsets;
extern unit_t	md_nunits;
extern int	md_verbose;
extern mddb_set_t	set_dbs[MD_MAXSETS];

extern int	snarf_sets(void);
extern int	findset(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDINCLUDE_H */
