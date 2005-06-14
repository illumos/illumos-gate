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

#ifndef	_TOPO_ENUM_H
#define	_TOPO_ENUM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo_enum.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The structures below describe hashes of enumerators.  Enumerators
 * are chunks of code either built-in to or loaded by the library to
 * search for and enumerate items in the hardware topology.  They
 * currently have just three entry points, initialize and finish entry
 * points te_init() and te_fini() and then the actual enumeration
 * function te_enum().  The te_init() routine will be called exactly
 * once, the first time that libtopo needs to use the enumerator.  If
 * initialization of the enumerator fails, the te_init() function
 * should return a value of TE_INITFAIL, else it should return
 * TE_INITOK.  The te_fini() routine will also be called exactly once,
 * called exactly once, the first time that libtopo needs to use the
 * enumerator.  The te_fini() routine will also be called exactly
 * once, when libtopo shuts down.  The te_enum() routine may be called
 * multiple times to enumerate items at various points in the
 * topology.
 */

struct tenumr_hashent {
	const char *te_nodetype;
	struct tenumr *te;
	struct tenumr_hashent *te_next;
};

struct tenumr_hash {
	struct tenumr_hashent **te_hash;	/* hash bucket array */
	uint_t te_hashlen;			/* size of hash bucket array */
	uint_t te_nelems;			/* # of nodes in the hash */
};

/*
 * Enumerator status, stashed in the status field of the
 * tenumr_prvt_data structure
 */
#define	ENUMR_INITD	0x1
#define	ENUMR_NOTFOUND	0x2
#define	ENUMR_BAD	0x4
#define	ENUMR_INITFAIL	0x8

struct tenumr_prvt_data {
	struct tenumr *(*einit)(void);
	uint_t status;
	void *hdl;
};

/*
 * The enumeration subsystem has its own bookkeeping to do, accomplished
 * in its own init() and fini() routines, prototyped below.
 */
void topo_enum_init(void);
void topo_enum_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_ENUM_H */
