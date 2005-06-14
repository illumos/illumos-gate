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

#ifndef	_LIBTOPO_ENUM_H
#define	_LIBTOPO_ENUM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * System Topology Modeling Library Enumerator interfaces
 *
 * Note: The contents of this file are private to the implementation of the
 * Solaris system and FMD subsystem and are subject to change at any time
 * without notice.  Applications and drivers using these interfaces will fail
 * to run on future releases.  These interfaces should not be used for any
 * purpose until they are publicly documented for use outside of Sun.
 *
 * Library libtopo is intended as a simple, extensible, library for
 * capturing hardware topology information.  System topology is
 * abstracted in a tree of "topology nodes" or "tnode_t"s.  The
 * topology tree is constructed by combining static topology
 * information from ".topo" files with instance information collected
 * by enumerators.  This include file contains definitions
 * specifically for use by these enumerators.
 */

/*
 * Standard properties placed on enumerated components
 */
#define	PLATASRU	"PLAT-ASRU"
#define	PLATFRU		"PLAT-FRU"

#define	ATTACHP "ATTACHMENT-POINT"
#define	ATTACHD "DRIVER-ATTACHED"
#define	DRIVER	"DRIVER"
#define	LABEL	"LABEL"
#define	SCAN	"SCAN"
#define	DEV	"DEV"
#define	PKG	"PKG"
#define	ON	"ON"

#define	TPROP_FALSE	"false"
#define	TPROP_TRUE	"true"

/*
 * The structure below describes an enumerator.  Enumerators are
 * chunks of code either built-in to or loaded by the library to
 * search for and enumerate items in the hardware topology.  They
 * currently have just three entry points, initialize and finish entry
 * points te_init() and te_fini() and then the actual enumeration
 * function te_enum().  The te_init() routine will be called exactly
 * once, the first time that libtopo needs to use the enumerator.  If
 * initialization of the enumerator fails, the te_init() function
 * should return a value of TE_INITFAIL, else it should return
 * TE_INITOK.  The te_fini() routine will also be called exactly once,
 * when libtopo shuts down.  The te_enum() routine may be called
 * multiple times to request enumeration at various points in the
 * topology.
 *
 * An enumerator is required to have an _enum_init() function that
 * libtopo will call when the enumerator is initially loaded.  The
 * function is expected to return a pointer to a struct tenumr.
 */

#define	TE_INITOK	0
#define	TE_INITFAIL	1

struct tenumr {
	/*
	 * te_private should be initialized to NULL by a registering
	 * enumerator and not manipulated by the enumerator in any
	 * other manner.
	 */
	void *te_private;
	int (*te_init)(void);
	void (*te_fini)(void);
	void (*te_enum)(tnode_t *);
};

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBTOPO_ENUM_H */
