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

#ifndef _HC_CANON_H
#define	_HC_CANON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <topo_parse.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Array declaring all known canonical HC scheme component names.
 * Hopefully this file will one day be generated from the event registry
 * automagically.
 */
static const char *Hc_canon[] = {
	"CMP",
	"centerplane",
	"chip",
	"chip-select",
	"cpu",
	"dimm",
	"hostbridge",
	"interconnect",
	"ioboard",
	"memory-controller",
	"motherboard",
	"pcibus",
	"pcidev",
	"pciexbus",
	"pciexdev",
	"pciexfn",
	"pciexrc",
	"pcifn",
	"systemboard"
};

static int Hc_ncanon = sizeof (Hc_canon) / sizeof (const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _HC_CANON_H */
