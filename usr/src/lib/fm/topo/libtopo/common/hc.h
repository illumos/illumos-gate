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

#ifndef	_HC_H
#define	_HC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	HC_VERSION	1
#define	HC		"hc"

/*
 * Array declaring all known canonical HC scheme component names.
 * Hopefully this file will one day be generated from the event registry
 * automagically.
 */
typedef struct hcc {
	const char *hcc_name;
	topo_stability_t hcc_stability;
} hcc_t;

extern int hc_init(topo_mod_t *, topo_version_t);	/* see hc.c */
extern void hc_fini(topo_mod_t *);			/* see hc.c */

#ifdef	__cplusplus
}
#endif

#endif	/* _HC_H */
