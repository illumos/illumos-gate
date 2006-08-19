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

#ifndef	_MDI_H
#define	_MDI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * dcmds
 */
extern int mdipi(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int mdiprops(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int mdiphci(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int mdivhci(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int mdiclient_paths(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int mdiphci_paths(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int mdiphcis(uintptr_t, uint_t, int, const mdb_arg_t *);

/*
 * walkers
 */
/* mdi_pathinfo:pi_client_link */
extern int mdi_pi_client_link_walk_init(mdb_walk_state_t *);
extern int mdi_pi_client_link_walk_step(mdb_walk_state_t *);
extern void mdi_pi_client_link_walk_fini(mdb_walk_state_t *);

/* mdi_pathinfo:pi_phci_link */
extern int mdi_pi_phci_link_walk_init(mdb_walk_state_t *);
extern int mdi_pi_phci_link_walk_step(mdb_walk_state_t *);
extern void mdi_pi_phci_link_walk_fini(mdb_walk_state_t *);

/* mdi_phci:ph_next */
extern int mdi_phci_ph_next_walk_init(mdb_walk_state_t *);
extern int mdi_phci_ph_next_walk_step(mdb_walk_state_t *);
extern void mdi_phci_ph_next_walk_fini(mdb_walk_state_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDI_H */
