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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MAIN_H
#define	_MAIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/scsi/adapters/scsi_vhci.h>
#include <sys/scsi/scsi_types.h>
#include <sys/disp.h>
#include <sys/types.h>
#include <sys/mdb_modapi.h>

#define	FT(var, typ)	(*((typ *)(&(var))))

extern char *client_lb_str[];
extern char *client_flags[];
extern char *mdi_client_states[];
extern char *mdi_pathinfo_states[];
extern char *mdi_pathinfo_ext_states[];
extern char *mdi_phci_flags[];
extern char *vhci_conf_flags[];
extern char *svlun_flags[];

extern char mdipathinfo_cb_str[];
extern char mdiphci_cb_str[];

/* Soft State */
int dump_states(uintptr_t array_vaddr, int verbose,
    struct i_ddi_soft_state *sp);
int i_vhci_states(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv, struct i_ddi_soft_state *sp);
int vhci_states(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
int vhci(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);

/* DCMDS */
int mdiclient(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
int mdipi(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
int mdiphci(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
int mdivhci(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
int vhciguid(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
int vhcilun(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
int mdiprops(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);

/* WALKERS */
/* mdi_pathinfo:pi_client_link */
int mdi_pi_client_link_walk_init(mdb_walk_state_t *);
int mdi_pi_client_link_walk_step(mdb_walk_state_t *);
void mdi_pi_client_link_walk_fini(mdb_walk_state_t *);
/* associated dcmd */
int mdiclient_paths(uintptr_t, uint_t, int, const mdb_arg_t *);

/* mdi_pathinfo:pi_phci_link */
int mdi_pi_phci_link_walk_init(mdb_walk_state_t *);
int mdi_pi_phci_link_walk_step(mdb_walk_state_t *);
void mdi_pi_phci_link_walk_fini(mdb_walk_state_t *);
/* associated dcmd */
int mdiphci_paths(uintptr_t, uint_t, int, const mdb_arg_t *);

/* mdi_phci:ph_next */
extern int mdi_phci_ph_next_walk_init(mdb_walk_state_t *);
extern int mdi_phci_ph_next_walk_step(mdb_walk_state_t *);
extern void mdi_phci_ph_next_walk_fini(mdb_walk_state_t *);
/* associated dcmd */
int mdiphcis(uintptr_t, uint_t, int, const mdb_arg_t *);


/* Utils */
int get_mdbstr(uintptr_t addr, char *name);

void dump_fc_types(uint32_t type);
void dump_flags(unsigned long long flags, char **strings);
void dump_mutex(kmutex_t m, char *name);
void dump_condvar(kcondvar_t c, char *name);
void dump_string(uintptr_t addr, char *name);
void dump_nvpair(uintptr_t addr, nvpair_t nvpair);
void dump_state_str(char *name, uintptr_t addr, char **strings);

int mpxio_walk_cb(uintptr_t addr, const void *data, void *cbdata);
int i_vhcilun(uintptr_t addr, uint_t display_single_guid, char *guid);

#ifdef	__cplusplus
}
#endif

#endif /* _MAIN_H */
