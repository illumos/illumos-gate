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
#include "mdi.h"

#define	FT(var, typ)	(*((typ *)(&(var))))

/* Utils */
static int get_mdbstr(uintptr_t addr, char *name);
static void dump_flags(unsigned long long flags, char **strings);
static void dump_mutex(kmutex_t m, char *name);
static void dump_condvar(kcondvar_t c, char *name);
static void dump_string(uintptr_t addr, char *name);
static void dump_state_str(char *name, uintptr_t addr, char **strings);

static int mpxio_walk_cb(uintptr_t addr, const void *data, void *cbdata);

static char *client_lb_str[] =
{
	"NONE",
	"RR",
	"LBA",
	NULL
};

static char *mdi_pathinfo_states[] =
{
	"MDI_PATHINFO_STATE_INIT",
	"MDI_PATHINFO_STATE_ONLINE",
	"MDI_PATHINFO_STATE_STANDBY",
	"MDI_PATHINFO_STATE_FAULT",
	"MDI_PATHINFO_STATE_OFFLINE",
	NULL
};

static char *mdi_pathinfo_ext_states[] =
{
	"MDI_PATHINFO_STATE_USER_DISABLE",
	"MDI_PATHINFO_STATE_DRV_DISABLE",
	"MDI_PATHINFO_STATE_DRV_DISABLE_TRANSIENT",
	NULL
};

static char *mdi_phci_flags[] =
{
	"MDI_PHCI_FLAGS_OFFLINE",
	"MDI_PHCI_FLAGS_SUSPEND",
	"MDI_PHCI_FLAGS_POWER_DOWN",
	"MDI_PHCI_FLAGS_DETACH",
	"MDI_PHCI_FLAGS_USER_DISABLE",
	"MDI_PHCI_FLAGS_D_DISABLE",
	"MDI_PHCI_FLAGS_D_DISABLE_TRANS",
	"MDI_PHCI_FLAGS_POWER_TRANSITION",
	NULL
};

static uintptr_t firstaddr = 0;
static char mdipathinfo_cb_str[] = "::print struct mdi_pathinfo";
static char mdiphci_cb_str[] = "::print struct mdi_phci";

/*
 * mdipi()
 *
 * Given a path, dump mdi_pathinfo struct and detailed pi_prop list.
 */
/* ARGSUSED */
int
mdipi(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct mdi_pathinfo	value;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("mdipi: requires an address");
		return (DCMD_ERR);
	}

	if (mdb_vread(&value, sizeof (struct mdi_pathinfo), addr) !=
	    sizeof (struct mdi_pathinfo)) {
		mdb_warn("mdipi: Failed read on %l#r\n", addr);
		return (DCMD_ERR);
	}
	mdb_printf("------------- mdi_pathinfo @ %#lr ----------\n", addr);

	dump_string((uintptr_t)value.pi_addr, "PWWN,LUN (pi_addr)");

	mdb_printf("\n");
	mdb_printf("pi_client: %25l#r::print struct mdi_client\n",
	    value.pi_client);
	mdb_printf("pi_phci: %27l#r::print struct mdi_phci\n", value.pi_phci);
	mdb_printf("pi_pprivate: %23l#r\n", value.pi_pprivate);
	mdb_printf("pi_client_link: %20l#r::print struct mdi_pathinfo\n",
	    value.pi_client_link);
	mdb_printf("pi_phci_link: %22l#r::print struct mdi_pathinfo\n",
	    value.pi_phci_link);
	mdb_printf("pi_prop: %27l#r::print struct nv_list\n", value.pi_prop);

	mdiprops((uintptr_t)value.pi_prop, flags, 0, NULL);

	mdb_printf("\n");
	dump_state_str("Pathinfo State (pi_state)        ",
	    MDI_PI_STATE(&value), mdi_pathinfo_states);
	if (MDI_PI_IS_TRANSIENT(&value)) {
		mdb_printf("Pathinfo State is TRANSIENT\n");
	}
	if (MDI_PI_EXT_STATE(&value)) {
		mdb_printf("      Extended (pi_state)        : ");
		/*
		 * Need to shift right 20 bits to match mdi_pathinfo_ext_states
		 * array.
		 */
		dump_flags((unsigned long long)MDI_PI_EXT_STATE(&value) >> 20,
		    mdi_pathinfo_ext_states);
	}
	dump_state_str("Old Pathinfo State (pi_old_state)",
	    MDI_PI_OLD_STATE(&value), mdi_pathinfo_states);
	if (MDI_PI_OLD_EXT_STATE(&value)) {
		mdb_printf("      Extended (pi_old_state)    : ");
		/*
		 * Need to shift right 20 bits to match mdi_pathinfo_ext_states
		 * array.
		 */
		dump_flags((unsigned long long)MDI_PI_OLD_EXT_STATE(&value)
		>> 20, mdi_pathinfo_ext_states);
	}
	dump_mutex(value.pi_mutex, "per-path mutex (pi_mutex):");
	dump_condvar(value.pi_state_cv, "Path state (pi_state_cv)");

	mdb_printf("\n");
	mdb_printf("pi_ref_cnt: %d\n", value.pi_ref_cnt);
	dump_condvar(value.pi_ref_cv, "pi_ref_cv");

	mdb_printf("\n");
	mdb_printf("pi_kstats: %25l#r::print struct mdi_pi_kstats\n",
	    value.pi_kstats);
	mdb_printf("pi_cprivate UNUSED: %16l#r \n", value.pi_cprivate);

	return (DCMD_OK);
}

/*
 * mdiprops()
 *
 * Given a pi_prop, dump the pi_prop list.
 */
/* ARGSUSED */
int
mdiprops(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("mdiprops: requires an address");
		return (DCMD_ERR);
	}

	mdb_printf("\tnvpairs @ %#lr:\n", addr);
	mdb_pwalk_dcmd("nvpair", "nvpair", argc, argv, addr);
	mdb_printf("\n");

	return (DCMD_OK);
}

/*
 * mdiphci()
 *
 * Given a phci, dump mdi_phci struct.
 */
/* ARGSUSED */
int
mdiphci(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct mdi_phci value;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("mdiphci: requires an address");
		return (DCMD_ERR);
	}

	if (mdb_vread(&value, sizeof (struct mdi_phci), addr) !=
	    sizeof (struct mdi_phci)) {
		mdb_warn("mdiphci: Failed read on %l#r\n", addr);
		return (DCMD_ERR);
	}
	mdb_printf("---------------- mdi_phci @ %#lr ----------\n", addr);

	mdb_printf("ph_next: %27l#r::print struct mdi_phci\n", value.ph_next);
	mdb_printf("ph_prev: %27l#r::print struct mdi_phci\n", value.ph_prev);
	mdb_printf("ph_vhci: %27l#r::print struct mdi_vhci\n", value.ph_vhci);
	mdb_printf("ph_dip: %28l#r::print struct dev_info\n", value.ph_dip);
	mdb_printf("\nph_path_head: %22l#r::print struct mdi_pathinfo\n",
	    value.ph_path_head);
	mdb_printf("ph_path_tail: %22l#r::print struct mdi_pathinfo\n",
	    value.ph_path_tail);
	mdb_printf("ph_path_count: %21d\n", value.ph_path_count);
	mdb_printf("List of paths:\n");
	mdb_pwalk("mdipi_phci_list", (mdb_walk_cb_t)mpxio_walk_cb,
			mdipathinfo_cb_str, (uintptr_t)value.ph_path_head);

	mdb_printf("\n");
	mdb_printf("ph_flags: %26d\n", value.ph_flags);
	if (value.ph_flags) {
		dump_flags((unsigned long long)value.ph_flags, mdi_phci_flags);
	}
	dump_mutex(value.ph_mutex, "per-pHCI mutex (ph_mutex):");
	dump_condvar(value.ph_unstable_cv,
	    "Paths in transient state (ph_unstable_cv)");
	mdb_printf("ph_unstable: %23d\n", value.ph_unstable);

	return (DCMD_OK);
}

/*
 * mdivhci()
 *
 * Given a vhci, dump mdi_vhci struct and list all phcis.
 */
/* ARGSUSED */
int
mdivhci(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct mdi_vhci value;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("mdivhci: requires an address");
		return (DCMD_ERR);
	}

	if (mdb_vread(&value, sizeof (struct mdi_vhci), addr) !=
	    sizeof (struct mdi_vhci)) {
		mdb_warn("mdivhci: Failed read on %l#r\n", addr);
		return (DCMD_ERR);
	}
	mdb_printf("----------------- mdi_vhci @ %#lr ----------\n", addr);

	dump_string((uintptr_t)value.vh_class, "Class name (vh_class)");
	mdb_printf("vh_refcnt: %19d\n", value.vh_refcnt);
	mdb_printf("vh_dip: %28l#r::print struct dev_info\n", value.vh_dip);
	mdb_printf("vh_next: %27l#r::print struct mdi_vhci\n", value.vh_next);
	mdb_printf("vh_prev: %27l#r::print struct mdi_vhci\n", value.vh_prev);
	dump_state_str("Load Balance (vh_lb)", value.vh_lb, client_lb_str);
	mdb_printf("vh_ops: %28l#r::print struct mdi_vhci_ops\n",
	    value.vh_ops);

	dump_mutex(value.vh_phci_mutex, "phci mutex (vh_phci_mutex):");
	mdb_printf("vh_phci_count: %21d\n", value.vh_phci_count);
	mdb_printf("\nvh_phci_head: %22l#r::print struct mdi_phci\n",
	    value.vh_phci_head);
	mdb_printf("vh_phci_tail: %22l#r::print struct mdi_phci\n",
	    value.vh_phci_tail);

	dump_mutex(value.vh_phci_mutex, "client mutex (vh_client_mutex):");
	mdb_printf("vh_client_count: %19d\n", value.vh_client_count);
	mdb_printf("vh_client_table: %19l#r::print struct client_hash\n",
	    value.vh_client_table);

	mdb_printf("List of pHCIs:\n");
	mdb_pwalk("mdiphci_list", (mdb_walk_cb_t)mpxio_walk_cb,
			mdiphci_cb_str, (uintptr_t)value.vh_phci_head);
	mdb_printf("\n");
	return (DCMD_OK);
}

/* mdi_pathinfo client walker */

/* ARGUSED */
int
mdi_pi_client_link_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("Address is required");
		return (WALK_ERR);
	}
	wsp->walk_data = mdb_alloc(sizeof (struct mdi_pathinfo), UM_SLEEP);
	firstaddr = wsp->walk_addr;
	return (WALK_NEXT);
}

/* ARGUSED */
int
mdi_pi_client_link_walk_step(mdb_walk_state_t *wsp)
{
	int		status = 0;
	static int	counts = 0;

	if (firstaddr == wsp->walk_addr && counts != 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (wsp->walk_addr == 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (mdb_vread(wsp->walk_data, sizeof (struct mdi_pathinfo),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read mdi_pathinfo at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)
	    (((struct mdi_pathinfo *)wsp->walk_data)->pi_client_link);
	counts++;
	return (status);
}

/* ARGUSED */
void
mdi_pi_client_link_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct mdi_pathinfo));
}

/*
 * mdiclient_paths()
 *
 * Given a path, walk through mdi_pathinfo client links.
 */
/* ARGUSED */
int
mdiclient_paths(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status;
	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("Address needs to be specified");
		return (DCMD_ERR);
	}
	status =
	    mdb_pwalk_dcmd("mdipi_client_list", "mdipi", argc, argv, addr);
	return (status);
}

/* mdi_pathinfo phci walker */
int
mdi_pi_phci_link_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("Address is required");
		return (WALK_ERR);
	}
	wsp->walk_data = mdb_alloc(sizeof (struct mdi_pathinfo), UM_SLEEP);
	firstaddr = wsp->walk_addr;
	return (WALK_NEXT);
}

int
mdi_pi_phci_link_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	static int	counts = 0;

	if (firstaddr == wsp->walk_addr && counts != 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (wsp->walk_addr == 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (mdb_vread(wsp->walk_data, sizeof (struct mdi_pathinfo),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read mdi_pathinfo at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)
	    (((struct mdi_pathinfo *)wsp->walk_data)->pi_phci_link);
	counts++;
	return (status);
}

void
mdi_pi_phci_link_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct mdi_pathinfo));
}

/*
 * mdiphci_paths()
 *
 * Given a path, walk through mdi_pathinfo phci links.
 */
int
mdiphci_paths(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status;
	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("Address needs to be specified");
		return (DCMD_ERR);
	}
	status =
	    mdb_pwalk_dcmd("mdipi_phci_list", "mdipi", argc, argv, addr);
	return (status);
}

/* mdi_phci walker */
int
mdi_phci_ph_next_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("Address is required");
		return (WALK_ERR);
	}
	wsp->walk_data = mdb_alloc(sizeof (struct mdi_phci), UM_SLEEP);
	firstaddr = wsp->walk_addr;
	return (WALK_NEXT);
}

int
mdi_phci_ph_next_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	static int counts = 0;

	if (firstaddr == wsp->walk_addr && counts != 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (wsp->walk_addr == 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (mdb_vread(wsp->walk_data, sizeof (struct mdi_phci), wsp->walk_addr)
	    == -1) {
		mdb_warn("failed to read mdi_phci at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)
	    (((struct mdi_phci *)wsp->walk_data)->ph_next);
	counts++;
	return (status);
}

void
mdi_phci_ph_next_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct mdi_phci));
}

/*
 * mdiphcis()
 *
 * Given a phci, walk through mdi_phci ph_next links.
 */
int
mdiphcis(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status;
	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("Address needs to be specified");
		return (DCMD_ERR);
	}
	status =
	    mdb_pwalk_dcmd("mdiphci_list", "mdiphci", argc, argv, addr);
	return (status);
}

/*
 * Print the flag name by comparing flags to the mask variable.
 */
static void
dump_flags(unsigned long long flags, char **strings)
{
	int i, linel = 8, first = 1;
	unsigned long long mask = 1;

	for (i = 0; i < 64; i++) {
		if (strings[i] == NULL)
			break;
		if (flags & mask) {
			if (!first) {
				mdb_printf(" | ");
			} else {
				first = 0;
			}
			/* make output pretty */
			linel += strlen(strings[i]) + 3;
			if (linel > 80) {
				mdb_printf("\n\t");
				linel = strlen(strings[i]) + 1 + 8;
			}
			mdb_printf("%s", strings[i]);
		}
		mask <<= 1;
	}
	mdb_printf("\n");
}

static void
dump_mutex(kmutex_t m, char *name)
{
	mdb_printf("%s is%s held\n", name, FT(m, uint64_t) == 0 ? " not" : "");
}

static void
dump_condvar(kcondvar_t c, char *name)
{
	mdb_printf("Threads sleeping on %s = %d\n", name, (int)FT(c, ushort_t));
}

static int
get_mdbstr(uintptr_t addr, char *string_val)
{
	if (mdb_readstr(string_val, MAXNAMELEN, addr) == -1) {
		mdb_warn("Error Reading String from %l#r\n", addr);
		return (1);
	}

	return (0);
}

static void
dump_string(uintptr_t addr, char *name)
{
	char string_val[MAXNAMELEN];

	if (get_mdbstr(addr, string_val)) {
		return;
	}
	mdb_printf("%s: %s (%l#r)\n", name, string_val, addr);
}

static void
dump_state_str(char *name, uintptr_t addr, char **strings)
{
	mdb_printf("%s: %s (%l#r)\n", name, strings[(unsigned long)addr], addr);
}

/* ARGSUSED */
static int
mpxio_walk_cb(uintptr_t addr, const void *data, void *cbdata)
{
	mdb_printf("%t%l#r%s\n", addr, (char *)cbdata);
	return (0);
}
