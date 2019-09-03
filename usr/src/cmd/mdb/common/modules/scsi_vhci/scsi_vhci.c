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
 *
 * Copyright 2019 Joyent, Inc.
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

#define	FT(var, typ)	(*((typ *)(&(var))))

static int dump_states(uintptr_t array_vaddr, int verbose,
    struct i_ddi_soft_state *sp);
static int i_vhci_states(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv, struct i_ddi_soft_state *sp);
static int vhci_states(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);

static int mdiclient(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
static int vhciguid(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
static int vhcilun(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
static int i_vhcilun(uintptr_t addr, uint_t display_single_guid, char *guid);

/* Utils */
static int get_mdbstr(uintptr_t addr, char *name);
static void dump_mutex(kmutex_t m, char *name);
static void dump_condvar(kcondvar_t c, char *name);
static void dump_string(uintptr_t addr, char *name);
static void dump_flags(unsigned long long flags, char **strings);
static void dump_state_str(char *name, uintptr_t addr, char **strings);

static int mpxio_walk_cb(uintptr_t addr, const void *data, void *cbdata);

static const mdb_dcmd_t dcmds[] = {
	{ "vhci_states", "[ -v ]", "dump all the vhci state pointers",
		vhci_states },
	{ "vhciguid", NULL, "list all clients or given a guid, list one client",
		vhciguid },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

static char *client_lb_str[] =
{
	"NONE",
	"RR",
	"LBA",
	NULL
};

static char *mdi_client_states[] =
{
	NULL,
	"OPTIMAL",
	"DEGRADED",
	"FAILED",
	NULL
};

static char *client_flags[] =
{
	"MDI_CLIENT_FLAGS_OFFLINE",
	"MDI_CLIENT_FLAGS_SUSPEND",
	"MDI_CLIENT_FLAGS_POWER_DOWN",
	"MDI_CLIENT_FLAGS_DETACH",
	"MDI_CLIENT_FLAGS_FAILOVER",
	"MDI_CLIENT_FLAGS_REPORT_DEV",
	"MDI_CLIENT_FLAGS_PATH_FREE_IN_PROGRESS",
	"MDI_CLIENT_FLAGS_ASYNC_FREE",
	"MDI_CLIENT_FLAGS_DEV_NOT_SUPPORTED",
	NULL
};

static char *vhci_conf_flags[] =
{
	"VHCI_CONF_FLAGS_AUTO_FAILBACK",
	NULL
};

static char *svlun_flags[] =
{
	"VLUN_TASK_D_ALIVE_FLG",
	"VLUN_RESERVE_ACTIVE_FLG",
	"VLUN_QUIESCED_FLG",
	NULL
};

static char mdipathinfo_cb_str[] = "::print struct mdi_pathinfo";

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

/*
 * mdiclient()
 *
 * Dump mdi_client_t info and list all paths.
 */
/* ARGSUSED */
static int
mdiclient(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct mdi_client	value;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("mdiclient: requires an address");
		return (DCMD_ERR);
	}

	if (mdb_vread(&value, sizeof (struct mdi_client), addr)
	    != sizeof (struct mdi_client)) {
		mdb_warn("mdiclient: Failed read on %l#r\n", addr);
		return (DCMD_ERR);
	}
	mdb_printf("----------------- mdi_client @ %#lr ----------\n", addr);
	dump_string((uintptr_t)value.ct_guid, "GUID (ct_guid)");
	dump_string((uintptr_t)value.ct_drvname, "Driver Name (ct_drvname)");
	dump_state_str("Load Balance (ct_lb)", value.ct_lb, client_lb_str);
	mdb_printf("\n");
	mdb_printf("ct_hnext: %26l#r::print struct mdi_client\n",
	    value.ct_hnext);
	mdb_printf("ct_hprev: %26l#r::print struct mdi_client\n",
	    value.ct_hprev);
	mdb_printf("ct_dip: %28l#r::print struct dev_info\n", value.ct_dip);
	mdb_printf("ct_vhci: %27l#r::print struct mdi_vhci\n", value.ct_vhci);
	mdb_printf("ct_cprivate: %23l#r\n", value.ct_cprivate);
	mdb_printf("\nct_path_head: %22l#r::print struct mdi_pathinfo\n",
	    value.ct_path_head);
	mdb_printf("ct_path_tail: %22l#r::print struct mdi_pathinfo\n",
	    value.ct_path_tail);
	mdb_printf("ct_path_last: %22l#r::print struct mdi_pathfinfo\n",
	    value.ct_path_last);
	mdb_printf("ct_path_count: %21d\n", value.ct_path_count);
	mdb_printf("List of paths:\n");
	mdb_pwalk("mdipi_client_list", (mdb_walk_cb_t)mpxio_walk_cb,
	    mdipathinfo_cb_str, (uintptr_t)value.ct_path_head);

	mdb_printf("\n");
	dump_state_str("Client State (ct_state)", value.ct_state,
	    mdi_client_states);
	dump_mutex(value.ct_mutex, "per-client mutex (ct_mutex):");
	mdb_printf("ct_flags: %26d\n", value.ct_flags);
	if (value.ct_flags) {
		dump_flags((unsigned long long)value.ct_flags, client_flags);
	}
	mdb_printf("ct_unstable: %23d\n", value.ct_unstable);
	dump_condvar(value.ct_unstable_cv, "ct_unstable_cv");
	dump_condvar(value.ct_failover_cv, "ct_failover_cv");

	mdb_printf("\n");
	mdb_printf("ct_failover_flags TEMP_VAR: %8d\n",
	    value.ct_failover_flags);
	mdb_printf("ct_failover_status UNUSED: %9d\n",
	    value.ct_failover_status);

	return (DCMD_OK);
}

/*
 * vhcilun()
 *
 * Get client info given a guid.
 */
/* ARGSUSED */
static int
vhcilun(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("sv_lun: requires an address");
		return (DCMD_ERR);
	}

	return (i_vhcilun(addr, 0 /* display_single_guid */, 0));
}

/*
 * vhciguid()
 *
 * List all the clients.
 */
/* ARGSUSED */
static int
vhciguid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{

	struct i_ddi_soft_state ss;
	int i;

	mdi_vhci_t	*mdi_vhci_value;
	mdi_client_t	*mdi_client_value;
	struct client_hash	*ct_hash_val;
	struct client_hash	*ct_hash_table_val;

	int		len = strlen(MDI_HCI_CLASS_SCSI);
	int		mdi_vhci_len = sizeof (*mdi_vhci_value);
	int		mdi_client_len = sizeof (*mdi_client_value);
	int		ct_hash_len = sizeof (*ct_hash_val);

	int		ct_hash_count = 0;
	char		*class;
	int		found = 0;
	uintptr_t	buf;
	uintptr_t	temp;



	if (flags & DCMD_ADDRSPEC)
		mdb_warn("This command doesn't use an address\n");

	if (i_vhci_states(0, 0, 0, 0, &ss) != DCMD_OK)
		return (DCMD_ERR);

	if (mdb_readvar(&buf, "mdi_vhci_head") == -1) {
		mdb_warn("mdi driver variable mdi_vhci_head not found.\n");
		mdb_warn("Is the driver loaded ?\n");
		return (DCMD_ERR);
	}
	mdb_printf("----------------- mdi_vhci_head @ %#lr ----------\n", buf);
	mdi_vhci_value = (mdi_vhci_t *)mdb_alloc(mdi_vhci_len, UM_SLEEP|UM_GC);
	if (mdb_vread(mdi_vhci_value, mdi_vhci_len, buf) != mdi_vhci_len) {
		mdb_warn("vhciguid: Failed read on %l#r\n", mdi_vhci_value);
		mdb_free(mdi_vhci_value, mdi_vhci_len);
		return (DCMD_ERR);
	}
	temp = (uintptr_t)mdi_vhci_value->vh_class;
	class = (char *)mdb_alloc(len, UM_SLEEP|UM_GC);
	if (mdb_vread(class, strlen(MDI_HCI_CLASS_SCSI), temp)
	    != strlen(MDI_HCI_CLASS_SCSI)) {
		mdb_warn("vhciguid: Failed read of class %l#r\n",
		    mdi_vhci_value);
		mdb_free(mdi_vhci_value, mdi_vhci_len);
		mdb_free(class, len);
		return (DCMD_ERR);
	}
	class[len] = 0;
	mdb_printf("----------------- class @ %s----------\n", class);
	while (class) {
		if (strcmp(class, MDI_HCI_CLASS_SCSI) == 0) {
			found = 1;
			break;
		}
		if (mdi_vhci_value->vh_next == NULL) {
			break;
		}
		temp = (uintptr_t)mdi_vhci_value->vh_next;
		if (mdb_vread(mdi_vhci_value, mdi_vhci_len, temp)
		    != mdi_vhci_len) {
			mdb_warn("vhciguid: Failed read on vh->next %l#r\n",
			    mdi_vhci_value);
			break;
		}
		temp = (uintptr_t)mdi_vhci_value->vh_class;
		if (mdb_vread(class, strlen(MDI_HCI_CLASS_SCSI), temp) !=
		    strlen(MDI_HCI_CLASS_SCSI)) {
			mdb_warn("vhciguid: Failed read on vh->next %l#r\n",
			    mdi_vhci_value);
			break;
		}
		class[len] = 0;
	}

	if (found == 0) {
		mdb_warn("vhciguid: No scsi_vhci class found");
		mdb_free(mdi_vhci_value, mdi_vhci_len);
		mdb_free(class, len);
		return (DCMD_ERR);
	}
	mdb_printf("----- Number of devices found %d ----------\n",
	    mdi_vhci_value->vh_client_count);
	for (i = 0; i < CLIENT_HASH_TABLE_SIZE; i++) {
		ct_hash_table_val = &mdi_vhci_value->vh_client_table[i];
		if (ct_hash_table_val == NULL)
			continue;

		/* Read client_hash structure */
		ct_hash_val = (struct client_hash *)mdb_alloc(ct_hash_len,
		    UM_SLEEP|UM_GC);
		temp = (uintptr_t)ct_hash_table_val;
		if (mdb_vread(ct_hash_val, ct_hash_len, temp) != ct_hash_len) {
			mdb_warn("Failed read on hash %l#r\n",
			    ct_hash_val);
			break;
		}
		mdb_printf("----hash[%d] %l#r: devices mapped  = %d --\n",
		    i, ct_hash_table_val, ct_hash_val->ct_hash_count);
		if (ct_hash_val->ct_hash_count == 0) {
			continue;
		}

		ct_hash_count = ct_hash_val->ct_hash_count;

		/* Read mdi_client structures */
		mdi_client_value = (mdi_client_t *)mdb_alloc(mdi_client_len,
		    UM_SLEEP|UM_GC);
		temp = (uintptr_t)ct_hash_val->ct_hash_head;
		if (mdb_vread(mdi_client_value, mdi_client_len, temp)
		    != mdi_client_len) {
			mdb_warn("Failed read on client %l#r\n",
			    mdi_client_value);
			break;
		}
		mdb_printf("mdi_client %l#r %l#r ------\n",
		    mdi_client_value, mdi_client_value->ct_vprivate);
		vhcilun((uintptr_t)mdi_client_value->ct_vprivate,
		    DCMD_ADDRSPEC, 0, 0);

		while (--ct_hash_count) {
			temp = (uintptr_t)mdi_client_value->ct_hnext;
			if (mdb_vread(mdi_client_value, mdi_client_len,
			    temp) != mdi_client_len) {
				mdb_warn("Failed read on client %l#r\n",
				    mdi_client_value);
				break;
			}
			vhcilun((uintptr_t)mdi_client_value->ct_vprivate,
			    DCMD_ADDRSPEC, 0, 0);
		}
	}
	mdb_printf("----------done----------\n");

	return (DCMD_OK);
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

/* ARGSUSED */
static int
vhci_states(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (i_vhci_states(addr, flags, argc, argv, NULL));
}

/*
 * dump_states()
 *
 * Print the state information for vhci_states().
 */
static int
dump_states(uintptr_t array_vaddr, int verbose, struct i_ddi_soft_state *sp)
{
	int i;
	int array_size;
	struct i_ddi_soft_state *ss;
	struct scsi_vhci vhci;

	if (sp == NULL) {
		ss = (struct i_ddi_soft_state *)mdb_alloc(sizeof (*ss),
		    UM_SLEEP|UM_GC);
	} else {
		ss = sp;
	}
	if (mdb_vread(ss, sizeof (*ss), array_vaddr) != sizeof (*ss)) {
		mdb_warn("Cannot read softstate struct (Invalid pointer?).\n");
		return (DCMD_ERR);
	}
	array_size = ss->n_items * (sizeof (void *));
	array_vaddr = (uintptr_t)ss->array;
	ss->array = mdb_alloc(array_size, UM_SLEEP|UM_GC);
	if (mdb_vread(ss->array, array_size, array_vaddr) != array_size) {
		mdb_warn("Corrupted softstate struct.\n");
		return (DCMD_ERR);
	}
	if (sp != NULL)
		return (DCMD_OK);
	if (verbose) {
	/*
	 * ss->size is of type size_t which is 4 bytes and 8 bytes
	 * on 32-bit and 64-bit systems respectively.
	 */
#ifdef _LP64
		mdb_printf("Softstate size is %lld(0x%llx) bytes.\n\n",
		    ss->size, ss->size);
#else
		mdb_printf("Softstate size is %ld(0x%lx) bytes.\n\n",
		    ss->size, ss->size);
#endif
		mdb_printf("state pointer\t\t\t\t\tinstance\n");
		mdb_printf("=============\t\t\t\t\t========\n");
	}
	for (i = 0; i < ss->n_items; i++) {
		if (ss->array[i] == 0)
			continue;

		if (mdb_vread(&vhci, sizeof (vhci), (uintptr_t)ss->array[i])
		    != sizeof (vhci)) {
			mdb_warn("Corrupted softstate struct.\n");
			return (DCMD_ERR);
		}
		if (verbose) {
			mdb_printf("%l#r::print struct scsi_vhci\t\t   %d\n",
			    ss->array[i], i);
			mdb_printf("\nvhci_conf_flags: %d\n",
			    vhci.vhci_conf_flags);
			if (vhci.vhci_conf_flags) {
				mdb_printf("\t");
				dump_flags((unsigned long long)
				    vhci.vhci_conf_flags, vhci_conf_flags);
			}
		} else {
			mdb_printf("%l#r\n", ss->array[i]);
		}
	}
	return (DCMD_OK);
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
dump_state_str(char *name, uintptr_t addr, char **strings)
{
	mdb_printf("%s: %s (%l#r)\n", name, strings[(unsigned long)addr], addr);
}

/* VHCI UTILS */

/*
 * i_vhci_states()
 *
 * Internal routine for vhci_states() to check for -v arg and then
 * print state info.
 */
/* ARGSUSED */
static int
i_vhci_states(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    struct i_ddi_soft_state *sp)
{
	uintptr_t adr;
	int verbose = 0;

	if (mdb_readvar(&adr, "vhci_softstate") == -1) {
		mdb_warn("vhci driver variable vhci_softstate not found.\n");
		mdb_warn("Is the driver loaded ?\n");
		return (DCMD_ERR);
	}
	if (sp == NULL) {
		if (mdb_getopts(argc, argv,
		    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc) {
			return (DCMD_USAGE);
		}
	}

	return (dump_states(adr, verbose, sp));
}

/*
 * i_vhcilun()
 *
 * Internal routine for vhciguid() to print client info.
 */
static int
i_vhcilun(uintptr_t addr, uint_t display_single_guid, char *guid)
{

	scsi_vhci_lun_t		value;
	struct dev_info		dev_info_value;
	char			string_val[MAXNAMELEN];
	int			found = 0;
	struct mdi_client	ct_value;
	uintptr_t		temp_addr;

	do {
		if (mdb_vread(&value, sizeof (scsi_vhci_lun_t), addr) !=
		    sizeof (scsi_vhci_lun_t)) {
			mdb_warn("sv_lun: Failed read on %l#r", addr);
			return (DCMD_ERR);
		}

		temp_addr = addr;
		addr = (uintptr_t)value.svl_hash_next;

		if (!get_mdbstr((uintptr_t)value.svl_lun_wwn, string_val)) {
			if (display_single_guid) {
				if (strcmp(string_val, guid) == 0) {
					found = 1;
				} else continue;
			}
		}

		mdb_printf("%t%l#r::print struct scsi_vhci_lun", temp_addr);

		if (mdb_vread(&dev_info_value, sizeof (struct dev_info),
		    (uintptr_t)value.svl_dip) != sizeof (struct dev_info)) {
			mdb_warn("svl_dip: Failed read on %l#r",
			    value.svl_dip);
			return (DCMD_ERR);
		}

		mdb_printf("\n%tGUID: %s\n", string_val);
		if (value.svl_active_pclass != NULL) {
			if (!get_mdbstr((uintptr_t)value.svl_active_pclass,
			    string_val)) {
				mdb_printf("%tActv_cl: %s", string_val);
			}
		} else {
			mdb_printf("   No active pclass");
		}
		if (display_single_guid) {
			mdb_printf(" (%l#r)", value.svl_active_pclass);
		}

		mdb_printf("\n%t%l#r::print struct mdi_client",
		    dev_info_value.devi_mdi_client);

		if (value.svl_flags) {
			mdb_printf("\t");
			dump_flags((unsigned long long)value.svl_flags,
			    svlun_flags);
		} else {
			mdb_printf("\n");
		}

		if (found) {
			mdiclient((uintptr_t)dev_info_value.devi_mdi_client,
			    DCMD_ADDRSPEC, 0, 0);
		} else {
			if (mdb_vread(&ct_value, sizeof (struct mdi_client),
			    (uintptr_t)dev_info_value.devi_mdi_client) !=
			    sizeof (struct mdi_client)) {
				mdb_warn("mdiclient: Failed read on %l#r",
				    dev_info_value.devi_mdi_client);
				return (DCMD_ERR);
			}
			if (ct_value.ct_flags) {
				mdb_printf("\t");
				dump_flags((unsigned long long)
				    ct_value.ct_flags, client_flags);
			}
			mdb_printf("%t");
			dump_state_str("LB", ct_value.ct_lb, client_lb_str);
			mdb_printf("\n");
		}
	} while (addr && !found);
	return (DCMD_OK);
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

static void
dump_string(uintptr_t addr, char *name)
{
	char string_val[MAXNAMELEN];

	if (get_mdbstr(addr, string_val)) {
		return;
	}
	mdb_printf("%s: %s (%l#r)\n", name, string_val, addr);
}

/* ARGSUSED */
static int
mpxio_walk_cb(uintptr_t addr, const void *data, void *cbdata)
{
	mdb_printf("%t%l#r%s\n", addr, (char *)cbdata);
	return (0);
}
