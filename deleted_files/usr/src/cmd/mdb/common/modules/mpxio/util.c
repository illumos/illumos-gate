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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "main.h"

/*
 * Print the flag name by comparing flags to the mask variable.
 */
void
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

void
dump_mutex(kmutex_t m, char *name)
{
	mdb_printf("%s is%s held\n", name, FT(m, uint64_t) == 0 ? " not" : "");
}

void
dump_condvar(kcondvar_t c, char *name)
{
	mdb_printf("Threads sleeping on %s = %d\n", name, (int)FT(c, ushort_t));
}

/*
 * dump_states()
 *
 * Print the state information for vhci_states().
 */
int
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

int
get_mdbstr(uintptr_t addr, char *string_val)
{
	if (mdb_readstr(string_val, MAXNAMELEN, addr) == -1) {
		mdb_warn("Error Reading String from %l#r\n", addr);
		return (1);
	}

	return (0);
}

void
dump_string(uintptr_t addr, char *name)
{
	char string_val[MAXNAMELEN];

	if (get_mdbstr(addr, string_val)) {
		return;
	}
	mdb_printf("%s: %s (%l#r)\n", name, string_val, addr);
}

void
dump_nvpair(uintptr_t addr, nvpair_t nvpair)
{
	int 	offset = 24; /* size of nvpair_t and offset of name */

	mdb_printf("\tsize: %d\n", nvpair.nvp_size);
	mdb_printf("\tname_sz: %d\n", nvpair.nvp_name_sz);
	mdb_printf("\tnum_elem: %d\n", nvpair.nvp_value_elem);
	mdb_printf("\ttype: %d\n", nvpair.nvp_type);
	dump_string(addr+offset, "nvpair name:");
}

void
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
int
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
		    'v', MDB_OPT_SETBITS, TRUE, &verbose) != argc) {
			return (DCMD_USAGE);
		}
	}

	return (dump_states(adr, verbose, sp));
}

/* ARGSUSED */
int
mpxio_walk_cb(uintptr_t addr, const void *data, void *cbdata)
{
	mdb_printf("%t%l#r%s\n", addr, (char *)cbdata);
	return (0);
}

/*
 * i_vhcilun()
 *
 * Internal routine for vhciguid() to print client info.
 */
int
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
