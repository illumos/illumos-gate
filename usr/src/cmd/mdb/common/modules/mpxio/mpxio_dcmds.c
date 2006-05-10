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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "main.h"

/*
 * mdiclient()
 *
 * Dump mdi_client_t info and list all paths.
 */
/* ARGSUSED */
int
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
	mdb_printf("ct_failover_flags TEMP_VAR: %8d\n", value.ct_failover_flags)
;
	mdb_printf("ct_failover_status UNUSED: %9d\n", value.ct_failover_status)
;

	return (DCMD_OK);
}

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

/*
 * vhcilun()
 *
 * Get client info given a guid.
 */
/* ARGSUSED */
int
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
int
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

/* ARGSUSED */
int
vhci_states(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (i_vhci_states(addr, flags, argc, argv, NULL));
}
