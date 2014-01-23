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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <limits.h>
#include <sys/mdb_modapi.h>
#include <sys/sysinfo.h>
#include <sys/sunmdi.h>
#include <sys/list.h>
#include <sys/scsi/scsi.h>

#pragma pack(1)
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_cnfg.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_init.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_ioc.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_sas.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_raid.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_tool.h>
#pragma pack()

#include <sys/scsi/adapters/mpt_sas/mptsas_var.h>
#include <sys/scsi/adapters/mpt_sas/mptsas_hash.h>

struct {
	int	value;
	char	*text;
} devinfo_array[] = {
	{ MPI2_SAS_DEVICE_INFO_SEP,		"SEP" },
	{ MPI2_SAS_DEVICE_INFO_ATAPI_DEVICE,	"ATAPI device" },
	{ MPI2_SAS_DEVICE_INFO_LSI_DEVICE,	"LSI device" },
	{ MPI2_SAS_DEVICE_INFO_DIRECT_ATTACH,	"direct attach" },
	{ MPI2_SAS_DEVICE_INFO_SSP_TARGET,	"SSP tgt" },
	{ MPI2_SAS_DEVICE_INFO_STP_TARGET,	"STP tgt" },
	{ MPI2_SAS_DEVICE_INFO_SMP_TARGET,	"SMP tgt" },
	{ MPI2_SAS_DEVICE_INFO_SATA_DEVICE,	"SATA dev" },
	{ MPI2_SAS_DEVICE_INFO_SSP_INITIATOR,	"SSP init" },
	{ MPI2_SAS_DEVICE_INFO_STP_INITIATOR,	"STP init" },
	{ MPI2_SAS_DEVICE_INFO_SMP_INITIATOR,	"SMP init" },
	{ MPI2_SAS_DEVICE_INFO_SATA_HOST,	"SATA host" }
};

int
construct_path(uintptr_t addr, char *result)
{
	struct	dev_info	d;
	char	devi_node[PATH_MAX];
	char	devi_addr[PATH_MAX];

	if (mdb_vread(&d, sizeof (d), addr) == -1) {
		mdb_warn("couldn't read dev_info");
		return (DCMD_ERR);
	}

	if (d.devi_parent) {
		construct_path((uintptr_t)d.devi_parent, result);
		mdb_readstr(devi_node, sizeof (devi_node),
		    (uintptr_t)d.devi_node_name);
		mdb_readstr(devi_addr, sizeof (devi_addr),
		    (uintptr_t)d.devi_addr);
		mdb_snprintf(result+strlen(result),
		    PATH_MAX-strlen(result),
		    "/%s%s%s", devi_node, (*devi_addr ? "@" : ""),
		    devi_addr);
	}
	return (DCMD_OK);
}

/* ARGSUSED */
int
mdi_info_cb(uintptr_t addr, const void *data, void *cbdata)
{
	struct	mdi_pathinfo	pi;
	struct	mdi_client	c;
	char	dev_path[PATH_MAX];
	char	string[PATH_MAX];
	int	mdi_target = 0, mdi_lun = 0;
	int	target = *(int *)cbdata;

	if (mdb_vread(&pi, sizeof (pi), addr) == -1) {
		mdb_warn("couldn't read mdi_pathinfo");
		return (DCMD_ERR);
	}
	mdb_readstr(string, sizeof (string), (uintptr_t)pi.pi_addr);
	mdi_target = (int)mdb_strtoull(string);
	mdi_lun = (int)mdb_strtoull(strchr(string, ',') + 1);
	if (target != mdi_target)
		return (0);

	if (mdb_vread(&c, sizeof (c), (uintptr_t)pi.pi_client) == -1) {
		mdb_warn("couldn't read mdi_client");
		return (-1);
	}

	*dev_path = NULL;
	if (construct_path((uintptr_t)c.ct_dip, dev_path) != DCMD_OK)
		strcpy(dev_path, "unknown");

	mdb_printf("LUN %d: %s\n", mdi_lun, dev_path);
	mdb_printf("       dip: %p %s path", c.ct_dip,
	    (pi.pi_preferred ? "preferred" : ""));
	switch (pi.pi_state & MDI_PATHINFO_STATE_MASK) {
		case MDI_PATHINFO_STATE_INIT:
			mdb_printf(" initializing");
			break;
		case MDI_PATHINFO_STATE_ONLINE:
			mdb_printf(" online");
			break;
		case MDI_PATHINFO_STATE_STANDBY:
			mdb_printf(" standby");
			break;
		case MDI_PATHINFO_STATE_FAULT:
			mdb_printf(" fault");
			break;
		case MDI_PATHINFO_STATE_OFFLINE:
			mdb_printf(" offline");
			break;
		default:
			mdb_printf(" invalid state");
			break;
	}
	mdb_printf("\n");
	return (0);
}

void
mdi_info(struct mptsas m, int target)
{
	struct	dev_info	d;
	struct	mdi_phci	p;

	if (mdb_vread(&d, sizeof (d), (uintptr_t)m.m_dip) == -1) {
		mdb_warn("couldn't read m_dip");
		return;
	}

	if (MDI_PHCI(&d)) {
		if (mdb_vread(&p, sizeof (p), (uintptr_t)d.devi_mdi_xhci)
		    == -1) {
			mdb_warn("couldn't read m_dip.devi_mdi_xhci");
			return;
		}
		if (p.ph_path_head)
			mdb_pwalk("mdipi_phci_list", (mdb_walk_cb_t)mdi_info_cb,
			    &target, (uintptr_t)p.ph_path_head);
		return;
	}
}

void
print_cdb(mptsas_cmd_t *m)
{
	struct	scsi_pkt	pkt;
	uchar_t	cdb[512];	/* an arbitrarily large number */
	int	j;

	if (mdb_vread(&pkt, sizeof (pkt), (uintptr_t)m->cmd_pkt) == -1) {
		mdb_warn("couldn't read cmd_pkt");
		return;
	}

	/*
	 * We use cmd_cdblen here because 5.10 doesn't
	 * have the cdb length in the pkt
	 */
	if (mdb_vread(&cdb, m->cmd_cdblen, (uintptr_t)pkt.pkt_cdbp) == -1) {
		mdb_warn("couldn't read pkt_cdbp");
		return;
	}

	mdb_printf("%3d,%-3d [ ",
	    pkt.pkt_address.a_target, pkt.pkt_address.a_lun);

	for (j = 0; j < m->cmd_cdblen; j++)
		mdb_printf("%02x ", cdb[j]);

	mdb_printf("]\n");
}


void
display_ports(struct mptsas *mp)
{
	int i;
	mdb_printf("\n");
	mdb_printf("phy number and port mapping table\n");
	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		if (mp->m_phy_info[i].attached_devhdl) {
			mdb_printf("phy %x --> port %x, phymask %x,"
			"attached_devhdl %x\n", i, mp->m_phy_info[i].port_num,
			    mp->m_phy_info[i].phy_mask,
			    mp->m_phy_info[i].attached_devhdl);
		}
	}
	mdb_printf("\n");
}

static uintptr_t
klist_head(list_t *lp, uintptr_t klp)
{
	if ((uintptr_t)lp->list_head.list_next ==
	    klp + offsetof(struct list, list_head))
		return (NULL);

	return ((uintptr_t)(((char *)lp->list_head.list_next) -
	    lp->list_offset));
}

static uintptr_t
klist_next(list_t *lp, uintptr_t klp, void *op)
{
	/* LINTED E_BAD_PTR_CAST_ALIG */
	struct list_node *np = (struct list_node *)(((char *)op) +
	    lp->list_offset);

	if ((uintptr_t)np->list_next == klp + offsetof(struct list, list_head))
		return (NULL);

	return (((uintptr_t)(np->list_next)) - lp->list_offset);
}

static void *
krefhash_first(uintptr_t khp)
{
	refhash_t mh;
	uintptr_t klp;
	uintptr_t kop;
	void *rp;

	mdb_vread(&mh, sizeof (mh), khp);
	klp = klist_head(&mh.rh_objs, khp + offsetof(refhash_t, rh_objs));
	if (klp == 0)
		return (NULL);

	kop = klp - mh.rh_link_off;
	rp = mdb_alloc(mh.rh_obj_size, UM_SLEEP);
	mdb_vread(rp, mh.rh_obj_size, kop);

	return (rp);
}

static void *
krefhash_next(uintptr_t khp, void *op)
{
	refhash_t mh;
	void *prev = op;
	refhash_link_t *lp;
	uintptr_t klp;
	uintptr_t kop;
	refhash_link_t ml;
	void *rp;

	mdb_vread(&mh, sizeof (mh), khp);
	/* LINTED E_BAD_PTR_CAST_ALIG */
	lp = (refhash_link_t *)(((char *)(op)) + mh.rh_link_off);
	ml = *lp;
	while ((klp = klist_next(&mh.rh_objs,
	    khp + offsetof(refhash_t, rh_objs), &ml)) != NULL) {
		mdb_vread(&ml, sizeof (ml), klp);
		if (!(ml.rhl_flags & RHL_F_DEAD))
			break;
	}

	if (klp == 0) {
		mdb_free(prev, mh.rh_obj_size);
		return (NULL);
	}

	kop = klp - mh.rh_link_off;
	rp = mdb_alloc(mh.rh_obj_size, UM_SLEEP);
	mdb_vread(rp, mh.rh_obj_size, kop);

	mdb_free(prev, mh.rh_obj_size);
	return (rp);
}

void
display_targets(struct mptsas *mp)
{
	mptsas_target_t *ptgt;
	mptsas_smp_t *psmp;

	mdb_printf("\n");
	mdb_printf("The SCSI target information\n");
	for (ptgt = (mptsas_target_t *)krefhash_first((uintptr_t)mp->m_targets);
	    ptgt != NULL;
	    ptgt = krefhash_next((uintptr_t)mp->m_targets, ptgt)) {
		mdb_printf("\n");
		mdb_printf("devhdl %x, sasaddress %"PRIx64", phymask %x,"
		    "devinfo %x\n", ptgt->m_devhdl, ptgt->m_addr.mta_wwn,
		    ptgt->m_addr.mta_phymask, ptgt->m_deviceinfo);
		mdb_printf("throttle %x, dr_flag %x, m_t_ncmds %x, "
		    "enclosure %x, slot_num %x\n", ptgt->m_t_throttle,
		    ptgt->m_dr_flag, ptgt->m_t_ncmds, ptgt->m_enclosure,
		    ptgt->m_slot_num);
	}

	mdb_printf("\n");
	mdb_printf("The smp child information\n");
	for (psmp = (mptsas_smp_t *)krefhash_first(
	    (uintptr_t)mp->m_smp_targets);
	    psmp != NULL;
	    psmp = krefhash_next((uintptr_t)mp->m_smp_targets, psmp)) {
		mdb_printf("\n");
		mdb_printf("devhdl %x, sasaddress %"PRIx64", phymask %x \n",
		    psmp->m_devhdl, psmp->m_addr.mta_wwn,
		    psmp->m_addr.mta_phymask);
	}
	mdb_printf("\n");
#if 0
	mdb_printf("targ         wwn      ncmds throttle "
	    "dr_flag  timeout  dups\n");
	mdb_printf("-------------------------------"
	    "--------------------------------\n");
	for (i = 0; i < MPTSAS_MAX_TARGETS; i++) {
		if (s->m_target[i].m_addr.mta_wwn ||
		    s->m_target[i].m_deviceinfo) {
			mdb_printf("%4d ", i);
			if (s->m_target[i].m_addr.mta_wwn)
				mdb_printf("%"PRIx64" ",
				    s->m_target[i].m_addr.mta_wwn);
			mdb_printf("%3d", s->m_target[i].m_t_ncmds);
			switch (s->m_target[i].m_t_throttle) {
				case QFULL_THROTTLE:
					mdb_printf("   QFULL ");
					break;
				case DRAIN_THROTTLE:
					mdb_printf("   DRAIN ");
					break;
				case HOLD_THROTTLE:
					mdb_printf("    HOLD ");
					break;
				case MAX_THROTTLE:
					mdb_printf("     MAX ");
					break;
				case CHOKE_THROTTLE:
					mdb_printf("   CHOKE ");
					break;
				default:
					mdb_printf("%8d ",
					    s->m_target[i].m_t_throttle);
			}
			switch (s->m_target[i].m_dr_flag) {
				case MPTSAS_DR_INACTIVE:
					mdb_printf("  INACTIVE ");
					break;
				case MPTSAS_DR_PRE_OFFLINE_TIMEOUT:
					mdb_printf("   TIMEOUT ");
					break;
				case MPTSAS_DR_PRE_OFFLINE_TIMEOUT_NO_CANCEL:
					mdb_printf("TIMEOUT_NC ");
					break;
				case MPTSAS_DR_OFFLINE_IN_PROGRESS:
					mdb_printf(" OFFLINING ");
					break;
				case MPTSAS_DR_ONLINE_IN_PROGRESS:
					mdb_printf("  ONLINING ");
					break;
				default:
					mdb_printf("   UNKNOWN ");
					break;
				}
			mdb_printf("%3d/%-3d   %d/%d\n",
			    s->m_target[i].m_dr_timeout, m.m_offline_delay,
			    s->m_target[i].m_dr_online_dups,
			    s->m_target[i].m_dr_offline_dups);

			if (verbose) {
				mdb_inc_indent(5);
				if ((s->m_target[i].m_deviceinfo &
				    MPI2_SAS_DEVICE_INFO_MASK_DEVICE_TYPE) ==
				    MPI2_SAS_DEVICE_INFO_FANOUT_EXPANDER)
					mdb_printf("Fanout expander: ");
				if ((s->m_target[i].m_deviceinfo &
				    MPI2_SAS_DEVICE_INFO_MASK_DEVICE_TYPE) ==
				    MPI2_SAS_DEVICE_INFO_EDGE_EXPANDER)
					mdb_printf("Edge expander: ");
				if ((s->m_target[i].m_deviceinfo &
				    MPI2_SAS_DEVICE_INFO_MASK_DEVICE_TYPE) ==
				    MPI2_SAS_DEVICE_INFO_END_DEVICE)
					mdb_printf("End device: ");
				if ((s->m_target[i].m_deviceinfo &
				    MPI2_SAS_DEVICE_INFO_MASK_DEVICE_TYPE) ==
				    MPI2_SAS_DEVICE_INFO_NO_DEVICE)
					mdb_printf("No device ");

				for (loop = 0, comma = 0;
				    loop < (sizeof (devinfo_array) /
				    sizeof (devinfo_array[0])); loop++) {
					if (s->m_target[i].m_deviceinfo &
					    devinfo_array[loop].value) {
						mdb_printf("%s%s",
						    (comma ? ", " : ""),
						    devinfo_array[loop].text);
						comma++;
					}
				}
				mdb_printf("\n");

				if (s->m_target[i].m_tgt_dip) {
					*target_path = 0;
					if (construct_path((uintptr_t)
					    s->m_target[i].m_tgt_dip,
					    target_path)
					    == DCMD_OK)
						mdb_printf("%s\n", target_path);
				}
				mdi_info(m, i);
				mdb_dec_indent(5);
			}
		}
	}
#endif
}

int
display_slotinfo()
{
#if 0
	int	i, nslots;
	struct	mptsas_cmd		c, *q, *slots;
	int	header_output = 0;
	int	rv = DCMD_OK;
	int	slots_in_use = 0;
	int	tcmds = 0;
	int	mismatch = 0;
	int	wq, dq;
	int	ncmds = 0;
	ulong_t	saved_indent;

	nslots = s->m_n_normal;

	slots = mdb_alloc(sizeof (mptsas_cmd_t) * nslots, UM_SLEEP);

	for (i = 0; i < nslots; i++)
		if (s->m_slot[i]) {
			slots_in_use++;
			if (mdb_vread(&slots[i], sizeof (mptsas_cmd_t),
			    (uintptr_t)s->m_slot[i]) == -1) {
				mdb_warn("couldn't read slot");
				s->m_slot[i] = NULL;
			}
			if ((slots[i].cmd_flags & CFLAG_CMDIOC) == 0)
				tcmds++;
			if (i != slots[i].cmd_slot)
				mismatch++;
		}

	for (q = m.m_waitq, wq = 0; q; q = c.cmd_linkp, wq++)
		if (mdb_vread(&c, sizeof (mptsas_cmd_t), (uintptr_t)q) == -1) {
			mdb_warn("couldn't follow m_waitq");
			rv = DCMD_ERR;
			goto exit;
		}

	for (q = m.m_doneq, dq = 0; q; q = c.cmd_linkp, dq++)
		if (mdb_vread(&c, sizeof (mptsas_cmd_t), (uintptr_t)q) == -1) {
			mdb_warn("couldn't follow m_doneq");
			rv = DCMD_ERR;
			goto exit;
		}

	for (i = 0; i < MPTSAS_MAX_TARGETS; i++)
		ncmds += s->m_target[i].m_t_ncmds;

	mdb_printf("\n");
	mdb_printf("   mpt.  slot               mptsas_slots     slot");
	mdb_printf("\n");
	mdb_printf("m_ncmds total"
	    " targ throttle m_t_ncmds targ_tot wq dq");
	mdb_printf("\n");
	mdb_printf("----------------------------------------------------");
	mdb_printf("\n");

	mdb_printf("%7d ", m.m_ncmds);
	mdb_printf("%s", (m.m_ncmds == slots_in_use ? "  " : "!="));
	mdb_printf("%3d               total %3d ", slots_in_use, ncmds);
	mdb_printf("%s", (tcmds == ncmds ? "     " : "   !="));
	mdb_printf("%3d %2d %2d\n", tcmds, wq, dq);

	saved_indent = mdb_dec_indent(0);
	mdb_dec_indent(saved_indent);

	for (i = 0; i < s->m_n_normal; i++)
		if (s->m_slot[i]) {
			if (!header_output) {
				mdb_printf("\n");
				mdb_printf("mptsas_cmd          slot cmd_slot "
				    "cmd_flags cmd_pkt_flags scsi_pkt      "
				    "  targ,lun [ pkt_cdbp ...\n");
				mdb_printf("-------------------------------"
				    "--------------------------------------"
				    "--------------------------------------"
				    "------\n");
				header_output = 1;
			}
			mdb_printf("%16p %4d %s %4d  %8x      %8x %16p ",
			    s->m_slot[i], i,
			    (i == slots[i].cmd_slot?"   ":"BAD"),
			    slots[i].cmd_slot,
			    slots[i].cmd_flags,
			    slots[i].cmd_pkt_flags,
			    slots[i].cmd_pkt);
			(void) print_cdb(&slots[i]);
		}

	/* print the wait queue */

	for (q = m.m_waitq; q; q = c.cmd_linkp) {
		if (q == m.m_waitq)
			mdb_printf("\n");
		if (mdb_vread(&c, sizeof (mptsas_cmd_t), (uintptr_t)q)
		    == -1) {
			mdb_warn("couldn't follow m_waitq");
			rv = DCMD_ERR;
			goto exit;
		}
		mdb_printf("%16p wait n/a %4d  %8x      %8x %16p ",
		    q, c.cmd_slot, c.cmd_flags, c.cmd_pkt_flags,
		    c.cmd_pkt);
		print_cdb(&c);
	}

	/* print the done queue */

	for (q = m.m_doneq; q; q = c.cmd_linkp) {
		if (q == m.m_doneq)
			mdb_printf("\n");
		if (mdb_vread(&c, sizeof (mptsas_cmd_t), (uintptr_t)q)
		    == -1) {
			mdb_warn("couldn't follow m_doneq");
			rv = DCMD_ERR;
			goto exit;
		}
		mdb_printf("%16p done  n/a %4d  %8x      %8x %16p ",
		    q, c.cmd_slot, c.cmd_flags, c.cmd_pkt_flags,
		    c.cmd_pkt);
		print_cdb(&c);
	}

	mdb_inc_indent(saved_indent);

	if (m.m_ncmds != slots_in_use)
		mdb_printf("WARNING: mpt.m_ncmds does not match the number of "
		    "slots in use\n");

	if (tcmds != ncmds)
		mdb_printf("WARNING: the total of m_target[].m_t_ncmds does "
		    "not match the slots in use\n");

	if (mismatch)
		mdb_printf("WARNING: corruption in slot table, "
		    "m_slot[].cmd_slot incorrect\n");

	/* now check for corruptions */

	for (q = m.m_waitq; q; q = c.cmd_linkp) {
		for (i = 0; i < nslots; i++)
			if (s->m_slot[i] == q)
				mdb_printf("WARNING: m_waitq entry"
				    "(mptsas_cmd_t) %p is in m_slot[%i]\n",
				    q, i);

		if (mdb_vread(&c, sizeof (mptsas_cmd_t), (uintptr_t)q) == -1) {
			mdb_warn("couldn't follow m_waitq");
			rv = DCMD_ERR;
			goto exit;
		}
	}

	for (q = m.m_doneq; q; q = c.cmd_linkp) {
		for (i = 0; i < nslots; i++)
			if (s->m_slot[i] == q)
				mdb_printf("WARNING: m_doneq entry "
				"(mptsas_cmd_t) %p is in m_slot[%i]\n", q, i);

		if (mdb_vread(&c, sizeof (mptsas_cmd_t), (uintptr_t)q) == -1) {
			mdb_warn("couldn't follow m_doneq");
			rv = DCMD_ERR;
			goto exit;
		}
		if ((c.cmd_flags & CFLAG_FINISHED) == 0)
			mdb_printf("WARNING: m_doneq entry (mptsas_cmd_t) %p "
			    "should have CFLAG_FINISHED set\n", q);
		if (c.cmd_flags & CFLAG_IN_TRANSPORT)
			mdb_printf("WARNING: m_doneq entry (mptsas_cmd_t) %p "
			    "should not have CFLAG_IN_TRANSPORT set\n", q);
		if (c.cmd_flags & CFLAG_CMDARQ)
			mdb_printf("WARNING: m_doneq entry (mptsas_cmd_t) %p "
			    "should not have CFLAG_CMDARQ set\n", q);
		if (c.cmd_flags & CFLAG_COMPLETED)
			mdb_printf("WARNING: m_doneq entry (mptsas_cmd_t) %p "
			    "should not have CFLAG_COMPLETED set\n", q);
	}

exit:
	mdb_free(slots, sizeof (mptsas_cmd_t) * nslots);
	return (rv);
#endif
	mdb_printf("\n");
	mdb_printf("The slot information is not implemented yet\n");
	return (0);
}

void
display_deviceinfo(struct mptsas *mp)
{
	char	device_path[PATH_MAX];

	*device_path = 0;
	if (construct_path((uintptr_t)mp->m_dip, device_path) != DCMD_OK) {
		strcpy(device_path, "couldn't determine device path");
	}

	mdb_printf("\n");
	mdb_printf("Path in device tree %s\n", device_path);
#if 0
	mdb_printf("base_wwid          phys "
	    "mptid prodid  devid        revid   ssid\n");
	mdb_printf("-----------------------------"
	    "----------------------------------\n");
	mdb_printf("%"PRIx64"     %2d   %3d "
	    "0x%04x 0x%04x ", m.un.m_base_wwid, m.m_num_phys, m.m_mptid,
	    m.m_productid, m.m_devid);
	switch (m.m_devid) {
		case MPTSAS_909:
			mdb_printf("(909)   ");
			break;
		case MPTSAS_929:
			mdb_printf("(929)   ");
			break;
		case MPTSAS_919:
			mdb_printf("(919)   ");
			break;
		case MPTSAS_1030:
			mdb_printf("(1030)  ");
			break;
		case MPTSAS_1064:
			mdb_printf("(1064)  ");
			break;
		case MPTSAS_1068:
			mdb_printf("(1068)  ");
			break;
		case MPTSAS_1064E:
			mdb_printf("(1064E) ");
			break;
		case MPTSAS_1068E:
			mdb_printf("(1068E) ");
			break;
		default:
			mdb_printf("(?????) ");
			break;
	}
	mdb_printf("0x%02x 0x%04x\n", m.m_revid, m.m_ssid);
	mdb_printf("%s\n", device_path);

	for (i = 0; i < MAX_MPI2_PORTS; i++) {
		if (i%4 == 0)
			mdb_printf("\n");

		mdb_printf("%d:", i);

		switch (m.m_port_type[i]) {
			case MPI2_PORTFACTS_PORTTYPE_INACTIVE:
				mdb_printf("inactive     ",
				    m.m_protocol_flags[i]);
				break;
			case MPI2_PORTFACTS_PORTTYPE_SCSI:
				mdb_printf("SCSI (0x%1x)   ",
				    m.m_protocol_flags[i]);
				break;
			case MPI2_PORTFACTS_PORTTYPE_FC:
				mdb_printf("FC (0x%1x)     ",
				    m.m_protocol_flags[i]);
				break;
			case MPI2_PORTFACTS_PORTTYPE_ISCSI:
				mdb_printf("iSCSI (0x%1x)  ",
				    m.m_protocol_flags[i]);
				break;
			case MPI2_PORTFACTS_PORTTYPE_SAS:
				mdb_printf("SAS (0x%1x)    ",
				    m.m_protocol_flags[i]);
				break;
			default:
				mdb_printf("unknown      ");
		}
	}
#endif
	mdb_printf("\n");
}

static int
mptsas_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct mptsas		m;
	struct mptsas_slots	*s;

	int			nslots;
	int			slot_size = 0;
	uint_t			verbose = FALSE;
	uint_t			target_info = FALSE;
	uint_t			slot_info = FALSE;
	uint_t			device_info = FALSE;
	uint_t			port_info = FALSE;
	int			rv = DCMD_OK;
	void			*mptsas_state;

	if (!(flags & DCMD_ADDRSPEC)) {
		mptsas_state = NULL;
		if (mdb_readvar(&mptsas_state, "mptsas_state") == -1) {
			mdb_warn("can't read mptsas_state");
			return (DCMD_ERR);
		}
		if (mdb_pwalk_dcmd("genunix`softstate", "mpt_sas`mptsas", argc,
		    argv, (uintptr_t)mptsas_state) == -1) {
			mdb_warn("mdb_pwalk_dcmd failed");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    's', MDB_OPT_SETBITS, TRUE, &slot_info,
	    'd', MDB_OPT_SETBITS, TRUE, &device_info,
	    't', MDB_OPT_SETBITS, TRUE, &target_info,
	    'p', MDB_OPT_SETBITS, TRUE, &port_info,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);


	if (mdb_vread(&m, sizeof (m), addr) == -1) {
		mdb_warn("couldn't read mpt struct at 0x%p", addr);
		return (DCMD_ERR);
	}

	s = mdb_alloc(sizeof (mptsas_slots_t), UM_SLEEP);

	if (mdb_vread(s, sizeof (mptsas_slots_t),
	    (uintptr_t)m.m_active) == -1) {
		mdb_warn("couldn't read small mptsas_slots_t at 0x%p",
		    m.m_active);
		mdb_free(s, sizeof (mptsas_slots_t));
		return (DCMD_ERR);
	}

	nslots = s->m_n_normal;

	mdb_free(s, sizeof (mptsas_slots_t));

	slot_size = sizeof (mptsas_slots_t) +
	    (sizeof (mptsas_cmd_t *) * (nslots-1));

	s = mdb_alloc(slot_size, UM_SLEEP);

	if (mdb_vread(s, slot_size, (uintptr_t)m.m_active) == -1) {
		mdb_warn("couldn't read large mptsas_slots_t at 0x%p",
		    m.m_active);
		mdb_free(s, slot_size);
		return (DCMD_ERR);
	}

	/* processing completed */

	if (((flags & DCMD_ADDRSPEC) && !(flags & DCMD_LOOP)) ||
	    (flags & DCMD_LOOPFIRST) || slot_info || device_info ||
	    target_info) {
		if ((flags & DCMD_LOOP) && !(flags & DCMD_LOOPFIRST))
			mdb_printf("\n");
		mdb_printf("        mptsas_t inst ncmds suspend  power");
		mdb_printf("\n");
		mdb_printf("========================================="
		    "=======================================");
		mdb_printf("\n");
	}

	mdb_printf("%16p %4d %5d ", addr, m.m_instance, m.m_ncmds);
	mdb_printf("%7d", m.m_suspended);
	switch (m.m_power_level) {
		case PM_LEVEL_D0:
			mdb_printf(" ON=D0 ");
			break;
		case PM_LEVEL_D1:
			mdb_printf("    D1 ");
			break;
		case PM_LEVEL_D2:
			mdb_printf("    D2 ");
			break;
		case PM_LEVEL_D3:
			mdb_printf("OFF=D3 ");
			break;
		default:
			mdb_printf("INVALD ");
	}
	mdb_printf("\n");

	mdb_inc_indent(17);

	if (target_info)
		display_targets(&m);

	if (port_info)
		display_ports(&m);

	if (device_info)
		display_deviceinfo(&m);

	if (slot_info)
		display_slotinfo();

	mdb_dec_indent(17);

	mdb_free(s, slot_size);

	return (rv);
}

void
mptsas_help()
{
	mdb_printf("Prints summary information about each mpt_sas instance, "
	    "including warning\nmessages when slot usage doesn't match "
	    "summary information.\n"
	    "Without the address of a \"struct mptsas\", prints every "
	    "instance.\n\n"
	    "Switches:\n"
	    "  -t   includes information about targets\n"
	    "  -p   includes information about port\n"
	    "  -d   includes information about the hardware\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "mptsas", "?[-tpd]", "print mpt_sas information", mptsas_dcmd,
	    mptsas_help}, { NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
