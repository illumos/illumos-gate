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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/nvpair.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/cyclic.h>
#include <sys/errorq.h>
#include <sys/stat.h>
#include <sys/cpuvar.h>
#include <sys/mc_intel.h>
#include <sys/mc.h>
#include <sys/fm/protocol.h>
#include "nb_log.h"
#include "nb5000.h"

nvlist_t *inb_mc_nvl;
krwlock_t inb_mc_lock;

char *inb_mc_snapshot;
uint_t nb_config_gen;
uint_t inb_mc_snapshotgen;
size_t inb_mc_snapshotsz;
static dev_info_t *inb_dip;
int nb_allow_detach = 0;
int nb_no_smbios;

static uint64_t
rank_to_base(uint8_t branch, uint8_t rank, uint8_t *interleave, uint64_t *limit,
    uint64_t *hole_base, uint64_t *hole_size, uint8_t *wayp,
    uint8_t *branch_interleavep)
{
	uint8_t i, j;
	uint64_t base = 0;
	uint64_t lt = 0;
	uint64_t h = 0;
	uint64_t hs = 0;
	uint8_t il = 1;
	uint8_t way = 0;
	uint8_t branch_interleave = 0;

	for (i = 0; i < NB_MEM_RANK_SELECT; i++) {
		for (j = 0; j < NB_RANKS_IN_SELECT; j++) {
			if (nb_ranks[branch][i].rank[j] == rank) {
				base = nb_ranks[branch][i].base;
				lt = nb_ranks[branch][i].limit;
				il = nb_ranks[branch][i].interleave;
				h = nb_ranks[branch][i].hole_base;
				hs = nb_ranks[branch][i].hole_size;
				way = j;
				branch_interleave =
				    nb_ranks[branch][i].branch_interleave;
				i = NB_MEM_RANK_SELECT;
				break;
			}
		}
	}
	if (lt == 0) {
		for (i = 0; lt == 0 && i < NB_MEM_BRANCH_SELECT; i++) {
			if (nb_banks[i].way[branch] &&
			    base >= nb_banks[i].base &&
			    base < nb_banks[i].base + nb_banks[i].limit) {
				lt = nb_banks[i].limit;
				break;
			}
		}
	}
	*interleave = il;
	*limit = lt;
	*hole_base = h;
	*hole_size = hs;
	*wayp = way;
	*branch_interleavep = branch_interleave;
	return (base);
}

/*ARGSUSED*/
void
inb_rank(nvlist_t *newdimm, nb_dimm_t *nb_dimm, uint8_t channel, uint32_t dimm)
{
	nvlist_t **newrank;
	int i;

	newrank = kmem_zalloc(sizeof (nvlist_t *) * nb_dimm->nranks, KM_SLEEP);
	for (i = 0; i < nb_dimm->nranks; i++) {
		uint64_t dimm_base;
		uint64_t limit;
		uint8_t interleave;
		uint8_t way;
		uint8_t branch_interleave;
		uint64_t hole_base;
		uint64_t hole_size;

		dimm_base = rank_to_base(channel/nb_channels_per_branch,
		    nb_dimm->start_rank + i, &interleave,
		    &limit, &hole_base, &hole_size, &way, &branch_interleave);
		(void) nvlist_alloc(&newrank[i], NV_UNIQUE_NAME, KM_SLEEP);

		(void) nvlist_add_uint64(newrank[i], "dimm-rank-base",
		    dimm_base);
		if (hole_size) {
			(void) nvlist_add_uint64(newrank[i], "dimm-hole",
			    hole_base);
			(void) nvlist_add_uint64(newrank[i], "dimm-hole-size",
			    hole_size);
		}
		(void) nvlist_add_uint64(newrank[i], "dimm-rank-limit",
		    limit);
		if (interleave > 1) {
			(void) nvlist_add_uint32(newrank[i],
			    "dimm-rank-interleave", (uint32_t)interleave);
			(void) nvlist_add_uint32(newrank[i],
			    "dimm-rank-interleave-way", (uint32_t)way);
			if (branch_interleave) {
				(void) nvlist_add_uint32(newrank[i],
				    "dimm-rank-interleave-branch", (uint32_t)1);
			}
		}
	}
	(void) nvlist_add_nvlist_array(newdimm, MCINTEL_NVLIST_RANKS, newrank,
	    nb_dimm->nranks);
	for (i = 0; i < nb_dimm->nranks; i++)
		nvlist_free(newrank[i]);
	kmem_free(newrank, sizeof (nvlist_t *) * nb_dimm->nranks);
}

nvlist_t *
inb_dimm(nb_dimm_t *nb_dimm, uint8_t channel, uint32_t dimm)
{
	nvlist_t *newdimm;
	uint8_t t;
	char sbuf[65];

	(void) nvlist_alloc(&newdimm, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_uint32(newdimm, "dimm-number", dimm);

	if (nb_dimm->dimm_size >= 1024*1024*1024) {
		(void) snprintf(sbuf, sizeof (sbuf), "%dG",
		    (int)(nb_dimm->dimm_size / (1024*1024*1024)));
	} else {
		(void) snprintf(sbuf, sizeof (sbuf), "%dM",
		    (int)(nb_dimm->dimm_size / (1024*1024)));
	}
	(void) nvlist_add_string(newdimm, "dimm-size", sbuf);
	(void) nvlist_add_uint64(newdimm, "size", nb_dimm->dimm_size);
	(void) nvlist_add_uint32(newdimm, "nbanks", (uint32_t)nb_dimm->nbanks);
	(void) nvlist_add_uint32(newdimm, "ncolumn",
	    (uint32_t)nb_dimm->ncolumn);
	(void) nvlist_add_uint32(newdimm, "nrow", (uint32_t)nb_dimm->nrow);
	(void) nvlist_add_uint32(newdimm, "width", (uint32_t)nb_dimm->width);
	(void) nvlist_add_int32(newdimm, MCINTEL_NVLIST_1ST_RANK,
	    (int32_t)nb_dimm->start_rank);
	(void) nvlist_add_uint32(newdimm, "ranks", (uint32_t)nb_dimm->nranks);
	inb_rank(newdimm, nb_dimm, channel, dimm);
	(void) nvlist_add_uint32(newdimm, "manufacture-id",
	    (uint32_t)nb_dimm->manufacture_id);
	(void) nvlist_add_uint32(newdimm, "manufacture-location",
	    (uint32_t)nb_dimm->manufacture_location);
	(void) nvlist_add_uint32(newdimm, "manufacture-week",
	    (uint32_t)nb_dimm->manufacture_week);
	(void) nvlist_add_uint32(newdimm, "manufacture-year",
	    (uint32_t)nb_dimm->manufacture_year + 2000);
	/* create Sun Serial number from SPD data */
	(void) snprintf(sbuf, sizeof (sbuf), "%04x%02x%02x%02x%08x",
	    (uint32_t)nb_dimm->manufacture_id & 0x7fff,
	    (uint32_t)nb_dimm->manufacture_location,
	    (uint32_t)nb_dimm->manufacture_year,
	    (uint32_t)nb_dimm->manufacture_week,
	    nb_dimm->serial_number);
	(void) nvlist_add_string(newdimm, FM_FMRI_HC_SERIAL_ID, sbuf);
	if (nb_dimm->part_number && nb_dimm->part_number[0]) {
		t = sizeof (nb_dimm->part_number);
		(void) strncpy(sbuf, nb_dimm->part_number, t);
		sbuf[t] = 0;
		(void) nvlist_add_string(newdimm, FM_FMRI_HC_PART, sbuf);
	}
	if (nb_dimm->revision && nb_dimm->revision[0]) {
		t = sizeof (nb_dimm->revision);
		(void) strncpy(sbuf, nb_dimm->revision, t);
		sbuf[t] = 0;
		(void) nvlist_add_string(newdimm, FM_FMRI_HC_REVISION, sbuf);
	}
	t = sizeof (nb_dimm->label);
	(void) strncpy(sbuf, nb_dimm->label, t);
	sbuf[t] = 0;
	(void) nvlist_add_string(newdimm, FM_FAULT_FRU_LABEL, sbuf);
	return (newdimm);
}

static void
inb_dimmlist(nvlist_t *nvl)
{
	nvlist_t **dimmlist;
	nvlist_t **newchannel;
	int nchannels = nb_number_memory_controllers * nb_channels_per_branch;
	int nd;
	uint8_t i, j;
	nb_dimm_t **dimmpp;
	nb_dimm_t *dimmp;

	dimmlist =  kmem_zalloc(sizeof (nvlist_t *) * nb_dimms_per_channel,
	    KM_SLEEP);
	newchannel = kmem_zalloc(sizeof (nvlist_t *) * nchannels, KM_SLEEP);
	dimmpp = nb_dimms;
	for (i = 0; i < nchannels; i++) {
		(void) nvlist_alloc(&newchannel[i], NV_UNIQUE_NAME, KM_SLEEP);
		nd = 0;
		for (j = 0; j < nb_dimms_per_channel; j++) {
			dimmp = *dimmpp;
			if (dimmp != NULL) {
				dimmlist[nd] = inb_dimm(dimmp, i, (uint32_t)j);
				nd++;
			}
			dimmpp++;
		}
		if (nd) {
			(void) nvlist_add_nvlist_array(newchannel[i],
			    "memory-dimms", dimmlist, nd);
			for (j = 0; j < nd; j++)
				nvlist_free(dimmlist[j]);
		}
	}
	(void) nvlist_add_nvlist_array(nvl, MCINTEL_NVLIST_MC, newchannel,
	    nchannels);
	for (i = 0; i < nchannels; i++)
		nvlist_free(newchannel[i]);
	kmem_free(dimmlist, sizeof (nvlist_t *) * nb_dimms_per_channel);
	kmem_free(newchannel, sizeof (nvlist_t *) * nchannels);
}

static char *
inb_mc_name()
{
	char *mc;

	switch (nb_chipset) {
	case INTEL_NB_7300:
		mc = "Intel 7300";
		break;
	case INTEL_NB_5400:
		mc = "Intel 5400";
		break;
	case INTEL_NB_5400A:
		mc = "Intel 5400A";
		break;
	case INTEL_NB_5400B:
		mc = "Intel 5400B";
		break;
	case INTEL_NB_5100:
		mc = "Intel 5100";
		break;
	case INTEL_NB_5000P:
		mc = "Intel 5000P";
		break;
	case INTEL_NB_5000V:
		mc = "Intel 5000V";
		break;
	case INTEL_NB_5000X:
		mc = "Intel 5000X";
		break;
	case INTEL_NB_5000Z:
		mc = "Intel 5000Z";
		break;
	default:
		mc = "Intel 5000";
		break;
	}
	return (mc);
}

static void
inb_create_nvl()
{
	nvlist_t *nvl;

	(void) nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_uint8(nvl, MCINTEL_NVLIST_VERSTR,
	    MCINTEL_NVLIST_VERS);
	(void) nvlist_add_string(nvl, "memory-controller", inb_mc_name());
	if (nb_chipset == INTEL_NB_5100)
		(void) nvlist_add_uint8(nvl, MCINTEL_NVLIST_NMEM,
		    (uint8_t)nb_number_memory_controllers);
	inb_dimmlist(nvl);

	nvlist_free(inb_mc_nvl);
	inb_mc_nvl = nvl;
}

static void
inb_mc_snapshot_destroy()
{
	ASSERT(RW_LOCK_HELD(&inb_mc_lock));

	if (inb_mc_snapshot == NULL)
		return;

	kmem_free(inb_mc_snapshot, inb_mc_snapshotsz);
	inb_mc_snapshot = NULL;
	inb_mc_snapshotsz = 0;
	inb_mc_snapshotgen++;
}

static int
inb_mc_snapshot_update()
{
	ASSERT(RW_LOCK_HELD(&inb_mc_lock));

	if (inb_mc_snapshot != NULL)
		return (0);

	if (nvlist_pack(inb_mc_nvl, &inb_mc_snapshot, &inb_mc_snapshotsz,
	    NV_ENCODE_XDR, KM_SLEEP) != 0)
		return (-1);

	return (0);
}

/*ARGSUSED*/
static int
inb_mc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int rc = 0;
	mc_snapshot_info_t mcs;

	if (cmd != MC_IOC_SNAPSHOT_INFO && cmd != MC_IOC_SNAPSHOT)
		return (EINVAL);

	rw_enter(&inb_mc_lock, RW_READER);
	if (inb_mc_nvl == NULL || inb_mc_snapshotgen != nb_config_gen) {
		if (!rw_tryupgrade(&inb_mc_lock)) {
			rw_exit(&inb_mc_lock);
			return (EAGAIN);
		}
		if (inb_mc_nvl)
			inb_mc_snapshot_destroy();
		inb_create_nvl();
		nb_config_gen = inb_mc_snapshotgen;
		(void) inb_mc_snapshot_update();
	}
	switch (cmd) {
	case MC_IOC_SNAPSHOT_INFO:
		mcs.mcs_size = (uint32_t)inb_mc_snapshotsz;
		mcs.mcs_gen = inb_mc_snapshotgen;

		if (ddi_copyout(&mcs, (void *)arg, sizeof (mc_snapshot_info_t),
		    mode) < 0)
			rc = EFAULT;
		break;
	case MC_IOC_SNAPSHOT:
		if (ddi_copyout(inb_mc_snapshot, (void *)arg, inb_mc_snapshotsz,
		    mode) < 0)
			rc = EFAULT;
		break;
	}
	rw_exit(&inb_mc_lock);
	return (rc);
}

/*ARGSUSED*/
static int
inb_mc_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	if ((infocmd != DDI_INFO_DEVT2DEVINFO &&
	    infocmd != DDI_INFO_DEVT2INSTANCE) || inb_dip == NULL) {
		*result = NULL;
		return (DDI_FAILURE);
	}
	if (infocmd == DDI_INFO_DEVT2DEVINFO)
		*result = inb_dip;
	else
		*result = (void *)(uintptr_t)ddi_get_instance(inb_dip);
	return (0);
}

static int
inb_mc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd == DDI_RESUME) {
		nb_dev_reinit();
		return (DDI_SUCCESS);
	}
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if (inb_dip == NULL) {
		inb_dip = dip;
		nb_no_smbios = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "no-smbios", 0);
		nb_pci_cfg_setup(dip);
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
		    inb_mc_name());
		if (nb_dev_init()) {
			nb_pci_cfg_free();
			inb_dip = NULL;
			return (DDI_FAILURE);
		}
		if (ddi_create_minor_node(dip, "mc-intel", S_IFCHR, 0,
		    "ddi_mem_ctrl", 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "failed to create minor node"
			    " for memory controller\n");
		}
		cmi_hdl_walk(inb_mc_register, NULL, NULL, NULL);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
inb_mc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (nb_allow_detach && cmd == DDI_DETACH && dip == inb_dip) {
		rw_enter(&inb_mc_lock, RW_WRITER);
		inb_mc_snapshot_destroy();
		rw_exit(&inb_mc_lock);
		inb_dip = NULL;
		return (DDI_SUCCESS);
	} else if (cmd == DDI_SUSPEND || cmd == DDI_PM_SUSPEND) {
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
inb_mc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	rw_enter(&inb_mc_lock, RW_READER);
	if (getminor(*devp) >= 1) {
		rw_exit(&inb_mc_lock);
		return (EINVAL);
	}
	rw_exit(&inb_mc_lock);

	return (0);
}

/*ARGSUSED*/
static int
inb_mc_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}


static struct cb_ops inb_mc_cb_ops = {
	inb_mc_open,
	inb_mc_close,
	nodev,		/* not a block driver */
	nodev,		/* no print routine */
	nodev,		/* no dump routine */
	nodev,		/* no read routine */
	nodev,		/* no write routine */
	inb_mc_ioctl,
	nodev,		/* no devmap routine */
	nodev,		/* no mmap routine */
	nodev,		/* no segmap routine */
	nochpoll,	/* no chpoll routine */
	ddi_prop_op,
	0,		/* not a STREAMS driver */
	D_NEW | D_MP,	/* safe for multi-thread/multi-processor */
};

static struct dev_ops inb_mc_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	inb_mc_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	inb_mc_attach,		/* devo_attach */
	inb_mc_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&inb_mc_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Intel 5000 Memory Controller Hub Module",
	&inb_mc_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int err;

	err = nb_init();
	if (err == 0 && (err = mod_install(&modlinkage)) == 0)
		rw_init(&inb_mc_lock, NULL, RW_DRIVER, NULL);

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) == 0) {
		nb_unload();
		rw_destroy(&inb_mc_lock);
	}

	return (err);
}
