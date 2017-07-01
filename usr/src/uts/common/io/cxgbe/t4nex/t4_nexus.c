/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/pci.h>
#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/queue.h>

#include "version.h"
#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "firmware/t4_fw.h"
#include "firmware/t4_cfg.h"
#include "firmware/t5_fw.h"
#include "firmware/t5_cfg.h"
#include "firmware/t6_fw.h"
#include "firmware/t6_cfg.h"
#include "t4_l2t.h"

static int t4_cb_open(dev_t *devp, int flag, int otyp, cred_t *credp);
static int t4_cb_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int t4_cb_ioctl(dev_t dev, int cmd, intptr_t d, int mode, cred_t *credp,
    int *rp);
struct cb_ops t4_cb_ops = {
	.cb_open =		t4_cb_open,
	.cb_close =		t4_cb_close,
	.cb_strategy =		nodev,
	.cb_print = 		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_ioctl =		t4_cb_ioctl,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_flag =		D_MP,
	.cb_rev =		CB_REV,
	.cb_aread =		nodev,
	.cb_awrite =		nodev
};

static int t4_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op,
    void *arg, void *result);
static int t4_bus_config(dev_info_t *dip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **cdipp);
static int t4_bus_unconfig(dev_info_t *dip, uint_t flags,
    ddi_bus_config_op_t op, void *arg);
struct bus_ops t4_bus_ops = {
	.busops_rev =		BUSO_REV,
	.bus_ctl =		t4_bus_ctl,
	.bus_prop_op =		ddi_bus_prop_op,
	.bus_config =		t4_bus_config,
	.bus_unconfig =		t4_bus_unconfig,
};

static int t4_devo_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **rp);
static int t4_devo_probe(dev_info_t *dip);
static int t4_devo_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int t4_devo_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int t4_devo_quiesce(dev_info_t *dip);
struct dev_ops t4_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_getinfo =		t4_devo_getinfo,
	.devo_identify =	nulldev,
	.devo_probe =		t4_devo_probe,
	.devo_attach =		t4_devo_attach,
	.devo_detach =		t4_devo_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&t4_cb_ops,
	.devo_bus_ops =		&t4_bus_ops,
	.devo_quiesce =		&t4_devo_quiesce,
};

static struct modldrv modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"Chelsio T4 nexus " DRV_VERSION,
	.drv_dev_ops =		&t4_dev_ops
};

static struct modlinkage modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{&modldrv, NULL},
};

void *t4_list;

struct intrs_and_queues {
	int intr_type;		/* DDI_INTR_TYPE_* */
	int nirq;		/* Number of vectors */
	int intr_fwd;		/* Interrupts forwarded */
	int ntxq10g;		/* # of NIC txq's for each 10G port */
	int nrxq10g;		/* # of NIC rxq's for each 10G port */
	int ntxq1g;		/* # of NIC txq's for each 1G port */
	int nrxq1g;		/* # of NIC rxq's for each 1G port */
#ifdef TCP_OFFLOAD_ENABLE
	int nofldtxq10g;	/* # of TOE txq's for each 10G port */
	int nofldrxq10g;	/* # of TOE rxq's for each 10G port */
	int nofldtxq1g;		/* # of TOE txq's for each 1G port */
	int nofldrxq1g;		/* # of TOE rxq's for each 1G port */
#endif
};

struct fw_info fi[3];

static int cpl_not_handled(struct sge_iq *iq, const struct rss_header *rss,
    mblk_t *m);
static int fw_msg_not_handled(struct adapter *, const __be64 *);
int t4_register_cpl_handler(struct adapter *sc, int opcode, cpl_handler_t h);
static unsigned int getpf(struct adapter *sc);
static int prep_firmware(struct adapter *sc);
static int upload_config_file(struct adapter *sc, uint32_t *mt, uint32_t *ma);
static int partition_resources(struct adapter *sc);
static int adap__pre_init_tweaks(struct adapter *sc);
static int get_params__pre_init(struct adapter *sc);
static int get_params__post_init(struct adapter *sc);
static int set_params__post_init(struct adapter *);
static void setup_memwin(struct adapter *sc);
static int validate_mt_off_len(struct adapter *, int, uint32_t, int,
    uint32_t *);
void memwin_info(struct adapter *, int, uint32_t *, uint32_t *);
uint32_t position_memwin(struct adapter *, int, uint32_t);
static int prop_lookup_int_array(struct adapter *sc, char *name, int *data,
    uint_t count);
static int prop_lookup_int_array(struct adapter *sc, char *name, int *data,
    uint_t count);
static int init_driver_props(struct adapter *sc, struct driver_properties *p);
static int remove_extra_props(struct adapter *sc, int n10g, int n1g);
static int cfg_itype_and_nqueues(struct adapter *sc, int n10g, int n1g,
    struct intrs_and_queues *iaq);
static int add_child_node(struct adapter *sc, int idx);
static int remove_child_node(struct adapter *sc, int idx);
static kstat_t *setup_kstats(struct adapter *sc);
static kstat_t *setup_wc_kstats(struct adapter *);
static int update_wc_kstats(kstat_t *, int);
#ifdef TCP_OFFLOAD_ENABLE
static int toe_capability(struct port_info *pi, int enable);
static int activate_uld(struct adapter *sc, int id, struct uld_softc *usc);
static int deactivate_uld(struct uld_softc *usc);
#endif
static kmutex_t t4_adapter_list_lock;
static SLIST_HEAD(, adapter) t4_adapter_list;
#ifdef TCP_OFFLOAD_ENABLE
static kmutex_t t4_uld_list_lock;
static SLIST_HEAD(, uld_info) t4_uld_list;
#endif

int
_init(void)
{
	int rc;

	rc = ddi_soft_state_init(&t4_list, sizeof (struct adapter), 0);
	if (rc != 0)
		return (rc);

	rc = mod_install(&modlinkage);
	if (rc != 0)
		ddi_soft_state_fini(&t4_list);

	mutex_init(&t4_adapter_list_lock, NULL, MUTEX_DRIVER, NULL);
	SLIST_INIT(&t4_adapter_list);

#ifdef TCP_OFFLOAD_ENABLE
	mutex_init(&t4_uld_list_lock, NULL, MUTEX_DRIVER, NULL);
	SLIST_INIT(&t4_uld_list);
#endif

	return (rc);
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&modlinkage);
	if (rc != 0)
		return (rc);

	ddi_soft_state_fini(&t4_list);
	return (0);
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&modlinkage, mi));
}

/* ARGSUSED */
static int
t4_devo_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **rp)
{
	struct adapter *sc;
	minor_t minor;

	minor = getminor((dev_t)arg);	/* same as instance# in our case */

	if (cmd == DDI_INFO_DEVT2DEVINFO) {
		sc = ddi_get_soft_state(t4_list, minor);
		if (sc == NULL)
			return (DDI_FAILURE);

		ASSERT(sc->dev == (dev_t)arg);
		*rp = (void *)sc->dip;
	} else if (cmd == DDI_INFO_DEVT2INSTANCE)
		*rp = (void *) (unsigned long) minor;
	else
		ASSERT(0);

	return (DDI_SUCCESS);
}

static int
t4_devo_probe(dev_info_t *dip)
{
	int rc, id, *reg;
	uint_t n, pf;

	id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", 0xffff);
	if (id == 0xffff)
		return (DDI_PROBE_DONTCARE);

	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &reg, &n);
	if (rc != DDI_SUCCESS)
		return (DDI_PROBE_DONTCARE);

	pf = PCI_REG_FUNC_G(reg[0]);
	ddi_prop_free(reg);

	/* Prevent driver attachment on any PF except 0 on the FPGA */
	if (id == 0xa000 && pf != 0)
		return (DDI_PROBE_FAILURE);

	return (DDI_PROBE_DONTCARE);
}

static int
t4_devo_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct adapter *sc = NULL;
	struct sge *s;
	int i, instance, rc = DDI_SUCCESS, rqidx, tqidx, q;
	int irq = 0, nxg, n100g, n40g, n25g, n10g, n1g;
#ifdef TCP_OFFLOAD_ENABLE
	int ofld_rqidx, ofld_tqidx;
#endif
	char name[16];
	struct driver_properties *prp;
	struct intrs_and_queues iaq;
	ddi_device_acc_attr_t da = {
		.devacc_attr_version = DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder = DDI_UNORDERED_OK_ACC
	};
	ddi_device_acc_attr_t da1 = {
		.devacc_attr_version = DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder = DDI_MERGING_OK_ACC
	};
 
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Allocate space for soft state.
	 */
	instance = ddi_get_instance(dip);
	rc = ddi_soft_state_zalloc(t4_list, instance);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to allocate soft state: %d", rc);
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(t4_list, instance);
	sc->dip = dip;
	sc->dev = makedevice(ddi_driver_major(dip), instance);
	mutex_init(&sc->lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sc->cv, NULL, CV_DRIVER, NULL);
	mutex_init(&sc->sfl_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&t4_adapter_list_lock);
	SLIST_INSERT_HEAD(&t4_adapter_list, sc, link);
	mutex_exit(&t4_adapter_list_lock);

	sc->pf = getpf(sc);
	if (sc->pf > 8) {
		rc = EINVAL;
		cxgb_printf(dip, CE_WARN,
		    "failed to determine PCI PF# of device");
		goto done;
	}
	sc->mbox = sc->pf;

	/* Initialize the driver properties */
	prp = &sc->props;
	(void)init_driver_props(sc, prp);

	/*
	 * Enable access to the PCI config space.
	 */
	rc = pci_config_setup(dip, &sc->pci_regh);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to enable PCI config space access: %d", rc);
		goto done;
	}

	/* TODO: Set max read request to 4K */

	/*
	 * Enable MMIO access.
	 */
	rc = ddi_regs_map_setup(dip, 1, &sc->regp, 0, 0, &da, &sc->regh);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to map device registers: %d", rc);
		goto done;
	}

	(void) memset(sc->chan_map, 0xff, sizeof (sc->chan_map));

	/*
	 * Initialize cpl handler.
	 */
	for (i = 0; i < ARRAY_SIZE(sc->cpl_handler); i++) {
		sc->cpl_handler[i] = cpl_not_handled;
	}

	for (i = 0; i < ARRAY_SIZE(sc->fw_msg_handler); i++) {
		sc->fw_msg_handler[i] = fw_msg_not_handled;
	}
 
	/*
	 * Prepare the adapter for operation.
	 */
	rc = -t4_prep_adapter(sc, false);
	if (rc != 0) {
		cxgb_printf(dip, CE_WARN, "failed to prepare adapter: %d", rc);
		goto done;
	}

	/*
	 * Enable BAR1 access.
	 */
	sc->doorbells |= DOORBELL_KDB;
	rc = ddi_regs_map_setup(dip, 2, &sc->reg1p, 0, 0, &da1, &sc->reg1h);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to map BAR1 device registers: %d", rc);
		goto done;
	} else {
		if (is_t5(sc->params.chip)) {
			sc->doorbells |= DOORBELL_UDB;
			if (prp->wc) {
				/*
				 * Enable write combining on BAR2.  This is the
				 * userspace doorbell BAR and is split into 128B
				 * (UDBS_SEG_SIZE) doorbell regions, each associated
				 * with an egress queue.  The first 64B has the doorbell
				 * and the second 64B can be used to submit a tx work
				 * request with an implicit doorbell.
				 */
				sc->doorbells &= ~DOORBELL_UDB;
				sc->doorbells |= (DOORBELL_WCWR |
				    DOORBELL_UDBWC);
				t4_write_reg(sc, A_SGE_STAT_CFG,
				    V_STATSOURCE_T5(7) | V_STATMODE(0));
			}
		}
	}

	/*
	 * Do this really early.  Note that minor number = instance.
	 */
	(void) snprintf(name, sizeof (name), "%s,%d", T4_NEXUS_NAME, instance);
	rc = ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    DDI_NT_NEXUS, 0);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to create device node: %d", rc);
		rc = DDI_SUCCESS; /* carry on */
	}

	/* Do this early. Memory window is required for loading config file. */
	setup_memwin(sc);

	/* Prepare the firmware for operation */
	rc = prep_firmware(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = adap__pre_init_tweaks(sc);
	if (rc != 0)
		goto done;

	rc = get_params__pre_init(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	t4_sge_init(sc);

	if (sc->flags & MASTER_PF) {
		/* get basic stuff going */
		rc = -t4_fw_initialize(sc, sc->mbox);
		if (rc != 0) {
			cxgb_printf(sc->dip, CE_WARN,
			    "early init failed: %d.\n", rc);
			goto done;
		}
	}

	rc = get_params__post_init(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = set_params__post_init(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	/*
	 * TODO: This is the place to call t4_set_filter_mode()
	 */

	/* tweak some settings */
	t4_write_reg(sc, A_TP_SHIFT_CNT, V_SYNSHIFTMAX(6) | V_RXTSHIFTMAXR1(4) |
	    V_RXTSHIFTMAXR2(15) | V_PERSHIFTBACKOFFMAX(8) | V_PERSHIFTMAX(8) |
	    V_KEEPALIVEMAXR1(4) | V_KEEPALIVEMAXR2(9));
	t4_write_reg(sc, A_ULP_RX_TDDP_PSZ, V_HPZ0(PAGE_SHIFT - 12));

	/*
	 * Work-around for bug 2619
	 * Set DisableVlan field in TP_RSS_CONFIG_VRT register so that the
	 * VLAN tag extraction is disabled.
	 */
	t4_set_reg_field(sc, A_TP_RSS_CONFIG_VRT, F_DISABLEVLAN, F_DISABLEVLAN);

	/* Store filter mode */
	t4_read_indirect(sc, A_TP_PIO_ADDR, A_TP_PIO_DATA, &sc->filter_mode, 1,
	    A_TP_VLAN_PRI_MAP);

	/*
	 * First pass over all the ports - allocate VIs and initialize some
	 * basic parameters like mac address, port type, etc.  We also figure
	 * out whether a port is 10G or 1G and use that information when
	 * calculating how many interrupts to attempt to allocate.
	 */
	n100g = n40g = n25g = n10g = n1g = 0;
	for_each_port(sc, i) {
		struct port_info *pi;

		pi = kmem_zalloc(sizeof (*pi), KM_SLEEP);
		sc->port[i] = pi;

		/* These must be set before t4_port_init */
		pi->adapter = sc;
		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->port_id = i;
	}

	/* Allocate the vi and initialize parameters like mac addr */
	rc = -t4_port_init(sc, sc->mbox, sc->pf, 0);
	if (rc) {
		cxgb_printf(dip, CE_WARN,
			    "unable to initialize port: %d", rc);
		goto done;
	}

	for_each_port(sc, i) {
		struct port_info *pi = sc->port[i];

		mutex_init(&pi->lock, NULL, MUTEX_DRIVER, NULL);
		pi->mtu = ETHERMTU;

		if (is_100G_port(pi)) {
			n100g++;
			pi->tmr_idx = prp->tmr_idx_10g;
			pi->pktc_idx = prp->pktc_idx_10g;
		} else if (is_40G_port(pi)) {
			n40g++;
			pi->tmr_idx = prp->tmr_idx_10g;
			pi->pktc_idx = prp->pktc_idx_10g;
		} else if (is_25G_port(pi)) {
			n25g++;
			pi->tmr_idx = prp->tmr_idx_10g;
			pi->pktc_idx = prp->pktc_idx_10g;
		} else if (is_10G_port(pi)) {
			n10g++;
			pi->tmr_idx = prp->tmr_idx_10g;
			pi->pktc_idx = prp->pktc_idx_10g;
		} else {
			n1g++;
			pi->tmr_idx = prp->tmr_idx_1g;
			pi->pktc_idx = prp->pktc_idx_1g;
		}

		pi->xact_addr_filt = -1;
		t4_mc_init(pi);

		setbit(&sc->registered_device_map, i);
	}

	nxg = n10g + n25g + n40g + n100g;
	(void) remove_extra_props(sc, nxg, n1g);

	if (sc->registered_device_map == 0) {
		cxgb_printf(dip, CE_WARN, "no usable ports");
		rc = DDI_FAILURE;
		goto done;
	}

	rc = cfg_itype_and_nqueues(sc, nxg, n1g, &iaq);
	if (rc != 0)
		goto done; /* error message displayed already */

	sc->intr_type = iaq.intr_type;
	sc->intr_count = iaq.nirq;

	if (sc->props.multi_rings && (sc->intr_type != DDI_INTR_TYPE_MSIX)) {
		sc->props.multi_rings = 0;
		cxgb_printf(dip, CE_WARN,
		    "Multiple rings disabled as interrupt type is not MSI-X");
	}

	if (sc->props.multi_rings && iaq.intr_fwd) {
		sc->props.multi_rings = 0;
		cxgb_printf(dip, CE_WARN,
		    "Multiple rings disabled as interrupts are forwarded");
	}

	if (!sc->props.multi_rings) {
		iaq.ntxq10g = 1;
		iaq.ntxq1g = 1;
	}
	s = &sc->sge;
	s->nrxq = nxg * iaq.nrxq10g + n1g * iaq.nrxq1g;
	s->ntxq = nxg * iaq.ntxq10g + n1g * iaq.ntxq1g;
	s->neq = s->ntxq + s->nrxq;	/* the fl in an rxq is an eq */
#ifdef TCP_OFFLOAD_ENABLE
	/* control queues, 1 per port + 1 mgmtq */
	s->neq += sc->params.nports + 1;
#endif
	s->niq = s->nrxq + 1;		/* 1 extra for firmware event queue */
	if (iaq.intr_fwd != 0)
		sc->flags |= INTR_FWD;
#ifdef TCP_OFFLOAD_ENABLE
	if (is_offload(sc) != 0) {

		s->nofldrxq = nxg * iaq.nofldrxq10g + n1g * iaq.nofldrxq1g;
		s->nofldtxq = nxg * iaq.nofldtxq10g + n1g * iaq.nofldtxq1g;
		s->neq += s->nofldtxq + s->nofldrxq;
		s->niq += s->nofldrxq;

		s->ofld_rxq = kmem_zalloc(s->nofldrxq *
		    sizeof (struct sge_ofld_rxq), KM_SLEEP);
		s->ofld_txq = kmem_zalloc(s->nofldtxq *
		    sizeof (struct sge_wrq), KM_SLEEP);
		s->ctrlq = kmem_zalloc(sc->params.nports *
		    sizeof (struct sge_wrq), KM_SLEEP);

	}
#endif
	s->rxq = kmem_zalloc(s->nrxq * sizeof (struct sge_rxq), KM_SLEEP);
	s->txq = kmem_zalloc(s->ntxq * sizeof (struct sge_txq), KM_SLEEP);
	s->iqmap = kmem_zalloc(s->niq * sizeof (struct sge_iq *), KM_SLEEP);
	s->eqmap = kmem_zalloc(s->neq * sizeof (struct sge_eq *), KM_SLEEP);

	sc->intr_handle = kmem_zalloc(sc->intr_count *
	    sizeof (ddi_intr_handle_t), KM_SLEEP);

	/*
	 * Second pass over the ports.  This time we know the number of rx and
	 * tx queues that each port should get.
	 */
	rqidx = tqidx = 0;
#ifdef TCP_OFFLOAD_ENABLE
	ofld_rqidx = ofld_tqidx = 0;
#endif
	for_each_port(sc, i) {
		struct port_info *pi = sc->port[i];

		if (pi == NULL)
			continue;

		t4_mc_cb_init(pi);
		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->first_rxq = rqidx;
		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->nrxq = (is_10XG_port(pi)) ? iaq.nrxq10g
		    : iaq.nrxq1g;
		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->first_txq = tqidx;
		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->ntxq = (is_10XG_port(pi)) ? iaq.ntxq10g
		    : iaq.ntxq1g;

		rqidx += pi->nrxq;
		tqidx += pi->ntxq;

#ifdef TCP_OFFLOAD_ENABLE
		if (is_offload(sc) != 0) {
			/* LINTED: E_ASSIGN_NARROW_CONV */
			pi->first_ofld_rxq = ofld_rqidx;
			pi->nofldrxq = max(1, pi->nrxq / 4);

			/* LINTED: E_ASSIGN_NARROW_CONV */
			pi->first_ofld_txq = ofld_tqidx;
			pi->nofldtxq = max(1, pi->ntxq / 2);

			ofld_rqidx += pi->nofldrxq;
			ofld_tqidx += pi->nofldtxq;
		}
#endif

		/*
		 * Enable hw checksumming and LSO for all ports by default.
		 * They can be disabled using ndd (hw_csum and hw_lso).
		 */
		pi->features |= (CXGBE_HW_CSUM | CXGBE_HW_LSO);
	}

#ifdef TCP_OFFLOAD_ENABLE
		sc->l2t = t4_init_l2t(sc);
#endif

	/*
	 * Setup Interrupts.
	 */

	i = 0;
	rc = ddi_intr_alloc(dip, sc->intr_handle, sc->intr_type, 0,
	    sc->intr_count, &i, DDI_INTR_ALLOC_STRICT);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to allocate %d interrupt(s) of type %d: %d, %d",
		    sc->intr_count, sc->intr_type, rc, i);
		goto done;
	}
	ASSERT(sc->intr_count == i); /* allocation was STRICT */
	(void) ddi_intr_get_cap(sc->intr_handle[0], &sc->intr_cap);
	(void) ddi_intr_get_pri(sc->intr_handle[0], &sc->intr_pri);
	if (sc->intr_count == 1) {
		ASSERT(sc->flags & INTR_FWD);
		(void) ddi_intr_add_handler(sc->intr_handle[0], t4_intr_all, sc,
		    &s->fwq);
	} else {
		/* Multiple interrupts.  The first one is always error intr */
		(void) ddi_intr_add_handler(sc->intr_handle[0], t4_intr_err, sc,
		    NULL);
		irq++;

		/* The second one is always the firmware event queue */
		(void) ddi_intr_add_handler(sc->intr_handle[1], t4_intr, sc,
		    &s->fwq);
		irq++;
		/*
		 * Note that if INTR_FWD is set then either the NIC rx
		 * queues or (exclusive or) the TOE rx queueus will be taking
		 * direct interrupts.
		 *
		 * There is no need to check for is_offload(sc) as nofldrxq
		 * will be 0 if offload is disabled.
		 */
		for_each_port(sc, i) {
			struct port_info *pi = sc->port[i];
			struct sge_rxq *rxq;
#ifdef TCP_OFFLOAD_ENABLE
			struct sge_ofld_rxq *ofld_rxq;

			/*
			 * Skip over the NIC queues if they aren't taking direct
			 * interrupts.
			 */
			if ((sc->flags & INTR_FWD) &&
			    pi->nofldrxq > pi->nrxq)
				goto ofld_queues;
#endif
			rxq = &s->rxq[pi->first_rxq];
			for (q = 0; q < pi->nrxq; q++, rxq++) {
				(void) ddi_intr_add_handler(
				    sc->intr_handle[irq], t4_intr, sc,
				    &rxq->iq);
				irq++;
			}

#ifdef TCP_OFFLOAD_ENABLE
			/*
			 * Skip over the offload queues if they aren't taking
			 * direct interrupts.
			 */
			if ((sc->flags & INTR_FWD))
				continue;
ofld_queues:
			ofld_rxq = &s->ofld_rxq[pi->first_ofld_rxq];
			for (q = 0; q < pi->nofldrxq; q++, ofld_rxq++) {
				(void) ddi_intr_add_handler(
				    sc->intr_handle[irq], t4_intr, sc,
				    &ofld_rxq->iq);
				irq++;
			}
#endif
		}

	}
	sc->flags |= INTR_ALLOCATED;

	ASSERT(rc == DDI_SUCCESS);
	ddi_report_dev(dip);

	/*
	 * Hardware/Firmware/etc. Version/Revision IDs.
	 */
	t4_dump_version_info(sc);

	if (n100g) {
		cxgb_printf(dip, CE_NOTE,
		    "%dx100G (%d rxq, %d txq total) %d %s.",
		    n100g, rqidx, tqidx, sc->intr_count,
		    sc->intr_type == DDI_INTR_TYPE_MSIX ? "MSI-X interrupts" :
		    sc->intr_type == DDI_INTR_TYPE_MSI ? "MSI interrupts" :
		    "fixed interrupt");
	} else if (n40g) {
		cxgb_printf(dip, CE_NOTE,
		    "%dx40G (%d rxq, %d txq total) %d %s.",
		    n40g, rqidx, tqidx, sc->intr_count,
		    sc->intr_type == DDI_INTR_TYPE_MSIX ? "MSI-X interrupts" :
		    sc->intr_type == DDI_INTR_TYPE_MSI ? "MSI interrupts" :
		    "fixed interrupt");
	} else if (n25g) {
		cxgb_printf(dip, CE_NOTE,
		    "%dx25G (%d rxq, %d txq total) %d %s.",
		    n25g, rqidx, tqidx, sc->intr_count,
		    sc->intr_type == DDI_INTR_TYPE_MSIX ? "MSI-X interrupts" :
		    sc->intr_type == DDI_INTR_TYPE_MSI ? "MSI interrupts" :
		    "fixed interrupt");
	} else if (n10g && n1g) {
		cxgb_printf(dip, CE_NOTE,
		    "%dx10G %dx1G (%d rxq, %d txq total) %d %s.",
		    n10g, n1g, rqidx, tqidx, sc->intr_count,
		    sc->intr_type == DDI_INTR_TYPE_MSIX ? "MSI-X interrupts" :
		    sc->intr_type == DDI_INTR_TYPE_MSI ? "MSI interrupts" :
		    "fixed interrupt");
	} else {
		cxgb_printf(dip, CE_NOTE,
		    "%dx%sG (%d rxq, %d txq per port) %d %s.",
		    n10g ? n10g : n1g,
		    n10g ? "10" : "1",
		    n10g ? iaq.nrxq10g : iaq.nrxq1g,
		    n10g ? iaq.ntxq10g : iaq.ntxq1g,
		    sc->intr_count,
		    sc->intr_type == DDI_INTR_TYPE_MSIX ? "MSI-X interrupts" :
		    sc->intr_type == DDI_INTR_TYPE_MSI ? "MSI interrupts" :
		    "fixed interrupt");
	}

	sc->ksp = setup_kstats(sc);
	sc->ksp_stat = setup_wc_kstats(sc);
	sc->params.drv_memwin = MEMWIN_NIC;

done:
	if (rc != DDI_SUCCESS) {
		(void) t4_devo_detach(dip, DDI_DETACH);

		/* rc may have errno style errors or DDI errors */
		rc = DDI_FAILURE;
	}

	return (rc);
}

static int
t4_devo_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance, i;
	struct adapter *sc;
	struct port_info *pi;
	struct sge *s;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(t4_list, instance);
	if (sc == NULL)
		return (DDI_SUCCESS);

	if (sc->flags & FULL_INIT_DONE) {
		t4_intr_disable(sc);
		for_each_port(sc, i) {
			pi = sc->port[i];
			if (pi && pi->flags & PORT_INIT_DONE)
				(void) port_full_uninit(pi);
		}
		(void) adapter_full_uninit(sc);
	}

	/* Safe to call no matter what */
	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);

	if (sc->ksp != NULL)
		kstat_delete(sc->ksp);
	if (sc->ksp_stat != NULL)
		kstat_delete(sc->ksp_stat);

	s = &sc->sge;
	if (s->rxq != NULL)
		kmem_free(s->rxq, s->nrxq * sizeof (struct sge_rxq));
#ifdef TCP_OFFLOAD_ENABLE
	if (s->ofld_txq != NULL)
		kmem_free(s->ofld_txq, s->nofldtxq * sizeof (struct sge_wrq));
	if (s->ofld_rxq != NULL)
		kmem_free(s->ofld_rxq,
		    s->nofldrxq * sizeof (struct sge_ofld_rxq));
	if (s->ctrlq != NULL)
		kmem_free(s->ctrlq,
		    sc->params.nports * sizeof (struct sge_wrq));
#endif
	if (s->txq != NULL)
		kmem_free(s->txq, s->ntxq * sizeof (struct sge_txq));
	if (s->iqmap != NULL)
		kmem_free(s->iqmap, s->niq * sizeof (struct sge_iq *));
	if (s->eqmap != NULL)
		kmem_free(s->eqmap, s->neq * sizeof (struct sge_eq *));

	if (s->rxbuf_cache != NULL)
		rxbuf_cache_destroy(s->rxbuf_cache);

	if (sc->flags & INTR_ALLOCATED) {
		for (i = 0; i < sc->intr_count; i++) {
			(void) ddi_intr_remove_handler(sc->intr_handle[i]);
			(void) ddi_intr_free(sc->intr_handle[i]);
		}
		sc->flags &= ~INTR_ALLOCATED;
	}

	if (sc->intr_handle != NULL) {
		kmem_free(sc->intr_handle,
		    sc->intr_count * sizeof (*sc->intr_handle));
	}

	for_each_port(sc, i) {
		pi = sc->port[i];
		if (pi != NULL) {
			mutex_destroy(&pi->lock);
			kmem_free(pi, sizeof (*pi));
			clrbit(&sc->registered_device_map, i);
		}
	}

	if (sc->flags & FW_OK)
		(void) t4_fw_bye(sc, sc->mbox);

	if (sc->reg1h != NULL)
		ddi_regs_map_free(&sc->reg1h);

	if (sc->regh != NULL)
		ddi_regs_map_free(&sc->regh);

	if (sc->pci_regh != NULL)
		pci_config_teardown(&sc->pci_regh);

	mutex_enter(&t4_adapter_list_lock);
	SLIST_REMOVE_HEAD(&t4_adapter_list, link);
	mutex_exit(&t4_adapter_list_lock);

	mutex_destroy(&sc->lock);
	cv_destroy(&sc->cv);
	mutex_destroy(&sc->sfl_lock);

#ifdef DEBUG
	bzero(sc, sizeof (*sc));
#endif
	ddi_soft_state_free(t4_list, instance);

	return (DDI_SUCCESS);
}

static int
t4_devo_quiesce(dev_info_t *dip)
{
	int instance;
	struct adapter *sc;

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(t4_list, instance);
	if (sc == NULL)
		return (DDI_SUCCESS);

	t4_set_reg_field(sc, A_SGE_CONTROL, F_GLOBALENABLE, 0);
	t4_intr_disable(sc);
	t4_write_reg(sc, A_PL_RST, F_PIORSTMODE | F_PIORST);

	return (DDI_SUCCESS);
}

static int
t4_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op, void *arg,
    void *result)
{
	char s[4];
	struct port_info *pi;
	dev_info_t *child = (dev_info_t *)arg;

	switch (op) {
	case DDI_CTLOPS_REPORTDEV:
		pi = ddi_get_parent_data(rdip);
		pi->instance = ddi_get_instance(dip);
		pi->child_inst = ddi_get_instance(rdip);
		cmn_err(CE_CONT, "?%s%d is port %s on %s%d\n",
		    ddi_node_name(rdip), ddi_get_instance(rdip),
		    ddi_get_name_addr(rdip), ddi_driver_name(dip),
		    ddi_get_instance(dip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		pi = ddi_get_parent_data(child);
		if (pi == NULL)
			return (DDI_NOT_WELL_FORMED);
		(void) snprintf(s, sizeof (s), "%d", pi->port_id);
		ddi_set_name_addr(child, s);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:
		ddi_set_name_addr(child, NULL);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_ATTACH:
	case DDI_CTLOPS_DETACH:
		return (DDI_SUCCESS);

	default:
		return (ddi_ctlops(dip, rdip, op, arg, result));
	}
}

static int
t4_bus_config(dev_info_t *dip, uint_t flags, ddi_bus_config_op_t op, void *arg,
    dev_info_t **cdipp)
{
	int instance, i;
	struct adapter *sc;

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(t4_list, instance);

	if (op == BUS_CONFIG_ONE) {
		char *c;

		/*
		 * arg is something like "cxgb@0" where 0 is the port_id hanging
		 * off this nexus.
		 */

		c = arg;
		while (*(c + 1))
			c++;

		/* There should be exactly 1 digit after '@' */
		if (*(c - 1) != '@')
			return (NDI_FAILURE);

		i = *c - '0';

		if (add_child_node(sc, i) != 0)
			return (NDI_FAILURE);

		flags |= NDI_ONLINE_ATTACH;

	} else if (op == BUS_CONFIG_ALL || op == BUS_CONFIG_DRIVER) {
		/* Allocate and bind all child device nodes */
		for_each_port(sc, i)
		    (void) add_child_node(sc, i);
		flags |= NDI_ONLINE_ATTACH;
	}

	return (ndi_busop_bus_config(dip, flags, op, arg, cdipp, 0));
}

static int
t4_bus_unconfig(dev_info_t *dip, uint_t flags, ddi_bus_config_op_t op,
    void *arg)
{
	int instance, i, rc;
	struct adapter *sc;

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(t4_list, instance);

	if (op == BUS_CONFIG_ONE || op == BUS_UNCONFIG_ALL ||
	    op == BUS_UNCONFIG_DRIVER)
		flags |= NDI_UNCONFIG;

	rc = ndi_busop_bus_unconfig(dip, flags, op, arg);
	if (rc != 0)
		return (rc);

	if (op == BUS_UNCONFIG_ONE) {
		char *c;

		c = arg;
		while (*(c + 1))
			c++;

		if (*(c - 1) != '@')
			return (NDI_SUCCESS);

		i = *c - '0';

		rc = remove_child_node(sc, i);

	} else if (op == BUS_UNCONFIG_ALL || op == BUS_UNCONFIG_DRIVER) {

		for_each_port(sc, i)
		    (void) remove_child_node(sc, i);
	}

	return (rc);
}

/* ARGSUSED */
static int
t4_cb_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	struct adapter *sc;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	sc = ddi_get_soft_state(t4_list, getminor(*devp));
	if (sc == NULL)
		return (ENXIO);

	return (atomic_cas_uint(&sc->open, 0, EBUSY));
}

/* ARGSUSED */
static int
t4_cb_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	struct adapter *sc;

	sc = ddi_get_soft_state(t4_list, getminor(dev));
	if (sc == NULL)
		return (EINVAL);

	(void) atomic_swap_uint(&sc->open, 0);
	return (0);
}

/* ARGSUSED */
static int
t4_cb_ioctl(dev_t dev, int cmd, intptr_t d, int mode, cred_t *credp, int *rp)
{
	int instance;
	struct adapter *sc;
	void *data = (void *)d;

	if (crgetuid(credp) != 0)
		return (EPERM);

	instance = getminor(dev);
	sc = ddi_get_soft_state(t4_list, instance);
	if (sc == NULL)
		return (EINVAL);

	return (t4_ioctl(sc, cmd, data, mode));
}

static unsigned int
getpf(struct adapter *sc)
{
	int rc, *data;
	uint_t n, pf;

	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, sc->dip,
	    DDI_PROP_DONTPASS, "reg", &data, &n);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to lookup \"reg\" property: %d", rc);
		return (0xff);
	}

	pf = PCI_REG_FUNC_G(data[0]);
	ddi_prop_free(data);

	return (pf);
}


static struct fw_info *
find_fw_info(int chip)
{
	u32 i;

	fi[0].chip = CHELSIO_T4;
	fi[0].fw_hdr.chip = FW_HDR_CHIP_T4;
	fi[0].fw_hdr.fw_ver = cpu_to_be32(FW_VERSION(T4));
	fi[0].fw_hdr.intfver_nic = FW_INTFVER(T4, NIC);
	fi[0].fw_hdr.intfver_vnic = FW_INTFVER(T4, VNIC);
	fi[0].fw_hdr.intfver_ofld = FW_INTFVER(T4, OFLD);
	fi[0].fw_hdr.intfver_ri = FW_INTFVER(T4, RI);
	fi[0].fw_hdr.intfver_iscsipdu = FW_INTFVER(T4, ISCSIPDU);
	fi[0].fw_hdr.intfver_iscsi = FW_INTFVER(T4, ISCSI);
	fi[0].fw_hdr.intfver_fcoepdu = FW_INTFVER(T4, FCOEPDU);
	fi[0].fw_hdr.intfver_fcoe = FW_INTFVER(T4, FCOE);

	fi[1].chip = CHELSIO_T5;
	fi[1].fw_hdr.chip = FW_HDR_CHIP_T5;
	fi[1].fw_hdr.fw_ver = cpu_to_be32(FW_VERSION(T5));
	fi[1].fw_hdr.intfver_nic = FW_INTFVER(T5, NIC);
	fi[1].fw_hdr.intfver_vnic = FW_INTFVER(T5, VNIC);
	fi[1].fw_hdr.intfver_ofld = FW_INTFVER(T5, OFLD);
	fi[1].fw_hdr.intfver_ri = FW_INTFVER(T5, RI);
	fi[1].fw_hdr.intfver_iscsipdu = FW_INTFVER(T5, ISCSIPDU);
	fi[1].fw_hdr.intfver_iscsi = FW_INTFVER(T5, ISCSI);
	fi[1].fw_hdr.intfver_fcoepdu = FW_INTFVER(T5, FCOEPDU);
	fi[1].fw_hdr.intfver_fcoe = FW_INTFVER(T5, FCOE);

	fi[2].chip = CHELSIO_T6;
	fi[2].fw_hdr.chip = FW_HDR_CHIP_T6;
	fi[2].fw_hdr.fw_ver = cpu_to_be32(FW_VERSION(T6));
	fi[2].fw_hdr.intfver_nic = FW_INTFVER(T6, NIC);
	fi[2].fw_hdr.intfver_vnic = FW_INTFVER(T6, VNIC);
	fi[2].fw_hdr.intfver_ofld = FW_INTFVER(T6, OFLD);
	fi[2].fw_hdr.intfver_ri = FW_INTFVER(T6, RI);
	fi[2].fw_hdr.intfver_iscsipdu = FW_INTFVER(T6, ISCSIPDU);
	fi[2].fw_hdr.intfver_iscsi = FW_INTFVER(T6, ISCSI);
	fi[2].fw_hdr.intfver_fcoepdu = FW_INTFVER(T6, FCOEPDU);
	fi[2].fw_hdr.intfver_fcoe = FW_INTFVER(T6, FCOE);

	for (i = 0; i < ARRAY_SIZE(fi); i++) {
		if (fi[i].chip == chip)
			return &fi[i];
	}

	return NULL;
}

/*
 * Install a compatible firmware (if required), establish contact with it,
 * become the master, and reset the device.
 */
static int
prep_firmware(struct adapter *sc)
{
	int rc;
	int fw_size;
	int reset = 1;
	enum dev_state state;
	unsigned char *fw_data;
	struct fw_info *fw_info;
	struct fw_hdr *card_fw;
	
	struct driver_properties *p = &sc->props;

	/* Contact firmware, request master */
	rc = t4_fw_hello(sc, sc->mbox, sc->mbox, MASTER_MUST, &state);
	if (rc < 0) {
		rc = -rc;
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to connect to the firmware: %d.", rc);
		return (rc);
	}

	if (rc == sc->mbox)
		sc->flags |= MASTER_PF;

	/* We may need FW version info for later reporting */
	t4_get_version_info(sc);
	fw_info = find_fw_info(CHELSIO_CHIP_VERSION(sc->params.chip));
	/* allocate memory to read the header of the firmware on the
	 * card
	 */
	if (!fw_info) {
		cxgb_printf(sc->dip, CE_WARN,
			    "unable to look up firmware information for chip %d.\n",
			    CHELSIO_CHIP_VERSION(sc->params.chip));
		return EINVAL;
	}
	card_fw = kmem_zalloc(sizeof(*card_fw), KM_SLEEP);
	if(!card_fw) {
		cxgb_printf(sc->dip, CE_WARN,
			    "Memory allocation for card FW header failed\n");
		return ENOMEM;
	}
	switch(CHELSIO_CHIP_VERSION(sc->params.chip)) {
	case CHELSIO_T4:
		fw_data = t4fw_data;
		fw_size = t4fw_size;
		break;
	case CHELSIO_T5:
		fw_data = t5fw_data;
		fw_size = t5fw_size;
		break;
	case CHELSIO_T6:
		fw_data = t6fw_data;
		fw_size = t6fw_size;
		break;
	default:
		cxgb_printf(sc->dip, CE_WARN, "Adapter type not supported\n");
		kmem_free(card_fw, sizeof(*card_fw));
		return EINVAL;
	}
		
	rc = -t4_prep_fw(sc, fw_info, fw_data, fw_size, card_fw,
			 p->t4_fw_install, state, &reset);

	kmem_free(card_fw, sizeof(*card_fw));

	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to install firmware: %d", rc);
		return (rc);
	} else {
		/* refresh */
		(void) t4_check_fw_version(sc);
	}

	/* Reset device */
	rc = -t4_fw_reset(sc, sc->mbox, F_PIORSTMODE | F_PIORST);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "firmware reset failed: %d.", rc);
		if (rc != ETIMEDOUT && rc != EIO)
			(void) t4_fw_bye(sc, sc->mbox);
		return (rc);
	}

	/* Partition adapter resources as specified in the config file. */
	if (sc->flags & MASTER_PF) {
		/* Handle default vs special T4 config file */

		rc = partition_resources(sc);
		if (rc != 0)
			goto err;	/* error message displayed already */
	}

	sc->flags |= FW_OK;
	return (0);
err:
	return (rc);

}

static const struct memwin t4_memwin[] = {
	{ MEMWIN0_BASE, MEMWIN0_APERTURE },
	{ MEMWIN1_BASE, MEMWIN1_APERTURE },
	{ MEMWIN2_BASE, MEMWIN2_APERTURE }
};

static const struct memwin t5_memwin[] = {
	{ MEMWIN0_BASE, MEMWIN0_APERTURE },
	{ MEMWIN1_BASE, MEMWIN1_APERTURE },
	{ MEMWIN2_BASE_T5, MEMWIN2_APERTURE_T5 },
};

#define	FW_PARAM_DEV(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) | \
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_##param))
#define	FW_PARAM_PFVF(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) | \
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_##param))

/*
 * Verify that the memory range specified by the memtype/offset/len pair is
 * valid and lies entirely within the memtype specified.  The global address of
 * the start of the range is returned in addr.
 */
int
validate_mt_off_len(struct adapter *sc, int mtype, uint32_t off, int len,
	uint32_t *addr)
{
	uint32_t em, addr_len, maddr, mlen;

	/* Memory can only be accessed in naturally aligned 4 byte units */
	if (off & 3 || len & 3 || len == 0)
		return (EINVAL);

	em = t4_read_reg(sc, A_MA_TARGET_MEM_ENABLE);
	switch (mtype) {
		case MEM_EDC0:
			if (!(em & F_EDRAM0_ENABLE))
				return (EINVAL);
			addr_len = t4_read_reg(sc, A_MA_EDRAM0_BAR);
			maddr = G_EDRAM0_BASE(addr_len) << 20;
			mlen = G_EDRAM0_SIZE(addr_len) << 20;
			break;
		case MEM_EDC1:
			if (!(em & F_EDRAM1_ENABLE))
				return (EINVAL);
			addr_len = t4_read_reg(sc, A_MA_EDRAM1_BAR);
			maddr = G_EDRAM1_BASE(addr_len) << 20;
			mlen = G_EDRAM1_SIZE(addr_len) << 20;
			break;
		case MEM_MC:
			if (!(em & F_EXT_MEM_ENABLE))
				return (EINVAL);
			addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY_BAR);
			maddr = G_EXT_MEM_BASE(addr_len) << 20;
			mlen = G_EXT_MEM_SIZE(addr_len) << 20;
			break;
		case MEM_MC1:
			if (is_t4(sc->params.chip) || !(em & F_EXT_MEM1_ENABLE))
				return (EINVAL);
			addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY1_BAR);
			maddr = G_EXT_MEM1_BASE(addr_len) << 20;
			mlen = G_EXT_MEM1_SIZE(addr_len) << 20;
			break;
		default:
			return (EINVAL);
	}

	if (mlen > 0 && off < mlen && off + len <= mlen) {
		*addr = maddr + off;    /* global address */
		return (0);
	}

	return (EFAULT);
}

void
memwin_info(struct adapter *sc, int win, uint32_t *base, uint32_t *aperture)
{
	const struct memwin *mw;

	if (is_t4(sc->params.chip)) {
		mw = &t4_memwin[win];
	} else {
		mw = &t5_memwin[win];
	}

	if (base != NULL)
		*base = mw->base;
	if (aperture != NULL)
		*aperture = mw->aperture;
}

/*
 * Upload configuration file to card's memory.
 */
static int
upload_config_file(struct adapter *sc, uint32_t *mt, uint32_t *ma)
{
	int rc = 0, cflen;
	u_int i, n;
	uint32_t param, val, addr, mtype, maddr;
	uint32_t off, mw_base, mw_aperture;
	const uint32_t *cfdata;

	/* Figure out where the firmware wants us to upload it. */
	param = FW_PARAM_DEV(CF);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
	if (rc != 0) {
		/* Firmwares without config file support will fail this way */
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query config file location: %d.\n", rc);
		return (rc);
	}
	*mt = mtype = G_FW_PARAMS_PARAM_Y(val);
	*ma = maddr = G_FW_PARAMS_PARAM_Z(val) << 16;

	switch (CHELSIO_CHIP_VERSION(sc->params.chip)) {
	case CHELSIO_T4:
		cflen = t4cfg_size & ~3;
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		cfdata = (const uint32_t *)t4cfg_data;
		break;
	case CHELSIO_T5:
		cflen = t5cfg_size & ~3;
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		cfdata = (const uint32_t *)t5cfg_data;
		break;
	case CHELSIO_T6:
		cflen = t6cfg_size & ~3;
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		cfdata = (const uint32_t *)t6cfg_data;
		break;
	default:
		cxgb_printf(sc->dip, CE_WARN,
			    "Invalid Adapter detected\n");
		return EINVAL; 
	}

	if (cflen > FLASH_CFG_MAX_SIZE) {
		cxgb_printf(sc->dip, CE_WARN,
		    "config file too long (%d, max allowed is %d).  ",
		    cflen, FLASH_CFG_MAX_SIZE);
		return (EFBIG);
	}

	rc = validate_mt_off_len(sc, mtype, maddr, cflen, &addr);
	if (rc != 0) {

		cxgb_printf(sc->dip, CE_WARN,
		    "%s: addr (%d/0x%x) or len %d is not valid: %d.  "
		    "Will try to use the config on the card, if any.\n",
		    __func__, mtype, maddr, cflen, rc);
		return (EFAULT);
	}

	memwin_info(sc, 2, &mw_base, &mw_aperture);
	while (cflen) {
		off = position_memwin(sc, 2, addr);
		n = min(cflen, mw_aperture - off);
		for (i = 0; i < n; i += 4)
			t4_write_reg(sc, mw_base + off + i, *cfdata++);
		cflen -= n;
		addr += n;
	}

	return (rc);
}

/*
 * Partition chip resources for use between various PFs, VFs, etc.  This is done
 * by uploading the firmware configuration file to the adapter and instructing
 * the firmware to process it.
 */
static int
partition_resources(struct adapter *sc)
{
	int rc;
	struct fw_caps_config_cmd caps;
	uint32_t mtype, maddr, finicsum, cfcsum;

	rc = upload_config_file(sc, &mtype, &maddr);
	if (rc != 0) {
		mtype = FW_MEMTYPE_CF_FLASH;
		maddr = t4_flash_cfg_addr(sc);
	}

	bzero(&caps, sizeof (caps));
	caps.op_to_write = BE_32(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_READ);
	caps.cfvalid_to_len16 = BE_32(F_FW_CAPS_CONFIG_CMD_CFVALID |
	    V_FW_CAPS_CONFIG_CMD_MEMTYPE_CF(mtype) |
	    V_FW_CAPS_CONFIG_CMD_MEMADDR64K_CF(maddr >> 16) | FW_LEN16(caps));
	rc = -t4_wr_mbox(sc, sc->mbox, &caps, sizeof (caps), &caps);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to pre-process config file: %d.\n", rc);
		return (rc);
	}

	finicsum = ntohl(caps.finicsum);
	cfcsum = ntohl(caps.cfcsum);
	if (finicsum != cfcsum) {
		cxgb_printf(sc->dip, CE_WARN,
		    "WARNING: config file checksum mismatch: %08x %08x\n",
		    finicsum, cfcsum);
	}
	sc->cfcsum = cfcsum;

	/* TODO: Need to configure this correctly */
	caps.toecaps = htons(FW_CAPS_CONFIG_TOE);
	caps.iscsicaps = 0;
	caps.rdmacaps = 0;
	caps.fcoecaps = 0;
	/* TODO: Disable VNIC cap for now */
	caps.niccaps ^= htons(FW_CAPS_CONFIG_NIC_VM);

	caps.op_to_write = htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_WRITE);
	caps.cfvalid_to_len16 = htonl(FW_LEN16(caps));
	rc = -t4_wr_mbox(sc, sc->mbox, &caps, sizeof (caps), NULL);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to process config file: %d.\n", rc);
		return (rc);
	}

	return (0);
}

/*
 * Tweak configuration based on module parameters, etc.  Most of these have
 * defaults assigned to them by Firmware Configuration Files (if we're using
 * them) but need to be explicitly set if we're using hard-coded
 * initialization.  But even in the case of using Firmware Configuration
 * Files, we'd like to expose the ability to change these via module
 * parameters so these are essentially common tweaks/settings for
 * Configuration Files and hard-coded initialization ...
 */
static int
adap__pre_init_tweaks(struct adapter *sc)
{
	int rx_dma_offset = 2; /* Offset of RX packets into DMA buffers */

	/*
	 * Fix up various Host-Dependent Parameters like Page Size, Cache
	 * Line Size, etc.  The firmware default is for a 4KB Page Size and
	 * 64B Cache Line Size ...
	 */
	(void) t4_fixup_host_params_compat(sc, PAGE_SIZE, CACHE_LINE, T5_LAST_REV);

	t4_set_reg_field(sc, A_SGE_CONTROL,
			 V_PKTSHIFT(M_PKTSHIFT), V_PKTSHIFT(rx_dma_offset));

	return 0;
}
/*
 * Retrieve parameters that are needed (or nice to have) prior to calling
 * t4_sge_init and t4_fw_initialize.
 */
static int
get_params__pre_init(struct adapter *sc)
{
	int rc;
	uint32_t param[2], val[2];
	struct fw_devlog_cmd cmd;
	struct devlog_params *dlog = &sc->params.devlog;

	/*
	 * Grab the raw VPD parameters.
	 */
	rc = -t4_get_raw_vpd_params(sc, &sc->params.vpd);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query VPD parameters (pre_init): %d.\n", rc);
		return (rc);
	}

	param[0] = FW_PARAM_DEV(PORTVEC);
	param[1] = FW_PARAM_DEV(CCLK);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 2, param, val);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query parameters (pre_init): %d.\n", rc);
		return (rc);
	}

	sc->params.portvec = val[0];
	sc->params.nports = 0;
	while (val[0]) {
		sc->params.nports++;
		val[0] &= val[0] - 1;
	}

	sc->params.vpd.cclk = val[1];

	/* Read device log parameters. */
	bzero(&cmd, sizeof (cmd));
	cmd.op_to_write = htonl(V_FW_CMD_OP(FW_DEVLOG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_READ);
	cmd.retval_len16 = htonl(FW_LEN16(cmd));
	rc = -t4_wr_mbox(sc, sc->mbox, &cmd, sizeof (cmd), &cmd);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to get devlog parameters: %d.\n", rc);
		bzero(dlog, sizeof (*dlog));
		rc = 0;	/* devlog isn't critical for device operation */
	} else {
		val[0] = ntohl(cmd.memtype_devlog_memaddr16_devlog);
		dlog->memtype = G_FW_DEVLOG_CMD_MEMTYPE_DEVLOG(val[0]);
		dlog->start = G_FW_DEVLOG_CMD_MEMADDR16_DEVLOG(val[0]) << 4;
		dlog->size = ntohl(cmd.memsize_devlog);
	}

	return (rc);
}

/*
 * Retrieve various parameters that are of interest to the driver.  The device
 * has been initialized by the firmware at this point.
 */
static int
get_params__post_init(struct adapter *sc)
{
	int rc;
	uint32_t param[7], val[7];
	struct fw_caps_config_cmd caps;

	param[0] = FW_PARAM_PFVF(IQFLINT_START);
	param[1] = FW_PARAM_PFVF(EQ_START);
	param[2] = FW_PARAM_PFVF(FILTER_START);
	param[3] = FW_PARAM_PFVF(FILTER_END);
	param[4] = FW_PARAM_PFVF(L2T_START);
	param[5] = FW_PARAM_PFVF(L2T_END);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 6, param, val);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query parameters (post_init): %d.\n", rc);
		return (rc);
	}

	/* LINTED: E_ASSIGN_NARROW_CONV */
	sc->sge.iq_start = val[0];
	sc->sge.eq_start = val[1];
	sc->tids.ftid_base = val[2];
	sc->tids.nftids = val[3] - val[2] + 1;
	sc->vres.l2t.start = val[4];
	sc->vres.l2t.size = val[5] - val[4] + 1;

	/* get capabilites */
	bzero(&caps, sizeof (caps));
	caps.op_to_write = htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_READ);
	caps.cfvalid_to_len16 = htonl(FW_LEN16(caps));
	rc = -t4_wr_mbox(sc, sc->mbox, &caps, sizeof (caps), &caps);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to get card capabilities: %d.\n", rc);
		return (rc);
	}

	if (caps.toecaps != 0) {
		/* query offload-related parameters */
		param[0] = FW_PARAM_DEV(NTID);
		param[1] = FW_PARAM_PFVF(SERVER_START);
		param[2] = FW_PARAM_PFVF(SERVER_END);
		param[3] = FW_PARAM_PFVF(TDDP_START);
		param[4] = FW_PARAM_PFVF(TDDP_END);
		param[5] = FW_PARAM_DEV(FLOWC_BUFFIFO_SZ);
		rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 6, param, val);
		if (rc != 0) {
			cxgb_printf(sc->dip, CE_WARN,
			    "failed to query TOE parameters: %d.\n", rc);
			return (rc);
		}
		sc->tids.ntids = val[0];
		sc->tids.natids = min(sc->tids.ntids / 2, MAX_ATIDS);
		sc->tids.stid_base = val[1];
		sc->tids.nstids = val[2] - val[1] + 1;
		sc->vres.ddp.start = val[3];
		sc->vres.ddp.size = val[4] - val[3] + 1;
		sc->params.ofldq_wr_cred = val[5];
		sc->params.offload = 1;
	}

	/* These are finalized by FW initialization, load their values now */
	val[0] = t4_read_reg(sc, A_TP_TIMER_RESOLUTION);
	sc->params.tp.tre = G_TIMERRESOLUTION(val[0]);
	sc->params.tp.dack_re = G_DELAYEDACKRESOLUTION(val[0]);
	t4_read_mtu_tbl(sc, sc->params.mtus, NULL);

	return (rc);
}

static int
set_params__post_init(struct adapter *sc)
{
	uint32_t param, val;

	/* ask for encapsulated CPLs */
	param = FW_PARAM_PFVF(CPLFW4MSG_ENCAP);
	val = 1;
	(void)t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);

	return (0);
}

/* TODO: verify */
static void
setup_memwin(struct adapter *sc)
{
	pci_regspec_t *data;
	int rc;
	uint_t n;
	uintptr_t bar0;
	uintptr_t mem_win0_base, mem_win1_base, mem_win2_base;
	uintptr_t mem_win2_aperture;

	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, sc->dip,
	    DDI_PROP_DONTPASS, "assigned-addresses", (int **)&data, &n);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to lookup \"assigned-addresses\" property: %d", rc);
		return;
	}
	n /= sizeof (*data);

	bar0 = ((uint64_t)data[0].pci_phys_mid << 32) | data[0].pci_phys_low;
	ddi_prop_free(data);

	if (is_t4(sc->params.chip)) {
		mem_win0_base = bar0 + MEMWIN0_BASE;
		mem_win1_base = bar0 + MEMWIN1_BASE;
		mem_win2_base = bar0 + MEMWIN2_BASE;
		mem_win2_aperture = MEMWIN2_APERTURE;
	} else {
		/* For T5, only relative offset inside the PCIe BAR is passed */
		mem_win0_base = MEMWIN0_BASE;
		mem_win1_base = MEMWIN1_BASE;
		mem_win2_base = MEMWIN2_BASE_T5;
		mem_win2_aperture = MEMWIN2_APERTURE_T5;
	}

	t4_write_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 0),
	    mem_win0_base | V_BIR(0) |
	    V_WINDOW(ilog2(MEMWIN0_APERTURE) - 10));

	t4_write_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 1),
	    mem_win1_base | V_BIR(0) |
	    V_WINDOW(ilog2(MEMWIN1_APERTURE) - 10));

	t4_write_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 2),
	    mem_win2_base | V_BIR(0) |
	    V_WINDOW(ilog2(mem_win2_aperture) - 10));

	/* flush */
	(void)t4_read_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 2));
}

/*
 * Positions the memory window such that it can be used to access the specified
 * address in the chip's address space.  The return value is the offset of addr
 * from the start of the window.
 */
uint32_t
position_memwin(struct adapter *sc, int n, uint32_t addr)
{
	uint32_t start, pf;
	uint32_t reg;

	if (addr & 3) {
		cxgb_printf(sc->dip, CE_WARN,
		    "addr (0x%x) is not at a 4B boundary.\n", addr);
		return (EFAULT);
	}

	if (is_t4(sc->params.chip)) {
		pf = 0;
		start = addr & ~0xf;    /* start must be 16B aligned */
	} else {
		pf = V_PFNUM(sc->pf);
		start = addr & ~0x7f;   /* start must be 128B aligned */
	}
	reg = PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, n);

	t4_write_reg(sc, reg, start | pf);
	(void) t4_read_reg(sc, reg);

	return (addr - start);
}
 

/*
 * Reads the named property and fills up the "data" array (which has at least
 * "count" elements).  We first try and lookup the property for our dev_t and
 * then retry with DDI_DEV_T_ANY if it's not found.
 *
 * Returns non-zero if the property was found and "data" has been updated.
 */
static int
prop_lookup_int_array(struct adapter *sc, char *name, int *data, uint_t count)
{
	dev_info_t *dip = sc->dip;
	dev_t dev = sc->dev;
	int rc, *d;
	uint_t i, n;

	rc = ddi_prop_lookup_int_array(dev, dip, DDI_PROP_DONTPASS,
	    name, &d, &n);
	if (rc == DDI_PROP_SUCCESS)
		goto found;

	if (rc != DDI_PROP_NOT_FOUND) {
		cxgb_printf(dip, CE_WARN,
		    "failed to lookup property %s for minor %d: %d.",
		    name, getminor(dev), rc);
		return (0);
	}

	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    name, &d, &n);
	if (rc == DDI_PROP_SUCCESS)
		goto found;

	if (rc != DDI_PROP_NOT_FOUND) {
		cxgb_printf(dip, CE_WARN,
		    "failed to lookup property %s: %d.", name, rc);
		return (0);
	}

	return (0);

found:
	if (n > count) {
		cxgb_printf(dip, CE_NOTE,
		    "property %s has too many elements (%d), ignoring extras",
		    name, n);
	}

	for (i = 0; i < n && i < count; i++)
		data[i] = d[i];
	ddi_prop_free(d);

	return (1);
}

static int
prop_lookup_int(struct adapter *sc, char *name, int defval)
{
	int rc;

	rc = ddi_prop_get_int(sc->dev, sc->dip, DDI_PROP_DONTPASS, name, -1);
	if (rc != -1)
		return (rc);

	return (ddi_prop_get_int(DDI_DEV_T_ANY, sc->dip, DDI_PROP_DONTPASS,
	    name, defval));
}

static int
init_driver_props(struct adapter *sc, struct driver_properties *p)
{
	dev_t dev = sc->dev;
	dev_info_t *dip = sc->dip;
	int i, *data;
	uint_t tmr[SGE_NTIMERS] = {5, 10, 20, 50, 100, 200};
	uint_t cnt[SGE_NCOUNTERS] = {1, 8, 16, 32}; /* 63 max */

	/*
	 * Holdoff timer
	 */
	data = &p->timer_val[0];
	for (i = 0; i < SGE_NTIMERS; i++)
		data[i] = tmr[i];
	(void) prop_lookup_int_array(sc, "holdoff-timer-values", data,
	    SGE_NTIMERS);
	for (i = 0; i < SGE_NTIMERS; i++) {
		int limit = 200U;
		if (data[i] > limit) {
			cxgb_printf(dip, CE_WARN,
			    "holdoff timer %d is too high (%d), lowered to %d.",
			    i, data[i], limit);
			data[i] = limit;
		}
	}
	(void) ddi_prop_update_int_array(dev, dip, "holdoff-timer-values",
	    data, SGE_NTIMERS);

	/*
	 * Holdoff packet counter
	 */
	data = &p->counter_val[0];
	for (i = 0; i < SGE_NCOUNTERS; i++)
		data[i] = cnt[i];
	(void) prop_lookup_int_array(sc, "holdoff-pkt-counter-values", data,
	    SGE_NCOUNTERS);
	for (i = 0; i < SGE_NCOUNTERS; i++) {
		int limit = M_THRESHOLD_0;
		if (data[i] > limit) {
			cxgb_printf(dip, CE_WARN,
			    "holdoff pkt-counter %d is too high (%d), "
			    "lowered to %d.", i, data[i], limit);
			data[i] = limit;
		}
	}
	(void) ddi_prop_update_int_array(dev, dip, "holdoff-pkt-counter-values",
	    data, SGE_NCOUNTERS);

	/*
	 * Maximum # of tx and rx queues to use for each 
	 * 100G, 40G, 25G, 10G and 1G port.
	 */
	p->max_ntxq_10g = prop_lookup_int(sc, "max-ntxq-10G-port", 8);
	(void) ddi_prop_update_int(dev, dip, "max-ntxq-10G-port",
	    p->max_ntxq_10g);

	p->max_nrxq_10g = prop_lookup_int(sc, "max-nrxq-10G-port", 8);
	(void) ddi_prop_update_int(dev, dip, "max-nrxq-10G-port",
	    p->max_nrxq_10g);

	p->max_ntxq_1g = prop_lookup_int(sc, "max-ntxq-1G-port", 2);
	(void) ddi_prop_update_int(dev, dip, "max-ntxq-1G-port",
	    p->max_ntxq_1g);

	p->max_nrxq_1g = prop_lookup_int(sc, "max-nrxq-1G-port", 2);
	(void) ddi_prop_update_int(dev, dip, "max-nrxq-1G-port",
	    p->max_nrxq_1g);

#ifdef TCP_OFFLOAD_ENABLE
	p->max_nofldtxq_10g = prop_lookup_int(sc, "max-nofldtxq-10G-port", 8);
	(void) ddi_prop_update_int(dev, dip, "max-ntxq-10G-port",
	    p->max_nofldtxq_10g);

	p->max_nofldrxq_10g = prop_lookup_int(sc, "max-nofldrxq-10G-port", 2);
	(void) ddi_prop_update_int(dev, dip, "max-nrxq-10G-port",
	    p->max_nofldrxq_10g);

	p->max_nofldtxq_1g = prop_lookup_int(sc, "max-nofldtxq-1G-port", 2);
	(void) ddi_prop_update_int(dev, dip, "max-ntxq-1G-port",
	    p->max_nofldtxq_1g);

	p->max_nofldrxq_1g = prop_lookup_int(sc, "max-nofldrxq-1G-port", 1);
	(void) ddi_prop_update_int(dev, dip, "max-nrxq-1G-port",
	    p->max_nofldrxq_1g);
#endif

	/*
	 * Holdoff parameters for 10G and 1G ports.
	 */
	p->tmr_idx_10g = prop_lookup_int(sc, "holdoff-timer-idx-10G", 0);
	(void) ddi_prop_update_int(dev, dip, "holdoff-timer-idx-10G",
	    p->tmr_idx_10g);

	p->pktc_idx_10g = prop_lookup_int(sc, "holdoff-pktc-idx-10G", 2);
	(void) ddi_prop_update_int(dev, dip, "holdoff-pktc-idx-10G",
	    p->pktc_idx_10g);

	p->tmr_idx_1g = prop_lookup_int(sc, "holdoff-timer-idx-1G", 0);
	(void) ddi_prop_update_int(dev, dip, "holdoff-timer-idx-1G",
	    p->tmr_idx_1g);

	p->pktc_idx_1g = prop_lookup_int(sc, "holdoff-pktc-idx-1G", 2);
	(void) ddi_prop_update_int(dev, dip, "holdoff-pktc-idx-1G",
	    p->pktc_idx_1g);

	/*
	 * Size (number of entries) of each tx and rx queue.
	 */
	i = prop_lookup_int(sc, "qsize-txq", TX_EQ_QSIZE);
	p->qsize_txq = max(i, 128);
	if (p->qsize_txq != i) {
		cxgb_printf(dip, CE_WARN,
		    "using %d instead of %d as the tx queue size",
		    p->qsize_txq, i);
	}
	(void) ddi_prop_update_int(dev, dip, "qsize-txq", p->qsize_txq);

	i = prop_lookup_int(sc, "qsize-rxq", RX_IQ_QSIZE);
	p->qsize_rxq = max(i, 128);
	while (p->qsize_rxq & 7)
		p->qsize_rxq--;
	if (p->qsize_rxq != i) {
		cxgb_printf(dip, CE_WARN,
		    "using %d instead of %d as the rx queue size",
		    p->qsize_rxq, i);
	}
	(void) ddi_prop_update_int(dev, dip, "qsize-rxq", p->qsize_rxq);

	/*
	 * Interrupt types allowed.
	 * Bits 0, 1, 2 = INTx, MSI, MSI-X respectively.  See sys/ddi_intr.h
	 */
	p->intr_types = prop_lookup_int(sc, "interrupt-types",
	    DDI_INTR_TYPE_MSIX | DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_FIXED);
	(void) ddi_prop_update_int(dev, dip, "interrupt-types", p->intr_types);

	/*
	 * Forwarded interrupt queues.  Create this property to force the driver
	 * to use forwarded interrupt queues.
	 */
	if (ddi_prop_exists(dev, dip, DDI_PROP_DONTPASS,
	    "interrupt-forwarding") != 0 ||
	    ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-forwarding") != 0) {
		UNIMPLEMENTED();
		(void) ddi_prop_create(dev, dip, DDI_PROP_CANSLEEP,
		    "interrupt-forwarding", NULL, 0);
	}

	/*
	 * Write combining
	 * 0 to disable, 1 to enable
	 */
	p->wc = prop_lookup_int(sc, "write-combine", 1);
	cxgb_printf(dip, CE_WARN, "write-combine: using of %d", p->wc);
	if (p->wc != 0 && p->wc != 1) {
		cxgb_printf(dip, CE_WARN,
		    "write-combine: using 1 instead of %d", p->wc);
		p->wc = 1;
	}
	(void) ddi_prop_update_int(dev, dip, "write-combine", p->wc);

	p->t4_fw_install = prop_lookup_int(sc, "t4_fw_install", 1);
	if (p->t4_fw_install != 0 && p->t4_fw_install != 2)
		p->t4_fw_install = 1;
	(void) ddi_prop_update_int(dev, dip, "t4_fw_install", p->t4_fw_install);

	/* Multiple Rings */
	p->multi_rings = prop_lookup_int(sc, "multi-rings", 1);
	if (p->multi_rings != 0 && p->multi_rings != 1) {
		cxgb_printf(dip, CE_NOTE,
			   "multi-rings: using value 1 instead of %d", p->multi_rings);
		p->multi_rings = 1;
	}

	(void) ddi_prop_update_int(dev, dip, "multi-rings", p->multi_rings);

	return (0);
}

static int
remove_extra_props(struct adapter *sc, int n10g, int n1g)
{
	if (n10g == 0) {
		(void) ddi_prop_remove(sc->dev, sc->dip, "max-ntxq-10G-port");
		(void) ddi_prop_remove(sc->dev, sc->dip, "max-nrxq-10G-port");
		(void) ddi_prop_remove(sc->dev, sc->dip,
		    "holdoff-timer-idx-10G");
		(void) ddi_prop_remove(sc->dev, sc->dip,
		    "holdoff-pktc-idx-10G");
	}

	if (n1g == 0) {
		(void) ddi_prop_remove(sc->dev, sc->dip, "max-ntxq-1G-port");
		(void) ddi_prop_remove(sc->dev, sc->dip, "max-nrxq-1G-port");
		(void) ddi_prop_remove(sc->dev, sc->dip,
		    "holdoff-timer-idx-1G");
		(void) ddi_prop_remove(sc->dev, sc->dip, "holdoff-pktc-idx-1G");
	}

	return (0);
}

static int
cfg_itype_and_nqueues(struct adapter *sc, int n10g, int n1g,
    struct intrs_and_queues *iaq)
{
	struct driver_properties *p = &sc->props;
	int rc, itype, itypes, navail, nc, nrxq10g, nrxq1g, n;
	int nofldrxq10g = 0, nofldrxq1g = 0;

	bzero(iaq, sizeof (*iaq));
	nc = ncpus;	/* our snapshot of the number of CPUs */
	iaq->ntxq10g = min(nc, p->max_ntxq_10g);
	iaq->ntxq1g = min(nc, p->max_ntxq_1g);
	iaq->nrxq10g = nrxq10g = min(nc, p->max_nrxq_10g);
	iaq->nrxq1g = nrxq1g = min(nc, p->max_nrxq_1g);
#ifdef TCP_OFFLOAD_ENABLE
	iaq->nofldtxq10g = min(nc, p->max_nofldtxq_10g);
	iaq->nofldtxq1g = min(nc, p->max_nofldtxq_1g);
	iaq->nofldrxq10g = nofldrxq10g = min(nc, p->max_nofldrxq_10g);
	iaq->nofldrxq1g = nofldrxq1g = min(nc, p->max_nofldrxq_1g);
#endif

	rc = ddi_intr_get_supported_types(sc->dip, &itypes);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to determine supported interrupt types: %d", rc);
		return (rc);
	}

	for (itype = DDI_INTR_TYPE_MSIX; itype; itype >>= 1) {
		ASSERT(itype == DDI_INTR_TYPE_MSIX ||
		    itype == DDI_INTR_TYPE_MSI ||
		    itype == DDI_INTR_TYPE_FIXED);

		if ((itype & itypes & p->intr_types) == 0)
			continue;	/* not supported or not allowed */

		navail = 0;
		rc = ddi_intr_get_navail(sc->dip, itype, &navail);
		if (rc != DDI_SUCCESS || navail == 0) {
			cxgb_printf(sc->dip, CE_WARN,
			    "failed to get # of interrupts for type %d: %d",
			    itype, rc);
			continue;	/* carry on */
		}

		iaq->intr_type = itype;
		if (navail == 0)
			continue;

		/*
		 * Best option: an interrupt vector for errors, one for the
		 * firmware event queue, and one each for each rxq (NIC as well
		 * as offload).
		 */
		iaq->nirq = T4_EXTRA_INTR;
		iaq->nirq += n10g * (nrxq10g + nofldrxq10g);
		iaq->nirq += n1g * (nrxq1g + nofldrxq1g);

		if (iaq->nirq <= navail &&
		    (itype != DDI_INTR_TYPE_MSI || ISP2(iaq->nirq))) {
			iaq->intr_fwd = 0;
			goto allocate;
		}

		/*
		 * Second best option: an interrupt vector for errors, one for
		 * the firmware event queue, and one each for either NIC or
		 * offload rxq's.
		 */
		iaq->nirq = T4_EXTRA_INTR;
		iaq->nirq += n10g * max(nrxq10g, nofldrxq10g);
		iaq->nirq += n1g * max(nrxq1g, nofldrxq1g);
		if (iaq->nirq <= navail &&
		    (itype != DDI_INTR_TYPE_MSI || ISP2(iaq->nirq))) {
			iaq->intr_fwd = 1;
			goto allocate;
		}

		/*
		 * Next best option: an interrupt vector for errors, one for the
		 * firmware event queue, and at least one per port.  At this
		 * point we know we'll have to downsize nrxq or nofldrxq to fit
		 * what's available to us.
		 */
		iaq->nirq = T4_EXTRA_INTR;
		iaq->nirq += n10g + n1g;
		if (iaq->nirq <= navail) {
			int leftover = navail - iaq->nirq;

			if (n10g > 0) {
				int target = max(nrxq10g, nofldrxq10g);

				n = 1;
				while (n < target && leftover >= n10g) {
					leftover -= n10g;
					iaq->nirq += n10g;
					n++;
				}
				iaq->nrxq10g = min(n, nrxq10g);
#ifdef TCP_OFFLOAD_ENABLE
				iaq->nofldrxq10g = min(n, nofldrxq10g);
#endif
			}

			if (n1g > 0) {
				int target = max(nrxq1g, nofldrxq1g);

				n = 1;
				while (n < target && leftover >= n1g) {
					leftover -= n1g;
					iaq->nirq += n1g;
					n++;
				}
				iaq->nrxq1g = min(n, nrxq1g);
#ifdef TCP_OFFLOAD_ENABLE
				iaq->nofldrxq1g = min(n, nofldrxq1g);
#endif
			}

			/* We have arrived at a minimum value required to enable
			 * per queue irq(either NIC or offload). Thus for non-
			 * offload case, we will get a vector per queue, while
			 * offload case, we will get a vector per offload/NIC q.
			 * Hence enable Interrupt forwarding only for offload
			 * case.
			 */
#ifdef TCP_OFFLOAD_ENABLE
			if (itype != DDI_INTR_TYPE_MSI || ISP2(iaq->nirq)) {
				iaq->intr_fwd = 1;
#else
			if (itype != DDI_INTR_TYPE_MSI) {
#endif
				goto allocate;
			}
		}

		/*
		 * Least desirable option: one interrupt vector for everything.
		 */
		iaq->nirq = iaq->nrxq10g = iaq->nrxq1g = 1;
#ifdef TCP_OFFLOAD_ENABLE
		iaq->nofldrxq10g = iaq->nofldrxq1g = 1;
#endif
		iaq->intr_fwd = 1;

allocate:
		return (0);
	}

	cxgb_printf(sc->dip, CE_WARN,
	    "failed to find a usable interrupt type.  supported=%d, allowed=%d",
	    itypes, p->intr_types);
	return (DDI_FAILURE);
}

static int
add_child_node(struct adapter *sc, int idx)
{
	int rc;
	struct port_info *pi;

	if (idx < 0 || idx >= sc->params.nports)
		return (EINVAL);

	pi = sc->port[idx];
	if (pi == NULL)
		return (ENODEV);	/* t4_port_init failed earlier */

	PORT_LOCK(pi);
	if (pi->dip != NULL) {
		rc = 0;		/* EEXIST really, but then bus_config fails */
		goto done;
	}

	rc = ndi_devi_alloc(sc->dip, T4_PORT_NAME, DEVI_SID_NODEID, &pi->dip);
	if (rc != DDI_SUCCESS || pi->dip == NULL) {
		rc = ENOMEM;
		goto done;
	}

	(void) ddi_set_parent_data(pi->dip, pi);
	(void) ndi_devi_bind_driver(pi->dip, 0);
	rc = 0;
done:
	PORT_UNLOCK(pi);
	return (rc);
}

static int
remove_child_node(struct adapter *sc, int idx)
{
	int rc;
	struct port_info *pi;

	if (idx < 0 || idx >= sc->params.nports)
		return (EINVAL);

	pi = sc->port[idx];
	if (pi == NULL)
		return (ENODEV);

	PORT_LOCK(pi);
	if (pi->dip == NULL) {
		rc = ENODEV;
		goto done;
	}

	rc = ndi_devi_free(pi->dip);
	if (rc == 0)
		pi->dip = NULL;
done:
	PORT_UNLOCK(pi);
	return (rc);
}

#define	KS_UINIT(x)	kstat_named_init(&kstatp->x, #x, KSTAT_DATA_ULONG)
#define	KS_CINIT(x)	kstat_named_init(&kstatp->x, #x, KSTAT_DATA_CHAR)
#define	KS_U_SET(x, y)	kstatp->x.value.ul = (y)
#define	KS_C_SET(x, ...)	\
			(void) snprintf(kstatp->x.value.c, 16,  __VA_ARGS__)

/*
 * t4nex:X:config
 */
struct t4_kstats {
	kstat_named_t chip_ver;
	kstat_named_t fw_vers;
	kstat_named_t tp_vers;
	kstat_named_t driver_version;
	kstat_named_t serial_number;
	kstat_named_t ec_level;
	kstat_named_t id;
	kstat_named_t bus_type;
	kstat_named_t bus_width;
	kstat_named_t bus_speed;
	kstat_named_t core_clock;
	kstat_named_t port_cnt;
	kstat_named_t port_type;
	kstat_named_t pci_vendor_id;
	kstat_named_t pci_device_id;
};
static kstat_t *
setup_kstats(struct adapter *sc)
{
	kstat_t *ksp;
	struct t4_kstats *kstatp;
	int ndata;
	struct pci_params *p = &sc->params.pci;
	struct vpd_params *v = &sc->params.vpd;
	uint16_t pci_vendor, pci_device;

	ndata = sizeof (struct t4_kstats) / sizeof (kstat_named_t);

	ksp = kstat_create(T4_NEXUS_NAME, ddi_get_instance(sc->dip), "config",
	    "nexus", KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(sc->dip, CE_WARN, "failed to initialize kstats.");
		return (NULL);
	}

	kstatp = (struct t4_kstats *)ksp->ks_data;

	KS_UINIT(chip_ver);
	KS_CINIT(fw_vers);
	KS_CINIT(tp_vers);
	KS_CINIT(driver_version);
	KS_CINIT(serial_number);
	KS_CINIT(ec_level);
	KS_CINIT(id);
	KS_CINIT(bus_type);
	KS_CINIT(bus_width);
	KS_CINIT(bus_speed);
	KS_UINIT(core_clock);
	KS_UINIT(port_cnt);
	KS_CINIT(port_type);
	KS_CINIT(pci_vendor_id);
	KS_CINIT(pci_device_id);

	KS_U_SET(chip_ver, sc->params.chip);
	KS_C_SET(fw_vers, "%d.%d.%d.%d",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.fw_vers));
	KS_C_SET(tp_vers, "%d.%d.%d.%d",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.tp_vers));
	KS_C_SET(driver_version, DRV_VERSION);
	KS_C_SET(serial_number, "%s", v->sn);
	KS_C_SET(ec_level, "%s", v->ec);
	KS_C_SET(id, "%s", v->id);
	KS_C_SET(bus_type, "pci-express");
	KS_C_SET(bus_width, "x%d lanes", p->width);
	KS_C_SET(bus_speed, "%d", p->speed);
	KS_U_SET(core_clock, v->cclk);
	KS_U_SET(port_cnt, sc->params.nports);

	t4_os_pci_read_cfg2(sc, PCI_CONF_VENID, &pci_vendor);
	KS_C_SET(pci_vendor_id, "0x%x", pci_vendor);

	t4_os_pci_read_cfg2(sc, PCI_CONF_DEVID, &pci_device);
	KS_C_SET(pci_device_id, "0x%x", pci_device);

	KS_C_SET(port_type, "%s/%s/%s/%s",
		 print_port_speed(sc->port[0]),
		 print_port_speed(sc->port[1]),
		 print_port_speed(sc->port[2]),
		 print_port_speed(sc->port[3]));

	/* Do NOT set ksp->ks_update.  These kstats do not change. */

	/* Install the kstat */
	ksp->ks_private = (void *)sc;
	kstat_install(ksp);

	return (ksp);
}

/*
 * t4nex:X:stat
 */
struct t4_wc_kstats {
	kstat_named_t write_coal_success;
	kstat_named_t write_coal_failure;
};
static kstat_t *
setup_wc_kstats(struct adapter *sc)
{
	kstat_t *ksp;
	struct t4_wc_kstats *kstatp;
	int ndata;

	ndata = sizeof(struct t4_wc_kstats) / sizeof(kstat_named_t);
	ksp = kstat_create(T4_NEXUS_NAME, ddi_get_instance(sc->dip), "stats",
	    "nexus", KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(sc->dip, CE_WARN, "failed to initialize kstats.");
		return (NULL);
	}

	kstatp = (struct t4_wc_kstats *)ksp->ks_data;

	KS_UINIT(write_coal_success);
	KS_UINIT(write_coal_failure);

	ksp->ks_update = update_wc_kstats;
	/* Install the kstat */
	ksp->ks_private = (void *)sc;
	kstat_install(ksp);

	return (ksp);
}

static int
update_wc_kstats(kstat_t *ksp, int rw)
{
	struct t4_wc_kstats *kstatp = (struct t4_wc_kstats *)ksp->ks_data;
	struct adapter *sc = ksp->ks_private;
	uint32_t wc_total, wc_success, wc_failure;

	if (rw == KSTAT_WRITE)
		return (0);

	if (is_t5(sc->params.chip)) {
		wc_total = t4_read_reg(sc, A_SGE_STAT_TOTAL);
		wc_failure = t4_read_reg(sc, A_SGE_STAT_MATCH);
		wc_success = wc_total - wc_failure;
	} else {
		wc_success = 0;
		wc_failure = 0;
	}

	KS_U_SET(write_coal_success, wc_success);
	KS_U_SET(write_coal_failure, wc_failure);

	return (0);
}

int
adapter_full_init(struct adapter *sc)
{
	int i, rc = 0;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	rc = t4_setup_adapter_queues(sc);
	if (rc != 0)
		goto done;

	if (sc->intr_cap & DDI_INTR_FLAG_BLOCK)
		(void) ddi_intr_block_enable(sc->intr_handle, sc->intr_count);
	else {
		for (i = 0; i < sc->intr_count; i++)
			(void) ddi_intr_enable(sc->intr_handle[i]);
	}
	t4_intr_enable(sc);
	sc->flags |= FULL_INIT_DONE;

#ifdef TCP_OFFLOAD_ENABLE
	/* TODO: wrong place to enable TOE capability */
	if (is_offload(sc) != 0) {
		for_each_port(sc, i) {
			struct port_info *pi = sc->port[i];
			rc = toe_capability(pi, 1);
			if (rc != 0) {
				cxgb_printf(pi->dip, CE_WARN,
				    "Failed to activate toe capability: %d",
				    rc);
				rc = 0;		/* not a fatal error */
			}
		}
	}
#endif

done:
	if (rc != 0)
		(void) adapter_full_uninit(sc);

	return (rc);
}

int
adapter_full_uninit(struct adapter *sc)
{
	int i, rc = 0;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	if (sc->intr_cap & DDI_INTR_FLAG_BLOCK)
		(void) ddi_intr_block_disable(sc->intr_handle, sc->intr_count);
	else {
		for (i = 0; i < sc->intr_count; i++)
			(void) ddi_intr_disable(sc->intr_handle[i]);
	}

	rc = t4_teardown_adapter_queues(sc);
	if (rc != 0)
		return (rc);

	sc->flags &= ~FULL_INIT_DONE;

	return (0);
}

int
port_full_init(struct port_info *pi)
{
	struct adapter *sc = pi->adapter;
	uint16_t *rss;
	struct sge_rxq *rxq;
	int rc, i;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);
	ASSERT((pi->flags & PORT_INIT_DONE) == 0);

	/*
	 * Allocate tx/rx/fl queues for this port.
	 */
	rc = t4_setup_port_queues(pi);
	if (rc != 0)
		goto done;	/* error message displayed already */

	/*
	 * Setup RSS for this port.
	 */
	rss = kmem_zalloc(pi->nrxq * sizeof (*rss), KM_SLEEP);
	for_each_rxq(pi, i, rxq) {
		rss[i] = rxq->iq.abs_id;
	}
	rc = -t4_config_rss_range(sc, sc->mbox, pi->viid, 0,
	    pi->rss_size, rss, pi->nrxq);
	kmem_free(rss, pi->nrxq * sizeof (*rss));
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "rss_config failed: %d", rc);
		goto done;
	}

	pi->flags |= PORT_INIT_DONE;
done:
	if (rc != 0)
		(void) port_full_uninit(pi);

	return (rc);
}

/*
 * Idempotent.
 */
int
port_full_uninit(struct port_info *pi)
{

	ASSERT(pi->flags & PORT_INIT_DONE);

	(void) t4_teardown_port_queues(pi);
	pi->flags &= ~PORT_INIT_DONE;

	return (0);
}

void
enable_port_queues(struct port_info *pi)
{
	struct adapter *sc = pi->adapter;
	int i;
	struct sge_iq *iq;
	struct sge_rxq *rxq;
#ifdef TCP_OFFLOAD_ENABLE
	struct sge_ofld_rxq *ofld_rxq;
#endif

	ASSERT(pi->flags & PORT_INIT_DONE);

	/*
	 * TODO: whatever was queued up after we set iq->state to IQS_DISABLED
	 * back in disable_port_queues will be processed now, after an unbounded
	 * delay.  This can't be good.
	 */

#ifdef TCP_OFFLOAD_ENABLE
	for_each_ofld_rxq(pi, i, ofld_rxq) {
		iq = &ofld_rxq->iq;
		if (atomic_cas_uint(&iq->state, IQS_DISABLED, IQS_IDLE) !=
		    IQS_DISABLED)
			panic("%s: iq %p wasn't disabled", __func__,
			    (void *)iq);
		t4_write_reg(sc, MYPF_REG(A_SGE_PF_GTS),
		    V_SEINTARM(iq->intr_params) | V_INGRESSQID(iq->cntxt_id));
	}
#endif

	for_each_rxq(pi, i, rxq) {
		iq = &rxq->iq;
		if (atomic_cas_uint(&iq->state, IQS_DISABLED, IQS_IDLE) !=
		    IQS_DISABLED)
			panic("%s: iq %p wasn't disabled", __func__,
			    (void *) iq);
		t4_write_reg(sc, MYPF_REG(A_SGE_PF_GTS),
		    V_SEINTARM(iq->intr_params) | V_INGRESSQID(iq->cntxt_id));
	}
}

void
disable_port_queues(struct port_info *pi)
{
	int i;
	struct adapter *sc = pi->adapter;
	struct sge_rxq *rxq;
#ifdef TCP_OFFLOAD_ENABLE
	struct sge_ofld_rxq *ofld_rxq;
#endif

	ASSERT(pi->flags & PORT_INIT_DONE);

	/*
	 * TODO: need proper implementation for all tx queues (ctrl, eth, ofld).
	 */

#ifdef TCP_OFFLOAD_ENABLE
	for_each_ofld_rxq(pi, i, ofld_rxq) {
		while (atomic_cas_uint(&ofld_rxq->iq.state, IQS_IDLE,
		    IQS_DISABLED) != IQS_IDLE)
			msleep(1);
	}
#endif

	for_each_rxq(pi, i, rxq) {
		while (atomic_cas_uint(&rxq->iq.state, IQS_IDLE,
		    IQS_DISABLED) != IQS_IDLE)
			msleep(1);
	}

	mutex_enter(&sc->sfl_lock);
#ifdef TCP_OFFLOAD_ENABLE
	for_each_ofld_rxq(pi, i, ofld_rxq)
	    ofld_rxq->fl.flags |= FL_DOOMED;
#endif
	for_each_rxq(pi, i, rxq)
	    rxq->fl.flags |= FL_DOOMED;
	mutex_exit(&sc->sfl_lock);
	/* TODO: need to wait for all fl's to be removed from sc->sfl */
}

void
t4_fatal_err(struct adapter *sc)
{
	t4_set_reg_field(sc, A_SGE_CONTROL, F_GLOBALENABLE, 0);
	t4_intr_disable(sc);
	cxgb_printf(sc->dip, CE_WARN,
	    "encountered fatal error, adapter stopped.");
}

int
t4_os_find_pci_capability(struct adapter *sc, int cap)
{
	uint16_t stat;
	uint8_t cap_ptr, cap_id;

	t4_os_pci_read_cfg2(sc, PCI_CONF_STAT, &stat);
	if ((stat & PCI_STAT_CAP) == 0)
		return (0); /* does not implement capabilities */

	t4_os_pci_read_cfg1(sc, PCI_CONF_CAP_PTR, &cap_ptr);
	while (cap_ptr) {
		t4_os_pci_read_cfg1(sc, cap_ptr + PCI_CAP_ID, &cap_id);
		if (cap_id == cap)
			return (cap_ptr); /* found */
		t4_os_pci_read_cfg1(sc, cap_ptr + PCI_CAP_NEXT_PTR, &cap_ptr);
	}

	return (0); /* not found */
}

void
t4_os_portmod_changed(const struct adapter *sc, int idx)
{
	static const char *mod_str[] = {
		NULL, "LR", "SR", "ER", "TWINAX", "active TWINAX", "LRM"
	};
	const struct port_info *pi = sc->port[idx];

	if (pi->mod_type == FW_PORT_MOD_TYPE_NONE)
		cxgb_printf(pi->dip, CE_NOTE, "transceiver unplugged.");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_UNKNOWN)
		cxgb_printf(pi->dip, CE_NOTE,
		    "unknown transceiver inserted.\n");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_NOTSUPPORTED)
		cxgb_printf(pi->dip, CE_NOTE,
		    "unsupported transceiver inserted.\n");
	else if (pi->mod_type > 0 && pi->mod_type < ARRAY_SIZE(mod_str))
		cxgb_printf(pi->dip, CE_NOTE, "%s transceiver inserted.\n",
		    mod_str[pi->mod_type]);
	else
		cxgb_printf(pi->dip, CE_NOTE, "transceiver (type %d) inserted.",
		    pi->mod_type);
}

/* ARGSUSED */
static int
cpl_not_handled(struct sge_iq *iq, const struct rss_header *rss, mblk_t *m)
{
	if (m != NULL)
		freemsg(m);
	return (0);
}

int
t4_register_cpl_handler(struct adapter *sc, int opcode, cpl_handler_t h)
{
	uint_t *loc, new;

	if (opcode >= ARRAY_SIZE(sc->cpl_handler))
		return (EINVAL);

	new = (uint_t)(unsigned long) (h ? h : cpl_not_handled);
	loc = (uint_t *)&sc->cpl_handler[opcode];
	(void) atomic_swap_uint(loc, new);

	return (0);
}

static int
fw_msg_not_handled(struct adapter *sc, const __be64 *data)
{
	struct cpl_fw6_msg *cpl = container_of(data, struct cpl_fw6_msg, data);

	cxgb_printf(sc->dip, CE_WARN, "%s fw_msg type %d", __func__, cpl->type);
	return (0);
}

int
t4_register_fw_msg_handler(struct adapter *sc, int type, fw_msg_handler_t h)
{
	fw_msg_handler_t *loc, new;

	if (type >= ARRAY_SIZE(sc->fw_msg_handler))
		return (EINVAL);

	/*
	 * These are dispatched by the handler for FW{4|6}_CPL_MSG using the CPL
	 * handler dispatch table.  Reject any attempt to install a handler for
	 * this subtype.
	 */
	if (type == FW_TYPE_RSSCPL || type == FW6_TYPE_RSSCPL)
		return (EINVAL);

	new = h ? h : fw_msg_not_handled;
	loc = &sc->fw_msg_handler[type];
	(void)atomic_swap_ptr(loc, (void *)new);

	return (0);
}

#ifdef TCP_OFFLOAD_ENABLE
static int
toe_capability(struct port_info *pi, int enable)
{
	int rc;
	struct adapter *sc = pi->adapter;

	if (!is_offload(sc))
		return (ENODEV);

	if (enable != 0) {
		if (isset(&sc->offload_map, pi->port_id) != 0)
			return (0);

		if (sc->offload_map == 0) {
			rc = activate_uld(sc, ULD_TOM, &sc->tom);
			if (rc != 0)
				return (rc);
		}

		setbit(&sc->offload_map, pi->port_id);
	} else {
		if (!isset(&sc->offload_map, pi->port_id))
			return (0);

		clrbit(&sc->offload_map, pi->port_id);

		if (sc->offload_map == 0) {
			rc = deactivate_uld(&sc->tom);
			if (rc != 0) {
				setbit(&sc->offload_map, pi->port_id);
				return (rc);
			}
		}
	}

	return (0);
}

/*
 * Add an upper layer driver to the global list.
 */
int
t4_register_uld(struct uld_info *ui)
{
	int rc = 0;
	struct uld_info *u;

	mutex_enter(&t4_uld_list_lock);
	SLIST_FOREACH(u, &t4_uld_list, link) {
		if (u->uld_id == ui->uld_id) {
			rc = EEXIST;
			goto done;
		}
	}

	SLIST_INSERT_HEAD(&t4_uld_list, ui, link);
	ui->refcount = 0;
done:
	mutex_exit(&t4_uld_list_lock);
	return (rc);
}

int
t4_unregister_uld(struct uld_info *ui)
{
	int rc = EINVAL;
	struct uld_info *u;

	mutex_enter(&t4_uld_list_lock);

	SLIST_FOREACH(u, &t4_uld_list, link) {
		if (u == ui) {
			if (ui->refcount > 0) {
				rc = EBUSY;
				goto done;
			}

			SLIST_REMOVE(&t4_uld_list, ui, uld_info, link);
			rc = 0;
			goto done;
		}
	}
done:
	mutex_exit(&t4_uld_list_lock);
	return (rc);
}

static int
activate_uld(struct adapter *sc, int id, struct uld_softc *usc)
{
	int rc = EAGAIN;
	struct uld_info *ui;

	mutex_enter(&t4_uld_list_lock);

	SLIST_FOREACH(ui, &t4_uld_list, link) {
		if (ui->uld_id == id) {
			rc = ui->attach(sc, &usc->softc);
			if (rc == 0) {
				ASSERT(usc->softc != NULL);
				ui->refcount++;
				usc->uld = ui;
			}
			goto done;
		}
	}
done:
	mutex_exit(&t4_uld_list_lock);

	return (rc);
}

static int
deactivate_uld(struct uld_softc *usc)
{
	int rc;

	mutex_enter(&t4_uld_list_lock);

	if (usc->uld == NULL || usc->softc == NULL) {
		rc = EINVAL;
		goto done;
	}

	rc = usc->uld->detach(usc->softc);
	if (rc == 0) {
		ASSERT(usc->uld->refcount > 0);
		usc->uld->refcount--;
		usc->uld = NULL;
		usc->softc = NULL;
	}
done:
	mutex_exit(&t4_uld_list_lock);

	return (rc);
}

void
t4_iterate(void (*func)(int, void *), void *arg)
{
	struct adapter *sc;

	mutex_enter(&t4_adapter_list_lock);
	SLIST_FOREACH(sc, &t4_adapter_list, link) {
		/*
		 * func should not make any assumptions about what state sc is
		 * in - the only guarantee is that sc->sc_lock is a valid lock.
		 */
		func(ddi_get_instance(sc->dip), arg);
	}
	mutex_exit(&t4_adapter_list_lock);
}

#endif
