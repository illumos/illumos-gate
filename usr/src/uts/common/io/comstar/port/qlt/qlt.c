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
 * Copyright 2009-2015 QLogic Corporation.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2009, 2015, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/scsi/scsi.h>

#include <sys/stmf_defines.h>
#include <sys/fct_defines.h>
#include <sys/stmf.h>
#include <sys/portif.h>
#include <sys/fct.h>

#include "qlt.h"
#include "qlt_dma.h"
#include "qlt_ioctl.h"
#include "qlt_open.h"
#include <sys/stmf_ioctl.h>

static int qlt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int qlt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static uint8_t *qlt_vpd_findtag(qlt_state_t *qlt, uint8_t *vpdbuf,
    int8_t *opcode);
static int qlt_vpd_lookup(qlt_state_t *qlt, uint8_t *opcode, uint8_t *bp,
    int32_t bplen);
static void qlt_enable_intr(qlt_state_t *);
static void qlt_disable_intr(qlt_state_t *);
static fct_status_t qlt_reset_chip(qlt_state_t *qlt);
static fct_status_t qlt_download_fw(qlt_state_t *qlt);
static fct_status_t qlt_load_risc_ram(qlt_state_t *qlt, uint32_t *host_addr,
    uint32_t word_count, uint32_t risc_addr);
static fct_status_t qlt_raw_mailbox_command(qlt_state_t *qlt);
static mbox_cmd_t *qlt_alloc_mailbox_command(qlt_state_t *qlt,
    uint32_t dma_size);
void qlt_free_mailbox_command(qlt_state_t *qlt, mbox_cmd_t *mcp);
static fct_status_t qlt_mailbox_command(qlt_state_t *qlt, mbox_cmd_t *mcp);
static uint_t qlt_isr(caddr_t arg, caddr_t arg2);
static uint_t qlt_msix_resp_handler(caddr_t arg, caddr_t arg2);
static uint_t qlt_msix_default_handler(caddr_t arg, caddr_t arg2);
static fct_status_t qlt_firmware_dump(fct_local_port_t *port,
    stmf_state_change_info_t *ssci);
static void qlt_handle_inot(qlt_state_t *qlt, uint8_t *inot);
static void qlt_handle_purex(qlt_state_t *qlt, uint8_t *resp);
static void qlt_handle_atio(qlt_state_t *qlt, uint8_t *atio);
static void qlt_handle_ctio_completion(qlt_state_t *qlt, uint8_t *rsp,
    uint16_t qi);
static void qlt_handle_sol_abort_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_dereg_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_unsol_els_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_unsol_els_abort_completion(qlt_state_t *qlt,
    uint8_t *rsp);
static void qlt_handle_sol_els_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_rcvd_abts(qlt_state_t *qlt, uint8_t *resp, uint16_t qi);
static void qlt_handle_abts_completion(qlt_state_t *qlt, uint8_t *resp,
    uint16_t qi);
static fct_status_t qlt_read_nvram(qlt_state_t *qlt);
static fct_status_t qlt_read_vpd(qlt_state_t *qlt);
static fct_status_t qlt_read_rom_image(qlt_state_t *qlt);
static void qlt_verify_fw(qlt_state_t *qlt);
static void qlt_handle_verify_fw_completion(qlt_state_t *qlt, uint8_t *rsp);
fct_status_t qlt_port_start(caddr_t arg);
fct_status_t qlt_port_stop(caddr_t arg);
fct_status_t qlt_port_online(qlt_state_t *qlt);
fct_status_t qlt_port_offline(qlt_state_t *qlt);
static fct_status_t qlt_get_link_info(fct_local_port_t *port,
    fct_link_info_t *li);
static void qlt_ctl(struct fct_local_port *port, int cmd, void *arg);
static fct_status_t qlt_force_lip(qlt_state_t *);
static fct_status_t qlt_do_flogi(struct fct_local_port *port,
    fct_flogi_xchg_t *fx);
void qlt_handle_atio_queue_update(qlt_state_t *qlt);
void qlt_handle_resp_queue_update(qlt_state_t *qlt, uint16_t qi);
fct_status_t qlt_register_remote_port(fct_local_port_t *port,
    fct_remote_port_t *rp, fct_cmd_t *login);
fct_status_t qlt_deregister_remote_port(fct_local_port_t *port,
    fct_remote_port_t *rp);
fct_status_t qlt_send_cmd_response(fct_cmd_t *cmd, uint32_t ioflags);
fct_status_t qlt_send_els_response(qlt_state_t *qlt, fct_cmd_t *cmd);
fct_status_t qlt_send_abts_response(qlt_state_t *qlt,
    fct_cmd_t *cmd, int terminate);
static void qlt_handle_inot(qlt_state_t *qlt, uint8_t *inot);
int qlt_set_uniq_flag(uint16_t *ptr, uint16_t setf, uint16_t abortf);
fct_status_t qlt_abort_cmd(struct fct_local_port *port,
    fct_cmd_t *cmd, uint32_t flags);
fct_status_t qlt_abort_sol_cmd(qlt_state_t *qlt, fct_cmd_t *cmd);
fct_status_t qlt_abort_purex(qlt_state_t *qlt, fct_cmd_t *cmd);
fct_status_t qlt_abort_unsol_scsi_cmd(qlt_state_t *qlt, fct_cmd_t *cmd);
fct_status_t qlt_send_cmd(fct_cmd_t *cmd);
fct_status_t qlt_send_els(qlt_state_t *qlt, fct_cmd_t *cmd);
fct_status_t qlt_send_status(qlt_state_t *qlt, fct_cmd_t *cmd);
fct_status_t qlt_xfer_scsi_data(fct_cmd_t *cmd,
    stmf_data_buf_t *dbuf, uint32_t ioflags);
fct_status_t qlt_send_ct(qlt_state_t *qlt, fct_cmd_t *cmd);
static void qlt_handle_ct_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_release_intr(qlt_state_t *qlt);
static int qlt_setup_interrupts(qlt_state_t *qlt);
static void qlt_destroy_mutex(qlt_state_t *qlt);

static fct_status_t qlt_read_risc_ram(qlt_state_t *qlt, uint32_t addr,
    uint32_t words);
static fct_status_t qlt_mbx_mpi_ram(qlt_state_t *qlt, uint32_t addr,
    uint32_t words, uint16_t direction);
static int qlt_dump_queue(qlt_state_t *qlt, caddr_t qadr, int entries,
    caddr_t buf, uint_t size_left);
static int qlt_dump_risc_ram(qlt_state_t *qlt, uint32_t addr, uint32_t words,
    caddr_t buf, uint_t size_left);
static int qlt_fwdump_dump_regs(qlt_state_t *qlt, caddr_t buf, int startaddr,
    int count, uint_t size_left);
static int qlt_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
static int qlt_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int qlt_close(dev_t dev, int flag, int otype, cred_t *credp);

static int qlt_setup_msi(qlt_state_t *qlt);
static int qlt_setup_msix(qlt_state_t *qlt);

static int qlt_el_trace_desc_ctor(qlt_state_t *qlt);
static int qlt_el_trace_desc_dtor(qlt_state_t *qlt);

static int qlt_read_int_prop(qlt_state_t *qlt, char *prop, int defval);
static int qlt_read_string_prop(qlt_state_t *qlt, char *prop, char **prop_val);
static int qlt_read_string_instance_prop(qlt_state_t *qlt, char *prop,
    char **prop_val);
static int qlt_read_int_instance_prop(qlt_state_t *, char *, int);
static int qlt_convert_string_to_ull(char *prop, int radix,
    u_longlong_t *result);
static boolean_t qlt_wwn_overload_prop(qlt_state_t *qlt);
static int qlt_quiesce(dev_info_t *dip);
static void qlt_disable_intr(qlt_state_t *qlt);
static fct_status_t qlt_raw_wrt_risc_ram_word(qlt_state_t *qlt, uint32_t,
    uint32_t);
static fct_status_t qlt_raw_rd_risc_ram_word(qlt_state_t *qlt, uint32_t,
    uint32_t *);
static void qlt_mps_reset(qlt_state_t *qlt);
static void qlt_properties(qlt_state_t *qlt);

static fct_status_t qlt_mq_create(qlt_state_t *qlt, int idx);
static fct_status_t qlt_mq_destroy(qlt_state_t *qlt);

static fct_status_t qlt_27xx_get_dmp_template(qlt_state_t *);
static uint32_t qlt_27xx_dmp_parse_template(qlt_state_t *, qlt_dt_hdr_t *,
	uint8_t *, uint32_t);
static int qlt_27xx_dump_ram(qlt_state_t *, uint16_t, uint32_t,
	uint32_t, uint8_t *);

#define	SETELSBIT(bmp, els)	(bmp)[((els) >> 3) & 0x1F] = \
	(uint8_t)((bmp)[((els) >> 3) & 0x1F] | ((uint8_t)1) << ((els) & 7))

int qlt_enable_msix = 1;
int qlt_enable_msi = 1;


string_table_t prop_status_tbl[] = DDI_PROP_STATUS();

/* Array to quickly calculate next free buf index to use */
#if 0
static int qlt_nfb[] = { 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 0xff };
#endif

static struct cb_ops qlt_cb_ops = {
	qlt_open,
	qlt_close,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	qlt_ioctl,
	nodev,
	nodev,
	nodev,
	nochpoll,
	ddi_prop_op,
	0,
	D_MP | D_NEW
};

static struct dev_ops qlt_ops = {
	DEVO_REV,
	0,
	nodev,
	nulldev,
	nulldev,
	qlt_attach,
	qlt_detach,
	nodev,
	&qlt_cb_ops,
	NULL,
	ddi_power,
	qlt_quiesce
};

#ifndef	PORT_SPEED_16G
#define	PORT_SPEED_16G		32
#endif

#ifndef	PORT_SPEED_32G
#define	PORT_SPEED_32G		64
#endif

#ifndef QL_NAME
#define	QL_NAME "qlt"
#endif

static struct modldrv modldrv = {
	&mod_driverops,
	QLT_NAME" "QLT_VERSION,
	&qlt_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

void *qlt_state = NULL;
kmutex_t qlt_global_lock;
static	uint32_t qlt_loaded_counter = 0;
uint8_t qlt_reprocess_attempt_cnt = 5;
uint32_t qlt_reprocess_delay = 75;	/* default 75 microseconds */

static char *pci_speeds[] = { " 33", "-X Mode 1 66", "-X Mode 1 100",
			"-X Mode 1 133", "--Invalid--",
			"-X Mode 2 66", "-X Mode 2 100",
			"-X Mode 2 133", " 66" };

/* Always use 64 bit DMA. */
static ddi_dma_attr_t qlt_queue_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* low DMA address range */
	0xffffffffffffffff,	/* high DMA address range */
	0xffffffff,		/* DMA counter register */
	64,			/* DMA address alignment */
	0xff,			/* DMA burstsizes */
	1,			/* min effective DMA size */
	0xffffffff,		/* max DMA xfer size */
	0xffffffff,		/* segment boundary */
	1,			/* s/g list length */
	1,			/* granularity of device */
	0			/* DMA transfer flags */
};


/* Always use 64 bit DMA. */
static ddi_dma_attr_t qlt_queue_dma_attr_mq_req1 = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* low DMA address range */
	0xffffffffffffffff,	/* high DMA address range */
	0xffffffff,		/* DMA counter register */
	64,			/* DMA address alignment */
	0xff,			/* DMA burstsizes */
	1,			/* min effective DMA size */
	0xffffffff,		/* max DMA xfer size */
	0xffffffff,		/* segment boundary */
	1,			/* s/g list length */
	1,			/* granularity of device */
	0			/* DMA transfer flags */
};

/* Always use 64 bit DMA. */
static ddi_dma_attr_t qlt_queue_dma_attr_mq_rsp1 = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* low DMA address range */
	0xffffffffffffffff,	/* high DMA address range */
	0xffffffff,		/* DMA counter register */
	64,			/* DMA address alignment */
	0xff,			/* DMA burstsizes */
	1,			/* min effective DMA size */
	0xffffffff,		/* max DMA xfer size */
	0xffffffff,		/* segment boundary */
	1,			/* s/g list length */
	1,			/* granularity of device */
	0			/* DMA transfer flags */
};


/* qlogic logging */
int enable_extended_logging = 0;
static char qlt_provider_name[] = "qlt";
static struct stmf_port_provider *qlt_pp;

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&qlt_state, sizeof (qlt_state_t), 0);
	if (ret == 0) {
		mutex_init(&qlt_global_lock, 0, MUTEX_DRIVER, 0);
		qlt_pp = (stmf_port_provider_t *)stmf_alloc(
		    STMF_STRUCT_PORT_PROVIDER, 0, 0);
		qlt_pp->pp_portif_rev = PORTIF_REV_1;
		qlt_pp->pp_name = qlt_provider_name;
		if (stmf_register_port_provider(qlt_pp) != STMF_SUCCESS) {
			stmf_free(qlt_pp);
			mutex_destroy(&qlt_global_lock);
			ddi_soft_state_fini(&qlt_state);
			return (EIO);
		}
		ret = mod_install(&modlinkage);
		if (ret != 0) {
			(void) stmf_deregister_port_provider(qlt_pp);
			stmf_free(qlt_pp);
			mutex_destroy(&qlt_global_lock);
			ddi_soft_state_fini(&qlt_state);
		}
	}
	return (ret);
}

int
_fini(void)
{
	int ret;

	if (qlt_loaded_counter)
		return (EBUSY);
	ret = mod_remove(&modlinkage);
	if (ret == 0) {
		(void) stmf_deregister_port_provider(qlt_pp);
		stmf_free(qlt_pp);
		mutex_destroy(&qlt_global_lock);
		ddi_soft_state_fini(&qlt_state);
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
qlt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	qlt_state_t	*qlt;
	ddi_device_acc_attr_t	dev_acc_attr;
	uint16_t	did;
	uint16_t	val;
	uint16_t	mr;
	size_t		discard;
	uint_t		ncookies;
	int		max_read_size;
	int		max_payload_size;
	fct_status_t	ret;

	/* No support for suspend resume yet */
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	instance = ddi_get_instance(dip);

	cmn_err(CE_CONT, "!Qlogic %s(%d) FCA Driver v%s\n",
	    QLT_NAME, instance, QLT_VERSION);

	if (ddi_soft_state_zalloc(qlt_state, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qlt(%d): soft state alloc failed", instance);
		return (DDI_FAILURE);
	}

	if ((qlt = (qlt_state_t *)ddi_get_soft_state(qlt_state, instance)) ==
	    NULL) {
		cmn_err(CE_WARN, "qlt(%d): can't get soft state", instance);
		goto attach_fail_1;
	}

	qlt->instance = instance;

	qlt->nvram = (qlt_nvram_t *)kmem_zalloc(sizeof (qlt_nvram_t), KM_SLEEP);
	qlt->vpd = (uint32_t *)kmem_zalloc(QL_24XX_VPD_SIZE, KM_SLEEP);
	qlt->dip = dip;

	if (qlt_el_trace_desc_ctor(qlt) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qlt(%d): can't setup el tracing", instance);
		goto attach_fail_2;
	}

	EL(qlt, "instance=%d, ptr=%p\n", instance, (void *)qlt);

	if (pci_config_setup(dip, &qlt->pcicfg_acc_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qlt(%d): pci_config_setup failed", instance);
		goto attach_fail_3;
	}

	did = PCICFG_RD16(qlt, PCI_CONF_DEVID);
	if ((did != 0x2422) && (did != 0x2432) &&
	    (did != 0x8432) && (did != 0x2532) &&
	    (did != 0x8001) && (did != 0x2031) &&
	    (did != 0x2071) && (did != 0x2261)) {
		cmn_err(CE_WARN, "qlt(%d): unknown devid(%x), failing attach",
		    instance, did);
		goto attach_fail_4;
	}

	if ((did & 0xFFFF) == 0x2071) {
		qlt->qlt_27xx_chip = 1;
		qlt->qlt_fcoe_enabled = 0;
	} else if ((did & 0xFFFF) == 0x2261) {
		qlt->qlt_27xx_chip = 1;
		qlt->qlt_fcoe_enabled = 0;
	} else if ((did & 0xFFFF) == 0x2031) {
		qlt->qlt_83xx_chip = 1;
		qlt->qlt_fcoe_enabled = 0;
	} else if ((did & 0xFFF0) == 0x8000) {
		qlt->qlt_81xx_chip = 1;
		qlt->qlt_fcoe_enabled = 1;
	} else if ((did & 0xFF00) == 0x2500)
		qlt->qlt_25xx_chip = 1;

	dev_acc_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_acc_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	dev_acc_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		int stat_1;
		off_t regsize_1;

		stat_1 = ddi_dev_regsize(dip, 1, &regsize_1);
		if (stat_1 != DDI_SUCCESS) {
			stmf_trace(qlt->qlt_port_alias,
			    "instance=%d, reg 1 regsize failed,"
			    " stat %x", instance, stat_1);
			goto attach_fail_4;
		}

		if (ddi_regs_map_setup(dip, 1, &qlt->regs, 0, regsize_1,
		    &dev_acc_attr, &qlt->regs_acc_handle) != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "qlt(%d) ddi_regs_map_setup failed\n",
			    instance);
			goto attach_fail_4;
		}
	} else {
		/*
		 * 24xx and 25xx: rnumber 0 is config space
		 * rnumber 1 is for IO space
		 * rnumber 2 is for MBAR0: ISP, MSIX, PBA
		 */
		if (ddi_regs_map_setup(dip, 2, &qlt->regs, 0, 0x100,
		    &dev_acc_attr, &qlt->regs_acc_handle) != DDI_SUCCESS) {
			goto attach_fail_4;
		}
	}

	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {

		uint32_t w32h;
		uint32_t w32l;
		int stat;
		off_t regsize;

		w32l = PCICFG_RD32(qlt, PCI_CONF_BASE2);
		w32h = PCICFG_RD32(qlt, PCI_CONF_BASE3);

		if ((w32h > 0) || w32l > 0) {
			stat = ddi_dev_regsize(dip, 2, &regsize);
			if (stat != DDI_SUCCESS) {
				stmf_trace(qlt->qlt_port_alias,
				    "instance=%d, MSI-X regsize failed,"
				    " stat %x", instance, stat);
			}
			stmf_trace(qlt->qlt_port_alias,
			    "instance=%d, MSI-X MEM Bar size %x",
			    instance, regsize);

			stat = ddi_regs_map_setup(dip, 2, &qlt->msix_base, 0,
			    /* ((MQ_MAX_QUEUES * 2) +1) << 2, */
			    regsize,
			    &dev_acc_attr, &qlt->msix_acc_handle);

			if (stat != DDI_SUCCESS || qlt->msix_base == NULL ||
			    qlt->msix_acc_handle == NULL) {

				cmn_err(CE_WARN,
				    "qlt(%d): can't map MBar for MSI-X",
				    instance);
				stmf_trace(qlt->qlt_port_alias,
				    "instance=%d, MSI-X MEM Bar map fail",
				    instance);

				if (qlt->msix_acc_handle != NULL) {
					ddi_regs_map_free(
					    &qlt->msix_acc_handle);
				}
				goto attach_fail_5;
			}
		} else {
			cmn_err(CE_WARN, "qlt(%d): can't setup MBar for MSI-X",
			    instance);
			stmf_trace(qlt->qlt_port_alias,
			    "instance=%d, No MSI-X MEM Bar", instance);
			goto attach_fail_5;
		}

		w32l = PCICFG_RD32(qlt, PCI_CONF_BASE4);
		w32h = PCICFG_RD32(qlt, PCI_CONF_BASE5);

		if ((w32h > 0) || w32l > 0) {
			stat = ddi_dev_regsize(dip, 3, &regsize);
			if (stat != DDI_SUCCESS) {
				stmf_trace(qlt->qlt_port_alias,
				    "instance=%d, MQ regsize failed, stat %x",
				    instance, stat);
			}
			stmf_trace(qlt->qlt_port_alias,
			    "instance=%d, MQ MEM Bar size %x",
			    instance, regsize);

			/* for 83xx the QP pointers are in the 3rd MBar */
			stat = ddi_regs_map_setup(dip, 3, &qlt->mq_reg_base, 0,
			    (MQ_MAX_QUEUES * MQBAR_REG_OFFSET),
			    &dev_acc_attr, &qlt->mq_reg_acc_handle);

			if (stat != DDI_SUCCESS || qlt->mq_reg_base == NULL ||
			    qlt->mq_reg_acc_handle == NULL) {

				cmn_err(CE_WARN, "qlt(%d): can't map QP MBar",
				    instance);
				stmf_trace(qlt->qlt_port_alias,
				    "instance=%d, QP MEM Bar map fail st:%x",
				    instance, stat);

				if (qlt->msix_acc_handle != NULL) {
					ddi_regs_map_free(
					    &qlt->msix_acc_handle);
				}
				if (qlt->mq_reg_acc_handle != NULL) {
					ddi_regs_map_free(
					    &qlt->mq_reg_acc_handle);
				}
				goto attach_fail_5;
			} else {
				qlt->qlt_mq_enabled = 1;
			}
		} else {
			cmn_err(CE_WARN, "qlt(%d): can't setup MBar for QPs",
			    instance);
			stmf_trace(qlt->qlt_port_alias,
			    "instance=%d, No QPs MEM Bar", instance);

			if (qlt->msix_acc_handle != NULL) {
				ddi_regs_map_free(
				    &qlt->msix_acc_handle);
			}
			goto attach_fail_5;
		}
	} else if (qlt->qlt_81xx_chip) {

		uint32_t w32;
		int stat;

		w32 = PCICFG_RD32(qlt, PCI_CONF_BASE3);
		if (w32 == 0) {

			cmn_err(CE_WARN, "qlt(%d): can't setup MBar2",
			    instance);
			stmf_trace(qlt->qlt_port_alias,
			    "instance=%d, No MEM Bar2", instance);
			goto attach_fail_5;
		}

		stat = ddi_regs_map_setup(dip, 3, &qlt->mq_reg_base, 0,
		    (MQ_MAX_QUEUES * MQBAR_REG_OFFSET),
		    &dev_acc_attr, &qlt->mq_reg_acc_handle);

		if (stat != DDI_SUCCESS || qlt->mq_reg_base == NULL ||
		    qlt->mq_reg_acc_handle == NULL) {

			cmn_err(CE_WARN, "qlt(%d): can't map MBar2",
			    instance);
			stmf_trace(qlt->qlt_port_alias,
			    "instance=%d, MEM Bar2 map fail", instance);

			if (qlt->mq_reg_acc_handle != NULL) {
				ddi_regs_map_free(&qlt->mq_reg_acc_handle);
			}
			goto attach_fail_5;
		} else {
			qlt->qlt_mq_enabled = 1;
		}
	} else if (qlt->qlt_25xx_chip) {
		uint32_t w32h;
		uint32_t w32l;
		int stat;
		off_t regsize;

		/* MBAR2 rnumber 3 */
		w32l = PCICFG_RD32(qlt, PCI_CONF_BASE3);
		w32h = PCICFG_RD32(qlt, PCI_CONF_BASE4);

		if ((w32h > 0) || (w32l > 0)) {
			stat = ddi_dev_regsize(dip, 3, &regsize);
			if (stat != DDI_SUCCESS) {
				stmf_trace(qlt->qlt_port_alias,
				"ISP25xx inst=%d, MQ regsize failed, stat %x",
				    instance, stat);
				EL(qlt, "ISP25xx MQ regsize failed, stat %x\n",
				    stat);

			}
			stmf_trace(qlt->qlt_port_alias,
			    "ISP25xx instance=%d, MQ MEM Bar size %lx",
			    instance, regsize);
			EL(qlt, "ISP25xx MQ MEM Bar (MBAR2) size: %x\n",
			    regsize);

			stat = ddi_regs_map_setup(dip, 3, &qlt->mq_reg_base, 0,
			    (MQ_MAX_QUEUES * MQBAR_REG_OFFSET),
			    &dev_acc_attr, &qlt->mq_reg_acc_handle);
			if (stat != DDI_SUCCESS || qlt->mq_reg_base == NULL ||
			    qlt->mq_reg_acc_handle == NULL) {
				cmn_err(CE_WARN,
				    "qlt(%d): ISP25xx can't map QP MBar",
				    instance);
				stmf_trace(qlt->qlt_port_alias,
				    "instance=%d, QP MEM Bar map fail st:%x",
				    instance, stat);
				if (qlt->mq_reg_acc_handle != NULL) {
					ddi_regs_map_free(
					    &qlt->mq_reg_acc_handle);
				}
			} else {
				qlt->qlt_mq_enabled = 1;
			}
		} else {
			stmf_trace(qlt->qlt_port_alias,
			    "instance=%d, No QPs MEM Bar", instance);
			EL(qlt,
			    "ISP25xx can't setup MBar QPs, use baseq\n");
		}
	}

	if (qlt->qlt_mq_enabled) {
		qlt->mq_req = kmem_zalloc(
		    ((sizeof (qlt_mq_req_ptr_blk_t)) * MQ_MAX_QUEUES),
		    KM_SLEEP);
		qlt->mq_resp = kmem_zalloc(
		    ((sizeof (qlt_mq_rsp_ptr_blk_t)) * MQ_MAX_QUEUES),
		    KM_SLEEP);
	} else {
		qlt->mq_req = kmem_zalloc(
		    (sizeof (qlt_mq_req_ptr_blk_t)), KM_SLEEP);
		qlt->mq_resp = kmem_zalloc(
		    (sizeof (qlt_mq_rsp_ptr_blk_t)), KM_SLEEP);
	}

	if (did == 0x2422) {
		uint32_t pci_bits = REG_RD32(qlt, REG_CTRL_STATUS);
		uint32_t slot = pci_bits & PCI_64_BIT_SLOT;
		pci_bits >>= 8;
		pci_bits &= 0xf;
		if ((pci_bits == 3) || (pci_bits == 7)) {
			cmn_err(CE_NOTE,
			    "!qlt(%d): HBA running at PCI%sMHz (%d)",
			    instance, pci_speeds[pci_bits], pci_bits);
		} else {
			cmn_err(CE_WARN,
			    "qlt(%d): HBA running at PCI%sMHz %s(%d)",
			    instance, (pci_bits <= 8) ? pci_speeds[pci_bits] :
			    "(Invalid)", ((pci_bits == 0) ||
			    (pci_bits == 8)) ? (slot ? "64 bit slot " :
			    "32 bit slot ") : "", pci_bits);
		}
	}
	if ((ret = qlt_read_nvram(qlt)) != QLT_SUCCESS) {
		cmn_err(CE_WARN, "qlt(%d): read nvram failure %llx", instance,
		    (unsigned long long)ret);
		goto attach_fail_5;
	}
	if ((ret = qlt_read_vpd(qlt)) != QLT_SUCCESS) {
		cmn_err(CE_WARN, "qlt(%d): read vpd failure %llx", instance,
		    (unsigned long long)ret);
		goto attach_fail_5;
	}
	if ((ret = qlt_read_rom_image(qlt)) != QLT_SUCCESS) {
		cmn_err(CE_WARN, "qlt(%d): read rom image failure %llx",
		    instance, (unsigned long long)ret);
		goto attach_fail_5;
	}

	qlt_properties(qlt);

	if (ddi_dma_alloc_handle(dip, &qlt_queue_dma_attr, DDI_DMA_SLEEP,
	    0, &qlt->queue_mem_dma_handle) != DDI_SUCCESS) {
		goto attach_fail_5;
	}
	if (ddi_dma_mem_alloc(qlt->queue_mem_dma_handle, TOTAL_DMA_MEM_SIZE,
	    &dev_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &qlt->queue_mem_ptr, &discard, &qlt->queue_mem_acc_handle) !=
	    DDI_SUCCESS) {
		goto attach_fail_6;
	}
	if (ddi_dma_addr_bind_handle(qlt->queue_mem_dma_handle, NULL,
	    qlt->queue_mem_ptr, TOTAL_DMA_MEM_SIZE,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &qlt->queue_mem_cookie, &ncookies) != DDI_SUCCESS) {
		goto attach_fail_7;
	}
	if (ncookies != 1)
		goto attach_fail_8;

	/*
	 * Base queue (0), alwasy available
	 */
	qlt->mq_req[0].queue_mem_mq_base_addr =
	    qlt->mq_req[0].mq_ptr =
	    qlt->queue_mem_ptr + REQUEST_QUEUE_OFFSET;
	qlt->mq_resp[0].queue_mem_mq_base_addr =
	    qlt->mq_resp[0].mq_ptr =
	    qlt->queue_mem_ptr + RESPONSE_QUEUE_OFFSET;

	qlt->preq_ptr = qlt->queue_mem_ptr + PRIORITY_QUEUE_OFFSET;
	qlt->atio_ptr = qlt->queue_mem_ptr + ATIO_QUEUE_OFFSET;

	/* mutex are inited in this function */
	if (qlt_setup_interrupts(qlt) != DDI_SUCCESS)
		goto attach_fail_8;

	qlt->qlt_queue_cnt = 1;
	if ((qlt->qlt_mq_enabled) && (qlt->intr_cnt > 1)) {
		int i;

		for (i = 1; i < qlt->intr_cnt; i++) {
			if (qlt_mq_create(qlt, i) != QLT_SUCCESS) {
				cmn_err(CE_WARN, "qlt(%d) mq create (%d) "
				    "failed\n", qlt->instance, i);
				break;
			}
			qlt->qlt_queue_cnt++;
			if (qlt->qlt_queue_cnt >= MQ_MAX_QUEUES)
				break;
		}
	}
	EL(qlt, "Queue count = %d\n", qlt->qlt_queue_cnt);

	(void) snprintf(qlt->qlt_minor_name, sizeof (qlt->qlt_minor_name),
	    "qlt%d", instance);
	(void) snprintf(qlt->qlt_port_alias, sizeof (qlt->qlt_port_alias),
	    "%s,0", qlt->qlt_minor_name);

	if (ddi_create_minor_node(dip, qlt->qlt_minor_name, S_IFCHR,
	    instance, DDI_NT_STMF_PP, 0) != DDI_SUCCESS) {
		goto attach_fail_9;
	}

	cv_init(&qlt->rp_dereg_cv, NULL, CV_DRIVER, NULL);
	cv_init(&qlt->mbox_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&qlt->qlt_ioctl_lock, NULL, MUTEX_DRIVER, NULL);

	/* Setup PCI cfg space registers */
	max_read_size = qlt_read_int_prop(qlt, "pci-max-read-request", 11);
	if (max_read_size == 11)
		goto over_max_read_xfer_setting;
	if (did == 0x2422) {
		if (max_read_size == 512)
			val = 0;
		else if (max_read_size == 1024)
			val = 1;
		else if (max_read_size == 2048)
			val = 2;
		else if (max_read_size == 4096)
			val = 3;
		else {
			cmn_err(CE_WARN, "qlt(%d) malformed "
			    "pci-max-read-request in qlt.conf. Valid values "
			    "for this HBA are 512/1024/2048/4096", instance);
			goto over_max_read_xfer_setting;
		}
		mr = (uint16_t)PCICFG_RD16(qlt, 0x4E);
		mr = (uint16_t)(mr & 0xfff3);
		mr = (uint16_t)(mr | (val << 2));
		PCICFG_WR16(qlt, 0x4E, mr);
	} else if ((did == 0x2432) || (did == 0x8432) ||
	    (did == 0x2532) || (did == 0x8001) ||
	    (did == 0x2031) || (did == 0x2071) ||
	    (did == 0x2261)) {
		if (max_read_size == 128)
			val = 0;
		else if (max_read_size == 256)
			val = 1;
		else if (max_read_size == 512)
			val = 2;
		else if (max_read_size == 1024)
			val = 3;
		else if (max_read_size == 2048)
			val = 4;
		else if (max_read_size == 4096)
			val = 5;
		else {
			cmn_err(CE_WARN, "qlt(%d) malformed "
			    "pci-max-read-request in qlt.conf. Valid values "
			    "for this HBA are 128/256/512/1024/2048/4096",
			    instance);
			goto over_max_read_xfer_setting;
		}
		mr = (uint16_t)PCICFG_RD16(qlt, 0x54);
		mr = (uint16_t)(mr & 0x8fff);
		mr = (uint16_t)(mr | (val << 12));
		PCICFG_WR16(qlt, 0x54, mr);
	} else {
		cmn_err(CE_WARN, "qlt(%d): dont know how to set "
		    "pci-max-read-request for this device (%x)",
		    instance, did);
	}
over_max_read_xfer_setting:;

	max_payload_size = qlt_read_int_prop(qlt, "pcie-max-payload-size", 11);
	if (max_payload_size == 11)
		goto over_max_payload_setting;
	if ((did == 0x2432) || (did == 0x8432) ||
	    (did == 0x2532) || (did == 0x8001) ||
	    (did == 0x2031) || (did == 0x2071) ||
	    (did == 0x2261)) {
		if (max_payload_size == 128)
			val = 0;
		else if (max_payload_size == 256)
			val = 1;
		else if (max_payload_size == 512)
			val = 2;
		else if (max_payload_size == 1024)
			val = 3;
		else {
			cmn_err(CE_WARN, "qlt(%d) malformed "
			    "pcie-max-payload-size in qlt.conf. Valid values "
			    "for this HBA are 128/256/512/1024",
			    instance);
			goto over_max_payload_setting;
		}
		mr = (uint16_t)PCICFG_RD16(qlt, 0x54);
		mr = (uint16_t)(mr & 0xff1f);
		mr = (uint16_t)(mr | (val << 5));
		PCICFG_WR16(qlt, 0x54, mr);
	} else {
		cmn_err(CE_WARN, "qlt(%d): dont know how to set "
		    "pcie-max-payload-size for this device (%x)",
		    instance, did);
	}

over_max_payload_setting:;

	qlt_enable_intr(qlt);

	if (qlt_port_start((caddr_t)qlt) != QLT_SUCCESS) {
		EL(qlt, "qlt_port_start failed, tear down\n");
		qlt_disable_intr(qlt);
		goto attach_fail_10;
	}

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

attach_fail_10:;
	mutex_destroy(&qlt->qlt_ioctl_lock);
	cv_destroy(&qlt->mbox_cv);
	cv_destroy(&qlt->rp_dereg_cv);
	ddi_remove_minor_node(dip, qlt->qlt_minor_name);
attach_fail_9:;
	qlt_destroy_mutex(qlt);
	qlt_release_intr(qlt);
	(void) qlt_mq_destroy(qlt);

attach_fail_8:;
	(void) ddi_dma_unbind_handle(qlt->queue_mem_dma_handle);
attach_fail_7:;
	ddi_dma_mem_free(&qlt->queue_mem_acc_handle);
attach_fail_6:;
	ddi_dma_free_handle(&qlt->queue_mem_dma_handle);
attach_fail_5:;
	if (qlt->mq_resp) {
		kmem_free(qlt->mq_resp,
		    (qlt->qlt_mq_enabled ?
		    (sizeof (qlt_mq_rsp_ptr_blk_t) * MQ_MAX_QUEUES) :
		    (sizeof (qlt_mq_rsp_ptr_blk_t))));
	}
	qlt->mq_resp = NULL;
	if (qlt->mq_req) {
		kmem_free(qlt->mq_req,
		    (qlt->qlt_mq_enabled ?
		    (sizeof (qlt_mq_req_ptr_blk_t) * MQ_MAX_QUEUES) :
		    (sizeof (qlt_mq_req_ptr_blk_t))));
	}
	qlt->mq_req = NULL;

	ddi_regs_map_free(&qlt->regs_acc_handle);
attach_fail_4:;
	pci_config_teardown(&qlt->pcicfg_acc_handle);
attach_fail_3:;
	(void) qlt_el_trace_desc_dtor(qlt);
attach_fail_2:;
	kmem_free(qlt->vpd, QL_24XX_VPD_SIZE);
	kmem_free(qlt->nvram, sizeof (qlt_nvram_t));
attach_fail_1:;
	ddi_soft_state_free(qlt_state, instance);
	return (DDI_FAILURE);
}

#define	FCT_I_EVENT_BRING_PORT_OFFLINE	0x83

/* ARGSUSED */
static int
qlt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	qlt_state_t *qlt;

	int instance;

	instance = ddi_get_instance(dip);
	if ((qlt = (qlt_state_t *)ddi_get_soft_state(qlt_state, instance)) ==
	    NULL) {
		return (DDI_FAILURE);
	}

	if (qlt->fw_code01) {
		return (DDI_FAILURE);
	}

	if ((qlt->qlt_state != FCT_STATE_OFFLINE) ||
	    qlt->qlt_state_not_acked) {
		return (DDI_FAILURE);
	}
	if (qlt_port_stop((caddr_t)qlt) != FCT_SUCCESS) {
		return (DDI_FAILURE);
	}

	qlt_disable_intr(qlt);

	if (qlt->dmp_template_addr != NULL) {
		(void) ddi_dma_unbind_handle(qlt->dmp_template_dma_handle);
		ddi_dma_mem_free(&qlt->dmp_template_acc_handle);
		ddi_dma_free_handle(&qlt->dmp_template_dma_handle);
	}

	if (qlt->fw_bin_dump_buf != NULL) {
		kmem_free(qlt->fw_bin_dump_buf, qlt->fw_bin_dump_size);
		qlt->fw_bin_dump_buf = NULL;
		qlt->fw_bin_dump_size = 0;
		qlt->fw_ascii_dump_size = 0;
	}

	if (qlt->qlt_fwdump_buf) {
		kmem_free(qlt->qlt_fwdump_buf, qlt->fw_dump_size);
		qlt->qlt_fwdump_buf = NULL;
	}

	ddi_remove_minor_node(dip, qlt->qlt_minor_name);
	qlt_destroy_mutex(qlt);
	qlt_release_intr(qlt);
	if (qlt->qlt_mq_enabled == 1) {
		(void) qlt_mq_destroy(qlt);
	}

	(void) ddi_dma_unbind_handle(qlt->queue_mem_dma_handle);
	ddi_dma_mem_free(&qlt->queue_mem_acc_handle);
	ddi_dma_free_handle(&qlt->queue_mem_dma_handle);
	ddi_regs_map_free(&qlt->regs_acc_handle);

	if (qlt->mq_resp) {
		kmem_free(qlt->mq_resp,
		    (qlt->qlt_mq_enabled ?
		    (sizeof (qlt_mq_rsp_ptr_blk_t) * MQ_MAX_QUEUES) :
		    (sizeof (qlt_mq_rsp_ptr_blk_t))));
	}
	qlt->mq_resp = NULL;
	if (qlt->mq_req) {
		kmem_free(qlt->mq_req,
		    (qlt->qlt_mq_enabled ?
		    (sizeof (qlt_mq_req_ptr_blk_t) * MQ_MAX_QUEUES) :
		    (sizeof (qlt_mq_req_ptr_blk_t))));
	}
	qlt->mq_req = NULL;

	if (qlt->qlt_mq_enabled == 1) {
		if ((qlt->msix_acc_handle != NULL) &&
		    ((qlt->qlt_83xx_chip == 1) ||
		    (qlt->qlt_27xx_chip == 1))) {
			ddi_regs_map_free(&qlt->msix_acc_handle);
		}
		ddi_regs_map_free(&qlt->mq_reg_acc_handle);
	}
	pci_config_teardown(&qlt->pcicfg_acc_handle);
	kmem_free(qlt->nvram, sizeof (qlt_nvram_t));
	cv_destroy(&qlt->mbox_cv);
	cv_destroy(&qlt->rp_dereg_cv);
	(void) qlt_el_trace_desc_dtor(qlt);
	ddi_soft_state_free(qlt_state, instance);

	return (DDI_SUCCESS);
}

/*
 * qlt_quiesce	quiesce a device attached to the system.
 */
static int
qlt_quiesce(dev_info_t *dip)
{
	qlt_state_t	*qlt;
	uint32_t	timer;
	uint32_t	stat;

	qlt = ddi_get_soft_state(qlt_state, ddi_get_instance(dip));
	if (qlt == NULL) {
		/* Oh well.... */
		return (DDI_SUCCESS);
	}

	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_HOST_TO_RISC_INTR));
	REG_WR16(qlt, REG_MBOX0, MBC_STOP_FIRMWARE);
	REG_WR16(qlt, REG_MBOX(1), 0);
	REG_WR16(qlt, REG_MBOX(2), 0);
	REG_WR16(qlt, REG_MBOX(3), 0);
	REG_WR16(qlt, REG_MBOX(4), 0);
	REG_WR16(qlt, REG_MBOX(5), 0);
	REG_WR16(qlt, REG_MBOX(6), 0);
	REG_WR16(qlt, REG_MBOX(7), 0);
	REG_WR16(qlt, REG_MBOX(8), 0);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(SET_HOST_TO_RISC_INTR));
	for (timer = 0; timer < 30000; timer++) {
		stat = REG_RD32(qlt, REG_RISC_STATUS);
		if (stat & RISC_HOST_INTR_REQUEST) {
			if ((stat & FW_INTR_STATUS_MASK) < 0x12) {
				REG_WR32(qlt, REG_HCCR,
				    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
				break;
			}
			REG_WR32(qlt, REG_HCCR,
			    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		}
		drv_usecwait(100);
	}


	/* need to ensure no one accesses the hw during the reset 100us */
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		REG_WR32(qlt, REG_INTR_CTRL, 0);
		mutex_enter(&qlt->mbox_lock);
		if (qlt->qlt_mq_enabled == 1) {
			int i;
			for (i = 1; i < qlt->qlt_queue_cnt; i++) {
				mutex_enter(&qlt->mq_req[i].mq_lock);
			}
		}
		mutex_enter(&qlt->mq_req[0].mq_lock);
		drv_usecwait(40);
	}

	/* Reset the chip. */
	REG_WR32(qlt, REG_CTRL_STATUS, CHIP_SOFT_RESET | DMA_SHUTDOWN_CTRL |
	    PCI_X_XFER_CTRL);
	drv_usecwait(100);

	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		mutex_exit(&qlt->mq_req[0].mq_lock);
		if (qlt->qlt_mq_enabled == 1) {
			int i;
			for (i = 1; i < qlt->qlt_queue_cnt; i++) {
				mutex_exit(&qlt->mq_req[i].mq_lock);
			}
		}
		mutex_exit(&qlt->mbox_lock);
	}

	qlt_disable_intr(qlt);

	return (DDI_SUCCESS);
}

static void
qlt_enable_intr(qlt_state_t *qlt)
{
	if (qlt->intr_cap & DDI_INTR_FLAG_BLOCK) {
		int stat;

		stat = ddi_intr_block_enable(qlt->htable, qlt->intr_cnt);
		if (stat != DDI_SUCCESS) {
			stmf_trace(qlt->qlt_port_alias,
			    "qlt_enable_intr: ddi_intr_block_enable failed:%x",
			    stat);

			cmn_err(CE_WARN, "!qlt(%d): qlt_enable_intr: "
			    "ddi_intr_block_enable failed:%x",
			    qlt->instance, stat);
		}

#ifndef __sparc
		else {
			/* Please see CR6840537, MSI isn't re-enabled x86 */
			off_t offset;
			uint8_t val8;
			ddi_intr_handle_impl_t	*hdlp;

			if (qlt->qlt_81xx_chip || qlt->qlt_25xx_chip) {
				offset = (off_t)0x8a;
			} else {
				offset = (off_t)0x66;
			}

			hdlp = (ddi_intr_handle_impl_t *)qlt->htable[0];
			if ((hdlp->ih_state == DDI_IHDL_STATE_ENABLE) &&
			    (hdlp->ih_type == DDI_INTR_TYPE_MSI)) {

				/* get MSI control */
				val8 = pci_config_get8(qlt->pcicfg_acc_handle,
				    offset);

				if ((val8 & 1) == 0) {
					stmf_trace(qlt->qlt_port_alias,
					    "qlt(%d): qlt_enable_intr: "
					    "MSI enable failed (%x)",
					    qlt->instance, val8);

					/* write enable to MSI control */
					val8 = (uint8_t)(val8 | 1);
					pci_config_put8(qlt->pcicfg_acc_handle,
					    offset, val8);

					/* read back to veriy */
					val8 = pci_config_get8
					    (qlt->pcicfg_acc_handle, offset);

					if (val8 & 1) {
						stmf_trace(qlt->qlt_port_alias,
						    "qlt(%d): qlt_enable_intr: "
						    "MSI enabled kludge!(%x)",
						    qlt->instance, val8);
					}
				}
			}
		}
#endif /* x86 specific hack */
	} else {
		int i;
		int stat = DDI_SUCCESS;

		for (i = 0;
		    ((i < qlt->intr_cnt) && (stat == DDI_SUCCESS)); i++) {
			stat = ddi_intr_enable(qlt->htable[i]);
		}
		if (stat != DDI_SUCCESS) {
			stmf_trace(qlt->qlt_port_alias,
			    "qlt_enable_intr: ddi_intr_enable failed:%x",
			    stat);

			cmn_err(CE_WARN, "!qlt(%d): qlt_enable_intr: "
			    "ddi_intr_enable failed:%x", qlt->instance, stat);
		}
	}
}

static void
qlt_disable_intr(qlt_state_t *qlt)
{
	if (qlt->intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(qlt->htable, qlt->intr_cnt);
	} else {
		int i;
		for (i = 0; i < qlt->intr_cnt; i++)
			(void) ddi_intr_disable(qlt->htable[i]);
	}
	qlt->qlt_intr_enabled = 0;
}

static void
qlt_release_intr(qlt_state_t *qlt)
{
	if (qlt->htable) {
		int i;
		for (i = 0; i < qlt->intr_cnt; i++) {
			(void) ddi_intr_remove_handler(qlt->htable[i]);
			(void) ddi_intr_free(qlt->htable[i]);
		}
		kmem_free(qlt->htable, (uint_t)qlt->intr_size);
	}
	qlt->htable = NULL;
	qlt->intr_pri = 0;
	qlt->intr_cnt = 0;
	qlt->intr_size = 0;
	qlt->intr_cap = 0;
}

static void
qlt_init_mutex(qlt_state_t *qlt)
{
	if (qlt->qlt_mq_enabled == 1) {
		int i;

		for (i = 1; i < MQ_MAX_QUEUES; i++) {
			mutex_init(&qlt->mq_req[i].mq_lock, 0, MUTEX_DRIVER,
			    INT2PTR(qlt->intr_pri, void *));
			mutex_init(&qlt->mq_resp[i].mq_lock, 0, MUTEX_DRIVER,
			    INT2PTR(qlt->intr_pri, void *));
		}
	}
	mutex_init(&qlt->mq_req[0].mq_lock, 0, MUTEX_DRIVER,
	    INT2PTR(qlt->intr_pri, void *));
	mutex_init(&qlt->preq_lock, 0, MUTEX_DRIVER,
	    INT2PTR(qlt->intr_pri, void *));
	mutex_init(&qlt->mbox_lock, NULL, MUTEX_DRIVER,
	    INT2PTR(qlt->intr_pri, void *));
	mutex_init(&qlt->intr_lock, NULL, MUTEX_DRIVER,
	    INT2PTR(qlt->intr_pri, void *));
}

static void
qlt_destroy_mutex(qlt_state_t *qlt)
{
	if (qlt->qlt_mq_enabled == 1) {
		int i;

		for (i = 1; i < MQ_MAX_QUEUES; i++) {
			mutex_destroy(&qlt->mq_req[i].mq_lock);
			mutex_destroy(&qlt->mq_resp[i].mq_lock);
		}
	}
	mutex_destroy(&qlt->mq_req[0].mq_lock);
	mutex_destroy(&qlt->preq_lock);
	mutex_destroy(&qlt->mbox_lock);
	mutex_destroy(&qlt->intr_lock);
}

static int
qlt_setup_msix(qlt_state_t *qlt)
{
	int count, avail, actual;
	int ret;
	int itype = DDI_INTR_TYPE_MSIX;
	int i;

	/* check 24xx revision */
	if ((!qlt->qlt_25xx_chip) && (!qlt->qlt_81xx_chip) &&
	    (!qlt->qlt_83xx_chip) && (!qlt->qlt_27xx_chip)) {
		uint8_t rev_id;
		rev_id = (uint8_t)
		    pci_config_get8(qlt->pcicfg_acc_handle, PCI_CONF_REVID);
		if (rev_id < 3) {
			return (DDI_FAILURE);
		}
	}

	ret = ddi_intr_get_nintrs(qlt->dip, itype, &count);
	if (ret != DDI_SUCCESS || count == 0) {
		EL(qlt, "ddi_intr_get_nintrs status=%xh, count=%d\n", ret,
		    count);
		return (DDI_FAILURE);
	}
	ret = ddi_intr_get_navail(qlt->dip, itype, &avail);
	if (ret != DDI_SUCCESS || avail == 0) {
		EL(qlt, "ddi_intr_get_navail status=%xh, avail=%d\n", ret,
		    avail);
		return (DDI_FAILURE);
	}
	if (avail < count) {
		stmf_trace(qlt->qlt_port_alias,
		    "qlt_setup_msix: nintrs=%d,avail=%d", count, avail);
	}

	if ((qlt->qlt_25xx_chip) && (qlt->qlt_mq_enabled == 0)) {
		count = 2;
	}

	qlt->intr_size = (int)(count * (int)sizeof (ddi_intr_handle_t));
	qlt->htable = kmem_zalloc((uint_t)qlt->intr_size, KM_SLEEP);
	ret = ddi_intr_alloc(qlt->dip, qlt->htable, itype,
	    DDI_INTR_ALLOC_NORMAL, count, &actual, 0);

	EL(qlt, "qlt_setup_msix: count=%d,avail=%d,actual=%d\n", count,
	    avail, actual);

	/* we need at least 2 interrupt vectors */
	if (((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) &&
	    (ret != DDI_SUCCESS || actual < 2)) {
		EL(qlt, "ddi_intr_alloc status=%xh, actual=%d\n", ret,
		    actual);
		ret = DDI_FAILURE;
		goto release_intr;
	} else if ((qlt->qlt_81xx_chip) && (ret != DDI_SUCCESS || actual < 3)) {
		EL(qlt, "ddi_intr_alloc status=%xh, actual=%d\n", ret,
		    actual);
		ret = DDI_FAILURE;
		goto release_intr;
	} else if (ret != DDI_SUCCESS || actual < 2) {
		EL(qlt, "ddi_intr_alloc status=%xh, actual=%d\n", ret,
		    actual);
		ret = DDI_FAILURE;
		goto release_intr;
	}
	if (actual < count) {
		EL(qlt, "requested: %d, received: %d\n", count, actual);
	}

	qlt->intr_cnt = actual;
	ret =  ddi_intr_get_pri(qlt->htable[0], &qlt->intr_pri);
	if (ret != DDI_SUCCESS) {
		EL(qlt, "ddi_intr_get_pri status=%xh\n", ret);
		ret = DDI_FAILURE;
		goto release_intr;
	}
	qlt_init_mutex(qlt);
	for (i = 0; i < qlt->intr_cnt; i++) {
		ret = ddi_intr_add_handler(qlt->htable[i],
		    (i != 0) ? qlt_msix_resp_handler :
		    qlt_msix_default_handler,
		    qlt, INT2PTR((uint_t)i, void *));
		if (ret != DDI_SUCCESS) {
			EL(qlt, "ddi_intr_add_handler status=%xh\n", ret);
			goto release_mutex;
		}
	}

	(void) ddi_intr_get_cap(qlt->htable[0], &qlt->intr_cap);
	qlt->intr_flags |= QLT_INTR_MSIX;
	return (DDI_SUCCESS);

release_mutex:
	qlt_destroy_mutex(qlt);
release_intr:
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(qlt->htable[i]);

	kmem_free(qlt->htable, (uint_t)qlt->intr_size);
	qlt->htable = NULL;
	qlt_release_intr(qlt);
	return (ret);
}

static int
qlt_setup_msi(qlt_state_t *qlt)
{
	int count, avail, actual;
	int itype = DDI_INTR_TYPE_MSI;
	int ret;
	int i;

	/* 83xx and 27xx doesn't do MSI - don't even bother? */
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		return (DDI_FAILURE);
	}

	/* get the # of interrupts */
	ret = ddi_intr_get_nintrs(qlt->dip, itype, &count);
	if (ret != DDI_SUCCESS || count == 0) {
		EL(qlt, "ddi_intr_get_nintrs status=%xh, count=%d\n", ret,
		    count);
		return (DDI_FAILURE);
	}
	ret = ddi_intr_get_navail(qlt->dip, itype, &avail);
	if (ret != DDI_SUCCESS || avail == 0) {
		EL(qlt, "ddi_intr_get_navail status=%xh, avail=%d\n", ret,
		    avail);
		return (DDI_FAILURE);
	}
	if (avail < count) {
		EL(qlt, "nintrs=%d, avail=%d\n", count, avail);
	}
	/* MSI requires only 1 interrupt. */
	count = 1;

	/* allocate interrupt */
	qlt->intr_size = (int)(count * (int)sizeof (ddi_intr_handle_t));
	qlt->htable = kmem_zalloc((uint_t)qlt->intr_size, KM_SLEEP);
	ret = ddi_intr_alloc(qlt->dip, qlt->htable, itype,
	    0, count, &actual, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS || actual == 0) {
		EL(qlt, "ddi_intr_alloc status=%xh, actual=%d\n", ret,
		    actual);
		ret = DDI_FAILURE;
		goto free_mem;
	}
	if (actual < count) {
		EL(qlt, "requested: %d, received: %d\n", count, actual);
	}
	qlt->intr_cnt = actual;

	/*
	 * Get priority for first msi, assume remaining are all the same.
	 */
	ret =  ddi_intr_get_pri(qlt->htable[0], &qlt->intr_pri);
	if (ret != DDI_SUCCESS) {
		EL(qlt, "ddi_intr_get_pri status=%xh\n", ret);
		ret = DDI_FAILURE;
		goto release_intr;
	}
	qlt_init_mutex(qlt);

	/* add handler */
	for (i = 0; i < actual; i++) {
		ret = ddi_intr_add_handler(qlt->htable[i], qlt_isr,
		    qlt, INT2PTR((uint_t)i, void *));
		if (ret != DDI_SUCCESS) {
			EL(qlt, "ddi_intr_add_handler status=%xh\n", ret);
			goto release_mutex;
		}
	}

	(void) ddi_intr_get_cap(qlt->htable[0], &qlt->intr_cap);
	qlt->intr_flags |= QLT_INTR_MSI;
	return (DDI_SUCCESS);

release_mutex:
	qlt_destroy_mutex(qlt);
release_intr:
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(qlt->htable[i]);
free_mem:
	kmem_free(qlt->htable, (uint_t)qlt->intr_size);
	qlt->htable = NULL;
	qlt_release_intr(qlt);
	return (ret);
}

static int
qlt_setup_fixed(qlt_state_t *qlt)
{
	int count;
	int actual;
	int ret;
	int itype = DDI_INTR_TYPE_FIXED;

	ret = ddi_intr_get_nintrs(qlt->dip, itype, &count);
	/* Fixed interrupts can only have one interrupt. */
	if (ret != DDI_SUCCESS || count != 1) {
		EL(qlt, "ddi_intr_get_nintrs status=%xh, count=%d\n", ret,
		    count);
		return (DDI_FAILURE);
	}

	qlt->intr_size = sizeof (ddi_intr_handle_t);
	qlt->htable = kmem_zalloc((uint_t)qlt->intr_size, KM_SLEEP);
	ret = ddi_intr_alloc(qlt->dip, qlt->htable, itype,
	    DDI_INTR_ALLOC_NORMAL, count, &actual, 0);
	if (ret != DDI_SUCCESS || actual != 1) {
		EL(qlt, "ddi_intr_alloc status=%xh, actual=%d\n", ret,
		    actual);
		ret = DDI_FAILURE;
		goto free_mem;
	}

	qlt->intr_cnt = actual;
	ret =  ddi_intr_get_pri(qlt->htable[0], &qlt->intr_pri);
	if (ret != DDI_SUCCESS) {
		EL(qlt, "ddi_intr_get_pri status=%xh\n", ret);
		ret = DDI_FAILURE;
		goto release_intr;
	}
	qlt_init_mutex(qlt);
	ret = ddi_intr_add_handler(qlt->htable[0], qlt_isr, qlt, 0);
	if (ret != DDI_SUCCESS) {
		EL(qlt, "ddi_intr_add_handler status=%xh\n", ret);
		goto release_mutex;
	}

	qlt->intr_flags |= QLT_INTR_FIXED;
	return (DDI_SUCCESS);

release_mutex:
	qlt_destroy_mutex(qlt);
release_intr:
	(void) ddi_intr_free(qlt->htable[0]);
free_mem:
	kmem_free(qlt->htable, (uint_t)qlt->intr_size);
	qlt->htable = NULL;
	qlt_release_intr(qlt);
	return (ret);
}

static int
qlt_setup_interrupts(qlt_state_t *qlt)
{
	int itypes = 0;

/*
 * x86 has a bug in the ddi_intr_block_enable/disable area (6562198).
 */
#ifndef __sparc
	if ((qlt_enable_msi != 0) || (qlt_enable_msix != 0)) {
#endif
	if (ddi_intr_get_supported_types(qlt->dip, &itypes) != DDI_SUCCESS) {
		itypes = DDI_INTR_TYPE_FIXED;
	}
	if (qlt_enable_msix && (itypes & DDI_INTR_TYPE_MSIX)) {
		if (qlt_setup_msix(qlt) == DDI_SUCCESS)
			return (DDI_SUCCESS);
	}
	if (qlt_enable_msi && (itypes & DDI_INTR_TYPE_MSI)) {
		if (qlt_setup_msi(qlt) == DDI_SUCCESS)
			return (DDI_SUCCESS);
	}
#ifndef __sparc
	}
#endif
	return (qlt_setup_fixed(qlt));
}

static uint8_t *
qlt_vpd_findtag(qlt_state_t *qlt, uint8_t *vpdbuf, int8_t *opcode)
{
	uint8_t	*vpd = vpdbuf;
	uint8_t	*end = vpdbuf + QL_24XX_VPD_SIZE;
	uint32_t found = 0;

	if (vpdbuf == NULL || opcode == NULL) {
		EL(qlt, "null parameter passed!\n");
		return (NULL);
	}

	while (vpd < end) {
		if (vpd[0] == VPD_TAG_END) {
			if (opcode[0] == VPD_TAG_END) {
				found = 1;
			} else {
				found = 0;
			}
			break;
		}

		if (bcmp(opcode, vpd, strlen(opcode)) == 0) {
			found = 1;
			break;
		}

		if (!(strncmp((char *)vpd, (char *)VPD_TAG_PRODID, 1))) {
			vpd += (vpd[2] << 8) + vpd[1] + 3;
		} else if (*vpd == VPD_TAG_LRT || *vpd == VPD_TAG_LRTC) {
			vpd += 3;
		} else {
			vpd += vpd[2] +3;
		}
	}
	return (found == 1 ? vpd : NULL);
}

/*
 * qlt_vpd_lookup
 *      Return the VPD data for the request VPD tag
 *
 * Input:
 *      qlt      = adapter state pointer.
 *      opcode  = VPD opcode to find (must be NULL terminated).
 *      bp      = Pointer to returned data buffer.
 *      bplen   = Length of returned data buffer.
 *
 * Returns:
 *      Length of data copied into returned data buffer.
 *              >0 = VPD data field (NULL terminated)
 *               0 = no data.
 *              -1 = Could not find opcode in vpd buffer / error.
 *
 * Context:
 *      Kernel context.
 *
 * NB: The opcode buffer and the bp buffer *could* be the same buffer!
 *
 */
static int
qlt_vpd_lookup(qlt_state_t *qlt, uint8_t *opcode, uint8_t *bp,
    int32_t bplen)
{
	uint8_t	*vpd = NULL;
	uint8_t	*vpdbuf = NULL;
	int32_t	len = -1;

	if (opcode == NULL || bp == NULL || bplen < 1) {
		EL(qlt, "invalid parameter passed: opcode=%ph, "
		    "bp=%ph, bplen=%xh\n", opcode, bp, bplen);
		return (len);
	}

	vpdbuf = (uint8_t *)qlt->vpd;
	if ((vpd = qlt_vpd_findtag(qlt, vpdbuf, (int8_t *)opcode)) != NULL) {
		/*
		 * Found the tag
		 */
		if (*opcode == VPD_TAG_END || *opcode == VPD_TAG_LRT ||
		    *opcode == VPD_TAG_LRTC) {
			/*
			 * We found it, but the tag doesn't have a data
			 * field.
			 */
			len = 0;
		} else if (!(strncmp((char *)vpd, (char *)
		    VPD_TAG_PRODID, 1))) {
			len = vpd[2] << 8;
			len += vpd[1];
		} else {
			len = vpd[2];
		}

		/*
		 * Make sure that the vpd len does not exceed the
		 * vpd end
		 */
		if (vpd+len > vpdbuf + QL_24XX_VPD_SIZE) {
			EL(qlt, "vpd tag len (%xh) exceeds vpd buffer "
			    "length\n", len);
			len = -1;
		}
	} else {
		EL(qlt, "Cna't find vpd tag \n");
		return (-1);
	}

	if (len >= 0) {
		/*
		 * make sure we don't exceed callers buffer space len
		 */
		if (len > bplen) {
			len = bplen - 1;
		}
		/* copy the data back */
		(void) strncpy((int8_t *)bp, (int8_t *)(vpd+3), (int64_t)len);
		bp[len] = '\0';
	} else {
		/* error -- couldn't find tag */
		bp[0] = '\0';
		if (opcode[1] != '\0') {
			EL(qlt, "unable to find tag '%s'\n", opcode);
		} else {
			EL(qlt, "unable to find tag '%xh'\n", opcode[0]);
		}
	}
	return (len);
}

void
qlt_get_rom_version(qlt_state_t *qlt, caddr_t orv)
{
	int i;
	char bios0_str[32];
	char fcode_str[32];
	char efi_str[32];
	char hppa_str[32];
	char tmp[80];
	uint32_t bios_cnt = 0;
	uint32_t fcode_cnt = 0;
	boolean_t last_image = FALSE;

	/* collect right rom_version from image[] */
	i = 0;
	do {
		if (qlt->rimage[0].header.signature[0] != PCI_HEADER0) {
			break;
		}

		if (qlt->rimage[i].data.codetype == PCI_CODE_X86PC) {
			/* BIOS */
			if (bios_cnt == 0) {
				(void) snprintf(bios0_str,
				    32,
				    "%d.%02d",
				    qlt->rimage[i].data.
				    revisionlevel[1],
				    qlt->rimage[i].data.
				    revisionlevel[0]);
				(void) snprintf(tmp, 80,
				    " BIOS: %s;", bios0_str);
				(void) strcat(orv, tmp);
			}
			bios_cnt++;
		} else if (qlt->rimage[i].data.codetype == PCI_CODE_FCODE) {
			/* FCode */
			if (fcode_cnt == 0) {
				(void) snprintf(fcode_str,
				    32,
				    "%d.%02d",
				    qlt->rimage[i].data.revisionlevel[1],
				    qlt->rimage[i].data.revisionlevel[0]);
				(void) snprintf(tmp, 80,
				    " FCode: %s;", fcode_str);
				(void) strcat(orv, tmp);
			}
			fcode_cnt++;
		} else if (qlt->rimage[i].data.codetype == PCI_CODE_EFI) {
			/* EFI */
			(void) snprintf(efi_str,
			    32,
			    "%d.%02d",
			    qlt->rimage[i].data.revisionlevel[1],
			    qlt->rimage[i].data.revisionlevel[0]);
			(void) snprintf(tmp, 80, " EFI: %s;", efi_str);
			(void) strcat(orv, tmp);
		} else if (qlt->rimage[i].data.codetype == PCI_CODE_HPPA) {
			/* HPPA */
			(void) snprintf(hppa_str,
			    32,
			    "%d.%02d",
			    qlt->rimage[i].data.revisionlevel[1],
			    qlt->rimage[i].data.revisionlevel[0]);
			(void) snprintf(orv, 80, " HPPA: %s;", hppa_str);
			(void) strcat(orv, tmp);
		} else if (qlt->rimage[i].data.codetype == PCI_CODE_FW) {
			EL(qlt, "fw infor skip\n");
		} else {
			/* Unknown */
			EL(qlt, "unknown image\n");
			break;
		}

		if (qlt->rimage[i].data.indicator == PCI_IND_LAST_IMAGE) {
			last_image = TRUE;
			break;
		}

		i ++;
	} while ((last_image != TRUE) && (i < 6));

	if (last_image != TRUE) {
		/* No boot image detected */
		(void) snprintf(orv, FCHBA_OPTION_ROM_VERSION_LEN, "%s",
		    "No boot image detected");
	}
}

/*
 * Filling the hba attributes
 */
void
qlt_populate_hba_fru_details(struct fct_local_port *port,
    struct fct_port_attrs *port_attrs)
{
	int len;
	qlt_state_t *qlt = (qlt_state_t *)port->port_fca_private;

	(void) snprintf(port_attrs->manufacturer, FCHBA_MANUFACTURER_LEN,
	    "QLogic Corp.");
	(void) snprintf(port_attrs->driver_name, FCHBA_DRIVER_NAME_LEN,
	    "%s", QLT_NAME);
	(void) snprintf(port_attrs->driver_version, FCHBA_DRIVER_VERSION_LEN,
	    "%s", QLT_VERSION);
	/* get serial_number from vpd data */
	if (qlt_vpd_lookup(qlt, (uint8_t *)VPD_TAG_SN, (uint8_t *)
	    port_attrs->serial_number, FCHBA_SERIAL_NUMBER_LEN) == -1) {
			port_attrs->serial_number[0] = '\0';
	}
	port_attrs->hardware_version[0] = '\0';

	(void) snprintf(port_attrs->firmware_version,
	    FCHBA_FIRMWARE_VERSION_LEN, "%d.%d.%d", qlt->fw_major,
	    qlt->fw_minor, qlt->fw_subminor);

	/* Get FCode version */
	qlt_get_rom_version(qlt, (caddr_t)&port_attrs->option_rom_version[0]);

	port_attrs->vendor_specific_id = qlt->nvram->subsystem_vendor_id[0] |
	    qlt->nvram->subsystem_vendor_id[1] << 8;

	port_attrs->max_frame_size = qlt->nvram->max_frame_length[1] << 8 |
	    qlt->nvram->max_frame_length[0];

	port_attrs->supported_cos = 0x10000000;

	if (qlt->qlt_fcoe_enabled) {
		port_attrs->supported_speed = PORT_SPEED_10G;
	} else if (qlt->qlt_27xx_chip) {
		if ((qlt->qlt_27xx_speed & MAX_SPEED_MASK) == MAX_SPEED_32G) {
			port_attrs->supported_speed = PORT_SPEED_8G |
			    PORT_SPEED_16G | PORT_SPEED_32G;
		} else {
			port_attrs->supported_speed = PORT_SPEED_4G |
			    PORT_SPEED_8G | PORT_SPEED_16G;
		}
	} else if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		port_attrs->supported_speed = PORT_SPEED_4G |
		    PORT_SPEED_8G | PORT_SPEED_16G;
	} else if (qlt->qlt_25xx_chip) {
		port_attrs->supported_speed = PORT_SPEED_2G | PORT_SPEED_4G |
		    PORT_SPEED_8G;
	} else {
		port_attrs->supported_speed = PORT_SPEED_1G |
		    PORT_SPEED_2G | PORT_SPEED_4G;
	}

	/* limit string length to nvr model_name length */
	len = ((qlt->qlt_81xx_chip) || (qlt->qlt_83xx_chip) ||
	    (qlt->qlt_27xx_chip)) ? 16 : 8;
	(void) snprintf(port_attrs->model,
	    (uint_t)(len < FCHBA_MODEL_LEN ? len : FCHBA_MODEL_LEN),
	    "%s", qlt->nvram->model_name);

	(void) snprintf(port_attrs->model_description,
	    (uint_t)(len < FCHBA_MODEL_DESCRIPTION_LEN ? len :
	    FCHBA_MODEL_DESCRIPTION_LEN),
	    "%s", qlt->nvram->model_name);
}

/* ARGSUSED */
fct_status_t
qlt_info(uint32_t cmd, fct_local_port_t *port,
    void *arg, uint8_t *buf, uint32_t *bufsizep)
{
	qlt_state_t	*qlt = (qlt_state_t *)port->port_fca_private;
	mbox_cmd_t	*mcp;
	fct_status_t	ret = FCT_SUCCESS;
	uint8_t		*p;
	fct_port_link_status_t	*link_status;

	switch (cmd) {
	case FC_TGT_PORT_RLS:
		if (qlt->qlt_state != FCT_STATE_ONLINE) {
			break;
		}
		if ((*bufsizep) < sizeof (fct_port_link_status_t)) {
			EL(qlt, "FC_TGT_PORT_RLS bufsizep=%xh < "
			    "fct_port_link_status_t=%xh\n", *bufsizep,
			    sizeof (fct_port_link_status_t));
			ret = FCT_FAILURE;
			break;
		}
		/* send mailbox command to get link status */
		mcp = qlt_alloc_mailbox_command(qlt, 156);
		if (mcp == NULL) {
			EL(qlt, "qlt_alloc_mailbox_command mcp=null\n");
			ret = FCT_ALLOC_FAILURE;
			break;
		}

		/* GET LINK STATUS count */
		mcp->to_fw[0] = MBC_GET_STATUS_COUNTS;
		mcp->to_fw[8] = 156/4;
		mcp->to_fw_mask |= BIT_1 | BIT_8;
		mcp->from_fw_mask |= BIT_1 | BIT_2;

		ret = qlt_mailbox_command(qlt, mcp);
		if (ret != QLT_SUCCESS) {
			EL(qlt, "qlt_mbox_command=6dh status=%llxh\n", ret);
			qlt_free_mailbox_command(qlt, mcp);
			break;
		}
		qlt_dmem_dma_sync(mcp->dbuf, DDI_DMA_SYNC_FORCPU);

		p = mcp->dbuf->db_sglist[0].seg_addr;
		link_status = (fct_port_link_status_t *)buf;
		link_status->LinkFailureCount = LE_32(*((uint32_t *)p));
		link_status->LossOfSyncCount = LE_32(*((uint32_t *)(p + 4)));
		link_status->LossOfSignalsCount = LE_32(*((uint32_t *)(p + 8)));
		link_status->PrimitiveSeqProtocolErrorCount =
		    LE_32(*((uint32_t *)(p + 12)));
		link_status->InvalidTransmissionWordCount =
		    LE_32(*((uint32_t *)(p + 16)));
		link_status->InvalidCRCCount =
		    LE_32(*((uint32_t *)(p + 20)));

		qlt_free_mailbox_command(qlt, mcp);
		break;
	default:
		EL(qlt, "Unknown cmd=%xh\n", cmd);
		ret = FCT_FAILURE;
		break;
	}
	return (ret);
}

fct_status_t
qlt_port_start(caddr_t arg)
{
	qlt_state_t *qlt = (qlt_state_t *)arg;
	fct_local_port_t *port;
	fct_dbuf_store_t *fds;
	fct_status_t ret;

	if (qlt_dmem_init(qlt) != QLT_SUCCESS) {
		return (FCT_FAILURE);
	}

	/* Initialize the ddi_dma_handle free pool */
	qlt_dma_handle_pool_init(qlt);

	port = (fct_local_port_t *)fct_alloc(FCT_STRUCT_LOCAL_PORT, 0, 0);
	if (port == NULL) {
		goto qlt_pstart_fail_1;
	}
	fds = (fct_dbuf_store_t *)fct_alloc(FCT_STRUCT_DBUF_STORE, 0, 0);
	if (fds == NULL) {
		goto qlt_pstart_fail_2;
	}
	qlt->qlt_port = port;
	fds->fds_alloc_data_buf = qlt_dmem_alloc;
	fds->fds_free_data_buf = qlt_dmem_free;
	fds->fds_setup_dbuf = qlt_dma_setup_dbuf;
	fds->fds_teardown_dbuf = qlt_dma_teardown_dbuf;
	fds->fds_max_sgl_xfer_len = QLT_DMA_SG_LIST_LENGTH * MMU_PAGESIZE;
	fds->fds_copy_threshold = (uint32_t)MMU_PAGESIZE;
	fds->fds_fca_private = (void *)qlt;
	/*
	 * Since we keep everything in the state struct and dont allocate any
	 * port private area, just use that pointer to point to the
	 * state struct.
	 */
	port->port_fca_private = qlt;
	port->port_fca_abort_timeout = 5 * 1000;	/* 5 seconds */
	bcopy(qlt->nvram->node_name, port->port_nwwn, 8);
	bcopy(qlt->nvram->port_name, port->port_pwwn, 8);
	fct_wwn_to_str(port->port_nwwn_str, port->port_nwwn);
	fct_wwn_to_str(port->port_pwwn_str, port->port_pwwn);
	port->port_default_alias = qlt->qlt_port_alias;
	port->port_pp = qlt_pp;
	port->port_fds = fds;
	port->port_max_logins = QLT_MAX_LOGINS;
	port->port_max_xchges = QLT_MAX_XCHGES;
	port->port_fca_fcp_cmd_size = sizeof (qlt_cmd_t);
	port->port_fca_rp_private_size = sizeof (qlt_remote_port_t);
	port->port_fca_sol_els_private_size = sizeof (qlt_cmd_t);
	port->port_fca_sol_ct_private_size = sizeof (qlt_cmd_t);
	port->port_get_link_info = qlt_get_link_info;
	port->port_register_remote_port = qlt_register_remote_port;
	port->port_deregister_remote_port = qlt_deregister_remote_port;
	port->port_send_cmd = qlt_send_cmd;
	port->port_xfer_scsi_data = qlt_xfer_scsi_data;
	port->port_send_cmd_response = qlt_send_cmd_response;
	port->port_abort_cmd = qlt_abort_cmd;
	port->port_ctl = qlt_ctl;
	port->port_flogi_xchg = qlt_do_flogi;
	port->port_populate_hba_details = qlt_populate_hba_fru_details;
	port->port_info = qlt_info;
	port->port_fca_version = FCT_FCA_MODREV_1;

	if ((ret = fct_register_local_port(port)) != FCT_SUCCESS) {
		EL(qlt, "fct_register_local_port status=%llxh\n", ret);
		goto qlt_pstart_fail_2_5;
	}

	EL(qlt, "Qlogic qlt(%d) "
	    "WWPN=%02x%02x%02x%02x%02x%02x%02x%02x:"
	    "WWNN=%02x%02x%02x%02x%02x%02x%02x%02x\n",
	    qlt->instance,
	    qlt->nvram->port_name[0],
	    qlt->nvram->port_name[1],
	    qlt->nvram->port_name[2],
	    qlt->nvram->port_name[3],
	    qlt->nvram->port_name[4],
	    qlt->nvram->port_name[5],
	    qlt->nvram->port_name[6],
	    qlt->nvram->port_name[7],
	    qlt->nvram->node_name[0],
	    qlt->nvram->node_name[1],
	    qlt->nvram->node_name[2],
	    qlt->nvram->node_name[3],
	    qlt->nvram->node_name[4],
	    qlt->nvram->node_name[5],
	    qlt->nvram->node_name[6],
	    qlt->nvram->node_name[7]);

	return (QLT_SUCCESS);
#if 0
qlt_pstart_fail_3:
	(void) fct_deregister_local_port(port);
#endif
qlt_pstart_fail_2_5:
	fct_free(fds);
qlt_pstart_fail_2:
	fct_free(port);
	qlt->qlt_port = NULL;
qlt_pstart_fail_1:
	qlt_dma_handle_pool_fini(qlt);
	qlt_dmem_fini(qlt);
	return (QLT_FAILURE);
}

fct_status_t
qlt_port_stop(caddr_t arg)
{
	qlt_state_t *qlt = (qlt_state_t *)arg;
	fct_status_t ret;

	if ((ret = fct_deregister_local_port(qlt->qlt_port)) != FCT_SUCCESS) {
		EL(qlt, "fct_register_local_port status=%llxh\n", ret);
		return (QLT_FAILURE);
	}
	fct_free(qlt->qlt_port->port_fds);
	fct_free(qlt->qlt_port);
	qlt_dma_handle_pool_fini(qlt);
	qlt->qlt_port = NULL;
	qlt_dmem_fini(qlt);
	return (QLT_SUCCESS);
}

/*
 * Called by framework to init the HBA.
 * Can be called in the middle of I/O. (Why ??)
 * Should make sure sane state both before and after the initialization
 */
fct_status_t
qlt_port_online(qlt_state_t *qlt)
{
	uint64_t	da;
	int		instance, i, j;
	fct_status_t	ret;
	uint16_t	rcount;
	caddr_t		icb;
	mbox_cmd_t	*mcp;
	uint8_t		*elsbmp;

	instance = ddi_get_instance(qlt->dip);

	/* XXX Make sure a sane state */

	if ((ret = qlt_download_fw(qlt)) != QLT_SUCCESS) {
		cmn_err(CE_NOTE, "qlt(%d): reset chip failed %llx",
		    qlt->instance, (long long)ret);
		return (ret);
	}

	bzero(qlt->queue_mem_ptr, TOTAL_DMA_MEM_SIZE);

	/* Get resource count */
	REG_WR16(qlt, REG_MBOX(0), MBC_GET_RESOURCE_COUNTS);
	ret = qlt_raw_mailbox_command(qlt);
	rcount = REG_RD16(qlt, REG_MBOX(3));
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_raw_mailbox_command=42h status=%llxh\n", ret);
		return (ret);
	}

	/* Enable PUREX */
	REG_WR16(qlt, REG_MBOX(0), MBC_SET_ADDITIONAL_FIRMWARE_OPT);
	REG_WR16(qlt, REG_MBOX(1), OPT_PUREX_ENABLE);
	REG_WR16(qlt, REG_MBOX(2), 0x0);
	REG_WR16(qlt, REG_MBOX(3), 0x0);
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_raw_mailbox_command=38h status=%llxh\n", ret);
		cmn_err(CE_NOTE, "Enable PUREX failed");
		return (ret);
	}

	/* Pass ELS bitmap to fw */
	REG_WR16(qlt, REG_MBOX(0), MBC_SET_PARAMETERS);
	REG_WR16(qlt, REG_MBOX(1), PARAM_TYPE(PUREX_ELS_CMDS));
	elsbmp = (uint8_t *)qlt->queue_mem_ptr + MBOX_DMA_MEM_OFFSET;
	bzero(elsbmp, 32);
	da = qlt->queue_mem_cookie.dmac_laddress;
	da += MBOX_DMA_MEM_OFFSET;
	REG_WR16(qlt, REG_MBOX(3), LSW(LSD(da)));
	REG_WR16(qlt, REG_MBOX(2), MSW(LSD(da)));
	REG_WR16(qlt, REG_MBOX(7), LSW(MSD(da)));
	REG_WR16(qlt, REG_MBOX(6), MSW(MSD(da)));
	SETELSBIT(elsbmp, ELS_OP_PLOGI);
	SETELSBIT(elsbmp, ELS_OP_LOGO);
	SETELSBIT(elsbmp, ELS_OP_ABTX);
/*	SETELSBIT(elsbmp, ELS_OP_ECHO); till fct handles it */
	SETELSBIT(elsbmp, ELS_OP_PRLI);
	SETELSBIT(elsbmp, ELS_OP_PRLO);
	SETELSBIT(elsbmp, ELS_OP_SCN);
	SETELSBIT(elsbmp, ELS_OP_TPRLO);
	SETELSBIT(elsbmp, ELS_OP_PDISC);
	SETELSBIT(elsbmp, ELS_OP_ADISC);
	SETELSBIT(elsbmp, ELS_OP_RSCN);
	SETELSBIT(elsbmp, ELS_OP_RNID);
	(void) ddi_dma_sync(qlt->queue_mem_dma_handle, MBOX_DMA_MEM_OFFSET, 32,
	    DDI_DMA_SYNC_FORDEV);
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_raw_mailbox_command=59h status=llxh\n", ret);
		cmn_err(CE_NOTE, "Set ELS Bitmap failed ret=%llx, "
		    "elsbmp0=%x elabmp1=%x", (long long)ret, elsbmp[0],
		    elsbmp[1]);
		return (ret);
	}

	/* Init queue pointers */
	if (qlt->qlt_mq_enabled == 1) {
		uint16_t qi;

		for (qi = 0; qi < MQ_MAX_QUEUES; qi++) {
			MQBAR_WR32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_REQ_IN, 0);
			MQBAR_WR32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_REQ_OUT, 0);
			MQBAR_WR32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_IN, 0);
			MQBAR_WR32(qlt,
			    (qi * MQBAR_REG_OFFSET) +
			    MQBAR_RESP_OUT, 0);
		}
	} else {
		REG_WR32(qlt, REG_REQ_IN_PTR, 0);
		REG_WR32(qlt, REG_REQ_OUT_PTR, 0);
		REG_WR32(qlt, REG_RESP_IN_PTR, 0);
		REG_WR32(qlt, REG_RESP_OUT_PTR, 0);
	}

	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		REG_WR32(qlt, REG_PREQ_IN_PTR, 0);
		REG_WR32(qlt, REG_PREQ_OUT_PTR, 0);
		REG_WR32(qlt, REG_ATIO_IN_PTR, 0);
		REG_WR32(qlt, REG_ATIO_OUT_PTR, 0);
	}
	qlt->mq_req[0].mq_ndx_to_fw = qlt->mq_req[0].mq_ndx_from_fw = 0;
	qlt->mq_req[0].mq_available = REQUEST_QUEUE_ENTRIES - 1;

	if (qlt->qlt_mq_enabled == 1) {
		for (i = 1; i < qlt->qlt_queue_cnt; i++) {
			qlt->mq_req[i].mq_ndx_to_fw = 0;
			qlt->mq_req[i].mq_ndx_from_fw = 0;
			qlt->mq_req[i].mq_available =
			    REQUEST_QUEUE_MQ_ENTRIES - 1;
		}
	}
	qlt->mq_resp[0].mq_ndx_to_fw = qlt->mq_resp[0].mq_ndx_from_fw = 0;

	if (qlt->qlt_mq_enabled == 1) {
		caddr_t resp;

		for (i = 1; i < qlt->qlt_queue_cnt; i++) {
			qlt->mq_resp[i].mq_ndx_to_fw = 0;
			qlt->mq_resp[i].mq_ndx_from_fw = 0;
			for (j = 0; j < RESPONSE_QUEUE_MQ_ENTRIES; j++) {
				resp = &qlt->mq_resp[i].mq_ptr[j << 6];
				QMEM_WR32_RSPQ(qlt, i, resp+0x3c, 0xdeadbeef);
			}
		}
	}

	for (i = 0; i < ATIO_QUEUE_ENTRIES; i++) {
		caddr_t atio;

		atio = &qlt->atio_ptr[i << 6];
		QMEM_WR32(qlt, atio+0x3c, 0xdeadbeef);
	}

	qlt->preq_ndx_to_fw = qlt->preq_ndx_from_fw = 0;
	qlt->atio_ndx_to_fw = qlt->atio_ndx_from_fw = 0;

	/*
	 * XXX support for tunables. Also should we cache icb ?
	 */
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_27xx_chip) || ((qlt->qlt_25xx_chip) &&
	    (qlt->qlt_mq_enabled))) {
		/*
		 * allocate extra 64 bytes for Extended init control block,
		 * with separation to allow for a minimal MID section.
		 */
		mcp = qlt_alloc_mailbox_command(qlt, 0xE0);
	} else {
		mcp = qlt_alloc_mailbox_command(qlt, 0x80);
	}
	if (mcp == NULL) {
		EL(qlt, "qlt_alloc_mailbox_command mcp=null\n");
		return (STMF_ALLOC_FAILURE);
	}
	icb = (caddr_t)mcp->dbuf->db_sglist[0].seg_addr;
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_27xx_chip) || ((qlt->qlt_25xx_chip) &&
	    (qlt->qlt_mq_enabled))) {
		bzero(icb, 0xE0);
	} else {
		bzero(icb, 0x80);
	}
	da = qlt->queue_mem_cookie.dmac_laddress;
	DMEM_WR16(qlt, icb, 1);		/* Version */
	DMEM_WR16(qlt, icb+4, 2112);	/* Max frame length */
	DMEM_WR16(qlt, icb+6, 16);	/* Execution throttle */
	DMEM_WR16(qlt, icb+8, rcount);	/* Xchg count */
	DMEM_WR16(qlt, icb+0x0a, 0x00);	/* Hard address (not used) */
	bcopy(qlt->qlt_port->port_pwwn, icb+0x0c, 8);
	bcopy(qlt->qlt_port->port_nwwn, icb+0x14, 8);
	DMEM_WR16(qlt, icb+0x20, 3);	/* Login retry count */
	DMEM_WR16(qlt, icb+0x24, RESPONSE_QUEUE_ENTRIES);
	DMEM_WR16(qlt, icb+0x26, REQUEST_QUEUE_ENTRIES);
	if ((!qlt->qlt_83xx_chip) && (!qlt->qlt_81xx_chip) &&
	    (!qlt->qlt_27xx_chip)) {
		DMEM_WR16(qlt, icb+0x28, 100); /* ms of NOS/OLS for Link down */
	}
	if ((!qlt->qlt_83xx_chip) || (!qlt->qlt_27xx_chip)) {
		DMEM_WR16(qlt, icb+0x2a, PRIORITY_QUEUE_ENTRIES);
	}
	DMEM_WR64(qlt, icb+0x2c, (da+REQUEST_QUEUE_OFFSET));
	DMEM_WR64(qlt, icb+0x34, (da+RESPONSE_QUEUE_OFFSET));
	if ((!qlt->qlt_83xx_chip) || (!qlt->qlt_27xx_chip)) {
		DMEM_WR64(qlt, icb+0x3c, (da+PRIORITY_QUEUE_OFFSET));
	}
	/* XXX: all hba model atio/resp 0  use vector 0 */
	DMEM_WR16(qlt, icb+0x4e, ATIO_QUEUE_ENTRIES);
	DMEM_WR64(qlt, icb+0x50, (da+ATIO_QUEUE_OFFSET));
	DMEM_WR16(qlt, icb+0x58, 2);	/* Interrupt delay Timer */
	DMEM_WR16(qlt, icb+0x5a, 4);	/* Login timeout (secs) */
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_27xx_chip) || ((qlt->qlt_25xx_chip) &&
	    (qlt->qlt_mq_enabled))) {
		qlt_nvram_81xx_t *qlt81nvr = (qlt_nvram_81xx_t *)qlt->nvram;

		/* fw options 1 */
		if (qlt->qlt_fcoe_enabled) {
			DMEM_WR32(qlt, icb+0x5c, BIT_5 | BIT_4);
		} else {
			DMEM_WR32(qlt, icb+0x5c,
			    BIT_11 | BIT_5 | BIT_4 | BIT_2 | BIT_1 | BIT_0);
		}
		/* fw options 2 */
		if (qlt->qlt_mq_enabled) {
			if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
				if (qlt->qlt_fcoe_enabled) {
					DMEM_WR32(qlt, icb+0x60,
					    BIT_26 | BIT_23 | BIT_22);
				} else {
					DMEM_WR32(qlt, icb+0x60,
					    BIT_26 | BIT_23 | BIT_22 | BIT_5);
				}
			} else {
				DMEM_WR32(qlt,
				    icb+0x60, BIT_26 | BIT_23 | BIT_22 | BIT_5);
			}
		}

		/* fw options 3 */
		if (qlt->qlt_fcoe_enabled) {
			DMEM_WR32(qlt, icb+0x64, BIT_4);
		} else {
			DMEM_WR32(qlt, icb+0x64,
			    BIT_14 | BIT_8 | BIT_7 | BIT_4);
		}

		if (qlt->qlt_mq_enabled) {
			DMEM_WR16(qlt, icb+0x68, 5); /* QoS priority = 5 */
		}

		DMEM_WR32(qlt, icb+0x70,
		    qlt81nvr->enode_mac[0] |
		    (qlt81nvr->enode_mac[1] << 8) |
		    (qlt81nvr->enode_mac[2] << 16) |
		    (qlt81nvr->enode_mac[3] << 24));
		DMEM_WR16(qlt, icb+0x74,
		    qlt81nvr->enode_mac[4] |
		    (qlt81nvr->enode_mac[5] << 8));
	} else {
		DMEM_WR32(qlt, icb+0x5c, BIT_11 | BIT_5 | BIT_4 |
		    BIT_2 | BIT_1 | BIT_0);
		DMEM_WR32(qlt, icb+0x60, BIT_5);
		DMEM_WR32(qlt, icb+0x64, BIT_14 | BIT_8 | BIT_7 |
		    BIT_4);

/* null MID setup */
		DMEM_WR16(qlt, icb+0x80, 1); /* VP count 1 */
	}

	if (qlt->qlt_fcoe_enabled) {
		qlt_dmem_bctl_t		*bctl;
		uint32_t		index;
		caddr_t			src;
		caddr_t			dst;
		qlt_nvram_81xx_t	*qlt81nvr;

		dst = icb+0xA0;
		qlt81nvr = (qlt_nvram_81xx_t *)qlt->nvram;
		src = (caddr_t)&qlt81nvr->ext_blk;
		index = sizeof (qlt_ext_icb_81xx_t);

		/* Use defaults for cases where we find nothing in NVR */
		if ((qlt->qlt_83xx_chip) || (*src == 0)) {
			if (*src == 0) {
				EL(qlt, "nvram eicb=null\n");
				cmn_err(CE_NOTE, "qlt(%d) NVR eicb is zeroed",
				    instance);
			}
			qlt81nvr->ext_blk.version[0] = 1;
/*
 * not yet, for !FIP firmware at least
 *
 *                qlt81nvr->ext_blk.fcf_vlan_match = 0x81;
 */
#ifdef _LITTLE_ENDIAN
			qlt81nvr->ext_blk.fcf_vlan_id[0] = 0xEA;
			qlt81nvr->ext_blk.fcf_vlan_id[1] = 0x03;
#else
			qlt81nvr->ext_blk.fcf_vlan_id[1] = 0xEA;
			qlt81nvr->ext_blk.fcf_vlan_id[0] = 0x03;
#endif
		}

		while (index--) {
			*dst++ = *src++;
		}

		bctl = (qlt_dmem_bctl_t *)mcp->dbuf->db_port_private;
		da = bctl->bctl_dev_addr + 0xA0; /* base addr of eicb (phys) */

		mcp->to_fw[11] = LSW(LSD(da));
		mcp->to_fw[10] = MSW(LSD(da));
		mcp->to_fw[13] = LSW(MSD(da));
		mcp->to_fw[12] = MSW(MSD(da));
		mcp->to_fw[14] = (uint16_t)(sizeof (qlt_ext_icb_81xx_t) &
		    0xffff);

		/* eicb enable */
		mcp->to_fw[1] = (uint16_t)(mcp->to_fw[1] | BIT_0);
		mcp->to_fw_mask |= BIT_14 | BIT_13 | BIT_12 | BIT_11 | BIT_10 |
		    BIT_1;
	}

	qlt_dmem_dma_sync(mcp->dbuf, DDI_DMA_SYNC_FORDEV);
	if (((qlt->qlt_83xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_27xx_chip) || ((qlt->qlt_25xx_chip) &&
	    (qlt->qlt_mq_enabled))) && (qlt->fw_attr & BIT_6)) {
		mcp->to_fw[0] = MBC_INITIALIZE_MULTI_ID_FW;
	} else {
		mcp->to_fw[0] = MBC_INITIALIZE_FIRMWARE;
	}

	/*
	 * This is the 1st command after adapter initialize which will
	 * use interrupts and regular mailbox interface.
	 */
	qlt->qlt_intr_enabled = 1;
	qlt->mbox_io_state = MBOX_STATE_READY;
	REG_WR32(qlt, REG_INTR_CTRL, ENABLE_RISC_INTR);
	/* Issue mailbox to firmware */
	ret = qlt_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_mbox_command=48h/60h status=%llxh\n", ret);
		cmn_err(CE_NOTE, "qlt(%d) init fw failed %llx, intr status %x",
		    instance, (long long)ret, REG_RD32(qlt, REG_INTR_STATUS));
		qlt_free_mailbox_command(qlt, mcp);
		return (ret);
	}

	mcp->to_fw_mask = BIT_0;
	mcp->from_fw_mask = BIT_0 | BIT_1;
	mcp->to_fw[0] = 0x28;
	ret = qlt_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_mbox_command=28h status=%llxh\n", ret);
		cmn_err(CE_NOTE, "qlt(%d) get_fw_options %llx", instance,
		    (long long)ret);
		qlt_free_mailbox_command(qlt, mcp);
		return (ret);
	}

	if (qlt->qlt_mq_enabled == 1) {

		for (i = 1; i < qlt->qlt_queue_cnt; i++) {
			da = qlt->mq_resp[i].queue_mem_mq_cookie.dmac_laddress;

			mcp->to_fw_mask = BIT_14 | BIT_13 | BIT_12 | BIT_11 |
			    BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 |
			    BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0;
			mcp->from_fw_mask = BIT_0 | BIT_1;

			/* msix vector setup */
			mcp->to_fw[14] = (uint16_t)(i);

			mcp->to_fw[13] = 0;
			mcp->to_fw[12] = 0;
			mcp->to_fw[11] = 0;
			mcp->to_fw[10] = 0;
			mcp->to_fw[9] = 0;
			mcp->to_fw[8] = 0;
			mcp->to_fw[7] = LSW(MSD(da));
			mcp->to_fw[6] = MSW(MSD(da));
			mcp->to_fw[5] = RESPONSE_QUEUE_MQ_ENTRIES;
			mcp->to_fw[4] = (uint16_t)(i);
			mcp->to_fw[3] = LSW(LSD(da));
			mcp->to_fw[2] = MSW(LSD(da));
			mcp->to_fw[1] = BIT_6 | BIT_1;
			mcp->to_fw[0] = 0x1F;
			ret = qlt_mailbox_command(qlt, mcp);

			if (ret != QLT_SUCCESS) {
				EL(qlt, "qlt_mbox_command=1fh status=%llxh\n",
				    ret);
				cmn_err(CE_NOTE, "qlt(%d) queue manage %llx",
				    instance, (long long)ret);
				qlt_free_mailbox_command(qlt, mcp);
				return (ret);
			}

			da = qlt->mq_req[i].queue_mem_mq_cookie.dmac_laddress;

			mcp->to_fw_mask = BIT_14 | BIT_13 | BIT_12 | BIT_11 |
			    BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 |
			    BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0;
			mcp->from_fw_mask = BIT_0 | BIT_1;

			/*
			 * msix vector does not apply for request queue create
			 */
			mcp->to_fw[14] = 2;
			mcp->to_fw[13] = 0;
			mcp->to_fw[12] = 4;
			mcp->to_fw[11] = 0;
			mcp->to_fw[10] = (uint16_t)(i);
			mcp->to_fw[9] = 0;
			mcp->to_fw[8] = 0;
			mcp->to_fw[7] = LSW(MSD(da));
			mcp->to_fw[6] = MSW(MSD(da));
			mcp->to_fw[5] = REQUEST_QUEUE_MQ_ENTRIES;
			mcp->to_fw[4] = (uint16_t)(i);
			mcp->to_fw[3] = LSW(LSD(da));
			mcp->to_fw[2] = MSW(LSD(da));
			mcp->to_fw[1] = BIT_6;
			mcp->to_fw[0] = 0x1F;
			ret = qlt_mailbox_command(qlt, mcp);

			if (ret != QLT_SUCCESS) {
				EL(qlt, "qlt_mbox_command=1fh status=%llxh\n",
				    ret);
				cmn_err(CE_NOTE, "qlt(%d) queue manage %llx",
				    instance, (long long)ret);
				qlt_free_mailbox_command(qlt, mcp);
				return (ret);
			}
		}
	}

	/*
	 * Report FW versions for 81xx - MPI rev is useful
	 */
	/* if ((qlt->qlt_83xx_chip) || (qlt->qlt_81xx_chip)) { */
	if (qlt->qlt_fcoe_enabled) {
		mcp->to_fw_mask = BIT_0;
		mcp->from_fw_mask = BIT_11 | BIT_10 | BIT_6 | BIT_3 | BIT_2 |
		    BIT_1 | BIT_0;

		mcp->to_fw[0] = MBC_ABOUT_FIRMWARE;
		ret = qlt_mailbox_command(qlt, mcp);
		if (ret != QLT_SUCCESS) {
			EL(qlt, "about fw failed: %llx\n", (long long)ret);
		} else {
			EL(qlt, "Firmware version %d.%d.%d, MPI: %d.%d.%d\n",
			    mcp->from_fw[1], mcp->from_fw[2], mcp->from_fw[3],
			    mcp->from_fw[10] & 0xff, mcp->from_fw[11] >> 8,
			    mcp->from_fw[11] & 0xff);
			EL(qlt, "Firmware Attributes %x[h]\n",
			    mcp->from_fw[6]);
		}
	}

	qlt_free_mailbox_command(qlt, mcp);

	for (i = 0; i < 5; i++) {
		qlt->qlt_bufref[i] = 0;
	}
	qlt->qlt_bumpbucket = 0;
	qlt->qlt_pmintry = 0;
	qlt->qlt_pmin_ok = 0;

	if (ret != QLT_SUCCESS)
		return (ret);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_port_offline(qlt_state_t *qlt)
{
	int retries;
	int i;

	mutex_enter(&qlt->mbox_lock);

	if (qlt->mbox_io_state == MBOX_STATE_UNKNOWN) {
		mutex_exit(&qlt->mbox_lock);
		goto poff_mbox_done;
	}

	/* Wait to grab the mailboxes */
	for (retries = 0; qlt->mbox_io_state != MBOX_STATE_READY;
	    retries++) {
		cv_wait(&qlt->mbox_cv, &qlt->mbox_lock);
		if ((retries > 5) ||
		    (qlt->mbox_io_state == MBOX_STATE_UNKNOWN)) {
			qlt->mbox_io_state = MBOX_STATE_UNKNOWN;
			mutex_exit(&qlt->mbox_lock);
			goto poff_mbox_done;
		}
	}
	qlt->mbox_io_state = MBOX_STATE_UNKNOWN;
	mutex_exit(&qlt->mbox_lock);
poff_mbox_done:;
	qlt->intr_sneak_counter = 10;
	mutex_enter(&qlt->intr_lock);
	if (qlt->qlt_mq_enabled == 1) {
		for (i = 1; i < qlt->qlt_queue_cnt; i++) {
			mutex_enter(&qlt->mq_resp[i].mq_lock);
		}
	}
	(void) qlt_reset_chip(qlt);
	drv_usecwait(20);
	qlt->intr_sneak_counter = 0;
	if (qlt->qlt_mq_enabled == 1) {
		for (i = 1; i < qlt->qlt_queue_cnt; i++) {
			mutex_exit(&qlt->mq_resp[i].mq_lock);
		}
	}
	mutex_exit(&qlt->intr_lock);

	return (FCT_SUCCESS);
}

static fct_status_t
qlt_get_link_info(fct_local_port_t *port, fct_link_info_t *li)
{
	qlt_state_t *qlt = (qlt_state_t *)port->port_fca_private;
	mbox_cmd_t *mcp;
	fct_status_t fc_ret;
	fct_status_t ret;
	clock_t et;

	et = ddi_get_lbolt() + drv_usectohz(5000000);
	mcp = qlt_alloc_mailbox_command(qlt, 0);
link_info_retry:
	mcp->to_fw[0] = MBC_GET_ID;
	mcp->to_fw[9] = 0;
	mcp->to_fw_mask |= BIT_0 | BIT_9;
	mcp->from_fw_mask |= BIT_0 | BIT_1 | BIT_2 | BIT_3 | BIT_6 | BIT_7;
	/* Issue mailbox to firmware */
	ret = qlt_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_mbox_command=20h status=%llxh\n", ret);
		if ((mcp->from_fw[0] == 0x4005) &&
		    ((mcp->from_fw[1] == 7) || (mcp->from_fw[1] == 0x1b))) {
			/* Firmware is not ready */
			if (ddi_get_lbolt() < et) {
				delay(drv_usectohz(50000));
				goto link_info_retry;
			}
		}
		EL(qlt, "GET ID mbox failed, ret=%llx mb0=%x mb1=%x",
		    ret, mcp->from_fw[0], mcp->from_fw[1]);
		stmf_trace(qlt->qlt_port_alias, "GET ID mbox failed, ret=%llx "
		    "mb0=%x mb1=%x", ret, mcp->from_fw[0], mcp->from_fw[1]);
		fc_ret = FCT_FAILURE;
	} else {
		li->portid = ((uint32_t)(mcp->from_fw[2])) |
		    (((uint32_t)(mcp->from_fw[3])) << 16);

		li->port_speed = qlt->link_speed;
		switch (mcp->from_fw[6]) {
		case 1:
			li->port_topology = PORT_TOPOLOGY_PUBLIC_LOOP;
			li->port_fca_flogi_done = 1;
			break;
		case 0:
			li->port_topology = PORT_TOPOLOGY_PRIVATE_LOOP;
			li->port_no_fct_flogi = 1;
			break;
		case 3:
			li->port_topology = PORT_TOPOLOGY_FABRIC_PT_TO_PT;
			li->port_fca_flogi_done = 1;
			break;
		case 2: /*FALLTHROUGH*/
		case 4:
			li->port_topology = PORT_TOPOLOGY_PT_TO_PT;
			li->port_fca_flogi_done = 1;
			break;
		default:
			li->port_topology = PORT_TOPOLOGY_UNKNOWN;
			EL(qlt, "Unknown topology=%xh\n", mcp->from_fw[6]);
		}
		qlt->cur_topology = li->port_topology;
		fc_ret = FCT_SUCCESS;

		EL(qlt, "MBC_GET_ID done, Topology=%x, portid=%xh, "
		    "port speed=%xh\n", li->port_topology, li->portid,
		    li->port_speed);
	}
	qlt_free_mailbox_command(qlt, mcp);

	if ((fc_ret == FCT_SUCCESS) && (li->port_fca_flogi_done)) {
		mcp = qlt_alloc_mailbox_command(qlt, 64);
		mcp->to_fw[0] = MBC_GET_PORT_DATABASE;
		mcp->to_fw[1] = 0x7FE;
		mcp->to_fw[9] = 0;
		mcp->to_fw[10] = 0;
		mcp->to_fw_mask |= BIT_0 | BIT_1 | BIT_9 | BIT_10;
		fc_ret = qlt_mailbox_command(qlt, mcp);
		if (fc_ret != QLT_SUCCESS) {
			EL(qlt, "qlt_mbox_command=64h status=%llxh\n",
			    fc_ret);
			stmf_trace(qlt->qlt_port_alias, "Attempt to get port "
			    "database for F_port failed, ret = %llx", fc_ret);
		} else {
			uint8_t *p;

			qlt_dmem_dma_sync(mcp->dbuf, DDI_DMA_SYNC_FORCPU);
			p = mcp->dbuf->db_sglist[0].seg_addr;
			bcopy(p + 0x18, li->port_rpwwn, 8);
			bcopy(p + 0x20, li->port_rnwwn, 8);
			EL(qlt, "qlt_mbox_command=64h, GET_PORT_DATABASE "
			    "complete\n");
		}
		qlt_free_mailbox_command(qlt, mcp);
	}
	return (fc_ret);
}

static int
qlt_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	int		instance;
	qlt_state_t	*qlt;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	/*
	 * Since this is for debugging only, only allow root to issue ioctl now
	 */
	if (drv_priv(credp)) {
		return (EPERM);
	}

	instance = (int)getminor(*devp);
	qlt = ddi_get_soft_state(qlt_state, instance);
	if (qlt == NULL) {
		return (ENXIO);
	}

	mutex_enter(&qlt->qlt_ioctl_lock);
	if (qlt->qlt_ioctl_flags & QLT_IOCTL_FLAG_EXCL) {
		/*
		 * It is already open for exclusive access.
		 * So shut the door on this caller.
		 */
		mutex_exit(&qlt->qlt_ioctl_lock);
		return (EBUSY);
	}

	if (flag & FEXCL) {
		if (qlt->qlt_ioctl_flags & QLT_IOCTL_FLAG_OPEN) {
			/*
			 * Exclusive operation not possible
			 * as it is already opened
			 */
			mutex_exit(&qlt->qlt_ioctl_lock);
			return (EBUSY);
		}
		qlt->qlt_ioctl_flags |= QLT_IOCTL_FLAG_EXCL;
	}
	qlt->qlt_ioctl_flags |= QLT_IOCTL_FLAG_OPEN;
	mutex_exit(&qlt->qlt_ioctl_lock);

	return (0);
}

/* ARGSUSED */
static int
qlt_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	int		instance;
	qlt_state_t	*qlt;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	instance = (int)getminor(dev);
	qlt = ddi_get_soft_state(qlt_state, instance);
	if (qlt == NULL) {
		return (ENXIO);
	}

	mutex_enter(&qlt->qlt_ioctl_lock);
	if ((qlt->qlt_ioctl_flags & QLT_IOCTL_FLAG_OPEN) == 0) {
		mutex_exit(&qlt->qlt_ioctl_lock);
		return (ENODEV);
	}

	/*
	 * It looks there's one hole here, maybe there could several concurrent
	 * shareed open session, but we never check this case.
	 * But it will not hurt too much, disregard it now.
	 */
	qlt->qlt_ioctl_flags &= ~QLT_IOCTL_FLAG_MASK;
	mutex_exit(&qlt->qlt_ioctl_lock);

	return (0);
}

/*
 * All of these ioctls are unstable interfaces which are meant to be used
 * in a controlled lab env. No formal testing will be (or needs to be) done
 * for these ioctls. Specially note that running with an additional
 * uploaded firmware is not supported and is provided here for test
 * purposes only.
 */
/* ARGSUSED */
static int
qlt_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval)
{
	qlt_state_t	*qlt;
	int		ret = 0;
#ifdef _LITTLE_ENDIAN
	int		i;
#endif
	stmf_iocdata_t	*iocd;
	void		*ibuf = NULL;
	void		*obuf = NULL;
	uint32_t	*intp;
	qlt_fw_info_t	*fwi;
	mbox_cmd_t	*mcp;
	fct_status_t	st;
	char		info[80];
	fct_status_t	ret2;

	if (drv_priv(credp) != 0)
		return (EPERM);

	qlt = ddi_get_soft_state(qlt_state, (int32_t)getminor(dev));
	ret = stmf_copyin_iocdata(data, mode, &iocd, &ibuf, &obuf);
	if (ret)
		return (ret);
	iocd->stmf_error = 0;

	switch (cmd) {
	case QLT_IOCTL_FETCH_FWDUMP:
		if (iocd->stmf_obuf_size < QLT_FWDUMP_BUFSIZE) {
			EL(qlt, "FETCH_FWDUMP obuf_size=%d < %d\n",
			    iocd->stmf_obuf_size, QLT_FWDUMP_BUFSIZE);
			ret = EINVAL;
			break;
		}
		mutex_enter(&qlt->qlt_ioctl_lock);
		if (!(qlt->qlt_ioctl_flags & QLT_FWDUMP_ISVALID)) {
			mutex_exit(&qlt->qlt_ioctl_lock);
			ret = ENODATA;
			EL(qlt, "no fwdump\n");
			iocd->stmf_error = QLTIO_NO_DUMP;
			break;
		}
		if (qlt->qlt_ioctl_flags & QLT_FWDUMP_INPROGRESS) {
			mutex_exit(&qlt->qlt_ioctl_lock);
			ret = EBUSY;
			EL(qlt, "fwdump inprogress\n");
			iocd->stmf_error = QLTIO_DUMP_INPROGRESS;
			break;
		}
		if (qlt->qlt_ioctl_flags & QLT_FWDUMP_FETCHED_BY_USER) {
			mutex_exit(&qlt->qlt_ioctl_lock);
			ret = EEXIST;
			EL(qlt, "fwdump already fetched\n");
			iocd->stmf_error = QLTIO_ALREADY_FETCHED;
			break;
		}
		bcopy(qlt->qlt_fwdump_buf, obuf, QLT_FWDUMP_BUFSIZE);
		qlt->qlt_ioctl_flags |= QLT_FWDUMP_FETCHED_BY_USER;
		mutex_exit(&qlt->qlt_ioctl_lock);

		break;

	case QLT_IOCTL_TRIGGER_FWDUMP:
		if (qlt->qlt_state != FCT_STATE_ONLINE) {
			ret = EACCES;
			iocd->stmf_error = QLTIO_NOT_ONLINE;
			break;
		}
		(void) snprintf(info, 80, "qlt_ioctl: qlt-%p, "
		    "user triggered FWDUMP with RFLAG_RESET", (void *)qlt);
		info[79] = 0;
		if ((ret2 = fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_USER_REQUEST | STMF_RFLAG_RESET |
		    STMF_RFLAG_COLLECT_DEBUG_DUMP, info)) != FCT_SUCCESS) {
			EL(qlt, "TRIGGER_FWDUMP fct_port_shutdown status="
			    "%llxh\n", ret2);
			ret = EIO;
		}
		break;
	case QLT_IOCTL_UPLOAD_FW:
		if ((iocd->stmf_ibuf_size < 1024) ||
		    (iocd->stmf_ibuf_size & 3)) {
			EL(qlt, "UPLOAD_FW ibuf_size=%d < 1024\n",
			    iocd->stmf_ibuf_size);
			ret = EINVAL;
			iocd->stmf_error = QLTIO_INVALID_FW_SIZE;
			break;
		}
		intp = (uint32_t *)ibuf;
#ifdef _LITTLE_ENDIAN
		for (i = 0; (i << 2) < iocd->stmf_ibuf_size; i++) {
			intp[i] = BSWAP_32(intp[i]);
		}
#endif
		if (((intp[3] << 2) >= iocd->stmf_ibuf_size) ||
		    (((intp[intp[3] + 3] + intp[3]) << 2) !=
		    iocd->stmf_ibuf_size)) {
			EL(qlt, "UPLOAD_FW fw_size=%d >= %d\n", intp[3] << 2,
			    iocd->stmf_ibuf_size);
			ret = EINVAL;
			iocd->stmf_error = QLTIO_INVALID_FW_SIZE;
			break;
		}
		if ((qlt->qlt_81xx_chip && ((intp[8] & 8) == 0)) ||
		    (qlt->qlt_25xx_chip && ((intp[8] & 4) == 0)) ||
		    (!qlt->qlt_25xx_chip && !qlt->qlt_81xx_chip &&
		    !qlt->qlt_83xx_chip && !qlt->qlt_27xx_chip &&
		    ((intp[8] & 3) == 0))) {
			EL(qlt, "UPLOAD_FW fw_type=%d\n", intp[8]);
			ret = EACCES;
			iocd->stmf_error = QLTIO_INVALID_FW_TYPE;
			break;
		}

		/* Everything looks ok, lets copy this firmware */
		if (qlt->fw_code01) {
			kmem_free(qlt->fw_code01, (qlt->fw_length01 +
			    qlt->fw_length02) << 2);
			qlt->fw_code01 = NULL;
		} else {
			atomic_inc_32(&qlt_loaded_counter);
		}
		qlt->fw_length01 = intp[3];
		qlt->fw_code01 = (uint32_t *)kmem_alloc(iocd->stmf_ibuf_size,
		    KM_SLEEP);
		bcopy(intp, qlt->fw_code01, iocd->stmf_ibuf_size);
		qlt->fw_addr01 = intp[2];
		qlt->fw_code02 = &qlt->fw_code01[intp[3]];
		qlt->fw_addr02 = qlt->fw_code02[2];
		qlt->fw_length02 = qlt->fw_code02[3];
		break;

	case QLT_IOCTL_CLEAR_FW:
		if (qlt->fw_code01) {
			kmem_free(qlt->fw_code01, (qlt->fw_length01 +
			    qlt->fw_length02) << 2);
			qlt->fw_code01 = NULL;
			atomic_dec_32(&qlt_loaded_counter);
		}
		break;

	case QLT_IOCTL_GET_FW_INFO:
		if (iocd->stmf_obuf_size != sizeof (qlt_fw_info_t)) {
			EL(qlt, "GET_FW_INFO obuf_size=%d != %d\n",
			    iocd->stmf_obuf_size, sizeof (qlt_fw_info_t));
			ret = EINVAL;
			break;
		}
		fwi = (qlt_fw_info_t *)obuf;
		if (qlt->qlt_stay_offline) {
			fwi->fwi_stay_offline = 1;
		}
		if (qlt->qlt_state == FCT_STATE_ONLINE) {
			fwi->fwi_port_active = 1;
		}
		fwi->fwi_active_major = qlt->fw_major;
		fwi->fwi_active_minor = qlt->fw_minor;
		fwi->fwi_active_subminor = qlt->fw_subminor;
		fwi->fwi_active_attr = qlt->fw_attr;
		if (qlt->fw_code01) {
			fwi->fwi_fw_uploaded = 1;
			fwi->fwi_loaded_major = (uint16_t)qlt->fw_code01[4];
			fwi->fwi_loaded_minor = (uint16_t)qlt->fw_code01[5];
			fwi->fwi_loaded_subminor = (uint16_t)qlt->fw_code01[6];
			fwi->fwi_loaded_attr = (uint16_t)qlt->fw_code01[7];
		}
		if (qlt->qlt_27xx_chip) {
			fwi->fwi_default_major = (uint16_t)fw2700_code01[4];
			fwi->fwi_default_minor = (uint16_t)fw2700_code01[5];
			fwi->fwi_default_subminor = (uint16_t)fw2700_code01[6];
			fwi->fwi_default_attr = (uint16_t)fw2700_code01[7];
		} else if (qlt->qlt_83xx_chip) {
			fwi->fwi_default_major = (uint16_t)fw8300fc_code01[4];
			fwi->fwi_default_minor = (uint16_t)fw8300fc_code01[5];
			fwi->fwi_default_subminor =
			    (uint16_t)fw8300fc_code01[6];
			fwi->fwi_default_attr = (uint16_t)fw8300fc_code01[7];
		} else if (qlt->qlt_81xx_chip) {
			fwi->fwi_default_major = (uint16_t)fw8100_code01[4];
			fwi->fwi_default_minor = (uint16_t)fw8100_code01[5];
			fwi->fwi_default_subminor = (uint16_t)fw8100_code01[6];
			fwi->fwi_default_attr = (uint16_t)fw8100_code01[7];
		} else if (qlt->qlt_25xx_chip) {
			fwi->fwi_default_major = (uint16_t)fw2500_code01[4];
			fwi->fwi_default_minor = (uint16_t)fw2500_code01[5];
			fwi->fwi_default_subminor = (uint16_t)fw2500_code01[6];
			fwi->fwi_default_attr = (uint16_t)fw2500_code01[7];
		} else {
			fwi->fwi_default_major = (uint16_t)fw2400_code01[4];
			fwi->fwi_default_minor = (uint16_t)fw2400_code01[5];
			fwi->fwi_default_subminor = (uint16_t)fw2400_code01[6];
			fwi->fwi_default_attr = (uint16_t)fw2400_code01[7];
		}
		break;

	case QLT_IOCTL_STAY_OFFLINE:
		if (!iocd->stmf_ibuf_size) {
			EL(qlt, "STAY_OFFLINE ibuf_size=%d\n",
			    iocd->stmf_ibuf_size);
			ret = EINVAL;
			break;
		}
		if (*((char *)ibuf)) {
			qlt->qlt_stay_offline = 1;
		} else {
			qlt->qlt_stay_offline = 0;
		}
		break;

	case QLT_IOCTL_MBOX:
		if ((iocd->stmf_ibuf_size < sizeof (qlt_ioctl_mbox_t)) ||
		    (iocd->stmf_obuf_size < sizeof (qlt_ioctl_mbox_t))) {
			EL(qlt, "IOCTL_MBOX ibuf_size=%d, obuf_size=%d\n",
			    iocd->stmf_ibuf_size, iocd->stmf_obuf_size);
			ret = EINVAL;
			break;
		}
		mcp = qlt_alloc_mailbox_command(qlt, 0);
		if (mcp == NULL) {
			EL(qlt, "IOCTL_MBOX mcp == NULL\n");
			ret = ENOMEM;
			break;
		}
		bcopy(ibuf, mcp, sizeof (qlt_ioctl_mbox_t));
		st = qlt_mailbox_command(qlt, mcp);
		bcopy(mcp, obuf, sizeof (qlt_ioctl_mbox_t));
		qlt_free_mailbox_command(qlt, mcp);
		if (st != QLT_SUCCESS) {
			if ((st & (~((uint64_t)(0xFFFF)))) == QLT_MBOX_FAILED)
				st = QLT_SUCCESS;
		}
		if (st != QLT_SUCCESS) {
			EL(qlt, "IOCTL_MBOX status=%xh\n", st);
			ret = EIO;
			switch (st) {
			case QLT_MBOX_NOT_INITIALIZED:
				iocd->stmf_error = QLTIO_MBOX_NOT_INITIALIZED;
				break;
			case QLT_MBOX_BUSY:
				iocd->stmf_error = QLTIO_CANT_GET_MBOXES;
				break;
			case QLT_MBOX_TIMEOUT:
				iocd->stmf_error = QLTIO_MBOX_TIMED_OUT;
				break;
			case QLT_MBOX_ABORTED:
				iocd->stmf_error = QLTIO_MBOX_ABORTED;
				break;
			}
		}
		break;

	case QLT_IOCTL_ELOG:
		EL(qlt, "Not support yet, ioctl-%xh\n", cmd);
		break;

	default:
		EL(qlt, "Unknown ioctl-%xh\n", cmd);
		ret = ENOTTY;
	}

	if (ret == 0) {
		ret = stmf_copyout_iocdata(data, mode, iocd, obuf);
	} else if (iocd->stmf_error) {
		(void) stmf_copyout_iocdata(data, mode, iocd, obuf);
	}
	if (obuf) {
		kmem_free(obuf, iocd->stmf_obuf_size);
		obuf = NULL;
	}
	if (ibuf) {
		kmem_free(ibuf, iocd->stmf_ibuf_size);
		ibuf = NULL;
	}
	kmem_free(iocd, sizeof (stmf_iocdata_t));
	return (ret);
}

static fct_status_t
qlt_force_lip(qlt_state_t *qlt)
{
	mbox_cmd_t	*mcp;
	fct_status_t	 rval;

	mcp = qlt_alloc_mailbox_command(qlt, 0);
	if (qlt->qlt_fcoe_enabled) {
		mcp->to_fw[0] = MBC_PORT_RESET;
	} else {
		mcp->to_fw[0] = MBC_LIP_FULL_LOGIN;
		mcp->to_fw[1] = BIT_4;
		mcp->to_fw[3] = 1;
		mcp->to_fw_mask |= BIT_1 | BIT_3;
	}
	rval = qlt_mailbox_command(qlt, mcp);
	if (rval != FCT_SUCCESS) {
		EL(qlt, "qlt force lip MB failed: rval=%x\n", rval);
	} else {
		if (mcp->from_fw[0] != QLT_MBX_CMD_SUCCESS) {
			QLT_LOG(qlt->qlt_port_alias, "qlt FLIP: fw[0]=%x",
			    mcp->from_fw[0]);
			rval = FCT_FAILURE;
		}
	}
	qlt_free_mailbox_command(qlt, mcp);
	return (rval);
}

static void
qlt_ctl(struct fct_local_port *port, int cmd, void *arg)
{
	stmf_change_status_t		st;
	stmf_state_change_info_t	*ssci = (stmf_state_change_info_t *)arg;
	qlt_state_t			*qlt;
	fct_status_t			ret;

	ASSERT((cmd == FCT_CMD_PORT_ONLINE) ||
	    (cmd == FCT_CMD_PORT_OFFLINE) ||
	    (cmd == FCT_CMD_FORCE_LIP) ||
	    (cmd == FCT_ACK_PORT_ONLINE_COMPLETE) ||
	    (cmd == FCT_ACK_PORT_OFFLINE_COMPLETE));

	qlt = (qlt_state_t *)port->port_fca_private;
	st.st_completion_status = FCT_SUCCESS;
	st.st_additional_info = NULL;

	EL(qlt, "port (%p) qlt_state (%xh) cmd (%xh) arg (%p)\n",
	    port, qlt->qlt_state, cmd, arg);

	switch (cmd) {
	case FCT_CMD_PORT_ONLINE:
		if (qlt->qlt_state == FCT_STATE_ONLINE)
			st.st_completion_status = STMF_ALREADY;
		else if (qlt->qlt_state != FCT_STATE_OFFLINE)
			st.st_completion_status = FCT_FAILURE;
		if (st.st_completion_status == FCT_SUCCESS) {
			qlt->qlt_state = FCT_STATE_ONLINING;
			qlt->qlt_state_not_acked = 1;
			st.st_completion_status = qlt_port_online(qlt);
			if (st.st_completion_status != STMF_SUCCESS) {
				EL(qlt, "PORT_ONLINE status=%xh\n",
				    st.st_completion_status);
				qlt->qlt_state = FCT_STATE_OFFLINE;
				qlt->qlt_state_not_acked = 0;
			} else {
				qlt->qlt_state = FCT_STATE_ONLINE;
			}
		}
		fct_ctl(port->port_lport, FCT_CMD_PORT_ONLINE_COMPLETE, &st);
		qlt->qlt_change_state_flags = 0;
		break;

	case FCT_CMD_PORT_OFFLINE:
		if (qlt->qlt_state == FCT_STATE_OFFLINE) {
			st.st_completion_status = STMF_ALREADY;
		} else if (qlt->qlt_state != FCT_STATE_ONLINE) {
			st.st_completion_status = FCT_FAILURE;
		}
		if (st.st_completion_status == FCT_SUCCESS) {
			qlt->qlt_state = FCT_STATE_OFFLINING;
			qlt->qlt_state_not_acked = 1;

			if (ssci->st_rflags & STMF_RFLAG_COLLECT_DEBUG_DUMP) {
				(void) qlt_firmware_dump(port, ssci);
			}
			qlt->qlt_change_state_flags = (uint32_t)ssci->st_rflags;
			st.st_completion_status = qlt_port_offline(qlt);
			if (st.st_completion_status != STMF_SUCCESS) {
				EL(qlt, "PORT_OFFLINE status=%xh\n",
				    st.st_completion_status);
				qlt->qlt_state = FCT_STATE_ONLINE;
				qlt->qlt_state_not_acked = 0;
			} else {
				qlt->qlt_state = FCT_STATE_OFFLINE;
			}
		}
		fct_ctl(port->port_lport, FCT_CMD_PORT_OFFLINE_COMPLETE, &st);
		break;

	case FCT_ACK_PORT_ONLINE_COMPLETE:
		qlt->qlt_state_not_acked = 0;
		break;

	case FCT_ACK_PORT_OFFLINE_COMPLETE:
		qlt->qlt_state_not_acked = 0;
		if ((qlt->qlt_change_state_flags & STMF_RFLAG_RESET) &&
		    (qlt->qlt_stay_offline == 0)) {
			if ((ret = fct_port_initialize(port,
			    qlt->qlt_change_state_flags,
			    "qlt_ctl FCT_ACK_PORT_OFFLINE_COMPLETE "
			    "with RLFLAG_RESET")) != FCT_SUCCESS) {
				EL(qlt, "fct_port_initialize status=%llxh\n",
				    ret);
				cmn_err(CE_WARN, "qlt_ctl: "
				    "fct_port_initialize failed, please use "
				    "stmfstate to start the port-%s manualy",
				    qlt->qlt_port_alias);
			}
		}
		break;

	case FCT_CMD_FORCE_LIP:
		if (qlt->qlt_fcoe_enabled) {
			EL(qlt, "force lip is an unsupported command "
			    "for this adapter type\n");
		} else {
			if (qlt->qlt_state == FCT_STATE_ONLINE) {
				*((fct_status_t *)arg) = qlt_force_lip(qlt);
				EL(qlt, "forcelip done\n");
			}
		}
		break;

	default:
		EL(qlt, "unsupport cmd - 0x%02X\n", cmd);
		break;
	}
}

/* ARGSUSED */
static fct_status_t
qlt_do_flogi(fct_local_port_t *port, fct_flogi_xchg_t *fx)
{
	qlt_state_t	*qlt = (qlt_state_t *)port->port_fca_private;

	EL(qlt, "FLOGI requested not supported\n");
	cmn_err(CE_WARN, "qlt: FLOGI requested (not supported)");
	return (FCT_FAILURE);
}

/*
 * Return a pointer to n entries in the request queue. Assumes that
 * request queue lock is held. Does a very short busy wait if
 * less/zero entries are available. Retuns NULL if it still cannot
 * fullfill the request.
 * **CALL qlt_submit_req_entries() BEFORE DROPPING THE LOCK**
 */
caddr_t
qlt_get_req_entries(qlt_state_t *qlt, uint32_t n, uint16_t qi)
{
	int try = 0;

	while (qlt->mq_req[qi].mq_available < n) {
		uint32_t val1, val2, val3;

		if (qlt->qlt_mq_enabled) {
			/* debounce */
			val1 = MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_REQ_OUT);
			val2 = MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_REQ_OUT);
			val3 = MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_REQ_OUT);
		} else {
			val1 = REG_RD32(qlt, REG_REQ_OUT_PTR);
			val2 = REG_RD32(qlt, REG_REQ_OUT_PTR);
			val3 = REG_RD32(qlt, REG_REQ_OUT_PTR);
		}
		if ((val1 != val2) || (val2 != val3))
			continue;

		qlt->mq_req[qi].mq_ndx_from_fw = val1;
		if (qi != 0) {
			qlt->mq_req[qi].mq_available =
			    REQUEST_QUEUE_MQ_ENTRIES - 1 -
			    ((qlt->mq_req[qi].mq_ndx_to_fw -
			    qlt->mq_req[qi].mq_ndx_from_fw) &
			    (REQUEST_QUEUE_MQ_ENTRIES - 1));
		} else {
			qlt->mq_req[qi].mq_available =
			    REQUEST_QUEUE_ENTRIES - 1 -
			    ((qlt->mq_req[qi].mq_ndx_to_fw -
			    qlt->mq_req[qi].mq_ndx_from_fw) &
			    (REQUEST_QUEUE_ENTRIES - 1));
		}
		if (qlt->mq_req[qi].mq_available < n) {
			if (try < 2) {
				drv_usecwait(100);
				try++;
				continue;
			} else {
				stmf_trace(qlt->qlt_port_alias,
				    "Req Q# %xh is full", qi);
				EL(qlt, "Req %xh is full (%d,%d) (%d,%d)\n",
				    qi, qlt->mq_req[qi].mq_ndx_to_fw,
				    qlt->mq_req[qi].mq_ndx_from_fw,
				    n, qlt->mq_req[qi].mq_available);
				return (NULL);
			}
		}
		break;
	}
	/* We dont change anything until the entries are sumitted */
	return (&qlt->mq_req[qi].mq_ptr[qlt->mq_req[qi].mq_ndx_to_fw << 6]);
}

/*
 * updates the req in ptr to fw. Assumes that req lock is held.
 */
void
qlt_submit_req_entries(qlt_state_t *qlt, uint32_t n, uint16_t qi)
{

	ASSERT(n >= 1);

	qlt->mq_req[qi].mq_ndx_to_fw += n;
	if (qi != 0) {
		qlt->mq_req[qi].mq_ndx_to_fw &= REQUEST_QUEUE_MQ_ENTRIES - 1;
	} else {
		qlt->mq_req[qi].mq_ndx_to_fw &= REQUEST_QUEUE_ENTRIES - 1;
	}
	qlt->mq_req[qi].mq_available -= n;

	if (qlt->qlt_mq_enabled) {
		MQBAR_WR32(qlt, (qi * MQBAR_REG_OFFSET) + MQBAR_REQ_IN,
		    qlt->mq_req[qi].mq_ndx_to_fw);
	} else {
		REG_WR32(qlt, REG_REQ_IN_PTR, qlt->mq_req[0].mq_ndx_to_fw);
	}
}

/*
 * Return a pointer to n entries in the priority request queue. Assumes that
 * priority request queue lock is held. Does a very short busy wait if
 * less/zero entries are available. Retuns NULL if it still cannot
 * fullfill the request.
 * **CALL qlt_submit_preq_entries() BEFORE DROPPING THE LOCK**
 */
caddr_t
qlt_get_preq_entries(qlt_state_t *qlt, uint32_t n)
{
	int try = 0;
	uint32_t req_available = PRIORITY_QUEUE_ENTRIES - 1 -
	    ((qlt->preq_ndx_to_fw - qlt->preq_ndx_from_fw) &
	    (PRIORITY_QUEUE_ENTRIES - 1));

	while (req_available < n) {
		uint32_t val1, val2, val3;
		val1 = REG_RD32(qlt, REG_PREQ_OUT_PTR);
		val2 = REG_RD32(qlt, REG_PREQ_OUT_PTR);
		val3 = REG_RD32(qlt, REG_PREQ_OUT_PTR);
		if ((val1 != val2) || (val2 != val3))
			continue;

		qlt->preq_ndx_from_fw = val1;
		req_available = PRIORITY_QUEUE_ENTRIES - 1 -
		    ((qlt->preq_ndx_to_fw - qlt->preq_ndx_from_fw) &
		    (PRIORITY_QUEUE_ENTRIES - 1));
		if (req_available < n) {
			if (try < 2) {
				drv_usecwait(100);
				try++;
				continue;
			} else {
				return (NULL);
			}
		}
		break;
	}
	/* We dont change anything until the entries are sumitted */
	return (&qlt->preq_ptr[qlt->preq_ndx_to_fw << 6]);
}

/*
 * updates the req in ptr to fw. Assumes that req lock is held.
 */
void
qlt_submit_preq_entries(qlt_state_t *qlt, uint32_t n)
{
	ASSERT(n >= 1);
	qlt->preq_ndx_to_fw += n;
	qlt->preq_ndx_to_fw &= PRIORITY_QUEUE_ENTRIES - 1;
	REG_WR32(qlt, REG_PREQ_IN_PTR, qlt->preq_ndx_to_fw);
}

/*
 * - Should not be called from Interrupt.
 * - A very hardware specific function. Does not touch driver state.
 * - Assumes that interrupts are disabled or not there.
 * - Expects that the caller makes sure that all activity has stopped
 *   and its ok now to go ahead and reset the chip. Also the caller
 *   takes care of post reset damage control.
 * - called by initialize adapter() and dump_fw(for reset only).
 * - During attach() nothing much is happening and during initialize_adapter()
 *   the function (caller) does all the housekeeping so that this function
 *   can execute in peace.
 * - Returns 0 on success.
 */
static fct_status_t
qlt_reset_chip(qlt_state_t *qlt)
{
	int cntr;

	EL(qlt, "initiated\n");

	/* XXX: Switch off LEDs */

	qlt->qlt_intr_enabled = 0;
	/* Disable Interrupts */
	REG_WR32(qlt, REG_INTR_CTRL, 0);
	(void) REG_RD32(qlt, REG_INTR_CTRL);
	/* Stop DMA */
	REG_WR32(qlt, REG_CTRL_STATUS, DMA_SHUTDOWN_CTRL | PCI_X_XFER_CTRL);

	/* Wait for DMA to be stopped */
	cntr = 0;
	while (REG_RD32(qlt, REG_CTRL_STATUS) & DMA_ACTIVE_STATUS) {
		delay(drv_usectohz(10000)); /* mostly 10ms is 1 tick */
		cntr++;
		/* 3 sec should be more than enough */
		if (cntr == 300)
			return (QLT_DMA_STUCK);
	}

	/* need to ensure no one accesses the hw during the reset 100us */
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		mutex_enter(&qlt->mbox_lock);
		if (qlt->qlt_mq_enabled == 1) {
			int i;

			for (i = 1; i < qlt->qlt_queue_cnt; i++) {
				mutex_enter(&qlt->mq_req[i].mq_lock);
			}
		}
		mutex_enter(&qlt->mq_req[0].mq_lock);
		/*
		 * We need to give time for other threads to finsh their
		 * interupts (or we need another lock)
		 */
		drv_usecwait(40);
	}

	/* Reset the Chip */
	REG_WR32(qlt, REG_CTRL_STATUS,
	    DMA_SHUTDOWN_CTRL | PCI_X_XFER_CTRL | CHIP_SOFT_RESET);

	qlt->qlt_link_up = 0;

	drv_usecwait(100);

	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		mutex_exit(&qlt->mq_req[0].mq_lock);
		if (qlt->qlt_mq_enabled == 1) {
			int i;

			for (i = 1; i < qlt->qlt_queue_cnt; i++) {
				mutex_exit(&qlt->mq_req[i].mq_lock);
			}
		}
		mutex_exit(&qlt->mbox_lock);
	}

	/* Wait for ROM firmware to initialize (0x0000) in mailbox 0 */
	cntr = 0;
	while (REG_RD16(qlt, REG_MBOX(0)) != 0) {
		delay(drv_usectohz(10000));
		cntr++;
		/* 3 sec should be more than enough */
		if (cntr == 300)
			return (QLT_ROM_STUCK);
	}
	/* Disable Interrupts (Probably not needed) */
	REG_WR32(qlt, REG_INTR_CTRL, 0);

	return (QLT_SUCCESS);
}

/*
 * - Should not be called from Interrupt.
 * - A very hardware specific function. Does not touch driver state.
 * - Assumes that interrupts are disabled or not there.
 * - Expects that the caller makes sure that all activity has stopped
 *   and its ok now to go ahead and reset the chip. Also the caller
 *   takes care of post reset damage control.
 * - called by initialize adapter() and dump_fw(for reset only).
 * - During attach() nothing much is happening and during initialize_adapter()
 *   the function (caller) does all the housekeeping so that this function
 *   can execute in peace.
 * - Returns 0 on success.
 */
static fct_status_t
qlt_download_fw(qlt_state_t *qlt)
{
	uint32_t start_addr;
	fct_status_t ret;

	EL(qlt, "initiated\n");

	(void) qlt_reset_chip(qlt);

	if (qlt->qlt_81xx_chip) {
		qlt_mps_reset(qlt);
	}

	/* Load the two segments */
	if (qlt->fw_code01 != NULL) {
		ret = qlt_load_risc_ram(qlt, qlt->fw_code01, qlt->fw_length01,
		    qlt->fw_addr01);
		if (ret == QLT_SUCCESS) {
			ret = qlt_load_risc_ram(qlt, qlt->fw_code02,
			    qlt->fw_length02, qlt->fw_addr02);
		}
		start_addr = qlt->fw_addr01;
	} else if (qlt->qlt_27xx_chip) {
		(void) qlt_27xx_get_dmp_template(qlt);
		ret = qlt_load_risc_ram(qlt, fw2700_code01,
		    fw2700_length01, fw2700_addr01);
		if (ret == QLT_SUCCESS) {
			ret = qlt_load_risc_ram(qlt, fw2700_code02,
			    fw2700_length02, fw2700_addr02);
		}
		start_addr = fw2700_addr01;
	} else if (qlt->qlt_83xx_chip) {
		ret = qlt_load_risc_ram(qlt, fw8300fc_code01,
		    fw8300fc_length01, fw8300fc_addr01);
		if (ret == QLT_SUCCESS) {
			ret = qlt_load_risc_ram(qlt, fw8300fc_code02,
			    fw8300fc_length02, fw8300fc_addr02);
		}
		start_addr = fw8300fc_addr01;
	} else if (qlt->qlt_81xx_chip) {
		ret = qlt_load_risc_ram(qlt, fw8100_code01, fw8100_length01,
		    fw8100_addr01);
		if (ret == QLT_SUCCESS) {
			ret = qlt_load_risc_ram(qlt, fw8100_code02,
			    fw8100_length02, fw8100_addr02);
		}
		start_addr = fw8100_addr01;
	} else if (qlt->qlt_25xx_chip) {
		ret = qlt_load_risc_ram(qlt, fw2500_code01, fw2500_length01,
		    fw2500_addr01);
		if (ret == QLT_SUCCESS) {
			ret = qlt_load_risc_ram(qlt, fw2500_code02,
			    fw2500_length02, fw2500_addr02);
		}
		start_addr = fw2500_addr01;
	} else {
		ret = qlt_load_risc_ram(qlt, fw2400_code01, fw2400_length01,
		    fw2400_addr01);
		if (ret == QLT_SUCCESS) {
			ret = qlt_load_risc_ram(qlt, fw2400_code02,
			    fw2400_length02, fw2400_addr02);
		}
		start_addr = fw2400_addr01;
	}
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_load_risc_ram status=%llxh\n", ret);
		return (ret);
	}

	/* Verify Checksum */
	REG_WR16(qlt, REG_MBOX(0), MBC_VERIFY_CHECKSUM);
	REG_WR16(qlt, REG_MBOX(1), MSW(start_addr));
	REG_WR16(qlt, REG_MBOX(2), LSW(start_addr));
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_raw_mailbox_command=7h status=%llxh\n", ret);
		return (ret);
	}

	/* Execute firmware */
	REG_WR16(qlt, REG_MBOX(0), MBC_EXECUTE_FIRMWARE);
	REG_WR16(qlt, REG_MBOX(1), MSW(start_addr));
	REG_WR16(qlt, REG_MBOX(2), LSW(start_addr));
	REG_WR16(qlt, REG_MBOX(3), 0);
#ifdef EXTRA_CREDIT
	/* enable extra credits (reduces available buffers) */
	if ((qlt->qlt_25xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		REG_WR16(qlt, REG_MBOX(4), 1);
	} else {
		REG_WR16(qlt, REG_MBOX(4), 0);
	}
#else
	REG_WR16(qlt, REG_MBOX(4), 0);
#endif
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_raw_mailbox_command=2h status=%llxh\n", ret);
		return (ret);
	} else {
		if (qlt->qlt_27xx_chip) {
			qlt->qlt_27xx_speed = (uint32_t)
			    (REG_RD16(qlt, REG_MBOX(3)) << 16 |
			    REG_RD16(qlt, REG_MBOX(2)));

		}
	}

	/* Get revisions (About Firmware) */
	REG_WR16(qlt, REG_MBOX(0), MBC_ABOUT_FIRMWARE);
	ret = qlt_raw_mailbox_command(qlt);
	qlt->fw_major = REG_RD16(qlt, REG_MBOX(1));
	qlt->fw_minor = REG_RD16(qlt, REG_MBOX(2));
	qlt->fw_subminor = REG_RD16(qlt, REG_MBOX(3));
	qlt->fw_endaddrlo = REG_RD16(qlt, REG_MBOX(4));
	qlt->fw_endaddrhi = REG_RD16(qlt, REG_MBOX(5));
	qlt->fw_attr = REG_RD16(qlt, REG_MBOX(6));
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_raw_mailbox_command=8h status=%llxh\n", ret);
		return (ret);
	}

	if (qlt->qlt_27xx_chip) {
		qlt->fw_ext_memory_end = SHORT_TO_LONG(
		    REG_RD16(qlt, REG_MBOX(4)),
		    REG_RD16(qlt, REG_MBOX(5)));
		qlt->fw_shared_ram_start = SHORT_TO_LONG(
		    REG_RD16(qlt, REG_MBOX(18)),
		    REG_RD16(qlt, REG_MBOX(19)));
		qlt->fw_shared_ram_end = SHORT_TO_LONG(
		    REG_RD16(qlt, REG_MBOX(20)),
		    REG_RD16(qlt, REG_MBOX(21)));
		qlt->fw_ddr_ram_start = SHORT_TO_LONG(
		    REG_RD16(qlt, REG_MBOX(22)),
		    REG_RD16(qlt, REG_MBOX(23)));
		qlt->fw_ddr_ram_end = SHORT_TO_LONG(
		    REG_RD16(qlt, REG_MBOX(24)),
		    REG_RD16(qlt, REG_MBOX(25)));
	}


	return (QLT_SUCCESS);
}

/*
 * Used only from qlt_download_fw().
 */
static fct_status_t
qlt_load_risc_ram(qlt_state_t *qlt, uint32_t *host_addr,
    uint32_t word_count, uint32_t risc_addr)
{
	uint32_t words_sent = 0;
	uint32_t words_being_sent;
	uint32_t *cur_host_addr;
	uint32_t cur_risc_addr;
	uint64_t da;
	fct_status_t ret;

	while (words_sent < word_count) {
		cur_host_addr = &(host_addr[words_sent]);
		cur_risc_addr = risc_addr + (words_sent << 2);
		words_being_sent = min(word_count - words_sent,
		    TOTAL_DMA_MEM_SIZE >> 2);
		ddi_rep_put32(qlt->queue_mem_acc_handle, cur_host_addr,
		    (uint32_t *)qlt->queue_mem_ptr, words_being_sent,
		    DDI_DEV_AUTOINCR);
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle, 0,
		    words_being_sent << 2, DDI_DMA_SYNC_FORDEV);
		da = qlt->queue_mem_cookie.dmac_laddress;
		REG_WR16(qlt, REG_MBOX(0), MBC_LOAD_RAM_EXTENDED);
		REG_WR16(qlt, REG_MBOX(1), LSW(risc_addr));
		REG_WR16(qlt, REG_MBOX(8), MSW(cur_risc_addr));
		REG_WR16(qlt, REG_MBOX(3), LSW(LSD(da)));
		REG_WR16(qlt, REG_MBOX(2), MSW(LSD(da)));
		REG_WR16(qlt, REG_MBOX(7), LSW(MSD(da)));
		REG_WR16(qlt, REG_MBOX(6), MSW(MSD(da)));
		REG_WR16(qlt, REG_MBOX(5), LSW(words_being_sent));
		REG_WR16(qlt, REG_MBOX(4), MSW(words_being_sent));
		ret = qlt_raw_mailbox_command(qlt);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		if (ret != QLT_SUCCESS) {
			EL(qlt, "qlt_raw_mailbox_command=0Bh status=%llxh\n",
			    ret);
			return (ret);
		}
		words_sent += words_being_sent;
	}
	EL(qlt, "qlt_raw_mailbox_command=0Bh, LOAD_RAM_EXTENDED complete\n");
	return (QLT_SUCCESS);
}

/*
 * Not used during normal operation. Only during driver init.
 * Assumes that interrupts are disabled and mailboxes are loaded.
 * Just triggers the mailbox command an waits for the completion.
 * Also expects that There is nothing else going on and we will only
 * get back a mailbox completion from firmware.
 * ---DOES NOT CLEAR INTERRUPT---
 * Used only from the code path originating from
 * qlt_reset_chip()
 */
static fct_status_t
qlt_raw_mailbox_command(qlt_state_t *qlt)
{
	int cntr = 0;
	uint32_t status;
	fct_local_port_t *port = qlt->qlt_port;

	REG_WR32(qlt, REG_HCCR, HCCR_CMD(SET_HOST_TO_RISC_INTR));
retry_raw:;
	while ((REG_RD32(qlt, REG_INTR_STATUS) & RISC_PCI_INTR_REQUEST) == 0) {
		cntr++;
		if (cntr == 3000) {
			EL(qlt, "polling exhausted, dump fw now..\n");
			(void) qlt_firmware_dump(port,
			    (stmf_state_change_info_t *)NULL);
			return (QLT_MAILBOX_STUCK);
		}
		delay(drv_usectohz(10000));
	}
	status = (REG_RD32(qlt, REG_RISC_STATUS) & FW_INTR_STATUS_MASK);

	if ((status == ROM_MBX_CMD_SUCCESSFUL) ||
	    (status == ROM_MBX_CMD_NOT_SUCCESSFUL) ||
	    (status == MBX_CMD_SUCCESSFUL) ||
	    (status == MBX_CMD_NOT_SUCCESSFUL)) {
		uint16_t mbox0 = REG_RD16(qlt, REG_MBOX(0));
		if (mbox0 == QLT_MBX_CMD_SUCCESS) {
			return (QLT_SUCCESS);
		} else {
			EL(qlt, "mbx cmd failed, dump fw now..\n");
			(void) qlt_firmware_dump(port,
			    (stmf_state_change_info_t *)NULL);
			return (QLT_MBOX_FAILED | mbox0);
		}
	} else if (status == ASYNC_EVENT) {
		uint16_t mbox0, mbox1, mbox2, mbox3;
		uint16_t mbox4, mbox5, mbox6, mbox7;

		mbox0 = REG_RD16(qlt, REG_MBOX(0));
		mbox1 = REG_RD16(qlt, REG_MBOX(1));
		mbox2 = REG_RD16(qlt, REG_MBOX(2));
		mbox3 = REG_RD16(qlt, REG_MBOX(3));
		mbox4 = REG_RD16(qlt, REG_MBOX(4));
		mbox5 = REG_RD16(qlt, REG_MBOX(5));
		mbox6 = REG_RD16(qlt, REG_MBOX(6));
		mbox7 = REG_RD16(qlt, REG_MBOX(7));

		cmn_err(CE_NOTE, "!qlt(%d): Async event %x mb1=%x mb2=%x"
		    "mb3=%x mb4=%x mb5=%x mb6=%x mb7=%x",
		    qlt->instance, mbox0, mbox1, mbox2, mbox3,
		    mbox4, mbox5, mbox6, mbox7);
		if (mbox0 == 0x8002) {
			(void) qlt_firmware_dump(port,
			    (stmf_state_change_info_t *)NULL);
			return (QLT_UNEXPECTED_RESPONSE);
		} else {
			REG_WR32(qlt,
			    REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
			cntr = 0;
			goto retry_raw;
		}
	}

	/* This is unexpected, dump a message */
	cmn_err(CE_WARN, "qlt(%d): Unexpect intr status %llx",
	    ddi_get_instance(qlt->dip), (unsigned long long)status);
	return (QLT_UNEXPECTED_RESPONSE);
}

static mbox_cmd_t *
qlt_alloc_mailbox_command(qlt_state_t *qlt, uint32_t dma_size)
{
	mbox_cmd_t *mcp;

	mcp = (mbox_cmd_t *)kmem_zalloc(sizeof (mbox_cmd_t), KM_SLEEP);
	if (dma_size) {
		qlt_dmem_bctl_t *bctl;
		uint64_t da;

		mcp->dbuf = qlt_i_dmem_alloc(qlt, dma_size, &dma_size, 0);
		if (mcp->dbuf == NULL) {
			kmem_free(mcp, sizeof (*mcp));
			return (NULL);
		}
		mcp->dbuf->db_data_size = dma_size;
		ASSERT(mcp->dbuf->db_sglist_length == 1);

		bctl = (qlt_dmem_bctl_t *)mcp->dbuf->db_port_private;
		da = bctl->bctl_dev_addr;
		/* This is the most common initialization of dma ptrs */
		mcp->to_fw[3] = LSW(LSD(da));
		mcp->to_fw[2] = MSW(LSD(da));
		mcp->to_fw[7] = LSW(MSD(da));
		mcp->to_fw[6] = MSW(MSD(da));
		mcp->to_fw_mask |= BIT_2 | BIT_3 | BIT_7 | BIT_6;
	}
	mcp->to_fw_mask |= BIT_0;
	mcp->from_fw_mask |= BIT_0;
	return (mcp);
}

void
qlt_free_mailbox_command(qlt_state_t *qlt, mbox_cmd_t *mcp)
{
	if (mcp->dbuf)
		qlt_i_dmem_free(qlt, mcp->dbuf);
	kmem_free(mcp, sizeof (*mcp));
}

/*
 * This can sleep. Should never be called from interrupt context.
 */
static fct_status_t
qlt_mailbox_command(qlt_state_t *qlt, mbox_cmd_t *mcp)
{
	int	retries;
	int	i;
	char	info[80];

	if (curthread->t_flag & T_INTR_THREAD) {
		ASSERT(0);
		return (QLT_MBOX_FAILED);
	}

	EL(qlt, "mailbox:[0]=%xh [1]=%xh\n",
	    mcp->to_fw[0], mcp->to_fw[1]);

	mutex_enter(&qlt->mbox_lock);
	/* See if mailboxes are still uninitialized */
	if (qlt->mbox_io_state == MBOX_STATE_UNKNOWN) {
		mutex_exit(&qlt->mbox_lock);
		return (QLT_MBOX_NOT_INITIALIZED);
	}

	/* Wait to grab the mailboxes */
	for (retries = 0; qlt->mbox_io_state != MBOX_STATE_READY;
	    retries++) {
		cv_wait(&qlt->mbox_cv, &qlt->mbox_lock);
		if ((retries > 5) ||
		    (qlt->mbox_io_state == MBOX_STATE_UNKNOWN)) {
			mutex_exit(&qlt->mbox_lock);
			return (QLT_MBOX_BUSY);
		}
	}
	/* Make sure we always ask for mailbox 0 */
	mcp->from_fw_mask |= BIT_0;

	/* Load mailboxes, set state and generate RISC interrupt */
	qlt->mbox_io_state = MBOX_STATE_CMD_RUNNING;
	qlt->mcp = mcp;
	for (i = 0; i < MAX_MBOXES; i++) {
		if (mcp->to_fw_mask & ((uint32_t)1 << i))
			REG_WR16(qlt, REG_MBOX(i), mcp->to_fw[i]);
	}
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(SET_HOST_TO_RISC_INTR));

qlt_mbox_wait_loop:;
	/* Wait for mailbox command completion */
	if (cv_timedwait(&qlt->mbox_cv, &qlt->mbox_lock, ddi_get_lbolt()
	    + drv_usectohz(MBOX_TIMEOUT)) < 0) {
		(void) snprintf(info, 80, "qlt_mailbox_command: qlt-%p, "
		    "cmd-0x%02X timed out", (void *)qlt, qlt->mcp->to_fw[0]);
		info[79] = 0;
		qlt->mcp = NULL;
		qlt->mbox_io_state = MBOX_STATE_UNKNOWN;
		mutex_exit(&qlt->mbox_lock);

		/*
		 * XXX Throw HBA fatal error event
		 */
		(void) fct_port_shutdown(qlt->qlt_port, STMF_RFLAG_FATAL_ERROR |
		    STMF_RFLAG_RESET | STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
		return (QLT_MBOX_TIMEOUT);
	}
	if (qlt->mbox_io_state == MBOX_STATE_CMD_RUNNING)
		goto qlt_mbox_wait_loop;

	qlt->mcp = NULL;

	/* Make sure its a completion */
	if (qlt->mbox_io_state != MBOX_STATE_CMD_DONE) {
		ASSERT(qlt->mbox_io_state == MBOX_STATE_UNKNOWN);
		mutex_exit(&qlt->mbox_lock);
		return (QLT_MBOX_ABORTED);
	}

	/* MBox command completed. Clear state, retuen based on mbox 0 */
	/* Mailboxes are already loaded by interrupt routine */
	qlt->mbox_io_state = MBOX_STATE_READY;
	mutex_exit(&qlt->mbox_lock);
	if (mcp->from_fw[0] != QLT_MBX_CMD_SUCCESS) {
		EL(qlt, "fw[0] = %xh\n", mcp->from_fw[0]);
		if ((mcp->from_fw[0] != 0x4005) &&
		    (mcp->from_fw[1] != 0x7)) {
			(void) qlt_firmware_dump(qlt->qlt_port,
			    (stmf_state_change_info_t *)NULL);
		}
		return (QLT_MBOX_FAILED | mcp->from_fw[0]);
	}

	return (QLT_SUCCESS);
}

/*
 * **SHOULD ONLY BE CALLED FROM INTERRUPT CONTEXT. DO NOT CALL ELSEWHERE**
 */
/* ARGSUSED */
static uint_t
qlt_msix_resp_handler(caddr_t arg, caddr_t arg2)
{
	qlt_state_t	*qlt = (qlt_state_t *)arg;
	uint32_t	risc_status;
	uint16_t 	qi = 0;

	risc_status = REG_RD32(qlt, REG_RISC_STATUS);
	if (qlt->qlt_mq_enabled) {
		/* XXX: */
		/* qi = (uint16_t)((unsigned long)arg2); */
		qi = (uint16_t)(risc_status >> 16);

		mutex_enter(&qlt->mq_resp[qi].mq_lock);
		if (!qlt->qlt_intr_enabled) {
			/*
			 * No further interrupt since intr disabled.
			 */
			REG_WR32(qlt, REG_HCCR,
			    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
			mutex_exit(&qlt->mq_resp[qi].mq_lock);
			return (DDI_INTR_UNCLAIMED);
		}

		qlt->mq_resp[qi].mq_ndx_from_fw =
		    (uint16_t)MQBAR_RD32(qlt,
		    (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_IN);

		qlt_handle_resp_queue_update(qlt, qi);
		mutex_exit(&qlt->mq_resp[qi].mq_lock);
	} else {
		mutex_enter(&qlt->intr_lock);
		if (!qlt->qlt_intr_enabled) {
			/*
			 * No further interrupt since intr disabled.
			 */
			REG_WR32(qlt, REG_HCCR,
			    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
			mutex_exit(&qlt->intr_lock);
			return (DDI_INTR_UNCLAIMED);
		}

		qlt->atio_ndx_from_fw =
		    (uint16_t)REG_RD32(qlt, REG_ATIO_IN_PTR);
		qlt_handle_atio_queue_update(qlt);

		qlt->mq_resp[qi].mq_ndx_from_fw = risc_status >> 16;
		qlt_handle_resp_queue_update(qlt, qi);
		mutex_exit(&qlt->intr_lock);
	}

	if (risc_status & BIT_15) {
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	}
	return (DDI_INTR_CLAIMED);
}


/*
 * **SHOULD ONLY BE CALLED FROM INTERRUPT CONTEXT. DO NOT CALL ELSEWHERE**
 */
/* ARGSUSED */
static uint_t
qlt_msix_default_handler(caddr_t arg, caddr_t arg2)
{
	qlt_state_t	*qlt = (qlt_state_t *)arg;
	uint32_t	risc_status, intr_type;
	int		i;
	char		info[80];

	risc_status = REG_RD32(qlt, REG_RISC_STATUS);
	if (!mutex_tryenter(&qlt->intr_lock)) {
		/*
		 * Normally we will always get this lock. If tryenter is
		 * failing then it means that driver is trying to do
		 * some cleanup and is masking the intr but some intr
		 * has sneaked in between. See if our device has generated
		 * this intr. If so then wait a bit and return claimed.
		 * If not then return claimed if this is the 1st instance
		 * of a interrupt after driver has grabbed the lock.
		 */
		if ((risc_status & BIT_15) == 0) {
			return (DDI_INTR_UNCLAIMED);
		} else {
			/* try again */
			drv_usecwait(10);
			if (!mutex_tryenter(&qlt->intr_lock)) {
				/* really bad! */
				return (DDI_INTR_CLAIMED);
			}
		}
	}
	if (((risc_status & BIT_15) == 0) ||
	    (qlt->qlt_intr_enabled == 0)) {
		/*
		 * This might be a pure coincedence that we are operating
		 * in a interrupt disabled mode and another device
		 * sharing the interrupt line has generated an interrupt
		 * while an interrupt from our device might be pending. Just
		 * ignore it and let the code handling the interrupt
		 * disabled mode handle it.
		 */
		mutex_exit(&qlt->intr_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/* REG_WR32(qlt, REG_INTR_CTRL, 0); */

	/* check for risc pause - unlikely */
	if (risc_status & BIT_8) {
		uint32_t hccsr;

		hccsr = REG_RD32(qlt, REG_HCCR);
		EL(qlt, "Risc Pause status=%xh hccsr=%x\n",
		    risc_status, hccsr);
		cmn_err(CE_WARN, "qlt(%d): Risc Pause %08x hccsr:%x",
		    qlt->instance, risc_status, hccsr);
		(void) snprintf(info, 80, "Risc Pause %08x hccsr:%x",
		    risc_status, hccsr);
		info[79] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
		    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
	}

	/* check most likely types first */
	intr_type = risc_status & 0xff;
	if (intr_type == 0x1D) {
		qlt->atio_ndx_from_fw =
		    (uint16_t)REG_RD32(qlt, REG_ATIO_IN_PTR);
		qlt_handle_atio_queue_update(qlt);
		qlt->mq_resp[0].mq_ndx_from_fw = risc_status >> 16;
		qlt_handle_resp_queue_update(qlt, 0);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	} else if (intr_type == 0x1C) {
		qlt->atio_ndx_from_fw = (uint16_t)(risc_status >> 16);
		qlt_handle_atio_queue_update(qlt);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	} else if (intr_type == 0x1E) {
		/* 83xx */
		qlt->atio_ndx_from_fw =
		    (uint16_t)MQBAR_RD32(qlt, MQBAR_ATIO_IN);
		qlt_handle_atio_queue_update(qlt);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	} else if (intr_type == 0x13) {
		uint16_t qi;

		qlt->atio_ndx_from_fw =
		    (uint16_t)REG_RD32(qlt, REG_ATIO_IN_PTR);
		qlt_handle_atio_queue_update(qlt);

		if (qlt->qlt_mq_enabled) {
			qi = (uint16_t)(risc_status >> 16);
			qlt->mq_resp[qi].mq_ndx_from_fw =
			    (uint16_t)MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_IN);
			/* FIX THIS to be optional */
			REG_WR32(qlt, REG_HCCR,
			    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		} else {
			qi = 0;
			REG_WR32(qlt, REG_HCCR,
			    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
			qlt->mq_resp[qi].mq_ndx_from_fw = risc_status >> 16;
		}
		qlt_handle_resp_queue_update(qlt, qi);

	} else if (intr_type == 0x14) {
		uint16_t qi = (uint16_t)(risc_status >> 16);

		if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
			qlt->atio_ndx_from_fw =
			    (uint16_t)MQBAR_RD32(qlt, MQBAR_ATIO_IN);
		} else {
			qlt->atio_ndx_from_fw = (uint16_t)
			    REG_RD32(qlt, REG_ATIO_IN_PTR);
		}
		qlt_handle_atio_queue_update(qlt);

		qlt->mq_resp[qi].mq_ndx_from_fw =
		    (uint16_t)MQBAR_RD32(qlt,
		    (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_IN);
		qlt_handle_resp_queue_update(qlt, qi);

		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));

	} else if (intr_type == 0x12) {
		uint16_t code, mbox1, mbox2, mbox3, mbox4, mbox5, mbox6;

		REG_WR32(qlt, REG_INTR_CTRL, 0);

		code = (uint16_t)(risc_status >> 16);
		mbox1 = REG_RD16(qlt, REG_MBOX(1));
		mbox2 = REG_RD16(qlt, REG_MBOX(2));
		mbox3 = REG_RD16(qlt, REG_MBOX(3));
		mbox4 = REG_RD16(qlt, REG_MBOX(4));
		mbox5 = REG_RD16(qlt, REG_MBOX(5));
		mbox6 = REG_RD16(qlt, REG_MBOX(6));

		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		EL(qlt, "Async event: %x mb1=%x mb2=%x,"
		    " mb3=%x, mb4=%x, mb5=%x, mb6=%x", code, mbox1, mbox2,
		    mbox3, mbox4, mbox5, mbox6);
		stmf_trace(qlt->qlt_port_alias, "Async event: %x mb1=%x mb2=%x,"
		    " mb3=%x, mb4=%x, mb5=%x, mb6=%x", code, mbox1, mbox2,
		    mbox3, mbox4, mbox5, mbox6);
		cmn_err(CE_NOTE, "!qlt(%d): Async event %x mb1=%x mb2=%x,"
		    " mb3=%x, mb4=%x,  mb5=%x, mb6=%x", qlt->instance, code,
		    mbox1, mbox2, mbox3, mbox4, mbox5, mbox6);

		if ((code == 0x8030) || (code == 0x8010) || (code == 0x8013)) {
			if (qlt->qlt_link_up) {
				fct_handle_event(qlt->qlt_port,
				    FCT_EVENT_LINK_RESET, 0, 0);
			}
		} else if (code == 0x8012) {
			qlt->qlt_link_up = 0;
			fct_handle_event(qlt->qlt_port, FCT_EVENT_LINK_DOWN,
			    0, 0);
		} else if (code == 0x8014) {
			if (mbox1 == 0xffff) { /* global event */
				uint8_t reason_code;

				reason_code = (uint8_t)(mbox3 >> 8);

				switch (reason_code) {
				case 0x1d: /* FIP Clear Virtual Link received */
				case 0x1a: /* received FLOGO */
				case 0x1c: /* FCF configuration changed */
				case 0x1e: /* FKA timeout */
					if (mbox2 == 7) {
						qlt->qlt_link_up = 0;
						fct_handle_event(qlt->qlt_port,
						    FCT_EVENT_LINK_DOWN, 0, 0);
					}
					break;
				case 0x12:
					if (mbox2 == 4) {
						qlt->qlt_link_up = 1;
						fct_handle_event(qlt->qlt_port,
						    FCT_EVENT_LINK_UP, 0, 0);
						stmf_trace(qlt->qlt_port_alias,
						    "SNS login and SCR done");
					}
					break;
				case 0:
					if ((mbox2 == 6) &&
					    (!qlt->qlt_link_up)) {
						qlt->qlt_link_up = 1;
						fct_handle_event(qlt->qlt_port,
						    FCT_EVENT_LINK_UP, 0, 0);
						stmf_trace(qlt->qlt_port_alias,
						    "Link reinitialised");
					}
					break;
				default:
					stmf_trace(qlt->qlt_port_alias,
					    "AEN ignored");
					break;
				}
			}
		} else if (code == 0x8011) {
			switch (mbox1) {
			case 0: qlt->link_speed = PORT_SPEED_1G;
				break;
			case 1: qlt->link_speed = PORT_SPEED_2G;
				break;
			case 3: qlt->link_speed = PORT_SPEED_4G;
				break;
			case 4: qlt->link_speed = PORT_SPEED_8G;
				break;
			case 5: qlt->link_speed = PORT_SPEED_16G;
				break;
			case 0x13: qlt->link_speed = PORT_SPEED_10G;
				break;
			default:
				qlt->link_speed = PORT_SPEED_UNKNOWN;
			}
			qlt->qlt_link_up = 1;
			fct_handle_event(qlt->qlt_port, FCT_EVENT_LINK_UP,
			    0, 0);
		} else if ((code == 0x8002) || (code == 0x8003) ||
		    (code == 0x8004) || (code == 0x8005)) {
			(void) snprintf(info, 80,
			    "Got %04x, mb1=%x mb2=%x mb5=%x mb6=%x",
			    code, mbox1, mbox2, mbox5, mbox6);
			info[79] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
			    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
		} else if (code == 0x800F) {
			(void) snprintf(info, 80,
			    "Got 800F, mb1=%x mb2=%x mb3=%x",
			    mbox1, mbox2, mbox3);

			if (mbox1 != 1) {
				/* issue "verify fw" */
				qlt_verify_fw(qlt);
			}
		} else if (code == 0x8101) {
			(void) snprintf(info, 80,
			    "IDC Req Rcvd:%04x, mb1=%x mb2=%x mb3=%x",
			    code, mbox1, mbox2, mbox3);
			info[79] = 0;

			/* check if "ACK" is required (timeout != 0) */
			if (mbox1 & 0x0f00) {
				caddr_t	req;

				/*
				 * Ack the request (queue work to do it?)
				 * using a mailbox iocb
				 * (Only Queue #0 allowed)
				 */
				mutex_enter(&qlt->mq_req[0].mq_lock);
				req = qlt_get_req_entries(qlt, 1, 0);
				if (req) {
					bzero(req, IOCB_SIZE);
					req[0] = 0x39; req[1] = 1;
					QMEM_WR16(qlt, req+8, 0x101);
					QMEM_WR16(qlt, req+10, mbox1);
					QMEM_WR16(qlt, req+12, mbox2);
					QMEM_WR16(qlt, req+14, mbox3);
					QMEM_WR16(qlt, req+16, mbox4);
					QMEM_WR16(qlt, req+18, mbox5);
					QMEM_WR16(qlt, req+20, mbox6);
					qlt_submit_req_entries(qlt, 1, 0);
				} else {
					(void) snprintf(info, 80,
					    "IDC ACK failed");
					info[79] = 0;
				}
				mutex_exit(&qlt->mq_req[0].mq_lock);
			}
		} else {
			stmf_trace(qlt->qlt_port_alias,
			    "Async event: 0x%x ignored",
			    code);
		}
		REG_WR32(qlt, REG_INTR_CTRL, ENABLE_RISC_INTR);
	} else if ((intr_type == 0x10) || (intr_type == 0x11)) {
		/* Handle mailbox completion */
		mutex_enter(&qlt->mbox_lock);
		if (qlt->mbox_io_state != MBOX_STATE_CMD_RUNNING) {
			cmn_err(CE_WARN, "qlt(%d): mailbox completion received"
			    " when driver wasn't waiting for it %d",
			    qlt->instance, qlt->mbox_io_state);
		} else {
			for (i = 0; i < MAX_MBOXES; i++) {
				if (qlt->mcp->from_fw_mask &
				    (((uint32_t)1) << i)) {
					qlt->mcp->from_fw[i] =
					    REG_RD16(qlt, REG_MBOX(i));
				}
			}
			qlt->mbox_io_state = MBOX_STATE_CMD_DONE;
		}
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		cv_broadcast(&qlt->mbox_cv);
		mutex_exit(&qlt->mbox_lock);
	} else {
		cmn_err(CE_WARN, "qlt(%d): Unknown intr type 0x%x",
		    qlt->instance, intr_type);
		stmf_trace(qlt->qlt_port_alias,
		    "%s: Unknown intr type 0x%x [%x]",
		    __func__, intr_type, risc_status);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	}

	/* REG_WR32(qlt, REG_INTR_CTRL, ENABLE_RISC_INTR); */
	mutex_exit(&qlt->intr_lock);

	return (DDI_INTR_CLAIMED);
}

/*
 * **SHOULD ONLY BE CALLED FROM INTERRUPT CONTEXT. DO NOT CALL ELSEWHERE**
 */
/* ARGSUSED */
static uint_t
qlt_isr(caddr_t arg, caddr_t arg2)
{
	qlt_state_t	*qlt = (qlt_state_t *)arg;
	uint32_t	risc_status, intr_type;
	int		i;
	int		intr_loop_count;
	char		info[80];

	risc_status = REG_RD32(qlt, REG_RISC_STATUS);
	if (!mutex_tryenter(&qlt->intr_lock)) {
		/*
		 * Normally we will always get this lock. If tryenter is
		 * failing then it means that driver is trying to do
		 * some cleanup and is masking the intr but some intr
		 * has sneaked in between. See if our device has generated
		 * this intr. If so then wait a bit and return claimed.
		 * If not then return claimed if this is the 1st instance
		 * of a interrupt after driver has grabbed the lock.
		 */
		if (risc_status & BIT_15) {
			drv_usecwait(10);
			return (DDI_INTR_CLAIMED);
		} else if (qlt->intr_sneak_counter) {
			qlt->intr_sneak_counter--;
			return (DDI_INTR_CLAIMED);
		} else {
			return (DDI_INTR_UNCLAIMED);
		}
	}
	if (((risc_status & BIT_15) == 0) ||
	    (qlt->qlt_intr_enabled == 0)) {
		/*
		 * This might be a pure coincedence that we are operating
		 * in a interrupt disabled mode and another device
		 * sharing the interrupt line has generated an interrupt
		 * while an interrupt from our device might be pending. Just
		 * ignore it and let the code handling the interrupt
		 * disabled mode handle it.
		 */
		mutex_exit(&qlt->intr_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * XXX take care for MSI-X case. disable intrs
	 * Its gonna be complicated because of the max iterations.
	 * as hba will have posted the intr which did not go on PCI
	 * but we did not service it either because of max iterations.
	 * Maybe offload the intr on a different thread.
	 */
	intr_loop_count = 0;

	REG_WR32(qlt, REG_INTR_CTRL, 0);

intr_again:;

	/* check for risc pause */
	if (risc_status & BIT_8) {
		EL(qlt, "Risc Pause status=%xh\n", risc_status);
		cmn_err(CE_WARN, "qlt(%d): Risc Pause %08x",
		    qlt->instance, risc_status);
		(void) snprintf(info, 80, "Risc Pause %08x", risc_status);
		info[79] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
		    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
	}

	/* First check for high performance path */
	intr_type = risc_status & 0xff;
	if (intr_type == 0x1D) {

		/* process the atio queue first */
		qlt->atio_ndx_from_fw =
		    (uint16_t)REG_RD32(qlt, REG_ATIO_IN_PTR);
		qlt_handle_atio_queue_update(qlt);

		/* process the response queue next */
		qlt->mq_resp[0].mq_ndx_from_fw =
		    (uint16_t)REG_RD32(qlt, REG_RESP_IN_PTR);
		qlt_handle_resp_queue_update(qlt, 0);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));

	} else if (intr_type == 0x1C) {
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		qlt->atio_ndx_from_fw = (uint16_t)(risc_status >> 16);
		qlt_handle_atio_queue_update(qlt);
	} else if (intr_type == 0x1E) {
		/* 83xx Atio Queue update */
		qlt->atio_ndx_from_fw =
		    (uint16_t)MQBAR_RD32(qlt, MQBAR_ATIO_IN);
		qlt_handle_atio_queue_update(qlt);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	} else if (intr_type == 0x13) {
		uint16_t qi;

		qlt->atio_ndx_from_fw =
		    (uint16_t)REG_RD32(qlt, REG_ATIO_IN_PTR);
		qlt_handle_atio_queue_update(qlt);

		if (qlt->qlt_mq_enabled) {
			qi = (uint16_t)(risc_status >> 16);
			qlt->mq_resp[0].mq_ndx_from_fw =
			    (uint16_t)MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_IN);
			/* FIX THIS to be optional */
			REG_WR32(qlt, REG_HCCR,
			    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		} else {
			qi = 0;
			REG_WR32(qlt, REG_HCCR,
			    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
			qlt->mq_resp[qi].mq_ndx_from_fw = risc_status >> 16;
			REG_WR32(qlt, REG_HCCR,
			    HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		}
		qlt_handle_resp_queue_update(qlt, qi);

	} else if (intr_type == 0x14) {
		/* MQ */
		uint16_t qi = 0;

		if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
			qlt->atio_ndx_from_fw =
			    (uint16_t)MQBAR_RD32(qlt, MQBAR_ATIO_IN);
		} else {
			qi = (uint16_t)(risc_status >> 16);
			qlt->atio_ndx_from_fw = (uint16_t)
			    REG_RD32(qlt, REG_ATIO_IN_PTR);
		}
		qlt_handle_atio_queue_update(qlt);

		qlt->mq_resp[qi].mq_ndx_from_fw =
		    (uint16_t)MQBAR_RD32(qlt,
		    (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_IN);
		qlt_handle_resp_queue_update(qlt, qi);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));

	} else if (intr_type == 0x12) {
		uint16_t code = (uint16_t)(risc_status >> 16);
		uint16_t mbox1 = REG_RD16(qlt, REG_MBOX(1));
		uint16_t mbox2 = REG_RD16(qlt, REG_MBOX(2));
		uint16_t mbox3 = REG_RD16(qlt, REG_MBOX(3));
		uint16_t mbox4 = REG_RD16(qlt, REG_MBOX(4));
		uint16_t mbox5 = REG_RD16(qlt, REG_MBOX(5));
		uint16_t mbox6 = REG_RD16(qlt, REG_MBOX(6));

		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		EL(qlt, "Async event %x mb1=%x, mb2=%x, mb3=%x, mb4=%x, "
		    "mb5=%x, mb6=%x\n", code, mbox1, mbox2, mbox3, mbox4,
		    mbox5, mbox6);
		stmf_trace(qlt->qlt_port_alias, "Async event %x mb1=%x mb2=%x,"
		    " mb3=%x, mb4=%x, mb5=%x, mb6=%x", code, mbox1, mbox2,
		    mbox3, mbox4, mbox5, mbox6);
		cmn_err(CE_NOTE, "!qlt(%d): Async event %x mb1=%x mb2=%x,"
		    " mb3=%x, mb4=%x, mb5=%x, mb6=%x", qlt->instance, code,
		    mbox1, mbox2, mbox3, mbox4, mbox5, mbox6);

		if ((code == 0x8030) || (code == 0x8010) || (code == 0x8013)) {
			if (qlt->qlt_link_up) {
				fct_handle_event(qlt->qlt_port,
				    FCT_EVENT_LINK_RESET, 0, 0);
			}
		} else if (code == 0x8012) {
			qlt->qlt_link_up = 0;
			fct_handle_event(qlt->qlt_port, FCT_EVENT_LINK_DOWN,
			    0, 0);
		} else if (code == 0x8014) {
			if (mbox1 == 0xffff) { /* global event */
				uint8_t reason_code;

				reason_code = (uint8_t)(mbox3 >> 8);

				switch (reason_code) {
				case 0x1d: /* FIP Clear Virtual Link received */
				case 0x1a: /* received FLOGO */
				case 0x1c: /* FCF configuration changed */
				case 0x1e: /* FKA timeout */
					if (mbox2 == 7) {
						qlt->qlt_link_up = 0;
						fct_handle_event(qlt->qlt_port,
						    FCT_EVENT_LINK_DOWN, 0, 0);
					}
					break;
				case 0x12:
					if (mbox2 == 4) {
						qlt->qlt_link_up = 1;
						fct_handle_event(qlt->qlt_port,
						    FCT_EVENT_LINK_UP, 0, 0);
						stmf_trace(qlt->qlt_port_alias,
						    "SNS login and SCR done");
					}
					break;
				case 0:
					if ((mbox2 == 6) &&
					    (!qlt->qlt_link_up)) {
						qlt->qlt_link_up = 1;
						fct_handle_event(qlt->qlt_port,
						    FCT_EVENT_LINK_UP, 0, 0);
						stmf_trace(qlt->qlt_port_alias,
						    "Link reinitialised");
					}
					break;
				default:
					stmf_trace(qlt->qlt_port_alias,
					    "AEN ignored");
					break;
				}
			}
		} else if (code == 0x8011) {
			switch (mbox1) {
			case 0: qlt->link_speed = PORT_SPEED_1G;
				break;
			case 1: qlt->link_speed = PORT_SPEED_2G;
				break;
			case 3: qlt->link_speed = PORT_SPEED_4G;
				break;
			case 4: qlt->link_speed = PORT_SPEED_8G;
				break;
			case 5: qlt->link_speed = PORT_SPEED_16G;
				break;
			case 6: qlt->link_speed = PORT_SPEED_32G;
				break;
			case 0x13: qlt->link_speed = PORT_SPEED_10G;
				break;
			default:
				qlt->link_speed = PORT_SPEED_UNKNOWN;
			}
			qlt->qlt_link_up = 1;
			fct_handle_event(qlt->qlt_port, FCT_EVENT_LINK_UP,
			    0, 0);
		} else if ((code == 0x8002) || (code == 0x8003) ||
		    (code == 0x8004) || (code == 0x8005)) {
			(void) snprintf(info, 80,
			    "Got %04x, mb1=%x mb2=%x mb5=%x mb6=%x",
			    code, mbox1, mbox2, mbox5, mbox6);
			info[79] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
			    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
		} else if (code == 0x800F) {
			(void) snprintf(info, 80,
			    "Got 800F, mb1=%x mb2=%x mb3=%x",
			    mbox1, mbox2, mbox3);

			if (mbox1 != 1) {
				/* issue "verify fw" */
				qlt_verify_fw(qlt);
			}
		} else if (code == 0x8101) {
			(void) snprintf(info, 80,
			    "IDC Req Rcvd:%04x, mb1=%x mb2=%x mb3=%x",
			    code, mbox1, mbox2, mbox3);
			info[79] = 0;

			/* check if "ACK" is required (timeout != 0) */
			if (mbox1 & 0x0f00) {
				caddr_t	req;

				/*
				 * Ack the request (queue work to do it?)
				 * using a mailbox iocb (only Queue 0 allowed)
				 */
				mutex_enter(&qlt->mq_req[0].mq_lock);
				req = qlt_get_req_entries(qlt, 1, 0);
				if (req) {
					bzero(req, IOCB_SIZE);
					req[0] = 0x39; req[1] = 1;
					QMEM_WR16(qlt, req+8, 0x101);
					QMEM_WR16(qlt, req+10, mbox1);
					QMEM_WR16(qlt, req+12, mbox2);
					QMEM_WR16(qlt, req+14, mbox3);
					QMEM_WR16(qlt, req+16, mbox4);
					QMEM_WR16(qlt, req+18, mbox5);
					QMEM_WR16(qlt, req+20, mbox6);
					qlt_submit_req_entries(qlt, 1, 0);
				} else {
					(void) snprintf(info, 80,
					    "IDC ACK failed");
					info[79] = 0;
				}
				mutex_exit(&qlt->mq_req[0].mq_lock);
			}
		}
	} else if ((intr_type == 0x10) || (intr_type == 0x11)) {
		/* Handle mailbox completion */
		mutex_enter(&qlt->mbox_lock);
		if (qlt->mbox_io_state != MBOX_STATE_CMD_RUNNING) {
			cmn_err(CE_WARN, "qlt(%d): mailbox completion received"
			    " when driver wasn't waiting for it %d",
			    qlt->instance, qlt->mbox_io_state);
		} else {
			for (i = 0; i < MAX_MBOXES; i++) {
				if (qlt->mcp->from_fw_mask &
				    (((uint32_t)1) << i)) {
					qlt->mcp->from_fw[i] =
					    REG_RD16(qlt, REG_MBOX(i));
				}
			}
			qlt->mbox_io_state = MBOX_STATE_CMD_DONE;
		}
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
		cv_broadcast(&qlt->mbox_cv);
		mutex_exit(&qlt->mbox_lock);
	} else {
		cmn_err(CE_WARN, "qlt(%d): Unknown intr type 0x%x",
		    qlt->instance, intr_type);
		stmf_trace(qlt->qlt_port_alias,
		    "%s: Unknown intr type 0x%x [%x]",
		    __func__, intr_type, risc_status);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	}

	(void) REG_RD32(qlt, REG_HCCR); /* PCI Posting */

	if ((qlt->intr_flags & QLT_INTR_MSIX) == 0) {
		risc_status = REG_RD32(qlt, REG_RISC_STATUS);
		if ((risc_status & BIT_15) &&
		    (++intr_loop_count < QLT_MAX_ITERATIONS_PER_INTR)) {
			goto intr_again;
		}
		REG_WR32(qlt, REG_INTR_CTRL, ENABLE_RISC_INTR);
		mutex_exit(&qlt->intr_lock);
	} else {
		mutex_exit(&qlt->intr_lock);
		REG_WR32(qlt, REG_INTR_CTRL, ENABLE_RISC_INTR);
	}

	return (DDI_INTR_CLAIMED);
}

/* **************** NVRAM Functions ********************** */

fct_status_t
qlt_read_flash_word(qlt_state_t *qlt, uint32_t faddr, uint32_t *bp)
{
	uint32_t	timer;

	/* Clear access error flag */
	REG_WR32(qlt, REG_CTRL_STATUS,
	    REG_RD32(qlt, REG_CTRL_STATUS) | FLASH_ERROR);

	REG_WR32(qlt, REG_FLASH_ADDR, faddr & ~BIT_31);

	/* Wait for READ cycle to complete. */
	for (timer = 3000; timer; timer--) {
		if (REG_RD32(qlt, REG_FLASH_ADDR) & BIT_31) {
			break;
		}
		drv_usecwait(10);
	}
	if (timer == 0) {
		EL(qlt, "flash timeout\n");
		return (QLT_FLASH_TIMEOUT);
	} else if (REG_RD32(qlt, REG_CTRL_STATUS) & FLASH_ERROR) {
		EL(qlt, "flash access error\n");
		return (QLT_FLASH_ACCESS_ERROR);
	}

	*bp = REG_RD32(qlt, REG_FLASH_DATA);

	return (QLT_SUCCESS);
}

fct_status_t
qlt_read_nvram(qlt_state_t *qlt)
{
	uint32_t index, addr, chksum;
	uint32_t val, *ptr;
	fct_status_t ret;
	qlt_nvram_t *nv;
	uint64_t empty_node_name = 0;

	if (qlt->qlt_27xx_chip) {
		int func;

		func = ((REG_RD32(qlt, REG_CTRL_STATUS) & 0x0000f000) >> 12);
		switch (func) {
		case 0: addr = QLT27_NVRAM_FUNC0_ADDR; break;
		case 1: addr = QLT27_NVRAM_FUNC1_ADDR; break;
		case 2: addr = QLT27_NVRAM_FUNC2_ADDR; break;
		case 3: addr = QLT27_NVRAM_FUNC3_ADDR; break;
		}
	} else if (qlt->qlt_83xx_chip) {
		if (qlt->qlt_fcoe_enabled) {
			addr = REG_RD32(qlt, REG_CTRL_STATUS) & BIT_12 ?
			    QLT83FCOE_NVRAM_FUNC1_ADDR :
			    QLT83FCOE_NVRAM_FUNC0_ADDR;
		} else {
			addr = REG_RD32(qlt, REG_CTRL_STATUS) & BIT_12 ?
			    QLT83FC_NVRAM_FUNC1_ADDR :
			    QLT83FC_NVRAM_FUNC0_ADDR;
		}
	} else if (qlt->qlt_81xx_chip) {
		addr = REG_RD32(qlt, REG_CTRL_STATUS) & BIT_12 ?
		    QLT81_NVRAM_FUNC1_ADDR : QLT81_NVRAM_FUNC0_ADDR;
	} else if (qlt->qlt_25xx_chip) {
		addr = REG_RD32(qlt, REG_CTRL_STATUS) & FUNCTION_NUMBER ?
		    QLT25_NVRAM_FUNC1_ADDR : QLT25_NVRAM_FUNC0_ADDR;
	} else {
		addr = REG_RD32(qlt, REG_CTRL_STATUS) & FUNCTION_NUMBER ?
		    NVRAM_FUNC1_ADDR : NVRAM_FUNC0_ADDR;
	}
	mutex_enter(&qlt_global_lock);

	/* Pause RISC. */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(SET_RISC_PAUSE));
	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting. */

	/* Get NVRAM data and calculate checksum. */
	ptr = (uint32_t *)qlt->nvram;
	chksum = 0;
	for (index = 0; index < sizeof (qlt_nvram_t) / 4; index++) {
		ret = qlt_read_flash_word(qlt, addr++, &val);
		if (ret != QLT_SUCCESS) {
			EL(qlt, "qlt_read_flash_word, status=%llxh\n", ret);
			mutex_exit(&qlt_global_lock);
			return (ret);
		}
		chksum += val;
		*ptr = LE_32(val);
		ptr++;
	}

	/* Release RISC Pause */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_PAUSE));
	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting. */

	mutex_exit(&qlt_global_lock);

	/* Sanity check NVRAM Data */
	nv = qlt->nvram;
	if (chksum || nv->id[0] != 'I' || nv->id[1] != 'S' ||
	    nv->id[2] != 'P' || nv->id[3] != ' ' ||
	    (nv->nvram_version[0] | nv->nvram_version[1]) == 0) {
		EL(qlt, "chksum=%xh, id=%c%c%c%c, ver=%02d%02d\n", chksum,
		    nv->id[0], nv->id[1], nv->id[2], nv->id[3],
		    nv->nvram_version[1], nv->nvram_version[0]);
		return (QLT_BAD_NVRAM_DATA);
	}

	/* If node name is zero, hand craft it from port name */
	if (bcmp(nv->node_name, &empty_node_name, 8) == 0) {
		bcopy(nv->port_name, nv->node_name, 8);
		nv->node_name[0] = (uint8_t)(nv->node_name[0] & ~BIT_0);
		nv->port_name[0] = (uint8_t)(nv->node_name[0] | BIT_0);
	}

	return (QLT_SUCCESS);
}

fct_status_t
qlt_read_vpd(qlt_state_t *qlt)
{
	uint32_t index, addr, chksum;
	uint32_t val, *ptr;
	fct_status_t ret;

	if (qlt->qlt_27xx_chip) {
		int func;

		func = ((REG_RD32(qlt, REG_CTRL_STATUS) & 0x0000f000) >> 12);
		switch (func) {
		case 0: addr = QLT27_VPD_FUNC0_ADDR; break;
		case 1: addr = QLT27_VPD_FUNC1_ADDR; break;
		case 2: addr = QLT27_VPD_FUNC2_ADDR; break;
		case 3: addr = QLT27_VPD_FUNC3_ADDR; break;
		}
	} else if (qlt->qlt_83xx_chip) {
		if (qlt->qlt_fcoe_enabled) {
			addr = REG_RD32(qlt, REG_CTRL_STATUS) & BIT_12 ?
			    QLT83FCOE_VPD_FUNC1_ADDR :
			    QLT83FCOE_VPD_FUNC0_ADDR;
		} else {
			addr = REG_RD32(qlt, REG_CTRL_STATUS) & BIT_12 ?
			    QLT83FC_VPD_FUNC1_ADDR :
			    QLT83FC_VPD_FUNC0_ADDR;
		}
	} else if (qlt->qlt_81xx_chip) {
		addr = REG_RD32(qlt, REG_CTRL_STATUS) & BIT_12 ?
		    QLT81_VPD_FUNC1_ADDR : QLT81_VPD_FUNC0_ADDR;
	} else if (qlt->qlt_25xx_chip) {
		addr = REG_RD32(qlt, REG_CTRL_STATUS) & FUNCTION_NUMBER ?
		    QLT25_VPD_FUNC1_ADDR : QLT25_VPD_FUNC0_ADDR;
	} else {
		addr = REG_RD32(qlt, REG_CTRL_STATUS) & FUNCTION_NUMBER ?
		    QLT24_VPD_FUNC1_ADDR : QLT24_VPD_FUNC0_ADDR;
	}
	mutex_enter(&qlt_global_lock);

	/* Pause RISC. */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(SET_RISC_PAUSE));
	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting. */

	/* Get VPD data and calculate checksum. */
	ptr = (uint32_t *)qlt->vpd;
	chksum = 0;
	for (index = 0; index < QL_24XX_VPD_SIZE / 4; index++) {
		ret = qlt_read_flash_word(qlt, addr++, &val);
		if (ret != QLT_SUCCESS) {
			EL(qlt, "qlt_read_flash_word, status=%llxh\n", ret);
			mutex_exit(&qlt_global_lock);
			return (ret);
		}
		chksum += val;
		*ptr = LE_32(val);
		ptr++;
	}

	/* Release RISC Pause */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_PAUSE));
	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting. */

	mutex_exit(&qlt_global_lock);

	return (QLT_SUCCESS);
}

fct_status_t
qlt_read_bfe(qlt_state_t *qlt, uint32_t in_addr, uint32_t *out_addr, uint32_t i)
{
	uint32_t index;
	uint32_t chksum;
	fct_status_t ret = QLT_SUCCESS;
	uint32_t val;
	uint16_t dataoffset;
	uint32_t *ptr;
	uint32_t addr, addr0;
	uint16_t length;

	val = chksum = 0;
	ptr = (uint32_t *)&qlt->rimage[i].header;

	addr = in_addr;
	addr0 = addr;

	/* read rom header first */
	for (index = 0; index < sizeof (qlt_rom_header_t)/4;
	    index ++) {
		ret = qlt_read_flash_word(qlt, addr++, &val);
		if (ret != QLT_SUCCESS) {
			EL(qlt, "read flash, status=%llxh\n", ret);
			return (ret);
		}
		chksum += val;
		*ptr = LE_32(val);
		ptr++;
	}

	/* check the signature */
	if (qlt->rimage[i].header.signature[0] != PCI_HEADER0) {
		EL(qlt, "hdr[%d] sig[1] [0] (%xh) (%xh) is wrong.\n",
		    i, qlt->rimage[i].header.signature[1],
		    qlt->rimage[i].header.signature[0]);
		return (QLT_SUCCESS);
	}

	if ((qlt->rimage[i].header.signature[0] == PCI_HEADER0) &&
	    (qlt->rimage[i].header.signature[1] == PCI_HEADER1)) {
		/* get dataoffset */
		dataoffset = (qlt->rimage[i].header.dataoffset[1] |
		    qlt->rimage[i].header.dataoffset[0]);
		EL(qlt, "dataoffset[0] = %xh\n", dataoffset);

		ptr = (uint32_t *)&qlt->rimage[i].data;

		/* adjust addr */
		addr = addr0 + (dataoffset/4);
		for (index = 0; index < sizeof (qlt_rom_data_t)/4;
		    index ++) {
			ret = qlt_read_flash_word(qlt, addr++, &val);
			if (ret != QLT_SUCCESS) {
				EL(qlt, "read flash, status=%llxh\n", ret);
				return (ret);
			}
			chksum += val;
			*ptr = LE_32(val);
			ptr++;
		}

		/* check signature */
		if ((qlt->rimage[i].data.signature[0] != 0x50) &&
		    (qlt->rimage[i].data.signature[1] != 0x43) &&
		    (qlt->rimage[i].data.signature[2] != 0x49) &&
		    (qlt->rimage[i].data.signature[3] != 0x52)) {
			EL(qlt,
			    "data sig[3] [2] [1] [0] (%xh)(%xh)(%xh)(%xh)\n",
			    qlt->rimage[i].data.signature[3],
			    qlt->rimage[i].data.signature[2],
			    qlt->rimage[i].data.signature[1],
			    qlt->rimage[i].data.signature[0]);
			return (QLT_SUCCESS);
		}

		EL(qlt, "codetype (%xh) revisionlevel[1][0] (%xh)(%xh)\n",
		    qlt->rimage[i].data.codetype,
		    qlt->rimage[i].data.revisionlevel[1],
		    qlt->rimage[i].data.revisionlevel[0]);

		/* check if this is the last image */
		if (qlt->rimage[i].data.indicator == PCI_IND_LAST_IMAGE) {
			EL(qlt, "last image (%xh)\n",
			    qlt->rimage[i].data.indicator);
			return (QLT_SUCCESS);

		}

		/* Get the image length and adjust the addr according */
		length = (qlt->rimage[i].data.imagelength[1] |
		    qlt->rimage[i].data.imagelength[0]);

		EL(qlt, "image[%d] length[1][0] (%xh) (%xh) in sectors\n",
		    i, length);

		/* the starting addr of the next image */
		addr = addr0 + ((length * 512)/4);
		*out_addr = addr;
	}

	return (QLT_SUCCESS);
}

fct_status_t
qlt_read_rom_image(qlt_state_t *qlt)
{
	uint32_t addr;
	uint32_t out_addr = 0;
	uint32_t count = 0;
	boolean_t last_image = FALSE;
	fct_status_t ret;

	if (qlt->qlt_27xx_chip) {
		addr = FLASH_2700_DATA_ADDR + FLASH_2700_BOOT_CODE_ADDR;
	} else if (qlt->qlt_83xx_chip) {
		addr = FLASH_8300_DATA_ADDR + FLASH_8300_BOOT_CODE_ADDR;
	} else if (qlt->qlt_81xx_chip) {
		addr = FLASH_8100_DATA_ADDR + FLASH_8100_BOOT_CODE_ADDR;
	} else if (qlt->qlt_25xx_chip) {
		addr = FLASH_2500_DATA_ADDR + FLASH_2500_BOOT_CODE_ADDR;
	} else {
		addr = FLASH_2400_DATA_ADDR + FLASH_2400_BOOT_CODE_ADDR;
	}
	mutex_enter(&qlt_global_lock);

	/* Pause RISC. */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(SET_RISC_PAUSE));
	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting. */

	do {
		ret = qlt_read_bfe(qlt, addr, &out_addr, count);
		if (ret != QLT_SUCCESS) {
			EL(qlt, "qlt_read_bfe, status=%llxh\n", ret);
			break;
		}
		if (qlt->rimage[count].data.indicator ==
		    PCI_IND_LAST_IMAGE) {
			last_image = TRUE;
		} else {
			addr = out_addr;
		}
		count ++;
	} while ((last_image != TRUE) && (count < 6));

	/* Release RISC Pause */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_PAUSE));
	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting. */

	mutex_exit(&qlt_global_lock);

	return (QLT_SUCCESS);
}

uint32_t
qlt_sync_atio_queue(qlt_state_t *qlt)
{
	uint32_t total_ent;

	if (qlt->atio_ndx_from_fw > qlt->atio_ndx_to_fw) {
		total_ent = qlt->atio_ndx_from_fw - qlt->atio_ndx_to_fw;
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle, ATIO_QUEUE_OFFSET
		    + (qlt->atio_ndx_to_fw << 6), total_ent << 6,
		    DDI_DMA_SYNC_FORCPU);
	} else {
		total_ent = ATIO_QUEUE_ENTRIES - qlt->atio_ndx_to_fw +
		    qlt->atio_ndx_from_fw;
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle, ATIO_QUEUE_OFFSET
		    + (qlt->atio_ndx_to_fw << 6), (uint_t)(ATIO_QUEUE_ENTRIES -
		    qlt->atio_ndx_to_fw) << 6, DDI_DMA_SYNC_FORCPU);
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
		    ATIO_QUEUE_OFFSET, (uint_t)(qlt->atio_ndx_from_fw << 6),
		    DDI_DMA_SYNC_FORCPU);
	}
	return (total_ent);
}

void
qlt_handle_atio_queue_update(qlt_state_t *qlt)
{
	uint32_t total_ent;

	if (qlt->atio_ndx_to_fw == qlt->atio_ndx_from_fw)
		return;

	total_ent = qlt_sync_atio_queue(qlt);

	do {
		uint8_t *atio = (uint8_t *)&qlt->atio_ptr[
		    qlt->atio_ndx_to_fw << 6];
		uint32_t ent_cnt;

		ent_cnt = (uint32_t)(atio[1]);
		if (ent_cnt > total_ent) {
			break;
		}
		switch ((uint8_t)(atio[0])) {
		case 0x06:	/* ATIO, make performance case the 1st test */
			qlt_handle_atio(qlt, atio);
			break;
		case 0x0d:	/* INOT */
			qlt_handle_inot(qlt, atio);
			break;
		default:
			EL(qlt, "atio_queue_update atio[0]=%xh\n", atio[0]);
			cmn_err(CE_WARN, "qlt_handle_atio_queue_update: "
			    "atio[0] is %x, qlt-%p", atio[0], (void *)qlt);
			break;
		}
		qlt->atio_ndx_to_fw = (uint16_t)(
		    (qlt->atio_ndx_to_fw + ent_cnt) & (ATIO_QUEUE_ENTRIES - 1));
		total_ent -= ent_cnt;
	} while (total_ent > 0);

	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		MQBAR_WR32(qlt, MQBAR_ATIO_OUT, qlt->atio_ndx_to_fw);
	} else {
		REG_WR32(qlt, REG_ATIO_OUT_PTR, qlt->atio_ndx_to_fw);
	}
}

uint32_t
qlt_sync_resp_queue(qlt_state_t *qlt, uint16_t qi)
{
	uint32_t total_ent;

	if (qlt->mq_resp[qi].mq_ndx_from_fw > qlt->mq_resp[qi].mq_ndx_to_fw) {
		total_ent = qlt->mq_resp[qi].mq_ndx_from_fw -
		    qlt->mq_resp[qi].mq_ndx_to_fw;
		if (qi) {
			(void) ddi_dma_sync(
			    qlt->mq_resp[qi].queue_mem_mq_dma_handle,
			    (qlt->mq_resp[qi].mq_ndx_to_fw << 6),
			    total_ent << 6,
			    DDI_DMA_SYNC_FORCPU);
		} else {
			(void) ddi_dma_sync(
			    qlt->queue_mem_dma_handle,
			    RESPONSE_QUEUE_OFFSET +
			    (qlt->mq_resp[qi].mq_ndx_to_fw << 6),
			    total_ent << 6,
			    DDI_DMA_SYNC_FORCPU);
		}
	} else {
		total_ent =
		    (qi ? RESPONSE_QUEUE_MQ_ENTRIES : RESPONSE_QUEUE_ENTRIES) -
		    qlt->mq_resp[qi].mq_ndx_to_fw +
		    qlt->mq_resp[qi].mq_ndx_from_fw;

		if (qi) {

			(void) ddi_dma_sync(
			    qlt->mq_resp[qi].queue_mem_mq_dma_handle,
			    qlt->mq_resp[qi].mq_ndx_to_fw << 6,
			    (RESPONSE_QUEUE_MQ_ENTRIES -
			    qlt->mq_resp[qi].mq_ndx_to_fw) << 6,
			    DDI_DMA_SYNC_FORCPU);
			(void) ddi_dma_sync(
			    qlt->mq_resp[qi].queue_mem_mq_dma_handle, 0,
			    qlt->mq_resp[qi].mq_ndx_from_fw << 6,
			    DDI_DMA_SYNC_FORCPU);
		} else {
			(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
			    RESPONSE_QUEUE_OFFSET +
			    (qlt->mq_resp[qi].mq_ndx_to_fw << 6),
			    (RESPONSE_QUEUE_ENTRIES -
			    qlt->mq_resp[qi].mq_ndx_to_fw) << 6,
			    DDI_DMA_SYNC_FORCPU);
			(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
			    RESPONSE_QUEUE_OFFSET,
			    qlt->mq_resp[qi].mq_ndx_from_fw << 6,
			    DDI_DMA_SYNC_FORCPU);
		}
	}

	return (total_ent);
}

void
qlt_handle_resp_queue_update(qlt_state_t *qlt, uint16_t qi)
{
	uint32_t total_ent;
	uint8_t c;

	if (qlt->mq_resp[qi].mq_ndx_to_fw == qlt->mq_resp[qi].mq_ndx_from_fw)
		return;

	total_ent = qlt_sync_resp_queue(qlt, qi);

	do {
		uint32_t qe = qlt->mq_resp[qi].mq_ndx_to_fw;
		caddr_t resp = &qlt->mq_resp[qi].mq_ptr[qe << 6];

		uint32_t ent_cnt;

		ent_cnt = (uint32_t)(resp[0] == 0x51 ? resp[1] : 1);
		if (ent_cnt > total_ent) {
			break;
		}
		switch ((uint8_t)(resp[0])) {
		case 0x12:	/* CTIO completion */
			qlt_handle_ctio_completion(qlt, (uint8_t *)resp, qi);
			break;
		case 0x0e:	/* NACK */
			/* Do Nothing */
			break;
		case 0x1b:	/* Verify FW */
			qlt_handle_verify_fw_completion(qlt, (uint8_t *)resp);
			break;
		case 0x29:	/* CT PassThrough */
			qlt_handle_ct_completion(qlt, (uint8_t *)resp);
			break;
		case 0x32:	/* Report ID */
			EL(qlt, "report Id received [type %xh]\n", resp[0]);
			break;
		case 0x33:	/* Abort IO IOCB completion */
			qlt_handle_sol_abort_completion(qlt, (uint8_t *)resp);
			break;
		case 0x51:	/* PUREX */
			qlt_handle_purex(qlt, (uint8_t *)resp);
			break;
		case 0x52:
			qlt_handle_dereg_completion(qlt, (uint8_t *)resp);
			break;
		case 0x53:	/* ELS passthrough */
			c = (uint8_t)(((uint8_t)resp[0x1f]) >> 5);
			if (c == 0) {
				qlt_handle_sol_els_completion(qlt,
				    (uint8_t *)resp);
			} else if (c == 3) {
				qlt_handle_unsol_els_abort_completion(qlt,
				    (uint8_t *)resp);
			} else {
				qlt_handle_unsol_els_completion(qlt,
				    (uint8_t *)resp);
			}
			break;
		case 0x54:	/* ABTS received */
			qlt_handle_rcvd_abts(qlt, (uint8_t *)resp, qi);
			break;
		case 0x55:	/* ABTS completion */
			qlt_handle_abts_completion(qlt, (uint8_t *)resp, qi);
			break;
		default:
			EL(qlt, "response entry=%xh\n", resp[0]);
			break;
		}
		if (qi != 0) {
			qlt->mq_resp[qi].mq_ndx_to_fw =
			    (qlt->mq_resp[qi].mq_ndx_to_fw + ent_cnt) &
			    (RESPONSE_QUEUE_MQ_ENTRIES - 1);
		} else {
			qlt->mq_resp[qi].mq_ndx_to_fw =
			    (qlt->mq_resp[qi].mq_ndx_to_fw + ent_cnt) &
			    (RESPONSE_QUEUE_ENTRIES - 1);
		}
		total_ent -= ent_cnt;
	} while (total_ent > 0);
	if (qlt->qlt_mq_enabled) {
		MQBAR_WR32(qlt, (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_OUT,
		    qlt->mq_resp[qi].mq_ndx_to_fw);
	} else {
		REG_WR32(qlt, REG_RESP_OUT_PTR, qlt->mq_resp[qi].mq_ndx_to_fw);
	}
}

fct_status_t
qlt_portid_to_handle(qlt_state_t *qlt, uint32_t id, uint16_t cmd_handle,
    uint16_t *ret_handle)
{
	fct_status_t ret;
	mbox_cmd_t *mcp;
	uint16_t n;
	uint16_t h;
	uint32_t ent_id;
	uint8_t *p;
	int found = 0;

	mcp = qlt_alloc_mailbox_command(qlt, 2048 * 8);
	if (mcp == NULL) {
		return (STMF_ALLOC_FAILURE);
	}
	mcp->to_fw[0] = MBC_GET_ID_LIST;
	mcp->to_fw[8] = 2048 * 8;
	mcp->to_fw[9] = 0;
	mcp->to_fw_mask |= BIT_9 | BIT_8;
	mcp->from_fw_mask |= BIT_1 | BIT_2;

	ret = qlt_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_mbox_command=7Ch status=%llxh\n", ret);
		cmn_err(CE_WARN, "qlt(%d) GET ID list failed, ret = %llx, "
		    "mb0=%x, mb1=%x, mb2=%x", qlt->instance, (long long)ret,
		    mcp->from_fw[0], mcp->from_fw[1], mcp->from_fw[2]);
		qlt_free_mailbox_command(qlt, mcp);
		return (ret);
	}

	EL(qlt, "mbx cmd=7Ch, GET_ID_LIST id=%x fw[1]=%x\n",
	    id, mcp->from_fw[1]);

	qlt_dmem_dma_sync(mcp->dbuf, DDI_DMA_SYNC_FORCPU);
	p = mcp->dbuf->db_sglist[0].seg_addr;
	for (n = 0; n < mcp->from_fw[1]; n++) {
		ent_id = LE_32(*((uint32_t *)p)) & 0xFFFFFF;
		h = (uint16_t)((uint16_t)p[4] | (((uint16_t)p[5]) << 8));
		if (ent_id == id) {
			found = 1;
			*ret_handle = h;
			if ((cmd_handle != FCT_HANDLE_NONE) &&
			    (cmd_handle != h)) {
				cmn_err(CE_WARN, "qlt(%d) login for portid %x "
				    "came in with handle %x, while the portid "
				    "was already using a different handle %x",
				    qlt->instance, id, cmd_handle, h);
				qlt_free_mailbox_command(qlt, mcp);
				return (QLT_FAILURE);
			}
			break;
		}
		if ((cmd_handle != FCT_HANDLE_NONE) && (h == cmd_handle)) {
			cmn_err(CE_WARN, "qlt(%d) login for portid %x came in "
			    "with handle %x, while the handle was already in "
			    "use for portid %x",
			    qlt->instance, id, cmd_handle, ent_id);
			qlt_free_mailbox_command(qlt, mcp);
			return (QLT_FAILURE);
		}
		p += 8;
	}
	if (!found) {
		*ret_handle = cmd_handle;
	}
	qlt_free_mailbox_command(qlt, mcp);
	return (FCT_SUCCESS);
}

/* ARGSUSED */
fct_status_t
qlt_fill_plogi_req(fct_local_port_t *port, fct_remote_port_t *rp,
    fct_cmd_t *login)
{
	uint8_t *p;

	p = ((fct_els_t *)login->cmd_specific)->els_req_payload;
	p[0] = ELS_OP_PLOGI;
	*((uint16_t *)(&p[4])) = 0x2020;
	p[7] = 3;
	p[8] = 0x88;
	p[10] = 8;
	p[13] = 0xff; p[15] = 0x1f;
	p[18] = 7; p[19] = 0xd0;

	bcopy(port->port_pwwn, p + 20, 8);
	bcopy(port->port_nwwn, p + 28, 8);

	p[68] = 0x80;
	p[74] = 8;
	p[77] = 0xff;
	p[81] = 1;

	return (FCT_SUCCESS);
}

/* ARGSUSED */
fct_status_t
qlt_fill_plogi_resp(fct_local_port_t *port, fct_remote_port_t *rp,
    fct_cmd_t *login)
{
	return (FCT_SUCCESS);
}

fct_status_t
qlt_register_remote_port(fct_local_port_t *port, fct_remote_port_t *rp,
    fct_cmd_t *login)
{
	uint16_t h;
	fct_status_t ret;
	qlt_state_t *qlt = (qlt_state_t *)port->port_fca_private;

	switch (rp->rp_id) {
	case 0xFFFFFC:	h = 0x7FC; break;
	case 0xFFFFFD:	h = 0x7FD; break;
	case 0xFFFFFE:	h = 0x7FE; break;
	case 0xFFFFFF:	h = 0x7FF; break;
	default:
		ret = qlt_portid_to_handle(qlt, rp->rp_id,
		    login->cmd_rp_handle, &h);
		if (ret != FCT_SUCCESS) {
			EL(qlt, "qlt_portid_to_handle, status=%llxh\n", ret);
			return (ret);
		}
	}

	if (login->cmd_type == FCT_CMD_SOL_ELS) {
		ret = qlt_fill_plogi_req(port, rp, login);
	} else {
		ret = qlt_fill_plogi_resp(port, rp, login);
	}

	if (ret != FCT_SUCCESS) {
		EL(qlt, "qlt_fill_plogi, status=%llxh\n", ret);
		return (ret);
	}

	EL(qlt, "rport id=%xh cmd_type=%xh handle=%xh(%xh)\n",
	    rp->rp_id, login->cmd_type, h, rp->rp_handle);

	if (h == FCT_HANDLE_NONE)
		return (FCT_SUCCESS);

	if (rp->rp_handle == FCT_HANDLE_NONE) {
		rp->rp_handle = h;
		return (FCT_SUCCESS);
	}

	if (rp->rp_handle == h)
		return (FCT_SUCCESS);

	EL(qlt, "failed, rp_handle=%xh != h=%xh\n", rp->rp_handle, h);
	return (FCT_FAILURE);
}

/* invoked in single thread */
fct_status_t
qlt_deregister_remote_port(fct_local_port_t *port, fct_remote_port_t *rp)
{
	uint8_t *req;
	qlt_state_t *qlt;
	clock_t	dereg_req_timer;
	fct_status_t ret;

	qlt = (qlt_state_t *)port->port_fca_private;

	if ((qlt->qlt_state == FCT_STATE_OFFLINE) ||
	    (qlt->qlt_state == FCT_STATE_OFFLINING))
		return (FCT_SUCCESS);
	ASSERT(qlt->rp_id_in_dereg == 0);

	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		mutex_enter(&qlt->mq_req[0].mq_lock);
		req = (uint8_t *)qlt_get_req_entries(qlt, 1, 0);
		if (req == NULL) {
			EL(qlt, "req = NULL\n");
			mutex_exit(&qlt->mq_req[0].mq_lock);
			return (FCT_BUSY);
		}
	} else {
		mutex_enter(&qlt->preq_lock);
		req = (uint8_t *)qlt_get_preq_entries(qlt, 1);
		if (req == NULL) {
			EL(qlt, "req = NULL\n");
			mutex_exit(&qlt->preq_lock);
			return (FCT_BUSY);
		}
	}
	bzero(req, IOCB_SIZE);
	req[0] = 0x52; req[1] = 1;
	/* QMEM_WR32(qlt, (&req[4]), 0xffffffff);  */
	QMEM_WR16(qlt, (&req[0xA]), rp->rp_handle);
	QMEM_WR16(qlt, (&req[0xC]), 0x98); /* implicit logo */
	QMEM_WR32(qlt, (&req[0x10]), rp->rp_id);
	qlt->rp_id_in_dereg = rp->rp_id;
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		qlt_submit_req_entries(qlt, 1, 0);
	} else {
		qlt_submit_preq_entries(qlt, 1);
	}

	dereg_req_timer = ddi_get_lbolt() + drv_usectohz(DEREG_RP_TIMEOUT);
	if (cv_timedwait(&qlt->rp_dereg_cv,
	    (((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) ?
	    &qlt->mq_req[0].mq_lock : &qlt->preq_lock),
	    dereg_req_timer) > 0) {
		ret = qlt->rp_dereg_status;
	} else {
		ret = FCT_BUSY;
	}
	qlt->rp_dereg_status = 0;
	qlt->rp_id_in_dereg = 0;
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		mutex_exit(&qlt->mq_req[0].mq_lock);
	} else {
		mutex_exit(&qlt->preq_lock);
	}

	EL(qlt, "Dereg remote port(%Xh), ret=%llxh\n",
	    rp->rp_id, ret);

	return (ret);
}

/*
 * Pass received ELS up to framework.
 */
static void
qlt_handle_purex(qlt_state_t *qlt, uint8_t *resp)
{
	fct_cmd_t		*cmd;
	fct_els_t		*els;
	qlt_cmd_t		*qcmd;
	uint32_t		payload_size;
	uint32_t		remote_portid;
	uint8_t			*pldptr, *bndrptr;
	int			i, off;
	uint16_t		iocb_flags;
	char			info[160];

	remote_portid = ((uint32_t)(QMEM_RD16(qlt, (&resp[0x18])))) |
	    ((uint32_t)(resp[0x1A])) << 16;
	iocb_flags = QMEM_RD16(qlt, (&resp[8]));
	if (iocb_flags & BIT_15) {
		payload_size = (QMEM_RD16(qlt, (&resp[0x0e])) & 0xfff) - 24;
	} else {
		payload_size = QMEM_RD16(qlt, (&resp[0x0c])) - 24;
	}

	if (payload_size > ((uint32_t)resp[1] * IOCB_SIZE - 0x2C)) {
		EL(qlt, "payload is too large = %xh\n", payload_size);
		cmn_err(CE_WARN, "handle_purex: payload is too large");
		goto cmd_null;
	}

	cmd = (fct_cmd_t *)fct_alloc(FCT_STRUCT_CMD_RCVD_ELS,
	    (int)(payload_size + GET_STRUCT_SIZE(qlt_cmd_t)), 0);
	if (cmd == NULL) {
		EL(qlt, "fct_alloc cmd==NULL\n");
cmd_null:;
		(void) snprintf(info, 160, "qlt_handle_purex: qlt-%p, can't "
		    "allocate space for fct_cmd", (void *)qlt);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
		return;
	}

	cmd->cmd_port = qlt->qlt_port;
	cmd->cmd_rp_handle = QMEM_RD16(qlt, resp+0xa);
	if (cmd->cmd_rp_handle == 0xFFFF) {
		cmd->cmd_rp_handle = FCT_HANDLE_NONE;
	}

	els = (fct_els_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	els->els_req_size = (uint16_t)payload_size;
	els->els_req_payload = GET_BYTE_OFFSET(qcmd,
	    GET_STRUCT_SIZE(qlt_cmd_t));
	qcmd->fw_xchg_addr = QMEM_RD32(qlt, (&resp[0x10]));
	cmd->cmd_rportid = remote_portid;
	cmd->cmd_lportid = ((uint32_t)(QMEM_RD16(qlt, (&resp[0x14])))) |
	    ((uint32_t)(resp[0x16])) << 16;
	cmd->cmd_oxid = QMEM_RD16(qlt, (&resp[0x26]));
	cmd->cmd_rxid = QMEM_RD16(qlt, (&resp[0x24]));
	pldptr = &resp[0x2C];
	bndrptr = (uint8_t *)(qlt->mq_resp[0].mq_ptr
	    + (RESPONSE_QUEUE_ENTRIES << 6));
	for (i = 0, off = 0x2c; i < payload_size; i += 4) {
		/* Take care of fw's swapping of payload */
		els->els_req_payload[i] = pldptr[3];
		els->els_req_payload[i+1] = pldptr[2];
		els->els_req_payload[i+2] = pldptr[1];
		els->els_req_payload[i+3] = pldptr[0];
		pldptr += 4;
		if (pldptr == bndrptr)
			pldptr = (uint8_t *)qlt->mq_resp[0].mq_ptr;
		off += 4;
		if (off >= IOCB_SIZE) {
			off = 4;
			pldptr += 4;
		}
	}

	EL(qlt, "remote portid = %xh logi/o(%xh) to us revd rex1=%xh\n",
	    remote_portid, els->els_req_payload[0], qcmd->fw_xchg_addr);

	fct_post_rcvd_cmd(cmd, 0);
}

fct_status_t
qlt_send_cmd_response(fct_cmd_t *cmd, uint32_t ioflags)
{
	qlt_state_t	*qlt;
	char		info[160];

	qlt = (qlt_state_t *)cmd->cmd_port->port_fca_private;

	if (cmd->cmd_type == FCT_CMD_FCP_XCHG) {
		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			EL(qlt, "ioflags = %xh\n", ioflags);
			goto fatal_panic;
		} else {
			return (qlt_send_status(qlt, cmd));
		}
	}

	if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			goto fatal_panic;
		} else {
			return (qlt_send_els_response(qlt, cmd));
		}
	}

	if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
		cmd->cmd_handle = 0;
	}

	if (cmd->cmd_type == FCT_CMD_RCVD_ABTS) {
		return (qlt_send_abts_response(qlt, cmd, 0));
	} else {
		EL(qlt, "cmd->cmd_type=%xh\n", cmd->cmd_type);
		ASSERT(0);
		return (FCT_FAILURE);
	}

fatal_panic:;
	(void) snprintf(info, 160, "qlt_send_cmd_response: can not handle "
	    "FCT_IOF_FORCE_FCA_DONE for cmd %p, ioflags-%x", (void *)cmd,
	    ioflags);
	info[159] = 0;
	(void) fct_port_shutdown(qlt->qlt_port,
	    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
	return (FCT_FAILURE);
}

/* ARGSUSED */
fct_status_t
qlt_xfer_scsi_data(fct_cmd_t *cmd, stmf_data_buf_t *dbuf, uint32_t ioflags)
{
	qlt_dmem_bctl_t *bctl = (qlt_dmem_bctl_t *)dbuf->db_port_private;
	qlt_state_t *qlt = (qlt_state_t *)cmd->cmd_port->port_fca_private;
	qlt_cmd_t *qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	uint8_t *req, rcnt;
	uint16_t flags;
	uint16_t cookie_count;
	uint32_t ent_cnt;
	uint16_t qi;

	qi = qcmd->qid;

	if (dbuf->db_handle == 0)
		qcmd->dbuf = dbuf;
	flags = (uint16_t)(((uint16_t)qcmd->param.atio_byte3 & 0xf0) << 5);
	if (dbuf->db_flags & DB_DIRECTION_TO_RPORT) {
		flags = (uint16_t)(flags | 2);
		qlt_dmem_dma_sync(dbuf, DDI_DMA_SYNC_FORDEV);
	} else {
		flags = (uint16_t)(flags | 1);
	}

	if (dbuf->db_flags & DB_SEND_STATUS_GOOD)
		flags = (uint16_t)(flags | BIT_15);

	if (dbuf->db_flags & DB_LU_DATA_BUF) {
		/*
		 * Data bufs from LU are in scatter/gather list format.
		 */
		cookie_count = qlt_get_cookie_count(dbuf);
		rcnt = qlt_get_iocb_count(cookie_count);
	} else {
		cookie_count = 1;
		rcnt = 1;
	}
	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return (FCT_BUSY);
	}
	bzero(req, IOCB_SIZE);
	req[0] = 0x12;
	req[1] = rcnt;
	req[2] = dbuf->db_handle;
	QMEM_WR32_REQ(qlt, qi, req+4, cmd->cmd_handle);
	QMEM_WR16_REQ(qlt, qi, req+8, cmd->cmd_rp->rp_handle);
	QMEM_WR16_REQ(qlt, qi, req+10, 60);	/* 60 seconds timeout */
	QMEM_WR16_REQ(qlt, qi, req+12, cookie_count);
	QMEM_WR32_REQ(qlt, qi, req+0x10, cmd->cmd_rportid);
	QMEM_WR32_REQ(qlt, qi, req+0x14, qcmd->fw_xchg_addr);
	QMEM_WR16_REQ(qlt, qi, req+0x1A, flags);
	QMEM_WR16_REQ(qlt, qi, req+0x20, cmd->cmd_oxid);
	QMEM_WR32_REQ(qlt, qi, req+0x24, dbuf->db_relative_offset);
	QMEM_WR32_REQ(qlt, qi, req+0x2C, dbuf->db_data_size);
	if (dbuf->db_flags & DB_LU_DATA_BUF) {
		uint8_t			*qptr;	/* qlt continuation segs */
		uint16_t		cookie_resid;
		uint16_t		cont_segs;
		ddi_dma_cookie_t	cookie, *ckp;

		/*
		 * See if the dma cookies are in simple array format.
		 */
		ckp = qlt_get_cookie_array(dbuf);

		/*
		 * Program the first segment into main record.
		 */
		if (ckp) {
			ASSERT(ckp->dmac_size);
			QMEM_WR64_REQ(qlt, qi, req+0x34, ckp->dmac_laddress);
			QMEM_WR32_REQ(qlt, qi, req+0x3c, ckp->dmac_size);
		} else {
			qlt_ddi_dma_nextcookie(dbuf, &cookie);
			ASSERT(cookie.dmac_size);
			QMEM_WR64_REQ(qlt, qi, req+0x34, cookie.dmac_laddress);
			QMEM_WR32_REQ(qlt, qi, req+0x3c, cookie.dmac_size);
		}
		cookie_resid = cookie_count-1;

		ent_cnt = (qi == 0) ? REQUEST_QUEUE_ENTRIES :
		    REQUEST_QUEUE_MQ_ENTRIES;
		/*
		 * Program remaining segments into continuation records.
		 */
		while (cookie_resid) {
			req += IOCB_SIZE;
			if (req >= (uint8_t *)(qlt->mq_req[qi].mq_ptr +
			    (ent_cnt * IOCB_SIZE))) {
				req = (uint8_t *)(qlt->mq_req[qi].mq_ptr);
			}

			req[0] = 0x0a;
			req[1] = 1;
			req[2] = req[3] = 0;	/* tidy */
			qptr = &req[4];
			for (cont_segs = CONT_A64_DATA_SEGMENTS;
			    cont_segs && cookie_resid; cont_segs--) {

				if (ckp) {
					++ckp;		/* next cookie */
					ASSERT(ckp->dmac_size != 0);
					QMEM_WR64_REQ(qlt, qi, qptr,
					    ckp->dmac_laddress);
					qptr += 8;	/* skip over laddress */
					QMEM_WR32_REQ(qlt, qi, qptr,
					    ckp->dmac_size);
					qptr += 4;	/* skip over size */
				} else {
					qlt_ddi_dma_nextcookie(dbuf, &cookie);
					ASSERT(cookie.dmac_size != 0);
					QMEM_WR64_REQ(qlt, qi, qptr,
					    cookie.dmac_laddress);
					qptr += 8;	/* skip over laddress */
					QMEM_WR32_REQ(qlt, qi, qptr,
					    cookie.dmac_size);
					qptr += 4;	/* skip over size */
				}
				cookie_resid--;
			}
			/*
			 * zero unused remainder of IOCB
			 */
			if (cont_segs) {
				size_t resid;
				resid = (size_t)((uintptr_t)(req+IOCB_SIZE) -
				    (uintptr_t)qptr);
				ASSERT(resid < IOCB_SIZE);
				bzero(qptr, resid);
			}
		}
	} else {
		/* Single, contiguous buffer */
		QMEM_WR64_REQ(qlt, qi, req+0x34, bctl->bctl_dev_addr);
		QMEM_WR32_REQ(qlt, qi, req+0x34+8, dbuf->db_data_size);
	}

	qlt_submit_req_entries(qlt, rcnt, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (STMF_SUCCESS);
}

/*
 * We must construct proper FCP_RSP_IU now. Here we only focus on
 * the handling of FCP_SNS_INFO. If there's protocol failures (FCP_RSP_INFO),
 * we could have caught them before we enter here.
 */
fct_status_t
qlt_send_status(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	qlt_cmd_t *qcmd		= (qlt_cmd_t *)cmd->cmd_fca_private;
	scsi_task_t *task	= (scsi_task_t *)cmd->cmd_specific;
	qlt_dmem_bctl_t *bctl;
	uint32_t size;
	uint8_t *req, *fcp_rsp_iu;
	uint8_t *psd, sensbuf[24];		/* sense data */
	uint16_t flags;
	uint16_t scsi_status;
	int use_mode2;
	int ndx;
	uint16_t qi;

	qi = qcmd->qid;

	/*
	 * Enter fast channel for non check condition
	 */
	if (task->task_scsi_status != STATUS_CHECK) {
		/*
		 * We will use mode1
		 */
		flags = (uint16_t)(BIT_6 | BIT_15 |
		    (((uint16_t)qcmd->param.atio_byte3 & 0xf0) << 5));
		scsi_status = (uint16_t)task->task_scsi_status;
		if (task->task_status_ctrl == TASK_SCTRL_OVER) {
			scsi_status = (uint16_t)(scsi_status | FCP_RESID_OVER);
		} else if (task->task_status_ctrl == TASK_SCTRL_UNDER) {
			scsi_status = (uint16_t)(scsi_status | FCP_RESID_UNDER);
		}
		qcmd->dbuf_rsp_iu = NULL;

		/*
		 * Fillout CTIO type 7 IOCB
		 */
		mutex_enter(&qlt->mq_req[qi].mq_lock);
		req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
		if (req == NULL) {
			mutex_exit(&qlt->mq_req[qi].mq_lock);
			return (FCT_BUSY);
		}

		/*
		 * Common fields
		 */
		bzero(req, IOCB_SIZE);
		req[0x00] = 0x12;
		req[0x01] = 0x1;
		req[0x02] = BIT_7;	/* indicate if it's a pure status req */
		QMEM_WR32_REQ(qlt, qi, req + 0x04, cmd->cmd_handle);
		QMEM_WR16_REQ(qlt, qi, req + 0x08, cmd->cmd_rp->rp_handle);
		QMEM_WR32_REQ(qlt, qi, req + 0x10, cmd->cmd_rportid);
		QMEM_WR32_REQ(qlt, qi, req + 0x14, qcmd->fw_xchg_addr);

		/* handle TMF completion - !!! Important FIX */
		if (task->task_mgmt_function) {
			scsi_status =
			    (uint16_t)(scsi_status | FCP_RESP_LEN_VALID);

			/* no sense length, 4 bytes of resp info */
			QMEM_WR16_REQ(qlt, qi, req + 0x24, 4);
		}

		/*
		 * Mode-specific fields
		 */
		QMEM_WR16_REQ(qlt, qi, req + 0x1A, flags);
		QMEM_WR32_REQ(qlt, qi, req + 0x1C, task->task_resid);
		QMEM_WR16_REQ(qlt, qi, req + 0x20, cmd->cmd_oxid);
		QMEM_WR16_REQ(qlt, qi, req + 0x22, scsi_status);

		/*
		 * Trigger FW to send SCSI status out
		 */
		qlt_submit_req_entries(qlt, 1, qi);
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return (STMF_SUCCESS);
	}

	ASSERT(task->task_scsi_status == STATUS_CHECK);
	/*
	 * Decide the SCSI status mode, that should be used
	 */
	use_mode2 = (task->task_sense_length > 24);

	/*
	 * Prepare required information per the SCSI status mode
	 */
	flags = (uint16_t)(BIT_15 |
	    (((uint16_t)qcmd->param.atio_byte3 & 0xf0) << 5));
	if (use_mode2) {
		flags = (uint16_t)(flags | BIT_7);

		size = task->task_sense_length;
		qcmd->dbuf_rsp_iu = qlt_i_dmem_alloc(qlt,
		    task->task_sense_length, &size, 0);
		if (!qcmd->dbuf_rsp_iu) {
			return (FCT_ALLOC_FAILURE);
		}

		/*
		 * Start to construct FCP_RSP IU
		 */
		fcp_rsp_iu = qcmd->dbuf_rsp_iu->db_sglist[0].seg_addr;
		bzero(fcp_rsp_iu, 24);

		/*
		 * FCP_RSP IU flags, byte10
		 */
		fcp_rsp_iu[10] = (uint8_t)(fcp_rsp_iu[10] | BIT_1);
		if (task->task_status_ctrl == TASK_SCTRL_OVER) {
			fcp_rsp_iu[10] = (uint8_t)(fcp_rsp_iu[10] | BIT_2);
		} else if (task->task_status_ctrl == TASK_SCTRL_UNDER) {
			fcp_rsp_iu[10] = (uint8_t)(fcp_rsp_iu[10] | BIT_3);
		}

		/*
		 * SCSI status code, byte11
		 */
		fcp_rsp_iu[11] = task->task_scsi_status;

		/*
		 * FCP_RESID (Overrun or underrun)
		 */
		fcp_rsp_iu[12] = (uint8_t)((task->task_resid >> 24) & 0xFF);
		fcp_rsp_iu[13] = (uint8_t)((task->task_resid >> 16) & 0xFF);
		fcp_rsp_iu[14] = (uint8_t)((task->task_resid >>  8) & 0xFF);
		fcp_rsp_iu[15] = (uint8_t)((task->task_resid >>  0) & 0xFF);

		/*
		 * FCP_SNS_LEN
		 */
		fcp_rsp_iu[18] = (uint8_t)((task->task_sense_length >> 8) &
		    0xFF);
		fcp_rsp_iu[19] = (uint8_t)((task->task_sense_length >> 0) &
		    0xFF);

		/*
		 * FCP_RSP_LEN
		 */
		/*
		 * no FCP_RSP_INFO
		 */
		/*
		 * FCP_SNS_INFO
		 */
		bcopy(task->task_sense_data, fcp_rsp_iu + 24,
		    task->task_sense_length);

		/*
		 * Ensure dma data consistency
		 */
		qlt_dmem_dma_sync(qcmd->dbuf_rsp_iu, DDI_DMA_SYNC_FORDEV);
	} else {
		flags = (uint16_t)(flags | BIT_6);

		scsi_status = (uint16_t)task->task_scsi_status;
		if (task->task_status_ctrl == TASK_SCTRL_OVER) {
			scsi_status = (uint16_t)(scsi_status | BIT_10);
		} else if (task->task_status_ctrl == TASK_SCTRL_UNDER) {
			scsi_status = (uint16_t)(scsi_status | BIT_11);
		}
		if (task->task_sense_length) {
			scsi_status = (uint16_t)(scsi_status | BIT_9);
		}
		bcopy(task->task_sense_data, sensbuf, task->task_sense_length);
		qcmd->dbuf_rsp_iu = NULL;
	}

	/*
	 * Fillout CTIO type 7 IOCB
	 */
	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		if (use_mode2) {
			qlt_dmem_free(cmd->cmd_port->port_fds,
			    qcmd->dbuf_rsp_iu);
			qcmd->dbuf_rsp_iu = NULL;
		}
		return (FCT_BUSY);
	}

	/*
	 * Common fields
	 */
	bzero(req, IOCB_SIZE);
	req[0x00] = 0x12;
	req[0x01] = 0x1;
	req[0x02] = BIT_7;	/* to indicate if it's a pure status req */
	QMEM_WR32_REQ(qlt, qi, req + 0x04, cmd->cmd_handle);
	QMEM_WR16_REQ(qlt, qi, req + 0x08, cmd->cmd_rp->rp_handle);
	QMEM_WR16_REQ(qlt, qi, req + 0x0A, 0);	/* not timed by FW */
	if (use_mode2) {
		/* FCP RSP IU data field */
		QMEM_WR16_REQ(qlt, qi, req+0x0C, 1);
	}
	QMEM_WR32_REQ(qlt, qi, req + 0x10, cmd->cmd_rportid);
	QMEM_WR32_REQ(qlt, qi, req + 0x14, qcmd->fw_xchg_addr);

	/*
	 * Mode-specific fields
	 */
	if (!use_mode2) {
		QMEM_WR16_REQ(qlt, qi, req + 0x18, task->task_sense_length);
	}
	QMEM_WR16_REQ(qlt, qi, req + 0x1A, flags);
	QMEM_WR32_REQ(qlt, qi, req + 0x1C, task->task_resid);
	QMEM_WR16_REQ(qlt, qi, req + 0x20, cmd->cmd_oxid);
	if (use_mode2) {
		bctl = (qlt_dmem_bctl_t *)qcmd->dbuf_rsp_iu->db_port_private;
		QMEM_WR32_REQ(qlt, qi, req + 0x2C,
		    24 + task->task_sense_length);
		QMEM_WR64_REQ(qlt, qi, req + 0x34, bctl->bctl_dev_addr);
		QMEM_WR32_REQ(qlt, qi, req + 0x3C,
		    24 + task->task_sense_length);
	} else {
		QMEM_WR16_REQ(qlt, qi, req + 0x22, scsi_status);
		psd = req+0x28;

		/*
		 * Data in sense buf is always big-endian, data in IOCB
		 * should always be little-endian, so we must do swapping.
		 */
		size = ((task->task_sense_length + 3) & (~3));
		for (ndx = 0; ndx < size; ndx += 4) {
			psd[ndx + 0] = sensbuf[ndx + 3];
			psd[ndx + 1] = sensbuf[ndx + 2];
			psd[ndx + 2] = sensbuf[ndx + 1];
			psd[ndx + 3] = sensbuf[ndx + 0];
		}
	}

	/*
	 * Trigger FW to send SCSI status out
	 */
	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (STMF_SUCCESS);
}

fct_status_t
qlt_send_els_response(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	qlt_cmd_t	*qcmd;
	fct_els_t *els = (fct_els_t *)cmd->cmd_specific;
	uint8_t *req, *addr;
	qlt_dmem_bctl_t *bctl;
	uint32_t minsize;
	uint8_t elsop, req1f;
	uint16_t qi = 0;

	addr = els->els_resp_payload;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;

	minsize = els->els_resp_size;
	qcmd->dbuf = qlt_i_dmem_alloc(qlt, els->els_resp_size, &minsize, 0);
	if (qcmd->dbuf == NULL)
		return (FCT_BUSY);

	bctl = (qlt_dmem_bctl_t *)qcmd->dbuf->db_port_private;

	bcopy(addr, qcmd->dbuf->db_sglist[0].seg_addr, els->els_resp_size);
	qlt_dmem_dma_sync(qcmd->dbuf, DDI_DMA_SYNC_FORDEV);

	if (addr[0] == 0x02) {	/* ACC */
		req1f = BIT_5;
	} else {
		req1f = BIT_6;
	}
	elsop = els->els_req_payload[0];
	if ((elsop == ELS_OP_PRLI) || (elsop == ELS_OP_PRLO) ||
	    (elsop == ELS_OP_TPRLO) || (elsop == ELS_OP_LOGO)) {
		req1f = (uint8_t)(req1f | BIT_4);
	}

	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		EL(qlt, "req = NULL, %xh %xh %p %xh\n", cmd->cmd_oxid,
		    cmd->cmd_rportid, cmd, qcmd->fw_xchg_addr);
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		qlt_dmem_free(NULL, qcmd->dbuf);
		qcmd->dbuf = NULL;
		return (FCT_BUSY);
	}
	bzero(req, IOCB_SIZE);
	req[0] = 0x53; req[1] = 1; req[0xf] = 0x10;
	req[0x16] = elsop; req[0x1f] = req1f;
	QMEM_WR32(qlt, (&req[4]), cmd->cmd_handle);
	QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp->rp_handle);
	QMEM_WR16(qlt, (&req[0xC]), 1);
	QMEM_WR32(qlt, (&req[0x10]), qcmd->fw_xchg_addr);
	QMEM_WR32(qlt, (&req[0x18]), cmd->cmd_rportid);
	if (qlt->cur_topology == PORT_TOPOLOGY_PT_TO_PT) {
		req[0x1b] = (uint8_t)((cmd->cmd_lportid >> 16) & 0xff);
		req[0x1c] = (uint8_t)(cmd->cmd_lportid & 0xff);
		req[0x1d] = (uint8_t)((cmd->cmd_lportid >> 8) & 0xff);
	}
	QMEM_WR32(qlt, (&req[0x24]), els->els_resp_size);
	QMEM_WR64(qlt, (&req[0x28]), bctl->bctl_dev_addr);
	QMEM_WR32(qlt, (&req[0x30]), els->els_resp_size);

	EL(qlt, "elsop=%xh req1f=%xh IOCB_TYPE_ELSPASS: rex1=%xh\n",
	    elsop, req1f, qcmd->fw_xchg_addr);

	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_send_abts_response(qlt_state_t *qlt, fct_cmd_t *cmd, int terminate)
{
	qlt_abts_cmd_t *qcmd;
	fct_rcvd_abts_t *abts = (fct_rcvd_abts_t *)cmd->cmd_specific;
	uint8_t *req;
	uint32_t lportid;
	uint32_t fctl;
	int i;
	uint16_t qi;
	uint32_t rex1, rex2;
	uint8_t temp[64];

	qi = 0;

	qcmd = (qlt_abts_cmd_t *)cmd->cmd_fca_private;

	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		bcopy(qcmd->buf, &temp, IOCB_SIZE);
		for (i = 0; i < 12; i += 4) {
			/* Take care of firmware's LE requirement */
			temp[0x2C+i] = abts->abts_resp_payload[i+3];
			temp[0x2C+i+1] = abts->abts_resp_payload[i+2];
			temp[0x2C+i+2] = abts->abts_resp_payload[i+1];
			temp[0x2C+i+3] = abts->abts_resp_payload[i];
		}
		rex1 = QMEM_RD32(qlt, &temp[0x10]);
		rex2 = QMEM_RD32(qlt, &temp[0x3C]);

		EL(qlt, "req = NULL, %xh %xh %p %xh %xh\n", cmd->cmd_oxid,
		    cmd->cmd_rportid, cmd, rex1, rex2);

		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return (FCT_BUSY);
	}
	bcopy(qcmd->buf, req, IOCB_SIZE);
	lportid = QMEM_RD32(qlt, req+0x14) & 0xFFFFFF;
	fctl = QMEM_RD32(qlt, req+0x1C);
	fctl = ((fctl ^ BIT_23) & ~BIT_22) | (BIT_19 | BIT_16);
	req[0] = 0x55; req[1] = 1; req[2] = (uint8_t)terminate;
	QMEM_WR32(qlt, (&req[4]), cmd->cmd_handle);
	if (cmd->cmd_rp)
		QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp->rp_handle);
	else
		QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp_handle);
	if (terminate) {
		QMEM_WR16(qlt, (&req[0xC]), 1);
	}
	QMEM_WR32(qlt, req+0x14, cmd->cmd_rportid);
	req[0x17] = abts->abts_resp_rctl;
	QMEM_WR32(qlt, req+0x18, lportid);
	QMEM_WR32(qlt, req+0x1C, fctl);
	req[0x23]++;
	for (i = 0; i < 12; i += 4) {
		/* Take care of firmware's LE requirement */
		req[0x2C+i] = abts->abts_resp_payload[i+3];
		req[0x2C+i+1] = abts->abts_resp_payload[i+2];
		req[0x2C+i+2] = abts->abts_resp_payload[i+1];
		req[0x2C+i+3] = abts->abts_resp_payload[i];
	}

	rex1 = QMEM_RD32(qlt, &req[0x10]);
	rex2 = QMEM_RD32(qlt, &req[0x3C]);

	EL(qlt, "%xh %xh %d %p %xh %xh\n",
	    QMEM_RD16(qlt, req+0x26), QMEM_RD16(qlt, req+0x24),
	    terminate, cmd, rex1, rex2);

	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (FCT_SUCCESS);
}

static void
qlt_handle_inot(qlt_state_t *qlt, uint8_t *inot)
{
	int i;
	uint32_t d;
	caddr_t req;
	uint16_t qi;
	uint8_t *entry = inot;

	qi = 0;

	/* Just put it on the request queue */
	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		stmf_trace(qlt->qlt_port_alias,
		    "qlt_handle_inot: can't get a ReqQ entry");
		EL(qlt, "req = NULL\n");
		return;
	}
	for (i = 0; i < 16; i++) {
		d = QMEM_RD32(qlt, inot);
		inot += 4;
		QMEM_WR32(qlt, req, d);
		req += 4;
	}
	req -= 64;
	req[0] = 0x0e;

	QMEM_WR32(qlt, entry+0x3c, 0xdeadbeef);
	EL(qlt, "Issue inot ack\n");

	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);
}

static uint16_t
qlt_get_queue_id(qlt_state_t *qlt, int id)
{
	uint16_t	qid;

	if ((!qlt->qlt_mq_enabled) || (qlt->qlt_queue_cnt == 1)) {
		return (0);
	}

	mutex_enter(&qlt->qlock);
	if ((id == 0) && (qlt->last_qi == 0)) {
		qlt->last_qi++;
	}
	qid = qlt->last_qi;
	qlt->last_qi++;

	if (qlt->last_qi >= qlt->qlt_queue_cnt) {
		qlt->last_qi -= qlt->qlt_queue_cnt;
	}
	mutex_exit(&qlt->qlock);

	return (qid);
}

static fct_status_t
qlt_verify_atio_entry(qlt_state_t *qlt, uint8_t *atio)
{
	uint32_t sig;
	int i;
	char info[160];


	sig = QMEM_RD32(qlt, atio+0x3c);
	for (i = 0; ((sig == 0xdeadbeef) &&
	    (i < qlt_reprocess_attempt_cnt)); i++) {
		(void) ddi_dma_sync(
		    qlt->queue_mem_dma_handle,
		    ATIO_QUEUE_OFFSET + (qlt->atio_ndx_to_fw << 6),
		    IOCB_SIZE, DDI_DMA_SYNC_FORCPU);

		qlt->qlt_atio_reproc_cnt++;
		drv_usecwait(qlt_reprocess_delay);
		sig = QMEM_RD32(qlt, atio+0x3c);
	}

	if (i) {
		if (i >= qlt_reprocess_attempt_cnt) {
			EL(qlt, "atio entry reprocess failed, %x\n",
			    qlt->qlt_atio_reproc_cnt);
			cmn_err(CE_WARN, "qlt%d: atio entry reprocess"
			    " failed %x\n",
			    qlt->instance, qlt->qlt_atio_reproc_cnt);
			(void) snprintf(info, 160,
			    "qlt_handle_ctio_completion: atio entry reprocess"
			    " failed, %x rsp-%p",
			    qlt->qlt_atio_reproc_cnt, (void *)atio);
			info[159] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
			    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
			return (QLT_FAILURE);
		} else {
			EL(qlt, "atio entry reprocess succeeded, %x %x\n",
			    i, qlt->qlt_atio_reproc_cnt);
		}
	}

	return (QLT_SUCCESS);
}

uint8_t qlt_task_flags[] = { 1, 3, 2, 1, 4, 0, 1, 1 };
static void
qlt_handle_atio(qlt_state_t *qlt, uint8_t *atio)
{
	fct_cmd_t	*cmd;
	scsi_task_t	*task;
	qlt_cmd_t	*qcmd;
	uint32_t	rportid, fw_xchg_addr;
	uint8_t		*p, *q, *req, tm;
	uint16_t	cdb_size, flags, oxid;
	char		info[160];
	uint16_t	qi;

	if (qlt_verify_atio_entry(qlt, atio) != QLT_SUCCESS)
		return;

	/*
	 * If either bidirection xfer is requested of there is extended
	 * CDB, atio[0x20 + 11] will be greater than or equal to 3.
	 */
	cdb_size = 16;
	if (atio[0x20 + 11] >= 3) {
		uint8_t b = atio[0x20 + 11];
		uint16_t b1;
		if ((b & 3) == 3) {
			EL(qlt, "bidirectional I/O not supported\n");
			cmn_err(CE_WARN, "qlt(%d) CMD with bidirectional I/O "
			    "received, dropping the cmd as bidirectional "
			    " transfers are not yet supported", qlt->instance);
			/* XXX abort the I/O */
			return;
		}
		cdb_size = (uint16_t)(cdb_size + (b & 0xfc));
		/*
		 * Verify that we have enough entries. Without additional CDB
		 * Everything will fit nicely within the same 64 bytes. So the
		 * additional cdb size is essentially the # of additional bytes
		 * we need.
		 */
		b1 = (uint16_t)b;
		if (((((b1 & 0xfc) + 63) >> 6) + 1) > ((uint16_t)atio[1])) {
			EL(qlt, "extended cdb received\n");
			cmn_err(CE_WARN, "qlt(%d): cmd received with extended "
			    " cdb (cdb size = %d bytes), however the firmware "
			    " did not DMAed the entire FCP_CMD IU, entry count "
			    " is %d while it should be %d", qlt->instance,
			    cdb_size, atio[1], ((((b1 & 0xfc) + 63) >> 6) + 1));
			/* XXX abort the I/O */
			return;
		}
	}

	rportid = (((uint32_t)atio[8 + 5]) << 16) |
	    (((uint32_t)atio[8 + 6]) << 8) | atio[8+7];
	fw_xchg_addr = QMEM_RD32(qlt, atio+4);
	oxid = (uint16_t)((((uint16_t)atio[8 + 16]) << 8) | atio[8+17]);

	if (fw_xchg_addr == 0xFFFFFFFF) {
		EL(qlt, "fw_xchg_addr==0xFFFFFFFF\n");
		cmd = NULL;
	} else {
		cmd = fct_scsi_task_alloc(qlt->qlt_port, FCT_HANDLE_NONE,
		    rportid, atio+0x20, cdb_size, STMF_TASK_EXT_NONE);
		if (cmd == NULL) {
			EL(qlt, "fct_scsi_task_alloc cmd==NULL\n");
		}
	}
	if (cmd == NULL) {
		qi = 0;	/* just use request queue 0 */

		EL(qlt, "fct_scsi_task_alloc cmd==NULL\n");
		/* Abort this IO */
		flags = (uint16_t)(BIT_14 | ((atio[3] & 0xF0) << 5));

		mutex_enter(&qlt->mq_req[qi].mq_lock);
		req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
		if (req == NULL) {
			mutex_exit(&qlt->mq_req[0].mq_lock);

			(void) snprintf(info, 160,
			    "qlt_handle_atio: qlt-%p, can't "
			    "allocate space for scsi_task", (void *)qlt);
			info[159] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
			return;
		}
		bzero(req, IOCB_SIZE);
		req[0] = 0x12; req[1] = 0x1;
		QMEM_WR32(qlt, req+4, 0);
		QMEM_WR16(qlt, req+8, fct_get_rp_handle(qlt->qlt_port,
		    rportid));
		QMEM_WR16(qlt, req+10, 60);
		QMEM_WR32(qlt, req+0x10, rportid);
		QMEM_WR32(qlt, req+0x14, fw_xchg_addr);
		QMEM_WR16(qlt, req+0x1A, flags);
		QMEM_WR16(qlt, req+0x20, oxid);
		qlt_submit_req_entries(qlt, 1, qi);
		mutex_exit(&qlt->mq_req[qi].mq_lock);

		return;
	}
	if (cmd == NULL) {
		uint32_t res;
		uint16_t scsi_status = 0;
		uint16_t rphdl = 0;

		qi = 0; /* always use request queue 0 */

		rphdl = fct_get_rp_handle(qlt->qlt_port, rportid);
		if ((rphdl != 0xFFFF) &&
		    (rphdl >= qlt->qlt_port->port_max_logins)) {
			rphdl = 0xFFFF;
		}

		mutex_enter(&qlt->mq_req[qi].mq_lock);
		req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
		if (req == NULL) {
			EL(qlt, "cannot get reqq\n");
			mutex_exit(&qlt->mq_req[qi].mq_lock);
			(void) snprintf(info, 160,
			    "qlt_handle_atio: qlt-%p, can't "
			    "allocate space for termi-excg", (void *)qlt);
			info[159] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
			return;
		}

		if (rphdl != 0xFFFF) {
			/* Driver send scsi qfull status now */
			flags = (uint16_t)(BIT_15 |
			    ((uint16_t)(atio[0x3] & 0xF0) << 5));
			/* always use SCSI status mode 1 */
			flags = (uint16_t)(flags | BIT_6);

			scsi_status |= (uint16_t)(0x28);

			/* Build SCSI Status Mode 1, FCP_RSP IU 24-48 byte */
			bzero(req, IOCB_SIZE);
			req[0] = 0x12;
			req[1] = 0x1;

			/* allocate a special IOCB handle? or donot care  */
			QMEM_WR32(qlt, req+4, 0);
			QMEM_WR16(qlt, req+8, rphdl);
			QMEM_WR16(qlt, req+10, 60);
			QMEM_WR32(qlt, req+0x10, rportid);
			QMEM_WR32(qlt, req+0x14, fw_xchg_addr);

			/* sense_length set to 0 */
			QMEM_WR16(qlt, req+0x18, 0);

			QMEM_WR16(qlt, req+0x1A, flags);

			/* Residual transfer length */
			res = QMEM_RD32(qlt, atio+0x3C);
			BIG_ENDIAN_32(&res);
			if (res != 0) {
				scsi_status |= FCP_RESID_UNDER;
			}
			QMEM_WR32_REQ(qlt, qi, req + 0x1C, res);

			QMEM_WR16(qlt, req+0x20, oxid);
			QMEM_WR16_REQ(qlt, qi, req + 0x22, scsi_status);

			EL(qlt, "Send qfull (%Xh) (%Xh)(%Xh)(%Xh) from port "
			    "(%Xh:%Xh)\n", scsi_status, fw_xchg_addr, flags,
			    oxid, rportid, rphdl);
		} else {
			/* Terminate exchange because no remote port context */
			flags = (uint16_t)(BIT_14 | ((atio[3] & 0xF0) << 5));

			bzero(req, IOCB_SIZE);
			req[0] = 0x12;
			req[1] = 0x1;

			QMEM_WR32(qlt, req+4, 0);
			QMEM_WR16(qlt, req+8, rphdl);
			QMEM_WR16(qlt, req+10, 60);
			QMEM_WR32(qlt, req+0x10, rportid);
			QMEM_WR32(qlt, req+0x14, fw_xchg_addr);
			QMEM_WR16(qlt, req+0x1A, flags);
			QMEM_WR16(qlt, req+0x20, oxid);

			EL(qlt, "Termi excg (%Xh)(%Xh)(%Xh) from port (%Xh)\n",
			    fw_xchg_addr, flags, oxid, rportid);

			EL(qlt, "Termi rp_handle (%Xh)\n", rphdl);
		}

		qlt_submit_req_entries(qlt, 1, qi);
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return;
	}

	qi = qlt_get_queue_id(qlt, 0);
	task = (scsi_task_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->fw_xchg_addr = fw_xchg_addr;
	qcmd->param.atio_byte3 = atio[3];
	qcmd->qid = qi;
	cmd->cmd_oxid = oxid;
	cmd->cmd_rxid = (uint16_t)((((uint16_t)atio[8 + 18]) << 8) |
	    atio[8+19]);
	cmd->cmd_rportid = rportid;
	cmd->cmd_lportid = (((uint32_t)atio[8 + 1]) << 16) |
	    (((uint32_t)atio[8 + 2]) << 8) | atio[8 + 3];
	cmd->cmd_rp_handle = FCT_HANDLE_NONE;
	/* Dont do a 64 byte read as this is IOMMU */
	q = atio+0x28;
	/* XXX Handle fcp_cntl */
	task->task_cmd_seq_no = (uint32_t)(*q++);
	task->task_csn_size = 8;
	task->task_flags = qlt_task_flags[(*q++) & 7];
	tm = *q++;
	if (tm) {
		if (tm & BIT_1)
			task->task_mgmt_function = TM_ABORT_TASK_SET;
		else if (tm & BIT_2)
			task->task_mgmt_function = TM_CLEAR_TASK_SET;
		else if (tm & BIT_4)
			task->task_mgmt_function = TM_LUN_RESET;
		else if (tm & BIT_5)
			task->task_mgmt_function = TM_TARGET_COLD_RESET;
		else if (tm & BIT_6)
			task->task_mgmt_function = TM_CLEAR_ACA;
		else
			task->task_mgmt_function = TM_ABORT_TASK;
	}
	task->task_max_nbufs = STMF_BUFS_MAX;
	task->task_csn_size = 8;
	task->task_flags = (uint8_t)(task->task_flags | (((*q++) & 3) << 5));
	p = task->task_cdb;
	*p++ = *q++; *p++ = *q++; *p++ = *q++; *p++ = *q++;
	*p++ = *q++; *p++ = *q++; *p++ = *q++; *p++ = *q++;
	*p++ = *q++; *p++ = *q++; *p++ = *q++; *p++ = *q++;
	*p++ = *q++; *p++ = *q++; *p++ = *q++; *p++ = *q++;
	if (cdb_size > 16) {
		uint16_t xtra = (uint16_t)(cdb_size - 16);
		uint16_t i;
		uint8_t cb[4];

		while (xtra) {
			*p++ = *q++;
			xtra--;
			if (q == ((uint8_t *)qlt->queue_mem_ptr +
			    ATIO_QUEUE_OFFSET + (ATIO_QUEUE_ENTRIES * 64))) {
				q = (uint8_t *)qlt->queue_mem_ptr +
				    ATIO_QUEUE_OFFSET;
			}
		}
		for (i = 0; i < 4; i++) {
			cb[i] = *q++;
			if (q == ((uint8_t *)qlt->queue_mem_ptr +
			    ATIO_QUEUE_OFFSET + (ATIO_QUEUE_ENTRIES * 64))) {
				q = (uint8_t *)qlt->queue_mem_ptr +
				    ATIO_QUEUE_OFFSET;
			}
		}
		task->task_expected_xfer_length = (((uint32_t)cb[0]) << 24) |
		    (((uint32_t)cb[1]) << 16) |
		    (((uint32_t)cb[2]) << 8) | cb[3];
	} else {
		task->task_expected_xfer_length = (((uint32_t)q[0]) << 24) |
		    (((uint32_t)q[1]) << 16) |
		    (((uint32_t)q[2]) << 8) | q[3];
	}

	QMEM_WR32(qlt, atio+0x3c, 0xdeadbeef);
	fct_post_rcvd_cmd(cmd, 0);
}

static void
qlt_handle_dereg_completion(qlt_state_t *qlt, uint8_t *rsp)
{
	uint16_t status;
	uint32_t portid;
	uint32_t subcode1, subcode2;

	status = QMEM_RD16(qlt, rsp+8);
	portid = QMEM_RD32(qlt, rsp+0x10) & 0xffffff;
	subcode1 = QMEM_RD32(qlt, rsp+0x14);
	subcode2 = QMEM_RD32(qlt, rsp+0x18);

	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		mutex_enter(&qlt->mq_req[0].mq_lock);
	} else {
		mutex_enter(&qlt->preq_lock);
	}
	if (portid != qlt->rp_id_in_dereg) {
		int instance = ddi_get_instance(qlt->dip);

		EL(qlt, "implicit logout reveived portid = %xh\n", portid);
		cmn_err(CE_WARN, "qlt(%d): implicit logout completion for 0x%x"
		    " received when driver wasn't waiting for it",
		    instance, portid);
		if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
			mutex_exit(&qlt->mq_req[0].mq_lock);
		} else {
			mutex_exit(&qlt->preq_lock);
		}
		return;
	}

	if (status != 0) {
		EL(qlt, "implicit logout completed for %xh with status %xh, "
		    "subcode1 %xh subcode2 %xh\n", portid, status, subcode1,
		    subcode2);
		if (status == 0x31 && subcode1 == 0x0a) {
			qlt->rp_dereg_status = FCT_SUCCESS;
		} else {
			EL(qlt, "implicit logout portid=%xh, status=%xh, "
			    "subcode1=%xh, subcode2=%xh\n", portid, status,
			    subcode1, subcode2);
			qlt->rp_dereg_status =
			    QLT_FIRMWARE_ERROR(status, subcode1, subcode2);
		}
	} else {
		qlt->rp_dereg_status = FCT_SUCCESS;
	}
	cv_signal(&qlt->rp_dereg_cv);
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_27xx_chip)) {
		mutex_exit(&qlt->mq_req[0].mq_lock);
	} else {
		mutex_exit(&qlt->preq_lock);
	}
}

/*
 * Note that when an ELS is aborted, the regular or aborted completion
 * (if any) gets posted before the abort IOCB comes back on response queue.
 */
static void
qlt_handle_unsol_els_completion(qlt_state_t *qlt, uint8_t *rsp)
{
	char		info[160];
	fct_cmd_t	*cmd;
	qlt_cmd_t	*qcmd;
	uint32_t	hndl;
	uint32_t	subcode1, subcode2;
	uint16_t	status;
	uint8_t		elsop;

	hndl = QMEM_RD32(qlt, rsp+4);
	status = QMEM_RD16(qlt, rsp+8);
	subcode1 = QMEM_RD32(qlt, rsp+0x24);
	subcode2 = QMEM_RD32(qlt, rsp+0x28);
	elsop = rsp[0x16];

	if (!CMD_HANDLE_VALID(hndl)) {
		EL(qlt, "handle = %xh\n", hndl);
		/*
		 * This cannot happen for unsol els completion. This can
		 * only happen when abort for an unsol els completes.
		 * This condition indicates a firmware bug.
		 */
		(void) snprintf(info, 160, "qlt_handle_unsol_els_completion: "
		    "Invalid handle: hndl-%x, status-%x/%x/%x, rsp-%p",
		    hndl, status, subcode1, subcode2, (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
		    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
		return;
	}

	if (status == 5) {
		/*
		 * When an unsolicited els is aborted, the abort is done
		 * by a ELSPT iocb with abort control. This is the aborted IOCB
		 * and not the abortee. We will do the cleanup when the
		 * IOCB which caused the abort, returns.
		 */
		EL(qlt, "status = %xh\n", status);
		stmf_trace(0, "--UNSOL ELS returned with status 5 --");
		return;
	}

	cmd = fct_handle_to_cmd(qlt->qlt_port, hndl);
	if (cmd == NULL) {
		EL(qlt, "fct_handle_to_cmd cmd==NULL, hndl=%xh\n", hndl);
		/*
		 * Now why would this happen ???
		 */
		(void) snprintf(info, 160,
		    "qlt_handle_unsol_els_completion: can not "
		    "get cmd, hndl-%x, status-%x, rsp-%p", hndl, status,
		    (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

		return;
	}

	ASSERT(cmd->cmd_type == FCT_CMD_RCVD_ELS);
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	if (qcmd->flags & QLT_CMD_ABORTING) {
		/*
		 * This is the same case as "if (status == 5)" above. The
		 * only difference is that in this case the firmware actually
		 * finished sending the response. So the abort attempt will
		 * come back with status ?. We will handle it there.
		 */
		stmf_trace(0, "--UNSOL ELS finished while we are trying to "
		    "abort it");
		return;
	}

	if (qcmd->dbuf != NULL) {
		qlt_dmem_free(NULL, qcmd->dbuf);
		qcmd->dbuf = NULL;
	}

	if (status == 0) {
		fct_send_response_done(cmd, FCT_SUCCESS, FCT_IOF_FCA_DONE);

		if ((elsop == ELS_OP_LOGO) &&
		    (qlt->cur_topology == PORT_TOPOLOGY_PT_TO_PT)) {
			EL(qlt, "reset link since this is LOGO and N2N\n");
			(void) snprintf(info, 80,
			    "qlt_handle_unsol_els_completion: qlt-%p, "
			    "trigger RFLAG_RESET to recover",
			    (void *)qlt);

			info[79] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET,
			    info);
		}
	} else {
		EL(qlt, "status (0xh) sucode1=%xh subconde2=%xh\n",
		    status, subcode1, subcode2);
		fct_send_response_done(cmd,
		    QLT_FIRMWARE_ERROR(status, subcode1, subcode2), 0);
	}
}

static void
qlt_handle_unsol_els_abort_completion(qlt_state_t *qlt, uint8_t *rsp)
{
	char		info[160];
	fct_cmd_t	*cmd;
	qlt_cmd_t	*qcmd;
	uint32_t	hndl;
	uint32_t	subcode1, subcode2;
	uint16_t	status;

	hndl = QMEM_RD32(qlt, rsp+4);
	status = QMEM_RD16(qlt, rsp+8);
	subcode1 = QMEM_RD32(qlt, rsp+0x24);
	subcode2 = QMEM_RD32(qlt, rsp+0x28);

	if (!CMD_HANDLE_VALID(hndl)) {
		EL(qlt, "handle = %xh\n", hndl);
		ASSERT(hndl == 0);
		/*
		 * Someone has requested to abort it, but no one is waiting for
		 * this completion.
		 */
		if ((status != 0) && (status != 8)) {
			EL(qlt, "status = %xh\n", status);
			/*
			 * There could be exchange resource leakage, so
			 * throw HBA fatal error event now
			 */
			(void) snprintf(info, 160,
			    "qlt_handle_unsol_els_abort_completion: "
			    "Invalid handle: hndl-%x, status-%x/%x/%x, rsp-%p",
			    hndl, status, subcode1, subcode2, (void *)rsp);
			info[159] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
			    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
			return;
		}

		return;
	}

	cmd = fct_handle_to_cmd(qlt->qlt_port, hndl);
	if (cmd == NULL) {
		EL(qlt, "fct_handle_to_cmd cmd==NULL, hndl=%xh\n", hndl);
		/*
		 * Why would this happen ??
		 */
		(void) snprintf(info, 160,
		    "qlt_handle_unsol_els_abort_completion: can not get "
		    "cmd, hndl-%x, status-%x, rsp-%p", hndl, status,
		    (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

		return;
	}

	ASSERT(cmd->cmd_type == FCT_CMD_RCVD_ELS);
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	ASSERT(qcmd->flags & QLT_CMD_ABORTING);

	if (qcmd->dbuf != NULL) {
		qlt_dmem_free(NULL, qcmd->dbuf);
		qcmd->dbuf = NULL;
	}

	if (status == 0) {
		fct_cmd_fca_aborted(cmd, FCT_ABORT_SUCCESS, FCT_IOF_FCA_DONE);
	} else if (status == 8) {
		fct_cmd_fca_aborted(cmd, FCT_NOT_FOUND, FCT_IOF_FCA_DONE);
	} else {
		fct_cmd_fca_aborted(cmd,
		    QLT_FIRMWARE_ERROR(status, subcode1, subcode2), 0);
	}
}

static void
qlt_handle_sol_els_completion(qlt_state_t *qlt, uint8_t *rsp)
{
	char		info[160];
	fct_cmd_t	*cmd;
	fct_els_t	*els;
	qlt_cmd_t	*qcmd;
	uint32_t	hndl;
	uint32_t	subcode1, subcode2;
	uint16_t	status;

	hndl = QMEM_RD32(qlt, rsp+4);
	status = QMEM_RD16(qlt, rsp+8);
	subcode1 = QMEM_RD32(qlt, rsp+0x24);
	subcode2 = QMEM_RD32(qlt, rsp+0x28);

	if (!CMD_HANDLE_VALID(hndl)) {
		EL(qlt, "handle = %xh\n", hndl);
		/*
		 * This cannot happen for sol els completion.
		 */
		(void) snprintf(info, 160, "qlt_handle_sol_els_completion: "
		    "Invalid handle: hndl-%x, status-%x/%x/%x, rsp-%p",
		    hndl, status, subcode1, subcode2, (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
		    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
		return;
	}

	cmd = fct_handle_to_cmd(qlt->qlt_port, hndl);
	if (cmd == NULL) {
		EL(qlt, "fct_handle_to_cmd cmd==NULL, hndl=%xh\n", hndl);
		(void) snprintf(info, 160,
		    "qlt_handle_sol_els_completion: can not "
		    "get cmd, hndl-%x, status-%x, rsp-%p", hndl, status,
		    (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

		return;
	}

	ASSERT(cmd->cmd_type == FCT_CMD_SOL_ELS);
	els = (fct_els_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->fw_xchg_addr = QMEM_RD32(qlt, (&rsp[0x10]));

	if (qcmd->flags & QLT_CMD_ABORTING) {
		/*
		 * We will handle it when the ABORT IO IOCB returns.
		 */
		return;
	}

	if (qcmd->dbuf != NULL) {
		if (status == 0) {
			qlt_dmem_dma_sync(qcmd->dbuf, DDI_DMA_SYNC_FORKERNEL);
			bcopy(qcmd->dbuf->db_sglist[0].seg_addr +
			    qcmd->param.resp_offset,
			    els->els_resp_payload, els->els_resp_size);
		}
		qlt_dmem_free(NULL, qcmd->dbuf);
		qcmd->dbuf = NULL;
	}

	if (status == 0) {
		fct_send_cmd_done(cmd, FCT_SUCCESS, FCT_IOF_FCA_DONE);
	} else {
		fct_send_cmd_done(cmd,
		    QLT_FIRMWARE_ERROR(status, subcode1, subcode2), 0);
	}
}

static void
qlt_handle_ct_completion(qlt_state_t *qlt, uint8_t *rsp)
{
	fct_cmd_t	*cmd;
	fct_sol_ct_t	*ct;
	qlt_cmd_t	*qcmd;
	uint32_t	 hndl;
	uint16_t	 status;
	char		 info[160];

	hndl = QMEM_RD32(qlt, rsp+4);
	status = QMEM_RD16(qlt, rsp+8);

	if (!CMD_HANDLE_VALID(hndl)) {
		EL(qlt, "handle = %xh\n", hndl);
		/*
		 * Solicited commands will always have a valid handle.
		 */
		(void) snprintf(info, 160, "qlt_handle_ct_completion: hndl-"
		    "%x, status-%x, rsp-%p", hndl, status, (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
		    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
		return;
	}

	cmd = fct_handle_to_cmd(qlt->qlt_port, hndl);
	EL(qlt, "cmd=%ph hndl=%xh status=%xh\n", cmd, hndl, status);
	if (cmd == NULL) {
		EL(qlt, "fct_handle_to_cmd cmd==NULL, hndl=%xh\n", hndl);
		(void) snprintf(info, 160,
		    "qlt_handle_ct_completion: cannot find "
		    "cmd, hndl-%x, status-%x, rsp-%p", hndl, status,
		    (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

		return;
	}

	ct = (fct_sol_ct_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	ASSERT(cmd->cmd_type == FCT_CMD_SOL_CT);

	if (qcmd->flags & QLT_CMD_ABORTING) {
		/*
		 * We will handle it when ABORT IO IOCB returns;
		 */
		return;
	}

	ASSERT(qcmd->dbuf);
	if ((status == 0) || (status == 0x15)) {
		qlt_dmem_dma_sync(qcmd->dbuf, DDI_DMA_SYNC_FORKERNEL);
		bcopy(qcmd->dbuf->db_sglist[0].seg_addr +
		    qcmd->param.resp_offset,
		    ct->ct_resp_payload, ct->ct_resp_size);
	}
	qlt_dmem_free(NULL, qcmd->dbuf);
	qcmd->dbuf = NULL;

	if ((status == 0) || (status == 0x15)) {
		fct_send_cmd_done(cmd, FCT_SUCCESS, FCT_IOF_FCA_DONE);
	} else {
		fct_send_cmd_done(cmd, QLT_FIRMWARE_ERROR(status, 0, 0), 0);
	}
}

static fct_status_t
qlt_verify_resp_entry(qlt_state_t *qlt, uint8_t *rsp, uint16_t qi)
{
	uint32_t sig;
	int i;
	char info[160];

	sig = QMEM_RD32_RSPQ(qlt, qi, rsp+0x3c);
	for (i = 0; ((sig == 0xdeadbeef) &&
	    (i < qlt_reprocess_attempt_cnt)); i++) {
		(void) ddi_dma_sync(
		    qlt->mq_resp[qi].queue_mem_mq_dma_handle,
		    (qlt->mq_resp[qi].mq_ndx_to_fw << 6),
		    IOCB_SIZE, DDI_DMA_SYNC_FORCPU);

		qlt->qlt_resp_reproc_cnt++;
		drv_usecwait(qlt_reprocess_delay);
		sig = QMEM_RD32_RSPQ(qlt, qi, rsp+0x3c);
	}

	if (i) {
		if (i >= qlt_reprocess_attempt_cnt) {
			EL(qlt, "resp entry reprocess failed, %x\n",
			    qlt->qlt_resp_reproc_cnt);
			cmn_err(CE_WARN, "qlt%d: resp entry reprocess"
			    " failed %x\n",
			    qlt->instance, qlt->qlt_resp_reproc_cnt);
			(void) snprintf(info, 160,
			    "qlt_handle_ctio_completion: resp entry reprocess"
			    " failed, %x rsp-%p",
			    qlt->qlt_resp_reproc_cnt, (void *)rsp);
			info[159] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET,
			    info);
			return (QLT_FAILURE);
		} else {
			EL(qlt, "resp entry reprocess succeeded, %x %x\n",
			    i, qlt->qlt_resp_reproc_cnt);
		}
	}

	return (QLT_SUCCESS);
}

static void
qlt_handle_ctio_completion(qlt_state_t *qlt, uint8_t *rsp, uint16_t qi)
{
	fct_cmd_t	*cmd;
	scsi_task_t	*task;
	qlt_cmd_t	*qcmd;
	stmf_data_buf_t	*dbuf;
	fct_status_t	fc_st;
	uint32_t	iof = 0;
	uint32_t	hndl;
	uint32_t	rex1;
	uint16_t	oxid;
	uint16_t	status;
	uint16_t	flags;
	uint8_t		abort_req;
	uint8_t		n;
	char		info[160];

	if (qlt_verify_resp_entry(qlt, rsp, qi) != QLT_SUCCESS)
		return;

	/* write a deadbeef in the last 4 bytes of the IOCB */
	QMEM_WR32_RSPQ(qlt, qi, rsp+0x3c, 0xdeadbeef);

	/* XXX: Check validity of the IOCB by checking 4th byte. */
	hndl = QMEM_RD32_RSPQ(qlt, qi, rsp+4);
	status = QMEM_RD16_RSPQ(qlt, qi, rsp+8);
	flags = QMEM_RD16_RSPQ(qlt, qi, rsp+0x1a);
	oxid = QMEM_RD16_RSPQ(qlt, qi, rsp+0x20);
	rex1 = QMEM_RD32_RSPQ(qlt, qi, rsp+0x14);
	n = rsp[2];

	if (!CMD_HANDLE_VALID(hndl)) {
		EL(qlt, "handle = %xh\n", hndl);
		ASSERT(hndl == 0);
		/*
		 * Someone has requested to abort it, but no one is waiting for
		 * this completion.
		 */
		EL(qlt, "hndl-%xh, status-%xh, rsp-%p\n", hndl, status,
		    (void *)rsp);
		if ((status != 1) && (status != 2)) {
			EL(qlt, "status = %xh\n", status);
			if (status == 0x29) {
				uint8_t		*req;

				/*
				 * The qlt port received an ATIO request from
				 * remote port before it issued a plogi.
				 * The qlt fw returned the CTIO completion
				 * status 0x29 to inform driver to do cleanup
				 * (terminate the IO exchange). The subsequent
				 * ABTS from the initiator can be handled
				 * cleanly.
				 */
				qi = 0;
				mutex_enter(&qlt->mq_req[qi].mq_lock);
				req = (uint8_t *)
				    qlt_get_req_entries(qlt, 1, qi);

				if (req == NULL) {
					EL(qlt, "No reqq entry available to "
					    "termi exchg\n");
					mutex_exit(&qlt->mq_req[qi].mq_lock);

					(void) snprintf(info, 160,
					    "qlt_handle_ctio_completion: no "
					    "reqq entry available, status-%x,"
					    "rsp-%p", status, (void *)rsp);

					info[159] = 0;

					(void) fct_port_shutdown(qlt->qlt_port,
					    STMF_RFLAG_FATAL_ERROR |
					    STMF_RFLAG_RESET,
					    info);

					return;
				}

				flags &= 0x1E00;
				flags |= BIT_14;

				bzero(req, IOCB_SIZE);
				req[0] = 0x12;
				req[1] = 0x1;

				QMEM_WR32(qlt, req+4, 0);
				QMEM_WR16(qlt, req+8, 0xFFFF);
				QMEM_WR16(qlt, req+10, 60);
				QMEM_WR32(qlt, req+0x14, rex1);
				QMEM_WR16(qlt, req+0x1A, flags);
				QMEM_WR16(qlt, req+0x20, oxid);

				EL(qlt, "Termi exchg (%Xh)(%Xh)(%Xh) "
				    "rphdl=0xFFFF\n", rex1, flags, oxid);

				qlt_submit_req_entries(qlt, 1, qi);
				mutex_exit(&qlt->mq_req[qi].mq_lock);
			} else {
				/*
				 * There could be exchange resource leakage,
				 * so throw HBA fatal error event now
				 */
				(void) snprintf(info, 160,
				    "qlt_handle_ctio_completion: hndl-%x, "
				    "status-%x, rsp-%p", hndl, status,
				    (void *)rsp);

				info[159] = 0;

				(void) fct_port_shutdown(qlt->qlt_port,
				    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET,
				    info);
			}
		}

		return;
	}

	if (flags & BIT_14) {
		abort_req = 1;
		EL(qlt, "abort: hndl-%x, status-%x, rsp-%p\n", hndl, status,
		    (void *)rsp);
	} else {
		abort_req = 0;
	}

	cmd = fct_handle_to_cmd(qlt->qlt_port, hndl);
	if (cmd == NULL) {
		EL(qlt, "fct_handle_to_cmd cmd==NULL, hndl=%xh\n", hndl);
		(void) snprintf(info, 160,
		    "qlt_handle_ctio_completion: cannot find "
		    "cmd, hndl-%x, status-%x, rsp-%p", hndl, status,
		    (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    /* STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info); */
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
		    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);

		return;
	}

	task = (scsi_task_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	if (qcmd->dbuf_rsp_iu) {
		ASSERT((flags & (BIT_6 | BIT_7)) == BIT_7);
		qlt_dmem_free(NULL, qcmd->dbuf_rsp_iu);
		qcmd->dbuf_rsp_iu = NULL;
	}

	if ((status == 1) || (status == 2)) {
		if (abort_req) {
			fc_st = FCT_ABORT_SUCCESS;
			iof = FCT_IOF_FCA_DONE;
		} else {
			fc_st = FCT_SUCCESS;
			if (flags & BIT_15) {
				iof = FCT_IOF_FCA_DONE;
			}
		}
	} else {
		EL(qlt, "status = %xh\n", status);
		if ((status == 8) && abort_req) {
			fc_st = FCT_NOT_FOUND;
			iof = FCT_IOF_FCA_DONE;
		} else {
			fc_st = QLT_FIRMWARE_ERROR(status, 0, 0);
		}
	}
	dbuf = NULL;
	if (((n & BIT_7) == 0) && (!abort_req)) {
		/* A completion of data xfer */
		if (n == 0) {
			dbuf = qcmd->dbuf;
		} else {
			dbuf = stmf_handle_to_buf(task, n);
		}

		ASSERT(dbuf != NULL);
		if (dbuf->db_flags & DB_DIRECTION_FROM_RPORT)
			qlt_dmem_dma_sync(dbuf, DDI_DMA_SYNC_FORCPU);
		if (flags & BIT_15) {
			dbuf->db_flags = (uint16_t)(dbuf->db_flags |
			    DB_STATUS_GOOD_SENT);
		}

		dbuf->db_xfer_status = fc_st;
		fct_scsi_data_xfer_done(cmd, dbuf, iof);
		return;
	}
	if (!abort_req) {
		/*
		 * This was just a pure status xfer.
		 */
		fct_send_response_done(cmd, fc_st, iof);
		return;
	}

	fct_cmd_fca_aborted(cmd, fc_st, iof);

	EL(qlt, "(%d) (%p)(%xh,%xh),%x %x %x\n",
	    qi, cmd, cmd->cmd_oxid, cmd->cmd_rxid,
	    cmd->cmd_handle, qcmd->fw_xchg_addr,
	    fc_st);
}

static void
qlt_handle_sol_abort_completion(qlt_state_t *qlt, uint8_t *rsp)
{
	char		info[80];
	fct_cmd_t	*cmd;
	qlt_cmd_t	*qcmd;
	uint32_t	h;
	uint16_t	status;

	h = QMEM_RD32(qlt, rsp+4);
	status = QMEM_RD16(qlt, rsp+8);

	if (!CMD_HANDLE_VALID(h)) {
		EL(qlt, "handle = %xh\n", h);
		/*
		 * Solicited commands always have a valid handle.
		 */
		(void) snprintf(info, 80,
		    "qlt_handle_sol_abort_completion: hndl-"
		    "%x, status-%x, rsp-%p", h, status, (void *)rsp);
		info[79] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
		    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
		return;
	}
	cmd = fct_handle_to_cmd(qlt->qlt_port, h);
	if (cmd == NULL) {
		EL(qlt, "fct_handle_to_cmd cmd==NULL, hndl=%xh\n", h);
		/*
		 * What happened to the cmd ??
		 */
		(void) snprintf(info, 80,
		    "qlt_handle_sol_abort_completion: cannot "
		    "find cmd, hndl-%x, status-%x, rsp-%p", h, status,
		    (void *)rsp);
		info[79] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

		return;
	}

	ASSERT((cmd->cmd_type == FCT_CMD_SOL_ELS) ||
	    (cmd->cmd_type == FCT_CMD_SOL_CT));
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	if (qcmd->dbuf != NULL) {
		qlt_dmem_free(NULL, qcmd->dbuf);
		qcmd->dbuf = NULL;
	}
	ASSERT(qcmd->flags & QLT_CMD_ABORTING);
	EL(qlt, "status=%xh\n", status);
	if (status == 0) {
		fct_cmd_fca_aborted(cmd, FCT_ABORT_SUCCESS, FCT_IOF_FCA_DONE);
	} else if (status == 0x31) {
		fct_cmd_fca_aborted(cmd, FCT_NOT_FOUND, FCT_IOF_FCA_DONE);
	} else {
		fct_cmd_fca_aborted(cmd, QLT_FIRMWARE_ERROR(status, 0, 0), 0);
	}
}

static void
qlt_handle_rcvd_abts(qlt_state_t *qlt, uint8_t *resp, uint16_t qi)
{
	qlt_abts_cmd_t	*qcmd;
	fct_cmd_t	*cmd;
	uint32_t	remote_portid;
	uint32_t	rex1;
	uint32_t	rex2;
	char		info[160];

	remote_portid = ((uint32_t)(QMEM_RD16(qlt, (&resp[0x18])))) |
	    ((uint32_t)(resp[0x1A])) << 16;
	cmd = (fct_cmd_t *)fct_alloc(FCT_STRUCT_CMD_RCVD_ABTS,
	    sizeof (qlt_abts_cmd_t), 0);
	if (cmd == NULL) {
		EL(qlt, "fct_alloc cmd==NULL\n");
		(void) snprintf(info, 160,
		    "qlt_handle_rcvd_abts: qlt-%p, can't "
		    "allocate space for fct_cmd", (void *)qlt);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);
		return;
	}

	resp[0xC] = resp[0xD] = resp[0xE] = 0;
	qcmd = (qlt_abts_cmd_t *)cmd->cmd_fca_private;
	qcmd->qid = qi;
	bcopy(resp, qcmd->buf, IOCB_SIZE);
	cmd->cmd_port = qlt->qlt_port;
	cmd->cmd_rp_handle = QMEM_RD16(qlt, resp+0xA);
	if (cmd->cmd_rp_handle == 0xFFFF)
		cmd->cmd_rp_handle = FCT_HANDLE_NONE;

	cmd->cmd_rportid = remote_portid;
	cmd->cmd_lportid = ((uint32_t)(QMEM_RD16(qlt, (&resp[0x14])))) |
	    ((uint32_t)(resp[0x16])) << 16;
	cmd->cmd_oxid = QMEM_RD16(qlt, (&resp[0x26]));
	cmd->cmd_rxid = QMEM_RD16(qlt, (&resp[0x24]));

	rex1 = QMEM_RD32(qlt, resp+0x10);
	rex2 = QMEM_RD32(qlt, resp+0x3C);

	EL(qlt, "(%d)(%xh %xh) (%xh)(%p) (%xh %xh) (%x)\n",
	    qi, cmd->cmd_oxid, cmd->cmd_rxid, remote_portid,
	    cmd, rex1, rex2, cmd->cmd_handle);

	fct_post_rcvd_cmd(cmd, 0);
}

static void
qlt_handle_abts_completion(qlt_state_t *qlt, uint8_t *resp, uint16_t qi)
{
	uint16_t status;
	char	info[80];

	status = QMEM_RD16(qlt, resp+8);

	if ((status == 0) || (status == 5)) {
		EL(qlt, "qi(%d) status =%xh,(%xh %xh)\n",
		    qi, status, QMEM_RD16(qlt, resp+0x26),
		    QMEM_RD16(qlt, resp+0x24));
		return;
	}

	EL(qlt, "ABTS status=%x/%x/%x resp_off %x",
	    status, QMEM_RD32(qlt, resp+0x34),
	    QMEM_RD32(qlt, resp+0x38),
	    ((uint32_t)(qlt->mq_resp[0].mq_ndx_to_fw)) << 6);

	(void) snprintf(info, 80, "ABTS completion failed %x/%x/%x resp_off %x",
	    status, QMEM_RD32(qlt, resp+0x34), QMEM_RD32(qlt, resp+0x38),
	    ((uint32_t)(qlt->mq_resp[0].mq_ndx_to_fw)) << 6);
	info[79] = 0;
	(void) fct_port_shutdown(qlt->qlt_port, STMF_RFLAG_FATAL_ERROR |
	    STMF_RFLAG_RESET | STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
}

#ifdef	DEBUG
uint32_t qlt_drop_abort_counter = 0;
#endif

fct_status_t
qlt_abort_cmd(struct fct_local_port *port, fct_cmd_t *cmd, uint32_t flags)
{
	qlt_state_t *qlt = (qlt_state_t *)port->port_fca_private;

	if ((qlt->qlt_state == FCT_STATE_OFFLINE) ||
	    (qlt->qlt_state == FCT_STATE_OFFLINING)) {
		return (FCT_NOT_FOUND);
	}

#ifdef DEBUG
	if (qlt_drop_abort_counter > 0) {
		if (atomic_dec_32_nv(&qlt_drop_abort_counter) == 1)
			return (FCT_SUCCESS);
	}
#endif

	EL(qlt, "cmd_type = %x\n", cmd->cmd_type);
	if (cmd->cmd_type == FCT_CMD_FCP_XCHG) {
		return (qlt_abort_unsol_scsi_cmd(qlt, cmd));
	}

	if (flags & FCT_IOF_FORCE_FCA_DONE) {
		cmd->cmd_handle = 0;
	}

	if (cmd->cmd_type == FCT_CMD_RCVD_ABTS) {
		/* this is retried ABTS, terminate it now */
		return (qlt_send_abts_response(qlt, cmd, 1));
	}

	if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
		return (qlt_abort_purex(qlt, cmd));
	}

	if ((cmd->cmd_type == FCT_CMD_SOL_ELS) ||
	    (cmd->cmd_type == FCT_CMD_SOL_CT)) {
		return (qlt_abort_sol_cmd(qlt, cmd));
	}
	EL(qlt, "cmd->cmd_type = %x\n", cmd->cmd_type);

	ASSERT(0);
	return (FCT_FAILURE);
}

fct_status_t
qlt_abort_sol_cmd(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	uint8_t *req;
	qlt_cmd_t *qcmd;
	uint16_t qi;

	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->flags = (uint16_t)(qcmd->flags | QLT_CMD_ABORTING);
	qi = qcmd->qid;

	EL(qlt, "fctcmd-%p, cmd_handle-%xh rportid=%xh\n",
	    cmd, cmd->cmd_handle, cmd->cmd_rportid);

	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		EL(qlt, "req == NULL\n");
		mutex_exit(&qlt->mq_req[qi].mq_lock);

		return (FCT_BUSY);
	}
	bzero(req, IOCB_SIZE);
	req[0] = 0x33; req[1] = 1;
	QMEM_WR32(qlt, req+4, cmd->cmd_handle);
	if (cmd->cmd_rp) {
		QMEM_WR16(qlt, req+8, cmd->cmd_rp->rp_handle);
	} else {
		QMEM_WR16(qlt, req+8, 0xFFFF);
	}

	QMEM_WR32(qlt, req+0xc, cmd->cmd_handle);
	QMEM_WR32(qlt, req+0x30, cmd->cmd_rportid);
	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_abort_purex(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	uint8_t *req;
	qlt_cmd_t *qcmd;
	fct_els_t *els;
	uint8_t elsop, req1f;
	uint16_t qi;

	els = (fct_els_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qi = qcmd->qid;
	elsop = els->els_req_payload[0];
	EL(qlt, "fctcmd-%p, cmd_handle-%xh, elsop-%xh\n", cmd,
	    cmd->cmd_handle, elsop);
	req1f = 0x60;	/* Terminate xchg */
	if ((elsop == ELS_OP_PRLI) || (elsop == ELS_OP_PRLO) ||
	    (elsop == ELS_OP_TPRLO) || (elsop == ELS_OP_LOGO)) {
		req1f = (uint8_t)(req1f | BIT_4);
	}

	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		EL(qlt, "req == NULL\n");
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return (FCT_BUSY);
	}

	qcmd->flags = (uint16_t)(qcmd->flags | QLT_CMD_ABORTING);
	bzero(req, IOCB_SIZE);
	req[0] = 0x53; req[1] = 1; req[0xf] = 0x10;
	req[0x16] = elsop; req[0x1f] = req1f;
	QMEM_WR32(qlt, (&req[4]), cmd->cmd_handle);
	if (cmd->cmd_rp) {
		QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp->rp_handle);
		EL(qlt, "rp_handle-%x\n", cmd->cmd_rp->rp_handle);
	} else {
		QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp_handle);
		EL(qlt, "cmd_rp_handle-%x\n", cmd->cmd_rp_handle);
	}

	QMEM_WR32(qlt, (&req[0x10]), qcmd->fw_xchg_addr);
	QMEM_WR32(qlt, (&req[0x18]), cmd->cmd_rportid);
	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_abort_unsol_scsi_cmd(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	qlt_cmd_t *qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	uint8_t *req;
	uint16_t flags;
	uint16_t qi;

	qi = qcmd->qid;

	flags = (uint16_t)(BIT_14 |
	    (((uint16_t)qcmd->param.atio_byte3 & 0xf0) << 5));

	EL(qlt, "(%d) (%x) (%p) (%x)\n", qi, cmd->cmd_oxid,
	    cmd, qcmd->fw_xchg_addr);

	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		EL(qlt, "req == NULL\n");
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return (FCT_BUSY);
	}

	qcmd->flags = (uint16_t)(qcmd->flags | QLT_CMD_ABORTING);
	bzero(req, IOCB_SIZE);
	req[0] = 0x12; req[1] = 0x1;
	QMEM_WR32_REQ(qlt, qi, req+4, cmd->cmd_handle);
	QMEM_WR16_REQ(qlt, qi, req+8, cmd->cmd_rp->rp_handle);
	QMEM_WR16_REQ(qlt, qi, req+10, 60);	/* 60 seconds timeout */
	QMEM_WR32_REQ(qlt, qi, req+0x10, cmd->cmd_rportid);
	QMEM_WR32_REQ(qlt, qi, req+0x14, qcmd->fw_xchg_addr);
	QMEM_WR16_REQ(qlt, qi, req+0x1A, flags);
	QMEM_WR16_REQ(qlt, qi, req+0x20, cmd->cmd_oxid);
	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_send_cmd(fct_cmd_t *cmd)
{
	qlt_state_t *qlt;

	qlt = (qlt_state_t *)cmd->cmd_port->port_fca_private;
	EL(qlt, "cmd->cmd_type = %xh\n", cmd->cmd_type);
	if (cmd->cmd_type == FCT_CMD_SOL_ELS) {
		return (qlt_send_els(qlt, cmd));
	} else if (cmd->cmd_type == FCT_CMD_SOL_CT) {
		return (qlt_send_ct(qlt, cmd));
	}
	EL(qlt, "Unknown cmd->cmd_type = %xh\n", cmd->cmd_type);

	ASSERT(0);
	return (FCT_FAILURE);
}

fct_status_t
qlt_send_els(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	uint8_t *req;
	fct_els_t *els;
	qlt_cmd_t *qcmd;
	stmf_data_buf_t *buf;
	qlt_dmem_bctl_t *bctl;
	uint32_t sz, minsz;
	uint16_t qi;

	qi = 0;

	els = (fct_els_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->flags = QLT_CMD_TYPE_SOLICITED;
	qcmd->param.resp_offset = (uint16_t)((els->els_req_size + 7) & ~7);
	sz = minsz = qcmd->param.resp_offset + els->els_resp_size;
	buf = qlt_i_dmem_alloc(qlt, sz, &minsz, 0);
	if (buf == NULL) {
		return (FCT_BUSY);
	}
	bctl = (qlt_dmem_bctl_t *)buf->db_port_private;

	qcmd->dbuf = buf;
	bcopy(els->els_req_payload, buf->db_sglist[0].seg_addr,
	    els->els_req_size);
	qlt_dmem_dma_sync(buf, DDI_DMA_SYNC_FORDEV);

	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		EL(qlt, "req = NULL, %xh %xh %p %xh\n", cmd->cmd_oxid,
		    cmd->cmd_rportid, cmd, qcmd->fw_xchg_addr);
		qlt_dmem_free(NULL, buf);
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return (FCT_BUSY);
	}
	bzero(req, IOCB_SIZE);
	req[0] = 0x53; req[1] = 1;
	QMEM_WR32(qlt, (&req[4]), cmd->cmd_handle);
	QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp->rp_handle);
	QMEM_WR16(qlt, (&req[0xC]), 1);
	QMEM_WR16(qlt, (&req[0xE]), 0x1000);
	QMEM_WR16(qlt, (&req[0x14]), 1);
	req[0x16] = els->els_req_payload[0];
	if (qlt->cur_topology == PORT_TOPOLOGY_PT_TO_PT) {
		req[0x1b] = (uint8_t)((cmd->cmd_lportid >> 16) & 0xff);
		req[0x1c] = (uint8_t)(cmd->cmd_lportid & 0xff);
		req[0x1d] = (uint8_t)((cmd->cmd_lportid >> 8) & 0xff);
	}
	QMEM_WR32(qlt, (&req[0x18]), cmd->cmd_rp->rp_id);
	QMEM_WR32(qlt, (&req[0x20]), els->els_resp_size);
	QMEM_WR32(qlt, (&req[0x24]), els->els_req_size);
	QMEM_WR64(qlt, (&req[0x28]), bctl->bctl_dev_addr);
	QMEM_WR32(qlt, (&req[0x30]), els->els_req_size);
	QMEM_WR64(qlt, (&req[0x34]), (bctl->bctl_dev_addr +
	    qcmd->param.resp_offset));
	QMEM_WR32(qlt, (&req[0x3C]), els->els_resp_size);

	EL(qlt, "ELS opcode %xh to %xh\n",
	    req[0x16], cmd->cmd_rp->rp_id);

	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_send_ct(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	uint8_t *req;
	fct_sol_ct_t *ct;
	qlt_cmd_t *qcmd;
	stmf_data_buf_t *buf;
	qlt_dmem_bctl_t *bctl;
	uint32_t sz, minsz;
	uint16_t qi;

	qi =  0;

	ct = (fct_sol_ct_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->flags = QLT_CMD_TYPE_SOLICITED;
	qcmd->param.resp_offset = (uint16_t)((ct->ct_req_size + 7) & ~7);
	sz = minsz = qcmd->param.resp_offset + ct->ct_resp_size;
	buf = qlt_i_dmem_alloc(qlt, sz, &minsz, 0);
	if (buf == NULL) {
		return (FCT_BUSY);
	}
	bctl = (qlt_dmem_bctl_t *)buf->db_port_private;

	qcmd->dbuf = buf;
	bcopy(ct->ct_req_payload, buf->db_sglist[0].seg_addr,
	    ct->ct_req_size);
	qlt_dmem_dma_sync(buf, DDI_DMA_SYNC_FORDEV);

	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		EL(qlt, "req = NULL, %xh %xh %p %xh\n", cmd->cmd_oxid,
		    cmd->cmd_rportid, cmd, qcmd->fw_xchg_addr);
		qlt_dmem_free(NULL, buf);
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return (FCT_BUSY);
	}
	bzero(req, IOCB_SIZE);
	req[0] = 0x29; req[1] = 1;
	QMEM_WR32(qlt, (&req[4]), cmd->cmd_handle);
	QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp->rp_handle);
	QMEM_WR16(qlt, (&req[0xC]), 1);
	QMEM_WR16(qlt, (&req[0x10]), 0x20);	/* > (2 * RA_TOV) */
	QMEM_WR16(qlt, (&req[0x14]), 1);

	QMEM_WR32(qlt, (&req[0x20]), ct->ct_resp_size);
	QMEM_WR32(qlt, (&req[0x24]), ct->ct_req_size);

	QMEM_WR64(qlt, (&req[0x28]), bctl->bctl_dev_addr); /* COMMAND DSD */
	QMEM_WR32(qlt, (&req[0x30]), ct->ct_req_size);
	QMEM_WR64(qlt, (&req[0x34]), (bctl->bctl_dev_addr +
	    qcmd->param.resp_offset));		/* RESPONSE DSD */
	QMEM_WR32(qlt, (&req[0x3C]), ct->ct_resp_size);

	EL(qlt, "%p cmd_hdl=%xh %xh %xh\n",
	    cmd, cmd->cmd_handle, ct->ct_req_size, ct->ct_resp_size);

	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);

	return (FCT_SUCCESS);
}

/*ARGSUSED*/
caddr_t
qlt_str_ptr(qlt_state_t *qlt, caddr_t bp, uint32_t *len)
{
	caddr_t sp;
	uint32_t i = 0;

	sp = bp;
	while (*sp++ != 0) i++;
	if (i > *len || !(*len -= i)) {
		EL(qlt, "full buffer\n");
		return (NULL);
	}
	return (bp += i);
}

static fct_status_t
qlt_27xx_fw_dump(fct_local_port_t *port, stmf_state_change_info_t *ssci)
{
	qlt_state_t *qlt = (qlt_state_t *)port->port_fca_private;
	qlt_dmp_template_t *template_buff;
	uint32_t tsize, dsize, len;
	uint32_t cnt, *dp, *bp;
	uint8_t *fw;
	caddr_t	sp;

	EL(qlt, "enter...\n");

	mutex_enter(&qlt->qlt_ioctl_lock);
	/*
	 * To make sure that there's no outstanding dumping task
	 */
	if (qlt->qlt_ioctl_flags & QLT_FWDUMP_INPROGRESS) {
		mutex_exit(&qlt->qlt_ioctl_lock);
		EL(qlt, "qlt_ioctl_flags=%xh, inprogress\n",
		    qlt->qlt_ioctl_flags);
		return (FCT_FAILURE);
	}

	/*
	 * To make sure not to overwrite existing dump
	 */
	if ((qlt->qlt_ioctl_flags & QLT_FWDUMP_ISVALID) &&
	    !(qlt->qlt_ioctl_flags & QLT_FWDUMP_TRIGGERED_BY_USER) &&
	    !(qlt->qlt_ioctl_flags & QLT_FWDUMP_FETCHED_BY_USER)) {
		/*
		 * If we have already one dump, but it's not triggered by user
		 * and the user hasn't fetched it, we shouldn't dump again.
		 * But if qlt force a fw dump, then we need to overwrite the
		 * previous one anyway.
		 */
		mutex_exit(&qlt->qlt_ioctl_lock);
		EL(qlt, "qlt_ioctl_flags=%xh, already done\n",
		    qlt->qlt_ioctl_flags);
		cmn_err(CE_NOTE, "qlt(%d): Skipping firmware dump as there "
		    "is one already outstanding.", qlt->instance);
		return (FCT_FAILURE);
	}

	if (qlt->dmp_template_addr == NULL) {
		mutex_exit(&qlt->qlt_ioctl_lock);
		EL(qlt, "dmp_template_addr is NULL, can't "
		    "perform firmware dump\n");
		cmn_err(CE_WARN, "!qlt(%d) dmp_template_addr is NULL, can't "
		    "perform firmware dump", qlt->instance);
		return (FCT_FAILURE);
	}

	qlt->qlt_ioctl_flags |= QLT_FWDUMP_INPROGRESS;
	if (ssci != NULL && (ssci->st_rflags & STMF_RFLAG_USER_REQUEST)) {
		qlt->qlt_ioctl_flags |= QLT_FWDUMP_TRIGGERED_BY_USER;
	} else {
		qlt->qlt_ioctl_flags &= ~QLT_FWDUMP_TRIGGERED_BY_USER;
	}
	mutex_exit(&qlt->qlt_ioctl_lock);

	template_buff = (qlt_dmp_template_t *)qlt->dmp_template_addr;
	tsize = template_buff->hdr.size_of_template;

	if (qlt->fw_bin_dump_size == 0) {
		qlt->fw_bin_dump_buf = kmem_zalloc(tsize, KM_NOSLEEP);
		if (qlt->fw_bin_dump_buf == NULL) {
			cmn_err(CE_WARN, "!qlt(%d) cannot alloc bin dump buf",
			    qlt->instance);
			return (FCT_FAILURE);
		}
		cnt = (uint32_t)(tsize / sizeof (uint32_t));
		dp = (uint32_t *)qlt->fw_bin_dump_buf;
		bp = (uint32_t *)&template_buff->hdr;
		while (cnt--) {
			*dp++ = ddi_get32(qlt->dmp_template_acc_handle, bp++);
		}
		qlt->fw_bin_dump_size = qlt_27xx_dmp_parse_template(qlt,
		    (qlt_dt_hdr_t *)qlt->fw_bin_dump_buf, NULL, 0);
		kmem_free(qlt->fw_bin_dump_buf, tsize);
		qlt->fw_bin_dump_buf = NULL;

		if (qlt->fw_bin_dump_size == 0) {
			return (FCT_FAILURE);
		}

		/*
		 * Determine ascii dump file size
		 * 2 ascii bytes per binary byte + a space and
		 * a newline every 16 binary bytes
		 */
		qlt->fw_ascii_dump_size = qlt->fw_bin_dump_size << 1;
		qlt->fw_ascii_dump_size += qlt->fw_bin_dump_size;
		qlt->fw_ascii_dump_size += qlt->fw_bin_dump_size / 16 + 1;

		EL(qlt, "fw_bin_dump_size=%xh, "
		    "fw_acsii_dump_size=%xh\n", qlt->fw_bin_dump_size,
		    qlt->fw_ascii_dump_size);
	}

	if (qlt->fw_bin_dump_buf != NULL) {
		/* overwrite the previous fw dump by qlt forced fw dump */
		bzero((void *) qlt->fw_bin_dump_buf, qlt->fw_bin_dump_size);
	} else {
		qlt->fw_bin_dump_buf = kmem_zalloc(qlt->fw_bin_dump_size,
		    KM_NOSLEEP);
		if (qlt->fw_bin_dump_buf == NULL) {
			qlt->fw_bin_dump_size = 0;
			EL(qlt, "done, failed alloc bin dump buf\n");
			return (FCT_FAILURE);
		}
	}

	if ((qlt->fw_dump_size != 0) &&
	    (qlt->fw_dump_size != qlt->fw_ascii_dump_size)) {
		if (qlt->qlt_fwdump_buf != NULL) {
			/* Release previously allocated buffer */
			kmem_free(qlt->qlt_fwdump_buf, qlt->fw_dump_size);
			qlt->qlt_fwdump_buf = NULL;
		}
	}

	if (qlt->qlt_fwdump_buf == NULL) {
		qlt->qlt_fwdump_buf = kmem_zalloc(qlt->fw_ascii_dump_size,
		    KM_NOSLEEP);
		if (qlt->qlt_fwdump_buf == NULL) {
			EL(qlt, "done, failed alloc ascii fw dump buf\n");
			return (FCT_FAILURE);
		}
		qlt->fw_dump_size = qlt->fw_ascii_dump_size;
	}

	/* Disable ISP interrupts. */
	REG_WR32(qlt, 0xc, 0);

	cnt = (uint32_t)(tsize / sizeof (uint32_t));
	dp = (uint32_t *)qlt->fw_bin_dump_buf;
	bp = (uint32_t *)&template_buff->hdr;
	while (cnt--) {
		*dp++ = ddi_get32(qlt->dmp_template_acc_handle, bp++);
	}

	(void) qlt_27xx_dmp_parse_template(qlt,
	    (qlt_dt_hdr_t *)qlt->fw_bin_dump_buf,
	    (uint8_t *)dp, qlt->fw_bin_dump_size);

#ifdef _BIG_ENDIAN
	cnt = (uint32_t)(tsize / sizeof (uint32_t));
	dp = (uint32_t *)qlt->fw_bin_dump_buf;
	while (cnt--) {
		qlt_chg_endian((uint8_t *)dp, 4);
		dp++;
	}
#endif

	/*
	 * Build ascii dump
	 */
	len = qlt->fw_ascii_dump_size;
	dsize = qlt->fw_bin_dump_size;
	fw = (uint8_t *)qlt->fw_bin_dump_buf;
	sp = qlt->qlt_fwdump_buf;

	EL(qlt, "fw_dump_buffer=%ph, fw=%ph, fw_ascii_dump_size=%xh, "
	    "dsize=%xh\n", (void *)qlt->qlt_fwdump_buf, (void *)fw,
	    len, dsize);

	/*
	 * 2 ascii bytes per binary byte + a space and
	 * a newline every 16 binary bytes
	 */
	cnt = 0;
	while (cnt < dsize) {
		(void) snprintf(sp, len, "%02x ", *fw++);
		if ((sp = qlt_str_ptr(qlt, sp, &len)) == NULL) {
			break;
		}
		if (++cnt % 16 == 0) {
			(void) snprintf(sp, len, "\n");
			if ((sp = qlt_str_ptr(qlt, sp, &len)) == NULL) {
				break;
			}
		}
	}
	if (cnt % 16 != 0) {
		(void) snprintf(sp, len, "\n");
		sp = qlt_str_ptr(qlt, sp, &len);
	}

	mutex_enter(&qlt->qlt_ioctl_lock);
	qlt->qlt_ioctl_flags &=
	    ~(QLT_FWDUMP_INPROGRESS | QLT_FWDUMP_FETCHED_BY_USER);
	qlt->qlt_ioctl_flags |= QLT_FWDUMP_ISVALID;
	mutex_exit(&qlt->qlt_ioctl_lock);

	EL(qlt, "done...\n");
	return (FCT_SUCCESS);
}

/*
 * All QLT_FIRMWARE_* will mainly be handled in this function
 * It can not be called in interrupt context
 *
 * FWDUMP's purpose is to serve ioctl, so we will use qlt_ioctl_flags
 * and qlt_ioctl_lock
 */
static fct_status_t
qlt_firmware_dump(fct_local_port_t *port, stmf_state_change_info_t *ssci)
{
	qlt_state_t	*qlt = (qlt_state_t *)port->port_fca_private;
	int		i;
	int		retries, n;
	uint_t		size_left;
	char		c = ' ';
	uint32_t	addr, endaddr, words_to_read;
	caddr_t		buf;
	fct_status_t	ret;

	if (qlt->qlt_27xx_chip) {
		return (qlt_27xx_fw_dump(port, ssci));
	}
	mutex_enter(&qlt->qlt_ioctl_lock);
	/*
	 * To make sure that there's no outstanding dumping task
	 */
	if (qlt->qlt_ioctl_flags & QLT_FWDUMP_INPROGRESS) {
		mutex_exit(&qlt->qlt_ioctl_lock);
		EL(qlt, "qlt_ioctl_flags=%xh, inprogress\n",
		    qlt->qlt_ioctl_flags);
		return (FCT_FAILURE);
	}

	/*
	 * To make sure not to overwrite existing dump
	 */
	if ((qlt->qlt_ioctl_flags & QLT_FWDUMP_ISVALID) &&
	    !(qlt->qlt_ioctl_flags & QLT_FWDUMP_TRIGGERED_BY_USER) &&
	    !(qlt->qlt_ioctl_flags & QLT_FWDUMP_FETCHED_BY_USER)) {
		/*
		 * If we have already one dump, but it's not triggered by user
		 * and the user hasn't fetched it, we shouldn't dump again.
		 */
		mutex_exit(&qlt->qlt_ioctl_lock);
		EL(qlt, "qlt_ioctl_flags=%xh, already done\n",
		    qlt->qlt_ioctl_flags);
		cmn_err(CE_NOTE, "qlt(%d): Skipping firmware dump as there "
		    "is one already outstanding.", qlt->instance);
		return (FCT_FAILURE);
	}
	qlt->qlt_ioctl_flags |= QLT_FWDUMP_INPROGRESS;
	if ((ssci != NULL) && (ssci->st_rflags & STMF_RFLAG_USER_REQUEST)) {
		qlt->qlt_ioctl_flags |= QLT_FWDUMP_TRIGGERED_BY_USER;
	} else {
		qlt->qlt_ioctl_flags &= ~QLT_FWDUMP_TRIGGERED_BY_USER;
	}
	mutex_exit(&qlt->qlt_ioctl_lock);

	size_left = QLT_FWDUMP_BUFSIZE;
	if (qlt->qlt_mq_enabled && qlt->qlt_queue_cnt >= 8) {
		size_left += 512 * 1024;
	}
	qlt->fw_dump_size = size_left;
	if (!qlt->qlt_fwdump_buf) {
		ASSERT(!(qlt->qlt_ioctl_flags & QLT_FWDUMP_ISVALID));
		/*
		 * It's the only place that we allocate buf for dumping. After
		 * it's allocated, we will use it until the port is detached.
		 */
		qlt->qlt_fwdump_buf = kmem_zalloc(size_left, KM_NOSLEEP);
		if (qlt->qlt_fwdump_buf == NULL) {
			EL(qlt, "cannot alloc fwdump buffer\n");
			cmn_err(CE_WARN, "!qlt(%d): cannot alloc fwdump buf",
			    qlt->instance);
			return (FCT_FAILURE);
		}
	}

	EL(qlt, "starting firmware dump...\n");
	cmn_err(CE_WARN, "!qlt(%d) starting firmware dump...",
	    qlt->instance);

	/*
	 * Start to dump firmware
	 */
	buf = (caddr_t)qlt->qlt_fwdump_buf;

	/*
	 * Print the ISP firmware revision number and attributes information
	 * Read the RISC to Host Status register
	 */
	n = (int)snprintf(buf, size_left, "ISP FW Version %d.%02d.%02d "
	    "Attributes %04x\n\nR2H Status register\n%08x",
	    qlt->fw_major, qlt->fw_minor,
	    qlt->fw_subminor, qlt->fw_attr, REG_RD32(qlt, REG_RISC_STATUS));
	buf += n; size_left -= n;

	/*
	 * Before pausing the RISC, make sure no mailbox can execute
	 */
	mutex_enter(&qlt->mbox_lock);
	if ((qlt->mbox_io_state != MBOX_STATE_UNKNOWN) &&
	    (qlt->qlt_intr_enabled)) {
		/*
		 * Wait to grab the mailboxes
		 */
		for (retries = 0; (qlt->mbox_io_state != MBOX_STATE_READY) &&
		    (qlt->mbox_io_state != MBOX_STATE_UNKNOWN); retries++) {
			(void) cv_timedwait(&qlt->mbox_cv, &qlt->mbox_lock,
			    ddi_get_lbolt() + drv_usectohz(1000000));
			if (retries > 5) {
				mutex_exit(&qlt->mbox_lock);
				EL(qlt, "can't drain out mailbox commands\n");
				goto dump_fail;
			}
		}
		qlt->mbox_io_state = MBOX_STATE_UNKNOWN;
		cv_broadcast(&qlt->mbox_cv);
	}
	mutex_exit(&qlt->mbox_lock);

	/*
	 * Pause the RISC processor
	 */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(SET_RISC_PAUSE));

	/*
	 * Wait for the RISC processor to pause
	 */
	for (i = 0; i < 200; i++) {
		if (REG_RD32(qlt, REG_RISC_STATUS) & 0x100) {
			break;
		}
		drv_usecwait(1000);
	}
	if (i == 200) {
		EL(qlt, "can't pause\n");
		return (FCT_FAILURE);
	}

	if (qlt->qlt_83xx_chip) {
		/* Disable ECC checks in FB registers */
		REG_WR32(qlt, 0x54, 0x6000);
		REG_WR32(qlt, 0xC0, 0); /* 6000h */
		REG_WR32(qlt, 0xCC, 0); /* 6003h */
		REG_WR32(qlt, 0x54, 0x6010);
		REG_WR32(qlt, 0xD4, 0); /* 6015h */

		/* disable ECC detection in PCR whilst dumping */
		REG_WR32(qlt, 0x54, 0xF70);
		REG_WR32(qlt, 0xF0, 0x60000000);
	}

	if ((!qlt->qlt_25xx_chip) && (!qlt->qlt_81xx_chip) &&
	    (!qlt->qlt_83xx_chip) && (!qlt->qlt_27xx_chip)) {
		goto over_25xx_specific_dump;
	}
	n = (int)snprintf(buf, size_left, "\n\nHostRisc registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7000);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7010);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	if (qlt->qlt_83xx_chip) {
		REG_WR32(qlt, 0x54, 0x7040);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	REG_WR32(qlt, 0x54, 0x7C00);

	n = (int)snprintf(buf, size_left, "\nPCIe registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0xC0, 0x1);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc4, 3, size_left);
	buf += n; size_left -= n;
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 1, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0xC0, 0x0);

	/* don't need to do this for 83xx */
	if ((!qlt->qlt_83xx_chip) && (qlt->qlt_mq_enabled)) {
		uint16_t qi;

		for (qi = 0; qi < qlt->qlt_queue_cnt; qi++) {

			n = (int)snprintf(buf, size_left,
			    "\n\nQueue Pointers #%x\n", qi);
			buf += n; size_left -= n;

			n = (int)snprintf(buf, size_left, "%08x ",
			    MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_REQ_IN));
			buf += n; size_left -= n;
			n = (int)snprintf(buf, size_left, "%08x ",
			    MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_REQ_OUT));
			buf += n; size_left -= n;
			n = (int)snprintf(buf, size_left, "%08x ",
			    MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_IN));
			buf += n; size_left -= n;
			n = (int)snprintf(buf, size_left, "%08x",
			    MQBAR_RD32(qlt,
			    (qi * MQBAR_REG_OFFSET) + MQBAR_RESP_OUT));
			buf += n; size_left -= n;
		}
	}

over_25xx_specific_dump:;
	n = (int)snprintf(buf, size_left, "\n\nHost Interface registers\n");
	buf += n; size_left -= n;
	/*
	 * Capture data from 32 registers
	 */
	n = qlt_fwdump_dump_regs(qlt, buf, 0, 32, size_left);
	buf += n; size_left -= n;

	/*
	 * Disable interrupts
	 */
	REG_WR32(qlt, 0xc, 0);
	EL(qlt, "Disable interrupt\n");

	/*
	 * Shadow registers
	 */
	n = (int)snprintf(buf, size_left, "\nShadow registers\n");
	buf += n; size_left -= n;

	REG_WR32(qlt, 0x54, 0xF70);
	addr = 0xb0000000;
	for (i = 0; i < 0xb; i++) {
		if ((!qlt->qlt_25xx_chip) &&
		    (!qlt->qlt_81xx_chip) &&
		    (!qlt->qlt_83xx_chip) &&
		    (i >= 7)) {
			break;
		}
		if (i && ((i & 7) == 0)) {
			n = (int)snprintf(buf, size_left, "\n");
			buf += n; size_left -= n;
		}
		REG_WR32(qlt, 0xF0, addr);
		n = (int)snprintf(buf, size_left, "%08x ", REG_RD32(qlt, 0xFC));
		buf += n; size_left -= n;
		addr += 0x100000;
	}

	if ((qlt->qlt_25xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_83xx_chip)) {
		REG_WR32(qlt, 0x54, 0x10);
		n = (int)snprintf(buf, size_left,
		    "\n\nRISC IO register\n%08x", REG_RD32(qlt, 0xC0));
		buf += n; size_left -= n;
	}

	/*
	 * Mailbox registers
	 */
	n = (int)snprintf(buf, size_left, "\n\nMailbox registers\n");
	buf += n; size_left -= n;
	for (i = 0; i < 32; i += 2) {
		if ((i + 2) & 15) {
			c = ' ';
		} else {
			c = '\n';
		}
		n = (int)snprintf(buf, size_left, "%04x %04x%c",
		    REG_RD16(qlt, 0x80 + (i << 1)),
		    REG_RD16(qlt, 0x80 + ((i+1) << 1)), c);
		buf += n; size_left -= n;
	}

	/*
	 * Transfer sequence registers
	 */
	n = (int)snprintf(buf, size_left, "\nXSEQ GP registers\n");
	buf += n; size_left -= n;

	if (qlt->qlt_83xx_chip) {
		REG_WR32(qlt, 0x54, 0xBE00);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBE10);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBE20);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBE30);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBE40);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBE50);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBE60);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBE70);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	REG_WR32(qlt, 0x54, 0xBF00);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBF10);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBF20);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBF30);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBF40);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBF50);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBF60);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBF70);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nXSEQ-0 registers\n");
	buf += n; size_left -= n;
	if ((qlt->qlt_25xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_83xx_chip)) {
		REG_WR32(qlt, 0x54, 0xBFC0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBFD0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	REG_WR32(qlt, 0x54, 0xBFE0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nXSEQ-1 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBFF0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	if (qlt->qlt_83xx_chip) {
		n = (int)snprintf(buf, size_left, "\nXSEQ-2 registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xBEF0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	/*
	 * Receive sequence registers
	 */
	n = (int)snprintf(buf, size_left, "\nRSEQ GP registers\n");
	buf += n; size_left -= n;
	if (qlt->qlt_83xx_chip) {
		REG_WR32(qlt, 0x54, 0xFE00);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xFE10);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xFE20);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xFE30);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xFE40);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xFE50);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xFE60);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xFE70);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	REG_WR32(qlt, 0x54, 0xFF00);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFF10);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFF20);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFF30);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFF40);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFF50);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFF60);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFF70);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nRSEQ-0 registers\n");
	buf += n; size_left -= n;
	if ((qlt->qlt_25xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_83xx_chip)) {
		REG_WR32(qlt, 0x54, 0xFFC0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	REG_WR32(qlt, 0x54, 0xFFD0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nRSEQ-1 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFFE0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nRSEQ-2 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFFF0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	if (qlt->qlt_83xx_chip) {
		n = (int)snprintf(buf, size_left, "\nRSEQ-3 registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xFEF0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	if ((!qlt->qlt_25xx_chip) && (!qlt->qlt_81xx_chip) &&
	    (!qlt->qlt_83xx_chip))
		goto over_aseq_regs;

	/*
	 * Auxiliary sequencer registers
	 */
	n = (int)snprintf(buf, size_left, "\nASEQ GP registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB000);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB010);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB020);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB030);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB040);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB050);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB060);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB070);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	if (qlt->qlt_83xx_chip) {
		REG_WR32(qlt, 0x54, 0xB100);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xB110);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xB120);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xB130);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xB140);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xB150);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xB160);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xB170);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	n = (int)snprintf(buf, size_left, "\nASEQ-0 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB0C0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB0D0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nASEQ-1 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB0E0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nASEQ-2 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB0F0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	if (qlt->qlt_83xx_chip) {
		n = (int)snprintf(buf, size_left, "\nASEQ-3 registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0xB1F0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

over_aseq_regs:;

	/*
	 * Command DMA registers
	 */
	n = (int)snprintf(buf, size_left, "\nCommand DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7100);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	if (qlt->qlt_83xx_chip) {
		REG_WR32(qlt, 0x54, 0x7120);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x7130);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x71F0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	/*
	 * Queues
	 */
	n = (int)snprintf(buf, size_left,
	    "\nRequest0 Queue DMA Channel registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7200);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 8, size_left);
	buf += n; size_left -= n;
	n = qlt_fwdump_dump_regs(qlt, buf, 0xe4, 7, size_left);
	buf += n; size_left -= n;

	n = (int)snprintf(buf, size_left,
	    "\n\nResponse0 Queue DMA Channel registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7300);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 8, size_left);
	buf += n; size_left -= n;
	n = qlt_fwdump_dump_regs(qlt, buf, 0xe4, 7, size_left);
	buf += n; size_left -= n;

	n = (int)snprintf(buf, size_left,
	    "\n\nRequest1 Queue DMA Channel registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7400);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 8, size_left);
	buf += n; size_left -= n;
	n = qlt_fwdump_dump_regs(qlt, buf, 0xe4, 7, size_left);
	buf += n; size_left -= n;

	/*
	 * Transmit DMA registers
	 */
	n = (int)snprintf(buf, size_left, "\n\nXMT0 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7600);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7610);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nXMT1 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7620);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7630);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nXMT2 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7640);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7650);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nXMT3 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7660);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7670);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nXMT4 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7680);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7690);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left, "\nXMT Data DMA Common registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x76A0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	/*
	 * Receive DMA registers
	 */
	n = (int)snprintf(buf, size_left,
	    "\nRCV Thread 0 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7700);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7710);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = (int)snprintf(buf, size_left,
	    "\nRCV Thread 1 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7720);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7730);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	/*
	 * RISC registers
	 */
	n = (int)snprintf(buf, size_left, "\nRISC GP registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x0F00);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x0F10);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x0F20);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x0F30);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x0F40);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x0F50);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x0F60);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x0F70);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	/*
	 * Local memory controller registers
	 */
	n = (int)snprintf(buf, size_left, "\nLMC registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x3000);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x3010);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x3020);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x3030);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x3040);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x3050);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x3060);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	if ((qlt->qlt_25xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_83xx_chip)) {
		REG_WR32(qlt, 0x54, 0x3070);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	/*
	 * Fibre protocol module registers
	 */
	n = (int)snprintf(buf, size_left, "\nFPM hardware registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4000);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4010);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4020);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4030);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4040);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4050);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4060);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4070);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4080);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x4090);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x40A0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x40B0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_81xx_chip)) {
		REG_WR32(qlt, 0x54, 0x40C0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x40D0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	if (qlt->qlt_83xx_chip) {
		REG_WR32(qlt, 0x54, 0x40E0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x40F0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;

		n = (int)snprintf(buf, size_left, "\nRQ0 Array registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C00);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C10);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C20);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C30);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C40);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C50);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C60);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C70);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C80);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5C90);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5CA0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5CB0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5CC0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5CD0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5CE0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5CF0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;

		n = (int)snprintf(buf, size_left, "\nRQ1 Array registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D00);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D10);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D20);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D30);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D40);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D50);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D60);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D70);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D80);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5D90);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5DA0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5DB0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5DC0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5DD0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5DE0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5DF0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;

		n = (int)snprintf(buf, size_left, "\nRP0 Array registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E00);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E10);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E20);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E30);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E40);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E50);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E60);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E70);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E80);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5E90);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5EA0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5EB0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5EC0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5ED0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5EE0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5EF0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;

		n = (int)snprintf(buf, size_left, "\nRP1 Array registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F00);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F10);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F20);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F30);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F40);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F50);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F60);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F70);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F80);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5F90);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5FA0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5FB0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5FC0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5FD0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5FE0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x5FF0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;

		n = (int)snprintf(buf,
		    size_left, "\nQueue Control Registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x7800);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	/*
	 * Fibre buffer registers
	 */
	n = (int)snprintf(buf, size_left, "\nFB hardware registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6000);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6010);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6020);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6030);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6040);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	if (qlt->qlt_83xx_chip) {
		REG_WR32(qlt, 0x54, 0x6060);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x6070);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	REG_WR32(qlt, 0x54, 0x6100);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6130);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6150);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6170);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x6190);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x61B0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	if ((qlt->qlt_83xx_chip) || (qlt->qlt_81xx_chip)) {
		REG_WR32(qlt, 0x54, 0x61C0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	if (qlt->qlt_83xx_chip) {
		REG_WR32(qlt, 0x54, 0x6530);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x6540);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x6550);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x6560);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x6570);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x6580);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x6590);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x65A0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x65B0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x65C0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x65D0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x65E0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}
	if ((qlt->qlt_25xx_chip) || (qlt->qlt_81xx_chip) ||
	    (qlt->qlt_83xx_chip)) {
		REG_WR32(qlt, 0x54, 0x6F00);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	if (qlt->qlt_83xx_chip) {
		n = (int)snprintf(buf, size_left, "\nAT0 Array registers\n");
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x7080);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x7090);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x70A0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x70B0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x70C0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x70D0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x70E0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
		REG_WR32(qlt, 0x54, 0x70F0);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	EL(qlt, "reset chip\n");
	qlt->intr_sneak_counter = 10;
	mutex_enter(&qlt->intr_lock);
	if (qlt->qlt_mq_enabled) {
		for (i = 1; i < qlt->qlt_queue_cnt; i++) {
			mutex_enter(&qlt->mq_resp[i].mq_lock);
		}
	}
	(void) qlt_reset_chip(qlt);
	drv_usecwait(20);
	qlt->intr_sneak_counter = 0;
	if (qlt->qlt_mq_enabled) {
		for (i = 1; i < qlt->qlt_queue_cnt; i++) {
			mutex_exit(&qlt->mq_resp[i].mq_lock);
		}
	}
	mutex_exit(&qlt->intr_lock);
	EL(qlt, "reset chip, done\n");

	/*
	 * Memory
	 */
	n = (int)snprintf(buf, size_left, "\nCode RAM\n");
	buf += n; size_left -= n;

	addr = 0x20000;
	endaddr = (qlt->qlt_83xx_chip) ? 0x22400 : 0x22000;
	words_to_read = 0;
	while (addr < endaddr) {
		words_to_read = MBOX_DMA_MEM_SIZE >> 2;
		if ((words_to_read + addr) > endaddr) {
			words_to_read = endaddr - addr;
		}
		if ((ret = qlt_read_risc_ram(qlt, addr, words_to_read)) !=
		    QLT_SUCCESS) {
			EL(qlt, "Error reading risc ram - CODE RAM status="
			    "%llxh\n", ret);
			goto dump_fail;
		}

		n = qlt_dump_risc_ram(qlt, addr, words_to_read, buf, size_left);
		buf += n; size_left -= n;

		if (size_left < 100000) {
			EL(qlt, "run out of space - CODE RAM size_left=%d\n",
			    size_left);
			goto dump_ok;
		}
		addr += words_to_read;
	}

	n = (int)snprintf(buf, size_left, "\nExternal Memory\n");
	buf += n; size_left -= n;

	addr = 0x100000;
	endaddr = (((uint32_t)(qlt->fw_endaddrhi)) << 16) | qlt->fw_endaddrlo;
	endaddr++;
	if (endaddr & 7) {
		endaddr = (endaddr + 7) & 0xFFFFFFF8;
	}

	words_to_read = 0;
	while (addr < endaddr) {
		words_to_read = MBOX_DMA_MEM_SIZE >> 2;
		if ((words_to_read + addr) > endaddr) {
			words_to_read = endaddr - addr;
		}
		if ((ret = qlt_read_risc_ram(qlt, addr, words_to_read)) !=
		    QLT_SUCCESS) {
			EL(qlt, "Error reading risc ram - EXT RAM status="
			    "%llxh\n", ret);
			goto dump_fail;
		}
		n = qlt_dump_risc_ram(qlt, addr, words_to_read, buf, size_left);
		buf += n; size_left -= n;
		if (size_left < 100000) {
			EL(qlt, "run out of space - EXT RAM\n");
			goto dump_ok;
		}
		addr += words_to_read;
	}

	/*
	 * Label the end tag
	 */
	n = (int)snprintf(buf, size_left, "[<==END] ISP Debug Dump\n");
	buf += n; size_left -= n;

	/*
	 * Queue dumping
	 */
	n = (int)snprintf(buf, size_left, "\nRequest Queue\n");
	buf += n; size_left -= n;

	if (qlt->qlt_mq_enabled) {
		for (i = 0; i < qlt->qlt_queue_cnt; i++) {
			if (qlt->mq_req[i].queue_mem_mq_base_addr) {
				n = (int)snprintf(buf, size_left,
				    "\nQueue %d:\n", i);
				buf += n; size_left -= n;
				n = qlt_dump_queue(qlt,
				    qlt->mq_req[i].queue_mem_mq_base_addr,
				    REQUEST_QUEUE_MQ_ENTRIES,
				    buf, size_left);
				buf += n; size_left -= n;
			}
		}
	} else {
		n = (int)snprintf(buf, size_left, "\nQueue 0:\n");
		buf += n; size_left -= n;
		n = qlt_dump_queue(qlt,
		    qlt->queue_mem_ptr + REQUEST_QUEUE_OFFSET,
		    REQUEST_QUEUE_ENTRIES, buf, size_left);
		buf += n; size_left -= n;
	}

	if (!qlt->qlt_83xx_chip) {
		n = (int)snprintf(buf, size_left, "\nPriority Queue\n");
		buf += n; size_left -= n;
		n = qlt_dump_queue(qlt,
		    qlt->queue_mem_ptr + PRIORITY_QUEUE_OFFSET,
		    PRIORITY_QUEUE_ENTRIES, buf, size_left);
		buf += n; size_left -= n;
	}

	n = (int)snprintf(buf, size_left, "\nResponse Queue\n");
	buf += n; size_left -= n;

	if (qlt->qlt_mq_enabled) {
		for (i = 0; i < qlt->qlt_queue_cnt; i++) {
			if (qlt->mq_resp[i].queue_mem_mq_base_addr) {
				n = (int)snprintf(buf, size_left,
				    "\nQueue %d:\n", i);
				buf += n; size_left -= n;
				n = qlt_dump_queue(qlt,
				    qlt->mq_resp[i].queue_mem_mq_base_addr,
				    RESPONSE_QUEUE_MQ_ENTRIES,
				    buf, size_left);
				buf += n; size_left -= n;
			}
		}
	} else {
		n = (int)snprintf(buf, size_left, "\nQueue 0:\n");
		buf += n; size_left -= n;
		n = qlt_dump_queue(qlt,
		    qlt->queue_mem_ptr + RESPONSE_QUEUE_OFFSET,
		    RESPONSE_QUEUE_ENTRIES, buf, size_left);
		buf += n; size_left -= n;
	}

	n = (int)snprintf(buf, size_left, "\nATIO Queue\nQueue 0:\n");
	buf += n; size_left -= n;
	n = qlt_dump_queue(qlt, qlt->queue_mem_ptr + ATIO_QUEUE_OFFSET,
	    ATIO_QUEUE_ENTRIES, buf, size_left);
	buf += n; size_left -= n;

	/*
	 * Label dump reason
	 */
	if (ssci != NULL) {
		n = (int)snprintf(buf, size_left,
		    "\nFirmware dump reason: %s-%s\n",
		    qlt->qlt_port_alias, ssci->st_additional_info);
	} else {
		n = (int)snprintf(buf, size_left,
		    "\nFirmware dump reason: %s-%s\n",
		    qlt->qlt_port_alias, "no additional infor");
	}
	buf += n; size_left -= n;

dump_ok:
	EL(qlt, "left-%d\n", size_left);
	mutex_enter(&qlt->qlt_ioctl_lock);
	qlt->qlt_ioctl_flags &=
	    ~(QLT_FWDUMP_INPROGRESS | QLT_FWDUMP_FETCHED_BY_USER);
	qlt->qlt_ioctl_flags |= QLT_FWDUMP_ISVALID;
	mutex_exit(&qlt->qlt_ioctl_lock);
	return (FCT_SUCCESS);

dump_fail:
	EL(qlt, "dump not done\n");
	mutex_enter(&qlt->qlt_ioctl_lock);
	qlt->qlt_ioctl_flags &= QLT_IOCTL_FLAG_MASK;
	mutex_exit(&qlt->qlt_ioctl_lock);
	return (FCT_FAILURE);
}

static int
qlt_fwdump_dump_regs(qlt_state_t *qlt, caddr_t buf, int startaddr, int count,
    uint_t size_left)
{
	int		i;
	int		n;
	char		c = ' ';

	for (i = 0, n = 0; i < count; i++) {
		if ((i + 1) & 7) {
			c = ' ';
		} else {
			c = '\n';
		}
		n = (int)(n + (int)snprintf(&buf[n], (uint_t)(size_left - n),
		    "%08x%c", REG_RD32(qlt, startaddr + (i << 2)), c));
	}
	return (n);
}

static int
qlt_dump_risc_ram(qlt_state_t *qlt, uint32_t addr, uint32_t words,
    caddr_t buf, uint_t size_left)
{
	int		i;
	int		n;
	char		c = ' ';
	uint32_t	*ptr;

	ptr = (uint32_t *)((caddr_t)qlt->queue_mem_ptr + MBOX_DMA_MEM_OFFSET);
	for (i = 0, n = 0; i < words; i++) {
		if ((i & 7) == 0) {
			n = (int)(n + (int)snprintf(&buf[n],
			    (uint_t)(size_left - n), "%08x: ", addr + i));
		}
		if ((i + 1) & 7) {
			c = ' ';
		} else {
			c = '\n';
		}
		n = (int)(n + (int)snprintf(&buf[n], (uint_t)(size_left - n),
		    "%08x%c", ptr[i], c));
	}
	return (n);
}

static int
qlt_dump_queue(qlt_state_t *qlt, caddr_t qadr, int entries, caddr_t buf,
    uint_t size_left)
{
	int		i;
	int		n;
	char		c = ' ';
	int		words;
	uint32_t	*ptr;
	uint32_t	w;

	words = entries * 16;
	ptr = (uint32_t *)qadr;
	for (i = 0, n = 0; i < words; i++) {
		if ((i & 7) == 0) {
			n = (int)(n + (int)snprintf(&buf[n],
			    (uint_t)(size_left - n), "%05x: ", i));
		}
		if ((i + 1) & 7) {
			c = ' ';
		} else {
			c = '\n';
		}
		w = QMEM_RD32(qlt, &ptr[i]);
		n = (int)(n + (int)snprintf(&buf[n], (size_left - n), "%08x%c",
		    w, c));
	}
	return (n);
}

/*
 * Only called by debug dump. Interrupts are disabled and mailboxes alongwith
 * mailbox ram is available.
 * Copy data from RISC RAM to system memory
 */
static fct_status_t
qlt_read_risc_ram(qlt_state_t *qlt, uint32_t addr, uint32_t words)
{
	uint64_t	da;
	fct_status_t	ret;

	REG_WR16(qlt, REG_MBOX(0), MBC_DUMP_RAM_EXTENDED);
	da = qlt->queue_mem_cookie.dmac_laddress;
	da += MBOX_DMA_MEM_OFFSET;

	/* System destination address */
	REG_WR16(qlt, REG_MBOX(3), LSW(LSD(da)));
	REG_WR16(qlt, REG_MBOX(2), MSW(LSD(da)));
	REG_WR16(qlt, REG_MBOX(7), LSW(MSD(da)));
	REG_WR16(qlt, REG_MBOX(6), MSW(MSD(da)));

	/* Length */
	REG_WR16(qlt, REG_MBOX(5), LSW(words));
	REG_WR16(qlt, REG_MBOX(4), MSW(words));

	/* RISC source address */
	REG_WR16(qlt, REG_MBOX(1), LSW(addr));
	REG_WR16(qlt, REG_MBOX(8), MSW(addr));

	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret == QLT_SUCCESS) {
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
		    MBOX_DMA_MEM_OFFSET, words << 2, DDI_DMA_SYNC_FORCPU);
	} else {
		EL(qlt, "qlt_raw_mailbox_command=0x0ch status=%llxh\n", ret);
	}
	return (ret);
}

static fct_status_t
qlt_mbx_mpi_ram(qlt_state_t *qlt, uint32_t addr, uint32_t words,
    uint16_t direction)
{
	uint64_t	da;
	fct_status_t	ret;

	REG_WR16(qlt, REG_MBOX(0), MBC_MPI_RAM);
	da = qlt->queue_mem_cookie.dmac_laddress;
	da += MBOX_DMA_MEM_OFFSET;

	/* System destination address */
	REG_WR16(qlt, REG_MBOX(3), LSW(LSD(da)));
	REG_WR16(qlt, REG_MBOX(2), MSW(LSD(da)));
	REG_WR16(qlt, REG_MBOX(7), LSW(MSD(da)));
	REG_WR16(qlt, REG_MBOX(6), MSW(MSD(da)));

	/* Length */
	REG_WR16(qlt, REG_MBOX(5), LSW(words));
	REG_WR16(qlt, REG_MBOX(4), MSW(words));

	/* RISC source address */
	REG_WR16(qlt, REG_MBOX(1), LSW(addr));
	REG_WR16(qlt, REG_MBOX(8), MSW(addr));

	REG_WR16(qlt, REG_MBOX(9), direction);
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret == QLT_SUCCESS) {
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
		    MBOX_DMA_MEM_OFFSET, words << 2, DDI_DMA_SYNC_FORCPU);
	} else {
		EL(qlt, "qlt_raw_mailbox_command=0x05h status=%llxh\n", ret);
	}
	return (ret);
}

static void
qlt_verify_fw(qlt_state_t *qlt)
{
	caddr_t req;
	uint16_t qi = 0;

	/* Just put it on the request queue */
	mutex_enter(&qlt->mq_req[qi].mq_lock);
	req = qlt_get_req_entries(qlt, 1, qi);
	if (req == NULL) {
		EL(qlt, "req = NULL\n");
		mutex_exit(&qlt->mq_req[qi].mq_lock);
		return;
	}

	bzero(req, IOCB_SIZE);

	req[0] = 0x1b;
	req[1] = 1;

	QMEM_WR32(qlt, (&req[4]), 0xffffffff);
	QMEM_WR16(qlt, (&req[0x8]), 1);    /*  options - don't update */
	QMEM_WR32(qlt, (&req[0x14]), 0x80010300);

	qlt_submit_req_entries(qlt, 1, qi);
	mutex_exit(&qlt->mq_req[qi].mq_lock);
}

static fct_status_t
qlt_mq_destroy(qlt_state_t *qlt)
{
	int idx;

	for (idx = 1; idx < qlt->qlt_queue_cnt; idx++) {
		(void) ddi_dma_unbind_handle(
		    qlt->mq_req[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_req[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_req[idx].queue_mem_mq_dma_handle);
		(void) ddi_dma_unbind_handle(
		    qlt->mq_resp[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_resp[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_resp[idx].queue_mem_mq_dma_handle);
	}
	return (QLT_SUCCESS);
}

static fct_status_t
qlt_mq_create(qlt_state_t *qlt, int idx)
{
	ddi_device_acc_attr_t dev_acc_attr;
	size_t discard;
	uint_t ncookies;

	dev_acc_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_acc_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	dev_acc_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/*
	 * MQ Request queue
	 */
	if (ddi_dma_alloc_handle(qlt->dip, &qlt_queue_dma_attr_mq_req1,
	    DDI_DMA_SLEEP, 0,
	    &qlt->mq_req[idx].queue_mem_mq_dma_handle) != DDI_SUCCESS) {
		return (QLT_FAILURE);
	}
	if (ddi_dma_mem_alloc(qlt->mq_req[idx].queue_mem_mq_dma_handle,
	    REQUEST_QUEUE_MQ_SIZE,
	    &dev_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &qlt->mq_req[idx].queue_mem_mq_base_addr, &discard,
	    &qlt->mq_req[idx].queue_mem_mq_acc_handle) != DDI_SUCCESS) {
		ddi_dma_free_handle(&qlt->mq_req[idx].queue_mem_mq_dma_handle);
		return (QLT_FAILURE);
	}
	if (ddi_dma_addr_bind_handle(
	    qlt->mq_req[idx].queue_mem_mq_dma_handle,
	    NULL, qlt->mq_req[idx].queue_mem_mq_base_addr,
	    REQUEST_QUEUE_MQ_SIZE,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &qlt->mq_req[idx].queue_mem_mq_cookie,
	    &ncookies) != DDI_SUCCESS) {
		ddi_dma_mem_free(&qlt->mq_req[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_req[idx].queue_mem_mq_dma_handle);
		return (QLT_FAILURE);
	}
	if (ncookies != 1) {
		(void) ddi_dma_unbind_handle(
		    qlt->mq_req[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_req[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_req[idx].queue_mem_mq_dma_handle);
		return (QLT_FAILURE);
	}

	/*
	 * MQ Response queue
	 */
	if (ddi_dma_alloc_handle(qlt->dip, &qlt_queue_dma_attr_mq_rsp1,
	    DDI_DMA_SLEEP, 0,
	    &qlt->mq_resp[idx].queue_mem_mq_dma_handle) != DDI_SUCCESS) {
		(void) ddi_dma_unbind_handle(
		    qlt->mq_req[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_req[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_req[idx].queue_mem_mq_dma_handle);
		return (QLT_FAILURE);
	}
	if (ddi_dma_mem_alloc(qlt->mq_resp[idx].queue_mem_mq_dma_handle,
	    RESPONSE_QUEUE_MQ_SIZE,
	    &dev_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &qlt->mq_resp[idx].queue_mem_mq_base_addr, &discard,
	    &qlt->mq_resp[idx].queue_mem_mq_acc_handle) != DDI_SUCCESS) {
		(void) ddi_dma_unbind_handle(
		    qlt->mq_req[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_req[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_req[idx].queue_mem_mq_dma_handle);
		ddi_dma_free_handle(&qlt->mq_resp[idx].queue_mem_mq_dma_handle);
		return (QLT_FAILURE);
	}
	if (ddi_dma_addr_bind_handle(
	    qlt->mq_resp[idx].queue_mem_mq_dma_handle,
	    NULL, qlt->mq_resp[idx].queue_mem_mq_base_addr,
	    RESPONSE_QUEUE_MQ_SIZE,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &qlt->mq_resp[idx].queue_mem_mq_cookie,
	    &ncookies) != DDI_SUCCESS) {
		(void) ddi_dma_unbind_handle(
		    qlt->mq_req[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_req[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_req[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_resp[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_resp[idx].queue_mem_mq_dma_handle);
		return (QLT_FAILURE);
	}
	if (ncookies != 1) {
		(void) ddi_dma_unbind_handle(
		    qlt->mq_req[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_req[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_req[idx].queue_mem_mq_dma_handle);
		(void) ddi_dma_unbind_handle(
		    qlt->mq_resp[idx].queue_mem_mq_dma_handle);
		ddi_dma_mem_free(&qlt->mq_resp[idx].queue_mem_mq_acc_handle);
		ddi_dma_free_handle(&qlt->mq_resp[idx].queue_mem_mq_dma_handle);
		return (QLT_FAILURE);
	}

	qlt->mq_req[idx].mq_ptr = qlt->mq_req[idx].queue_mem_mq_base_addr;
	qlt->mq_req[idx].mq_ndx_to_fw = qlt->mq_req[idx].mq_ndx_from_fw = 0;
	qlt->mq_req[idx].mq_available = REQUEST_QUEUE_MQ_ENTRIES - 1;
	bzero(qlt->mq_req[idx].mq_ptr, REQUEST_QUEUE_MQ_SIZE);

	qlt->mq_resp[idx].mq_ptr = qlt->mq_resp[idx].queue_mem_mq_base_addr;
	qlt->mq_resp[idx].mq_ndx_to_fw = qlt->mq_resp[idx].mq_ndx_from_fw = 0;
	bzero(qlt->mq_resp[idx].mq_ptr, RESPONSE_QUEUE_MQ_SIZE);

	return (QLT_SUCCESS);
}

static void
qlt_handle_verify_fw_completion(qlt_state_t *qlt, uint8_t *rsp)
{
	uint16_t	status;
	char		info[80];

	status = QMEM_RD16(qlt, rsp+8);
	if (status != 0) {
		(void) snprintf(info, 80, "qlt_handle_verify_fw_completion: "
		    "status:%x, rsp:%p", status, (void *)rsp);
		if (status == 3) {
			uint16_t error_code;

			error_code = QMEM_RD16(qlt, rsp+0xA);
			(void) snprintf(info, 80, "qlt_handle_verify_fw_"
			    "completion: error code:%x", error_code);
		}
	}
}

/*
 * qlt_el_trace_desc_ctor - Construct an extended logging trace descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	Success or Failure.
 * Context:	Kernel context.
 */
static int
qlt_el_trace_desc_ctor(qlt_state_t *qlt)
{
	qlt_trace_entry_t	*entry;
	size_t			maxsize;

	qlt->qlt_trace_desc =
	    (qlt_trace_desc_t *)kmem_zalloc(
	    sizeof (qlt_trace_desc_t), KM_SLEEP);

	qlt->qlt_log_entries = QL_LOG_ENTRIES;
	maxsize = qlt->qlt_log_entries * sizeof (qlt_trace_entry_t);
	entry = kmem_zalloc(maxsize, KM_SLEEP);

	mutex_init(&qlt->qlt_trace_desc->mutex, NULL,
	    MUTEX_DRIVER, NULL);

	qlt->qlt_trace_desc->trace_buffer = entry;
	qlt->qlt_trace_desc->trace_buffer_size = maxsize;
	qlt->qlt_trace_desc->nindex = 0;

	qlt->qlt_trace_desc->nentries = qlt->qlt_log_entries;
	qlt->qlt_trace_desc->start = qlt->qlt_trace_desc->end = 0;
	qlt->qlt_trace_desc->csize = 0;
	qlt->qlt_trace_desc->count = 0;

	return (DDI_SUCCESS);
}

/*
 * qlt_el_trace_desc_dtor - Destroy an extended logging trace descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	Success or Failure.
 * Context:	Kernel context.
 */
static int
qlt_el_trace_desc_dtor(qlt_state_t *qlt)
{
	int	rval = DDI_SUCCESS;

	if (qlt->qlt_trace_desc != NULL) {
		if (qlt->qlt_trace_desc->trace_buffer != NULL) {
			kmem_free(qlt->qlt_trace_desc->trace_buffer,
			    qlt->qlt_trace_desc->trace_buffer_size);
		}
		mutex_destroy(&qlt->qlt_trace_desc->mutex);
		kmem_free(qlt->qlt_trace_desc, sizeof (qlt_trace_desc_t));
	}

	return (rval);
}

/*
 * qlt_el_msg
 *	Extended logging message
 *
 * Input:
 *	qlt:	adapter state pointer.
 *	fn:	function name.
 *	ce:	level
 *	...:	Variable argument list.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
void
qlt_el_msg(qlt_state_t *qlt, const char *fn, int ce, ...)
{
	char	*s, *fmt = 0, *fmt1 = 0;

	/*
	 * EL_BUFFER_RESERVE 256 is the max # of bytes
	 * that driver's log could be collected.
	 * add 3 more buytes for safely maniplulation.
	 */
	char	buf[EL_BUFFER_RESERVE + 3];
	char	buf1[QL_LOG_LENGTH];
	size_t	tmp;
	size_t	rval, rval1;
	va_list	vl;
	qlt_trace_desc_t *desc = qlt->qlt_trace_desc;
	qlt_trace_entry_t	*entry;
	uint32_t	cindex;
	timespec_t	time;
	uint32_t	count;
	size_t		left;

	(void) bzero((void *)&buf[0], EL_BUFFER_RESERVE + 3);
	fmt1 = &buf[0];

	TRACE_BUFFER_LOCK(qlt);

	/* locate the entry to be filled out */
	cindex = desc->nindex;
	entry = &desc->trace_buffer[cindex];

	count = desc->count;

	desc->end = desc->nindex;
	desc->nindex++;
	if (desc->nindex == desc->nentries) {
		desc->nindex = 0;
	}

	if (desc->csize < desc->nentries) {
		desc->csize ++;
	} else {
		/*
		 * once wrapped, csize is fixed.
		 * so we have to adjust start point
		 */
		desc->start = desc->nindex;
	}

	gethrestime(&time);

	rval = snprintf(fmt1, (size_t)EL_BUFFER_RESERVE,
	    QL_BANG "%d=>QEL %s(%d,%d):: %s, ", count, QL_NAME,
	    qlt->instance, 0, fn);

	rval1 = rval;

	va_start(vl, ce);
	s = va_arg(vl, char *);
	fmt = fmt1 + rval;
	tmp = vsnprintf(fmt,
	    (size_t)(uint32_t)((int)EL_BUFFER_RESERVE - rval), s, vl);
	va_end(vl);

	rval += tmp;
	if (rval > QL_LOG_LENGTH - 1) {
		left = rval - (QL_LOG_LENGTH - 1);

		/* store the remaining string */
		(void) strncpy(buf1, fmt1 + (QL_LOG_LENGTH - 1), left);
		(void) strncpy(entry->buf, fmt1, (QL_LOG_LENGTH - 1));
		entry->buf[QL_LOG_LENGTH - 1] = '\n';

		bcopy((void *)&time, (void *)&entry->hs_time,
		    sizeof (timespec_t));

		/*
		 * remaining msg will be stored in the nex entry
		 * with same timestamp and same sequence number
		 */
		cindex = desc->nindex;
		entry = &desc->trace_buffer[cindex];

		desc->end = desc->nindex;
		desc->nindex++;
		if (desc->nindex == desc->nentries) {
			desc->nindex = 0;
		}

		if (desc->csize < desc->nentries) {
			desc->csize ++;
		} else {
			desc->start = desc->nindex;
		}

		(void) strncpy(&entry->buf[0], fmt1, rval1);
		(void) strncpy(&entry->buf[rval1], &buf1[0], left);
		entry->buf[rval1 + left] = 0;

		bcopy((void *)&time, (void *)&entry->hs_time,
		    sizeof (timespec_t));

		if (qlt->qlt_eel_level == 1) {
			cmn_err(ce, fmt1);
		}

		desc->count++;

		TRACE_BUFFER_UNLOCK(qlt);
		return;
	}

	desc->count ++;
	bcopy((void *)&time, (void *)&entry->hs_time,
	    sizeof (timespec_t));

	/*
	 * Here we know that fmt1 will fit within QL_LOG_LENGTH due to the
	 * check above, but smatch identifies a potential problem.
	 */
	(void) strncpy(entry->buf, fmt1, rval);
	entry->buf[rval] = 0;

	TRACE_BUFFER_UNLOCK(qlt);

	if (qlt->qlt_eel_level == 1) {
		cmn_err(ce, fmt1);
	}
}

static int
qlt_read_int_prop(qlt_state_t *qlt, char *prop, int defval)
{
	return (ddi_getprop(DDI_DEV_T_ANY, qlt->dip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, prop, defval));
}

static int
qlt_read_string_prop(qlt_state_t *qlt, char *prop, char **prop_val)
{
	return (ddi_prop_lookup_string(DDI_DEV_T_ANY, qlt->dip,
	    DDI_PROP_DONTPASS, prop, prop_val));
}

static int
qlt_read_int_instance_prop(qlt_state_t *qlt, char *prop, int defval)
{
	char		inst_prop[256];
	int		val;

	/*
	 * Get adapter instance specific parameters. If the instance
	 * specific parameter isn't there, try the global parameter.
	 */

	(void) sprintf(inst_prop, "hba%d-%s", qlt->instance, prop);

	if ((val = qlt_read_int_prop(qlt, inst_prop, defval)) == defval) {
		val = qlt_read_int_prop(qlt, prop, defval);
	}

	return (val);
}

static int
qlt_read_string_instance_prop(qlt_state_t *qlt, char *prop, char **prop_val)
{
	char		instance_prop[256];

	/* Get adapter instance specific parameter. */
	(void) sprintf(instance_prop, "hba%d-%s", qlt->instance, prop);
	return (qlt_read_string_prop(qlt, instance_prop, prop_val));
}

static int
qlt_convert_string_to_ull(char *prop, int radix,
    u_longlong_t *result)
{
	return (ddi_strtoull((const char *)prop, 0, radix, result));
}

static boolean_t
qlt_wwn_overload_prop(qlt_state_t *qlt)
{
	char		*prop_val = NULL;
	int		rval;
	int		radix;
	u_longlong_t	wwnn = 0, wwpn = 0;
	boolean_t	overloaded = FALSE;

	radix = 16;

	rval = qlt_read_string_instance_prop(qlt, "adapter-wwnn", &prop_val);
	if (rval == DDI_PROP_SUCCESS) {
		rval = qlt_convert_string_to_ull(prop_val, radix, &wwnn);
	}
	if (rval == DDI_PROP_SUCCESS) {
		rval = qlt_read_string_instance_prop(qlt, "adapter-wwpn",
		    &prop_val);
		if (rval == DDI_PROP_SUCCESS) {
			rval = qlt_convert_string_to_ull(prop_val, radix,
			    &wwpn);
		}
	}
	if (rval == DDI_PROP_SUCCESS) {
		overloaded = TRUE;
		/* Overload the current node/port name nvram copy */
		bcopy((char *)&wwnn, qlt->nvram->node_name, 8);
		BIG_ENDIAN_64(qlt->nvram->node_name);
		bcopy((char *)&wwpn, qlt->nvram->port_name, 8);
		BIG_ENDIAN_64(qlt->nvram->port_name);
	}
	return (overloaded);
}

/*
 * prop_text - Return a pointer to a string describing the status
 *
 * Input:	prop_status = the return status from a property function.
 * Returns:	pointer to a string.
 * Context:	Kernel context.
 */
char *
prop_text(int prop_status)
{
	string_table_t *entry = &prop_status_tbl[0];

	return (value2string(entry, prop_status, 0xFFFF));
}

/*
 * value2string	Return a pointer to a string associated with the value
 *
 * Input:	entry = the value to string table
 *		value = the value
 * Returns:	pointer to a string.
 * Context:	Kernel context.
 */
char *
value2string(string_table_t *entry, int value, int delimiter)
{
	for (; entry->value != delimiter; entry++) {
		if (entry->value == value) {
			break;
		}
	}
	return (entry->string);
}

/*
 * qlt_chg_endian Change endianess of byte array.
 *
 * Input:	buf = array pointer.
 *		size = size of array in bytes.
 *
 * Context:	Interrupt or Kernel context.
 */
void
qlt_chg_endian(uint8_t buf[], size_t size)
{
	uint8_t byte;
	size_t  cnt1;
	size_t  cnt;

	cnt1 = size - 1;
	for (cnt = 0; cnt < size / 2; cnt++) {
		byte = buf[cnt1];
		buf[cnt1] = buf[cnt];
		buf[cnt] = byte;
		cnt1--;
	}
}

/*
 * ql_mps_reset
 *	Reset MPS for FCoE functions.
 *
 * Input:
 *	ha = virtual adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
qlt_mps_reset(qlt_state_t *qlt)
{
	uint32_t	data, dctl = 1000;

	do {
		if (dctl-- == 0 || qlt_raw_wrt_risc_ram_word(qlt, 0x7c00, 1) !=
		    QLT_SUCCESS) {
			EL(qlt, "qlt_mps_reset: semaphore request fail,"
			    " cnt=%d\n", dctl);
			return;
		}
		if (qlt_raw_rd_risc_ram_word(qlt, 0x7c00, &data) !=
		    QLT_SUCCESS) {
			(void) qlt_raw_wrt_risc_ram_word(qlt, 0x7c00, 0);
			EL(qlt, "qlt_mps_reset: semaphore read fail,"
			    " cnt=%d\n", dctl);
			return;
		}
	} while (!(data & BIT_0));

	if (qlt_raw_rd_risc_ram_word(qlt, 0x7A15, &data) == QLT_SUCCESS) {
		dctl = (uint16_t)PCICFG_RD16(qlt, 0x54);
		if ((data & 0xe0) != (dctl & 0xe0)) {
			data &= 0xff1f;
			data |= dctl & 0xe0;
			(void) qlt_raw_wrt_risc_ram_word(qlt, 0x7A15, data);
		}
	} else {
		EL(qlt, "qlt_mps_reset: read 0x7a15 failed.\n");
	}
	(void) qlt_raw_wrt_risc_ram_word(qlt, 0x7c00, 0);
}

/*
 * qlt_raw_wrt_risc_ram_word
 *	Write RISC RAM word.
 *
 * Input:	qlt:		adapter state pointer.
 *		risc_address:	risc ram word address.
 *		data:		data.
 *
 * Returns:	qlt local function return status code.
 *
 * Context:	Kernel context.
 */
static fct_status_t
qlt_raw_wrt_risc_ram_word(qlt_state_t *qlt, uint32_t risc_address,
    uint32_t data)
{
	fct_status_t	ret;

	REG_WR16(qlt, REG_MBOX(0), MBC_WRITE_RAM_EXTENDED);
	REG_WR16(qlt, REG_MBOX(1), LSW(risc_address));
	REG_WR16(qlt, REG_MBOX(2), LSW(data));
	REG_WR16(qlt, REG_MBOX(3), MSW(data));
	REG_WR16(qlt, REG_MBOX(8), MSW(risc_address));
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_raw_mailbox_command=MBC_WRITE_RAM_EXTENDED status"
		    "=%llxh\n", ret);
	}
	return (ret);
}

/*
 * ql_raw_rd_risc_ram_word
 *	Read RISC RAM word.
 *
 * Input:	qlt:		adapter state pointer.
 *		risc_address:	risc ram word address.
 *		data:		data pointer.
 *
 * Returns:	ql local function return status code.
 *
 * Context:	Kernel context.
 */
static fct_status_t
qlt_raw_rd_risc_ram_word(qlt_state_t *qlt, uint32_t risc_address,
    uint32_t *data)
{
	fct_status_t	ret;

	REG_WR16(qlt, REG_MBOX(0), MBC_READ_RAM_EXTENDED);
	REG_WR16(qlt, REG_MBOX(1), LSW(risc_address));
	REG_WR16(qlt, REG_MBOX(2), MSW(risc_address));
	ret = qlt_raw_mailbox_command(qlt);
	*data = REG_RD16(qlt, REG_MBOX(2));
	*data |= (REG_RD16(qlt, REG_MBOX(3)) << 16);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD(CLEAR_RISC_TO_PCI_INTR));
	if (ret != QLT_SUCCESS) {
		EL(qlt, "qlt_raw_mailbox_command=MBC_READ_RAM_EXTENDED status"
		    "=%llxh\n", ret);
	}
	return (ret);
}

static void
qlt_properties(qlt_state_t *qlt)
{
	int32_t		cnt = 0;
	int32_t		defval = 0xffff;

	if (qlt_wwn_overload_prop(qlt) == TRUE) {
		EL(qlt, "wwnn overloaded.\n");
	}

	/* configure extended logging from conf file */
	if ((cnt = qlt_read_int_instance_prop(qlt, "extended-logging",
	    defval)) != defval) {
		qlt->qlt_eel_level = (uint8_t)(cnt & 0xff);
		EL(qlt, "extended error logging=%d\n", cnt);
	}

	if ((cnt = qlt_read_int_instance_prop(qlt, "bucketcnt2k", defval)) !=
	    defval) {
		qlt->qlt_bucketcnt[0] = cnt;
		EL(qlt, "2k bucket o/l=%d\n", cnt);
	}

	if ((cnt = qlt_read_int_instance_prop(qlt, "bucketcnt8k", defval)) !=
	    defval) {
		qlt->qlt_bucketcnt[1] = cnt;
		EL(qlt, "8k bucket o/l=%d\n", cnt);
	}

	if ((cnt = qlt_read_int_instance_prop(qlt, "bucketcnt64k", defval)) !=
	    defval) {
		qlt->qlt_bucketcnt[2] = cnt;
		EL(qlt, "64k bucket o/l=%d\n", cnt);
	}

	if ((cnt = qlt_read_int_instance_prop(qlt, "bucketcnt128k", defval)) !=
	    defval) {
		qlt->qlt_bucketcnt[3] = cnt;
		EL(qlt, "128k bucket o/l=%d\n", cnt);
	}

	if ((cnt = qlt_read_int_instance_prop(qlt, "bucketcnt256", defval)) !=
	    defval) {
		qlt->qlt_bucketcnt[4] = cnt;
		EL(qlt, "256k bucket o/l=%d\n", cnt);
	}
}

/* ******************************************************************* */
/* ****************** 27xx Dump Template Functions ******************* */
/* ******************************************************************* */

/*
 * qlt_get_dmp_template
 *	Get dump template from firmware module
 *
 * Input:
 *	qlt:	qlt_state_t pointer.
 *
 * Returns:
 *	qlt local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static fct_status_t
qlt_27xx_get_dmp_template(qlt_state_t *qlt)
{
	ddi_device_acc_attr_t dev_acc_attr;
	dev_info_t *dip = qlt->dip;
	uint_t ncookies;
	size_t discard;
	uint32_t word_count, cnt, *bp, *dp;

	if (qlt->dmp_template_dma_handle != NULL) {
		(void) ddi_dma_unbind_handle(qlt->dmp_template_dma_handle);
		if (qlt->dmp_template_acc_handle != NULL) {
			ddi_dma_mem_free(&qlt->dmp_template_acc_handle);
		}
		ddi_dma_free_handle(&qlt->dmp_template_dma_handle);
	}

	if ((word_count = tmplt2700_length01) == 0) {
		EL(qlt, "No dump template, length=0\n");
		return (QLT_FAILURE);
	}

	dev_acc_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_acc_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	dev_acc_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_dma_alloc_handle(dip, &qlt_queue_dma_attr,
	    DDI_DMA_SLEEP, 0, &qlt->dmp_template_dma_handle) !=
	    DDI_SUCCESS) {
		EL(qlt, "Unable to allocate template handle");
		return (QLT_FAILURE);
	}

	if (ddi_dma_mem_alloc(qlt->dmp_template_dma_handle,
	    (word_count << 2), &dev_acc_attr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &qlt->dmp_template_addr, &discard,
	    &qlt->dmp_template_acc_handle) != DDI_SUCCESS) {
		ddi_dma_free_handle(&qlt->dmp_template_dma_handle);
		EL(qlt, "Unable to allocate template buffer");
		return (QLT_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(qlt->dmp_template_dma_handle, NULL,
	    qlt->dmp_template_addr, (word_count << 2),
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &qlt->dmp_template_cookie, &ncookies) != DDI_SUCCESS) {
		ddi_dma_mem_free(&qlt->dmp_template_acc_handle);
		ddi_dma_free_handle(&qlt->dmp_template_dma_handle);
		EL(qlt, "Unable to bind template handle");
		return (QLT_FAILURE);
	}

	if (ncookies != 1) {
		(void) ddi_dma_unbind_handle(qlt->dmp_template_dma_handle);
		ddi_dma_mem_free(&qlt->dmp_template_acc_handle);
		ddi_dma_free_handle(&qlt->dmp_template_dma_handle);
		EL(qlt, "cookies (%d) > 1.\n", ncookies);
		return (QLT_FAILURE);
	}

	/* Get big endian template. */
	bp = (uint32_t *)qlt->dmp_template_addr;
	dp = (uint32_t *)tmplt2700_code01;
	for (cnt = 0; cnt < word_count; cnt++) {
		ddi_put32(qlt->dmp_template_acc_handle, bp, *dp++);
		if (cnt > 6) {
			qlt_chg_endian((uint8_t *)bp, 4);
		}
		bp++;
	}

	return (QLT_SUCCESS);
}

static int
qlt_27xx_dt_riob1(qlt_state_t *qlt, qlt_dt_riob1_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int esize;
	uint32_t i, cnt;
	uint8_t	 *bp = dbuff;
	uint32_t addr = entry->addr;
	uint32_t reg = entry->pci_offset;

	cnt = CHAR_TO_SHORT(entry->reg_count_l, entry->reg_count_h);
	esize = cnt * 4;		/* addr */
	esize += cnt * entry->reg_size;	/* data */

	if (dbuff == NULL) {
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	REG_WR32(qlt, REG_IOBUS_BASE_ADDR, addr);
	while (cnt--) {
		*bp++ = LSB(LSW(addr));
		*bp++ = MSB(LSW(addr));
		*bp++ = LSB(MSW(addr));
		*bp++ = MSB(MSW(addr));
		for (i = 0; i < entry->reg_size; i++) {
			*bp++ = REG_RD8(qlt, reg++);
		}
		addr++;
	}

	return (esize);
}

static void
qlt_27xx_dt_wiob1(qlt_state_t *qlt, qlt_dt_wiob1_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	uint32_t reg = entry->pci_offset;

	if (dbuff == NULL) {
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	REG_WR32(qlt, REG_IOBUS_BASE_ADDR, entry->addr);
	REG_WR32(qlt, reg, entry->data);
}

static int
qlt_27xx_dt_riob2(qlt_state_t *qlt, qlt_dt_riob2_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int esize;
	uint32_t i, cnt;
	uint8_t	 *bp = dbuff;
	uint32_t reg = entry->pci_offset;
	uint32_t addr = entry->addr;

	cnt = CHAR_TO_SHORT(entry->reg_count_l, entry->reg_count_h);
	esize = cnt * 4;		/* addr */
	esize += cnt * entry->reg_size;	/* data */

	if (dbuff == NULL) {
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	REG_WR32(qlt, REG_IOBUS_BASE_ADDR, addr);
	REG_WR32(qlt, entry->bank_sel_offset, entry->reg_bank);
	while (cnt--) {
		*bp++ = LSB(LSW(addr));
		*bp++ = MSB(LSW(addr));
		*bp++ = LSB(MSW(addr));
		*bp++ = MSB(MSW(addr));
		for (i = 0; i < entry->reg_size; i++) {
			*bp++ = REG_RD8(qlt, reg++);
		}
		addr++;
	}

	return (esize);
}

static void
qlt_27xx_dt_wiob2(qlt_state_t *qlt, qlt_dt_wiob2_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	uint16_t data;
	uint32_t reg = entry->pci_offset;

	if (dbuff == NULL) {
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	data = CHAR_TO_SHORT(entry->data_l, entry->data_h);

	REG_WR32(qlt, REG_IOBUS_BASE_ADDR, entry->addr);
	REG_WR32(qlt, entry->bank_sel_offset, entry->reg_bank);
	REG_WR16(qlt, reg, data);
}

static int
qlt_27xx_dt_rpci(qlt_state_t *qlt, qlt_dt_rpci_t *entry, uint8_t *dbuff,
    uint8_t *dbuff_end)
{
	int esize;
	uint32_t i;
	uint8_t	*bp = dbuff;
	uint32_t reg = entry->addr;

	esize = 4;	/* addr */
	esize += 4;	/* data */

	if (dbuff == NULL) {
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	*bp++ = LSB(LSW(entry->addr));
	*bp++ = MSB(LSW(entry->addr));
	*bp++ = LSB(MSW(entry->addr));
	*bp++ = MSB(MSW(entry->addr));
	for (i = 0; i < 4; i++) {
		*bp++ = REG_RD8(qlt, reg++);
	}

	return (esize);
}

static void
qlt_27xx_dt_wpci(qlt_state_t *qlt, qlt_dt_wpci_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	uint32_t reg = entry->addr;

	if (dbuff == NULL) {
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	REG_WR32(qlt, reg, entry->data);
}

static int
qlt_27xx_dt_rram(qlt_state_t *qlt, qlt_dt_rram_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int esize, rval;
	uint32_t start = entry->start_addr;
	uint32_t end = entry->end_addr;

	if (entry->ram_area == 2) {
		end = qlt->fw_ext_memory_end;
	} else if (entry->ram_area == 3) {
		start = qlt->fw_shared_ram_start;
		end = qlt->fw_shared_ram_end;
	} else if (entry->ram_area == 4) {
		start = qlt->fw_ddr_ram_start;
		end = qlt->fw_ddr_ram_end;
	} else if (entry->ram_area != 1) {
		EL(qlt, "skipped, unknown RAM_AREA %d\n", entry->ram_area);
		start = 0;
		end = 0;
	}
	esize = end > start ? end - start : 0;
	if (esize) {
		esize = (esize + 1) * 4;
	}

	if (dbuff == NULL) {
		return (esize);
	}
	if (esize == 0 || esize + dbuff >= dbuff_end) {
		if (esize != 0) {
			EL(qlt, "skipped, no buffer space, needed=%xh\n",
			    esize);
		} else {
			EL(qlt, "skipped, no ram_area=%xh, start=%xh "
			    "end=%xh\n", entry->ram_area, start, end);
		}
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}
	entry->end_addr = end;
	entry->start_addr = start;

	if ((rval = qlt_27xx_dump_ram(qlt, MBC_DUMP_RAM_EXTENDED,
	    start, esize / 4, dbuff)) != QLT_SUCCESS) {
		EL(qlt, "dump_ram failed, rval=%xh, addr=%xh, len=%xh, "
		    "esize=0\n", rval, start, esize / 4);
		return (0);
	}

	return (esize);
}

static int
qlt_27xx_dt_gque(qlt_state_t *qlt, qlt_dt_gque_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int esize;
	uint32_t cnt, q_cnt, e_cnt, i;
	uint8_t	*bp = dbuff, *dp;

	if (entry->queue_type == 1) {
		e_cnt = qlt->qlt_queue_cnt;
		esize = e_cnt * 2;	/* queue number */
		esize += e_cnt * 2;	/* queue entries */

		/* queue size */
		esize += REQUEST_QUEUE_ENTRIES * IOCB_SIZE;
		for (q_cnt = 1; q_cnt < qlt->qlt_queue_cnt; q_cnt++) {
			esize += REQUEST_QUEUE_MQ_ENTRIES * IOCB_SIZE;
		}

		if (dbuff == NULL) {
			return (esize);
		}
		if (esize + dbuff >= dbuff_end) {
			EL(qlt, "skipped, no buffer space, needed=%xh\n",
			    esize);
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			return (0);
		}
		entry->num_queues = e_cnt;

		for (q_cnt = 0; q_cnt < entry->num_queues; q_cnt++) {
			e_cnt = q_cnt == 0 ?
			    REQUEST_QUEUE_ENTRIES : REQUEST_QUEUE_MQ_ENTRIES;
			dp = (uint8_t *)qlt->mq_req[q_cnt].mq_ptr;
			*bp++ = LSB(q_cnt);
			*bp++ = MSB(q_cnt);
			*bp++ = LSB(e_cnt);
			*bp++ = MSB(e_cnt);
			for (cnt = 0; cnt < e_cnt; cnt++) {
				for (i = 0; i < IOCB_SIZE; i++) {
					*bp++ = *dp++;
				}
			}
		}
	} else if (entry->queue_type == 2) {

		e_cnt = qlt->qlt_queue_cnt;
		esize = e_cnt * 2;	/* queue number */
		esize += e_cnt * 2;	/* queue entries */

		/* queue size */
		esize += RESPONSE_QUEUE_ENTRIES * IOCB_SIZE;
		for (q_cnt = 1; q_cnt < qlt->qlt_queue_cnt; q_cnt++) {
			esize += RESPONSE_QUEUE_MQ_ENTRIES * IOCB_SIZE;
		}

		if (dbuff == NULL) {
			return (esize);
		}
		if (esize + dbuff >= dbuff_end) {
			EL(qlt, "skipped2, no buffer space, needed=%xh\n",
			    esize);
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			return (0);
		}
		entry->num_queues = e_cnt;

		for (q_cnt = 0; q_cnt < entry->num_queues; q_cnt++) {
			e_cnt = q_cnt == 0 ?
			    RESPONSE_QUEUE_ENTRIES : RESPONSE_QUEUE_MQ_ENTRIES;
			dp = (uint8_t *)qlt->mq_resp[q_cnt].mq_ptr;
			*bp++ = LSB(q_cnt);
			*bp++ = MSB(q_cnt);
			*bp++ = LSB(e_cnt);
			*bp++ = MSB(e_cnt);
			for (cnt = 0; cnt < e_cnt; cnt++) {
				for (i = 0; i < IOCB_SIZE; i++) {
					*bp++ = *dp++;
				}
			}
		}
	} else if (entry->queue_type == 3) {
		e_cnt = 1;
		esize = e_cnt * 2;	/* queue number */
		esize += e_cnt * 2;	/* queue entries */

		/* queue size */
		esize += RESPONSE_QUEUE_ENTRIES * IOCB_SIZE;

		if (dbuff == NULL) {
			return (esize);
		}
		if (esize + dbuff >= dbuff_end) {
			EL(qlt, "skipped2, no buffer space, needed=%xh\n",
			    esize);
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			return (0);
		}
		entry->num_queues = e_cnt;

		for (q_cnt = 0; q_cnt < entry->num_queues; q_cnt++) {
			e_cnt = ATIO_QUEUE_ENTRIES;
			dp = (uint8_t *)qlt->atio_ptr;
			*bp++ = LSB(q_cnt);
			*bp++ = MSB(q_cnt);
			*bp++ = LSB(e_cnt);
			*bp++ = MSB(e_cnt);
			for (cnt = 0; cnt < e_cnt; cnt++) {
				for (i = 0; i < IOCB_SIZE; i++) {
					*bp++ = *dp++;
				}
			}
		}
	} else {
		EL(qlt, "skipped, unknown queue_type %d, esize=0\n",
		    entry->queue_type);
		if (dbuff != NULL) {
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	}

	return (esize);
}

/*ARGSUSED*/
static int
qlt_27xx_dt_gfce(qlt_state_t *qlt, qlt_dt_gfce_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	if (dbuff != NULL) {
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
	}

	return (0);
}

static void
qlt_27xx_dt_prisc(qlt_state_t *qlt, qlt_dt_prisc_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	clock_t	timer;

	if (dbuff == NULL) {
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	/* Pause RISC. */
	if ((REG_RD32(qlt, REG_RISC_STATUS) & BIT_8) == 0) {
		REG_WR32(qlt, REG_HCCR, 0x30000000);
		for (timer = 30000;
		    (REG_RD32(qlt, REG_RISC_STATUS) & BIT_8) == 0;
		    timer--) {
			if (timer) {
				drv_usecwait(100);
				if (timer % 10000 == 0) {
					EL(qlt, "risc pause %d\n", timer);
				}
			} else {
				EL(qlt, "risc pause timeout\n");
				break;
			}
		}
	}
}

static void
qlt_27xx_dt_rrisc(qlt_state_t *qlt, qlt_dt_rrisc_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	clock_t	timer;
	uint16_t rom_status;

	if (dbuff == NULL) {
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	/* Shutdown DMA. */
	REG_WR32(qlt, REG_CTRL_STATUS, DMA_SHUTDOWN_CTRL);

	/* Wait for DMA to stop. */
	for (timer = 0; timer < 30000; timer++) {
		if (!(REG_RD32(qlt, REG_CTRL_STATUS) & DMA_ACTIVE_STATUS)) {
			break;
		}
		drv_usecwait(100);
	}

	/* Reset the chip. */
	REG_WR32(qlt, REG_CTRL_STATUS, CHIP_SOFT_RESET);
	drv_usecwait(200);

	/* Wait for RISC to recover from reset. */
	for (timer = 30000; timer; timer--) {
		rom_status = REG_RD16(qlt, REG_MBOX0);
		if ((rom_status & MBS_ROM_STATUS_MASK) != MBS_ROM_BUSY) {
			break;
		}
		drv_usecwait(100);
	}

	/* Wait for reset to finish. */
	for (timer = 30000; timer; timer--) {
		if (!(REG_RD32(qlt, REG_CTRL_STATUS) & CHIP_SOFT_RESET)) {
			break;
		}
		drv_usecwait(100);
	}

	/* XXX: Disable Interrupts (Probably not needed) */
	REG_WR32(qlt, REG_INTR_CTRL, 0);

	qlt->qlt_intr_enabled = 0;
}

static void
qlt_27xx_dt_dint(qlt_state_t *qlt, qlt_dt_dint_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	if (dbuff == NULL) {
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	PCICFG_WR32(qlt, entry->pci_offset, entry->data);
}

/*ARGSUSED*/
static int
qlt_27xx_dt_ghbd(qlt_state_t *qlt, qlt_dt_ghbd_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	if (dbuff != NULL) {
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
	}

	return (0);
}

/*ARGSUSED*/
static int
qlt_27xx_dt_scra(qlt_state_t *qlt, qlt_dt_scra_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	if (dbuff != NULL) {
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
	}

	return (0);
}

static int
qlt_27xx_dt_rrreg(qlt_state_t *qlt, qlt_dt_rrreg_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int esize;
	uint32_t i;
	uint8_t	*bp = dbuff;
	uint32_t addr = entry->addr;
	uint32_t cnt = entry->count;

	esize = cnt * 4;	/* addr */
	esize += cnt * 4;	/* data */

	if (dbuff == NULL) {
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	REG_WR32(qlt, REG_IOBUS_BASE_ADDR, 0x40);
	while (cnt--) {
		REG_WR32(qlt, 0xc0, addr | 0x80000000);
		*bp++ = LSB(LSW(addr));
		*bp++ = MSB(LSW(addr));
		*bp++ = LSB(MSW(addr));
		*bp++ = MSB(MSW(addr));
		for (i = 0; i < 4; i++) {
			*bp++ = REG_RD8(qlt, i);
		}
		addr += 4;
	}

	return (esize);
}

static void
qlt_27xx_dt_wrreg(qlt_state_t *qlt, qlt_dt_wrreg_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	if (dbuff == NULL) {
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	REG_WR32(qlt, REG_IOBUS_BASE_ADDR, 0x40);
	REG_WR32(qlt, 0xc4, entry->data);
	REG_WR32(qlt, 0xc0, entry->addr);
}

static int
qlt_27xx_dt_rrram(qlt_state_t *qlt, qlt_dt_rrram_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int rval, esize;

	esize = entry->count * 4;	/* data */

	if (dbuff == NULL) {
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	if ((rval = qlt_27xx_dump_ram(qlt, MBC_MPI_RAM, entry->addr,
	    entry->count, dbuff)) != QLT_SUCCESS) {
		EL(qlt, "dump_ram failed, rval=%xh, addr=%xh, len=%xh, "
		    "esize=0\n", rval, entry->addr, entry->count);
		return (0);
	}

	return (esize);
}

static int
qlt_27xx_dt_rpcic(qlt_state_t *qlt, qlt_dt_rpcic_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int esize;
	uint32_t i;
	uint8_t	*bp = dbuff;
	uint32_t addr = entry->addr;
	uint32_t cnt = entry->count;

	esize = cnt * 4;	/* addr */
	esize += cnt * 4;	/* data */

	if (dbuff == NULL) {
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	while (cnt--) {
		*bp++ = LSB(LSW(addr));
		*bp++ = MSB(LSW(addr));
		*bp++ = LSB(MSW(addr));
		*bp++ = MSB(MSW(addr));
		for (i = 0; i < 4; i++) {
			*bp++ = PCICFG_RD8(qlt, addr++);
		}
	}

	return (esize);
}

/*ARGSUSED*/
static int
qlt_27xx_dt_gques(qlt_state_t *qlt, qlt_dt_gques_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	if (entry->queue_type == 1) {
		EL(qlt, "skipped, no request queue shadowing, esize=0\n");
		if (dbuff != NULL) {
			entry->num_queues = 0;
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	} else if (entry->queue_type == 2) {
		EL(qlt, "skipped, no response queue shadowing, esize=0\n");
		if (dbuff != NULL) {
			entry->num_queues = 0;
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	} else if (entry->queue_type == 3) {
		EL(qlt, "skipped, no ATIO queue, esize=0\n");
		if (dbuff != NULL) {
			entry->num_queues = 0;
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	} else {
		EL(qlt, "skipped, unknown queue_type %d, esize=0\n",
		    entry->queue_type);
		if (dbuff != NULL) {
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	}
}

static int
qlt_27xx_dt_wdmp(qlt_state_t *qlt, qlt_dt_wdmp_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int esize;
	uint8_t *bp = dbuff;
	uint32_t data, cnt = entry->length, *dp = entry->data;

	esize = cnt;
	if (dbuff == NULL) {
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(qlt, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	while (cnt--) {
		data = *dp++;
		*bp++ = LSB(LSW(data));
		*bp++ = MSB(LSW(data));
		*bp++ = LSB(MSW(data));
		*bp++ = MSB(MSW(data));
	}

	return (esize);
}

/*
 * qlt_27xx_dump_ram
 *	Dumps RAM.
 *	Risc interrupts must be disabled when this routine is called.
 *
 * Input:
 *	pi:		port info pointer.
 *	cmd:		MBC_DUMP_RAM_EXTENDED/MBC_MPI_RAM.
 *	risc_address:	RISC code start address.
 *	len:		Number of words.
 *	bp:		buffer pointer.
 *
 * Returns:
 *	qlt local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/*ARGSUSED*/
static int
qlt_27xx_dump_ram(qlt_state_t *qlt, uint16_t cmd, uint32_t risc_address,
    uint32_t len, uint8_t *bp)
{
	uint8_t *dp;
	uint32_t words_to_read, endaddr;
	uint32_t i;
	int rval = QLT_SUCCESS;

	endaddr = risc_address + len;
	words_to_read = 0;
	while (risc_address < endaddr) {
		words_to_read = MBOX_DMA_MEM_SIZE >> 2;
		if ((words_to_read + risc_address) > endaddr) {
			words_to_read = endaddr - risc_address;
		}

		if (cmd == MBC_DUMP_RAM_EXTENDED) {
			rval = qlt_read_risc_ram(qlt, risc_address,
			    words_to_read);
		} else {
			rval = qlt_mbx_mpi_ram(qlt, risc_address,
			    words_to_read, 0);
		}

		if (rval != QLT_SUCCESS) {
			EL(qlt, "Error reading risc ram = %xh len = %x\n",
			    risc_address, words_to_read);
			return (rval);
		}

		dp = (uint8_t *)(qlt->queue_mem_ptr + MBOX_DMA_MEM_OFFSET);
		for (i = 0; i < (words_to_read * 4); i++) {
			*bp++ = *dp++;
		}
		risc_address += words_to_read;
	}

	return (rval);
}

static uint32_t
qlt_27xx_dmp_parse_template(qlt_state_t *qlt, qlt_dt_hdr_t *template_hdr,
    uint8_t *dump_buff, uint32_t buff_size)
{
	int e_cnt, esize, num_of_entries;
	uint32_t bsize;
	time_t time;
	uint8_t *dbuff, *dbuff_end;
	qlt_dt_entry_t *entry;
	int sane_end = 0;

	dbuff = dump_buff;	/* dbuff = NULL	size determination. */
	dbuff_end = dump_buff + buff_size;

	if (template_hdr->type != DT_THDR) {
		EL(qlt, "Template header not found\n");
		return (0);
	}
	if (dbuff != NULL) {
		(void) drv_getparm(TIME, &time);
		template_hdr->driver_timestamp = LSD(time);
	}

	num_of_entries = template_hdr->num_of_entries;
	entry = (qlt_dt_entry_t *)((caddr_t)template_hdr +
	    template_hdr->first_entry_offset);

	bsize = template_hdr->size_of_template;
	for (e_cnt = 0; e_cnt < num_of_entries; e_cnt++) {
		/*
		 * Decode the entry type and process it accordingly
		 */
		esize = 0;
		switch (entry->h.type) {
		case DT_NOP:
			if (dbuff != NULL) {
				entry->h.driver_flags = (uint8_t)
				    (entry->h.driver_flags | SKIPPED_FLAG);
			}
			break;
		case DT_TEND:
			if (dbuff != NULL) {
				entry->h.driver_flags = (uint8_t)
				    (entry->h.driver_flags | SKIPPED_FLAG);
			}
			sane_end++;
			break;
		case DT_RIOB1:
			esize = qlt_27xx_dt_riob1(qlt, (qlt_dt_riob1_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WIOB1:
			qlt_27xx_dt_wiob1(qlt, (qlt_dt_wiob1_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RIOB2:
			esize = qlt_27xx_dt_riob2(qlt, (qlt_dt_riob2_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WIOB2:
			qlt_27xx_dt_wiob2(qlt, (qlt_dt_wiob2_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RPCI:
			esize = qlt_27xx_dt_rpci(qlt, (qlt_dt_rpci_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WPCI:
			qlt_27xx_dt_wpci(qlt, (qlt_dt_wpci_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RRAM:
			esize = qlt_27xx_dt_rram(qlt, (qlt_dt_rram_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_GQUE:
			esize = qlt_27xx_dt_gque(qlt, (qlt_dt_gque_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_GFCE:
			esize = qlt_27xx_dt_gfce(qlt, (qlt_dt_gfce_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_PRISC:
			qlt_27xx_dt_prisc(qlt, (qlt_dt_prisc_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RRISC:
			qlt_27xx_dt_rrisc(qlt, (qlt_dt_rrisc_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_DINT:
			qlt_27xx_dt_dint(qlt, (qlt_dt_dint_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_GHBD:
			esize = qlt_27xx_dt_ghbd(qlt, (qlt_dt_ghbd_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_SCRA:
			esize = qlt_27xx_dt_scra(qlt, (qlt_dt_scra_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RRREG:
			esize = qlt_27xx_dt_rrreg(qlt, (qlt_dt_rrreg_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WRREG:
			qlt_27xx_dt_wrreg(qlt, (qlt_dt_wrreg_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RRRAM:
			esize = qlt_27xx_dt_rrram(qlt, (qlt_dt_rrram_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RPCIC:
			esize = qlt_27xx_dt_rpcic(qlt, (qlt_dt_rpcic_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_GQUES:
			esize = qlt_27xx_dt_gques(qlt, (qlt_dt_gques_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WDMP:
			esize = qlt_27xx_dt_wdmp(qlt, (qlt_dt_wdmp_t *)entry,
			    dbuff, dbuff_end);
			break;
		default:
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			EL(qlt, "Entry ID=%d, type=%d unknown\n", e_cnt,
			    entry->h.type);
			break;
		}
		if (dbuff != NULL && esize) {
			dbuff += esize;
		}
		bsize += esize;
		/* next entry in the template */
		entry = (qlt_dt_entry_t *)((caddr_t)entry + entry->h.size);
	}
	if (sane_end > 1) {
		EL(qlt, "Template configuration error. Check Template\n");
	}

	return (bsize);
}
