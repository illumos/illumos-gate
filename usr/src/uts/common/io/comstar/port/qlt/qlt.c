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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#include <stmf_defines.h>
#include <fct_defines.h>
#include <stmf.h>
#include <portif.h>
#include <fct.h>
#include <qlt.h>
#include <qlt_dma.h>
#include <qlt_ioctl.h>
#include <stmf_ioctl.h>

static int qlt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int qlt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static fct_status_t qlt_reset_chip_and_download_fw(qlt_state_t *qlt,
    int reset_only);
static fct_status_t qlt_load_risc_ram(qlt_state_t *qlt, uint32_t *host_addr,
    uint32_t word_count, uint32_t risc_addr);
static fct_status_t qlt_raw_mailbox_command(qlt_state_t *qlt);
static mbox_cmd_t *qlt_alloc_mailbox_command(qlt_state_t *qlt,
					uint32_t dma_size);
void qlt_free_mailbox_command(qlt_state_t *qlt, mbox_cmd_t *mcp);
static fct_status_t qlt_mailbox_command(qlt_state_t *qlt, mbox_cmd_t *mcp);
static uint_t qlt_isr(caddr_t arg, caddr_t arg2);
static fct_status_t qlt_initialize_adapter(fct_local_port_t *port);
static fct_status_t qlt_firmware_dump(fct_local_port_t *port,
    stmf_state_change_info_t *ssci);
static void qlt_handle_inot(qlt_state_t *qlt, uint8_t *inot);
static void qlt_handle_purex(qlt_state_t *qlt, uint8_t *resp);
static void qlt_handle_atio(qlt_state_t *qlt, uint8_t *atio);
static void qlt_handle_ctio_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_sol_abort_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_dereg_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_unsol_els_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_unsol_els_abort_completion(qlt_state_t *qlt,
    uint8_t *rsp);
static void qlt_handle_sol_els_completion(qlt_state_t *qlt, uint8_t *rsp);
static void qlt_handle_rcvd_abts(qlt_state_t *qlt, uint8_t *resp);
static void qlt_handle_abts_completion(qlt_state_t *qlt, uint8_t *resp);
static fct_status_t qlt_reset_chip_and_download_fw(qlt_state_t *qlt,
    int reset_only);
static fct_status_t qlt_load_risc_ram(qlt_state_t *qlt, uint32_t *host_addr,
    uint32_t word_count, uint32_t risc_addr);
static fct_status_t qlt_read_nvram(qlt_state_t *qlt);
fct_status_t qlt_port_start(caddr_t arg);
fct_status_t qlt_port_stop(caddr_t arg);
fct_status_t qlt_port_online(qlt_state_t *qlt);
fct_status_t qlt_port_offline(qlt_state_t *qlt);
static fct_status_t qlt_get_link_info(fct_local_port_t *port,
    fct_link_info_t *li);
static void qlt_ctl(struct fct_local_port *port, int cmd, void *arg);
static fct_status_t qlt_do_flogi(struct fct_local_port *port,
						fct_flogi_xchg_t *fx);
void qlt_handle_atio_queue_update(qlt_state_t *qlt);
void qlt_handle_resp_queue_update(qlt_state_t *qlt);
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
static int qlt_dump_queue(qlt_state_t *qlt, caddr_t qadr, int entries,
    caddr_t buf, int size_left);
static int qlt_dump_risc_ram(qlt_state_t *qlt, uint32_t addr, uint32_t words,
    caddr_t buf, int size_left);
static int qlt_fwdump_dump_regs(qlt_state_t *qlt, caddr_t buf, int startaddr,
    int count, int size_left);
static int qlt_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
static int qlt_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int qlt_close(dev_t dev, int flag, int otype, cred_t *credp);

#define	SETELSBIT(bmp, els)	(bmp)[((els) >> 3) & 0x1F] |= \
				    ((uint8_t)1) << ((els) & 7)

int qlt_enable_msix = 0;

/* Array to quickly calculate next free buf index to use */
static int qlt_nfb[] = { 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 0xff };

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
	ddi_power
};

#define	QLT_NAME    "COMSTAR QLT"
#define	QLT_VERSION "1.0"

static struct modldrv modldrv = {
	&mod_driverops,
	QLT_NAME,
	&qlt_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

void *qlt_state = NULL;
kmutex_t qlt_global_lock;
static uint32_t qlt_loaded_counter = 0;

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

int
qlt_read_int_prop(qlt_state_t *qlt, char *prop, int defval)
{
	return (ddi_getprop(DDI_DEV_T_ANY, qlt->dip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, prop, defval));
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

	if (ddi_soft_state_zalloc(qlt_state, instance) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if ((qlt = (qlt_state_t *)ddi_get_soft_state(qlt_state, instance))
		== NULL) {
		goto attach_fail_1;
	}
	qlt->instance = instance;
	qlt->nvram = (qlt_nvram_t *)kmem_zalloc(sizeof (qlt_nvram_t), KM_SLEEP);
	qlt->dip = dip;
	if (pci_config_setup(dip, &qlt->pcicfg_acc_handle) != DDI_SUCCESS) {
		goto attach_fail_2;
	}
	did = PCICFG_RD16(qlt, PCI_CONF_DEVID);
	if ((did != 0x2422) && (did != 0x2432) &&
	    (did != 0x2522) && (did != 0x2532)) {
		cmn_err(CE_WARN, "qlt(%d): unknwon devid(%x), failing attach",
		    instance, did);
		goto attach_fail_4;
	}
	if ((did & 0xFF00) == 0x2500)
		qlt->qlt_25xx_chip = 1;

	dev_acc_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_acc_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	dev_acc_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	if (ddi_regs_map_setup(dip, 2, &qlt->regs, 0, 0x100,
	    &dev_acc_attr, &qlt->regs_acc_handle) != DDI_SUCCESS) {
		goto attach_fail_4;
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
	qlt->req_ptr = qlt->queue_mem_ptr + REQUEST_QUEUE_OFFSET;
	qlt->resp_ptr = qlt->queue_mem_ptr + RESPONSE_QUEUE_OFFSET;
	qlt->preq_ptr = qlt->queue_mem_ptr + PRIORITY_QUEUE_OFFSET;
	qlt->atio_ptr = qlt->queue_mem_ptr + ATIO_QUEUE_OFFSET;

	/* mutex are inited in this function */
	if (qlt_setup_interrupts(qlt) != DDI_SUCCESS)
		goto attach_fail_8;

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
		mr = PCICFG_RD16(qlt, 0x4E);
		mr &= 0xfff3;
		mr |= (val << 2);
		PCICFG_WR16(qlt, 0x4E, mr);
	} else if ((did == 0x2432) || (did == 0x2532)) {
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
		mr = PCICFG_RD16(qlt, 0x54);
		mr &= 0x8fff;
		mr |= (val << 12);
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
	if ((did == 0x2432) || (did == 0x2532)) {
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
		mr = PCICFG_RD16(qlt, 0x54);
		mr &= 0xff1f;
		mr |= (val << 5);
		PCICFG_WR16(qlt, 0x54, mr);
	} else {
		cmn_err(CE_WARN, "qlt(%d): dont know how to set "
		    "pcie-max-payload-size for this device (%x)",
		    instance, did);
	}

over_max_payload_setting:;

	if (qlt_port_start((caddr_t)qlt) != QLT_SUCCESS)
		goto attach_fail_10;

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
attach_fail_8:;
	(void) ddi_dma_unbind_handle(qlt->queue_mem_dma_handle);
attach_fail_7:;
	ddi_dma_mem_free(&qlt->queue_mem_acc_handle);
attach_fail_6:;
	ddi_dma_free_handle(&qlt->queue_mem_dma_handle);
attach_fail_5:;
	ddi_regs_map_free(&qlt->regs_acc_handle);
attach_fail_4:;
	pci_config_teardown(&qlt->pcicfg_acc_handle);
	kmem_free(qlt->nvram, sizeof (qlt_nvram_t));
attach_fail_2:;
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
	if ((qlt = (qlt_state_t *)ddi_get_soft_state(qlt_state, instance))
					== NULL) {
		return (DDI_FAILURE);
	}

	if (qlt->fw_code01) {
		return (DDI_FAILURE);
	}

	if ((qlt->qlt_state != FCT_STATE_OFFLINE) ||
				qlt->qlt_state_not_acked) {
		return (DDI_FAILURE);
	}
	if (qlt_port_stop((caddr_t)qlt) != FCT_SUCCESS)
		return (DDI_FAILURE);
	ddi_remove_minor_node(dip, qlt->qlt_minor_name);
	qlt_destroy_mutex(qlt);
	qlt_release_intr(qlt);
	(void) ddi_dma_unbind_handle(qlt->queue_mem_dma_handle);
	ddi_dma_mem_free(&qlt->queue_mem_acc_handle);
	ddi_dma_free_handle(&qlt->queue_mem_dma_handle);
	ddi_regs_map_free(&qlt->regs_acc_handle);
	pci_config_teardown(&qlt->pcicfg_acc_handle);
	kmem_free(qlt->nvram, sizeof (qlt_nvram_t));
	cv_destroy(&qlt->mbox_cv);
	cv_destroy(&qlt->rp_dereg_cv);
	ddi_soft_state_free(qlt_state, instance);

	return (DDI_SUCCESS);
}

static void
qlt_enable_intr(qlt_state_t *qlt)
{
	if (qlt->intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_enable(qlt->htable, qlt->intr_cnt);
	} else {
		int i;
		for (i = 0; i < qlt->intr_cnt; i++)
			(void) ddi_intr_enable(qlt->htable[i]);
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
		kmem_free(qlt->htable, qlt->intr_size);
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
	mutex_init(&qlt->req_lock, 0, MUTEX_DRIVER,
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
	mutex_destroy(&qlt->req_lock);
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

	ret = ddi_intr_get_nintrs(qlt->dip, itype, &count);
	if (ret != DDI_SUCCESS || count == 0) {
		return (DDI_FAILURE);
	}
	ret = ddi_intr_get_navail(qlt->dip, itype, &avail);
	if (ret != DDI_SUCCESS || avail == 0) {
		return (DDI_FAILURE);
	}
	if (avail < count) {
		stmf_trace(qlt->qlt_port_alias,
		    "qlt_setup_msix: nintrs=%d,avail=%d", count, avail);
	}

	qlt->intr_size = count * sizeof (ddi_intr_handle_t);
	qlt->htable = kmem_zalloc(qlt->intr_size, KM_SLEEP);
	ret = ddi_intr_alloc(qlt->dip, qlt->htable, itype,
	    DDI_INTR_ALLOC_NORMAL, count, &actual, 0);
	/* we need at least 2 interrupt vectors */
	if (ret != DDI_SUCCESS || actual < 2) {
		ret = DDI_FAILURE;
		goto release_intr;
	}
	if (actual < count) {
		QLT_LOG(qlt->qlt_port_alias, "qlt_setup_msix: "
		    "requested: %d, received: %d\n",
		    count, actual);
	}

	qlt->intr_cnt = actual;
	ret =  ddi_intr_get_pri(qlt->htable[0], &qlt->intr_pri);
	if (ret != DDI_SUCCESS) {
		ret = DDI_FAILURE;
		goto release_intr;
	}
	qlt_init_mutex(qlt);
	for (i = 0; i < actual; i++) {
		ret = ddi_intr_add_handler(qlt->htable[i], qlt_isr,
		    qlt, INT2PTR(i, void *));
		if (ret != DDI_SUCCESS)
			goto release_mutex;
	}

	(void) ddi_intr_get_cap(qlt->htable[0], &qlt->intr_cap);
	qlt->intr_flags |= QLT_INTR_MSIX;
	return (DDI_SUCCESS);

release_mutex:
	qlt_destroy_mutex(qlt);
release_intr:
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(qlt->htable[i]);
free_mem:
	kmem_free(qlt->htable, qlt->intr_size);
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

	/* get the # of interrupts */
	ret = ddi_intr_get_nintrs(qlt->dip, itype, &count);
	if (ret != DDI_SUCCESS || count == 0) {
		return (DDI_FAILURE);
	}
	ret = ddi_intr_get_navail(qlt->dip, itype, &avail);
	if (ret != DDI_SUCCESS || avail == 0) {
		return (DDI_FAILURE);
	}
	if (avail < count) {
		QLT_LOG(qlt->qlt_port_alias,
		    "qlt_setup_msi: nintrs=%d, avail=%d", count, avail);
	}
	/* MSI requires only 1 interrupt. */
	count = 1;

	/* allocate interrupt */
	qlt->intr_size = count * sizeof (ddi_intr_handle_t);
	qlt->htable = kmem_zalloc(qlt->intr_size, KM_SLEEP);
	ret = ddi_intr_alloc(qlt->dip, qlt->htable, itype,
	    0, count, &actual, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS || actual == 0) {
		ret = DDI_FAILURE;
		goto free_mem;
	}
	if (actual < count) {
		QLT_LOG(qlt->qlt_port_alias, "qlt_setup_msi: "
		    "requested: %d, received:%d",
		    count, actual);
	}
	qlt->intr_cnt = actual;

	/*
	 * Get priority for first msi, assume remaining are all the same.
	 */
	ret =  ddi_intr_get_pri(qlt->htable[0], &qlt->intr_pri);
	if (ret != DDI_SUCCESS) {
		ret = DDI_FAILURE;
		goto release_intr;
	}
	qlt_init_mutex(qlt);

	/* add handler */
	for (i = 0; i < actual; i++) {
		ret = ddi_intr_add_handler(qlt->htable[i], qlt_isr,
		    qlt, INT2PTR(i, void *));
		if (ret != DDI_SUCCESS)
			goto release_mutex;
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
	kmem_free(qlt->htable, qlt->intr_size);
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
		return (DDI_FAILURE);
	}

	qlt->intr_size = sizeof (ddi_intr_handle_t);
	qlt->htable = kmem_zalloc(qlt->intr_size, KM_SLEEP);
	ret = ddi_intr_alloc(qlt->dip, qlt->htable, itype,
	    DDI_INTR_ALLOC_NORMAL, count, &actual, 0);
	if (ret != DDI_SUCCESS || actual != 1) {
		ret = DDI_FAILURE;
		goto free_mem;
	}

	qlt->intr_cnt = actual;
	ret =  ddi_intr_get_pri(qlt->htable[0], &qlt->intr_pri);
	if (ret != DDI_SUCCESS) {
		ret = DDI_FAILURE;
		goto release_intr;
	}
	qlt_init_mutex(qlt);
	ret = ddi_intr_add_handler(qlt->htable[0], qlt_isr, qlt, 0);
	if (ret != DDI_SUCCESS)
		goto release_mutex;

	qlt->intr_flags |= QLT_INTR_FIXED;
	return (DDI_SUCCESS);

release_mutex:
	qlt_destroy_mutex(qlt);
release_intr:
	(void) ddi_intr_free(qlt->htable[0]);
free_mem:
	kmem_free(qlt->htable, qlt->intr_size);
	qlt->htable = NULL;
	qlt_release_intr(qlt);
	return (ret);
}


static int
qlt_setup_interrupts(qlt_state_t *qlt)
{
#if defined(__sparc)
	int itypes = 0;
#endif

/*
 * x86 has a bug in the ddi_intr_block_enable/disable area (6562198). So use
 * MSI for sparc only for now.
 */
#if defined(__sparc)
	if (ddi_intr_get_supported_types(qlt->dip, &itypes) != DDI_SUCCESS) {
		itypes = DDI_INTR_TYPE_FIXED;
	}

	if (qlt_enable_msix && (itypes & DDI_INTR_TYPE_MSIX)) {
		if (qlt_setup_msix(qlt) == DDI_SUCCESS)
			return (DDI_SUCCESS);
	}
	if (itypes & DDI_INTR_TYPE_MSI) {
		if (qlt_setup_msi(qlt) == DDI_SUCCESS)
			return (DDI_SUCCESS);
	}
#endif
	return (qlt_setup_fixed(qlt));
}

/*
 * Filling the hba attributes
 */
void
qlt_populate_hba_fru_details(struct fct_local_port *port,
    struct fct_port_attrs *port_attrs)
{
	caddr_t	bufp;
	int len;
	qlt_state_t *qlt = (qlt_state_t *)port->port_fca_private;

	(void) snprintf(port_attrs->manufacturer, FCHBA_MANUFACTURER_LEN,
	    "QLogic Corp.");
	(void) snprintf(port_attrs->driver_name, FCHBA_DRIVER_NAME_LEN,
	    "%s", QLT_NAME);
	(void) snprintf(port_attrs->driver_version, FCHBA_DRIVER_VERSION_LEN,
	    "%s", QLT_VERSION);
	port_attrs->serial_number[0] = '\0';
	port_attrs->hardware_version[0] = '\0';

	(void) snprintf(port_attrs->firmware_version,
	    FCHBA_FIRMWARE_VERSION_LEN, "%d.%d.%d", qlt->fw_major,
	    qlt->fw_minor, qlt->fw_subminor);

	/* Get FCode version */
	if (ddi_getlongprop(DDI_DEV_T_ANY, qlt->dip, PROP_LEN_AND_VAL_ALLOC |
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "version", (caddr_t)&bufp,
	    (int *)&len) == DDI_PROP_SUCCESS) {
		(void) snprintf(port_attrs->option_rom_version,
		    FCHBA_OPTION_ROM_VERSION_LEN, "%s", bufp);
		kmem_free(bufp, len);
		bufp = NULL;
	} else {
		(void) snprintf(port_attrs->option_rom_version,
		    FCHBA_OPTION_ROM_VERSION_LEN, "%s",
#ifdef __sparc
		    "No Fcode found");
#else
		    "N/A");
#endif
	}
	port_attrs->vendor_specific_id = qlt->nvram->subsystem_vendor_id[0] |
	    qlt->nvram->subsystem_vendor_id[1] << 8;

	port_attrs->max_frame_size = qlt->nvram->max_frame_length[1] << 8 |
	    qlt->nvram->max_frame_length[0];

	port_attrs->supported_cos = 0x10000000;
	port_attrs->supported_speed = PORT_SPEED_1G |
	    PORT_SPEED_2G | PORT_SPEED_4G;
	if (qlt->qlt_25xx_chip)
		port_attrs->supported_speed |= PORT_SPEED_8G;

	(void) snprintf(port_attrs->model, FCHBA_MODEL_LEN, "%s",
	    qlt->nvram->model_name);
	(void) snprintf(port_attrs->model_description,
	    FCHBA_MODEL_DESCRIPTION_LEN, "%s", qlt->nvram->model_name);
}

fct_status_t
qlt_port_start(caddr_t arg)
{
	qlt_state_t *qlt = (qlt_state_t *)arg;
	fct_local_port_t *port;
	fct_dbuf_store_t *fds;

	if (qlt_dmem_init(qlt) != QLT_SUCCESS) {
		return (FCT_FAILURE);
	}
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

	if (fct_register_local_port(port) != FCT_SUCCESS) {
		goto qlt_pstart_fail_2_5;
	}

	return (QLT_SUCCESS);

qlt_pstart_fail_3:
	(void) fct_deregister_local_port(port);
qlt_pstart_fail_2_5:
	fct_free(fds);
qlt_pstart_fail_2:
	fct_free(port);
	qlt->qlt_port = NULL;
qlt_pstart_fail_1:
	qlt_dmem_fini(qlt);
	return (QLT_FAILURE);
}

fct_status_t
qlt_port_stop(caddr_t arg)
{
	qlt_state_t *qlt = (qlt_state_t *)arg;

	if (fct_deregister_local_port(qlt->qlt_port) != FCT_SUCCESS)
		return (QLT_FAILURE);
	fct_free(qlt->qlt_port->port_fds);
	fct_free(qlt->qlt_port);
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
	int		instance;
	fct_status_t	ret;
	uint16_t	rcount;
	caddr_t		icb;
	mbox_cmd_t	*mcp;
	uint8_t		*elsbmp;

	instance = ddi_get_instance(qlt->dip);

	/* XXX Make sure a sane state */

	if ((ret = qlt_reset_chip_and_download_fw(qlt, 0)) != QLT_SUCCESS) {
		cmn_err(CE_NOTE, "reset chip failed %llx", (long long)ret);
		return (ret);
	}

	bzero(qlt->queue_mem_ptr, TOTAL_DMA_MEM_SIZE);

	/* Get resource count */
	REG_WR16(qlt, REG_MBOX(0), 0x42);
	ret = qlt_raw_mailbox_command(qlt);
	rcount = REG_RD16(qlt, REG_MBOX(3));
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
	if (ret != QLT_SUCCESS)
		return (ret);

	/* Enable PUREX */
	REG_WR16(qlt, REG_MBOX(0), 0x38);
	REG_WR16(qlt, REG_MBOX(1), 0x0400);
	REG_WR16(qlt, REG_MBOX(2), 0x0);
	REG_WR16(qlt, REG_MBOX(3), 0x0);
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
	if (ret != QLT_SUCCESS) {
		cmn_err(CE_NOTE, "Enable PUREX failed");
		return (ret);
	}

	/* Pass ELS bitmap to fw */
	REG_WR16(qlt, REG_MBOX(0), 0x59);
	REG_WR16(qlt, REG_MBOX(1), 0x0500);
	elsbmp = (uint8_t *)qlt->queue_mem_ptr + MBOX_DMA_MEM_OFFSET;
	bzero(elsbmp, 32);
	da = qlt->queue_mem_cookie.dmac_laddress;
	da += MBOX_DMA_MEM_OFFSET;
	REG_WR16(qlt, REG_MBOX(3), da & 0xffff);
	da >>= 16;
	REG_WR16(qlt, REG_MBOX(2), da & 0xffff);
	da >>= 16;
	REG_WR16(qlt, REG_MBOX(7), da & 0xffff);
	da >>= 16;
	REG_WR16(qlt, REG_MBOX(6), da & 0xffff);
	SETELSBIT(elsbmp, ELS_OP_PLOGI);
	SETELSBIT(elsbmp, ELS_OP_LOGO);
	SETELSBIT(elsbmp, ELS_OP_ABTX);
	SETELSBIT(elsbmp, ELS_OP_ECHO);
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
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
	if (ret != QLT_SUCCESS) {
		cmn_err(CE_NOTE, "Set ELS Bitmap failed ret=%llx, "
		    "elsbmp0=%x elabmp1=%x", (long long)ret, elsbmp[0],
		    elsbmp[1]);
		return (ret);
	}

	/* Init queue pointers */
	REG_WR32(qlt, REG_REQ_IN_PTR, 0);
	REG_WR32(qlt, REG_REQ_OUT_PTR, 0);
	REG_WR32(qlt, REG_RESP_IN_PTR, 0);
	REG_WR32(qlt, REG_RESP_OUT_PTR, 0);
	REG_WR32(qlt, REG_PREQ_IN_PTR, 0);
	REG_WR32(qlt, REG_PREQ_OUT_PTR, 0);
	REG_WR32(qlt, REG_ATIO_IN_PTR, 0);
	REG_WR32(qlt, REG_ATIO_OUT_PTR, 0);
	qlt->req_ndx_to_fw = qlt->req_ndx_from_fw = 0;
	qlt->req_available = REQUEST_QUEUE_ENTRIES - 1;
	qlt->resp_ndx_to_fw = qlt->resp_ndx_from_fw = 0;
	qlt->preq_ndx_to_fw = qlt->preq_ndx_from_fw = 0;
	qlt->atio_ndx_to_fw = qlt->atio_ndx_from_fw = 0;

	/*
	 * XXX support for tunables. Also should we cache icb ?
	 */
	mcp = qlt_alloc_mailbox_command(qlt, 0x80);
	if (mcp == NULL) {
		return (STMF_ALLOC_FAILURE);
	}
	icb = (caddr_t)mcp->dbuf->db_sglist[0].seg_addr;
	bzero(icb, 0x80);
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
	DMEM_WR16(qlt, icb+0x28, 100);	/* ms of NOS/OLS for Link down */
	DMEM_WR16(qlt, icb+0x2a, PRIORITY_QUEUE_ENTRIES);
	DMEM_WR64(qlt, icb+0x2c, da+REQUEST_QUEUE_OFFSET);
	DMEM_WR64(qlt, icb+0x34, da+RESPONSE_QUEUE_OFFSET);
	DMEM_WR64(qlt, icb+0x3c, da+PRIORITY_QUEUE_OFFSET);
	DMEM_WR16(qlt, icb+0x4e, ATIO_QUEUE_ENTRIES);
	DMEM_WR64(qlt, icb+0x50, da+ATIO_QUEUE_OFFSET);
	DMEM_WR16(qlt, icb+0x58, 2);	/* Interrupt delay Timer */
	DMEM_WR16(qlt, icb+0x5a, 4);	/* Login timeout (secs) */
	DMEM_WR32(qlt, icb+0x5c, BIT_11 | BIT_5 | BIT_4 |
				BIT_2 | BIT_1 | BIT_0);
	DMEM_WR32(qlt, icb+0x60, BIT_5);
	DMEM_WR32(qlt, icb+0x64, BIT_14 | BIT_8 | BIT_7 | BIT_4);
	qlt_dmem_dma_sync(mcp->dbuf, DDI_DMA_SYNC_FORDEV);
	mcp->to_fw[0] = 0x60;

	/*
	 * This is the 1st command adter adapter initialize which will
	 * use interrupts and regular mailbox interface.
	 */
	qlt->mbox_io_state = MBOX_STATE_READY;
	qlt_enable_intr(qlt);
	qlt->qlt_intr_enabled = 1;
	REG_WR32(qlt, REG_INTR_CTRL, ENABLE_RISC_INTR);
	/* Issue mailbox to firmware */
	ret = qlt_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS) {
		cmn_err(CE_NOTE, "qlt(%d) init fw failed %llx, intr status %x",
		    instance, (long long)ret, REG_RD32(qlt, REG_INTR_STATUS));
	}

	mcp->to_fw_mask = BIT_0;
	mcp->from_fw_mask = BIT_0 | BIT_1;
	mcp->to_fw[0] = 0x28;
	ret = qlt_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS) {
		cmn_err(CE_NOTE, "qlt(%d) get_fw_options %llx", instance,
		    (long long)ret);
	}

	qlt_free_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS)
		return (ret);
	return (FCT_SUCCESS);
}

fct_status_t
qlt_port_offline(qlt_state_t *qlt)
{
	int		retries;

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
	qlt_disable_intr(qlt);
	mutex_enter(&qlt->intr_lock);
	qlt->qlt_intr_enabled = 0;
	(void) qlt_reset_chip_and_download_fw(qlt, 1);
	drv_usecwait(20);
	qlt->intr_sneak_counter = 0;
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
	mcp->to_fw[0] = 0x20;
	mcp->to_fw_mask |= BIT_0;
	mcp->from_fw_mask |= BIT_0 | BIT_1 | BIT_2 | BIT_3 | BIT_6 | BIT_7;
	/* Issue mailbox to firmware */
	ret = qlt_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS) {
		if ((mcp->from_fw[0] == 0x4005) && (mcp->from_fw[1] == 7)) {
			/* Firmware is not ready */
			if (ddi_get_lbolt() < et) {
				delay(drv_usectohz(50000));
				goto link_info_retry;
			}
		}
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
			QLT_LOG(qlt->qlt_port_alias, "Unknown link speed "
			    "reported by fw %x", mcp->from_fw[6]);
		}
		qlt->cur_topology = li->port_topology;
		fc_ret = FCT_SUCCESS;
	}
	qlt_free_mailbox_command(qlt, mcp);

	if ((fc_ret == FCT_SUCCESS) && (li->port_fca_flogi_done)) {
		mcp = qlt_alloc_mailbox_command(qlt, 64);
		mcp->to_fw[0] = 0x64;
		mcp->to_fw[1] = 0x7FE;
		mcp->to_fw[10] = 0;
		mcp->to_fw_mask |= BIT_0 | BIT_1 | BIT_10;
		fc_ret = qlt_mailbox_command(qlt, mcp);
		if (fc_ret != QLT_SUCCESS) {
			stmf_trace(qlt->qlt_port_alias, "Attempt to get port "
			    "database for F_port failed, ret = %llx", fc_ret);
		} else {
			uint8_t *p;

			qlt_dmem_dma_sync(mcp->dbuf, DDI_DMA_SYNC_FORCPU);
			p = mcp->dbuf->db_sglist[0].seg_addr;
			bcopy(p + 0x18, li->port_rpwwn, 8);
			bcopy(p + 0x20, li->port_rnwwn, 8);
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
			ret = EINVAL;
			break;
		}
		mutex_enter(&qlt->qlt_ioctl_lock);
		if (!(qlt->qlt_ioctl_flags & QLT_FWDUMP_ISVALID)) {
			mutex_exit(&qlt->qlt_ioctl_lock);
			ret = ENODATA;
			iocd->stmf_error = QLTIO_NO_DUMP;
			break;
		}
		if (qlt->qlt_ioctl_flags & QLT_FWDUMP_INPROGRESS) {
			mutex_exit(&qlt->qlt_ioctl_lock);
			ret = EBUSY;
			iocd->stmf_error = QLTIO_DUMP_INPROGRESS;
			break;
		}
		if (qlt->qlt_ioctl_flags & QLT_FWDUMP_FETCHED_BY_USER) {
			mutex_exit(&qlt->qlt_ioctl_lock);
			ret = EEXIST;
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
		if (fct_port_shutdown(qlt->qlt_port, STMF_RFLAG_USER_REQUEST |
		    STMF_RFLAG_RESET | STMF_RFLAG_COLLECT_DEBUG_DUMP,
		    info) != FCT_SUCCESS) {
			ret = EIO;
		}
		break;
	case QLT_IOCTL_UPLOAD_FW:
		if ((iocd->stmf_ibuf_size < 1024) ||
		    (iocd->stmf_ibuf_size & 3)) {
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
			ret = EINVAL;
			iocd->stmf_error = QLTIO_INVALID_FW_SIZE;
			break;
		}
		if ((qlt->qlt_25xx_chip && ((intp[8] & 4) == 0)) ||
		    (!qlt->qlt_25xx_chip && ((intp[8] & 3) == 0))) {
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
			atomic_add_32(&qlt_loaded_counter, 1);
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
			atomic_add_32(&qlt_loaded_counter, -1);
		}
		break;

	case QLT_IOCTL_GET_FW_INFO:
		if (iocd->stmf_obuf_size != sizeof (qlt_fw_info_t)) {
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
		if (qlt->qlt_25xx_chip) {
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
			ret = EINVAL;
			break;
		}
		mcp = qlt_alloc_mailbox_command(qlt, 0);
		if (mcp == NULL) {
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

	default:
		QLT_LOG(qlt->qlt_port_alias, "qlt_ioctl: ioctl-0x%02X", cmd);
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

static void
qlt_ctl(struct fct_local_port *port, int cmd, void *arg)
{
	stmf_change_status_t		st;
	stmf_state_change_info_t	*ssci = (stmf_state_change_info_t *)arg;
	qlt_state_t			*qlt;

	ASSERT((cmd == FCT_CMD_PORT_ONLINE) ||
	    (cmd == FCT_CMD_PORT_OFFLINE) ||
	    (cmd == FCT_ACK_PORT_ONLINE_COMPLETE) ||
	    (cmd == FCT_ACK_PORT_OFFLINE_COMPLETE));

	qlt = (qlt_state_t *)port->port_fca_private;
	st.st_completion_status = FCT_SUCCESS;
	st.st_additional_info = NULL;

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
			qlt->qlt_change_state_flags = ssci->st_rflags;
			st.st_completion_status = qlt_port_offline(qlt);
			if (st.st_completion_status != STMF_SUCCESS) {
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
			if (fct_port_initialize(port,
			    qlt->qlt_change_state_flags,
			    "qlt_ctl FCT_ACK_PORT_OFFLINE_COMPLETE "
			    "with RLFLAG_RESET") != FCT_SUCCESS) {
				cmn_err(CE_WARN, "qlt_ctl: "
				    "fct_port_initialize failed, please use "
				    "stmfstate to start the port-%s manualy",
				    qlt->qlt_port_alias);
			}
		}
		break;
	}
}

/* ARGSUSED */
static fct_status_t
qlt_do_flogi(fct_local_port_t *port, fct_flogi_xchg_t *fx)
{
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
qlt_get_req_entries(qlt_state_t *qlt, uint32_t n)
{
	int try = 0;

	while (qlt->req_available < n) {
		uint32_t val1, val2, val3;
		val1 = REG_RD32(qlt, REG_REQ_OUT_PTR);
		val2 = REG_RD32(qlt, REG_REQ_OUT_PTR);
		val3 = REG_RD32(qlt, REG_REQ_OUT_PTR);
		if ((val1 != val2) || (val2 != val3))
			continue;

		qlt->req_ndx_from_fw = val1;
		qlt->req_available = REQUEST_QUEUE_ENTRIES - 1 -
			((qlt->req_ndx_to_fw - qlt->req_ndx_from_fw) &
			    (REQUEST_QUEUE_ENTRIES - 1));
		if (qlt->req_available < n) {
			if (try < 2) {
				drv_usecwait(100);
				try++;
				continue;
			} else {
				stmf_trace(qlt->qlt_port_alias,
				    "Req Q is full");
				return (NULL);
			}
		}
		break;
	}
	/* We dont change anything until the entries are sumitted */
	return (&qlt->req_ptr[qlt->req_ndx_to_fw << 6]);
}

/*
 * updates the req in ptr to fw. Assumes that req lock is held.
 */
void
qlt_submit_req_entries(qlt_state_t *qlt, uint32_t n)
{
	ASSERT(n >= 1);
	qlt->req_ndx_to_fw += n;
	qlt->req_ndx_to_fw &= REQUEST_QUEUE_ENTRIES - 1;
	qlt->req_available -= n;
	REG_WR32(qlt, REG_REQ_IN_PTR, qlt->req_ndx_to_fw);
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
qlt_reset_chip_and_download_fw(qlt_state_t *qlt, int reset_only)
{
	int cntr;
	uint32_t start_addr;
	fct_status_t ret;

	/* XXX: Switch off LEDs */

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

	/* Reset the Chip */
	REG_WR32(qlt, REG_CTRL_STATUS,
		DMA_SHUTDOWN_CTRL | PCI_X_XFER_CTRL | CHIP_SOFT_RESET);

	qlt->qlt_link_up = 0;

	drv_usecwait(100);

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
	if (reset_only)
		return (QLT_SUCCESS);

	/* Load the two segments */
	if (qlt->fw_code01 != NULL) {
		ret = qlt_load_risc_ram(qlt, qlt->fw_code01, qlt->fw_length01,
						qlt->fw_addr01);
		if (ret == QLT_SUCCESS) {
			ret = qlt_load_risc_ram(qlt, qlt->fw_code02,
			    qlt->fw_length02, qlt->fw_addr02);
		}
		start_addr = qlt->fw_addr01;
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
	if (ret != QLT_SUCCESS)
		return (ret);

	/* Verify Checksum */
	REG_WR16(qlt, REG_MBOX(0), 7);
	REG_WR16(qlt, REG_MBOX(1), (start_addr >> 16) & 0xffff);
	REG_WR16(qlt, REG_MBOX(2),  start_addr & 0xffff);
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
	if (ret != QLT_SUCCESS)
		return (ret);

	/* Execute firmware */
	REG_WR16(qlt, REG_MBOX(0), 2);
	REG_WR16(qlt, REG_MBOX(1), (start_addr >> 16) & 0xffff);
	REG_WR16(qlt, REG_MBOX(2),  start_addr & 0xffff);
	REG_WR16(qlt, REG_MBOX(3), 0);
	REG_WR16(qlt, REG_MBOX(4), 1);	/* 25xx enable additional credits */
	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
	if (ret != QLT_SUCCESS)
		return (ret);

	/* Get revisions (About Firmware) */
	REG_WR16(qlt, REG_MBOX(0), 8);
	ret = qlt_raw_mailbox_command(qlt);
	qlt->fw_major = REG_RD16(qlt, REG_MBOX(1));
	qlt->fw_minor = REG_RD16(qlt, REG_MBOX(2));
	qlt->fw_subminor = REG_RD16(qlt, REG_MBOX(3));
	qlt->fw_endaddrlo = REG_RD16(qlt, REG_MBOX(4));
	qlt->fw_endaddrhi = REG_RD16(qlt, REG_MBOX(5));
	qlt->fw_attr = REG_RD16(qlt, REG_MBOX(6));
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
	if (ret != QLT_SUCCESS)
		return (ret);

	return (QLT_SUCCESS);
}

/*
 * Used only from qlt_reset_chip_and_download_fw().
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
		REG_WR16(qlt, REG_MBOX(0), 0x0B);
		REG_WR16(qlt, REG_MBOX(1), risc_addr & 0xffff);
		REG_WR16(qlt, REG_MBOX(8), ((cur_risc_addr >> 16) & 0xffff));
		REG_WR16(qlt, REG_MBOX(3), da & 0xffff);
		da >>= 16;
		REG_WR16(qlt, REG_MBOX(2), da & 0xffff);
		da >>= 16;
		REG_WR16(qlt, REG_MBOX(7), da & 0xffff);
		da >>= 16;
		REG_WR16(qlt, REG_MBOX(6), da & 0xffff);
		REG_WR16(qlt, REG_MBOX(5), words_being_sent & 0xffff);
		REG_WR16(qlt, REG_MBOX(4), (words_being_sent >> 16) & 0xffff);
		ret = qlt_raw_mailbox_command(qlt);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
		if (ret != QLT_SUCCESS)
			return (ret);
		words_sent += words_being_sent;
	}
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
 * qlt_reset_chip_and_download_fw()
 */
static fct_status_t
qlt_raw_mailbox_command(qlt_state_t *qlt)
{
	int cntr = 0;
	uint32_t status;

	REG_WR32(qlt, REG_HCCR, HCCR_CMD_SET_HOST_TO_RISC_INTR);
	while ((REG_RD32(qlt, REG_INTR_STATUS) & RISC_INTR_REQUEST) == 0) {
		cntr++;
		if (cntr == 100)
			return (QLT_MAILBOX_STUCK);
		delay(drv_usectohz(10000));
	}
	status = (REG_RD32(qlt, REG_RISC_STATUS) & 0xff);
	if ((status == 1) || (status == 2) ||
	    (status == 0x10) || (status == 0x11)) {
		uint16_t mbox0 = REG_RD16(qlt, REG_MBOX(0));
		if (mbox0 == 0x4000)
			return (QLT_SUCCESS);
		else
			return (QLT_MBOX_FAILED | mbox0);
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
		mcp->to_fw[3] = da & 0xffff;
		da >>= 16;
		mcp->to_fw[2] = da & 0xffff;
		da >>= 16;
		mcp->to_fw[7] = da & 0xffff;
		da >>= 16;
		mcp->to_fw[6] = da & 0xffff;
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
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_SET_HOST_TO_RISC_INTR);

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
	if (mcp->from_fw[0] != 0x4000)
		return (QLT_MBOX_FAILED | mcp->from_fw[0]);

	return (QLT_SUCCESS);
}

/*
 * **SHOULD ONLY BE CALLED FROM INTERRUPT CONTEXT. DO NOT CALL ELSEWHERE**
 */
/* ARGSUSED */
static uint_t
qlt_isr(caddr_t arg, caddr_t arg2)
{
	qlt_state_t	*qlt = (qlt_state_t *)arg;
	int		instance;
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
	 * XXX take care for MSI case. disable intrs
	 * Its gonna be complicated becasue of the max iterations.
	 * as hba will have posted the intr which did not go on PCI
	 * but we did not service it either becasue of max iterations.
	 * Maybe offload the intr on a different thread.
	 */
	instance = ddi_get_instance(qlt->dip);
	intr_loop_count = 0;

	REG_WR32(qlt, REG_INTR_CTRL, 0);

intr_again:;
	/* First check for high performance path */
	intr_type = risc_status & 0xff;
	if (intr_type == 0x1C) {
		REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
		qlt->atio_ndx_from_fw = risc_status >> 16;
		qlt_handle_atio_queue_update(qlt);
	} else if (intr_type == 0x13) {
		REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
		qlt->resp_ndx_from_fw = risc_status >> 16;
		qlt_handle_resp_queue_update(qlt);
		/* XXX what about priority queue */
	} else if (intr_type == 0x1D) {
		qlt->atio_ndx_from_fw = REG_RD32(qlt, REG_ATIO_IN_PTR);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
		qlt->resp_ndx_from_fw = risc_status >> 16;
		qlt_handle_atio_queue_update(qlt);
		qlt_handle_resp_queue_update(qlt);
	} else if (intr_type == 0x12) {
		uint16_t code = risc_status >> 16;
		uint16_t mbox1 = REG_RD16(qlt, REG_MBOX(1));
		uint16_t mbox2 = REG_RD16(qlt, REG_MBOX(2));
		uint16_t mbox5 = REG_RD16(qlt, REG_MBOX(5));
		uint16_t mbox6 = REG_RD16(qlt, REG_MBOX(6));

		REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
		stmf_trace(qlt->qlt_port_alias, "Async event %x mb1=%x mb2=%x,"
		    " mb5=%x, mb6=%x", code, mbox1, mbox2, mbox5, mbox6);
		cmn_err(CE_NOTE, "!qlt(%d): Async event %x mb1=%x mb2=%x,"
		    " mb5=%x, mb6=%x", instance, code, mbox1, mbox2, mbox5,
		    mbox6);

		if ((code == 0x8030) || (code == 0x8010) || (code == 0x8013)) {
			if (qlt->qlt_link_up) {
				fct_handle_event(qlt->qlt_port,
				    FCT_EVENT_LINK_RESET, 0, 0);
			}
		} else if (code == 0x8012) {
			qlt->qlt_link_up = 0;
			fct_handle_event(qlt->qlt_port, FCT_EVENT_LINK_DOWN,
						0, 0);
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
			default:
				qlt->link_speed = PORT_SPEED_UNKNOWN;
			}
			qlt->qlt_link_up = 1;
			fct_handle_event(qlt->qlt_port, FCT_EVENT_LINK_UP,
						0, 0);
		} else if (code == 0x8002) {
			(void) snprintf(info, 80,
			    "Got 8002, mb1=%x mb2=%x mb5=%x mb6=%x",
			    mbox1, mbox2, mbox5, mbox6);
			info[79] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET |
			    STMF_RFLAG_COLLECT_DEBUG_DUMP, info);
		}
	} else if ((intr_type == 0x10) || (intr_type == 0x11)) {
		/* Handle mailbox completion */
		mutex_enter(&qlt->mbox_lock);
		if (qlt->mbox_io_state != MBOX_STATE_CMD_RUNNING) {
			cmn_err(CE_WARN, "qlt(%d): mailbox completion received"
			    " when driver wasn't waiting for it %d",
				instance, qlt->mbox_io_state);
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
		REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
		cv_broadcast(&qlt->mbox_cv);
		mutex_exit(&qlt->mbox_lock);
	} else {
		cmn_err(CE_WARN, "qlt(%d): Unknown intr type 0x%x",
		    instance, intr_type);
		REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_TO_PCI_INTR);
	}

	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting */
	risc_status = REG_RD32(qlt, REG_RISC_STATUS);
	if ((risc_status & BIT_15) &&
	    (++intr_loop_count < QLT_MAX_ITERATIONS_PER_INTR)) {
		goto intr_again;
	}

	REG_WR32(qlt, REG_INTR_CTRL, ENABLE_RISC_INTR);

	mutex_exit(&qlt->intr_lock);
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
		return (QLT_FLASH_TIMEOUT);
	} else if (REG_RD32(qlt, REG_CTRL_STATUS) & FLASH_ERROR) {
		return (QLT_FLASH_ACCESS_ERROR);
	}

	*bp = REG_RD32(qlt, REG_FLASH_DATA);

	return (QLT_SUCCESS);
}

fct_status_t
qlt_read_nvram(qlt_state_t *qlt)
{
	uint32_t		index, addr, chksum;
	uint32_t		val, *ptr;
	fct_status_t		ret;
	qlt_nvram_t		*nv;
	uint64_t		empty_node_name = 0;

	if (qlt->qlt_25xx_chip) {
		addr = REG_RD32(qlt, REG_CTRL_STATUS) & FUNCTION_NUMBER ?
			QLT25_NVRAM_FUNC1_ADDR : QLT25_NVRAM_FUNC0_ADDR;
	} else {
		addr = REG_RD32(qlt, REG_CTRL_STATUS) & FUNCTION_NUMBER ?
				NVRAM_FUNC1_ADDR : NVRAM_FUNC0_ADDR;
	}
	mutex_enter(&qlt_global_lock);

	/* Pause RISC. */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_SET_RISC_PAUSE);
	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting. */

	/* Get NVRAM data and calculate checksum. */
	ptr = (uint32_t *)qlt->nvram;
	chksum = 0;
	for (index = 0; index < sizeof (qlt_nvram_t) / 4; index++) {
		ret = qlt_read_flash_word(qlt, addr++, &val);
		if (ret != QLT_SUCCESS) {
			mutex_exit(&qlt_global_lock);
			return (ret);
		}
		chksum += val;
		*ptr = LE_32(val);
		ptr++;
	}

	/* Release RISC Pause */
	REG_WR32(qlt, REG_HCCR, HCCR_CMD_CLEAR_RISC_PAUSE);
	(void) REG_RD32(qlt, REG_HCCR);	/* PCI Posting. */

	mutex_exit(&qlt_global_lock);

	/* Sanity check NVRAM Data */
	nv = qlt->nvram;
	if (chksum || nv->id[0] != 'I' || nv->id[1] != 'S' ||
	    nv->id[2] != 'P' || nv->id[3] != ' ' ||
	    (nv->nvram_version[0] | nv->nvram_version[1]) == 0) {
		return (QLT_BAD_NVRAM_DATA);
	}

	/* If node name is zero, hand craft it from port name */
	if (bcmp(nv->node_name, &empty_node_name, 8) == 0) {
		bcopy(nv->port_name, nv->node_name, 8);
		nv->node_name[0] = nv->node_name[0] & ~BIT_0;
		nv->port_name[0] = nv->node_name[0] | BIT_0;
	}

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
		    + (qlt->atio_ndx_to_fw << 6), (ATIO_QUEUE_ENTRIES -
		    qlt->atio_ndx_to_fw) << 6, DDI_DMA_SYNC_FORCPU);
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
		    ATIO_QUEUE_OFFSET,
		    qlt->atio_ndx_from_fw << 6, DDI_DMA_SYNC_FORCPU);
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
		case 0x0d:	/* INOT */
			qlt_handle_inot(qlt, atio);
			break;
		case 0x06:	/* ATIO */
			qlt_handle_atio(qlt, atio);
			break;
		default:
			cmn_err(CE_WARN, "qlt_handle_atio_queue_update: "
			    "atio[0] is %x, qlt-%p", atio[0], (void *)qlt);
			break;
		}
		qlt->atio_ndx_to_fw = (qlt->atio_ndx_to_fw + ent_cnt) &
					(ATIO_QUEUE_ENTRIES - 1);
		total_ent -= ent_cnt;
	} while (total_ent > 0);
	REG_WR32(qlt, REG_ATIO_OUT_PTR, qlt->atio_ndx_to_fw);
}

uint32_t
qlt_sync_resp_queue(qlt_state_t *qlt)
{
	uint32_t total_ent;

	if (qlt->resp_ndx_from_fw > qlt->resp_ndx_to_fw) {
		total_ent = qlt->resp_ndx_from_fw - qlt->resp_ndx_to_fw;
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
		    RESPONSE_QUEUE_OFFSET
		    + (qlt->resp_ndx_to_fw << 6), total_ent << 6,
		    DDI_DMA_SYNC_FORCPU);
	} else {
		total_ent = RESPONSE_QUEUE_ENTRIES - qlt->resp_ndx_to_fw +
			qlt->resp_ndx_from_fw;
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
		    RESPONSE_QUEUE_OFFSET
		    + (qlt->resp_ndx_to_fw << 6), (RESPONSE_QUEUE_ENTRIES -
		    qlt->resp_ndx_to_fw) << 6, DDI_DMA_SYNC_FORCPU);
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
		    RESPONSE_QUEUE_OFFSET,
		    qlt->resp_ndx_from_fw << 6, DDI_DMA_SYNC_FORCPU);
	}
	return (total_ent);
}

void
qlt_handle_resp_queue_update(qlt_state_t *qlt)
{
	uint32_t total_ent;
	uint8_t c;

	if (qlt->resp_ndx_to_fw == qlt->resp_ndx_from_fw)
		return;

	total_ent = qlt_sync_resp_queue(qlt);

	do {
		caddr_t resp = &qlt->resp_ptr[qlt->resp_ndx_to_fw << 6];
		uint32_t ent_cnt;

		ent_cnt = (uint32_t)(resp[1]);
		if (ent_cnt > total_ent) {
			break;
		}
		switch ((uint8_t)(resp[0])) {
		case 0x12:	/* CTIO completion */
			qlt_handle_ctio_completion(qlt, (uint8_t *)resp);
			break;
		case 0x0e:	/* NACK */
			/* Do Nothing */
			break;
		case 0x29:	/* CT PassThrough */
			qlt_handle_ct_completion(qlt, (uint8_t *)resp);
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
			c = ((uint8_t)resp[0x1f]) >> 5;
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
			qlt_handle_rcvd_abts(qlt, (uint8_t *)resp);
			break;
		case 0x55:	/* ABTS completion */
			qlt_handle_abts_completion(qlt, (uint8_t *)resp);
			break;
		}
		qlt->resp_ndx_to_fw = (qlt->resp_ndx_to_fw + ent_cnt) &
					(RESPONSE_QUEUE_ENTRIES - 1);
		total_ent -= ent_cnt;
	} while (total_ent > 0);
	REG_WR32(qlt, REG_RESP_OUT_PTR, qlt->resp_ndx_to_fw);
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
	mcp->to_fw[0] = 0x7C;	/* GET ID LIST */
	mcp->to_fw[8] = 2048 * 8;
	mcp->to_fw_mask |= BIT_8;
	mcp->from_fw_mask |= BIT_1 | BIT_2;

	ret = qlt_mailbox_command(qlt, mcp);
	if (ret != QLT_SUCCESS) {
		cmn_err(CE_WARN, "GET ID list failed, ret = %llx, mb0=%x, "
		    "mb1=%x, mb2=%x", (long long)ret, mcp->from_fw[0],
		    mcp->from_fw[1], mcp->from_fw[2]);
		qlt_free_mailbox_command(qlt, mcp);
		return (ret);
	}
	qlt_dmem_dma_sync(mcp->dbuf, DDI_DMA_SYNC_FORCPU);
	p = mcp->dbuf->db_sglist[0].seg_addr;
	for (n = 0; n < mcp->from_fw[1]; n++) {
		ent_id = LE_32(*((uint32_t *)p)) & 0xFFFFFF;
		h = (uint16_t)p[4] | (((uint16_t)p[5]) << 8);
		if (ent_id == id) {
			found = 1;
			*ret_handle = h;
			if ((cmd_handle != FCT_HANDLE_NONE) &&
			    (cmd_handle != h)) {
				cmn_err(CE_WARN, "login for portid %x came in "
				    "with handle %x, while the portid was "
				    "already using a different handle %x",
					id, cmd_handle, h);
				qlt_free_mailbox_command(qlt, mcp);
				return (QLT_FAILURE);
			}
			break;
		}
		if ((cmd_handle != FCT_HANDLE_NONE) && (h == cmd_handle)) {
			cmn_err(CE_WARN, "login for portid %x came in with "
			    "handle %x, while the handle was already in use "
			    "for portid %x", id, cmd_handle, ent_id);
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

	switch (rp->rp_id) {
	case 0xFFFFFC:	h = 0x7FC; break;
	case 0xFFFFFD:	h = 0x7FD; break;
	case 0xFFFFFE:	h = 0x7FE; break;
	case 0xFFFFFF:	h = 0x7FF; break;
	default:
		ret = qlt_portid_to_handle(
	    (qlt_state_t *)port->port_fca_private, rp->rp_id,
		login->cmd_rp_handle, &h);
		if (ret != FCT_SUCCESS)
			return (ret);
	}

	if (login->cmd_type == FCT_CMD_SOL_ELS) {
		ret = qlt_fill_plogi_req(port, rp, login);
	} else {
		ret = qlt_fill_plogi_resp(port, rp, login);
	}

	if (ret != FCT_SUCCESS)
		return (ret);

	if (h == FCT_HANDLE_NONE)
		return (FCT_SUCCESS);

	if (rp->rp_handle == FCT_HANDLE_NONE) {
		rp->rp_handle = h;
		return (FCT_SUCCESS);
	}

	if (rp->rp_handle == h)
		return (FCT_SUCCESS);

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

	mutex_enter(&qlt->preq_lock);
	req = (uint8_t *)qlt_get_preq_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->preq_lock);
		return (FCT_BUSY);
	}
	bzero(req, IOCB_SIZE);
	req[0] = 0x52; req[1] = 1;
	/* QMEM_WR32(qlt, (&req[4]), 0xffffffff);  */
	QMEM_WR16(qlt, (&req[0xA]), rp->rp_handle);
	QMEM_WR16(qlt, (&req[0xC]), 0x98); /* implicit logo */
	QMEM_WR32(qlt, (&req[0x10]), rp->rp_id);
	qlt->rp_id_in_dereg = rp->rp_id;
	qlt_submit_preq_entries(qlt, 1);

	dereg_req_timer = ddi_get_lbolt() + drv_usectohz(DEREG_RP_TIMEOUT);
	if (cv_timedwait(&qlt->rp_dereg_cv,
	    &qlt->preq_lock, dereg_req_timer) > 0) {
		ret = qlt->rp_dereg_status;
	} else {
		ret = FCT_BUSY;
	}
	qlt->rp_dereg_status = 0;
	qlt->rp_id_in_dereg = 0;
	mutex_exit(&qlt->preq_lock);
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
		cmn_err(CE_WARN, "handle_purex: payload is too large");
		goto cmd_null;
	}

	cmd = (fct_cmd_t *)fct_alloc(FCT_STRUCT_CMD_RCVD_ELS, payload_size +
	    GET_STRUCT_SIZE(qlt_cmd_t), 0);
	if (cmd == NULL) {
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
	els->els_req_size = payload_size;
	els->els_req_payload = GET_BYTE_OFFSET(qcmd,
	    GET_STRUCT_SIZE(qlt_cmd_t));
	qcmd->fw_xchg_addr = QMEM_RD32(qlt, (&resp[0x10]));
	cmd->cmd_rportid = remote_portid;
	cmd->cmd_lportid = ((uint32_t)(QMEM_RD16(qlt, (&resp[0x14])))) |
	    ((uint32_t)(resp[0x16])) << 16;
	cmd->cmd_oxid = QMEM_RD16(qlt, (&resp[0x26]));
	cmd->cmd_rxid = QMEM_RD16(qlt, (&resp[0x24]));
	pldptr = &resp[0x2C];
	bndrptr = (uint8_t *)(qlt->resp_ptr + (RESPONSE_QUEUE_ENTRIES << 6));
	for (i = 0, off = 0x2c; i < payload_size; i += 4) {
		/* Take care of fw's swapping of payload */
		els->els_req_payload[i] = pldptr[3];
		els->els_req_payload[i+1] = pldptr[2];
		els->els_req_payload[i+2] = pldptr[1];
		els->els_req_payload[i+3] = pldptr[0];
		pldptr += 4;
		if (pldptr == bndrptr)
			pldptr = (uint8_t *)qlt->resp_ptr;
		off += 4;
		if (off >= IOCB_SIZE) {
			off = 4;
			pldptr += 4;
		}
	}
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
	uint8_t *req;
	uint16_t flags;

	if (dbuf->db_handle == 0)
		qcmd->dbuf = dbuf;
	flags = ((uint16_t)qcmd->param.atio_byte3 & 0xf0) << 5;
	if (dbuf->db_flags & DB_DIRECTION_TO_RPORT) {
		flags |= 2;
		qlt_dmem_dma_sync(dbuf, DDI_DMA_SYNC_FORDEV);
	} else {
		flags |= 1;
	}

	if (dbuf->db_flags & DB_SEND_STATUS_GOOD)
		flags |= BIT_15;

	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->req_lock);
		return (FCT_BUSY);
	}
	bzero(req, IOCB_SIZE);
	req[0] = 0x12; req[1] = 0x1;
	req[2] = dbuf->db_handle;
	QMEM_WR32(qlt, req+4, cmd->cmd_handle);
	QMEM_WR16(qlt, req+8, cmd->cmd_rp->rp_handle);
	QMEM_WR16(qlt, req+10, 60);	/* 60 seconds timeout */
	req[12] = 1;
	QMEM_WR32(qlt, req+0x10, cmd->cmd_rportid);
	QMEM_WR32(qlt, req+0x14, qcmd->fw_xchg_addr);
	QMEM_WR16(qlt, req+0x1A, flags);
	QMEM_WR16(qlt, req+0x20, cmd->cmd_oxid);
	QMEM_WR32(qlt, req+0x24, dbuf->db_relative_offset);
	QMEM_WR32(qlt, req+0x2C, dbuf->db_data_size);
	QMEM_WR64(qlt, req+0x34, bctl->bctl_dev_addr);
	QMEM_WR32(qlt, req+0x34+8, dbuf->db_data_size);
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

	return (STMF_SUCCESS);
}

/*
 * We must construct proper FCP_RSP_IU now. Here we only focus on
 * the handling of FCP_SNS_INFO. If there's protocol failures (FCP_RSP_INFO),
 * we could have catched them before we enter here.
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

	/*
	 * Enter fast channel for non check condition
	 */
	if (task->task_scsi_status != STATUS_CHECK) {
		/*
		 * We will use mode1
		 */
		flags = BIT_6 | BIT_15 |
		    (((uint16_t)qcmd->param.atio_byte3 & 0xf0) << 5);
		scsi_status = (uint16_t)task->task_scsi_status;
		if (task->task_status_ctrl == TASK_SCTRL_OVER) {
			scsi_status |= BIT_10;
		} else if (task->task_status_ctrl == TASK_SCTRL_UNDER) {
			scsi_status |= BIT_11;
		}
		qcmd->dbuf_rsp_iu = NULL;

		/*
		 * Fillout CTIO type 7 IOCB
		 */
		mutex_enter(&qlt->req_lock);
		req = (uint8_t *)qlt_get_req_entries(qlt, 1);
		if (req == NULL) {
			mutex_exit(&qlt->req_lock);
			return (FCT_BUSY);
		}

		/*
		 * Common fields
		 */
		bzero(req, IOCB_SIZE);
		req[0x00] = 0x12;
		req[0x01] = 0x1;
		req[0x02] = BIT_7;	/* indicate if it's a pure status req */
		QMEM_WR32(qlt, req + 0x04, cmd->cmd_handle);
		QMEM_WR16(qlt, req + 0x08, cmd->cmd_rp->rp_handle);
		QMEM_WR32(qlt, req + 0x10, cmd->cmd_rportid);
		QMEM_WR32(qlt, req + 0x14, qcmd->fw_xchg_addr);

		/*
		 * Mode-specific fields
		 */
		QMEM_WR16(qlt, req + 0x1A, flags);
		QMEM_WR32(qlt, req + 0x1C, task->task_resid);
		QMEM_WR16(qlt, req + 0x20, cmd->cmd_oxid);
		QMEM_WR16(qlt, req + 0x22, scsi_status);

		/*
		 * Trigger FW to send SCSI status out
		 */
		qlt_submit_req_entries(qlt, 1);
		mutex_exit(&qlt->req_lock);
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
	flags = BIT_15 | (((uint16_t)qcmd->param.atio_byte3 & 0xf0) << 5);
	if (use_mode2) {
		flags |= BIT_7;

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
		fcp_rsp_iu[10] |= BIT_1;
		if (task->task_status_ctrl == TASK_SCTRL_OVER) {
			fcp_rsp_iu[10] |= BIT_2;
		} else if (task->task_status_ctrl == TASK_SCTRL_UNDER) {
			fcp_rsp_iu[10] |= BIT_3;
		}

		/*
		 * SCSI status code, byte11
		 */
		fcp_rsp_iu[11] = task->task_scsi_status;

		/*
		 * FCP_RESID (Overrun or underrun)
		 */
		fcp_rsp_iu[12] = (task->task_resid >> 24) & 0xFF;
		fcp_rsp_iu[13] = (task->task_resid >> 16) & 0xFF;
		fcp_rsp_iu[14] = (task->task_resid >>  8) & 0xFF;
		fcp_rsp_iu[15] = (task->task_resid >>  0) & 0xFF;

		/*
		 * FCP_SNS_LEN
		 */
		fcp_rsp_iu[18] = (task->task_sense_length >> 8) & 0xFF;
		fcp_rsp_iu[19] = (task->task_sense_length >> 0) & 0xFF;

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
		flags |= BIT_6;

		scsi_status = (uint16_t)task->task_scsi_status;
		if (task->task_status_ctrl == TASK_SCTRL_OVER) {
			scsi_status |= BIT_10;
		} else if (task->task_status_ctrl == TASK_SCTRL_UNDER) {
			scsi_status |= BIT_11;
		}
		if (task->task_sense_length) {
			scsi_status |= BIT_9;
		}
		bcopy(task->task_sense_data, sensbuf, task->task_sense_length);
		qcmd->dbuf_rsp_iu = NULL;
	}

	/*
	 * Fillout CTIO type 7 IOCB
	 */
	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->req_lock);
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
	QMEM_WR32(qlt, req + 0x04, cmd->cmd_handle);
	QMEM_WR16(qlt, req + 0x08, cmd->cmd_rp->rp_handle);
	QMEM_WR16(qlt, req + 0x0A, 0);	/* not timed by FW */
	if (use_mode2) {
		QMEM_WR16(qlt, req+0x0C, 1);	/* FCP RSP IU data field */
	}
	QMEM_WR32(qlt, req + 0x10, cmd->cmd_rportid);
	QMEM_WR32(qlt, req + 0x14, qcmd->fw_xchg_addr);

	/*
	 * Mode-specific fields
	 */
	if (!use_mode2) {
		QMEM_WR16(qlt, req + 0x18, task->task_sense_length);
	}
	QMEM_WR16(qlt, req + 0x1A, flags);
	QMEM_WR32(qlt, req + 0x1C, task->task_resid);
	QMEM_WR16(qlt, req + 0x20, cmd->cmd_oxid);
	if (use_mode2) {
		bctl = (qlt_dmem_bctl_t *)qcmd->dbuf_rsp_iu->db_port_private;
		QMEM_WR32(qlt, req + 0x2C, 24 + task->task_sense_length);
		QMEM_WR64(qlt, req + 0x34, bctl->bctl_dev_addr);
		QMEM_WR32(qlt, req + 0x3C, 24 + task->task_sense_length);
	} else {
		QMEM_WR16(qlt, req + 0x22, scsi_status);
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
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

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
		req1f |= BIT_4;
	}

	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->req_lock);
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
		req[0x1b] = (cmd->cmd_lportid >> 16) & 0xff;
		req[0x1c] = cmd->cmd_lportid & 0xff;
		req[0x1d] = (cmd->cmd_lportid >> 8) & 0xff;
	}
	QMEM_WR32(qlt, (&req[0x24]), els->els_resp_size);
	QMEM_WR64(qlt, (&req[0x28]), bctl->bctl_dev_addr);
	QMEM_WR32(qlt, (&req[0x30]), els->els_resp_size);
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

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

	qcmd = (qlt_abts_cmd_t *)cmd->cmd_fca_private;

	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->req_lock);
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
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

	return (FCT_SUCCESS);
}

static void
qlt_handle_inot(qlt_state_t *qlt, uint8_t *inot)
{
	int i;
	uint32_t d;
	caddr_t req;
	/* Just put it on the request queue */
	mutex_enter(&qlt->req_lock);
	req = qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->req_lock);
		/* XXX handle this */
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
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);
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

	/*
	 * If either bidirection xfer is requested of there is extended
	 * CDB, atio[0x20 + 11] will be greater than or equal to 3.
	 */
	cdb_size = 16;
	if (atio[0x20 + 11] >= 3) {
		uint8_t b = atio[0x20 + 11];
		uint16_t b1;
		if ((b & 3) == 3) {
			cmn_err(CE_WARN, "qlt(%d) CMD with bidirectional I/O "
			    "received, dropping the cmd as bidirectional "
			    " transfers are not yet supported", qlt->instance);
			/* XXX abort the I/O */
			return;
		}
		cdb_size += b & 0xfc;
		/*
		 * Verify that we have enough entries. Without additional CDB
		 * Everything will fit nicely within the same 64 bytes. So the
		 * additional cdb size is essentially the # of additional bytes
		 * we need.
		 */
		b1 = (uint16_t)b;
		if (((((b1 & 0xfc) + 63) >> 6) + 1) > ((uint16_t)atio[1])) {
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
	oxid = (((uint16_t)atio[8 + 16]) << 8) | atio[8+17];

	if (fw_xchg_addr == 0xFFFFFFFF) {
		cmd = NULL;
	} else {
		cmd = fct_scsi_task_alloc(qlt->qlt_port, FCT_HANDLE_NONE,
		    rportid, atio+0x20, cdb_size, STMF_TASK_EXT_NONE);
	}
	if (cmd == NULL) {
		/* Abort this IO */
		flags = BIT_14 | ((atio[3] & 0xF0) << 5);

		mutex_enter(&qlt->req_lock);
		req = (uint8_t *)qlt_get_req_entries(qlt, 1);
		if (req == NULL) {
			mutex_exit(&qlt->req_lock);

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
		qlt_submit_req_entries(qlt, 1);
		mutex_exit(&qlt->req_lock);

		return;
	}

	task = (scsi_task_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->fw_xchg_addr = fw_xchg_addr;
	qcmd->param.atio_byte3 = atio[3];
	cmd->cmd_oxid = oxid;
	cmd->cmd_rxid = (((uint16_t)atio[8 + 18]) << 8) | atio[8+19];
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
	task->task_flags |= ((*q++) & 3) << 5;
	p = task->task_cdb;
	*p++ = *q++; *p++ = *q++; *p++ = *q++; *p++ = *q++;
	*p++ = *q++; *p++ = *q++; *p++ = *q++; *p++ = *q++;
	*p++ = *q++; *p++ = *q++; *p++ = *q++; *p++ = *q++;
	*p++ = *q++; *p++ = *q++; *p++ = *q++; *p++ = *q++;
	if (cdb_size > 16) {
		uint16_t xtra = cdb_size - 16;
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

	mutex_enter(&qlt->preq_lock);
	if (portid != qlt->rp_id_in_dereg) {
		int instance = ddi_get_instance(qlt->dip);
		cmn_err(CE_WARN, "qlt(%d): implicit logout completion for 0x%x"
		    " received when driver wasn't waiting for it",
		    instance, portid);
		mutex_exit(&qlt->preq_lock);
		return;
	}

	if (status != 0) {
		QLT_LOG(qlt->qlt_port_alias, "implicit logout completed "
		    "for 0x%x with status %x, subcode1 %x subcode2 %x",
		    portid, status, subcode1, subcode2);
		if (status == 0x31 && subcode1 == 0x0a)
			qlt->rp_dereg_status = FCT_SUCCESS;
		else
			qlt->rp_dereg_status =
			    QLT_FIRMWARE_ERROR(status, subcode1, subcode2);
	} else {
		qlt->rp_dereg_status = FCT_SUCCESS;
	}
	cv_signal(&qlt->rp_dereg_cv);
	mutex_exit(&qlt->preq_lock);
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

	hndl = QMEM_RD32(qlt, rsp+4);
	status = QMEM_RD16(qlt, rsp+8);
	subcode1 = QMEM_RD32(qlt, rsp+0x24);
	subcode2 = QMEM_RD32(qlt, rsp+0x28);

	if (!CMD_HANDLE_VALID(hndl)) {
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
		stmf_trace(0, "--UNSOL ELS returned with status 5 --");
		return;
	}

	cmd = fct_handle_to_cmd(qlt->qlt_port, hndl);
	if (cmd == NULL) {
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
	} else {
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
		ASSERT(hndl == 0);
		/*
		 * Someone has requested to abort it, but no one is waiting for
		 * this completion.
		 */
		if ((status != 0) && (status != 8)) {
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
	if (cmd == NULL) {
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
	if (status == 0) {
		qlt_dmem_dma_sync(qcmd->dbuf, DDI_DMA_SYNC_FORKERNEL);
		bcopy(qcmd->dbuf->db_sglist[0].seg_addr +
		    qcmd->param.resp_offset,
		    ct->ct_resp_payload, ct->ct_resp_size);
	}
	qlt_dmem_free(NULL, qcmd->dbuf);
	qcmd->dbuf = NULL;

	if (status == 0) {
		fct_send_cmd_done(cmd, FCT_SUCCESS, FCT_IOF_FCA_DONE);
	} else {
		fct_send_cmd_done(cmd, QLT_FIRMWARE_ERROR(status, 0, 0), 0);
	}
}

static void
qlt_handle_ctio_completion(qlt_state_t *qlt, uint8_t *rsp)
{
	fct_cmd_t	*cmd;
	scsi_task_t	*task;
	qlt_cmd_t	*qcmd;
	stmf_data_buf_t	*dbuf;
	fct_status_t	fc_st;
	uint32_t	iof = 0;
	uint32_t	hndl;
	uint16_t	status;
	uint16_t	flags;
	uint8_t		abort_req;
	uint8_t		n;
	char		info[160];

	/* XXX: Check validity of the IOCB by checking 4th byte. */
	hndl = QMEM_RD32(qlt, rsp+4);
	status = QMEM_RD16(qlt, rsp+8);
	flags = QMEM_RD16(qlt, rsp+0x1a);
	n = rsp[2];

	if (!CMD_HANDLE_VALID(hndl)) {
		ASSERT(hndl == 0);
		/*
		 * Someone has requested to abort it, but no one is waiting for
		 * this completion.
		 */
		QLT_LOG(qlt->qlt_port_alias, "qlt_handle_ctio_completion: "
		    "hndl-%x, status-%x, rsp-%p", hndl, status, (void *)rsp);
		if ((status != 1) && (status != 2)) {
			/*
			 * There could be exchange resource leakage, so
			 * throw HBA fatal error event now
			 */
			(void) snprintf(info, 160,
			    "qlt_handle_ctio_completion: hndl-"
			    "%x, status-%x, rsp-%p", hndl, status, (void *)rsp);
			info[159] = 0;
			(void) fct_port_shutdown(qlt->qlt_port,
			    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

		}

		return;
	}

	if (flags & BIT_14) {
		abort_req = 1;
		QLT_EXT_LOG(qlt->qlt_port_alias, "qlt_handle_ctio_completion: "
		    "abort: hndl-%x, status-%x, rsp-%p", hndl, status,
		    (void *)rsp);
	} else {
		abort_req = 0;
	}

	cmd = fct_handle_to_cmd(qlt->qlt_port, hndl);
	if (cmd == NULL) {
		(void) snprintf(info, 160,
		    "qlt_handle_ctio_completion: cannot find "
		    "cmd, hndl-%x, status-%x, rsp-%p", hndl, status,
		    (void *)rsp);
		info[159] = 0;
		(void) fct_port_shutdown(qlt->qlt_port,
		    STMF_RFLAG_FATAL_ERROR | STMF_RFLAG_RESET, info);

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
			dbuf->db_flags |= DB_STATUS_GOOD_SENT;
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
	if (status == 0) {
		fct_cmd_fca_aborted(cmd, FCT_ABORT_SUCCESS, FCT_IOF_FCA_DONE);
	} else if (status == 0x31) {
		fct_cmd_fca_aborted(cmd, FCT_NOT_FOUND, FCT_IOF_FCA_DONE);
	} else {
		fct_cmd_fca_aborted(cmd, QLT_FIRMWARE_ERROR(status, 0, 0), 0);
	}
}

static void
qlt_handle_rcvd_abts(qlt_state_t *qlt, uint8_t *resp)
{
	qlt_abts_cmd_t	*qcmd;
	fct_cmd_t	*cmd;
	uint32_t	remote_portid;
	char		info[160];

	remote_portid = ((uint32_t)(QMEM_RD16(qlt, (&resp[0x18])))) |
	    ((uint32_t)(resp[0x1A])) << 16;
	cmd = (fct_cmd_t *)fct_alloc(FCT_STRUCT_CMD_RCVD_ABTS,
	    sizeof (qlt_abts_cmd_t), 0);
	if (cmd == NULL) {
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
	fct_post_rcvd_cmd(cmd, 0);
}

static void
qlt_handle_abts_completion(qlt_state_t *qlt, uint8_t *resp)
{
	uint16_t status;
	char	info[80];

	status = QMEM_RD16(qlt, resp+8);

	if ((status == 0) || (status == 5)) {
		return;
	}
	(void) snprintf(info, 80, "ABTS completion failed %x/%x/%x resp_off %x",
	    status, QMEM_RD32(qlt, resp+0x34), QMEM_RD32(qlt, resp+0x38),
	    ((uint32_t)(qlt->resp_ndx_to_fw)) << 6);
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
		if (atomic_add_32_nv(&qlt_drop_abort_counter, -1) == 1)
			return (FCT_SUCCESS);
	}
#endif

	if (cmd->cmd_type == FCT_CMD_FCP_XCHG) {
		return (qlt_abort_unsol_scsi_cmd(qlt, cmd));
	}

	if (flags & FCT_IOF_FORCE_FCA_DONE) {
		cmd->cmd_handle = 0;
	}

	if (cmd->cmd_type == FCT_CMD_RCVD_ABTS) {
		return (qlt_send_abts_response(qlt, cmd, 1));
	}

	if (cmd->cmd_type == FCT_CMD_RCVD_ELS) {
		return (qlt_abort_purex(qlt, cmd));
	}

	if ((cmd->cmd_type == FCT_CMD_SOL_ELS) ||
	    (cmd->cmd_type == FCT_CMD_SOL_CT)) {
		return (qlt_abort_sol_cmd(qlt, cmd));
	}

	ASSERT(0);
	return (FCT_FAILURE);
}

fct_status_t
qlt_abort_sol_cmd(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	uint8_t *req;
	qlt_cmd_t *qcmd;

	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->flags |= QLT_CMD_ABORTING;
	QLT_LOG(qlt->qlt_port_alias, "qlt_abort_sol_cmd: fctcmd-%p, "
	    "cmd_handle-%x", cmd, cmd->cmd_handle);

	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->req_lock);

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
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_abort_purex(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	uint8_t *req;
	qlt_cmd_t *qcmd;
	fct_els_t *els;
	uint8_t elsop, req1f;

	els = (fct_els_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	elsop = els->els_req_payload[0];
	QLT_LOG(qlt->qlt_port_alias,
	    "qlt_abort_purex: fctcmd-%p, cmd_handle-%x, "
	    "elsop-%x", cmd, cmd->cmd_handle, elsop);
	req1f = 0x60;	/* Terminate xchg */
	if ((elsop == ELS_OP_PRLI) || (elsop == ELS_OP_PRLO) ||
	    (elsop == ELS_OP_TPRLO) || (elsop == ELS_OP_LOGO)) {
		req1f |= BIT_4;
	}

	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->req_lock);

		return (FCT_BUSY);
	}

	qcmd->flags |= QLT_CMD_ABORTING;
	bzero(req, IOCB_SIZE);
	req[0] = 0x53; req[1] = 1; req[0xf] = 0x10;
	req[0x16] = elsop; req[0x1f] = req1f;
	QMEM_WR32(qlt, (&req[4]), cmd->cmd_handle);
	if (cmd->cmd_rp) {
		QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp->rp_handle);
	} else {
		QMEM_WR16(qlt, (&req[0xA]), cmd->cmd_rp_handle);
	}

	QMEM_WR32(qlt, (&req[0x10]), qcmd->fw_xchg_addr);
	QMEM_WR32(qlt, (&req[0x18]), cmd->cmd_rportid);
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_abort_unsol_scsi_cmd(qlt_state_t *qlt, fct_cmd_t *cmd)
{
	qlt_cmd_t *qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	uint8_t *req;
	uint16_t flags;

	flags = BIT_14 | (((uint16_t)qcmd->param.atio_byte3 & 0xf0) << 5);
	QLT_EXT_LOG(qlt->qlt_port_alias, "qlt_abort_unsol_scsi_cmd: fctcmd-%p, "
	    "cmd_handle-%x", cmd, cmd->cmd_handle);

	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		mutex_exit(&qlt->req_lock);

		return (FCT_BUSY);
	}

	qcmd->flags |= QLT_CMD_ABORTING;
	bzero(req, IOCB_SIZE);
	req[0] = 0x12; req[1] = 0x1;
	QMEM_WR32(qlt, req+4, cmd->cmd_handle);
	QMEM_WR16(qlt, req+8, cmd->cmd_rp->rp_handle);
	QMEM_WR16(qlt, req+10, 60);	/* 60 seconds timeout */
	QMEM_WR32(qlt, req+0x10, cmd->cmd_rportid);
	QMEM_WR32(qlt, req+0x14, qcmd->fw_xchg_addr);
	QMEM_WR16(qlt, req+0x1A, flags);
	QMEM_WR16(qlt, req+0x20, cmd->cmd_oxid);
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

	return (FCT_SUCCESS);
}

fct_status_t
qlt_send_cmd(fct_cmd_t *cmd)
{
	qlt_state_t *qlt;

	qlt = (qlt_state_t *)cmd->cmd_port->port_fca_private;
	if (cmd->cmd_type == FCT_CMD_SOL_ELS) {
		return (qlt_send_els(qlt, cmd));
	} else if (cmd->cmd_type == FCT_CMD_SOL_CT) {
		return (qlt_send_ct(qlt, cmd));
	}

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

	els = (fct_els_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->flags = QLT_CMD_TYPE_SOLICITED;
	qcmd->param.resp_offset = (els->els_req_size + 7) & ~7;
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

	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		qlt_dmem_free(NULL, buf);
		mutex_exit(&qlt->req_lock);
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
		req[0x1b] = (cmd->cmd_lportid >> 16) & 0xff;
		req[0x1c] = cmd->cmd_lportid & 0xff;
		req[0x1d] = (cmd->cmd_lportid >> 8) & 0xff;
	}
	QMEM_WR32(qlt, (&req[0x18]), cmd->cmd_rp->rp_id);
	QMEM_WR32(qlt, (&req[0x20]), els->els_resp_size);
	QMEM_WR32(qlt, (&req[0x24]), els->els_req_size);
	QMEM_WR64(qlt, (&req[0x28]), bctl->bctl_dev_addr);
	QMEM_WR32(qlt, (&req[0x30]), els->els_req_size);
	QMEM_WR64(qlt, (&req[0x34]), bctl->bctl_dev_addr +
					qcmd->param.resp_offset);
	QMEM_WR32(qlt, (&req[0x3C]), els->els_resp_size);
	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

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

	ct = (fct_sol_ct_t *)cmd->cmd_specific;
	qcmd = (qlt_cmd_t *)cmd->cmd_fca_private;
	qcmd->flags = QLT_CMD_TYPE_SOLICITED;
	qcmd->param.resp_offset = (ct->ct_req_size + 7) & ~7;
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

	mutex_enter(&qlt->req_lock);
	req = (uint8_t *)qlt_get_req_entries(qlt, 1);
	if (req == NULL) {
		qlt_dmem_free(NULL, buf);
		mutex_exit(&qlt->req_lock);
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
	QMEM_WR64(qlt, (&req[0x34]), bctl->bctl_dev_addr +
	    qcmd->param.resp_offset);		/* RESPONSE DSD */
	QMEM_WR32(qlt, (&req[0x3C]), ct->ct_resp_size);

	qlt_submit_req_entries(qlt, 1);
	mutex_exit(&qlt->req_lock);

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
	int		retries;
	int		n, size_left;
	char		c = ' ';
	uint32_t	addr, endaddr, words_to_read;
	caddr_t		buf;

	mutex_enter(&qlt->qlt_ioctl_lock);
	/*
	 * To make sure that there's no outstanding dumping task
	 */
	if (qlt->qlt_ioctl_flags & QLT_FWDUMP_INPROGRESS) {
		mutex_exit(&qlt->qlt_ioctl_lock);
		QLT_LOG(qlt->qlt_port_alias, "qlt_firmware_dump: outstanding");
		return (FCT_FAILURE);
	}

	/*
	 * To make sure not to overwrite existing dump
	 */
	if ((qlt->qlt_ioctl_flags & QLT_FWDUMP_ISVALID) &&
	    !(qlt->qlt_ioctl_flags & QLT_FWDUMP_TRIGGERED_BY_USER) &&
	    !(qlt->qlt_ioctl_flags & QLT_FWDUMP_FETCHED_BY_USER)) {
		/*
		 * If we have alreay one dump, but it's not triggered by user
		 * and the user hasn't fetched it, we shouldn't dump again.
		 */
		mutex_exit(&qlt->qlt_ioctl_lock);
		QLT_LOG(qlt->qlt_port_alias, "qlt_firmware_dump: There's one "
		    "dump, please fetech it");
		cmn_err(CE_NOTE, "qlt(%d): Skipping firmware dump as there "
		    "is one already outstanding.", qlt->instance);
		return (FCT_FAILURE);
	}
	qlt->qlt_ioctl_flags |= QLT_FWDUMP_INPROGRESS;
	if (ssci->st_rflags & STMF_RFLAG_USER_REQUEST) {
		qlt->qlt_ioctl_flags |= QLT_FWDUMP_TRIGGERED_BY_USER;
	} else {
		qlt->qlt_ioctl_flags &= ~QLT_FWDUMP_TRIGGERED_BY_USER;
	}
	mutex_exit(&qlt->qlt_ioctl_lock);

	size_left = QLT_FWDUMP_BUFSIZE;
	if (!qlt->qlt_fwdump_buf) {
		ASSERT(!(qlt->qlt_ioctl_flags & QLT_FWDUMP_ISVALID));
		/*
		 * It's the only place that we allocate buf for dumping. After
		 * it's allocated, we will use it until the port is detached.
		 */
		qlt->qlt_fwdump_buf = kmem_zalloc(size_left, KM_SLEEP);
	}

	/*
	 * Start to dump firmware
	 */
	buf = (caddr_t)qlt->qlt_fwdump_buf;

	/*
	 * Print the ISP firmware revision number and attributes information
	 * Read the RISC to Host Status register
	 */
	n = snprintf(buf, size_left, "ISP FW Version %d.%02d.%02d "
	    "Attributes %04x\n\nR2H Status Register\n%08x",
	    qlt->fw_major, qlt->fw_minor,
	    qlt->fw_subminor, qlt->fw_attr, REG_RD32(qlt, 0x44));
	buf += n; size_left -= n;

	/*
	 * Before pausing the RISC, make sure no mailbox can execute
	 */
	mutex_enter(&qlt->mbox_lock);
	if (qlt->mbox_io_state != MBOX_STATE_UNKNOWN) {
		/*
		 * Wait to grab the mailboxes
		 */
		for (retries = 0; (qlt->mbox_io_state != MBOX_STATE_READY) &&
		    (qlt->mbox_io_state != MBOX_STATE_UNKNOWN); retries++) {
			(void) cv_timedwait(&qlt->mbox_cv, &qlt->mbox_lock,
			    ddi_get_lbolt() + drv_usectohz(1000000));
			if (retries > 5) {
				mutex_exit(&qlt->mbox_lock);
				QLT_LOG(qlt->qlt_port_alias,
				    "qlt_firmware_dump: "
				    "can't drain out mailbox commands");
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
	REG_WR32(qlt, REG_HCCR, 0x30000000);

	/*
	 * Wait for the RISC processor to pause
	 */
	for (i = 0; i < 200; i++) {
		if (REG_RD32(qlt, 0x44) & 0x100) {
			break;
		}
		drv_usecwait(1000);
	}
	if (i == 200) {
		QLT_LOG(qlt->qlt_port_alias, "qlt_firmware_dump: can't pause");
		return (FCT_FAILURE);
	}

	if (!qlt->qlt_25xx_chip) {
		goto over_25xx_specific_dump;
	}
	n = snprintf(buf, size_left, "\n\nHostRisc registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7000);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7010);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7C00);

	n = snprintf(buf, size_left, "\nPCIe registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0xC0, 0x1);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc4, 3, size_left);
	buf += n; size_left -= n;
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 1, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0xC0, 0x0);

over_25xx_specific_dump:;
	n = snprintf(buf, size_left, "\n\nHost Interface Registers\n");
	buf += n; size_left -= n;
	/*
	 * Capture data from 32 regsiters
	 */
	n = qlt_fwdump_dump_regs(qlt, buf, 0, 32, size_left);
	buf += n; size_left -= n;

	/*
	 * Disable interrupts
	 */
	REG_WR32(qlt, 0xc, 0);

	/*
	 * Shadow registers
	 */
	n = snprintf(buf, size_left, "\nShadow Registers\n");
	buf += n; size_left -= n;

	REG_WR32(qlt, 0x54, 0xF70);
	addr = 0xb0000000;
	for (i = 0; i < 0xb; i++) {
		if ((!qlt->qlt_25xx_chip) && (i >= 7)) {
			break;
		}
		if (i && ((i & 7) == 0)) {
			n = snprintf(buf, size_left, "\n");
			buf += n; size_left -= n;
		}
		REG_WR32(qlt, 0xF0, addr);
		n = snprintf(buf, size_left, "%08x ", REG_RD32(qlt, 0xFC));
		buf += n; size_left -= n;
		addr += 0x100000;
	}

	if (qlt->qlt_25xx_chip) {
		REG_WR32(qlt, 0x54, 0x10);
		n = snprintf(buf, size_left, "\n\nRISC IO Register\n%08x",
		    REG_RD32(qlt, 0xC0));
		buf += n; size_left -= n;
	}

	/*
	 * Mailbox registers
	 */
	n = snprintf(buf, size_left, "\n\nMailbox Registers\n");
	buf += n; size_left -= n;
	for (i = 0; i < 32; i += 2) {
		if ((i + 2) & 15) {
			c = ' ';
		} else {
			c = '\n';
		}
		n = snprintf(buf, size_left, "%04x %04x%c",
		    REG_RD16(qlt, 0x80 + (i << 1)),
		    REG_RD16(qlt, 0x80 + ((i+1) << 1)), c);
		buf += n; size_left -= n;
	}

	/*
	 * Transfer sequence registers
	 */
	n = snprintf(buf, size_left, "\nXSEQ GP Registers\n");
	buf += n; size_left -= n;

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
	n = snprintf(buf, size_left, "\nXSEQ-0 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBFE0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nXSEQ-1 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xBFF0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	/*
	 * Receive sequence registers
	 */
	n = snprintf(buf, size_left, "\nRSEQ GP Registers\n");
	buf += n; size_left -= n;
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
	n = snprintf(buf, size_left, "\nRSEQ-0 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFFD0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nRSEQ-1 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFFE0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nRSEQ-2 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xFFF0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	if (!qlt->qlt_25xx_chip)
		goto over_aseq_regs;

	/*
	 * Auxiliary sequencer registers
	 */
	n = snprintf(buf, size_left, "\nASEQ GP Registers\n");
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
	n = snprintf(buf, size_left, "\nASEQ-0 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB0C0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB0D0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nASEQ-1 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB0E0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nASEQ-2 registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0xB0F0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

over_aseq_regs:;

	/*
	 * Command DMA registers
	 */
	n = snprintf(buf, size_left, "\nCommand DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7100);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	/*
	 * Queues
	 */
	n = snprintf(buf, size_left,
			"\nRequest0 Queue DMA Channel registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7200);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 8, size_left);
	buf += n; size_left -= n;
	n = qlt_fwdump_dump_regs(qlt, buf, 0xe4, 7, size_left);
	buf += n; size_left -= n;

	n = snprintf(buf, size_left,
			"\n\nResponse0 Queue DMA Channel registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7300);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 8, size_left);
	buf += n; size_left -= n;
	n = qlt_fwdump_dump_regs(qlt, buf, 0xe4, 7, size_left);
	buf += n; size_left -= n;

	n = snprintf(buf, size_left,
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
	n = snprintf(buf, size_left, "\n\nXMT0 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7600);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7610);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nXMT1 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7620);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7630);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nXMT2 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7640);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7650);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nXMT3 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7660);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7670);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nXMT4 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7680);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7690);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nXMT Data DMA Common registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x76A0);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;

	/*
	 * Receive DMA registers
	 */
	n = snprintf(buf, size_left, "\nRCV Thread 0 Data DMA registers\n");
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7700);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	REG_WR32(qlt, 0x54, 0x7710);
	n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
	buf += n; size_left -= n;
	n = snprintf(buf, size_left, "\nRCV Thread 1 Data DMA registers\n");
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
	n = snprintf(buf, size_left, "\nRISC GP registers\n");
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
	n = snprintf(buf, size_left, "\nLMC registers\n");
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

	if (qlt->qlt_25xx_chip) {
		REG_WR32(qlt, 0x54, 0x3070);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	/*
	 * Fibre protocol module regsiters
	 */
	n = snprintf(buf, size_left, "\nFPM hardware registers\n");
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

	/*
	 * Fibre buffer registers
	 */
	n = snprintf(buf, size_left, "\nFB hardware registers\n");
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

	if (qlt->qlt_25xx_chip) {
		REG_WR32(qlt, 0x54, 0x6F00);
		n = qlt_fwdump_dump_regs(qlt, buf, 0xc0, 16, size_left);
		buf += n; size_left -= n;
	}

	qlt->intr_sneak_counter = 10;
	qlt_disable_intr(qlt);
	mutex_enter(&qlt->intr_lock);
	qlt->qlt_intr_enabled = 0;
	(void) qlt_reset_chip_and_download_fw(qlt, 1);
	drv_usecwait(20);
	qlt->intr_sneak_counter = 0;
	mutex_exit(&qlt->intr_lock);

	/*
	 * Memory
	 */
	n = snprintf(buf, size_left, "\nCode RAM\n");
	buf += n; size_left -= n;

	addr = 0x20000;
	endaddr = 0x22000;
	words_to_read = 0;
	while (addr < endaddr) {
		words_to_read = MBOX_DMA_MEM_SIZE >> 2;
		if ((words_to_read + addr) > endaddr) {
			words_to_read = endaddr - addr;
		}
		if (qlt_read_risc_ram(qlt, addr, words_to_read) !=
		    QLT_SUCCESS) {
			QLT_LOG(qlt->qlt_port_alias, "qlt_firmware_dump: Error "
			    "reading risc ram - CODE RAM");
			goto dump_fail;
		}

		n = qlt_dump_risc_ram(qlt, addr, words_to_read, buf, size_left);
		buf += n; size_left -= n;

		if (size_left < 100000) {
			QLT_LOG(qlt->qlt_port_alias, "qlt_firmware_dump: run "
			    "out of space - CODE RAM");
			goto dump_ok;
		}
		addr += words_to_read;
	}

	n = snprintf(buf, size_left, "\nExternal Memory\n");
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
		if (qlt_read_risc_ram(qlt, addr, words_to_read) !=
		    QLT_SUCCESS) {
			QLT_LOG(qlt->qlt_port_alias, "qlt_firmware_dump: Error "
			    "reading risc ram - EXT RAM");
			goto dump_fail;
		}
		n = qlt_dump_risc_ram(qlt, addr, words_to_read, buf, size_left);
		buf += n; size_left -= n;
		if (size_left < 100000) {
			QLT_LOG(qlt->qlt_port_alias, "qlt_firmware_dump: run "
			    "out of space - EXT RAM");
			goto dump_ok;
		}
		addr += words_to_read;
	}

	/*
	 * Label the end tag
	 */
	n = snprintf(buf, size_left, "[<==END] ISP Debug Dump\n");
	buf += n; size_left -= n;

	/*
	 * Queue dumping
	 */
	n = snprintf(buf, size_left, "\nRequest Queue\n");
	buf += n; size_left -= n;
	n = qlt_dump_queue(qlt, qlt->queue_mem_ptr + REQUEST_QUEUE_OFFSET,
	    REQUEST_QUEUE_ENTRIES, buf, size_left);
	buf += n; size_left -= n;

	n = snprintf(buf, size_left, "\nPriority Queue\n");
	buf += n; size_left -= n;
	n = qlt_dump_queue(qlt, qlt->queue_mem_ptr + PRIORITY_QUEUE_OFFSET,
	    PRIORITY_QUEUE_ENTRIES, buf, size_left);
	buf += n; size_left -= n;

	n = snprintf(buf, size_left, "\nResponse Queue\n");
	buf += n; size_left -= n;
	n = qlt_dump_queue(qlt, qlt->queue_mem_ptr + RESPONSE_QUEUE_OFFSET,
	    RESPONSE_QUEUE_ENTRIES, buf, size_left);
	buf += n; size_left -= n;

	n = snprintf(buf, size_left, "\nATIO queue\n");
	buf += n; size_left -= n;
	n = qlt_dump_queue(qlt, qlt->queue_mem_ptr + ATIO_QUEUE_OFFSET,
	    ATIO_QUEUE_ENTRIES, buf, size_left);
	buf += n; size_left -= n;

	/*
	 * Lable dump reason
	 */
	n = snprintf(buf, size_left, "\nFirmware dump reason: %s-%s\n",
	    qlt->qlt_port_alias, ssci->st_additional_info);
	buf += n; size_left -= n;

dump_ok:
	QLT_LOG(qlt->qlt_port_alias, "qlt_fireware_dump: left-%d", size_left);

	mutex_enter(&qlt->qlt_ioctl_lock);
	qlt->qlt_ioctl_flags &=
		~(QLT_FWDUMP_INPROGRESS | QLT_FWDUMP_FETCHED_BY_USER);
	qlt->qlt_ioctl_flags |= QLT_FWDUMP_ISVALID;
	mutex_exit(&qlt->qlt_ioctl_lock);
	return (FCT_SUCCESS);

dump_fail:
	mutex_enter(&qlt->qlt_ioctl_lock);
	qlt->qlt_ioctl_flags &= QLT_IOCTL_FLAG_MASK;
	mutex_exit(&qlt->qlt_ioctl_lock);
	return (FCT_FAILURE);
}

static int
qlt_fwdump_dump_regs(qlt_state_t *qlt, caddr_t buf, int startaddr, int count,
    int size_left)
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
		n += snprintf(&buf[n], (size_left - n), "%08x%c",
		    REG_RD32(qlt, startaddr + (i << 2)), c);
	}
	return (n);
}

static int
qlt_dump_risc_ram(qlt_state_t *qlt, uint32_t addr, uint32_t words,
    caddr_t buf, int size_left)
{
	int		i;
	int		n;
	char		c = ' ';
	uint32_t	*ptr;

	ptr = (uint32_t *)((caddr_t)qlt->queue_mem_ptr + MBOX_DMA_MEM_OFFSET);
	for (i = 0, n = 0; i < words; i++) {
		if ((i & 7) == 0) {
			n += snprintf(&buf[n], (size_left - n), "%08x: ",
				addr + i);
		}
		if ((i + 1) & 7) {
			c = ' ';
		} else {
			c = '\n';
		}
		n += snprintf(&buf[n], (size_left - n), "%08x%c", ptr[i], c);
	}
	return (n);
}

static int
qlt_dump_queue(qlt_state_t *qlt, caddr_t qadr, int entries, caddr_t buf,
    int size_left)
{
	int		i;
	int		n;
	char		c = ' ';
	int		words;
	uint16_t	*ptr;
	uint16_t	w;

	words = entries * 32;
	ptr = (uint16_t *)qadr;
	for (i = 0, n = 0; i < words; i++) {
		if ((i & 7) == 0) {
			n += snprintf(&buf[n], (size_left - n), "%05x: ", i);
		}
		if ((i + 1) & 7) {
			c = ' ';
		} else {
			c = '\n';
		}
		w = QMEM_RD16(qlt, &ptr[i]);
		n += snprintf(&buf[n], (size_left - n), "%04x%c", w, c);
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

	REG_WR16(qlt, REG_MBOX(0), 0xc);
	da = qlt->queue_mem_cookie.dmac_laddress;
	da += MBOX_DMA_MEM_OFFSET;

	/*
	 * System destination address
	 */
	REG_WR16(qlt, REG_MBOX(3), da & 0xffff);
	da >>= 16;
	REG_WR16(qlt, REG_MBOX(2), da & 0xffff);
	da >>= 16;
	REG_WR16(qlt, REG_MBOX(7), da & 0xffff);
	da >>= 16;
	REG_WR16(qlt, REG_MBOX(6), da & 0xffff);

	/*
	 * Length
	 */
	REG_WR16(qlt, REG_MBOX(5), words & 0xffff);
	REG_WR16(qlt, REG_MBOX(4), ((words >> 16) & 0xffff));

	/*
	 * RISC source address
	 */
	REG_WR16(qlt, REG_MBOX(1), addr & 0xffff);
	REG_WR16(qlt, REG_MBOX(8), ((addr >> 16) & 0xffff));

	ret = qlt_raw_mailbox_command(qlt);
	REG_WR32(qlt, REG_HCCR, 0xA0000000);
	if (ret == QLT_SUCCESS) {
		(void) ddi_dma_sync(qlt->queue_mem_dma_handle,
		    MBOX_DMA_MEM_OFFSET, words << 2, DDI_DMA_SYNC_FORCPU);
	} else {
		QLT_LOG(qlt->qlt_port_alias, "qlt_read_risc_ram: qlt raw_mbox "
		    "failed 0x%llX", ret);
	}
	return (ret);
}
