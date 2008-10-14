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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#define	DEF_ICFG  1

#include "emlxs.h"
#include "emlxs_version.h"

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_SOLARIS_C);

#ifdef MENLO_SUPPORT
static int32_t emlxs_send_menlo_cmd(emlxs_port_t *port, emlxs_buf_t *sbp);
#endif	/* MENLO_SUPPORT */

static void emlxs_fca_attach(emlxs_hba_t *hba);
static void emlxs_fca_detach(emlxs_hba_t *hba);
static void emlxs_drv_banner(emlxs_hba_t *hba);

static int32_t emlxs_get_props(emlxs_hba_t *hba);
static int32_t emlxs_send_fcp_cmd(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_send_fcp_status(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_send_ip(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_send_sequence(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_send_els(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_send_els_rsp(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_send_ct(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_send_ct_rsp(emlxs_port_t *port, emlxs_buf_t *sbp);
static uint32_t emlxs_add_instance(int32_t ddiinst);
static void emlxs_iodone(emlxs_buf_t *sbp);
static int emlxs_pm_lower_power(dev_info_t *dip);
static int emlxs_pm_raise_power(dev_info_t *dip);
static void emlxs_driver_remove(dev_info_t *dip, uint32_t init_flag,
    uint32_t failed);
static void emlxs_iodone_server(void *arg1, void *arg2, void *arg3);
static uint32_t emlxs_integrity_check(emlxs_hba_t *hba);
static uint32_t emlxs_test(emlxs_hba_t *hba, uint32_t test_code,
    uint32_t args, uint32_t *arg);

#ifdef SLI3_SUPPORT
static uint32_t emlxs_sli3_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);
static void emlxs_read_vport_prop(emlxs_hba_t *hba);
#endif	/* SLI3_SUPPORT */

static uint32_t emlxs_sli2_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);
static uint32_t emlxs_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);


/*
 * Driver Entry Routines.
 */
static int32_t emlxs_detach(dev_info_t *, ddi_detach_cmd_t);
static int32_t emlxs_attach(dev_info_t *, ddi_attach_cmd_t);
static int32_t emlxs_open(dev_t *dev_p, int32_t flag, int32_t otyp,
    cred_t *cred_p);
static int32_t emlxs_close(dev_t dev_p, int32_t flag, int32_t otyp,
    cred_t *cred_p);
static int32_t emlxs_ioctl(dev_t dev, int32_t cmd, intptr_t arg, int32_t mode,
    cred_t *cred_p, int32_t *rval_p);
static int32_t emlxs_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);


/*
 * FC_AL Transport Functions.
 */
static opaque_t emlxs_bind_port(dev_info_t *dip, fc_fca_port_info_t *port_info,
    fc_fca_bind_info_t *bind_info);
static void emlxs_unbind_port(opaque_t fca_port_handle);
static void emlxs_initialize_pkt(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_get_cap(opaque_t fca_port_handle, char *cap, void *ptr);
static int32_t emlxs_set_cap(opaque_t fca_port_handle, char *cap, void *ptr);
static int32_t emlxs_get_map(opaque_t fca_port_handle, fc_lilpmap_t *mapbuf);
static int32_t emlxs_ub_alloc(opaque_t fca_port_handle, uint64_t tokens[],
    uint32_t size, uint32_t *count, uint32_t type);
static int32_t emlxs_ub_free(opaque_t fca_port_handle, uint32_t count,
    uint64_t tokens[]);

static opaque_t emlxs_get_device(opaque_t fca_port_handle, fc_portid_t d_id);
static int32_t emlxs_notify(opaque_t fca_port_handle, uint32_t cmd);
static void emlxs_ub_els_reject(emlxs_port_t *port, fc_unsol_buf_t *ubp);

/*
 * Driver Internal Functions.
 */

static void emlxs_poll(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t emlxs_power(dev_info_t *dip, int32_t comp, int32_t level);
static int32_t emlxs_hba_resume(dev_info_t *dip);
static int32_t emlxs_hba_suspend(dev_info_t *dip);
static int32_t emlxs_hba_detach(dev_info_t *dip);
static int32_t emlxs_hba_attach(dev_info_t *dip);
static void emlxs_lock_destroy(emlxs_hba_t *hba);
static void emlxs_lock_init(emlxs_hba_t *hba);
static ULP_BDE64 *emlxs_pkt_to_bpl(ULP_BDE64 *bpl, fc_packet_t *pkt,
    uint32_t bpl_type, uint8_t bdeFlags);

char *emlxs_pm_components[] =
{
	"NAME=emlxx000",
	"0=Device D3 State",
	"1=Device D0 State"
};


/*
 * Default emlx dma limits
 */
ddi_dma_lim_t emlxs_dma_lim =
{
	(uint32_t)0,	/* dlim_addr_lo    */
	(uint32_t)0xffffffff,	/* dlim_addr_hi    */
	(uint_t)0x00ffffff,	/* dlim_cntr_max   */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dlim_burstsizes */
	1,	/* dlim_minxfer    */
	0x00ffffff	/* dlim_dmaspeed   */
};

/*
 * Be careful when using these attributes; the defaults listed below are
 * (almost) the most general case, permitting allocation in almost any way
 * supported by the LightPulse family.  The sole exception is the alignment
 * specified as requiring memory allocation on a 4-byte boundary;
 * the Lightpulse can DMA memory on any byte boundary.
 *
 * The LightPulse family currently is limited to 16M transfers;
 * this restriction affects the dma_attr_count_max and
 * dma_attr_maxxfer fields.
 */
ddi_dma_attr_t emlxs_dma_attr =
{
	DMA_ATTR_V0,	/* dma_attr_version    */
	(uint64_t)0,	/* dma_attr_addr_lo    */
	(uint64_t)0xffffffffffffffff,	/* dma_attr_addr_hi    */
	(uint64_t)0x00ffffff,	/* dma_attr_count_max  */
	1,	/* dma_attr_align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dma_attr_burstsizes */
	1,	/* dma_attr_minxfer    */
	(uint64_t)0x00ffffff,	/* dma_attr_maxxfer */
	(uint64_t)0xffffffff,	/* dma_attr_seg */
	EMLXS_SGLLEN,	/* dma_attr_sgllen */
	1,	/* dma_attr_granular */
	0	/* dma_attr_flags */

};

ddi_dma_attr_t emlxs_dma_attr_ro =
{
	DMA_ATTR_V0,	/* dma_attr_version    */
	(uint64_t)0,	/* dma_attr_addr_lo    */
	(uint64_t)0xffffffffffffffff,	/* dma_attr_addr_hi    */
	(uint64_t)0x00ffffff,	/* dma_attr_count_max  */
	1,	/* dma_attr_align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dma_attr_burstsizes */
	1,	/* dma_attr_minxfer    */
	(uint64_t)0x00ffffff,	/* dma_attr_maxxfer    */
	(uint64_t)0xffffffff,	/* dma_attr_seg */
	EMLXS_SGLLEN,	/* dma_attr_sgllen */
	1,	/* dma_attr_granular */
	DDI_DMA_RELAXED_ORDERING	/* dma_attr_flags */

};

ddi_dma_attr_t emlxs_dma_attr_1sg =
{
	DMA_ATTR_V0,	/* dma_attr_version    */
	(uint64_t)0,	/* dma_attr_addr_lo    */
	(uint64_t)0xffffffffffffffff,	/* dma_attr_addr_hi    */
	(uint64_t)0x00ffffff,	/* dma_attr_count_max  */
	1,	/* dma_attr_align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dma_attr_burstsizes */
	1,	/* dma_attr_minxfer    */
	(uint64_t)0x00ffffff,	/* dma_attr_maxxfer    */
	(uint64_t)0xffffffff,	/* dma_attr_seg */
	1,	/* dma_attr_sgllen */
	1,	/* dma_attr_granular   */
	0	/* dma_attr_flags */
};

#if (EMLXS_MODREV >= EMLXS_MODREV3)
ddi_dma_attr_t emlxs_dma_attr_fcip_rsp =
{
	DMA_ATTR_V0,	/* dma_attr_version    */
	(uint64_t)0,	/* dma_attr_addr_lo    */
	(uint64_t)0xffffffffffffffff,	/* dma_attr_addr_hi    */
	(uint64_t)0x00ffffff,	/* dma_attr_count_max  */
	1,	/* dma_attr_align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dma_attr_burstsizes */
	1,	/* dma_attr_minxfer    */
	(uint64_t)0x00ffffff,	/* dma_attr_maxxfer    */
	(uint64_t)0xffffffff,	/* dma_attr_seg */
	EMLXS_SGLLEN,	/* dma_attr_sgllen */
	1,	/* dma_attr_granular   */
	0	/* dma_attr_flags */
};
#endif	/* >= EMLXS_MODREV3 */

/*
 * DDI access attributes for device
 */
ddi_device_acc_attr_t emlxs_dev_acc_attr =
{
	(uint16_t)DDI_DEVICE_ATTR_V0,	/* devacc_attr_version   */
	(uint8_t)DDI_STRUCTURE_LE_ACC,	/* PCI is Little Endian  */
	(uint8_t)DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

/*
 * DDI access attributes for data
 */
ddi_device_acc_attr_t emlxs_data_acc_attr =
{
	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version   */
	DDI_NEVERSWAP_ACC,	/* don't swap for Data   */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

/*
 * Fill in the FC Transport structure, as defined in the Fibre Channel
 * Transport Programmming Guide.
 */
#if (EMLXS_MODREV == EMLXS_MODREV5)
static fc_fca_tran_t emlxs_fca_tran =
{
	FCTL_FCA_MODREV_5,	/* fca_version, with SUN NPIV support */
	MAX_VPORTS,	/* fca numerb of ports */
	sizeof (emlxs_buf_t),	/* fca pkt size */
	2048,	/* fca cmd max */
	&emlxs_dma_lim,	/* fca dma limits */
	0,	/* fca iblock, to be filled in later */
	&emlxs_dma_attr,	/* fca dma attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcp cmd attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcp rsp attributes */
	&emlxs_dma_attr_ro,	/* fca dma fcp data attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcip cmd attributes */
	&emlxs_dma_attr_fcip_rsp,	/* fca dma fcip rsp attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcsm cmd attributes */
	&emlxs_dma_attr,	/* fca dma fcsm rsp attributes */
	&emlxs_data_acc_attr,	/* fca access atributes */
	0,	/* fca_num_npivports */
	{0, 0, 0, 0, 0, 0, 0, 0},	/* Physical port WWPN */
	emlxs_bind_port,
	emlxs_unbind_port,
	emlxs_pkt_init,
	emlxs_pkt_uninit,
	emlxs_transport,
	emlxs_get_cap,
	emlxs_set_cap,
	emlxs_get_map,
	emlxs_transport,
	emlxs_ub_alloc,
	emlxs_ub_free,
	emlxs_ub_release,
	emlxs_pkt_abort,
	emlxs_reset,
	emlxs_port_manage,
	emlxs_get_device,
	emlxs_notify
};
#endif	/* EMLXS_MODREV5 */


#if (EMLXS_MODREV == EMLXS_MODREV4)
static fc_fca_tran_t emlxs_fca_tran =
{
	FCTL_FCA_MODREV_4,	/* fca_version */
	MAX_VPORTS,	/* fca numerb of ports */
	sizeof (emlxs_buf_t),	/* fca pkt size */
	2048,	/* fca cmd max */
	&emlxs_dma_lim,	/* fca dma limits */
	0,	/* fca iblock, to be filled in later */
	&emlxs_dma_attr,	/* fca dma attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcp cmd attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcp rsp attributes */
	&emlxs_dma_attr_ro,	/* fca dma fcp data attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcip cmd attributes */
	&emlxs_dma_attr_fcip_rsp,	/* fca dma fcip rsp attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcsm cmd attributes */
	&emlxs_dma_attr,	/* fca dma fcsm rsp attributes */
	&emlxs_data_acc_attr,	/* fca access atributes */
	emlxs_bind_port,
	emlxs_unbind_port,
	emlxs_pkt_init,
	emlxs_pkt_uninit,
	emlxs_transport,
	emlxs_get_cap,
	emlxs_set_cap,
	emlxs_get_map,
	emlxs_transport,
	emlxs_ub_alloc,
	emlxs_ub_free,
	emlxs_ub_release,
	emlxs_pkt_abort,
	emlxs_reset,
	emlxs_port_manage,
	emlxs_get_device,
	emlxs_notify
};
#endif	/* EMLXS_MODEREV4 */


#if (EMLXS_MODREV == EMLXS_MODREV3)
static fc_fca_tran_t emlxs_fca_tran =
{
	FCTL_FCA_MODREV_3,	/* fca_version */
	MAX_VPORTS,	/* fca numerb of ports */
	sizeof (emlxs_buf_t),	/* fca pkt size */
	2048,	/* fca cmd max */
	&emlxs_dma_lim,	/* fca dma limits */
	0,	/* fca iblock, to be filled in later */
	&emlxs_dma_attr,	/* fca dma attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcp cmd attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcp rsp attributes */
	&emlxs_dma_attr_ro,	/* fca dma fcp data attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcip cmd attributes */
	&emlxs_dma_attr_fcip_rsp,	/* fca dma fcip rsp attributes */
	&emlxs_dma_attr_1sg,	/* fca dma fcsm cmd attributes */
	&emlxs_dma_attr,	/* fca dma fcsm rsp attributes */
	&emlxs_data_acc_attr,	/* fca access atributes */
	emlxs_bind_port,
	emlxs_unbind_port,
	emlxs_pkt_init,
	emlxs_pkt_uninit,
	emlxs_transport,
	emlxs_get_cap,
	emlxs_set_cap,
	emlxs_get_map,
	emlxs_transport,
	emlxs_ub_alloc,
	emlxs_ub_free,
	emlxs_ub_release,
	emlxs_pkt_abort,
	emlxs_reset,
	emlxs_port_manage,
	emlxs_get_device,
	emlxs_notify
};
#endif	/* EMLXS_MODREV3 */


#if (EMLXS_MODREV == EMLXS_MODREV2)
static fc_fca_tran_t emlxs_fca_tran =
{
	FCTL_FCA_MODREV_2,	/* fca_version */
	MAX_VPORTS,	/* number of ports */
	sizeof (emlxs_buf_t),	/* pkt size */
	2048,	/* max cmds */
	&emlxs_dma_lim,	/* DMA limits */
	0,	/* iblock, to be filled in later */
	&emlxs_dma_attr,	/* dma attributes */
	&emlxs_data_acc_attr,	/* access atributes */
	emlxs_bind_port,
	emlxs_unbind_port,
	emlxs_pkt_init,
	emlxs_pkt_uninit,
	emlxs_transport,
	emlxs_get_cap,
	emlxs_set_cap,
	emlxs_get_map,
	emlxs_transport,
	emlxs_ub_alloc,
	emlxs_ub_free,
	emlxs_ub_release,
	emlxs_pkt_abort,
	emlxs_reset,
	emlxs_port_manage,
	emlxs_get_device,
	emlxs_notify
};
#endif	/* EMLXS_MODREV2 */

/*
 * This is needed when the module gets loaded by the kernel so
 * ddi library calls get resolved.
 */
#ifdef S8S9
#ifdef DHCHAP_SUPPORT
char _depends_on[] = "misc/fctl drv/random";
#else	/* DHCHAP_SUPPORT */
char _depends_on[] = "misc/fctl";
#endif	/* DHCHAP_SUPPORT */
#else	/* S10S11 */
#ifndef MODSYM_SUPPORT
char _depends_on[] = "misc/fctl";
#endif	/* MODSYM_SUPPORT */
#endif	/* S8S9 */


/*
 * state pointer which the implementation uses as a place to hang
 * a set of per-driver structures;
 */
void *emlxs_soft_state = NULL;

/*
 * Driver Global variables.
 */
int32_t emlxs_scsi_reset_delay = 3000;	/* milliseconds */

emlxs_device_t emlxs_device;

uint32_t emlxs_instance[MAX_FC_BRDS];	/* Protected by the emlxs_device.lock */
uint32_t emlxs_instance_count = 0;	/* Protected by the emlxs_device.lock */


/*
 * Single private "global" lock used to gain access to the hba_list
 * and/or any other case where we want need to be single-threaded.
 */
uint32_t emlxs_diag_state;

/*
 * CB ops vector.  Used for administration only.
 */
static struct cb_ops emlxs_cb_ops =
{
	emlxs_open,	/* cb_open */
	emlxs_close,	/* cb_close */
	nodev,	/* cb_strategy */
	nodev,	/* cb_print */
	nodev,	/* cb_dump */
	nodev,	/* cb_read */
	nodev,	/* cb_write */
	emlxs_ioctl,	/* cb_ioctl */
	nodev,	/* cb_devmap */
	nodev,	/* cb_mmap */
	nodev,	/* cb_segmap */
	nochpoll,	/* cb_chpoll */
	ddi_prop_op,	/* cb_prop_op */
	0,	/* cb_stream */
#ifdef _LP64
	D_64BIT | D_HOTPLUG | D_MP | D_NEW,	/* cb_flag */
#else
	D_HOTPLUG | D_MP | D_NEW,	/* cb_flag */
#endif
	CB_REV,	/* rev */
	nodev,	/* cb_aread */
	nodev	/* cb_awrite */
};

/* Generic bus ops */
static struct bus_ops emlxs_bus_ops =
{
	BUSO_REV,
	nullbusmap,	/* bus_map */
	NULL,	/* bus_get_intrspec */
	NULL,	/* bus_add_intrspec */
	NULL,	/* bus_remove_intrspec */
	i_ddi_map_fault,	/* bus_map_fault */
	ddi_dma_map,	/* bus_dma_map */
	ddi_dma_allochdl,	/* bus_dma_allochdl */
	ddi_dma_freehdl,	/* bus_dma_freehdl */
	ddi_dma_bindhdl,	/* bus_dma_bindhdl */
	ddi_dma_unbindhdl,	/* bus_unbindhdl */
	ddi_dma_flush,	/* bus_dma_flush */
	ddi_dma_win,	/* bus_dma_win */
	ddi_dma_mctl,	/* bus_dma_ctl */
	ddi_ctlops,	/* bus_ctl */
	ddi_bus_prop_op,	/* bus_prop_op */
};

static struct dev_ops emlxs_ops =
{
	DEVO_REV,	/* rev */
	0,	/* refcnt */
	emlxs_info,	/* getinfo */
	nulldev,	/* identify */
	nulldev,	/* probe */
	emlxs_attach,	/* attach */
	emlxs_detach,	/* detach */
	nodev,	/* reset */
	&emlxs_cb_ops,	/* devo_cb_ops */
	&emlxs_bus_ops,	/* bus ops - Gets replaced by fctl_fca_busops in */
			/* fc_fca_init */
	emlxs_power	/* power ops */
};

#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

/*
 * Module linkage information for the kernel.
 */
static struct modldrv emlxs_modldrv =
{
	&mod_driverops,	/* module type - driver */
	emlxs_name,	/* module name */
	&emlxs_ops,	/* driver ops */
};


/*
 * Driver module linkage structure
 */
static struct modlinkage emlxs_modlinkage = {
	MODREV_1,	/* ml_rev - must be MODREV_1 */
	&emlxs_modldrv,	/* ml_linkage */
	NULL	/* end of driver linkage */
};


/* We only need to add entries for non-default return codes. */
/* Entries do not need to be in order. */
/* Default: FC_PKT_TRAN_ERROR, FC_REASON_ABORTED, */
/* FC_EXPLN_NONE, FC_ACTION_RETRYABLE}  */
emlxs_xlat_err_t emlxs_iostat_tbl[] =
{
/* 	{f/w code, pkt_state, pkt_reason, */
/* 	pkt_expln, pkt_action}, */

	/* 0x00 - Do not remove */
	{IOSTAT_SUCCESS, FC_PKT_SUCCESS, FC_REASON_NONE,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x01 - Do not remove */
	{IOSTAT_FCP_RSP_ERROR, FC_PKT_SUCCESS, FC_REASON_NONE,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x02 */
	{IOSTAT_REMOTE_STOP, FC_PKT_REMOTE_STOP, FC_REASON_ABTS,
	FC_EXPLN_NONE, FC_ACTION_NON_RETRYABLE},

	/*
	 * This is a default entry.  The real codes are written dynamically
	 * in emlxs_els.c
	 */
	{IOSTAT_LS_RJT, FC_PKT_LS_RJT, FC_REASON_CMD_UNABLE,	/* 0x09 */
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* Special error code */
	/* 0x10 */
	{IOSTAT_DATA_OVERRUN, FC_PKT_TRAN_ERROR, FC_REASON_OVERRUN,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* Special error code */
	/* 0x11 */
	{IOSTAT_DATA_UNDERRUN, FC_PKT_TRAN_ERROR, FC_REASON_ABORTED,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* CLASS 2 only */
	/* 0x04 */
	{IOSTAT_NPORT_RJT, FC_PKT_NPORT_RJT, FC_REASON_PROTOCOL_ERROR,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* CLASS 2 only */
	/* 0x05 */
	{IOSTAT_FABRIC_RJT, FC_PKT_FABRIC_RJT, FC_REASON_PROTOCOL_ERROR,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* CLASS 2 only */
	/* 0x06 */
	{IOSTAT_NPORT_BSY, FC_PKT_NPORT_BSY, FC_REASON_PHYSICAL_BUSY,
	FC_EXPLN_NONE, FC_ACTION_SEQ_TERM_RETRY},

	/* CLASS 2 only */
	/* 0x07 */
	{IOSTAT_FABRIC_BSY, FC_PKT_FABRIC_BSY, FC_REASON_FABRIC_BSY,
	FC_EXPLN_NONE, FC_ACTION_SEQ_TERM_RETRY},
};
#define	IOSTAT_MAX    (sizeof (emlxs_iostat_tbl)/sizeof (emlxs_xlat_err_t))


/* We only need to add entries for non-default return codes. */
/* Entries do not need to be in order. */
/* Default: FC_PKT_TRAN_ERROR, FC_REASON_ABORTED, */
/* FC_EXPLN_NONE, FC_ACTION_RETRYABLE}  */
emlxs_xlat_err_t emlxs_ioerr_tbl[] =
{
/* 	{f/w code, pkt_state, pkt_reason, */
/* 	pkt_expln, pkt_action}, */
	/* 0x01 */
	{IOERR_MISSING_CONTINUE, FC_PKT_TRAN_ERROR, FC_REASON_OVERRUN,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x02 */
	{IOERR_SEQUENCE_TIMEOUT, FC_PKT_TIMEOUT, FC_REASON_SEQ_TIMEOUT,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x04 */
	{IOERR_INVALID_RPI, FC_PKT_PORT_OFFLINE, FC_REASON_OFFLINE,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x05 */
	{IOERR_NO_XRI, FC_PKT_LOCAL_RJT, FC_REASON_XCHG_DROPPED,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x06 */
	{IOERR_ILLEGAL_COMMAND, FC_PKT_LOCAL_RJT, FC_REASON_ILLEGAL_REQ,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x07 */
	{IOERR_XCHG_DROPPED, FC_PKT_LOCAL_RJT, FC_REASON_XCHG_DROPPED,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x08 */
	{IOERR_ILLEGAL_FIELD, FC_PKT_LOCAL_RJT, FC_REASON_ILLEGAL_REQ,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x0B */
	{IOERR_RCV_BUFFER_WAITING, FC_PKT_LOCAL_RJT, FC_REASON_NOMEM,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x0D */
	{IOERR_TX_DMA_FAILED, FC_PKT_LOCAL_RJT, FC_REASON_DMA_ERROR,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x0E */
	{IOERR_RX_DMA_FAILED, FC_PKT_LOCAL_RJT, FC_REASON_DMA_ERROR,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x0F */
	{IOERR_ILLEGAL_FRAME, FC_PKT_LOCAL_RJT, FC_REASON_ILLEGAL_FRAME,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x11 */
	{IOERR_NO_RESOURCES, FC_PKT_LOCAL_RJT, FC_REASON_NOMEM,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x13 */
	{IOERR_ILLEGAL_LENGTH, FC_PKT_LOCAL_RJT, FC_REASON_ILLEGAL_LENGTH,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x14 */
	{IOERR_UNSUPPORTED_FEATURE, FC_PKT_LOCAL_RJT, FC_REASON_UNSUPPORTED,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x15 */
	{IOERR_ABORT_IN_PROGRESS, FC_PKT_LOCAL_RJT, FC_REASON_ABORTED,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x16 */
	{IOERR_ABORT_REQUESTED, FC_PKT_LOCAL_RJT, FC_REASON_ABORTED,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x17 */
	{IOERR_RCV_BUFFER_TIMEOUT, FC_PKT_LOCAL_RJT, FC_REASON_RX_BUF_TIMEOUT,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x18 */
	{IOERR_LOOP_OPEN_FAILURE, FC_PKT_LOCAL_RJT, FC_REASON_FCAL_OPN_FAIL,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x1A */
	{IOERR_LINK_DOWN, FC_PKT_PORT_OFFLINE, FC_REASON_OFFLINE,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x21 */
	{IOERR_BAD_HOST_ADDRESS, FC_PKT_LOCAL_RJT, FC_REASON_BAD_SID,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* Occurs at link down */
	/* 0x28 */
	{IOERR_BUFFER_SHORTAGE, FC_PKT_PORT_OFFLINE, FC_REASON_OFFLINE,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0xF0 */
	{IOERR_ABORT_TIMEOUT, FC_PKT_TIMEOUT, FC_REASON_SEQ_TIMEOUT,
	FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

};
#define	IOERR_MAX    (sizeof (emlxs_ioerr_tbl)/sizeof (emlxs_xlat_err_t))



emlxs_table_t emlxs_error_table[] =
{
	{IOERR_SUCCESS, "No error."},
	{IOERR_MISSING_CONTINUE, "Missing continue."},
	{IOERR_SEQUENCE_TIMEOUT, "Sequence timeout."},
	{IOERR_INTERNAL_ERROR, "Internal error."},
	{IOERR_INVALID_RPI, "Invalid RPI."},
	{IOERR_NO_XRI, "No XRI."},
	{IOERR_ILLEGAL_COMMAND, "Illegal command."},
	{IOERR_XCHG_DROPPED, "Exchange dropped."},
	{IOERR_ILLEGAL_FIELD, "Illegal field."},
	{IOERR_RCV_BUFFER_WAITING, "RX buffer waiting."},
	{IOERR_TX_DMA_FAILED, "TX DMA failed."},
	{IOERR_RX_DMA_FAILED, "RX DMA failed."},
	{IOERR_ILLEGAL_FRAME, "Illegal frame."},
	{IOERR_NO_RESOURCES, "No resources."},
	{IOERR_ILLEGAL_LENGTH, "Illegal length."},
	{IOERR_UNSUPPORTED_FEATURE, "Unsupported feature."},
	{IOERR_ABORT_IN_PROGRESS, "Abort in progess."},
	{IOERR_ABORT_REQUESTED, "Abort requested."},
	{IOERR_RCV_BUFFER_TIMEOUT, "RX buffer timeout."},
	{IOERR_LOOP_OPEN_FAILURE, "Loop open failed."},
	{IOERR_RING_RESET, "Ring reset."},
	{IOERR_LINK_DOWN, "Link down."},
	{IOERR_CORRUPTED_DATA, "Corrupted data."},
	{IOERR_CORRUPTED_RPI, "Corrupted RPI."},
	{IOERR_OUT_OF_ORDER_DATA, "Out-of-order data."},
	{IOERR_OUT_OF_ORDER_ACK, "Out-of-order ack."},
	{IOERR_DUP_FRAME, "Duplicate frame."},
	{IOERR_LINK_CONTROL_FRAME, "Link control frame."},
	{IOERR_BAD_HOST_ADDRESS, "Bad host address."},
	{IOERR_RCV_HDRBUF_WAITING, "RX header buffer waiting."},
	{IOERR_MISSING_HDR_BUFFER, "Missing header buffer."},
	{IOERR_MSEQ_CHAIN_CORRUPTED, "MSEQ chain corrupted."},
	{IOERR_ABORTMULT_REQUESTED, "Abort multiple requested."},
	{IOERR_BUFFER_SHORTAGE, "Buffer shortage."},
	{IOERR_XRIBUF_WAITING, "XRI buffer shortage"},
	{IOERR_XRIBUF_MISSING, "XRI buffer missing"},
	{IOERR_ROFFSET_INVAL, "Relative offset invalid."},
	{IOERR_ROFFSET_MISSING, "Relative offset missing."},
	{IOERR_INSUF_BUFFER, "Buffer too small."},
	{IOERR_MISSING_SI, "ELS frame missing SI"},
	{IOERR_MISSING_ES, "Exhausted burst without ES"},
	{IOERR_INCOMP_XFER, "Transfer incomplete."},
	{IOERR_ABORT_TIMEOUT, "Abort timeout."}

};	/* emlxs_error_table */


emlxs_table_t emlxs_state_table[] =
{
	{IOSTAT_SUCCESS, "Success."},
	{IOSTAT_FCP_RSP_ERROR, "FCP response error."},
	{IOSTAT_REMOTE_STOP, "Remote stop."},
	{IOSTAT_LOCAL_REJECT, "Local reject."},
	{IOSTAT_NPORT_RJT, "NPort reject."},
	{IOSTAT_FABRIC_RJT, "Fabric reject."},
	{IOSTAT_NPORT_BSY, "Nport busy."},
	{IOSTAT_FABRIC_BSY, "Fabric busy."},
	{IOSTAT_INTERMED_RSP, "Intermediate response."},
	{IOSTAT_LS_RJT, "LS reject."},
	{IOSTAT_CMD_REJECT, "Cmd reject."},
	{IOSTAT_FCP_TGT_LENCHK, "TGT length check."},
	{IOSTAT_NEED_BUF_ENTRY, "Need buffer entry."},
	{IOSTAT_ILLEGAL_FRAME_RCVD, "Illegal frame."},
	{IOSTAT_DATA_UNDERRUN, "Data underrun."},
	{IOSTAT_DATA_OVERRUN, "Data overrun."},

};	/* emlxs_state_table */


#ifdef MENLO_SUPPORT
emlxs_table_t emlxs_menlo_cmd_table[] =
{
	{MENLO_CMD_INITIALIZE, "MENLO_INIT"},
	{MENLO_CMD_FW_DOWNLOAD, "MENLO_FW_DOWNLOAD"},
	{MENLO_CMD_READ_MEMORY, "MENLO_READ_MEM"},
	{MENLO_CMD_WRITE_MEMORY, "MENLO_WRITE_MEM"},
	{MENLO_CMD_FTE_INSERT, "MENLO_FTE_INSERT"},
	{MENLO_CMD_FTE_DELETE, "MENLO_FTE_DELETE"},

	{MENLO_CMD_GET_INIT, "MENLO_GET_INIT"},
	{MENLO_CMD_GET_CONFIG, "MENLO_GET_CONFIG"},
	{MENLO_CMD_GET_PORT_STATS, "MENLO_GET_PORT_STATS"},
	{MENLO_CMD_GET_LIF_STATS, "MENLO_GET_LIF_STATS"},
	{MENLO_CMD_GET_ASIC_STATS, "MENLO_GET_ASIC_STATS"},
	{MENLO_CMD_GET_LOG_CONFIG, "MENLO_GET_LOG_CFG"},
	{MENLO_CMD_GET_LOG_DATA, "MENLO_GET_LOG_DATA"},
	{MENLO_CMD_GET_PANIC_LOG, "MENLO_GET_PANIC_LOG"},
	{MENLO_CMD_GET_LB_MODE, "MENLO_GET_LB_MODE"},

	{MENLO_CMD_SET_PAUSE, "MENLO_SET_PAUSE"},
	{MENLO_CMD_SET_FCOE_COS, "MENLO_SET_FCOE_COS"},
	{MENLO_CMD_SET_UIF_PORT_TYPE, "MENLO_SET_UIF_TYPE"},

	{MENLO_CMD_DIAGNOSTICS, "MENLO_DIAGNOSTICS"},
	{MENLO_CMD_LOOPBACK, "MENLO_LOOPBACK"},

	{MENLO_CMD_RESET, "MENLO_RESET"},
	{MENLO_CMD_SET_MODE, "MENLO_SET_MODE"}

};	/* emlxs_menlo_cmd_table */

emlxs_table_t emlxs_menlo_rsp_table[] =
{
	{MENLO_RSP_SUCCESS, "SUCCESS"},
	{MENLO_ERR_FAILED, "FAILED"},
	{MENLO_ERR_INVALID_CMD, "INVALID_CMD"},
	{MENLO_ERR_INVALID_CREDIT, "INVALID_CREDIT"},
	{MENLO_ERR_INVALID_SIZE, "INVALID_SIZE"},
	{MENLO_ERR_INVALID_ADDRESS, "INVALID_ADDRESS"},
	{MENLO_ERR_INVALID_CONTEXT, "INVALID_CONTEXT"},
	{MENLO_ERR_INVALID_LENGTH, "INVALID_LENGTH"},
	{MENLO_ERR_INVALID_TYPE, "INVALID_TYPE"},
	{MENLO_ERR_INVALID_DATA, "INVALID_DATA"},
	{MENLO_ERR_INVALID_VALUE1, "INVALID_VALUE1"},
	{MENLO_ERR_INVALID_VALUE2, "INVALID_VALUE2"},
	{MENLO_ERR_INVALID_MASK, "INVALID_MASK"},
	{MENLO_ERR_CHECKSUM, "CHECKSUM_ERROR"},
	{MENLO_ERR_UNKNOWN_FCID, "UNKNOWN_FCID"},
	{MENLO_ERR_UNKNOWN_WWN, "UNKNOWN_WWN"},
	{MENLO_ERR_BUSY, "BUSY"},

};	/* emlxs_menlo_rsp_table */

#endif	/* MENLO_SUPPORT */


emlxs_table_t emlxs_mscmd_table[] =
{
	{SLI_CT_RESPONSE_FS_ACC, "CT_ACC"},
	{SLI_CT_RESPONSE_FS_RJT, "CT_RJT"},
	{MS_GTIN, "MS_GTIN"},
	{MS_GIEL, "MS_GIEL"},
	{MS_GIET, "MS_GIET"},
	{MS_GDID, "MS_GDID"},
	{MS_GMID, "MS_GMID"},
	{MS_GFN, "MS_GFN"},
	{MS_GIELN, "MS_GIELN"},
	{MS_GMAL, "MS_GMAL"},
	{MS_GIEIL, "MS_GIEIL"},
	{MS_GPL, "MS_GPL"},
	{MS_GPT, "MS_GPT"},
	{MS_GPPN, "MS_GPPN"},
	{MS_GAPNL, "MS_GAPNL"},
	{MS_GPS, "MS_GPS"},
	{MS_GPSC, "MS_GPSC"},
	{MS_GATIN, "MS_GATIN"},
	{MS_GSES, "MS_GSES"},
	{MS_GPLNL, "MS_GPLNL"},
	{MS_GPLT, "MS_GPLT"},
	{MS_GPLML, "MS_GPLML"},
	{MS_GPAB, "MS_GPAB"},
	{MS_GNPL, "MS_GNPL"},
	{MS_GPNL, "MS_GPNL"},
	{MS_GPFCP, "MS_GPFCP"},
	{MS_GPLI, "MS_GPLI"},
	{MS_GNID, "MS_GNID"},
	{MS_RIELN, "MS_RIELN"},
	{MS_RPL, "MS_RPL"},
	{MS_RPLN, "MS_RPLN"},
	{MS_RPLT, "MS_RPLT"},
	{MS_RPLM, "MS_RPLM"},
	{MS_RPAB, "MS_RPAB"},
	{MS_RPFCP, "MS_RPFCP"},
	{MS_RPLI, "MS_RPLI"},
	{MS_DPL, "MS_DPL"},
	{MS_DPLN, "MS_DPLN"},
	{MS_DPLM, "MS_DPLM"},
	{MS_DPLML, "MS_DPLML"},
	{MS_DPLI, "MS_DPLI"},
	{MS_DPAB, "MS_DPAB"},
	{MS_DPALL, "MS_DPALL"}

};	/* emlxs_mscmd_table */


emlxs_table_t emlxs_ctcmd_table[] =
{
	{SLI_CT_RESPONSE_FS_ACC, "CT_ACC"},
	{SLI_CT_RESPONSE_FS_RJT, "CT_RJT"},
	{SLI_CTNS_GA_NXT, "GA_NXT"},
	{SLI_CTNS_GPN_ID, "GPN_ID"},
	{SLI_CTNS_GNN_ID, "GNN_ID"},
	{SLI_CTNS_GCS_ID, "GCS_ID"},
	{SLI_CTNS_GFT_ID, "GFT_ID"},
	{SLI_CTNS_GSPN_ID, "GSPN_ID"},
	{SLI_CTNS_GPT_ID, "GPT_ID"},
	{SLI_CTNS_GID_PN, "GID_PN"},
	{SLI_CTNS_GID_NN, "GID_NN"},
	{SLI_CTNS_GIP_NN, "GIP_NN"},
	{SLI_CTNS_GIPA_NN, "GIPA_NN"},
	{SLI_CTNS_GSNN_NN, "GSNN_NN"},
	{SLI_CTNS_GNN_IP, "GNN_IP"},
	{SLI_CTNS_GIPA_IP, "GIPA_IP"},
	{SLI_CTNS_GID_FT, "GID_FT"},
	{SLI_CTNS_GID_PT, "GID_PT"},
	{SLI_CTNS_RPN_ID, "RPN_ID"},
	{SLI_CTNS_RNN_ID, "RNN_ID"},
	{SLI_CTNS_RCS_ID, "RCS_ID"},
	{SLI_CTNS_RFT_ID, "RFT_ID"},
	{SLI_CTNS_RSPN_ID, "RSPN_ID"},
	{SLI_CTNS_RPT_ID, "RPT_ID"},
	{SLI_CTNS_RIP_NN, "RIP_NN"},
	{SLI_CTNS_RIPA_NN, "RIPA_NN"},
	{SLI_CTNS_RSNN_NN, "RSNN_NN"},
	{SLI_CTNS_DA_ID, "DA_ID"},
	{SLI_CT_LOOPBACK, "LOOPBACK"}	/* Driver special */

};	/* emlxs_ctcmd_table */



emlxs_table_t emlxs_rmcmd_table[] =
{
	{SLI_CT_RESPONSE_FS_ACC, "CT_ACC"},
	{SLI_CT_RESPONSE_FS_RJT, "CT_RJT"},
	{CT_OP_GSAT, "RM_GSAT"},
	{CT_OP_GHAT, "RM_GHAT"},
	{CT_OP_GPAT, "RM_GPAT"},
	{CT_OP_GDAT, "RM_GDAT"},
	{CT_OP_GPST, "RM_GPST"},
	{CT_OP_GDP, "RM_GDP"},
	{CT_OP_GDPG, "RM_GDPG"},
	{CT_OP_GEPS, "RM_GEPS"},
	{CT_OP_GLAT, "RM_GLAT"},
	{CT_OP_SSAT, "RM_SSAT"},
	{CT_OP_SHAT, "RM_SHAT"},
	{CT_OP_SPAT, "RM_SPAT"},
	{CT_OP_SDAT, "RM_SDAT"},
	{CT_OP_SDP, "RM_SDP"},
	{CT_OP_SBBS, "RM_SBBS"},
	{CT_OP_RPST, "RM_RPST"},
	{CT_OP_VFW, "RM_VFW"},
	{CT_OP_DFW, "RM_DFW"},
	{CT_OP_RES, "RM_RES"},
	{CT_OP_RHD, "RM_RHD"},
	{CT_OP_UFW, "RM_UFW"},
	{CT_OP_RDP, "RM_RDP"},
	{CT_OP_GHDR, "RM_GHDR"},
	{CT_OP_CHD, "RM_CHD"},
	{CT_OP_SSR, "RM_SSR"},
	{CT_OP_RSAT, "RM_RSAT"},
	{CT_OP_WSAT, "RM_WSAT"},
	{CT_OP_RSAH, "RM_RSAH"},
	{CT_OP_WSAH, "RM_WSAH"},
	{CT_OP_RACT, "RM_RACT"},
	{CT_OP_WACT, "RM_WACT"},
	{CT_OP_RKT, "RM_RKT"},
	{CT_OP_WKT, "RM_WKT"},
	{CT_OP_SSC, "RM_SSC"},
	{CT_OP_QHBA, "RM_QHBA"},
	{CT_OP_GST, "RM_GST"},
	{CT_OP_GFTM, "RM_GFTM"},
	{CT_OP_SRL, "RM_SRL"},
	{CT_OP_SI, "RM_SI"},
	{CT_OP_SRC, "RM_SRC"},
	{CT_OP_GPB, "RM_GPB"},
	{CT_OP_SPB, "RM_SPB"},
	{CT_OP_RPB, "RM_RPB"},
	{CT_OP_RAPB, "RM_RAPB"},
	{CT_OP_GBC, "RM_GBC"},
	{CT_OP_GBS, "RM_GBS"},
	{CT_OP_SBS, "RM_SBS"},
	{CT_OP_GANI, "RM_GANI"},
	{CT_OP_GRV, "RM_GRV"},
	{CT_OP_GAPBS, "RM_GAPBS"},
	{CT_OP_APBC, "RM_APBC"},
	{CT_OP_GDT, "RM_GDT"},
	{CT_OP_GDLMI, "RM_GDLMI"},
	{CT_OP_GANA, "RM_GANA"},
	{CT_OP_GDLV, "RM_GDLV"},
	{CT_OP_GWUP, "RM_GWUP"},
	{CT_OP_GLM, "RM_GLM"},
	{CT_OP_GABS, "RM_GABS"},
	{CT_OP_SABS, "RM_SABS"},
	{CT_OP_RPR, "RM_RPR"},
	{SLI_CT_LOOPBACK, "LOOPBACK"}	/* Driver special */

};	/* emlxs_rmcmd_table */


emlxs_table_t emlxs_elscmd_table[] =
{
	{ELS_CMD_ACC, "ACC"},
	{ELS_CMD_LS_RJT, "LS_RJT"},
	{ELS_CMD_PLOGI, "PLOGI"},
	{ELS_CMD_FLOGI, "FLOGI"},
	{ELS_CMD_LOGO, "LOGO"},
	{ELS_CMD_ABTX, "ABTX"},
	{ELS_CMD_RCS, "RCS"},
	{ELS_CMD_RES, "RES"},
	{ELS_CMD_RSS, "RSS"},
	{ELS_CMD_RSI, "RSI"},
	{ELS_CMD_ESTS, "ESTS"},
	{ELS_CMD_ESTC, "ESTC"},
	{ELS_CMD_ADVC, "ADVC"},
	{ELS_CMD_RTV, "RTV"},
	{ELS_CMD_RLS, "RLS"},
	{ELS_CMD_ECHO, "ECHO"},
	{ELS_CMD_TEST, "TEST"},
	{ELS_CMD_RRQ, "RRQ"},
	{ELS_CMD_PRLI, "PRLI"},
	{ELS_CMD_PRLO, "PRLO"},
	{ELS_CMD_SCN, "SCN"},
	{ELS_CMD_TPLS, "TPLS"},
	{ELS_CMD_GPRLO, "GPRLO"},
	{ELS_CMD_GAID, "GAID"},
	{ELS_CMD_FACT, "FACT"},
	{ELS_CMD_FDACT, "FDACT"},
	{ELS_CMD_NACT, "NACT"},
	{ELS_CMD_NDACT, "NDACT"},
	{ELS_CMD_QoSR, "QoSR"},
	{ELS_CMD_RVCS, "RVCS"},
	{ELS_CMD_PDISC, "PDISC"},
	{ELS_CMD_FDISC, "FDISC"},
	{ELS_CMD_ADISC, "ADISC"},
	{ELS_CMD_FARP, "FARP"},
	{ELS_CMD_FARPR, "FARPR"},
	{ELS_CMD_FAN, "FAN"},
	{ELS_CMD_RSCN, "RSCN"},
	{ELS_CMD_SCR, "SCR"},
	{ELS_CMD_LINIT, "LINIT"},
	{ELS_CMD_RNID, "RNID"},
	{ELS_CMD_AUTH, "AUTH"}

};	/* emlxs_elscmd_table */


/*
 *
 *		  Device Driver Entry Routines
 *
 */

#ifdef MODSYM_SUPPORT
static void emlxs_fca_modclose();
static int emlxs_fca_modopen();
emlxs_modsym_t emlxs_modsym;

static int
emlxs_fca_modopen()
{
	int err;

	if (emlxs_modsym.mod_fctl) {
		return (EEXIST);
	}
	/* Leadville (fctl) */
	err = 0;
	emlxs_modsym.mod_fctl = ddi_modopen("misc/fctl",
	    KRTLD_MODE_FIRST, &err);
	if (!emlxs_modsym.mod_fctl) {
		cmn_err(CE_WARN,
		    "?%s: misc/fctl: ddi_modopen misc/fctl failed: error=%d",
		    DRIVER_NAME, err);

		goto failed;
	}
	err = 0;
	/* Check if the fctl fc_fca_attach is present */
	emlxs_modsym.fc_fca_attach = (int (*) ())
	    ddi_modsym(emlxs_modsym.mod_fctl, "fc_fca_attach", &err);
	if ((void *) emlxs_modsym.fc_fca_attach == NULL) {
		cmn_err(CE_WARN,
		    "?%s: misc/fctl: fc_fca_attach not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fctl fc_fca_detach is present */
	emlxs_modsym.fc_fca_detach = (int (*) ())
	    ddi_modsym(emlxs_modsym.mod_fctl, "fc_fca_detach", &err);
	if ((void *) emlxs_modsym.fc_fca_detach == NULL) {
		cmn_err(CE_WARN,
		    "?%s: misc/fctl: fc_fca_detach not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fctl fc_fca_init is present */
	emlxs_modsym.fc_fca_init = (int (*) ())
	    ddi_modsym(emlxs_modsym.mod_fctl, "fc_fca_init", &err);
	if ((void *) emlxs_modsym.fc_fca_init == NULL) {
		cmn_err(CE_WARN,
		    "?%s: misc/fctl: fc_fca_init not present", DRIVER_NAME);
		goto failed;
	}
	return (0);

failed:

	emlxs_fca_modclose();

	return (ENODEV);


} /* emlxs_fca_modopen() */


static void
emlxs_fca_modclose()
{
	if (emlxs_modsym.mod_fctl) {
		(void) ddi_modclose(emlxs_modsym.mod_fctl);
		emlxs_modsym.mod_fctl = 0;
	}
	emlxs_modsym.fc_fca_attach = NULL;
	emlxs_modsym.fc_fca_detach = NULL;
	emlxs_modsym.fc_fca_init = NULL;

	return;

} /* emlxs_fca_modclose() */

#endif	/* MODSYM_SUPPORT */



/*
 * Global driver initialization, called once when driver is loaded
 */
int
_init(void)
{
	int ret;
	char buf[64];

	/*
	 * First init call for this driver, so initialize the emlxs_dev_ctl
	 * structure.
	 */
	bzero(&emlxs_device, sizeof (emlxs_device));

#ifdef MODSYM_SUPPORT
	bzero(&emlxs_modsym, sizeof (emlxs_modsym_t));
#endif	/* MODSYM_SUPPORT */

	(void) sprintf(buf, "%s_device mutex", DRIVER_NAME);
	mutex_init(&emlxs_device.lock, buf, MUTEX_DRIVER, NULL);

	(void) drv_getparm(LBOLT, &emlxs_device.log_timestamp);
	emlxs_device.drv_timestamp = ddi_get_time();

	for (ret = 0; ret < MAX_FC_BRDS; ret++) {
		emlxs_instance[ret] = (uint32_t)-1;
	}

	/*
	 * Provide for one ddiinst of the emlxs_dev_ctl structure for each
	 * possible board in the system.
	 */
	if ((ret = ddi_soft_state_init(&emlxs_soft_state,
	    sizeof (emlxs_hba_t), MAX_FC_BRDS)) != 0) {
		cmn_err(CE_WARN,
		    "?%s: _init: ddi_soft_state_init failed. rval=%x",
		    DRIVER_NAME, ret);

		return (ret);
	}
	if ((ret = mod_install(&emlxs_modlinkage)) != 0) {
		(void) ddi_soft_state_fini(&emlxs_soft_state);
	}
	return (ret);

} /* _init() */


/*
 * Called when driver is unloaded.
 */
int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&emlxs_modlinkage)) != 0) {
		/*
		 * cmn_err(CE_WARN, "?%s: _fini: mod_remove failed. rval=%x",
		 * DRIVER_NAME, ret);
		 */
		return (ret);
	}
#ifdef MODSYM_SUPPORT
	/* Close SFS */
	emlxs_fca_modclose();
#ifdef SFCT_SUPPORT
	/* Close FCT */
	emlxs_fct_modclose();
#endif	/* SFCT_SUPPORT */
#endif	/* MODSYM_SUPPORT */

	/*
	 * Destroy the soft state structure
	 */
	(void) ddi_soft_state_fini(&emlxs_soft_state);

	/* Destroy the global device lock */
	mutex_destroy(&emlxs_device.lock);

	return (ret);

} /* _fini() */



int
_info(struct modinfo *modinfop)
{

	return (mod_info(&emlxs_modlinkage, modinfop));

} /* _info() */


/*
 * Attach an ddiinst of an emlx host adapter. Allocate data structures,
 * initialize the adapter and we're ready to fly.
 */
static int
emlxs_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int rval;

	switch (cmd) {
	case DDI_ATTACH:

		/* If successful this will set EMLXS_PM_IN_ATTACH */
		rval = emlxs_hba_attach(dip);
		break;

	case DDI_PM_RESUME:

		/* This will resume the driver */
		rval = emlxs_pm_raise_power(dip);
		break;

	case DDI_RESUME:

		/* This will resume the driver */
		rval = emlxs_hba_resume(dip);
		break;

	default:
		rval = DDI_FAILURE;
	}

	return (rval);


} /* emlxs_attach() */


/*
 * Detach/prepare driver to unload (see detach(9E)).
 */
static int
emlxs_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	int ddiinst;
	int emlxinst;
	int rval;

	ddiinst = ddi_get_instance(dip);
	emlxinst = emlxs_get_instance(ddiinst);
	hba = emlxs_device.hba[emlxinst];

	if (hba == NULL) {
		cmn_err(CE_WARN, "?%s: Detach: NULL device.", DRIVER_NAME);

		return (DDI_FAILURE);
	}
	if (hba == (emlxs_hba_t *)-1) {
		cmn_err(CE_WARN, "?%s: Detach: Device attach failed.",
		    DRIVER_NAME);

		return (DDI_FAILURE);
	}
	port = &PPORT;
	rval = DDI_SUCCESS;

	switch (cmd) {
	case DDI_DETACH:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_debug_msg,
		    "DDI_DETACH");

		rval = emlxs_hba_detach(dip);

		if (rval != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
			    "Unable to detach.");
		}
		break;


	case DDI_PM_SUSPEND:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_debug_msg,
		    "DDI_PM_SUSPEND");

		/* This will suspend the driver */
		rval = emlxs_pm_lower_power(dip);

		if (rval != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
			    "Unable to lower power.");
		}
		break;


	case DDI_SUSPEND:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_debug_msg,
		    "DDI_SUSPEND");

		/* Suspend the driver */
		rval = emlxs_hba_suspend(dip);

		if (rval != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
			    "Unable to suspend driver.");
		}
		break;


	default:
		cmn_err(CE_WARN, "?%s: Detach: Unknown cmd received. cmd=%x",
		    DRIVER_NAME, cmd);
		rval = DDI_FAILURE;
	}

	return (rval);

} /* emlxs_detach() */


/* EMLXS_PORT_LOCK must be held when calling this */
extern void
emlxs_port_init(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;

	/* Initialize the base node */
	bzero((caddr_t)&port->node_base, sizeof (NODELIST));
	port->node_base.nlp_Rpi = 0;
	port->node_base.nlp_DID = 0xffffff;
	port->node_base.nlp_list_next = NULL;
	port->node_base.nlp_list_prev = NULL;
	port->node_base.nlp_active = 1;
	port->node_base.nlp_base = 1;
	port->node_count = 0;

	if (!(port->flag & EMLXS_PORT_ENABLE)) {
		uint8_t dummy_wwn[8] =
		    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

		bcopy((caddr_t)dummy_wwn, (caddr_t)&port->wwnn,
		    sizeof (NAME_TYPE));
		bcopy((caddr_t)dummy_wwn, (caddr_t)&port->wwpn,
		    sizeof (NAME_TYPE));
	}
	if (!(port->flag & EMLXS_PORT_CONFIG)) {
		(void) strncpy((caddr_t)port->snn, (caddr_t)hba->snn, 256);
		(void) strncpy((caddr_t)port->spn, (caddr_t)hba->spn, 256);
	}
	bcopy((caddr_t)&hba->sparam, (caddr_t)&port->sparam,
	    sizeof (SERV_PARM));
	bcopy((caddr_t)&port->wwnn, (caddr_t)&port->sparam.nodeName,
	    sizeof (NAME_TYPE));
	bcopy((caddr_t)&port->wwpn, (caddr_t)&port->sparam.portName,
	    sizeof (NAME_TYPE));

	return;

} /* emlxs_port_init() */



/*
 * emlxs_bind_port
 *
 * Arguments:
 * dip: the dev_info pointer for the ddiinst
 * port_info: pointer to info handed back to the transport
 * bind info: pointer to info from the transport
 *
 * Return values: a port handle for this port, NULL for failure
 *
 */
static opaque_t
emlxs_bind_port(dev_info_t *dip, fc_fca_port_info_t *port_info,
    fc_fca_bind_info_t *bind_info)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	emlxs_port_t *vport;
	int ddiinst;
	emlxs_vpd_t *vpd;
	emlxs_config_t *cfg;
	char *dptr;
	char buffer[16];
	uint32_t length;
	uint32_t len;
	/* char buf[64]; */
	char topology[32];
	char linkspeed[32];

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	ddiinst = hba->ddiinst;
	vpd = &VPD;
	cfg = &CFG;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (bind_info->port_num > 0) {
#if (EMLXS_MODREV >= EMLXS_MODREV5)
		if (!(hba->flag & FC_NPIV_ENABLED) ||
		    !(bind_info->port_npiv) ||
		    (bind_info->port_num > hba->vpi_max))
#elif (EMLXS_MODREV >= EMLXS_MODREV3)
			if (!(hba->flag & FC_NPIV_ENABLED) ||
			    (bind_info->port_num > hba->vpi_high))
#endif
			{
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "emlxs_port_bind: Port %d not supported.",
				    bind_info->port_num);

				mutex_exit(&EMLXS_PORT_LOCK);

				port_info->pi_error = FC_OUTOFBOUNDS;
				return (NULL);
			}
	}
	/* Get true port pointer */
	port = &VPORT(bind_info->port_num);

	if (port->tgt_mode) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_port_bind: Port %d is in target mode.",
		    bind_info->port_num);

		mutex_exit(&EMLXS_PORT_LOCK);

		port_info->pi_error = FC_OUTOFBOUNDS;
		return (NULL);
	}
	if (!port->ini_mode) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_port_bind: Port %d is not in initiator mode.",
		    bind_info->port_num);

		mutex_exit(&EMLXS_PORT_LOCK);

		port_info->pi_error = FC_OUTOFBOUNDS;
		return (NULL);
	}
	/* Make sure the port is not already bound to the transport */
	if (port->flag & EMLXS_PORT_BOUND) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_port_bind: Port %d already bound. flag=%x",
		    bind_info->port_num, port->flag);

		mutex_exit(&EMLXS_PORT_LOCK);

		port_info->pi_error = FC_ALREADY;
		return (NULL);
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_bind_port: Port %d: port_info=%p bind_info=%p",
	    bind_info->port_num, port_info, bind_info);

#if (EMLXS_MODREV >= EMLXS_MODREV5)
	if (bind_info->port_npiv) {
		bcopy((caddr_t)&bind_info->port_nwwn, (caddr_t)&port->wwnn,
		    sizeof (NAME_TYPE));
		bcopy((caddr_t)&bind_info->port_pwwn, (caddr_t)&port->wwpn,
		    sizeof (NAME_TYPE));
		if (port->snn[0] == 0) {
			(void) strncpy((caddr_t)port->snn, (caddr_t)hba->snn,
			    256);
		}
		if (port->spn[0] == 0) {
			(void) sprintf((caddr_t)port->spn, "%s VPort-%d",
			    (caddr_t)hba->spn, port->vpi);
		}
		port->flag |= (EMLXS_PORT_CONFIG | EMLXS_PORT_ENABLE);

		if (cfg[CFG_VPORT_RESTRICTED].current) {
			port->flag |= EMLXS_PORT_RESTRICTED;
		}
	}
#endif	/* >= EMLXS_MODREV5 */

	/* Perform generic port initialization */
	emlxs_port_init(port);

	/* Perform SFS specific initialization */
	port->ulp_handle = bind_info->port_handle;
	port->ulp_statec_cb = bind_info->port_statec_cb;
	port->ulp_unsol_cb = bind_info->port_unsol_cb;
	port->ub_count = EMLXS_UB_TOKEN_OFFSET;
	port->ub_pool = NULL;

#ifdef MENLO_TEST
	if ((hba->model_info.device_id == PCI_DEVICE_ID_LP21000_M) &&
	    (cfg[CFG_HORNET_FLOGI].current == 0)) {
		hba->flag |= FC_MENLO_MODE;
	}
#endif	/* MENLO_TEST */


	/* Update the port info structure */

	/* Set the topology and state */
	if ((hba->state < FC_LINK_UP) ||
	    ((port->vpi > 0) && (!(port->flag & EMLXS_PORT_ENABLE) ||
	    !(hba->flag & FC_NPIV_SUPPORTED)))) {
		port_info->pi_port_state = FC_STATE_OFFLINE;
		port_info->pi_topology = FC_TOP_UNKNOWN;
	}
#ifdef MENLO_SUPPORT
	else if (hba->flag & FC_MENLO_MODE) {
		port_info->pi_port_state = FC_STATE_OFFLINE;
		port_info->pi_topology = FC_TOP_UNKNOWN;
	}
#endif	/* MENLO_SUPPORT */
	else {
		/* Check for loop topology */
		if (hba->topology == TOPOLOGY_LOOP) {
			port_info->pi_port_state = FC_STATE_LOOP;
			(void) strcpy(topology, ", loop");

			if (hba->flag & FC_FABRIC_ATTACHED) {
				port_info->pi_topology = FC_TOP_PUBLIC_LOOP;
			} else {
				port_info->pi_topology = FC_TOP_PRIVATE_LOOP;
			}
		} else {
			port_info->pi_topology = FC_TOP_FABRIC;
			port_info->pi_port_state = FC_STATE_ONLINE;
			(void) strcpy(topology, ", fabric");
		}

		/* Set the link speed */
		switch (hba->linkspeed) {
		case 0:
			(void) strcpy(linkspeed, "Gb");
			port_info->pi_port_state |= FC_STATE_1GBIT_SPEED;
			break;

		case LA_1GHZ_LINK:
			(void) strcpy(linkspeed, "1Gb");
			port_info->pi_port_state |= FC_STATE_1GBIT_SPEED;
			break;
		case LA_2GHZ_LINK:
			(void) strcpy(linkspeed, "2Gb");
			port_info->pi_port_state |= FC_STATE_2GBIT_SPEED;
			break;
		case LA_4GHZ_LINK:
			(void) strcpy(linkspeed, "4Gb");
			port_info->pi_port_state |= FC_STATE_4GBIT_SPEED;
			break;
		case LA_8GHZ_LINK:
			(void) strcpy(linkspeed, "8Gb");
			port_info->pi_port_state |= FC_STATE_8GBIT_SPEED;
			break;
		case LA_10GHZ_LINK:
			(void) strcpy(linkspeed, "10Gb");
			port_info->pi_port_state |= FC_STATE_10GBIT_SPEED;
			break;
		default:
			(void) sprintf(linkspeed, "unknown(0x%x)",
			    hba->linkspeed);
			break;
		}

		/* Adjusting port context for link up messages */
		vport = port;
		port = &PPORT;
		if (vport->vpi == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg, "%s%s",
			    linkspeed, topology);
		} else if (!(hba->flag & FC_NPIV_LINKUP)) {
			hba->flag |= FC_NPIV_LINKUP;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_npiv_link_up_msg,
			    "%s%s", linkspeed, topology);
		}
		port = vport;

	}

	/* Save initial state */
	port->ulp_statec = port_info->pi_port_state;

	/*
	 * The transport needs a copy of the common service parameters for
	 * this port. The transport can get any updates throuth the getcap
	 * entry point.
	 */
	bcopy((void *) &port->sparam,
	    (void *) &port_info->pi_login_params.common_service,
	    sizeof (SERV_PARM));

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	/* Swap the service parameters for ULP */
	emlxs_swap_service_params((SERV_PARM *)
	    &port_info->pi_login_params.common_service);
#endif	/* EMLXS_MODREV2X */

	port_info->pi_login_params.common_service.btob_credit = 0xffff;

	bcopy((void *) &port->wwnn,
	    (void *) &port_info->pi_login_params.node_ww_name,
	    sizeof (NAME_TYPE));

	bcopy((void *) &port->wwpn,
	    (void *) &port_info->pi_login_params.nport_ww_name,
	    sizeof (NAME_TYPE));

	/*
	 * We need to turn off CLASS2 support. Otherwise, FC transport will
	 * use CLASS2 as default class and never try with CLASS3.
	 */
#if (EMLXS_MODREV >= EMLXS_MODREV3)
#if (EMLXS_MODREVX >= EMLXS_MODREV3X)
	if ((port_info->pi_login_params.class_1.class_opt) & 0x0080) {
		port_info->pi_login_params.class_1.class_opt &= ~0x0080;
	}
	if ((port_info->pi_login_params.class_2.class_opt) & 0x0080) {
		port_info->pi_login_params.class_2.class_opt &= ~0x0080;
	}
#else	/* EMLXS_SPARC or EMLXS_MODREV2X */
	if ((port_info->pi_login_params.class_1.class_opt) & 0x8000) {
		port_info->pi_login_params.class_1.class_opt &= ~0x8000;
	}
	if ((port_info->pi_login_params.class_2.class_opt) & 0x8000) {
		port_info->pi_login_params.class_2.class_opt &= ~0x8000;
	}
#endif	/* >= EMLXS_MODREV3X */
#endif	/* >= EMLXS_MODREV3 */


#if (EMLXS_MODREV <= EMLXS_MODREV2)
	if ((port_info->pi_login_params.class_1.data[0]) & 0x80) {
		port_info->pi_login_params.class_1.data[0] &= ~0x80;
	}
	if ((port_info->pi_login_params.class_2.data[0]) & 0x80) {
		port_info->pi_login_params.class_2.data[0] &= ~0x80;
	}
#endif	/* <= EMLXS_MODREV2 */

	/* Additional parameters */
	port_info->pi_s_id.port_id = port->did;
	port_info->pi_s_id.priv_lilp_posit = 0;
	port_info->pi_hard_addr.hard_addr = cfg[CFG_ASSIGN_ALPA].current;

	/* Initialize the RNID parameters */
	bzero(&port_info->pi_rnid_params, sizeof (port_info->pi_rnid_params));

	(void) sprintf((char *)port_info->pi_rnid_params.params.global_id,
	    "%01x%01x%02x%02x%02x%02x%02x%02x%02x",
	    hba->wwpn.nameType, hba->wwpn.IEEEextMsn, hba->wwpn.IEEEextLsb,
	    hba->wwpn.IEEE[0], hba->wwpn.IEEE[1], hba->wwpn.IEEE[2],
	    hba->wwpn.IEEE[3], hba->wwpn.IEEE[4], hba->wwpn.IEEE[5]);

	port_info->pi_rnid_params.params.unit_type = RNID_HBA;
	port_info->pi_rnid_params.params.port_id = port->did;
	port_info->pi_rnid_params.params.ip_version = RNID_IPV4;

	/* Initialize the port attributes */
	bzero(&port_info->pi_attrs, sizeof (port_info->pi_attrs));

	(void) strcpy(port_info->pi_attrs.manufacturer, "Emulex");

	port_info->pi_rnid_params.status = FC_SUCCESS;

	(void) strcpy(port_info->pi_attrs.serial_number, vpd->serial_num);

	(void) sprintf(port_info->pi_attrs.firmware_version, "%s (%s)",
	    vpd->fw_version, vpd->fw_label);

	(void) strcpy(port_info->pi_attrs.option_rom_version,
	    vpd->fcode_version);

	(void) sprintf(port_info->pi_attrs.driver_version, "%s (%s)",
	    emlxs_version, emlxs_revision);

	(void) strcpy(port_info->pi_attrs.driver_name, DRIVER_NAME);

	port_info->pi_attrs.vendor_specific_id =
	    ((hba->model_info.device_id << 16) | PCI_VENDOR_ID_EMULEX);

	port_info->pi_attrs.supported_cos = SWAP_DATA32(FC_NS_CLASS3);

	port_info->pi_attrs.max_frame_size = FF_FRAME_SIZE;

#if (EMLXS_MODREV >= EMLXS_MODREV5)

	port_info->pi_rnid_params.params.num_attached = 0;

	/*
	 * Copy the serial number string (right most 16 chars) into the right
	 * justified local buffer
	 */
	bzero(buffer, sizeof (buffer));
	length = strlen(vpd->serial_num);
	len = (length > 16) ? 16 : length;
	bcopy(&vpd->serial_num[(length - len)],
	    &buffer[(sizeof (buffer) - len)], len);

	port_info->pi_attrs.hba_fru_details.port_index = vpd->port_index;

#endif	/* >= EMLXS_MODREV5 */

#if ((EMLXS_MODREV == EMLXS_MODREV3) || (EMLX_MODREV == EMLXS_MODREV4))

	port_info->pi_rnid_params.params.num_attached = 0;

	if (hba->flag & FC_NPIV_ENABLED) {
		uint8_t byte;
		uint8_t *wwpn;
		uint32_t i;
		uint32_t j;

		/* Copy the WWPN as a string into the local buffer */
		wwpn = (uint8_t *)&hba->wwpn;
		for (i = 0; i < 16; i++) {
			byte = *wwpn++;
			j = ((byte & 0xf0) >> 4);
			if (j <= 9) {
				buffer[i] = (char)((uint8_t)'0' +
				    (uint8_t)j);
			} else {
				buffer[i] = (char)((uint8_t)'A' +
				    (uint8_t)(j - 10));
			}

			i++;
			j = (byte & 0xf);
			if (j <= 9) {
				buffer[i] = (char)((uint8_t)'0' +
				    (uint8_t)j);
			} else {
				buffer[i] = (char)((uint8_t)'A' +
				    (uint8_t)(j - 10));
			}
		}

		port_info->pi_attrs.hba_fru_details.port_index = port->vpi;
	} else {
		/*
		 * Copy the serial number string (right most 16 chars) into
		 * the right justified local buffer
		 */
		bzero(buffer, sizeof (buffer));
		length = strlen(vpd->serial_num);
		len = (length > 16) ? 16 : length;
		bcopy(&vpd->serial_num[(length - len)],
		    &buffer[(sizeof (buffer) - len)], len);

		port_info->pi_attrs.hba_fru_details.port_index =
		    vpd->port_index;
	}

#endif	/* == EMLXS_MODREV3 || EMLXS_MODREV4 */

#if (EMLXS_MODREV >= EMLXS_MODREV3)

	dptr = (char *)&port_info->pi_attrs.hba_fru_details.high;
	dptr[0] = buffer[0];
	dptr[1] = buffer[1];
	dptr[2] = buffer[2];
	dptr[3] = buffer[3];
	dptr[4] = buffer[4];
	dptr[5] = buffer[5];
	dptr[6] = buffer[6];
	dptr[7] = buffer[7];
	port_info->pi_attrs.hba_fru_details.high =
	    SWAP_DATA64(port_info->pi_attrs.hba_fru_details.high);

	dptr = (char *)&port_info->pi_attrs.hba_fru_details.low;
	dptr[0] = buffer[8];
	dptr[1] = buffer[9];
	dptr[2] = buffer[10];
	dptr[3] = buffer[11];
	dptr[4] = buffer[12];
	dptr[5] = buffer[13];
	dptr[6] = buffer[14];
	dptr[7] = buffer[15];
	port_info->pi_attrs.hba_fru_details.low =
	    SWAP_DATA64(port_info->pi_attrs.hba_fru_details.low);

#endif	/* >= EMLXS_MODREV3 */

#if (EMLXS_MODREV >= EMLXS_MODREV4)
	(void) strncpy((caddr_t)port_info->pi_attrs.sym_node_name,
	    (caddr_t)port->snn, FCHBA_SYMB_NAME_LEN);
	(void) strncpy((caddr_t)port_info->pi_attrs.sym_port_name,
	    (caddr_t)port->spn, FCHBA_SYMB_NAME_LEN);
#endif	/* >= EMLXS_MODREV4 */

	(void) sprintf(port_info->pi_attrs.hardware_version, "%x", vpd->biuRev);

	/* Set the hba speed limit */
	if (vpd->link_speed & LMT_10GB_CAPABLE) {
		port_info->pi_attrs.supported_speed |= FC_HBA_PORTSPEED_10GBIT;
	}
	if (vpd->link_speed & LMT_8GB_CAPABLE) {
		port_info->pi_attrs.supported_speed |= FC_HBA_PORTSPEED_8GBIT;
	}
	if (vpd->link_speed & LMT_4GB_CAPABLE) {
		port_info->pi_attrs.supported_speed |= FC_HBA_PORTSPEED_4GBIT;
	}
	if (vpd->link_speed & LMT_2GB_CAPABLE) {
		port_info->pi_attrs.supported_speed |= FC_HBA_PORTSPEED_2GBIT;
	}
	if (vpd->link_speed & LMT_1GB_CAPABLE) {
		port_info->pi_attrs.supported_speed |= FC_HBA_PORTSPEED_1GBIT;
	}
	/* Set the hba model info */
	(void) strcpy(port_info->pi_attrs.model, hba->model_info.model);
	(void) strcpy(port_info->pi_attrs.model_description,
	    hba->model_info.model_desc);


	/* Log information */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Bind info: port_num           = %d", bind_info->port_num);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Bind info: port_handle        = %p", bind_info->port_handle);

#if (EMLXS_MODREV >= EMLXS_MODREV5)
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Bind info: port_npiv          = %d", bind_info->port_npiv);
#endif	/* >= EMLXS_MODREV5 */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: pi_topology        = %x", port_info->pi_topology);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: pi_error           = %x", port_info->pi_error);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: pi_port_state      = %x", port_info->pi_port_state);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: port_id            = %x", port_info->pi_s_id.port_id);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: priv_lilp_posit    = %x",
	    port_info->pi_s_id.priv_lilp_posit);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: hard_addr          = %x",
	    port_info->pi_hard_addr.hard_addr);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.status        = %x",
	    port_info->pi_rnid_params.status);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.global_id     = %16s",
	    port_info->pi_rnid_params.params.global_id);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.unit_type     = %x",
	    port_info->pi_rnid_params.params.unit_type);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.port_id       = %x",
	    port_info->pi_rnid_params.params.port_id);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.num_attached  = %x",
	    port_info->pi_rnid_params.params.num_attached);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.ip_version    = %x",
	    port_info->pi_rnid_params.params.ip_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.udp_port      = %x",
	    port_info->pi_rnid_params.params.udp_port);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.ip_addr       = %16s",
	    port_info->pi_rnid_params.params.ip_addr);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.spec_id_resv  = %x",
	    port_info->pi_rnid_params.params.specific_id_resv);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: rnid.topo_flags    = %x",
	    port_info->pi_rnid_params.params.topo_flags);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: manufacturer       = %s",
	    port_info->pi_attrs.manufacturer);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: serial_num         = %s",
	    port_info->pi_attrs.serial_number);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: model              = %s",
	    port_info->pi_attrs.model);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: model_description  = %s",
	    port_info->pi_attrs.model_description);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: hardware_version   = %s",
	    port_info->pi_attrs.hardware_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: driver_version     = %s",
	    port_info->pi_attrs.driver_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: option_rom_version = %s",
	    port_info->pi_attrs.option_rom_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: firmware_version   = %s",
	    port_info->pi_attrs.firmware_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: driver_name        = %s",
	    port_info->pi_attrs.driver_name);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: vendor_specific_id = %x",
	    port_info->pi_attrs.vendor_specific_id);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: supported_cos      = %x",
	    port_info->pi_attrs.supported_cos);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: supported_speed    = %x",
	    port_info->pi_attrs.supported_speed);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: max_frame_size     = %x",
	    port_info->pi_attrs.max_frame_size);

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: fru_port_index     = %x",
	    port_info->pi_attrs.hba_fru_details.port_index);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: fru_high           = %llx",
	    port_info->pi_attrs.hba_fru_details.high);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: fru_low            = %llx",
	    port_info->pi_attrs.hba_fru_details.low);
#endif	/* >= EMLXS_MODREV3 */

#if (EMLXS_MODREV >= EMLXS_MODREV4)
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: sym_node_name      = %s",
	    port_info->pi_attrs.sym_node_name);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Port info: sym_port_name      = %s",
	    port_info->pi_attrs.sym_port_name);
#endif	/* >= EMLXS_MODREV4 */

	/* Set the bound flag */
	port->flag |= EMLXS_PORT_BOUND;
	hba->num_of_ports++;

	mutex_exit(&EMLXS_PORT_LOCK);

	return ((opaque_t)port);

} /* emlxs_bind_port() */


static void
emlxs_unbind_port(opaque_t fca_port_handle)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;
	uint32_t count;
	/* uint32_t i; */
	/* NODELIST *nlp; */
	/* NODELIST *next; */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_unbind_port: port=%p", port);

	/* Check ub buffer pools */
	if (port->ub_pool) {
		mutex_enter(&EMLXS_UB_LOCK);

		/* Wait up to 10 seconds for all ub pools to be freed */
		count = 10 * 2;
		while (port->ub_pool && count) {
			mutex_exit(&EMLXS_UB_LOCK);
			delay(drv_usectohz(500000));	/* half second wait */
			count--;
			mutex_enter(&EMLXS_UB_LOCK);
		}

		if (port->ub_pool) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_unbind_port: Unsolicited buffers still "
			    "active. port=%p. Destroying...", port);

			/* Destroy all pools */
			while (port->ub_pool) {
				emlxs_ub_destroy(port, port->ub_pool);
			}
		}
		mutex_exit(&EMLXS_UB_LOCK);
	}
	/* Destroy & flush all port nodes, if they exist */
	if (port->node_count) {
		(void) emlxs_mb_unreg_rpi(port, 0xffff, 0, 0, 0);
	}
#if (EMLXS_MODREV >= EMLXS_MODREV5)
	if ((hba->flag & FC_NPIV_ENABLED) &&
	    (port->flag & (EMLXS_PORT_CONFIG | EMLXS_PORT_ENABLE))) {
		(void) emlxs_mb_unreg_vpi(port);
	}
#endif

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	port->flag &= ~EMLXS_PORT_BOUND;
	hba->num_of_ports--;

	port->ulp_handle = 0;
	port->ulp_statec = FC_STATE_OFFLINE;
	port->ulp_statec_cb = NULL;
	port->ulp_unsol_cb = NULL;

	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_unbind_port() */


/*ARGSUSED*/
extern int
emlxs_pkt_init(opaque_t fca_port_handle, fc_packet_t *pkt, int32_t sleep)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp = (emlxs_buf_t *)pkt->pkt_fca_private;
	uint32_t pkt_flags;

	if (!sbp) {
		return (FC_FAILURE);
	}
	pkt_flags = sbp->pkt_flags;
	bzero((void *) sbp, sizeof (emlxs_buf_t));

	mutex_init(&sbp->mtx, NULL, MUTEX_DRIVER, (void *) hba->intr_arg);
	sbp->pkt_flags = PACKET_VALID | PACKET_RETURNED |
	    (pkt_flags & PACKET_ALLOCATED);
	sbp->port = port;
	sbp->pkt = pkt;
	sbp->iocbq.sbp = sbp;

	return (FC_SUCCESS);

} /* emlxs_pkt_init() */



static void
emlxs_initialize_pkt(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	fc_packet_t *pkt = PRIV2PKT(sbp);
	uint32_t *iptr;

	mutex_enter(&sbp->mtx);

	/* Reinitialize */
	sbp->pkt = pkt;
	sbp->port = port;
	sbp->bmp = NULL;
	sbp->pkt_flags &= (PACKET_VALID | PACKET_ALLOCATED);
	sbp->iotag = 0;
	sbp->ticks = 0;
	sbp->abort_attempts = 0;
	sbp->fpkt = NULL;
	sbp->flush_count = 0;
	sbp->next = NULL;

	if (!port->tgt_mode) {
		sbp->node = NULL;
		sbp->did = 0;
		sbp->lun = 0;
		sbp->class = 0;
		sbp->ring = NULL;
		sbp->class = 0;
	}
	bzero((void *) &sbp->iocbq, sizeof (IOCBQ));
	sbp->iocbq.sbp = sbp;

	if ((pkt->pkt_tran_flags & FC_TRAN_NO_INTR) || !pkt->pkt_comp ||
	    ddi_in_panic()) {
		sbp->pkt_flags |= PACKET_POLLED;
	}
	/* Prepare the fc packet */
	pkt->pkt_state = FC_PKT_SUCCESS;
	pkt->pkt_reason = 0;
	pkt->pkt_action = 0;
	pkt->pkt_expln = 0;
	pkt->pkt_data_resid = 0;
	pkt->pkt_resp_resid = 0;

	/* Make sure all pkt's have a proper timeout */
	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		/* This disables all IOCB on chip timeouts */
		pkt->pkt_timeout = 0x80000000;
	} else if (pkt->pkt_timeout == 0 || pkt->pkt_timeout == 0xffffffff) {
		pkt->pkt_timeout = 60;
	}
	/* Clear the response buffer */
	if (pkt->pkt_rsplen) {
		/* Check for FCP commands */
		if ((pkt->pkt_tran_type == FC_PKT_FCP_READ) ||
		    (pkt->pkt_tran_type == FC_PKT_FCP_WRITE)) {
			iptr = (uint32_t *)pkt->pkt_resp;
			iptr[2] = 0;
			iptr[3] = 0;
		} else {
			bzero(pkt->pkt_resp, pkt->pkt_rsplen);
		}
	}
	mutex_exit(&sbp->mtx);

	return;

} /* emlxs_initialize_pkt() */



/*
 * We may not need this routine
 */
/*ARGSUSED*/
extern int
emlxs_pkt_uninit(opaque_t fca_port_handle, fc_packet_t *pkt)
{
	/* emlxs_port_t *port = (emlxs_port_t *)fca_port_handle; */
	emlxs_buf_t *sbp = PKT2PRIV(pkt);

	if (!sbp) {
		return (FC_FAILURE);
	}
	if (!(sbp->pkt_flags & PACKET_VALID)) {
		return (FC_FAILURE);
	}
	sbp->pkt_flags &= ~PACKET_VALID;
	mutex_destroy(&sbp->mtx);

	return (FC_SUCCESS);

} /* emlxs_pkt_uninit() */


static int
emlxs_get_cap(opaque_t fca_port_handle, char *cap, void *ptr)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;
	int32_t rval;

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		return (FC_CAP_ERROR);
	}
	if (strcmp(cap, FC_NODE_WWN) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_NODE_WWN");

		bcopy((void *) &hba->wwnn, (void *) ptr, sizeof (NAME_TYPE));
		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_LOGIN_PARAMS) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_LOGIN_PARAMS");

		/*
		 * We need to turn off CLASS2 support. Otherwise, FC
		 * transport will use CLASS2 as default class and never try
		 * with CLASS3.
		 */
		hba->sparam.cls2.classValid = 0;

		bcopy((void *) &hba->sparam, (void *) ptr, sizeof (SERV_PARM));

		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_CAP_UNSOL_BUF) == 0) {
		int32_t *num_bufs;
		emlxs_config_t *cfg = &CFG;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_CAP_UNSOL_BUF (%d)",
		    cfg[CFG_UB_BUFS].current);

		num_bufs = (int32_t *)ptr;

		/*
		 * We multiply by MAX_VPORTS because ULP uses a formula to
		 * calculate ub bufs from this
		 */
		*num_bufs = (cfg[CFG_UB_BUFS].current * MAX_VPORTS);

		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_CAP_PAYLOAD_SIZE) == 0) {
		int32_t *size;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_CAP_PAYLOAD_SIZE");

		size = (int32_t *)ptr;
		*size = -1;
		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_CAP_POST_RESET_BEHAVIOR) == 0) {
		fc_reset_action_t *action;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_CAP_POST_RESET_BEHAVIOR");

		action = (fc_reset_action_t *)ptr;
		*action = FC_RESET_RETURN_ALL;
		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_CAP_NOSTREAM_ON_UNALIGN_BUF) == 0) {
		fc_dma_behavior_t *behavior;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_CAP_NOSTREAM_ON_UNALIGN_BUF");

		behavior = (fc_dma_behavior_t *)ptr;
		*behavior = FC_ALLOW_STREAMING;
		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_CAP_FCP_DMA) == 0) {
		fc_fcp_dma_t *fcp_dma;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_CAP_FCP_DMA");

		fcp_dma = (fc_fcp_dma_t *)ptr;
		*fcp_dma = FC_DVMA_SPACE;
		rval = FC_CAP_FOUND;

	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: Unknown capability. [%s]", cap);

		rval = FC_CAP_ERROR;

	}

	return (rval);

} /* emlxs_get_cap() */



static int
emlxs_set_cap(opaque_t fca_port_handle, char *cap, void *ptr)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	/* emlxs_hba_t *hba = HBA; */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_set_cap: cap=[%s] arg=%p", cap, ptr);

	return (FC_CAP_ERROR);

} /* emlxs_set_cap() */


static opaque_t
emlxs_get_device(opaque_t fca_port_handle, fc_portid_t d_id)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	/* emlxs_hba_t *hba = HBA; */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_get_device: did=%x", d_id);

	return (NULL);

} /* emlxs_get_device() */


static int32_t
emlxs_notify(opaque_t fca_port_handle, uint32_t cmd)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	/* emlxs_hba_t *hba = HBA; */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_notify: cmd=%x", cmd);

	return (FC_SUCCESS);

} /* emlxs_notify */



static int
emlxs_get_map(opaque_t fca_port_handle, fc_lilpmap_t *mapbuf)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;

	uint32_t lilp_length;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_get_map: mapbuf=%p length=%d (%X,%X,%X,%X)", mapbuf,
	    port->alpa_map[0], port->alpa_map[1], port->alpa_map[2],
	    port->alpa_map[3], port->alpa_map[4]);

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		return (FC_NOMAP);
	}
	if (hba->topology != TOPOLOGY_LOOP) {
		return (FC_NOMAP);
	}
	/* Check if alpa map is available */
	if (port->alpa_map[0] != 0) {
		mapbuf->lilp_magic = MAGIC_LILP;
	} else {	/* No LILP map available */
		/*
		 * Set lilp_magic to MAGIC_LISA and this will trigger an ALPA
		 * scan in ULP
		 */
		mapbuf->lilp_magic = MAGIC_LISA;
	}

	mapbuf->lilp_myalpa = port->did;

	/* The first byte of the alpa_map is the lilp map length */
	/* Add one to include the lilp length byte itself */
	lilp_length = (uint32_t)port->alpa_map[0] + 1;

	/* Make sure the max transfer is 128 bytes */
	if (lilp_length > 128) {
		lilp_length = 128;
	}
	/*
	 * We start copying from the lilp_length field in order to get a word
	 * aligned address
	 */
	bcopy((void *) &port->alpa_map, (void *) &mapbuf->lilp_length,
	    lilp_length);

	return (FC_SUCCESS);

} /* emlxs_get_map() */



extern int
emlxs_transport(opaque_t fca_port_handle, fc_packet_t *pkt)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	uint32_t rval;
	uint32_t pkt_flags;

	/* Make sure adapter is online */
	if (!(hba->flag & FC_ONLINE_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Adapter offline.");

		return (FC_OFFLINE);
	}
	/* Validate packet */
	sbp = PKT2PRIV(pkt);

	/* Make sure ULP was told that the port was online */
	if ((port->ulp_statec == FC_STATE_OFFLINE) &&
	    !(sbp->pkt_flags & PACKET_ALLOCATED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Port offline.");

		return (FC_OFFLINE);
	}
	if (sbp->port != port) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_error_msg,
		    "Invalid port handle. sbp=%p port=%p flags=%x",
		    sbp, sbp->port, sbp->pkt_flags);
		return (FC_BADPACKET);
	}
	if (!(sbp->pkt_flags & (PACKET_VALID | PACKET_RETURNED))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_error_msg,
		    "Invalid packet flags. sbp=%p port=%p flags=%x",
		    sbp, sbp->port, sbp->pkt_flags);
		return (FC_BADPACKET);
	}
#ifdef SFCT_SUPPORT
	if (port->tgt_mode && !sbp->fct_cmd &&
	    !(sbp->pkt_flags & PACKET_ALLOCATED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_error_msg,
		    "Packet blocked. Target mode.");
		return (FC_TRANSPORT_ERROR);
	}
#endif	/* SFCT_SUPPORT */

#ifdef IDLE_TIMER
	emlxs_pm_busy_component(hba);
#endif	/* IDLE_TIMER */

	/* Prepare the packet for transport */
	emlxs_initialize_pkt(port, sbp);

	/*
	 * Save a copy of the pkt flags.  We will check the polling flag
	 * later
	 */
	pkt_flags = sbp->pkt_flags;

	/* Send the packet */
	switch (pkt->pkt_tran_type) {
	case FC_PKT_FCP_READ:
	case FC_PKT_FCP_WRITE:
		rval = emlxs_send_fcp_cmd(port, sbp);
		break;

	case FC_PKT_IP_WRITE:
	case FC_PKT_BROADCAST:
		rval = emlxs_send_ip(port, sbp);
		break;

	case FC_PKT_EXCHANGE:
		switch (pkt->pkt_cmd_fhdr.type) {
		case FC_TYPE_SCSI_FCP:
			rval = emlxs_send_fcp_cmd(port, sbp);
			break;

		case FC_TYPE_FC_SERVICES:
			rval = emlxs_send_ct(port, sbp);
			break;

#ifdef MENLO_SUPPORT
		case EMLXS_MENLO_TYPE:
			rval = emlxs_send_menlo_cmd(port, sbp);
			break;
#endif	/* MENLO_SUPPORT */

		default:
			rval = emlxs_send_els(port, sbp);
		}
		break;

	case FC_PKT_OUTBOUND:
		switch (pkt->pkt_cmd_fhdr.type) {
#ifdef SFCT_SUPPORT
		case FC_TYPE_SCSI_FCP:
			rval = emlxs_send_fcp_status(port, sbp);
			break;
#endif	/* SFCT_SUPPORT */

		case FC_TYPE_FC_SERVICES:
			rval = emlxs_send_ct_rsp(port, sbp);
			break;
#ifdef MENLO_SUPPORT
		case EMLXS_MENLO_TYPE:
			rval = emlxs_send_menlo_cmd(port, sbp);
			break;
#endif	/* MENLO_SUPPORT */

		default:
			rval = emlxs_send_els_rsp(port, sbp);
		}
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_error_msg,
		    "Unsupported pkt_tran_type. type=%x", pkt->pkt_tran_type);
		rval = FC_TRANSPORT_ERROR;
		break;
	}

	/* Check if send was not successful */
	if (rval != FC_SUCCESS) {
		/* Return packet to ULP */
		mutex_enter(&sbp->mtx);
		sbp->pkt_flags |= PACKET_RETURNED;
		mutex_exit(&sbp->mtx);

		return (rval);
	}
	/*
	 * Check if this packet should be polled for completion before
	 * returning
	 */
	/*
	 * This check must be done with a saved copy of the pkt_flags
	 * because the packet itself could already be freed from memory
	 * if it was not polled.
	 */
	if (pkt_flags & PACKET_POLLED) {
		emlxs_poll(port, sbp);
	}
	return (FC_SUCCESS);

} /* emlxs_transport() */



static void
emlxs_poll(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt = PRIV2PKT(sbp);
	clock_t timeout;
	clock_t time;
	int32_t pkt_ret;
	uint32_t att_bit;
	emlxs_ring_t *rp;

	/* Set thread timeout */
	timeout = emlxs_timeout(hba, (pkt->pkt_timeout +
	    (4 * hba->fc_ratov) + 60));

	/* Check for panic situation */
	if (ddi_in_panic()) {
		/*
		 * In panic situations there will be one thread with no
		 * interrrupts (hard or soft) and no timers
		 */

		/*
		 * We must manually poll everything in this thread to keep
		 * the driver going.
		 */
		rp = (emlxs_ring_t *)sbp->ring;
		switch (rp->ringno) {
		case FC_FCP_RING:
			att_bit = HA_R0ATT;
			break;

		case FC_IP_RING:
			att_bit = HA_R1ATT;
			break;

		case FC_ELS_RING:
			att_bit = HA_R2ATT;
			break;

		case FC_CT_RING:
			att_bit = HA_R3ATT;
			break;
		}

		/* Keep polling the chip until our IO is completed */
		(void) drv_getparm(LBOLT, &time);
		while ((time < timeout) &&
		    !(sbp->pkt_flags & PACKET_COMPLETED)) {
			emlxs_poll_intr(hba, att_bit);
			(void) drv_getparm(LBOLT, &time);
		}
	} else {
		/* Wait for IO completion or pkt timeout */
		mutex_enter(&EMLXS_PKT_LOCK);
		pkt_ret = 0;
		while ((pkt_ret != -1) &&
		    !(sbp->pkt_flags & PACKET_COMPLETED)) {
			pkt_ret = cv_timedwait(&EMLXS_PKT_CV,
			    &EMLXS_PKT_LOCK, timeout);
		}
		mutex_exit(&EMLXS_PKT_LOCK);
	}

	/*
	 * Check if timeout occured.  This is not good.  Something happened
	 * to our IO.
	 */
	if (!(sbp->pkt_flags & PACKET_COMPLETED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_timeout_msg,
		    "Polled I/O: sbp=%p tmo=%d", sbp, timeout);

		mutex_enter(&sbp->mtx);
		emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_ABORT_TIMEOUT, 0);
		sbp->pkt_flags |= (PACKET_IN_TIMEOUT | PACKET_IN_COMPLETION);
		mutex_exit(&sbp->mtx);

		(void) emlxs_unregister_pkt(sbp->ring, sbp->iotag, 1);
	}
	/* Check for fcp reset pkt */
	if (sbp->pkt_flags & PACKET_FCP_RESET) {
		if (sbp->pkt_flags & PACKET_FCP_TGT_RESET) {
			/* Flush the IO's on the chipq */
			(void) emlxs_chipq_node_flush(port,
			    &hba->ring[FC_FCP_RING], sbp->node, sbp);
		} else {
			/* Flush the IO's on the chipq for this lun */
			(void) emlxs_chipq_lun_flush(port, sbp->node, sbp->lun,
			    sbp);
		}

		if (sbp->flush_count == 0) {
			emlxs_node_open(port, sbp->node, FC_FCP_RING);
			goto done;
		}
		/* Reset the timeout so the flush has time to complete */
		timeout = emlxs_timeout(hba, 60);
		(void) drv_getparm(LBOLT, &time);
		while ((time < timeout) && sbp->flush_count > 0) {
			delay(drv_usectohz(2000000));
			(void) drv_getparm(LBOLT, &time);
		}

		if (sbp->flush_count == 0) {
			emlxs_node_open(port, sbp->node, FC_FCP_RING);
			goto done;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_flush_timeout_msg,
		    "sbp=%p flush_count=%d. Waiting...", sbp, sbp->flush_count);

		/* Let's try this one more time */

		if (sbp->pkt_flags & PACKET_FCP_TGT_RESET) {
			/* Flush the IO's on the chipq */
			(void) emlxs_chipq_node_flush(port,
			    &hba->ring[FC_FCP_RING], sbp->node, sbp);
		} else {
			/* Flush the IO's on the chipq for this lun */
			(void) emlxs_chipq_lun_flush(port, sbp->node, sbp->lun,
			    sbp);
		}

		/* Reset the timeout so the flush has time to complete */
		timeout = emlxs_timeout(hba, 60);
		(void) drv_getparm(LBOLT, &time);
		while ((time < timeout) && sbp->flush_count > 0) {
			delay(drv_usectohz(2000000));
			(void) drv_getparm(LBOLT, &time);
		}

		if (sbp->flush_count == 0) {
			emlxs_node_open(port, sbp->node, FC_FCP_RING);
			goto done;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_flush_timeout_msg,
		    "sbp=%p flush_count=%d. Resetting link.",
		    sbp, sbp->flush_count);

		/* Let's first try to reset the link */
		(void) emlxs_reset(port, FC_FCA_LINK_RESET);

		if (sbp->flush_count == 0) {
			goto done;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_flush_timeout_msg,
		    "sbp=%p flush_count=%d. Resetting HBA.",
		    sbp, sbp->flush_count);

		/* If that doesn't work, reset the adapter */
		(void) emlxs_reset(port, FC_FCA_RESET);

		if (sbp->flush_count != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_flush_timeout_msg,
			    "sbp=%p flush_count=%d. Giving up.",
			    sbp, sbp->flush_count);
		}
	}	/* PACKET_FCP_RESET */
done:

	/* Packet has been declared completed and is now ready to be returned */

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_unswap_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	mutex_enter(&sbp->mtx);
	sbp->pkt_flags |= PACKET_RETURNED;
	mutex_exit(&sbp->mtx);

	/* Make ULP completion callback if required */
	if (pkt->pkt_comp) {
		(*pkt->pkt_comp) (pkt);
	}
	return;

} /* emlxs_poll() */


static int
emlxs_ub_alloc(opaque_t fca_port_handle, uint64_t tokens[], uint32_t size,
    uint32_t *count, uint32_t type)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;

	char *err = NULL;
	emlxs_unsol_buf_t *pool;
	emlxs_unsol_buf_t *new_pool;
	/* emlxs_unsol_buf_t *prev_pool; */
	int32_t i;
	/* int32_t j; */
	int result;
	uint32_t free_resv;
	uint32_t free;
	emlxs_config_t *cfg = &CFG;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	/* RING *rp; */

	if (port->tgt_mode) {
		if (tokens && count) {
			bzero(tokens, (sizeof (uint64_t) * (*count)));
		}
		return (FC_SUCCESS);
	}
	if (!(port->flag & EMLXS_PORT_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "ub_alloc failed: Port not bound! size=%x count=%d type=%x",
		    size, *count, type);

		return (FC_FAILURE);
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "ub_alloc: size=%x count=%d type=%x", size, *count, type);

	if (count && (*count > EMLXS_MAX_UBUFS)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
		    "ub_alloc failed: Too many unsolicted buffers"
		    " requested. count=%x", *count);

		return (FC_FAILURE);

	}
	if (tokens == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
		    "ub_alloc failed: Token array is NULL.");

		return (FC_FAILURE);
	}
	/* Clear the token array */
	bzero(tokens, (sizeof (uint64_t) * (*count)));

	free_resv = 0;
	free = *count;
	switch (type) {
	case FC_TYPE_BASIC_LS:
		err = "BASIC_LS";
		break;
	case FC_TYPE_EXTENDED_LS:
		err = "EXTENDED_LS";
		free = *count / 2;	/* Hold 50% for normal use */
		free_resv = *count - free;	/* Reserve 50% for RSCN use */

		/* rp = &hba->ring[FC_ELS_RING]; */
		break;
	case FC_TYPE_IS8802:
		err = "IS8802";
		break;
	case FC_TYPE_IS8802_SNAP:
		err = "IS8802_SNAP";

		if (cfg[CFG_NETWORK_ON].current == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
			    "ub_alloc failed: IP support is disabled.");

			return (FC_FAILURE);
		}
		/* rp = &hba->ring[FC_IP_RING]; */
		break;
	case FC_TYPE_SCSI_FCP:
		err = "SCSI_FCP";
		break;
	case FC_TYPE_SCSI_GPP:
		err = "SCSI_GPP";
		break;
	case FC_TYPE_HIPP_FP:
		err = "HIPP_FP";
		break;
	case FC_TYPE_IPI3_MASTER:
		err = "IPI3_MASTER";
		break;
	case FC_TYPE_IPI3_SLAVE:
		err = "IPI3_SLAVE";
		break;
	case FC_TYPE_IPI3_PEER:
		err = "IPI3_PEER";
		break;
	case FC_TYPE_FC_SERVICES:
		err = "FC_SERVICES";
		break;
	}


	mutex_enter(&EMLXS_UB_LOCK);

	/*
	 * Walk through the list of the unsolicited buffers for this ddiinst
	 * of emlx.
	 */

	/* prev_pool = NULL; */
	pool = port->ub_pool;

	/*
	 * The emlxs_ub_alloc() can be called more than once with different
	 * size. We will reject the call if there are duplicate size with the
	 * same FC-4 type.
	 */
	while (pool) {
		if ((pool->pool_type == type) &&
		    (pool->pool_buf_size == size)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
			    "ub_alloc failed: Unsolicited buffer pool for"
			    " %s of size 0x%x bytes already exists.",
			    err, size);

			result = FC_FAILURE;
			goto fail;
		}
		/* prev_pool = pool; */
		pool = pool->pool_next;
	}

	new_pool = (emlxs_unsol_buf_t *)
	    kmem_zalloc(sizeof (emlxs_unsol_buf_t), KM_SLEEP);
	if (new_pool == NULL) {
		result = FC_FAILURE;
		goto fail;
	}
	new_pool->pool_next = NULL;
	new_pool->pool_type = type;
	new_pool->pool_buf_size = size;
	new_pool->pool_nentries = *count;
	new_pool->pool_available = new_pool->pool_nentries;
	new_pool->pool_free = free;
	new_pool->pool_free_resv = free_resv;
	new_pool->fc_ubufs =
	    kmem_zalloc((sizeof (fc_unsol_buf_t) * (*count)), KM_SLEEP);

	if (new_pool->fc_ubufs == NULL) {
		kmem_free(new_pool, sizeof (emlxs_unsol_buf_t));
		result = FC_FAILURE;
		goto fail;
	}
	new_pool->pool_first_token = port->ub_count;
	new_pool->pool_last_token = port->ub_count + new_pool->pool_nentries;

	for (i = 0; i < new_pool->pool_nentries; i++) {
		ubp = (fc_unsol_buf_t *)&new_pool->fc_ubufs[i];
		ubp->ub_port_handle = port->ulp_handle;
		ubp->ub_token = (uint64_t)(unsigned long)ubp;
		ubp->ub_bufsize = size;
		ubp->ub_class = FC_TRAN_CLASS3;
		ubp->ub_port_private = NULL;
		ubp->ub_fca_private = (emlxs_ub_priv_t *)
		    kmem_zalloc(sizeof (emlxs_ub_priv_t), KM_SLEEP);

		if (ubp->ub_fca_private == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
			    "ub_alloc failed: Unable to allocate "
			    "fca_private object.");

			result = FC_FAILURE;
			goto fail;
		}
		/*
		 * Initialize emlxs_ub_priv_t
		 */
		ub_priv = ubp->ub_fca_private;
		ub_priv->ubp = ubp;
		ub_priv->port = port;
		ub_priv->flags = EMLXS_UB_FREE;
		ub_priv->available = 1;
		ub_priv->pool = new_pool;
		ub_priv->time = 0;
		ub_priv->timeout = 0;
		ub_priv->token = port->ub_count;
		ub_priv->cmd = 0;

		/* Allocate the actual buffer */
		ubp->ub_buffer = (caddr_t)kmem_zalloc(size, KM_SLEEP);

		/* Check if we were not successful */
		if (ubp->ub_buffer == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
			    "ub_alloc failed: Unable to allocate buffer.");

			/* Free the private area of the current object */
			kmem_free(ubp->ub_fca_private,
			    sizeof (emlxs_ub_priv_t));

			result = FC_FAILURE;
			goto fail;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_detail_msg,
		    "ub_alloc: buffer=%p token=%x size=%x type=%x ",
		    ubp, ub_priv->token, ubp->ub_bufsize, type);

		tokens[i] = (uint64_t)(unsigned long)ubp;
		port->ub_count++;
	}

	/* Add the pool to the top of the pool list */
	new_pool->pool_prev = NULL;
	new_pool->pool_next = port->ub_pool;

	if (port->ub_pool) {
		port->ub_pool->pool_prev = new_pool;
	}
	port->ub_pool = new_pool;

	/* Set the post counts */
	if (type == FC_TYPE_IS8802_SNAP) {
		MAILBOXQ *mbox;

		port->ub_post[FC_IP_RING] += new_pool->pool_nentries;

		if ((mbox = (MAILBOXQ *)
		    emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
			emlxs_mb_config_farp(hba, (MAILBOX *) mbox);
			if (emlxs_mb_issue_cmd(hba, (MAILBOX *)mbox,
			    MBX_NOWAIT, 0) != MBX_BUSY) {
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mbox);
			}
		}
		port->flag |= EMLXS_PORT_IP_UP;
	} else if (type == FC_TYPE_EXTENDED_LS) {
		port->ub_post[FC_ELS_RING] += new_pool->pool_nentries;
	} else if (type == FC_TYPE_FC_SERVICES) {
		port->ub_post[FC_CT_RING] += new_pool->pool_nentries;
	}
	mutex_exit(&EMLXS_UB_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "%d unsolicited buffers allocated for %s of size 0x%x bytes.",
	    *count, err, size);

	return (FC_SUCCESS);

fail:

	/* Clean the pool */
	for (i = 0; tokens[i] != NULL; i++) {
		/* Get the buffer object */
		ubp = (fc_unsol_buf_t *)(unsigned long)tokens[i];
		ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_detail_msg,
		    "ub_alloc failed: Freed buffer=%p token=%x size=%x "
		    "type=%x ", ubp, ub_priv->token, ubp->ub_bufsize, type);

		/* Free the actual buffer */
		kmem_free(ubp->ub_buffer, ubp->ub_bufsize);

		/* Free the private area of the buffer object */
		kmem_free(ubp->ub_fca_private, sizeof (emlxs_ub_priv_t));

		tokens[i] = 0;
		port->ub_count--;
	}

	/* Free the array of buffer objects in the pool */
	kmem_free((caddr_t)new_pool->fc_ubufs,
	    (sizeof (fc_unsol_buf_t) * new_pool->pool_nentries));

	/* Free the pool object */
	kmem_free((caddr_t)new_pool, sizeof (emlxs_unsol_buf_t));

	mutex_exit(&EMLXS_UB_LOCK);

	return (result);

} /* emlxs_ub_alloc() */


static void
emlxs_ub_els_reject(emlxs_port_t *port, fc_unsol_buf_t *ubp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_ub_priv_t *ub_priv;
	fc_packet_t *pkt;
	ELS_PKT *els;
	/* uint32_t *word; */
	uint32_t sid;

	ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;

	if (hba->state <= FC_LINK_DOWN) {
		return;
	}
	if (!(pkt = emlxs_pkt_alloc(port, sizeof (uint32_t) + sizeof (LS_RJT),
	    0, 0, KM_NOSLEEP))) {
		return;
	}
	sid = SWAP_DATA24_LO(ubp->ub_frame.s_id);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "%s dropped: sid=%x. Rejecting.",
	    emlxs_elscmd_xlate(ub_priv->cmd), sid);

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout = (2 * hba->fc_ratov);

	if ((uint32_t)ubp->ub_class == FC_TRAN_CLASS2) {
		pkt->pkt_tran_flags &= ~FC_TRAN_CLASS3;
		pkt->pkt_tran_flags |= FC_TRAN_CLASS2;
	}
	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = ubp->ub_frame.s_id;
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = SWAP_DATA24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = (ub_priv->cmd >> ELS_CMD_SHIFT) & 0xff;
	pkt->pkt_cmd_fhdr.rx_id = ubp->ub_frame.rx_id;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the command */
	els = (ELS_PKT *) pkt->pkt_cmd;
	els->elsCode = 0x01;
	els->un.lsRjt.un.b.lsRjtRsvd0 = 0;
	els->un.lsRjt.un.b.lsRjtRsnCode = LSRJT_UNABLE_TPC;
	els->un.lsRjt.un.b.lsRjtRsnCodeExp = LSEXP_NOTHING_MORE;
	els->un.lsRjt.un.b.vendorUnique = 0x02;

	/* Send the pkt later in another thread */
	(void) emlxs_pkt_send(pkt, 0);

	return;

} /* emlxs_ub_els_reject() */

extern int
emlxs_ub_release(opaque_t fca_port_handle, uint32_t count, uint64_t tokens[])
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	uint32_t i;
	uint32_t time;
	emlxs_unsol_buf_t *pool;

	if (count == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "ub_release: Nothing to do. count=%d", count);

		return (FC_SUCCESS);
	}
	if (!(port->flag & EMLXS_PORT_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "ub_release failed: Port not bound. count=%d token[0]=%p",
		    count, tokens[0]);

		return (FC_UNBOUND);
	}
	mutex_enter(&EMLXS_UB_LOCK);

	if (!port->ub_pool) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "ub_release failed: No pools! count=%d token[0]=%p",
		    count, tokens[0]);

		mutex_exit(&EMLXS_UB_LOCK);
		return (FC_UB_BADTOKEN);
	}
	for (i = 0; i < count; i++) {
		ubp = (fc_unsol_buf_t *)(unsigned long)tokens[i];

		if (!ubp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "ub_release failed: count=%d tokens[%d]=0",
			    count, i);

			mutex_exit(&EMLXS_UB_LOCK);
			return (FC_UB_BADTOKEN);
		}
		ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;

		if (!ub_priv || (ub_priv == (emlxs_ub_priv_t *)DEAD_PTR)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "ub_release failed: Dead buffer found. ubp=%p",
			    ubp);

			mutex_exit(&EMLXS_UB_LOCK);
			return (FC_UB_BADTOKEN);
		}
		if (ub_priv->flags == EMLXS_UB_FREE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "ub_release: Buffer already free! ubp=%p token=%x",
			    ubp, ub_priv->token);

			continue;
		}
		/* Check for dropped els buffer */
		/* ULP will do this sometimes without sending a reply */
		if ((ubp->ub_frame.r_ctl == FC_ELS_REQ) &&
		    !(ub_priv->flags & EMLXS_UB_REPLY)) {
			emlxs_ub_els_reject(port, ubp);
		}
		/* Mark the buffer free */
		ub_priv->flags = EMLXS_UB_FREE;
		bzero(ubp->ub_buffer, ubp->ub_bufsize);

		time = hba->timer_tics - ub_priv->time;
		ub_priv->time = 0;
		ub_priv->timeout = 0;

		pool = ub_priv->pool;

		if (ub_priv->flags & EMLXS_UB_RESV) {
			pool->pool_free_resv++;
		} else {
			pool->pool_free++;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_detail_msg,
		    "ub_release: ubp=%p token=%x time=%d av=%d (%d,%d,%d,%d)",
		    ubp, ub_priv->token, time, ub_priv->available,
		    pool->pool_nentries, pool->pool_available,
		    pool->pool_free, pool->pool_free_resv);

		/* Check if pool can be destroyed now */
		if ((pool->pool_available == 0) &&
		    (pool->pool_free + pool->pool_free_resv ==
		    pool->pool_nentries)) {
			emlxs_ub_destroy(port, pool);
		}
	}

	mutex_exit(&EMLXS_UB_LOCK);

	return (FC_SUCCESS);

} /* emlxs_ub_release() */


static int
emlxs_ub_free(opaque_t fca_port_handle, uint32_t count, uint64_t tokens[])
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	/* emlxs_hba_t *hba = HBA; */
	emlxs_unsol_buf_t *pool;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	uint32_t i;

	if (port->tgt_mode) {
		return (FC_SUCCESS);
	}
	if (count == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "ub_free: Nothing to do. count=%d token[0]=%p",
		    count, tokens[0]);

		return (FC_SUCCESS);
	}
	if (!(port->flag & EMLXS_PORT_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "ub_free: Port not bound. count=%d token[0]=%p",
		    count, tokens[0]);

		return (FC_SUCCESS);
	}
	mutex_enter(&EMLXS_UB_LOCK);

	if (!port->ub_pool) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "ub_free failed: No pools! count=%d token[0]=%p",
		    count, tokens[0]);

		mutex_exit(&EMLXS_UB_LOCK);
		return (FC_UB_BADTOKEN);
	}
	/* Process buffer list */
	for (i = 0; i < count; i++) {
		ubp = (fc_unsol_buf_t *)(unsigned long)tokens[i];

		if (!ubp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "ub_free failed: count=%d tokens[%d]=0", count, i);

			mutex_exit(&EMLXS_UB_LOCK);
			return (FC_UB_BADTOKEN);
		}
		/* Mark buffer unavailable */
		ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;

		if (!ub_priv || (ub_priv == (emlxs_ub_priv_t *)DEAD_PTR)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "ub_free failed: Dead buffer found. ubp=%p", ubp);

			mutex_exit(&EMLXS_UB_LOCK);
			return (FC_UB_BADTOKEN);
		}
		ub_priv->available = 0;

		/* Mark one less buffer available in the parent pool */
		pool = ub_priv->pool;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_detail_msg,
		    "ub_free: ubp=%p token=%x (%d,%d,%d,%d)",
		    ubp, ub_priv->token, pool->pool_nentries,
		    pool->pool_available - 1, pool->pool_free,
		    pool->pool_free_resv);

		if (pool->pool_available) {
			pool->pool_available--;

			/* Check if pool can be destroyed */
			if ((pool->pool_available == 0) &&
			    (pool->pool_free + pool->pool_free_resv ==
			    pool->pool_nentries)) {
				emlxs_ub_destroy(port, pool);
			}
		}
	}

	mutex_exit(&EMLXS_UB_LOCK);

	return (FC_SUCCESS);

} /* emlxs_ub_free() */


/* EMLXS_UB_LOCK must be held when calling this routine */
extern void
emlxs_ub_destroy(emlxs_port_t *port, emlxs_unsol_buf_t *pool)
{
	/* emlxs_hba_t *hba = HBA; */
	emlxs_unsol_buf_t *next;
	emlxs_unsol_buf_t *prev;
	fc_unsol_buf_t *ubp;
	uint32_t i;

	/* Remove the pool object from the pool list */
	next = pool->pool_next;
	prev = pool->pool_prev;

	if (port->ub_pool == pool) {
		port->ub_pool = next;
	}
	if (prev) {
		prev->pool_next = next;
	}
	if (next) {
		next->pool_prev = prev;
	}
	pool->pool_prev = NULL;
	pool->pool_next = NULL;

	/* Clear the post counts */
	switch (pool->pool_type) {
	case FC_TYPE_IS8802_SNAP:
		port->ub_post[FC_IP_RING] -= pool->pool_nentries;
		break;

	case FC_TYPE_EXTENDED_LS:
		port->ub_post[FC_ELS_RING] -= pool->pool_nentries;
		break;

	case FC_TYPE_FC_SERVICES:
		port->ub_post[FC_CT_RING] -= pool->pool_nentries;
		break;
	}

	/* Now free the pool memory */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "ub_destroy: pool=%p type=%d size=%d count=%d",
	    pool, pool->pool_type, pool->pool_buf_size, pool->pool_nentries);

	/* Process the array of buffer objects in the pool */
	for (i = 0; i < pool->pool_nentries; i++) {
		/* Get the buffer object */
		ubp = (fc_unsol_buf_t *)&pool->fc_ubufs[i];

		/* Free the memory the buffer object represents */
		kmem_free(ubp->ub_buffer, ubp->ub_bufsize);

		/* Free the private area of the buffer object */
		kmem_free(ubp->ub_fca_private, sizeof (emlxs_ub_priv_t));
	}

	/* Free the array of buffer objects in the pool */
	kmem_free((caddr_t)pool->fc_ubufs,
	    (sizeof (fc_unsol_buf_t) * pool->pool_nentries));

	/* Free the pool object */
	kmem_free((caddr_t)pool, sizeof (emlxs_unsol_buf_t));

	return;

} /* emlxs_ub_destroy() */


/*ARGSUSED*/
extern int
emlxs_pkt_abort(opaque_t fca_port_handle, fc_packet_t *pkt, int32_t sleep)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;

	emlxs_buf_t *sbp;
	NODELIST *nlp;
	uint8_t ringno;
	RING *rp;
	clock_t timeout;
	clock_t time;
	int32_t pkt_ret;
	IOCBQ *iocbq;
	IOCBQ *next;
	IOCBQ *prev;
	uint32_t found;
	uint32_t att_bit;
	uint32_t pass = 0;

	sbp = (emlxs_buf_t *)pkt->pkt_fca_private;
	iocbq = &sbp->iocbq;
	nlp = (NODELIST *) sbp->node;
	rp = (RING *) sbp->ring;
	ringno = (rp) ? rp->ringno : 0;

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg, "fca_pkt_abort:
	 * pkt=%p sleep=%x", pkt, sleep);
	 */

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
		    "Port not bound.");
		return (FC_UNBOUND);
	}
	if (!(hba->flag & FC_ONLINE_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
		    "Adapter offline.");
		return (FC_OFFLINE);
	}
	/*
	 * ULP requires the aborted pkt to be completed
	 * back to ULP before returning from this call.
	 * SUN knows of problems with this call so they suggested that we
	 * always return a FC_FAILURE for this call, until it is worked out.
	 */

	/* Check if pkt is no good */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags & PACKET_RETURNED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
		    "Bad sbp. flags=%x", sbp->pkt_flags);
		return (FC_FAILURE);
	}
	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_msg, "sbp=%p sleep=%x
	 * flags=%x", sbp, sleep, sbp->pkt_flags);
	 */

	/* Tag this now */
	/* This will prevent any thread except ours from completing it */
	mutex_enter(&sbp->mtx);

	/* Check again if we still own this */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags & PACKET_RETURNED)) {
		mutex_exit(&sbp->mtx);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
		    "Bad sbp. flags=%x", sbp->pkt_flags);
		return (FC_FAILURE);
	}
	/* Check if pkt is a real polled command */
	if (!(sbp->pkt_flags & PACKET_IN_ABORT) &&
	    (sbp->pkt_flags & PACKET_POLLED)) {
		mutex_exit(&sbp->mtx);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
		    "Attempting to abort a polled I/O. sbp=%p flags=%x",
		    sbp, sbp->pkt_flags);
		return (FC_FAILURE);
	}
	sbp->pkt_flags |= PACKET_POLLED;
	sbp->pkt_flags |= PACKET_IN_ABORT;

	if (sbp->pkt_flags &
	    (PACKET_IN_COMPLETION | PACKET_IN_FLUSH | PACKET_IN_TIMEOUT)) {
		mutex_exit(&sbp->mtx);

		/* Do nothing, pkt already on its way out */
		goto done;
	}
	mutex_exit(&sbp->mtx);

begin:
	pass++;

	mutex_enter(&EMLXS_RINGTX_LOCK);

	if (sbp->pkt_flags & PACKET_IN_TXQ) {
		/* Find it on the queue */
		found = 0;
		if (iocbq->flag & IOCB_PRIORITY) {
			/* Search the priority queue */
			prev = NULL;
			next = (IOCBQ *) nlp->nlp_ptx[ringno].q_first;

			while (next) {
				if (next == iocbq) {
					/* Remove it */
					if (prev) {
						prev->next = iocbq->next;
					}
					if (nlp->nlp_ptx[ringno].q_last ==
					    (void *) iocbq) {
						nlp->nlp_ptx[ringno].q_last =
						    (void *) prev;
					}
					if (nlp->nlp_ptx[ringno].q_first ==
					    (void *) iocbq) {
						nlp->nlp_ptx[ringno].q_first =
						    (void *) iocbq->next;
					}
					nlp->nlp_ptx[ringno].q_cnt--;
					iocbq->next = NULL;
					found = 1;
					break;
				}
				prev = next;
				next = next->next;
			}
		} else {
			/* Search the normal queue */
			prev = NULL;
			next = (IOCBQ *) nlp->nlp_tx[ringno].q_first;

			while (next) {
				if (next == iocbq) {
					/* Remove it */
					if (prev) {
						prev->next = iocbq->next;
					}
					if (nlp->nlp_tx[ringno].q_last ==
					    (void *) iocbq) {
						nlp->nlp_tx[ringno].q_last =
						    (void *) prev;
					}
					if (nlp->nlp_tx[ringno].q_first ==
					    (void *) iocbq) {
						nlp->nlp_tx[ringno].q_first =
						    (void *) iocbq->next;
					}
					nlp->nlp_tx[ringno].q_cnt--;
					iocbq->next = NULL;
					found = 1;
					break;
				}
				prev = next;
				next = (IOCBQ *) next->next;
			}
		}

		if (!found) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
			    "I/O not found in driver. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
			mutex_exit(&EMLXS_RINGTX_LOCK);
			goto done;
		}
		/* Check if node still needs servicing */
		if ((nlp->nlp_ptx[ringno].q_first) ||
		    (nlp->nlp_tx[ringno].q_first &&
		    !(nlp->nlp_flag[ringno] & NLP_CLOSED))) {

			/*
			 * If this is the base node, then don't shift the
			 * pointers
			 */
			/* We want to drain the base node before moving on */
			if (!nlp->nlp_base) {
				/*
				 * Just shift ring queue pointers to next
				 * node
				 */
				rp->nodeq.q_last = (void *) nlp;
				rp->nodeq.q_first = nlp->nlp_next[ringno];
			}
		} else {
			/* Remove node from ring queue */

			/* If this is the last node on list */
			if (rp->nodeq.q_last == (void *) nlp) {
				rp->nodeq.q_last = NULL;
				rp->nodeq.q_first = NULL;
				rp->nodeq.q_cnt = 0;
			} else {
				/* Remove node from head */
				rp->nodeq.q_first = nlp->nlp_next[ringno];
				((NODELIST *)
				    rp->nodeq.q_last)->nlp_next[ringno] =
				    rp->nodeq.q_first;
				rp->nodeq.q_cnt--;
			}

			/* Clear node */
			nlp->nlp_next[ringno] = NULL;
		}

		mutex_enter(&sbp->mtx);

		if (sbp->pkt_flags & PACKET_IN_TXQ) {
			sbp->pkt_flags &= ~PACKET_IN_TXQ;
			hba->ring_tx_count[ringno]--;
		}
		mutex_exit(&sbp->mtx);

		/* Free the ulpIoTag and the bmp */
		(void) emlxs_unregister_pkt(rp, sbp->iotag, 0);

		mutex_exit(&EMLXS_RINGTX_LOCK);

		emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_ABORT_REQUESTED, 1);

		goto done;
	}
	mutex_exit(&EMLXS_RINGTX_LOCK);


	/* Check the chip queue */
	mutex_enter(&EMLXS_FCTAB_LOCK(ringno));

	if ((sbp->pkt_flags & PACKET_IN_CHIPQ) &&
	    !(sbp->pkt_flags & PACKET_XRI_CLOSED) &&
	    (sbp == rp->fc_table[sbp->iotag])) {

		/* Create the abort IOCB */
		if (hba->state >= FC_LINK_UP) {
			iocbq = emlxs_create_abort_xri_cn(port, sbp->node,
			    sbp->iotag, rp, sbp->class, ABORT_TYPE_ABTS);

			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_XRI_CLOSED;
			sbp->ticks = hba->timer_tics + (4 * hba->fc_ratov) + 10;
			sbp->abort_attempts++;
			mutex_exit(&sbp->mtx);
		} else {
			iocbq = emlxs_create_close_xri_cn(port, sbp->node,
			    sbp->iotag, rp);

			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_XRI_CLOSED;
			sbp->ticks = hba->timer_tics + 30;
			sbp->abort_attempts++;
			mutex_exit(&sbp->mtx);
		}

		mutex_exit(&EMLXS_FCTAB_LOCK(ringno));

		/* Send this iocbq */
		if (iocbq) {
			emlxs_issue_iocb_cmd(hba, rp, iocbq);
			iocbq = NULL;
		}
		goto done;
	}
	mutex_exit(&EMLXS_FCTAB_LOCK(ringno));

	/* Pkt was not on any queues */

	/* Check again if we still own this */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags & (PACKET_RETURNED | PACKET_IN_COMPLETION |
	    PACKET_IN_FLUSH | PACKET_IN_TIMEOUT))) {
		goto done;
	}
	/* Apparently the pkt was not found.  Let's delay and try again */
	if (pass < 5) {
		delay(drv_usectohz(5000000));	/* 5 seconds */

		/* Check again if we still own this */
		if (!(sbp->pkt_flags & PACKET_VALID) ||
		    (sbp->pkt_flags & (PACKET_RETURNED | PACKET_IN_COMPLETION |
		    PACKET_IN_FLUSH | PACKET_IN_TIMEOUT))) {
			goto done;
		}
		goto begin;
	}
force_it:

	/* Force the completion now */

	/* Unregister the pkt */
	(void) emlxs_unregister_pkt(rp, sbp->iotag, 1);

	/* Now complete it */
	emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, IOERR_ABORT_REQUESTED, 1);

done:

	/* Now wait for the pkt to complete */
	if (!(sbp->pkt_flags & PACKET_COMPLETED)) {
		/* Set thread timeout */
		timeout = emlxs_timeout(hba, 30);

		/* Check for panic situation */
		if (ddi_in_panic()) {

			/*
			 * In panic situations there will be one thread with
			 * no interrrupts (hard or soft) and no timers
			 */

			/*
			 * We must manually poll everything in this thread to
			 * keep the driver going.
			 */

			rp = (emlxs_ring_t *)sbp->ring;
			switch (rp->ringno) {
			case FC_FCP_RING:
				att_bit = HA_R0ATT;
				break;

			case FC_IP_RING:
				att_bit = HA_R1ATT;
				break;

			case FC_ELS_RING:
				att_bit = HA_R2ATT;
				break;

			case FC_CT_RING:
				att_bit = HA_R3ATT;
				break;
			}

			/* Keep polling the chip until our IO is completed */
			(void) drv_getparm(LBOLT, &time);
			while ((time < timeout) &&
			    !(sbp->pkt_flags & PACKET_COMPLETED)) {
				emlxs_poll_intr(hba, att_bit);
				(void) drv_getparm(LBOLT, &time);
			}
		} else {
			/* Wait for IO completion or timeout */
			mutex_enter(&EMLXS_PKT_LOCK);
			pkt_ret = 0;
			while ((pkt_ret != -1) &&
			    !(sbp->pkt_flags & PACKET_COMPLETED)) {
				pkt_ret = cv_timedwait(&EMLXS_PKT_CV,
				    &EMLXS_PKT_LOCK, timeout);
			}
			mutex_exit(&EMLXS_PKT_LOCK);
		}

		/*
		 * Check if timeout occured.  This is not good.  Something
		 * happened to our IO.
		 */
		if (!(sbp->pkt_flags & PACKET_COMPLETED)) {
			/* Force the completion now */
			goto force_it;
		}
	}
#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_unswap_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	/* Check again if we still own this */
	if ((sbp->pkt_flags & PACKET_VALID) &&
	    !(sbp->pkt_flags & PACKET_RETURNED)) {
		mutex_enter(&sbp->mtx);
		if ((sbp->pkt_flags & PACKET_VALID) &&
		    !(sbp->pkt_flags & PACKET_RETURNED)) {
			sbp->pkt_flags |= PACKET_RETURNED;
		}
		mutex_exit(&sbp->mtx);
	}
#ifdef ULP_PATCH5
	return (FC_FAILURE);

#else
	return (FC_SUCCESS);

#endif	/* ULP_PATCH5 */


} /* emlxs_pkt_abort() */


extern int32_t
emlxs_reset(opaque_t fca_port_handle, uint32_t cmd)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;
	int rval;
	int ret;
	clock_t timeout;

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset failed. Port not bound.");

		return (FC_UNBOUND);
	}
	switch (cmd) {
	case FC_FCA_LINK_RESET:

		if (!(hba->flag & FC_ONLINE_MODE) ||
		    (hba->state <= FC_LINK_DOWN)) {
			return (FC_SUCCESS);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset: Resetting Link.");

		mutex_enter(&EMLXS_LINKUP_LOCK);
		hba->linkup_wait_flag = TRUE;
		mutex_exit(&EMLXS_LINKUP_LOCK);

		if (emlxs_reset_link(hba, 1)) {
			mutex_enter(&EMLXS_LINKUP_LOCK);
			hba->linkup_wait_flag = FALSE;
			mutex_exit(&EMLXS_LINKUP_LOCK);

			return (FC_FAILURE);
		}
		mutex_enter(&EMLXS_LINKUP_LOCK);
		timeout = emlxs_timeout(hba, 60);
		ret = 0;
		while ((ret != -1) && (hba->linkup_wait_flag == TRUE)) {
			ret = cv_timedwait(&EMLXS_LINKUP_CV,
			    &EMLXS_LINKUP_LOCK, timeout);
		}

		hba->linkup_wait_flag = FALSE;
		mutex_exit(&EMLXS_LINKUP_LOCK);

		if (ret == -1) {
			return (FC_FAILURE);
		}
		return (FC_SUCCESS);

	case FC_FCA_RESET:
	case FC_FCA_RESET_CORE:
	case FC_FCA_CORE:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset: Resetting Adapter.");

		rval = FC_SUCCESS;
		if (hba->flag & (FC_OFFLINE_MODE | FC_OFFLINING_MODE)) {
			return (FC_SUCCESS);
		}
		if (emlxs_offline(hba) == 0) {
			(void) emlxs_online(hba);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_reset: Adapter reset failed. Device busy.");

			rval = FC_DEVICE_BUSY;
		}

		return (rval);

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset: Unknown command. cmd=%x", cmd);

		break;
	}

	return (FC_FAILURE);

} /* emlxs_reset() */


extern uint32_t emlxs_core_dump(emlxs_hba_t *hba, char *buffer, uint32_t size);
extern uint32_t emlxs_core_size(emlxs_hba_t *hba);

extern int
emlxs_port_manage(opaque_t fca_port_handle, fc_fca_pm_t *pm)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	/* emlxs_port_t *vport; */
	emlxs_hba_t *hba = HBA;
	int32_t ret;
	emlxs_vpd_t *vpd = &VPD;


	ret = FC_SUCCESS;

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		return (FC_UNBOUND);
	}
	if (!(hba->flag & FC_ONLINE_MODE)) {
		return (FC_OFFLINE);
	}
#ifdef IDLE_TIMER
	emlxs_pm_busy_component(hba);
#endif	/* IDLE_TIMER */

	switch (pm->pm_cmd_code) {

	case FC_PORT_GET_FW_REV:
		{
			char buffer[128];

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: FC_PORT_GET_FW_REV");

			(void) sprintf(buffer, "%s %s", hba->model_info.model,
			    vpd->fw_version);
			bzero(pm->pm_data_buf, pm->pm_data_len);

			if (pm->pm_data_len < strlen(buffer) + 1) {
				ret = FC_NOMEM;

				break;
			}
			(void) strcpy(pm->pm_data_buf, buffer);
			break;
		}

	case FC_PORT_GET_FCODE_REV:
		{
			char buffer[128];

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: FC_PORT_GET_FCODE_REV");

			/* Force update here just to be sure */
			emlxs_get_fcode_version(hba);

			(void) sprintf(buffer, "%s %s", hba->model_info.model,
			    vpd->fcode_version);
			bzero(pm->pm_data_buf, pm->pm_data_len);

			if (pm->pm_data_len < strlen(buffer) + 1) {
				ret = FC_NOMEM;
				break;
			}
			(void) strcpy(pm->pm_data_buf, buffer);
			break;
		}

	case FC_PORT_GET_DUMP_SIZE:
		{
			uint32_t dump_size;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: FC_PORT_GET_DUMP_SIZE");

			dump_size = emlxs_core_size(hba);

			if (pm->pm_data_len < sizeof (uint32_t)) {
				ret = FC_NOMEM;
				break;
			}
			*((uint32_t *)pm->pm_data_buf) = dump_size;

			break;
		}

	case FC_PORT_GET_DUMP:
		{
			/* char *c; */
			/* int32_t i; */
			uint32_t dump_size;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: FC_PORT_GET_DUMP");

			dump_size = emlxs_core_size(hba);

			if (pm->pm_data_len < dump_size) {
				ret = FC_NOMEM;
				break;
			}
			(void) emlxs_core_dump(hba, (char *)pm->pm_data_buf,
			    pm->pm_data_len);

			break;
		}

	case FC_PORT_FORCE_DUMP:
		{
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: FC_PORT_FORCE_DUMP");

			/*
			 * We don't do anything right now, just return
			 * success
			 */
			break;
		}

	case FC_PORT_LINK_STATE:
		{
			uint32_t *link_state;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: FC_PORT_LINK_STATE");

			if (pm->pm_stat_len != sizeof (*link_state)) {
				ret = FC_NOMEM;
				break;
			}
			if (pm->pm_cmd_buf != NULL) {

				/*
				 * Can't look beyond the FCA port.
				 */
				ret = FC_INVALID_REQUEST;
				break;
			}
			link_state = (uint32_t *)pm->pm_stat_buf;

			/* Set the state */
			if (hba->state >= FC_LINK_UP) {
				/* Check for loop topology */
				if (hba->topology == TOPOLOGY_LOOP) {
					*link_state = FC_STATE_LOOP;
				} else {
					*link_state = FC_STATE_ONLINE;
				}

				/* Set the link speed */
				switch (hba->linkspeed) {
				case LA_2GHZ_LINK:
					*link_state |= FC_STATE_2GBIT_SPEED;
					break;
				case LA_4GHZ_LINK:
					*link_state |= FC_STATE_4GBIT_SPEED;
					break;
				case LA_8GHZ_LINK:
					*link_state |= FC_STATE_8GBIT_SPEED;
					break;
				case LA_10GHZ_LINK:
					*link_state |= FC_STATE_10GBIT_SPEED;
					break;
				case LA_1GHZ_LINK:
				default:
					*link_state |= FC_STATE_1GBIT_SPEED;
					break;
				}
			} else {
				*link_state = FC_STATE_OFFLINE;
			}

			break;
		}


	case FC_PORT_ERR_STATS:
	case FC_PORT_RLS:
		{
			MAILBOX *mb;
			fc_rls_acc_t *bp;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: FC_PORT_RLS / FC_PORT_ERR_STATS");

			if (pm->pm_data_len < sizeof (fc_rls_acc_t)) {
				ret = FC_NOMEM;
				break;
			}
			if ((mb = (MAILBOX *)
			    emlxs_mem_get(hba, MEM_MBOX | MEM_PRI)) == 0) {
				ret = FC_NOMEM;
				break;
			}
			emlxs_mb_read_lnk_stat(hba, mb);
			if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) !=
			    MBX_SUCCESS) {
				ret = FC_PBUSY;
			} else {
				bp = (fc_rls_acc_t *)pm->pm_data_buf;

				bp->rls_link_fail =
				    mb->un.varRdLnk.linkFailureCnt;
				bp->rls_sync_loss = mb->un.varRdLnk.lossSyncCnt;
				bp->rls_sig_loss =
				    mb->un.varRdLnk.lossSignalCnt;
				bp->rls_prim_seq_err =
				    mb->un.varRdLnk.primSeqErrCnt;
				bp->rls_invalid_word =
				    mb->un.varRdLnk.invalidXmitWord;
				bp->rls_invalid_crc = mb->un.varRdLnk.crcCnt;
			}

			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
			break;
		}

	case FC_PORT_DOWNLOAD_FW:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_DOWNLOAD_FW");
		ret = emlxs_fw_download(hba, pm->pm_data_buf,
		    pm->pm_data_len, 1);
		break;

	case FC_PORT_DOWNLOAD_FCODE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_DOWNLOAD_FCODE");
		ret = emlxs_fw_download(hba, pm->pm_data_buf,
		    pm->pm_data_len, 1);
		break;

	case FC_PORT_DIAG:
		{
			uint32_t errno = 0;
			uint32_t did = 0;
			uint32_t pattern = 0;

			switch (pm->pm_cmd_flags) {
			case EMLXS_DIAG_BIU:
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_DIAG_BIU");

				if (pm->pm_data_len) {
					pattern =
					    *((uint32_t *)pm->pm_data_buf);
				}
				errno = emlxs_diag_biu_run(hba, pattern);

				if (pm->pm_stat_len == sizeof (errno)) {
					*(int *)pm->pm_stat_buf = errno;
				}
				break;


			case EMLXS_DIAG_POST:
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_DIAG_POST");

				errno = emlxs_diag_post_run(hba);

				if (pm->pm_stat_len == sizeof (errno)) {
					*(int *)pm->pm_stat_buf = errno;
				}
				break;


			case EMLXS_DIAG_ECHO:
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_DIAG_ECHO");

				if (pm->pm_cmd_len != sizeof (uint32_t)) {
					ret = FC_INVALID_REQUEST;
					break;
				}
				did = *((uint32_t *)pm->pm_cmd_buf);

				if (pm->pm_data_len) {
					pattern =
					    *((uint32_t *)pm->pm_data_buf);
				}
				errno = emlxs_diag_echo_run(port, did, pattern);

				if (pm->pm_stat_len == sizeof (errno)) {
					*(int *)pm->pm_stat_buf = errno;
				}
				break;


			case EMLXS_PARM_GET_NUM:
				{
				uint32_t *num;
				emlxs_config_t *cfg;
				uint32_t i;
				uint32_t count;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_PARM_GET_NUM");

				if (pm->pm_stat_len < sizeof (uint32_t)) {
					ret = FC_NOMEM;
					break;
				}
				num = (uint32_t *)pm->pm_stat_buf;
				count = 0;
				cfg = &CFG;
				for (i = 0; i < NUM_CFG_PARAM; i++, cfg++) {
					if (!(cfg->flags & PARM_HIDDEN)) {
						count++;
					}
				}

				*num = count;

				break;
				}

			case EMLXS_PARM_GET_LIST:
				{
				emlxs_parm_t *parm;
				emlxs_config_t *cfg;
				uint32_t i;
				uint32_t max_count;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_PARM_GET_LIST");

				if (pm->pm_stat_len < sizeof (emlxs_parm_t)) {
					ret = FC_NOMEM;
					break;
				}
				max_count = pm->pm_stat_len /
				    sizeof (emlxs_parm_t);

				parm = (emlxs_parm_t *)pm->pm_stat_buf;
				cfg = &CFG;
				for (i = 0; i < NUM_CFG_PARAM && max_count;
				    i++, cfg++) {
					if (!(cfg->flags & PARM_HIDDEN)) {
						(void) strcpy(parm->label,
						    cfg->string);
						parm->min = cfg->low;
						parm->max = cfg->hi;
						parm->def = cfg->def;
						parm->current = cfg->current;
						parm->flags = cfg->flags;
						(void) strcpy(parm->help,
						    cfg->help);
						parm++;
						max_count--;
					}
				}

				break;
				}

			case EMLXS_PARM_GET:
				{
				emlxs_parm_t *parm_in;
				emlxs_parm_t *parm_out;
				emlxs_config_t *cfg;
				uint32_t i;
				uint32_t len;

				if (pm->pm_cmd_len < sizeof (emlxs_parm_t)) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "fca_port_manage: EMLXS_PARM_GET. "
					    "inbuf to small.");

					ret = FC_BADCMD;
					break;
				}
				if (pm->pm_stat_len < sizeof (emlxs_parm_t)) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "fca_port_manage: EMLXS_PARM_GET. "
					    "outbuf to small");

					ret = FC_BADCMD;
					break;
				}
				parm_in = (emlxs_parm_t *)pm->pm_cmd_buf;
				parm_out = (emlxs_parm_t *)pm->pm_stat_buf;
				len = strlen(parm_in->label);
				cfg = &CFG;
				ret = FC_BADOBJECT;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_PARM_GET: %s",
				    parm_in->label);

				for (i = 0; i < NUM_CFG_PARAM; i++, cfg++) {
					if (len == strlen(cfg->string) &&
					    strcmp(parm_in->label,
					    cfg->string) == 0) {
						(void) strcpy(parm_out->label,
						    cfg->string);
						parm_out->min = cfg->low;
						parm_out->max = cfg->hi;
						parm_out->def = cfg->def;
						parm_out->current =
						    cfg->current;
						parm_out->flags = cfg->flags;
						(void) strcpy(parm_out->help,
						    cfg->help);

						ret = FC_SUCCESS;
						break;
					}
				}

				break;
				}

			case EMLXS_PARM_SET:
				{
				emlxs_parm_t *parm_in;
				emlxs_parm_t *parm_out;
				emlxs_config_t *cfg;
				uint32_t i;
				uint32_t len;

				if (pm->pm_cmd_len < sizeof (emlxs_parm_t)) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "fca_port_manage: EMLXS_PARM_GET. "
					    "inbuf to small.");

					ret = FC_BADCMD;
					break;
				}
				if (pm->pm_stat_len < sizeof (emlxs_parm_t)) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "fca_port_manage: EMLXS_PARM_GET. "
					    "outbuf to small");
					ret = FC_BADCMD;
					break;
				}
				parm_in = (emlxs_parm_t *)pm->pm_cmd_buf;
				parm_out = (emlxs_parm_t *)pm->pm_stat_buf;
				len = strlen(parm_in->label);
				cfg = &CFG;
				ret = FC_BADOBJECT;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_PARM_SET"
				    ": %s=0x%x,%d", parm_in->label,
				    parm_in->current, parm_in->current);

				for (i = 0; i < NUM_CFG_PARAM; i++, cfg++) {
					/*
					 * Find matching parameter
					 * string
					 */
					if (len == strlen(cfg->string) &&
					    strcmp(parm_in->label,
					    cfg->string) == 0) {
						/*
						 * Attempt to update
						 * parameter
						 */
						if (emlxs_set_parm(hba,
						    i, parm_in->current)
						    == FC_SUCCESS) {
							(void) strcpy(
							    parm_out->label,
							    cfg->string);
							parm_out->min =
							    cfg->low;
							parm_out->max = cfg->hi;
							parm_out->def =
							    cfg->def;
							parm_out->current =
							    cfg->current;
							parm_out->flags =
							    cfg->flags;
							(void) strcpy(
							    parm_out->help,
							    cfg->help);

							ret = FC_SUCCESS;
						}
						break;
					}
				}

				break;
				}

			case EMLXS_LOG_GET:
				{
				emlxs_log_req_t *req;
				emlxs_log_resp_t *resp;
				uint32_t len;

				/* Check command size */
				if (pm->pm_cmd_len < sizeof (emlxs_log_req_t)) {
					ret = FC_BADCMD;
					break;
				}
				/* Get the request */
				req = (emlxs_log_req_t *)pm->pm_cmd_buf;

				/*
				 * Calculate the response length from
				 * the request
				 */
				len = sizeof (emlxs_log_resp_t) +
				    (req->count * MAX_LOG_MSG_LENGTH);

				/* Check the response buffer length */
				if (pm->pm_stat_len < len) {
					ret = FC_BADCMD;
					break;
				}
				/* Get the response pointer */
				resp = (emlxs_log_resp_t *)pm->pm_stat_buf;

				/* Get the request log enties */
				(void) emlxs_msg_log_get(hba, req, resp);

				ret = FC_SUCCESS;
				break;
				}

			case EMLXS_GET_BOOT_REV:
				{
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_GET_BOOT_REV");

				if (pm->pm_stat_len <
				    strlen(vpd->boot_version)) {
					ret = FC_NOMEM;
					break;
				}
				bzero(pm->pm_stat_buf, pm->pm_stat_len);
				(void) sprintf(pm->pm_stat_buf, "%s %s",
				    hba->model_info.model, vpd->boot_version);

				break;
				}

			case EMLXS_DOWNLOAD_BOOT:
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_DOWNLOAD_BOOT");

				ret = emlxs_fw_download(hba, pm->pm_data_buf,
				    pm->pm_data_len, 1);
				break;

			case EMLXS_DOWNLOAD_CFL:
				{
				uint32_t *buffer;
				uint32_t region;
				uint32_t length;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_DOWNLOAD_CFL");

				/*
				 * Extract the region number from the
				 * first word.
				 */
				buffer = (uint32_t *)pm->pm_data_buf;
				region = *buffer++;

				/*
				 * Adjust the image length for the
				 * header word
				 */
				length = pm->pm_data_len - 4;

				ret = emlxs_cfl_download(hba, region,
				    (caddr_t)buffer, length);
				break;
				}

			case EMLXS_VPD_GET:
				{
				emlxs_vpd_desc_t *vpd_out;
				/* char buffer[80]; */
				/* uint32_t i; */
				/* uint32_t found = 0; */

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_VPD_GET");

				if (pm->pm_stat_len <
				    sizeof (emlxs_vpd_desc_t)) {
					ret = FC_BADCMD;
					break;
				}
				vpd_out = (emlxs_vpd_desc_t *)pm->pm_stat_buf;
				bzero(vpd_out, sizeof (emlxs_vpd_desc_t));

				(void) strncpy(vpd_out->id, vpd->id,
				    sizeof (vpd_out->id));
				(void) strncpy(vpd_out->part_num, vpd->part_num,
				    sizeof (vpd_out->part_num));
				(void) strncpy(vpd_out->eng_change,
				    vpd->eng_change,
				    sizeof (vpd_out->eng_change));
				(void) strncpy(vpd_out->manufacturer,
				    vpd->manufacturer,
				    sizeof (vpd_out->manufacturer));
				(void) strncpy(vpd_out->serial_num,
				    vpd->serial_num,
				    sizeof (vpd_out->serial_num));
				(void) strncpy(vpd_out->model, vpd->model,
				    sizeof (vpd_out->model));
				(void) strncpy(vpd_out->model_desc,
				    vpd->model_desc,
				    sizeof (vpd_out->model_desc));
				(void) strncpy(vpd_out->port_num,
				    vpd->port_num,
				    sizeof (vpd_out->port_num));
				(void) strncpy(vpd_out->prog_types,
				    vpd->prog_types,
				    sizeof (vpd_out->prog_types));

				ret = FC_SUCCESS;

				break;
				}

			case EMLXS_GET_FCIO_REV:
				{
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_GET_FCIO_REV");

				if (pm->pm_stat_len < sizeof (uint32_t)) {
					ret = FC_NOMEM;
					break;
				}
				bzero(pm->pm_stat_buf, pm->pm_stat_len);
				*(uint32_t *)pm->pm_stat_buf = FCIO_REV;

				break;
				}

			case EMLXS_GET_DFC_REV:
				{
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_GET_DFC_REV");

				if (pm->pm_stat_len < sizeof (uint32_t)) {
					ret = FC_NOMEM;
					break;
				}
				bzero(pm->pm_stat_buf, pm->pm_stat_len);
				*(uint32_t *)pm->pm_stat_buf = DFC_REV;

				break;
				}

			case EMLXS_SET_BOOT_STATE:
			case EMLXS_SET_BOOT_STATE_old:
				{
				uint32_t state;

				if (pm->pm_cmd_len < sizeof (uint32_t)) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "fca_port_manage: "
					    "EMLXS_SET_BOOT_STATE");
					ret = FC_BADCMD;
					break;
				}
				state = *(uint32_t *)pm->pm_cmd_buf;

				if (state == 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "fca_port_manage: "
					    "EMLXS_SET_BOOT_STATE: Disable");
					ret = emlxs_boot_code_disable(hba);
				} else {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "fca_port_manage: "
					    "EMLXS_SET_BOOT_STATE: Enable");
					ret = emlxs_boot_code_enable(hba);
				}

				break;
				}

			case EMLXS_GET_BOOT_STATE:
			case EMLXS_GET_BOOT_STATE_old:
				{
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_GET_BOOT_STATE");

				if (pm->pm_stat_len < sizeof (uint32_t)) {
					ret = FC_NOMEM;
					break;
				}
				bzero(pm->pm_stat_buf, pm->pm_stat_len);

				ret = emlxs_boot_code_state(hba);

				if (ret == FC_SUCCESS) {
					*(uint32_t *)pm->pm_stat_buf = 1;
					ret = FC_SUCCESS;
				} else if (ret == FC_FAILURE) {
					ret = FC_SUCCESS;
				}
				break;
				}


			case EMLXS_HW_ERROR_TEST:
				{
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_HW_ERROR_TEST");

				/* Trigger a mailbox timeout */
				hba->mbox_timer = hba->timer_tics;

				break;
				}

			case EMLXS_TEST_CODE:
				{
				uint32_t *cmd;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_TEST_CODE");

				if (pm->pm_cmd_len < sizeof (uint32_t)) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "fca_port_manage: EMLXS_TEST_CODE. "
					    "inbuf to small.");

					ret = FC_BADCMD;
					break;
				}
				cmd = (uint32_t *)pm->pm_cmd_buf;

				ret = emlxs_test(hba, cmd[0], (pm->pm_cmd_len /
				    sizeof (uint32_t)), &cmd[1]);

				break;
				}


			default:

				ret = FC_INVALID_REQUEST;
				break;
			}

			break;

		}

	case FC_PORT_INITIALIZE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_INITIALIZE");
		break;

	case FC_PORT_LOOPBACK:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_LOOPBACK");
		break;

	case FC_PORT_BYPASS:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_BYPASS");
		ret = FC_INVALID_REQUEST;
		break;

	case FC_PORT_UNBYPASS:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_UNBYPASS");
		ret = FC_INVALID_REQUEST;
		break;

	case FC_PORT_GET_NODE_ID:
		{
		fc_rnid_t *rnid;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_GET_NODE_ID");

		bzero(pm->pm_data_buf, pm->pm_data_len);

		if (pm->pm_data_len < sizeof (fc_rnid_t)) {
			ret = FC_NOMEM;
			break;
		}
		rnid = (fc_rnid_t *)pm->pm_data_buf;

		(void) sprintf((char *)rnid->global_id,
		    "%01x%01x%02x%02x%02x%02x%02x%02x%02x",
		    hba->wwpn.nameType, hba->wwpn.IEEEextMsn,
		    hba->wwpn.IEEEextLsb,
		    hba->wwpn.IEEE[0], hba->wwpn.IEEE[1],
		    hba->wwpn.IEEE[2], hba->wwpn.IEEE[3],
		    hba->wwpn.IEEE[4], hba->wwpn.IEEE[5]);

		rnid->unit_type = RNID_HBA;
		rnid->port_id = port->did;
		rnid->ip_version = RNID_IPV4;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: wwpn:       %s", rnid->global_id);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: unit_type:  0x%x", rnid->unit_type);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: port_id:    0x%x", rnid->port_id);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: num_attach: %d", rnid->num_attached);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: ip_version: 0x%x", rnid->ip_version);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: udp_port:   0x%x", rnid->udp_port);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: ip_addr:    %s", rnid->ip_addr);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: resv:       0x%x",
		    rnid->specific_id_resv);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "GET_NODE_ID: topo_flags: 0x%x", rnid->topo_flags);

		ret = FC_SUCCESS;
		break;
		}

	case FC_PORT_SET_NODE_ID:
		{
		fc_rnid_t *rnid;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_SET_NODE_ID");

		if (pm->pm_data_len < sizeof (fc_rnid_t)) {
			ret = FC_NOMEM;
			break;
		}
		rnid = (fc_rnid_t *)pm->pm_data_buf;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: wwpn:       %s", rnid->global_id);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: unit_type:  0x%x", rnid->unit_type);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: port_id:    0x%x", rnid->port_id);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: num_attach: %d", rnid->num_attached);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: ip_version: 0x%x", rnid->ip_version);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: udp_port:   0x%x", rnid->udp_port);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: ip_addr:    %s", rnid->ip_addr);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: resv:       0x%x",
		    rnid->specific_id_resv);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: topo_flags: 0x%x", rnid->topo_flags);

		ret = FC_SUCCESS;
		break;
		}

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: code=%x", pm->pm_cmd_code);
		ret = FC_INVALID_REQUEST;
		break;

	}

	return (ret);

} /* emlxs_port_manage() */


/*ARGSUSED*/
static uint32_t
emlxs_test(emlxs_hba_t *hba, uint32_t test_code, uint32_t args, uint32_t *arg)
{
	uint32_t rval = 0;
	emlxs_port_t *port = &PPORT;

	switch (test_code) {
#ifdef TEST_SUPPORT
	case 1:	/* SCSI underrun */
		{
		uint32_t count = 1;
		if (args >= 1) {
			if (*arg > 0 && *arg < 100) {
				count = *arg;
			}
		}
		hba->underrun_counter = count;
		break;
		}
#endif	/* TEST_SUPPORT */

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_test: Unsupported test code. (0x%x)", test_code);
		rval = FC_INVALID_REQUEST;
	}

	return (rval);

} /* emlxs_test() */


/*
 * Given the device number, return the devinfo pointer or the ddiinst number.
 * Note: this routine must be successful on
 * DDI_INFO_DEVT2INSTANCE even before attach.
 *
 * Translate "dev_t" to a pointer to the associated "dev_info_t".
 */
/*ARGSUSED*/
static int
emlxs_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	emlxs_hba_t *hba;
	int32_t ddiinst;

	ddiinst = getminor((dev_t)arg);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
		if (hba)
			*result = hba->dip;
		else
			*result = NULL;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(unsigned long)ddiinst;
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);

} /* emlxs_info() */


static int32_t
emlxs_power(dev_info_t *dip, int32_t comp, int32_t level)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	int32_t ddiinst;
	int rval = DDI_SUCCESS;

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_power: comp=%x level=%x", comp, level);

	if (hba == NULL || comp != EMLXS_PM_ADAPTER) {
		return (DDI_FAILURE);
	}
	mutex_enter(&hba->pm_lock);

	/* If we are already at the proper level then return success */
	if (hba->pm_level == level) {
		mutex_exit(&hba->pm_lock);
		return (DDI_SUCCESS);
	}
	switch (level) {
	case EMLXS_PM_ADAPTER_UP:

		/*
		 * If we are already in emlxs_attach, let emlxs_hba_attach
		 * take care of things
		 */
		if (hba->pm_state & EMLXS_PM_IN_ATTACH) {
			hba->pm_level = EMLXS_PM_ADAPTER_UP;
			break;
		}
		/* Check if adapter is suspended */
		if (hba->pm_state & EMLXS_PM_SUSPENDED) {
			hba->pm_level = EMLXS_PM_ADAPTER_UP;

			/* Try to resume the port */
			rval = emlxs_hba_resume(dip);

			if (rval != DDI_SUCCESS) {
				hba->pm_level = EMLXS_PM_ADAPTER_DOWN;
			}
			break;
		}
		/* Set adapter up */
		hba->pm_level = EMLXS_PM_ADAPTER_UP;
		break;

	case EMLXS_PM_ADAPTER_DOWN:


		/*
		 * If we are already in emlxs_detach, let emlxs_hba_detach
		 * take care of things
		 */
		if (hba->pm_state & EMLXS_PM_IN_DETACH) {
			hba->pm_level = EMLXS_PM_ADAPTER_DOWN;
			break;
		}
		/* Check if adapter is not suspended */
		if (!(hba->pm_state & EMLXS_PM_SUSPENDED)) {
			hba->pm_level = EMLXS_PM_ADAPTER_DOWN;

			/* Try to suspend the port */
			rval = emlxs_hba_suspend(dip);

			if (rval != DDI_SUCCESS) {
				hba->pm_level = EMLXS_PM_ADAPTER_UP;
			}
			break;
		}
		/* Set adapter down */
		hba->pm_level = EMLXS_PM_ADAPTER_DOWN;
		break;

	default:
		rval = DDI_FAILURE;
		break;

	}

	mutex_exit(&hba->pm_lock);

	return (rval);

} /* emlxs_power() */



static int
emlxs_open(dev_t *dev_p, int32_t flag, int32_t otype, cred_t *cred_p)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	int ddiinst;

	ddiinst = getminor(*dev_p);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);

	if (hba == NULL) {
		return (ENXIO);
	}
	port = &PPORT;

	if (hba->pm_state & EMLXS_PM_SUSPENDED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ioctl_detail_msg,
		    "open failed: Driver suspended.");
		return (ENXIO);
	}
	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ioctl_detail_msg, "open: flag=%x
	 * otype=%x", flag, otype);
	 */

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}
	if (drv_priv(cred_p)) {
		return (EPERM);
	}
	mutex_enter(&EMLXS_IOCTL_LOCK);

	if (hba->ioctl_flags & EMLXS_OPEN_EXCLUSIVE) {
		mutex_exit(&EMLXS_IOCTL_LOCK);
		return (EBUSY);
	}
	if (flag & FEXCL) {
		if (hba->ioctl_flags & EMLXS_OPEN) {
			mutex_exit(&EMLXS_IOCTL_LOCK);
			return (EBUSY);
		}
		hba->ioctl_flags |= EMLXS_OPEN_EXCLUSIVE;
	}
	hba->ioctl_flags |= EMLXS_OPEN;

	mutex_exit(&EMLXS_IOCTL_LOCK);

	return (0);

} /* emlxs_open() */



/*ARGSUSED*/
static int
emlxs_close(dev_t dev, int32_t flag, int32_t otype, cred_t *cred_p)
{
	emlxs_hba_t *hba;
	/* emlxs_port_t *port; */
	int ddiinst;

	ddiinst = getminor(dev);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);

	if (hba == NULL) {
		return (ENXIO);
	}
	/* port = &PPORT; */

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ioctl_detail_msg,
	 * "close: flag=%x otype=%x", flag, otype);
	 */

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}
	mutex_enter(&EMLXS_IOCTL_LOCK);

	if (!(hba->ioctl_flags & EMLXS_OPEN)) {
		mutex_exit(&EMLXS_IOCTL_LOCK);
		return (ENODEV);
	}
	hba->ioctl_flags &= ~EMLXS_OPEN;
	hba->ioctl_flags &= ~EMLXS_OPEN_EXCLUSIVE;

	mutex_exit(&EMLXS_IOCTL_LOCK);

	return (0);

} /* emlxs_close() */



/*ARGSUSED*/
static int
emlxs_ioctl(dev_t dev, int32_t cmd, intptr_t arg, int32_t mode,
    cred_t *cred_p, int32_t *rval_p)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	int rval = 0;	/* return code */
	int ddiinst;

	ddiinst = getminor(dev);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);

	if (hba == NULL) {
		return (ENXIO);
	}
	port = &PPORT;

	if (hba->pm_state & EMLXS_PM_SUSPENDED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ioctl_detail_msg,
		    "ioctl failed: Driver suspended.");

		return (ENXIO);
	}
	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ioctl_detail_msg, "ioctl: cmd=%x
	 * arg=%llx mode=%x busy=%x", cmd, arg, mode, hba->pm_busy);
	 */

	mutex_enter(&EMLXS_IOCTL_LOCK);
	if (!(hba->ioctl_flags & EMLXS_OPEN)) {
		mutex_exit(&EMLXS_IOCTL_LOCK);
		return (ENXIO);
	}
	mutex_exit(&EMLXS_IOCTL_LOCK);

#ifdef IDLE_TIMER
	emlxs_pm_busy_component(hba);
#endif	/* IDLE_TIMER */

	switch (cmd) {
#ifdef DFC_SUPPORT
	case EMLXS_DFC_COMMAND:
		rval = emlxs_dfc_manage(hba, (void *) arg, mode);
		break;
#endif	/* DFC_SUPPORT */

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ioctl_detail_msg,
		    "ioctl: Invalid command received. cmd=%x", cmd);
		rval = EINVAL;
	}

done:
	return (rval);

} /* emlxs_ioctl() */



/*
 *
 *		  Device Driver Common Routines
 *
 */

/* emlxs_pm_lock must be held for this call */
static int
emlxs_hba_resume(dev_info_t *dip)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	int ddiinst;

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_resume_msg, NULL);

	if (!(hba->pm_state & EMLXS_PM_SUSPENDED)) {
		return (DDI_SUCCESS);
	}
	hba->pm_state &= ~EMLXS_PM_SUSPENDED;

	/* Take the adapter online */
	if (emlxs_power_up(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_resume_failed_msg,
		    "Unable to take adapter online.");

		hba->pm_state |= EMLXS_PM_SUSPENDED;

		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);

} /* emlxs_hba_resume() */


/* emlxs_pm_lock must be held for this call */
static int
emlxs_hba_suspend(dev_info_t *dip)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	int ddiinst;
	/* int ringno; */
	/* RING *rp; */

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_suspend_msg, NULL);

	if (hba->pm_state & EMLXS_PM_SUSPENDED) {
		return (DDI_SUCCESS);
	}
	hba->pm_state |= EMLXS_PM_SUSPENDED;

	/* Take the adapter offline */
	if (emlxs_power_down(hba)) {
		hba->pm_state &= ~EMLXS_PM_SUSPENDED;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_suspend_failed_msg,
		    "Unable to take adapter offline.");

		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);

} /* emlxs_hba_suspend() */



static void
emlxs_lock_init(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int32_t ddiinst;
	char buf[64];
	uint32_t i;

	ddiinst = hba->ddiinst;

	/* Initialize the power management */
	(void) sprintf(buf, "%s%d_pm_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&hba->pm_lock, buf, MUTEX_DRIVER, (void *)hba->intr_arg);

	(void) sprintf(buf, "%s%d_adap_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&EMLXS_TIMER_LOCK, buf, MUTEX_DRIVER, (void *)hba->intr_arg);

	(void) sprintf(buf, "%s%d_adap_lock cv", DRIVER_NAME, ddiinst);
	cv_init(&hba->timer_lock_cv, buf, CV_DRIVER, NULL);

	(void) sprintf(buf, "%s%d_port_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&EMLXS_PORT_LOCK, buf, MUTEX_DRIVER, (void *) hba->intr_arg);

	(void) sprintf(buf, "%s%d_mbox_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&EMLXS_MBOX_LOCK, buf, MUTEX_DRIVER, (void *) hba->intr_arg);

	(void) sprintf(buf, "%s%d_mbox_lock cv", DRIVER_NAME, ddiinst);
	cv_init(&EMLXS_MBOX_CV, buf, CV_DRIVER, NULL);

	(void) sprintf(buf, "%s%d_linkup_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&EMLXS_LINKUP_LOCK, buf, MUTEX_DRIVER,
	    (void *)hba->intr_arg);

	(void) sprintf(buf, "%s%d_linkup_lock cv", DRIVER_NAME, ddiinst);
	cv_init(&EMLXS_LINKUP_CV, buf, CV_DRIVER, NULL);

	(void) sprintf(buf, "%s%d_ring_tx_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&EMLXS_RINGTX_LOCK, buf, MUTEX_DRIVER,
	    (void *)hba->intr_arg);

	for (i = 0; i < MAX_RINGS; i++) {
		(void) sprintf(buf, "%s%d_cmd_ring%d_lock mutex",
		    DRIVER_NAME, ddiinst, i);
		mutex_init(&EMLXS_CMD_RING_LOCK(i), buf, MUTEX_DRIVER,
		    (void *)hba->intr_arg);

		(void) sprintf(buf, "%s%d_fctab%d_lock mutex",
		    DRIVER_NAME, ddiinst, i);
		mutex_init(&EMLXS_FCTAB_LOCK(i), buf, MUTEX_DRIVER,
		    (void *)hba->intr_arg);
	}

	(void) sprintf(buf, "%s%d_memget_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&EMLXS_MEMGET_LOCK, buf, MUTEX_DRIVER,
	    (void *)hba->intr_arg);

	(void) sprintf(buf, "%s%d_memput_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&EMLXS_MEMPUT_LOCK, buf, MUTEX_DRIVER,
	    (void *)hba->intr_arg);

	(void) sprintf(buf, "%s%d_ioctl_lock mutex", DRIVER_NAME, ddiinst);
	mutex_init(&EMLXS_IOCTL_LOCK, buf, MUTEX_DRIVER, (void *)hba->intr_arg);

	/* Create per port locks */
	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);

		rw_init(&port->node_rwlock, NULL, RW_DRIVER, NULL);

		if (i == 0) {
			(void) sprintf(buf, "%s%d_pkt_lock mutex",
			    DRIVER_NAME, ddiinst);
			mutex_init(&EMLXS_PKT_LOCK, buf, MUTEX_DRIVER,
			    (void *) hba->intr_arg);

			(void) sprintf(buf, "%s%d_pkt_lock cv",
			    DRIVER_NAME, ddiinst);
			cv_init(&EMLXS_PKT_CV, buf, CV_DRIVER, NULL);

			(void) sprintf(buf, "%s%d_ub_lock mutex",
			    DRIVER_NAME, ddiinst);
			mutex_init(&EMLXS_UB_LOCK, buf, MUTEX_DRIVER,
			    (void *) hba->intr_arg);
		} else {
			(void) sprintf(buf, "%s%d.%d_pkt_lock mutex",
			    DRIVER_NAME, ddiinst, port->vpi);
			mutex_init(&EMLXS_PKT_LOCK, buf, MUTEX_DRIVER,
			    (void *) hba->intr_arg);

			(void) sprintf(buf, "%s%d.%d_pkt_lock cv",
			    DRIVER_NAME, ddiinst, port->vpi);
			cv_init(&EMLXS_PKT_CV, buf, CV_DRIVER, NULL);

			(void) sprintf(buf, "%s%d.%d_ub_lock mutex",
			    DRIVER_NAME, ddiinst, port->vpi);
			mutex_init(&EMLXS_UB_LOCK, buf, MUTEX_DRIVER,
			    (void *) hba->intr_arg);
		}
	}

	return;

} /* emlxs_lock_init() */



static void
emlxs_lock_destroy(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t i;

	mutex_destroy(&EMLXS_TIMER_LOCK);
	cv_destroy(&hba->timer_lock_cv);

	mutex_destroy(&EMLXS_PORT_LOCK);

	cv_destroy(&EMLXS_MBOX_CV);
	cv_destroy(&EMLXS_LINKUP_CV);

	mutex_destroy(&EMLXS_LINKUP_LOCK);
	mutex_destroy(&EMLXS_MBOX_LOCK);

	mutex_destroy(&EMLXS_RINGTX_LOCK);

	for (i = 0; i < MAX_RINGS; i++) {
		mutex_destroy(&EMLXS_CMD_RING_LOCK(i));
		mutex_destroy(&EMLXS_FCTAB_LOCK(i));
	}

	mutex_destroy(&EMLXS_MEMGET_LOCK);
	mutex_destroy(&EMLXS_MEMPUT_LOCK);
	mutex_destroy(&EMLXS_IOCTL_LOCK);
	mutex_destroy(&hba->pm_lock);

	/* Destroy per port locks */
	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);
		rw_destroy(&port->node_rwlock);
		mutex_destroy(&EMLXS_PKT_LOCK);
		cv_destroy(&EMLXS_PKT_CV);
		mutex_destroy(&EMLXS_UB_LOCK);
	}

	return;

} /* emlxs_lock_destroy() */


/* init_flag values */
#define	ATTACH_SOFT_STATE	0x00000001
#define	ATTACH_FCA_TRAN		0x00000002
#define	ATTACH_HBA		0x00000004
#define	ATTACH_LOG		0x00000008
#define	ATTACH_MAP		0x00000010
#define	ATTACH_INTR_INIT	0x00000020
#define	ATTACH_PROP		0x00000040
#define	ATTACH_LOCK		0x00000080
#define	ATTACH_THREAD		0x00000100
#define	ATTACH_INTR_ADD		0x00000200
#define	ATTACH_ONLINE		0x00000400
#define	ATTACH_NODE		0x00000800
#define	ATTACH_FCT		0x00001000
#define	ATTACH_FCA		0x00002000
#define	ATTACH_KSTAT		0x00004000
#define	ATTACH_DHCHAP		0x00008000

static void
emlxs_driver_remove(dev_info_t *dip, uint32_t init_flag, uint32_t failed)
{
	emlxs_hba_t *hba = NULL;
	int ddiinst;

	ddiinst = ddi_get_instance(dip);

	if (init_flag & ATTACH_HBA) {
		hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);

		if (init_flag & ATTACH_ONLINE) {
			(void) emlxs_offline(hba);
		}
		if (init_flag & ATTACH_INTR_ADD) {
			(void) EMLXS_INTR_REMOVE(hba);
		}
#ifdef SFCT_SUPPORT
		if (init_flag & ATTACH_FCT) {
			emlxs_fct_detach(hba);
		}
#endif	/* SFCT_SUPPORT */

#ifdef DHCHAP_SUPPORT
		if (init_flag & ATTACH_DHCHAP) {
			emlxs_dhc_detach(hba);
		}
#endif	/* DHCHAP_SUPPORT */

		if (init_flag & ATTACH_KSTAT) {
			kstat_delete(hba->kstat);
		}
		if (init_flag & ATTACH_FCA) {
			emlxs_fca_detach(hba);
		}
		if (init_flag & ATTACH_NODE) {
			(void) ddi_remove_minor_node(hba->dip, "devctl");
		}
		if (init_flag & ATTACH_THREAD) {
			emlxs_thread_destroy(&hba->iodone_thread);
		}
		if (init_flag & ATTACH_PROP) {
			(void) ddi_prop_remove_all(hba->dip);
		}
		if (init_flag & ATTACH_LOCK) {
			emlxs_lock_destroy(hba);
		}
		if (init_flag & ATTACH_INTR_INIT) {
			(void) EMLXS_INTR_UNINIT(hba);
		}
		if (init_flag & ATTACH_MAP) {
			emlxs_unmapmem(hba);
		}
		if (init_flag & ATTACH_LOG) {
			(void) emlxs_msg_log_destroy(hba);
		}
		if (init_flag & ATTACH_FCA_TRAN) {
			(void) ddi_set_driver_private(hba->dip, NULL);
			kmem_free(hba->fca_tran, sizeof (fc_fca_tran_t));
			hba->fca_tran = NULL;
		}
		if (init_flag & ATTACH_HBA) {
			emlxs_device.log[hba->emlxinst] = 0;
			emlxs_device.hba[hba->emlxinst] =
			    (emlxs_hba_t *)(unsigned long)((failed) ? -1 : 0);
		}
	}
	if (init_flag & ATTACH_SOFT_STATE) {
		(void) ddi_soft_state_free(emlxs_soft_state, ddiinst);
	}
	return;

} /* emlxs_driver_remove() */



/* This determines which ports will be initiator mode */
static void
emlxs_fca_init(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	uint32_t i;

	if (!hba->ini_mode) {
		return;
	}
#ifdef MODSYM_SUPPORT
	/* Open SFS */
	(void) emlxs_fca_modopen();
#endif	/* MODSYM_SUPPORT */

	/* Check if SFS present */
	if (((void *) MODSYM(fc_fca_init) == NULL) ||
	    ((void *) MODSYM(fc_fca_attach) == NULL)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "SFS not present. Initiator mode disabled.");
		goto failed;
	}
	/* Setup devops for SFS */
	MODSYM(fc_fca_init) (&emlxs_ops);

	/* Check if our SFS driver interface matches the current SFS stack */
	if (MODSYM(fc_fca_attach) (hba->dip, hba->fca_tran) != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "SFS/FCA version mismatch. FCA=0x%x",
		    hba->fca_tran->fca_version);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "SFS present. Initiator mode disabled.");

		goto failed;
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "SFS present. Initiator mode enabled.");

	return;

failed:

	hba->ini_mode = 0;
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vport->ini_mode = 0;
	}

	return;

} /* emlxs_fca_init() */


/* This determines which ports will be initiator or target mode */
static void
emlxs_set_mode(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	uint32_t i;
	/* char string[256]; */
	uint32_t tgt_mode = 0;

#ifdef SFCT_SUPPORT
	emlxs_config_t *cfg;

	cfg = &hba->config[CFG_TARGET_MODE];
	tgt_mode = cfg->current;

	port->fct_flags = 0;
#endif	/* SFCT_SUPPORT */

	/* Initialize physical port  */
	if (tgt_mode) {
		hba->tgt_mode = 1;
		hba->ini_mode = 0;

		port->tgt_mode = 1;
		port->ini_mode = 0;
	} else {
		hba->tgt_mode = 0;
		hba->ini_mode = 1;

		port->tgt_mode = 0;
		port->ini_mode = 1;
	}

	/* Initialize virtual ports */
	/* Virtual ports take on the mode of the parent physical port */
	for (i = 1; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);

#ifdef SFCT_SUPPORT
		vport->fct_flags = 0;
#endif	/* SFCT_SUPPORT */

		vport->ini_mode = port->ini_mode;
		vport->tgt_mode = port->tgt_mode;
	}

	/* Check if initiator mode is requested */
	if (hba->ini_mode) {
		emlxs_fca_init(hba);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Initiator mode not enabled.");
	}

#ifdef SFCT_SUPPORT
	/* Check if target mode is requested */
	if (hba->tgt_mode) {
		emlxs_fct_init(hba);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Target mode not enabled.");
	}
#endif	/* SFCT_SUPPORT */

	return;

} /* emlxs_set_mode() */



static void
emlxs_fca_attach(emlxs_hba_t *hba)
{
#if (EMLXS_MODREV >= EMLXS_MODREV5)
	emlxs_config_t *cfg = &CFG;
#endif	/* >= EMLXS_MODREV5 */

	/* Update our transport structure */
	hba->fca_tran->fca_iblock = (ddi_iblock_cookie_t *)&hba->intr_arg;
	hba->fca_tran->fca_cmd_max = hba->io_throttle;

#if (EMLXS_MODREV >= EMLXS_MODREV5)
	hba->fca_tran->fca_num_npivports =
	    (cfg[CFG_NPIV_ENABLE].current) ? hba->vpi_max : 0;
	bcopy((caddr_t)&hba->wwpn, (caddr_t)&hba->fca_tran->fca_perm_pwwn,
	    sizeof (NAME_TYPE));
#endif	/* >= EMLXS_MODREV5 */

	return;

} /* emlxs_fca_attach() */


static void
emlxs_fca_detach(emlxs_hba_t *hba)
{
	uint32_t i;
	emlxs_port_t *vport;

	if (hba->ini_mode) {
		if ((void *) MODSYM(fc_fca_detach) != NULL) {
			MODSYM(fc_fca_detach) (hba->dip);
		}
		hba->ini_mode = 0;

		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);
			vport->ini_mode = 0;
		}
	}
	return;

} /* emlxs_fca_detach() */



static void
emlxs_drv_banner(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	/* emlxs_port_t *vport; */
	uint32_t i;
	char msi_mode[16];
	char npiv_mode[16];
	emlxs_vpd_t *vpd = &VPD;
	emlxs_config_t *cfg = &CFG;
	uint8_t *wwpn;
	uint8_t *wwnn;

	/* Display firmware library one time */
	if (hba->emlxinst == 0) {
		for (i = 0; emlxs_fw_image[i].id; i++) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_library_msg,
			    "%s", emlxs_fw_image[i].label);
		}
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg, "%s (%s)",
	    emlxs_label, emlxs_revision);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
	    "%s Dev_id:%x Sub_id:%x Id:%d", hba->model_info.model,
	    hba->model_info.device_id, hba->model_info.ssdid,
	    hba->model_info.id);

#ifdef EMLXS_I386

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
	    "Firmware:%s (%s) Boot:%s", vpd->fw_version,
	    vpd->fw_label, vpd->boot_version);

#else	/* EMLXS_SPARC */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
	    "Firmware:%s (%s) Boot:%s Fcode:%s", vpd->fw_version,
	    vpd->fw_label, vpd->boot_version, vpd->fcode_version);

#endif	/* EMLXS_I386 */

	(void) strcpy(msi_mode, " INTX:1");

#ifdef MSI_SUPPORT
	if (hba->intr_flags & EMLXS_MSI_ENABLED) {
		switch (hba->intr_type) {
		case DDI_INTR_TYPE_FIXED:
			(void) strcpy(msi_mode, " MSI:0");
			break;

		case DDI_INTR_TYPE_MSI:
			(void) sprintf(msi_mode, " MSI:%d", hba->intr_count);
			break;

		case DDI_INTR_TYPE_MSIX:
			(void) sprintf(msi_mode, " MSIX:%d", hba->intr_count);
			break;
		}
	}
#endif

	(void) strcpy(npiv_mode, "");

#ifdef SLI3_SUPPORT
	if (hba->flag & FC_NPIV_ENABLED) {
		(void) sprintf(npiv_mode, " NPIV:%d", hba->vpi_max);
	} else {
		(void) strcpy(npiv_mode, " NPIV:0");
	}
#endif	/* SLI3_SUPPORT */


	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg, "SLI:%d%s%s%s%s",
	    hba->sli_mode, msi_mode, npiv_mode,
	    ((hba->ini_mode) ? " FCA" : ""), ((hba->tgt_mode) ? " FCT" : ""));

	wwpn = (uint8_t *)&hba->wwpn;
	wwnn = (uint8_t *)&hba->wwnn;
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
	    "WWPN:%02X%02X%02X%02X%02X%02X%02X%02X "
	    "WWNN:%02X%02X%02X%02X%02X%02X%02X%02X",
	    wwpn[0], wwpn[1], wwpn[2], wwpn[3],
	    wwpn[4], wwpn[5], wwpn[6], wwpn[7],
	    wwnn[0], wwnn[1], wwnn[2], wwnn[3],
	    wwnn[4], wwnn[5], wwnn[6], wwnn[7]);

#ifdef SLI3_SUPPORT
	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);

		if (!(port->flag & EMLXS_PORT_CONFIG)) {
			continue;
		}
		wwpn = (uint8_t *)&port->wwpn;
		wwnn = (uint8_t *)&port->wwnn;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
		    "WWPN:%02X%02X%02X%02X%02X%02X%02X%02X "
		    "WWNN:%02X%02X%02X%02X%02X%02X%02X%02X",
		    wwpn[0], wwpn[1], wwpn[2], wwpn[3],
		    wwpn[4], wwpn[5], wwpn[6], wwpn[7],
		    wwnn[0], wwnn[1], wwnn[2], wwnn[3],
		    wwnn[4], wwnn[5], wwnn[6], wwnn[7]);
	}
	port = &PPORT;

#ifdef NPIV_SUPPORT
	if (cfg[CFG_NPIV_ENABLE].current && cfg[CFG_VPORT_RESTRICTED].current) {
		port->flag |= EMLXS_PORT_RESTRICTED;
	} else {
		port->flag &= ~EMLXS_PORT_RESTRICTED;
	}
#endif	/* NPIV_SUPPORT */

#endif	/* SLI3_SUPPORT */

	/*
	 * Announce the device: ddi_report_dev() prints a banner at boot
	 * time, announcing the device pointed to by dip.
	 */
	(void) ddi_report_dev(hba->dip);

	return;

} /* emlxs_drv_banner() */


extern void
emlxs_get_fcode_version(emlxs_hba_t *hba)
{
	/* emlxs_port_t *port = &PPORT; */
	emlxs_vpd_t *vpd = &VPD;
	/* emlxs_config_t *cfg = &CFG; */
	char *prop_str;
	int status;

	/* Setup fcode version property */
	prop_str = NULL;
	status = ddi_prop_lookup_string(DDI_DEV_T_ANY, (dev_info_t *)hba->dip,
	    0, "fcode-version", (char **)&prop_str);

	if (status == DDI_PROP_SUCCESS) {
		bcopy(prop_str, vpd->fcode_version, strlen(prop_str));
		(void) ddi_prop_free((void *) prop_str);
	} else {
		(void) strcpy(vpd->fcode_version, "none");
	}

	return;

} /* emlxs_get_fcode_version() */


static int
emlxs_hba_attach(dev_info_t *dip)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	/* emlxs_port_t *vport; */
	emlxs_config_t *cfg;
	char *prop_str;
	/* emlxs_vpd_t *vpd; */
	int ddiinst;
	int32_t emlxinst;
	int status;
	/* uint_t rnumber; */
	uint32_t rval;
	/* uint32_t i; */
	/* uint32_t device_id_valid; */
	uint32_t init_flag = 0;
#ifdef EMLXS_I386
	uint32_t i;
#endif	/* EMLXS_I386 */

	ddiinst = ddi_get_instance(dip);
	emlxinst = emlxs_add_instance(ddiinst);

	if (emlxinst >= MAX_FC_BRDS) {
		cmn_err(CE_WARN, "?%s: fca_hba_attach failed. "
		    "Too many driver ddiinsts. inst=%x", DRIVER_NAME, ddiinst);
		return (DDI_FAILURE);
	}
	if (emlxs_device.hba[emlxinst] == (emlxs_hba_t *)-1) {
		return (DDI_FAILURE);
	}
	if (emlxs_device.hba[emlxinst]) {
		return (DDI_SUCCESS);
	}
	/*
	 * An adapter can accidentally be plugged into a slave-only PCI
	 * slot... not good.
	 */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		cmn_err(CE_WARN, "?%s%d: fca_hba_attach failed. "
		    "Device in slave-only slot.", DRIVER_NAME, ddiinst);
		return (DDI_FAILURE);
	}
	/* Allocate emlxs_dev_ctl structure. */
	if (ddi_soft_state_zalloc(emlxs_soft_state, ddiinst) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "?%s%d: fca_hba_attach failed. "
		    "Unable to allocate soft state.", DRIVER_NAME, ddiinst);
		return (DDI_FAILURE);
	}
	init_flag |= ATTACH_SOFT_STATE;

	if ((hba = (emlxs_hba_t *)
	    ddi_get_soft_state(emlxs_soft_state, ddiinst)) == NULL) {
		cmn_err(CE_WARN, "?%s%d: fca_hba_attach failed. "
		    "Unable to get soft state.", DRIVER_NAME, ddiinst);
		goto failed;
	}
	bzero((char *)hba, sizeof (emlxs_hba_t));

	emlxs_device.hba[emlxinst] = hba;
	emlxs_device.log[emlxinst] = &hba->log;
	hba->dip = dip;
	hba->emlxinst = emlxinst;
	hba->ddiinst = ddiinst;
	hba->ini_mode = 0;
	hba->tgt_mode = 0;
	hba->mem_bpl_size = MEM_BPL_SIZE;

	init_flag |= ATTACH_HBA;

	/* Enable the physical port on this HBA */
	port = &PPORT;
	port->hba = hba;
	port->vpi = 0;
	port->flag |= EMLXS_PORT_ENABLE;

	/* Allocate a transport structure */
	hba->fca_tran = (fc_fca_tran_t *)
	    kmem_zalloc(sizeof (fc_fca_tran_t), KM_NOSLEEP);
	if (hba->fca_tran == NULL) {
		cmn_err(CE_WARN, "?%s%d: fca_hba_attach failed. "
		    "Unable to allocate fca_tran memory.",
		    DRIVER_NAME, ddiinst);
		goto failed;
	}
	bcopy((caddr_t)&emlxs_fca_tran, (caddr_t)hba->fca_tran,
	    sizeof (fc_fca_tran_t));

	/* Set the transport structure pointer in our dip */
	/* SFS may panic if we are in target only mode    */
	/* We will update the transport structure later   */
	(void) ddi_set_driver_private(dip, (caddr_t)&emlxs_fca_tran);
	init_flag |= ATTACH_FCA_TRAN;

	/* Perform driver integrity check */
	rval = emlxs_integrity_check(hba);
	if (rval) {
		cmn_err(CE_WARN, "?%s%d: fca_hba_attach failed. "
		    "Driver integrity check failed. %d error(s) found.",
		    DRIVER_NAME, ddiinst, rval);
		goto failed;
	}
	/* vpd = &VPD; */
	cfg = &CFG;

	bcopy((uint8_t *)&emlxs_cfg, (uint8_t *)cfg, sizeof (emlxs_cfg));

#ifdef MSI_SUPPORT
	if ((void *) &ddi_intr_get_supported_types != NULL) {
		hba->intr_flags |= EMLXS_MSI_ENABLED;
	}
#endif	/* MSI_SUPPORT */

	/* Create the msg log file */
	if (emlxs_msg_log_create(hba) == 0) {
		cmn_err(CE_WARN, "?%s%d: fca_hba_attach failed. "
		    "Unable to create message log", DRIVER_NAME, ddiinst);
		goto failed;

	}
	init_flag |= ATTACH_LOG;

	/* We can begin to use EMLXS_MSGF from this point on */

	/*
	 * Find the I/O bus type If it is not a SBUS card, then it is a PCI
	 * card. Default is PCI_FC (0).
	 */
	prop_str = NULL;
	status = ddi_prop_lookup_string(DDI_DEV_T_ANY, (dev_info_t *)dip,
	    0, "name", (char **)&prop_str);

	if (status == DDI_PROP_SUCCESS) {
		if (strncmp(prop_str, "lpfs", 4) == 0) {
			hba->bus_type = SBUS_FC;
		}
		(void) ddi_prop_free((void *) prop_str);
	}
	if (emlxs_mapmem(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to map memory");
		goto failed;

	}
	init_flag |= ATTACH_MAP;

	/*
	 * Copy DDS from the config method and update configuration
	 * parameters
	 */
	(void) emlxs_get_props(hba);

#ifdef EMLXS_I386
	/* Update BPL size based on max_xfer_size */
	i = cfg[CFG_MAX_XFER_SIZE].current;
	if (i > 688128) {	/* 688128 = (((2048 / 12) - 2) * 4096) */
		hba->mem_bpl_size = 4096;
	} else if (i > 339968) {
		/* 339968 = (((1024 / 12) - 2) * 4096) */
		hba->mem_bpl_size = 2048;
	} else {
		hba->mem_bpl_size = 1024;
	}

	/* Update dma_attr_sgllen based on BPL size */
	i = BPL_TO_SGLLEN(hba->mem_bpl_size);
	emlxs_dma_attr.dma_attr_sgllen = i;
	emlxs_dma_attr_ro.dma_attr_sgllen = i;
	emlxs_dma_attr_fcip_rsp.dma_attr_sgllen = i;
#endif	/* EMLXS_I386 */

	/* Attempt to identify the adapter */
	rval = emlxs_init_adapter_info(hba);

	if (rval == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to get adapter info.  Id:%d  Device id:0x%x "
		    " Model:%s", hba->model_info.id,
		    hba->model_info.device_id, hba->model_info.model);
		goto failed;
	}
	/* Check if adapter is not supported */
	if (hba->model_info.flags & EMLXS_NOT_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unsupported adapter found.  Id:%d  Device id:0x%x  "
		    "SSDID:0x%x  Model:%s", hba->model_info.id,
		    hba->model_info.device_id, hba->model_info.ssdid,
		    hba->model_info.model);
		goto failed;
	}
	/* Initialize the interrupts. But don't add them yet */
	status = EMLXS_INTR_INIT(hba, 0);
	if (status != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to initalize interrupt(s).");
		goto failed;

	}
	init_flag |= ATTACH_INTR_INIT;

	/* Initialize LOCKs */
	emlxs_lock_init(hba);
	init_flag |= ATTACH_LOCK;

	/* Initialize the power management */
	mutex_enter(&hba->pm_lock);
	hba->pm_state = EMLXS_PM_IN_ATTACH;
	hba->pm_level = EMLXS_PM_ADAPTER_DOWN;
	hba->pm_busy = 0;
#ifdef IDLE_TIMER
	hba->pm_active = 1;
	hba->pm_idle_timer = 0;
#endif	/* IDLE_TIMER */
	mutex_exit(&hba->pm_lock);

	/* Set the pm component name */
	(void) sprintf(emlxs_pm_components[0], "NAME=%s%d", DRIVER_NAME,
	    ddiinst);

	/* Check if power management support is enabled */
	if (cfg[CFG_PM_SUPPORT].current) {
		if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
		    "pm-components", emlxs_pm_components,
		    sizeof (emlxs_pm_components) /
		    sizeof (emlxs_pm_components[0])) != DDI_PROP_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
			    "Unable to create pm components.");
			goto failed;
		}
	}
	/* Needed for suspend and resume support */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "pm-hardware-state", "needs-suspend-resume");
	init_flag |= ATTACH_PROP;

	emlxs_thread_create(hba, &hba->iodone_thread);
	init_flag |= ATTACH_THREAD;

	/* Setup initiator / target ports */
	emlxs_set_mode(hba);

	/*
	 * If driver did not attach to either stack, then driver attach
	 * failed
	 */
	if (!hba->tgt_mode && !hba->ini_mode) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Driver interfaces not enabled.");
		goto failed;
	}
	/*
	 *	Initialize HBA
	 */

	/* Set initial state */
	mutex_enter(&EMLXS_PORT_LOCK);
	emlxs_diag_state = DDI_OFFDI;
	hba->flag |= FC_OFFLINE_MODE;
	hba->flag &= ~(FC_ONLINE_MODE | FC_ONLINING_MODE | FC_OFFLINING_MODE);
	mutex_exit(&EMLXS_PORT_LOCK);

	if (status = emlxs_online(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to initialize adapter.");
		goto failed;
	}
	init_flag |= ATTACH_ONLINE;

	/* This is to ensure that the model property is properly set */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
	    hba->model_info.model);

	/* Create the device node. */
	if (ddi_create_minor_node(dip, "devctl", S_IFCHR, ddiinst, NULL, 0) ==
	    DDI_FAILURE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to create device node.");
		goto failed;
	}
	init_flag |= ATTACH_NODE;

	/* Attach initiator now */
	/* This must come after emlxs_online() */
	emlxs_fca_attach(hba);
	init_flag |= ATTACH_FCA;

	/* Initialize kstat information */
	hba->kstat = kstat_create(DRIVER_NAME, ddiinst, "statistics",
	    "controller", KSTAT_TYPE_RAW, sizeof (emlxs_stats_t),
	    KSTAT_FLAG_VIRTUAL);

	if (hba->kstat == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "kstat_create failed.");
	} else {
		hba->kstat->ks_data = (void *) &hba->stats;
		kstat_install(hba->kstat);
		init_flag |= ATTACH_KSTAT;
	}

#if (EMLXS_MODREV >= EMLXS_MODREV3) && (EMLXS_MODREV <= EMLXS_MODREV4)
	/* Setup virtual port properties */
	emlxs_read_vport_prop(hba);
#endif	/* EMLXS_MODREV3 || EMLXS_MODREV4 */


#ifdef DHCHAP_SUPPORT
	emlxs_dhc_attach(hba);
	init_flag |= ATTACH_DHCHAP;
#endif	/* DHCHAP_SUPPORT */

	/* Display the driver banner now */
	emlxs_drv_banner(hba);

	/* Raise the power level */

	/*
	 * This will not execute emlxs_hba_resume because EMLXS_PM_IN_ATTACH
	 * is set
	 */
	if (emlxs_pm_raise_power(dip) != DDI_SUCCESS) {
		/* Set power up anyway. This should not happen! */
		mutex_enter(&hba->pm_lock);
		hba->pm_level = EMLXS_PM_ADAPTER_UP;
		hba->pm_state &= ~EMLXS_PM_IN_ATTACH;
		mutex_exit(&hba->pm_lock);
	} else {
		mutex_enter(&hba->pm_lock);
		hba->pm_state &= ~EMLXS_PM_IN_ATTACH;
		mutex_exit(&hba->pm_lock);
	}

#ifdef SFCT_SUPPORT
	/* Do this last */
	emlxs_fct_attach(hba);
	init_flag |= ATTACH_FCT;
#endif	/* SFCT_SUPPORT */

	return (DDI_SUCCESS);

failed:

	emlxs_driver_remove(dip, init_flag, 1);

	return (DDI_FAILURE);

} /* emlxs_hba_attach() */


static int
emlxs_hba_detach(dev_info_t *dip)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	int ddiinst;
	uint32_t init_flag = (uint32_t)-1;

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_debug_msg, NULL);

	mutex_enter(&hba->pm_lock);
	hba->pm_state |= EMLXS_PM_IN_DETACH;
	mutex_exit(&hba->pm_lock);

	/* Lower the power level */
	/*
	 * This will not suspend the driver since the EMLXS_PM_IN_DETACH has
	 * been set
	 */
	if (emlxs_pm_lower_power(dip) != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
		    "Unable to lower power.");

		mutex_enter(&hba->pm_lock);
		hba->pm_state &= ~EMLXS_PM_IN_DETACH;
		mutex_exit(&hba->pm_lock);

		return (DDI_FAILURE);
	}
	/* Take the adapter offline first, if not already */
	if (emlxs_offline(hba) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
		    "Unable to take adapter offline.");

		mutex_enter(&hba->pm_lock);
		hba->pm_state &= ~EMLXS_PM_IN_DETACH;
		mutex_exit(&hba->pm_lock);

		(void) emlxs_pm_raise_power(dip);

		return (DDI_FAILURE);
	}
	init_flag &= ~ATTACH_ONLINE;

	/* Remove the driver instance */
	emlxs_driver_remove(dip, init_flag, 0);

	return (DDI_SUCCESS);

} /* emlxs_hba_detach() */


extern int
emlxs_mapmem(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	dev_info_t *dip;
	ddi_device_acc_attr_t dev_attr;
	int status;
	/* int32_t rc; */

	dip = (dev_info_t *)hba->dip;
	dev_attr = emlxs_dev_acc_attr;

	if (hba->bus_type == SBUS_FC) {
		if (hba->pci_acc_handle == 0) {
			status = ddi_regs_map_setup(dip,
			    SBUS_DFLY_PCI_CFG_RINDEX,
			    (caddr_t *)&hba->pci_addr,
			    0, 0, &emlxs_dev_acc_attr, &hba->pci_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup "
				    "PCI failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->slim_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_DFLY_SLIM_RINDEX,
			    (caddr_t *)&hba->slim_addr, 0, 0,
			    &dev_attr, &hba->slim_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup SLIM failed."
				    " status=%x", status);
				goto failed;
			}
		}
		if (hba->csr_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_DFLY_CSR_RINDEX,
			    (caddr_t *)&hba->csr_addr, 0, 0,
			    &dev_attr, &hba->csr_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup "
				    "DFLY CSR failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->sbus_flash_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_FLASH_RDWR,
			    (caddr_t *)&hba->sbus_flash_addr, 0, 0,
			    &dev_attr, &hba->sbus_flash_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup "
				    "Fcode Flash failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->sbus_core_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_TITAN_CORE_RINDEX,
			    (caddr_t *)&hba->sbus_core_addr, 0, 0,
			    &dev_attr, &hba->sbus_core_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup "
				    "TITAN CORE failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->sbus_pci_handle == 0) {
			status = ddi_regs_map_setup(dip,
			    SBUS_TITAN_PCI_CFG_RINDEX,
			    (caddr_t *)&hba->sbus_pci_addr, 0, 0,
			    &dev_attr, &hba->sbus_pci_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup "
				    "TITAN PCI failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->sbus_csr_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_TITAN_CSR_RINDEX,
			    (caddr_t *)&hba->sbus_csr_addr, 0, 0,
			    &dev_attr, &hba->sbus_csr_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup "
				    "TITAN CSR failed. status=%x", status);
				goto failed;
			}
		}
	} else {	/* ****** PCI ****** */

		if (hba->pci_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_CFG_RINDEX,
			    (caddr_t *)&hba->pci_addr, 0, 0,
			    &emlxs_dev_acc_attr, &hba->pci_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(PCI) ddi_regs_map_setup "
				    "PCI failed. status=%x", status);
				goto failed;
			}
		}
#ifdef EMLXS_I386
		/* Setting up PCI configure space */
		(void) ddi_put16(hba->pci_acc_handle,
		    (uint16_t *)(hba->pci_addr + PCI_COMMAND_REGISTER),
		    CMD_CFG_VALUE | CMD_IO_ENBL);
#endif	/* EMLXS_I386 */

		if (hba->slim_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_SLIM_RINDEX,
			    (caddr_t *)&hba->slim_addr, 0, 0,
			    &dev_attr, &hba->slim_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(PCI) ddi_regs_map_setup SLIM failed. "
				    "stat=%d mem=%p attr=%p hdl=%p",
				    status, &hba->slim_addr, &dev_attr,
				    &hba->slim_acc_handle);
				goto failed;
			}
		}
		/*
		 * Map in control registers, using memory-mapped version of
		 * the registers rather than the I/O space-mapped registers.
		 */
		if (hba->csr_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_CSR_RINDEX,
			    (caddr_t *)&hba->csr_addr, 0, 0,
			    &dev_attr, &hba->csr_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "ddi_regs_map_setup CSR failed. "
				    "status=%x", status);
				goto failed;
			}
		}
	}

	if (hba->slim2.virt == 0) {
		MBUF_INFO *buf_info;
		MBUF_INFO bufinfo;

		buf_info = &bufinfo;

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = SLI_SLIM2_SIZE;
		buf_info->flags = FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		buf_info->align = ddi_ptob(dip, 1L);

		(void) emlxs_mem_alloc(hba, buf_info);

		if (buf_info->virt == NULL) {
			goto failed;
		}
		hba->slim2.virt = (uint8_t *)buf_info->virt;
		hba->slim2.phys = buf_info->phys;
		hba->slim2.size = SLI_SLIM2_SIZE;
		hba->slim2.data_handle = buf_info->data_handle;
		hba->slim2.dma_handle = buf_info->dma_handle;
		bzero((char *)hba->slim2.virt, SLI_SLIM2_SIZE);
	}
	/* offset from beginning of register space */
	hba->ha_reg_addr = (sizeof (uint32_t) * HA_REG_OFFSET);
	hba->ca_reg_addr = (sizeof (uint32_t) * CA_REG_OFFSET);
	hba->hs_reg_addr = (sizeof (uint32_t) * HS_REG_OFFSET);
	hba->hc_reg_addr = (sizeof (uint32_t) * HC_REG_OFFSET);
	hba->bc_reg_addr = (sizeof (uint32_t) * BC_REG_OFFSET);

	if (hba->bus_type == SBUS_FC) {
		/*
		 * offset from beginning of register space for TITAN
		 * registers
		 */
		hba->shc_reg_addr = (sizeof (uint32_t) * SBUS_CTRL_REG_OFFSET);
		hba->shs_reg_addr = (sizeof (uint32_t) * SBUS_STAT_REG_OFFSET);
		hba->shu_reg_addr = (sizeof (uint32_t) *
		    SBUS_UPDATE_REG_OFFSET);
	}
	return (0);

failed:

	emlxs_unmapmem(hba);
	return (ENOMEM);

} /* emlxs_mapmem() */


extern void
emlxs_unmapmem(emlxs_hba_t *hba)
{
	/* emlxs_port_t *port = &PPORT; */
	MBUF_INFO bufinfo;
	MBUF_INFO *buf_info = &bufinfo;

	if (hba->pci_acc_handle) {
		(void) ddi_regs_map_free(&hba->pci_acc_handle);
		hba->pci_acc_handle = 0;
	}
	if (hba->csr_acc_handle) {
		(void) ddi_regs_map_free(&hba->csr_acc_handle);
		hba->csr_acc_handle = 0;
	}
	if (hba->slim_acc_handle) {
		(void) ddi_regs_map_free(&hba->slim_acc_handle);
		hba->slim_acc_handle = 0;
	}
	if (hba->sbus_flash_acc_handle) {
		(void) ddi_regs_map_free(&hba->sbus_flash_acc_handle);
		hba->sbus_flash_acc_handle = 0;
	}
	if (hba->sbus_core_acc_handle) {
		(void) ddi_regs_map_free(&hba->sbus_core_acc_handle);
		hba->sbus_core_acc_handle = 0;
	}
	if (hba->sbus_pci_handle) {
		(void) ddi_regs_map_free(&hba->sbus_pci_handle);
		hba->sbus_pci_handle = 0;
	}
	if (hba->sbus_csr_handle) {
		(void) ddi_regs_map_free(&hba->sbus_csr_handle);
		hba->sbus_csr_handle = 0;
	}
	if (hba->slim2.virt) {
		bzero(buf_info, sizeof (MBUF_INFO));

		if (hba->slim2.phys) {
			buf_info->phys = hba->slim2.phys;
			buf_info->data_handle = hba->slim2.data_handle;
			buf_info->dma_handle = hba->slim2.dma_handle;
			buf_info->flags = FC_MBUF_DMA;
		}
		buf_info->virt = (uint32_t *)hba->slim2.virt;
		buf_info->size = hba->slim2.size;
		emlxs_mem_free(hba, buf_info);

		hba->slim2.virt = 0;
	}
	return;

} /* emlxs_unmapmem() */


static int
emlxs_get_props(emlxs_hba_t *hba)
{
	/* emlxs_port_t *port = &PPORT; */
	emlxs_config_t *cfg;
	uint32_t i;
	char string[256];
	uint32_t new_value;

	/* Initialize each parameter */
	for (i = 0; i < NUM_CFG_PARAM; i++) {
		cfg = &hba->config[i];

		/* Ensure strings are terminated */
		cfg->string[(EMLXS_CFG_STR_SIZE - 1)] = 0;
		cfg->help[(EMLXS_CFG_HELP_SIZE - 1)] = 0;

		/* Set the current value to the default value */
		new_value = cfg->def;

		/* First check for the global setting */
		new_value = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY,
		    (void *)hba->dip, DDI_PROP_DONTPASS, cfg->string,
		    new_value);

		/* Now check for the per adapter ddiinst setting */
		(void) sprintf(string, "%s%d-%s", DRIVER_NAME,
		    hba->ddiinst, cfg->string);

		new_value = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY,
		    (void *) hba->dip, DDI_PROP_DONTPASS, string, new_value);

		/* Now check the parameter */
		cfg->current = emlxs_check_parm(hba, i, new_value);
	}

	return (0);

} /* emlxs_get_props() */


extern uint32_t
emlxs_check_parm(emlxs_hba_t *hba, uint32_t index, uint32_t new_value)
{
	emlxs_port_t *port = &PPORT;
	uint32_t i;
	emlxs_config_t *cfg;
	emlxs_vpd_t *vpd = &VPD;

	if (index > NUM_CFG_PARAM) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_check_parm failed. Invalid index = %d", index);

		return (new_value);
	}
	cfg = &hba->config[index];

	if (new_value > cfg->hi) {
		new_value = cfg->def;
	} else if (new_value < cfg->low) {
		new_value = cfg->def;
	}
	/* Perform additional checks */
	switch (index) {
#ifdef NPIV_SUPPORT
	case CFG_NPIV_ENABLE:
		if (hba->tgt_mode) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "enable-npiv: Not supported in target mode. "
			    "Disabling.");

			new_value = 0;
		}
		break;
#endif	/* NPIV_SUPPORT */

#ifdef DHCHAP_SUPPORT
	case CFG_AUTH_ENABLE:
		if (hba->tgt_mode) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "enable-auth: Not supported in target mode. "
			    "Disabling.");

			new_value = 0;
		}
		break;
#endif	/* DHCHAP_SUPPORT */

	case CFG_NUM_NODES:
		switch (new_value) {
		case 1:
		case 2:
			/* Must have at least 3 if not 0 */
			return (3);

		default:
			break;
		}
		break;

	case CFG_LINK_SPEED:
		if (vpd->link_speed) {
			switch (new_value) {
			case 0:
				break;

			case 1:
				if (!(vpd->link_speed & LMT_1GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 1Gb not supported by "
					    "adapter. "
					    "Switching to auto detect.");
				}
				break;

			case 2:
				if (!(vpd->link_speed & LMT_2GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 2Gb not supported "
					    "by adapter. "
					    "Switching to auto detect.");
				}
				break;
			case 4:
				if (!(vpd->link_speed & LMT_4GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 4Gb not supported "
					    "by adapter. "
					    "Switching to auto detect.");
				}
				break;

			case 8:
				if (!(vpd->link_speed & LMT_8GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 8Gb not supported "
					    "by adapter. "
					    "Switching to auto detect.");
				}
				break;

			case 10:
				if (!(vpd->link_speed & LMT_10GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 10Gb not supported "
					    "by adapter. "
					    "Switching to auto detect.");
				}
				break;

			default:
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "link-speed: Invalid value=%d "
				    "provided. Switching to "
				    "auto detect.", new_value);

				new_value = 0;
			}
		} else {	/* Perform basic validity check */
			/* Perform additional check on link speed */
			switch (new_value) {
			case 0:
			case 1:
			case 2:
			case 4:
			case 8:
			case 10:
				/* link-speed is a valid choice */
				break;

			default:
				new_value = cfg->def;
			}
		}
		break;

	case CFG_TOPOLOGY:
		/* Perform additional check on topology */
		switch (new_value) {
		case 0:
		case 2:
		case 4:
		case 6:
			/* topology is a valid choice */
			break;

		default:
			return (cfg->def);
		}
		break;

#ifdef DHCHAP_SUPPORT
	case CFG_AUTH_TYPE:
		{
			uint32_t shift;
			uint32_t mask;

			/* Perform additional check on auth type */
			shift = 12;
			mask = 0xF000;
			for (i = 0; i < 4; i++) {
				if (((new_value & mask) >> shift) >
				    DFC_AUTH_TYPE_MAX) {
					return (cfg->def);
				}
				shift -= 4;
				mask >>= 4;
			}
			break;
		}

	case CFG_AUTH_HASH:
		{
			uint32_t shift;
			uint32_t mask;

			/* Perform additional check on auth hash */
			shift = 12;
			mask = 0xF000;
			for (i = 0; i < 4; i++) {
				if (((new_value & mask) >> shift) >
				    DFC_AUTH_HASH_MAX) {
					return (cfg->def);
				}
				shift -= 4;
				mask >>= 4;
			}
			break;
		}

	case CFG_AUTH_GROUP:
		{
			uint32_t shift;
			uint32_t mask;

			/* Perform additional check on auth group */
			shift = 28;
			mask = 0xF0000000;
			for (i = 0; i < 8; i++) {
				if (((new_value & mask) >> shift) >
				    DFC_AUTH_GROUP_MAX) {
					return (cfg->def);
				}
				shift -= 4;
				mask >>= 4;
			}
			break;
		}

	case CFG_AUTH_INTERVAL:
		if (new_value < 10) {
			return (10);
		}
		break;


#endif	/* DHCHAP_SUPPORT */

	}	/* switch */

	return (new_value);

} /* emlxs_check_parm() */


extern uint32_t
emlxs_set_parm(emlxs_hba_t *hba, uint32_t index, uint32_t new_value)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	uint32_t vpi;
	/* uint32_t i; */
	emlxs_config_t *cfg;
	uint32_t old_value;

	if (index > NUM_CFG_PARAM) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_set_parm failed. Invalid index = %d", index);

		return ((uint32_t)FC_FAILURE);
	}
	cfg = &hba->config[index];

	if (!(cfg->flags & PARM_DYNAMIC)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_set_parm failed. %s is not dynamic.", cfg->string);

		return ((uint32_t)FC_FAILURE);
	}
	/* Check new value */
	old_value = new_value;
	new_value = emlxs_check_parm(hba, index, new_value);

	if (old_value != new_value) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_set_parm: %s invalid. 0x%x --> 0x%x",
		    cfg->string, old_value, new_value);
	}
	/* Return now if no actual change */
	if (new_value == cfg->current) {
		return (FC_SUCCESS);
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "emlxs_set_parm: %s changing. 0x%x --> 0x%x",
	    cfg->string, cfg->current, new_value);

	old_value = cfg->current;
	cfg->current = new_value;

	/* React to change if needed */
	switch (index) {
	case CFG_PCI_MAX_READ:
		/* Update MXR */
		emlxs_pcix_mxr_update(hba, 1);
		break;

#ifdef SLI3_SUPPORT
	case CFG_SLI_MODE:
		/* Check SLI mode */
		if ((hba->sli_mode == 3) && (new_value == 2)) {
			/* All vports must be disabled first */
			for (vpi = 1; vpi < MAX_VPORTS; vpi++) {
				vport = &VPORT(vpi);

				if (vport->flag & EMLXS_PORT_ENABLE) {
					/* Reset current value */
					cfg->current = old_value;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "emlxs_set_parm failed. %s: "
					    "vpi=%d still enabled. "
					    "Value restored to 0x%x.",
					    cfg->string, vpi, old_value);

					return (2);
				}
			}
		}
		break;

#ifdef NPIV_SUPPORT
	case CFG_NPIV_ENABLE:
		/* Check if NPIV is being disabled */
		if ((old_value == 1) && (new_value == 0)) {
			/* All vports must be disabled first */
			for (vpi = 1; vpi < MAX_VPORTS; vpi++) {
				vport = &VPORT(vpi);

				if (vport->flag & EMLXS_PORT_ENABLE) {
					/* Reset current value */
					cfg->current = old_value;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "emlxs_set_parm failed. "
					    "%s: vpi=%d still enabled. "
					    "Value restored to 0x%x.",
					    cfg->string, vpi, old_value);

					return (2);
				}
			}
		}
		/* Trigger adapter reset */
		/* emlxs_reset(port, FC_FCA_RESET); */

		break;


	case CFG_VPORT_RESTRICTED:
		for (vpi = 1; vpi < MAX_VPORTS; vpi++) {
			vport = &VPORT(vpi);

			if (!(vport->flag & EMLXS_PORT_CONFIG)) {
				continue;
			}
			if (vport->options & EMLXS_OPT_RESTRICT_MASK) {
				continue;
			}
			if (new_value) {
				vport->flag |= EMLXS_PORT_RESTRICTED;
			} else {
				vport->flag &= ~EMLXS_PORT_RESTRICTED;
			}
		}

		break;
#endif	/* NPIV_SUPPORT */
#endif	/* SLI3_SUPPORT */

#ifdef DHCHAP_SUPPORT
	case CFG_AUTH_ENABLE:
		(void) emlxs_reset(port, FC_FCA_LINK_RESET);
		break;

	case CFG_AUTH_TMO:
		hba->auth_cfg.authentication_timeout = cfg->current;
		break;

	case CFG_AUTH_MODE:
		hba->auth_cfg.authentication_mode = cfg->current;
		break;

	case CFG_AUTH_BIDIR:
		hba->auth_cfg.bidirectional = cfg->current;
		break;

	case CFG_AUTH_TYPE:
		hba->auth_cfg.authentication_type_priority[0] =
		    (cfg->current & 0xF000) >> 12;
		hba->auth_cfg.authentication_type_priority[1] =
		    (cfg->current & 0x0F00) >> 8;
		hba->auth_cfg.authentication_type_priority[2] =
		    (cfg->current & 0x00F0) >> 4;
		hba->auth_cfg.authentication_type_priority[3] =
		    (cfg->current & 0x000F);
		break;

	case CFG_AUTH_HASH:
		hba->auth_cfg.hash_priority[0] = (cfg->current & 0xF000) >> 12;
		hba->auth_cfg.hash_priority[1] = (cfg->current & 0x0F00) >> 8;
		hba->auth_cfg.hash_priority[2] = (cfg->current & 0x00F0) >> 4;
		hba->auth_cfg.hash_priority[3] = (cfg->current & 0x000F);
		break;

	case CFG_AUTH_GROUP:
		hba->auth_cfg.dh_group_priority[0] =
		    (cfg->current & 0xF0000000) >> 28;
		hba->auth_cfg.dh_group_priority[1] =
		    (cfg->current & 0x0F000000) >> 24;
		hba->auth_cfg.dh_group_priority[2] =
		    (cfg->current & 0x00F00000) >> 20;
		hba->auth_cfg.dh_group_priority[3] =
		    (cfg->current & 0x000F0000) >> 16;
		hba->auth_cfg.dh_group_priority[4] =
		    (cfg->current & 0x0000F000) >> 12;
		hba->auth_cfg.dh_group_priority[5] =
		    (cfg->current & 0x00000F00) >> 8;
		hba->auth_cfg.dh_group_priority[6] =
		    (cfg->current & 0x000000F0) >> 4;
		hba->auth_cfg.dh_group_priority[7] =
		    (cfg->current & 0x0000000F);
		break;

	case CFG_AUTH_INTERVAL:
		hba->auth_cfg.reauthenticate_time_interval = cfg->current;
		break;
#endif	/* DHCAHP_SUPPORT */

	}

	return (FC_SUCCESS);

} /* emlxs_set_parm() */


/*
 * emlxs_mem_alloc  OS specific routine for memory allocation / mapping
 *
 * The buf_info->flags field describes the memory operation requested.
 *
 * FC_MBUF_PHYSONLY set  requests a supplied virtual address be mapped for
 * DMA Virtual address is supplied in buf_info->virt DMA
 * mapping flag is in buf_info->align (DMA_READ_ONLY, DMA_WRITE_ONLY,
 * DMA_READ_WRITE) The mapped physical address is returned * buf_info->phys
 *
 * FC_MBUF_PHYSONLY cleared requests memory be allocated for driver use
 * and if FC_MBUF_DMA is set the memory is also mapped for DMA
 * The byte alignment of the memory request is supplied in
 * buf_info->align The byte size of the memory request is supplied
 * in buf_info->size The virtual address is returned buf_info->virt
 * The mapped physical address is returned buf_info->phys
 * (for FC_MBUF_DMA)
 */
extern uint8_t *
emlxs_mem_alloc(emlxs_hba_t *hba, MBUF_INFO *buf_info)
{
	emlxs_port_t *port = &PPORT;
	ddi_dma_attr_t dma_attr;
	ddi_device_acc_attr_t dev_attr;
	uint_t cookie_count;
	size_t dma_reallen;
	ddi_dma_cookie_t dma_cookie;
	uint_t dma_flag;
	int status;

	dma_attr = emlxs_dma_attr_1sg;
	dev_attr = emlxs_data_acc_attr;

	if (buf_info->flags & FC_MBUF_SNGLSG) {
		buf_info->flags &= ~FC_MBUF_SNGLSG;
		dma_attr.dma_attr_sgllen = 1;
	}
	if (buf_info->flags & FC_MBUF_DMA32) {
		buf_info->flags &= ~FC_MBUF_DMA32;
		dma_attr.dma_attr_addr_hi = (uint64_t)0xffffffff;
	}
	buf_info->flags &= ~(FC_MBUF_UNLOCK | FC_MBUF_IOCTL);

	switch (buf_info->flags) {
	case 0:	/* allocate host memory */

		buf_info->virt = (uint32_t *)
		    kmem_zalloc((size_t)buf_info->size, KM_NOSLEEP);
		buf_info->phys = 0;
		buf_info->data_handle = 0;
		buf_info->dma_handle = 0;

		if (buf_info->virt == (uint32_t *)0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "size=%x align=%x flags=%x", buf_info->size,
			    buf_info->align, buf_info->flags);
		}
		break;

	case FC_MBUF_PHYSONLY:
	case FC_MBUF_DMA | FC_MBUF_PHYSONLY:	/* fill in physical address */

		if (buf_info->virt == 0)
			break;

		/*
		 * Allocate the DMA handle for this DMA object
		 */
		status = ddi_dma_alloc_handle((void *) hba->dip, &dma_attr,
		    DDI_DMA_DONTWAIT, NULL,
		    (ddi_dma_handle_t *)&buf_info->dma_handle);
		if (status != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_alloc_handle failed: "
			    "size=%x align=%x flags=%x",
			    buf_info->size, buf_info->align, buf_info->flags);

			buf_info->phys = 0;
			buf_info->dma_handle = 0;
			break;
		}
		switch (buf_info->align) {
		case DMA_READ_WRITE:
			dma_flag = (DDI_DMA_RDWR | DDI_DMA_CONSISTENT);
			break;
		case DMA_READ_ONLY:
			dma_flag = (DDI_DMA_READ | DDI_DMA_CONSISTENT);
			break;
		case DMA_WRITE_ONLY:
			dma_flag = (DDI_DMA_WRITE | DDI_DMA_CONSISTENT);
			break;
		}

		/* Map this page of memory */
		status = ddi_dma_addr_bind_handle(
		    (ddi_dma_handle_t)buf_info->dma_handle, NULL,
		    (caddr_t)buf_info->virt, (size_t)buf_info->size,
		    dma_flag, DDI_DMA_DONTWAIT, NULL, &dma_cookie,
		    &cookie_count);

		if (status != DDI_DMA_MAPPED || (cookie_count > 1)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_addr_bind_handle failed: "
			    "status=%x count=%x flags=%x",
			    status, cookie_count, buf_info->flags);

			(void) ddi_dma_free_handle((ddi_dma_handle_t *)
			    &buf_info->dma_handle);
			buf_info->phys = 0;
			buf_info->dma_handle = 0;
			break;
		}
		if (hba->bus_type == SBUS_FC) {

			int32_t burstsizes_limit = 0xff;
			int32_t ret_burst;

			ret_burst = ddi_dma_burstsizes(buf_info->dma_handle)
			    &burstsizes_limit;
			if (ddi_dma_set_sbus64(buf_info->dma_handle, ret_burst)
			    == DDI_FAILURE) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mem_alloc_failed_msg,
				    "ddi_dma_set_sbus64 failed.");
			}
		}
		/* Save Physical address */
		buf_info->phys = dma_cookie.dmac_laddress;

		/*
		 * Just to be sure, let's add this
		 */
		emlxs_mpdata_sync((ddi_dma_handle_t)buf_info->dma_handle,
		    (off_t)0, (size_t)buf_info->size, DDI_DMA_SYNC_FORDEV);

		break;

	case FC_MBUF_DMA:	/* allocate and map DMA mem */

		dma_attr.dma_attr_align = buf_info->align;

		/*
		 * Allocate the DMA handle for this DMA object
		 */
		status = ddi_dma_alloc_handle((void *)hba->dip, &dma_attr,
		    DDI_DMA_DONTWAIT, NULL,
		    (ddi_dma_handle_t *)&buf_info->dma_handle);
		if (status != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_alloc_handle failed: "
			    "size=%x align=%x flags=%x",
			    buf_info->size, buf_info->align, buf_info->flags);

			buf_info->virt = 0;
			buf_info->phys = 0;
			buf_info->data_handle = 0;
			buf_info->dma_handle = 0;
			break;
		}
		status = ddi_dma_mem_alloc(
		    (ddi_dma_handle_t)buf_info->dma_handle,
		    (size_t)buf_info->size, &dev_attr, DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, NULL, (caddr_t *)&buf_info->virt,
		    &dma_reallen, (ddi_acc_handle_t *)&buf_info->data_handle);

		if ((status != DDI_SUCCESS) || (buf_info->size > dma_reallen)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_mem_alloc failed: "
			    "size=%x align=%x flags=%x",
			    buf_info->size, buf_info->align, buf_info->flags);

			(void) ddi_dma_free_handle(
			    (ddi_dma_handle_t *)&buf_info->dma_handle);

			buf_info->virt = 0;
			buf_info->phys = 0;
			buf_info->data_handle = 0;
			buf_info->dma_handle = 0;
			break;
		}
		/* Map this page of memory */
		status = ddi_dma_addr_bind_handle(
		    (ddi_dma_handle_t)buf_info->dma_handle, NULL,
		    (caddr_t)buf_info->virt, (size_t)buf_info->size,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT,
		    NULL, &dma_cookie, &cookie_count);

		if (status != DDI_DMA_MAPPED || (cookie_count > 1)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_addr_bind_handle failed: "
			    "status=%x count=%d: size=%x align=%x flags=%x",
			    status, cookie_count, buf_info->size,
			    buf_info->align, buf_info->flags);

			(void) ddi_dma_mem_free((ddi_acc_handle_t *)
			    &buf_info->data_handle);
			(void) ddi_dma_free_handle((ddi_dma_handle_t *)
			    &buf_info->dma_handle);

			buf_info->virt = 0;
			buf_info->phys = 0;
			buf_info->dma_handle = 0;
			buf_info->data_handle = 0;
			break;
		}
		if (hba->bus_type == SBUS_FC) {
			int32_t burstsizes_limit = 0xff;
			int32_t ret_burst;

			ret_burst = ddi_dma_burstsizes(buf_info->dma_handle)
			    &burstsizes_limit;
			if (ddi_dma_set_sbus64(buf_info->dma_handle, ret_burst)
			    == DDI_FAILURE) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mem_alloc_failed_msg,
				    "ddi_dma_set_sbus64 failed.");
			}
		}
		/* Save Physical address */
		buf_info->phys = dma_cookie.dmac_laddress;

		/* Just to be sure, let's add this */
		emlxs_mpdata_sync((ddi_dma_handle_t)buf_info->dma_handle,
		    (off_t)0, (size_t)buf_info->size, DDI_DMA_SYNC_FORDEV);

		break;
	}	/* End of switch */

	return ((uint8_t *)buf_info->virt);


} /* emlxs_mem_alloc() */



/*
 * emlxs_mem_free:  OS specific routine for memory de-allocation / unmapping
 *
 * The buf_info->flags field describes the memory operation requested.
 *
 * FC_MBUF_PHYSONLY set  requests a supplied virtual address be unmapped
 * for DMA, but not freed. The mapped physical address to be
 * unmapped is in buf_info->phys
 *
 * FC_MBUF_PHYSONLY cleared requests memory be freed and unmapped for
 * DMA only if FC_MBUF_DMA is set. The mapped physical address
 * to be unmapped is in buf_info->phys The virtual address to be
 * freed is in buf_info->virt
 */
/*ARGSUSED*/
extern void
emlxs_mem_free(emlxs_hba_t *hba, MBUF_INFO *buf_info)
{
	/* emlxs_port_t *port = &PPORT; */
	buf_info->flags &= ~(FC_MBUF_UNLOCK | FC_MBUF_IOCTL);

	switch (buf_info->flags) {
	case 0:	/* free host memory */

		if (buf_info->virt) {
			kmem_free(buf_info->virt, (size_t)buf_info->size);
			buf_info->virt = NULL;
		}
		break;

	case FC_MBUF_PHYSONLY:
	case FC_MBUF_DMA | FC_MBUF_PHYSONLY:	/* nothing to do */

		if (buf_info->dma_handle) {
			(void) ddi_dma_unbind_handle(buf_info->dma_handle);
			(void) ddi_dma_free_handle((ddi_dma_handle_t *)
			    &buf_info->dma_handle);
			buf_info->dma_handle = NULL;
		}
		break;

	case FC_MBUF_DMA:	/* unmap free DMA-able memory */


		if (buf_info->dma_handle) {
			(void) ddi_dma_unbind_handle(buf_info->dma_handle);
			(void) ddi_dma_mem_free((ddi_acc_handle_t *)
			    &buf_info->data_handle);
			(void) ddi_dma_free_handle((ddi_dma_handle_t *)
			    &buf_info->dma_handle);
			buf_info->dma_handle = NULL;
			buf_info->data_handle = NULL;
		}
		break;
	}

} /* emlxs_mem_free() */


#define	BPL_CMD   0
#define	BPL_RESP  1
#define	BPL_DATA  2

static ULP_BDE64 *
emlxs_pkt_to_bpl(ULP_BDE64 *bpl, fc_packet_t *pkt, uint32_t bpl_type,
    uint8_t bdeFlags)
{
	ddi_dma_cookie_t *cp;
	uint_t i;
	int32_t size;
	uint_t cookie_cnt;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	switch (bpl_type) {
	case BPL_CMD:
		cp = pkt->pkt_cmd_cookie;
		cookie_cnt = pkt->pkt_cmd_cookie_cnt;
		size = (int32_t)pkt->pkt_cmdlen;
		break;

	case BPL_RESP:
		cp = pkt->pkt_resp_cookie;
		cookie_cnt = pkt->pkt_resp_cookie_cnt;
		size = (int32_t)pkt->pkt_rsplen;
		break;


	case BPL_DATA:
		cp = pkt->pkt_data_cookie;
		cookie_cnt = pkt->pkt_data_cookie_cnt;
		size = (int32_t)pkt->pkt_datalen;
		break;
	}

#else
	switch (bpl_type) {
	case BPL_CMD:
		cp = &pkt->pkt_cmd_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_cmdlen;
		break;

	case BPL_RESP:
		cp = &pkt->pkt_resp_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_rsplen;
		break;


	case BPL_DATA:
		cp = &pkt->pkt_data_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_datalen;
		break;
	}
#endif	/* >= EMLXS_MODREV3 */

	for (i = 0; i < cookie_cnt && size > 0; i++, cp++) {
		bpl->addrHigh = PCIMEM_LONG((uint32_t)
		    putPaddrHigh(cp->dmac_laddress));
		bpl->addrLow = PCIMEM_LONG((uint32_t)
		    putPaddrLow(cp->dmac_laddress));
		bpl->tus.f.bdeSize = MIN(size, cp->dmac_size);
		bpl->tus.f.bdeFlags = bdeFlags;
		bpl->tus.w = PCIMEM_LONG(bpl->tus.w);

		bpl++;
		size -= cp->dmac_size;
	}

	return (bpl);

} /* emlxs_pkt_to_bpl */



static uint32_t
emlxs_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	uint32_t rval;

#ifdef SLI3_SUPPORT
	emlxs_hba_t *hba = HBA;

	if (hba->sli_mode < 3) {
		rval = emlxs_sli2_bde_setup(port, sbp);
	} else {
#if (EMLXS_MODREV >= EMLXS_MODREV3)
		fc_packet_t *pkt = PRIV2PKT(sbp);

		if ((pkt->pkt_cmd_cookie_cnt > 1) ||
		    (pkt->pkt_resp_cookie_cnt > 1) ||
		    ((pkt->pkt_cmd_cookie_cnt + pkt->pkt_resp_cookie_cnt +
		    pkt->pkt_data_cookie_cnt) > SLI3_MAX_BDE)) {
			rval = emlxs_sli2_bde_setup(port, sbp);
		} else {
			rval = emlxs_sli3_bde_setup(port, sbp);
		}

#else
		rval = emlxs_sli3_bde_setup(port, sbp);
#endif	/* >= EMLXS_MODREV3 */

	}

#else	/* !SLI3_SUPPORT */
	rval = emlxs_sli2_bde_setup(port, sbp);
#endif	/* SLI3_SUPPORT */

	return (rval);

} /* emlxs_bde_setup() */


static uint32_t
emlxs_sli2_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	MATCHMAP *bmp;
	ULP_BDE64 *bpl;
	uint64_t bp;
	uint8_t bdeFlag;
	IOCB *iocb;
	RING *rp;
	uint32_t cmd_cookie_cnt;
	uint32_t resp_cookie_cnt;
	uint32_t data_cookie_cnt;
	uint32_t cookie_cnt;

	rp = sbp->ring;
	iocb = (IOCB *) & sbp->iocbq;
	pkt = PRIV2PKT(sbp);

#ifdef EMLXS_SPARC
	if (rp->ringno == FC_FCP_RING) {
		/* Use FCP MEM_BPL table to get BPL buffer */
		bmp = &hba->fcp_bpl_table[sbp->iotag];
	} else {
		/* Use MEM_BPL pool to get BPL buffer */
		bmp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BPL);
	}

#else
	/* Use MEM_BPL pool to get BPL buffer */
	bmp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BPL);

#endif	/* EMLXS_SPARC */

	if (!bmp) {
		return (1);
	}
	sbp->bmp = bmp;
	bpl = (ULP_BDE64 *) bmp->virt;
	bp = bmp->phys;
	cookie_cnt = 0;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	cmd_cookie_cnt = pkt->pkt_cmd_cookie_cnt;
	resp_cookie_cnt = pkt->pkt_resp_cookie_cnt;
	data_cookie_cnt = pkt->pkt_data_cookie_cnt;
#else
	cmd_cookie_cnt = 1;
	resp_cookie_cnt = 1;
	data_cookie_cnt = 1;
#endif	/* >= EMLXS_MODREV3 */

	switch (rp->ringno) {
	case FC_FCP_RING:

		/* CMD payload */
		bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_CMD, 0);
		cookie_cnt = cmd_cookie_cnt;

		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			/* RSP payload */
			bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_RESP,
			    BUFF_USE_RCV);
			cookie_cnt += resp_cookie_cnt;

			/* DATA payload */
			if (pkt->pkt_datalen != 0) {
				bdeFlag = (pkt->pkt_tran_type ==
				    FC_PKT_FCP_READ) ? BUFF_USE_RCV : 0;
				bpl = emlxs_pkt_to_bpl(bpl, pkt,
				    BPL_DATA, bdeFlag);
				cookie_cnt += data_cookie_cnt;
			}
		}
		break;

	case FC_IP_RING:

		/* CMD payload */
		bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_CMD, 0);
		cookie_cnt = cmd_cookie_cnt;

		break;

	case FC_ELS_RING:

		/* CMD payload */
		bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_CMD, 0);
		cookie_cnt = cmd_cookie_cnt;

		/* RSP payload */
		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			bpl = emlxs_pkt_to_bpl(bpl, pkt,
			    BPL_RESP, BUFF_USE_RCV);
			cookie_cnt += resp_cookie_cnt;
		}
		break;


	case FC_CT_RING:

		/* CMD payload */
		bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_CMD, 0);
		cookie_cnt = cmd_cookie_cnt;

		if ((pkt->pkt_tran_type != FC_PKT_OUTBOUND) ||
		    (pkt->pkt_cmd_fhdr.type == EMLXS_MENLO_TYPE)) {
			/* RSP payload */
			bpl = emlxs_pkt_to_bpl(bpl, pkt,
			    BPL_RESP, BUFF_USE_RCV);
			cookie_cnt += resp_cookie_cnt;
		}
		break;

	}

	iocb->un.genreq64.bdl.bdeFlags = BUFF_TYPE_BDL;
	iocb->un.genreq64.bdl.addrHigh = (uint32_t)putPaddrHigh(bp);
	iocb->un.genreq64.bdl.addrLow = (uint32_t)putPaddrLow(bp);
	iocb->un.genreq64.bdl.bdeSize = cookie_cnt * sizeof (ULP_BDE64);

	iocb->ulpBdeCount = 1;
	iocb->ulpLe = 1;

	return (0);

} /* emlxs_sli2_bde_setup */


#ifdef SLI3_SUPPORT
/*ARGSUSED*/
static uint32_t
emlxs_sli3_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	ddi_dma_cookie_t *cp_cmd;
	ddi_dma_cookie_t *cp_resp;
	ddi_dma_cookie_t *cp_data;
	fc_packet_t *pkt;
	ULP_BDE64 *bde;
	/* uint16_t iotag; */
	/* uint32_t did; */
	int data_cookie_cnt;
	int i;
	IOCB *iocb;
	RING *rp;

	rp = sbp->ring;
	iocb = (IOCB *) & sbp->iocbq;
	pkt = PRIV2PKT(sbp);
	/* did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id); */

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	cp_cmd = pkt->pkt_cmd_cookie;
	cp_resp = pkt->pkt_resp_cookie;
	cp_data = pkt->pkt_data_cookie;
	data_cookie_cnt = pkt->pkt_data_cookie_cnt;
#else
	cp_cmd = &pkt->pkt_cmd_cookie;
	cp_resp = &pkt->pkt_resp_cookie;
	cp_data = &pkt->pkt_data_cookie;
	data_cookie_cnt = 1;
#endif	/* >= EMLXS_MODREV3 */

	iocb->unsli3.ext_iocb.ebde_count = 0;

	switch (rp->ringno) {
	case FC_FCP_RING:

		/* CMD payload */
		iocb->un.fcpi64.bdl.addrHigh =
		    putPaddrHigh(cp_cmd->dmac_laddress);
		iocb->un.fcpi64.bdl.addrLow =
		    putPaddrLow(cp_cmd->dmac_laddress);
		iocb->un.fcpi64.bdl.bdeSize = pkt->pkt_cmdlen;
		iocb->un.fcpi64.bdl.bdeFlags = 0;

		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			/* RSP payload */
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    putPaddrHigh(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    putPaddrLow(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeSize =
			    pkt->pkt_rsplen;
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeFlags = 0;
			iocb->unsli3.ext_iocb.ebde_count = 1;

			/* DATA payload */
			if (pkt->pkt_datalen != 0) {
				bde = (ULP_BDE64 *)&iocb->unsli3.ext_iocb.ebde2;
				for (i = 0; i < data_cookie_cnt; i++) {
					bde->addrHigh = putPaddrHigh(
					    cp_data->dmac_laddress);
					bde->addrLow = putPaddrLow(
					    cp_data->dmac_laddress);
					bde->tus.f.bdeSize = cp_data->dmac_size;
					bde->tus.f.bdeFlags = 0;
					cp_data++;
					bde++;
				}
				iocb->unsli3.ext_iocb.ebde_count +=
				    data_cookie_cnt;
			}
		}
		break;

	case FC_IP_RING:

		/* CMD payload */
		iocb->un.xseq64.bdl.addrHigh =
		    putPaddrHigh(cp_cmd->dmac_laddress);
		iocb->un.xseq64.bdl.addrLow =
		    putPaddrLow(cp_cmd->dmac_laddress);
		iocb->un.xseq64.bdl.bdeSize = pkt->pkt_cmdlen;
		iocb->un.xseq64.bdl.bdeFlags = 0;

		break;

	case FC_ELS_RING:

		/* CMD payload */
		iocb->un.elsreq64.bdl.addrHigh =
		    putPaddrHigh(cp_cmd->dmac_laddress);
		iocb->un.elsreq64.bdl.addrLow =
		    putPaddrLow(cp_cmd->dmac_laddress);
		iocb->un.elsreq64.bdl.bdeSize = pkt->pkt_cmdlen;
		iocb->un.elsreq64.bdl.bdeFlags = 0;

		/* RSP payload */
		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    putPaddrHigh(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    putPaddrLow(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeSize =
			    pkt->pkt_rsplen;
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeFlags =
			    BUFF_USE_RCV;
			iocb->unsli3.ext_iocb.ebde_count = 1;
		}
		break;

	case FC_CT_RING:

		/* CMD payload */
		iocb->un.genreq64.bdl.addrHigh =
		    putPaddrHigh(cp_cmd->dmac_laddress);
		iocb->un.genreq64.bdl.addrLow =
		    putPaddrLow(cp_cmd->dmac_laddress);
		iocb->un.genreq64.bdl.bdeSize = pkt->pkt_cmdlen;
		iocb->un.genreq64.bdl.bdeFlags = 0;

		if ((pkt->pkt_tran_type != FC_PKT_OUTBOUND) ||
		    (pkt->pkt_cmd_fhdr.type == EMLXS_MENLO_TYPE)) {
			/* RSP payload */
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    putPaddrHigh(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    putPaddrLow(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeSize =
			    pkt->pkt_rsplen;
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeFlags =
			    BUFF_USE_RCV;
			iocb->unsli3.ext_iocb.ebde_count = 1;
		}
		break;
	}

	iocb->ulpBdeCount = 0;
	iocb->ulpLe = 0;

	return (0);

} /* emlxs_sli3_bde_setup */
#endif	/* SLI3_SUPPORT */

static int32_t
emlxs_send_fcp_cmd(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	NODELIST *ndlp;
	/* int i; */
	char *cmd;
	uint16_t lun;
	uint16_t iotag;
	FCP_CMND *fcp_cmd;
	uint32_t did;
	/* fcp_rsp_t *rsp; */

	pkt = PRIV2PKT(sbp);
	fcp_cmd = (FCP_CMND *) pkt->pkt_cmd;
	rp = &hba->ring[FC_FCP_RING];
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Find target node object */
	ndlp = emlxs_node_find_did(port, did);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=%x", did);

		return (FC_BADPACKET);
	}
	/* If gate is closed */
	if (ndlp->nlp_flag[FC_FCP_RING] & NLP_CLOSED) {
		return (FC_TRAN_BUSY);
	}
	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag: did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_fcp_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	if (fcp_cmd->fcpCntl1 == FCP_QTYPE_UNTAGGED) {
		fcp_cmd->fcpCntl1 = FCP_QTYPE_SIMPLE;
	}
	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) ndlp;
	iocbq->ring = (void *) rp;

	/* Initalize iocb */
	iocb->ulpContext = ndlp->nlp_Rpi;
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		/* iocb->ulpClass = CLASS3; */
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	/*
	 * if device is FCP-2 device, set the following bit that says to run
	 * the FC-TAPE protocol.
	 */
	if (ndlp->nlp_fcp_info & NLP_FCP_2_DEVICE) {
		iocb->ulpFCP2Rcvy = 1;
	}
	if (pkt->pkt_datalen == 0) {
		iocb->ulpCommand = CMD_FCP_ICMND64_CR;
	} else if (pkt->pkt_tran_type == FC_PKT_FCP_READ) {
		iocb->ulpCommand = CMD_FCP_IREAD64_CR;
		iocb->ulpPU = PARM_READ_CHECK;
		iocb->un.fcpi64.fcpi_parm = pkt->pkt_datalen;
	} else {
		iocb->ulpCommand = CMD_FCP_IWRITE64_CR;
	}

	/* Snoop for target or lun resets */
	cmd = (char *)pkt->pkt_cmd;
	lun = *((uint16_t *)cmd);
	lun = SWAP_DATA16(lun);

	/* Check for target reset */
	if (cmd[10] & 0x20) {
		mutex_enter(&sbp->mtx);
		sbp->pkt_flags |= PACKET_FCP_TGT_RESET;
		sbp->pkt_flags |= PACKET_POLLED;
		mutex_exit(&sbp->mtx);

		iocbq->flag |= IOCB_PRIORITY;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Target Reset: did=%x", did);

		/* Close the node for any further normal IO */
		emlxs_node_close(port, ndlp, FC_FCP_RING, pkt->pkt_timeout);

		/* Flush the IO's on the tx queues */
		(void) emlxs_tx_node_flush(port, ndlp, rp, 0, sbp);
	}
	/* Check for lun reset */
	else if (cmd[10] & 0x10) {
		mutex_enter(&sbp->mtx);
		sbp->pkt_flags |= PACKET_FCP_LUN_RESET;
		sbp->pkt_flags |= PACKET_POLLED;
		mutex_exit(&sbp->mtx);

		iocbq->flag |= IOCB_PRIORITY;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "LUN Reset: did=%x LUN=%02x02x", did, cmd[0], cmd[1]);

		/* Flush the IO's on the tx queues for this lun */
		(void) emlxs_tx_lun_flush(port, ndlp, lun, sbp);
	}
	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *) ndlp;
	sbp->lun = lun;
	sbp->class = iocb->ulpClass;
	sbp->did = ndlp->nlp_DID;
	mutex_exit(&sbp->mtx);

	if (pkt->pkt_cmdlen) {
		emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}
	if (pkt->pkt_datalen && pkt->pkt_tran_type == FC_PKT_FCP_WRITE) {
		emlxs_mpdata_sync(pkt->pkt_data_dma, 0,
		    pkt->pkt_datalen, DDI_DMA_SYNC_FORDEV);
	}
	HBASTATS.FcpIssued++;

	emlxs_issue_iocb_cmd(hba, &hba->ring[FC_FCP_RING], iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_fcp_cmd() */


#ifdef SFCT_SUPPORT
static int32_t
emlxs_send_fcp_status(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;
	/* emlxs_buf_t *cmd_sbp; */
	ddi_dma_cookie_t *cp_cmd;

	pkt = PRIV2PKT(sbp);

	did = sbp->did;
	ndlp = sbp->node;

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Make sure node is still active */
	if (!ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "*Node not found. did=%x", did);

		return (FC_BADPACKET);
	}
	/* If gate is closed */
	if (ndlp->nlp_flag[FC_FCP_RING] & NLP_CLOSED) {
		return (FC_TRAN_BUSY);
	}
	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(sbp->ring, sbp);

	if (!iotag) {
		/* No more command slots available, retry later */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "*Adapter Busy. Unable to allocate iotag: did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	cp_cmd = pkt->pkt_cmd_cookie;
#else
	cp_cmd = &pkt->pkt_cmd_cookie;
#endif	/* >= EMLXS_MODREV3 */

	iocb->un.fcpt64.bdl.addrHigh = putPaddrHigh(cp_cmd->dmac_laddress);
	iocb->un.fcpt64.bdl.addrLow = putPaddrLow(cp_cmd->dmac_laddress);
	iocb->un.fcpt64.bdl.bdeSize = pkt->pkt_cmdlen;
	iocb->un.fcpt64.bdl.bdeFlags = 0;

	if (hba->sli_mode < 3) {
		iocb->ulpBdeCount = 1;
		iocb->ulpLe = 1;
	} else {	/* SLI3 */
		iocb->ulpBdeCount = 0;
		iocb->ulpLe = 0;
		iocb->unsli3.ext_iocb.ebde_count = 0;
	}

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) ndlp;
	iocbq->ring = (void *) sbp->ring;

	/* Initalize iocb */
	iocb->ulpContext = (uint16_t)pkt->pkt_cmd_fhdr.rx_id;
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;
	iocb->ulpClass = sbp->class;
	iocb->ulpCommand = CMD_FCP_TRSP64_CX;

	/* Set the pkt timer */
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);

	if (pkt->pkt_cmdlen) {
		emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0,
		    pkt->pkt_cmdlen, DDI_DMA_SYNC_FORDEV);
	}
	HBASTATS.FcpIssued++;

	emlxs_issue_iocb_cmd(hba, sbp->ring, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_fcp_status() */
#endif	/* SFCT_SUPPORT */


static int32_t
emlxs_send_sequence(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	/* uint32_t i; */
	NODELIST *ndlp;
	/* ddi_dma_cookie_t *cp; */
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	rp = &hba->ring[FC_CT_RING];
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Currently this routine is only used for loopback sequences */

	ndlp = emlxs_node_find_did(port, did);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=0x%x", did);

		return (FC_BADPACKET);
	}
	/* Check if gate is temporarily closed */
	if (ndlp->nlp_flag[FC_CT_RING] & NLP_CLOSED) {
		return (FC_TRAN_BUSY);
	}
	/* Check if an exchange has been created */
	if ((ndlp->nlp_Xri == 0)) {
		/* No exchange.  Try creating one */
		(void) emlxs_create_xri(port, rp, ndlp);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Exchange not found. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag: did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) ndlp;
	iocbq->ring = (void *) rp;

	/* Initalize iocb */

	/* Setup fibre channel header information */
	iocb->un.xseq64.w5.hcsw.Fctl = LA;

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_LAST_SEQ) {
		iocb->un.xseq64.w5.hcsw.Fctl |= LSEQ;
	}
	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_SEQ_INITIATIVE) {
		iocb->un.xseq64.w5.hcsw.Fctl |= SI;
	}
	iocb->un.xseq64.w5.hcsw.Dfctl = pkt->pkt_cmd_fhdr.df_ctl;
	iocb->un.xseq64.w5.hcsw.Rctl = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.xseq64.w5.hcsw.Type = pkt->pkt_cmd_fhdr.type;

	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;
	iocb->ulpClass = CLASS3;
	iocb->ulpCommand = CMD_XMIT_SEQUENCE64_CX;
	iocb->ulpContext = ndlp->nlp_Xri;

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *) ndlp;
	sbp->lun = 0;
	sbp->class = iocb->ulpClass;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	if (pkt->pkt_cmdlen) {
		emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0,
		    pkt->pkt_cmdlen, DDI_DMA_SYNC_FORDEV);
	}
	emlxs_issue_iocb_cmd(hba, &hba->ring[FC_CT_RING], iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_sequence() */


static int32_t
emlxs_send_ip(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	uint32_t i;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	rp = &hba->ring[FC_IP_RING];
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Check if node exists */
	/* Broadcast did is always a success */
	ndlp = emlxs_node_find_did(port, did);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=0x%x", did);

		return (FC_BADPACKET);
	}
	/* Check if gate is temporarily closed */
	if (ndlp->nlp_flag[FC_IP_RING] & NLP_CLOSED) {
		return (FC_TRAN_BUSY);
	}
	/* Check if an exchange has been created */
	if ((ndlp->nlp_Xri == 0) && (did != Bcast_DID)) {
		/* No exchange.  Try creating one */
		(void) emlxs_create_xri(port, rp, ndlp);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Exchange not found. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag: did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	/*
	 * ULP PATCH: pkt_cmdlen was found to be set to zero on BROADCAST
	 * commands
	 */
	if (pkt->pkt_cmdlen == 0) {
		/* Set the pkt_cmdlen to the cookie size */
#if (EMLXS_MODREV >= EMLXS_MODREV3)
		for (i = 0; i < pkt->pkt_cmd_cookie_cnt; i++) {
			pkt->pkt_cmdlen += pkt->pkt_cmd_cookie[i].dmac_size;
		}
#else
		pkt->pkt_cmdlen = pkt->pkt_cmd_cookie.dmac_size;
#endif	/* >= EMLXS_MODREV3 */

	}
	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) ndlp;
	iocbq->ring = (void *) rp;

	/* Initalize iocb */
	iocb->un.xseq64.w5.hcsw.Fctl = 0;

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_FIRST_SEQ) {
		iocb->un.xseq64.w5.hcsw.Fctl |= FSEQ;
	}
	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_SEQ_INITIATIVE) {
		iocb->un.xseq64.w5.hcsw.Fctl |= SI;
	}
	/* network headers */
	iocb->un.xseq64.w5.hcsw.Dfctl = pkt->pkt_cmd_fhdr.df_ctl;
	iocb->un.xseq64.w5.hcsw.Rctl = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.xseq64.w5.hcsw.Type = pkt->pkt_cmd_fhdr.type;

	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;

	if (pkt->pkt_tran_type == FC_PKT_BROADCAST) {
		HBASTATS.IpBcastIssued++;

		iocb->ulpCommand = CMD_XMIT_BCAST64_CN;
		iocb->ulpContext = 0;

#ifdef SLI3_SUPPORT
		if (hba->sli_mode >= 3) {
			if (hba->topology != TOPOLOGY_LOOP) {
				iocb->ulpCT = 0x1;
			}
			iocb->ulpContext = port->vpi;
		}
#endif	/* SLI3_SUPPORT */

	} else {
		HBASTATS.IpSeqIssued++;

		iocb->ulpCommand = CMD_XMIT_SEQUENCE64_CX;
		iocb->ulpContext = ndlp->nlp_Xri;
	}

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *) ndlp;
	sbp->lun = 0;
	sbp->class = iocb->ulpClass;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	if (pkt->pkt_cmdlen) {
		emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0,
		    pkt->pkt_cmdlen, DDI_DMA_SYNC_FORDEV);
	}
	emlxs_issue_iocb_cmd(hba, &hba->ring[FC_IP_RING], iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_ip() */


static int32_t
emlxs_send_els(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *vport;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	uint32_t cmd;
	int i;
	ELS_PKT *els_pkt;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;
	char fcsp_msg[32];

	fcsp_msg[0] = 0;
	pkt = PRIV2PKT(sbp);
	els_pkt = (ELS_PKT *) pkt->pkt_cmd;
	rp = &hba->ring[FC_ELS_RING];
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag: did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	cmd = *((uint32_t *)pkt->pkt_cmd);
	cmd &= ELS_CMD_MASK;

	/* Point of no return, except for ADISC & PLOGI */

	/* Check node */
	switch (cmd) {
	case ELS_CMD_FLOGI:
		if (port->vpi > 0) {
			cmd = ELS_CMD_FDISC;
			*((uint32_t *)pkt->pkt_cmd) = cmd;
		}
		ndlp = NULL;

		if (hba->flag & FC_NPIV_DELAY_REQUIRED) {
			sbp->pkt_flags |= PACKET_DELAY_REQUIRED;
		}
		/* We will process these cmds at the bottom of this routine */
		break;

	case ELS_CMD_PLOGI:
		/* Make sure we don't log into ourself */
		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);

			if (!(vport->flag & EMLXS_PORT_BOUND)) {
				continue;
			}
			if (did == vport->did) {
				/* Unregister the packet */
				(void) emlxs_unregister_pkt(rp, iotag, 0);

				pkt->pkt_state = FC_PKT_NPORT_RJT;

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
				emlxs_unswap_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

				return (FC_FAILURE);
			}
		}

		ndlp = NULL;

		/*
		 * Check if this is the first PLOGI after a PT_TO_PT
		 * connection
		 */
		if ((hba->flag & FC_PT_TO_PT) && (port->did == 0)) {
			MAILBOXQ *mbox;

			/* ULP bug fix */
			if (pkt->pkt_cmd_fhdr.s_id == 0) {
				pkt->pkt_cmd_fhdr.s_id =
				    pkt->pkt_cmd_fhdr.d_id - FP_DEFAULT_DID +
				    FP_DEFAULT_SID;
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_send_msg,
				    "PLOGI: P2P Fix. sid=0-->%x did=%x",
				    pkt->pkt_cmd_fhdr.s_id,
				    pkt->pkt_cmd_fhdr.d_id);
			}
			mutex_enter(&EMLXS_PORT_LOCK);
			port->did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.s_id);
			mutex_exit(&EMLXS_PORT_LOCK);

			/* Update our service parms */
			if ((mbox = (MAILBOXQ *)
			    emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
				emlxs_mb_config_link(hba, (MAILBOX *) mbox);

				if (emlxs_mb_issue_cmd(hba, (MAILBOX *) mbox,
				    MBX_NOWAIT, 0) != MBX_BUSY) {
					(void) emlxs_mem_put(hba, MEM_MBOX,
					    (uint8_t *)mbox);
				}
			}
		}
		/* We will process these cmds at the bottom of this routine */
		break;

	default:
		ndlp = emlxs_node_find_did(port, did);

		/*
		 * If an ADISC is being sent and we have no node, then we
		 * must fail the ADISC now
		 */
		if (!ndlp && (cmd == ELS_CMD_ADISC)) {
			/* Unregister the packet */
			(void) emlxs_unregister_pkt(rp, iotag, 0);

			/* Build the LS_RJT response */
			els_pkt = (ELS_PKT *) pkt->pkt_resp;
			els_pkt->elsCode = 0x01;
			els_pkt->un.lsRjt.un.b.lsRjtRsvd0 = 0;
			els_pkt->un.lsRjt.un.b.lsRjtRsnCode = LSRJT_LOGICAL_ERR;
			els_pkt->un.lsRjt.un.b.lsRjtRsnCodeExp =
			    LSEXP_NOTHING_MORE;
			els_pkt->un.lsRjt.un.b.vendorUnique = 0x03;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "ADISC Rejected. Node not found. did=0x%x", did);

			/* Return this as rejected by the target */
			emlxs_pkt_complete(sbp, IOSTAT_LS_RJT, 0, 1);

			return (FC_SUCCESS);
		}
	}

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) ndlp;
	iocbq->ring = (void *) rp;

	/* Initalize iocb */

	/*
	 * DID == Bcast_DID is special case to indicate that RPI is being
	 * passed in seq_id field
	 */
	/* This is used by emlxs_send_logo() for target mode */
	iocb->un.elsreq64.remoteID = (did == Bcast_DID) ? 0 : did;
	iocb->ulpContext = (did == Bcast_DID) ? pkt->pkt_cmd_fhdr.seq_id : 0;

	iocb->ulpCommand = CMD_ELS_REQUEST64_CR;
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

#ifdef SLI3_SUPPORT
	if (hba->sli_mode >= 3) {
		if (hba->topology != TOPOLOGY_LOOP) {
			if ((cmd == ELS_CMD_FLOGI) || (cmd == ELS_CMD_FDISC)) {
				iocb->ulpCT = 0x2;
			} else {
				iocb->ulpCT = 0x1;
			}
		}
		iocb->ulpContext = port->vpi;
	}
#endif	/* SLI3_SUPPORT */

	/* Check cmd */
	switch (cmd) {
	case ELS_CMD_PRLI:
		{
			/*
			 * if our firmware version is 3.20 or later, set the
			 * following bits for FC-TAPE support.
			 */

			if (port->ini_mode && hba->vpd.feaLevelHigh >= 0x02) {
				els_pkt->un.prli.ConfmComplAllowed = 1;
				els_pkt->un.prli.Retry = 1;
				els_pkt->un.prli.TaskRetryIdReq = 1;
			} else {
				els_pkt->un.prli.ConfmComplAllowed = 0;
				els_pkt->un.prli.Retry = 0;
				els_pkt->un.prli.TaskRetryIdReq = 0;
			}

			break;
		}

		/* This is a patch for the ULP stack. */

		/*
		 * ULP only reads our service paramters once during
		 * bind_port, but the service parameters change due to
		 * topology.
		 */
	case ELS_CMD_FLOGI:
	case ELS_CMD_FDISC:
	case ELS_CMD_PLOGI:
	case ELS_CMD_PDISC:
		{
			/* Copy latest service parameters to payload */
			bcopy((void *) &port->sparam,
			    (void *) &els_pkt->un.logi, sizeof (SERV_PARM));

#ifdef NPIV_SUPPORT
			if ((hba->flag & FC_NPIV_ENABLED) &&
			    (hba->flag & FC_NPIV_SUPPORTED) &&
			    (cmd == ELS_CMD_PLOGI)) {
				SERV_PARM *sp;
				emlxs_vvl_fmt_t *vvl;

				sp = (SERV_PARM *) & els_pkt->un.logi;
				sp->valid_vendor_version = 1;
				vvl = (emlxs_vvl_fmt_t *)&sp->vendorVersion[0];
				vvl->un0.w0.oui = 0x0000C9;
				vvl->un0.word0 = SWAP_DATA32(vvl->un0.word0);
				vvl->un1.w1.vport = (port->vpi > 0) ? 1 : 0;
				vvl->un1.word1 = SWAP_DATA32(vvl->un1.word1);
			}
#endif	/* NPIV_SUPPORT */

#ifdef DHCHAP_SUPPORT
			emlxs_dhc_init_sp(port, did,
			    (SERV_PARM *)&els_pkt->un.logi, fcsp_msg);
#endif	/* DHCHAP_SUPPORT */

			break;
		}

	}

	/* Initialize the sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *) ndlp;
	sbp->lun = 0;
	sbp->class = iocb->ulpClass;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_send_msg, "%s: sid=%x did=%x %s",
	    emlxs_elscmd_xlate(cmd), port->did, did, fcsp_msg);

	if (pkt->pkt_cmdlen) {
		emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}
	/* Check node */
	switch (cmd) {
	case ELS_CMD_FLOGI:
		if (port->ini_mode) {
			/* Make sure fabric node is destroyed */
			/* It should already have been destroyed at link down */
			/*
			 * Unregister the fabric did and attempt a deferred
			 * iocb send
			 */
			if (emlxs_mb_unreg_did(port, Fabric_DID, NULL,
			    NULL, iocbq) == 0) {
				/*
				 * Deferring iocb tx until completion of
				 * unreg
				 */
				return (FC_SUCCESS);
			}
		}
		break;

	case ELS_CMD_PLOGI:

		ndlp = emlxs_node_find_did(port, did);

		if (ndlp && ndlp->nlp_active) {
			/* Close the node for any further normal IO */
			emlxs_node_close(port, ndlp, FC_FCP_RING,
			    pkt->pkt_timeout + 10);
			emlxs_node_close(port, ndlp, FC_IP_RING,
			    pkt->pkt_timeout + 10);

			/* Flush tx queues */
			(void) emlxs_tx_node_flush(port, ndlp, 0, 0, 0);

			/* Flush chip queues */
			(void) emlxs_chipq_node_flush(port, 0, ndlp, 0);
		}
		break;

	case ELS_CMD_PRLI:

		ndlp = emlxs_node_find_did(port, did);

		if (ndlp && ndlp->nlp_active) {
			/* Close the node for any further FCP IO */
			emlxs_node_close(port, ndlp, FC_FCP_RING,
			    pkt->pkt_timeout + 10);

			/* Flush tx queues */
			(void) emlxs_tx_node_flush(port, ndlp,
			    &hba->ring[FC_FCP_RING], 0, 0);

			/* Flush chip queues */
			(void) emlxs_chipq_node_flush(port,
			    &hba->ring[FC_FCP_RING], ndlp, 0);
		}
		break;

	}

	HBASTATS.ElsCmdIssued++;

	emlxs_issue_iocb_cmd(hba, &hba->ring[FC_ELS_RING], iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_els() */




static int32_t
emlxs_send_els_rsp(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	NODELIST *ndlp;
	int i;
	uint32_t cmd;
	uint32_t ucmd;
	ELS_PKT *els_pkt;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	uint16_t iotag;
	uint32_t did;
	char fcsp_msg[32];
	uint8_t *ub_buffer;


	fcsp_msg[0] = 0;
	pkt = PRIV2PKT(sbp);
	els_pkt = (ELS_PKT *) pkt->pkt_cmd;
	rp = &hba->ring[FC_ELS_RING];
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Acquire the unsolicited command this pkt is replying to */
	if (pkt->pkt_cmd_fhdr.ox_id < EMLXS_UB_TOKEN_OFFSET) {
		/* This is for auto replies when no ub's are used */
		ucmd = pkt->pkt_cmd_fhdr.ox_id << ELS_CMD_SHIFT;
		ubp = NULL;
		ub_priv = NULL;
		ub_buffer = NULL;

#ifdef SFCT_SUPPORT
		if (sbp->fct_cmd) {
			fct_els_t *els =
			    (fct_els_t *)sbp->fct_cmd->cmd_specific;
			ub_buffer = (uint8_t *)els->els_req_payload;
		}
#endif	/* SFCT_SUPPORT */

	} else {
		/* Find the ub buffer that goes with this reply */
		if (!(ubp = emlxs_ub_find(port, pkt->pkt_cmd_fhdr.ox_id))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_error_msg,
			    "ELS reply: Invalid oxid=%x",
			    pkt->pkt_cmd_fhdr.ox_id);
			return (FC_BADPACKET);
		}
		ub_buffer = (uint8_t *)ubp->ub_buffer;
		ub_priv = ubp->ub_fca_private;
		ucmd = ub_priv->cmd;

		ub_priv->flags |= EMLXS_UB_REPLY;

		/* Reset oxid to ELS command */
		/*
		 * We do this because the ub is only valid until we return
		 * from this thread
		 */
		pkt->pkt_cmd_fhdr.ox_id = (ucmd >> ELS_CMD_SHIFT) & 0xff;
	}

	/* Save the result */
	sbp->ucmd = ucmd;

	/* Check for interceptions */
	switch (ucmd) {

#ifdef ULP_PATCH2
	case ELS_CMD_LOGO:
		{
			/* Check if this was generated by ULP and not us */
			if (!(sbp->pkt_flags & PACKET_ALLOCATED)) {

				/*
				 * Since we replied to this already, we won't
				 * need to send this now
				 */
				emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

				return (FC_SUCCESS);
			}
			break;
		}
#endif

#ifdef ULP_PATCH3
	case ELS_CMD_PRLI:
		{
			/* Check if this was generated by ULP and not us */
			if (!(sbp->pkt_flags & PACKET_ALLOCATED)) {

				/*
				 * Since we replied to this already, we won't
				 * need to send this now
				 */
				emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

				return (FC_SUCCESS);
			}
			break;
		}
#endif


#ifdef ULP_PATCH4
	case ELS_CMD_PRLO:
		{
			/* Check if this was generated by ULP and not us */
			if (!(sbp->pkt_flags & PACKET_ALLOCATED)) {
				/*
				 * Since we replied to this already, we won't
				 * need to send this now
				 */
				emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

				return (FC_SUCCESS);
			}
			break;
		}
#endif

#ifdef ULP_PATCH6
	case ELS_CMD_RSCN:
		{
			/* Check if this RSCN was generated by us */
			if (ub_priv && (ub_priv->flags & EMLXS_UB_INTERCEPT)) {
				cmd = *((uint32_t *)pkt->pkt_cmd);
				cmd = SWAP_DATA32(cmd);
				cmd &= ELS_CMD_MASK;

				/*
				 * If ULP is accepting this, then close
				 * affected node
				 */
				if (port->ini_mode &&
				    ub_buffer && cmd == ELS_CMD_ACC) {
					fc_rscn_t *rscn;
					uint32_t count;
					uint32_t *lp;

					/*
					 * Only the Leadville code path will
					 * come thru here. The RSCN data is
					 * NOT swapped properly for the
					 * Comstar code path.
					 */
					lp = (uint32_t *)ub_buffer;
					rscn = (fc_rscn_t *)lp++;
					count =
					    ((rscn->rscn_payload_len - 4) / 4);

					/* Close affected ports */
					for (i = 0; i < count; i++, lp++) {
						(void) emlxs_port_offline(port,
						    *lp);
					}
				}
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_reply_msg,
				    "RSCN %s: did=%x oxid=%x rxid=%x. "
				    "Intercepted.", emlxs_elscmd_xlate(cmd),
				    did, pkt->pkt_cmd_fhdr.ox_id,
				    pkt->pkt_cmd_fhdr.rx_id);

				/*
				 * Since we generated this RSCN, we won't
				 * need to send this reply
				 */
				emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

				return (FC_SUCCESS);
			}
			break;
		}
#endif

	case ELS_CMD_PLOGI:
		{
			/* Check if this PLOGI was generated by us */
			if (ub_priv && (ub_priv->flags & EMLXS_UB_INTERCEPT)) {
				cmd = *((uint32_t *)pkt->pkt_cmd);
				cmd = SWAP_DATA32(cmd);
				cmd &= ELS_CMD_MASK;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_reply_msg,
				    "PLOGI %s: did=%x oxid=%x rxid=%x. "
				    "Intercepted.", emlxs_elscmd_xlate(cmd),
				    did, pkt->pkt_cmd_fhdr.ox_id,
				    pkt->pkt_cmd_fhdr.rx_id);

				/*
				 * Since we generated this PLOGI, we won't
				 * need to send this reply
				 */
				emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

				return (FC_SUCCESS);
			}
			break;
		}

	}

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_pkt(sbp);
#endif	/* EMLXS_MODREV2X */


	cmd = *((uint32_t *)pkt->pkt_cmd);
	cmd &= ELS_CMD_MASK;

	/* Check if modifications are needed */
	switch (ucmd) {
	case (ELS_CMD_PRLI):

		if (cmd == ELS_CMD_ACC) {
			/* This is a patch for the ULP stack. */
			/* ULP does not keep track of FCP2 support */

			if (port->ini_mode && hba->vpd.feaLevelHigh >= 0x02) {
				els_pkt->un.prli.ConfmComplAllowed = 1;
				els_pkt->un.prli.Retry = 1;
				els_pkt->un.prli.TaskRetryIdReq = 1;
			} else {
				els_pkt->un.prli.ConfmComplAllowed = 0;
				els_pkt->un.prli.Retry = 0;
				els_pkt->un.prli.TaskRetryIdReq = 0;
			}
		}
		break;

	case ELS_CMD_FLOGI:
	case ELS_CMD_PLOGI:
	case ELS_CMD_FDISC:
	case ELS_CMD_PDISC:

		if (cmd == ELS_CMD_ACC) {
			/* This is a patch for the ULP stack. */

			/*
			 * ULP only reads our service parameters once during
			 * bind_port,
			 */
			/* but the service parameters change due to topology. */

			/* Copy latest service parameters to payload */
			bcopy((void *) &port->sparam,
			    (void *) &els_pkt->un.logi, sizeof (SERV_PARM));

#ifdef DHCHAP_SUPPORT
			emlxs_dhc_init_sp(port, did,
			    (SERV_PARM *)&els_pkt->un.logi, fcsp_msg);
#endif	/* DHCHAP_SUPPORT */

		}
		break;

	}

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) NULL;
	iocbq->ring = (void *) rp;

	/* Initalize iocb */
	iocb->ulpContext = (volatile uint16_t) pkt->pkt_cmd_fhdr.rx_id;
	iocb->ulpCommand = CMD_XMIT_ELS_RSP64_CX;
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *) NULL;
	sbp->lun = 0;
	sbp->class = iocb->ulpClass;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_reply_msg,
	    "%s %s: did=%x oxid=%x rxid=%x %s", emlxs_elscmd_xlate(ucmd),
	    emlxs_elscmd_xlate(cmd), did, pkt->pkt_cmd_fhdr.ox_id,
	    pkt->pkt_cmd_fhdr.rx_id, fcsp_msg);

	/* Process nodes */
	switch (ucmd) {
	case ELS_CMD_RSCN:
		{
			if (port->ini_mode && ub_buffer && cmd == ELS_CMD_ACC) {
				fc_rscn_t *rscn;
				uint32_t count;
				uint32_t *lp = NULL;

				/*
				 * Only the Leadville code path will come
				 * thru here. The RSCN data is NOT swapped
				 * properly for the Comstar code path.
				 */
				lp = (uint32_t *)ub_buffer;
				rscn = (fc_rscn_t *)lp++;
				count = ((rscn->rscn_payload_len - 4) / 4);

				/* Close affected ports */
				for (i = 0; i < count; i++, lp++) {
					(void) emlxs_port_offline(port, *lp);
				}
			}
			break;
		}
	case ELS_CMD_PLOGI:

		if (cmd == ELS_CMD_ACC) {
			ndlp = emlxs_node_find_did(port, did);

			if (ndlp && ndlp->nlp_active) {
				/* Close the node for any further normal IO */
				emlxs_node_close(port, ndlp, FC_FCP_RING,
				    pkt->pkt_timeout + 10);
				emlxs_node_close(port, ndlp, FC_IP_RING,
				    pkt->pkt_timeout + 10);

				/* Flush tx queue */
				(void) emlxs_tx_node_flush(port, ndlp, 0, 0, 0);

				/* Flush chip queue */
				(void) emlxs_chipq_node_flush(port, 0, ndlp, 0);
			}
		}
		break;

	case ELS_CMD_PRLI:

		if (cmd == ELS_CMD_ACC) {
			ndlp = emlxs_node_find_did(port, did);

			if (ndlp && ndlp->nlp_active) {
				/* Close the node for any further normal IO */
				emlxs_node_close(port, ndlp, FC_FCP_RING,
				    pkt->pkt_timeout + 10);

				/* Flush tx queues */
				(void) emlxs_tx_node_flush(port, ndlp,
				    &hba->ring[FC_FCP_RING], 0, 0);

				/* Flush chip queues */
				(void) emlxs_chipq_node_flush(port,
				    &hba->ring[FC_FCP_RING], ndlp, 0);
			}
		}
		break;

	case ELS_CMD_PRLO:

		if (cmd == ELS_CMD_ACC) {
			ndlp = emlxs_node_find_did(port, did);

			if (ndlp && ndlp->nlp_active) {
				/* Close the node for any further normal IO */
				emlxs_node_close(port, ndlp, FC_FCP_RING, 60);

				/* Flush tx queues */
				(void) emlxs_tx_node_flush(port, ndlp,
				    &hba->ring[FC_FCP_RING], 0, 0);

				/* Flush chip queues */
				(void) emlxs_chipq_node_flush(port,
				    &hba->ring[FC_FCP_RING], ndlp, 0);
			}
		}
		break;

	case ELS_CMD_LOGO:

		if (cmd == ELS_CMD_ACC) {
			ndlp = emlxs_node_find_did(port, did);

			if (ndlp && ndlp->nlp_active) {
				/* Close the node for any further normal IO */
				emlxs_node_close(port, ndlp, FC_FCP_RING, 60);
				emlxs_node_close(port, ndlp, FC_IP_RING, 60);

				/* Flush tx queues */
				(void) emlxs_tx_node_flush(port, ndlp, 0, 0, 0);

				/* Flush chip queues */
				(void) emlxs_chipq_node_flush(port, 0, ndlp, 0);
			}
		}
		break;
	}

	if (pkt->pkt_cmdlen) {
		emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}
	HBASTATS.ElsRspIssued++;

	emlxs_issue_iocb_cmd(hba, &hba->ring[FC_ELS_RING], iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_els_rsp() */


#ifdef MENLO_SUPPORT
static int32_t
emlxs_send_menlo_cmd(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	NODELIST *ndlp;
	/* int i; */
	uint16_t iotag;
	uint32_t did;
	uint32_t *lp;

	pkt = PRIV2PKT(sbp);
	did = EMLXS_MENLO_DID;
	rp = &hba->ring[FC_CT_RING];
	lp = (uint32_t *)pkt->pkt_cmd;

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	ndlp = emlxs_node_find_did(port, did);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=0x%x", did);

		return (FC_BADPACKET);
	}
	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) ndlp;
	iocbq->ring = (void *) rp;

	/* Fill in rest of iocb */
	iocb->un.genreq64.w5.hcsw.Fctl = LA;

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_LAST_SEQ) {
		iocb->un.genreq64.w5.hcsw.Fctl |= LSEQ;
	}
	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_SEQ_INITIATIVE) {
		iocb->un.genreq64.w5.hcsw.Fctl |= SI;
	}
	iocb->un.genreq64.w5.hcsw.Dfctl = 0;
	iocb->un.genreq64.w5.hcsw.Rctl = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.genreq64.w5.hcsw.Type = pkt->pkt_cmd_fhdr.type;

	iocb->ulpIoTag = iotag;
	iocb->ulpClass = CLASS3;
	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;

	if (pkt->pkt_tran_type == FC_PKT_EXCHANGE) {
		/* Cmd phase */

		/* Initalize iocb */
		iocb->ulpCommand = CMD_GEN_REQUEST64_CR;
		iocb->un.genreq64.param = pkt->pkt_cmd_fhdr.d_id;
		iocb->ulpContext = 0;
		iocb->ulpPU = 3;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: [%08x,%08x,%08x,%08x]",
		    emlxs_menlo_cmd_xlate(SWAP_LONG(lp[0])),
		    SWAP_LONG(lp[1]), SWAP_LONG(lp[2]),
		    SWAP_LONG(lp[3]), SWAP_LONG(lp[4]));

	} else {	/* FC_PKT_OUTBOUND */
		/* MENLO_CMD_FW_DOWNLOAD Data Phase */

		/* Initalize iocb */
		iocb->ulpCommand = CMD_GEN_REQUEST64_CX;
		iocb->un.genreq64.param = 0;
		iocb->ulpContext = pkt->pkt_cmd_fhdr.rx_id;
		iocb->ulpPU = 1;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: Data: rxid=0x%x size=%d",
		    emlxs_menlo_cmd_xlate(MENLO_CMD_FW_DOWNLOAD),
		    pkt->pkt_cmd_fhdr.rx_id, pkt->pkt_cmdlen);
	}

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *) ndlp;
	sbp->lun = 0;
	sbp->class = iocb->ulpClass;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
	    DDI_DMA_SYNC_FORDEV);

	HBASTATS.CtCmdIssued++;

	emlxs_issue_iocb_cmd(hba, &hba->ring[FC_CT_RING], iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_menlo_cmd() */
#endif	/* MENLO_SUPPORT */


static int32_t
emlxs_send_ct(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	NODELIST *ndlp;
	/* int i; */
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);
	rp = &hba->ring[FC_CT_RING];

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	ndlp = emlxs_node_find_did(port, did);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=0x%x", did);

		return (FC_BADPACKET);
	}
	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_ct_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) ndlp;
	iocbq->ring = (void *) rp;

	/* Fill in rest of iocb */
	iocb->un.genreq64.w5.hcsw.Fctl = LA;

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_LAST_SEQ) {
		iocb->un.genreq64.w5.hcsw.Fctl |= LSEQ;
	}
	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_SEQ_INITIATIVE) {
		iocb->un.genreq64.w5.hcsw.Fctl |= SI;
	}
	iocb->un.genreq64.w5.hcsw.Dfctl = 0;
	iocb->un.genreq64.w5.hcsw.Rctl = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.genreq64.w5.hcsw.Type = pkt->pkt_cmd_fhdr.type;

	/* Initalize iocb */
	iocb->ulpCommand = CMD_GEN_REQUEST64_CR;
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;
	iocb->ulpContext = ndlp->nlp_Rpi;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *) ndlp;
	sbp->lun = 0;
	sbp->class = iocb->ulpClass;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	if (did == NameServer_DID) {
		SLI_CT_REQUEST *CtCmd;
		uint32_t *lp0;

		CtCmd = (SLI_CT_REQUEST *) pkt->pkt_cmd;
		lp0 = (uint32_t *)pkt->pkt_cmd;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: did=%x [%08x,%08x]",
		    emlxs_ctcmd_xlate(
		    SWAP_DATA16(CtCmd->CommandResponse.bits.CmdRsp)), did,
		    SWAP_DATA32(lp0[4]), SWAP_DATA32(lp0[5]));

		if (hba->flag & FC_NPIV_DELAY_REQUIRED) {
			sbp->pkt_flags |= PACKET_DELAY_REQUIRED;
		}
	} else if (did == FDMI_DID) {
		SLI_CT_REQUEST *CtCmd;
		uint32_t *lp0;

		CtCmd = (SLI_CT_REQUEST *) pkt->pkt_cmd;
		lp0 = (uint32_t *)pkt->pkt_cmd;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: did=%x [%08x,%08x]",
		    emlxs_mscmd_xlate(
		    SWAP_DATA16(CtCmd->CommandResponse.bits.CmdRsp)), did,
		    SWAP_DATA32(lp0[4]), SWAP_DATA32(lp0[5]));
	} else {
		SLI_CT_REQUEST *CtCmd;
		uint32_t *lp0;

		CtCmd = (SLI_CT_REQUEST *) pkt->pkt_cmd;
		lp0 = (uint32_t *)pkt->pkt_cmd;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: did=%x [%08x,%08x]",
		    emlxs_rmcmd_xlate(
		    SWAP_DATA16(CtCmd->CommandResponse.bits.CmdRsp)), did,
		    SWAP_DATA32(lp0[4]), SWAP_DATA32(lp0[5]));
	}

	if (pkt->pkt_cmdlen) {
		emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}
	HBASTATS.CtCmdIssued++;

	emlxs_issue_iocb_cmd(hba, &hba->ring[FC_CT_RING], iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_ct() */


static int32_t
emlxs_send_ct_rsp(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	/* NODELIST *ndlp; */
	/* int i; */
	uint16_t iotag;
	uint32_t did;
	uint32_t *cmd;
	SLI_CT_REQUEST *CtCmd;

	pkt = PRIV2PKT(sbp);
	rp = &hba->ring[FC_CT_RING];
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);
	CtCmd = (SLI_CT_REQUEST *) pkt->pkt_cmd;
	cmd = (uint32_t *)pkt->pkt_cmd;

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_ct_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *) NULL;
	iocbq->ring = (void *) rp;

	/* Initalize iocb */
	iocb->ulpCommand = CMD_XMIT_SEQUENCE64_CX;
	iocb->ulpIoTag = iotag;

	/* Fill in rest of iocb */
	iocb->un.xseq64.w5.hcsw.Fctl = LA;

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_LAST_SEQ) {
		iocb->un.xseq64.w5.hcsw.Fctl |= LSEQ;
	}
	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_SEQ_INITIATIVE) {
		iocb->un.xseq64.w5.hcsw.Fctl |= SI;
	}
	iocb->un.xseq64.w5.hcsw.Dfctl = pkt->pkt_cmd_fhdr.df_ctl;
	iocb->un.xseq64.w5.hcsw.Rctl = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.xseq64.w5.hcsw.Type = pkt->pkt_cmd_fhdr.type;

	iocb->ulpRsvdByte = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpContext = pkt->pkt_cmd_fhdr.rx_id;
	iocb->ulpOwner = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = NULL;
	sbp->lun = 0;
	sbp->class = iocb->ulpClass;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_reply_msg,
	    "%s: Rsn=%x Exp=%x [%08x,%08x] rxid=%x ",
	    emlxs_rmcmd_xlate(SWAP_DATA16(CtCmd->CommandResponse.bits.CmdRsp)),
	    CtCmd->ReasonCode, CtCmd->Explanation, SWAP_DATA32(cmd[4]),
	    SWAP_DATA32(cmd[5]), pkt->pkt_cmd_fhdr.rx_id);

	if (pkt->pkt_cmdlen) {
		emlxs_mpdata_sync(pkt->pkt_cmd_dma, 0,
		    pkt->pkt_cmdlen, DDI_DMA_SYNC_FORDEV);
	}
	HBASTATS.CtRspIssued++;

	emlxs_issue_iocb_cmd(hba, &hba->ring[FC_CT_RING], iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_ct_rsp() */


/*
 * emlxs_get_instance() Given a ddi ddiinst, return a
 * Fibre Channel (emlx) ddiinst.
 */
extern uint32_t
emlxs_get_instance(int32_t ddiinst)
{
	uint32_t i;
	uint32_t inst;

	mutex_enter(&emlxs_device.lock);

	inst = MAX_FC_BRDS;
	for (i = 0; i < emlxs_instance_count; i++) {
		if (emlxs_instance[i] == ddiinst) {
			inst = i;
			break;
		}
	}

	mutex_exit(&emlxs_device.lock);

	return (inst);

} /* emlxs_get_instance() */


/*
 * emlxs_add_instance() Given a ddi ddiinst, create a Fibre Channel
 * (emlx) ddiinst. emlx ddiinsts are the order that
 * emlxs_attach gets called, starting at 0.
 */
static uint32_t
emlxs_add_instance(int32_t ddiinst)
{
	uint32_t i;

	mutex_enter(&emlxs_device.lock);

	/* First see if the ddiinst already exists */
	for (i = 0; i < emlxs_instance_count; i++) {
		if (emlxs_instance[i] == ddiinst) {
			break;
		}
	}

	/* If it doesn't already exist, add it */
	if (i >= emlxs_instance_count) {
		if ((i = emlxs_instance_count) < MAX_FC_BRDS) {
			emlxs_instance[i] = ddiinst;
			emlxs_instance_count++;
			emlxs_device.hba_count = emlxs_instance_count;
		}
	}
	mutex_exit(&emlxs_device.lock);

	return (i);

} /* emlxs_add_instance() */


/*ARGSUSED*/
extern void
emlxs_pkt_complete(emlxs_buf_t *sbp, uint32_t iostat, uint8_t localstat,
    uint32_t doneq)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	emlxs_buf_t *fpkt;

	port = sbp->port;

	if (!port) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_completion_error_msg,
		    "NULL port found. sbp=%p flags=%x", sbp, sbp->pkt_flags);

		return;
	}
	hba = HBA;

	mutex_enter(&sbp->mtx);

	/* Check for error conditions */
	if (sbp->pkt_flags & (PACKET_RETURNED | PACKET_COMPLETED |
	    PACKET_IN_DONEQ | PACKET_IN_COMPLETION |
	    PACKET_IN_TXQ | PACKET_IN_CHIPQ)) {
		if (sbp->pkt_flags & PACKET_RETURNED) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet already returned. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
		} else if (sbp->pkt_flags & PACKET_COMPLETED) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet already completed. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
		} else if (sbp->pkt_flags & PACKET_IN_DONEQ) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Pkt already on done queue. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
		} else if (sbp->pkt_flags & PACKET_IN_COMPLETION) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet already in completion. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
		} else if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet still on chip queue. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
		} else if (sbp->pkt_flags & PACKET_IN_TXQ) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet still on tx queue. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
		}
		mutex_exit(&sbp->mtx);
		return;
	}
	/* Packet is now in completion */
	sbp->pkt_flags |= PACKET_IN_COMPLETION;

	/* Set the state if not already set */
	if (!(sbp->pkt_flags & PACKET_STATE_VALID)) {
		emlxs_set_pkt_state(sbp, iostat, localstat, 0);
	}
	/* Check for parent flush packet */
	/* If pkt has a parent flush packet then adjust its count now */
	fpkt = sbp->fpkt;
	if (fpkt) {
		/*
		 * We will try to NULL sbp->fpkt inside the fpkt's mutex if
		 * possible
		 */

		if (!(fpkt->pkt_flags & PACKET_RETURNED)) {
			mutex_enter(&fpkt->mtx);
			if (fpkt->flush_count) {
				fpkt->flush_count--;
			}
			sbp->fpkt = NULL;
			mutex_exit(&fpkt->mtx);
		} else {	/* fpkt has been returned already */
			sbp->fpkt = NULL;
		}
	}
	/* If pkt is polled, then wake up sleeping thread */
	if (sbp->pkt_flags & PACKET_POLLED) {
		/*
		 * Don't set the PACKET_RETURNED flag here because the
		 * polling thread will do it
		 */
		sbp->pkt_flags |= PACKET_COMPLETED;
		mutex_exit(&sbp->mtx);

		/* Wake up sleeping thread */
		mutex_enter(&EMLXS_PKT_LOCK);
		cv_broadcast(&EMLXS_PKT_CV);
		mutex_exit(&EMLXS_PKT_LOCK);
	}
	/*
	 * If packet was generated by our driver, then complete it
	 * immediately
	 */
	else if (sbp->pkt_flags & PACKET_ALLOCATED) {
		mutex_exit(&sbp->mtx);

		emlxs_iodone(sbp);
	}
	/*
	 * Put the pkt on the done queue for callback completion in another
	 * thread
	 */
	else {
		sbp->pkt_flags |= PACKET_IN_DONEQ;
		sbp->next = NULL;
		mutex_exit(&sbp->mtx);

		/* Put pkt on doneq, so I/O's will be completed in order */
		mutex_enter(&EMLXS_PORT_LOCK);
		if (hba->iodone_tail == NULL) {
			hba->iodone_list = sbp;
			hba->iodone_count = 1;
		} else {
			hba->iodone_tail->next = sbp;
			hba->iodone_count++;
		}
		hba->iodone_tail = sbp;
		mutex_exit(&EMLXS_PORT_LOCK);

		/* Trigger a thread to service the doneq */
		emlxs_thread_trigger1(&hba->iodone_thread, emlxs_iodone_server);
	}

	return;

} /* emlxs_pkt_complete() */


/*ARGSUSED*/
static void
emlxs_iodone_server(void *arg1, void *arg2, void *arg3)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_buf_t *sbp;

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Remove one pkt from the doneq head and complete it */
	while ((sbp = hba->iodone_list) != NULL) {
		if ((hba->iodone_list = sbp->next) == NULL) {
			hba->iodone_tail = NULL;
			hba->iodone_count = 0;
		} else {
			hba->iodone_count--;
		}

		mutex_exit(&EMLXS_PORT_LOCK);

		/* Prepare the pkt for completion */
		mutex_enter(&sbp->mtx);
		sbp->next = NULL;
		sbp->pkt_flags &= ~PACKET_IN_DONEQ;
		mutex_exit(&sbp->mtx);

		/* Complete the IO now */
		emlxs_iodone(sbp);

		/* Reacquire lock and check if more work is to be done */
		mutex_enter(&EMLXS_PORT_LOCK);
	}

	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* End emlxs_iodone_server */


static void
emlxs_iodone(emlxs_buf_t *sbp)
{
	fc_packet_t *pkt;
	/* emlxs_hba_t *hba; */
	/* emlxs_port_t *port; */

	/* port = sbp->port; */
	pkt = PRIV2PKT(sbp);

	/* Check one more time that the  pkt has not already been returned */
	if (sbp->pkt_flags & PACKET_RETURNED) {
		return;
	}
#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_unswap_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	mutex_enter(&sbp->mtx);
	sbp->pkt_flags |= (PACKET_COMPLETED | PACKET_RETURNED);
	mutex_exit(&sbp->mtx);

	if (pkt->pkt_comp) {
		(*pkt->pkt_comp) (pkt);
	}
	return;

} /* emlxs_iodone() */



extern fc_unsol_buf_t *
emlxs_ub_find(emlxs_port_t *port, uint32_t token)
{
	/* emlxs_hba_t *hba = HBA; */
	emlxs_unsol_buf_t *pool;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;

	/* Check if this is a valid ub token */
	if (token < EMLXS_UB_TOKEN_OFFSET) {
		return (NULL);
	}
	mutex_enter(&EMLXS_UB_LOCK);

	pool = port->ub_pool;
	while (pool) {
		/* Find a pool with the proper token range */
		if (token >= pool->pool_first_token &&
		    token <= pool->pool_last_token) {
			ubp = (fc_unsol_buf_t *)
			    &pool->fc_ubufs[(token - pool->pool_first_token)];
			ub_priv = ubp->ub_fca_private;

			if (ub_priv->token != token) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "ub_find: Invalid token=%x", ubp,
				    token, ub_priv->token);

				ubp = NULL;
			} else if (!(ub_priv->flags & EMLXS_UB_IN_USE)) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "ub_find: Buffer not in use. "
				    "buffer=%p token=%x", ubp, token);

				ubp = NULL;
			}
			mutex_exit(&EMLXS_UB_LOCK);

			return (ubp);
		}
		pool = pool->pool_next;
	}

	mutex_exit(&EMLXS_UB_LOCK);

	return (NULL);

} /* emlxs_ub_find() */



extern fc_unsol_buf_t *
emlxs_ub_get(emlxs_port_t *port, uint32_t size, uint32_t type, uint32_t reserve)
{
	emlxs_hba_t *hba = HBA;
	emlxs_unsol_buf_t *pool;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	uint32_t i;
	uint32_t resv_flag;
	uint32_t pool_free;
	uint32_t pool_free_resv;

	mutex_enter(&EMLXS_UB_LOCK);

	pool = port->ub_pool;
	while (pool) {
		/* Find a pool of the appropriate type and size */
		if ((pool->pool_available == 0) ||
		    (pool->pool_type != type) ||
		    (pool->pool_buf_size < size)) {
			goto next_pool;
		}
		/* Adjust free counts based on availablity    */
		/* The free reserve count gets first priority */
		pool_free_resv =
		    min(pool->pool_free_resv, pool->pool_available);
		pool_free = min(pool->pool_free,
		    (pool->pool_available - pool_free_resv));

		/* Initialize reserve flag */
		resv_flag = reserve;

		if (resv_flag) {
			if (pool_free_resv == 0) {
				if (pool_free == 0) {
					goto next_pool;
				}
				resv_flag = 0;
			}
		} else if (pool_free == 0) {
			goto next_pool;
		}
		/* Find next available free buffer in this pool */
		for (i = 0; i < pool->pool_nentries; i++) {
			ubp = (fc_unsol_buf_t *)&pool->fc_ubufs[i];
			ub_priv = ubp->ub_fca_private;

			if (!ub_priv->available ||
			    ub_priv->flags != EMLXS_UB_FREE) {
				continue;
			}
			ub_priv->time = hba->timer_tics;
			ub_priv->timeout = (5 * 60);	/* Timeout in 5 mins */
			ub_priv->flags = EMLXS_UB_IN_USE;

			/* Alloc the buffer from the pool */
			if (resv_flag) {
				ub_priv->flags |= EMLXS_UB_RESV;
				pool->pool_free_resv--;
			} else {
				pool->pool_free--;
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_detail_msg,
			    "ub_get: ubp=%p token=%x (%d,%d,%d,%d)",
			    ubp, ub_priv->token, pool->pool_nentries,
			    pool->pool_available, pool->pool_free,
			    pool->pool_free_resv);

			mutex_exit(&EMLXS_UB_LOCK);

			return (ubp);
		}
next_pool:

		pool = pool->pool_next;
	}

	mutex_exit(&EMLXS_UB_LOCK);

	return (NULL);

} /* emlxs_ub_get() */



extern void
emlxs_set_pkt_state(emlxs_buf_t *sbp, uint32_t iostat, uint8_t localstat,
    uint32_t lock)
{
	/* emlxs_port_t *port = sbp->port; */
	/* emlxs_hba_t *hba = HBA; */
	fc_packet_t *pkt;
	fcp_rsp_t *fcp_rsp;
	uint32_t i;
	emlxs_xlat_err_t *tptr;
	emlxs_xlat_err_t *entry;


	pkt = PRIV2PKT(sbp);

	if (lock) {
		mutex_enter(&sbp->mtx);
	}
	if (!(sbp->pkt_flags & PACKET_STATE_VALID)) {
		sbp->pkt_flags |= PACKET_STATE_VALID;

		/* Perform table lookup */
		entry = NULL;
		if (iostat != IOSTAT_LOCAL_REJECT) {
			tptr = emlxs_iostat_tbl;
			for (i = 0; i < IOSTAT_MAX; i++, tptr++) {
				if (iostat == tptr->emlxs_status) {
					entry = tptr;
					break;
				}
			}
		} else {	/* iostate == IOSTAT_LOCAL_REJECT */
			tptr = emlxs_ioerr_tbl;
			for (i = 0; i < IOERR_MAX; i++, tptr++) {
				if (localstat == tptr->emlxs_status) {
					entry = tptr;
					break;
				}
			}
		}

		if (entry) {
			pkt->pkt_state = entry->pkt_state;
			pkt->pkt_reason = entry->pkt_reason;
			pkt->pkt_expln = entry->pkt_expln;
			pkt->pkt_action = entry->pkt_action;
		} else {
			/* Set defaults */
			pkt->pkt_state = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = FC_REASON_ABORTED;
			pkt->pkt_expln = FC_EXPLN_NONE;
			pkt->pkt_action = FC_ACTION_RETRYABLE;
		}


		/* Set the residual counts and response frame */
		/* Check if response frame was received from the chip */
		/* If so, then the residual counts will already be set */
		if (!(sbp->pkt_flags & (PACKET_FCP_RSP_VALID |
		    PACKET_CT_RSP_VALID | PACKET_ELS_RSP_VALID))) {
			/* We have to create the response frame */
			if (iostat == IOSTAT_SUCCESS) {
				pkt->pkt_resp_resid = 0;
				pkt->pkt_data_resid = 0;

				if ((pkt->pkt_cmd_fhdr.type ==
				    FC_TYPE_SCSI_FCP) &&
				    pkt->pkt_rsplen && pkt->pkt_resp) {
					fcp_rsp = (fcp_rsp_t *)pkt->pkt_resp;

					fcp_rsp->fcp_u.fcp_status.rsp_len_set =
					    1;
					fcp_rsp->fcp_response_len = 8;
				}
			} else {
				/*
				 * Otherwise assume no data and no response
				 * received
				 */
				pkt->pkt_data_resid = pkt->pkt_datalen;
				pkt->pkt_resp_resid = pkt->pkt_rsplen;
			}
		}
	}
	if (lock) {
		mutex_exit(&sbp->mtx);
	}
	return;

} /* emlxs_set_pkt_state() */


#if (EMLXS_MODREVX == EMLXS_MODREV2X)

extern void
emlxs_swap_service_params(SERV_PARM *sp)
{
	uint16_t *p;
	int size;
	int i;

	size = (sizeof (CSP) - 4) / 2;
	p = (uint16_t *)&sp->cmn;
	for (i = 0; i < size; i++) {
		p[i] = SWAP_DATA16(p[i]);
	}
	sp->cmn.e_d_tov = SWAP_DATA32(sp->cmn.e_d_tov);

	size = sizeof (CLASS_PARMS) / 2;
	p = (uint16_t *)&sp->cls1;
	for (i = 0; i < size; i++, p++) {
		*p = SWAP_DATA16(*p);
	}

	size = sizeof (CLASS_PARMS) / 2;
	p = (uint16_t *)&sp->cls2;
	for (i = 0; i < size; i++, p++) {
		*p = SWAP_DATA16(*p);
	}

	size = sizeof (CLASS_PARMS) / 2;
	p = (uint16_t *)&sp->cls3;
	for (i = 0; i < size; i++, p++) {
		*p = SWAP_DATA16(*p);
	}

	size = sizeof (CLASS_PARMS) / 2;
	p = (uint16_t *)&sp->cls4;
	for (i = 0; i < size; i++, p++) {
		*p = SWAP_DATA16(*p);
	}

	return;

} /* emlxs_swap_service_params() */

extern void
emlxs_unswap_pkt(emlxs_buf_t *sbp)
{
	if (sbp->pkt_flags & PACKET_FCP_SWAPPED) {
		emlxs_swap_fcp_pkt(sbp);
	} else if (sbp->pkt_flags & PACKET_ELS_SWAPPED) {
		emlxs_swap_els_pkt(sbp);
	} else if (sbp->pkt_flags & PACKET_CT_SWAPPED) {
		emlxs_swap_ct_pkt(sbp);
	}
} /* emlxs_unswap_pkt() */


extern void
emlxs_swap_fcp_pkt(emlxs_buf_t *sbp)
{
	fc_packet_t *pkt;
	FCP_CMND *cmd;
	fcp_rsp_t *rsp;
	uint16_t *lunp;
	uint32_t i;

	mutex_enter(&sbp->mtx);

	if (sbp->pkt_flags & PACKET_ALLOCATED) {
		mutex_exit(&sbp->mtx);
		return;
	}
	if (sbp->pkt_flags & PACKET_FCP_SWAPPED) {
		sbp->pkt_flags &= ~PACKET_FCP_SWAPPED;
	} else {
		sbp->pkt_flags |= PACKET_FCP_SWAPPED;
	}

	mutex_exit(&sbp->mtx);

	pkt = PRIV2PKT(sbp);

	cmd = (FCP_CMND *) pkt->pkt_cmd;
	rsp = (pkt->pkt_rsplen && (sbp->pkt_flags & PACKET_FCP_RSP_VALID)) ?
	    (fcp_rsp_t *)pkt->pkt_resp : NULL;

	/* The size of data buffer needs to be swapped. */
	cmd->fcpDl = SWAP_DATA32(cmd->fcpDl);

	/*
	 * Swap first 2 words of FCP CMND payload.
	 */
	lunp = (uint16_t *)&cmd->fcpLunMsl;
	for (i = 0; i < 4; i++) {
		lunp[i] = SWAP_DATA16(lunp[i]);
	}

	if (rsp) {
		rsp->fcp_resid = SWAP_DATA32(rsp->fcp_resid);
		rsp->fcp_sense_len = SWAP_DATA32(rsp->fcp_sense_len);
		rsp->fcp_response_len = SWAP_DATA32(rsp->fcp_response_len);
	}
	return;

} /* emlxs_swap_fcp_pkt() */


extern void
emlxs_swap_els_pkt(emlxs_buf_t *sbp)
{
	fc_packet_t *pkt;
	uint32_t *cmd;
	uint32_t *rsp;
	uint32_t command;
	uint16_t *c;
	uint32_t i;
	uint32_t swapped;

	mutex_enter(&sbp->mtx);

	if (sbp->pkt_flags & PACKET_ALLOCATED) {
		mutex_exit(&sbp->mtx);
		return;
	}
	if (sbp->pkt_flags & PACKET_ELS_SWAPPED) {
		sbp->pkt_flags &= ~PACKET_ELS_SWAPPED;
		swapped = 1;
	} else {
		sbp->pkt_flags |= PACKET_ELS_SWAPPED;
		swapped = 0;
	}

	mutex_exit(&sbp->mtx);

	pkt = PRIV2PKT(sbp);

	cmd = (uint32_t *)pkt->pkt_cmd;
	rsp = (pkt->pkt_rsplen && (sbp->pkt_flags & PACKET_ELS_RSP_VALID)) ?
	    (uint32_t *)pkt->pkt_resp : NULL;

	if (!swapped) {
		cmd[0] = SWAP_DATA32(cmd[0]);
		command = cmd[0] & ELS_CMD_MASK;
	} else {
		command = cmd[0] & ELS_CMD_MASK;
		cmd[0] = SWAP_DATA32(cmd[0]);
	}

	if (rsp) {
		rsp[0] = SWAP_DATA32(rsp[0]);
	}
	switch (command) {
	case ELS_CMD_ACC:
		if (sbp->ucmd == ELS_CMD_ADISC) {
			/* Hard address of originator */
			cmd[1] = SWAP_DATA32(cmd[1]);

			/* N_Port ID of originator */
			cmd[6] = SWAP_DATA32(cmd[6]);
		}
		break;

	case ELS_CMD_PLOGI:
	case ELS_CMD_FLOGI:
	case ELS_CMD_FDISC:
		if (rsp) {
			emlxs_swap_service_params((SERV_PARM *) & rsp[1]);
		}
		break;

	case ELS_CMD_RLS:
		cmd[1] = SWAP_DATA32(cmd[1]);

		if (rsp) {
			for (i = 0; i < 6; i++) {
				rsp[1 + i] = SWAP_DATA32(rsp[1 + i]);
			}
		}
		break;

	case ELS_CMD_ADISC:
		cmd[1] = SWAP_DATA32(cmd[1]);	/* Hard address of originator */
		cmd[6] = SWAP_DATA32(cmd[6]);	/* N_Port ID of originator */
		break;

	case ELS_CMD_PRLI:
		c = (uint16_t *)&cmd[1];
		c[1] = SWAP_DATA16(c[1]);

		cmd[4] = SWAP_DATA32(cmd[4]);

		if (rsp) {
			rsp[4] = SWAP_DATA32(rsp[4]);
		}
		break;

	case ELS_CMD_SCR:
		cmd[1] = SWAP_DATA32(cmd[1]);
		break;

	case ELS_CMD_LINIT:
		if (rsp) {
			rsp[1] = SWAP_DATA32(rsp[1]);
		}
		break;

	default:
		break;
	}

	return;

} /* emlxs_swap_els_pkt() */


extern void
emlxs_swap_ct_pkt(emlxs_buf_t *sbp)
{
	fc_packet_t *pkt;
	uint32_t *cmd;
	uint32_t *rsp;
	uint32_t command;
	uint32_t i;
	uint32_t swapped;

	mutex_enter(&sbp->mtx);

	if (sbp->pkt_flags & PACKET_ALLOCATED) {
		mutex_exit(&sbp->mtx);
		return;
	}
	if (sbp->pkt_flags & PACKET_CT_SWAPPED) {
		sbp->pkt_flags &= ~PACKET_CT_SWAPPED;
		swapped = 1;
	} else {
		sbp->pkt_flags |= PACKET_CT_SWAPPED;
		swapped = 0;
	}

	mutex_exit(&sbp->mtx);

	pkt = PRIV2PKT(sbp);

	cmd = (uint32_t *)pkt->pkt_cmd;
	rsp = (pkt->pkt_rsplen && (sbp->pkt_flags & PACKET_CT_RSP_VALID)) ?
	    (uint32_t *)pkt->pkt_resp : NULL;

	if (!swapped) {
		cmd[0] = 0x01000000;
		command = cmd[2];
	}
	cmd[0] = SWAP_DATA32(cmd[0]);
	cmd[1] = SWAP_DATA32(cmd[1]);
	cmd[2] = SWAP_DATA32(cmd[2]);
	cmd[3] = SWAP_DATA32(cmd[3]);

	if (swapped) {
		command = cmd[2];
	}
	switch ((command >> 16)) {
	case SLI_CTNS_GA_NXT:
		cmd[4] = SWAP_DATA32(cmd[4]);
		break;

	case SLI_CTNS_GPN_ID:
	case SLI_CTNS_GNN_ID:
	case SLI_CTNS_RPN_ID:
	case SLI_CTNS_RNN_ID:
		cmd[4] = SWAP_DATA32(cmd[4]);
		break;

	case SLI_CTNS_RCS_ID:
	case SLI_CTNS_RPT_ID:
		cmd[4] = SWAP_DATA32(cmd[4]);
		cmd[5] = SWAP_DATA32(cmd[5]);
		break;

	case SLI_CTNS_RFT_ID:
		cmd[4] = SWAP_DATA32(cmd[4]);

		/* Swap FC4 types */
		for (i = 0; i < 8; i++) {
			cmd[5 + i] = SWAP_DATA32(cmd[5 + i]);
		}
		break;

	case SLI_CTNS_GFT_ID:
		if (rsp) {
			/* Swap FC4 types */
			for (i = 0; i < 8; i++) {
				rsp[4 + i] = SWAP_DATA32(rsp[4 + i]);
			}
		}
		break;

	case SLI_CTNS_GCS_ID:
	case SLI_CTNS_GSPN_ID:
	case SLI_CTNS_GSNN_NN:
	case SLI_CTNS_GIP_NN:
	case SLI_CTNS_GIPA_NN:

	case SLI_CTNS_GPT_ID:
	case SLI_CTNS_GID_NN:
	case SLI_CTNS_GNN_IP:
	case SLI_CTNS_GIPA_IP:
	case SLI_CTNS_GID_FT:
	case SLI_CTNS_GID_PT:
	case SLI_CTNS_GID_PN:
	case SLI_CTNS_RSPN_ID:
	case SLI_CTNS_RIP_NN:
	case SLI_CTNS_RIPA_NN:
	case SLI_CTNS_RSNN_NN:
	case SLI_CTNS_DA_ID:
	case SLI_CT_RESPONSE_FS_RJT:
	case SLI_CT_RESPONSE_FS_ACC:

	default:
		break;
	}
	return;

} /* emlxs_swap_ct_pkt() */


extern void
emlxs_swap_els_ub(fc_unsol_buf_t *ubp)
{
	emlxs_ub_priv_t *ub_priv;
	fc_rscn_t *rscn;
	uint32_t count;
	uint32_t i;
	uint32_t *lp;
	la_els_logi_t *logi;

	ub_priv = ubp->ub_fca_private;

	switch (ub_priv->cmd) {
	case ELS_CMD_RSCN:
		rscn = (fc_rscn_t *)ubp->ub_buffer;

		rscn->rscn_payload_len = SWAP_DATA16(rscn->rscn_payload_len);

		count = ((rscn->rscn_payload_len - 4) / 4);
		lp = (uint32_t *)ubp->ub_buffer + 1;
		for (i = 0; i < count; i++, lp++) {
			*lp = SWAP_DATA32(*lp);
		}

		break;

	case ELS_CMD_FLOGI:
	case ELS_CMD_PLOGI:
	case ELS_CMD_FDISC:
	case ELS_CMD_PDISC:
		logi = (la_els_logi_t *)ubp->ub_buffer;
		emlxs_swap_service_params((SERV_PARM *) & logi->common_service);
		break;

		/* ULP handles this */
	case ELS_CMD_LOGO:
	case ELS_CMD_PRLI:
	case ELS_CMD_PRLO:
	case ELS_CMD_ADISC:
	default:
		break;
	}

	return;

} /* emlxs_swap_els_ub() */


#endif	/* EMLXS_MODREV2X */


extern char *
emlxs_elscmd_xlate(uint32_t elscmd)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_elscmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (elscmd == emlxs_elscmd_table[i].code) {
			return (emlxs_elscmd_table[i].string);
		}
	}

	(void) sprintf(buffer, "ELS=0x%x", elscmd);
	return (buffer);

} /* emlxs_elscmd_xlate() */


extern char *
emlxs_ctcmd_xlate(uint32_t ctcmd)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_ctcmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (ctcmd == emlxs_ctcmd_table[i].code) {
			return (emlxs_ctcmd_table[i].string);
		}
	}

	(void) sprintf(buffer, "cmd=0x%x", ctcmd);
	return (buffer);

} /* emlxs_ctcmd_xlate() */


#ifdef MENLO_SUPPORT
extern char *
emlxs_menlo_cmd_xlate(uint32_t cmd)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_menlo_cmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (cmd == emlxs_menlo_cmd_table[i].code) {
			return (emlxs_menlo_cmd_table[i].string);
		}
	}

	(void) sprintf(buffer, "Cmd=0x%x", cmd);
	return (buffer);

} /* emlxs_menlo_cmd_xlate() */

extern char *
emlxs_menlo_rsp_xlate(uint32_t rsp)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_menlo_rsp_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (rsp == emlxs_menlo_rsp_table[i].code) {
			return (emlxs_menlo_rsp_table[i].string);
		}
	}

	(void) sprintf(buffer, "Rsp=0x%x", rsp);
	return (buffer);

} /* emlxs_menlo_rsp_xlate() */

#endif	/* MENLO_SUPPORT */


extern char *
emlxs_rmcmd_xlate(uint32_t rmcmd)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_rmcmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (rmcmd == emlxs_rmcmd_table[i].code) {
			return (emlxs_rmcmd_table[i].string);
		}
	}

	(void) sprintf(buffer, "RM=0x%x", rmcmd);
	return (buffer);

} /* emlxs_rmcmd_xlate() */



extern char *
emlxs_mscmd_xlate(uint16_t mscmd)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_mscmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (mscmd == emlxs_mscmd_table[i].code) {
			return (emlxs_mscmd_table[i].string);
		}
	}

	(void) sprintf(buffer, "Cmd=0x%x", mscmd);
	return (buffer);

} /* emlxs_mscmd_xlate() */


extern char *
emlxs_state_xlate(uint8_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_state_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_state_table[i].code) {
			return (emlxs_state_table[i].string);
		}
	}

	(void) sprintf(buffer, "State=0x%x", state);
	return (buffer);

} /* emlxs_state_xlate() */


extern char *
emlxs_error_xlate(uint8_t errno)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_error_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (errno == emlxs_error_table[i].code) {
			return (emlxs_error_table[i].string);
		}
	}

	(void) sprintf(buffer, "Errno=0x%x", errno);
	return (buffer);

} /* emlxs_error_xlate() */


static int
emlxs_pm_lower_power(dev_info_t *dip)
{
	int ddiinst;
	int emlxinst;
	emlxs_config_t *cfg;
	int32_t rval;
	emlxs_hba_t *hba;

	ddiinst = ddi_get_instance(dip);
	emlxinst = emlxs_get_instance(ddiinst);
	hba = emlxs_device.hba[emlxinst];
	cfg = &CFG;

	rval = DDI_SUCCESS;

	/* Lower the power level */
	if (cfg[CFG_PM_SUPPORT].current) {
		rval = pm_lower_power(dip, EMLXS_PM_ADAPTER,
		    EMLXS_PM_ADAPTER_DOWN);
	} else {
		/* We do not have kernel support of power management enabled */
		/* therefore, call our power management routine directly */
		rval = emlxs_power(dip, EMLXS_PM_ADAPTER,
		    EMLXS_PM_ADAPTER_DOWN);
	}

	return (rval);

} /* emlxs_pm_lower_power() */


static int
emlxs_pm_raise_power(dev_info_t *dip)
{
	int ddiinst;
	int emlxinst;
	emlxs_config_t *cfg;
	int32_t rval;
	emlxs_hba_t *hba;

	ddiinst = ddi_get_instance(dip);
	emlxinst = emlxs_get_instance(ddiinst);
	hba = emlxs_device.hba[emlxinst];
	cfg = &CFG;

	/* Raise the power level */
	if (cfg[CFG_PM_SUPPORT].current) {
		rval = pm_raise_power(dip, EMLXS_PM_ADAPTER,
		    EMLXS_PM_ADAPTER_UP);
	} else {
		/* We do not have kernel support of power management enabled */
		/* therefore, call our power management routine directly */
		rval = emlxs_power(dip, EMLXS_PM_ADAPTER, EMLXS_PM_ADAPTER_UP);
	}

	return (rval);

} /* emlxs_pm_raise_power() */


#ifdef IDLE_TIMER

extern int
emlxs_pm_busy_component(emlxs_hba_t *hba)
{
	emlxs_config_t *cfg = &CFG;
	int rval;

	hba->pm_active = 1;

	if (hba->pm_busy) {
		return (DDI_SUCCESS);
	}
	mutex_enter(&hba->pm_lock);

	if (hba->pm_busy) {
		mutex_exit(&hba->pm_lock);
		return (DDI_SUCCESS);
	}
	hba->pm_busy = 1;

	mutex_exit(&hba->pm_lock);

	/* Attempt to notify system that we are busy */
	if (cfg[CFG_PM_SUPPORT].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "pm_busy_component.");

		rval = pm_busy_component(dip, EMLXS_PM_ADAPTER);

		if (rval != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "pm_busy_component failed. ret=%d", rval);

			/* If this attempt failed then clear our flags */
			mutex_enter(&hba->pm_lock);
			hba->pm_busy = 0;
			mutex_exit(&hba->pm_lock);

			return (rval);
		}
	}
	return (DDI_SUCCESS);

} /* emlxs_pm_busy_component() */


extern int
emlxs_pm_idle_component(emlxs_hba_t *hba)
{
	emlxs_config_t *cfg = &CFG;
	int rval;

	if (!hba->pm_busy) {
		return (DDI_SUCCESS);
	}
	mutex_enter(&hba->pm_lock);

	if (!hba->pm_busy) {
		mutex_exit(&hba->pm_lock);
		return (DDI_SUCCESS);
	}
	hba->pm_busy = 0;

	mutex_exit(&hba->pm_lock);

	if (cfg[CFG_PM_SUPPORT].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "pm_idle_component.");

		rval = pm_idle_component(dip, EMLXS_PM_ADAPTER);

		if (rval != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "pm_idle_component failed. ret=%d", rval);

			/*
			 * If this attempt failed then reset our flags for
			 * another attempt
			 */
			mutex_enter(&hba->pm_lock);
			hba->pm_busy = 1;
			mutex_exit(&hba->pm_lock);

			return (rval);
		}
	}
	return (DDI_SUCCESS);

} /* emlxs_pm_idle_component() */


extern void
emlxs_pm_idle_timer(emlxs_hba_t *hba)
{
	emlxs_config_t *cfg = &CFG;

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	 * "emlxs_pm_idle_timer. timer=%x active=%x busy=%x",
	 * hba->pm_idle_timer, hba->pm_active, hba->pm_busy);
	 */

	if (hba->pm_active) {
		/* Clear active flag and reset idle timer */
		mutex_enter(&hba->pm_lock);
		hba->pm_active = 0;
		hba->pm_idle_timer = hba->timer_tics + cfg[CFG_PM_IDLE].current;
		mutex_exit(&hba->pm_lock);
	}
	/* Check for idle timeout */
	else if (hba->timer_tics >= hba->pm_idle_timer) {
		if (emlxs_pm_idle_component(hba) == DDI_SUCCESS) {
			mutex_enter(&hba->pm_lock);
			hba->pm_idle_timer =
			    hba->timer_tics + cfg[CFG_PM_IDLE].current;
			mutex_exit(&hba->pm_lock);
		}
	}
	return;

} /* emlxs_pm_idle_timer() */

#endif	/* IDLE_TIMER */


#ifdef SLI3_SUPPORT
static void
emlxs_read_vport_prop(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	char **arrayp;
	uint8_t *s, *np;
	/* uint8_t *str; */
	NAME_TYPE pwwpn;
	NAME_TYPE wwnn;
	NAME_TYPE wwpn;
	/* uint32_t ddiinst; */
	uint32_t vpi;
	uint32_t cnt;
	uint32_t rval;
	uint32_t i;
	uint32_t j;
	uint32_t c1;
	uint32_t sum;
	uint32_t errors;
	/* uint8_t *wwn1; */
	/* uint8_t *wwn2; */
	char buffer[64];

	/* Check for the per adapter vport setting */
	(void) sprintf(buffer, "%s%d-vport", DRIVER_NAME, hba->ddiinst);
	cnt = 0;
	arrayp = NULL;
	rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
	    (DDI_PROP_DONTPASS), buffer, &arrayp, &cnt);

	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		/* Check for the global vport setting */
		cnt = 0;
		arrayp = NULL;
		rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
		    (DDI_PROP_DONTPASS), "vport", &arrayp, &cnt);
	}
	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		return;
	}
	for (i = 0; i < cnt; i++) {
		errors = 0;
		s = (uint8_t *)arrayp[i];

		if (!s) {
			break;
		}
		np = (uint8_t *)&pwwpn;
		for (j = 0; j < sizeof (NAME_TYPE); j++) {
			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum = ((c1 - '0') << 4);
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum = ((c1 - 'a' + 10) << 4);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum = ((c1 - 'A' + 10) << 4);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_debug_msg,
				    "Config error: Invalid PWWPN found. "
				    "entry=%d byte=%d hi_nibble=%c", i, j, c1);
				errors++;
			}

			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum |= (c1 - '0');
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum |= (c1 - 'a' + 10);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum |= (c1 - 'A' + 10);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_debug_msg,
				    "Config error: Invalid PWWPN found. "
				    "entry=%d byte=%d lo_nibble=%c", i, j, c1);
				errors++;
			}

			*np++ = sum;
		}

		if (*s++ != ':') {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
			    "Config error: Invalid delimiter after PWWPN. "
			    "entry=%d", i);
			goto out;
		}
		np = (uint8_t *)&wwnn;
		for (j = 0; j < sizeof (NAME_TYPE); j++) {
			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum = ((c1 - '0') << 4);
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum = ((c1 - 'a' + 10) << 4);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum = ((c1 - 'A' + 10) << 4);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_debug_msg,
				    "Config error: Invalid WWNN found. "
				    "entry=%d byte=%d hi_nibble=%c", i, j, c1);
				errors++;
			}

			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum |= (c1 - '0');
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum |= (c1 - 'a' + 10);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum |= (c1 - 'A' + 10);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_debug_msg,
				    "Config error: Invalid WWNN found. "
				    "entry=%d byte=%d lo_nibble=%c", i, j, c1);
				errors++;
			}

			*np++ = sum;
		}

		if (*s++ != ':') {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
			    "Config error: Invalid delimiter after WWNN. "
			    "entry=%d", i);
			goto out;
		}
		np = (uint8_t *)&wwpn;
		for (j = 0; j < sizeof (NAME_TYPE); j++) {
			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum = ((c1 - '0') << 4);
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum = ((c1 - 'a' + 10) << 4);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum = ((c1 - 'A' + 10) << 4);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_debug_msg,
				    "Config error: Invalid WWPN found. "
				    "entry=%d byte=%d hi_nibble=%c", i, j, c1);

				errors++;
			}

			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum |= (c1 - '0');
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum |= (c1 - 'a' + 10);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum |= (c1 - 'A' + 10);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_debug_msg,
				    "Config error: Invalid WWPN found. "
				    "entry=%d byte=%d lo_nibble=%c", i, j, c1);

				errors++;
			}

			*np++ = sum;
		}

		if (*s++ != ':') {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
			    "Config error: Invalid delimiter after WWPN. "
			    "entry=%d", i);

			goto out;
		}
		sum = 0;
		do {
			c1 = *s++;
			if ((c1 < '0') || (c1 > '9')) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_debug_msg,
				    "Config error: Invalid VPI found. "
				    "entry=%d c=%c vpi=%d", i, c1, sum);

				goto out;
			}
			sum = (sum * 10) + (c1 - '0');

		} while (*s != 0);

		vpi = sum;

		if (errors) {
			continue;
		}
		/* Entry has been read */

		/*
		 * Check if the physical port wwpn matches our physical port
		 * wwpn
		 */
		if (bcmp((caddr_t)&hba->wwpn, (caddr_t)&pwwpn, 8)) {
			continue;
		}
		/* Check vpi range */
		if ((vpi == 0) || (vpi >= MAX_VPORTS)) {
			continue;
		}
		/* Check if port has already been configured */
		if (hba->port[vpi].flag & EMLXS_PORT_CONFIG) {
			continue;
		}
		/* Set the highest configured vpi */
		if (vpi >= hba->vpi_high) {
			hba->vpi_high = vpi;
		}
		bcopy((caddr_t)&wwnn, (caddr_t)&hba->port[vpi].wwnn,
		    sizeof (NAME_TYPE));
		bcopy((caddr_t)&wwpn, (caddr_t)&hba->port[vpi].wwpn,
		    sizeof (NAME_TYPE));

		if (hba->port[vpi].snn[0] == 0) {
			(void) strncpy((caddr_t)hba->port[vpi].snn,
			    (caddr_t)hba->snn, 256);
		}
		if (hba->port[vpi].spn[0] == 0) {
			(void) sprintf((caddr_t)hba->port[vpi].spn,
			    "%s VPort-%d", (caddr_t)hba->spn, vpi);
		}
		hba->port[vpi].flag |= (EMLXS_PORT_CONFIG | EMLXS_PORT_ENABLE);

#ifdef NPIV_SUPPORT
		if (cfg[CFG_VPORT_RESTRICTED].current) {
			hba->port[vpi].flag |= EMLXS_PORT_RESTRICTED;
		}
#endif	/* NPIV_SUPPORT */

		/*
		 * wwn1 = (uint8_t*)&wwpn; wwn2 = (uint8_t*)&wwnn;
		 *
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		 * "vport[%d]: WWPN:%02X%02X%02X%02X%02X%02X%02X%02X
		 * WWNN:%02X%02X%02X%02X%02X%02X%02X%02X", vpi, wwn1[0],
		 * wwn1[1], wwn1[2], wwn1[3], wwn1[4], wwn1[5], wwn1[6],
		 * wwn1[7], wwn2[0], wwn2[1], wwn2[2], wwn2[3], wwn2[4],
		 * wwn2[5], wwn2[6], wwn2[7]);
		 */
	}

out:

	(void) ddi_prop_free((void *) arrayp);
	return;

} /* emlxs_read_vport_prop() */

#endif	/* SLI3_SUPPORT */



extern char *
emlxs_wwn_xlate(char *buffer, uint8_t *wwn)
{
	(void) sprintf(buffer, "%02x%02x%02x%02x%02x%02x%02x%02x",
	    wwn[0] & 0xff, wwn[1] & 0xff, wwn[2] & 0xff, wwn[3] & 0xff,
	    wwn[4] & 0xff, wwn[5] & 0xff, wwn[6] & 0xff, wwn[7] & 0xff);

	return (buffer);

} /* emlxs_wwn_xlate() */


/* This is called at port online and offline */
extern void
emlxs_ub_flush(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	emlxs_ub_priv_t *next;

	/* Return if nothing to do */
	if (!port->ub_wait_head) {
		return;
	}
	mutex_enter(&EMLXS_PORT_LOCK);
	ub_priv = port->ub_wait_head;
	port->ub_wait_head = NULL;
	port->ub_wait_tail = NULL;
	mutex_exit(&EMLXS_PORT_LOCK);

	while (ub_priv) {
		next = ub_priv->next;
		ubp = ub_priv->ubp;

		/* Check if ULP is online and we have a callback function */
		if ((port->ulp_statec != FC_STATE_OFFLINE) &&
		    port->ulp_unsol_cb) {
			/* Send ULP the ub buffer */
			port->ulp_unsol_cb(port->ulp_handle, ubp,
			    ubp->ub_frame.type);
		} else {	/* Drop the buffer */
			(void) emlxs_ub_release(port, 1, &ubp->ub_token);
		}

		ub_priv = next;

	}	/* while() */

	return;

} /* emlxs_ub_flush() */


extern void
emlxs_ub_callback(emlxs_port_t *port, fc_unsol_buf_t *ubp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_ub_priv_t *ub_priv;

	ub_priv = ubp->ub_fca_private;

	/* Check if ULP is online */
	if (port->ulp_statec != FC_STATE_OFFLINE) {
		if (port->ulp_unsol_cb) {
			port->ulp_unsol_cb(port->ulp_handle, ubp,
			    ubp->ub_frame.type);
		} else {
			(void) emlxs_ub_release(port, 1, &ubp->ub_token);
		}

		return;
	} else {	/* ULP offline */
		if (hba->state >= FC_LINK_UP) {
			/* Add buffer to queue tail */
			mutex_enter(&EMLXS_PORT_LOCK);

			if (port->ub_wait_tail) {
				port->ub_wait_tail->next = ub_priv;
			}
			port->ub_wait_tail = ub_priv;

			if (!port->ub_wait_head) {
				port->ub_wait_head = ub_priv;
			}
			mutex_exit(&EMLXS_PORT_LOCK);
		} else {
			(void) emlxs_ub_release(port, 1, &ubp->ub_token);
		}
	}

	return;

} /* emlxs_ub_callback() */


static uint32_t
emlxs_integrity_check(emlxs_hba_t *hba)
{
	/* emlxs_port_t *port = &PPORT; */
	uint32_t size;
	uint32_t errors = 0;
	int ddiinst = hba->ddiinst;

	size = 16;
	if (sizeof (ULP_BDL) != size) {
		cmn_err(CE_WARN, "?%s%d: ULP_BDL size incorrect.  %d != 16",
		    DRIVER_NAME, ddiinst, (int)sizeof (ULP_BDL));

		errors++;
	}
	size = 8;
	if (sizeof (ULP_BDE) != size) {
		cmn_err(CE_WARN, "?%s%d: ULP_BDE size incorrect.  %d != 8",
		    DRIVER_NAME, ddiinst, (int)sizeof (ULP_BDE));

		errors++;
	}
	size = 12;
	if (sizeof (ULP_BDE64) != size) {
		cmn_err(CE_WARN, "?%s%d: ULP_BDE64 size incorrect.  %d != 12",
		    DRIVER_NAME, ddiinst, (int)sizeof (ULP_BDE64));

		errors++;
	}
	size = 16;
	if (sizeof (HBQE_t) != size) {
		cmn_err(CE_WARN, "?%s%d: HBQE size incorrect.  %d != 16",
		    DRIVER_NAME, ddiinst, (int)sizeof (HBQE_t));

		errors++;
	}
	size = 8;
	if (sizeof (HGP) != size) {
		cmn_err(CE_WARN, "?%s%d: HGP size incorrect.  %d != 8",
		    DRIVER_NAME, ddiinst, (int)sizeof (HGP));

		errors++;
	}
	if (sizeof (PGP) != size) {
		cmn_err(CE_WARN, "?%s%d: PGP size incorrect.  %d != 8",
		    DRIVER_NAME, ddiinst, (int)sizeof (PGP));

		errors++;
	}
	size = 4;
	if (sizeof (WORD5) != size) {
		cmn_err(CE_WARN, "?%s%d: WORD5 size incorrect.  %d != 4",
		    DRIVER_NAME, ddiinst, (int)sizeof (WORD5));

		errors++;
	}
	size = 124;
	if (sizeof (MAILVARIANTS) != size) {
		cmn_err(CE_WARN, "?%s%d: MAILVARIANTS size incorrect.  "
		    "%d != 124", DRIVER_NAME, ddiinst,
		    (int)sizeof (MAILVARIANTS));

		errors++;
	}
	size = 128;
	if (sizeof (SLI1_DESC) != size) {
		cmn_err(CE_WARN, "?%s%d: SLI1_DESC size incorrect.  %d != 128",
		    DRIVER_NAME, ddiinst, (int)sizeof (SLI1_DESC));

		errors++;
	}
	if (sizeof (SLI2_DESC) != size) {
		cmn_err(CE_WARN, "?%s%d: SLI2_DESC size incorrect.  %d != 128",
		    DRIVER_NAME, ddiinst, (int)sizeof (SLI2_DESC));

		errors++;
	}
	size = MBOX_SIZE;
	if (sizeof (MAILBOX) != size) {
		cmn_err(CE_WARN, "?%s%d: MAILBOX size incorrect.  %d != %d",
		    DRIVER_NAME, ddiinst, (int)sizeof (MAILBOX), MBOX_SIZE);

		errors++;
	}
	size = PCB_SIZE;
	if (sizeof (PCB) != size) {
		cmn_err(CE_WARN, "?%s%d: PCB size incorrect.  %d != %d",
		    DRIVER_NAME, ddiinst, (int)sizeof (PCB), PCB_SIZE);

		errors++;
	}
	size = 260;
	if (sizeof (ATTRIBUTE_ENTRY) != size) {
		cmn_err(CE_WARN, "?%s%d: ATTRIBUTE_ENTRY size incorrect.  "
		    "%d != 260", DRIVER_NAME, ddiinst,
		    (int)sizeof (ATTRIBUTE_ENTRY));

		errors++;
	}
	size = SLI_SLIM1_SIZE;
	if (sizeof (SLIM1) != size) {
		cmn_err(CE_WARN, "?%s%d: SLIM1 size incorrect.  %d != %d",
		    DRIVER_NAME, ddiinst, (int)sizeof (SLIM1), SLI_SLIM1_SIZE);

		errors++;
	}
#ifdef SLI3_SUPPORT
	size = SLI3_IOCB_CMD_SIZE;
	if (sizeof (IOCB) != size) {
		cmn_err(CE_WARN, "?%s%d: IOCB size incorrect.  %d != %d",
		    DRIVER_NAME, ddiinst, (int)sizeof (IOCB),
		    SLI3_IOCB_CMD_SIZE);

		errors++;
	}
#else
	size = SLI2_IOCB_CMD_SIZE;
	if (sizeof (IOCB) != size) {
		cmn_err(CE_WARN, "?%s%d: IOCB size incorrect.  %d != %d",
		    DRIVER_NAME, ddiinst, (int)sizeof (IOCB),
		    SLI2_IOCB_CMD_SIZE);

		errors++;
	}
#endif	/* SLI3_SUPPORT */

	size = SLI_SLIM2_SIZE;
	if (sizeof (SLIM2) != size) {
		cmn_err(CE_WARN, "?%s%d: SLIM2 size incorrect.  %d != %d",
		    DRIVER_NAME, ddiinst, (int)sizeof (SLIM2),
		    SLI_SLIM2_SIZE);

		errors++;
	}
	return (errors);

} /* emlxs_integrity_check() */
