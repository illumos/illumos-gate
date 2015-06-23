/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#define	DEF_ICFG	1

#include <emlxs.h>
#include <emlxs_version.h>


static char emlxs_copyright[] = EMLXS_COPYRIGHT;
char emlxs_revision[] = EMLXS_REVISION;
char emlxs_version[] = EMLXS_VERSION;
char emlxs_name[] = EMLXS_NAME;
char emlxs_label[] = EMLXS_LABEL;

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_SOLARIS_C);

#ifdef MENLO_SUPPORT
static int32_t  emlxs_send_menlo(emlxs_port_t *port, emlxs_buf_t *sbp);
#endif /* MENLO_SUPPORT */

static void	emlxs_fca_attach(emlxs_hba_t *hba);
static void	emlxs_fca_detach(emlxs_hba_t *hba);
static void	emlxs_drv_banner(emlxs_hba_t *hba);

static int32_t	emlxs_get_props(emlxs_hba_t *hba);
static int32_t	emlxs_send_fcp_cmd(emlxs_port_t *port, emlxs_buf_t *sbp,
		    uint32_t *pkt_flags);
static int32_t	emlxs_send_fct_status(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t	emlxs_send_fct_abort(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t	emlxs_send_ip(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t	emlxs_send_els(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t	emlxs_send_els_rsp(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t	emlxs_send_ct(emlxs_port_t *port, emlxs_buf_t *sbp);
static int32_t	emlxs_send_ct_rsp(emlxs_port_t *port, emlxs_buf_t *sbp);
static uint32_t emlxs_add_instance(int32_t ddiinst);
static void	emlxs_iodone(emlxs_buf_t *sbp);
static int	emlxs_pm_lower_power(dev_info_t *dip);
static int	emlxs_pm_raise_power(dev_info_t *dip);
static void	emlxs_driver_remove(dev_info_t *dip, uint32_t init_flag,
		    uint32_t failed);
static void	emlxs_iodone_server(void *arg1, void *arg2, void *arg3);
static uint32_t	emlxs_integrity_check(emlxs_hba_t *hba);
static uint32_t	emlxs_test(emlxs_hba_t *hba, uint32_t test_code,
		    uint32_t args, uint32_t *arg);

#if (EMLXS_MODREV >= EMLXS_MODREV3) && (EMLXS_MODREV <= EMLXS_MODREV4)
static void	emlxs_read_vport_prop(emlxs_hba_t *hba);
#endif	/* EMLXS_MODREV3 && EMLXS_MODREV4 */

static void	emlxs_mode_init_masks(emlxs_hba_t *hba);


extern int
emlxs_msiid_to_chan(emlxs_hba_t *hba, int msi_id);
extern int
emlxs_select_msiid(emlxs_hba_t *hba);
extern void
emlxs_sli4_zero_queue_stat(emlxs_hba_t *hba);

/*
 * Driver Entry Routines.
 */
static int32_t	emlxs_detach(dev_info_t *, ddi_detach_cmd_t);
static int32_t	emlxs_attach(dev_info_t *, ddi_attach_cmd_t);
static int32_t	emlxs_open(dev_t *, int32_t, int32_t, cred_t *);
static int32_t	emlxs_close(dev_t, int32_t, int32_t, cred_t *);
static int32_t	emlxs_ioctl(dev_t, int32_t, intptr_t, int32_t,
		    cred_t *, int32_t *);
static int32_t	emlxs_info(dev_info_t *, ddi_info_cmd_t, void *, void **);


/*
 * FC_AL Transport Functions.
 */
static opaque_t	emlxs_fca_bind_port(dev_info_t *, fc_fca_port_info_t *,
		    fc_fca_bind_info_t *);
static void	emlxs_fca_unbind_port(opaque_t);
static void	emlxs_initialize_pkt(emlxs_port_t *, emlxs_buf_t *);
static int32_t	emlxs_fca_get_cap(opaque_t, char *, void *);
static int32_t	emlxs_fca_set_cap(opaque_t, char *, void *);
static int32_t	emlxs_fca_get_map(opaque_t, fc_lilpmap_t *);
static int32_t	emlxs_fca_ub_alloc(opaque_t, uint64_t *, uint32_t,
		    uint32_t *, uint32_t);
static int32_t	emlxs_fca_ub_free(opaque_t, uint32_t, uint64_t *);

static opaque_t	emlxs_fca_get_device(opaque_t, fc_portid_t);
static int32_t	emlxs_fca_notify(opaque_t, uint32_t);
static void	emlxs_ub_els_reject(emlxs_port_t *, fc_unsol_buf_t *);

/*
 * Driver Internal Functions.
 */

static void	emlxs_poll(emlxs_port_t *, emlxs_buf_t *);
static int32_t	emlxs_power(dev_info_t *, int32_t, int32_t);
#ifdef EMLXS_I386
#ifdef S11
static int32_t	emlxs_quiesce(dev_info_t *);
#endif /* S11 */
#endif /* EMLXS_I386 */
static int32_t	emlxs_hba_resume(dev_info_t *);
static int32_t	emlxs_hba_suspend(dev_info_t *);
static int32_t	emlxs_hba_detach(dev_info_t *);
static int32_t	emlxs_hba_attach(dev_info_t *);
static void	emlxs_lock_destroy(emlxs_hba_t *);
static void	emlxs_lock_init(emlxs_hba_t *);

char *emlxs_pm_components[] = {
	"NAME=" DRIVER_NAME "000",
	"0=Device D3 State",
	"1=Device D0 State"
};


/*
 * Default emlx dma limits
 */
ddi_dma_lim_t emlxs_dma_lim = {
	(uint32_t)0,				/* dlim_addr_lo */
	(uint32_t)0xffffffff,			/* dlim_addr_hi */
	(uint_t)0x00ffffff,			/* dlim_cntr_max */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dlim_burstsizes */
	1,					/* dlim_minxfer */
	0x00ffffff				/* dlim_dmaspeed */
};

/*
 * Be careful when using these attributes; the defaults listed below are
 * (almost) the most general case, permitting allocation in almost any
 * way supported by the LightPulse family.  The sole exception is the
 * alignment specified as requiring memory allocation on a 4-byte boundary;
 * the Lightpulse can DMA memory on any byte boundary.
 *
 * The LightPulse family currently is limited to 16M transfers;
 * this restriction affects the dma_attr_count_max and dma_attr_maxxfer fields.
 */
ddi_dma_attr_t emlxs_dma_attr = {
	DMA_ATTR_V0,				/* dma_attr_version */
	(uint64_t)0,				/* dma_attr_addr_lo */
	(uint64_t)0xffffffffffffffff,		/* dma_attr_addr_hi */
	(uint64_t)0x00ffffff,			/* dma_attr_count_max */
	1,					/* dma_attr_align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dma_attr_burstsizes */
	1,					/* dma_attr_minxfer */
	(uint64_t)0x00ffffff,			/* dma_attr_maxxfer */
	(uint64_t)0xffffffff,			/* dma_attr_seg */
	1,					/* dma_attr_sgllen */
	1,					/* dma_attr_granular */
	0					/* dma_attr_flags */
};

ddi_dma_attr_t emlxs_dma_attr_ro = {
	DMA_ATTR_V0,				/* dma_attr_version */
	(uint64_t)0,				/* dma_attr_addr_lo */
	(uint64_t)0xffffffffffffffff,		/* dma_attr_addr_hi */
	(uint64_t)0x00ffffff,			/* dma_attr_count_max */
	1,					/* dma_attr_align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dma_attr_burstsizes */
	1,					/* dma_attr_minxfer */
	(uint64_t)0x00ffffff,			/* dma_attr_maxxfer */
	(uint64_t)0xffffffff,			/* dma_attr_seg */
	1,					/* dma_attr_sgllen */
	1,					/* dma_attr_granular */
	DDI_DMA_RELAXED_ORDERING		/* dma_attr_flags */
};

ddi_dma_attr_t emlxs_dma_attr_1sg = {
	DMA_ATTR_V0,				/* dma_attr_version */
	(uint64_t)0,				/* dma_attr_addr_lo */
	(uint64_t)0xffffffffffffffff,		/* dma_attr_addr_hi */
	(uint64_t)0x00ffffff,			/* dma_attr_count_max */
	1,					/* dma_attr_align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dma_attr_burstsizes */
	1,					/* dma_attr_minxfer */
	(uint64_t)0x00ffffff,			/* dma_attr_maxxfer */
	(uint64_t)0xffffffff,			/* dma_attr_seg */
	1,					/* dma_attr_sgllen */
	1,					/* dma_attr_granular */
	0					/* dma_attr_flags */
};

#if (EMLXS_MODREV >= EMLXS_MODREV3)
ddi_dma_attr_t emlxs_dma_attr_fcip_rsp = {
	DMA_ATTR_V0,				/* dma_attr_version */
	(uint64_t)0,				/* dma_attr_addr_lo */
	(uint64_t)0xffffffffffffffff,		/* dma_attr_addr_hi */
	(uint64_t)0x00ffffff,			/* dma_attr_count_max */
	1,					/* dma_attr_align */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* dma_attr_burstsizes */
	1,					/* dma_attr_minxfer */
	(uint64_t)0x00ffffff,			/* dma_attr_maxxfer */
	(uint64_t)0xffffffff,			/* dma_attr_seg */
	1,					/* dma_attr_sgllen */
	1,					/* dma_attr_granular */
	0					/* dma_attr_flags */
};
#endif	/* >= EMLXS_MODREV3 */

/*
 * DDI access attributes for device
 */
ddi_device_acc_attr_t emlxs_dev_acc_attr = {
	DDI_DEVICE_ATTR_V1,	/* devacc_attr_version		*/
	DDI_STRUCTURE_LE_ACC,	/* PCI is Little Endian		*/
	DDI_STRICTORDER_ACC,	/* devacc_attr_dataorder	*/
	DDI_DEFAULT_ACC		/* devacc_attr_access		*/
};

/*
 * DDI access attributes for data
 */
ddi_device_acc_attr_t emlxs_data_acc_attr = {
	DDI_DEVICE_ATTR_V1,	/* devacc_attr_version		*/
	DDI_NEVERSWAP_ACC,	/* don't swap for Data		*/
	DDI_STRICTORDER_ACC,	/* devacc_attr_dataorder	*/
	DDI_DEFAULT_ACC		/* devacc_attr_access		*/
};

/*
 * Fill in the FC Transport structure,
 * as defined in the Fibre Channel Transport Programmming Guide.
 */
#if (EMLXS_MODREV == EMLXS_MODREV5)
	static fc_fca_tran_t emlxs_fca_tran = {
	FCTL_FCA_MODREV_5, 		/* fca_version, with SUN NPIV support */
	MAX_VPORTS,			/* fca numerb of ports */
	sizeof (emlxs_buf_t),		/* fca pkt size */
	2048,				/* fca cmd max */
	&emlxs_dma_lim,			/* fca dma limits */
	0,				/* fca iblock, to be filled in later */
	&emlxs_dma_attr,		/* fca dma attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcp cmd attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcp rsp attributes */
	&emlxs_dma_attr_ro,		/* fca dma fcp data attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcip cmd attributes */
	&emlxs_dma_attr_fcip_rsp,	/* fca dma fcip rsp attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcsm cmd attributes */
	&emlxs_dma_attr,		/* fca dma fcsm rsp attributes */
	&emlxs_data_acc_attr,   	/* fca access atributes */
	0,				/* fca_num_npivports */
	{0, 0, 0, 0, 0, 0, 0, 0},	/* Physical port WWPN */
	emlxs_fca_bind_port,
	emlxs_fca_unbind_port,
	emlxs_fca_pkt_init,
	emlxs_fca_pkt_uninit,
	emlxs_fca_transport,
	emlxs_fca_get_cap,
	emlxs_fca_set_cap,
	emlxs_fca_get_map,
	emlxs_fca_transport,
	emlxs_fca_ub_alloc,
	emlxs_fca_ub_free,
	emlxs_fca_ub_release,
	emlxs_fca_pkt_abort,
	emlxs_fca_reset,
	emlxs_fca_port_manage,
	emlxs_fca_get_device,
	emlxs_fca_notify
};
#endif	/* EMLXS_MODREV5 */


#if (EMLXS_MODREV == EMLXS_MODREV4)
static fc_fca_tran_t emlxs_fca_tran = {
	FCTL_FCA_MODREV_4,		/* fca_version */
	MAX_VPORTS,			/* fca numerb of ports */
	sizeof (emlxs_buf_t),		/* fca pkt size */
	2048,				/* fca cmd max */
	&emlxs_dma_lim,			/* fca dma limits */
	0,				/* fca iblock, to be filled in later */
	&emlxs_dma_attr,		/* fca dma attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcp cmd attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcp rsp attributes */
	&emlxs_dma_attr_ro,		/* fca dma fcp data attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcip cmd attributes */
	&emlxs_dma_attr_fcip_rsp,	/* fca dma fcip rsp attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcsm cmd attributes */
	&emlxs_dma_attr,		/* fca dma fcsm rsp attributes */
	&emlxs_data_acc_attr,		/* fca access atributes */
	emlxs_fca_bind_port,
	emlxs_fca_unbind_port,
	emlxs_fca_pkt_init,
	emlxs_fca_pkt_uninit,
	emlxs_fca_transport,
	emlxs_fca_get_cap,
	emlxs_fca_set_cap,
	emlxs_fca_get_map,
	emlxs_fca_transport,
	emlxs_fca_ub_alloc,
	emlxs_fca_ub_free,
	emlxs_fca_ub_release,
	emlxs_fca_pkt_abort,
	emlxs_fca_reset,
	emlxs_fca_port_manage,
	emlxs_fca_get_device,
	emlxs_fca_notify
};
#endif	/* EMLXS_MODEREV4 */


#if (EMLXS_MODREV == EMLXS_MODREV3)
static fc_fca_tran_t emlxs_fca_tran = {
	FCTL_FCA_MODREV_3,		/* fca_version */
	MAX_VPORTS,			/* fca numerb of ports */
	sizeof (emlxs_buf_t),		/* fca pkt size */
	2048,				/* fca cmd max */
	&emlxs_dma_lim,			/* fca dma limits */
	0,				/* fca iblock, to be filled in later */
	&emlxs_dma_attr,		/* fca dma attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcp cmd attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcp rsp attributes */
	&emlxs_dma_attr_ro,		/* fca dma fcp data attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcip cmd attributes */
	&emlxs_dma_attr_fcip_rsp,	/* fca dma fcip rsp attributes */
	&emlxs_dma_attr_1sg,		/* fca dma fcsm cmd attributes */
	&emlxs_dma_attr,		/* fca dma fcsm rsp attributes */
	&emlxs_data_acc_attr,		/* fca access atributes */
	emlxs_fca_bind_port,
	emlxs_fca_unbind_port,
	emlxs_fca_pkt_init,
	emlxs_fca_pkt_uninit,
	emlxs_fca_transport,
	emlxs_fca_get_cap,
	emlxs_fca_set_cap,
	emlxs_fca_get_map,
	emlxs_fca_transport,
	emlxs_fca_ub_alloc,
	emlxs_fca_ub_free,
	emlxs_fca_ub_release,
	emlxs_fca_pkt_abort,
	emlxs_fca_reset,
	emlxs_fca_port_manage,
	emlxs_fca_get_device,
	emlxs_fca_notify
};
#endif	/* EMLXS_MODREV3 */


#if (EMLXS_MODREV == EMLXS_MODREV2)
static fc_fca_tran_t emlxs_fca_tran = {
	FCTL_FCA_MODREV_2,		/* fca_version */
	MAX_VPORTS,			/* number of ports */
	sizeof (emlxs_buf_t),		/* pkt size */
	2048,				/* max cmds */
	&emlxs_dma_lim,			/* DMA limits */
	0,				/* iblock, to be filled in later */
	&emlxs_dma_attr,		/* dma attributes */
	&emlxs_data_acc_attr,		/* access atributes */
	emlxs_fca_bind_port,
	emlxs_fca_unbind_port,
	emlxs_fca_pkt_init,
	emlxs_fca_pkt_uninit,
	emlxs_fca_transport,
	emlxs_fca_get_cap,
	emlxs_fca_set_cap,
	emlxs_fca_get_map,
	emlxs_fca_transport,
	emlxs_fca_ub_alloc,
	emlxs_fca_ub_free,
	emlxs_fca_ub_release,
	emlxs_fca_pkt_abort,
	emlxs_fca_reset,
	emlxs_fca_port_manage,
	emlxs_fca_get_device,
	emlxs_fca_notify
};
#endif	/* EMLXS_MODREV2 */


/*
 * state pointer which the implementation uses as a place to
 * hang a set of per-driver structures;
 *
 */
void		*emlxs_soft_state = NULL;

/*
 * Driver Global variables.
 */
int32_t		emlxs_scsi_reset_delay = 3000;	/* milliseconds */

emlxs_device_t  emlxs_device;

uint32_t	emlxs_instance[MAX_FC_BRDS];	/* uses emlxs_device.lock */
uint32_t	emlxs_instance_count = 0;	/* uses emlxs_device.lock */
uint32_t	emlxs_instance_flag = 0;	/* uses emlxs_device.lock */
#define	EMLXS_FW_SHOW		0x00000001


/*
 * CB ops vector.  Used for administration only.
 */
static struct cb_ops emlxs_cb_ops = {
	emlxs_open,	/* cb_open	*/
	emlxs_close,	/* cb_close	*/
	nodev,		/* cb_strategy	*/
	nodev,		/* cb_print	*/
	nodev,		/* cb_dump	*/
	nodev,		/* cb_read	*/
	nodev,		/* cb_write	*/
	emlxs_ioctl,	/* cb_ioctl	*/
	nodev,		/* cb_devmap	*/
	nodev,		/* cb_mmap	*/
	nodev,		/* cb_segmap	*/
	nochpoll,	/* cb_chpoll	*/
	ddi_prop_op,	/* cb_prop_op	*/
	0,		/* cb_stream	*/
#ifdef _LP64
	D_64BIT | D_HOTPLUG | D_MP | D_NEW,	/* cb_flag */
#else
	D_HOTPLUG | D_MP | D_NEW,		/* cb_flag */
#endif
	CB_REV,		/* rev		*/
	nodev,		/* cb_aread	*/
	nodev		/* cb_awrite	*/
};

static struct dev_ops emlxs_ops = {
	DEVO_REV,	/* rev */
	0,	/* refcnt */
	emlxs_info,	/* getinfo	*/
	nulldev,	/* identify	*/
	nulldev,	/* probe	*/
	emlxs_attach,	/* attach	*/
	emlxs_detach,	/* detach	*/
	nodev,		/* reset	*/
	&emlxs_cb_ops,	/* devo_cb_ops	*/
	NULL,		/* devo_bus_ops */
	emlxs_power,	/* power ops	*/
#ifdef EMLXS_I386
#ifdef S11
	emlxs_quiesce,	/* quiesce	*/
#endif /* S11 */
#endif /* EMLXS_I386 */
};

#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

#ifdef SAN_DIAG_SUPPORT
extern kmutex_t		emlxs_sd_bucket_mutex;
extern sd_bucket_info_t	emlxs_sd_bucket;
#endif /* SAN_DIAG_SUPPORT */

/*
 * Module linkage information for the kernel.
 */
static struct modldrv emlxs_modldrv = {
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
/* Default:	FC_PKT_TRAN_ERROR,	FC_REASON_ABORTED, */
/*		FC_EXPLN_NONE,		FC_ACTION_RETRYABLE */

emlxs_xlat_err_t emlxs_iostat_tbl[] = {
/* 	{f/w code, pkt_state, pkt_reason, 	*/
/* 		pkt_expln, pkt_action}		*/

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
	 * This is a default entry.
	 * The real codes are written dynamically in emlxs_els.c
	 */
	/* 0x09 */
	{IOSTAT_LS_RJT, FC_PKT_LS_RJT, FC_REASON_CMD_UNABLE,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* Special error code */
	/* 0x10 */
	{IOSTAT_DATA_OVERRUN, FC_PKT_TRAN_ERROR, FC_REASON_OVERRUN,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* Special error code */
	/* 0x11 */
	{IOSTAT_DATA_UNDERRUN, FC_PKT_TRAN_ERROR, FC_REASON_ABORTED,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* Special error code */
	/* 0x12 */
	{IOSTAT_RSP_INVALID, FC_PKT_TRAN_ERROR, FC_REASON_ABORTED,
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

#define	IOSTAT_MAX (sizeof (emlxs_iostat_tbl)/sizeof (emlxs_xlat_err_t))


/* We only need to add entries for non-default return codes. */
/* Entries do not need to be in order. */
/* Default:	FC_PKT_TRAN_ERROR,	FC_REASON_ABORTED, */
/*		FC_EXPLN_NONE,		FC_ACTION_RETRYABLE} */

emlxs_xlat_err_t emlxs_ioerr_tbl[] = {
/*	{f/w code, pkt_state, pkt_reason,	*/
/*		pkt_expln, pkt_action}		*/

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
	{IOERR_ILLEGAL_COMMAND,	FC_PKT_LOCAL_RJT, FC_REASON_ILLEGAL_REQ,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x07 */
	{IOERR_XCHG_DROPPED, FC_PKT_LOCAL_RJT,	FC_REASON_XCHG_DROPPED,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x08 */
	{IOERR_ILLEGAL_FIELD, FC_PKT_LOCAL_RJT,	FC_REASON_ILLEGAL_REQ,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x0B */
	{IOERR_RCV_BUFFER_WAITING, FC_PKT_LOCAL_RJT, FC_REASON_NOMEM,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x0D */
	{IOERR_TX_DMA_FAILED, FC_PKT_LOCAL_RJT,	FC_REASON_DMA_ERROR,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x0E */
	{IOERR_RX_DMA_FAILED, FC_PKT_LOCAL_RJT,	FC_REASON_DMA_ERROR,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x0F */
	{IOERR_ILLEGAL_FRAME, FC_PKT_LOCAL_RJT,	FC_REASON_ILLEGAL_FRAME,
		FC_EXPLN_NONE, FC_ACTION_RETRYABLE},

	/* 0x11 */
	{IOERR_NO_RESOURCES, FC_PKT_LOCAL_RJT,	FC_REASON_NOMEM,
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



emlxs_table_t emlxs_error_table[] = {
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


emlxs_table_t emlxs_state_table[] = {
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
	{IOSTAT_CMD_REJECT,		"Cmd reject."},
	{IOSTAT_FCP_TGT_LENCHK, "TGT length check."},
	{IOSTAT_NEED_BUFF_ENTRY, "Need buffer entry."},
	{IOSTAT_DATA_UNDERRUN, "Data underrun."},
	{IOSTAT_DATA_OVERRUN,  "Data overrun."},
	{IOSTAT_RSP_INVALID,  "Response Invalid."},

};	/* emlxs_state_table */


#ifdef MENLO_SUPPORT
emlxs_table_t emlxs_menlo_cmd_table[] = {
	{MENLO_CMD_INITIALIZE,		"MENLO_INIT"},
	{MENLO_CMD_FW_DOWNLOAD,		"MENLO_FW_DOWNLOAD"},
	{MENLO_CMD_READ_MEMORY,		"MENLO_READ_MEM"},
	{MENLO_CMD_WRITE_MEMORY,	"MENLO_WRITE_MEM"},
	{MENLO_CMD_FTE_INSERT,		"MENLO_FTE_INSERT"},
	{MENLO_CMD_FTE_DELETE,		"MENLO_FTE_DELETE"},

	{MENLO_CMD_GET_INIT,		"MENLO_GET_INIT"},
	{MENLO_CMD_GET_CONFIG,		"MENLO_GET_CONFIG"},
	{MENLO_CMD_GET_PORT_STATS,	"MENLO_GET_PORT_STATS"},
	{MENLO_CMD_GET_LIF_STATS,	"MENLO_GET_LIF_STATS"},
	{MENLO_CMD_GET_ASIC_STATS,	"MENLO_GET_ASIC_STATS"},
	{MENLO_CMD_GET_LOG_CONFIG,	"MENLO_GET_LOG_CFG"},
	{MENLO_CMD_GET_LOG_DATA,	"MENLO_GET_LOG_DATA"},
	{MENLO_CMD_GET_PANIC_LOG,	"MENLO_GET_PANIC_LOG"},
	{MENLO_CMD_GET_LB_MODE,		"MENLO_GET_LB_MODE"},

	{MENLO_CMD_SET_PAUSE,		"MENLO_SET_PAUSE"},
	{MENLO_CMD_SET_FCOE_COS,	"MENLO_SET_FCOE_COS"},
	{MENLO_CMD_SET_UIF_PORT_TYPE,	"MENLO_SET_UIF_TYPE"},

	{MENLO_CMD_DIAGNOSTICS,		"MENLO_DIAGNOSTICS"},
	{MENLO_CMD_LOOPBACK,		"MENLO_LOOPBACK"},

	{MENLO_CMD_RESET,		"MENLO_RESET"},
	{MENLO_CMD_SET_MODE,		"MENLO_SET_MODE"}

};	/* emlxs_menlo_cmd_table */

emlxs_table_t emlxs_menlo_rsp_table[] = {
	{MENLO_RSP_SUCCESS,		"SUCCESS"},
	{MENLO_ERR_FAILED,		"FAILED"},
	{MENLO_ERR_INVALID_CMD,		"INVALID_CMD"},
	{MENLO_ERR_INVALID_CREDIT,	"INVALID_CREDIT"},
	{MENLO_ERR_INVALID_SIZE,	"INVALID_SIZE"},
	{MENLO_ERR_INVALID_ADDRESS,	"INVALID_ADDRESS"},
	{MENLO_ERR_INVALID_CONTEXT,	"INVALID_CONTEXT"},
	{MENLO_ERR_INVALID_LENGTH,	"INVALID_LENGTH"},
	{MENLO_ERR_INVALID_TYPE,	"INVALID_TYPE"},
	{MENLO_ERR_INVALID_DATA,	"INVALID_DATA"},
	{MENLO_ERR_INVALID_VALUE1,	"INVALID_VALUE1"},
	{MENLO_ERR_INVALID_VALUE2,	"INVALID_VALUE2"},
	{MENLO_ERR_INVALID_MASK,	"INVALID_MASK"},
	{MENLO_ERR_CHECKSUM,		"CHECKSUM_ERROR"},
	{MENLO_ERR_UNKNOWN_FCID,	"UNKNOWN_FCID"},
	{MENLO_ERR_UNKNOWN_WWN,		"UNKNOWN_WWN"},
	{MENLO_ERR_BUSY,		"BUSY"},

};	/* emlxs_menlo_rsp_table */

#endif /* MENLO_SUPPORT */


emlxs_table_t emlxs_mscmd_table[] = {
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


emlxs_table_t emlxs_ctcmd_table[] = {
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
	{SLI_CT_LOOPBACK, "LOOPBACK"} /* Driver special */

};	/* emlxs_ctcmd_table */



emlxs_table_t emlxs_rmcmd_table[] = {
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
	{SLI_CT_LOOPBACK, "LOOPBACK"} /* Driver special */

};	/* emlxs_rmcmd_table */


emlxs_table_t emlxs_elscmd_table[] = {
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
	{ELS_CMD_REC, "REC"},
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


emlxs_table_t emlxs_mode_table[] = {
	{MODE_NONE, "NONE"},
	{MODE_INITIATOR, "INITIATOR"},
	{MODE_TARGET, "TARGET"},
	{MODE_ALL, "INITIATOR | TARGET"}
};	/* emlxs_mode_table */

/*
 *
 *	Device Driver Entry Routines
 *
 */

#ifdef MODSYM_SUPPORT
static void emlxs_fca_modclose();
static int  emlxs_fca_modopen();
emlxs_modsym_t emlxs_modsym;	/* uses emlxs_device.lock */

static int
emlxs_fca_modopen()
{
	int err;

	if (emlxs_modsym.mod_fctl) {
		return (0);
	}

	/* Leadville (fctl) */
	err = 0;
	emlxs_modsym.mod_fctl =
	    ddi_modopen("misc/fctl", KRTLD_MODE_FIRST, &err);
	if (!emlxs_modsym.mod_fctl) {
		cmn_err(CE_WARN,
		    "?%s: misc/fctl: ddi_modopen misc/fctl failed: error=%d",
		    DRIVER_NAME, err);

		goto failed;
	}

	err = 0;
	/* Check if the fctl fc_fca_attach is present */
	emlxs_modsym.fc_fca_attach =
	    (int (*)())ddi_modsym(emlxs_modsym.mod_fctl, "fc_fca_attach",
	    &err);
	if ((void *)emlxs_modsym.fc_fca_attach == NULL) {
		cmn_err(CE_WARN,
		    "?%s: misc/fctl: fc_fca_attach not present", DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fctl fc_fca_detach is present */
	emlxs_modsym.fc_fca_detach =
	    (int (*)())ddi_modsym(emlxs_modsym.mod_fctl, "fc_fca_detach",
	    &err);
	if ((void *)emlxs_modsym.fc_fca_detach == NULL) {
		cmn_err(CE_WARN,
		    "?%s: misc/fctl: fc_fca_detach not present", DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fctl fc_fca_init is present */
	emlxs_modsym.fc_fca_init =
	    (int (*)())ddi_modsym(emlxs_modsym.mod_fctl, "fc_fca_init", &err);
	if ((void *)emlxs_modsym.fc_fca_init == NULL) {
		cmn_err(CE_WARN,
		    "?%s: misc/fctl: fc_fca_init not present", DRIVER_NAME);
		goto failed;
	}

	return (0);

failed:

	emlxs_fca_modclose();

	return (1);


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
	emlxs_modsym.fc_fca_init   = NULL;

	return;

} /* emlxs_fca_modclose() */

#endif /* MODSYM_SUPPORT */



/*
 * Global driver initialization, called once when driver is loaded
 */
int
_init(void)
{
	int ret;

	/*
	 * First init call for this driver,
	 * so initialize the emlxs_dev_ctl structure.
	 */
	bzero(&emlxs_device, sizeof (emlxs_device));

#ifdef MODSYM_SUPPORT
	bzero(&emlxs_modsym, sizeof (emlxs_modsym_t));
#endif /* MODSYM_SUPPORT */

	mutex_init(&emlxs_device.lock, NULL, MUTEX_DRIVER, NULL);

	(void) drv_getparm(LBOLT, &emlxs_device.log_timestamp);
	emlxs_device.drv_timestamp = ddi_get_time();

	for (ret = 0; ret < MAX_FC_BRDS; ret++) {
		emlxs_instance[ret] = (uint32_t)-1;
	}

	/*
	 * Provide for one ddiinst of the emlxs_dev_ctl structure
	 * for each possible board in the system.
	 */
	if ((ret = ddi_soft_state_init(&emlxs_soft_state,
	    sizeof (emlxs_hba_t), MAX_FC_BRDS)) != 0) {
		cmn_err(CE_WARN,
		    "?%s: _init: ddi_soft_state_init failed. rval=%x",
		    DRIVER_NAME, ret);

		return (ret);
	}

#ifdef MODSYM_SUPPORT
	/* Open SFS */
	(void) emlxs_fca_modopen();
#endif /* MODSYM_SUPPORT */

	/* Setup devops for SFS */
	MODSYM(fc_fca_init)(&emlxs_ops);

	if ((ret = mod_install(&emlxs_modlinkage)) != 0) {
		(void) ddi_soft_state_fini(&emlxs_soft_state);
#ifdef MODSYM_SUPPORT
		/* Close SFS */
		emlxs_fca_modclose();
#endif /* MODSYM_SUPPORT */

		return (ret);
	}

#ifdef SAN_DIAG_SUPPORT
	mutex_init(&emlxs_sd_bucket_mutex, NULL, MUTEX_DRIVER, NULL);
#endif /* SAN_DIAG_SUPPORT */

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
		return (ret);
	}
#ifdef MODSYM_SUPPORT
	/* Close SFS */
	emlxs_fca_modclose();
#endif /* MODSYM_SUPPORT */

	/*
	 * Destroy the soft state structure
	 */
	(void) ddi_soft_state_fini(&emlxs_soft_state);

	/* Destroy the global device lock */
	mutex_destroy(&emlxs_device.lock);

#ifdef SAN_DIAG_SUPPORT
	mutex_destroy(&emlxs_sd_bucket_mutex);
#endif /* SAN_DIAG_SUPPORT */

	return (ret);

} /* _fini() */



int
_info(struct modinfo *modinfop)
{

	return (mod_info(&emlxs_modlinkage, modinfop));

} /* _info() */


/*
 * Attach an ddiinst of an emlx host adapter.
 * Allocate data structures, initialize the adapter and we're ready to fly.
 */
static int
emlxs_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	emlxs_hba_t *hba;
	int ddiinst;
	int emlxinst;
	int rval;

	switch (cmd) {
	case DDI_ATTACH:
		/* If successful this will set EMLXS_PM_IN_ATTACH */
		rval = emlxs_hba_attach(dip);
		break;

	case DDI_RESUME:
		/* This will resume the driver */
		rval = emlxs_hba_resume(dip);
		break;

	default:
		rval = DDI_FAILURE;
	}

	if (rval == DDI_SUCCESS) {
		ddiinst = ddi_get_instance(dip);
		emlxinst = emlxs_get_instance(ddiinst);
		hba = emlxs_device.hba[emlxinst];

		if ((hba != NULL) && (hba != (emlxs_hba_t *)-1)) {

			/* Enable driver dump feature */
			mutex_enter(&EMLXS_PORT_LOCK);
			hba->flag |= FC_DUMP_SAFE;
			mutex_exit(&EMLXS_PORT_LOCK);
		}
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

	/* Check driver dump */
	mutex_enter(&EMLXS_PORT_LOCK);

	if (hba->flag & FC_DUMP_ACTIVE) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
		    "detach: Driver busy. Driver dump active.");

		return (DDI_FAILURE);
	}

#ifdef SFCT_SUPPORT
	if ((port->flag & EMLXS_TGT_BOUND) &&
	    ((port->fct_flags & FCT_STATE_PORT_ONLINE) ||
	    (port->fct_flags & FCT_STATE_NOT_ACKED))) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
		    "detach: Driver busy. Target mode active.");

		return (DDI_FAILURE);
	}
#endif /* SFCT_SUPPORT */

	if (port->flag & EMLXS_INI_BOUND) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
		    "detach: Driver busy. Initiator mode active.");

		return (DDI_FAILURE);
	}

	hba->flag &= ~FC_DUMP_SAFE;

	mutex_exit(&EMLXS_PORT_LOCK);

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

	if (rval == DDI_FAILURE) {
		/* Re-Enable driver dump feature */
		mutex_enter(&EMLXS_PORT_LOCK);
		hba->flag |= FC_DUMP_SAFE;
		mutex_exit(&EMLXS_PORT_LOCK);
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

	if (!(port->flag & EMLXS_PORT_ENABLED)) {
		uint8_t dummy_wwn[8] =
		    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

		bcopy((caddr_t)dummy_wwn, (caddr_t)&port->wwnn,
		    sizeof (NAME_TYPE));
		bcopy((caddr_t)dummy_wwn, (caddr_t)&port->wwpn,
		    sizeof (NAME_TYPE));
	}

	if (!(port->flag & EMLXS_PORT_CONFIG)) {
		(void) strncpy((caddr_t)port->snn, (caddr_t)hba->snn,
		    (sizeof (port->snn)-1));
		(void) strncpy((caddr_t)port->spn, (caddr_t)hba->spn,
		    (sizeof (port->spn)-1));
	}

	bcopy((caddr_t)&hba->sparam, (caddr_t)&port->sparam,
	    sizeof (SERV_PARM));
	bcopy((caddr_t)&port->wwnn, (caddr_t)&port->sparam.nodeName,
	    sizeof (NAME_TYPE));
	bcopy((caddr_t)&port->wwpn, (caddr_t)&port->sparam.portName,
	    sizeof (NAME_TYPE));

	return;

} /* emlxs_port_init() */


void
emlxs_disable_pcie_ce_err(emlxs_hba_t *hba)
{
	uint16_t	reg;

	if (!hba->pci_cap_offset[PCI_CAP_ID_PCI_E]) {
		return;
	}

	/* Turn off the Correctable Error Reporting */
	/* (the Device Control Register, bit 0). */
	reg = ddi_get16(hba->pci_acc_handle,
	    (uint16_t *)(hba->pci_addr +
	    hba->pci_cap_offset[PCI_CAP_ID_PCI_E] +
	    PCIE_DEVCTL));

	reg &= ~1;

	(void) ddi_put16(hba->pci_acc_handle,
	    (uint16_t *)(hba->pci_addr +
	    hba->pci_cap_offset[PCI_CAP_ID_PCI_E] +
	    PCIE_DEVCTL),
	    reg);

	return;

} /* emlxs_disable_pcie_ce_err() */


/*
 * emlxs_fca_bind_port
 *
 * Arguments:
 *
 * dip: the dev_info pointer for the ddiinst
 * port_info: pointer to info handed back to the transport
 * bind_info: pointer to info from the transport
 *
 * Return values: a port handle for this port, NULL for failure
 *
 */
static opaque_t
emlxs_fca_bind_port(dev_info_t *dip, fc_fca_port_info_t *port_info,
    fc_fca_bind_info_t *bind_info)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	emlxs_port_t *pport;
	emlxs_port_t *vport;
	int ddiinst;
	emlxs_vpd_t *vpd;
	emlxs_config_t *cfg;
	char *dptr;
	char buffer[16];
	uint32_t length;
	uint32_t len;
	char topology[32];
	char linkspeed[32];
	uint32_t linkstate;

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;
	pport = &PPORT;

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
			    "fca_bind_port: Port %d not supported.",
			    bind_info->port_num);

			mutex_exit(&EMLXS_PORT_LOCK);

			port_info->pi_error = FC_OUTOFBOUNDS;
			return (NULL);
		}
	}

	/* Get true port pointer */
	port = &VPORT(bind_info->port_num);

	/* Make sure the port is not already bound to the transport */
	if (port->flag & EMLXS_INI_BOUND) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_bind_port: Port %d already bound. flag=%x",
		    bind_info->port_num, port->flag);

		mutex_exit(&EMLXS_PORT_LOCK);

		port_info->pi_error = FC_ALREADY;
		return (NULL);
	}

	if (!(pport->flag & EMLXS_INI_ENABLED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_bind_port: Physical port does not support "
		    "initiator mode.");

		mutex_exit(&EMLXS_PORT_LOCK);

		port_info->pi_error = FC_OUTOFBOUNDS;
		return (NULL);
	}

	/* Make sure port enable flag is set */
	/* Just in case fca_port_unbind is called just prior to fca_port_bind */
	/* without a driver attach or resume operation */
	port->flag |= EMLXS_PORT_ENABLED;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_bind_port: Port %d: port_info=%p bind_info=%p",
	    bind_info->port_num, port_info, bind_info);

#if (EMLXS_MODREV >= EMLXS_MODREV5)
	if (bind_info->port_npiv) {
		/* Leadville is telling us about a new virtual port */
		bcopy((caddr_t)&bind_info->port_nwwn, (caddr_t)&port->wwnn,
		    sizeof (NAME_TYPE));
		bcopy((caddr_t)&bind_info->port_pwwn, (caddr_t)&port->wwpn,
		    sizeof (NAME_TYPE));
		if (port->snn[0] == 0) {
			(void) strncpy((caddr_t)port->snn, (caddr_t)hba->snn,
			    (sizeof (port->snn)-1));

		}

		if (port->spn[0] == 0) {
			(void) snprintf((caddr_t)port->spn,
			    (sizeof (port->spn)-1), "%s VPort-%d",
			    (caddr_t)hba->spn, port->vpi);
		}
		port->flag |= EMLXS_PORT_CONFIG;
	}
#endif /* >= EMLXS_MODREV5 */

	/*
	 * Restricted login should apply both physical and
	 * virtual ports.
	 */
	if (cfg[CFG_VPORT_RESTRICTED].current) {
		port->flag |= EMLXS_PORT_RESTRICTED;
	}

	/* Perform generic port initialization */
	emlxs_port_init(port);

	/* Perform SFS specific initialization */
	port->ulp_handle	= bind_info->port_handle;
	port->ulp_statec_cb	= bind_info->port_statec_cb;
	port->ulp_unsol_cb	= bind_info->port_unsol_cb;

	/* Set the bound flag */
	port->flag |= EMLXS_INI_BOUND;
	hba->num_of_ports++;

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		mutex_exit(&EMLXS_PORT_LOCK);
		(void) emlxs_vpi_port_bind_notify(port);
		mutex_enter(&EMLXS_PORT_LOCK);

		linkstate = (port->vpip->state == VPI_STATE_PORT_ONLINE)?
		    FC_LINK_UP:FC_LINK_DOWN;
	} else {
		linkstate = hba->state;
	}

	/* Update the port info structure */

	/* Set the topology and state */
	if (port->mode == MODE_TARGET) {
		port_info->pi_port_state = FC_STATE_OFFLINE;
		port_info->pi_topology = FC_TOP_UNKNOWN;
	} else if ((linkstate < FC_LINK_UP) ||
	    ((port->vpi > 0) && (!(port->flag & EMLXS_PORT_ENABLED) ||
	    !(hba->flag & FC_NPIV_SUPPORTED)))) {
		port_info->pi_port_state = FC_STATE_OFFLINE;
		port_info->pi_topology = FC_TOP_UNKNOWN;
	}
#ifdef MENLO_SUPPORT
	else if (hba->flag & FC_MENLO_MODE) {
		port_info->pi_port_state = FC_STATE_OFFLINE;
		port_info->pi_topology = FC_TOP_UNKNOWN;
	}
#endif /* MENLO_SUPPORT */
	else {
		/* Check for loop topology */
		if (hba->topology == TOPOLOGY_LOOP) {
			port_info->pi_port_state = FC_STATE_LOOP;
			(void) strlcpy(topology, ", loop", sizeof (topology));

			if (hba->flag & FC_FABRIC_ATTACHED) {
				port_info->pi_topology = FC_TOP_PUBLIC_LOOP;
			} else {
				port_info->pi_topology = FC_TOP_PRIVATE_LOOP;
			}
		} else {
			port_info->pi_topology = FC_TOP_FABRIC;
			port_info->pi_port_state = FC_STATE_ONLINE;
			(void) strlcpy(topology, ", fabric", sizeof (topology));
		}

		/* Set the link speed */
		switch (hba->linkspeed) {
		case 0:
			(void) strlcpy(linkspeed, "Gb", sizeof (linkspeed));
			port_info->pi_port_state |= FC_STATE_1GBIT_SPEED;
			break;

		case LA_1GHZ_LINK:
			(void) strlcpy(linkspeed, "1Gb", sizeof (linkspeed));
			port_info->pi_port_state |= FC_STATE_1GBIT_SPEED;
			break;
		case LA_2GHZ_LINK:
			(void) strlcpy(linkspeed, "2Gb", sizeof (linkspeed));
			port_info->pi_port_state |= FC_STATE_2GBIT_SPEED;
			break;
		case LA_4GHZ_LINK:
			(void) strlcpy(linkspeed, "4Gb", sizeof (linkspeed));
			port_info->pi_port_state |= FC_STATE_4GBIT_SPEED;
			break;
		case LA_8GHZ_LINK:
			(void) strlcpy(linkspeed, "8Gb", sizeof (linkspeed));
			port_info->pi_port_state |= FC_STATE_8GBIT_SPEED;
			break;
		case LA_10GHZ_LINK:
			(void) strlcpy(linkspeed, "10Gb", sizeof (linkspeed));
			port_info->pi_port_state |= FC_STATE_10GBIT_SPEED;
			break;
		case LA_16GHZ_LINK:
			(void) strlcpy(linkspeed, "16Gb", sizeof (linkspeed));
			port_info->pi_port_state |= FC_STATE_16GBIT_SPEED;
			break;
		default:
			(void) snprintf(linkspeed, sizeof (linkspeed),
			    "unknown(0x%x)", hba->linkspeed);
			break;
		}

		if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
			/* Adjusting port context for link up messages */
			vport = port;
			port = &PPORT;
			if (vport->vpi == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg,
				    "%s%s, initiator",
				    linkspeed, topology);
			} else if (!(hba->flag & FC_NPIV_LINKUP)) {
				hba->flag |= FC_NPIV_LINKUP;
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_npiv_link_up_msg,
				    "%s%s, initiator", linkspeed, topology);
			}
			port = vport;
		}
	}

	/* PCIE Correctable Error Reporting workaround */
	if (((hba->model_info.chip == EMLXS_BE2_CHIP) ||
	    (hba->model_info.chip == EMLXS_BE3_CHIP)) &&
	    (bind_info->port_num == 0)) {
		emlxs_disable_pcie_ce_err(hba);
	}

	/* Save initial state */
	port->ulp_statec = port_info->pi_port_state;

	/*
	 * The transport needs a copy of the common service parameters
	 * for this port. The transport can get any updates through
	 * the getcap entry point.
	 */
	bcopy((void *) &port->sparam,
	    (void *) &port_info->pi_login_params.common_service,
	    sizeof (SERV_PARM));

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	/* Swap the service parameters for ULP */
	emlxs_swap_service_params((SERV_PARM *)&port_info->pi_login_params.
	    common_service);
#endif /* EMLXS_MODREV2X */

	port_info->pi_login_params.common_service.btob_credit = 0xffff;

	bcopy((void *) &port->wwnn,
	    (void *) &port_info->pi_login_params.node_ww_name,
	    sizeof (NAME_TYPE));

	bcopy((void *) &port->wwpn,
	    (void *) &port_info->pi_login_params.nport_ww_name,
	    sizeof (NAME_TYPE));

	/*
	 * We need to turn off CLASS2 support.
	 * Otherwise, FC transport will use CLASS2 as default class
	 * and never try with CLASS3.
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

	(void) snprintf((char *)port_info->pi_rnid_params.params.global_id,
	    (sizeof (port_info->pi_rnid_params.params.global_id)-1),
	    "%01x%01x%02x%02x%02x%02x%02x%02x%02x", hba->wwpn.nameType,
	    hba->wwpn.IEEEextMsn, hba->wwpn.IEEEextLsb, hba->wwpn.IEEE[0],
	    hba->wwpn.IEEE[1], hba->wwpn.IEEE[2], hba->wwpn.IEEE[3],
	    hba->wwpn.IEEE[4], hba->wwpn.IEEE[5]);

	port_info->pi_rnid_params.params.unit_type  = RNID_HBA;
	port_info->pi_rnid_params.params.port_id    = port->did;
	port_info->pi_rnid_params.params.ip_version = RNID_IPV4;

	/* Initialize the port attributes */
	bzero(&port_info->pi_attrs, sizeof (port_info->pi_attrs));

	(void) strncpy(port_info->pi_attrs.manufacturer, "Emulex",
	    (sizeof (port_info->pi_attrs.manufacturer)-1));

	port_info->pi_rnid_params.status = FC_SUCCESS;

	(void) strncpy(port_info->pi_attrs.serial_number, vpd->serial_num,
	    (sizeof (port_info->pi_attrs.serial_number)-1));

	(void) snprintf(port_info->pi_attrs.firmware_version,
	    (sizeof (port_info->pi_attrs.firmware_version)-1), "%s (%s)",
	    vpd->fw_version, vpd->fw_label);

#ifdef EMLXS_I386
	(void) snprintf(port_info->pi_attrs.option_rom_version,
	    (sizeof (port_info->pi_attrs.option_rom_version)-1),
	    "Boot:%s", vpd->boot_version);
#else	/* EMLXS_SPARC */
	(void) snprintf(port_info->pi_attrs.option_rom_version,
	    (sizeof (port_info->pi_attrs.option_rom_version)-1),
	    "Boot:%s Fcode:%s", vpd->boot_version, vpd->fcode_version);
#endif	/* EMLXS_I386 */

	(void) snprintf(port_info->pi_attrs.driver_version,
	    (sizeof (port_info->pi_attrs.driver_version)-1), "%s (%s)",
	    emlxs_version, emlxs_revision);

	(void) strncpy(port_info->pi_attrs.driver_name, DRIVER_NAME,
	    (sizeof (port_info->pi_attrs.driver_name)-1));

	port_info->pi_attrs.vendor_specific_id =
	    ((hba->model_info.device_id << 16) | PCI_VENDOR_ID_EMULEX);

	port_info->pi_attrs.supported_cos = LE_SWAP32(FC_NS_CLASS3);

	port_info->pi_attrs.max_frame_size = FF_FRAME_SIZE;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	port_info->pi_rnid_params.params.num_attached = 0;

	if (hba->model_info.chip == EMLXS_LANCER_CHIP) {
		uint8_t		byte;
		uint8_t		*wwpn;
		uint32_t	i;
		uint32_t	j;

		/* Copy the WWPN as a string into the local buffer */
		wwpn = (uint8_t *)&hba->wwpn;
		for (i = 0; i < 16; i++) {
			byte = *wwpn++;
			j = ((byte & 0xf0) >> 4);
			if (j <= 9) {
				buffer[i] =
				    (char)((uint8_t)'0' + (uint8_t)j);
			} else {
				buffer[i] =
				    (char)((uint8_t)'A' + (uint8_t)(j -
				    10));
			}

			i++;
			j = (byte & 0xf);
			if (j <= 9) {
				buffer[i] =
				    (char)((uint8_t)'0' + (uint8_t)j);
			} else {
				buffer[i] =
				    (char)((uint8_t)'A' + (uint8_t)(j -
				    10));
			}
		}

		port_info->pi_attrs.hba_fru_details.port_index = 0;
#if ((EMLXS_MODREV == EMLXS_MODREV3) || (EMLXS_MODREV == EMLXS_MODREV4))

	} else if (hba->flag & FC_NPIV_ENABLED) {
		uint8_t		byte;
		uint8_t		*wwpn;
		uint32_t	i;
		uint32_t	j;

		/* Copy the WWPN as a string into the local buffer */
		wwpn = (uint8_t *)&hba->wwpn;
		for (i = 0; i < 16; i++) {
			byte = *wwpn++;
			j = ((byte & 0xf0) >> 4);
			if (j <= 9) {
				buffer[i] =
				    (char)((uint8_t)'0' + (uint8_t)j);
			} else {
				buffer[i] =
				    (char)((uint8_t)'A' + (uint8_t)(j -
				    10));
			}

			i++;
			j = (byte & 0xf);
			if (j <= 9) {
				buffer[i] =
				    (char)((uint8_t)'0' + (uint8_t)j);
			} else {
				buffer[i] =
				    (char)((uint8_t)'A' + (uint8_t)(j -
				    10));
			}
		}

		port_info->pi_attrs.hba_fru_details.port_index = port->vpi;
#endif /* == EMLXS_MODREV3 || EMLXS_MODREV4 */

	} else {
		/* Copy the serial number string (right most 16 chars) */
		/* into the right justified local buffer */
		bzero(buffer, sizeof (buffer));
		length = strlen(vpd->serial_num);
		len = (length > 16) ? 16 : length;
		bcopy(&vpd->serial_num[(length - len)],
		    &buffer[(sizeof (buffer) - len)], len);

		port_info->pi_attrs.hba_fru_details.port_index =
		    vpd->port_index;
	}

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
	    LE_SWAP64(port_info->pi_attrs.hba_fru_details.high);

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
	    LE_SWAP64(port_info->pi_attrs.hba_fru_details.low);

#endif /* >= EMLXS_MODREV3 */

#if (EMLXS_MODREV >= EMLXS_MODREV4)
	(void) strncpy((caddr_t)port_info->pi_attrs.sym_node_name,
	    (caddr_t)port->snn, FCHBA_SYMB_NAME_LEN);
	(void) strncpy((caddr_t)port_info->pi_attrs.sym_port_name,
	    (caddr_t)port->spn, FCHBA_SYMB_NAME_LEN);
#endif	/* >= EMLXS_MODREV4 */

	(void) snprintf(port_info->pi_attrs.hardware_version,
	    (sizeof (port_info->pi_attrs.hardware_version)-1),
	    "%x", vpd->biuRev);

	/* Set the hba speed limit */
	if (vpd->link_speed & LMT_16GB_CAPABLE) {
		port_info->pi_attrs.supported_speed |=
		    FC_HBA_PORTSPEED_16GBIT;
	}
	if (vpd->link_speed & LMT_10GB_CAPABLE) {
		port_info->pi_attrs.supported_speed |=
		    FC_HBA_PORTSPEED_10GBIT;
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
	(void) strncpy(port_info->pi_attrs.model, hba->model_info.model,
	    (sizeof (port_info->pi_attrs.model)-1));
	(void) strncpy(port_info->pi_attrs.model_description,
	    hba->model_info.model_desc,
	    (sizeof (port_info->pi_attrs.model_description)-1));


	/* Log information */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Bind info: port_num           = %d", bind_info->port_num);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Bind info: port_handle        = %p", bind_info->port_handle);

#if (EMLXS_MODREV >= EMLXS_MODREV5)
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Bind info: port_npiv          = %d", bind_info->port_npiv);
#endif /* >= EMLXS_MODREV5 */

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
	    "Port info: model              = %s", port_info->pi_attrs.model);
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

	mutex_exit(&EMLXS_PORT_LOCK);

#ifdef SFCT_SUPPORT
	if (port->flag & EMLXS_TGT_ENABLED) {
		emlxs_fct_bind_port(port);
	}
#endif /* SFCT_SUPPORT */

	return ((opaque_t)port);

} /* emlxs_fca_bind_port() */


static void
emlxs_fca_unbind_port(opaque_t fca_port_handle)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t *hba = HBA;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_unbind_port: port=%p", port);

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		return;
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		(void) emlxs_vpi_port_unbind_notify(port, 1);
	}

	/* Destroy & flush all port nodes, if they exist */
	if (port->node_count) {
		(void) EMLXS_SLI_UNREG_NODE(port, 0, 0, 0, 0);
	}

#if (EMLXS_MODREV >= EMLXS_MODREV5)
	if ((hba->sli_mode <= EMLXS_HBA_SLI3_MODE) &&
	    (hba->flag & FC_NPIV_ENABLED) &&
	    (port->flag & (EMLXS_PORT_CONFIG | EMLXS_PORT_ENABLED))) {
		(void) emlxs_mb_unreg_vpi(port);
	}
#endif

	mutex_enter(&EMLXS_PORT_LOCK);
	if (port->flag & EMLXS_INI_BOUND) {
#if (EMLXS_MODREV >= EMLXS_MODREV5)
		port->flag &= ~(EMLXS_PORT_CONFIG | EMLXS_PORT_ENABLED);
#endif
		port->flag &= ~EMLXS_INI_BOUND;
		hba->num_of_ports--;

		/* Wait until ulp callback interface is idle */
		while (port->ulp_busy) {
			mutex_exit(&EMLXS_PORT_LOCK);
			delay(drv_usectohz(500000));
			mutex_enter(&EMLXS_PORT_LOCK);
		}

		port->ulp_handle = 0;
		port->ulp_statec = FC_STATE_OFFLINE;
		port->ulp_statec_cb = NULL;
		port->ulp_unsol_cb = NULL;
	}
	mutex_exit(&EMLXS_PORT_LOCK);

#ifdef SFCT_SUPPORT
	/* Check if port was target bound */
	if (port->flag & EMLXS_TGT_BOUND) {
		emlxs_fct_unbind_port(port);
	}
#endif /* SFCT_SUPPORT */

	return;

} /* emlxs_fca_unbind_port() */


/*ARGSUSED*/
extern int
emlxs_fca_pkt_init(opaque_t fca_port_handle, fc_packet_t *pkt, int32_t sleep)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t  *hba = HBA;
	emlxs_buf_t  *sbp = (emlxs_buf_t *)pkt->pkt_fca_private;

	if (!sbp) {
		return (FC_FAILURE);
	}
	bzero((void *)sbp, sizeof (emlxs_buf_t));

	mutex_init(&sbp->mtx, NULL, MUTEX_DRIVER, DDI_INTR_PRI(hba->intr_arg));
	sbp->pkt_flags =
	    PACKET_VALID | PACKET_ULP_OWNED;
	sbp->port = port;
	sbp->pkt = pkt;
	sbp->iocbq.sbp = sbp;

	return (FC_SUCCESS);

} /* emlxs_fca_pkt_init() */



static void
emlxs_initialize_pkt(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	fc_packet_t *pkt = PRIV2PKT(sbp);

	mutex_enter(&sbp->mtx);

	/* Reinitialize */
	sbp->pkt   = pkt;
	sbp->port  = port;
	sbp->bmp   = NULL;
	sbp->pkt_flags &= (PACKET_VALID | PACKET_ALLOCATED);
	sbp->iotag = 0;
	sbp->ticks = 0;
	sbp->abort_attempts = 0;
	sbp->fpkt  = NULL;
	sbp->flush_count = 0;
	sbp->next  = NULL;

	if (port->mode == MODE_INITIATOR) {
		sbp->node  = NULL;
		sbp->did   = 0;
		sbp->lun   = EMLXS_LUN_NONE;
		sbp->class = 0;
		sbp->channel  = NULL;
	}

	bzero((void *)&sbp->iocbq, sizeof (IOCBQ));
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
		bzero(pkt->pkt_resp, pkt->pkt_rsplen);
	}

	mutex_exit(&sbp->mtx);

	return;

} /* emlxs_initialize_pkt() */



/*
 * We may not need this routine
 */
/*ARGSUSED*/
extern int
emlxs_fca_pkt_uninit(opaque_t fca_port_handle, fc_packet_t *pkt)
{
	emlxs_buf_t  *sbp = PKT2PRIV(pkt);

	if (!sbp) {
		return (FC_FAILURE);
	}

	if (!(sbp->pkt_flags & PACKET_VALID)) {
		return (FC_FAILURE);
	}
	sbp->pkt_flags &= ~PACKET_VALID;
	mutex_destroy(&sbp->mtx);

	return (FC_SUCCESS);

} /* emlxs_fca_pkt_uninit() */


static int
emlxs_fca_get_cap(opaque_t fca_port_handle, char *cap, void *ptr)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t  *hba = HBA;
	int32_t rval;
	emlxs_config_t *cfg = &CFG;

	if (!(port->flag & EMLXS_INI_BOUND)) {
		return (FC_CAP_ERROR);
	}

	if (strcmp(cap, FC_NODE_WWN) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_NODE_WWN");

		bcopy((void *)&hba->wwnn, (void *)ptr, sizeof (NAME_TYPE));
		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_LOGIN_PARAMS) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_LOGIN_PARAMS");

		/*
		 * We need to turn off CLASS2 support.
		 * Otherwise, FC transport will use CLASS2 as default class
		 * and never try with CLASS3.
		 */
		hba->sparam.cls2.classValid = 0;

		bcopy((void *)&hba->sparam, (void *)ptr, sizeof (SERV_PARM));

		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_CAP_UNSOL_BUF) == 0) {
		int32_t		*num_bufs;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_get_cap: FC_CAP_UNSOL_BUF (%d)",
		    cfg[CFG_UB_BUFS].current);

		num_bufs = (int32_t *)ptr;

		/* We multiply by MAX_VPORTS because ULP uses a */
		/* formula to calculate ub bufs from this */
		*num_bufs = (cfg[CFG_UB_BUFS].current * MAX_VPORTS);

		rval = FC_CAP_FOUND;

	} else if (strcmp(cap, FC_CAP_PAYLOAD_SIZE) == 0) {
		int32_t		*size;

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
		fc_fcp_dma_t   *fcp_dma;

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

} /* emlxs_fca_get_cap() */



static int
emlxs_fca_set_cap(opaque_t fca_port_handle, char *cap, void *ptr)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_set_cap: cap=[%s] arg=%p", cap, ptr);

	return (FC_CAP_ERROR);

} /* emlxs_fca_set_cap() */


static opaque_t
emlxs_fca_get_device(opaque_t fca_port_handle, fc_portid_t d_id)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_get_device: did=%x", d_id.port_id);

	return (NULL);

} /* emlxs_fca_get_device() */


static int32_t
emlxs_fca_notify(opaque_t fca_port_handle, uint32_t cmd)
{
	emlxs_port_t *port = (emlxs_port_t *)fca_port_handle;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg, "fca_notify: cmd=%x",
	    cmd);

	return (FC_SUCCESS);

} /* emlxs_fca_notify */



static int
emlxs_fca_get_map(opaque_t fca_port_handle, fc_lilpmap_t *mapbuf)
{
	emlxs_port_t	*port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t	*hba = HBA;
	uint32_t	lilp_length;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_get_map: mapbuf=%p length=%d (%X,%X,%X,%X)", mapbuf,
	    port->alpa_map[0], port->alpa_map[1], port->alpa_map[2],
	    port->alpa_map[3], port->alpa_map[4]);

	if (!(port->flag & EMLXS_INI_BOUND)) {
		return (FC_NOMAP);
	}

	if (hba->topology != TOPOLOGY_LOOP) {
		return (FC_NOMAP);
	}

	/* Check if alpa map is available */
	if (port->alpa_map[0] != 0) {
		mapbuf->lilp_magic  = MAGIC_LILP;
	} else {	/* No LILP map available */

		/* Set lilp_magic to MAGIC_LISA and this will */
		/* trigger an ALPA scan in ULP */
		mapbuf->lilp_magic  = MAGIC_LISA;
	}

	mapbuf->lilp_myalpa = port->did;

	/* The first byte of the alpa_map is the lilp map length */
	/* Add one to include the lilp length byte itself */
	lilp_length = (uint32_t)port->alpa_map[0] + 1;

	/* Make sure the max transfer is 128 bytes */
	if (lilp_length > 128) {
		lilp_length = 128;
	}

	/* We start copying from the lilp_length field */
	/* in order to get a word aligned address */
	bcopy((void *)&port->alpa_map, (void *)&mapbuf->lilp_length,
	    lilp_length);

	return (FC_SUCCESS);

} /* emlxs_fca_get_map() */



extern int
emlxs_fca_transport(opaque_t fca_port_handle, fc_packet_t *pkt)
{
	emlxs_port_t	*port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t	*hba = HBA;
	emlxs_buf_t	*sbp;
	uint32_t	rval;
	uint32_t	pkt_flags;

	/* Validate packet */
	sbp = PKT2PRIV(pkt);

	/* Make sure adapter is online */
	if (!(hba->flag & FC_ONLINE_MODE) &&
	    !(sbp->pkt_flags & PACKET_ALLOCATED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Adapter offline.");

		rval = (hba->flag & FC_ONLINING_MODE) ?
		    FC_TRAN_BUSY : FC_OFFLINE;
		return (rval);
	}

	/* Make sure ULP was told that the port was online */
	if ((port->ulp_statec == FC_STATE_OFFLINE) &&
	    !(sbp->pkt_flags & PACKET_ALLOCATED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Port offline.");

		return (FC_OFFLINE);
	}

	if (sbp->port != port) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_error_msg,
		    "Invalid port handle. sbp=%p port=%p flags=%x", sbp,
		    sbp->port, sbp->pkt_flags);
		return (FC_BADPACKET);
	}

	if (!(sbp->pkt_flags & (PACKET_VALID | PACKET_ULP_OWNED))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_error_msg,
		    "Invalid packet flags. sbp=%p port=%p flags=%x", sbp,
		    sbp->port, sbp->pkt_flags);
		return (FC_BADPACKET);
	}

#ifdef SFCT_SUPPORT
	if ((port->mode == MODE_TARGET) && !sbp->fct_cmd &&
	    !(sbp->pkt_flags & PACKET_ALLOCATED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_error_msg,
		    "Packet blocked. Target mode.");
		return (FC_TRANSPORT_ERROR);
	}
#endif /* SFCT_SUPPORT */

#ifdef IDLE_TIMER
	emlxs_pm_busy_component(hba);
#endif	/* IDLE_TIMER */

	/* Prepare the packet for transport */
	emlxs_initialize_pkt(port, sbp);

	/* Save a copy of the pkt flags. */
	/* We will check the polling flag later */
	pkt_flags = sbp->pkt_flags;

	/* Send the packet */
	switch (pkt->pkt_tran_type) {
	case FC_PKT_FCP_READ:
	case FC_PKT_FCP_WRITE:
		rval = emlxs_send_fcp_cmd(port, sbp, &pkt_flags);
		break;

	case FC_PKT_IP_WRITE:
	case FC_PKT_BROADCAST:
		rval = emlxs_send_ip(port, sbp);
		break;

	case FC_PKT_EXCHANGE:
		switch (pkt->pkt_cmd_fhdr.type) {
		case FC_TYPE_SCSI_FCP:
			rval = emlxs_send_fcp_cmd(port, sbp, &pkt_flags);
			break;

		case FC_TYPE_FC_SERVICES:
			rval = emlxs_send_ct(port, sbp);
			break;

#ifdef MENLO_SUPPORT
		case EMLXS_MENLO_TYPE:
			rval = emlxs_send_menlo(port, sbp);
			break;
#endif /* MENLO_SUPPORT */

		default:
			rval = emlxs_send_els(port, sbp);
		}
		break;

	case FC_PKT_OUTBOUND:
		switch (pkt->pkt_cmd_fhdr.type) {
#ifdef SFCT_SUPPORT
		case FC_TYPE_SCSI_FCP:
			rval = emlxs_send_fct_status(port, sbp);
			break;

		case FC_TYPE_BASIC_LS:
			rval = emlxs_send_fct_abort(port, sbp);
			break;
#endif /* SFCT_SUPPORT */

		case FC_TYPE_FC_SERVICES:
			rval = emlxs_send_ct_rsp(port, sbp);
			break;
#ifdef MENLO_SUPPORT
		case EMLXS_MENLO_TYPE:
			rval = emlxs_send_menlo(port, sbp);
			break;
#endif /* MENLO_SUPPORT */

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
		sbp->pkt_flags |= PACKET_ULP_OWNED;
		mutex_exit(&sbp->mtx);

		return (rval);
	}

	/* Check if this packet should be polled for completion before */
	/* returning. This check must be done with a saved copy of the */
	/* pkt_flags because the packet itself could already be freed from */
	/* memory if it was not polled. */
	if (pkt_flags & PACKET_POLLED) {
		emlxs_poll(port, sbp);
	}

	return (FC_SUCCESS);

} /* emlxs_fca_transport() */



static void
emlxs_poll(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt = PRIV2PKT(sbp);
	clock_t		timeout;
	clock_t		time;
	CHANNEL	*cp;
	int		in_panic = 0;

	mutex_enter(&EMLXS_PORT_LOCK);
	hba->io_poll_count++;
	mutex_exit(&EMLXS_PORT_LOCK);

	/* Check for panic situation */
	cp = (CHANNEL *)sbp->channel;

	if (ddi_in_panic()) {
		in_panic = 1;
		/*
		 * In panic situations there will be one thread with
		 * no interrrupts (hard or soft) and no timers
		 */

		/*
		 * We must manually poll everything in this thread
		 * to keep the driver going.
		 */

		/* Keep polling the chip until our IO is completed */
		/* Driver's timer will not function during panics. */
		/* Therefore, timer checks must be performed manually. */
		(void) drv_getparm(LBOLT, &time);
		timeout = time + drv_usectohz(1000000);
		while (!(sbp->pkt_flags & PACKET_COMPLETED)) {
			EMLXS_SLI_POLL_INTR(hba);
			(void) drv_getparm(LBOLT, &time);

			/* Trigger timer checks periodically */
			if (time >= timeout) {
				emlxs_timer_checks(hba);
				timeout = time + drv_usectohz(1000000);
			}
		}
	} else {
		/* Wait for IO completion */
		/* The driver's timer will detect */
		/* any timeout and abort the I/O. */
		mutex_enter(&EMLXS_PKT_LOCK);
		while (!(sbp->pkt_flags & PACKET_COMPLETED)) {
			cv_wait(&EMLXS_PKT_CV, &EMLXS_PKT_LOCK);
		}
		mutex_exit(&EMLXS_PKT_LOCK);
	}

	/* Check for fcp reset pkt */
	if (sbp->pkt_flags & PACKET_FCP_RESET) {
		if (sbp->pkt_flags & PACKET_FCP_TGT_RESET) {
			/* Flush the IO's on the chipq */
			(void) emlxs_chipq_node_flush(port,
			    &hba->chan[hba->channel_fcp],
			    sbp->node, sbp);
		} else {
			/* Flush the IO's on the chipq for this lun */
			(void) emlxs_chipq_lun_flush(port,
			    sbp->node, sbp->lun, sbp);
		}

		if (sbp->flush_count == 0) {
			emlxs_node_open(port, sbp->node, hba->channel_fcp);
			goto done;
		}

		/* Set the timeout so the flush has time to complete */
		timeout = emlxs_timeout(hba, 60);
		(void) drv_getparm(LBOLT, &time);
		while ((time < timeout) && sbp->flush_count > 0) {
			delay(drv_usectohz(500000));
			(void) drv_getparm(LBOLT, &time);
		}

		if (sbp->flush_count == 0) {
			emlxs_node_open(port, sbp->node, hba->channel_fcp);
			goto done;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_flush_timeout_msg,
		    "sbp=%p flush_count=%d. Waiting...", sbp,
		    sbp->flush_count);

		/* Let's try this one more time */

		if (sbp->pkt_flags & PACKET_FCP_TGT_RESET) {
			/* Flush the IO's on the chipq */
			(void) emlxs_chipq_node_flush(port,
			    &hba->chan[hba->channel_fcp],
			    sbp->node, sbp);
		} else {
			/* Flush the IO's on the chipq for this lun */
			(void) emlxs_chipq_lun_flush(port,
			    sbp->node, sbp->lun, sbp);
		}

		/* Reset the timeout so the flush has time to complete */
		timeout = emlxs_timeout(hba, 60);
		(void) drv_getparm(LBOLT, &time);
		while ((time < timeout) && sbp->flush_count > 0) {
			delay(drv_usectohz(500000));
			(void) drv_getparm(LBOLT, &time);
		}

		if (sbp->flush_count == 0) {
			emlxs_node_open(port, sbp->node, hba->channel_fcp);
			goto done;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_flush_timeout_msg,
		    "sbp=%p flush_count=%d. Resetting link.", sbp,
		    sbp->flush_count);

		/* Let's first try to reset the link */
		(void) emlxs_reset(port, FC_FCA_LINK_RESET);

		if (sbp->flush_count == 0) {
			goto done;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_flush_timeout_msg,
		    "sbp=%p flush_count=%d. Resetting HBA.", sbp,
		    sbp->flush_count);

		/* If that doesn't work, reset the adapter */
		(void) emlxs_reset(port, FC_FCA_RESET);

		if (sbp->flush_count != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_flush_timeout_msg,
			    "sbp=%p flush_count=%d. Giving up.", sbp,
			    sbp->flush_count);
		}

	}
	/* PACKET_FCP_RESET */
done:

	/* Packet has been declared completed and is now ready to be returned */

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_unswap_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	mutex_enter(&sbp->mtx);
	sbp->pkt_flags |= PACKET_ULP_OWNED;
	mutex_exit(&sbp->mtx);

	mutex_enter(&EMLXS_PORT_LOCK);
	hba->io_poll_count--;
	mutex_exit(&EMLXS_PORT_LOCK);

#ifdef FMA_SUPPORT
	if (!in_panic) {
		emlxs_check_dma(hba, sbp);
	}
#endif

	/* Make ULP completion callback if required */
	if (pkt->pkt_comp) {
		cp->ulpCmplCmd++;
		(*pkt->pkt_comp) (pkt);
	}

#ifdef FMA_SUPPORT
	if (hba->flag & FC_DMA_CHECK_ERROR) {
		emlxs_thread_spawn(hba, emlxs_restart_thread,
		    NULL, NULL);
	}
#endif

	return;

} /* emlxs_poll() */


static int
emlxs_fca_ub_alloc(opaque_t fca_port_handle, uint64_t tokens[], uint32_t size,
    uint32_t *count, uint32_t type)
{
	emlxs_port_t		*port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t		*hba = HBA;
	char			*err = NULL;
	emlxs_unsol_buf_t	*pool = NULL;
	emlxs_unsol_buf_t	*new_pool = NULL;
	emlxs_config_t		*cfg = &CFG;
	int32_t			i;
	int			result;
	uint32_t		free_resv;
	uint32_t		free;
	fc_unsol_buf_t		*ubp;
	emlxs_ub_priv_t		*ub_priv;
	int			rc;

	if (!(port->flag & EMLXS_INI_ENABLED)) {
		if (tokens && count) {
			bzero(tokens, (sizeof (uint64_t) * (*count)));
		}
		return (FC_SUCCESS);
	}

	if (!(port->flag & EMLXS_INI_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_ub_alloc failed: Port not bound!  size=%x count=%d "
		    "type=%x", size, *count, type);

		return (FC_FAILURE);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_ub_alloc: size=%x count=%d type=%x", size, *count, type);

	if (count && (*count > EMLXS_MAX_UBUFS)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
		    "fca_ub_alloc failed: Too many unsolicted buffers "
		    "requested. count=%x", *count);

		return (FC_FAILURE);

	}

	if (tokens == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
		    "fca_ub_alloc failed: Token array is NULL.");

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
		break;
	case FC_TYPE_IS8802:
		err = "IS8802";
		break;
	case FC_TYPE_IS8802_SNAP:
		err = "IS8802_SNAP";

		if (cfg[CFG_NETWORK_ON].current == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_ub_alloc failed: IP support is disabled.");

			return (FC_FAILURE);
		}
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
	 * Walk through the list of the unsolicited buffers
	 * for this ddiinst of emlx.
	 */

	pool = port->ub_pool;

	/*
	 * The emlxs_fca_ub_alloc() can be called more than once with different
	 * size. We will reject the call if there are
	 * duplicate size with the same FC-4 type.
	 */
	while (pool) {
		if ((pool->pool_type == type) &&
		    (pool->pool_buf_size == size)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
			    "fca_ub_alloc failed: Unsolicited buffer pool "
			    "for %s of size 0x%x bytes already exists.",
			    err, size);

			result = FC_FAILURE;
			goto fail;
		}

		pool = pool->pool_next;
	}

	mutex_exit(&EMLXS_UB_LOCK);

	new_pool = (emlxs_unsol_buf_t *)kmem_zalloc(sizeof (emlxs_unsol_buf_t),
	    KM_SLEEP);

	new_pool->pool_next = NULL;
	new_pool->pool_type = type;
	new_pool->pool_buf_size = size;
	new_pool->pool_nentries = *count;
	new_pool->pool_available = new_pool->pool_nentries;
	new_pool->pool_free = free;
	new_pool->pool_free_resv = free_resv;
	new_pool->fc_ubufs =
	    kmem_zalloc((sizeof (fc_unsol_buf_t) * (*count)), KM_SLEEP);

	new_pool->pool_first_token = port->ub_count;
	new_pool->pool_last_token = port->ub_count + new_pool->pool_nentries;

	for (i = 0; i < new_pool->pool_nentries; i++) {
		ubp = (fc_unsol_buf_t *)&new_pool->fc_ubufs[i];
		ubp->ub_port_handle = port->ulp_handle;
		ubp->ub_token = (uint64_t)((unsigned long)ubp);
		ubp->ub_bufsize = size;
		ubp->ub_class = FC_TRAN_CLASS3;
		ubp->ub_port_private = NULL;
		ubp->ub_fca_private =
		    (emlxs_ub_priv_t *)kmem_zalloc(sizeof (emlxs_ub_priv_t),
		    KM_SLEEP);

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


		tokens[i] = (uint64_t)((unsigned long)ubp);
		port->ub_count++;
	}

	mutex_enter(&EMLXS_UB_LOCK);

	/* Add the pool to the top of the pool list */
	new_pool->pool_prev = NULL;
	new_pool->pool_next = port->ub_pool;

	if (port->ub_pool) {
		port->ub_pool->pool_prev = new_pool;
	}
	port->ub_pool = new_pool;

	/* Set the post counts */
	if (type == FC_TYPE_IS8802_SNAP) {
		MAILBOXQ	*mbox;

		port->ub_post[hba->channel_ip] += new_pool->pool_nentries;

		if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
		    MEM_MBOX))) {
			emlxs_mb_config_farp(hba, mbox);
			rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba,
			    mbox, MBX_NOWAIT, 0);
			if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
				emlxs_mem_put(hba, MEM_MBOX, (void *)mbox);
			}
		}
		port->flag |= EMLXS_PORT_IP_UP;
	} else if (type == FC_TYPE_EXTENDED_LS) {
		port->ub_post[hba->channel_els] += new_pool->pool_nentries;
	} else if (type == FC_TYPE_FC_SERVICES) {
		port->ub_post[hba->channel_ct] += new_pool->pool_nentries;
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
		ubp = (fc_unsol_buf_t *)((unsigned long)tokens[i]);
		ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_detail_msg,
		    "fca_ub_alloc failed: Freed buffer=%p token=%x size=%x "
		    "type=%x ", ubp, ub_priv->token, ubp->ub_bufsize, type);

		/* Free the actual buffer */
		kmem_free(ubp->ub_buffer, ubp->ub_bufsize);

		/* Free the private area of the buffer object */
		kmem_free(ubp->ub_fca_private, sizeof (emlxs_ub_priv_t));

		tokens[i] = 0;
		port->ub_count--;
	}

	if (new_pool) {
		/* Free the array of buffer objects in the pool */
		kmem_free((caddr_t)new_pool->fc_ubufs,
		    (sizeof (fc_unsol_buf_t) * new_pool->pool_nentries));

		/* Free the pool object */
		kmem_free((caddr_t)new_pool, sizeof (emlxs_unsol_buf_t));
	}

	mutex_exit(&EMLXS_UB_LOCK);

	return (result);

} /* emlxs_fca_ub_alloc() */


static void
emlxs_ub_els_reject(emlxs_port_t *port, fc_unsol_buf_t *ubp)
{
	emlxs_hba_t	*hba = HBA;
	emlxs_ub_priv_t	*ub_priv;
	fc_packet_t	*pkt;
	ELS_PKT		*els;
	uint32_t	sid;

	ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;

	if (hba->state <= FC_LINK_DOWN) {
		emlxs_abort_els_exchange(hba, port, ubp->ub_frame.rx_id);
		return;
	}

	if (!(pkt = emlxs_pkt_alloc(port, sizeof (uint32_t) +
	    sizeof (LS_RJT), 0, 0, KM_NOSLEEP))) {
		emlxs_abort_els_exchange(hba, port, ubp->ub_frame.rx_id);
		return;
	}

	sid = LE_SWAP24_LO(ubp->ub_frame.s_id);

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
	pkt->pkt_cmd_fhdr.r_ctl =
	    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
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
emlxs_fca_ub_release(opaque_t fca_port_handle, uint32_t count,
    uint64_t tokens[])
{
	emlxs_port_t		*port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t		*hba = HBA;
	fc_unsol_buf_t		*ubp;
	emlxs_ub_priv_t		*ub_priv;
	uint32_t		i;
	uint32_t		time;
	emlxs_unsol_buf_t	*pool;

	if (count == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_ub_release: Nothing to do. count=%d", count);

		return (FC_SUCCESS);
	}

	if (!(port->flag & EMLXS_INI_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_ub_release failed: Port not bound. count=%d "
		    "token[0]=%p",
		    count, tokens[0]);

		return (FC_UNBOUND);
	}

	mutex_enter(&EMLXS_UB_LOCK);

	if (!port->ub_pool) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_ub_release failed: No pools! count=%d token[0]=%p",
		    count, tokens[0]);

		mutex_exit(&EMLXS_UB_LOCK);
		return (FC_UB_BADTOKEN);
	}

	for (i = 0; i < count; i++) {
		ubp = (fc_unsol_buf_t *)((unsigned long)tokens[i]);

		if (!ubp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_ub_release failed: count=%d tokens[%d]=0",
			    count, i);

			mutex_exit(&EMLXS_UB_LOCK);
			return (FC_UB_BADTOKEN);
		}

		ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;

		if (!ub_priv || (ub_priv == (emlxs_ub_priv_t *)DEAD_PTR)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_ub_release failed: Dead buffer found. ubp=%p",
			    ubp);

			mutex_exit(&EMLXS_UB_LOCK);
			return (FC_UB_BADTOKEN);
		}

		if (ub_priv->flags == EMLXS_UB_FREE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_ub_release: Buffer already free! ubp=%p "
			    "token=%x",
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
		    "fca_ub_release: ubp=%p token=%x time=%d av=%d "
		    "(%d,%d,%d,%d)",
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

} /* emlxs_fca_ub_release() */


static int
emlxs_fca_ub_free(opaque_t fca_port_handle, uint32_t count, uint64_t tokens[])
{
	emlxs_port_t		*port = (emlxs_port_t *)fca_port_handle;
	emlxs_unsol_buf_t	*pool;
	fc_unsol_buf_t		*ubp;
	emlxs_ub_priv_t		*ub_priv;
	uint32_t		i;

	if (!(port->flag & EMLXS_INI_ENABLED)) {
		return (FC_SUCCESS);
	}

	if (count == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_ub_free: Nothing to do. count=%d token[0]=%p", count,
		    tokens[0]);

		return (FC_SUCCESS);
	}

	if (!(port->flag & EMLXS_INI_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_ub_free: Port not bound. count=%d token[0]=%p", count,
		    tokens[0]);

		return (FC_SUCCESS);
	}

	mutex_enter(&EMLXS_UB_LOCK);

	if (!port->ub_pool) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_ub_free failed: No pools! count=%d token[0]=%p", count,
		    tokens[0]);

		mutex_exit(&EMLXS_UB_LOCK);
		return (FC_UB_BADTOKEN);
	}

	/* Process buffer list */
	for (i = 0; i < count; i++) {
		ubp = (fc_unsol_buf_t *)((unsigned long)tokens[i]);

		if (!ubp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_ub_free failed: count=%d tokens[%d]=0", count,
			    i);

			mutex_exit(&EMLXS_UB_LOCK);
			return (FC_UB_BADTOKEN);
		}

		/* Mark buffer unavailable */
		ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;

		if (!ub_priv || (ub_priv == (emlxs_ub_priv_t *)DEAD_PTR)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_ub_free failed: Dead buffer found. ubp=%p",
			    ubp);

			mutex_exit(&EMLXS_UB_LOCK);
			return (FC_UB_BADTOKEN);
		}

		ub_priv->available = 0;

		/* Mark one less buffer available in the parent pool */
		pool = ub_priv->pool;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_detail_msg,
		    "fca_ub_free: ubp=%p token=%x (%d,%d,%d,%d)", ubp,
		    ub_priv->token, pool->pool_nentries,
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

} /* emlxs_fca_ub_free() */


/* EMLXS_UB_LOCK must be held when calling this routine */
extern void
emlxs_ub_destroy(emlxs_port_t *port, emlxs_unsol_buf_t *pool)
{
	emlxs_hba_t		*hba = HBA;
	emlxs_unsol_buf_t	*next;
	emlxs_unsol_buf_t	*prev;
	fc_unsol_buf_t		*ubp;
	uint32_t		i;

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
		port->ub_post[hba->channel_ip] -= pool->pool_nentries;
		break;

	case FC_TYPE_EXTENDED_LS:
		port->ub_post[hba->channel_els] -= pool->pool_nentries;
		break;

	case FC_TYPE_FC_SERVICES:
		port->ub_post[hba->channel_ct] -= pool->pool_nentries;
		break;
	}

	/* Now free the pool memory */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "ub_destroy: pool=%p type=%d size=%d count=%d", pool,
	    pool->pool_type, pool->pool_buf_size, pool->pool_nentries);

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
	    (sizeof (fc_unsol_buf_t)*pool->pool_nentries));

	/* Free the pool object */
	kmem_free((caddr_t)pool, sizeof (emlxs_unsol_buf_t));

	return;

} /* emlxs_ub_destroy() */


/*ARGSUSED*/
extern int
emlxs_fca_pkt_abort(opaque_t fca_port_handle, fc_packet_t *pkt, int32_t sleep)
{
	emlxs_port_t	*port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t	*hba = HBA;
	emlxs_config_t	*cfg = &CFG;

	emlxs_buf_t	*sbp;
	NODELIST	*nlp;
	NODELIST	*prev_nlp;
	uint8_t		channelno;
	CHANNEL	*cp;
	clock_t		pkt_timeout;
	clock_t		timer;
	clock_t		time;
	int32_t		pkt_ret;
	IOCBQ		*iocbq;
	IOCBQ		*next;
	IOCBQ		*prev;
	uint32_t	found;
	uint32_t	pass = 0;

	sbp = (emlxs_buf_t *)pkt->pkt_fca_private;
	iocbq = &sbp->iocbq;
	nlp = (NODELIST *)sbp->node;
	cp = (CHANNEL *)sbp->channel;
	channelno = (cp) ? cp->channelno : 0;

	if (!(port->flag & EMLXS_INI_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
		    "Port not bound.");
		return (FC_UNBOUND);
	}

	if (!(hba->flag & FC_ONLINE_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
		    "Adapter offline.");
		return (FC_OFFLINE);
	}

	/* ULP requires the aborted pkt to be completed */
	/* back to ULP before returning from this call. */
	/* SUN knows of problems with this call so they suggested that we */
	/* always return a FC_FAILURE for this call, until it is worked out. */

	/* Check if pkt is no good */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags & PACKET_ULP_OWNED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
		    "Bad sbp. flags=%x", sbp->pkt_flags);
		return (FC_FAILURE);
	}

	/* Tag this now */
	/* This will prevent any thread except ours from completing it */
	mutex_enter(&sbp->mtx);

	/* Check again if we still own this */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags & PACKET_ULP_OWNED)) {
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
		    "Attempting to abort a polled I/O. sbp=%p flags=%x", sbp,
		    sbp->pkt_flags);
		return (FC_FAILURE);
	}

	sbp->pkt_flags |= PACKET_POLLED;
	sbp->pkt_flags |= PACKET_IN_ABORT;

	if (sbp->pkt_flags & (PACKET_IN_COMPLETION | PACKET_IN_FLUSH |
	    PACKET_IN_TIMEOUT)) {
		mutex_exit(&sbp->mtx);

		/* Do nothing, pkt already on its way out */
		goto done;
	}

	mutex_exit(&sbp->mtx);

begin:
	pass++;

	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	if (sbp->pkt_flags & PACKET_IN_TXQ) {
		/* Find it on the queue */
		found = 0;
		if (iocbq->flag & IOCB_PRIORITY) {
			/* Search the priority queue */
			prev = NULL;
			next = (IOCBQ *) nlp->nlp_ptx[channelno].q_first;

			while (next) {
				if (next == iocbq) {
					/* Remove it */
					if (prev) {
						prev->next = iocbq->next;
					}

					if (nlp->nlp_ptx[channelno].q_last ==
					    (void *)iocbq) {
						nlp->nlp_ptx[channelno].q_last =
						    (void *)prev;
					}

					if (nlp->nlp_ptx[channelno].q_first ==
					    (void *)iocbq) {
						nlp->nlp_ptx[channelno].
						    q_first =
						    (void *)iocbq->next;
					}

					nlp->nlp_ptx[channelno].q_cnt--;
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
			next = (IOCBQ *) nlp->nlp_tx[channelno].q_first;

			while (next) {
				if (next == iocbq) {
					/* Remove it */
					if (prev) {
						prev->next = iocbq->next;
					}

					if (nlp->nlp_tx[channelno].q_last ==
					    (void *)iocbq) {
						nlp->nlp_tx[channelno].q_last =
						    (void *)prev;
					}

					if (nlp->nlp_tx[channelno].q_first ==
					    (void *)iocbq) {
						nlp->nlp_tx[channelno].q_first =
						    (void *)iocbq->next;
					}

					nlp->nlp_tx[channelno].q_cnt--;
					iocbq->next = NULL;
					found = 1;
					break;
				}

				prev = next;
				next = (IOCBQ *) next->next;
			}
		}

		if (!found) {
			mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_abort_failed_msg,
			    "I/O not found in driver. sbp=%p flags=%x", sbp,
			    sbp->pkt_flags);
			goto done;
		}

		/* Check if node still needs servicing */
		if ((nlp->nlp_ptx[channelno].q_first) ||
		    (nlp->nlp_tx[channelno].q_first &&
		    !(nlp->nlp_flag[channelno] & NLP_CLOSED))) {

			/*
			 * If this is the base node,
			 * then don't shift the pointers
			 */
			/* We want to drain the base node before moving on */
			if (!nlp->nlp_base) {
				/* Just shift channel queue */
				/* pointers to next node */
				cp->nodeq.q_last = (void *) nlp;
				cp->nodeq.q_first = nlp->nlp_next[channelno];
			}
		} else {
			/* Remove node from channel queue */

			/* If this is the only node on list */
			if (cp->nodeq.q_first == (void *)nlp &&
			    cp->nodeq.q_last == (void *)nlp) {
				cp->nodeq.q_last = NULL;
				cp->nodeq.q_first = NULL;
				cp->nodeq.q_cnt = 0;
			} else if (cp->nodeq.q_first == (void *)nlp) {
				cp->nodeq.q_first = nlp->nlp_next[channelno];
				((NODELIST *) cp->nodeq.q_last)->
				    nlp_next[channelno] = cp->nodeq.q_first;
				cp->nodeq.q_cnt--;
			} else {
				/*
				 * This is a little more difficult find the
				 * previous node in the circular channel queue
				 */
				prev_nlp = nlp;
				while (prev_nlp->nlp_next[channelno] != nlp) {
					prev_nlp = prev_nlp->
					    nlp_next[channelno];
				}

				prev_nlp->nlp_next[channelno] =
				    nlp->nlp_next[channelno];

				if (cp->nodeq.q_last == (void *)nlp) {
					cp->nodeq.q_last = (void *)prev_nlp;
				}
				cp->nodeq.q_cnt--;

			}

			/* Clear node */
			nlp->nlp_next[channelno] = NULL;
		}

		/* Free the ULPIOTAG and the bmp */
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			emlxs_sli4_free_xri(port, sbp, sbp->xrip, 1);
		} else {
			(void) emlxs_unregister_pkt(cp, sbp->iotag, 1);
		}


		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

		emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_ABORT_REQUESTED, 1);

		goto done;
	}

	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);


	/* Check the chip queue */
	mutex_enter(&EMLXS_FCTAB_LOCK);

	if ((sbp->pkt_flags & PACKET_IN_CHIPQ) &&
	    !(sbp->pkt_flags & PACKET_XRI_CLOSED) &&
	    (sbp == hba->fc_table[sbp->iotag])) {

		/* Create the abort IOCB */
		if (hba->state >= FC_LINK_UP) {
			iocbq =
			    emlxs_create_abort_xri_cn(port, sbp->node,
			    sbp->iotag, cp, sbp->class, ABORT_TYPE_ABTS);

			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_XRI_CLOSED;
			sbp->ticks =
			    hba->timer_tics + (4 * hba->fc_ratov) + 10;
			sbp->abort_attempts++;
			mutex_exit(&sbp->mtx);
		} else {
			iocbq =
			    emlxs_create_close_xri_cn(port, sbp->node,
			    sbp->iotag, cp);

			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_XRI_CLOSED;
			sbp->ticks = hba->timer_tics + 30;
			sbp->abort_attempts++;
			mutex_exit(&sbp->mtx);
		}

		mutex_exit(&EMLXS_FCTAB_LOCK);

		/* Send this iocbq */
		if (iocbq) {
			EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);
			iocbq = NULL;
		}

		goto done;
	}

	mutex_exit(&EMLXS_FCTAB_LOCK);

	/* Pkt was not on any queues */

	/* Check again if we still own this */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags &
	    (PACKET_ULP_OWNED | PACKET_IN_COMPLETION |
	    PACKET_IN_FLUSH | PACKET_IN_TIMEOUT))) {
		goto done;
	}

	if (!sleep) {
		return (FC_FAILURE);
	}

	/* Apparently the pkt was not found.  Let's delay and try again */
	if (pass < 5) {
		delay(drv_usectohz(5000000));	/* 5 seconds */

		/* Check again if we still own this */
		if (!(sbp->pkt_flags & PACKET_VALID) ||
		    (sbp->pkt_flags &
		    (PACKET_ULP_OWNED | PACKET_IN_COMPLETION |
		    PACKET_IN_FLUSH | PACKET_IN_TIMEOUT))) {
			goto done;
		}

		goto begin;
	}

force_it:

	/* Force the completion now */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "Abort: Completing an IO thats not outstanding: %x", sbp->iotag);

	/* Now complete it */
	emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, IOERR_ABORT_REQUESTED,
	    1);

done:

	/* Now wait for the pkt to complete */
	if (!(sbp->pkt_flags & PACKET_COMPLETED)) {
		/* Set thread timeout */
		pkt_timeout = emlxs_timeout(hba, 30);

		/* Check for panic situation */
		if (ddi_in_panic()) {

			/*
			 * In panic situations there will be one thread with no
			 * interrrupts (hard or soft) and no timers
			 */

			/*
			 * We must manually poll everything in this thread
			 * to keep the driver going.
			 */

			/* Keep polling the chip until our IO is completed */
			(void) drv_getparm(LBOLT, &time);
			timer = time + drv_usectohz(1000000);
			while ((time < pkt_timeout) &&
			    !(sbp->pkt_flags & PACKET_COMPLETED)) {
				EMLXS_SLI_POLL_INTR(hba);
				(void) drv_getparm(LBOLT, &time);

				/* Trigger timer checks periodically */
				if (time >= timer) {
					emlxs_timer_checks(hba);
					timer = time + drv_usectohz(1000000);
				}
			}
		} else {
			/* Wait for IO completion or pkt_timeout */
			mutex_enter(&EMLXS_PKT_LOCK);
			pkt_ret = 0;
			while ((pkt_ret != -1) &&
			    !(sbp->pkt_flags & PACKET_COMPLETED)) {
				pkt_ret =
				    cv_timedwait(&EMLXS_PKT_CV,
				    &EMLXS_PKT_LOCK, pkt_timeout);
			}
			mutex_exit(&EMLXS_PKT_LOCK);
		}

		/* Check if pkt_timeout occured. This is not good. */
		/* Something happened to our IO. */
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
	    !(sbp->pkt_flags & PACKET_ULP_OWNED)) {
		mutex_enter(&sbp->mtx);
		if ((sbp->pkt_flags & PACKET_VALID) &&
		    !(sbp->pkt_flags & PACKET_ULP_OWNED)) {
			sbp->pkt_flags |= PACKET_ULP_OWNED;
		}
		mutex_exit(&sbp->mtx);
	}

#ifdef ULP_PATCH5
	if (cfg[CFG_ENABLE_PATCH].current & ULP_PATCH5) {
		return (FC_FAILURE);
	}
#endif /* ULP_PATCH5 */

	return (FC_SUCCESS);

} /* emlxs_fca_pkt_abort() */


static void
emlxs_abort_all(emlxs_hba_t *hba, uint32_t *tx, uint32_t *chip)
{
	emlxs_port_t   *port = &PPORT;
	fc_packet_t *pkt;
	emlxs_buf_t *sbp;
	uint32_t i;
	uint32_t flg;
	uint32_t rc;
	uint32_t txcnt;
	uint32_t chipcnt;

	txcnt = 0;
	chipcnt = 0;

	mutex_enter(&EMLXS_FCTAB_LOCK);
	for (i = 0; i < hba->max_iotag; i++) {
		sbp = hba->fc_table[i];
		if (sbp == NULL || sbp == STALE_PACKET) {
			continue;
		}
		flg =  (sbp->pkt_flags & PACKET_IN_CHIPQ);
		pkt = PRIV2PKT(sbp);
		mutex_exit(&EMLXS_FCTAB_LOCK);
		rc = emlxs_fca_pkt_abort(port, pkt, 0);
		if (rc == FC_SUCCESS) {
			if (flg) {
				chipcnt++;
			} else {
				txcnt++;
			}
		}
		mutex_enter(&EMLXS_FCTAB_LOCK);
	}
	mutex_exit(&EMLXS_FCTAB_LOCK);
	*tx = txcnt;
	*chip = chipcnt;
} /* emlxs_abort_all() */


extern int32_t
emlxs_reset(emlxs_port_t *port, uint32_t cmd)
{
	emlxs_hba_t	*hba = HBA;
	int		rval;
	int		i = 0;
	int		ret;
	clock_t		timeout;

	switch (cmd) {
	case FC_FCA_LINK_RESET:

		mutex_enter(&EMLXS_PORT_LOCK);
		if (!(hba->flag & FC_ONLINE_MODE) ||
		    (hba->state <= FC_LINK_DOWN)) {
			mutex_exit(&EMLXS_PORT_LOCK);
			return (FC_SUCCESS);
		}

		if (hba->reset_state &
		    (FC_LINK_RESET_INP | FC_PORT_RESET_INP)) {
			mutex_exit(&EMLXS_PORT_LOCK);
			return (FC_FAILURE);
		}

		hba->reset_state |= FC_LINK_RESET_INP;
		hba->reset_request |= FC_LINK_RESET;
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "Resetting Link.");

		mutex_enter(&EMLXS_LINKUP_LOCK);
		hba->linkup_wait_flag = TRUE;
		mutex_exit(&EMLXS_LINKUP_LOCK);

		if (emlxs_reset_link(hba, 1, 1)) {
			mutex_enter(&EMLXS_LINKUP_LOCK);
			hba->linkup_wait_flag = FALSE;
			mutex_exit(&EMLXS_LINKUP_LOCK);

			mutex_enter(&EMLXS_PORT_LOCK);
			hba->reset_state &= ~FC_LINK_RESET_INP;
			hba->reset_request &= ~FC_LINK_RESET;
			mutex_exit(&EMLXS_PORT_LOCK);

			return (FC_FAILURE);
		}

		mutex_enter(&EMLXS_LINKUP_LOCK);
		timeout = emlxs_timeout(hba, 60);
		ret = 0;
		while ((ret != -1) && (hba->linkup_wait_flag == TRUE)) {
			ret =
			    cv_timedwait(&EMLXS_LINKUP_CV, &EMLXS_LINKUP_LOCK,
			    timeout);
		}

		hba->linkup_wait_flag = FALSE;
		mutex_exit(&EMLXS_LINKUP_LOCK);

		mutex_enter(&EMLXS_PORT_LOCK);
		hba->reset_state &= ~FC_LINK_RESET_INP;
		hba->reset_request &= ~FC_LINK_RESET;
		mutex_exit(&EMLXS_PORT_LOCK);

		if (ret == -1) {
			return (FC_FAILURE);
		}

		return (FC_SUCCESS);

	case FC_FCA_CORE:
#ifdef DUMP_SUPPORT
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "Dumping Core.");

		/* Schedule a USER dump */
		emlxs_dump(hba, EMLXS_USER_DUMP, 0, 0);

		/* Wait for dump to complete */
		emlxs_dump_wait(hba);

		return (FC_SUCCESS);
#endif /* DUMP_SUPPORT */

	case FC_FCA_RESET:
	case FC_FCA_RESET_CORE:

		mutex_enter(&EMLXS_PORT_LOCK);
		if (hba->reset_state & FC_PORT_RESET_INP) {
			mutex_exit(&EMLXS_PORT_LOCK);
			return (FC_FAILURE);
		}

		hba->reset_state |= FC_PORT_RESET_INP;
		hba->reset_request |= (FC_PORT_RESET | FC_LINK_RESET);

		/* wait for any pending link resets to complete */
		while ((hba->reset_state & FC_LINK_RESET_INP) &&
		    (i++ < 1000)) {
			mutex_exit(&EMLXS_PORT_LOCK);
			delay(drv_usectohz(1000));
			mutex_enter(&EMLXS_PORT_LOCK);
		}

		if (hba->reset_state & FC_LINK_RESET_INP) {
			hba->reset_state &= ~FC_PORT_RESET_INP;
			hba->reset_request &= ~(FC_PORT_RESET | FC_LINK_RESET);
			mutex_exit(&EMLXS_PORT_LOCK);
			return (FC_FAILURE);
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "Resetting Adapter.");

		rval = FC_SUCCESS;

		if (emlxs_offline(hba, 0) == 0) {
			(void) emlxs_online(hba);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "Adapter reset failed. Device busy.");

			rval = FC_DEVICE_BUSY;
		}

		mutex_enter(&EMLXS_PORT_LOCK);
		hba->reset_state &= ~FC_PORT_RESET_INP;
		hba->reset_request &= ~(FC_PORT_RESET | FC_LINK_RESET);
		mutex_exit(&EMLXS_PORT_LOCK);

		return (rval);

	case EMLXS_DFC_RESET_ALL:
	case EMLXS_DFC_RESET_ALL_FORCE_DUMP:

		mutex_enter(&EMLXS_PORT_LOCK);
		if (hba->reset_state & FC_PORT_RESET_INP) {
			mutex_exit(&EMLXS_PORT_LOCK);
			return (FC_FAILURE);
		}

		hba->reset_state |= FC_PORT_RESET_INP;
		hba->reset_request |= (FC_PORT_RESET | FC_LINK_RESET);

		/* wait for any pending link resets to complete */
		while ((hba->reset_state & FC_LINK_RESET_INP) &&
		    (i++ < 1000)) {
			mutex_exit(&EMLXS_PORT_LOCK);
			delay(drv_usectohz(1000));
			mutex_enter(&EMLXS_PORT_LOCK);
		}

		if (hba->reset_state & FC_LINK_RESET_INP) {
			hba->reset_state &= ~FC_PORT_RESET_INP;
			hba->reset_request &= ~(FC_PORT_RESET | FC_LINK_RESET);
			mutex_exit(&EMLXS_PORT_LOCK);
			return (FC_FAILURE);
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		rval = FC_SUCCESS;

		if (cmd == EMLXS_DFC_RESET_ALL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "Resetting Adapter (All Firmware Reset).");

			emlxs_sli4_hba_reset_all(hba, 0);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "Resetting Adapter "
			    "(All Firmware Reset, Force Dump).");

			emlxs_sli4_hba_reset_all(hba, 1);
		}

		mutex_enter(&EMLXS_PORT_LOCK);
		hba->reset_state &= ~FC_PORT_RESET_INP;
		hba->reset_request &= ~(FC_PORT_RESET | FC_LINK_RESET);
		mutex_exit(&EMLXS_PORT_LOCK);

		/* Wait for the timer thread to detect the error condition */
		delay(drv_usectohz(1000000));

		/* Wait for the HBA to re-initialize */
		i = 0;
		mutex_enter(&EMLXS_PORT_LOCK);
		while (!(hba->flag & FC_ONLINE_MODE) && (i++ < 30)) {
			mutex_exit(&EMLXS_PORT_LOCK);
			delay(drv_usectohz(1000000));
			mutex_enter(&EMLXS_PORT_LOCK);
		}

		if (!(hba->flag & FC_ONLINE_MODE)) {
			rval = FC_FAILURE;
		}

		mutex_exit(&EMLXS_PORT_LOCK);

		return (rval);

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "reset: Unknown command. cmd=%x", cmd);

		break;
	}

	return (FC_FAILURE);

} /* emlxs_reset() */


extern int32_t
emlxs_fca_reset(opaque_t fca_port_handle, uint32_t cmd)
{
	emlxs_port_t	*port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t	*hba = HBA;
	int32_t		rval;

	if (port->mode != MODE_INITIATOR) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset failed. Port is not in initiator mode.");

		return (FC_FAILURE);
	}

	if (!(port->flag & EMLXS_INI_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset: Port not bound.");

		return (FC_UNBOUND);
	}

	switch (cmd) {
	case FC_FCA_LINK_RESET:
		if (hba->fw_flag & FW_UPDATE_NEEDED) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_reset: FC_FCA_LINK_RESET -> FC_FCA_RESET");
			cmd = FC_FCA_RESET;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_reset: FC_FCA_LINK_RESET");
		}
		break;

	case FC_FCA_CORE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset: FC_FCA_CORE");
		break;

	case FC_FCA_RESET:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset: FC_FCA_RESET");
		break;

	case FC_FCA_RESET_CORE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset: FC_FCA_RESET_CORE");
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_reset: Unknown command. cmd=%x", cmd);
		return (FC_FAILURE);
	}

	if (hba->fw_flag & FW_UPDATE_NEEDED) {
		hba->fw_flag |= FW_UPDATE_KERNEL;
	}

	rval = emlxs_reset(port, cmd);

	return (rval);

} /* emlxs_fca_reset() */


extern int
emlxs_fca_port_manage(opaque_t fca_port_handle, fc_fca_pm_t *pm)
{
	emlxs_port_t	*port = (emlxs_port_t *)fca_port_handle;
	emlxs_hba_t	*hba = HBA;
	int32_t		ret;
	emlxs_vpd_t	*vpd = &VPD;

	ret = FC_SUCCESS;

#ifdef IDLE_TIMER
	emlxs_pm_busy_component(hba);
#endif	/* IDLE_TIMER */

	switch (pm->pm_cmd_code) {

	case FC_PORT_GET_FW_REV:
	{
		char buffer[128];

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_GET_FW_REV");

		(void) snprintf(buffer, (sizeof (buffer)-1),
		    "%s %s", hba->model_info.model,
		    vpd->fw_version);
		bzero(pm->pm_data_buf, pm->pm_data_len);

		if (pm->pm_data_len < strlen(buffer) + 1) {
			ret = FC_NOMEM;

			break;
		}

		(void) strncpy(pm->pm_data_buf, buffer,
		    (pm->pm_data_len-1));
		break;
	}

	case FC_PORT_GET_FCODE_REV:
	{
		char buffer[128];

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_GET_FCODE_REV");

		/* Force update here just to be sure */
		emlxs_get_fcode_version(hba);

		(void) snprintf(buffer, (sizeof (buffer)-1),
		    "%s %s", hba->model_info.model,
		    vpd->fcode_version);
		bzero(pm->pm_data_buf, pm->pm_data_len);

		if (pm->pm_data_len < strlen(buffer) + 1) {
			ret = FC_NOMEM;
			break;
		}

		(void) strncpy(pm->pm_data_buf, buffer,
		    (pm->pm_data_len-1));
		break;
	}

	case FC_PORT_GET_DUMP_SIZE:
	{
#ifdef DUMP_SUPPORT
		uint32_t dump_size = 0;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_GET_DUMP_SIZE");

		if (pm->pm_data_len < sizeof (uint32_t)) {
			ret = FC_NOMEM;
			break;
		}

		(void) emlxs_get_dump(hba, NULL, &dump_size);

		*((uint32_t *)pm->pm_data_buf) = dump_size;

#else
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_GET_DUMP_SIZE unsupported.");

#endif /* DUMP_SUPPORT */

		break;
	}

	case FC_PORT_GET_DUMP:
	{
#ifdef DUMP_SUPPORT
		uint32_t dump_size = 0;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_GET_DUMP");

		(void) emlxs_get_dump(hba, NULL, &dump_size);

		if (pm->pm_data_len < dump_size) {
			ret = FC_NOMEM;
			break;
		}

		(void) emlxs_get_dump(hba, (uint8_t *)pm->pm_data_buf,
		    (uint32_t *)&dump_size);
#else
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_GET_DUMP unsupported.");

#endif /* DUMP_SUPPORT */

		break;
	}

	case FC_PORT_FORCE_DUMP:
	{
#ifdef DUMP_SUPPORT
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_FORCE_DUMP");

		/* Schedule a USER dump */
		emlxs_dump(hba, EMLXS_USER_DUMP, 0, 0);

		/* Wait for dump to complete */
		emlxs_dump_wait(hba);
#else
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_FORCE_DUMP unsupported.");

#endif /* DUMP_SUPPORT */
		break;
	}

	case FC_PORT_LINK_STATE:
	{
		uint32_t	*link_state;

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
			case LA_16GHZ_LINK:
				*link_state |= FC_STATE_16GBIT_SPEED;
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
		MAILBOXQ	*mbq;
		MAILBOX		*mb;
		fc_rls_acc_t	*bp;

		if (!(hba->flag & FC_ONLINE_MODE)) {
			return (FC_OFFLINE);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_RLS / FC_PORT_ERR_STATS");

		if (pm->pm_data_len < sizeof (fc_rls_acc_t)) {
			ret = FC_NOMEM;
			break;
		}

		if ((mbq = (MAILBOXQ *)emlxs_mem_get(hba,
		    MEM_MBOX)) == 0) {
			ret = FC_NOMEM;
			break;
		}
		mb = (MAILBOX *)mbq;

		emlxs_mb_read_lnk_stat(hba, mbq);
		if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0)
		    != MBX_SUCCESS) {
			ret = FC_PBUSY;
		} else {
			bp = (fc_rls_acc_t *)pm->pm_data_buf;

			bp->rls_link_fail = mb->un.varRdLnk.linkFailureCnt;
			bp->rls_sync_loss = mb->un.varRdLnk.lossSyncCnt;
			bp->rls_sig_loss = mb->un.varRdLnk.lossSignalCnt;
			bp->rls_prim_seq_err = mb->un.varRdLnk.primSeqErrCnt;
			bp->rls_invalid_word =
			    mb->un.varRdLnk.invalidXmitWord;
			bp->rls_invalid_crc = mb->un.varRdLnk.crcCnt;
		}

		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		break;
	}

	case FC_PORT_DOWNLOAD_FW:
		if (!(hba->flag & FC_ONLINE_MODE)) {
			return (FC_OFFLINE);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_DOWNLOAD_FW");
		ret = emlxs_fw_download(hba, pm->pm_data_buf,
		    pm->pm_data_len, 1);
		break;

	case FC_PORT_DOWNLOAD_FCODE:
		if (!(hba->flag & FC_ONLINE_MODE)) {
			return (FC_OFFLINE);
		}
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

			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: DIAG_BIU");

			if (pm->pm_data_len) {
				pattern = *((uint32_t *)pm->pm_data_buf);
			}

			errno = emlxs_diag_biu_run(hba, pattern);

			if (pm->pm_stat_len == sizeof (errno)) {
				*(int *)pm->pm_stat_buf = errno;
			}

			break;


		case EMLXS_DIAG_POST:

			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: DIAG_POST");

			errno = emlxs_diag_post_run(hba);

			if (pm->pm_stat_len == sizeof (errno)) {
				*(int *)pm->pm_stat_buf = errno;
			}

			break;


		case EMLXS_DIAG_ECHO:

			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: DIAG_ECHO");

			if (pm->pm_cmd_len != sizeof (uint32_t)) {
				ret = FC_INVALID_REQUEST;
				break;
			}

			did = *((uint32_t *)pm->pm_cmd_buf);

			if (pm->pm_data_len) {
				pattern = *((uint32_t *)pm->pm_data_buf);
			}

			errno = emlxs_diag_echo_run(port, did, pattern);

			if (pm->pm_stat_len == sizeof (errno)) {
				*(int *)pm->pm_stat_buf = errno;
			}

			break;


		case EMLXS_PARM_GET_NUM:
		{
			uint32_t	*num;
			emlxs_config_t	*cfg;
			uint32_t	i;
			uint32_t	count;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: PARM_GET_NUM");

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
			emlxs_parm_t	*parm;
			emlxs_config_t	*cfg;
			uint32_t	i;
			uint32_t	max_count;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: PARM_GET_LIST");

			if (pm->pm_stat_len < sizeof (emlxs_parm_t)) {
				ret = FC_NOMEM;
				break;
			}

			max_count = pm->pm_stat_len / sizeof (emlxs_parm_t);

			parm = (emlxs_parm_t *)pm->pm_stat_buf;
			cfg = &CFG;
			for (i = 0; i < NUM_CFG_PARAM && max_count; i++,
			    cfg++) {
				if (!(cfg->flags & PARM_HIDDEN)) {
					(void) strncpy(parm->label, cfg->string,
					    (sizeof (parm->label)-1));
					parm->min = cfg->low;
					parm->max = cfg->hi;
					parm->def = cfg->def;
					parm->current = cfg->current;
					parm->flags = cfg->flags;
					(void) strncpy(parm->help, cfg->help,
					    (sizeof (parm->help)-1));
					parm++;
					max_count--;
				}
			}

			break;
		}

		case EMLXS_PARM_GET:
		{
			emlxs_parm_t	*parm_in;
			emlxs_parm_t	*parm_out;
			emlxs_config_t	*cfg;
			uint32_t	i;
			uint32_t	len;

			if (pm->pm_cmd_len < sizeof (emlxs_parm_t)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "fca_port_manage: PARM_GET. "
				    "inbuf too small.");

				ret = FC_BADCMD;
				break;
			}

			if (pm->pm_stat_len < sizeof (emlxs_parm_t)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "fca_port_manage: PARM_GET. "
				    "outbuf too small");

				ret = FC_BADCMD;
				break;
			}

			parm_in = (emlxs_parm_t *)pm->pm_cmd_buf;
			parm_out = (emlxs_parm_t *)pm->pm_stat_buf;
			len = strlen(parm_in->label);
			cfg = &CFG;
			ret = FC_BADOBJECT;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: PARM_GET: %s=0x%x,%d",
			    parm_in->label, parm_in->current,
			    parm_in->current);

			for (i = 0; i < NUM_CFG_PARAM; i++, cfg++) {
				if (len == strlen(cfg->string) &&
				    (strcmp(parm_in->label,
				    cfg->string) == 0)) {
					(void) strncpy(parm_out->label,
					    cfg->string,
					    (sizeof (parm_out->label)-1));
					parm_out->min = cfg->low;
					parm_out->max = cfg->hi;
					parm_out->def = cfg->def;
					parm_out->current = cfg->current;
					parm_out->flags = cfg->flags;
					(void) strncpy(parm_out->help,
					    cfg->help,
					    (sizeof (parm_out->help)-1));

					ret = FC_SUCCESS;
					break;
				}
			}

			break;
		}

		case EMLXS_PARM_SET:
		{
			emlxs_parm_t	*parm_in;
			emlxs_parm_t	*parm_out;
			emlxs_config_t	*cfg;
			uint32_t	i;
			uint32_t	len;

			if (pm->pm_cmd_len < sizeof (emlxs_parm_t)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "fca_port_manage: PARM_GET. "
				    "inbuf too small.");

				ret = FC_BADCMD;
				break;
			}

			if (pm->pm_stat_len < sizeof (emlxs_parm_t)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "fca_port_manage: PARM_GET. "
				    "outbuf too small");
				ret = FC_BADCMD;
				break;
			}

			parm_in = (emlxs_parm_t *)pm->pm_cmd_buf;
			parm_out = (emlxs_parm_t *)pm->pm_stat_buf;
			len = strlen(parm_in->label);
			cfg = &CFG;
			ret = FC_BADOBJECT;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: PARM_SET: %s=0x%x,%d",
			    parm_in->label, parm_in->current,
			    parm_in->current);

			for (i = 0; i < NUM_CFG_PARAM; i++, cfg++) {
				/* Find matching parameter string */
				if (len == strlen(cfg->string) &&
				    (strcmp(parm_in->label,
				    cfg->string) == 0)) {
					/* Attempt to update parameter */
					if (emlxs_set_parm(hba, i,
					    parm_in->current) == FC_SUCCESS) {
						(void) strncpy(parm_out->label,
						    cfg->string,
						    (sizeof (parm_out->label)-
						    1));
						parm_out->min = cfg->low;
						parm_out->max = cfg->hi;
						parm_out->def = cfg->def;
						parm_out->current =
						    cfg->current;
						parm_out->flags = cfg->flags;
						(void) strncpy(parm_out->help,
						    cfg->help,
						    (sizeof (parm_out->help)-
						    1));

						ret = FC_SUCCESS;
					}

					break;
				}
			}

			break;
		}

		case EMLXS_LOG_GET:
		{
			emlxs_log_req_t		*req;
			emlxs_log_resp_t	*resp;
			uint32_t		len;

			/* Check command size */
			if (pm->pm_cmd_len < sizeof (emlxs_log_req_t)) {
				ret = FC_BADCMD;
				break;
			}

			/* Get the request */
			req = (emlxs_log_req_t *)pm->pm_cmd_buf;

			/* Calculate the response length from the request */
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
			    "fca_port_manage: GET_BOOT_REV");

			if (pm->pm_stat_len < strlen(vpd->boot_version)) {
				ret = FC_NOMEM;
				break;
			}

			bzero(pm->pm_stat_buf, pm->pm_stat_len);
			(void) snprintf(pm->pm_stat_buf, pm->pm_stat_len,
			    "%s %s", hba->model_info.model, vpd->boot_version);

			break;
		}

		case EMLXS_DOWNLOAD_BOOT:
			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: DOWNLOAD_BOOT");

			ret = emlxs_fw_download(hba, pm->pm_data_buf,
			    pm->pm_data_len, 1);
			break;

		case EMLXS_DOWNLOAD_CFL:
		{
			uint32_t *buffer;
			uint32_t region;
			uint32_t length;

			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: DOWNLOAD_CFL");

			/* Extract the region number from the first word. */
			buffer = (uint32_t *)pm->pm_data_buf;
			region = *buffer++;

			/* Adjust the image length for the header word */
			length = pm->pm_data_len - 4;

			ret =
			    emlxs_cfl_download(hba, region, (caddr_t)buffer,
			    length);
			break;
		}

		case EMLXS_VPD_GET:
		{
			emlxs_vpd_desc_t	*vpd_out;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: VPD_GET");

			if (pm->pm_stat_len < sizeof (emlxs_vpd_desc_t)) {
				ret = FC_BADCMD;
				break;
			}

			vpd_out = (emlxs_vpd_desc_t *)pm->pm_stat_buf;
			bzero(vpd_out, pm->pm_stat_len);

			(void) strncpy(vpd_out->id, vpd->id,
			    (sizeof (vpd_out->id)-1));
			(void) strncpy(vpd_out->part_num, vpd->part_num,
			    (sizeof (vpd_out->part_num)-1));
			(void) strncpy(vpd_out->eng_change, vpd->eng_change,
			    (sizeof (vpd_out->eng_change)-1));
			(void) strncpy(vpd_out->manufacturer, vpd->manufacturer,
			    (sizeof (vpd_out->manufacturer)-1));
			(void) strncpy(vpd_out->serial_num, vpd->serial_num,
			    (sizeof (vpd_out->serial_num)-1));
			(void) strncpy(vpd_out->model, vpd->model,
			    (sizeof (vpd_out->model)-1));
			(void) strncpy(vpd_out->model_desc, vpd->model_desc,
			    (sizeof (vpd_out->model_desc)-1));
			(void) strncpy(vpd_out->port_num, vpd->port_num,
			    (sizeof (vpd_out->port_num)-1));
			(void) strncpy(vpd_out->prog_types, vpd->prog_types,
			    (sizeof (vpd_out->prog_types)-1));

			ret = FC_SUCCESS;

			break;
		}

		case EMLXS_VPD_GET_V2:
		{
			emlxs_vpd_desc_v2_t	*vpd_out;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: VPD_GET_V2");

			if (pm->pm_stat_len < sizeof (emlxs_vpd_desc_v2_t)) {
				ret = FC_BADCMD;
				break;
			}

			vpd_out = (emlxs_vpd_desc_v2_t *)pm->pm_stat_buf;
			bzero(vpd_out, pm->pm_stat_len);

			(void) strncpy(vpd_out->id, vpd->id,
			    (sizeof (vpd_out->id)-1));
			(void) strncpy(vpd_out->part_num, vpd->part_num,
			    (sizeof (vpd_out->part_num)-1));
			(void) strncpy(vpd_out->eng_change, vpd->eng_change,
			    (sizeof (vpd_out->eng_change)-1));
			(void) strncpy(vpd_out->manufacturer, vpd->manufacturer,
			    (sizeof (vpd_out->manufacturer)-1));
			(void) strncpy(vpd_out->serial_num, vpd->serial_num,
			    (sizeof (vpd_out->serial_num)-1));
			(void) strncpy(vpd_out->model, vpd->model,
			    (sizeof (vpd_out->model)-1));
			(void) strncpy(vpd_out->model_desc, vpd->model_desc,
			    (sizeof (vpd_out->model_desc)-1));
			(void) strncpy(vpd_out->port_num, vpd->port_num,
			    (sizeof (vpd_out->port_num)-1));
			(void) strncpy(vpd_out->prog_types, vpd->prog_types,
			    (sizeof (vpd_out->prog_types)-1));

			ret = FC_SUCCESS;

			break;
		}

		case EMLXS_PHY_GET:
		{
			emlxs_phy_desc_t	*phy_out;
			MAILBOXQ *mbq;
			MAILBOX4 *mb;
			IOCTL_COMMON_GET_PHY_DETAILS *phy;
			mbox_req_hdr_t	*hdr_req;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: EMLXS_PHY_GET");

			if (pm->pm_stat_len < sizeof (emlxs_phy_desc_t)) {
				ret = FC_BADCMD;
				break;
			}

			if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "Invalid sli_mode. mode=%d", hba->sli_mode);
				ret = FC_BADCMD;
				break;
			}

			phy_out = (emlxs_phy_desc_t *)pm->pm_stat_buf;
			bzero(phy_out, sizeof (emlxs_phy_desc_t));

			if ((mbq = (MAILBOXQ *)emlxs_mem_get(hba,
			    MEM_MBOX)) == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "Unable to allocate mailbox buffer.");
				ret = FC_NOMEM;
				break;
			}

			mb = (MAILBOX4*)mbq;

			bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

			mb->un.varSLIConfig.be.embedded = 1;
			mbq->mbox_cmpl = NULL;

			mb->mbxCommand = MBX_SLI_CONFIG;
			mb->mbxOwner = OWN_HOST;

			hdr_req = (mbox_req_hdr_t *)
			    &mb->un.varSLIConfig.be.un_hdr.hdr_req;
			hdr_req->subsystem = IOCTL_SUBSYSTEM_COMMON;
			hdr_req->opcode = COMMON_OPCODE_GET_PHY_DETAILS;
			hdr_req->timeout = 0;
			hdr_req->req_length =
			    sizeof (IOCTL_COMMON_GET_PHY_DETAILS);

			phy = (IOCTL_COMMON_GET_PHY_DETAILS *)(hdr_req + 1);

			/* Send read request */
			if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) !=
			    MBX_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "Unable to get PHY details. status=%x",
				    mb->mbxStatus);

				emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

				ret = FC_FAILURE;
				break;
			}

			phy_out->phy_type = phy->params.response.phy_type;
			phy_out->interface_type =
			    phy->params.response.interface_type;
			phy_out->misc_params = phy->params.response.misc_params;
			phy_out->rsvd[0] = phy->params.response.rsvd[0];
			phy_out->rsvd[1] = phy->params.response.rsvd[1];
			phy_out->rsvd[2] = phy->params.response.rsvd[2];
			phy_out->rsvd[3] = phy->params.response.rsvd[3];

			emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

			ret = FC_SUCCESS;
			break;
		}

#ifdef NODE_THROTTLE_SUPPORT
		case EMLXS_SET_THROTTLE:
		{
			emlxs_node_t *node;
			uint32_t scope = 0;
			uint32_t i;
			char buf1[32];
			emlxs_throttle_desc_t *desc;

			if ((pm->pm_data_buf == NULL) ||
			    (pm->pm_data_len !=
			    sizeof (emlxs_throttle_desc_t))) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_SET_THROTTLE: "
				    "Descriptor buffer not valid. %d",
				    pm->pm_data_len);
				ret = FC_BADCMD;
				break;
			}

			if ((pm->pm_cmd_buf != NULL) &&
			    (pm->pm_cmd_len == sizeof (uint32_t))) {
				scope = *(uint32_t *)pm->pm_cmd_buf;
			}

			desc = (emlxs_throttle_desc_t *)pm->pm_data_buf;
			desc->throttle = MIN(desc->throttle, MAX_NODE_THROTTLE);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: EMLXS_SET_THROTTLE: scope=%d "
			    "depth=%d",
			    scope, desc->throttle);

			rw_enter(&port->node_rwlock, RW_WRITER);
			switch (scope) {
			case 1: /* all */
				for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				node = port->node_table[i];
				while (node != NULL) {
					node->io_throttle = desc->throttle;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "EMLXS_SET_THROTTLE: wwpn=%s "
					    "depth=%d",
					    emlxs_wwn_xlate(buf1, sizeof (buf1),
					    (uint8_t *)&node->nlp_portname),
					    node->io_throttle);

					node = (NODELIST *)node->nlp_list_next;
				}
				}
				break;

			case 2: /* FCP */
				for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				node = port->node_table[i];
				while (node != NULL) {
					if (!(node->nlp_fcp_info &
					    NLP_FCP_TGT_DEVICE)) {
						node = (NODELIST *)
						    node->nlp_list_next;
						continue;
					}

					node->io_throttle = desc->throttle;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "EMLXS_SET_THROTTLE: wwpn=%s "
					    "depth=%d",
					    emlxs_wwn_xlate(buf1, sizeof (buf1),
					    (uint8_t *)&node->nlp_portname),
					    node->io_throttle);

					node = (NODELIST *)node->nlp_list_next;
				}
				}
				break;

			case 0: /* WWPN */
			default:
				for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				node = port->node_table[i];
				while (node != NULL) {
					if (bcmp((caddr_t)&node->nlp_portname,
					    desc->wwpn, 8)) {
						node = (NODELIST *)
						    node->nlp_list_next;
						continue;
					}

					node->io_throttle = desc->throttle;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "EMLXS_SET_THROTTLE: wwpn=%s "
					    "depth=%d",
					    emlxs_wwn_xlate(buf1, sizeof (buf1),
					    (uint8_t *)&node->nlp_portname),
					    node->io_throttle);

					goto set_throttle_done;
				}
				}
set_throttle_done:
				break;
			}

			rw_exit(&port->node_rwlock);
			ret = FC_SUCCESS;

			break;
		}

		case EMLXS_GET_THROTTLE:
		{
			emlxs_node_t *node;
			uint32_t i;
			uint32_t j;
			char buf1[32];
			uint32_t count;
			emlxs_throttle_desc_t *desc;

			if (pm->pm_stat_len == sizeof (uint32_t)) {
				count = emlxs_nport_count(port);
				*(uint32_t *)pm->pm_stat_buf = count;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_GET_THROTTLE: "
				    "count=%d",
				    count);

				ret = FC_SUCCESS;
				break;
			}

			if ((pm->pm_stat_buf == NULL) ||
			    (pm->pm_stat_len <
			    sizeof (emlxs_throttle_desc_t))) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "fca_port_manage: EMLXS_GET_THROTTLE: "
				    "Descriptor buffer too small. %d",
				    pm->pm_data_len);
				ret = FC_BADCMD;
				break;
			}

			count = pm->pm_stat_len /
			    sizeof (emlxs_throttle_desc_t);
			desc = (emlxs_throttle_desc_t *)pm->pm_stat_buf;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: EMLXS_GET_THROTTLE: max=%d",
			    count);

			rw_enter(&port->node_rwlock, RW_READER);
			j = 0;
			for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				node = port->node_table[i];
				while (node != NULL) {
					if ((node->nlp_DID & 0xFFF000) ==
					    0xFFF000) {
						node = (NODELIST *)
						    node->nlp_list_next;
						continue;
					}

					bcopy((uint8_t *)&node->nlp_portname,
					    desc[j].wwpn, 8);
					desc[j].throttle = node->io_throttle;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "EMLXS_GET_THROTTLE: wwpn=%s "
					    "depth=%d",
					    emlxs_wwn_xlate(buf1, sizeof (buf1),
					    desc[j].wwpn),
					    desc[j].throttle);

					j++;
					if (j >= count) {
						goto get_throttle_done;
					}

					node = (NODELIST *)node->nlp_list_next;
				}
			}
get_throttle_done:
			rw_exit(&port->node_rwlock);
			ret = FC_SUCCESS;

			break;
		}
#endif /* NODE_THROTTLE_SUPPORT */

		case EMLXS_GET_FCIO_REV:
		{
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: GET_FCIO_REV");

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
			    "fca_port_manage: GET_DFC_REV");

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
			uint32_t	state;

			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}
			if (pm->pm_cmd_len < sizeof (uint32_t)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "fca_port_manage: SET_BOOT_STATE");
				ret = FC_BADCMD;
				break;
			}

			state = *(uint32_t *)pm->pm_cmd_buf;

			if (state == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "fca_port_manage: SET_BOOT_STATE: "
				    "Disable");
				ret = emlxs_boot_code_disable(hba);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "fca_port_manage: SET_BOOT_STATE: "
				    "Enable");
				ret = emlxs_boot_code_enable(hba);
			}

			break;
		}

		case EMLXS_GET_BOOT_STATE:
		case EMLXS_GET_BOOT_STATE_old:
		{
			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: GET_BOOT_STATE");

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
			/*
			 * This command is used for simulating HW ERROR
			 * on SLI4 only.
			 */
			if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
				ret = FC_INVALID_REQUEST;
				break;
			}
			hba->sli.sli4.flag |= EMLXS_SLI4_HW_ERROR;
			break;
		}

		case EMLXS_MB_TIMEOUT_TEST:
		{
			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: HW_ERROR_TEST");

			/* Trigger a mailbox timeout */
			hba->mbox_timer = hba->timer_tics;

			break;
		}

		case EMLXS_TEST_CODE:
		{
			uint32_t *cmd;

			if (!(hba->flag & FC_ONLINE_MODE)) {
				return (FC_OFFLINE);
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: TEST_CODE");

			if (pm->pm_cmd_len < sizeof (uint32_t)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "fca_port_manage: TEST_CODE. "
				    "inbuf to small.");

				ret = FC_BADCMD;
				break;
			}

			cmd = (uint32_t *)pm->pm_cmd_buf;

			ret = emlxs_test(hba, cmd[0],
			    (pm->pm_cmd_len/sizeof (uint32_t)) - 1, &cmd[1]);

			break;
		}

		case EMLXS_BAR_IO:
		{
			uint32_t *cmd;
			uint32_t *datap;
			FCIO_Q_STAT_t *qp;
			clock_t	 time;
			uint32_t offset;
			caddr_t  addr;
			uint32_t i;
			uint32_t tx_cnt;
			uint32_t chip_cnt;

			cmd = (uint32_t *)pm->pm_cmd_buf;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "fca_port_manage: BAR_IO %x %x %x",
			    cmd[0], cmd[1], cmd[2]);

			offset = cmd[1];

			ret = FC_SUCCESS;

			switch (cmd[0]) {
			case 2: /* bar1read */
				if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
					return (FC_BADCMD);
				}

				/* Registers in this range are invalid */
				if ((offset >= 0x4C00) && (offset < 0x5000)) {
					return (FC_BADCMD);
				}
				if ((offset >= 0x5800) || (offset & 0x3)) {
					return (FC_BADCMD);
				}
				datap = (uint32_t *)pm->pm_stat_buf;

				for (i = 0; i < pm->pm_stat_len;
				    i += sizeof (uint32_t)) {
					if ((offset >= 0x4C00) &&
					    (offset < 0x5000)) {
						pm->pm_stat_len = i;
						break;
					}
					if (offset >= 0x5800) {
						pm->pm_stat_len = i;
						break;
					}
					addr = hba->sli.sli4.bar1_addr + offset;
					*datap = READ_BAR1_REG(hba, addr);
					datap++;
					offset += sizeof (uint32_t);
				}
#ifdef FMA_SUPPORT
				/* Access handle validation */
				EMLXS_CHK_ACC_HANDLE(hba,
				    hba->sli.sli4.bar1_acc_handle);
#endif  /* FMA_SUPPORT */
				break;
			case 3: /* bar2read */
				if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
					return (FC_BADCMD);
				}
				if ((offset >= 0x1000) || (offset & 0x3)) {
					return (FC_BADCMD);
				}
				datap = (uint32_t *)pm->pm_stat_buf;

				for (i = 0; i < pm->pm_stat_len;
				    i += sizeof (uint32_t)) {
					*datap = READ_BAR2_REG(hba,
					    hba->sli.sli4.bar2_addr + offset);
					datap++;
					offset += sizeof (uint32_t);
				}
#ifdef FMA_SUPPORT
				/* Access handle validation */
				EMLXS_CHK_ACC_HANDLE(hba,
				    hba->sli.sli4.bar2_acc_handle);
#endif  /* FMA_SUPPORT */
				break;
			case 4: /* bar1write */
				if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
					return (FC_BADCMD);
				}
				WRITE_BAR1_REG(hba, hba->sli.sli4.bar1_addr +
				    offset, cmd[2]);
#ifdef FMA_SUPPORT
				/* Access handle validation */
				EMLXS_CHK_ACC_HANDLE(hba,
				    hba->sli.sli4.bar1_acc_handle);
#endif  /* FMA_SUPPORT */
				break;
			case 5: /* bar2write */
				if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
					return (FC_BADCMD);
				}
				WRITE_BAR2_REG(hba, hba->sli.sli4.bar2_addr +
				    offset, cmd[2]);
#ifdef FMA_SUPPORT
				/* Access handle validation */
				EMLXS_CHK_ACC_HANDLE(hba,
				    hba->sli.sli4.bar2_acc_handle);
#endif  /* FMA_SUPPORT */
				break;
			case 6: /* dumpbsmbox */
				if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
					return (FC_BADCMD);
				}
				if (offset != 0) {
					return (FC_BADCMD);
				}

				bcopy((caddr_t)hba->sli.sli4.bootstrapmb.virt,
				    (caddr_t)pm->pm_stat_buf, 256);
				break;
			case 7: /* pciread */
				if ((offset >= 0x200) || (offset & 0x3)) {
					return (FC_BADCMD);
				}
				datap = (uint32_t *)pm->pm_stat_buf;
				for (i = 0; i < pm->pm_stat_len;
				    i += sizeof (uint32_t)) {
					*datap = ddi_get32(hba->pci_acc_handle,
					    (uint32_t *)(hba->pci_addr +
					    offset));
					datap++;
					offset += sizeof (uint32_t);
				}
#ifdef FMA_SUPPORT
				/* Access handle validation */
				EMLXS_CHK_ACC_HANDLE(hba, hba->pci_acc_handle);
#endif  /* FMA_SUPPORT */
				break;
			case 8: /* abortall */
				if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
					return (FC_BADCMD);
				}
				emlxs_abort_all(hba, &tx_cnt, &chip_cnt);
				datap = (uint32_t *)pm->pm_stat_buf;
				*datap++ = tx_cnt;
				*datap = chip_cnt;
				break;
			case 9: /* get_q_info */
				if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
					return (FC_BADCMD);
				}
				qp = (FCIO_Q_STAT_t *)pm->pm_stat_buf;
				for (i = 0; i < FCIO_MAX_EQS; i++) {
					addr = hba->sli.sli4.eq[i].addr.virt;
					qp->eq[i].host_index =
					    hba->sli.sli4.eq[i].host_index;
					qp->eq[i].max_index =
					    hba->sli.sli4.eq[i].max_index;
					qp->eq[i].qid =
					    hba->sli.sli4.eq[i].qid;
					qp->eq[i].msix_vector =
					    hba->sli.sli4.eq[i].msix_vector;
					qp->eq[i].phys =
					    hba->sli.sli4.eq[i].addr.phys;
					qp->eq[i].virt = PADDR_LO(
					    (uintptr_t)addr);
					qp->eq[i].virt_hi  = PADDR_HI(
					    (uintptr_t)addr);
					qp->eq[i].max_proc =
					    hba->sli.sli4.eq[i].max_proc;
					qp->eq[i].isr_count =
					    hba->sli.sli4.eq[i].isr_count;
					qp->eq[i].num_proc =
					    hba->sli.sli4.eq[i].num_proc;
				}
				for (i = 0; i < FCIO_MAX_CQS; i++) {
					addr = hba->sli.sli4.cq[i].addr.virt;
					qp->cq[i].host_index =
					    hba->sli.sli4.cq[i].host_index;
					qp->cq[i].max_index =
					    hba->sli.sli4.cq[i].max_index;
					qp->cq[i].qid =
					    hba->sli.sli4.cq[i].qid;
					qp->cq[i].eqid =
					    hba->sli.sli4.cq[i].eqid;
					qp->cq[i].type =
					    hba->sli.sli4.cq[i].type;
					qp->cq[i].phys =
					    hba->sli.sli4.cq[i].addr.phys;
					qp->cq[i].virt = PADDR_LO(
					    (uintptr_t)addr);
					qp->cq[i].virt_hi = PADDR_HI(
					    (uintptr_t)addr);
					qp->cq[i].max_proc =
					    hba->sli.sli4.cq[i].max_proc;
					qp->cq[i].isr_count =
					    hba->sli.sli4.cq[i].isr_count;
					qp->cq[i].num_proc =
					    hba->sli.sli4.cq[i].num_proc;
				}
				for (i = 0; i < FCIO_MAX_WQS; i++) {
					addr = hba->sli.sli4.wq[i].addr.virt;
					qp->wq[i].host_index =
					    hba->sli.sli4.wq[i].host_index;
					qp->wq[i].max_index =
					    hba->sli.sli4.wq[i].max_index;
					qp->wq[i].port_index =
					    hba->sli.sli4.wq[i].port_index;
					qp->wq[i].release_depth =
					    hba->sli.sli4.wq[i].release_depth;
					qp->wq[i].qid =
					    hba->sli.sli4.wq[i].qid;
					qp->wq[i].cqid =
					    hba->sli.sli4.wq[i].cqid;
					qp->wq[i].phys =
					    hba->sli.sli4.wq[i].addr.phys;
					qp->wq[i].virt = PADDR_LO(
					    (uintptr_t)addr);
					qp->wq[i].virt_hi = PADDR_HI(
					    (uintptr_t)addr);
					qp->wq[i].num_proc =
					    hba->sli.sli4.wq[i].num_proc;
					qp->wq[i].num_busy =
					    hba->sli.sli4.wq[i].num_busy;
				}
				for (i = 0; i < FCIO_MAX_RQS; i++) {
					addr = hba->sli.sli4.rq[i].addr.virt;
					qp->rq[i].qid =
					    hba->sli.sli4.rq[i].qid;
					qp->rq[i].cqid =
					    hba->sli.sli4.rq[i].cqid;
					qp->rq[i].host_index =
					    hba->sli.sli4.rq[i].host_index;
					qp->rq[i].max_index =
					    hba->sli.sli4.rq[i].max_index;
					qp->rq[i].phys =
					    hba->sli.sli4.rq[i].addr.phys;
					qp->rq[i].virt = PADDR_LO(
					    (uintptr_t)addr);
					qp->rq[i].virt_hi = PADDR_HI(
					    (uintptr_t)addr);
					qp->rq[i].num_proc =
					    hba->sli.sli4.rq[i].num_proc;
				}
				qp->que_start_timer =
				    hba->sli.sli4.que_stat_timer;
				(void) drv_getparm(LBOLT, &time);
				qp->que_current_timer = (uint32_t)time;
				qp->intr_count = hba->intr_count;
				break;
			case 10: /* zero_q_stat */
				if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
					return (FC_BADCMD);
				}
				emlxs_sli4_zero_queue_stat(hba);
				break;
			default:
				ret = FC_BADCMD;
				break;
			}
			break;
		}

		default:

			ret = FC_INVALID_REQUEST;
			break;
		}

		break;

	}

	case FC_PORT_INITIALIZE:
		if (!(hba->flag & FC_ONLINE_MODE)) {
			return (FC_OFFLINE);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_INITIALIZE");
		break;

	case FC_PORT_LOOPBACK:
		if (!(hba->flag & FC_ONLINE_MODE)) {
			return (FC_OFFLINE);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_LOOPBACK");
		break;

	case FC_PORT_BYPASS:
		if (!(hba->flag & FC_ONLINE_MODE)) {
			return (FC_OFFLINE);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_BYPASS");
		ret = FC_INVALID_REQUEST;
		break;

	case FC_PORT_UNBYPASS:
		if (!(hba->flag & FC_ONLINE_MODE)) {
			return (FC_OFFLINE);
		}
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

		(void) snprintf((char *)rnid->global_id,
		    (sizeof (rnid->global_id)-1),
		    "%01x%01x%02x%02x%02x%02x%02x%02x%02x",
		    hba->wwpn.nameType, hba->wwpn.IEEEextMsn,
		    hba->wwpn.IEEEextLsb, hba->wwpn.IEEE[0],
		    hba->wwpn.IEEE[1], hba->wwpn.IEEE[2], hba->wwpn.IEEE[3],
		    hba->wwpn.IEEE[4], hba->wwpn.IEEE[5]);

		rnid->unit_type  = RNID_HBA;
		rnid->port_id    = port->did;
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
		    "GET_NODE_ID: resv:       0x%x", rnid->specific_id_resv);
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
		    "SET_NODE_ID: resv:       0x%x", rnid->specific_id_resv);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "SET_NODE_ID: topo_flags: 0x%x", rnid->topo_flags);

		ret = FC_SUCCESS;
		break;
	}

#ifdef S11
	case FC_PORT_GET_P2P_INFO:
	{
		fc_fca_p2p_info_t	*p2p_info;
		NODELIST		*ndlp;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: FC_PORT_GET_P2P_INFO");

		bzero(pm->pm_data_buf, pm->pm_data_len);

		if (pm->pm_data_len < sizeof (fc_fca_p2p_info_t)) {
			ret = FC_NOMEM;
			break;
		}

		p2p_info = (fc_fca_p2p_info_t *)pm->pm_data_buf;

		if (hba->state >= FC_LINK_UP) {
			if ((hba->topology == TOPOLOGY_PT_PT) &&
			    (hba->flag & FC_PT_TO_PT)) {
				p2p_info->fca_d_id = port->did;
				p2p_info->d_id = port->rdid;

				ndlp = emlxs_node_find_did(port,
				    port->rdid, 1);

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "FC_PORT_GET_P2P_INFO: fca_d_id: 0x%x, "
				    "d_id: 0x%x, ndlp: 0x%p", port->did,
				    port->rdid, ndlp);
				if (ndlp) {
					bcopy(&ndlp->nlp_portname,
					    (caddr_t)&p2p_info->pwwn,
					    sizeof (la_wwn_t));
					bcopy(&ndlp->nlp_nodename,
					    (caddr_t)&p2p_info->nwwn,
					    sizeof (la_wwn_t));

					ret = FC_SUCCESS;
					break;

				}
			}
		}

		ret = FC_FAILURE;
		break;
	}
#endif /* S11 */

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "fca_port_manage: code=%x", pm->pm_cmd_code);
		ret = FC_INVALID_REQUEST;
		break;

	}

	return (ret);

} /* emlxs_fca_port_manage() */


/*ARGSUSED*/
static uint32_t
emlxs_test(emlxs_hba_t *hba, uint32_t test_code, uint32_t args,
    uint32_t *arg)
{
	uint32_t rval = 0;
	emlxs_port_t   *port = &PPORT;

	switch (test_code) {
#ifdef TEST_SUPPORT
	case 1: /* SCSI underrun */
	{
		hba->underrun_counter = (args)? arg[0]:1;
		break;
	}
#endif /* TEST_SUPPORT */

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "test: Unsupported test code. (0x%x)", test_code);
		rval = FC_INVALID_REQUEST;
	}

	return (rval);

} /* emlxs_test() */


/*
 * Given the device number, return the devinfo pointer or the ddiinst number.
 * Note: this routine must be successful on DDI_INFO_DEVT2INSTANCE even
 * before attach.
 *
 * Translate "dev_t" to a pointer to the associated "dev_info_t".
 */
/*ARGSUSED*/
static int
emlxs_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	emlxs_hba_t	*hba;
	int32_t		ddiinst;

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
		*result = (void *)((unsigned long)ddiinst);
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);

} /* emlxs_info() */


static int32_t
emlxs_power(dev_info_t *dip, int32_t comp, int32_t level)
{
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	int32_t		ddiinst;
	int		rval = DDI_SUCCESS;

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "fca_power: comp=%x level=%x", comp, level);

	if (hba == NULL || comp != EMLXS_PM_ADAPTER) {
		return (DDI_FAILURE);
	}

	mutex_enter(&EMLXS_PM_LOCK);

	/* If we are already at the proper level then return success */
	if (hba->pm_level == level) {
		mutex_exit(&EMLXS_PM_LOCK);
		return (DDI_SUCCESS);
	}

	switch (level) {
	case EMLXS_PM_ADAPTER_UP:

		/*
		 * If we are already in emlxs_attach,
		 * let emlxs_hba_attach take care of things
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
		 * If we are already in emlxs_detach,
		 * let emlxs_hba_detach take care of things
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

	mutex_exit(&EMLXS_PM_LOCK);

	return (rval);

} /* emlxs_power() */


#ifdef EMLXS_I386
#ifdef S11
/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-thread at hight PIL
 * with preemption disabled. Therefore, this function must not be blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
emlxs_quiesce(dev_info_t *dip)
{
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	int32_t		ddiinst;
	int		rval = DDI_SUCCESS;

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	if (hba == NULL || port == NULL) {
		return (DDI_FAILURE);
	}

	/* The fourth arg 1 indicates the call is from quiesce */
	if (EMLXS_SLI_HBA_RESET(hba, 1, 1, 1) == 0) {
		return (rval);
	} else {
		return (DDI_FAILURE);
	}

} /* emlxs_quiesce */
#endif /* S11 */
#endif /* EMLXS_I386 */


static int
emlxs_open(dev_t *dev_p, int32_t flag, int32_t otype, cred_t *cred_p)
{
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	int		ddiinst;

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
	emlxs_hba_t	*hba;
	int		ddiinst;

	ddiinst = getminor(dev);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);

	if (hba == NULL) {
		return (ENXIO);
	}

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
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	int		rval = 0;	/* return code */
	int		ddiinst;

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
	case EMLXS_DFC_COMMAND:
		rval = emlxs_dfc_manage(hba, (void *)arg, mode);
		break;

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
 *	Device Driver Common Routines
 *
 */

/* EMLXS_PM_LOCK must be held for this call */
static int
emlxs_hba_resume(dev_info_t *dip)
{
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	int		ddiinst;

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_resume_msg, NULL);

	if (!(hba->pm_state & EMLXS_PM_SUSPENDED)) {
		return (DDI_SUCCESS);
	}

	hba->pm_state &= ~EMLXS_PM_SUSPENDED;

	/* Re-enable the physical port on this HBA */
	port->flag |= EMLXS_PORT_ENABLED;

	/* Take the adapter online */
	if (emlxs_power_up(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_resume_failed_msg,
		    "Unable to take adapter online.");

		hba->pm_state |= EMLXS_PM_SUSPENDED;

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);

} /* emlxs_hba_resume() */


/* EMLXS_PM_LOCK must be held for this call */
static int
emlxs_hba_suspend(dev_info_t *dip)
{
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	int		ddiinst;

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
	emlxs_port_t	*port = &PPORT;
	uint32_t	i;

	/* Initialize the power management */
	mutex_init(&EMLXS_PM_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	mutex_init(&EMLXS_TIMER_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	cv_init(&hba->timer_lock_cv, NULL, CV_DRIVER, NULL);

	mutex_init(&EMLXS_PORT_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	mutex_init(&EMLXS_MBOX_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	cv_init(&EMLXS_MBOX_CV, NULL, CV_DRIVER, NULL);

	mutex_init(&EMLXS_LINKUP_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	cv_init(&EMLXS_LINKUP_CV, NULL, CV_DRIVER, NULL);

	mutex_init(&EMLXS_TX_CHANNEL_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	for (i = 0; i < MAX_RINGS; i++) {
		mutex_init(&EMLXS_CMD_RING_LOCK(i), NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(hba->intr_arg));
	}


	for (i = 0; i < EMLXS_MAX_WQS; i++) {
		mutex_init(&EMLXS_QUE_LOCK(i), NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(hba->intr_arg));
	}

	mutex_init(&EMLXS_MSIID_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	mutex_init(&EMLXS_FCTAB_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	mutex_init(&EMLXS_MEMGET_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	mutex_init(&EMLXS_MEMPUT_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	mutex_init(&EMLXS_IOCTL_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

#ifdef DUMP_SUPPORT
	mutex_init(&EMLXS_DUMP_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));
#endif /* DUMP_SUPPORT */

	mutex_init(&EMLXS_SPAWN_LOCK, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	/* Create per port locks */
	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);

		rw_init(&port->node_rwlock, NULL, RW_DRIVER, NULL);

		if (i == 0) {
			mutex_init(&EMLXS_PKT_LOCK, NULL, MUTEX_DRIVER,
			    DDI_INTR_PRI(hba->intr_arg));

			cv_init(&EMLXS_PKT_CV, NULL, CV_DRIVER, NULL);

			mutex_init(&EMLXS_UB_LOCK, NULL, MUTEX_DRIVER,
			    DDI_INTR_PRI(hba->intr_arg));
		} else {
			mutex_init(&EMLXS_PKT_LOCK, NULL, MUTEX_DRIVER,
			    DDI_INTR_PRI(hba->intr_arg));

			cv_init(&EMLXS_PKT_CV, NULL, CV_DRIVER, NULL);

			mutex_init(&EMLXS_UB_LOCK, NULL, MUTEX_DRIVER,
			    DDI_INTR_PRI(hba->intr_arg));
		}
	}

	return;

} /* emlxs_lock_init() */



static void
emlxs_lock_destroy(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	i;

	mutex_destroy(&EMLXS_TIMER_LOCK);
	cv_destroy(&hba->timer_lock_cv);

	mutex_destroy(&EMLXS_PORT_LOCK);

	cv_destroy(&EMLXS_MBOX_CV);
	cv_destroy(&EMLXS_LINKUP_CV);

	mutex_destroy(&EMLXS_LINKUP_LOCK);
	mutex_destroy(&EMLXS_MBOX_LOCK);

	mutex_destroy(&EMLXS_TX_CHANNEL_LOCK);

	for (i = 0; i < MAX_RINGS; i++) {
		mutex_destroy(&EMLXS_CMD_RING_LOCK(i));
	}

	for (i = 0; i < EMLXS_MAX_WQS; i++) {
		mutex_destroy(&EMLXS_QUE_LOCK(i));
	}

	mutex_destroy(&EMLXS_MSIID_LOCK);

	mutex_destroy(&EMLXS_FCTAB_LOCK);
	mutex_destroy(&EMLXS_MEMGET_LOCK);
	mutex_destroy(&EMLXS_MEMPUT_LOCK);
	mutex_destroy(&EMLXS_IOCTL_LOCK);
	mutex_destroy(&EMLXS_SPAWN_LOCK);
	mutex_destroy(&EMLXS_PM_LOCK);

#ifdef DUMP_SUPPORT
	mutex_destroy(&EMLXS_DUMP_LOCK);
#endif /* DUMP_SUPPORT */

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
#define	ATTACH_MAP_BUS		0x00000010
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
#define	ATTACH_FM		0x00010000
#define	ATTACH_MAP_SLI		0x00020000
#define	ATTACH_SPAWN		0x00040000
#define	ATTACH_EVENTS		0x00080000

static void
emlxs_driver_remove(dev_info_t *dip, uint32_t init_flag, uint32_t failed)
{
	emlxs_hba_t	*hba = NULL;
	int		ddiinst;

	ddiinst = ddi_get_instance(dip);

	if (init_flag & ATTACH_HBA) {
		hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);

		if (init_flag & ATTACH_SPAWN) {
			emlxs_thread_spawn_destroy(hba);
		}

		if (init_flag & ATTACH_EVENTS) {
			(void) emlxs_event_queue_destroy(hba);
		}

		if (init_flag & ATTACH_ONLINE) {
			(void) emlxs_offline(hba, 1);
		}

		if (init_flag & ATTACH_INTR_ADD) {
			(void) EMLXS_INTR_REMOVE(hba);
		}
#ifdef SFCT_SUPPORT
		if (init_flag & ATTACH_FCT) {
			emlxs_fct_detach(hba);
			emlxs_fct_modclose();
		}
#endif /* SFCT_SUPPORT */

#ifdef DHCHAP_SUPPORT
		if (init_flag & ATTACH_DHCHAP) {
			emlxs_dhc_detach(hba);
		}
#endif /* DHCHAP_SUPPORT */

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

		if (init_flag & ATTACH_MAP_BUS) {
			emlxs_unmap_bus(hba);
		}

		if (init_flag & ATTACH_MAP_SLI) {
			EMLXS_SLI_UNMAP_HDW(hba);
		}

#ifdef FMA_SUPPORT
		if (init_flag & ATTACH_FM) {
			emlxs_fm_fini(hba);
		}
#endif	/* FMA_SUPPORT */

		if (init_flag & ATTACH_LOG) {
			emlxs_msg_log_destroy(hba);
		}

		if (init_flag & ATTACH_FCA_TRAN) {
			(void) ddi_set_driver_private(hba->dip, NULL);
			kmem_free(hba->fca_tran, sizeof (fc_fca_tran_t));
			hba->fca_tran = NULL;
		}

		if (init_flag & ATTACH_HBA) {
			emlxs_device.log[hba->emlxinst] = 0;
			emlxs_device.hba[hba->emlxinst] =
			    (emlxs_hba_t *)((unsigned long)((failed) ? -1 : 0));
#ifdef DUMP_SUPPORT
			emlxs_device.dump_txtfile[hba->emlxinst] = 0;
			emlxs_device.dump_dmpfile[hba->emlxinst] = 0;
			emlxs_device.dump_ceefile[hba->emlxinst] = 0;
#endif /* DUMP_SUPPORT */

		}
	}

	if (init_flag & ATTACH_SOFT_STATE) {
		(void) ddi_soft_state_free(emlxs_soft_state, ddiinst);
	}

	return;

} /* emlxs_driver_remove() */


/* This determines which ports will be initiator mode */
static uint32_t
emlxs_fca_init(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;

	/* Check if SFS present */
	if (((void *)MODSYM(fc_fca_init) == NULL) ||
	    ((void *)MODSYM(fc_fca_attach) == NULL)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "SFS not present.");
		return (1);
	}

	/* Check if our SFS driver interface matches the current SFS stack */
	if (MODSYM(fc_fca_attach) (hba->dip, hba->fca_tran) != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "SFS/FCA version mismatch. FCA=0x%x",
		    hba->fca_tran->fca_version);
		return (1);
	}

	return (0);

} /* emlxs_fca_init() */


/* This determines which ports will be initiator or target mode */
static void
emlxs_mode_init(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	emlxs_port_t	*vport;
	uint32_t	i;
	uint32_t	mode_mask;

	/* Initialize mode masks */
	(void) emlxs_mode_init_masks(hba);

	if (!(port->mode_mask & MODE_INITIATOR)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Initiator mode not enabled.");

#ifdef SFCT_SUPPORT
		/* Disable dynamic target mode */
		cfg[CFG_DTM_ENABLE].current = 0;
#endif /* SFCT_SUPPORT */

		goto done1;
	}

	/* Try to initialize fca interface */
	if (emlxs_fca_init(hba) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Initiator mode disabled.");

		/* Disable initiator mode */
		port->mode_mask &= ~MODE_INITIATOR;

#ifdef SFCT_SUPPORT
		/* Disable dynamic target mode */
		cfg[CFG_DTM_ENABLE].current = 0;
#endif /* SFCT_SUPPORT */

		goto done1;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Initiator mode enabled.");

done1:

#ifdef SFCT_SUPPORT
	if (!(port->mode_mask & MODE_TARGET)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Target mode not enabled.");

		/* Disable target modes */
		cfg[CFG_DTM_ENABLE].current = 0;
		cfg[CFG_TARGET_MODE].current = 0;

		goto done2;
	}

	/* Try to open the COMSTAR module */
	if (emlxs_fct_modopen() != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Target mode disabled.");

		/* Disable target modes */
		port->mode_mask &= ~MODE_TARGET;
		cfg[CFG_DTM_ENABLE].current = 0;
		cfg[CFG_TARGET_MODE].current = 0;

		goto done2;
	}

	/* Try to initialize fct interface */
	if (emlxs_fct_init(hba) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Target mode disabled.");

		/* Disable target modes */
		port->mode_mask &= ~MODE_TARGET;
		cfg[CFG_DTM_ENABLE].current = 0;
		cfg[CFG_TARGET_MODE].current = 0;

		goto done2;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Target mode enabled.");

done2:
	/* Adjust target mode parameter flags */
	if (cfg[CFG_DTM_ENABLE].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Dynamic target mode enabled.");

		cfg[CFG_TARGET_MODE].flags |= PARM_DYNAMIC;
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Dynamic target mode disabled.");

		cfg[CFG_TARGET_MODE].flags &= ~PARM_DYNAMIC;
	}
#endif /* SFCT_SUPPORT */

	/* Now set port flags */
	mutex_enter(&EMLXS_PORT_LOCK);

	/* Set flags for physical port */
	if (port->mode_mask & MODE_INITIATOR) {
		port->flag |= EMLXS_INI_ENABLED;
	} else {
		port->flag &= ~EMLXS_INI_ENABLED;
	}

	if (port->mode_mask & MODE_TARGET) {
		port->flag |= EMLXS_TGT_ENABLED;
	} else {
		port->flag &= ~EMLXS_TGT_ENABLED;
	}

	for (i = 1; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);

		/* Physical port mask has only allowable bits */
		mode_mask = vport->mode_mask & port->mode_mask;

		/* Set flags for physical port */
		if (mode_mask & MODE_INITIATOR) {
			vport->flag |= EMLXS_INI_ENABLED;
		} else {
			vport->flag &= ~EMLXS_INI_ENABLED;
		}

		if (mode_mask & MODE_TARGET) {
			vport->flag |= EMLXS_TGT_ENABLED;
		} else {
			vport->flag &= ~EMLXS_TGT_ENABLED;
		}
	}

	/* Set initial driver mode */
	emlxs_mode_set(hba);

	mutex_exit(&EMLXS_PORT_LOCK);

	/* Recheck possible mode dependent parameters */
	/* in case conditions have changed. */
	if (port->mode != MODE_NONE) {
		for (i = 0; i < NUM_CFG_PARAM; i++) {
			cfg = &hba->config[i];
			cfg->current = emlxs_check_parm(hba, i, cfg->current);
		}
	}

	return;

} /* emlxs_mode_init() */


/* This must be called while holding the EMLXS_PORT_LOCK */
extern void
emlxs_mode_set(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
#ifdef SFCT_SUPPORT
	emlxs_config_t *cfg = &CFG;
#endif /* SFCT_SUPPORT */
	emlxs_port_t	*vport;
	uint32_t	i;
	uint32_t cfg_tgt_mode = 0;

	/* mutex_enter(&EMLXS_PORT_LOCK); */

#ifdef SFCT_SUPPORT
	cfg_tgt_mode = cfg[CFG_TARGET_MODE].current;
#endif /* SFCT_SUPPORT */

	/* Initiator mode requested */
	if (!cfg_tgt_mode) {
		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);
			vport->mode = (vport->flag & EMLXS_INI_ENABLED)?
			    MODE_INITIATOR:MODE_NONE;
		}
#ifdef SFCT_SUPPORT
	/* Target mode requested */
	} else  {
		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);
			vport->mode = (vport->flag & EMLXS_TGT_ENABLED)?
			    MODE_TARGET:MODE_NONE;
		}
#endif /* SFCT_SUPPORT */
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "MODE: %s", emlxs_mode_xlate(port->mode));

	/* mutex_exit(&EMLXS_PORT_LOCK); */

	return;

} /* emlxs_mode_set() */


static void
emlxs_mode_init_masks(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	uint32_t	i;

#ifdef SFCT_SUPPORT
	emlxs_config_t	*cfg = &CFG;
	uint32_t	vport_mode_mask;
	uint32_t	cfg_vport_mode_mask;
	uint32_t	mode_mask;
	char		string[256];

	port->mode_mask = 0;

	if (!cfg[CFG_TARGET_MODE].current ||
	    cfg[CFG_DTM_ENABLE].current) {
		port->mode_mask |= MODE_INITIATOR;
	}

	if (cfg[CFG_TARGET_MODE].current ||
	    cfg[CFG_DTM_ENABLE].current) {
		port->mode_mask |= MODE_TARGET;
	}

	/* Physical port mask has only allowable bits */
	vport_mode_mask = port->mode_mask;
	cfg_vport_mode_mask = cfg[CFG_VPORT_MODE_MASK].current;

	/* Check dynamic target mode value for virtual ports */
	if (cfg[CFG_DTM_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "%s = 0: Virtual target ports are not supported.",
		    cfg[CFG_DTM_ENABLE].string);

		vport_mode_mask &= ~MODE_TARGET;
	}

	cfg_vport_mode_mask &= vport_mode_mask;

	if (cfg[CFG_VPORT_MODE_MASK].current != cfg_vport_mode_mask) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "%s: Changing 0x%x --> 0x%x",
		    cfg[CFG_VPORT_MODE_MASK].string,
		    cfg[CFG_VPORT_MODE_MASK].current,
		    cfg_vport_mode_mask);

		cfg[CFG_VPORT_MODE_MASK].current = cfg_vport_mode_mask;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "pport-mode-mask: %s", emlxs_mode_xlate(port->mode_mask));

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "vport-mode-mask: %s", emlxs_mode_xlate(cfg_vport_mode_mask));

	for (i = 1; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);

		(void) snprintf(string, sizeof (string),
		    "%s%d-vport%d-mode-mask", DRIVER_NAME, hba->ddiinst, i);

		mode_mask = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY,
		    (void *)hba->dip, DDI_PROP_DONTPASS, string,
		    cfg_vport_mode_mask);

		vport->mode_mask = mode_mask & vport_mode_mask;

		if (vport->mode_mask != cfg_vport_mode_mask) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
			    "vport%d-mode-mask: %s",
			    i, emlxs_mode_xlate(vport->mode_mask));
		}
	}
#else
	port->mode_mask = MODE_INITIATOR;
	for (i = 1; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vport->mode_mask = MODE_INITIATOR;
	}
#endif /* SFCT_SUPPORT */

	return;

} /* emlxs_mode_init_masks() */


static void
emlxs_fca_attach(emlxs_hba_t *hba)
{
	emlxs_port_t	*port;
	uint32_t	i;

	/* Update our transport structure */
	hba->fca_tran->fca_iblock  = (ddi_iblock_cookie_t *)&hba->intr_arg;
	hba->fca_tran->fca_cmd_max = hba->io_throttle;

	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);
		port->ub_count	= EMLXS_UB_TOKEN_OFFSET;
		port->ub_pool	= NULL;
	}

#if (EMLXS_MODREV >= EMLXS_MODREV5)
	bcopy((caddr_t)&hba->wwpn, (caddr_t)&hba->fca_tran->fca_perm_pwwn,
	    sizeof (NAME_TYPE));
#endif /* >= EMLXS_MODREV5 */

	return;

} /* emlxs_fca_attach() */


static void
emlxs_fca_detach(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	i;
	emlxs_port_t	*vport;

	if (!(port->flag & EMLXS_INI_ENABLED)) {
		return;
	}

	if ((void *)MODSYM(fc_fca_detach) != NULL) {
		MODSYM(fc_fca_detach)(hba->dip);
	}

	/* Disable INI mode for all ports */
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vport->flag &= ~EMLXS_INI_ENABLED;
	}

	return;

} /* emlxs_fca_detach() */


static void
emlxs_drv_banner(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	i;
	char		sli_mode[16];
	char		msi_mode[16];
	char		npiv_mode[16];
	emlxs_vpd_t	*vpd = &VPD;
	uint8_t		*wwpn;
	uint8_t		*wwnn;
	uint32_t	fw_show = 0;

	/* Display firmware library one time for all driver instances */
	mutex_enter(&emlxs_device.lock);
	if (!(emlxs_instance_flag & EMLXS_FW_SHOW)) {
		emlxs_instance_flag |= EMLXS_FW_SHOW;
		fw_show = 1;
	}
	mutex_exit(&emlxs_device.lock);

	if (fw_show) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg, "%s",
		    emlxs_copyright);
		emlxs_fw_show(hba);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg, "%s (%s)", emlxs_label,
	    emlxs_revision);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
	    "%s Dev_id:%x Sub_id:%x Id:%d", hba->model_info.model,
	    hba->model_info.device_id, hba->model_info.ssdid,
	    hba->model_info.id);

#ifdef EMLXS_I386

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
	    "Firmware:%s (%s) Boot:%s", vpd->fw_version, vpd->fw_label,
	    vpd->boot_version);

#else	/* EMLXS_SPARC */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
	    "Firmware:%s (%s) Boot:%s Fcode:%s", vpd->fw_version,
	    vpd->fw_label, vpd->boot_version, vpd->fcode_version);

#endif	/* EMLXS_I386 */

	if (hba->sli_mode > 3) {
		(void) snprintf(sli_mode, sizeof (sli_mode), "SLI:%d(%s)",
		    hba->sli_mode,
		    ((hba->flag & FC_FIP_SUPPORTED) ? "FIP" : "nonFIP"));
	} else {
		(void) snprintf(sli_mode, sizeof (sli_mode), "SLI:%d",
		    hba->sli_mode);
	}

	(void) strlcpy(msi_mode, " INTX:1", sizeof (msi_mode));

#ifdef MSI_SUPPORT
	if (hba->intr_flags & EMLXS_MSI_ENABLED) {
		switch (hba->intr_type) {
		case DDI_INTR_TYPE_FIXED:
			(void) strlcpy(msi_mode, " MSI:0", sizeof (msi_mode));
			break;

		case DDI_INTR_TYPE_MSI:
			(void) snprintf(msi_mode, sizeof (msi_mode), " MSI:%d",
			    hba->intr_count);
			break;

		case DDI_INTR_TYPE_MSIX:
			(void) snprintf(msi_mode, sizeof (msi_mode), " MSIX:%d",
			    hba->intr_count);
			break;
		}
	}
#endif /* MSI_SUPPORT */

	(void) strlcpy(npiv_mode, "", sizeof (npiv_mode));

	if (hba->flag & FC_NPIV_ENABLED) {
		(void) snprintf(npiv_mode, sizeof (npiv_mode), " NPIV:%d",
		    hba->vpi_max+1);
	} else {
		(void) strlcpy(npiv_mode, " NPIV:0", sizeof (npiv_mode));
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg, "%s%s%s%s%s%s",
		    sli_mode, msi_mode, npiv_mode,
		    ((port->flag & EMLXS_INI_ENABLED)? " FCA":""),
		    ((port->flag & EMLXS_TGT_ENABLED)? " FCT":""),
		    ((SLI4_FCOE_MODE)? " FCoE":" FC"));
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg, "%s%s%s%s%s",
		    sli_mode, msi_mode, npiv_mode,
		    ((port->flag & EMLXS_INI_ENABLED)? " FCA":""),
		    ((port->flag & EMLXS_TGT_ENABLED)? " FCT":""));
	}

	wwpn = (uint8_t *)&hba->wwpn;
	wwnn = (uint8_t *)&hba->wwnn;
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_msg,
	    "WWPN:%02X%02X%02X%02X%02X%02X%02X%02X "
	    "WWNN:%02X%02X%02X%02X%02X%02X%02X%02X",
	    wwpn[0], wwpn[1], wwpn[2], wwpn[3], wwpn[4], wwpn[5], wwpn[6],
	    wwpn[7], wwnn[0], wwnn[1], wwnn[2], wwnn[3], wwnn[4], wwnn[5],
	    wwnn[6], wwnn[7]);

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
		    wwpn[0], wwpn[1], wwpn[2], wwpn[3], wwpn[4], wwpn[5],
		    wwpn[6], wwpn[7], wwnn[0], wwnn[1], wwnn[2], wwnn[3],
		    wwnn[4], wwnn[5], wwnn[6], wwnn[7]);
	}

	/*
	 * Announce the device: ddi_report_dev() prints a banner at boot time,
	 * announcing the device pointed to by dip.
	 */
	(void) ddi_report_dev(hba->dip);

	return;

} /* emlxs_drv_banner() */


extern void
emlxs_get_fcode_version(emlxs_hba_t *hba)
{
	emlxs_vpd_t	*vpd = &VPD;
	char		*prop_str;
	int		status;

	/* Setup fcode version property */
	prop_str = NULL;
	status =
	    ddi_prop_lookup_string(DDI_DEV_T_ANY, (dev_info_t *)hba->dip, 0,
	    "fcode-version", (char **)&prop_str);

	if (status == DDI_PROP_SUCCESS) {
		bcopy(prop_str, vpd->fcode_version, strlen(prop_str));
		(void) ddi_prop_free((void *)prop_str);
	} else {
		(void) strncpy(vpd->fcode_version, "none",
		    (sizeof (vpd->fcode_version)-1));
	}

	return;

} /* emlxs_get_fcode_version() */


static int
emlxs_hba_attach(dev_info_t *dip)
{
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	emlxs_config_t	*cfg;
	char		*prop_str;
	int		ddiinst;
	int32_t		emlxinst;
	int		status;
	uint32_t	rval;
	uint32_t	init_flag = 0;
	char		local_pm_components[32];
	uint32_t	i;

	ddiinst = ddi_get_instance(dip);
	emlxinst = emlxs_add_instance(ddiinst);

	if (emlxinst >= MAX_FC_BRDS) {
		cmn_err(CE_WARN,
		    "?%s: fca_hba_attach failed. Too many driver ddiinsts. "
		    "inst=%x", DRIVER_NAME, ddiinst);
		return (DDI_FAILURE);
	}

	if (emlxs_device.hba[emlxinst] == (emlxs_hba_t *)-1) {
		return (DDI_FAILURE);
	}

	if (emlxs_device.hba[emlxinst]) {
		return (DDI_SUCCESS);
	}

	/* An adapter can accidentally be plugged into a slave-only PCI slot */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "?%s%d: fca_hba_attach failed. Device in slave-only slot.",
		    DRIVER_NAME, ddiinst);
		return (DDI_FAILURE);
	}

	/* Allocate emlxs_dev_ctl structure. */
	if (ddi_soft_state_zalloc(emlxs_soft_state, ddiinst) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "?%s%d: fca_hba_attach failed. Unable to allocate soft "
		    "state.", DRIVER_NAME, ddiinst);
		return (DDI_FAILURE);
	}
	init_flag |= ATTACH_SOFT_STATE;

	if ((hba = (emlxs_hba_t *)ddi_get_soft_state(emlxs_soft_state,
	    ddiinst)) == NULL) {
		cmn_err(CE_WARN,
		    "?%s%d: fca_hba_attach failed. Unable to get soft state.",
		    DRIVER_NAME, ddiinst);
		goto failed;
	}
	bzero((char *)hba, sizeof (emlxs_hba_t));

	emlxs_device.hba[emlxinst] = hba;
	emlxs_device.log[emlxinst] = &hba->log;

#ifdef DUMP_SUPPORT
	emlxs_device.dump_txtfile[emlxinst] = &hba->dump_txtfile;
	emlxs_device.dump_dmpfile[emlxinst] = &hba->dump_dmpfile;
	emlxs_device.dump_ceefile[emlxinst] = &hba->dump_ceefile;
#endif /* DUMP_SUPPORT */

	hba->dip = dip;
	hba->emlxinst = emlxinst;
	hba->ddiinst = ddiinst;

	init_flag |= ATTACH_HBA;

	/* Enable the physical port on this HBA */
	port = &PPORT;
	port->hba = hba;
	port->vpi = 0;
	port->flag |= EMLXS_PORT_ENABLED;

	/* Allocate a transport structure */
	hba->fca_tran =
	    (fc_fca_tran_t *)kmem_zalloc(sizeof (fc_fca_tran_t), KM_NOSLEEP);
	if (hba->fca_tran == NULL) {
		cmn_err(CE_WARN,
		    "?%s%d: fca_hba_attach failed. Unable to allocate fca_tran "
		    "memory.", DRIVER_NAME, ddiinst);
		goto failed;
	}
	bcopy((caddr_t)&emlxs_fca_tran, (caddr_t)hba->fca_tran,
	    sizeof (fc_fca_tran_t));

	/*
	 * Copy the global ddi_dma_attr to the local hba fields
	 */
	bcopy((caddr_t)&emlxs_dma_attr, (caddr_t)&hba->dma_attr,
	    sizeof (ddi_dma_attr_t));
	bcopy((caddr_t)&emlxs_dma_attr_ro, (caddr_t)&hba->dma_attr_ro,
	    sizeof (ddi_dma_attr_t));
	bcopy((caddr_t)&emlxs_dma_attr_1sg, (caddr_t)&hba->dma_attr_1sg,
	    sizeof (ddi_dma_attr_t));
	bcopy((caddr_t)&emlxs_dma_attr_fcip_rsp,
	    (caddr_t)&hba->dma_attr_fcip_rsp, sizeof (ddi_dma_attr_t));

	/* Reset the fca_tran dma_attr fields to the per-hba copies */
	hba->fca_tran->fca_dma_attr = &hba->dma_attr;
	hba->fca_tran->fca_dma_fcp_cmd_attr = &hba->dma_attr_1sg;
	hba->fca_tran->fca_dma_fcp_rsp_attr = &hba->dma_attr_1sg;
	hba->fca_tran->fca_dma_fcp_data_attr = &hba->dma_attr_ro;
	hba->fca_tran->fca_dma_fcip_cmd_attr = &hba->dma_attr_1sg;
	hba->fca_tran->fca_dma_fcip_rsp_attr = &hba->dma_attr_fcip_rsp;
	hba->fca_tran->fca_dma_fcsm_cmd_attr = &hba->dma_attr_1sg;
	hba->fca_tran->fca_dma_fcsm_rsp_attr = &hba->dma_attr;

	/* Set the transport structure pointer in our dip */
	/* SFS may panic if we are in target only mode    */
	/* We will update the transport structure later   */
	(void) ddi_set_driver_private(dip, (caddr_t)&emlxs_fca_tran);
	init_flag |= ATTACH_FCA_TRAN;

	/* Perform driver integrity check */
	rval = emlxs_integrity_check(hba);
	if (rval) {
		cmn_err(CE_WARN,
		    "?%s%d: fca_hba_attach failed. Driver integrity check "
		    "failed. %d error(s) found.", DRIVER_NAME, ddiinst, rval);
		goto failed;
	}

	cfg = &CFG;

	bcopy((uint8_t *)&emlxs_cfg, (uint8_t *)cfg, sizeof (emlxs_cfg));
#ifdef MSI_SUPPORT
	if ((void *)&ddi_intr_get_supported_types != NULL) {
		hba->intr_flags |= EMLXS_MSI_ENABLED;
	}
#endif	/* MSI_SUPPORT */


	/* Create the msg log file */
	if (emlxs_msg_log_create(hba) == 0) {
		cmn_err(CE_WARN,
		    "?%s%d: fca_hba_attach failed. Unable to create message "
		    "log", DRIVER_NAME, ddiinst);
		goto failed;

	}
	init_flag |= ATTACH_LOG;

	/* We can begin to use EMLXS_MSGF from this point on */

	/*
	 * Find the I/O bus type If it is not a SBUS card,
	 * then it is a PCI card. Default is PCI_FC (0).
	 */
	prop_str = NULL;
	status = ddi_prop_lookup_string(DDI_DEV_T_ANY,
	    (dev_info_t *)dip, 0, "name", (char **)&prop_str);

	if (status == DDI_PROP_SUCCESS) {
		if (strncmp(prop_str, "lpfs", 4) == 0) {
			hba->bus_type = SBUS_FC;
		}

		(void) ddi_prop_free((void *)prop_str);
	}

	/*
	 * Copy DDS from the config method and update configuration parameters
	 */
	(void) emlxs_get_props(hba);

#ifdef FMA_SUPPORT
	hba->fm_caps = cfg[CFG_FM_CAPS].current;

	emlxs_fm_init(hba);

	init_flag |= ATTACH_FM;
#endif	/* FMA_SUPPORT */

	if (emlxs_map_bus(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to map memory");
		goto failed;

	}
	init_flag |= ATTACH_MAP_BUS;

	/* Attempt to identify the adapter */
	rval = emlxs_init_adapter_info(hba);

	if (rval == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to get adapter info. Id:%d  Device id:0x%x "
		    "Model:%s", hba->model_info.id,
		    hba->model_info.device_id, hba->model_info.model);
		goto failed;
	}
#define	FILTER_ORACLE_BRANDED
#ifdef FILTER_ORACLE_BRANDED

	/* Oracle branded adapters are not supported in this driver */
	if (hba->model_info.flags & EMLXS_ORACLE_BRANDED) {
		hba->model_info.flags |= EMLXS_NOT_SUPPORTED;
	}
#endif /* FILTER_ORACLE_BRANDED */

	/* Check if adapter is not supported */
	if (hba->model_info.flags & EMLXS_NOT_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unsupported adapter found. Id:%d  Device id:0x%x "
		    "SSDID:0x%x  Model:%s", hba->model_info.id,
		    hba->model_info.device_id,
		    hba->model_info.ssdid, hba->model_info.model);
		goto failed;
	}

	if (hba->model_info.sli_mask & EMLXS_SLI4_MASK) {
		hba->sli.sli4.mem_sgl_size = MEM_SGL_SIZE;

#ifdef EMLXS_I386
		/*
		 * TigerShark has 64K limit for SG element size
		 * Do this for x86 alone. For SPARC, the driver
		 * breaks up the single SGE later on.
		 */
		hba->dma_attr_ro.dma_attr_count_max = 0xffff;

		i = cfg[CFG_MAX_XFER_SIZE].current;
		/* Update SGL size based on max_xfer_size */
		if (i > 516096) {
			/* 516096 = (((2048 / 16) - 2) * 4096) */
			hba->sli.sli4.mem_sgl_size = 4096;
		} else if (i > 253952) {
			/* 253952 = (((1024 / 16) - 2) * 4096) */
			hba->sli.sli4.mem_sgl_size = 2048;
		} else {
			hba->sli.sli4.mem_sgl_size = 1024;
		}
#endif /* EMLXS_I386 */

		i = SGL_TO_SGLLEN(hba->sli.sli4.mem_sgl_size);
	} else {
		hba->sli.sli3.mem_bpl_size = MEM_BPL_SIZE;

#ifdef EMLXS_I386
		i = cfg[CFG_MAX_XFER_SIZE].current;
		/* Update BPL size based on max_xfer_size */
		if (i > 688128) {
			/* 688128 = (((2048 / 12) - 2) * 4096) */
			hba->sli.sli3.mem_bpl_size = 4096;
		} else if (i > 339968) {
			/* 339968 = (((1024 / 12) - 2) * 4096) */
			hba->sli.sli3.mem_bpl_size = 2048;
		} else {
			hba->sli.sli3.mem_bpl_size = 1024;
		}
#endif /* EMLXS_I386 */

		i = BPL_TO_SGLLEN(hba->sli.sli3.mem_bpl_size);
	}

	/* Update dma_attr_sgllen based on true SGL length */
	hba->dma_attr.dma_attr_sgllen = i;
	hba->dma_attr_ro.dma_attr_sgllen = i;
	hba->dma_attr_fcip_rsp.dma_attr_sgllen = i;

	if (EMLXS_SLI_MAP_HDW(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to map memory");
		goto failed;

	}
	init_flag |= ATTACH_MAP_SLI;

	/* Initialize the interrupts. But don't add them yet */
	status = EMLXS_INTR_INIT(hba, 0);
	if (status != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to initalize interrupt(s).");
		goto failed;

	}
	init_flag |= ATTACH_INTR_INIT;

	/* Initialize LOCKs */
	emlxs_msg_lock_reinit(hba);
	emlxs_lock_init(hba);
	init_flag |= ATTACH_LOCK;

	/* Create the event queue */
	if (emlxs_event_queue_create(hba) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to create event queue");

		goto failed;

	}
	init_flag |= ATTACH_EVENTS;

	/* Initialize the power management */
	mutex_enter(&EMLXS_PM_LOCK);
	hba->pm_state = EMLXS_PM_IN_ATTACH;
	hba->pm_level = EMLXS_PM_ADAPTER_DOWN;
	hba->pm_busy = 0;
#ifdef IDLE_TIMER
	hba->pm_active = 1;
	hba->pm_idle_timer = 0;
#endif	/* IDLE_TIMER */
	mutex_exit(&EMLXS_PM_LOCK);

	/* Set the pm component name */
	(void) snprintf(local_pm_components, sizeof (local_pm_components),
	    "NAME=%s%d", DRIVER_NAME, ddiinst);
	emlxs_pm_components[0] = local_pm_components;

	/* Check if power management support is enabled */
	if (cfg[CFG_PM_SUPPORT].current) {
		if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
		    "pm-components", emlxs_pm_components,
		    sizeof (emlxs_pm_components) /
		    sizeof (emlxs_pm_components[0])) !=
		    DDI_PROP_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
			    "Unable to create pm components.");
			goto failed;
		}
	}

	/* Needed for suspend and resume support */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip, "pm-hardware-state",
	    "needs-suspend-resume");
	init_flag |= ATTACH_PROP;

	emlxs_thread_spawn_create(hba);
	init_flag |= ATTACH_SPAWN;

	emlxs_thread_create(hba, &hba->iodone_thread);

	init_flag |= ATTACH_THREAD;

retry:
	/* Setup initiator / target ports */
	emlxs_mode_init(hba);

	/* If driver did not attach to either stack, */
	/* then driver attach fails */
	if (port->mode == MODE_NONE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Driver interfaces not enabled.");
		goto failed;
	}

	/*
	 * Initialize HBA
	 */

	/* Set initial state */
	mutex_enter(&EMLXS_PORT_LOCK);
	hba->flag |= FC_OFFLINE_MODE;
	hba->flag &= ~(FC_ONLINE_MODE | FC_ONLINING_MODE | FC_OFFLINING_MODE);
	mutex_exit(&EMLXS_PORT_LOCK);

	if (status = emlxs_online(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "Unable to initialize adapter.");

		if (status == EAGAIN) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
			    "Retrying adapter initialization ...");
			goto retry;
		}
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
	hba->kstat = kstat_create(DRIVER_NAME,
	    ddiinst, "statistics", "controller",
	    KSTAT_TYPE_RAW, sizeof (emlxs_stats_t),
	    KSTAT_FLAG_VIRTUAL);

	if (hba->kstat == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "kstat_create failed.");
	} else {
		hba->kstat->ks_data = (void *)&hba->stats;
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
	 * This will not execute emlxs_hba_resume because
	 * EMLXS_PM_IN_ATTACH is set
	 */
	if (emlxs_pm_raise_power(dip) != DDI_SUCCESS) {
		/* Set power up anyway. This should not happen! */
		mutex_enter(&EMLXS_PM_LOCK);
		hba->pm_level = EMLXS_PM_ADAPTER_UP;
		hba->pm_state &= ~EMLXS_PM_IN_ATTACH;
		mutex_exit(&EMLXS_PM_LOCK);
	} else {
		mutex_enter(&EMLXS_PM_LOCK);
		hba->pm_state &= ~EMLXS_PM_IN_ATTACH;
		mutex_exit(&EMLXS_PM_LOCK);
	}

#ifdef SFCT_SUPPORT
	if (port->flag & EMLXS_TGT_ENABLED) {
		/* Do this last */
		emlxs_fct_attach(hba);
		init_flag |= ATTACH_FCT;
	}
#endif /* SFCT_SUPPORT */

	return (DDI_SUCCESS);

failed:

	emlxs_driver_remove(dip, init_flag, 1);

	return (DDI_FAILURE);

} /* emlxs_hba_attach() */


static int
emlxs_hba_detach(dev_info_t *dip)
{
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	int		ddiinst;
	int		count;
	uint32_t	init_flag = (uint32_t)-1;

	ddiinst = ddi_get_instance(dip);
	hba = ddi_get_soft_state(emlxs_soft_state, ddiinst);
	port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_debug_msg, NULL);

	mutex_enter(&EMLXS_PM_LOCK);
	hba->pm_state |= EMLXS_PM_IN_DETACH;
	mutex_exit(&EMLXS_PM_LOCK);

	/* Lower the power level */
	/*
	 * This will not suspend the driver since the
	 * EMLXS_PM_IN_DETACH has been set
	 */
	if (emlxs_pm_lower_power(dip) != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
		    "Unable to lower power.");

		mutex_enter(&EMLXS_PM_LOCK);
		hba->pm_state &= ~EMLXS_PM_IN_DETACH;
		mutex_exit(&EMLXS_PM_LOCK);

		return (DDI_FAILURE);
	}

	/* Take the adapter offline first, if not already */
	if (emlxs_offline(hba, 1) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_detach_failed_msg,
		    "Unable to take adapter offline.");

		mutex_enter(&EMLXS_PM_LOCK);
		hba->pm_state &= ~EMLXS_PM_IN_DETACH;
		mutex_exit(&EMLXS_PM_LOCK);

		(void) emlxs_pm_raise_power(dip);

		return (DDI_FAILURE);
	}
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
	init_flag &= ~ATTACH_ONLINE;

	/* Remove the driver instance */
	emlxs_driver_remove(dip, init_flag, 0);

	return (DDI_SUCCESS);

} /* emlxs_hba_detach() */


extern int
emlxs_map_bus(emlxs_hba_t *hba)
{
	emlxs_port_t		*port = &PPORT;
	dev_info_t		*dip;
	ddi_device_acc_attr_t	dev_attr;
	int			status;

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
				    "(SBUS) ddi_regs_map_setup PCI failed. "
				    "status=%x", status);
				goto failed;
			}
		}

		if (hba->sbus_pci_handle == 0) {
			status = ddi_regs_map_setup(dip,
			    SBUS_TITAN_PCI_CFG_RINDEX,
			    (caddr_t *)&hba->sbus_pci_addr,
			    0, 0, &dev_attr, &hba->sbus_pci_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup TITAN PCI "
				    "failed. status=%x", status);
				goto failed;
			}
		}

	} else {	/* ****** PCI ****** */

		if (hba->pci_acc_handle == 0) {
			status = ddi_regs_map_setup(dip,
			    PCI_CFG_RINDEX,
			    (caddr_t *)&hba->pci_addr,
			    0, 0, &emlxs_dev_acc_attr, &hba->pci_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(PCI) ddi_regs_map_setup PCI failed. "
				    "status=%x", status);
				goto failed;
			}
		}
#ifdef EMLXS_I386
		/* Setting up PCI configure space */
		(void) ddi_put16(hba->pci_acc_handle,
		    (uint16_t *)(hba->pci_addr + PCI_COMMAND_REGISTER),
		    CMD_CFG_VALUE | CMD_IO_ENBL);

#ifdef FMA_SUPPORT
		if (emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_access_handle_msg, NULL);
			goto failed;
		}
#endif  /* FMA_SUPPORT */

#endif	/* EMLXS_I386 */

	}
	return (0);

failed:

	emlxs_unmap_bus(hba);
	return (ENOMEM);

} /* emlxs_map_bus() */


extern void
emlxs_unmap_bus(emlxs_hba_t *hba)
{
	if (hba->pci_acc_handle) {
		(void) ddi_regs_map_free(&hba->pci_acc_handle);
		hba->pci_acc_handle = 0;
	}

	if (hba->sbus_pci_handle) {
		(void) ddi_regs_map_free(&hba->sbus_pci_handle);
		hba->sbus_pci_handle = 0;
	}

	return;

} /* emlxs_unmap_bus() */


static int
emlxs_get_props(emlxs_hba_t *hba)
{
	emlxs_config_t	*cfg;
	uint32_t	i;
	char		string[256];
	uint32_t	new_value;

	/* Initialize each parameter */
	for (i = 0; i < NUM_CFG_PARAM; i++) {
		cfg = &hba->config[i];

		/* Ensure strings are terminated */
		cfg->string[(EMLXS_CFG_STR_SIZE-1)] = 0;
		cfg->help[(EMLXS_CFG_HELP_SIZE-1)]  = 0;

		/* Set the current value to the default value */
		new_value = cfg->def;

		/* First check for the global setting */
		new_value = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY,
		    (void *)hba->dip, DDI_PROP_DONTPASS,
		    cfg->string, new_value);

		/* Now check for the per adapter ddiinst setting */
		(void) snprintf(string, sizeof (string), "%s%d-%s", DRIVER_NAME,
		    hba->ddiinst, cfg->string);

		new_value = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY,
		    (void *)hba->dip, DDI_PROP_DONTPASS, string, new_value);

		/* Now check the parameter */
		cfg->current = emlxs_check_parm(hba, i, new_value);
	}

	return (0);

} /* emlxs_get_props() */


extern uint32_t
emlxs_check_parm(emlxs_hba_t *hba, uint32_t index, uint32_t new_value)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	i;
	emlxs_config_t	*cfg;
	emlxs_vpd_t	*vpd = &VPD;

	if (index >= NUM_CFG_PARAM) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "check_parm failed. Invalid index = %d", index);

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
#ifdef SFCT_SUPPORT
	case CFG_NPIV_ENABLE:
		if (hba->config[CFG_TARGET_MODE].current &&
		    hba->config[CFG_DTM_ENABLE].current == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "enable-npiv: Not supported in pure target mode. "
			    "Disabling.");

			new_value = 0;
		}
		break;
#endif /* SFCT_SUPPORT */


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

	case CFG_FW_CHECK:
		/* The 0x2 bit implies the 0x1 bit will also be set */
		if (new_value & 0x2) {
			new_value |= 0x1;
		}

		/* The 0x4 bit should not be set if 0x1 or 0x2 is not set */
		if (!(new_value & 0x3) && (new_value & 0x4)) {
			new_value &= ~0x4;
		}
		break;

	case CFG_LINK_SPEED:
		if ((new_value > 8) &&
		    (hba->config[CFG_TOPOLOGY].current == 4)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "link-speed: %dGb not supported in loop topology. "
			    "Switching to auto detect.",
			    new_value);

			new_value = 0;
			break;
		}

		if (vpd->link_speed) {
			switch (new_value) {
			case 0:
				break;

			case 1:
				if (!(vpd->link_speed & LMT_1GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 1Gb not supported "
					    "by adapter. Switching to auto "
					    "detect.");
				}
				break;

			case 2:
				if (!(vpd->link_speed & LMT_2GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 2Gb not supported "
					    "by adapter. Switching to auto "
					    "detect.");
				}
				break;

			case 4:
				if (!(vpd->link_speed & LMT_4GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 4Gb not supported "
					    "by adapter. Switching to auto "
					    "detect.");
				}
				break;

			case 8:
				if (!(vpd->link_speed & LMT_8GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 8Gb not supported "
					    "by adapter. Switching to auto "
					    "detect.");
				}
				break;

			case 16:
				if (!(vpd->link_speed & LMT_16GB_CAPABLE)) {
					new_value = 0;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_msg,
					    "link-speed: 16Gb not supported "
					    "by adapter. Switching to auto "
					    "detect.");
				}
				break;

			default:
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "link-speed: Invalid value=%d provided. "
				    "Switching to auto detect.",
				    new_value);

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
			case 16:
				/* link-speed is a valid choice */
				break;

			default:
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "link-speed: Invalid value=%d provided. "
				    "Switching to auto detect.",
				    new_value);

				new_value = 0;
			}
		}
		break;

	case CFG_TOPOLOGY:
		if ((new_value == 4) &&
		    (hba->config[CFG_LINK_SPEED].current > 8)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "topology: Loop topology not supported "
			    "with link speeds greater than 8Gb. "
			    "Switching to auto detect.");

			new_value = 0;
			break;
		}

		/* Perform additional check on topology */
		switch (new_value) {
		case 0:
		case 2:
		case 4:
		case 6:
			/* topology is a valid choice */
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "topology: Invalid value=%d provided. "
			    "Switching to auto detect.",
			    new_value);

			new_value = 0;
			break;
		}
		break;

#ifdef DHCHAP_SUPPORT
	case CFG_AUTH_TYPE:
	{
		uint32_t shift;
		uint32_t mask;

		/* Perform additional check on auth type */
		shift = 12;
		mask  = 0xF000;
		for (i = 0; i < 4; i++) {
			if (((new_value & mask) >> shift) > DFC_AUTH_TYPE_MAX) {
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
		mask  = 0xF000;
		for (i = 0; i < 4; i++) {
			if (((new_value & mask) >> shift) > DFC_AUTH_HASH_MAX) {
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
		mask  = 0xF0000000;
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


#endif /* DHCHAP_SUPPORT */

	} /* switch */

	return (new_value);

} /* emlxs_check_parm() */


extern uint32_t
emlxs_set_parm(emlxs_hba_t *hba, uint32_t index, uint32_t new_value)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_port_t	*vport;
	uint32_t	vpi;
	emlxs_config_t	*cfg;
	uint32_t	old_value;

	if (index >= NUM_CFG_PARAM) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "set_parm failed. Invalid index = %d", index);

		return ((uint32_t)FC_FAILURE);
	}

	cfg = &hba->config[index];

	if (!(cfg->flags & PARM_DYNAMIC)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "set_parm failed. %s is not dynamic.", cfg->string);

		return ((uint32_t)FC_FAILURE);
	}

	/* Check new value */
	old_value = new_value;
	new_value = emlxs_check_parm(hba, index, new_value);

	if (old_value != new_value) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "set_parm: %s invalid. 0x%x --> 0x%x",
		    cfg->string, old_value, new_value);
	}

	/* Return now if no actual change */
	if (new_value == cfg->current) {
		return (FC_SUCCESS);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
	    "set_parm: %s changing. 0x%x --> 0x%x",
	    cfg->string, cfg->current, new_value);

	old_value = cfg->current;
	cfg->current = new_value;

	/* React to change if needed */
	switch (index) {

	case CFG_PCI_MAX_READ:
		/* Update MXR */
		emlxs_pcix_mxr_update(hba, 1);
		break;

#ifdef SFCT_SUPPORT
	case CFG_TARGET_MODE:
		(void) emlxs_reset(port, FC_FCA_LINK_RESET);
		break;
#endif /* SFCT_SUPPORT */

	case CFG_SLI_MODE:
		/* Check SLI mode */
		if ((hba->sli_mode == 3) && (new_value == 2)) {
			/* All vports must be disabled first */
			for (vpi = 1; vpi < MAX_VPORTS; vpi++) {
				vport = &VPORT(vpi);

				if (vport->flag & EMLXS_PORT_ENABLED) {
					/* Reset current value */
					cfg->current = old_value;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "set_parm failed. %s: vpi=%d "
					    "still enabled. Value restored to "
					    "0x%x.", cfg->string, vpi,
					    old_value);

					return (2);
				}
			}
		}

		if ((hba->sli_mode >= 4) && (new_value < 4)) {
			/*
			 * Not allow to set to SLI 2 or 3 if HBA supports SLI4
			 */
			cfg->current = old_value;
			return ((uint32_t)FC_FAILURE);
		}

		break;

	case CFG_NPIV_ENABLE:
		/* Check if NPIV is being disabled */
		if ((old_value == 1) && (new_value == 0)) {
			/* All vports must be disabled first */
			for (vpi = 1; vpi < MAX_VPORTS; vpi++) {
				vport = &VPORT(vpi);

				if (vport->flag & EMLXS_PORT_ENABLED) {
					/* Reset current value */
					cfg->current = old_value;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sfs_debug_msg,
					    "set_parm failed. %s: vpi=%d "
					    "still enabled. Value restored to "
					    "0x%x.", cfg->string, vpi,
					    old_value);

					return (2);
				}
			}
		}

		/* Trigger adapter reset */
		/* (void) emlxs_reset(port, FC_FCA_RESET); */

		break;


	case CFG_VPORT_RESTRICTED:
		for (vpi = 0; vpi < MAX_VPORTS; vpi++) {
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
		hba->auth_cfg.hash_priority[0] =
		    (cfg->current & 0xF000) >> 12;
		hba->auth_cfg.hash_priority[1] = (cfg->current & 0x0F00)>>8;
		hba->auth_cfg.hash_priority[2] = (cfg->current & 0x00F0)>>4;
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
#endif /* DHCHAP_SUPPORT */

	}

	return (FC_SUCCESS);

} /* emlxs_set_parm() */


/*
 * emlxs_mem_alloc  OS specific routine for memory allocation / mapping
 *
 * The buf_info->flags field describes the memory operation requested.
 *
 * FC_MBUF_PHYSONLY set  requests a supplied virtual address be mapped for DMA
 * Virtual address is supplied in buf_info->virt
 * DMA mapping flag is in buf_info->align
 * (DMA_READ_ONLY, DMA_WRITE_ONLY, DMA_READ_WRITE)
 * The mapped physical address is returned buf_info->phys
 *
 * FC_MBUF_PHYSONLY cleared requests memory be allocated for driver use and
 * if FC_MBUF_DMA is set the memory is also mapped for DMA
 * The byte alignment of the memory request is supplied in buf_info->align
 * The byte size of the memory request is supplied in buf_info->size
 * The virtual address is returned buf_info->virt
 * The mapped physical address is returned buf_info->phys (for FC_MBUF_DMA)
 */
extern uint8_t *
emlxs_mem_alloc(emlxs_hba_t *hba, MBUF_INFO *buf_info)
{
	emlxs_port_t		*port = &PPORT;
	ddi_dma_attr_t		dma_attr;
	ddi_device_acc_attr_t	dev_attr;
	uint_t			cookie_count;
	size_t			dma_reallen;
	ddi_dma_cookie_t	dma_cookie;
	uint_t			dma_flag;
	int			status;

	dma_attr = hba->dma_attr_1sg;
	dev_attr = emlxs_data_acc_attr;

	if (buf_info->flags & FC_MBUF_SNGLSG) {
		dma_attr.dma_attr_sgllen = 1;
	}

	if (buf_info->flags & FC_MBUF_DMA32) {
		dma_attr.dma_attr_addr_hi = (uint64_t)0xffffffff;
	}

	if (buf_info->flags & FC_MBUF_PHYSONLY) {

		if (buf_info->virt == NULL) {
			goto done;
		}

		/*
		 * Allocate the DMA handle for this DMA object
		 */
		status = ddi_dma_alloc_handle((void *)hba->dip,
		    &dma_attr, DDI_DMA_DONTWAIT,
		    NULL, (ddi_dma_handle_t *)&buf_info->dma_handle);
		if (status != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_alloc_handle failed: size=%x align=%x "
			    "flags=%x", buf_info->size, buf_info->align,
			    buf_info->flags);

			buf_info->phys = 0;
			buf_info->dma_handle = 0;
			goto done;
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
		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "Invalid DMA flag");
			(void) ddi_dma_free_handle(
			    (ddi_dma_handle_t *)&buf_info->dma_handle);
			buf_info->phys = 0;
			buf_info->dma_handle = 0;
			return ((uint8_t *)buf_info->virt);
		}

		/* Map this page of memory */
		status = ddi_dma_addr_bind_handle(
		    (ddi_dma_handle_t)buf_info->dma_handle, NULL,
		    (caddr_t)buf_info->virt, (size_t)buf_info->size,
		    dma_flag, DDI_DMA_DONTWAIT, NULL, &dma_cookie,
		    &cookie_count);

		if (status != DDI_DMA_MAPPED || (cookie_count > 1)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_addr_bind_handle failed: status=%x "
			    "count=%x flags=%x", status, cookie_count,
			    buf_info->flags);

			(void) ddi_dma_free_handle(
			    (ddi_dma_handle_t *)&buf_info->dma_handle);
			buf_info->phys = 0;
			buf_info->dma_handle = 0;
			goto done;
		}

		if (hba->bus_type == SBUS_FC) {

			int32_t burstsizes_limit = 0xff;
			int32_t ret_burst;

			ret_burst = ddi_dma_burstsizes(
			    buf_info->dma_handle) & burstsizes_limit;
			if (ddi_dma_set_sbus64(buf_info->dma_handle,
			    ret_burst) == DDI_FAILURE) {
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
		EMLXS_MPDATA_SYNC((ddi_dma_handle_t)buf_info->dma_handle,
		    (off_t)0, (size_t)buf_info->size, DDI_DMA_SYNC_FORDEV);

	} else if (buf_info->flags & (FC_MBUF_DMA|FC_MBUF_DMA32)) {

		dma_attr.dma_attr_align = buf_info->align;

		/*
		 * Allocate the DMA handle for this DMA object
		 */
		status = ddi_dma_alloc_handle((void *)hba->dip, &dma_attr,
		    DDI_DMA_DONTWAIT, NULL,
		    (ddi_dma_handle_t *)&buf_info->dma_handle);
		if (status != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_alloc_handle failed: size=%x align=%x "
			    "flags=%x", buf_info->size, buf_info->align,
			    buf_info->flags);

			buf_info->virt = NULL;
			buf_info->phys = 0;
			buf_info->data_handle = 0;
			buf_info->dma_handle = 0;
			goto done;
		}

		status = ddi_dma_mem_alloc(
		    (ddi_dma_handle_t)buf_info->dma_handle,
		    (size_t)buf_info->size, &dev_attr, DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, NULL, (caddr_t *)&buf_info->virt,
		    &dma_reallen, (ddi_acc_handle_t *)&buf_info->data_handle);

		if ((status != DDI_SUCCESS) || (buf_info->size > dma_reallen)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_mem_alloc failed: size=%x align=%x "
			    "flags=%x", buf_info->size, buf_info->align,
			    buf_info->flags);

			(void) ddi_dma_free_handle(
			    (ddi_dma_handle_t *)&buf_info->dma_handle);

			buf_info->virt = NULL;
			buf_info->phys = 0;
			buf_info->data_handle = 0;
			buf_info->dma_handle = 0;
			goto done;
		}

		/* Map this page of memory */
		status = ddi_dma_addr_bind_handle(
		    (ddi_dma_handle_t)buf_info->dma_handle, NULL,
		    (caddr_t)buf_info->virt, (size_t)buf_info->size,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    &dma_cookie, &cookie_count);

		if (status != DDI_DMA_MAPPED || (cookie_count > 1)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "ddi_dma_addr_bind_handle failed: status=%x "
			    "count=%d size=%x align=%x flags=%x", status,
			    cookie_count, buf_info->size, buf_info->align,
			    buf_info->flags);

			(void) ddi_dma_mem_free(
			    (ddi_acc_handle_t *)&buf_info->data_handle);
			(void) ddi_dma_free_handle(
			    (ddi_dma_handle_t *)&buf_info->dma_handle);

			buf_info->virt = NULL;
			buf_info->phys = 0;
			buf_info->dma_handle = 0;
			buf_info->data_handle = 0;
			goto done;
		}

		if (hba->bus_type == SBUS_FC) {
			int32_t burstsizes_limit = 0xff;
			int32_t ret_burst;

			ret_burst =
			    ddi_dma_burstsizes(buf_info->
			    dma_handle) & burstsizes_limit;
			if (ddi_dma_set_sbus64(buf_info->dma_handle,
			    ret_burst) == DDI_FAILURE) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mem_alloc_failed_msg,
				    "ddi_dma_set_sbus64 failed.");
			}
		}

		/* Save Physical address */
		buf_info->phys = dma_cookie.dmac_laddress;

		/* Just to be sure, let's add this */
		EMLXS_MPDATA_SYNC((ddi_dma_handle_t)buf_info->dma_handle,
		    (off_t)0, (size_t)buf_info->size, DDI_DMA_SYNC_FORDEV);

	} else {	/* allocate virtual memory */

		buf_info->virt =
		    kmem_zalloc((size_t)buf_info->size, KM_NOSLEEP);
		buf_info->phys = 0;
		buf_info->data_handle = 0;
		buf_info->dma_handle = 0;

		if (buf_info->virt == (uint32_t *)0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "size=%x flags=%x", buf_info->size,
			    buf_info->flags);
		}

	}

done:

	return ((uint8_t *)buf_info->virt);

} /* emlxs_mem_alloc() */



/*
 * emlxs_mem_free:
 *
 * OS specific routine for memory de-allocation / unmapping
 *
 * The buf_info->flags field describes the memory operation requested.
 *
 * FC_MBUF_PHYSONLY set  requests a supplied virtual address be unmapped
 * for DMA, but not freed. The mapped physical address to be unmapped is in
 * buf_info->phys
 *
 * FC_MBUF_PHYSONLY cleared requests memory be freed and unmapped for DMA only
 * if FC_MBUF_DMA is set. The mapped physical address to be unmapped is in
 * buf_info->phys. The virtual address to be freed is in buf_info->virt
 */
/*ARGSUSED*/
extern void
emlxs_mem_free(emlxs_hba_t *hba, MBUF_INFO *buf_info)
{
	if (buf_info->flags & FC_MBUF_PHYSONLY) {

		if (buf_info->dma_handle) {
			(void) ddi_dma_unbind_handle(buf_info->dma_handle);
			(void) ddi_dma_free_handle(
			    (ddi_dma_handle_t *)&buf_info->dma_handle);
			buf_info->dma_handle = NULL;
		}

	} else if (buf_info->flags & (FC_MBUF_DMA|FC_MBUF_DMA32)) {

		if (buf_info->dma_handle) {
			(void) ddi_dma_unbind_handle(buf_info->dma_handle);
			(void) ddi_dma_mem_free(
			    (ddi_acc_handle_t *)&buf_info->data_handle);
			(void) ddi_dma_free_handle(
			    (ddi_dma_handle_t *)&buf_info->dma_handle);
			buf_info->dma_handle = NULL;
			buf_info->data_handle = NULL;
		}

	} else {	/* allocate virtual memory */

		if (buf_info->virt) {
			kmem_free(buf_info->virt, (size_t)buf_info->size);
			buf_info->virt = NULL;
		}
	}

} /* emlxs_mem_free() */


static int
emlxs_select_fcp_channel(emlxs_hba_t *hba, NODELIST *ndlp, int reset)
{
	int		channel;
	int		msi_id;


	/* IO to FCP2 device or a device reset always use fcp channel */
	if ((ndlp->nlp_fcp_info & NLP_FCP_2_DEVICE) || reset) {
		return (hba->channel_fcp);
	}


	msi_id = emlxs_select_msiid(hba);
	channel = emlxs_msiid_to_chan(hba, msi_id);



	/* If channel is closed, then try fcp channel */
	if (ndlp->nlp_flag[channel] & NLP_CLOSED) {
		channel = hba->channel_fcp;
	}
	return (channel);

} /* emlxs_select_fcp_channel() */


static int32_t
emlxs_fast_target_reset(emlxs_port_t *port, emlxs_buf_t *sbp, NODELIST *ndlp)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt;
	emlxs_config_t	*cfg;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;
	uint32_t	rc;

	/*
	 * This routine provides a alternative target reset provessing
	 * method. Instead of sending an actual target reset to the
	 * NPort, we will first unreg the login to that NPort. This
	 * will cause all the outstanding IOs the quickly complete with
	 * a NO RPI local error. Next we will force the ULP to relogin
	 * to the NPort by sending an RSCN (for that NPort) to the
	 * upper layer. This method should result in a fast target
	 * reset, as far as IOs completing; however, since an actual
	 * target reset is not sent to the NPort, it is not 100%
	 * compatable. Things like reservations will not be broken.
	 * By default this option is DISABLED, and its only enabled thru
	 * a hidden configuration parameter (fast-tgt-reset).
	 */
	rc = FC_TRAN_BUSY;
	pkt = PRIV2PKT(sbp);
	cfg = &CFG;

	if ((mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		/* issue the mbox cmd to the sli */
		mb = (MAILBOX *) mbq->mbox;
		bzero((void *) mb, MAILBOX_CMD_BSIZE);
		mb->un.varUnregLogin.rpi = (uint16_t)ndlp->nlp_Rpi;
#ifdef SLI3_SUPPORT
		mb->un.varUnregLogin.vpi = port->vpi;
#endif	/* SLI3_SUPPORT */
		mb->mbxCommand = MBX_UNREG_LOGIN;
		mb->mbxOwner = OWN_HOST;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Fast Target Reset: unreg rpi=%d tmr=%d", ndlp->nlp_Rpi,
		    cfg[CFG_FAST_TGT_RESET_TMR].current);

		if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0)
		    == MBX_SUCCESS) {

			ndlp->nlp_Rpi = 0;

			mutex_enter(&sbp->mtx);
			sbp->node = (void *)ndlp;
			sbp->did = ndlp->nlp_DID;
			mutex_exit(&sbp->mtx);

			if (pkt->pkt_rsplen) {
				bzero((uint8_t *)pkt->pkt_resp,
				    pkt->pkt_rsplen);
			}
			if (cfg[CFG_FAST_TGT_RESET_TMR].current) {
				ndlp->nlp_force_rscn = hba->timer_tics +
				    cfg[CFG_FAST_TGT_RESET_TMR].current;
			}

			emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 0);
		}

		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		rc = FC_SUCCESS;
	}
	return (rc);
} /* emlxs_fast_target_reset() */

static int32_t
emlxs_send_fcp_cmd(emlxs_port_t *port, emlxs_buf_t *sbp, uint32_t *pkt_flags)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt;
	emlxs_config_t	*cfg;
	IOCBQ		*iocbq;
	IOCB		*iocb;
	CHANNEL		*cp;
	NODELIST	*ndlp;
	char		*cmd;
	uint16_t	lun;
	FCP_CMND	*fcp_cmd;
	uint32_t	did;
	uint32_t	reset = 0;
	int		channel;
	int32_t		rval;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	/* Find target node object */
	ndlp = emlxs_node_find_did(port, did, 1);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=%x", did);

		return (FC_BADPACKET);
	}

	/* When the fcp channel is closed we stop accepting any FCP cmd */
	if (ndlp->nlp_flag[hba->channel_fcp] & NLP_CLOSED) {
		return (FC_TRAN_BUSY);
	}

	/* Snoop for target or lun reset first */
	/* We always use FCP channel to send out target/lun reset fcp cmds */
	/* interrupt affinity only applies to non tgt lun reset fcp cmd */

	cmd = (char *)pkt->pkt_cmd;
	lun = *((uint16_t *)cmd);
	lun = LE_SWAP16(lun);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;
	iocbq->node = (void *) ndlp;

	/* Check for target reset */
	if (cmd[10] & 0x20) {
		/* prepare iocb */
		if ((rval = EMLXS_SLI_PREP_FCP_IOCB(port, sbp,
		    hba->channel_fcp)) != FC_SUCCESS) {

			if (rval == 0xff) {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    0, 1);
				rval = FC_SUCCESS;
			}

			return (rval);
		}

		mutex_enter(&sbp->mtx);
		sbp->pkt_flags |= PACKET_FCP_TGT_RESET;
		sbp->pkt_flags |= PACKET_POLLED;
		*pkt_flags = sbp->pkt_flags;
		mutex_exit(&sbp->mtx);

#ifdef SAN_DIAG_SUPPORT
		emlxs_log_sd_scsi_event(port, SD_SCSI_SUBCATEGORY_TGTRESET,
		    (HBA_WWN *)&ndlp->nlp_portname, -1);
#endif	/* SAN_DIAG_SUPPORT */

		iocbq->flag |= IOCB_PRIORITY;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Target Reset: did=%x", did);

		cfg = &CFG;
		if (cfg[CFG_FAST_TGT_RESET].current) {
			if (emlxs_fast_target_reset(port, sbp, ndlp) ==
			    FC_SUCCESS) {
				return (FC_SUCCESS);
			}
		}

		/* Close the node for any further normal IO */
		emlxs_node_close(port, ndlp, hba->channel_fcp,
		    pkt->pkt_timeout);

		/* Flush the IO's on the tx queues */
		(void) emlxs_tx_node_flush(port, ndlp,
		    &hba->chan[hba->channel_fcp], 0, sbp);

		/* This is the target reset fcp cmd */
		reset = 1;
	}

	/* Check for lun reset */
	else if (cmd[10] & 0x10) {
		/* prepare iocb */
		if ((rval = EMLXS_SLI_PREP_FCP_IOCB(port, sbp,
		    hba->channel_fcp)) != FC_SUCCESS) {

			if (rval == 0xff) {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    0, 1);
				rval = FC_SUCCESS;
			}

			return (rval);
		}

		mutex_enter(&sbp->mtx);
		sbp->pkt_flags |= PACKET_FCP_LUN_RESET;
		sbp->pkt_flags |= PACKET_POLLED;
		*pkt_flags = sbp->pkt_flags;
		mutex_exit(&sbp->mtx);

#ifdef SAN_DIAG_SUPPORT
		emlxs_log_sd_scsi_event(port, SD_SCSI_SUBCATEGORY_LUNRESET,
		    (HBA_WWN *)&ndlp->nlp_portname, lun);
#endif	/* SAN_DIAG_SUPPORT */

		iocbq->flag |= IOCB_PRIORITY;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "LUN Reset: did=%x lun=%02x LUN=%02x02x", did, lun,
		    cmd[0], cmd[1]);

		/* Flush the IO's on the tx queues for this lun */
		(void) emlxs_tx_lun_flush(port, ndlp, lun, sbp);

		/* This is the lun reset fcp cmd */
		reset = 1;
	}

	channel = emlxs_select_fcp_channel(hba, ndlp, reset);

#ifdef SAN_DIAG_SUPPORT
	sbp->sd_start_time = gethrtime();
#endif /* SAN_DIAG_SUPPORT */

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_fcp_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	fcp_cmd = (FCP_CMND *) pkt->pkt_cmd;

	if (fcp_cmd->fcpCntl1 == FCP_QTYPE_UNTAGGED) {
		fcp_cmd->fcpCntl1 = FCP_QTYPE_SIMPLE;
	}

	if (reset == 0) {
		/*
		 * tgt lun reset fcp cmd has been prepared
		 * separately in the beginning
		 */
		if ((rval = EMLXS_SLI_PREP_FCP_IOCB(port, sbp,
		    channel)) != FC_SUCCESS) {

			if (rval == 0xff) {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    0, 1);
				rval = FC_SUCCESS;
			}

			return (rval);
		}
	}

	cp = &hba->chan[channel];
	cp->ulpSendCmd++;

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *)ndlp;
	sbp->lun = lun;
	sbp->class = iocb->ULPCLASS;
	sbp->did = ndlp->nlp_DID;
	mutex_exit(&sbp->mtx);

	if (pkt->pkt_cmdlen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}

	if (pkt->pkt_datalen && pkt->pkt_tran_type == FC_PKT_FCP_WRITE) {
		EMLXS_MPDATA_SYNC(pkt->pkt_data_dma, 0, pkt->pkt_datalen,
		    DDI_DMA_SYNC_FORDEV);
	}

	HBASTATS.FcpIssued++;

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);
	return (FC_SUCCESS);

} /* emlxs_send_fcp_cmd() */




/*
 * We have to consider this setup works for INTX, MSI, and MSIX
 * For INTX, intr_count is always 1
 * For MSI, intr_count is always 2 by default
 * For MSIX, intr_count is configurable (1, 2, 4, 8) for now.
 */
extern int
emlxs_select_msiid(emlxs_hba_t *hba)
{
	int	msiid = 0;

	/* We use round-robin */
	mutex_enter(&EMLXS_MSIID_LOCK);
	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		msiid = hba->last_msiid;
		hba->last_msiid ++;
		if (hba->last_msiid >= hba->intr_count) {
			hba->last_msiid = 0;
		}
	} else {
		/* This should work for INTX and MSI also */
		/* For SLI3 the chan_count is always 4 */
		/* For SLI3 the msiid is limited to chan_count */
		msiid = hba->last_msiid;
		hba->last_msiid ++;
		if (hba->intr_count > hba->chan_count) {
			if (hba->last_msiid >= hba->chan_count) {
				hba->last_msiid = 0;
			}
		} else {
			if (hba->last_msiid >= hba->intr_count) {
				hba->last_msiid = 0;
			}
		}
	}
	mutex_exit(&EMLXS_MSIID_LOCK);

	return (msiid);
} /* emlxs_select_msiid */


/*
 * A channel has a association with a msi id.
 * One msi id could be associated with multiple channels.
 */
extern int
emlxs_msiid_to_chan(emlxs_hba_t *hba, int msi_id)
{
	emlxs_config_t *cfg = &CFG;
	EQ_DESC_t *eqp;
	int chan;
	int num_wq;

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		/* For SLI4 round robin all WQs associated with the msi_id */
		eqp = &hba->sli.sli4.eq[msi_id];

		mutex_enter(&eqp->lastwq_lock);
		chan = eqp->lastwq;
		eqp->lastwq++;
		num_wq = cfg[CFG_NUM_WQ].current;
		if (eqp->lastwq >= ((msi_id + 1) * num_wq)) {
			eqp->lastwq -= num_wq;
		}
		mutex_exit(&eqp->lastwq_lock);

		return (chan);
	} else {
		/* This is for SLI3 mode */
		return (hba->msi2chan[msi_id]);
	}

} /* emlxs_msiid_to_chan */


#ifdef SFCT_SUPPORT
static int32_t
emlxs_send_fct_status(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t		*hba = HBA;
	IOCBQ			*iocbq;
	IOCB			*iocb;
	NODELIST		*ndlp;
	CHANNEL			*cp;
	uint32_t		did;

	did = sbp->did;
	ndlp = sbp->node;
	cp = (CHANNEL *)sbp->channel;

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Make sure node is still active */
	if (!ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "*Node not found. did=%x", did);

		return (FC_BADPACKET);
	}

	/* If gate is closed */
	if (ndlp->nlp_flag[hba->channel_fcp] & NLP_CLOSED) {
		return (FC_TRAN_BUSY);
	}

	iocb->ULPCOMMAND = CMD_FCP_TRSP64_CX;
	if (EMLXS_SLI_PREP_FCT_IOCB(port, sbp, cp->channelno) !=
	    IOERR_SUCCESS) {
		return (FC_TRAN_BUSY);
	}

	HBASTATS.FcpIssued++;

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_fct_status() */


static int32_t
emlxs_send_fct_abort(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	IOCBQ		*iocbq;
	IOCB		*iocb;
	NODELIST	*ndlp;
	CHANNEL		*cp;
	uint32_t	did;

	did = sbp->did;
	ndlp = sbp->node;
	cp = (CHANNEL *)sbp->channel;

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Make sure node is still active */
	if ((ndlp == NULL) || (!ndlp->nlp_active)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "*Node not found. did=%x", did);

		return (FC_BADPACKET);
	}

	/* If gate is closed */
	if (ndlp->nlp_flag[hba->channel_fcp] & NLP_CLOSED) {
		return (FC_TRAN_BUSY);
	}

	iocb->ULPCOMMAND = CMD_ABORT_XRI_CX;
	if (EMLXS_SLI_PREP_FCT_IOCB(port, sbp, cp->channelno) !=
	    IOERR_SUCCESS) {
		return (FC_TRAN_BUSY);
	}

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, sbp->channel, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_fct_abort() */

#endif /* SFCT_SUPPORT */


static int32_t
emlxs_send_ip(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt;
	IOCBQ		*iocbq;
	IOCB		*iocb;
	CHANNEL		*cp;
	uint32_t	i;
	NODELIST	*ndlp;
	uint32_t	did;
	int32_t 	rval;

	pkt = PRIV2PKT(sbp);
	cp = &hba->chan[hba->channel_ip];
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	/* Check if node exists */
	/* Broadcast did is always a success */
	ndlp = emlxs_node_find_did(port, did, 1);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=0x%x", did);

		return (FC_BADPACKET);
	}

	/* Check if gate is temporarily closed */
	if (ndlp->nlp_flag[hba->channel_ip] & NLP_CLOSED) {
		return (FC_TRAN_BUSY);
	}

	/* Check if an exchange has been created */
	if ((ndlp->nlp_Xri == 0) && (did != BCAST_DID)) {
		/* No exchange.  Try creating one */
		(void) emlxs_create_xri(port, cp, ndlp);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Exchange not found. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}

	/* ULP PATCH: pkt_cmdlen was found to be set to zero */
	/* on BROADCAST commands */
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

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	iocbq->node = (void *)ndlp;
	if ((rval = EMLXS_SLI_PREP_IP_IOCB(port, sbp)) != FC_SUCCESS) {

		if (rval == 0xff) {
			emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, 0, 1);
			rval = FC_SUCCESS;
		}

		return (rval);
	}

	cp->ulpSendCmd++;

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *)ndlp;
	sbp->lun = EMLXS_LUN_NONE;
	sbp->class = iocb->ULPCLASS;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	if (pkt->pkt_cmdlen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_ip() */


static int32_t
emlxs_send_els(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	emlxs_port_t	*vport;
	fc_packet_t	*pkt;
	IOCBQ		*iocbq;
	CHANNEL		*cp;
	SERV_PARM	*sp;
	uint32_t	cmd;
	int		i;
	ELS_PKT		*els_pkt;
	NODELIST	*ndlp;
	uint32_t	did;
	char		fcsp_msg[32];
	int		rc;
	int32_t 	rval;
	emlxs_config_t  *cfg = &CFG;

	fcsp_msg[0] = 0;
	pkt = PRIV2PKT(sbp);
	els_pkt = (ELS_PKT *)pkt->pkt_cmd;
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	cmd = *((uint32_t *)pkt->pkt_cmd);
	cmd &= ELS_CMD_MASK;

	/* Point of no return, except for ADISC & PLOGI */

	/* Check node */
	switch (cmd) {
	case ELS_CMD_FLOGI:
	case ELS_CMD_FDISC:
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {

			if (emlxs_vpi_logi_notify(port, sbp)) {
				pkt->pkt_state = FC_PKT_LOCAL_RJT;
#if (EMLXS_MODREVX == EMLXS_MODREV2X)
				emlxs_unswap_pkt(sbp);
#endif  /* EMLXS_MODREV2X */
				return (FC_FAILURE);
			}
		} else {
			/*
			 * If FLOGI is already complete, then we
			 * should not be receiving another FLOGI.
			 * Reset the link to recover.
			 */
			if (port->flag & EMLXS_PORT_FLOGI_CMPL) {
				pkt->pkt_state = FC_PKT_LOCAL_RJT;
#if (EMLXS_MODREVX == EMLXS_MODREV2X)
				emlxs_unswap_pkt(sbp);
#endif  /* EMLXS_MODREV2X */

				(void) emlxs_reset(port, FC_FCA_LINK_RESET);
				return (FC_FAILURE);
			}

			if (port->vpi > 0) {
				*((uint32_t *)pkt->pkt_cmd) = ELS_CMD_FDISC;
			}
		}

		/* Command may have been changed */
		cmd = *((uint32_t *)pkt->pkt_cmd);
		cmd &= ELS_CMD_MASK;

		if (hba->flag & FC_NPIV_DELAY_REQUIRED) {
			sbp->pkt_flags |= PACKET_DELAY_REQUIRED;
		}

		ndlp = NULL;

		/* We will process these cmds at the bottom of this routine */
		break;

	case ELS_CMD_PLOGI:
		/* Make sure we don't log into ourself */
		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);

			if (!(vport->flag & EMLXS_INI_BOUND)) {
				continue;
			}

			if (did == vport->did) {
				pkt->pkt_state = FC_PKT_NPORT_RJT;

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
				emlxs_unswap_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

				return (FC_FAILURE);
			}
		}

		ndlp = NULL;

		if (hba->flag & FC_PT_TO_PT) {
			MAILBOXQ	*mbox;

			/* ULP bug fix */
			if (pkt->pkt_cmd_fhdr.s_id == 0) {
				pkt->pkt_cmd_fhdr.s_id = FP_DEFAULT_SID;
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_send_msg,
				    "PLOGI: P2P Fix. sid=0-->%x did=%x",
				    pkt->pkt_cmd_fhdr.s_id,
				    pkt->pkt_cmd_fhdr.d_id);
			}

			mutex_enter(&EMLXS_PORT_LOCK);
			port->did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.s_id);
			port->rdid = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
			mutex_exit(&EMLXS_PORT_LOCK);

			if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
				/* Update our service parms */
				if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
				    MEM_MBOX))) {
					emlxs_mb_config_link(hba, mbox);

					rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba,
					    mbox, MBX_NOWAIT, 0);
					if ((rc != MBX_BUSY) &&
					    (rc != MBX_SUCCESS)) {
						emlxs_mem_put(hba, MEM_MBOX,
						    (void *)mbox);
					}
				}
			}
		}

		/* We will process these cmds at the bottom of this routine */
		break;

	default:
		ndlp = emlxs_node_find_did(port, did, 1);

		/* If an ADISC is being sent and we have no node, */
		/* then we must fail the ADISC now */
		if (!ndlp && (cmd == ELS_CMD_ADISC) &&
		    (port->mode == MODE_INITIATOR)) {

			/* Build the LS_RJT response */
			els_pkt = (ELS_PKT *)pkt->pkt_resp;
			els_pkt->elsCode = 0x01;
			els_pkt->un.lsRjt.un.b.lsRjtRsvd0 = 0;
			els_pkt->un.lsRjt.un.b.lsRjtRsnCode =
			    LSRJT_LOGICAL_ERR;
			els_pkt->un.lsRjt.un.b.lsRjtRsnCodeExp =
			    LSEXP_NOTHING_MORE;
			els_pkt->un.lsRjt.un.b.vendorUnique = 0x03;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "ADISC Rejected. Node not found. did=0x%x", did);

			if (sbp->channel == NULL) {
				if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
					sbp->channel =
					    &hba->chan[hba->channel_els];
				} else {
					sbp->channel =
					    &hba->chan[FC_ELS_RING];
				}
			}

			/* Return this as rejected by the target */
			emlxs_pkt_complete(sbp, IOSTAT_LS_RJT, 0, 1);

			return (FC_SUCCESS);
		}
	}

	/* DID == BCAST_DID is special case to indicate that */
	/* RPI is being passed in seq_id field */
	/* This is used by emlxs_send_logo() for target mode */

	/* Initalize iocbq */
	iocbq->node = (void *)ndlp;
	if ((rval = EMLXS_SLI_PREP_ELS_IOCB(port, sbp)) != FC_SUCCESS) {

		if (rval == 0xff) {
			emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, 0, 1);
			rval = FC_SUCCESS;
		}

		return (rval);
	}

	cp = &hba->chan[hba->channel_els];
	cp->ulpSendCmd++;
	sp = (SERV_PARM *)&els_pkt->un.logi;

	/* Check cmd */
	switch (cmd) {
	case ELS_CMD_PRLI:
		/*
		 * if our firmware version is 3.20 or later,
		 * set the following bits for FC-TAPE support.
		 */
		if ((port->mode == MODE_INITIATOR) &&
		    (hba->vpd.feaLevelHigh >= 0x02) &&
		    (cfg[CFG_ADISC_SUPPORT].current != 0)) {
				els_pkt->un.prli.ConfmComplAllowed = 1;
				els_pkt->un.prli.Retry = 1;
				els_pkt->un.prli.TaskRetryIdReq = 1;
		} else {
				els_pkt->un.prli.ConfmComplAllowed = 0;
				els_pkt->un.prli.Retry = 0;
				els_pkt->un.prli.TaskRetryIdReq = 0;
		}

		break;

		/* This is a patch for the ULP stack. */

		/*
		 * ULP only reads our service parameters once during bind_port,
		 * but the service parameters change due to topology.
		 */
	case ELS_CMD_FLOGI:
	case ELS_CMD_FDISC:
	case ELS_CMD_PLOGI:
	case ELS_CMD_PDISC:
		/* Copy latest service parameters to payload */
		bcopy((void *) &port->sparam, (void *)sp, sizeof (SERV_PARM));

		if ((cmd == ELS_CMD_FLOGI) || (cmd == ELS_CMD_FDISC)) {

			/* Clear support for virtual fabrics */
			/* randomOffset bit controls this for FLOGI */
			sp->cmn.randomOffset = 0;

			/* Set R_A_TOV to current value */
			sp->cmn.w2.r_a_tov =
			    LE_SWAP32((hba->fc_ratov * 1000));
		}

		if ((hba->flag & FC_NPIV_ENABLED) &&
		    (hba->flag & FC_NPIV_SUPPORTED) &&
		    (cmd == ELS_CMD_PLOGI)) {
			emlxs_vvl_fmt_t	*vvl;

			sp->VALID_VENDOR_VERSION = 1;
			vvl = (emlxs_vvl_fmt_t *)&sp->vendorVersion[0];
			vvl->un0.w0.oui = 0x0000C9;
			vvl->un0.word0 = LE_SWAP32(vvl->un0.word0);
			vvl->un1.w1.vport =  (port->vpi > 0) ? 1 : 0;
			vvl->un1.word1 = LE_SWAP32(vvl->un1.word1);
		}

#ifdef DHCHAP_SUPPORT
		emlxs_dhc_init_sp(port, did, sp, (char **)&fcsp_msg);
#endif	/* DHCHAP_SUPPORT */

		break;
	}

	/* Initialize the sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *)ndlp;
	sbp->lun = EMLXS_LUN_NONE;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_send_msg, "%s: sid=%x did=%x %s",
	    emlxs_elscmd_xlate(cmd), port->did, did, fcsp_msg);

	if (pkt->pkt_cmdlen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}

	/* Check node */
	switch (cmd) {
	case ELS_CMD_FLOGI:
	case ELS_CMD_FDISC:
		if (port->mode == MODE_INITIATOR) {
			/* Make sure fabric node is destroyed */
			/* It should already have been destroyed at link down */
			if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
				ndlp = emlxs_node_find_did(port, FABRIC_DID, 1);
				if (ndlp) {
					if (EMLXS_SLI_UNREG_NODE(port, ndlp,
					    NULL, NULL, iocbq) == 0) {
						/* Deferring iocb tx until */
						/* completion of unreg */
						return (FC_SUCCESS);
					}
				}
			}
		}
		break;

	case ELS_CMD_PLOGI:

		ndlp = emlxs_node_find_did(port, did, 1);

		if (ndlp && ndlp->nlp_active) {
			/* Close the node for any further normal IO */
			emlxs_node_close(port, ndlp, hba->channel_fcp,
			    pkt->pkt_timeout + 10);
			emlxs_node_close(port, ndlp, hba->channel_ip,
			    pkt->pkt_timeout + 10);

			/* Flush tx queues */
			(void) emlxs_tx_node_flush(port, ndlp, 0, 0, 0);

			/* Flush chip queues */
			(void) emlxs_chipq_node_flush(port, 0, ndlp, 0);
		}

		break;

	case ELS_CMD_PRLI:

		ndlp = emlxs_node_find_did(port, did, 1);

		if (ndlp && ndlp->nlp_active) {
			/*
			 * Close the node for any further FCP IO;
			 * Flush all outstanding I/O only if
			 * "Establish Image Pair" bit is set.
			 */
			emlxs_node_close(port, ndlp, hba->channel_fcp,
			    pkt->pkt_timeout + 10);

			if (els_pkt->un.prli.estabImagePair) {
				/* Flush tx queues */
				(void) emlxs_tx_node_flush(port, ndlp,
				    &hba->chan[hba->channel_fcp], 0, 0);

				/* Flush chip queues */
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_fcp], ndlp, 0);
			}
		}

		break;

	}

	HBASTATS.ElsCmdIssued++;

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_els() */




static int32_t
emlxs_send_els_rsp(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	emlxs_config_t  *cfg = &CFG;
	fc_packet_t	*pkt;
	IOCBQ		*iocbq;
	IOCB		*iocb;
	NODELIST	*ndlp;
	CHANNEL		*cp;
	int		i;
	uint32_t	cmd;
	uint32_t	ucmd;
	ELS_PKT		*els_pkt;
	fc_unsol_buf_t	*ubp;
	emlxs_ub_priv_t	*ub_priv;
	uint32_t	did;
	char		fcsp_msg[32];
	uint8_t		*ub_buffer;
	int32_t		rval;

	fcsp_msg[0] = 0;
	pkt = PRIV2PKT(sbp);
	els_pkt = (ELS_PKT *)pkt->pkt_cmd;
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

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
#endif /* SFCT_SUPPORT */

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
		/* We do this because the ub is only valid */
		/* until we return from this thread */
		pkt->pkt_cmd_fhdr.ox_id = (ucmd >> ELS_CMD_SHIFT) & 0xff;
	}

	/* Save the result */
	sbp->ucmd = ucmd;

	if (sbp->channel == NULL) {
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			sbp->channel = &hba->chan[hba->channel_els];
		} else {
			sbp->channel = &hba->chan[FC_ELS_RING];
		}
	}

	/* Check for interceptions */
	switch (ucmd) {

#ifdef ULP_PATCH2
	case ELS_CMD_LOGO:
		if (!(cfg[CFG_ENABLE_PATCH].current & ULP_PATCH2)) {
			break;
		}

		/* Check if this was generated by ULP and not us */
		if (!(sbp->pkt_flags & PACKET_ALLOCATED)) {

			/*
			 * Since we replied to this already,
			 * we won't need to send this now
			 */
			emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

			return (FC_SUCCESS);
		}

		break;
#endif /* ULP_PATCH2 */

#ifdef ULP_PATCH3
	case ELS_CMD_PRLI:
		if (!(cfg[CFG_ENABLE_PATCH].current & ULP_PATCH3)) {
			break;
		}

		/* Check if this was generated by ULP and not us */
		if (!(sbp->pkt_flags & PACKET_ALLOCATED)) {

			/*
			 * Since we replied to this already,
			 * we won't need to send this now
			 */
			emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

			return (FC_SUCCESS);
		}

		break;
#endif /* ULP_PATCH3 */


#ifdef ULP_PATCH4
	case ELS_CMD_PRLO:
		if (!(cfg[CFG_ENABLE_PATCH].current & ULP_PATCH4)) {
			break;
		}

		/* Check if this was generated by ULP and not us */
		if (!(sbp->pkt_flags & PACKET_ALLOCATED)) {
			/*
			 * Since we replied to this already,
			 * we won't need to send this now
			 */
			emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

			return (FC_SUCCESS);
		}

		break;
#endif /* ULP_PATCH4 */

#ifdef ULP_PATCH6
	case ELS_CMD_RSCN:
		if (!(cfg[CFG_ENABLE_PATCH].current & ULP_PATCH6)) {
			break;
		}

		/* Check if this RSCN was generated by us */
		if (ub_priv && (ub_priv->flags & EMLXS_UB_INTERCEPT)) {
			cmd = *((uint32_t *)pkt->pkt_cmd);
			cmd = LE_SWAP32(cmd);
			cmd &= ELS_CMD_MASK;

			/*
			 * If ULP is accepting this,
			 * then close affected node
			 */
			if ((port->mode == MODE_INITIATOR) && ub_buffer &&
			    cmd == ELS_CMD_ACC) {
				fc_rscn_t	*rscn;
				uint32_t	count;
				uint32_t	*lp;

				/*
				 * Only the Leadville code path will
				 * come thru here. The RSCN data is NOT
				 * swapped properly for the Comstar code
				 * path.
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
			 * Since we generated this RSCN,
			 * we won't need to send this reply
			 */
			emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

			return (FC_SUCCESS);
		}

		break;
#endif /* ULP_PATCH6 */

	case ELS_CMD_PLOGI:
		/* Check if this PLOGI was generated by us */
		if (ub_priv && (ub_priv->flags & EMLXS_UB_INTERCEPT)) {
			cmd = *((uint32_t *)pkt->pkt_cmd);
			cmd = LE_SWAP32(cmd);
			cmd &= ELS_CMD_MASK;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_reply_msg,
			    "PLOGI %s: did=%x oxid=%x rxid=%x. "
			    "Intercepted.", emlxs_elscmd_xlate(cmd),
			    did, pkt->pkt_cmd_fhdr.ox_id,
			    pkt->pkt_cmd_fhdr.rx_id);

			/*
			 * Since we generated this PLOGI,
			 * we won't need to send this reply
			 */
			emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

			return (FC_SUCCESS);
		}

		break;
	}

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
			if ((port->mode == MODE_INITIATOR) &&
			    (hba->vpd.feaLevelHigh >= 0x02) &&
			    (cfg[CFG_ADISC_SUPPORT].current != 0)) {
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
	case ELS_CMD_FDISC:
		if (cmd == ELS_CMD_ACC) {
			SERV_PARM *sp = (SERV_PARM *)&els_pkt->un.logi;

			/* This is a patch for the ULP stack. */

			/*
			 * ULP only reads our service parameters
			 * once during bind_port, but the service
			 * parameters change due to topology.
			 */

			/* Copy latest service parameters to payload */
			bcopy((void *)&port->sparam,
			    (void *)sp, sizeof (SERV_PARM));

			/* We are in pt-to-pt mode. Set R_A_TOV to default */
			sp->cmn.w2.r_a_tov =
			    LE_SWAP32((FF_DEF_RATOV * 1000));

			/* Clear support for virtual fabrics */
			/* randomOffset bit controls this for FLOGI */
			sp->cmn.randomOffset = 0;
#ifdef DHCHAP_SUPPORT
			emlxs_dhc_init_sp(port, did, sp, (char **)&fcsp_msg);
#endif	/* DHCHAP_SUPPORT */
		}
		break;

	case ELS_CMD_PLOGI:
	case ELS_CMD_PDISC:
		if (cmd == ELS_CMD_ACC) {
			SERV_PARM *sp = (SERV_PARM *)&els_pkt->un.logi;

			/* This is a patch for the ULP stack. */

			/*
			 * ULP only reads our service parameters
			 * once during bind_port, but the service
			 * parameters change due to topology.
			 */

			/* Copy latest service parameters to payload */
			bcopy((void *)&port->sparam,
			    (void *)sp, sizeof (SERV_PARM));

#ifdef DHCHAP_SUPPORT
			emlxs_dhc_init_sp(port, did, sp, (char **)&fcsp_msg);
#endif	/* DHCHAP_SUPPORT */
		}
		break;

	}

	/* Initalize iocbq */
	iocbq->node = (void *)NULL;
	if ((rval = EMLXS_SLI_PREP_ELS_IOCB(port, sbp)) != FC_SUCCESS) {

		if (rval == 0xff) {
			emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, 0, 1);
			rval = FC_SUCCESS;
		}

		return (rval);
	}

	cp = &hba->chan[hba->channel_els];
	cp->ulpSendCmd++;

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *) NULL;
	sbp->lun = EMLXS_LUN_NONE;
	sbp->class = iocb->ULPCLASS;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_reply_msg,
	    "%s %s: did=%x oxid=%x rxid=%x %s", emlxs_elscmd_xlate(ucmd),
	    emlxs_elscmd_xlate(cmd), did, pkt->pkt_cmd_fhdr.ox_id,
	    pkt->pkt_cmd_fhdr.rx_id, fcsp_msg);

	/* Process nodes */
	switch (ucmd) {
	case ELS_CMD_RSCN:
		if ((port->mode == MODE_INITIATOR) && ub_buffer &&
		    cmd == ELS_CMD_ACC) {
			fc_rscn_t	*rscn;
			uint32_t	count;
			uint32_t	*lp = NULL;

			/*
			 * Only the Leadville code path will come thru
			 * here. The RSCN data is NOT swapped properly
			 * for the Comstar code path.
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

	case ELS_CMD_PLOGI:
		if (cmd == ELS_CMD_ACC) {
			ndlp = emlxs_node_find_did(port, did, 1);

			if (ndlp && ndlp->nlp_active) {
				/* Close the node for any further normal IO */
				emlxs_node_close(port, ndlp, hba->channel_fcp,
				    pkt->pkt_timeout + 10);
				emlxs_node_close(port, ndlp, hba->channel_ip,
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
			ndlp = emlxs_node_find_did(port, did, 1);

			if (ndlp && ndlp->nlp_active) {
				/* Close the node for any further normal IO */
				emlxs_node_close(port, ndlp, hba->channel_fcp,
				    pkt->pkt_timeout + 10);

				/* Flush tx queues */
				(void) emlxs_tx_node_flush(port, ndlp,
				    &hba->chan[hba->channel_fcp], 0, 0);

				/* Flush chip queues */
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_fcp], ndlp, 0);
			}
		}
		break;

	case ELS_CMD_PRLO:
		if (cmd == ELS_CMD_ACC) {
			ndlp = emlxs_node_find_did(port, did, 1);

			if (ndlp && ndlp->nlp_active) {
				/* Close the node for any further normal IO */
				emlxs_node_close(port, ndlp,
				    hba->channel_fcp, 60);

				/* Flush tx queues */
				(void) emlxs_tx_node_flush(port, ndlp,
				    &hba->chan[hba->channel_fcp], 0, 0);

				/* Flush chip queues */
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_fcp], ndlp, 0);
			}
		}

		break;

	case ELS_CMD_LOGO:
		if (cmd == ELS_CMD_ACC) {
			ndlp = emlxs_node_find_did(port, did, 1);

			if (ndlp && ndlp->nlp_active) {
				/* Close the node for any further normal IO */
				emlxs_node_close(port, ndlp,
				    hba->channel_fcp, 60);
				emlxs_node_close(port, ndlp,
				    hba->channel_ip, 60);

				/* Flush tx queues */
				(void) emlxs_tx_node_flush(port, ndlp, 0, 0, 0);

				/* Flush chip queues */
				(void) emlxs_chipq_node_flush(port, 0, ndlp, 0);
			}
		}

		break;
	}

	if (pkt->pkt_cmdlen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}

	HBASTATS.ElsRspIssued++;

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_els_rsp() */


#ifdef MENLO_SUPPORT
static int32_t
emlxs_send_menlo(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt;
	IOCBQ		*iocbq;
	IOCB		*iocb;
	CHANNEL		*cp;
	NODELIST	*ndlp;
	uint32_t	did;
	uint32_t	*lp;
	int32_t		rval;

	pkt = PRIV2PKT(sbp);
	did = EMLXS_MENLO_DID;
	lp = (uint32_t *)pkt->pkt_cmd;

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	ndlp = emlxs_node_find_did(port, did, 1);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=0x%x", did);

		return (FC_BADPACKET);
	}

	iocbq->node = (void *) ndlp;
	if ((rval = EMLXS_SLI_PREP_CT_IOCB(port, sbp)) != FC_SUCCESS) {

		if (rval == 0xff) {
			emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, 0, 1);
			rval = FC_SUCCESS;
		}

		return (rval);
	}

	cp = &hba->chan[hba->channel_ct];
	cp->ulpSendCmd++;

	if (pkt->pkt_tran_type == FC_PKT_EXCHANGE) {
		/* Cmd phase */

		/* Initalize iocb */
		iocb->un.genreq64.param = pkt->pkt_cmd_fhdr.d_id;
		iocb->ULPCONTEXT = 0;
		iocb->ULPPU = 3;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: [%08x,%08x,%08x,%08x]",
		    emlxs_menlo_cmd_xlate(BE_SWAP32(lp[0])), BE_SWAP32(lp[1]),
		    BE_SWAP32(lp[2]), BE_SWAP32(lp[3]), BE_SWAP32(lp[4]));

	} else {	/* FC_PKT_OUTBOUND */

		/* MENLO_CMD_FW_DOWNLOAD Data Phase */
		iocb->ULPCOMMAND = CMD_GEN_REQUEST64_CX;

		/* Initalize iocb */
		iocb->un.genreq64.param = 0;
		iocb->ULPCONTEXT = pkt->pkt_cmd_fhdr.rx_id;
		iocb->ULPPU = 1;

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
	sbp->lun = EMLXS_LUN_NONE;
	sbp->class = iocb->ULPCLASS;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	EMLXS_MPDATA_SYNC(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
	    DDI_DMA_SYNC_FORDEV);

	HBASTATS.CtCmdIssued++;

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_menlo() */
#endif /* MENLO_SUPPORT */


static int32_t
emlxs_send_ct(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt;
	IOCBQ		*iocbq;
	IOCB		*iocb;
	NODELIST	*ndlp;
	uint32_t	did;
	CHANNEL		*cp;
	int32_t 	rval;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	ndlp = emlxs_node_find_did(port, did, 1);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
		    "Node not found. did=0x%x", did);

		return (FC_BADPACKET);
	}

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_ct_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	iocbq->node = (void *)ndlp;
	if ((rval = EMLXS_SLI_PREP_CT_IOCB(port, sbp)) != FC_SUCCESS) {

		if (rval == 0xff) {
			emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, 0, 1);
			rval = FC_SUCCESS;
		}

		return (rval);
	}

	cp = &hba->chan[hba->channel_ct];
	cp->ulpSendCmd++;

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = (void *)ndlp;
	sbp->lun = EMLXS_LUN_NONE;
	sbp->class = iocb->ULPCLASS;
	sbp->did = did;
	mutex_exit(&sbp->mtx);

	if (did == NAMESERVER_DID) {
		SLI_CT_REQUEST	*CtCmd;
		uint32_t	*lp0;

		CtCmd = (SLI_CT_REQUEST *)pkt->pkt_cmd;
		lp0 = (uint32_t *)pkt->pkt_cmd;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: did=%x [%08x,%08x]",
		    emlxs_ctcmd_xlate(
		    LE_SWAP16(CtCmd->CommandResponse.bits.CmdRsp)),
		    did, LE_SWAP32(lp0[4]), LE_SWAP32(lp0[5]));

		if (hba->flag & FC_NPIV_DELAY_REQUIRED) {
			sbp->pkt_flags |= PACKET_DELAY_REQUIRED;
		}

	} else if (did == FDMI_DID) {
		SLI_CT_REQUEST	*CtCmd;
		uint32_t	*lp0;

		CtCmd = (SLI_CT_REQUEST *)pkt->pkt_cmd;
		lp0 = (uint32_t *)pkt->pkt_cmd;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: did=%x [%08x,%08x]",
		    emlxs_mscmd_xlate(
		    LE_SWAP16(CtCmd->CommandResponse.bits.CmdRsp)),
		    did, LE_SWAP32(lp0[4]), LE_SWAP32(lp0[5]));
	} else {
		SLI_CT_REQUEST	*CtCmd;
		uint32_t	*lp0;

		CtCmd = (SLI_CT_REQUEST *)pkt->pkt_cmd;
		lp0 = (uint32_t *)pkt->pkt_cmd;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg,
		    "%s: did=%x [%08x,%08x]",
		    emlxs_rmcmd_xlate(
		    LE_SWAP16(CtCmd->CommandResponse.bits.CmdRsp)),
		    did, LE_SWAP32(lp0[4]), LE_SWAP32(lp0[5]));
	}

	if (pkt->pkt_cmdlen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}

	HBASTATS.CtCmdIssued++;

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_ct() */


static int32_t
emlxs_send_ct_rsp(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt;
	CHANNEL		*cp;
	IOCBQ		*iocbq;
	IOCB		*iocb;
	uint32_t	*cmd;
	SLI_CT_REQUEST	*CtCmd;
	int32_t 	rval;

	pkt = PRIV2PKT(sbp);
	CtCmd = (SLI_CT_REQUEST *)pkt->pkt_cmd;
	cmd = (uint32_t *)pkt->pkt_cmd;

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_ct_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	if ((rval = EMLXS_SLI_PREP_CT_IOCB(port, sbp)) != FC_SUCCESS) {

		if (rval == 0xff) {
			emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, 0, 1);
			rval = FC_SUCCESS;
		}

		return (rval);
	}

	cp = &hba->chan[hba->channel_ct];
	cp->ulpSendCmd++;

	/* Initalize sbp */
	mutex_enter(&sbp->mtx);
	sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
	    ((pkt->pkt_timeout > 0xff) ? 0 : 10);
	sbp->node = NULL;
	sbp->lun = EMLXS_LUN_NONE;
	sbp->class = iocb->ULPCLASS;
	mutex_exit(&sbp->mtx);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_reply_msg,
	    "%s: Rsn=%x Exp=%x [%08x,%08x] rxid=%x ",
	    emlxs_rmcmd_xlate(LE_SWAP16(
	    CtCmd->CommandResponse.bits.CmdRsp)),
	    CtCmd->ReasonCode, CtCmd->Explanation,
	    LE_SWAP32(cmd[4]), LE_SWAP32(cmd[5]),
	    pkt->pkt_cmd_fhdr.rx_id);

	if (pkt->pkt_cmdlen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
		    DDI_DMA_SYNC_FORDEV);
	}

	HBASTATS.CtRspIssued++;

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);

	return (FC_SUCCESS);

} /* emlxs_send_ct_rsp() */


/*
 * emlxs_get_instance()
 * Given a ddi ddiinst, return a Fibre Channel (emlx) ddiinst.
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
 * emlxs_add_instance()
 * Given a ddi ddiinst, create a Fibre Channel (emlx) ddiinst.
 * emlx ddiinsts are the order that emlxs_attach gets called, starting at 0.
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
	emlxs_hba_t	*hba;
	emlxs_port_t	*port;
	emlxs_buf_t	*fpkt;

	port = sbp->port;

	if (!port) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_completion_error_msg,
		    "NULL port found. sbp=%p flags=%x", sbp, sbp->pkt_flags);

		return;
	}

	hba = HBA;

	if ((hba->sli_mode == EMLXS_HBA_SLI4_MODE) &&
	    (sbp->iotag)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_debug_msg,
		    "WARNING: Completing IO with iotag. sbp=%p iotag=%d "
		    "xri_flags=%x",
		    sbp, sbp->iotag, ((sbp->xrip)? sbp->xrip->flag:0));

		emlxs_sli4_free_xri(port, sbp, sbp->xrip, 1);
	}

	mutex_enter(&sbp->mtx);

	/* Check for error conditions */
	if (sbp->pkt_flags & (PACKET_ULP_OWNED | PACKET_COMPLETED |
	    PACKET_IN_DONEQ | PACKET_IN_COMPLETION |
	    PACKET_IN_TXQ | PACKET_IN_CHIPQ)) {
		if (sbp->pkt_flags & PACKET_ULP_OWNED) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet already returned. sbp=%p flags=%x", sbp,
			    sbp->pkt_flags);
		}

		else if (sbp->pkt_flags & PACKET_COMPLETED) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet already completed. sbp=%p flags=%x", sbp,
			    sbp->pkt_flags);
		}

		else if (sbp->pkt_flags & PACKET_IN_DONEQ) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Pkt already on done queue. sbp=%p flags=%x", sbp,
			    sbp->pkt_flags);
		}

		else if (sbp->pkt_flags & PACKET_IN_COMPLETION) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet already in completion. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
		}

		else if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet still on chip queue. sbp=%p flags=%x",
			    sbp, sbp->pkt_flags);
		}

		else if (sbp->pkt_flags & PACKET_IN_TXQ) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_pkt_completion_error_msg,
			    "Packet still on tx queue. sbp=%p flags=%x", sbp,
			    sbp->pkt_flags);
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
		 * We will try to NULL sbp->fpkt inside the
		 * fpkt's mutex if possible
		 */

		if (!(fpkt->pkt_flags & PACKET_ULP_OWNED)) {
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
		/* Don't set the PACKET_ULP_OWNED flag here */
		/* because the polling thread will do it */
		sbp->pkt_flags |= PACKET_COMPLETED;
		mutex_exit(&sbp->mtx);

		/* Wake up sleeping thread */
		mutex_enter(&EMLXS_PKT_LOCK);
		cv_broadcast(&EMLXS_PKT_CV);
		mutex_exit(&EMLXS_PKT_LOCK);
	}

	/* If packet was generated by our driver, */
	/* then complete it immediately */
	else if (sbp->pkt_flags & PACKET_ALLOCATED) {
		mutex_exit(&sbp->mtx);

		emlxs_iodone(sbp);
	}

	/* Put the pkt on the done queue for callback */
	/* completion in another thread */
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
		emlxs_thread_trigger1(&hba->iodone_thread,
		    emlxs_iodone_server);
	}

	return;

} /* emlxs_pkt_complete() */


#ifdef SAN_DIAG_SUPPORT
/*
 * This routine is called with EMLXS_PORT_LOCK held so we can just increment
 * normally. Don't have to use atomic operations.
 */
extern void
emlxs_update_sd_bucket(emlxs_buf_t *sbp)
{
	emlxs_port_t	*vport;
	fc_packet_t	*pkt;
	uint32_t	did;
	hrtime_t	t;
	hrtime_t	delta_time;
	int		i;
	NODELIST	*ndlp;

	vport = sbp->port;

	if ((emlxs_sd_bucket.search_type == 0) ||
	    (vport->sd_io_latency_state != SD_COLLECTING)) {
		return;
	}

	/* Compute the iolatency time in microseconds */
	t = gethrtime();
	delta_time = t - sbp->sd_start_time;
	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	ndlp = emlxs_node_find_did(vport, did, 1);

	if (!ndlp) {
		return;
	}

	if (delta_time >=
	    emlxs_sd_bucket.values[SD_IO_LATENCY_MAX_BUCKETS - 1]) {
		ndlp->sd_dev_bucket[SD_IO_LATENCY_MAX_BUCKETS - 1].
		    count++;
	} else if (delta_time <= emlxs_sd_bucket.values[0]) {
		ndlp->sd_dev_bucket[0].count++;
	} else {
		for (i = 1; i < SD_IO_LATENCY_MAX_BUCKETS; i++) {
			if ((delta_time > emlxs_sd_bucket.values[i-1]) &&
			    (delta_time <= emlxs_sd_bucket.values[i])) {
				ndlp->sd_dev_bucket[i].count++;
				break;
			}
		}
	}

	return;

} /* emlxs_update_sd_bucket() */
#endif /* SAN_DIAG_SUPPORT */

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

#ifdef FMA_SUPPORT
	if (hba->flag & FC_DMA_CHECK_ERROR) {
		emlxs_thread_spawn(hba, emlxs_restart_thread,
		    NULL, NULL);
	}
#endif /* FMA_SUPPORT */

	return;

} /* End emlxs_iodone_server */


static void
emlxs_iodone(emlxs_buf_t *sbp)
{
#ifdef FMA_SUPPORT
	emlxs_port_t	*port = sbp->port;
	emlxs_hba_t	*hba = port->hba;
#endif  /* FMA_SUPPORT */

	fc_packet_t	*pkt;
	CHANNEL		*cp;

	pkt = PRIV2PKT(sbp);

	/* Check one more time that the  pkt has not already been returned */
	if (sbp->pkt_flags & PACKET_ULP_OWNED) {
		return;
	}

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_unswap_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

	mutex_enter(&sbp->mtx);
	sbp->pkt_flags |= (PACKET_COMPLETED | PACKET_ULP_OWNED);
	mutex_exit(&sbp->mtx);

	if (pkt->pkt_comp) {
#ifdef FMA_SUPPORT
		emlxs_check_dma(hba, sbp);
#endif  /* FMA_SUPPORT */

		if (sbp->channel) {
			cp = (CHANNEL *)sbp->channel;
			cp->ulpCmplCmd++;
		}

		(*pkt->pkt_comp) (pkt);
	}

	return;

} /* emlxs_iodone() */



extern fc_unsol_buf_t *
emlxs_ub_find(emlxs_port_t *port, uint32_t token)
{
	emlxs_unsol_buf_t	*pool;
	fc_unsol_buf_t		*ubp;
	emlxs_ub_priv_t		*ub_priv;

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
			ubp = (fc_unsol_buf_t *)&pool->fc_ubufs[(token -
			    pool->pool_first_token)];
			ub_priv = ubp->ub_fca_private;

			if (ub_priv->token != token) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "ub_find: Invalid token=%x", ubp, token,
				    ub_priv->token);

				ubp = NULL;
			}

			else if (!(ub_priv->flags & EMLXS_UB_IN_USE)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sfs_debug_msg,
				    "ub_find: Buffer not in use. buffer=%p "
				    "token=%x", ubp, token);

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
emlxs_ub_get(emlxs_port_t *port, uint32_t size, uint32_t type,
    uint32_t reserve)
{
	emlxs_hba_t		*hba = HBA;
	emlxs_unsol_buf_t	*pool;
	fc_unsol_buf_t		*ubp;
	emlxs_ub_priv_t		*ub_priv;
	uint32_t		i;
	uint32_t		resv_flag;
	uint32_t		pool_free;
	uint32_t		pool_free_resv;

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
		pool_free =
		    min(pool->pool_free,
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

			/* Timeout in 5 minutes */
			ub_priv->timeout = (5 * 60);

			ub_priv->flags = EMLXS_UB_IN_USE;

			/* Alloc the buffer from the pool */
			if (resv_flag) {
				ub_priv->flags |= EMLXS_UB_RESV;
				pool->pool_free_resv--;
			} else {
				pool->pool_free--;
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_detail_msg,
			    "ub_get: ubp=%p token=%x (%d,%d,%d,%d)", ubp,
			    ub_priv->token, pool->pool_nentries,
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
	fc_packet_t		*pkt;
	fcp_rsp_t		*fcp_rsp;
	uint32_t		i;
	emlxs_xlat_err_t	*tptr;
	emlxs_xlat_err_t	*entry;


	pkt = PRIV2PKT(sbp);

	/* Warning: Some FCT sbp's don't have */
	/* fc_packet objects, so just return  */
	if (!pkt) {
		return;
	}

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
			pkt->pkt_state  = entry->pkt_state;
			pkt->pkt_reason = entry->pkt_reason;
			pkt->pkt_expln  = entry->pkt_expln;
			pkt->pkt_action = entry->pkt_action;
		} else {
			/* Set defaults */
			pkt->pkt_state  = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = FC_REASON_ABORTED;
			pkt->pkt_expln  = FC_EXPLN_NONE;
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
				    FC_TYPE_SCSI_FCP) && pkt->pkt_rsplen &&
				    pkt->pkt_resp) {
					fcp_rsp = (fcp_rsp_t *)pkt->pkt_resp;

					fcp_rsp->fcp_u.fcp_status.
					    rsp_len_set = 1;
					fcp_rsp->fcp_response_len = 8;
				}
			} else {
				/* Otherwise assume no data */
				/* and no response received */
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
	uint16_t	*p;
	int		size;
	int		i;

	size = (sizeof (CSP) - 4) / 2;
	p = (uint16_t *)&sp->cmn;
	for (i = 0; i < size; i++) {
		p[i] = LE_SWAP16(p[i]);
	}
	sp->cmn.e_d_tov = LE_SWAP32(sp->cmn.e_d_tov);

	size = sizeof (CLASS_PARMS) / 2;
	p = (uint16_t *)&sp->cls1;
	for (i = 0; i < size; i++, p++) {
		*p = LE_SWAP16(*p);
	}

	size = sizeof (CLASS_PARMS) / 2;
	p = (uint16_t *)&sp->cls2;
	for (i = 0; i < size; i++, p++) {
		*p = LE_SWAP16(*p);
	}

	size = sizeof (CLASS_PARMS) / 2;
	p = (uint16_t *)&sp->cls3;
	for (i = 0; i < size; i++, p++) {
		*p = LE_SWAP16(*p);
	}

	size = sizeof (CLASS_PARMS) / 2;
	p = (uint16_t *)&sp->cls4;
	for (i = 0; i < size; i++, p++) {
		*p = LE_SWAP16(*p);
	}

	return;

} /* emlxs_swap_service_params() */

extern void
emlxs_unswap_pkt(emlxs_buf_t *sbp)
{
	if (sbp->pkt_flags & PACKET_FCP_SWAPPED) {
		emlxs_swap_fcp_pkt(sbp);
	}

	else if (sbp->pkt_flags & PACKET_ELS_SWAPPED) {
		emlxs_swap_els_pkt(sbp);
	}

	else if (sbp->pkt_flags & PACKET_CT_SWAPPED) {
		emlxs_swap_ct_pkt(sbp);
	}

} /* emlxs_unswap_pkt() */


extern void
emlxs_swap_fcp_pkt(emlxs_buf_t *sbp)
{
	fc_packet_t	*pkt;
	FCP_CMND	*cmd;
	fcp_rsp_t	*rsp;
	uint16_t	*lunp;
	uint32_t	i;

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

	cmd = (FCP_CMND *)pkt->pkt_cmd;
	rsp = (pkt->pkt_rsplen &&
	    (sbp->pkt_flags & PACKET_FCP_RSP_VALID)) ?
	    (fcp_rsp_t *)pkt->pkt_resp : NULL;

	/* The size of data buffer needs to be swapped. */
	cmd->fcpDl = LE_SWAP32(cmd->fcpDl);

	/*
	 * Swap first 2 words of FCP CMND payload.
	 */
	lunp = (uint16_t *)&cmd->fcpLunMsl;
	for (i = 0; i < 4; i++) {
		lunp[i] = LE_SWAP16(lunp[i]);
	}

	if (rsp) {
		rsp->fcp_resid = LE_SWAP32(rsp->fcp_resid);
		rsp->fcp_sense_len = LE_SWAP32(rsp->fcp_sense_len);
		rsp->fcp_response_len = LE_SWAP32(rsp->fcp_response_len);
	}

	return;

} /* emlxs_swap_fcp_pkt() */


extern void
emlxs_swap_els_pkt(emlxs_buf_t *sbp)
{
	fc_packet_t	*pkt;
	uint32_t	*cmd;
	uint32_t	*rsp;
	uint32_t	command;
	uint16_t	*c;
	uint32_t	i;
	uint32_t	swapped;

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
	rsp = (pkt->pkt_rsplen &&
	    (sbp->pkt_flags & PACKET_ELS_RSP_VALID)) ?
	    (uint32_t *)pkt->pkt_resp : NULL;

	if (!swapped) {
		cmd[0] = LE_SWAP32(cmd[0]);
		command = cmd[0] & ELS_CMD_MASK;
	} else {
		command = cmd[0] & ELS_CMD_MASK;
		cmd[0] = LE_SWAP32(cmd[0]);
	}

	if (rsp) {
		rsp[0] = LE_SWAP32(rsp[0]);
	}

	switch (command) {
	case ELS_CMD_ACC:
		if (sbp->ucmd == ELS_CMD_ADISC) {
			/* Hard address of originator */
			cmd[1] = LE_SWAP32(cmd[1]);

			/* N_Port ID of originator */
			cmd[6] = LE_SWAP32(cmd[6]);
		}
		break;

	case ELS_CMD_PLOGI:
	case ELS_CMD_FLOGI:
	case ELS_CMD_FDISC:
		if (rsp) {
			emlxs_swap_service_params((SERV_PARM *) & rsp[1]);
		}
		break;

	case ELS_CMD_LOGO:
		cmd[1] = LE_SWAP32(cmd[1]);	/* N_Port ID */
		break;

	case ELS_CMD_RLS:
		cmd[1] = LE_SWAP32(cmd[1]);

		if (rsp) {
			for (i = 0; i < 6; i++) {
				rsp[1 + i] = LE_SWAP32(rsp[1 + i]);
			}
		}
		break;

	case ELS_CMD_ADISC:
		cmd[1] = LE_SWAP32(cmd[1]);	/* Hard address of originator */
		cmd[6] = LE_SWAP32(cmd[6]);	/* N_Port ID of originator */
		break;

	case ELS_CMD_PRLI:
		c = (uint16_t *)&cmd[1];
		c[1] = LE_SWAP16(c[1]);

		cmd[4] = LE_SWAP32(cmd[4]);

		if (rsp) {
			rsp[4] = LE_SWAP32(rsp[4]);
		}
		break;

	case ELS_CMD_SCR:
		cmd[1] = LE_SWAP32(cmd[1]);
		break;

	case ELS_CMD_LINIT:
		if (rsp) {
			rsp[1] = LE_SWAP32(rsp[1]);
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
	fc_packet_t	*pkt;
	uint32_t	*cmd;
	uint32_t	*rsp;
	uint32_t	command;
	uint32_t	i;
	uint32_t	swapped;

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
	rsp = (pkt->pkt_rsplen &&
	    (sbp->pkt_flags & PACKET_CT_RSP_VALID)) ?
	    (uint32_t *)pkt->pkt_resp : NULL;

	if (!swapped) {
		cmd[0] = 0x01000000;
		command = cmd[2];
	}

	cmd[0] = LE_SWAP32(cmd[0]);
	cmd[1] = LE_SWAP32(cmd[1]);
	cmd[2] = LE_SWAP32(cmd[2]);
	cmd[3] = LE_SWAP32(cmd[3]);

	if (swapped) {
		command = cmd[2];
	}

	switch ((command >> 16)) {
	case SLI_CTNS_GA_NXT:
		cmd[4] = LE_SWAP32(cmd[4]);
		break;

	case SLI_CTNS_GPN_ID:
	case SLI_CTNS_GNN_ID:
	case SLI_CTNS_RPN_ID:
	case SLI_CTNS_RNN_ID:
	case SLI_CTNS_RSPN_ID:
		cmd[4] = LE_SWAP32(cmd[4]);
		break;

	case SLI_CTNS_RCS_ID:
	case SLI_CTNS_RPT_ID:
		cmd[4] = LE_SWAP32(cmd[4]);
		cmd[5] = LE_SWAP32(cmd[5]);
		break;

	case SLI_CTNS_RFT_ID:
		cmd[4] = LE_SWAP32(cmd[4]);

		/* Swap FC4 types */
		for (i = 0; i < 8; i++) {
			cmd[5 + i] = LE_SWAP32(cmd[5 + i]);
		}
		break;

	case SLI_CTNS_GFT_ID:
		if (rsp) {
			/* Swap FC4 types */
			for (i = 0; i < 8; i++) {
				rsp[4 + i] = LE_SWAP32(rsp[4 + i]);
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
	emlxs_ub_priv_t	*ub_priv;
	fc_rscn_t	*rscn;
	uint32_t	count;
	uint32_t	i;
	uint32_t	*lp;
	la_els_logi_t	*logi;

	ub_priv = ubp->ub_fca_private;

	switch (ub_priv->cmd) {
	case ELS_CMD_RSCN:
		rscn = (fc_rscn_t *)ubp->ub_buffer;

		rscn->rscn_payload_len = LE_SWAP16(rscn->rscn_payload_len);

		count = ((rscn->rscn_payload_len - 4) / 4);
		lp = (uint32_t *)ubp->ub_buffer + 1;
		for (i = 0; i < count; i++, lp++) {
			*lp = LE_SWAP32(*lp);
		}

		break;

	case ELS_CMD_FLOGI:
	case ELS_CMD_PLOGI:
	case ELS_CMD_FDISC:
	case ELS_CMD_PDISC:
		logi = (la_els_logi_t *)ubp->ub_buffer;
		emlxs_swap_service_params(
		    (SERV_PARM *)&logi->common_service);
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
emlxs_mode_xlate(uint32_t mode)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_mode_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (mode == emlxs_mode_table[i].code) {
			return (emlxs_mode_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "Unknown (%x)", mode);
	return (buffer);

} /* emlxs_mode_xlate() */


extern char *
emlxs_elscmd_xlate(uint32_t elscmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_elscmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (elscmd == emlxs_elscmd_table[i].code) {
			return (emlxs_elscmd_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "ELS=0x%x", elscmd);
	return (buffer);

} /* emlxs_elscmd_xlate() */


extern char *
emlxs_ctcmd_xlate(uint32_t ctcmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_ctcmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (ctcmd == emlxs_ctcmd_table[i].code) {
			return (emlxs_ctcmd_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "cmd=0x%x", ctcmd);
	return (buffer);

} /* emlxs_ctcmd_xlate() */


#ifdef MENLO_SUPPORT
extern char *
emlxs_menlo_cmd_xlate(uint32_t cmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_menlo_cmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (cmd == emlxs_menlo_cmd_table[i].code) {
			return (emlxs_menlo_cmd_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "Cmd=0x%x", cmd);
	return (buffer);

} /* emlxs_menlo_cmd_xlate() */

extern char *
emlxs_menlo_rsp_xlate(uint32_t rsp)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_menlo_rsp_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (rsp == emlxs_menlo_rsp_table[i].code) {
			return (emlxs_menlo_rsp_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "Rsp=0x%x", rsp);
	return (buffer);

} /* emlxs_menlo_rsp_xlate() */

#endif /* MENLO_SUPPORT */


extern char *
emlxs_rmcmd_xlate(uint32_t rmcmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_rmcmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (rmcmd == emlxs_rmcmd_table[i].code) {
			return (emlxs_rmcmd_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "RM=0x%x", rmcmd);
	return (buffer);

} /* emlxs_rmcmd_xlate() */



extern char *
emlxs_mscmd_xlate(uint16_t mscmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_mscmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (mscmd == emlxs_mscmd_table[i].code) {
			return (emlxs_mscmd_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "Cmd=0x%x", mscmd);
	return (buffer);

} /* emlxs_mscmd_xlate() */


extern char *
emlxs_state_xlate(uint8_t state)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_state_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_state_table[i].code) {
			return (emlxs_state_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "State=0x%x", state);
	return (buffer);

} /* emlxs_state_xlate() */


extern char *
emlxs_error_xlate(uint8_t errno)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_error_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (errno == emlxs_error_table[i].code) {
			return (emlxs_error_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "Errno=0x%x", errno);
	return (buffer);

} /* emlxs_error_xlate() */


static int
emlxs_pm_lower_power(dev_info_t *dip)
{
	int		ddiinst;
	int		emlxinst;
	emlxs_config_t	*cfg;
	int32_t		rval;
	emlxs_hba_t	*hba;

	ddiinst = ddi_get_instance(dip);
	emlxinst = emlxs_get_instance(ddiinst);
	hba = emlxs_device.hba[emlxinst];
	cfg = &CFG;

	rval = DDI_SUCCESS;

	/* Lower the power level */
	if (cfg[CFG_PM_SUPPORT].current) {
		rval =
		    pm_lower_power(dip, EMLXS_PM_ADAPTER,
		    EMLXS_PM_ADAPTER_DOWN);
	} else {
		/* We do not have kernel support of power management enabled */
		/* therefore, call our power management routine directly */
		rval =
		    emlxs_power(dip, EMLXS_PM_ADAPTER, EMLXS_PM_ADAPTER_DOWN);
	}

	return (rval);

} /* emlxs_pm_lower_power() */


static int
emlxs_pm_raise_power(dev_info_t *dip)
{
	int		ddiinst;
	int		emlxinst;
	emlxs_config_t	*cfg;
	int32_t		rval;
	emlxs_hba_t	*hba;

	ddiinst = ddi_get_instance(dip);
	emlxinst = emlxs_get_instance(ddiinst);
	hba = emlxs_device.hba[emlxinst];
	cfg = &CFG;

	/* Raise the power level */
	if (cfg[CFG_PM_SUPPORT].current) {
		rval =
		    pm_raise_power(dip, EMLXS_PM_ADAPTER,
		    EMLXS_PM_ADAPTER_UP);
	} else {
		/* We do not have kernel support of power management enabled */
		/* therefore, call our power management routine directly */
		rval =
		    emlxs_power(dip, EMLXS_PM_ADAPTER, EMLXS_PM_ADAPTER_UP);
	}

	return (rval);

} /* emlxs_pm_raise_power() */


#ifdef IDLE_TIMER

extern int
emlxs_pm_busy_component(emlxs_hba_t *hba)
{
	emlxs_config_t	*cfg = &CFG;
	int		rval;

	hba->pm_active = 1;

	if (hba->pm_busy) {
		return (DDI_SUCCESS);
	}

	mutex_enter(&EMLXS_PM_LOCK);

	if (hba->pm_busy) {
		mutex_exit(&EMLXS_PM_LOCK);
		return (DDI_SUCCESS);
	}
	hba->pm_busy = 1;

	mutex_exit(&EMLXS_PM_LOCK);

	/* Attempt to notify system that we are busy */
	if (cfg[CFG_PM_SUPPORT].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "pm_busy_component.");

		rval = pm_busy_component(dip, EMLXS_PM_ADAPTER);

		if (rval != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "pm_busy_component failed. ret=%d", rval);

			/* If this attempt failed then clear our flags */
			mutex_enter(&EMLXS_PM_LOCK);
			hba->pm_busy = 0;
			mutex_exit(&EMLXS_PM_LOCK);

			return (rval);
		}
	}

	return (DDI_SUCCESS);

} /* emlxs_pm_busy_component() */


extern int
emlxs_pm_idle_component(emlxs_hba_t *hba)
{
	emlxs_config_t	*cfg = &CFG;
	int		rval;

	if (!hba->pm_busy) {
		return (DDI_SUCCESS);
	}

	mutex_enter(&EMLXS_PM_LOCK);

	if (!hba->pm_busy) {
		mutex_exit(&EMLXS_PM_LOCK);
		return (DDI_SUCCESS);
	}
	hba->pm_busy = 0;

	mutex_exit(&EMLXS_PM_LOCK);

	if (cfg[CFG_PM_SUPPORT].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "pm_idle_component.");

		rval = pm_idle_component(dip, EMLXS_PM_ADAPTER);

		if (rval != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
			    "pm_idle_component failed. ret=%d", rval);

			/* If this attempt failed then */
			/* reset our flags for another attempt */
			mutex_enter(&EMLXS_PM_LOCK);
			hba->pm_busy = 1;
			mutex_exit(&EMLXS_PM_LOCK);

			return (rval);
		}
	}

	return (DDI_SUCCESS);

} /* emlxs_pm_idle_component() */


extern void
emlxs_pm_idle_timer(emlxs_hba_t *hba)
{
	emlxs_config_t *cfg = &CFG;

	if (hba->pm_active) {
		/* Clear active flag and reset idle timer */
		mutex_enter(&EMLXS_PM_LOCK);
		hba->pm_active = 0;
		hba->pm_idle_timer =
		    hba->timer_tics + cfg[CFG_PM_IDLE].current;
		mutex_exit(&EMLXS_PM_LOCK);
	}

	/* Check for idle timeout */
	else if (hba->timer_tics >= hba->pm_idle_timer) {
		if (emlxs_pm_idle_component(hba) == DDI_SUCCESS) {
			mutex_enter(&EMLXS_PM_LOCK);
			hba->pm_idle_timer =
			    hba->timer_tics + cfg[CFG_PM_IDLE].current;
			mutex_exit(&EMLXS_PM_LOCK);
		}
	}

	return;

} /* emlxs_pm_idle_timer() */

#endif	/* IDLE_TIMER */


#if (EMLXS_MODREV >= EMLXS_MODREV3) && (EMLXS_MODREV <= EMLXS_MODREV4)
static void
emlxs_read_vport_prop(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_config_t	*cfg = &CFG;
	char		**arrayp;
	uint8_t		*s;
	uint8_t		*np;
	NAME_TYPE	pwwpn;
	NAME_TYPE	wwnn;
	NAME_TYPE	wwpn;
	uint32_t	vpi;
	uint32_t	cnt;
	uint32_t	rval;
	uint32_t	i;
	uint32_t	j;
	uint32_t	c1;
	uint32_t	sum;
	uint32_t	errors;
	char		buffer[64];

	/* Check for the per adapter vport setting */
	(void) snprintf(buffer, sizeof (buffer), "%s%d-vport", DRIVER_NAME,
	    hba->ddiinst);
	cnt = 0;
	arrayp = NULL;
	rval =
	    ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
	    (DDI_PROP_DONTPASS), buffer, &arrayp, &cnt);

	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		/* Check for the global vport setting */
		cnt = 0;
		arrayp = NULL;
		rval =
		    ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
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
				    "entry=%d byte=%d hi_nibble=%c",
				    i, j, c1);
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
				    "entry=%d byte=%d lo_nibble=%c",
				    i, j, c1);
				errors++;
			}

			*np++ = (uint8_t)sum;
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
				    "entry=%d byte=%d hi_nibble=%c",
				    i, j, c1);
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
				    "entry=%d byte=%d lo_nibble=%c",
				    i, j, c1);
				errors++;
			}

			*np++ = (uint8_t)sum;
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
				    "entry=%d byte=%d hi_nibble=%c",
				    i, j, c1);

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
				    "entry=%d byte=%d lo_nibble=%c",
				    i, j, c1);

				errors++;
			}

			*np++ = (uint8_t)sum;
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

		/* Check if the physical port wwpn */
		/* matches our physical port wwpn */
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
		if (vpi > hba->vpi_high) {
			hba->vpi_high = vpi;
		}

		bcopy((caddr_t)&wwnn, (caddr_t)&hba->port[vpi].wwnn,
		    sizeof (NAME_TYPE));
		bcopy((caddr_t)&wwpn, (caddr_t)&hba->port[vpi].wwpn,
		    sizeof (NAME_TYPE));

		if (hba->port[vpi].snn[0] == 0) {
			(void) strncpy((caddr_t)hba->port[vpi].snn,
			    (caddr_t)hba->snn,
			    (sizeof (hba->port[vpi].snn)-1));
		}

		if (hba->port[vpi].spn[0] == 0) {
			(void) snprintf((caddr_t)hba->port[vpi].spn,
			    sizeof (hba->port[vpi].spn),
			    "%s VPort-%d",
			    (caddr_t)hba->spn, vpi);
		}

		hba->port[vpi].flag |=
		    (EMLXS_PORT_CONFIG | EMLXS_PORT_ENABLED);

		if (cfg[CFG_VPORT_RESTRICTED].current) {
			hba->port[vpi].flag |= EMLXS_PORT_RESTRICTED;
		}
	}

out:

	(void) ddi_prop_free((void *) arrayp);
	return;

} /* emlxs_read_vport_prop() */
#endif	/* EMLXS_MODREV3 || EMLXS_MODREV4 */


extern char *
emlxs_wwn_xlate(char *buffer, size_t len, uint8_t *wwn)
{
	(void) snprintf(buffer, len, "%02x%02x%02x%02x%02x%02x%02x%02x",
	    wwn[0] & 0xff, wwn[1] & 0xff, wwn[2] & 0xff, wwn[3] & 0xff,
	    wwn[4] & 0xff, wwn[5] & 0xff, wwn[6] & 0xff, wwn[7] & 0xff);

	return (buffer);

} /* emlxs_wwn_xlate() */


extern int32_t
emlxs_wwn_cmp(uint8_t *wwn1, uint8_t *wwn2)
{
	uint32_t i;

	for (i = 0; i < 8; i ++, wwn1 ++, wwn2 ++) {
		if (*wwn1 > *wwn2) {
			return (1);
		}
		if (*wwn1 < *wwn2) {
			return (-1);
		}
	}

	return (0);

} /* emlxs_wwn_cmp() */


/* This is called at port online and offline */
extern void
emlxs_ub_flush(emlxs_port_t *port)
{
	emlxs_hba_t	*hba = HBA;
	fc_unsol_buf_t	*ubp;
	emlxs_ub_priv_t	*ub_priv;
	emlxs_ub_priv_t	*next;

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
		if (port->ulp_statec != FC_STATE_OFFLINE) {
			/* Send ULP the ub buffer */
			emlxs_ulp_unsol_cb(port, ubp);
		} else {	/* Drop the buffer */
			(void) emlxs_fca_ub_release(port, 1, &ubp->ub_token);
		}

		ub_priv = next;

	}	/* while () */

	return;

} /* emlxs_ub_flush() */


extern void
emlxs_ub_callback(emlxs_port_t *port, fc_unsol_buf_t *ubp)
{
	emlxs_hba_t	*hba = HBA;
	emlxs_ub_priv_t	*ub_priv;

	ub_priv = ubp->ub_fca_private;

	/* Check if ULP is online */
	if (port->ulp_statec != FC_STATE_OFFLINE) {
		emlxs_ulp_unsol_cb(port, ubp);

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
			(void) emlxs_fca_ub_release(port, 1, &ubp->ub_token);
		}
	}

	return;

} /* emlxs_ub_callback() */


extern void
emlxs_fca_link_up(emlxs_port_t *port)
{
	emlxs_ulp_statec_cb(port, port->ulp_statec);
	return;

} /* emlxs_fca_link_up() */


extern void
emlxs_fca_link_down(emlxs_port_t *port)
{
	emlxs_ulp_statec_cb(port, FC_STATE_OFFLINE);
	return;

} /* emlxs_fca_link_down() */


static uint32_t
emlxs_integrity_check(emlxs_hba_t *hba)
{
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
	size = SLI3_IOCB_CMD_SIZE;
	if (sizeof (IOCB) != size) {
		cmn_err(CE_WARN, "?%s%d: IOCB size incorrect.  %d != %d",
		    DRIVER_NAME, ddiinst, (int)sizeof (IOCB),
		    SLI3_IOCB_CMD_SIZE);

		errors++;
	}

	size = SLI_SLIM2_SIZE;
	if (sizeof (SLIM2) != size) {
		cmn_err(CE_WARN, "?%s%d: SLIM2 size incorrect.  %d != %d",
		    DRIVER_NAME, ddiinst, (int)sizeof (SLIM2),
		    SLI_SLIM2_SIZE);

		errors++;
	}
	return (errors);

} /* emlxs_integrity_check() */


#ifdef FMA_SUPPORT
/*
 * FMA support
 */

extern void
emlxs_fm_init(emlxs_hba_t *hba)
{
	ddi_iblock_cookie_t iblk;

	if (hba->fm_caps == DDI_FM_NOT_CAPABLE) {
		return;
	}

	if (DDI_FM_ACC_ERR_CAP(hba->fm_caps)) {
		emlxs_dev_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
		emlxs_data_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	}

	if (DDI_FM_DMA_ERR_CAP(hba->fm_caps)) {
		hba->dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		hba->dma_attr_ro.dma_attr_flags |= DDI_DMA_FLAGERR;
		hba->dma_attr_1sg.dma_attr_flags |= DDI_DMA_FLAGERR;
		hba->dma_attr_fcip_rsp.dma_attr_flags |= DDI_DMA_FLAGERR;
	} else {
		hba->dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		hba->dma_attr_ro.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		hba->dma_attr_1sg.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		hba->dma_attr_fcip_rsp.dma_attr_flags &= ~DDI_DMA_FLAGERR;
	}

	ddi_fm_init(hba->dip, &hba->fm_caps, &iblk);

	if (DDI_FM_EREPORT_CAP(hba->fm_caps) ||
	    DDI_FM_ERRCB_CAP(hba->fm_caps)) {
		pci_ereport_setup(hba->dip);
	}

	if (DDI_FM_ERRCB_CAP(hba->fm_caps)) {
		ddi_fm_handler_register(hba->dip, emlxs_fm_error_cb,
		    (void *)hba);
	}

} /* emlxs_fm_init() */


extern void
emlxs_fm_fini(emlxs_hba_t *hba)
{
	if (hba->fm_caps == DDI_FM_NOT_CAPABLE) {
		return;
	}

	if (DDI_FM_EREPORT_CAP(hba->fm_caps) ||
	    DDI_FM_ERRCB_CAP(hba->fm_caps)) {
		pci_ereport_teardown(hba->dip);
	}

	if (DDI_FM_ERRCB_CAP(hba->fm_caps)) {
		ddi_fm_handler_unregister(hba->dip);
	}

	(void) ddi_fm_fini(hba->dip);

} /* emlxs_fm_fini() */


extern int
emlxs_fm_check_acc_handle(emlxs_hba_t *hba, ddi_acc_handle_t handle)
{
	ddi_fm_error_t err;

	if (!DDI_FM_ACC_ERR_CAP(hba->fm_caps)) {
		return (DDI_FM_OK);
	}

	/* Some S10 versions do not define the ahi_err structure */
	if (((ddi_acc_impl_t *)handle)->ahi_err == NULL) {
		return (DDI_FM_OK);
	}

	err.fme_status = DDI_FM_OK;
	(void) ddi_fm_acc_err_get(handle, &err, DDI_FME_VERSION);

	/* Some S10 versions do not define the ddi_fm_acc_err_clear function */
	if ((void *)&ddi_fm_acc_err_clear != NULL) {
		(void) ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	}

	return (err.fme_status);

} /* emlxs_fm_check_acc_handle() */


extern int
emlxs_fm_check_dma_handle(emlxs_hba_t *hba, ddi_dma_handle_t handle)
{
	ddi_fm_error_t err;

	if (!DDI_FM_ACC_ERR_CAP(hba->fm_caps)) {
		return (DDI_FM_OK);
	}

	err.fme_status = DDI_FM_OK;
	(void) ddi_fm_dma_err_get(handle, &err, DDI_FME_VERSION);

	return (err.fme_status);

} /* emlxs_fm_check_dma_handle() */


extern void
emlxs_fm_ereport(emlxs_hba_t *hba, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	if (!DDI_FM_EREPORT_CAP(hba->fm_caps)) {
		return;
	}

	if (detail == NULL) {
		return;
	}

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);

	ddi_fm_ereport_post(hba->dip, buf, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);

} /* emlxs_fm_ereport() */


extern void
emlxs_fm_service_impact(emlxs_hba_t *hba, int impact)
{
	if (!DDI_FM_EREPORT_CAP(hba->fm_caps)) {
		return;
	}

	if (impact == NULL) {
		return;
	}

	if ((hba->pm_state & EMLXS_PM_IN_DETACH) &&
	    (impact == DDI_SERVICE_DEGRADED)) {
		impact = DDI_SERVICE_UNAFFECTED;
	}

	ddi_fm_service_impact(hba->dip, impact);

	return;

} /* emlxs_fm_service_impact() */


/*
 * The I/O fault service error handling callback function
 */
/*ARGSUSED*/
extern int
emlxs_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err,
    const void *impl_data)
{
	/*
	 * as the driver can always deal with an error
	 * in any dma or access handle, we can just return
	 * the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);

} /* emlxs_fm_error_cb() */

extern void
emlxs_check_dma(emlxs_hba_t *hba, emlxs_buf_t *sbp)
{
	emlxs_port_t	*port = sbp->port;
	fc_packet_t	*pkt = PRIV2PKT(sbp);

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		if (emlxs_fm_check_dma_handle(hba,
		    hba->sli.sli4.slim2.dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "slim2: hdl=%p",
			    hba->sli.sli4.slim2.dma_handle);

			mutex_enter(&EMLXS_PORT_LOCK);
			hba->flag |= FC_DMA_CHECK_ERROR;
			mutex_exit(&EMLXS_PORT_LOCK);
		}
	} else {
		if (emlxs_fm_check_dma_handle(hba,
		    hba->sli.sli3.slim2.dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "slim2: hdl=%p",
			    hba->sli.sli3.slim2.dma_handle);

			mutex_enter(&EMLXS_PORT_LOCK);
			hba->flag |= FC_DMA_CHECK_ERROR;
			mutex_exit(&EMLXS_PORT_LOCK);
		}
	}

	if (hba->flag & FC_DMA_CHECK_ERROR) {
		pkt->pkt_state  = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_DMA_ERROR;
		pkt->pkt_expln  = FC_EXPLN_NONE;
		pkt->pkt_action = FC_ACTION_RETRYABLE;
		return;
	}

	if (pkt->pkt_cmdlen) {
		if (emlxs_fm_check_dma_handle(hba, pkt->pkt_cmd_dma)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "pkt_cmd_dma: hdl=%p",
			    pkt->pkt_cmd_dma);

			pkt->pkt_state  = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = FC_REASON_DMA_ERROR;
			pkt->pkt_expln  = FC_EXPLN_NONE;
			pkt->pkt_action = FC_ACTION_RETRYABLE;

			return;
		}
	}

	if (pkt->pkt_rsplen) {
		if (emlxs_fm_check_dma_handle(hba, pkt->pkt_resp_dma)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "pkt_resp_dma: hdl=%p",
			    pkt->pkt_resp_dma);

			pkt->pkt_state  = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = FC_REASON_DMA_ERROR;
			pkt->pkt_expln  = FC_EXPLN_NONE;
			pkt->pkt_action = FC_ACTION_RETRYABLE;

			return;
		}
	}

	if (pkt->pkt_datalen) {
		if (emlxs_fm_check_dma_handle(hba, pkt->pkt_data_dma)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "pkt_data_dma: hdl=%p",
			    pkt->pkt_data_dma);

			pkt->pkt_state  = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = FC_REASON_DMA_ERROR;
			pkt->pkt_expln  = FC_EXPLN_NONE;
			pkt->pkt_action = FC_ACTION_RETRYABLE;

			return;
		}
	}

	return;

}
#endif	/* FMA_SUPPORT */


extern void
emlxs_swap32_buffer(uint8_t *buffer, uint32_t size)
{
	uint32_t word;
	uint32_t *wptr;
	uint32_t i;

	VERIFY((size % 4) == 0);

	wptr = (uint32_t *)buffer;

	for (i = 0; i < size / 4; i++) {
		word = *wptr;
		*wptr++ = SWAP32(word);
	}

	return;

}  /* emlxs_swap32_buffer() */


extern void
emlxs_swap32_bcopy(uint8_t *src, uint8_t *dst, uint32_t size)
{
	uint32_t word;
	uint32_t *sptr;
	uint32_t *dptr;
	uint32_t i;

	VERIFY((size % 4) == 0);

	sptr = (uint32_t *)src;
	dptr = (uint32_t *)dst;

	for (i = 0; i < size / 4; i++) {
		word = *sptr++;
		*dptr++ = SWAP32(word);
	}

	return;

}  /* emlxs_swap32_buffer() */


extern char *
emlxs_strtoupper(char *str)
{
	char *cptr = str;

	while (*cptr) {
		if ((*cptr >= 'a') && (*cptr <= 'z')) {
			*cptr -= ('a' - 'A');
		}
		cptr++;
	}

	return (str);

} /* emlxs_strtoupper() */


extern void
emlxs_ulp_statec_cb(emlxs_port_t *port, uint32_t statec)
{
	emlxs_hba_t *hba = HBA;

	/* This routine coordinates protection with emlxs_fca_unbind_port() */

	mutex_enter(&EMLXS_PORT_LOCK);
	if (!(port->flag & EMLXS_INI_BOUND)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	port->ulp_busy++;
	mutex_exit(&EMLXS_PORT_LOCK);

	port->ulp_statec_cb(port->ulp_handle, statec);

	mutex_enter(&EMLXS_PORT_LOCK);
	port->ulp_busy--;
	mutex_exit(&EMLXS_PORT_LOCK);

	return;

}  /* emlxs_ulp_statec_cb() */


extern void
emlxs_ulp_unsol_cb(emlxs_port_t *port, fc_unsol_buf_t *ubp)
{
	emlxs_hba_t *hba = HBA;

	/* This routine coordinates protection with emlxs_fca_unbind_port() */

	mutex_enter(&EMLXS_PORT_LOCK);
	if (!(port->flag & EMLXS_INI_BOUND)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	port->ulp_busy++;
	mutex_exit(&EMLXS_PORT_LOCK);

	port->ulp_unsol_cb(port->ulp_handle, ubp, ubp->ub_frame.type);

	mutex_enter(&EMLXS_PORT_LOCK);
	port->ulp_busy--;
	mutex_exit(&EMLXS_PORT_LOCK);

	return;

}  /* emlxs_ulp_unsol_cb() */
