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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2016 Joyent, Inc.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */


/*
 * scsa2usb bridge nexus driver:
 *
 * This driver supports the following wire transports:
 * a. Bulk Only transport (see usb_ms_bulkonly.c)
 * b. CB transport (see usb_ms_cbi.c)
 * c. CBI transport with interrupt status completion (see usb_ms_cbi.c)
 *
 * It handles the following command sets:
 * a. SCSI
 * b. ATAPI command set (subset of SCSI command set)
 * c. UFI command set (
 *	http://www.usb.org/developers/devclass_docs/usbmass-ufi10.pdf)
 *
 * For details on USB Mass Storage Class overview:
 *	http://www.usb.org/developers/devclass_docs/usbmassover_11.pdf
 */
#if defined(lint) && !defined(DEBUG)
#define	DEBUG	1
#endif

#include <sys/usb/usba/usbai_version.h>
#include <sys/scsi/scsi.h>
#include <sys/cdio.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/callb.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>

#include <sys/usb/usba.h>
#include <sys/usb/clients/ugen/usb_ugen.h>
#include <sys/usb/usba/usba_ugen.h>

#include <sys/usb/usba/usba_private.h>
#include <sys/usb/usba/usba_ugend.h>
#include <sys/usb/clients/mass_storage/usb_bulkonly.h>
#include <sys/usb/scsa2usb/scsa2usb.h>

/*
 * Function Prototypes
 */
static int	scsa2usb_attach(dev_info_t *, ddi_attach_cmd_t);
static int	scsa2usb_info(dev_info_t *, ddi_info_cmd_t, void *,
						void **);
static int	scsa2usb_detach(dev_info_t *, ddi_detach_cmd_t);
static int	scsa2usb_cleanup(dev_info_t *, scsa2usb_state_t *);
static void	scsa2usb_validate_attrs(scsa2usb_state_t *);
static void	scsa2usb_create_luns(scsa2usb_state_t *);
static int	scsa2usb_is_usb(dev_info_t *);
static void	scsa2usb_fake_inquiry(scsa2usb_state_t *,
		    struct scsi_inquiry *);
static void	scsa2usb_do_inquiry(scsa2usb_state_t *,
						uint_t, uint_t);
static int	scsa2usb_do_tur(scsa2usb_state_t *, struct scsi_address *);

/* override property handling */
static void	scsa2usb_override(scsa2usb_state_t *);
static int	scsa2usb_parse_input_str(char *, scsa2usb_ov_t *,
		    scsa2usb_state_t *);
static void	scsa2usb_override_error(char *, scsa2usb_state_t *);
static char	*scsa2usb_strtok_r(char *, char *, char **);


/* PANIC callback handling */
static void	scsa2usb_panic_callb_init(scsa2usb_state_t *);
static void	scsa2usb_panic_callb_fini(scsa2usb_state_t *);
static boolean_t scsa2usb_panic_callb(void *, int);

/* SCSA support */
static int	scsa2usb_scsi_tgt_probe(struct scsi_device *, int (*)(void));
static int	scsa2usb_scsi_tgt_init(dev_info_t *, dev_info_t *,
		    scsi_hba_tran_t *, struct scsi_device *);
static void	scsa2usb_scsi_tgt_free(dev_info_t *, dev_info_t *,
		    scsi_hba_tran_t *, struct scsi_device *);
static struct	scsi_pkt *scsa2usb_scsi_init_pkt(struct scsi_address *,
		    struct scsi_pkt *, struct buf *, int, int,
		    int, int, int (*)(), caddr_t);
static void	scsa2usb_scsi_destroy_pkt(struct scsi_address *,
		    struct scsi_pkt *);
static int	scsa2usb_scsi_start(struct scsi_address *, struct scsi_pkt *);
static int	scsa2usb_scsi_abort(struct scsi_address *, struct scsi_pkt *);
static int	scsa2usb_scsi_reset(struct scsi_address *, int);
static int	scsa2usb_scsi_getcap(struct scsi_address *, char *, int);
static int	scsa2usb_scsi_setcap(struct scsi_address *, char *, int, int);
static int	scsa2usb_scsi_bus_config(dev_info_t *, uint_t,
		    ddi_bus_config_op_t, void *, dev_info_t **);
static int	scsa2usb_scsi_bus_unconfig(dev_info_t *, uint_t,
		    ddi_bus_config_op_t, void *);

/* functions for command and transport support */
static void	scsa2usb_prepare_pkt(scsa2usb_state_t *, struct scsi_pkt *);
static int	scsa2usb_cmd_transport(scsa2usb_state_t *, scsa2usb_cmd_t *);
static int	scsa2usb_check_bulkonly_blacklist_attrs(scsa2usb_state_t *,
		    scsa2usb_cmd_t *, uchar_t);
static int	scsa2usb_check_ufi_blacklist_attrs(scsa2usb_state_t *, uchar_t,
		    scsa2usb_cmd_t *);
static int	scsa2usb_handle_scsi_cmd_sub_class(scsa2usb_state_t *,
		    scsa2usb_cmd_t *, struct scsi_pkt *);
static int	scsa2usb_handle_ufi_subclass_cmd(scsa2usb_state_t *,
		    scsa2usb_cmd_t *, struct scsi_pkt *);

/* waitQ handling */
static void	scsa2usb_work_thread(void *);
static void	scsa2usb_transport_request(scsa2usb_state_t *, uint_t);
static void	scsa2usb_flush_waitQ(scsa2usb_state_t *, uint_t, uchar_t);
static int	scsa2usb_all_waitQs_empty(scsa2usb_state_t *);

/* auto request sense handling */
static int	scsa2usb_create_arq_pkt(scsa2usb_state_t *,
		    struct scsi_address *);
static void	scsa2usb_delete_arq_pkt(scsa2usb_state_t *);
static void	scsa2usb_complete_arq_pkt(scsa2usb_state_t *, struct scsi_pkt *,
		    scsa2usb_cmd_t *, struct buf *);

/* utility functions for any transport */
static int	scsa2usb_open_usb_pipes(scsa2usb_state_t *);
void		scsa2usb_close_usb_pipes(scsa2usb_state_t *);

static void	scsa2usb_fill_up_cdb_len(scsa2usb_cmd_t *, int);
static void	scsa2usb_fill_up_cdb_lba(scsa2usb_cmd_t *, int);
static void	scsa2usb_fill_up_ReadCD_cdb_len(scsa2usb_cmd_t *, int, int);
static void	scsa2usb_fill_up_12byte_cdb_len(scsa2usb_cmd_t *, int, int);
static int	scsa2usb_read_cd_blk_size(uchar_t);
int		scsa2usb_rw_transport(scsa2usb_state_t *, struct scsi_pkt *);
void		scsa2usb_setup_next_xfer(scsa2usb_state_t *, scsa2usb_cmd_t *);

static mblk_t	*scsa2usb_bp_to_mblk(scsa2usb_state_t *);
int		scsa2usb_handle_data_start(scsa2usb_state_t *,
		    scsa2usb_cmd_t *, usb_bulk_req_t *);
void		scsa2usb_handle_data_done(scsa2usb_state_t *,
		    scsa2usb_cmd_t *cmd, usb_bulk_req_t *);

usb_bulk_req_t *scsa2usb_init_bulk_req(scsa2usb_state_t *,
			    size_t, uint_t, usb_req_attrs_t, usb_flags_t);
int		scsa2usb_bulk_timeout(int);
int		scsa2usb_clear_ept_stall(scsa2usb_state_t *, uint_t,
		    usb_pipe_handle_t, char *);
static void	scsa2usb_pkt_completion(scsa2usb_state_t *, struct scsi_pkt *);

/* event handling */
static int	scsa2usb_reconnect_event_cb(dev_info_t *);
static int	scsa2usb_disconnect_event_cb(dev_info_t *);
static int	scsa2usb_cpr_suspend(dev_info_t *);
static void	scsa2usb_cpr_resume(dev_info_t *);
static void	scsa2usb_restore_device_state(dev_info_t *, scsa2usb_state_t *);

/* PM handling */
static void	scsa2usb_create_pm_components(dev_info_t *, scsa2usb_state_t *);
static void	scsa2usb_raise_power(scsa2usb_state_t *);
static int	scsa2usb_pwrlvl0(scsa2usb_state_t *);
static int	scsa2usb_pwrlvl1(scsa2usb_state_t *);
static int	scsa2usb_pwrlvl2(scsa2usb_state_t *);
static int	scsa2usb_pwrlvl3(scsa2usb_state_t *);
static int	scsa2usb_power(dev_info_t *, int comp, int level);
static void	scsa2usb_pm_busy_component(scsa2usb_state_t *);
static void	scsa2usb_pm_idle_component(scsa2usb_state_t *);

/* external functions for Bulk only (BO) support */
extern int	scsa2usb_bulk_only_transport(scsa2usb_state_t *,
		    scsa2usb_cmd_t *);
extern int	scsa2usb_bulk_only_get_max_lun(scsa2usb_state_t *);

/* external functions for CB/CBI support */
extern int	scsa2usb_cbi_transport(scsa2usb_state_t *, scsa2usb_cmd_t *);
extern void	scsa2usb_cbi_stop_intr_polling(scsa2usb_state_t *);


/* cmd decoding */
static char *scsa2usb_cmds[] = {
	"\000tur",
	"\001rezero",
	"\003rqsense",
	"\004format",
	"\014cartprot",
	"\022inquiry",
	"\026tranlba",
	"\030fmtverify",
	"\032modesense",
	"\033start",
	"\035snddiag",
	"\036doorlock",
	"\043formatcap",
	"\045readcap",
	"\050read10",
	"\052write10",
	"\053seek10",
	"\056writeverify",
	"\057verify",
	"\065synchcache",
	"\076readlong",
	"\077writelong",
	"\102readsubchan",
	"\103readtoc",
	"\104readhdr",
	"\105playaudio10",
	"\107playaudio_msf",
	"\110playaudio_ti",
	"\111playtrk_r10",
	"\112geteventnotify",
	"\113pause_resume",
	"\116stop/play_scan",
	"\121readdiscinfo",
	"\122readtrkinfo",
	"\123reservedtrk",
	"\124sendopcinfo",
	"\125modeselect",
	"\132modesense",
	"\133closetrksession",
	"\135sendcuesheet",
	"\136prin",
	"\137prout",
	"\241blankcd",
	"\245playaudio12",
	"\250read12",
	"\251playtrk12",
	"\252write12",
	"\254getperf",
	"\271readcdmsf",
	"\273setcdspeed",
	"\275mechanism_sts",
	"\276readcd",
	NULL
};


/*
 * Mass-Storage devices masquerade as "sd" disks.
 *
 * These devices may not support all SCSI CDBs in their
 * entirety due to their hardware implementation limitations.
 *
 * As such, following is a list of some of the black-listed
 * devices w/ the attributes that they do not support.
 * (See scsa2usb.h for description on each attribute)
 */
#define	X	((uint16_t)(-1))

static struct blacklist {
	uint16_t	idVendor;	/* vendor ID			*/
	uint16_t	idProduct;	/* product ID			*/
	uint16_t	bcdDevice;	/* device release number in bcd */
	uint16_t	attributes;	/* attributes to blacklist	*/
} scsa2usb_blacklist[] = {
	/* Iomega Zip100 drive (prototype) with flaky bridge */
	{MS_IOMEGA_VID, MS_IOMEGA_PID1_ZIP100, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_PM},

	/* Iomega Zip100 drive (newer model) with flaky bridge */
	{MS_IOMEGA_VID, MS_IOMEGA_PID2_ZIP100, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_PM},

	/* Iomega Zip100 drive (newer model) with flaky bridge */
	{MS_IOMEGA_VID, MS_IOMEGA_PID3_ZIP100, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_PM},

	/* Iomega Zip250 drive */
	{MS_IOMEGA_VID, MS_IOMEGA_PID_ZIP250, 0, SCSA2USB_ATTRS_GET_LUN},

	/* Iomega Clik! drive */
	{MS_IOMEGA_VID, MS_IOMEGA_PID_CLIK, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_START_STOP},

	/* Kingston DataTraveler Stick / PNY Attache Stick */
	{MS_TOSHIBA_VID, MS_TOSHIBA_PID0, 0,
	    SCSA2USB_ATTRS_GET_LUN},

	/* PNY Floppy drive */
	{MS_PNY_VID, MS_PNY_PID0, 0,
	    SCSA2USB_ATTRS_GET_LUN},

	/* SMSC floppy Device - and its clones */
	{MS_SMSC_VID, X, 0, SCSA2USB_ATTRS_START_STOP},

	/* Hagiwara SmartMedia Device */
	{MS_HAGIWARA_SYS_COM_VID, MS_HAGIWARA_SYSCOM_PID1, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_START_STOP},

	/* Hagiwara CompactFlash Device */
	{MS_HAGIWARA_SYS_COM_VID, MS_HAGIWARA_SYSCOM_PID2, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_START_STOP},

	/* Hagiwara SmartMedia/CompactFlash Combo Device */
	{MS_HAGIWARA_SYS_COM_VID, MS_HAGIWARA_SYSCOM_PID3, 0,
	    SCSA2USB_ATTRS_START_STOP},

	/* Hagiwara new SM Device */
	{MS_HAGIWARA_SYS_COM_VID, MS_HAGIWARA_SYSCOM_PID4, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_START_STOP},

	/* Hagiwara new CF Device */
	{MS_HAGIWARA_SYS_COM_VID, MS_HAGIWARA_SYSCOM_PID5, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_START_STOP},

	/* Mitsumi CD-RW Device(s) */
	{MS_MITSUMI_VID, X, X, SCSA2USB_ATTRS_BIG_TIMEOUT |
	    SCSA2USB_ATTRS_GET_CONF | SCSA2USB_ATTRS_GET_PERF},

	/* Neodio Technologies Corporation SM/CF/MS/SD Combo Device */
	{MS_NEODIO_VID, MS_NEODIO_DEVICE_3050, 0,
	    SCSA2USB_ATTRS_MODE_SENSE },

	/* dumb flash devices */
	{MS_SONY_FLASH_VID, MS_SONY_FLASH_PID, 0,
	    SCSA2USB_ATTRS_REDUCED_CMD},

	{MS_TREK_FLASH_VID, MS_TREK_FLASH_PID, 0,
	    SCSA2USB_ATTRS_REDUCED_CMD},

	{MS_PENN_FLASH_VID, MS_PENN_FLASH_PID, 0,
	    SCSA2USB_ATTRS_REDUCED_CMD},

	/* SimpleTech UCF-100 CF Device */
	{MS_SIMPLETECH_VID, MS_SIMPLETECH_PID1, 0,
	    SCSA2USB_ATTRS_REDUCED_CMD},

	{MS_ADDONICS_CARD_READER_VID, MS_ADDONICS_CARD_READER_PID,
	    0, SCSA2USB_ATTRS_REDUCED_CMD},

	/* Acomdata 80GB USB/1394 Hard Disk */
	{MS_ACOMDATA_VID, MS_ACOMDATA_PID1, 0,
	    SCSA2USB_ATTRS_USE_CSW_RESIDUE},

	/* OTi6828 Flash Disk */
	{MS_OTI_VID, MS_OTI_DEVICE_6828, 0,
	    SCSA2USB_ATTRS_USE_CSW_RESIDUE},

	/* AMI Virtual Floppy */
	{MS_AMI_VID, MS_AMI_VIRTUAL_FLOPPY, 0,
	    SCSA2USB_ATTRS_NO_MEDIA_CHECK},

	/* ScanLogic USB Storage Device */
	{MS_SCANLOGIC_VID, MS_SCANLOGIC_PID1, 0,
	    SCSA2USB_ATTRS_NO_CAP_ADJUST},

	/* Super Top USB 2.0 IDE Device */
	{MS_SUPERTOP_VID, MS_SUPERTOP_DEVICE_6600, 0,
	    SCSA2USB_ATTRS_USE_CSW_RESIDUE},

	/* Aigo Miniking Device NEHFSP14 */
	{MS_AIGO_VID, MS_AIGO_DEVICE_6981, 0,
	    SCSA2USB_ATTRS_USE_CSW_RESIDUE},

	/* Alcor Micro Corp 6387 flash disk */
	{MS_ALCOR_VID, MS_ALCOR_PID0, 0,
	    SCSA2USB_ATTRS_GET_LUN | SCSA2USB_ATTRS_USE_CSW_RESIDUE},

	/* Western Digital External HDD */
	{MS_WD_VID, MS_WD_PID, 0,
	    SCSA2USB_ATTRS_INQUIRY_EVPD}
};


#define	N_SCSA2USB_BLACKLIST (sizeof (scsa2usb_blacklist))/ \
				sizeof (struct blacklist)

/*
 * Attribute values can be overridden by values
 * contained in the scsa2usb.conf file.
 * These arrays define possible user input values.
 */

struct scsa2usb_subclass_protocol_override {
	char	*name;
	int	value;
};

static struct scsa2usb_subclass_protocol_override scsa2usb_protocol[] =  {
	{"CB", SCSA2USB_CB_PROTOCOL},
	{"CBI", SCSA2USB_CBI_PROTOCOL},
	{"BO", SCSA2USB_BULK_ONLY_PROTOCOL}
};

static struct scsa2usb_subclass_protocol_override scsa2usb_subclass[] = {
	{"SCSI", SCSA2USB_SCSI_CMDSET},
	{"ATAPI", SCSA2USB_ATAPI_CMDSET},
	{"UFI", SCSA2USB_UFI_CMDSET}
};


#define	N_SCSA2USB_SUBC_OVERRIDE (sizeof (scsa2usb_subclass))/ \
			sizeof (struct scsa2usb_subclass_protocol_override)

#define	N_SCSA2USB_PROT_OVERRIDE (sizeof (scsa2usb_protocol))/ \
			sizeof (struct scsa2usb_subclass_protocol_override)

/* global variables */
static void *scsa2usb_statep;				/* for soft state */
static boolean_t scsa2usb_sync_message = B_TRUE;	/* for syncing */

/* for debug messages */
uint_t	scsa2usb_errmask	= (uint_t)DPRINT_MASK_ALL;
uint_t	scsa2usb_errlevel	= USB_LOG_L4;
uint_t	scsa2usb_instance_debug = (uint_t)-1;
uint_t	scsa2usb_scsi_bus_config_debug = 0;
uint_t	scsa2usb_long_timeout	= 50 * SCSA2USB_BULK_PIPE_TIMEOUT;


/*
 * Some devices have problems with big bulk transfers,
 * transfers >= 128kbytes hang the device.  This tunable allows to
 * limit the maximum bulk transfers rate.
 */
uint_t	scsa2usb_max_bulk_xfer_size = SCSA2USB_MAX_BULK_XFER_SIZE;


#ifdef	SCSA2USB_BULK_ONLY_TEST
/*
 * Test BO 13 cases. (See USB Mass Storage Class - Bulk Only Transport).
 * We are not covering test cases 1, 6, and 12 as these are the "good"
 * test cases and are tested as part of the normal drive access operations.
 *
 * NOTE: This is for testing only. It will be replaced by a uscsi test.
 * Some are listed here while; other test cases are moved to usb_bulkonly.c
 */
static int scsa2usb_test_case_5 = 0;
int scsa2usb_test_case_8 = 0;
int scsa2usb_test_case_10 = 0;
static int scsa2usb_test_case_11 = 0;

static void	scsa2usb_test_mblk(scsa2usb_state_t *, boolean_t);
#endif	/* SCSA2USB_BULK_ONLY_TEST */

static int	scsa2usb_ugen_open(dev_t *, int, int, cred_t *);
static int	scsa2usb_ugen_close(dev_t, int, int, cred_t *);
static int	scsa2usb_ugen_read(dev_t, struct uio *, cred_t *);
static int	scsa2usb_ugen_write(dev_t, struct uio *, cred_t *);
static int	scsa2usb_ugen_poll(dev_t, short, int,  short *,
						struct pollhead **);

/* scsa2usb cb_ops */
static struct cb_ops scsa2usb_cbops = {
	scsa2usb_ugen_open,	/* open  */
	scsa2usb_ugen_close,	/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	scsa2usb_ugen_read,	/* read */
	scsa2usb_ugen_write,	/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	scsa2usb_ugen_poll,	/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_MP,			/* cb_flag */
	CB_REV, 		/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

/* modloading support */
static struct dev_ops scsa2usb_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	scsa2usb_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	scsa2usb_attach,	/* attach */
	scsa2usb_detach,	/* detach */
	nodev,			/* reset */
	&scsa2usb_cbops,	/* driver operations */
	NULL,			/* bus operations */
	scsa2usb_power,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* Module type. This one is a driver */
	"SCSA to USB Driver",	/* Name of the module. */
	&scsa2usb_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/* event support */
static usb_event_t scsa2usb_events = {
	scsa2usb_disconnect_event_cb,
	scsa2usb_reconnect_event_cb,
	NULL, NULL
};

int
_init(void)
{
	int rval;

	if (((rval = ddi_soft_state_init(&scsa2usb_statep,
	    sizeof (scsa2usb_state_t), SCSA2USB_INITIAL_ALLOC)) != 0)) {

		return (rval);
	}

	if ((rval = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&scsa2usb_statep);

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&scsa2usb_statep);

		return (rval);
	}

	return (rval);
}


int
_fini(void)
{
	int	rval;

	if ((rval = mod_remove(&modlinkage)) == 0) {
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&scsa2usb_statep);
	}

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * scsa2usb_info :
 *	Get minor number, soft state structure etc.
 */
/*ARGSUSED*/
static int
scsa2usb_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
	scsa2usb_state_t *scsa2usbp = NULL;
	int error = DDI_FAILURE;
	int instance = SCSA2USB_MINOR_TO_INSTANCE(getminor((dev_t)arg));

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (((scsa2usbp = ddi_get_soft_state(scsa2usb_statep,
		    instance)) != NULL) &&
		    scsa2usbp->scsa2usb_dip) {
			*result = scsa2usbp->scsa2usb_dip;
			error = DDI_SUCCESS;
		} else {
			*result = NULL;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}


/*
 * scsa2usb_attach:
 *	Attach driver
 *	Allocate a "scsi_hba_tran" - call scsi_hba_tran_alloc()
 *	Invoke scsi_hba_attach_setup
 *	Get the serialno of the device
 *	Open bulk pipes
 *	Create disk child(ren)
 *	Register events
 *	Create and register panic callback
 *
 * NOTE: Replaced CBW_DIR_OUT with USB_EP_DIR_OUT and CBW_DIR_IN with
 * USB_EP_DIR_IN as they are the same #defines.
 */
static int
scsa2usb_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	int			interface;
	uint_t			lun;
	boolean_t		ept_check = B_TRUE;
	scsi_hba_tran_t		*tran;		/* scsi transport */
	scsa2usb_state_t	*scsa2usbp;
	usb_log_handle_t	log_handle;
	usb_ep_data_t		*ep_data;
	usb_client_dev_data_t	*dev_data;
	usb_alt_if_data_t	*altif_data;
	usb_ugen_info_t 	usb_ugen_info;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, NULL,
	    "scsa2usb_attach: dip = 0x%p", (void *)dip);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		scsa2usb_cpr_resume(dip);

		return (DDI_SUCCESS);
	default:
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, NULL,
		    "scsa2usb_attach: failed");

		return (DDI_FAILURE);
	}

	/* Allocate softc information */
	if (ddi_soft_state_zalloc(scsa2usb_statep, instance) != DDI_SUCCESS) {
		ddi_prop_remove_all(dip);

		return (DDI_FAILURE);
	}

	/* get soft state space and initialize */
	if ((scsa2usbp = ddi_get_soft_state(scsa2usb_statep,
	    instance)) == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, NULL,
		    "scsa2usb%d: bad soft state", instance);
		ddi_prop_remove_all(dip);

		return (DDI_FAILURE);
	}

	scsa2usbp->scsa2usb_dip 	= dip;
	scsa2usbp->scsa2usb_instance	= instance;

	/* allocate a log handle for debug/error messages */
	scsa2usbp->scsa2usb_log_handle = log_handle =
	    usb_alloc_log_hdl(dip, "s2u",
	    &scsa2usb_errlevel,
	    &scsa2usb_errmask, &scsa2usb_instance_debug,
	    0);

	/* attach to USBA */
	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "usb_client_attach failed");

		goto fail;
	}
	if (usb_get_dev_data(dip, &dev_data, USB_PARSE_LVL_IF, 0) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "usb_get_dev_data failed");

		goto fail;
	}

	/* initialize the mutex with the right cookie */
	mutex_init(&scsa2usbp->scsa2usb_mutex, NULL, MUTEX_DRIVER,
	    dev_data->dev_iblock_cookie);
	cv_init(&scsa2usbp->scsa2usb_transport_busy_cv, NULL, CV_DRIVER, NULL);

	for (lun = 0; lun < SCSA2USB_MAX_LUNS; lun++) {
		usba_init_list(&scsa2usbp->scsa2usb_waitQ[lun], NULL,
		    dev_data->dev_iblock_cookie);
	}
	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	scsa2usbp->scsa2usb_dip 	= dip;
	scsa2usbp->scsa2usb_instance	= instance;
	scsa2usbp->scsa2usb_attrs	= SCSA2USB_ALL_ATTRS;
	scsa2usbp->scsa2usb_dev_data	= dev_data;


	/* save the default pipe handle */
	scsa2usbp->scsa2usb_default_pipe = dev_data->dev_default_ph;

	/* basic inits are done */
	scsa2usbp->scsa2usb_flags |= SCSA2USB_FLAGS_LOCKS_INIT;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, log_handle,
	    "curr_cfg=%ld, curr_if=%d",
	    (long)(dev_data->dev_curr_cfg - &dev_data->dev_cfg[0]),
	    dev_data->dev_curr_if);

	interface = dev_data->dev_curr_if;
	scsa2usbp->scsa2usb_intfc_num = dev_data->dev_curr_if;

	/* now find out relevant descriptors for alternate 0 */
	altif_data = &dev_data->dev_curr_cfg->cfg_if[interface].if_alt[0];

	if (altif_data->altif_n_ep == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "invalid alt 0 for interface %d", interface);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		goto fail;
	}

	/* All CB/CBI, BO devices should have this value set */
	if (altif_data->altif_descr.bInterfaceClass !=
	    USB_CLASS_MASS_STORAGE) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "invalid interface class (0x%x)",
		    altif_data->altif_descr.bInterfaceClass);
	}
	scsa2usbp->scsa2usb_intfc_descr = altif_data->altif_descr;

	/* figure out the endpoints and copy the descr */
	if ((ep_data = usb_lookup_ep_data(dip, dev_data, interface, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_OUT)) != NULL) {
		if (usb_ep_xdescr_fill(USB_EP_XDESCR_CURRENT_VERSION,
		    dip, ep_data, &scsa2usbp->scsa2usb_bulkout_xept) !=
		    USB_SUCCESS) {

			mutex_exit(&scsa2usbp->scsa2usb_mutex);

			goto fail;
		}
	}
	if ((ep_data = usb_lookup_ep_data(dip, dev_data, interface, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN)) != NULL) {
		if (usb_ep_xdescr_fill(USB_EP_XDESCR_CURRENT_VERSION,
		    dip, ep_data, &scsa2usbp->scsa2usb_bulkin_xept) !=
		    USB_SUCCESS) {

			mutex_exit(&scsa2usbp->scsa2usb_mutex);

			goto fail;
		}
	}
	if ((ep_data = usb_lookup_ep_data(dip, dev_data, interface, 0, 0,
	    USB_EP_ATTR_INTR, USB_EP_DIR_IN)) != NULL) {
		if (usb_ep_xdescr_fill(USB_EP_XDESCR_CURRENT_VERSION,
		    dip, ep_data, &scsa2usbp->scsa2usb_intr_xept) !=
		    USB_SUCCESS) {

			mutex_exit(&scsa2usbp->scsa2usb_mutex);

			goto fail;
		}
	}

	/*
	 * check here for protocol and subclass supported by this driver
	 *
	 * first check if conf file has override values
	 * Note: override values are not used if supplied values are legal
	 */
	scsa2usb_override(scsa2usbp);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, log_handle,
	    "protocol=0x%x override=0x%x subclass=0x%x override=0x%x",
	    scsa2usbp->scsa2usb_intfc_descr.bInterfaceProtocol,
	    scsa2usbp->scsa2usb_protocol_override,
	    scsa2usbp->scsa2usb_intfc_descr.bInterfaceSubClass,
	    scsa2usbp->scsa2usb_subclass_override);

	switch (scsa2usbp->scsa2usb_intfc_descr.bInterfaceProtocol) {
	case USB_PROTO_MS_CBI:
		scsa2usbp->scsa2usb_cmd_protocol |= SCSA2USB_CB_PROTOCOL;
		break;
	case USB_PROTO_MS_CBI_WC:
		scsa2usbp->scsa2usb_cmd_protocol |= SCSA2USB_CBI_PROTOCOL;
		break;
	case USB_PROTO_MS_ISD_1999_SILICN:
	case USB_PROTO_MS_BULK_ONLY:
		scsa2usbp->scsa2usb_cmd_protocol |= SCSA2USB_BULK_ONLY_PROTOCOL;
		break;
	default:
		if (scsa2usbp->scsa2usb_protocol_override) {
			scsa2usbp->scsa2usb_cmd_protocol |=
			    scsa2usbp->scsa2usb_protocol_override;
			USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
			    "overriding protocol %x",
			    scsa2usbp->scsa2usb_intfc_descr.bInterfaceProtocol);
			break;
		}

		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "unsupported protocol = %x",
		    scsa2usbp->scsa2usb_intfc_descr.bInterfaceProtocol);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		goto fail;
	}

	switch (scsa2usbp->scsa2usb_intfc_descr.bInterfaceSubClass) {
	case USB_SUBCLS_MS_SCSI:		/* transparent SCSI */
		scsa2usbp->scsa2usb_cmd_protocol |= SCSA2USB_SCSI_CMDSET;
		break;
	case USB_SUBCLS_MS_SFF8020I:
	case USB_SUBCLS_MS_SFF8070I:
		scsa2usbp->scsa2usb_cmd_protocol |= SCSA2USB_ATAPI_CMDSET;
		break;
	case USB_SUBCLS_MS_UFI:		/* UFI */
		scsa2usbp->scsa2usb_cmd_protocol |= SCSA2USB_UFI_CMDSET;
		break;
	default:
		if (scsa2usbp->scsa2usb_subclass_override) {
			scsa2usbp->scsa2usb_cmd_protocol |=
			    scsa2usbp->scsa2usb_subclass_override;
			USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
			    "overriding subclass %x",
			    scsa2usbp->scsa2usb_intfc_descr.bInterfaceSubClass);
			break;
		}

		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "unsupported subclass = %x",
		    scsa2usbp->scsa2usb_intfc_descr.bInterfaceSubClass);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		goto fail;
	}

	/* check that we have the right set of endpoint descriptors */
	if (SCSA2USB_IS_BULK_ONLY(scsa2usbp) || SCSA2USB_IS_CB(scsa2usbp)) {
		if ((scsa2usbp->scsa2usb_bulkout_ept.bLength == 0) ||
		    (scsa2usbp->scsa2usb_bulkin_ept.bLength == 0)) {
			ept_check = B_FALSE;
		}
	} else if (SCSA2USB_IS_CBI(scsa2usbp)) {
		if ((scsa2usbp->scsa2usb_bulkout_ept.bLength == 0) ||
		    (scsa2usbp->scsa2usb_bulkin_ept.bLength == 0) ||
		    (scsa2usbp->scsa2usb_intr_ept.bLength == 0)) {
			ept_check = B_FALSE;
		}
	}

	if (ept_check == B_FALSE) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "scsa2usb%d doesn't support minimum required endpoints",
		    instance);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		goto fail;
	}

	/*
	 * Validate the black-listed attributes
	 */
	scsa2usb_validate_attrs(scsa2usbp);

	/* Print the serial number from the registration data */
	if (scsa2usbp->scsa2usb_dev_data->dev_serial) {
		USB_DPRINTF_L4(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle, "Serial Number = %s",
		    scsa2usbp->scsa2usb_dev_data->dev_serial);
	}

	/*
	 * Allocate a SCSA transport structure
	 */
	tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);
	scsa2usbp->scsa2usb_tran = tran;

	/*
	 * initialize transport structure
	 */
	tran->tran_hba_private		= scsa2usbp;
	tran->tran_tgt_private		= NULL;
	tran->tran_tgt_init		= scsa2usb_scsi_tgt_init;
	tran->tran_tgt_probe		= scsa2usb_scsi_tgt_probe;
	tran->tran_tgt_free		= scsa2usb_scsi_tgt_free;
	tran->tran_start		= scsa2usb_scsi_start;
	tran->tran_abort		= scsa2usb_scsi_abort;
	tran->tran_reset		= scsa2usb_scsi_reset;
	tran->tran_getcap		= scsa2usb_scsi_getcap;
	tran->tran_setcap		= scsa2usb_scsi_setcap;
	tran->tran_init_pkt		= scsa2usb_scsi_init_pkt;
	tran->tran_destroy_pkt		= scsa2usb_scsi_destroy_pkt;
	tran->tran_dmafree		= NULL;
	tran->tran_sync_pkt		= NULL;
	tran->tran_reset_notify		= NULL;
	tran->tran_get_bus_addr		= NULL;
	tran->tran_get_name		= NULL;
	tran->tran_quiesce		= NULL;
	tran->tran_unquiesce		= NULL;
	tran->tran_bus_reset		= NULL;
	tran->tran_add_eventcall	= NULL;
	tran->tran_get_eventcookie	= NULL;
	tran->tran_post_event		= NULL;
	tran->tran_remove_eventcall	= NULL;
	tran->tran_bus_config		= scsa2usb_scsi_bus_config;
	tran->tran_bus_unconfig		= scsa2usb_scsi_bus_unconfig;

	/*
	 * register with SCSA as an HBA
	 * Note that the dma attributes are from parent nexus
	 */
	if (scsi_hba_attach_setup(dip, usba_get_hc_dma_attr(dip), tran, 0)) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "scsi_hba_attach_setup failed");
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		goto fail;
	}

	scsa2usbp->scsa2usb_flags |= SCSA2USB_FLAGS_HBA_ATTACH_SETUP;

	/* create minor node */
	if (ddi_create_minor_node(dip, "scsa2usb", S_IFCHR,
	    instance << SCSA2USB_MINOR_INSTANCE_SHIFT,
	    DDI_NT_SCSI_NEXUS, 0) != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsi_attach: ddi_create_minor_node failed");
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		goto fail;
	}

	/* open pipes and set scsa2usb_flags */
	if (scsa2usb_open_usb_pipes(scsa2usbp) == USB_FAILURE) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "error opening pipes");
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		goto fail;
	}

	/* set default block size. updated after read cap cmd */
	for (lun = 0; lun < SCSA2USB_MAX_LUNS; lun++) {
		scsa2usbp->scsa2usb_lbasize[lun] = DEV_BSIZE;
	}

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	/* initialize PANIC callback */
	scsa2usb_panic_callb_init(scsa2usbp);

	/* finally we are all done 'initializing' the device */
	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	scsa2usbp->scsa2usb_dev_state = USB_DEV_ONLINE;

	/* enable PM, mutex needs to be held across this */
	scsa2usb_create_pm_components(dip, scsa2usbp);
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	/* register for connect/disconnect events */
	if (usb_register_event_cbs(scsa2usbp->scsa2usb_dip, &scsa2usb_events,
	    0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, log_handle,
		    "error cb registering");
		goto fail;
	}

	/* free the dev_data tree, we no longer need it */
	usb_free_descr_tree(dip, dev_data);

	scsa2usb_pm_idle_component(scsa2usbp);

	/* log the conf file override string if there is one */
	if (scsa2usbp->scsa2usb_override_str) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb.conf override: %s",
		    scsa2usbp->scsa2usb_override_str);
	}

	if (usb_owns_device(dip)) {
		/* get a ugen handle */
		bzero(&usb_ugen_info, sizeof (usb_ugen_info));
		usb_ugen_info.usb_ugen_flags = 0;
		usb_ugen_info.usb_ugen_minor_node_ugen_bits_mask =
		    (dev_t)SCSA2USB_MINOR_UGEN_BITS_MASK;
		usb_ugen_info.usb_ugen_minor_node_instance_mask =
		    (dev_t)~SCSA2USB_MINOR_UGEN_BITS_MASK;
		scsa2usbp->scsa2usb_ugen_hdl =
		    usb_ugen_get_hdl(dip, &usb_ugen_info);

		if (usb_ugen_attach(scsa2usbp->scsa2usb_ugen_hdl, cmd) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "usb_ugen_attach failed");

			usb_ugen_release_hdl(scsa2usbp->scsa2usb_ugen_hdl);
			scsa2usbp->scsa2usb_ugen_hdl = NULL;
		}
	}

	/* report device */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	if (scsa2usbp) {
		(void) scsa2usb_cleanup(dip, scsa2usbp);
	}

	return (DDI_FAILURE);
}


/*
 * scsa2usb_detach:
 *	detach or suspend driver instance
 */
static int
scsa2usb_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	scsi_hba_tran_t	*tran;
	scsa2usb_state_t *scsa2usbp;
	int rval;

	tran = ddi_get_driver_private(dip);
	ASSERT(tran != NULL);

	scsa2usbp = (scsa2usb_state_t *)tran->tran_hba_private;
	ASSERT(scsa2usbp);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_detach: dip = 0x%p, cmd = %d", (void *)dip, cmd);

	switch (cmd) {
	case DDI_DETACH:

		if (scsa2usb_cleanup(dip, scsa2usbp) != USB_SUCCESS) {

			return (DDI_FAILURE);
		}

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		rval = scsa2usb_cpr_suspend(dip);

		return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
	default:

		return (DDI_FAILURE);
	}
}

/*
 * ugen support
 */
/*
 * scsa2usb_ugen_open()
 * (all ugen opens and pipe opens are by definition exclusive so it is OK
 * to count opens)
 */
static int
scsa2usb_ugen_open(dev_t *devp, int flag, int sflag, cred_t *cr)
{
	scsa2usb_state_t *scsa2usbp;
	int		rval;

	if ((scsa2usbp = ddi_get_soft_state(scsa2usb_statep,
	    SCSA2USB_MINOR_TO_INSTANCE(getminor(*devp)))) == NULL) {
		/* deferred detach */

		return (ENXIO);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_ugen_open: dev_t=0x%lx", *devp);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	/* if this is the first ugen open, check on transport busy */
	if (scsa2usbp->scsa2usb_busy_proc != curproc) {
		while (scsa2usbp->scsa2usb_transport_busy ||
		    (scsa2usb_all_waitQs_empty(scsa2usbp) !=
		    USB_SUCCESS)) {
			rval = cv_wait_sig(
			    &scsa2usbp->scsa2usb_transport_busy_cv,
			    &scsa2usbp->scsa2usb_mutex);
			if (rval == 0) {
				mutex_exit(&scsa2usbp->scsa2usb_mutex);

				return (EINTR);
			}
		}
		scsa2usbp->scsa2usb_transport_busy++;
		scsa2usbp->scsa2usb_busy_proc = curproc;
	}

	scsa2usbp->scsa2usb_ugen_open_count++;

	scsa2usb_raise_power(scsa2usbp);

	scsa2usb_close_usb_pipes(scsa2usbp);

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	rval = usb_ugen_open(scsa2usbp->scsa2usb_ugen_hdl, devp, flag,
	    sflag, cr);
	if (!rval) {
		/*
		 * if usb_ugen_open() succeeded, we'll change the minor number
		 * so that we can keep track of every open()/close() issued by
		 * the userland processes. We need to pick a minor number that
		 * is not used by the ugen framework
		 */

		usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl;
		ugen_state_t		*ugenp;
		int			ugen_minor, clone;

		mutex_enter(&scsa2usbp->scsa2usb_mutex);

		usb_ugen_hdl_impl =
		    (usb_ugen_hdl_impl_t *)scsa2usbp->scsa2usb_ugen_hdl;
		ugenp =  usb_ugen_hdl_impl->hdl_ugenp;

		/* 'clone' is bigger than any ugen minor in use */
		for (clone = ugenp->ug_minor_node_table_index + 1;
		    clone < SCSA2USB_MAX_CLONE; clone++) {
			if (!scsa2usbp->scsa2usb_clones[clone])
				break;
		}

		if (clone >= SCSA2USB_MAX_CLONE) {
			cmn_err(CE_WARN, "scsa2usb_ugen_open: too many clones");
			rval = EBUSY;
			mutex_exit(&scsa2usbp->scsa2usb_mutex);
			goto open_done;
		}

		ugen_minor = getminor(*devp) & SCSA2USB_MINOR_UGEN_BITS_MASK;
		*devp = makedevice(getmajor(*devp),
		    (scsa2usbp->scsa2usb_instance
		    << SCSA2USB_MINOR_INSTANCE_SHIFT)
		    + clone);

		/* save the ugen minor */
		scsa2usbp->scsa2usb_clones[clone] = (uint8_t)ugen_minor;
		USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_ugen_open: new dev=%lx, old minor=%x",
		    *devp, ugen_minor);

		mutex_exit(&scsa2usbp->scsa2usb_mutex);
	}

open_done:

	if (rval) {
		mutex_enter(&scsa2usbp->scsa2usb_mutex);

		/* reopen the pipes */
		if (--scsa2usbp->scsa2usb_ugen_open_count == 0) {
			scsa2usbp->scsa2usb_transport_busy--;
			scsa2usbp->scsa2usb_busy_proc = NULL;
			cv_signal(&scsa2usbp->scsa2usb_transport_busy_cv);
		}
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		scsa2usb_pm_idle_component(scsa2usbp);
	}

	return (rval);
}


/*
 * scsa2usb_ugen_close()
 */
static int
scsa2usb_ugen_close(dev_t dev, int flag, int otype, cred_t *cr)
{
	int rval;
	int	ugen_minor, clone;

	scsa2usb_state_t *scsa2usbp = ddi_get_soft_state(scsa2usb_statep,
	    SCSA2USB_MINOR_TO_INSTANCE(getminor(dev)));

	if (scsa2usbp == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_ugen_close: dev_t=0x%lx", dev);

	clone = getminor(dev) & SCSA2USB_MINOR_UGEN_BITS_MASK;
	ugen_minor = scsa2usbp->scsa2usb_clones[clone];
	dev = makedevice(getmajor(dev),
	    (scsa2usbp->scsa2usb_instance << SCSA2USB_MINOR_INSTANCE_SHIFT)
	    + ugen_minor);
	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_ugen_close: old dev=%lx", dev);
	rval = usb_ugen_close(scsa2usbp->scsa2usb_ugen_hdl, dev, flag,
	    otype, cr);

	if (rval == 0) {
		mutex_enter(&scsa2usbp->scsa2usb_mutex);

		scsa2usbp->scsa2usb_clones[clone] = 0;
		/* reopen the pipes */
		if (--scsa2usbp->scsa2usb_ugen_open_count == 0) {
			scsa2usbp->scsa2usb_transport_busy--;
			scsa2usbp->scsa2usb_busy_proc = NULL;
			cv_signal(&scsa2usbp->scsa2usb_transport_busy_cv);
		}
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		scsa2usb_pm_idle_component(scsa2usbp);
	}

	return (rval);
}


/*
 * scsa2usb_ugen_read/write()
 */
/*ARGSUSED*/
static int
scsa2usb_ugen_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int clone, ugen_minor;
	scsa2usb_state_t *scsa2usbp = ddi_get_soft_state(scsa2usb_statep,
	    SCSA2USB_MINOR_TO_INSTANCE(getminor(dev)));

	if (scsa2usbp == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_ugen_read: dev_t=0x%lx", dev);

	clone = getminor(dev) & SCSA2USB_MINOR_UGEN_BITS_MASK;
	ugen_minor = scsa2usbp->scsa2usb_clones[clone];
	dev = makedevice(getmajor(dev),
	    (scsa2usbp->scsa2usb_instance << SCSA2USB_MINOR_INSTANCE_SHIFT)
	    + ugen_minor);

	return (usb_ugen_read(scsa2usbp->scsa2usb_ugen_hdl, dev,
	    uiop, credp));
}


/*ARGSUSED*/
static int
scsa2usb_ugen_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int clone, ugen_minor;
	scsa2usb_state_t *scsa2usbp = ddi_get_soft_state(scsa2usb_statep,
	    SCSA2USB_MINOR_TO_INSTANCE(getminor(dev)));

	if (scsa2usbp == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_ugen_write: dev_t=0x%lx", dev);

	clone = getminor(dev) & SCSA2USB_MINOR_UGEN_BITS_MASK;
	ugen_minor = scsa2usbp->scsa2usb_clones[clone];
	dev = makedevice(getmajor(dev),
	    (scsa2usbp->scsa2usb_instance << SCSA2USB_MINOR_INSTANCE_SHIFT)
	    + ugen_minor);

	return (usb_ugen_write(scsa2usbp->scsa2usb_ugen_hdl,
	    dev, uiop, credp));
}


/*
 * scsa2usb_ugen_poll
 */
static int
scsa2usb_ugen_poll(dev_t dev, short events,
    int anyyet,  short *reventsp, struct pollhead **phpp)
{
	int clone, ugen_minor;
	scsa2usb_state_t *scsa2usbp = ddi_get_soft_state(scsa2usb_statep,
	    SCSA2USB_MINOR_TO_INSTANCE(getminor(dev)));

	if (scsa2usbp == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_ugen_poll: dev_t=0x%lx", dev);

	clone = getminor(dev) & SCSA2USB_MINOR_UGEN_BITS_MASK;
	ugen_minor = scsa2usbp->scsa2usb_clones[clone];
	dev = makedevice(getmajor(dev),
	    (scsa2usbp->scsa2usb_instance << SCSA2USB_MINOR_INSTANCE_SHIFT)
	    + ugen_minor);

	return (usb_ugen_poll(scsa2usbp->scsa2usb_ugen_hdl, dev, events,
	    anyyet, reventsp, phpp));
}


/*
 * scsa2usb_cleanup:
 *	cleanup whatever attach has setup
 */
static int
scsa2usb_cleanup(dev_info_t *dip, scsa2usb_state_t *scsa2usbp)
{
	int		rval, i;
	scsa2usb_power_t *pm;
	uint_t		lun;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cleanup:");

	/* wait till the work thread is done */
	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	for (i = 0; i < SCSA2USB_DRAIN_TIMEOUT; i++) {
		if (scsa2usbp->scsa2usb_work_thread_id == NULL) {

			break;
		}
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		delay(drv_usectohz(1000000));
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
	}
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	if (i >= SCSA2USB_DRAIN_TIMEOUT) {

		return (USB_FAILURE);
	}

	/*
	 * Disable the event callbacks first, after this point, event
	 * callbacks will never get called. Note we shouldn't hold
	 * mutex while unregistering events because there may be a
	 * competing event callback thread. Event callbacks are done
	 * with ndi mutex held and this can cause a potential deadlock.
	 */
	usb_unregister_event_cbs(scsa2usbp->scsa2usb_dip, &scsa2usb_events);

	if (scsa2usbp->scsa2usb_flags & SCSA2USB_FLAGS_LOCKS_INIT) {
		/*
		 * if a waitQ exists, get rid of it before destroying it
		 */
		for (lun = 0; lun < SCSA2USB_MAX_LUNS; lun++) {
			scsa2usb_flush_waitQ(scsa2usbp, lun, CMD_TRAN_ERR);
			usba_destroy_list(&scsa2usbp->scsa2usb_waitQ[lun]);
		}

		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		if (scsa2usbp->scsa2usb_flags &
		    SCSA2USB_FLAGS_HBA_ATTACH_SETUP) {
			(void) scsi_hba_detach(dip);
			scsi_hba_tran_free(scsa2usbp->scsa2usb_tran);
		}

		if (scsa2usbp->scsa2usb_flags &
		    SCSA2USB_FLAGS_PIPES_OPENED) {
			scsa2usb_close_usb_pipes(scsa2usbp);
		}

		/* Lower the power */
		pm = scsa2usbp->scsa2usb_pm;

		if (pm && (scsa2usbp->scsa2usb_dev_state !=
		    USB_DEV_DISCONNECTED)) {
			if (pm->scsa2usb_wakeup_enabled) {
				mutex_exit(&scsa2usbp->scsa2usb_mutex);
				(void) pm_raise_power(dip, 0,
				    USB_DEV_OS_FULL_PWR);

				if ((rval = usb_handle_remote_wakeup(dip,
				    USB_REMOTE_WAKEUP_DISABLE)) !=
				    USB_SUCCESS) {
					USB_DPRINTF_L2(DPRINT_MASK_SCSA,
					    scsa2usbp->scsa2usb_log_handle,
					    "disable remote wakeup failed "
					    "(%d)", rval);
				}
			} else {
				mutex_exit(&scsa2usbp->scsa2usb_mutex);
			}

			(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);

			mutex_enter(&scsa2usbp->scsa2usb_mutex);
		}

		if (pm) {
			kmem_free(pm, sizeof (scsa2usb_power_t));
		}

		if (scsa2usbp->scsa2usb_override_str) {
			kmem_free(scsa2usbp->scsa2usb_override_str,
			    strlen(scsa2usbp->scsa2usb_override_str) + 1);
			scsa2usbp->scsa2usb_override_str = NULL;
		}

		/* remove the minor nodes */
		ddi_remove_minor_node(dip, NULL);

		/* Cancel the registered panic callback */
		scsa2usb_panic_callb_fini(scsa2usbp);

		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		mutex_destroy(&scsa2usbp->scsa2usb_mutex);
		cv_destroy(&scsa2usbp->scsa2usb_transport_busy_cv);
	}

	usb_client_detach(scsa2usbp->scsa2usb_dip,
	    scsa2usbp->scsa2usb_dev_data);

	if (scsa2usbp->scsa2usb_ugen_hdl) {
		(void) usb_ugen_detach(scsa2usbp->scsa2usb_ugen_hdl,
		    DDI_DETACH);
		usb_ugen_release_hdl(scsa2usbp->scsa2usb_ugen_hdl);
	}

	usb_free_log_hdl(scsa2usbp->scsa2usb_log_handle);

	ddi_prop_remove_all(dip);

	ddi_soft_state_free(scsa2usb_statep, ddi_get_instance(dip));

	return (USB_SUCCESS);
}


/*
 * scsa2usb_override:
 *	some devices may be attached even though their subclass or
 *	protocol info is not according to spec.
 *	these can be determined by the 'subclass-protocol-override'
 *	property set in the conf file.
 */
static void
scsa2usb_override(scsa2usb_state_t *scsa2usbp)
{
	scsa2usb_ov_t ov;
	char	**override_str = NULL;
	char	*override_str_cpy;
	uint_t	override_str_len, override_str_cpy_len;
	uint_t	i;
	usb_dev_descr_t *descr = scsa2usbp->scsa2usb_dev_data->dev_descr;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	scsa2usbp->scsa2usb_subclass_override =
	    scsa2usbp->scsa2usb_protocol_override = 0;

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, scsa2usbp->scsa2usb_dip,
	    DDI_PROP_DONTPASS, "attribute-override-list",
	    &override_str, &override_str_len) != DDI_PROP_SUCCESS) {

		return;
	}

	/* parse each string in the subclass-protocol-override property */
	for (i = 0; i < override_str_len; i++) {

		USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "override_str[%d] = %s", i, override_str[i]);

		/*
		 * save a copy of the override string for possible
		 * inclusion in soft state later
		 */
		override_str_cpy_len = strlen(override_str[i]) + 1;
		override_str_cpy = kmem_zalloc(override_str_cpy_len, KM_SLEEP);
		(void) strcpy(override_str_cpy, override_str[i]);

		bzero(&ov, sizeof (scsa2usb_ov_t));

		if (scsa2usb_parse_input_str(override_str[i], &ov,
		    scsa2usbp) == USB_FAILURE) {
			kmem_free(override_str_cpy, override_str_cpy_len);
			continue;
		}

		/*
		 * see if subclass/protocol needs to be overridden for device
		 * or if device should not be power managed
		 * if there'a a match, save the override string in soft state
		 */
		if (((descr->idVendor == (uint16_t)ov.vid) || (ov.vid == 0)) &&
		    ((descr->idProduct == (uint16_t)ov.pid) || (ov.pid == 0)) &&
		    ((descr->bcdDevice == (uint16_t)ov.rev) || (ov.rev == 0))) {
			scsa2usbp->scsa2usb_subclass_override = ov.subclass;
			scsa2usbp->scsa2usb_protocol_override = ov.protocol;

			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "vid=0x%x pid=0x%x rev=0x%x subclass=0x%x "
			    "protocol=0x%x "
			    "pmoff=%d fake_removable=%d modesense=%d "
			    "reduced-cmd-support=%d",
			    ov.vid, ov.pid, ov.rev, ov.subclass, ov.protocol,
			    ov.pmoff, ov.fake_removable, ov.no_modesense,
			    ov.reduced_cmd_support);

			if (ov.pmoff) {
				scsa2usbp->scsa2usb_attrs &= ~SCSA2USB_ATTRS_PM;
			}
			if (ov.fake_removable) {
				scsa2usbp->scsa2usb_attrs &=
				    ~SCSA2USB_ATTRS_RMB;
			}
			if (ov.no_modesense) {
				scsa2usbp->scsa2usb_attrs &=
				    ~SCSA2USB_ATTRS_MODE_SENSE;
			}
			if (ov.reduced_cmd_support) {
				scsa2usbp->scsa2usb_attrs &=
				    ~SCSA2USB_ATTRS_REDUCED_CMD;
			}
			scsa2usbp->scsa2usb_override_str = override_str_cpy;
			break;
		} else {
			kmem_free(override_str_cpy, override_str_cpy_len);
		}
	}

	ddi_prop_free(override_str);
}


/*
 * scsa2usb_parse_input_str:
 *	parse one conf file subclass-protocol-override string
 *	return vendor id, product id, revision, subclass, protocol
 *	function return is success or failure
 */
static int
scsa2usb_parse_input_str(char *str, scsa2usb_ov_t *ovp,
    scsa2usb_state_t *scsa2usbp)
{
	char		*input_field, *input_value;
	char		*lasts;
	uint_t		i;
	u_longlong_t	value;

	/* parse all the input pairs in the string */
	for (input_field = scsa2usb_strtok_r(str, "=", &lasts);
	    input_field != NULL;
	    input_field = scsa2usb_strtok_r(lasts, "=", &lasts)) {

		if ((input_value = scsa2usb_strtok_r(lasts, " ", &lasts)) ==
		    NULL) {
			scsa2usb_override_error("format", scsa2usbp);

			return (USB_FAILURE);
		}
		/* if input value is a 'don't care', skip to the next pair */
		if (strcmp(input_value, "*") == 0) {
			continue;
		}
		if (strcasecmp(input_field, "vid") == 0) {
			if (kobj_getvalue(input_value, &value) == -1) {
				scsa2usb_override_error("vendor id", scsa2usbp);

				return (USB_FAILURE);
			}
			ovp->vid = (int)value;
		} else if (strcasecmp(input_field, "pid") == 0) {
			if (kobj_getvalue(input_value, &value) == -1) {
				scsa2usb_override_error("product id",
				    scsa2usbp);

				return (USB_FAILURE);
			}
			ovp->pid = (int)value;
		} else if (strcasecmp(input_field, "rev") == 0) {
			if (kobj_getvalue(input_value, &value) == -1) {
				scsa2usb_override_error("revision id",
				    scsa2usbp);

				return (USB_FAILURE);
			}
			ovp->rev = (int)value;
		} else if (strcasecmp(input_field, "subclass") == 0) {
			for (i = 0; i < N_SCSA2USB_SUBC_OVERRIDE; i++) {
				if (strcasecmp(input_value,
				    scsa2usb_subclass[i].name) == 0) {
					ovp->subclass =
					    scsa2usb_subclass[i].value;
					break;
				}
			}
			if (ovp->subclass == 0) {
				scsa2usb_override_error("subclass", scsa2usbp);

				return (USB_FAILURE);
			}
		} else if (strcasecmp(input_field, "protocol") == 0) {
			for (i = 0; i < N_SCSA2USB_PROT_OVERRIDE; i++) {
				if (strcasecmp(input_value,
				    scsa2usb_protocol[i].name) == 0) {
					ovp->protocol =
					    scsa2usb_protocol[i].value;
					break;
				}
			}
			if (ovp->protocol == 0) {
				scsa2usb_override_error("protocol", scsa2usbp);

				return (USB_FAILURE);
			}
		} else if (strcasecmp(input_field, "pm") == 0) {
			if (strcasecmp(input_value, "off") == 0) {
				ovp->pmoff = 1;
				break;
			} else {
				scsa2usb_override_error("pm", scsa2usbp);

				return (USB_FAILURE);
			}
		} else if (strcasecmp(input_field, "removable") == 0) {
			if (strcasecmp(input_value, "true") == 0) {
				ovp->fake_removable = 1;
				break;
			} else {
				scsa2usb_override_error("removable", scsa2usbp);

				return (USB_FAILURE);
			}
		} else if (strcasecmp(input_field, "modesense") == 0) {
			if (strcasecmp(input_value, "false") == 0) {
				ovp->no_modesense = 1;
				break;
			} else {
				scsa2usb_override_error("modesense",
				    scsa2usbp);

				return (USB_FAILURE);
			}
		} else if (strcasecmp(input_field,
		    "reduced-cmd-support") == 0) {
			if (strcasecmp(input_value, "true") == 0) {
				ovp->reduced_cmd_support = 1;
				break;
			} else {
				scsa2usb_override_error(
				    "reduced-cmd-support", scsa2usbp);

				return (USB_FAILURE);
			}
		} else {
			scsa2usb_override_error(input_field, scsa2usbp);

			return (USB_FAILURE);
		}
	}

	return (USB_SUCCESS);
}


/*
 * scsa2usb_override_error:
 *	print an error message if conf file string is bad format
 */
static void
scsa2usb_override_error(char *input_field, scsa2usb_state_t *scsa2usbp)
{
	USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "invalid %s in scsa2usb.conf file entry", input_field);
}

/*
 * scsa2usb_strtok_r:
 *	parse a list of tokens
 */
static char *
scsa2usb_strtok_r(char *p, char *sep, char **lasts)
{
	char	*e;
	char	*tok = NULL;

	if (p == 0 || *p == 0) {

		return (NULL);
	}

	e = p+strlen(p);

	do {
		if (strchr(sep, *p) != NULL) {
			if (tok != NULL) {
				*p = 0;
				*lasts = p+1;

				return (tok);
			}
		} else if (tok == NULL) {
			tok = p;
		}
	} while (++p < e);

	*lasts = NULL;

	return (tok);
}


/*
 * scsa2usb_validate_attrs:
 *	many devices have BO/CB/CBI protocol support issues.
 *	use vendor/product info to reset the
 *	individual erroneous attributes
 *
 * NOTE: we look at only device at a time (at attach time)
 */
static void
scsa2usb_validate_attrs(scsa2usb_state_t *scsa2usbp)
{
	int i, mask;
	usb_dev_descr_t *desc = scsa2usbp->scsa2usb_dev_data->dev_descr;

	if (!SCSA2USB_IS_BULK_ONLY(scsa2usbp)) {
		scsa2usbp->scsa2usb_attrs &= ~SCSA2USB_ATTRS_GET_LUN;
	}

	/* determine if this device is on the blacklist */
	for (i = 0; i < N_SCSA2USB_BLACKLIST; i++) {
		if ((scsa2usb_blacklist[i].idVendor == desc->idVendor) &&
		    ((scsa2usb_blacklist[i].idProduct == desc->idProduct) ||
		    (scsa2usb_blacklist[i].idProduct == X))) {
			scsa2usbp->scsa2usb_attrs &=
			    ~(scsa2usb_blacklist[i].attributes);
			break;
		}
	}

	/*
	 * Mitsumi's CD-RW drives subclass isn't UFI.
	 * But they support UFI command-set (this code ensures that)
	 * NOTE: This is a special case, and is being called out so.
	 */
	if (desc->idVendor == MS_MITSUMI_VID) {
		mask = scsa2usbp->scsa2usb_cmd_protocol & SCSA2USB_CMDSET_MASK;
		if (mask) {
			scsa2usbp->scsa2usb_cmd_protocol &= ~mask;
		}
		scsa2usbp->scsa2usb_cmd_protocol |= SCSA2USB_UFI_CMDSET;
	}

	if (scsa2usbp->scsa2usb_attrs != SCSA2USB_ALL_ATTRS) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb attributes modified: 0x%x",
		    scsa2usbp->scsa2usb_attrs);
	}
}


/*
 * scsa2usb_create_luns:
 *	check the number of luns but continue if the check fails,
 *	create child nodes for each lun
 */
static void
scsa2usb_create_luns(scsa2usb_state_t *scsa2usbp)
{
	int		lun, rval;
	char		*compatible[MAX_COMPAT_NAMES];	/* compatible names */
	dev_info_t	*cdip;
	uchar_t		dtype;
	char		*node_name;
	char		*driver_name = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_create_luns:");

	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	/* Set n_luns to 1 by default (for floppies and other devices) */
	scsa2usbp->scsa2usb_n_luns = 1;

	/*
	 * Check if there are any device out there which don't
	 * support the GET_MAX_LUN command. If so, don't issue
	 * control request to them.
	 */
	if ((scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_GET_LUN) == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "get_max_lun cmd not supported");
	} else {
		if (SCSA2USB_IS_BULK_ONLY(scsa2usbp)) {
			scsa2usbp->scsa2usb_n_luns =
			    scsa2usb_bulk_only_get_max_lun(scsa2usbp);
		}
	}

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_create_luns: %d luns found", scsa2usbp->scsa2usb_n_luns);

	/*
	 * create disk child for each lun
	 */
	for (lun = 0; lun < scsa2usbp->scsa2usb_n_luns; lun++) {
		ASSERT(scsa2usbp->scsa2usb_lun_dip[lun] == NULL);

		/* do an inquiry to get the dtype of this lun */
		scsa2usb_do_inquiry(scsa2usbp, 0, lun);

		dtype = scsa2usbp->scsa2usb_lun_inquiry[lun].
		    inq_dtype & DTYPE_MASK;

		USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "dtype[%d]=0x%x", lun, dtype);

		driver_name = NULL;

		switch (dtype) {
		case DTYPE_DIRECT:
		case DTYPE_RODIRECT:
		case DTYPE_OPTICAL:
			node_name = "disk";
			driver_name = "sd";

			break;
		case DTYPE_SEQUENTIAL:
			node_name = "tape";
			driver_name = "st";

			break;
		case DTYPE_PRINTER:
			node_name = "printer";

			break;
		case DTYPE_PROCESSOR:
			node_name = "processor";

			break;
		case DTYPE_WORM:
			node_name = "worm";

			break;
		case DTYPE_SCANNER:
			node_name = "scanner";

			break;
		case DTYPE_CHANGER:
			node_name = "changer";

			break;
		case DTYPE_COMM:
			node_name = "comm";

			break;
		case DTYPE_ARRAY_CTRL:
			node_name = "array_ctrl";

			break;
		case DTYPE_ESI:
			node_name = "esi";
			driver_name = "ses";

			break;
		default:
			node_name = "generic";

			break;
		}

		if (driver_name) {
			compatible[0] = driver_name;
		}

		ndi_devi_alloc_sleep(scsa2usbp->scsa2usb_dip, node_name,
		    (pnode_t)DEVI_SID_NODEID, &cdip);

		/* attach target & lun properties */
		rval = ndi_prop_update_int(DDI_DEV_T_NONE, cdip, "target", 0);
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "ndi_prop_update_int target failed %d", rval);
			(void) ndi_devi_free(cdip);
			continue;
		}

		rval = ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip,
		    "hotpluggable");
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "ndi_prop_create_boolean hotpluggable failed %d",
			    rval);
			ddi_prop_remove_all(cdip);
			(void) ndi_devi_free(cdip);
			continue;
		}
		/*
		 * Some devices don't support LOG SENSE, so tells
		 * sd driver not to send this command.
		 */
		rval = ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    "pm-capable", 1);
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "ndi_prop_update_int pm-capable failed %d", rval);
			ddi_prop_remove_all(cdip);
			(void) ndi_devi_free(cdip);
			continue;
		}

		rval = ndi_prop_update_int(DDI_DEV_T_NONE, cdip, "lun", lun);
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "ndi_prop_update_int lun failed %d", rval);
			ddi_prop_remove_all(cdip);
			(void) ndi_devi_free(cdip);
			continue;
		}

		if (driver_name) {
			rval = ndi_prop_update_string_array(DDI_DEV_T_NONE,
			    cdip, "compatible", (char **)compatible,
			    MAX_COMPAT_NAMES);
			if (rval != DDI_PROP_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_SCSA,
				    scsa2usbp->scsa2usb_log_handle,
				    "ndi_prop_update_string_array failed %d",
				    rval);
				ddi_prop_remove_all(cdip);
				(void) ndi_devi_free(cdip);
				continue;
			}
		}

		/*
		 * add property "usb" so we always verify that it is our child
		 */
		rval = ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip, "usb");
		if (rval != DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "ndi_prop_create_boolean failed %d", rval);
			ddi_prop_remove_all(cdip);
			(void) ndi_devi_free(cdip);
			continue;
		}

		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		(void) ddi_initchild(scsa2usbp->scsa2usb_dip, cdip);
		mutex_enter(&scsa2usbp->scsa2usb_mutex);

		usba_set_usba_device(cdip,
		    usba_get_usba_device(scsa2usbp->scsa2usb_dip));
	}
	mutex_exit(&scsa2usbp->scsa2usb_mutex);
}


/*
 * scsa2usb_is_usb:
 *	scsa2usb gets called for all possible sd children.
 *	we can only accept usb children
 */
static int
scsa2usb_is_usb(dev_info_t *dip)
{
	if (dip) {
		return (ddi_prop_exists(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "usb"));
	}
	return (0);
}


/*
 * Panic Stuff
 * scsa2usb_panic_callb_init:
 *	initialize PANIC callb and free allocated resources
 */
static void
scsa2usb_panic_callb_init(scsa2usb_state_t *scsa2usbp)
{
	/*
	 * In case the system panics, the sync command flushes
	 * dirty FS pages or buffers. This would cause a hang
	 * in USB.
	 * The reason for the failure is that we enter
	 * polled mode (interrupts disabled) and HCD gets stuck
	 * trying to execute bulk requests
	 * The panic_callback registered below provides a warning
	 * that a panic has occurred and from that point onwards, we
	 * complete each request successfully and immediately. This
	 * will fake successful syncing so at least the rest of the
	 * filesystems complete syncing.
	 */
	scsa2usbp->scsa2usb_panic_info =
	    kmem_zalloc(sizeof (scsa2usb_cpr_t), KM_SLEEP);
	mutex_init(&scsa2usbp->scsa2usb_panic_info->lockp,
	    NULL, MUTEX_DRIVER,
	    scsa2usbp->scsa2usb_dev_data->dev_iblock_cookie);
	scsa2usbp->scsa2usb_panic_info->statep = scsa2usbp;
	scsa2usbp->scsa2usb_panic_info->cpr.cc_lockp =
	    &scsa2usbp->scsa2usb_panic_info->lockp;
	scsa2usbp->scsa2usb_panic_info->cpr.cc_id =
	    callb_add(scsa2usb_panic_callb,
	    (void *)scsa2usbp->scsa2usb_panic_info,
	    CB_CL_PANIC, "scsa2usb");
}


/*
 * scsa2usb_panic_callb_fini:
 *	cancel out PANIC callb and free allocated resources
 */
static void
scsa2usb_panic_callb_fini(scsa2usb_state_t *scsa2usbp)
{
	if (scsa2usbp->scsa2usb_panic_info) {
		SCSA2USB_CANCEL_CB(scsa2usbp->scsa2usb_panic_info->cpr.cc_id);
		mutex_destroy(&scsa2usbp->scsa2usb_panic_info->lockp);
		scsa2usbp->scsa2usb_panic_info->statep = NULL;
		kmem_free(scsa2usbp->scsa2usb_panic_info,
		    sizeof (scsa2usb_cpr_t));
		scsa2usbp->scsa2usb_panic_info = NULL;
	}
}


/*
 * scsa2usb_panic_callb:
 *	This routine is called when there is a system panic.
 */
/* ARGSUSED */
static boolean_t
scsa2usb_panic_callb(void *arg, int code)
{
	scsa2usb_cpr_t *cpr_infop;
	scsa2usb_state_t *scsa2usbp;
	uint_t		lun;

	_NOTE(NO_COMPETING_THREADS_NOW);
	cpr_infop = (scsa2usb_cpr_t *)arg;
	scsa2usbp = (scsa2usb_state_t *)cpr_infop->statep;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_panic_callb: code=%d", code);

	/*
	 * If we return error here, "sd" prints lots of error
	 * messages and could retry the same pkt over and over again.
	 * The sync recovery isn't "smooth" in that case. By faking
	 * a success return, instead,  we force sync to complete.
	 */
	if (scsa2usbp->scsa2usb_cur_pkt) {
		/*
		 * Do not print the "no sync" warning here. it will then be
		 * displayed before we actually start syncing. Also we don't
		 * replace this code with a call to scsa2usb_pkt_completion().
		 * NOTE: mutexes are disabled during panic.
		 */
		scsa2usbp->scsa2usb_cur_pkt->pkt_reason = CMD_CMPLT;
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		scsa2usb_pkt_completion(scsa2usbp, scsa2usbp->scsa2usb_cur_pkt);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
	}

	/* get rid of waitQ */
	for (lun = 0; lun < SCSA2USB_MAX_LUNS; lun++) {
		scsa2usb_flush_waitQ(scsa2usbp, lun, CMD_CMPLT);
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	return (B_TRUE);
}

/*
 * scsa2usb_cpr_suspend
 *	determine if the device's state can be changed to SUSPENDED
 *	close pipes if there is no activity
 */
/* ARGSUSED */
static int
scsa2usb_cpr_suspend(dev_info_t *dip)
{
	scsa2usb_state_t *scsa2usbp;
	int	prev_state;
	int	rval = USB_FAILURE;

	scsa2usbp = ddi_get_soft_state(scsa2usb_statep, ddi_get_instance(dip));

	ASSERT(scsa2usbp != NULL);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cpr_suspend:");

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	switch (scsa2usbp->scsa2usb_dev_state) {
	case USB_DEV_ONLINE:
	case USB_DEV_PWRED_DOWN:
	case USB_DEV_DISCONNECTED:
		prev_state = scsa2usbp->scsa2usb_dev_state;
		scsa2usbp->scsa2usb_dev_state = USB_DEV_SUSPENDED;

		/*
		 * If the device is busy, we cannot suspend
		 */
		if (SCSA2USB_BUSY(scsa2usbp)) {
			USB_DPRINTF_L3(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "scsa2usb_cpr_suspend: I/O active");

			/* fall back to previous state */
			scsa2usbp->scsa2usb_dev_state = prev_state;
		} else {
			rval = USB_SUCCESS;
		}

		break;
	case USB_DEV_SUSPENDED:
	default:
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_cpr_suspend: Illegal dev state: %d",
		    scsa2usbp->scsa2usb_dev_state);

		break;
	}
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	if ((rval == USB_SUCCESS) && scsa2usbp->scsa2usb_ugen_hdl) {
		rval = usb_ugen_detach(scsa2usbp->scsa2usb_ugen_hdl,
		    DDI_SUSPEND);
	}

	return (rval);
}


/*
 * scsa2usb_cpr_resume:
 *	restore device's state
 */
static void
scsa2usb_cpr_resume(dev_info_t *dip)
{
	scsa2usb_state_t *scsa2usbp =
	    ddi_get_soft_state(scsa2usb_statep, ddi_get_instance(dip));

	ASSERT(scsa2usbp != NULL);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cpr_resume: dip = 0x%p", (void *)dip);

	scsa2usb_restore_device_state(dip, scsa2usbp);

	if (scsa2usbp->scsa2usb_ugen_hdl) {
		(void) usb_ugen_attach(scsa2usbp->scsa2usb_ugen_hdl,
		    DDI_RESUME);
	}
}


/*
 * scsa2usb_restore_device_state:
 *	- raise the device's power
 *	- reopen all the pipes
 */
static void
scsa2usb_restore_device_state(dev_info_t *dip, scsa2usb_state_t *scsa2usbp)
{
	uint_t	prev_state;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_restore_device_state:");

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	prev_state = scsa2usbp->scsa2usb_dev_state;

	scsa2usb_raise_power(scsa2usbp);

	ASSERT((prev_state == USB_DEV_DISCONNECTED) ||
	    (prev_state == USB_DEV_SUSPENDED));

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	/* Check for the same device */
	if (usb_check_same_device(dip, scsa2usbp->scsa2usb_log_handle,
	    USB_LOG_L0, DPRINT_MASK_ALL, USB_CHK_ALL, NULL) != USB_SUCCESS) {

		/* change the flags to active */
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		scsa2usbp->scsa2usb_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		scsa2usb_pm_idle_component(scsa2usbp);

		return;
	}

	/*
	 * if the device had remote wakeup earlier,
	 * enable it again
	 */
	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	if (scsa2usbp->scsa2usb_pm &&
	    scsa2usbp->scsa2usb_pm->scsa2usb_wakeup_enabled) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		(void) usb_handle_remote_wakeup(scsa2usbp->scsa2usb_dip,
		    USB_REMOTE_WAKEUP_ENABLE);
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
	}

	scsa2usbp->scsa2usb_dev_state = USB_DEV_ONLINE;
	scsa2usbp->scsa2usb_pkt_state = SCSA2USB_PKT_NONE;
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	scsa2usb_pm_idle_component(scsa2usbp);
}


/*
 * SCSA entry points:
 *
 * scsa2usb_scsi_tgt_probe:
 * scsa functions are exported by means of the transport table
 * Issue a probe to get the inquiry data.
 */
/* ARGSUSED */
static int
scsa2usb_scsi_tgt_probe(struct scsi_device *sd, int (*waitfunc)(void))
{
	scsi_hba_tran_t *tran;
	scsa2usb_state_t *scsa2usbp;
	dev_info_t *dip = ddi_get_parent(sd->sd_dev);
	int	rval;

	ASSERT(dip);

	tran = ddi_get_driver_private(dip);
	ASSERT(tran != NULL);
	scsa2usbp = (scsa2usb_state_t *)tran->tran_hba_private;
	ASSERT(scsa2usbp);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_tgt_probe:");

	/* if device is disconnected (ie. pipes closed), fail immediately */
	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	if (!(SCSA2USB_DEVICE_ACCESS_OK(scsa2usbp))) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (SCSIPROBE_FAILURE);
	}
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_tgt_probe: scsi_device = 0x%p", (void *)sd);

	if ((rval = scsi_hba_probe(sd, waitfunc)) == SCSIPROBE_EXISTS) {
		/*
		 * respect the removable bit on all USB storage devices
		 * unless overridden by a scsa2usb.conf entry
		 */
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_RMB)) {
			_NOTE(SCHEME_PROTECTS_DATA("unshared", scsi_inquiry))
			sd->sd_inq->inq_rmb = 1;
		}
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
	}

	return (rval);
}


/*
 * scsa2usb_scsi_tgt_init:
 *	check whether we created this child ourselves
 */
/* ARGSUSED */
static int
scsa2usb_scsi_tgt_init(dev_info_t *dip, dev_info_t *cdip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	scsa2usb_state_t *scsa2usbp = (scsa2usb_state_t *)
	    tran->tran_hba_private;
	int lun;
	int t_len = sizeof (lun);

	if (ddi_prop_op(DDI_DEV_T_ANY, cdip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS|DDI_PROP_CANSLEEP, "lun", (caddr_t)&lun,
	    &t_len) != DDI_PROP_SUCCESS) {

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_tgt_init: %s, lun%d", ddi_driver_name(cdip), lun);

	/* is this a child we created? */
	if (scsa2usb_is_usb(cdip) == 0) {

		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_scsi_tgt_init: new child %s%d",
		    ddi_driver_name(cdip), ddi_get_instance(cdip));

		/*
		 * add property "usb" so we can always verify that it
		 * is our child
		 */
		if (ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip, "usb") !=
		    DDI_PROP_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "ndi_prop_create_boolean failed");

			return (DDI_FAILURE);
		}

		usba_set_usba_device(cdip,
		    usba_get_usba_device(scsa2usbp->scsa2usb_dip));

		/*
		 * we don't store this dip in scsa2usb_lun_dip, there
		 * might be multiple dips for the same device
		 */

		return (DDI_SUCCESS);
	}

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	if ((lun >= scsa2usbp->scsa2usb_n_luns) ||
	    (scsa2usbp->scsa2usb_lun_dip[lun] != NULL)) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (DDI_FAILURE);
	}

	scsa2usbp->scsa2usb_lun_dip[lun] = cdip;
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	return (DDI_SUCCESS);
}


/*
 * scsa2usb_scsi_tgt_free:
 */
/* ARGSUSED */
static void
scsa2usb_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *cdip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	scsa2usb_state_t *scsa2usbp = (scsa2usb_state_t *)
	    tran->tran_hba_private;
	int lun;
	int t_len = sizeof (lun);

	/* is this our child? */
	if (scsa2usb_is_usb(cdip) == 0) {

		return;
	}

	if (ddi_prop_op(DDI_DEV_T_ANY, cdip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS|DDI_PROP_CANSLEEP, "lun", (caddr_t)&lun,
	    &t_len) != DDI_PROP_SUCCESS) {

		return;
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_tgt_free: %s lun%d", ddi_driver_name(cdip), lun);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	if (lun < scsa2usbp->scsa2usb_n_luns) {
		if (scsa2usbp->scsa2usb_lun_dip[lun] == cdip) {
			scsa2usbp->scsa2usb_lun_dip[lun] = NULL;
		}
	}
	mutex_exit(&scsa2usbp->scsa2usb_mutex);
}


/*
 * bus enumeration entry points
 */
static int
scsa2usb_scsi_bus_config(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child)
{
	int	circ;
	int	rval;

	scsa2usb_state_t *scsa2usbp =
	    ddi_get_soft_state(scsa2usb_statep, ddi_get_instance(dip));

	ASSERT(scsa2usbp != NULL);

	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_bus_config: op=%d", op);

	if (scsa2usb_scsi_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	ndi_devi_enter(dip, &circ);
	/* create children if necessary */
	if (DEVI(dip)->devi_child == NULL) {
		scsa2usb_create_luns(scsa2usbp);
	}

	rval = ndi_busop_bus_config(dip, flag, op, arg, child, 0);

	ndi_devi_exit(dip, circ);

	return (rval);
}


static int
scsa2usb_scsi_bus_unconfig(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg)
{
	scsa2usb_state_t *scsa2usbp =
	    ddi_get_soft_state(scsa2usb_statep, ddi_get_instance(dip));

	int		circular_count;
	int		rval = NDI_SUCCESS;
	uint_t		save_flag = flag;

	ASSERT(scsa2usbp != NULL);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_bus_unconfig: op=%d", op);

	if (scsa2usb_scsi_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	/*
	 * first offline and if offlining successful, then
	 * remove children
	 */
	if (op == BUS_UNCONFIG_ALL) {
		flag &= ~(NDI_DEVI_REMOVE | NDI_UNCONFIG);
	}

	ndi_devi_enter(dip, &circular_count);
	rval = ndi_busop_bus_unconfig(dip, flag, op, arg);

	/*
	 * If unconfig is successful and not part of modunload
	 * daemon, attempt to remove children.
	 */
	if (op == BUS_UNCONFIG_ALL && rval == NDI_SUCCESS &&
	    (flag & NDI_AUTODETACH) == 0) {
		flag |= NDI_DEVI_REMOVE;
		rval = ndi_busop_bus_unconfig(dip, flag, op, arg);
	}
	ndi_devi_exit(dip, circular_count);

	if ((rval != NDI_SUCCESS) && (op == BUS_UNCONFIG_ALL) &&
	    (save_flag & NDI_DEVI_REMOVE)) {
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		if (scsa2usbp->scsa2usb_warning_given != B_TRUE) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "Disconnected device was busy, "
			    "please reconnect.");
			scsa2usbp->scsa2usb_warning_given = B_TRUE;
		}
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_bus_unconfig: rval=%d", rval);

	return (rval);
}


/*
 * scsa2usb_scsi_init_pkt:
 *	Set up the scsi_pkt for transport. Also initialize
 *	scsa2usb_cmd struct for the transport.
 *	NOTE: We do not do any DMA setup here as USBA framework
 *	does that for us.
 */
static struct scsi_pkt *
scsa2usb_scsi_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg)
{
	scsa2usb_cmd_t	 *cmd;
	scsa2usb_state_t *scsa2usbp;
	struct scsi_pkt	 *in_pkt = pkt;

	ASSERT(callback == NULL_FUNC || callback == SLEEP_FUNC);

	scsa2usbp = (scsa2usb_state_t *)ADDR2SCSA2USB(ap);

	/* Print sync message */
	if (ddi_in_panic()) {
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		SCSA2USB_PRINT_SYNC_MSG(scsa2usb_sync_message, scsa2usbp);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		/* continue so caller will not hang or complain */
	}

	/* allocate a pkt, if none already allocated */
	if (pkt == NULL) {
		if (statuslen < sizeof (struct scsi_arq_status)) {
			statuslen = sizeof (struct scsi_arq_status);
		}

		pkt = scsi_hba_pkt_alloc(scsa2usbp->scsa2usb_dip, ap, cmdlen,
		    statuslen, tgtlen, sizeof (scsa2usb_cmd_t),
		    callback, arg);
		if (pkt == NULL) {

			return (NULL);
		}

		cmd = PKT2CMD(pkt);
		cmd->cmd_pkt	= pkt; /* back link to pkt */
		cmd->cmd_scblen	= statuslen;
		cmd->cmd_cdblen	= (uchar_t)cmdlen;

		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		cmd->cmd_tag	= scsa2usbp->scsa2usb_tag++;
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		cmd->cmd_bp	= bp;
		/*
		 * The buffer size of cmd->cmd_scb is constrained
		 * to sizeof (struct scsi_arq_status), if the scblen
		 * is bigger than that, we use pkt->pkt_scbp directly.
		 */
		if (cmd->cmd_scblen == sizeof (struct scsi_arq_status)) {
			pkt->pkt_scbp = (opaque_t)&cmd->cmd_scb;
		}

		usba_init_list(&cmd->cmd_waitQ, (usb_opaque_t)cmd,
		    scsa2usbp->scsa2usb_dev_data->dev_iblock_cookie);
	} else {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb: pkt != NULL");

		/* nothing to do */
	}

	if (bp && (bp->b_bcount != 0)) {
		if ((bp_mapin_common(bp, (callback == SLEEP_FUNC) ?
		    VM_SLEEP : VM_NOSLEEP)) == NULL) {
			if (pkt != in_pkt) {
				scsi_hba_pkt_free(ap, pkt);
			}

			return (NULL);
		}

		USB_DPRINTF_L3(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_scsi_init_pkt: mapped in 0x%p, addr=0x%p",
		    (void *)bp, (void *)bp->b_un.b_addr);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_init_pkt: ap = 0x%p pkt: 0x%p\n\t"
	    "bp = 0x%p cmdlen = %x stlen = 0x%x tlen = 0x%x flags = 0x%x",
	    (void *)ap, (void *)pkt, (void *)bp, cmdlen, statuslen,
	    tgtlen, flags);

	return (pkt);
}


/*
 * scsa2usb_scsi_destroy_pkt:
 *	We are done with the packet. Get rid of it.
 */
static void
scsa2usb_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsa2usb_cmd_t *cmd = PKT2CMD(pkt);
	scsa2usb_state_t *scsa2usbp = ADDR2SCSA2USB(ap);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_destroy_pkt: pkt=0x%p", (void *)pkt);

	usba_destroy_list(&cmd->cmd_waitQ);
	scsi_hba_pkt_free(ap, pkt);
}


/*
 * scsa2usb_scsi_start:
 *	For each command being issued, build up the CDB
 *	and call scsi_transport to issue the command. This
 *	function is based on the assumption that USB allows
 *	a subset of SCSI commands. Other SCSI commands we fail.
 */
static int
scsa2usb_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsa2usb_cmd_t		*cmd;
	scsa2usb_state_t	*scsa2usbp = ADDR2SCSA2USB(ap);
	uint_t			lun = ap->a_lun;

	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	cmd = PKT2CMD(pkt);
	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_start:\n\t"
	    "bp: 0x%p ap: 0x%p pkt: 0x%p flag: 0x%x time: 0x%x\n\tcdb0: 0x%x "
	    "dev_state: 0x%x pkt_state: 0x%x flags: 0x%x pipe_state: 0x%x",
	    (void *)cmd->cmd_bp, (void *)ap, (void *)pkt, pkt->pkt_flags,
	    pkt->pkt_time, pkt->pkt_cdbp[0], scsa2usbp->scsa2usb_dev_state,
	    scsa2usbp->scsa2usb_pkt_state, scsa2usbp->scsa2usb_flags,
	    scsa2usbp->scsa2usb_pipe_state);

	if (pkt->pkt_time == 0) {
		USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "pkt submitted with 0 timeout which may cause indefinite "
		    "hangs");
	}

	/*
	 * if we are in panic, we are in polled mode, so we can just
	 * accept the request, drop it and return
	 * if we fail this request, the rest of the file systems do not
	 * get synced
	 */
	if (ddi_in_panic()) {
		extern int do_polled_io;

		ASSERT(do_polled_io);
		scsa2usb_prepare_pkt(scsa2usbp, pkt);
		SCSA2USB_PRINT_SYNC_MSG(scsa2usb_sync_message, scsa2usbp);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (TRAN_ACCEPT);
	}

	/* we cannot do polling, this should not happen */
	if (pkt->pkt_flags & FLAG_NOINTR) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "NOINTR packet: opcode = 0%x", pkt->pkt_cdbp[0]);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (TRAN_BADPKT);
	}

	/* prepare packet */
	scsa2usb_prepare_pkt(scsa2usbp, pkt);

	/* just queue up the requests in the waitQ if below max */
	if (usba_list_entry_count(&scsa2usbp->scsa2usb_waitQ[lun]) >
	    SCSA2USB_MAX_REQ_PER_LUN) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_scsi_start: limit (%d) exceeded",
		    SCSA2USB_MAX_REQ_PER_LUN);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (TRAN_BUSY);
	}

	usba_add_to_list(&scsa2usbp->scsa2usb_waitQ[lun], &cmd->cmd_waitQ);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_work_thread_id=0x%p, count=%d, lun=%d",
	    (void *)scsa2usbp->scsa2usb_work_thread_id,
	    usba_list_entry_count(&scsa2usbp->scsa2usb_waitQ[lun]), lun);

	/* fire up a thread to start executing the protocol */
	if (scsa2usbp->scsa2usb_work_thread_id == 0) {
		if ((usb_async_req(scsa2usbp->scsa2usb_dip,
		    scsa2usb_work_thread,
		    (void *)scsa2usbp, USB_FLAGS_SLEEP)) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "no work thread started");

			if (usba_rm_from_list(
			    &scsa2usbp->scsa2usb_waitQ[lun],
			    &cmd->cmd_waitQ) == USB_SUCCESS) {
				mutex_exit(&scsa2usbp->scsa2usb_mutex);

				return (TRAN_BUSY);
			} else {

				mutex_exit(&scsa2usbp->scsa2usb_mutex);

				return (TRAN_ACCEPT);
			}
		}
		scsa2usbp->scsa2usb_work_thread_id = (kthread_t *)1;
	}

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	return (TRAN_ACCEPT);
}


/*
 * scsa2usb_scsi_abort:
 *	Issue SCSI abort command. This function is a NOP.
 */
/* ARGSUSED */
static int
scsa2usb_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsa2usb_state_t *scsa2usbp = (scsa2usb_state_t *)ADDR2SCSA2USB(ap);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_abort: pkt = %p", (void *)pkt);

	/* if device is disconnected (ie. pipes closed), fail immediately */
	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	if (!(SCSA2USB_DEVICE_ACCESS_OK(scsa2usbp))) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (0);
	}

	/* flush waitQ if target and lun match */
	if ((ap->a_target == pkt->pkt_address.a_target) &&
	    (ap->a_lun == pkt->pkt_address.a_lun)) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		scsa2usb_flush_waitQ(scsa2usbp, ap->a_lun, CMD_ABORTED);
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
	}
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	return (0);
}


/*
 * scsa2usb_scsi_reset:
 *	device reset may turn the device into a brick and bus reset
 *	is not applicable.
 *	just flush the waitQ
 *	We return success, always.
 */
/* ARGSUSED */
static int
scsa2usb_scsi_reset(struct scsi_address *ap, int level)
{
	scsa2usb_state_t *scsa2usbp = (scsa2usb_state_t *)ADDR2SCSA2USB(ap);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_reset: ap = 0x%p, level = %d", (void *)ap, level);

	/* flush waitQ */
	scsa2usb_flush_waitQ(scsa2usbp, ap->a_lun, CMD_RESET);

	return (1);
}


/*
 * scsa2usb_scsi_getcap:
 *	Get SCSI capabilities.
 */
/* ARGSUSED */
static int
scsa2usb_scsi_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int rval = -1;
	uint_t cidx;
	size_t dev_bsize_cap;
	scsa2usb_state_t *scsa2usbp = (scsa2usb_state_t *)ADDR2SCSA2USB(ap);
	ASSERT(scsa2usbp);

	if (cap == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_scsi_getcap: invalid arg, "
		    "cap = 0x%p whom = %d", (void *)cap, whom);

		return (rval);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_getcap: cap = %s", cap);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	/* if device is disconnected (ie. pipes closed), fail immediately */
	if (!(SCSA2USB_DEVICE_ACCESS_OK(scsa2usbp))) {

		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (rval);
	}

	cidx =	scsi_hba_lookup_capstr(cap);
	switch (cidx) {
	case SCSI_CAP_GEOMETRY:
		/* Just check and fail immediately if zero, rarely happens */
		if (scsa2usbp->scsa2usb_secsz[ap->a_lun] == 0) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "scsa2usb_scsi_getcap failed:"
			    "scsa2usbp->scsa2usb_secsz[ap->a_lun] == 0");
			mutex_exit(&scsa2usbp->scsa2usb_mutex);

			return (rval);
		}

		dev_bsize_cap = scsa2usbp->scsa2usb_totalsec[ap->a_lun];

		if (scsa2usbp->scsa2usb_secsz[ap->a_lun] > DEV_BSIZE) {
			dev_bsize_cap *=
			    scsa2usbp->scsa2usb_secsz[ap->a_lun] / DEV_BSIZE;
		} else if (scsa2usbp->scsa2usb_secsz[ap->a_lun] <
		    DEV_BSIZE) {
			dev_bsize_cap /=
			    DEV_BSIZE / scsa2usbp->scsa2usb_secsz[ap->a_lun];
		}

		if (dev_bsize_cap < 65536 * 2 * 18) {		/* < ~1GB */
			/* unlabeled floppy, 18k per cylinder */
			rval = ((2 << 16) | 18);
		} else if (dev_bsize_cap < 65536 * 64 * 32) {	/* < 64GB */
			/* 1024k per cylinder */
			rval = ((64 << 16) | 32);
		} else if (dev_bsize_cap < 65536 * 255 * 63) {	/* < ~500GB */
			/* ~8m per cylinder */
			rval = ((255 << 16) | 63);
		} else {					/* .. 8TB */
			/* 64m per cylinder */
			rval = ((512 << 16) | 256);
		}
		break;

	case SCSI_CAP_DMA_MAX:
		rval = scsa2usbp->scsa2usb_max_bulk_xfer_size;
		break;
	case SCSI_CAP_SCSI_VERSION:
		rval = SCSI_VERSION_2;
		break;
	case SCSI_CAP_INTERCONNECT_TYPE:
		rval = INTERCONNECT_USB;
		break;
	case SCSI_CAP_ARQ:
		/* FALLTHRU */
	case SCSI_CAP_UNTAGGED_QING:
		rval = 1;
		break;
	default:
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_scsi_getcap: unsupported cap = %s", cap);
		break;
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_getcap: cap = %s, returned = %d", cap, rval);

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	return (rval);
}


/*
 * scsa2usb_scsi_setcap:
 *	Set SCSI capabilities.
 */
/* ARGSUSED */
static int
scsa2usb_scsi_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int rval = -1; /* default is cap undefined */
	uint_t cidx;
	scsa2usb_state_t *scsa2usbp = (scsa2usb_state_t *)ADDR2SCSA2USB(ap);
	ASSERT(scsa2usbp);

	if (cap == NULL || whom == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_scsi_setcap: invalid arg");

		return (rval);
	}

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	/* if device is disconnected (ie. pipes closed), fail immediately */
	if (!(SCSA2USB_DEVICE_ACCESS_OK(scsa2usbp))) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (rval);
	}

	cidx =	scsi_hba_lookup_capstr(cap);
	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_scsi_setcap: ap = 0x%p value = 0x%x whom = 0x%x "
	    "cidx = 0x%x", (void *)ap, value, whom, cidx);

	switch (cidx) {
	case SCSI_CAP_SECTOR_SIZE:
		if (value) {
			scsa2usbp->scsa2usb_secsz[ap->a_lun] = value;
		}
		break;
	case SCSI_CAP_TOTAL_SECTORS:
		if (value) {
			scsa2usbp->scsa2usb_totalsec[ap->a_lun] = value;
		}
		break;
	case SCSI_CAP_ARQ:
		rval = 1;
		break;
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_SCSI_VERSION:
	case SCSI_CAP_INTERCONNECT_TYPE:
	case SCSI_CAP_UNTAGGED_QING:
		/* supported but not settable */
		rval = 0;
		break;
	default:
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_scsi_setcap: unsupported cap = %s", cap);
		break;
	}

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	return (rval);
}


/*
 * scsa2usb - cmd and transport stuff
 */
/*
 * scsa2usb_prepare_pkt:
 *	initialize some fields of the pkt and cmd
 *	(the pkt may have been resubmitted/retried)
 */
static void
scsa2usb_prepare_pkt(scsa2usb_state_t *scsa2usbp, struct scsi_pkt *pkt)
{
	scsa2usb_cmd_t	*cmd = PKT2CMD(pkt);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_prepare_pkt: pkt=0x%p cdb: 0x%x (%s)",
	    (void *)pkt, pkt->pkt_cdbp[0],
	    scsi_cname(pkt->pkt_cdbp[0], scsa2usb_cmds));

	pkt->pkt_reason = CMD_CMPLT;	/* Set reason to pkt_complete */
	pkt->pkt_state = 0;		/* Reset next three fields */
	pkt->pkt_statistics = 0;
	pkt->pkt_resid = 0;
	bzero(pkt->pkt_scbp, cmd->cmd_scblen); /* Set status to good */

	if (cmd) {
		cmd->cmd_timeout = pkt->pkt_time;
		cmd->cmd_xfercount = 0;		/* Reset the fields */
		cmd->cmd_total_xfercount = 0;
		cmd->cmd_lba = 0;
		cmd->cmd_done = 0;
		cmd->cmd_dir = 0;
		cmd->cmd_offset = 0;
		cmd->cmd_actual_len = cmd->cmd_cdblen;
	}
}


/*
 * scsa2usb_force_invalid_request
 */
static void
scsa2usb_force_invalid_request(scsa2usb_state_t *scsa2usbp,
    scsa2usb_cmd_t *cmd)
{
	struct scsi_arq_status	*arqp;

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_force_invalid_request: pkt = 0x%p", (void *)cmd->cmd_pkt);

	if (cmd->cmd_scblen >= sizeof (struct scsi_arq_status)) {
		arqp = (struct scsi_arq_status *)cmd->cmd_pkt->pkt_scbp;
		bzero(arqp, cmd->cmd_scblen);

		arqp->sts_status.sts_chk = 1;
		arqp->sts_rqpkt_reason = CMD_CMPLT;
		arqp->sts_rqpkt_state = STATE_XFERRED_DATA |
		    STATE_GOT_BUS | STATE_GOT_STATUS;
		arqp->sts_sensedata.es_valid = 1;
		arqp->sts_sensedata.es_class = 7;
		arqp->sts_sensedata.es_key = KEY_ILLEGAL_REQUEST;

		cmd->cmd_pkt->pkt_state = STATE_ARQ_DONE |
		    STATE_GOT_BUS | STATE_GOT_BUS | STATE_GOT_BUS |
		    STATE_GOT_STATUS;
#ifdef DEBUG
		{
			uchar_t *p = (uchar_t *)(&arqp->sts_sensedata);
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "cdb: %x rqsense: "
			    "%x %x %x %x %x %x %x %x %x %x "
			    "%x %x %x %x %x %x %x %x %x %x",
			    cmd->cmd_pkt->pkt_cdbp[0],
			    p[0], p[1], p[2], p[3], p[4],
			    p[5], p[6], p[7], p[8], p[9],
			    p[10], p[11], p[12], p[13], p[14],
			    p[15], p[16], p[17], p[18], p[19]);
		}
#endif

	}
}


/*
 * scsa2usb_cmd_transport:
 */
static int
scsa2usb_cmd_transport(scsa2usb_state_t *scsa2usbp, scsa2usb_cmd_t *cmd)
{
	int rval, transport;
	struct scsi_pkt *pkt;

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cmd_transport: pkt: 0x%p, cur_pkt = 0x%p",
	    (void *)cmd->cmd_pkt, (void *)scsa2usbp->scsa2usb_cur_pkt);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));
	ASSERT(scsa2usbp->scsa2usb_cur_pkt == NULL);

	pkt = scsa2usbp->scsa2usb_cur_pkt = cmd->cmd_pkt;

	/* check black-listed attrs first */
	if (SCSA2USB_IS_BULK_ONLY(scsa2usbp)) {
		transport = scsa2usb_check_bulkonly_blacklist_attrs(scsa2usbp,
		    cmd, pkt->pkt_cdbp[0]);
	} else if (SCSA2USB_IS_CB(scsa2usbp) || SCSA2USB_IS_CBI(scsa2usbp)) {
		transport =  scsa2usb_check_ufi_blacklist_attrs(scsa2usbp,
		    pkt->pkt_cdbp[0], cmd);
	}

	/* just accept the command or return error */
	if (transport == SCSA2USB_JUST_ACCEPT) {
		SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);

		return (TRAN_ACCEPT);
	} else if (transport == SCSA2USB_REJECT) {
		return (TRAN_FATAL_ERROR);
	}

	/* check command set next */
	if (SCSA2USB_IS_SCSI_CMDSET(scsa2usbp) ||
	    SCSA2USB_IS_ATAPI_CMDSET(scsa2usbp)) {
		transport =
		    scsa2usb_handle_scsi_cmd_sub_class(scsa2usbp, cmd, pkt);
	} else if (SCSA2USB_IS_UFI_CMDSET(scsa2usbp)) {
		transport =
		    scsa2usb_handle_ufi_subclass_cmd(scsa2usbp, cmd, pkt);
	} else {
		transport = SCSA2USB_REJECT;
	}

	switch (transport) {
	case SCSA2USB_TRANSPORT:
		if (SCSA2USB_IS_BULK_ONLY(scsa2usbp)) {
			rval = scsa2usb_bulk_only_transport(scsa2usbp, cmd);
		} else if (SCSA2USB_IS_CB(scsa2usbp) ||
		    SCSA2USB_IS_CBI(scsa2usbp)) {
			rval = scsa2usb_cbi_transport(scsa2usbp, cmd);
		} else {
			rval = TRAN_FATAL_ERROR;
		}
		break;
	case SCSA2USB_JUST_ACCEPT:
		SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);
		rval = TRAN_ACCEPT;
		break;
	default:
		rval = TRAN_FATAL_ERROR;
	}

	return (rval);
}


/*
 * scsa2usb_check_bulkonly_blacklist_attrs:
 *	validate "scsa2usb_blacklist_attrs" (see scsa2usb.h)
 *	if blacklisted attrs match accept the request
 *	attributes checked are:-
 *		SCSA2USB_ATTRS_START_STOP
 */
int
scsa2usb_check_bulkonly_blacklist_attrs(scsa2usb_state_t *scsa2usbp,
    scsa2usb_cmd_t *cmd, uchar_t opcode)
{
	struct scsi_inquiry *inq =
	    &scsa2usbp->scsa2usb_lun_inquiry[cmd->cmd_pkt->pkt_address.a_lun];

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_check_bulkonly_blacklist_attrs: opcode = %s",
	    scsi_cname(opcode, scsa2usb_cmds));

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	/*
	 * decode and convert the packet
	 * for most cmds, we can bcopy the cdb
	 */
	switch (opcode) {
	case SCMD_DOORLOCK:
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_DOORLOCK)) {

			return (SCSA2USB_JUST_ACCEPT);

		/*
		 * only lock the door for CD and DVD drives
		 */
		} else if ((inq->inq_dtype == DTYPE_RODIRECT) ||
		    (inq->inq_dtype == DTYPE_OPTICAL)) {

			if (inq->inq_rmb) {

				break;
			}
		}

		return (SCSA2USB_JUST_ACCEPT);

	case SCMD_START_STOP:	/* SCMD_LOAD for sequential devices */
		/*
		 * these devices don't have mechanics that spin the
		 * media up and down. So, it doesn't make much sense
		 * to issue this cmd.
		 *
		 * Furthermore, Hagiwara devices do not handle these
		 * cmds well. just accept this command as success.
		 */
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_START_STOP)) {

			return (SCSA2USB_JUST_ACCEPT);

		} else if (inq->inq_dtype == DTYPE_SEQUENTIAL) {
			/*
			 * In case of USB tape device, we need to send the
			 * command to the device to unload the media.
			 */
			break;

		} else if (cmd->cmd_pkt->pkt_cdbp[4] & LOEJECT) {
			/*
			 * if the device is really a removable then
			 * pass it on to the device, else just accept
			 */
			if (inq->inq_rmb) {

				break;
			}

			return (SCSA2USB_JUST_ACCEPT);

		} else if (!scsa2usbp->scsa2usb_rcvd_not_ready) {
			/*
			 * if we have not received a NOT READY condition,
			 * just accept since some device choke on this too.
			 * we do have to let EJECT get through though
			 */
			return (SCSA2USB_JUST_ACCEPT);
		}

		break;
	case SCMD_INQUIRY:
		/*
		 * Some devices do not handle the inquiry cmd well
		 * so build an inquiry and accept this command as
		 * success.
		 */
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_INQUIRY)) {
			uchar_t evpd = 0x01;
			unsigned int bufsize;
			int count;

			if (cmd->cmd_pkt->pkt_cdbp[1] & evpd)
				return (SCSA2USB_REJECT);

			scsa2usb_fake_inquiry(scsa2usbp, inq);

			/* Copy no more than requested */
			count = MIN(cmd->cmd_bp->b_bcount,
			    sizeof (struct scsi_inquiry));
			bufsize = cmd->cmd_pkt->pkt_cdbp[4];
			count = MIN(count, bufsize);
			bcopy(inq, cmd->cmd_bp->b_un.b_addr, count);

			cmd->cmd_pkt->pkt_resid = bufsize - count;
			cmd->cmd_pkt->pkt_state |= STATE_XFERRED_DATA;

			return (SCSA2USB_JUST_ACCEPT);
		} else if (!(scsa2usbp->scsa2usb_attrs &
		    SCSA2USB_ATTRS_INQUIRY_EVPD)) {
			/*
			 * Some devices do not handle the inquiry cmd with
			 * evpd bit set well, e.g. some devices return the
			 * same page 0x83 data which will cause the generated
			 * devid by sd is not unique, thus return CHECK
			 * CONDITION directly to sd.
			 */
			uchar_t evpd = 0x01;

			if (!(cmd->cmd_pkt->pkt_cdbp[1] & evpd))
				break;

			if (cmd->cmd_bp) {
				cmd->cmd_pkt->pkt_resid = cmd->cmd_bp->
				    b_bcount;
			}
			scsa2usb_force_invalid_request(scsa2usbp, cmd);

			return (SCSA2USB_JUST_ACCEPT);
		}
		break;
	/*
	 * Fake accepting the following  Opcodes
	 * (as most drives don't support these)
	 * These are needed by format command.
	 */
	case SCMD_RESERVE:
	case SCMD_RELEASE:
	case SCMD_PERSISTENT_RESERVE_IN:
	case SCMD_PERSISTENT_RESERVE_OUT:

		return (SCSA2USB_JUST_ACCEPT);

	case SCMD_MODE_SENSE:
	case SCMD_MODE_SELECT:
	case SCMD_MODE_SENSE_G1:
	case SCMD_MODE_SELECT_G1:
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_MODE_SENSE)) {
			if (cmd->cmd_bp) {
				cmd->cmd_pkt->pkt_resid = cmd->cmd_bp->
				    b_bcount;
			}
			scsa2usb_force_invalid_request(scsa2usbp, cmd);

			return (SCSA2USB_JUST_ACCEPT);
		}

		break;
	default:

		break;
	}

	return (SCSA2USB_TRANSPORT);
}


/*
 * scsa2usb_handle_scsi_cmd_sub_class:
 *	prepare a scsi cmd
 *	returns SCSA2USB_TRANSPORT, SCSA2USB_REJECT, SCSA2USB_JUST_ACCEPT
 */
int
scsa2usb_handle_scsi_cmd_sub_class(scsa2usb_state_t *scsa2usbp,
    scsa2usb_cmd_t *cmd, struct scsi_pkt *pkt)
{
	uchar_t evpd = 0x01;
	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_scsi_cmd_sub_class: cmd = 0x%p pkt = 0x%p",
	    (void *)cmd, (void *)pkt);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	bzero(&cmd->cmd_cdb, SCSI_CDB_SIZE);
	cmd->cmd_cdb[SCSA2USB_OPCODE] = pkt->pkt_cdbp[0];   /* Set the opcode */
	cmd->cmd_cdb[SCSA2USB_LUN] = pkt->pkt_cdbp[1];

	/*
	 * decode and convert the packet
	 * for most cmds, we can bcopy the cdb
	 */
	switch (pkt->pkt_cdbp[0]) {
	case SCMD_FORMAT:
		/*
		 * SCMD_FORMAT used to limit cmd->cmd_xfercount
		 * to 4 bytes, but this hangs
		 * formatting dvd media using cdrecord (that is,
		 * a SCSI FORMAT UNIT command with a parameter list > 4 bytes)
		 * (bit 4 in cdb1 is the Fmtdata bit)
		 */
		if ((pkt->pkt_cdbp[1] & 0x10) && cmd->cmd_bp) {
			cmd->cmd_xfercount = cmd->cmd_bp->b_bcount;
		} else {
			cmd->cmd_xfercount = 4;
		}
		cmd->cmd_dir = CBW_DIR_OUT;
		cmd->cmd_actual_len = CDB_GROUP0;
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		break;

	case SCMD_INQUIRY:
		cmd->cmd_dir = CBW_DIR_IN;
		cmd->cmd_actual_len = CDB_GROUP0;
		cmd->cmd_cdb[SCSA2USB_LBA_0] = pkt->pkt_cdbp[2];

		/*
		 * If vpd pages data is limited to maximum SCSA2USB_MAX_INQ_LEN,
		 * the page data may be truncated, which may cause some issues
		 * such as making the unique page 0x83 or 0x80 data from
		 * different devices become the same. So don't limit return
		 * length for vpd page inquiry cmd.
		 * Another, in order to maintain compatibility, the original
		 * length limitation for standard inquiry retains here. It
		 * can be removed in future if it is verified that enough
		 * devices can work well.
		 */
		if (pkt->pkt_cdbp[1] & evpd) {
			cmd->cmd_cdb[SCSA2USB_LBA_2] = cmd->cmd_xfercount =
			    (cmd->cmd_bp ? cmd->cmd_bp->b_bcount : 0);
		} else {
			cmd->cmd_cdb[SCSA2USB_LBA_2] = cmd->cmd_xfercount =
			    min(SCSA2USB_MAX_INQ_LEN,
			    cmd->cmd_bp ? cmd->cmd_bp->b_bcount : 0);
		}
		break;

	case SCMD_READ_CAPACITY:
		cmd->cmd_dir = CBW_DIR_IN;
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		cmd->cmd_xfercount = sizeof (scsa2usb_read_cap_t);
		break;

	/*
	 * SCMD_READ/SCMD_WRITE are converted to G1 cmds
	 * (as ATAPI devices don't recognize G0 commands)
	 *
	 * SCMD_READ_LONG/SCMD_WRITE_LONG are handled in
	 * scsa2usb_rw_transport() along with other commands.
	 *
	 * USB Host Controllers cannot handle large (read/write)
	 * xfers. We split the large request to chunks of
	 * smaller ones to meet the HCD limitations.
	 */
	case SCMD_READ:
	case SCMD_WRITE:
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
	case SCMD_READ_G5:
	case SCMD_WRITE_G5:
	case SCMD_READ_LONG:
	case SCMD_WRITE_LONG:
	case SCMD_READ_CD:
		switch (scsa2usbp->
		    scsa2usb_lun_inquiry[pkt->pkt_address.a_lun].
		    inq_dtype & DTYPE_MASK) {
		case DTYPE_DIRECT:
		case DTYPE_RODIRECT:
		case DTYPE_OPTICAL:
			return (scsa2usb_rw_transport(
			    scsa2usbp, pkt));
		default:
			bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
			if (cmd->cmd_bp) {
				cmd->cmd_dir =
				    (cmd->cmd_bp->b_flags & B_READ) ?
				    CBW_DIR_IN : CBW_DIR_OUT;
				cmd->cmd_xfercount =
				    cmd->cmd_bp->b_bcount;
			}
			break;
		}
		break;

	case SCMD_REQUEST_SENSE:
		cmd->cmd_dir = CBW_DIR_IN;
		cmd->cmd_xfercount = pkt->pkt_cdbp[4];
		cmd->cmd_cdb[SCSA2USB_LBA_2] = pkt->pkt_cdbp[4];
		cmd->cmd_actual_len = CDB_GROUP0;
		break;

	case SCMD_DOORLOCK:
	case SCMD_START_STOP:
	case SCMD_TEST_UNIT_READY:
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		break;

	/*
	 * Needed by zip protocol to reset the device
	 */
	case SCMD_SDIAG:
	case SCMD_REZERO_UNIT:
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		cmd->cmd_actual_len = CDB_GROUP1;
		break;

	case SCMD_WRITE_VERIFY:
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		cmd->cmd_dir = CBW_DIR_OUT;
		cmd->cmd_xfercount = (pkt->pkt_cdbp[7] << 8) | pkt->pkt_cdbp[8];
		cmd->cmd_actual_len = CDB_GROUP1;
		break;

	/*
	 * Next command does not have a SCSI equivalent as
	 * it is vendor specific.
	 * It was listed in the vendor's ATAPI Zip specs.
	 */
	case SCMD_READ_FORMAT_CAP:
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		cmd->cmd_dir = CBW_DIR_IN;
		cmd->cmd_xfercount = (pkt->pkt_cdbp[7] << 8) | pkt->pkt_cdbp[8];
		cmd->cmd_actual_len = CDB_GROUP1;
		break;
	case IOMEGA_CMD_CARTRIDGE_PROTECT:
		cmd->cmd_dir = CBW_DIR_OUT;
		cmd->cmd_cdb[SCSA2USB_LBA_2] = pkt->pkt_cdbp[4];
		cmd->cmd_cdb[SCSA2USB_LBA_2] &= ~1;	/* Make it even */
		cmd->cmd_cdb[SCSA2USB_LUN] = pkt->pkt_cdbp[1];
		cmd->cmd_actual_len = CDB_GROUP0;
		cmd->cmd_xfercount = pkt->pkt_cdbp[4]; /* Length of password */
		break;

	/*
	 * Do not convert SCMD_MODE_SENSE/SELECT to G1 cmds because
	 * the mode header is different as well. USB devices don't
	 * support 0x03 & 0x04 mode pages, which are already obsoleted
	 * by SPC-2 specification.
	 */
	case SCMD_MODE_SENSE:
	case SCMD_MODE_SELECT:
		if (((pkt->pkt_cdbp[2] & SD_MODE_SENSE_PAGE_MASK)
		    == SD_MODE_SENSE_PAGE3_CODE) ||
		    ((pkt->pkt_cdbp[2] & SD_MODE_SENSE_PAGE_MASK)
		    == SD_MODE_SENSE_PAGE4_CODE)) {
			if (cmd->cmd_bp) {
				cmd->cmd_pkt->pkt_resid = cmd->cmd_bp->b_bcount;
			}
			scsa2usb_force_invalid_request(scsa2usbp, cmd);
			return (SCSA2USB_JUST_ACCEPT);
		}
		/* FALLTHROUGH */

	default:
		/*
		 * an unknown command may be a uscsi cmd which we
		 * should let go thru without mapping
		 */
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		if (cmd->cmd_bp) {
			cmd->cmd_dir = (cmd->cmd_bp->b_flags & B_READ) ?
			    CBW_DIR_IN : CBW_DIR_OUT;
			cmd->cmd_xfercount = cmd->cmd_bp->b_bcount;
		}

		break;
	} /* end of switch */

	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_scsi_cmd_sub_class: opcode = 0x%x count = 0x%lx",
	    pkt->pkt_cdbp[SCSA2USB_OPCODE], cmd->cmd_xfercount);

	cmd->cmd_total_xfercount = cmd->cmd_xfercount;

	return (SCSA2USB_TRANSPORT);
}


/*
 * scsa2usb_do_tur is performed before READ CAPACITY command is issued.
 * It returns media status, 0 for media ready, -1 for media not ready
 * or other errors.
 */
static int
scsa2usb_do_tur(scsa2usb_state_t *scsa2usbp, struct scsi_address *ap)
{
	struct scsi_pkt		*pkt;
	scsa2usb_cmd_t		*turcmd;
	int			rval = -1;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_do_tur:");

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	if ((pkt = scsi_init_pkt(ap, NULL, NULL, CDB_GROUP0, 1,
	    PKT_PRIV_LEN, PKT_CONSISTENT, SLEEP_FUNC, NULL)) == NULL) {
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		USB_DPRINTF_L2(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_do_tur: init pkt failed");

		return (rval);
	}

	RQ_MAKECOM_G0(pkt, FLAG_HEAD | FLAG_NODISCON,
	    (char)SCMD_TEST_UNIT_READY, 0, 0);

	pkt->pkt_comp = NULL;
	pkt->pkt_time = PKT_DEFAULT_TIMEOUT;
	turcmd = PKT2CMD(pkt);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	scsa2usb_prepare_pkt(scsa2usbp, turcmd->cmd_pkt);

	if (scsa2usb_cmd_transport(scsa2usbp, turcmd) != TRAN_ACCEPT) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_do_tur: cmd transport failed, "
		    "pkt_reason=0x%x", turcmd->cmd_pkt->pkt_reason);
	} else if (*(turcmd->cmd_pkt->pkt_scbp) != STATUS_GOOD) {
		/*
		 * Theoretically, the sense data should be retrieved and
		 * sense key be checked when check condition happens. If
		 * the sense key is UNIT ATTENTION, TEST UNIT READY cmd
		 * needs to be sent again to clear the UNIT ATTENTION and
		 * another TUR to be sent to get the real media status.
		 * But the AMI virtual floppy device simply cannot recover
		 * from UNIT ATTENTION by re-sending a TUR cmd, so it
		 * doesn't make any difference whether to check sense key
		 * or not. Just ignore sense key checking here and assume
		 * the device is NOT READY.
		 */
		USB_DPRINTF_L2(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_do_tur: media not ready");
	} else {
		rval = 0;
	}

	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	scsi_destroy_pkt(pkt);
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	return (rval);
}


/*
 * scsa2usb_check_ufi_blacklist_attrs:
 *	validate "scsa2usb_blacklist_attrs" (see scsa2usb.h)
 *	if blacklisted attrs match accept the request
 *	attributes checked are:-
 *		SCSA2USB_ATTRS_GET_CONF
 *		SCSA2USB_ATTRS_GET_PERF
 *		SCSA2USB_ATTRS_GET_START_STOP
 */
static int
scsa2usb_check_ufi_blacklist_attrs(scsa2usb_state_t *scsa2usbp, uchar_t opcode,
    scsa2usb_cmd_t *cmd)
{
	int	rval = SCSA2USB_TRANSPORT;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	switch (opcode) {
	case SCMD_PRIN:
	case SCMD_PROUT:
		rval = SCSA2USB_JUST_ACCEPT;
		break;
	case SCMD_MODE_SENSE:
	case SCMD_MODE_SELECT:
		if (cmd->cmd_bp) {
			cmd->cmd_pkt->pkt_resid = cmd->cmd_bp->b_bcount;
		}
		scsa2usb_force_invalid_request(scsa2usbp, cmd);
		rval = SCSA2USB_JUST_ACCEPT;
		break;
	case SCMD_GET_CONFIGURATION:
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_GET_CONF)) {
			rval = SCSA2USB_JUST_ACCEPT;
		}
		break;
	case SCMD_GET_PERFORMANCE:
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_GET_PERF)) {
			rval = SCSA2USB_JUST_ACCEPT;
		}
		break;
	case SCMD_START_STOP:
		/*
		 * some CB/CBI devices don't have mechanics that spin the
		 * media up and down. So, it doesn't make much sense
		 * to issue this cmd to those devices.
		 */
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_START_STOP)) {
			rval = SCSA2USB_JUST_ACCEPT;
		}
		break;
	case SCMD_READ_CAPACITY:
		/*
		 * Some devices don't support READ CAPACITY command
		 * when media is not ready. Need to check media status
		 * before issuing the cmd to such device.
		 */
		if (!(scsa2usbp->scsa2usb_attrs &
		    SCSA2USB_ATTRS_NO_MEDIA_CHECK)) {
			struct scsi_pkt *pkt = cmd->cmd_pkt;

			ASSERT(scsa2usbp->scsa2usb_cur_pkt == pkt);
			scsa2usbp->scsa2usb_cur_pkt = NULL;

			if (scsa2usb_do_tur(scsa2usbp,
			    &pkt->pkt_address) != 0) {
				/* media not ready, force cmd invalid */
				if (cmd->cmd_bp) {
					cmd->cmd_pkt->pkt_resid =
					    cmd->cmd_bp->b_bcount;
				}
				scsa2usb_force_invalid_request(scsa2usbp, cmd);
				rval = SCSA2USB_JUST_ACCEPT;
			}

			scsa2usbp->scsa2usb_cur_pkt = pkt;
		}
		break;
	default:
		break;
	}

	return (rval);
}


/*
 * scsa2usb_handle_ufi_subclass_cmd:
 *	prepare a UFI cmd
 *	returns SCSA2USB_TRANSPORT, SCSA2USB_REJECT
 */
int
scsa2usb_handle_ufi_subclass_cmd(scsa2usb_state_t *scsa2usbp,
    scsa2usb_cmd_t *cmd, struct scsi_pkt *pkt)
{
	uchar_t opcode =  pkt->pkt_cdbp[0];

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_ufi_subclass_cmd: cmd = 0x%p pkt = 0x%p",
	    (void *)cmd, (void *)pkt);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	bzero(&cmd->cmd_cdb, SCSI_CDB_SIZE);
	cmd->cmd_cdb[SCSA2USB_OPCODE] = opcode;   /* Set the opcode */
	cmd->cmd_cdb[SCSA2USB_LUN] = pkt->pkt_cdbp[1];

	/*
	 * decode and convert the packet if necessary
	 * for most cmds, we can bcopy the cdb
	 */
	switch (opcode) {
	case SCMD_FORMAT:
		/* if parameter list is specified */
		if (pkt->pkt_cdbp[1] & 0x10) {
			cmd->cmd_xfercount =
			    (pkt->pkt_cdbp[7] << 8) | pkt->pkt_cdbp[8];
			cmd->cmd_dir = USB_EP_DIR_OUT;
			cmd->cmd_actual_len = CDB_GROUP5;
		}
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		break;
	case SCMD_INQUIRY:
		cmd->cmd_dir = USB_EP_DIR_IN;
		cmd->cmd_actual_len = CDB_GROUP0;
		cmd->cmd_cdb[SCSA2USB_LBA_0] = pkt->pkt_cdbp[2];
		cmd->cmd_cdb[SCSA2USB_LBA_2] = cmd->cmd_xfercount =
		    min(SCSA2USB_MAX_INQ_LEN,
		    cmd->cmd_bp ? cmd->cmd_bp->b_bcount : 0);
		break;
	case SCMD_READ_CAPACITY:
		cmd->cmd_dir = USB_EP_DIR_IN;
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		cmd->cmd_xfercount = sizeof (scsa2usb_read_cap_t);
		break;
	case SCMD_REQUEST_SENSE:
		cmd->cmd_dir = USB_EP_DIR_IN;
		cmd->cmd_xfercount = pkt->pkt_cdbp[4];
		cmd->cmd_cdb[SCSA2USB_LBA_2] = pkt->pkt_cdbp[4];
		cmd->cmd_actual_len = CDB_GROUP0;
		break;

	/*
	 * do not convert SCMD_MODE_SENSE/SELECT because the
	 * mode header is different as well
	 */

	/*
	 * see usb_bulkonly.c for comments on the next set of commands
	 */
	case SCMD_READ:
	case SCMD_WRITE:
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
	case SCMD_READ_G5:
	case SCMD_WRITE_G5:
	case SCMD_READ_LONG:
	case SCMD_WRITE_LONG:
	case SCMD_READ_CD:

		return (scsa2usb_rw_transport(scsa2usbp, pkt));

	case SCMD_TEST_UNIT_READY:
		/*
		 * Some CB/CBI devices may not support TUR.
		 */
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		break;
	case SCMD_READ_FORMAT_CAP:
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		cmd->cmd_dir = USB_EP_DIR_IN;
		cmd->cmd_actual_len = CDB_GROUP1;
		cmd->cmd_xfercount = (pkt->pkt_cdbp[7] << 8) | pkt->pkt_cdbp[8];
		break;
	case SCMD_WRITE_VERIFY:
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		cmd->cmd_dir = USB_EP_DIR_OUT;
		cmd->cmd_actual_len = CDB_GROUP1;
		cmd->cmd_xfercount = (pkt->pkt_cdbp[7] << 8) | pkt->pkt_cdbp[8];
		break;
	case SCMD_START_STOP:
		/* A larger timeout is needed for 'flaky' CD-RW devices */
		if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_BIG_TIMEOUT)) {
			cmd->cmd_timeout = max(cmd->cmd_timeout,
			    20 * SCSA2USB_BULK_PIPE_TIMEOUT);
		}
		/* FALLTHRU */
	default:
		/*
		 * all other commands don't need special mapping
		 */
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		if (cmd->cmd_bp) {
			cmd->cmd_dir = (cmd->cmd_bp->b_flags & B_READ) ?
			    CBW_DIR_IN : CBW_DIR_OUT;
			cmd->cmd_xfercount = cmd->cmd_bp->b_bcount;
		}
		break;

	} /* end of switch */

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_ufi_subclass_cmd: opcode = 0x%x count = 0x%lx",
	    opcode, cmd->cmd_xfercount);

	cmd->cmd_total_xfercount = cmd->cmd_xfercount;

	return (SCSA2USB_TRANSPORT);
}


/*
 * scsa2usb_rw_transport:
 *	Handle splitting READ and WRITE requests to the
 *	device to a size that the host controller allows.
 *
 *	returns TRAN_* values and not USB_SUCCESS/FAILURE
 *
 * To support CD-R/CD-RW/DVD media, we need to support a
 * variety of block sizes for the different types of CD
 * data (audio, data, video, CD-XA, yellowbook, redbook etc.)
 *
 * Some of the block sizes used are:- 512, 1k, 2k, 2056, 2336
 * 2340, 2352, 2368, 2448, 2646, 2647 etc.
 *
 * NOTE: the driver could be entertaining a SCSI CDB that uses
 * any of the above listed block sizes at a given time, and a
 * totally different block size at any other given time for a
 * different CDB.
 *
 * We need to compute block size every time and figure out
 * matching LBA and LEN accordingly.
 *
 * Also UHCI has a limitation that it can only xfer 32k at a
 * given time. So, with "odd" sized blocks and a limitation of
 * how much we can xfer per shot, we need to compute xfer_count
 * as well each time.
 *
 * The same computation is also done in the function
 * scsa2usb_setup_next_xfer().	To save computing block_size in
 * this function, I am saving block_size in "cmd" now.
 */
int
scsa2usb_rw_transport(scsa2usb_state_t *scsa2usbp, struct scsi_pkt *pkt)
{
	scsa2usb_cmd_t *cmd = PKT2CMD(pkt);
	int lba, dir, opcode;
	struct buf *bp = cmd->cmd_bp;
	size_t len, xfer_count;
	size_t blk_size;	/* calculate the block size to be used */
	int sz;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_rw_transport:");

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	opcode = pkt->pkt_cdbp[0];
	blk_size  = scsa2usbp->scsa2usb_lbasize[pkt->pkt_address.a_lun];
						/* set to default */

	switch (opcode) {
	case SCMD_READ:
		/*
		 * Note that READ/WRITE(6) are not supported by the drive.
		 * convert it into a 10 byte read/write.
		 */
		lba = SCSA2USB_LBA_6BYTE(pkt);
		len = SCSA2USB_LEN_6BYTE(pkt);
		opcode = SCMD_READ_G1;	/* Overwrite it w/ byte 10 cmd val */
		dir = USB_EP_DIR_IN;
		break;
	case SCMD_WRITE:
		lba = SCSA2USB_LBA_6BYTE(pkt);
		len = SCSA2USB_LEN_6BYTE(pkt);
		opcode = SCMD_WRITE_G1;	/* Overwrite it w/ byte 10 cmd val */
		dir = USB_EP_DIR_OUT;
		break;
	case SCMD_READ_G1:
	case SCMD_READ_LONG:
		lba = SCSA2USB_LBA_10BYTE(pkt);
		len = SCSA2USB_LEN_10BYTE(pkt);
		dir = USB_EP_DIR_IN;
		break;
	case SCMD_WRITE_G1:
	case SCMD_WRITE_LONG:
		lba = SCSA2USB_LBA_10BYTE(pkt);
		len = SCSA2USB_LEN_10BYTE(pkt);
		dir = USB_EP_DIR_OUT;
		if (len) {
			sz = SCSA2USB_CDRW_BLKSZ(bp ? bp->b_bcount : 0, len);
			if (SCSA2USB_VALID_CDRW_BLKSZ(sz)) {
				blk_size = sz;	/* change it accordingly */
			}
		}
		break;
	case SCMD_READ_CD:
		lba = SCSA2USB_LBA_10BYTE(pkt);
		len = SCSA2USB_LEN_READ_CD(pkt);
		dir = USB_EP_DIR_IN;

		/* Figure out the block size */
		blk_size = scsa2usb_read_cd_blk_size(pkt->pkt_cdbp[1] >> 2);
		break;
	case SCMD_READ_G5:
		lba = SCSA2USB_LBA_12BYTE(pkt);
		len = SCSA2USB_LEN_12BYTE(pkt);
		dir = USB_EP_DIR_IN;
		break;
	case SCMD_WRITE_G5:
		lba = SCSA2USB_LBA_12BYTE(pkt);
		len = SCSA2USB_LEN_12BYTE(pkt);
		dir = USB_EP_DIR_OUT;
		break;
	}

	cmd->cmd_total_xfercount = xfer_count = len * blk_size;

	/* reduce xfer count if necessary */
	if (blk_size &&
	    (xfer_count > scsa2usbp->scsa2usb_max_bulk_xfer_size)) {
		/*
		 * For CD-RW devices reduce the xfer count based
		 * on the block size used by these devices. The
		 * block size could change for READ_CD and WRITE
		 * opcodes.
		 *
		 * Also as UHCI allows a max xfer of 32k at a time;
		 * compute the xfer_count based on the new block_size.
		 *
		 * The len part of the cdb changes as a result of that.
		 */
		if (SCSA2USB_VALID_CDRW_BLKSZ(blk_size)) {
			xfer_count = ((scsa2usbp->scsa2usb_max_bulk_xfer_size/
			    blk_size) * blk_size);
			len = xfer_count/blk_size;
			xfer_count = blk_size * len;
		} else {
			xfer_count = scsa2usbp->scsa2usb_max_bulk_xfer_size;
			len = xfer_count/blk_size;
		}
	}

	cmd->cmd_xfercount = xfer_count;
	cmd->cmd_dir = (uchar_t)dir;
	cmd->cmd_blksize = (int)blk_size;

	/*
	 * Having figured out the 'partial' xfer len based on the
	 * block size; fill it in to the cmd->cmd_cdb
	 */
	cmd->cmd_cdb[SCSA2USB_OPCODE] = (uchar_t)opcode;
	switch (opcode) {
	case SCMD_READ_CD:
		bcopy(pkt->pkt_cdbp, &cmd->cmd_cdb, cmd->cmd_cdblen);
		scsa2usb_fill_up_ReadCD_cdb_len(cmd, len, CDB_GROUP5);
		break;
	case SCMD_WRITE_G5:
	case SCMD_READ_G5:
		scsa2usb_fill_up_12byte_cdb_len(cmd, len, CDB_GROUP5);
		break;
	default:
		scsa2usb_fill_up_cdb_len(cmd, len);
		cmd->cmd_actual_len = CDB_GROUP1;
		break;
	}

	scsa2usb_fill_up_cdb_lba(cmd, lba);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "bcount=0x%lx lba=0x%x len=0x%lx xfercount=0x%lx total=0x%lx",
	    bp ? bp->b_bcount : 0, lba, len, cmd->cmd_xfercount,
	    cmd->cmd_total_xfercount);

	/* Set the timeout value as per command request */
	if ((opcode == SCMD_WRITE_G1) && SCSA2USB_VALID_CDRW_BLKSZ(blk_size)) {
		/*
		 * We increase the time as CD-RW writes have two things
		 * to do. After writing out the data to the media, a
		 * TOC needs to be filled up at the beginning of the media
		 * This is when the write gets "finalized".
		 * Hence the actual write could take longer than the
		 * value specified in cmd->cmd_timeout.
		 */
		cmd->cmd_timeout *= 4;

		USB_DPRINTF_L4(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "new timeout value = 0x%x", cmd->cmd_timeout);
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "lba 0x%x len 0x%lx xfercount 0x%lx total 0x%lx",
	    lba, len, cmd->cmd_xfercount, cmd->cmd_total_xfercount);

	return (SCSA2USB_TRANSPORT);
}


/*
 * scsa2usb_setup_next_xfer:
 *	For READs and WRITEs we split up the transfer in terms of
 *	HCD understood units. This function handles the split transfers.
 *
 * See comments in the previous function scsa2usb_rw_transport
 *
 * The lba computation was being done based on scsa2usb_max_bulk_xfer_size
 * earlier. With CD-RW devices, the xfer_count and the block_size may
 * no longer be a multiple of scsa2usb_max_bulk_xfer_size. So compute
 * xfer_count all over again. Adjust lba, based on the previous requests'
 * len. Find out the len and add it to cmd->cmd_lba to get the new lba
 */
void
scsa2usb_setup_next_xfer(scsa2usb_state_t *scsa2usbp, scsa2usb_cmd_t *cmd)
{
	int xfer_len = min(scsa2usbp->scsa2usb_max_bulk_xfer_size,
	    cmd->cmd_total_xfercount);
	int cdb_len;
	size_t blk_size;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_setup_next_xfer: opcode = 0x%x lba = 0x%x "
	    "total count = 0x%lx", cmd->cmd_cdb[SCSA2USB_OPCODE],
	    cmd->cmd_lba, cmd->cmd_total_xfercount);

	ASSERT(cmd->cmd_total_xfercount > 0);
	cmd->cmd_xfercount = xfer_len;
	blk_size = scsa2usbp->scsa2usb_lbasize[
	    cmd->cmd_pkt->pkt_address.a_lun];

	/*
	 * For CD-RW devices reduce the xfer count based on the
	 * block_size used by these devices. See changes below
	 * where xfer_count is being adjusted.
	 *
	 * Also adjust len/lba based on the block_size and xfer_count.
	 * NOTE: Always calculate lba first, as it based on previous
	 * commands' values.
	 */
	switch (cmd->cmd_cdb[SCSA2USB_OPCODE]) {
	case SCMD_READ_CD:
		/* calculate lba = current_lba + len_of_prev_cmd */
		cmd->cmd_lba += (cmd->cmd_cdb[6] << 16) +
		    (cmd->cmd_cdb[7] << 8) + cmd->cmd_cdb[8];
		cdb_len = xfer_len/cmd->cmd_blksize;
		cmd->cmd_cdb[SCSA2USB_READ_CD_LEN_2] = (uchar_t)cdb_len;
		/* re-adjust xfer count */
		cmd->cmd_xfercount = cdb_len * cmd->cmd_blksize;
		break;
	case SCMD_WRITE_G5:
	case SCMD_READ_G5:
		/* calculate lba = current_lba + len_of_prev_cmd */
		cmd->cmd_lba += (cmd->cmd_cdb[6] << 24) +
		    (cmd->cmd_cdb[7] << 16) + (cmd->cmd_cdb[8] << 8) +
		    cmd->cmd_cdb[9];
		if (blk_size) {
			xfer_len /= blk_size;
		}
		scsa2usb_fill_up_12byte_cdb_len(cmd, xfer_len, CDB_GROUP5);
		break;
	case SCMD_WRITE_G1:
	case SCMD_WRITE_LONG:
		/* calculate lba = current_lba + len_of_prev_cmd */
		cmd->cmd_lba += (cmd->cmd_cdb[7] << 8) + cmd->cmd_cdb[8];
		if (SCSA2USB_VALID_CDRW_BLKSZ(cmd->cmd_blksize)) {
			blk_size = cmd->cmd_blksize;
		}
		cdb_len = xfer_len/blk_size;
		scsa2usb_fill_up_cdb_len(cmd, cdb_len);
		/* re-adjust xfer count */
		cmd->cmd_xfercount = cdb_len * blk_size;
		break;
	default:
		if (blk_size) {
			xfer_len /= blk_size;
		}
		scsa2usb_fill_up_cdb_len(cmd, xfer_len);
		cmd->cmd_lba += scsa2usbp->scsa2usb_max_bulk_xfer_size/blk_size;
	}

	/* fill in the lba */
	scsa2usb_fill_up_cdb_lba(cmd, cmd->cmd_lba);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_setup_next_xfer:\n\tlba = 0x%x xfer_len = 0x%x "
	    "xfercount = 0x%lx total = 0x%lx", cmd->cmd_lba, xfer_len,
	    cmd->cmd_xfercount, cmd->cmd_total_xfercount);
}


/*
 * take one request from the lun's waitQ and transport it
 */
static void
scsa2usb_transport_request(scsa2usb_state_t *scsa2usbp, uint_t lun)
{
	int			rval;
	struct scsi_pkt		*pkt;
	struct scsa2usb_cmd	*cmd, *arqcmd;

	if ((cmd = (scsa2usb_cmd_t *)
	    usba_rm_first_pvt_from_list(
	    &scsa2usbp->scsa2usb_waitQ[lun])) == NULL) {

		return;
	}
	pkt = cmd->cmd_pkt;

	/*
	 * if device has been disconnected, just complete it
	 */
	if (scsa2usbp->scsa2usb_dev_state == USB_DEV_DISCONNECTED) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "device not accessible");
		pkt->pkt_reason = CMD_DEV_GONE;
		SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);
		scsa2usb_pkt_completion(scsa2usbp, pkt);

		return;
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA,
	    scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_transport_request: cmd=0x%p bp=0x%p addr=0x%p",
	    (void *)cmd, (void *)cmd->cmd_bp,
	    (void *)(cmd->cmd_bp ? cmd->cmd_bp->b_un.b_addr : NULL));

	rval = scsa2usb_cmd_transport(scsa2usbp, cmd);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA,
	    scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_transport_request: transport rval = %d",
	    rval);

	if (scsa2usbp->scsa2usb_cur_pkt == NULL) {

		return;
	}

	ASSERT(pkt == scsa2usbp->scsa2usb_cur_pkt);

	if (ddi_in_panic()) {
		pkt->pkt_reason = CMD_CMPLT;
		scsa2usb_pkt_completion(scsa2usbp, pkt);

		return;
	}

	/*
	 * start an auto-request sense iff
	 * there was a check condition, we have enough
	 * space in the status block, and we have not
	 * faked an auto request sense
	 */
	if ((*(pkt->pkt_scbp) == STATUS_CHECK) &&
	    (cmd->cmd_scblen >= sizeof (struct scsi_arq_status)) &&
	    ((pkt->pkt_state & STATE_ARQ_DONE) == 0) &&
	    (scsa2usb_create_arq_pkt(scsa2usbp,
	    &pkt->pkt_address) == USB_SUCCESS)) {
		arqcmd = scsa2usbp->scsa2usb_arq_cmd;

		/*
		 * copy the timeout from the
		 * original packet
		 * for lack of a better value
		 */
		arqcmd->cmd_pkt->pkt_time = pkt->pkt_time;
		scsa2usb_prepare_pkt(scsa2usbp,
		    arqcmd->cmd_pkt);

		scsa2usbp->scsa2usb_cur_pkt = NULL;
		if (scsa2usb_cmd_transport(
		    scsa2usbp, arqcmd) == TRAN_ACCEPT) {

			/* finish w/ this packet */
			scsa2usb_complete_arq_pkt(
			    scsa2usbp, arqcmd->cmd_pkt, cmd,
			    scsa2usbp->scsa2usb_arq_bp);

			/*
			 * we have valid request sense
			 * data so clear the pkt_reason
			 */
			pkt->pkt_reason = CMD_CMPLT;
		}
		scsa2usbp->scsa2usb_cur_pkt = pkt;
		scsa2usb_delete_arq_pkt(scsa2usbp);
	}

	if ((rval != TRAN_ACCEPT) &&
	    (pkt->pkt_reason == CMD_CMPLT)) {
		pkt->pkt_reason = CMD_TRAN_ERR;
	}

	SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);
	scsa2usb_pkt_completion(scsa2usbp, pkt);

	ASSERT(scsa2usbp->scsa2usb_cur_pkt == NULL);
}


/*
 * scsa2usb_work_thread:
 *	The taskq thread that kicks off the transport (BO and CB/CBI)
 */
static void
scsa2usb_work_thread(void *arg)
{
	scsa2usb_state_t	*scsa2usbp = (scsa2usb_state_t *)arg;
	uint_t			lun;
	uint_t			count;

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_work_thread start: thread_id=0x%p",
	    (void *)scsa2usbp->scsa2usb_work_thread_id);

	ASSERT(scsa2usbp->scsa2usb_work_thread_id == (kthread_t *)1);
	scsa2usbp->scsa2usb_work_thread_id = curthread;

	/* exclude ugen accesses */
	while (scsa2usbp->scsa2usb_transport_busy) {
		cv_wait(&scsa2usbp->scsa2usb_transport_busy_cv,
		    &scsa2usbp->scsa2usb_mutex);
	}
	ASSERT(scsa2usbp->scsa2usb_ugen_open_count == 0);
	scsa2usbp->scsa2usb_transport_busy++;
	scsa2usbp->scsa2usb_busy_proc = curproc;

	scsa2usb_raise_power(scsa2usbp);

	/* reopen the pipes if necessary */
	(void) scsa2usb_open_usb_pipes(scsa2usbp);

	for (;;) {
		ASSERT(scsa2usbp->scsa2usb_ugen_open_count == 0);
		for (lun = 0; lun < scsa2usbp->scsa2usb_n_luns; lun++) {
			scsa2usb_transport_request(scsa2usbp, lun);
		}
		count = 0;
		for (lun = 0; lun < SCSA2USB_MAX_LUNS; lun++) {
			count += usba_list_entry_count(
			    &scsa2usbp->scsa2usb_waitQ[lun]);
		}

		if (count == 0) {

			break;
		}
	}

	scsa2usbp->scsa2usb_work_thread_id = 0;

	ASSERT(scsa2usbp->scsa2usb_ugen_open_count == 0);

	scsa2usbp->scsa2usb_transport_busy--;
	scsa2usbp->scsa2usb_busy_proc = NULL;
	cv_signal(&scsa2usbp->scsa2usb_transport_busy_cv);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_work_thread: exit");

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	scsa2usb_pm_idle_component(scsa2usbp);
}


/*
 * scsa2usb_flush_waitQ:
 *	empties the entire waitQ with errors asap.
 *
 * It is called from scsa2usb_scsi_reset and scsa2usb_panic_callb.
 * If the device is reset; we should empty the waitQ right away.
 * If the system has paniced; we should empty the waitQ right away.
 *
 * CPR suspend will only succeed if device is idle. No need to call
 * this function for CPR suspend case.
 */
static void
scsa2usb_flush_waitQ(scsa2usb_state_t *scsa2usbp, uint_t lun,
    uchar_t error)
{
	struct scsi_pkt		*pkt;
	struct scsa2usb_cmd	*cmd;
	usba_list_entry_t	head;

	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	usba_move_list(&scsa2usbp->scsa2usb_waitQ[lun], &head,
	    scsa2usbp->scsa2usb_dev_data->dev_iblock_cookie);
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	while ((cmd = (scsa2usb_cmd_t *)usba_rm_first_pvt_from_list(&head)) !=
	    NULL) {
		pkt = cmd->cmd_pkt;
		pkt->pkt_reason = error;	/* set error */

		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		scsa2usbp->scsa2usb_pkt_state = SCSA2USB_PKT_DO_COMP;
		scsa2usb_pkt_completion(scsa2usbp, pkt);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
	} /* end of while */
}


/*
 * scsa2usb_do_inquiry is performed before INIT CHILD and we have
 * to fake a few things normally done by SCSA
 */
static void
scsa2usb_do_inquiry(scsa2usb_state_t *scsa2usbp, uint_t target, uint_t lun)
{
	struct buf	*bp;
	struct scsi_pkt *pkt;
	struct scsi_address ap;
	int		len = SCSA2USB_MAX_INQ_LEN;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_do_inquiry: %d bytes", len);

	/* is it inquiry-challenged? */
	if (!(scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_INQUIRY)) {
		scsa2usb_fake_inquiry(scsa2usbp,
		    &scsa2usbp->scsa2usb_lun_inquiry[lun]);
		return;
	}

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	bzero(&ap, sizeof (struct scsi_address));
	ap.a_hba_tran = scsa2usbp->scsa2usb_tran;
	ap.a_target = (ushort_t)target;
	ap.a_lun = (uchar_t)lun;

	/* limit inquiry to 36 bytes */
	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	if ((bp = scsi_alloc_consistent_buf(&ap, (struct buf *)NULL,
	    len, B_READ, SLEEP_FUNC, NULL)) == NULL) {
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		USB_DPRINTF_L2(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_do_inquiry: failed");

		return;
	}

	pkt = scsi_init_pkt(&ap, NULL, bp, CDB_GROUP0, 1,
	    PKT_PRIV_LEN, PKT_CONSISTENT, SLEEP_FUNC, NULL);

	RQ_MAKECOM_G0(pkt, FLAG_NOINTR, (char)SCMD_INQUIRY, 0, (char)len);

	pkt->pkt_comp = NULL;
	pkt->pkt_time = 5;
	bzero(bp->b_un.b_addr, len);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_do_inquiry:INQUIRY");

	(void) scsi_transport(pkt);

	if (pkt->pkt_reason) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "INQUIRY failed, cannot determine device type, "
		    "pkt_reason=0x%x", pkt->pkt_reason);

		/* not much hope for other cmds, reduce */
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		scsa2usbp->scsa2usb_attrs &=
		    ~SCSA2USB_ATTRS_REDUCED_CMD;
		scsa2usb_fake_inquiry(scsa2usbp,
		    &scsa2usbp->scsa2usb_lun_inquiry[lun]);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
	}

	scsi_destroy_pkt(pkt);
	scsi_free_consistent_buf(bp);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
}


/*
 * scsa2usb_fake_inquiry:
 *    build an inquiry for a given device that doesnt like inquiry
 *    commands.
 */
static void
scsa2usb_fake_inquiry(scsa2usb_state_t *scsa2usbp, struct scsi_inquiry *inqp)
{
	usb_client_dev_data_t *dev_data = scsa2usbp->scsa2usb_dev_data;
	int len;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_fake_inquiry:");

	bzero(inqp, sizeof (struct scsi_inquiry));
	for (len = 0; len < sizeof (inqp->inq_vid); len++) {
		*(inqp->inq_vid + len) = ' ';
	}

	for (len = 0; len < sizeof (inqp->inq_pid); len++) {
		*(inqp->inq_pid + len) = ' ';
	}

	inqp->inq_dtype = DTYPE_DIRECT;
	inqp->inq_rmb = 1;
	inqp->inq_ansi = 2;
	inqp->inq_rdf = RDF_SCSI2;
	inqp->inq_len = sizeof (struct scsi_inquiry)-4;

	/* Fill in the Vendor id/Product id strings */
	if (dev_data->dev_mfg) {
		if ((len = strlen(dev_data->dev_mfg)) >
		    sizeof (inqp->inq_vid)) {
			len = sizeof (inqp->inq_vid);
		}
		bcopy(dev_data->dev_mfg, inqp->inq_vid, len);
	}

	if (dev_data->dev_product) {
		if ((len = strlen(dev_data->dev_product)) >
		    sizeof (inqp->inq_pid)) {
			len = sizeof (inqp->inq_pid);
		}
		bcopy(dev_data->dev_product, inqp->inq_pid, len);
	}

	/* Set the Revision to the Device */
	inqp->inq_revision[0] = 0x30 +
	    ((dev_data->dev_descr->bcdDevice>>12) & 0xF);
	inqp->inq_revision[1] = 0x30 +
	    ((dev_data->dev_descr->bcdDevice>>8) & 0xF);
	inqp->inq_revision[2] = 0x30 +
	    ((dev_data->dev_descr->bcdDevice>>4) & 0xF);
	inqp->inq_revision[3] = 0x30 +
	    ((dev_data->dev_descr->bcdDevice) & 0xF);
}


/*
 * scsa2usb_create_arq_pkt:
 *	Create and ARQ packet to get request sense data
 */
static int
scsa2usb_create_arq_pkt(scsa2usb_state_t *scsa2usbp, struct scsi_address *ap)
{
	struct buf *bp;
	scsa2usb_cmd_t *arq_cmd;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_create_arq_pkt: scsa2usbp: %p, ap: %p",
	    (void *)scsa2usbp, (void *)ap);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	if ((bp = scsi_alloc_consistent_buf(ap, (struct buf *)NULL,
	    SENSE_LENGTH, B_READ, SLEEP_FUNC, NULL)) == NULL) {
		mutex_enter(&scsa2usbp->scsa2usb_mutex);

		return (USB_FAILURE);
	}

	arq_cmd = PKT2CMD(scsi_init_pkt(ap, NULL, bp, CDB_GROUP0, 1,
	    PKT_PRIV_LEN, PKT_CONSISTENT, SLEEP_FUNC, NULL));
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	RQ_MAKECOM_G0(arq_cmd->cmd_pkt,
	    FLAG_SENSING | FLAG_HEAD | FLAG_NODISCON,
	    (char)SCMD_REQUEST_SENSE, 0, (char)SENSE_LENGTH);

	arq_cmd->cmd_pkt->pkt_ha_private = arq_cmd;
	scsa2usbp->scsa2usb_arq_cmd = arq_cmd;
	scsa2usbp->scsa2usb_arq_bp = bp;
	arq_cmd->cmd_pkt->pkt_comp = NULL;
	bzero(bp->b_un.b_addr, SENSE_LENGTH);

	return (USB_SUCCESS);
}


/*
 * scsa2usb_delete_arq_pkt:
 *	Destroy the ARQ packet
 */
static void
scsa2usb_delete_arq_pkt(scsa2usb_state_t *scsa2usbp)
{
	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_delete_arq_pkt: cmd: 0x%p",
	    (void *)scsa2usbp->scsa2usb_arq_cmd);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	if (scsa2usbp->scsa2usb_arq_cmd != NULL) {
		scsi_destroy_pkt(scsa2usbp->scsa2usb_arq_cmd->cmd_pkt);
		scsi_free_consistent_buf(scsa2usbp->scsa2usb_arq_bp);
	}
	scsa2usbp->scsa2usb_arq_cmd = NULL;
	scsa2usbp->scsa2usb_arq_bp = NULL;
}


/*
 * scsa2usb_complete_arq_pkt:
 *	finish processing the arq packet
 */
static void
scsa2usb_complete_arq_pkt(scsa2usb_state_t *scsa2usbp,
    struct scsi_pkt *pkt, scsa2usb_cmd_t *ssp, struct buf *bp)
{
	scsa2usb_cmd_t		*sp = pkt->pkt_ha_private;
	struct scsi_arq_status	*arqp;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	arqp = (struct scsi_arq_status *)(ssp->cmd_pkt->pkt_scbp);
	arqp->sts_rqpkt_status = *((struct scsi_status *)
	    (sp->cmd_pkt->pkt_scbp));
	arqp->sts_rqpkt_reason = CMD_CMPLT;
	arqp->sts_rqpkt_state |= STATE_XFERRED_DATA;
	arqp->sts_rqpkt_statistics = arqp->sts_rqpkt_resid = 0;

	/* is this meaningful sense data */
	if (*(bp->b_un.b_addr) != 0) {
		bcopy(bp->b_un.b_addr, &arqp->sts_sensedata, SENSE_LENGTH);
		ssp->cmd_pkt->pkt_state |= STATE_ARQ_DONE;
	}

	/* we will not sense start cmd until we receive a NOT READY */
	if (arqp->sts_sensedata.es_key == KEY_NOT_READY) {
		scsa2usbp->scsa2usb_rcvd_not_ready = B_TRUE;
	}
}


/*
 * Miscellaneous functions for any command/transport
 */
/*
 * scsa2usb_open_usb_pipes:
 *	set up a pipe policy
 *	open usb bulk pipes (BO and CB/CBI)
 *	open usb interrupt pipe (CBI)
 */
static int
scsa2usb_open_usb_pipes(scsa2usb_state_t *scsa2usbp)
{
	int			rval;
	usb_pipe_policy_t	policy;	/* bulk pipe policy */
	size_t			sz;

	ASSERT(scsa2usbp);
	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_open_usb_pipes: dip = 0x%p flag = 0x%x",
	    (void *)scsa2usbp->scsa2usb_dip, scsa2usbp->scsa2usb_flags);

	if (!(scsa2usbp->scsa2usb_flags & SCSA2USB_FLAGS_PIPES_OPENED)) {

		/*
		 * one pipe policy for all bulk pipes
		 */
		bzero(&policy, sizeof (usb_pipe_policy_t));
		/* at least 2, for the normal and exceptional callbacks */
		policy.pp_max_async_reqs = 1;

		USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_open_usb_pipes: opening bulk pipes");

		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		/* Open the USB bulk-in pipe */
		if ((rval = usb_pipe_xopen(scsa2usbp->scsa2usb_dip,
		    &scsa2usbp->scsa2usb_bulkin_xept, &policy, USB_FLAGS_SLEEP,
		    &scsa2usbp->scsa2usb_bulkin_pipe)) != USB_SUCCESS) {
			mutex_enter(&scsa2usbp->scsa2usb_mutex);
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "scsa2usb_open_usb_pipes: bulk/in pipe open "
			    " failed rval = %d", rval);

			return (USB_FAILURE);
		}

		/* Open the bulk-out pipe  using the same policy */
		if ((rval = usb_pipe_xopen(scsa2usbp->scsa2usb_dip,
		    &scsa2usbp->scsa2usb_bulkout_xept, &policy, USB_FLAGS_SLEEP,
		    &scsa2usbp->scsa2usb_bulkout_pipe)) != USB_SUCCESS) {
			usb_pipe_close(scsa2usbp->scsa2usb_dip,
			    scsa2usbp->scsa2usb_bulkin_pipe,
			    USB_FLAGS_SLEEP, NULL, NULL);

			mutex_enter(&scsa2usbp->scsa2usb_mutex);
			scsa2usbp->scsa2usb_bulkin_pipe = NULL;

			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "scsa2usb_open_usb_pipes: bulk/out pipe open"
			    " failed rval = %d", rval);

			return (USB_FAILURE);
		}

		mutex_enter(&scsa2usbp->scsa2usb_mutex);

		/* open interrupt pipe for CBI protocol */
		if (SCSA2USB_IS_CBI(scsa2usbp)) {
			mutex_exit(&scsa2usbp->scsa2usb_mutex);

			if ((rval = usb_pipe_xopen(scsa2usbp->scsa2usb_dip,
			    &scsa2usbp->scsa2usb_intr_xept, &policy,
			    USB_FLAGS_SLEEP, &scsa2usbp->scsa2usb_intr_pipe)) !=
			    USB_SUCCESS) {
				usb_pipe_close(scsa2usbp->scsa2usb_dip,
				    scsa2usbp->scsa2usb_bulkin_pipe,
				    USB_FLAGS_SLEEP, NULL, NULL);

				usb_pipe_close(scsa2usbp->scsa2usb_dip,
				    scsa2usbp->scsa2usb_bulkout_pipe,
				    USB_FLAGS_SLEEP, NULL, NULL);

				mutex_enter(&scsa2usbp->scsa2usb_mutex);
				scsa2usbp->scsa2usb_bulkin_pipe = NULL;
				scsa2usbp->scsa2usb_bulkout_pipe = NULL;

				USB_DPRINTF_L2(DPRINT_MASK_SCSA,
				    scsa2usbp->scsa2usb_log_handle,
				    "scsa2usb_open_usb_pipes: intr pipe open"
				    " failed rval = %d", rval);

				return (USB_FAILURE);
			}

			mutex_enter(&scsa2usbp->scsa2usb_mutex);
		}

		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		/* get the max transfer size of the bulk pipe */
		if (usb_pipe_get_max_bulk_transfer_size(scsa2usbp->scsa2usb_dip,
		    &sz) == USB_SUCCESS) {
			mutex_enter(&scsa2usbp->scsa2usb_mutex);
			scsa2usbp->scsa2usb_max_bulk_xfer_size = sz;
		} else {
			mutex_enter(&scsa2usbp->scsa2usb_mutex);
			scsa2usbp->scsa2usb_max_bulk_xfer_size = DEV_BSIZE;
		}

		/* limit the xfer size */
		scsa2usbp->scsa2usb_max_bulk_xfer_size = min(
		    scsa2usbp->scsa2usb_max_bulk_xfer_size,
		    scsa2usb_max_bulk_xfer_size);

		USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_open_usb_pipes: max bulk transfer size = %lx",
		    scsa2usbp->scsa2usb_max_bulk_xfer_size);

		/* Set the pipes opened flag */
		scsa2usbp->scsa2usb_flags |= SCSA2USB_FLAGS_PIPES_OPENED;

		scsa2usbp->scsa2usb_pipe_state = SCSA2USB_PIPE_NORMAL;

		/* Set the state to NONE */
		scsa2usbp->scsa2usb_pkt_state = SCSA2USB_PKT_NONE;
	}

	return (USB_SUCCESS);
}


/*
 * scsa2usb_close_usb_pipes:
 *	close all pipes synchronously
 */
void
scsa2usb_close_usb_pipes(scsa2usb_state_t *scsa2usbp)
{
	usb_flags_t flags = USB_FLAGS_SLEEP;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_close_usb_pipes: scsa2usb_state = 0x%p",
	    (void *)scsa2usbp);

	ASSERT(scsa2usbp);
	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	if ((scsa2usbp->scsa2usb_flags & SCSA2USB_FLAGS_PIPES_OPENED) == 0) {

		return;
	}

	scsa2usbp->scsa2usb_pipe_state = SCSA2USB_PIPE_CLOSING;
	/* to avoid races, reset the flag first */
	scsa2usbp->scsa2usb_flags &= ~SCSA2USB_FLAGS_PIPES_OPENED;

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	usb_pipe_close(scsa2usbp->scsa2usb_dip,
	    scsa2usbp->scsa2usb_bulkout_pipe, flags, NULL, NULL);

	usb_pipe_close(scsa2usbp->scsa2usb_dip,
	    scsa2usbp->scsa2usb_bulkin_pipe, flags, NULL, NULL);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	if (SCSA2USB_IS_CBI(scsa2usbp)) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		usb_pipe_close(scsa2usbp->scsa2usb_dip,
		    scsa2usbp->scsa2usb_intr_pipe, flags, NULL, NULL);
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
	}
	scsa2usbp->scsa2usb_bulkout_pipe = NULL;
	scsa2usbp->scsa2usb_bulkin_pipe = NULL;
	scsa2usbp->scsa2usb_intr_pipe = NULL;

	scsa2usbp->scsa2usb_pipe_state = SCSA2USB_PIPE_NORMAL;
}


/*
 * scsa2usb_fill_up_cdb_lba:
 *	fill up command CDBs' LBA part
 */
static void
scsa2usb_fill_up_cdb_lba(scsa2usb_cmd_t *cmd, int lba)
{
	/* zero cdb1, lba bits so they won't get copied in the new cdb */
	cmd->cmd_cdb[SCSA2USB_LUN] &= 0xE0;
	cmd->cmd_cdb[SCSA2USB_LBA_0] = lba >> 24;
	cmd->cmd_cdb[SCSA2USB_LBA_1] = lba >> 16;
	cmd->cmd_cdb[SCSA2USB_LBA_2] = lba >> 8;
	cmd->cmd_cdb[SCSA2USB_LBA_3] = (uchar_t)lba;
	cmd->cmd_lba = lba;
}


/*
 * scsa2usb_fill_up_ReadCD_cdb_len:
 *	fill up READ_CD command CDBs' len part
 */
static void
scsa2usb_fill_up_ReadCD_cdb_len(scsa2usb_cmd_t *cmd, int len, int actual_len)
{
	cmd->cmd_cdb[SCSA2USB_READ_CD_LEN_0] = len >> 16;
	cmd->cmd_cdb[SCSA2USB_READ_CD_LEN_1] = len >> 8;
	cmd->cmd_cdb[SCSA2USB_READ_CD_LEN_2] = (uchar_t)len;
	cmd->cmd_actual_len = (uchar_t)actual_len;
}


/*
 * scsa2usb_fill_up_12byte_cdb_len:
 *	fill up generic 12-byte command CDBs' len part
 */
static void
scsa2usb_fill_up_12byte_cdb_len(scsa2usb_cmd_t *cmd, int len, int actual_len)
{
	cmd->cmd_cdb[6] = len >> 24;
	cmd->cmd_cdb[7] = len >> 16;
	cmd->cmd_cdb[8] = len >> 8;
	cmd->cmd_cdb[9] = (uchar_t)len;
	cmd->cmd_actual_len = (uchar_t)actual_len;
}


/*
 * scsa2usb_fill_up_cdb_len:
 *	fill up generic 10-byte command CDBs' len part
 */
static void
scsa2usb_fill_up_cdb_len(scsa2usb_cmd_t *cmd, int len)
{
	cmd->cmd_cdb[SCSA2USB_LEN_0] = len >> 8;
	cmd->cmd_cdb[SCSA2USB_LEN_1] = (uchar_t)len;
}


/*
 * scsa2usb_read_cd_blk_size:
 *	For SCMD_READ_CD opcode (0xbe). Figure out the
 *	block size based on expected sector type field
 *	definition. See MMC SCSI Specs section 6.1.15
 *
 *	Based on the value of the "expected_sector_type"
 *	field, the block size could be different.
 */
static int
scsa2usb_read_cd_blk_size(uchar_t expected_sector_type)
{
	int blk_size;

	switch (expected_sector_type) {
	case READ_CD_EST_CDDA:
		blk_size = CDROM_BLK_2352;
		break;
	case READ_CD_EST_MODE2:
		blk_size = CDROM_BLK_2336;
		break;
	case READ_CD_EST_MODE2FORM2:
		blk_size = CDROM_BLK_2324;
		break;
	case READ_CD_EST_MODE2FORM1:
	case READ_CD_EST_ALLTYPE:
	case READ_CD_EST_MODE1:
	default:
		blk_size = CDROM_BLK_2048;
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, NULL, "scsa2usb_read_cd_blk_size: "
	    "est = 0x%x blk_size = %d", expected_sector_type, blk_size);

	return (blk_size);
}


/*
 * scsa2usb_bp_to_mblk:
 *	Convert a bp to mblk_t. USBA framework understands mblk_t.
 */
static mblk_t *
scsa2usb_bp_to_mblk(scsa2usb_state_t *scsa2usbp)
{
	size_t		size;
	mblk_t		*mp;
	struct buf	*bp;
	scsa2usb_cmd_t	*cmd = PKT2CMD(scsa2usbp->scsa2usb_cur_pkt);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_bp_to_mblk: ");

	ASSERT(scsa2usbp->scsa2usb_cur_pkt);
	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	bp = cmd->cmd_bp;

	if (bp && (bp->b_bcount > 0)) {
		size = ((bp->b_bcount > cmd->cmd_xfercount) ?
		    cmd->cmd_xfercount : bp->b_bcount);
	} else {

		return (NULL);
	}

	mp = esballoc_wait((uchar_t *)bp->b_un.b_addr + cmd->cmd_offset,
	    size, BPRI_LO, &frnop);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_bp_to_mblk: "
	    "mp=0x%p bp=0x%p pkt=0x%p off=0x%lx sz=%lu add=0x%p",
	    (void *)mp, (void *)bp, (void *)scsa2usbp->scsa2usb_cur_pkt,
	    cmd->cmd_offset, bp->b_bcount - cmd->cmd_offset,
	    (void *)bp->b_un.b_addr);

	mp->b_wptr += size;
	cmd->cmd_offset += size;

	return (mp);
}


/*
 * scsa2usb_handle_data_start:
 *	Initiate the data xfer. It could be IN/OUT direction.
 *
 *	Data IN:
 *		Send out the bulk-xfer request
 *		if rval implies STALL
 *			clear endpoint stall and reset bulk-in pipe
 *			handle data read in so far; set cmd->cmd_done
 *			also adjust data xfer length accordingly
 *		else other error
 *			report back to transport
 *			typically transport will call reset recovery
 *		else (no error)
 *			return success
 *
 *	Data OUT:
 *		Send out the bulk-xfer request
 *		if rval implies STALL
 *			clear endpoint stall and reset bulk-in pipe
 *			adjust data xfer length
 *		else other error
 *			report back to transport
 *			typically transport will call reset recovery
 *		else (no error)
 *			return success
 *
 *	NOTE: We call this function only if there is xfercount.
 */
int
scsa2usb_handle_data_start(scsa2usb_state_t *scsa2usbp,
    scsa2usb_cmd_t *cmd, usb_bulk_req_t *req)
{
	int		rval = USB_SUCCESS;
	uint_t		ept_addr;
	usb_flags_t	flags = USB_FLAGS_SLEEP;
#ifdef	SCSA2USB_BULK_ONLY_TEST
	usb_req_attrs_t	attrs = 0;
#else
	usb_req_attrs_t	attrs = USB_ATTRS_SHORT_XFER_OK;
#endif

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_data_start: BEGIN cmd = %p, req = %p",
	    (void *)cmd, (void *)req);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	switch (cmd->cmd_dir) {
	case USB_EP_DIR_IN:
#ifdef	SCSA2USB_BULK_ONLY_TEST
		/*
		 * This case occurs when the host expects to receive
		 * more data than the device actually transfers. Hi > Di
		 */
		if (scsa2usb_test_case_5) {
			usb_bulk_req_t *req2;

			req->bulk_len = cmd->cmd_xfercount - 1;
			req->bulk_attributes = 0;
			mutex_exit(&scsa2usbp->scsa2usb_mutex);
			SCSA2USB_FREE_MSG(req->bulk_data);
			req->bulk_data = allocb_wait(req->bulk_len, BPRI_LO,
			    STR_NOSIG, NULL);

			ASSERT(req->bulk_timeout);
			rval = usb_pipe_bulk_xfer(
			    scsa2usbp->scsa2usb_bulkin_pipe, req, flags);
			mutex_enter(&scsa2usbp->scsa2usb_mutex);
			USB_DPRINTF_L1(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle, "rval = %x", rval);

			req2 = scsa2usb_init_bulk_req(scsa2usbp,
			    cmd->cmd_xfercount + 2,
			    cmd->cmd_timeout, 0, flags);
			req2->bulk_len = cmd->cmd_xfercount + 2;
			mutex_exit(&scsa2usbp->scsa2usb_mutex);

			ASSERT(req2->bulk_timeout);
			rval = usb_pipe_bulk_xfer(
			    scsa2usbp->scsa2usb_bulkin_pipe, req2, flags);
			mutex_enter(&scsa2usbp->scsa2usb_mutex);

			USB_DPRINTF_L1(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "TEST 5: Hi > Di: rval = 0x%x", rval);
			scsa2usb_test_case_5 = 0;
			usb_free_bulk_req(req2);

			return (rval);
		}

		/*
		 * This happens when the host expects to send data to the
		 * device while the device intends to send data to the host.
		 */
		if (scsa2usb_test_case_8 && (cmd->cmd_cdb[0] == SCMD_READ_G1)) {
			USB_DPRINTF_L1(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "TEST 8: Hi <> Do: Step 2");
			scsa2usb_test_mblk(scsa2usbp, B_TRUE);
			scsa2usb_test_case_8 = 0;

			return (rval);
		}
#endif	/* SCSA2USB_BULK_ONLY_TEST */

		ept_addr = scsa2usbp->scsa2usb_bulkin_ept.bEndpointAddress;
		req->bulk_len = cmd->cmd_xfercount;
		req->bulk_attributes = attrs;
		SCSA2USB_FREE_MSG(req->bulk_data);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		req->bulk_data = esballoc_wait(
		    (uchar_t *)cmd->cmd_bp->b_un.b_addr +
		    cmd->cmd_offset,
		    req->bulk_len, BPRI_LO, &frnop);

		ASSERT(req->bulk_timeout);
		rval = usb_pipe_bulk_xfer(scsa2usbp->scsa2usb_bulkin_pipe,
		    req, flags);
		mutex_enter(&scsa2usbp->scsa2usb_mutex);

		break;

	case USB_EP_DIR_OUT:
#ifdef	SCSA2USB_BULK_ONLY_TEST
		/*
		 * This happens when the host expects to receive data
		 * from the device while the device intends to receive
		 * data from the host.
		 */
		if (scsa2usb_test_case_10 &&
		    (cmd->cmd_cdb[0] == SCMD_WRITE_G1)) {
			req->bulk_len = CSW_LEN;
			mutex_exit(&scsa2usbp->scsa2usb_mutex);

			ASSERT(req->bulk_timeout);
			rval = usb_pipe_bulk_xfer(
			    scsa2usbp->scsa2usb_bulkin_pipe, req, flags);
			mutex_enter(&scsa2usbp->scsa2usb_mutex);

			USB_DPRINTF_L1(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "TEST 10: Ho <> Di: done rval = 0x%x",  rval);
			scsa2usb_test_case_10 = 0;

			return (rval);
		}
#endif	/* SCSA2USB_BULK_ONLY_TEST */

		req->bulk_data = scsa2usb_bp_to_mblk(scsa2usbp);
		if (req->bulk_data == NULL) {

			return (USB_FAILURE);
		}

#ifdef	SCSA2USB_BULK_ONLY_TEST
		if (scsa2usb_test_case_11) {
			/*
			 * Host expects to send data to the device and
			 * device doesn't expect to receive any data
			 */
			USB_DPRINTF_L1(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle, "TEST 11: Ho > Do");

			scsa2usb_test_mblk(scsa2usbp, B_FALSE);
			scsa2usb_test_case_11 = 0;
		}
#endif	/* SCSA2USB_BULK_ONLY_TEST */

		ept_addr = scsa2usbp->scsa2usb_bulkout_ept.bEndpointAddress;
		req->bulk_len = MBLKL(req->bulk_data);
		req->bulk_timeout = scsa2usb_bulk_timeout(cmd->cmd_timeout);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		ASSERT(req->bulk_timeout);
		rval = usb_pipe_bulk_xfer(scsa2usbp->scsa2usb_bulkout_pipe,
		    req, flags);
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		break;
	}

	USB_DPRINTF_L3(DPRINT_MASK_SCSA,
	    scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_data_start: rval=%d cr=%d", rval,
	    req->bulk_completion_reason);

	if (rval != USB_SUCCESS) {
		/* Handle Errors now */
		if (req->bulk_completion_reason == USB_CR_STALL) {
			if (cmd->cmd_dir == USB_EP_DIR_IN) {
				(void) scsa2usb_clear_ept_stall(
				    scsa2usbp, ept_addr,
				    scsa2usbp-> scsa2usb_bulkin_pipe,
				    "bulk-in");
			} else {
				(void) scsa2usb_clear_ept_stall(
				    scsa2usbp, ept_addr,
				    scsa2usbp-> scsa2usb_bulkout_pipe,
				    "bulk-out");
			}
		}

		/* no more data to transfer after this */
		cmd->cmd_done = 1;
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_data_start: END %s data rval = %d",
	    (cmd->cmd_dir == USB_EP_DIR_IN) ? "bulk-in" : "bulk-out", rval);

	return (rval);
}


/*
 * scsa2usb_handle_data_done:
 *	This function handles the completion of the data xfer.
 *	It also massages the inquiry data. This function may
 *	also be called after a stall.
 */
void
scsa2usb_handle_data_done(scsa2usb_state_t *scsa2usbp,
    scsa2usb_cmd_t *cmd, usb_bulk_req_t *req)
{
	struct buf	*bp = cmd->cmd_bp;
	struct scsi_pkt	*pkt = scsa2usbp->scsa2usb_cur_pkt;
	mblk_t		*data = req->bulk_data;
	int		len = data ? MBLKL(data) : 0;
	uint32_t	max_lba;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_data_done:\n\tcmd = 0x%p data = 0x%p len = 0x%x",
	    (void *)cmd, (void *)data, len);

	cmd->cmd_resid_xfercount = cmd->cmd_xfercount - len;

	if (len)  {
		uchar_t	*p;
		uchar_t dtype;
		scsa2usb_read_cap_t *cap;
		struct scsi_inquiry *inq;

		switch (cmd->cmd_cdb[SCSA2USB_OPCODE]) {
		case SCMD_INQUIRY:
			/*
			 * cache a copy of the inquiry data for our own use
			 * but ensure that we have at least up to
			 * inq_revision, inq_serial is not required.
			 * ignore inquiry data returned for inquiry commands
			 * with SCSI-3 EVPD, CmdDt bits set.
			 */
			if (((cmd->cmd_cdb[SCSA2USB_LUN] & 0x1f) == 0) &&
			    (len >= SCSA2USB_MAX_INQ_LEN)) {
				inq = (struct scsi_inquiry *)data->b_rptr;
				dtype = inq->inq_dtype & DTYPE_MASK;
				/*
				 * scsi framework sends zero byte write(10) cmd
				 * to (Simplified) direct-access devices with
				 * inquiry version > 2 for reservation changes.
				 * But some USB devices don't support zero byte
				 * write(10) even though they have inquiry
				 * version > 2. Considering scsa2usb driver
				 * doesn't support reservation and all the
				 * reservation cmds are being faked, we fake
				 * the inquiry version to 0 to make scsi
				 * framework send test unit ready cmd which is
				 * supported by all the usb devices.
				 */
				if (((dtype == DTYPE_DIRECT) ||
				    (dtype == DTYPE_RBC)) &&
				    (inq->inq_ansi > 2)) {
					inq->inq_ansi = 0;
				}

				bzero(&scsa2usbp->scsa2usb_lun_inquiry
				    [pkt->pkt_address.a_lun],
				    sizeof (struct scsi_inquiry));
				bcopy(data->b_rptr,
				    &scsa2usbp->scsa2usb_lun_inquiry
				    [pkt->pkt_address.a_lun], len);
			}

			USB_DPRINTF_L3(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "scsi inquiry type = 0x%x",
			    scsa2usbp->scsa2usb_lun_inquiry
			    [pkt->pkt_address.a_lun].inq_dtype);

			cmd->cmd_done = 1;
			goto handle_data;

		case SCMD_READ_CAPACITY:
			cap = (scsa2usb_read_cap_t *)data->b_rptr;

			/* Figure out the logical block size */
			if ((len >= sizeof (struct scsa2usb_read_cap)) &&
			    (req->bulk_completion_reason == USB_CR_OK)) {
				scsa2usbp->
				    scsa2usb_lbasize[pkt->pkt_address.a_lun] =
				    SCSA2USB_MK_32BIT(
				    cap->scsa2usb_read_cap_blen3,
				    cap->scsa2usb_read_cap_blen2,
				    cap->scsa2usb_read_cap_blen1,
				    cap->scsa2usb_read_cap_blen0);

				max_lba = SCSA2USB_MK_32BIT(
				    cap->scsa2usb_read_cap_lba3,
				    cap->scsa2usb_read_cap_lba2,
				    cap->scsa2usb_read_cap_lba1,
				    cap->scsa2usb_read_cap_lba0);

				/*
				 * Some devices return total logical block
				 * number instead of highest logical block
				 * address. Adjust the value by minus 1.
				 */
				if (max_lba > 0 && (scsa2usbp->scsa2usb_attrs &
				    SCSA2USB_ATTRS_NO_CAP_ADJUST) == 0) {
					max_lba -= 1;
					cap->scsa2usb_read_cap_lba0 =
					    (uchar_t)(max_lba & 0xFF);
					cap->scsa2usb_read_cap_lba1 =
					    (uchar_t)(max_lba >> 8 & 0xFF);
					cap->scsa2usb_read_cap_lba2 =
					    (uchar_t)(max_lba >> 16 & 0xFF);
					cap->scsa2usb_read_cap_lba3 =
					    (uchar_t)(max_lba >> 24 & 0xFF);
				}

				USB_DPRINTF_L2(DPRINT_MASK_SCSA,
				    scsa2usbp->scsa2usb_log_handle,
				    "bytes in each logical block=0x%lx,"
				    "number of total logical blocks=0x%x",
				    scsa2usbp->
				    scsa2usb_lbasize[pkt->pkt_address.a_lun],
				    max_lba + 1);
			}
			cmd->cmd_done = 1;
			goto handle_data;

		case SCMD_REQUEST_SENSE:
			p = data->b_rptr;
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "cdb: %x rqsense: "
			    "%x %x %x %x %x %x %x %x %x %x\n\t"
			    "%x %x %x %x %x %x %x %x %x %x",
			    cmd->cmd_cdb[0],
			    p[0], p[1], p[2], p[3], p[4],
			    p[5], p[6], p[7], p[8], p[9],
			    p[10], p[11], p[12], p[13], p[14],
			    p[15], p[16], p[17], p[18], p[19]);

			scsa2usbp->scsa2usb_last_cmd.status = p[2];
			cmd->cmd_done = 1;
			/* FALLTHROUGH */

		default:
handle_data:
			if (bp && len && (cmd->cmd_dir == USB_EP_DIR_IN)) {
				/*
				 * we don't have to copy the data, the
				 * data pointers for the mblk_t for
				 * the bulk-in xfer points to the
				 * struct buf * data.
				 */
				cmd->cmd_offset += len;
			}

			USB_DPRINTF_L3(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "len = 0x%x total = 0x%lx offset = 0x%lx",
			    len, cmd->cmd_total_xfercount, cmd->cmd_offset);

			/*
			 * update total_xfercount now but it may be
			 * adjusted after receiving the residue
			 */
			cmd->cmd_total_xfercount -= len;

			if ((req->bulk_completion_reason != USB_CR_OK) ||
			    (cmd->cmd_resid_xfercount != 0) ||
			    (cmd->cmd_total_xfercount == 0)) {
				/* set pkt_resid to total to be sure */
				pkt->pkt_resid = cmd->cmd_total_xfercount;
				cmd->cmd_done = 1;
			}

			break;
		}
	} else {
		if (cmd->cmd_dir == USB_EP_DIR_OUT) {
			if (cmd->cmd_total_xfercount == 0) {
				cmd->cmd_done = 1;
			}
		}
	}
}


/*
 * scsa2usb_init_bulk_req:
 *	Allocate (synchronously) and fill in a bulk-request
 */
usb_bulk_req_t *
scsa2usb_init_bulk_req(scsa2usb_state_t *scsa2usbp, size_t length,
    uint_t timeout, usb_req_attrs_t attrs, usb_flags_t flags)
{
	usb_bulk_req_t	*req;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	req = usb_alloc_bulk_req(scsa2usbp->scsa2usb_dip, length,
	    flags | USB_FLAGS_SLEEP);

	req->bulk_len = (uint_t)length;			/* xfer length */
	req->bulk_timeout = scsa2usb_bulk_timeout(timeout); /* xfer timeout */
	req->bulk_attributes = attrs;		/* xfer attrs */
	req->bulk_client_private = (usb_opaque_t)scsa2usbp; /* statep */

	return (req);
}


/*
 * scsa2usb_bulk_timeout:
 *	ensure that bulk requests do not have infinite timeout values
 */
int
scsa2usb_bulk_timeout(int timeout)
{
	return ((timeout == 0) ? scsa2usb_long_timeout : timeout);
}


/*
 * scsa2usb_clear_ept_stall:
 *	clear endpoint stall and reset pipes
 */
int
scsa2usb_clear_ept_stall(scsa2usb_state_t *scsa2usbp, uint_t ept_addr,
    usb_pipe_handle_t ph, char *what)
{
	int rval;
	dev_info_t *dip = scsa2usbp->scsa2usb_dip;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));
	if (!(SCSA2USB_DEVICE_ACCESS_OK(scsa2usbp))) {

		return (USB_FAILURE);
	}

	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	rval = usb_clr_feature(dip, USB_DEV_REQ_RCPT_EP, 0, ept_addr,
	    USB_FLAGS_SLEEP, NULL, NULL);

	usb_pipe_reset(dip, ph, USB_FLAGS_SLEEP, NULL, NULL);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_clear_ept_stall: on %s: ept = 0x%x rval = %d",
	    what, ept_addr, rval);

	return (rval);
}


/*
 * scsa2usb_pkt_completion:
 *	Handle pkt completion.
 */
static void
scsa2usb_pkt_completion(scsa2usb_state_t *scsa2usbp, struct scsi_pkt *pkt)
{
	scsa2usb_cmd_t *cmd = PKT2CMD(pkt);
	size_t len;

	ASSERT(pkt);
	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_pkt_completion:\n\tscsa2usbp = 0x%p "
	    "reason=%d, status=%d state=0x%x stats=0x%x resid=0x%lx",
	    (void *)scsa2usbp, pkt->pkt_reason, *(pkt->pkt_scbp),
	    pkt->pkt_state, pkt->pkt_statistics, pkt->pkt_resid);

	if (pkt->pkt_reason == CMD_CMPLT) {
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;
		if (cmd->cmd_xfercount) {
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
	} else {
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD;
	}

	/*
	 * don't zap the current state when in panic as this will
	 * make debugging harder
	 */
	if ((scsa2usbp->scsa2usb_cur_pkt == pkt) && !ddi_in_panic()) {
		SCSA2USB_RESET_CUR_PKT(scsa2usbp);

		len = sizeof (scsa2usbp->scsa2usb_last_cmd.cdb);
		bzero(scsa2usbp->scsa2usb_last_cmd.cdb, len);

		len = (len < cmd->cmd_cdblen) ? len : cmd->cmd_cdblen;
		USB_DPRINTF_L3(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_pkt_completion: save last cmd, len=%ld", len);

		/* save the last command */
		bcopy(pkt->pkt_cdbp, scsa2usbp->scsa2usb_last_cmd.cdb, len);

		/* reset the scsa2usb_last_cmd.status value */
		if ((pkt->pkt_cdbp[0] != SCMD_REQUEST_SENSE) &&
		    (pkt->pkt_cdbp[0] != SCMD_INQUIRY)) {
			scsa2usbp->scsa2usb_last_cmd.status = 0;
		}

		/*
		 * set pkt state to NONE *before* calling back as the target
		 * driver will immediately submit the next packet
		 */
		scsa2usbp->scsa2usb_pkt_state = SCSA2USB_PKT_NONE;
	}

	if (pkt->pkt_comp) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		scsi_hba_pkt_comp(pkt);
		mutex_enter(&scsa2usbp->scsa2usb_mutex);

	}
}


/*
 * Even handling functions:
 *
 * scsa2usb_reconnect_event_cb:
 *	event handling
 */
static int
scsa2usb_reconnect_event_cb(dev_info_t *dip)
{
	scsa2usb_state_t *scsa2usbp =
	    ddi_get_soft_state(scsa2usb_statep, ddi_get_instance(dip));
	dev_info_t	*cdip;
	int		circ;
	int		rval = USB_SUCCESS;

	ASSERT(scsa2usbp != NULL);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_reconnect_event_cb: dip = 0x%p", (void *)dip);

	scsa2usb_restore_device_state(dip, scsa2usbp);

	USB_DPRINTF_L0(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "Reinserted device is accessible again.");

	ndi_devi_enter(dip, &circ);
	for (cdip = ddi_get_child(dip); cdip; ) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		mutex_enter(&DEVI(cdip)->devi_lock);
		DEVI_SET_DEVICE_REINSERTED(cdip);
		mutex_exit(&DEVI(cdip)->devi_lock);

		cdip = next;
	}
	ndi_devi_exit(dip, circ);

	/* stop suppressing warnings */
	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	scsa2usbp->scsa2usb_warning_given = B_FALSE;
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	if (scsa2usbp->scsa2usb_ugen_hdl) {
		rval = usb_ugen_reconnect_ev_cb(
		    scsa2usbp->scsa2usb_ugen_hdl);
	}

	return (rval);
}


/*
 * scsa2usb_all_waitQs_empty:
 *	check if all waitQs empty
 */
static int
scsa2usb_all_waitQs_empty(scsa2usb_state_t *scsa2usbp)
{
	uint_t	lun;

	for (lun = 0; lun < SCSA2USB_MAX_LUNS; lun++) {
		if (usba_list_entry_count(
		    &scsa2usbp->scsa2usb_waitQ[lun])) {

			return (USB_FAILURE);
		}
	}

	return (USB_SUCCESS);
}


/*
 * scsa2usb_disconnect_event_cb:
 *	callback for disconnect events
 */
static int
scsa2usb_disconnect_event_cb(dev_info_t *dip)
{
	scsa2usb_state_t *scsa2usbp =
	    ddi_get_soft_state(scsa2usb_statep, ddi_get_instance(dip));
	dev_info_t	*cdip;
	int		circ, i;
	int		rval = USB_SUCCESS;

	ASSERT(scsa2usbp != NULL);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_disconnect_event_cb: dip = 0x%p", (void *)dip);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	scsa2usbp->scsa2usb_dev_state = USB_DEV_DISCONNECTED;

	/*
	 * wait till the work thread is done, carry on regardless
	 * if not.
	 */
	for (i = 0; i < SCSA2USB_DRAIN_TIMEOUT; i++) {
		if ((scsa2usbp->scsa2usb_work_thread_id == NULL) &&
		    (scsa2usbp->scsa2usb_cur_pkt == NULL) &&
		    (scsa2usb_all_waitQs_empty(scsa2usbp) ==
		    USB_SUCCESS)) {

			break;
		}
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		delay(drv_usectohz(1000000));
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
	}
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	ndi_devi_enter(dip, &circ);
	for (cdip = ddi_get_child(dip); cdip; ) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		mutex_enter(&DEVI(cdip)->devi_lock);
		DEVI_SET_DEVICE_REMOVED(cdip);
		mutex_exit(&DEVI(cdip)->devi_lock);

		cdip = next;
	}
	ndi_devi_exit(dip, circ);

	if (scsa2usbp->scsa2usb_ugen_hdl) {
		rval = usb_ugen_disconnect_ev_cb(
		    scsa2usbp->scsa2usb_ugen_hdl);
	}

	return (rval);
}


/*
 * PM support
 *
 * scsa2usb_create_pm_components:
 *	create the pm components required for power management
 *	no mutex is need when calling USBA interfaces
 */
static void
scsa2usb_create_pm_components(dev_info_t *dip, scsa2usb_state_t *scsa2usbp)
{
	scsa2usb_power_t *pm;
	uint_t		pwr_states;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	USB_DPRINTF_L4(DPRINT_MASK_PM, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_create_pm_components: dip = 0x%p, scsa2usbp = 0x%p",
	    (void *)dip, (void *)scsa2usbp);

	/*
	 * determine if this device is on the blacklist
	 * or if a conf file entry has disabled PM
	 */
	if ((scsa2usbp->scsa2usb_attrs & SCSA2USB_ATTRS_PM) == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_PM, scsa2usbp->scsa2usb_log_handle,
		    "device cannot be power managed");

		return;
	}

	/* Allocate the PM state structure */
	pm = kmem_zalloc(sizeof (scsa2usb_power_t), KM_SLEEP);

	scsa2usbp->scsa2usb_pm = pm;
	pm->scsa2usb_current_power = USB_DEV_OS_FULL_PWR;
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	if (usb_create_pm_components(dip, &pwr_states) ==
	    USB_SUCCESS) {
		if (usb_handle_remote_wakeup(dip,
		    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
			pm->scsa2usb_wakeup_enabled = 1;
		}

		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		pm->scsa2usb_pwr_states = (uint8_t)pwr_states;
		scsa2usb_raise_power(scsa2usbp);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
	}

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
}


/*
 * scsa2usb_raise_power:
 *	check if the device is using full power or not
 */
static void
scsa2usb_raise_power(scsa2usb_state_t *scsa2usbp)
{
	USB_DPRINTF_L4(DPRINT_MASK_PM, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_raise_power:");

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	if (scsa2usbp->scsa2usb_pm) {
		scsa2usb_pm_busy_component(scsa2usbp);
		if (scsa2usbp->scsa2usb_pm->scsa2usb_current_power !=
		    USB_DEV_OS_FULL_PWR) {
			mutex_exit(&scsa2usbp->scsa2usb_mutex);
			(void) pm_raise_power(scsa2usbp->scsa2usb_dip,
			    0, USB_DEV_OS_FULL_PWR);
			mutex_enter(&scsa2usbp->scsa2usb_mutex);
		}
	}
}


/*
 * functions to handle power transition for OS levels 0 -> 3
 */
static int
scsa2usb_pwrlvl0(scsa2usb_state_t *scsa2usbp)
{
	int	rval;

	switch (scsa2usbp->scsa2usb_dev_state) {
	case USB_DEV_ONLINE:
		/* Deny the powerdown request if the device is busy */
		if (scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy != 0) {

			return (USB_FAILURE);
		}

		/*
		 * stop polling on interrupt pipe
		 */
		scsa2usb_cbi_stop_intr_polling(scsa2usbp);

		/* Issue USB D3 command to the device here */
		rval = usb_set_device_pwrlvl3(scsa2usbp->scsa2usb_dip);
		ASSERT(rval == USB_SUCCESS);

		scsa2usbp->scsa2usb_dev_state = USB_DEV_PWRED_DOWN;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
	case USB_DEV_PWRED_DOWN:
	default:
		scsa2usbp->scsa2usb_pm->scsa2usb_current_power =
		    USB_DEV_OS_PWR_OFF;

		return (USB_SUCCESS);
	}
}


static int
scsa2usb_pwrlvl1(scsa2usb_state_t *scsa2usbp)
{
	int	rval;

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(scsa2usbp->scsa2usb_dip);
	ASSERT(rval == USB_SUCCESS);

	return (DDI_FAILURE);
}


static int
scsa2usb_pwrlvl2(scsa2usb_state_t *scsa2usbp)
{
	int	rval;

	/* Issue USB D1 command to the device here */
	rval = usb_set_device_pwrlvl1(scsa2usbp->scsa2usb_dip);
	ASSERT(rval == USB_SUCCESS);

	return (DDI_FAILURE);
}


static int
scsa2usb_pwrlvl3(scsa2usb_state_t *scsa2usbp)
{
	int	rval;

	/*
	 * PM framework tries to put us in full power
	 * during system shutdown. If we are disconnected
	 * return success anyways
	 */
	if (scsa2usbp->scsa2usb_dev_state != USB_DEV_DISCONNECTED) {
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(scsa2usbp->scsa2usb_dip);
		ASSERT(rval == USB_SUCCESS);

		scsa2usbp->scsa2usb_dev_state = USB_DEV_ONLINE;
	}
	scsa2usbp->scsa2usb_pm->scsa2usb_current_power = USB_DEV_OS_FULL_PWR;

	return (DDI_SUCCESS);
}


/*
 * scsa2usb_power:
 *	power entry point
 */
/* ARGSUSED */
static int
scsa2usb_power(dev_info_t *dip, int comp, int level)
{
	scsa2usb_state_t	*scsa2usbp;
	scsa2usb_power_t	*pm;
	int			rval = DDI_FAILURE;

	scsa2usbp = ddi_get_soft_state(scsa2usb_statep, ddi_get_instance(dip));

	USB_DPRINTF_L3(DPRINT_MASK_PM, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_power: Begin scsa2usbp (%p): level = %d",
	    (void *)scsa2usbp, level);

	mutex_enter(&scsa2usbp->scsa2usb_mutex);
	if (SCSA2USB_BUSY(scsa2usbp)) {
		USB_DPRINTF_L2(DPRINT_MASK_PM, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_power: busy");
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (rval);
	}

	pm = scsa2usbp->scsa2usb_pm;
	if (pm == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_PM, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_power: pm NULL");
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (rval);
	}

	/* check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->scsa2usb_pwr_states, level)) {
		USB_DPRINTF_L2(DPRINT_MASK_PM, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_power: illegal power level = %d "
		    "pwr_states: %x", level, pm->scsa2usb_pwr_states);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		return (rval);
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		rval = scsa2usb_pwrlvl0(scsa2usbp);
		break;
	case USB_DEV_OS_PWR_1 :
		rval = scsa2usb_pwrlvl1(scsa2usbp);
		break;
	case USB_DEV_OS_PWR_2 :
		rval = scsa2usb_pwrlvl2(scsa2usbp);
		break;
	case USB_DEV_OS_FULL_PWR :
		rval = scsa2usb_pwrlvl3(scsa2usbp);
		break;
	}

	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


static void
scsa2usb_pm_busy_component(scsa2usb_state_t *scsa2usbp)
{
	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	if (scsa2usbp->scsa2usb_pm) {
		scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy++;

		USB_DPRINTF_L4(DPRINT_MASK_PM,
		    scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_pm_busy_component: %d",
		    scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy);

		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		if (pm_busy_component(scsa2usbp->scsa2usb_dip, 0) !=
		    DDI_SUCCESS) {
			mutex_enter(&scsa2usbp->scsa2usb_mutex);
			ASSERT(scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy > 0);
			scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy--;

			USB_DPRINTF_L2(DPRINT_MASK_PM,
			    scsa2usbp->scsa2usb_log_handle,
			    "scsa2usb_pm_busy_component failed: %d",
			    scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy);

			return;
		}
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
	}
}


/*
 * scsa2usb_pm_idle_component:
 *	idles the device
 */
static void
scsa2usb_pm_idle_component(scsa2usb_state_t *scsa2usbp)
{
	ASSERT(!mutex_owned(&scsa2usbp->scsa2usb_mutex));

	if (scsa2usbp->scsa2usb_pm) {
		if (pm_idle_component(scsa2usbp->scsa2usb_dip, 0) ==
		    DDI_SUCCESS) {
			mutex_enter(&scsa2usbp->scsa2usb_mutex);
			ASSERT(scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy > 0);
			scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy--;

			USB_DPRINTF_L4(DPRINT_MASK_PM,
			    scsa2usbp->scsa2usb_log_handle,
			    "scsa2usb_pm_idle_component: %d",
			    scsa2usbp->scsa2usb_pm->scsa2usb_pm_busy);

			mutex_exit(&scsa2usbp->scsa2usb_mutex);
		}
	}
}


#ifdef	DEBUG
/*
 * scsa2usb_print_cdb:
 *	prints CDB
 */
void
scsa2usb_print_cdb(scsa2usb_state_t *scsa2usbp, scsa2usb_cmd_t *cmd)
{
	uchar_t *c = (uchar_t *)&cmd->cmd_cdb;

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "cmd = 0x%p opcode=%s "
	    "cdb: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
	    (void *)cmd,
	    scsi_cname(cmd->cmd_cdb[SCSA2USB_OPCODE], scsa2usb_cmds),
	    c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8],
	    c[9], c[10], c[11], c[12], c[13], c[14], c[15]);
}
#endif	/* DEBUG */


#ifdef	SCSA2USB_BULK_ONLY_TEST
/*
 * scsa2usb_test_mblk:
 *	This function sends a dummy data mblk_t to simulate
 *	the following test cases: 5 and 11.
 */
static void
scsa2usb_test_mblk(scsa2usb_state_t *scsa2usbp, boolean_t large)
{
	int			i, rval;
	size_t			len;
	usb_flags_t		flags = USB_FLAGS_SLEEP;
	usb_bulk_req_t		*req;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	/* should we create a larger mblk? */
	len = (large == B_TRUE) ? DEV_BSIZE : USB_BULK_CBWCMD_LEN;

	req = scsa2usb_init_bulk_req(scsa2usbp, len,
	    SCSA2USB_BULK_PIPE_TIMEOUT, 0, flags);

	/* fill up the data mblk */
	for (i = 0; i < len; i++) {
		*req->bulk_data->b_wptr++ = (uchar_t)i;
	}

	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	ASSERT(req->bulk_timeout);
	rval = usb_pipe_bulk_xfer(scsa2usbp->scsa2usb_bulkout_pipe, req, flags);
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_test_mblk: Sent Data Out rval = 0x%x", rval);

	usb_free_bulk_req(req);
}
#endif	/* SCSA2USB_BULK_ONLY_TEST */
