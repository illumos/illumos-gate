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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SATA Framework
 * Generic SATA Host Adapter Implementation
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/thread.h>
#include <sys/kstat.h>
#include <sys/note.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <sys/taskq.h>

#include <sys/sata/impl/sata.h>
#include <sys/sata/sata_hba.h>
#include <sys/sata/sata_defs.h>
#include <sys/sata/sata_cfgadm.h>

/* Debug flags - defined in sata.h */
int	sata_debug_flags = 0;

/*
 * Flags enabling selected SATA HBA framework functionality
 */
#define	SATA_ENABLE_QUEUING		1
#define	SATA_ENABLE_NCQ			2
#define	SATA_ENABLE_PROCESS_EVENTS	4
int sata_func_enable =
	SATA_ENABLE_PROCESS_EVENTS | SATA_ENABLE_QUEUING | SATA_ENABLE_NCQ;

/*
 * Global variable setting default maximum queue depth (NCQ or TCQ)
 * Note:minimum queue depth is 1
 */
int sata_max_queue_depth = SATA_MAX_QUEUE_DEPTH; /* max NCQ/TCQ queue depth */

/*
 * Currently used default NCQ/TCQ queue depth. It is set-up during the driver
 * initialization, using value from sata_max_queue_depth
 * It is adjusted to minimum supported by the controller and by the device,
 * if queueing is enabled.
 */
static	int sata_current_max_qdepth;

#ifdef SATA_DEBUG

#define	SATA_LOG_D(args)	sata_log args
uint64_t mbuf_count = 0;
uint64_t mbuffail_count = 0;

sata_atapi_cmd_t sata_atapi_trace[64];
uint32_t sata_atapi_trace_index = 0;
int sata_atapi_trace_save = 1;
static	void sata_save_atapi_trace(sata_pkt_txlate_t *, int);
#define	SATAATAPITRACE(spx, count)	if (sata_atapi_trace_save) \
    sata_save_atapi_trace(spx, count);

#else
#define	SATA_LOG_D(arg)
#define	SATAATAPITRACE(spx, count)
#endif

#if 0
static void
sata_test_atapi_packet_command(sata_hba_inst_t *, int);
#endif
#define	LEGACY_HWID_LEN	64	/* Model (40) + Serial (20) + pad */


/*
 * SATA cb_ops functions
 */
static 	int sata_hba_open(dev_t *, int, int, cred_t *);
static 	int sata_hba_close(dev_t, int, int, cred_t *);
static 	int sata_hba_ioctl(dev_t, int, intptr_t, int, cred_t *,	int *);

/*
 * SCSA required entry points
 */
static	int sata_scsi_tgt_init(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static	int sata_scsi_tgt_probe(struct scsi_device *,
    int (*callback)(void));
static void sata_scsi_tgt_free(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static 	int sata_scsi_start(struct scsi_address *, struct scsi_pkt *);
static 	int sata_scsi_abort(struct scsi_address *, struct scsi_pkt *);
static 	int sata_scsi_reset(struct scsi_address *, int);
static 	int sata_scsi_getcap(struct scsi_address *, char *, int);
static 	int sata_scsi_setcap(struct scsi_address *, char *, int, int);
static 	struct scsi_pkt *sata_scsi_init_pkt(struct scsi_address *,
    struct scsi_pkt *, struct buf *, int, int, int, int, int (*)(caddr_t),
    caddr_t);
static 	void sata_scsi_destroy_pkt(struct scsi_address *, struct scsi_pkt *);
static 	void sata_scsi_dmafree(struct scsi_address *, struct scsi_pkt *);
static 	void sata_scsi_sync_pkt(struct scsi_address *, struct scsi_pkt *);

/*
 * SATA HBA interface functions are defined in sata_hba.h header file
 */

/* Event processing functions */
static	void sata_event_daemon(void *);
static	void sata_event_thread_control(int);
static	void sata_process_controller_events(sata_hba_inst_t *sata_hba_inst);
static	void sata_process_device_reset(sata_hba_inst_t *, sata_address_t *);
static	void sata_process_port_failed_event(sata_hba_inst_t *,
    sata_address_t *);
static	void sata_process_port_link_events(sata_hba_inst_t *,
    sata_address_t *);
static	void sata_process_device_detached(sata_hba_inst_t *, sata_address_t *);
static	void sata_process_device_attached(sata_hba_inst_t *, sata_address_t *);
static	void sata_process_port_pwr_change(sata_hba_inst_t *, sata_address_t *);
static	void sata_process_cntrl_pwr_level_change(sata_hba_inst_t *);
static	void sata_process_target_node_cleanup(sata_hba_inst_t *,
    sata_address_t *);


/*
 * Local translation functions
 */
static	int sata_txlt_inquiry(sata_pkt_txlate_t *);
static	int sata_txlt_test_unit_ready(sata_pkt_txlate_t *);
static	int sata_txlt_start_stop_unit(sata_pkt_txlate_t *);
static	int sata_txlt_read_capacity(sata_pkt_txlate_t *);
static	int sata_txlt_request_sense(sata_pkt_txlate_t *);
static 	int sata_txlt_read(sata_pkt_txlate_t *);
static 	int sata_txlt_write(sata_pkt_txlate_t *);
static 	int sata_txlt_log_sense(sata_pkt_txlate_t *);
static 	int sata_txlt_log_select(sata_pkt_txlate_t *);
static 	int sata_txlt_mode_sense(sata_pkt_txlate_t *);
static 	int sata_txlt_mode_select(sata_pkt_txlate_t *);
static 	int sata_txlt_synchronize_cache(sata_pkt_txlate_t *);
static 	int sata_txlt_write_buffer(sata_pkt_txlate_t *);
static 	int sata_txlt_nodata_cmd_immediate(sata_pkt_txlate_t *);

static 	int sata_hba_start(sata_pkt_txlate_t *, int *);
static	int sata_txlt_invalid_command(sata_pkt_txlate_t *);
static	int sata_txlt_lba_out_of_range(sata_pkt_txlate_t *);
static 	void sata_txlt_rw_completion(sata_pkt_t *);
static 	void sata_txlt_nodata_cmd_completion(sata_pkt_t *);
static 	void sata_txlt_download_mcode_cmd_completion(sata_pkt_t *);
static 	int sata_emul_rw_completion(sata_pkt_txlate_t *);
static 	struct scsi_extended_sense *sata_immediate_error_response(
    sata_pkt_txlate_t *, int);
static	struct scsi_extended_sense *sata_arq_sense(sata_pkt_txlate_t *);

static 	int sata_txlt_atapi(sata_pkt_txlate_t *);
static 	void sata_txlt_atapi_completion(sata_pkt_t *);

/*
 * Local functions for ioctl
 */
static	int32_t sata_get_port_num(sata_hba_inst_t *,  struct devctl_iocdata *);
static	void sata_cfgadm_state(sata_hba_inst_t *, int32_t,
    devctl_ap_state_t *);
static	dev_info_t *sata_get_target_dip(dev_info_t *, int32_t);
static	dev_info_t *sata_devt_to_devinfo(dev_t);

/*
 * Local functions
 */
static 	void sata_remove_hba_instance(dev_info_t *);
static 	int sata_validate_sata_hba_tran(dev_info_t *, sata_hba_tran_t *);
static 	void sata_probe_ports(sata_hba_inst_t *);
static 	int sata_reprobe_port(sata_hba_inst_t *, sata_device_t *, int);
static 	int sata_add_device(dev_info_t *, sata_hba_inst_t *, int cport,
    int pmport);
static 	dev_info_t *sata_create_target_node(dev_info_t *, sata_hba_inst_t *,
    sata_address_t *);
static 	int sata_validate_scsi_address(sata_hba_inst_t *,
    struct scsi_address *, sata_device_t *);
static 	int sata_validate_sata_address(sata_hba_inst_t *, int, int, int);
static	sata_pkt_t *sata_pkt_alloc(sata_pkt_txlate_t *, int (*)(caddr_t));
static	void sata_pkt_free(sata_pkt_txlate_t *);
static	int sata_dma_buf_setup(sata_pkt_txlate_t *, int, int (*)(caddr_t),
    caddr_t, ddi_dma_attr_t *);
static	int sata_probe_device(sata_hba_inst_t *, sata_device_t *);
static	sata_drive_info_t *sata_get_device_info(sata_hba_inst_t *,
    sata_device_t *);
static 	int sata_identify_device(sata_hba_inst_t *, sata_drive_info_t *);
static	struct buf *sata_alloc_local_buffer(sata_pkt_txlate_t *, int);
static 	void sata_free_local_buffer(sata_pkt_txlate_t *);
static 	uint64_t sata_check_capacity(sata_drive_info_t *);
void 	sata_adjust_dma_attr(sata_drive_info_t *, ddi_dma_attr_t *,
    ddi_dma_attr_t *);
static 	int sata_fetch_device_identify_data(sata_hba_inst_t *,
    sata_drive_info_t *);
static	void sata_update_port_info(sata_hba_inst_t *, sata_device_t *);
static	void sata_update_port_scr(sata_port_scr_t *, sata_device_t *);
static	int sata_set_dma_mode(sata_hba_inst_t *, sata_drive_info_t *);
static	int sata_set_cache_mode(sata_hba_inst_t *, sata_drive_info_t *, int);
static	int sata_set_rmsn(sata_hba_inst_t *, sata_drive_info_t *, int);
static	int sata_set_drive_features(sata_hba_inst_t *,
    sata_drive_info_t *, int flag);
static	void sata_init_write_cache_mode(sata_drive_info_t *sdinfo);
static	int sata_initialize_device(sata_hba_inst_t *, sata_drive_info_t *);
static	void sata_identdev_to_inquiry(sata_hba_inst_t *, sata_drive_info_t *,
    uint8_t *);
static	int sata_get_atapi_inquiry_data(sata_hba_inst_t *, sata_address_t *,
    struct scsi_inquiry *);
static	int sata_build_msense_page_1(sata_drive_info_t *, int, uint8_t *);
static	int sata_build_msense_page_8(sata_drive_info_t *, int, uint8_t *);
static	int sata_build_msense_page_1a(sata_drive_info_t *, int, uint8_t *);
static	int sata_build_msense_page_1c(sata_drive_info_t *, int, uint8_t *);
static	int sata_mode_select_page_8(sata_pkt_txlate_t *,
    struct mode_cache_scsi3 *, int, int *, int *, int *);
static	int sata_mode_select_page_1c(sata_pkt_txlate_t *,
    struct mode_info_excpt_page *, int, int *, int *, int *);
static	int sata_build_msense_page_30(sata_drive_info_t *, int, uint8_t *);
static	int sata_mode_select_page_30(sata_pkt_txlate_t *,
    struct mode_acoustic_management *, int, int *, int *, int *);

static	int sata_build_lsense_page_0(sata_drive_info_t *, uint8_t *);
static	int sata_build_lsense_page_10(sata_drive_info_t *, uint8_t *,
    sata_hba_inst_t *);
static	int sata_build_lsense_page_2f(sata_drive_info_t *, uint8_t *,
    sata_hba_inst_t *);
static	int sata_build_lsense_page_30(sata_drive_info_t *, uint8_t *,
    sata_hba_inst_t *);
static	void sata_save_drive_settings(sata_drive_info_t *);
static	void sata_show_drive_info(sata_hba_inst_t *, sata_drive_info_t *);
static	void sata_log(sata_hba_inst_t *, uint_t, char *fmt, ...);
static	int sata_fetch_smart_return_status(sata_hba_inst_t *,
    sata_drive_info_t *);
static	int sata_fetch_smart_data(sata_hba_inst_t *, sata_drive_info_t *,
    struct smart_data *);
static	int sata_smart_selftest_log(sata_hba_inst_t *,
    sata_drive_info_t *,
    struct smart_selftest_log *);
static	int sata_ext_smart_selftest_read_log(sata_hba_inst_t *,
    sata_drive_info_t *, struct smart_ext_selftest_log *, uint16_t);
static	int sata_smart_read_log(sata_hba_inst_t *, sata_drive_info_t *,
    uint8_t *, uint8_t, uint8_t);
static	int sata_read_log_ext_directory(sata_hba_inst_t *, sata_drive_info_t *,
    struct read_log_ext_directory *);
static	void sata_gen_sysevent(sata_hba_inst_t *, sata_address_t *, int);
static	void sata_xlate_errors(sata_pkt_txlate_t *);
static	void sata_decode_device_error(sata_pkt_txlate_t *,
    struct scsi_extended_sense *);
static	void sata_set_device_removed(dev_info_t *);
static	boolean_t sata_check_device_removed(dev_info_t *);
static	void sata_set_target_node_cleanup(sata_hba_inst_t *, int cport);
static	int sata_ncq_err_ret_cmd_setup(sata_pkt_txlate_t *,
    sata_drive_info_t *);
static	int sata_atapi_err_ret_cmd_setup(sata_pkt_txlate_t *,
    sata_drive_info_t *);
static	void sata_atapi_packet_cmd_setup(sata_cmd_t *, sata_drive_info_t *);
static	void sata_fixed_sense_data_preset(struct scsi_extended_sense *);
static  void sata_target_devid_register(dev_info_t *, sata_drive_info_t *);
static  int sata_check_modser(char *, int);



/*
 * SATA Framework will ignore SATA HBA driver cb_ops structure and
 * register following one with SCSA framework.
 * Open & close are provided, so scsi framework will not use its own
 */
static struct cb_ops sata_cb_ops = {
	sata_hba_open,			/* open */
	sata_hba_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	sata_hba_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_NEW | D_MP,			/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* aread */
	nodev				/* awrite */
};


extern struct mod_ops mod_miscops;
extern uchar_t	scsi_cdb_size[];

static struct modlmisc modlmisc = {
	&mod_miscops,			/* Type of module */
	"SATA Module v%I%"		/* module name */
};


static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

/*
 * Default sata pkt timeout. Used when a target driver scsi_pkt time is zero,
 * i.e. when scsi_pkt has not timeout specified.
 */
static int sata_default_pkt_time = 60;	/* 60 seconds */

/*
 * Intermediate buffer device access attributes - they are required,
 * but not necessarily used.
 */
static ddi_device_acc_attr_t sata_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};


/*
 * Mutexes protecting structures in multithreaded operations.
 * Because events are relatively rare, a single global mutex protecting
 * data structures should be sufficient. To increase performance, add
 * separate mutex per each sata port and use global mutex only to protect
 * common data structures.
 */
static	kmutex_t sata_mutex;		/* protects sata_hba_list */
static	kmutex_t sata_log_mutex;	/* protects log */

static 	char sata_log_buf[256];

/* Default write cache setting for SATA hard disks */
int	sata_write_cache = 1;		/* enabled */

/* Default write cache setting for SATA ATAPI CD/DVD */
int 	sata_atapicdvd_write_cache = 1; /* enabled */

/*
 * Linked list of HBA instances
 */
static 	sata_hba_inst_t *sata_hba_list = NULL;
static 	sata_hba_inst_t *sata_hba_list_tail = NULL;
/*
 * Pointer to per-instance SATA HBA soft structure is stored in sata_hba_tran
 * structure and in sata soft state.
 */

/*
 * Event daemon related variables
 */
static 	kmutex_t sata_event_mutex;
static 	kcondvar_t sata_event_cv;
static 	kthread_t *sata_event_thread = NULL;
static 	int sata_event_thread_terminate = 0;
static 	int sata_event_pending = 0;
static 	int sata_event_thread_active = 0;
extern 	pri_t minclsyspri;

/*
 * NCQ error recovery command
 */
static const sata_cmd_t sata_rle_cmd = {
	SATA_CMD_REV,
	NULL,
	{
		SATA_DIR_READ
	},
	ATA_ADDR_LBA48,
	0,
	0,
	0,
	0,
	0,
	1,
	READ_LOG_EXT_NCQ_ERROR_RECOVERY,
	0,
	0,
	0,
	SATAC_READ_LOG_EXT,
	0,
	0,
	0,
};

/*
 * ATAPI error recovery CDB
 */
static const uint8_t sata_rqsense_cdb[SATA_ATAPI_RQSENSE_CDB_LEN] = {
	SCMD_REQUEST_SENSE,
	0,			/* Only fixed RQ format is supported */
	0,
	0,
	SATA_ATAPI_MIN_RQSENSE_LEN, /* Less data may be returned */
	0
};


/* Warlock directives */

_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", scsi_hba_tran))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", scsi_device))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", dev_ops))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", scsi_extended_sense))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", scsi_arq_status))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", ddi_dma_attr))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", ddi_dma_cookie_t))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", devctl_ap_state))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", dev_info::devi_state))
_NOTE(MUTEX_PROTECTS_DATA(sata_mutex, sata_hba_list))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_hba_list))
_NOTE(MUTEX_PROTECTS_DATA(sata_mutex, sata_hba_inst::satahba_next))
_NOTE(MUTEX_PROTECTS_DATA(sata_mutex, sata_hba_inst::satahba_prev))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", \
    sata_hba_inst::satahba_scsi_tran))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", sata_hba_inst::satahba_tran))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", sata_hba_inst::satahba_dip))
_NOTE(SCHEME_PROTECTS_DATA("Scheme", sata_hba_inst::satahba_attached))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_hba_inst::satahba_dev_port))
_NOTE(MUTEX_PROTECTS_DATA(sata_hba_inst::satahba_mutex, 
    sata_hba_inst::satahba_event_flags))
_NOTE(MUTEX_PROTECTS_DATA(sata_cport_info::cport_mutex, \
    sata_cport_info::cport_devp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_cport_info::cport_devp))
_NOTE(SCHEME_PROTECTS_DATA("Scheme", sata_cport_info::cport_addr))
_NOTE(MUTEX_PROTECTS_DATA(sata_cport_info::cport_mutex, \
    sata_cport_info::cport_dev_type))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_cport_info::cport_dev_type))
_NOTE(MUTEX_PROTECTS_DATA(sata_cport_info::cport_mutex, \
    sata_cport_info::cport_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_cport_info::cport_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_pmport_info::pmport_dev_type))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_pmport_info::pmport_sata_drive))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_pmult_info::pmult_dev_port))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sata_pmult_info::pmult_num_dev_ports))
#ifdef SATA_DEBUG
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", mbuf_count))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", mbuffail_count))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", sata_atapi_trace))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", sata_atapi_trace_index))
#endif

/* End of warlock directives */

/* ************** loadable module configuration functions ************** */

int
_init()
{
	int rval;

	mutex_init(&sata_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sata_event_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sata_log_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sata_event_cv, NULL, CV_DRIVER, NULL);
	if ((rval = mod_install(&modlinkage)) != 0) {
#ifdef SATA_DEBUG
		cmn_err(CE_WARN, "sata: _init: mod_install failed\n");
#endif
		mutex_destroy(&sata_log_mutex);
		cv_destroy(&sata_event_cv);
		mutex_destroy(&sata_event_mutex);
		mutex_destroy(&sata_mutex);
	}
	return (rval);
}

int
_fini()
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) != 0)
		return (rval);

	mutex_destroy(&sata_log_mutex);
	cv_destroy(&sata_event_cv);
	mutex_destroy(&sata_event_mutex);
	mutex_destroy(&sata_mutex);
	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/* ********************* SATA HBA entry points ********************* */


/*
 * Called by SATA HBA from _init().
 * Registers HBA driver instance/sata framework pair with scsi framework, by
 * calling scsi_hba_init().
 *
 * SATA HBA driver cb_ops are ignored - SATA HBA framework cb_ops are used
 * instead. SATA HBA framework cb_ops pointer overwrites SATA HBA driver
 * cb_ops pointer in SATA HBA driver dev_ops structure.
 * SATA HBA framework cb_ops supplies cb_open cb_close and cb_ioctl vectors.
 *
 * Return status of the scsi_hba_init() is returned to a calling SATA HBA
 * driver.
 */
int
sata_hba_init(struct modlinkage *modlp)
{
	int rval;
	struct dev_ops *hba_ops;

	SATADBG1(SATA_DBG_HBA_IF, NULL,
	    "sata_hba_init: name %s \n",
	    ((struct modldrv *)(modlp->ml_linkage[0]))->drv_linkinfo);
	/*
	 * Fill-up cb_ops and dev_ops when necessary
	 */
	hba_ops = ((struct modldrv *)(modlp->ml_linkage[0]))->drv_dev_ops;
	/*
	 * Provide pointer to SATA dev_ops
	 */
	hba_ops->devo_cb_ops = &sata_cb_ops;

	/*
	 * Register SATA HBA with SCSI framework
	 */
	if ((rval = scsi_hba_init(modlp)) != 0) {
		SATADBG1(SATA_DBG_HBA_IF, NULL,
		    "sata_hba_init: scsi hba init failed\n", NULL);
		return (rval);
	}

	return (0);
}


/* HBA attach stages */
#define	HBA_ATTACH_STAGE_SATA_HBA_INST	1
#define	HBA_ATTACH_STAGE_SCSI_ATTACHED	2
#define	HBA_ATTACH_STAGE_SETUP		4
#define	HBA_ATTACH_STAGE_LINKED		8


/*
 *
 * Called from SATA HBA driver's attach routine to attach an instance of
 * the HBA.
 *
 * For DDI_ATTACH command:
 * sata_hba_inst structure is allocated here and initialized with pointers to
 * SATA framework implementation of required scsi tran functions.
 * The scsi_tran's tran_hba_private field is used by SATA Framework to point
 * to the soft structure (sata_hba_inst) allocated by SATA framework for
 * SATA HBA instance related data.
 * The scsi_tran's tran_hba_private field is used by SATA framework to
 * store a pointer to per-HBA-instance of sata_hba_inst structure.
 * The sata_hba_inst structure is cross-linked to scsi tran structure.
 * Among other info, a pointer to sata_hba_tran structure is stored in
 * sata_hba_inst. The sata_hba_inst structures for different HBA instances are
 * linked together into the list, pointed to by sata_hba_list.
 * On the first HBA instance attach the sata event thread is initialized.
 * Attachment points are created for all SATA ports of the HBA being attached.
 * All HBA instance's SATA ports are probed and type of plugged devices is
 * determined. For each device of a supported type, a target node is created.
 *
 * DDI_SUCCESS is returned when attachment process is successful,
 * DDI_FAILURE is returned otherwise.
 *
 * For DDI_RESUME command:
 * Not implemented at this time (postponed until phase 2 of the development).
 */
int
sata_hba_attach(dev_info_t *dip, sata_hba_tran_t *sata_tran,
    ddi_attach_cmd_t cmd)
{
	sata_hba_inst_t	*sata_hba_inst;
	scsi_hba_tran_t *scsi_tran = NULL;
	int hba_attach_state = 0;
	char taskq_name[MAXPATHLEN];

	SATADBG3(SATA_DBG_HBA_IF, NULL,
	    "sata_hba_attach: node %s (%s%d)\n",
	    ddi_node_name(dip), ddi_driver_name(dip),
	    ddi_get_instance(dip));

	if (cmd == DDI_RESUME) {
		/*
		 * Postponed until phase 2 of the development
		 */
		return (DDI_FAILURE);
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/* cmd == DDI_ATTACH */

	if (sata_validate_sata_hba_tran(dip, sata_tran) != SATA_SUCCESS) {
		SATA_LOG_D((NULL, CE_WARN,
		    "sata_hba_attach: invalid sata_hba_tran"));
		return (DDI_FAILURE);
	}
	/*
	 * Allocate and initialize SCSI tran structure.
	 * SATA copy of tran_bus_config is provided to create port nodes.
	 */
	scsi_tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);
	if (scsi_tran == NULL)
		return (DDI_FAILURE);
	/*
	 * Allocate soft structure for SATA HBA instance.
	 * There is a separate softstate for each HBA instance.
	 */
	sata_hba_inst = kmem_zalloc(sizeof (struct sata_hba_inst), KM_SLEEP);
	ASSERT(sata_hba_inst != NULL); /* this should not fail */
	mutex_init(&sata_hba_inst->satahba_mutex, NULL, MUTEX_DRIVER, NULL);
	hba_attach_state |= HBA_ATTACH_STAGE_SATA_HBA_INST;

	/*
	 * scsi_trans's tran_hba_private is used by SATA Framework to point to
	 * soft structure allocated by SATA framework for
	 * SATA HBA instance related data.
	 */
	scsi_tran->tran_hba_private	= sata_hba_inst;
	scsi_tran->tran_tgt_private	= NULL;

	scsi_tran->tran_tgt_init	= sata_scsi_tgt_init;
	scsi_tran->tran_tgt_probe	= sata_scsi_tgt_probe;
	scsi_tran->tran_tgt_free	= sata_scsi_tgt_free;

	scsi_tran->tran_start		= sata_scsi_start;
	scsi_tran->tran_reset		= sata_scsi_reset;
	scsi_tran->tran_abort		= sata_scsi_abort;
	scsi_tran->tran_getcap		= sata_scsi_getcap;
	scsi_tran->tran_setcap		= sata_scsi_setcap;
	scsi_tran->tran_init_pkt	= sata_scsi_init_pkt;
	scsi_tran->tran_destroy_pkt	= sata_scsi_destroy_pkt;

	scsi_tran->tran_dmafree		= sata_scsi_dmafree;
	scsi_tran->tran_sync_pkt	= sata_scsi_sync_pkt;

	scsi_tran->tran_reset_notify	= NULL;
	scsi_tran->tran_get_bus_addr	= NULL;
	scsi_tran->tran_quiesce		= NULL;
	scsi_tran->tran_unquiesce	= NULL;
	scsi_tran->tran_bus_reset	= NULL;

	if (scsi_hba_attach_setup(dip, sata_tran->sata_tran_hba_dma_attr,
	    scsi_tran, 0) != DDI_SUCCESS) {
#ifdef SATA_DEBUG
		cmn_err(CE_WARN, "?SATA: %s%d hba scsi attach failed",
		    ddi_driver_name(dip), ddi_get_instance(dip));
#endif
		goto fail;
	}
	hba_attach_state |= HBA_ATTACH_STAGE_SCSI_ATTACHED;

	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "sata")) {
		if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "sata", 1) != DDI_PROP_SUCCESS) {
			SATA_LOG_D((NULL, CE_WARN, "sata_hba_attach: "
			    "failed to create hba sata prop"));
			goto fail;
		}
	}

	/*
	 * Save pointers in hba instance soft state.
	 */
	sata_hba_inst->satahba_scsi_tran = scsi_tran;
	sata_hba_inst->satahba_tran = sata_tran;
	sata_hba_inst->satahba_dip = dip;

	/*
	 * Create a task queue to handle emulated commands completion
	 * Use node name, dash, instance number as the queue name.
	 */
	taskq_name[0] = '\0';
	(void) strlcat(taskq_name, DEVI(dip)->devi_node_name,
	    sizeof (taskq_name));
	(void) snprintf(taskq_name + strlen(taskq_name),
	    sizeof (taskq_name) - strlen(taskq_name),
	    "-%d", DEVI(dip)->devi_instance);
	sata_hba_inst->satahba_taskq = taskq_create(taskq_name, 1,
	    minclsyspri, 1, sata_tran->sata_tran_hba_num_cports,
	    TASKQ_DYNAMIC);

	hba_attach_state |= HBA_ATTACH_STAGE_SETUP;

	/*
	 * Create events thread if not created yet.
	 */
	sata_event_thread_control(1);

	/*
	 * Link this hba instance into the list.
	 */
	mutex_enter(&sata_mutex);

	if (sata_hba_list == NULL) {
		/*
		 * The first instance of HBA is attached.
		 * Set current/active default maximum NCQ/TCQ queue depth for
		 * all SATA devices. It is done here and now, to eliminate the
		 * possibility of the dynamic, programatic modification of the
		 * queue depth via global (and public) sata_max_queue_depth
		 * variable (this would require special handling in HBA drivers)
		 */
		sata_current_max_qdepth = sata_max_queue_depth;
		if (sata_current_max_qdepth > 32)
			sata_current_max_qdepth = 32;
		else if (sata_current_max_qdepth < 1)
			sata_current_max_qdepth = 1;
	}

	sata_hba_inst->satahba_next = NULL;
	sata_hba_inst->satahba_prev = sata_hba_list_tail;
	if (sata_hba_list == NULL) {
		sata_hba_list = sata_hba_inst;
	}
	if (sata_hba_list_tail != NULL) {
		sata_hba_list_tail->satahba_next = sata_hba_inst;
	}
	sata_hba_list_tail = sata_hba_inst;
	mutex_exit(&sata_mutex);
	hba_attach_state |= HBA_ATTACH_STAGE_LINKED;

	/*
	 * Create SATA HBA devctl minor node for sata_hba_open, close, ioctl
	 * SATA HBA driver should not use its own open/close entry points.
	 *
	 * Make sure that instance number doesn't overflow
	 * when forming minor numbers.
	 */
	ASSERT(ddi_get_instance(dip) <= (L_MAXMIN >> INST_MINOR_SHIFT));
	if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
	    INST2DEVCTL(ddi_get_instance(dip)),
	    DDI_NT_SATA_NEXUS, 0) != DDI_SUCCESS) {
#ifdef SATA_DEBUG
		cmn_err(CE_WARN, "sata_hba_attach: "
		    "cannot create devctl minor node");
#endif
		goto fail;
	}


	/*
	 * Set-up kstats here, if necessary.
	 * (postponed until phase 2 of the development).
	 */


	/*
	 * Probe controller ports. This operation will describe a current
	 * controller/port/multipliers/device configuration and will create
	 * attachment points.
	 * We may end-up with just a controller with no devices attached.
	 * For the ports with a supported device attached, device target nodes
	 * are created and devices are initialized.
	 */
	sata_probe_ports(sata_hba_inst);

	sata_hba_inst->satahba_attached = 1;
	return (DDI_SUCCESS);

fail:
	if (hba_attach_state & HBA_ATTACH_STAGE_LINKED) {
		(void) sata_remove_hba_instance(dip);
		if (sata_hba_list == NULL)
			sata_event_thread_control(0);
	}

	if (hba_attach_state & HBA_ATTACH_STAGE_SETUP) {
		(void) ddi_prop_remove(DDI_DEV_T_ANY, dip, "sata");
		taskq_destroy(sata_hba_inst->satahba_taskq);
	}

	if (hba_attach_state & HBA_ATTACH_STAGE_SCSI_ATTACHED)
		(void) scsi_hba_detach(dip);

	if (hba_attach_state & HBA_ATTACH_STAGE_SATA_HBA_INST) {
		mutex_destroy(&sata_hba_inst->satahba_mutex);
		kmem_free((void *)sata_hba_inst,
		    sizeof (struct sata_hba_inst));
		scsi_hba_tran_free(scsi_tran);
	}

	sata_log(NULL, CE_WARN, "?SATA: %s%d hba attach failed",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	return (DDI_FAILURE);
}


/*
 * Called by SATA HBA from to detach an instance of the driver.
 *
 * For DDI_DETACH command:
 * Free local structures allocated for SATA HBA instance during
 * sata_hba_attach processing.
 *
 * Returns DDI_SUCCESS when HBA was detached, DDI_FAILURE otherwise.
 *
 * For DDI_SUSPEND command:
 * Not implemented at this time (postponed until phase 2 of the development)
 * Returnd DDI_SUCCESS.
 *
 * When the last HBA instance is detached, the event daemon is terminated.
 *
 * NOTE: cport support only, no port multiplier support.
 */
int
sata_hba_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	dev_info_t	*tdip;
	sata_hba_inst_t	*sata_hba_inst;
	scsi_hba_tran_t *scsi_hba_tran;
	sata_cport_info_t *cportinfo;
	sata_drive_info_t *sdinfo;
	int ncport;

	SATADBG3(SATA_DBG_HBA_IF, NULL, "sata_hba_detach: node %s (%s%d)\n",
	    ddi_node_name(dip), ddi_driver_name(dip), ddi_get_instance(dip));

	switch (cmd) {
	case DDI_DETACH:

		if ((scsi_hba_tran = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		sata_hba_inst = scsi_hba_tran->tran_hba_private;
		if (sata_hba_inst == NULL)
			return (DDI_FAILURE);

		if (scsi_hba_detach(dip) == DDI_FAILURE) {
			sata_hba_inst->satahba_attached = 1;
			return (DDI_FAILURE);
		}

		/*
		 * Free all target nodes - at this point
		 * devices should be at least offlined
		 * otherwise scsi_hba_detach() should not be called.
		 */
		for (ncport = 0; ncport < SATA_NUM_CPORTS(sata_hba_inst);
		    ncport++) {
			cportinfo = SATA_CPORT_INFO(sata_hba_inst, ncport);
			if (cportinfo->cport_dev_type != SATA_DTYPE_PMULT) {
				sdinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);
				if (sdinfo != NULL) {
					tdip = sata_get_target_dip(dip,
					    ncport);
					if (tdip != NULL) {
						if (ndi_devi_offline(tdip,
						    NDI_DEVI_REMOVE) !=
						    NDI_SUCCESS) {
							SATA_LOG_D((
							    sata_hba_inst,
							    CE_WARN,
							    "sata_hba_detach: "
							    "Target node not "
							    "removed !"));
							return (DDI_FAILURE);
						}
					}
				}
			}
		}
		/*
		 * Disable sata event daemon processing for this HBA
		 */
		sata_hba_inst->satahba_attached = 0;

		/*
		 * Remove event daemon thread, if it is last HBA instance.
		 */

		mutex_enter(&sata_mutex);
		if (sata_hba_list->satahba_next == NULL) {
			mutex_exit(&sata_mutex);
			sata_event_thread_control(0);
			mutex_enter(&sata_mutex);
		}
		mutex_exit(&sata_mutex);

		/* Remove this HBA instance from the HBA list */
		sata_remove_hba_instance(dip);

		/*
		 * At this point there should be no target nodes attached.
		 * Detach and destroy device and port info structures.
		 */
		for (ncport = 0; ncport < SATA_NUM_CPORTS(sata_hba_inst);
		    ncport++) {
			cportinfo = SATA_CPORT_INFO(sata_hba_inst, ncport);
			if (cportinfo->cport_dev_type != SATA_DTYPE_PMULT) {
				sdinfo =
				    cportinfo->cport_devp.cport_sata_drive;
				if (sdinfo != NULL) {
					/* Release device structure */
					kmem_free(sdinfo,
					    sizeof (sata_drive_info_t));
				}
				/* Release cport info */
				mutex_destroy(&cportinfo->cport_mutex);
				kmem_free(cportinfo,
				    sizeof (sata_cport_info_t));
			}
		}

		scsi_hba_tran_free(sata_hba_inst->satahba_scsi_tran);

		(void) ddi_prop_remove(DDI_DEV_T_ANY, dip, "sata");

		taskq_destroy(sata_hba_inst->satahba_taskq);

		mutex_destroy(&sata_hba_inst->satahba_mutex);
		kmem_free((void *)sata_hba_inst,
		    sizeof (struct sata_hba_inst));

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/*
		 * Postponed until phase 2
		 */
		return (DDI_FAILURE);

	default:
		return (DDI_FAILURE);
	}
}


/*
 * Called by an HBA drive from _fini() routine.
 * Unregisters SATA HBA instance/SATA framework pair from the scsi framework.
 */
void
sata_hba_fini(struct modlinkage *modlp)
{
	SATADBG1(SATA_DBG_HBA_IF, NULL,
	    "sata_hba_fini: name %s\n",
	    ((struct modldrv *)(modlp->ml_linkage[0]))->drv_linkinfo);

	scsi_hba_fini(modlp);
}


/*
 * Default open and close routine for sata_hba framework.
 *
 */
/*
 * Open devctl node.
 *
 * Returns:
 * 0 if node was open successfully, error code otherwise.
 *
 *
 */

static int
sata_hba_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(credp))
#endif
	int rv = 0;
	dev_info_t *dip;
	scsi_hba_tran_t *scsi_hba_tran;
	sata_hba_inst_t	*sata_hba_inst;

	SATADBG1(SATA_DBG_IOCTL_IF, NULL, "sata_hba_open: entered", NULL);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	dip = sata_devt_to_devinfo(*devp);
	if (dip == NULL)
		return (ENXIO);

	if ((scsi_hba_tran = ddi_get_driver_private(dip)) == NULL)
		return (ENXIO);

	sata_hba_inst = scsi_hba_tran->tran_hba_private;
	if (sata_hba_inst == NULL || sata_hba_inst->satahba_attached == 0)
		return (ENXIO);

	mutex_enter(&sata_mutex);
	if (flags & FEXCL) {
		if (sata_hba_inst->satahba_open_flag != 0) {
			rv = EBUSY;
		} else {
			sata_hba_inst->satahba_open_flag =
			    SATA_DEVCTL_EXOPENED;
		}
	} else {
		if (sata_hba_inst->satahba_open_flag == SATA_DEVCTL_EXOPENED) {
			rv = EBUSY;
		} else {
			sata_hba_inst->satahba_open_flag =
			    SATA_DEVCTL_SOPENED;
		}
	}
	mutex_exit(&sata_mutex);

	return (rv);
}


/*
 * Close devctl node.
 * Returns:
 * 0 if node was closed successfully, error code otherwise.
 *
 */

static int
sata_hba_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(credp))
	_NOTE(ARGUNUSED(flag))
#endif
	dev_info_t *dip;
	scsi_hba_tran_t *scsi_hba_tran;
	sata_hba_inst_t	*sata_hba_inst;

	SATADBG1(SATA_DBG_IOCTL_IF, NULL, "sata_hba_close: entered", NULL);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	dip = sata_devt_to_devinfo(dev);
	if (dip == NULL)
		return (ENXIO);

	if ((scsi_hba_tran = ddi_get_driver_private(dip)) == NULL)
		return (ENXIO);

	sata_hba_inst = scsi_hba_tran->tran_hba_private;
	if (sata_hba_inst == NULL || sata_hba_inst->satahba_attached == 0)
		return (ENXIO);

	mutex_enter(&sata_mutex);
	sata_hba_inst->satahba_open_flag = 0;
	mutex_exit(&sata_mutex);
	return (0);
}



/*
 * Standard IOCTL commands for SATA hotplugging.
 * Implemented DEVCTL_AP commands:
 * DEVCTL_AP_CONNECT
 * DEVCTL_AP_DISCONNECT
 * DEVCTL_AP_CONFIGURE
 * DEVCTL_UNCONFIGURE
 * DEVCTL_AP_CONTROL
 *
 * Commands passed to default ndi ioctl handler:
 * DEVCTL_DEVICE_GETSTATE
 * DEVCTL_DEVICE_ONLINE
 * DEVCTL_DEVICE_OFFLINE
 * DEVCTL_DEVICE_REMOVE
 * DEVCTL_DEVICE_INSERT
 * DEVCTL_BUS_GETSTATE
 *
 * All other cmds are passed to HBA if it provide ioctl handler, or failed
 * if not.
 *
 * Returns:
 * 0 if successful,
 * error code if operation failed.
 *
 * NOTE: Port Multiplier is not supported.
 *
 */

static int
sata_hba_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(credp))
	_NOTE(ARGUNUSED(rvalp))
#endif
	int rv = 0;
	int32_t	comp_port = -1;
	dev_info_t *dip, *tdip;
	devctl_ap_state_t ap_state;
	struct devctl_iocdata *dcp = NULL;
	scsi_hba_tran_t *scsi_hba_tran;
	sata_hba_inst_t *sata_hba_inst;
	sata_device_t sata_device;
	sata_drive_info_t *sdinfo;
	sata_cport_info_t *cportinfo;
	int cport, pmport, qual;
	int rval = SATA_SUCCESS;

	dip = sata_devt_to_devinfo(dev);
	if (dip == NULL)
		return (ENXIO);

	if ((scsi_hba_tran = ddi_get_driver_private(dip)) == NULL)
		return (ENXIO);

	sata_hba_inst = scsi_hba_tran->tran_hba_private;
	if (sata_hba_inst == NULL)
		return (ENXIO);

	if (sata_hba_inst->satahba_tran == NULL)
		return (ENXIO);

	switch (cmd) {

	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_BUS_GETSTATE:
		/*
		 * There may be more cases that we want to pass to default
		 * handler rather than fail them.
		 */
		return (ndi_devctl_ioctl(dip, cmd, arg, mode, 0));
	}

	/* read devctl ioctl data */
	if (cmd != DEVCTL_AP_CONTROL) {
		if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
			return (EFAULT);

		if ((comp_port = sata_get_port_num(sata_hba_inst, dcp)) ==
		    -1) {
			if (dcp)
				ndi_dc_freehdl(dcp);
			return (EINVAL);
		}

		cport = SCSI_TO_SATA_CPORT(comp_port);
		pmport = SCSI_TO_SATA_PMPORT(comp_port);
		/* Only cport is considered now, i.e. SATA_ADDR_CPORT */
		qual = SATA_ADDR_CPORT;
		if (sata_validate_sata_address(sata_hba_inst, cport, pmport,
		    qual) != 0) {
			ndi_dc_freehdl(dcp);
			return (EINVAL);
		}

		cportinfo = SATA_CPORT_INFO(sata_hba_inst, cport);
		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
		    cport_mutex);
		if (cportinfo->cport_event_flags & SATA_EVNT_LOCK_PORT_BUSY) {
			/*
			 * Cannot process ioctl request now. Come back later.
			 */
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			ndi_dc_freehdl(dcp);
			return (EBUSY);
		}
		/* Block event processing for this port */
		cportinfo->cport_event_flags |= SATA_APCTL_LOCK_PORT_BUSY;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);

		sata_device.satadev_addr.cport = cport;
		sata_device.satadev_addr.pmport = pmport;
		sata_device.satadev_addr.qual = SATA_ADDR_CPORT;
		sata_device.satadev_rev = SATA_DEVICE_REV;
	}

	switch (cmd) {

	case DEVCTL_AP_DISCONNECT:
		/*
		 * Normally, cfgadm sata plugin will try to offline
		 * (unconfigure) device before this request. Nevertheless,
		 * if a device is still configured, we need to
		 * attempt to offline and unconfigure device first, and we will
		 * deactivate the port regardless of the unconfigure
		 * operation results.
		 *
		 * DEVCTL_AP_DISCONNECT invokes
		 * sata_hba_inst->satahba_tran->
		 * sata_tran_hotplug_ops->sata_tran_port_deactivate().
		 * If successful, the device structure (if any) attached
		 * to a port is removed and state of the port marked
		 * appropriately.
		 * Failure of the port_deactivate may keep port in
		 * the active state, or may fail the port.
		 */

		/* Check the current state of the port */
		rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
		    (dip, &sata_device);
		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
		    cport_mutex);
		sata_update_port_info(sata_hba_inst, &sata_device);
		if (rval != SATA_SUCCESS ||
		    (sata_device.satadev_state & SATA_PSTATE_FAILED)) {
			cportinfo->cport_state = SATA_PSTATE_FAILED;
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			rv = EIO;
			break;
		}
		/* Sanity check */
		if (SATA_PORT_DEACTIVATE_FUNC(sata_hba_inst) == NULL) {
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			/* No physical port deactivation supported. */
			break;
		}

		/*
		 * set port's dev_state to not ready - this will disable
		 * an access to an attached device.
		 */
		cportinfo->cport_state &= ~SATA_STATE_READY;

		if (cportinfo->cport_dev_type != SATA_DTYPE_NONE) {
			sdinfo = cportinfo->cport_devp.cport_sata_drive;
			ASSERT(sdinfo != NULL);
			if ((sdinfo->satadrv_type &
			    (SATA_VALID_DEV_TYPE))) {
				/*
				 * If a target node exists, try to offline
				 * a device and remove target node.
				 */
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				tdip = sata_get_target_dip(dip, comp_port);
				if (tdip != NULL && ndi_devi_offline(tdip,
				    NDI_DEVI_REMOVE) != NDI_SUCCESS) {
					/*
					 * Problem
					 * A target node remained
					 * attached. This happens when
					 * the file was open or a node
					 * was waiting for resources.
					 * Cannot do anything about it.
					 */
					SATA_LOG_D((sata_hba_inst, CE_WARN,
					    "sata_hba_ioctl: "
					    "disconnect: could not "
					    "unconfigure device before "
					    "disconnecting the SATA "
					    "port %d", cport));

					/*
					 * Set DEVICE REMOVED state
					 * in the target node. It
					 * will prevent access to
					 * the device even when a
					 * new device is attached,
					 * until the old target node
					 * is released, removed and
					 * recreated for a new
					 * device.
					 */
					sata_set_device_removed(tdip);
					/*
					 * Instruct event daemon to
					 * try the target node cleanup
					 * later.
					 */
					sata_set_target_node_cleanup(
					    sata_hba_inst, cport);
				}
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				/*
				 * Remove and release sata_drive_info
				 * structure.
				 */
				if (SATA_CPORTINFO_DRV_INFO(cportinfo) !=
				    NULL) {
					SATA_CPORTINFO_DRV_INFO(cportinfo) =
					    NULL;
					(void) kmem_free((void *)sdinfo,
					    sizeof (sata_drive_info_t));
					cportinfo->cport_dev_type =
					    SATA_DTYPE_NONE;
				}
			}
			/*
			 * Note: PMult info requires different handling.
			 * Put PMult handling code here, when PMult is
			 * supported.
			 */

		}
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
		/* Just ask HBA driver to deactivate port */
		sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;

		rval = (*SATA_PORT_DEACTIVATE_FUNC(sata_hba_inst))
		    (dip, &sata_device);

		/*
		 * Generate sysevent - EC_DR / ESC_DR_AP_STATE_CHANGE
		 * without the hint.
		 */
		sata_gen_sysevent(sata_hba_inst,
		    &sata_device.satadev_addr, SE_NO_HINT);

		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
		    cport_mutex);
		sata_update_port_info(sata_hba_inst, &sata_device);

		if (rval != SATA_SUCCESS) {
			/*
			 * Port deactivation failure - do not
			 * change port state unless the state
			 * returned by HBA indicates a port failure.
			 */
			if (sata_device.satadev_state & SATA_PSTATE_FAILED)
				cportinfo->cport_state = SATA_PSTATE_FAILED;
			rv = EIO;
		} else {
			/*
			 * Deactivation succeded. From now on the framework
			 * will not know what is happening to the device, until
			 * the port is activated again.
			 */
			cportinfo->cport_state |= SATA_PSTATE_SHUTDOWN;
		}
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
		break;

	case DEVCTL_AP_UNCONFIGURE:

		/*
		 * The unconfigure operation uses generic nexus operation to
		 * offline a device. It leaves a target device node attached.
		 * and obviously sata_drive_info attached as well, because
		 * from the hardware point of view nothing has changed.
		 */
		if ((tdip = sata_get_target_dip(dip, comp_port)) != NULL) {

			if (ndi_devi_offline(tdip, NDI_UNCONFIG) !=
			    NDI_SUCCESS) {
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: unconfigure: "
				    "failed to unconfigure "
				    "device at SATA port %d", cport));
				rv = EIO;
			}
			/*
			 * The target node devi_state should be marked with
			 * DEVI_DEVICE_OFFLINE by ndi_devi_offline().
			 * This would be the indication for cfgadm that
			 * the AP node occupant state is 'unconfigured'.
			 */

		} else {
			/*
			 * This would indicate a failure on the part of cfgadm
			 * to detect correct state of the node prior to this
			 * call - one cannot unconfigure non-existing device.
			 */
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "sata_hba_ioctl: unconfigure: "
			    "attempt to unconfigure non-existing device "
			    "at SATA port %d", cport));
			rv = ENXIO;
		}

		break;

	case DEVCTL_AP_CONNECT:
	{
		/*
		 * The sata cfgadm pluging will invoke this operation only if
		 * port was found in the disconnect state (failed state
		 * is also treated as the disconnected state).
		 * DEVCTL_AP_CONNECT would invoke
		 * sata_hba_inst->satahba_tran->
		 * sata_tran_hotplug_ops->sata_tran_port_activate().
		 * If successful and a device is found attached to the port,
		 * the initialization sequence is executed to attach
		 * a device structure to a port structure. The device is not
		 * set in configured state (system-wise) by this operation.
		 * The state of the port and a device would be set
		 * appropriately.
		 *
		 * Note, that activating the port may generate link events,
		 * so is is important that following processing and the
		 * event processing does not interfere with each other!
		 *
		 * This operation may remove port failed state and will
		 * try to make port active and in good standing.
		 */

		/* We only care about host sata cport for now */

		if (SATA_PORT_ACTIVATE_FUNC(sata_hba_inst) != NULL) {
			/* Just let HBA driver to activate port */

			if ((*SATA_PORT_ACTIVATE_FUNC(sata_hba_inst))
			    (dip, &sata_device) != SATA_SUCCESS) {
				/*
				 * Port activation failure.
				 */
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				sata_update_port_info(sata_hba_inst,
				    &sata_device);
				if (sata_device.satadev_state &
				    SATA_PSTATE_FAILED) {
					cportinfo->cport_state =
					    SATA_PSTATE_FAILED;
				}
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: connect: "
				    "failed to activate SATA port %d",
				    cport));
				rv = EIO;
				break;
			}
		}
		/* Virgin port state - will be updated by the port re-probe. */
		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
		    cport)->cport_mutex);
		cportinfo->cport_state = 0;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
		    cport)->cport_mutex);

		/*
		 * Probe the port to find its state and attached device.
		 */
		if (sata_reprobe_port(sata_hba_inst, &sata_device,
		    SATA_DEV_IDENTIFY_RETRY) == SATA_FAILURE)
			rv = EIO;
		/*
		 * Generate sysevent - EC_DR / ESC_DR_AP_STATE_CHANGE
		 * without the hint
		 */
		sata_gen_sysevent(sata_hba_inst,
		    &sata_device.satadev_addr, SE_NO_HINT);
		/*
		 * If there is a device attached to the port, emit
		 * a message.
		 */
		if (cportinfo->cport_dev_type != SATA_DTYPE_NONE) {
			sata_log(sata_hba_inst, CE_WARN,
			    "SATA device detected at port %d", cport);
		}
		break;
	}

	case DEVCTL_AP_CONFIGURE:
	{
		boolean_t target = TRUE;

		/*
		 * A port may be in an active or shutdown state.
		 * If port is in a failed state, operation is aborted - one
		 * has to use explicit connect or port activate request
		 * to try to get a port into non-failed mode.
		 *
		 * If a port is in a shutdown state, arbitrarily invoke
		 * sata_tran_port_activate() prior to any other operation.
		 *
		 * Verify that port state is READY and there is a device
		 * of a supported type attached to this port.
		 * If target node exists, a device was most likely offlined.
		 * If target node does not exist, create a target node an
		 * attempt to online it.
		 *		 *
		 * NO PMult or devices beyond PMult are supported yet.
		 */

		/* We only care about host controller's sata cport for now. */
		if (cportinfo->cport_state & SATA_PSTATE_FAILED) {
			rv = ENXIO;
			break;
		}
		/* Check the current state of the port */
		sata_device.satadev_addr.qual = SATA_ADDR_CPORT;

		rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
		    (dip, &sata_device);
		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
		    cport_mutex);
		sata_update_port_info(sata_hba_inst, &sata_device);
		if (rval != SATA_SUCCESS ||
		    (sata_device.satadev_state & SATA_PSTATE_FAILED)) {
			cportinfo->cport_state = SATA_PSTATE_FAILED;
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			rv = EIO;
			break;
		}
		if (cportinfo->cport_state & SATA_PSTATE_SHUTDOWN) {
			target = FALSE;
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);

			if (SATA_PORT_ACTIVATE_FUNC(sata_hba_inst) != NULL) {
				/* Just let HBA driver to activate port */
				if ((*SATA_PORT_ACTIVATE_FUNC(sata_hba_inst))
				    (dip, &sata_device) != SATA_SUCCESS) {
					/*
					 * Port activation failure - do not
					 * change port state unless the state
					 * returned by HBA indicates a port
					 * failure.
					 */
					mutex_enter(&SATA_CPORT_INFO(
					    sata_hba_inst, cport)->cport_mutex);
					sata_update_port_info(sata_hba_inst,
					    &sata_device);
					if (sata_device.satadev_state &
					    SATA_PSTATE_FAILED) {
						cportinfo->cport_state =
						    SATA_PSTATE_FAILED;
					}
					mutex_exit(&SATA_CPORT_INFO(
					    sata_hba_inst, cport)->cport_mutex);
					SATA_LOG_D((sata_hba_inst, CE_WARN,
					    "sata_hba_ioctl: configure: "
					    "failed to activate SATA port %d",
					    cport));
					rv = EIO;
					break;
				}
			}
			/*
			 * Generate sysevent - EC_DR / ESC_DR_AP_STATE_CHANGE
			 * without the hint.
			 */
			sata_gen_sysevent(sata_hba_inst,
			    &sata_device.satadev_addr, SE_NO_HINT);

			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			/* Virgin port state */
			cportinfo->cport_state = 0;
		}
		/*
		 * Always reprobe port, to get current device info.
		 */
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
		if (sata_reprobe_port(sata_hba_inst, &sata_device,
		    SATA_DEV_IDENTIFY_RETRY) != SATA_SUCCESS) {
			rv = EIO;
			break;
		}
		if (target == FALSE &&
		    cportinfo->cport_dev_type != SATA_DTYPE_NONE) {
			/*
			 * That's the transition from "inactive" port
			 * to active one with device attached.
			 */
			sata_log(sata_hba_inst, CE_WARN,
			    "SATA device detected at port %d",
			    cport);
		}

		/*
		 * This is where real configure starts.
		 * Change following check for PMult support.
		 */
		if (!(sata_device.satadev_type & SATA_VALID_DEV_TYPE)) {
			/* No device to configure */
			rv = ENXIO; /* No device to configure */
			break;
		}

		/*
		 * Here we may have a device in reset condition,
		 * but because we are just configuring it, there is
		 * no need to process the reset other than just
		 * to clear device reset condition in the HBA driver.
		 * Setting the flag SATA_EVNT_CLEAR_DEVICE_RESET will
		 * cause a first command sent the HBA driver with the request
		 * to clear device reset condition.
		 */
		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
		    cport_mutex);
		sdinfo = sata_get_device_info(sata_hba_inst, &sata_device);
		if (sdinfo == NULL) {
			rv = ENXIO;
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			break;
		}
		if (sdinfo->satadrv_event_flags &
		    (SATA_EVNT_DEVICE_RESET | SATA_EVNT_INPROC_DEVICE_RESET))
			sdinfo->satadrv_event_flags = 0;
		sdinfo->satadrv_event_flags |= SATA_EVNT_CLEAR_DEVICE_RESET;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);

		if ((tdip = sata_get_target_dip(dip, comp_port)) != NULL) {
			/*
			 * Target node exists. Verify, that it belongs
			 * to existing, attached device and not to
			 * a removed device.
			 */
			if (sata_check_device_removed(tdip) == B_FALSE) {
				if (ndi_devi_online(tdip, 0) != NDI_SUCCESS) {
					SATA_LOG_D((sata_hba_inst, CE_WARN,
					    "sata_hba_ioctl: configure: "
					    "onlining device at SATA port %d "
					    "failed", cport));
					rv = EIO;
					break;
				} else {
					mutex_enter(&SATA_CPORT_INFO(
					    sata_hba_inst, cport)->cport_mutex);
					SATA_CPORT_INFO(sata_hba_inst, cport)->
					    cport_tgtnode_clean = B_TRUE;
					mutex_exit(&SATA_CPORT_INFO(
					    sata_hba_inst, cport)->cport_mutex);
				}
			} else {
				sata_log(sata_hba_inst, CE_WARN,
				    "SATA device at port %d cannot be "
				    "configured. "
				    "Application(s) accessing previously "
				    "attached device "
				    "have to release it before newly inserted "
				    "device can be made accessible.",
				    cport);
				break;
			}
		} else {
			/*
			 * No target node - need to create a new target node.
			 */
			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_tgtnode_clean = B_TRUE;
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			tdip = sata_create_target_node(dip, sata_hba_inst,
			    &sata_device.satadev_addr);
			if (tdip == NULL) {
				/* configure failed */
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: configure: "
				    "configuring SATA device at port %d "
				    "failed", cport));
				rv = EIO;
				break;
			}
		}

		break;
	}

	case DEVCTL_AP_GETSTATE:

		sata_cfgadm_state(sata_hba_inst, comp_port, &ap_state);

		ap_state.ap_last_change = (time_t)-1;
		ap_state.ap_error_code = 0;
		ap_state.ap_in_transition = 0;

		/* Copy the return AP-state information to the user space */
		if (ndi_dc_return_ap_state(&ap_state, dcp) != NDI_SUCCESS) {
			rv = EFAULT;
		}
		break;

	case DEVCTL_AP_CONTROL:
	{
		/*
		 * Generic devctl for hardware specific functionality
		 */
		sata_ioctl_data_t	ioc;

		ASSERT(dcp == NULL);

		/* Copy in user ioctl data first */
#ifdef _MULTI_DATAMODEL
		if (ddi_model_convert_from(mode & FMODELS) ==
		    DDI_MODEL_ILP32) {

			sata_ioctl_data_32_t	ioc32;

			if (ddi_copyin((void *)arg, (void *)&ioc32,
			    sizeof (ioc32), mode) != 0) {
				rv = EFAULT;
				break;
			}
			ioc.cmd 	= (uint_t)ioc32.cmd;
			ioc.port	= (uint_t)ioc32.port;
			ioc.get_size	= (uint_t)ioc32.get_size;
			ioc.buf		= (caddr_t)(uintptr_t)ioc32.buf;
			ioc.bufsiz	= (uint_t)ioc32.bufsiz;
			ioc.misc_arg	= (uint_t)ioc32.misc_arg;
		} else
#endif /* _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, (void *)&ioc, sizeof (ioc),
		    mode) != 0) {
			return (EFAULT);
		}

		SATADBG2(SATA_DBG_IOCTL_IF, sata_hba_inst,
		    "sata_hba_ioctl: DEVCTL_AP_CONTROL "
		    "cmd 0x%x, port 0x%x", ioc.cmd, ioc.port);

		/*
		 * To avoid BE/LE and 32/64 issues, a get_size always returns
		 * a 32-bit number.
		 */
		if (ioc.get_size != 0 && ioc.bufsiz != (sizeof (uint32_t))) {
			return (EINVAL);
		}
		/* validate address */
		cport = SCSI_TO_SATA_CPORT(ioc.port);
		pmport = SCSI_TO_SATA_PMPORT(ioc.port);
		qual = SCSI_TO_SATA_ADDR_QUAL(ioc.port);

		/* Override address qualifier - handle cport only for now */
		qual = SATA_ADDR_CPORT;

		if (sata_validate_sata_address(sata_hba_inst, cport,
		    pmport, qual) != 0)
			return (EINVAL);

		cportinfo = SATA_CPORT_INFO(sata_hba_inst, cport);
		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
		    cport_mutex);
		/* Is the port locked by event processing daemon ? */
		if (cportinfo->cport_event_flags & SATA_EVNT_LOCK_PORT_BUSY) {
			/*
			 * Cannot process ioctl request now. Come back later
			 */
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			return (EBUSY);
		}
		/* Block event processing for this port */
		cportinfo->cport_event_flags |= SATA_APCTL_LOCK_PORT_BUSY;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);


		sata_device.satadev_addr.cport = cport;
		sata_device.satadev_addr.pmport = pmport;
		sata_device.satadev_rev = SATA_DEVICE_REV;

		switch (ioc.cmd) {

		case SATA_CFGA_RESET_PORT:
			/*
			 * There is no protection here for configured
			 * device.
			 */

			/* Sanity check */
			if (SATA_RESET_DPORT_FUNC(sata_hba_inst) == NULL) {
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: "
				    "sata_hba_tran missing required "
				    "function sata_tran_reset_dport"));
				rv = EINVAL;
				break;
			}

			/* handle cport only for now */
			sata_device.satadev_addr.qual = SATA_ADDR_CPORT;
			if ((*SATA_RESET_DPORT_FUNC(sata_hba_inst))
			    (dip, &sata_device) != SATA_SUCCESS) {
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: reset port: "
				    "failed cport %d pmport %d",
				    cport, pmport));
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				sata_update_port_info(sata_hba_inst,
				    &sata_device);
				SATA_CPORT_STATE(sata_hba_inst, cport) =
				    SATA_PSTATE_FAILED;
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				rv = EIO;
			}
			/*
			 * Since the port was reset, it should be probed and
			 * attached device reinitialized. At this point the
			 * port state is unknown - it's state is HBA-specific.
			 * Re-probe port to get its state.
			 */
			if (sata_reprobe_port(sata_hba_inst, &sata_device,
			    SATA_DEV_IDENTIFY_RETRY) != SATA_SUCCESS) {
				rv = EIO;
				break;
			}
			break;

		case SATA_CFGA_RESET_DEVICE:
			/*
			 * There is no protection here for configured
			 * device.
			 */

			/* Sanity check */
			if (SATA_RESET_DPORT_FUNC(sata_hba_inst) == NULL) {
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: "
				    "sata_hba_tran missing required "
				    "function sata_tran_reset_dport"));
				rv = EINVAL;
				break;
			}

			/* handle only device attached to cports, for now */
			sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;

			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			sdinfo = sata_get_device_info(sata_hba_inst,
			    &sata_device);
			if (sdinfo == NULL) {
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				rv = EINVAL;
				break;
			}
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);

			/* only handle cport for now */
			sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;
			if ((*SATA_RESET_DPORT_FUNC(sata_hba_inst))
			    (dip, &sata_device) != SATA_SUCCESS) {
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: reset device: failed "
				    "cport %d pmport %d", cport, pmport));
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				sata_update_port_info(sata_hba_inst,
				    &sata_device);
				/*
				 * Device info structure remains
				 * attached. Another device reset or
				 * port disconnect/connect and re-probing is
				 * needed to change it's state
				 */
				sdinfo->satadrv_state &= ~SATA_STATE_READY;
				sdinfo->satadrv_state |=
				    SATA_DSTATE_FAILED;
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				rv = EIO;
			}
			/*
			 * Since the device was reset, we expect reset event
			 * to be reported and processed.
			 */
			break;

		case SATA_CFGA_RESET_ALL:
		{
			int tcport;

			/*
			 * There is no protection here for configured
			 * devices.
			 */
			/* Sanity check */
			if (SATA_RESET_DPORT_FUNC(sata_hba_inst) == NULL) {
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: "
				    "sata_hba_tran missing required "
				    "function sata_tran_reset_dport"));
				rv = EINVAL;
				break;
			}

			/*
			 * Need to lock all ports, not just one.
			 * If any port is locked by event processing, fail
			 * the whole operation.
			 * One port is already locked, but for simplicity
			 * lock it again.
			 */
			for (tcport = 0;
			    tcport < SATA_NUM_CPORTS(sata_hba_inst);
			    tcport++) {
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    tcport)->cport_mutex);
				if (((SATA_CPORT_INFO(sata_hba_inst, tcport)->
				    cport_event_flags) &
				    SATA_EVNT_LOCK_PORT_BUSY) != 0) {
					rv = EBUSY;
					mutex_exit(
					    &SATA_CPORT_INFO(sata_hba_inst,
					    tcport)->cport_mutex);
					break;
				} else {
					SATA_CPORT_INFO(sata_hba_inst,
					    tcport)->cport_event_flags |=
					    SATA_APCTL_LOCK_PORT_BUSY;
				}
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    tcport)->cport_mutex);
			}

			if (rv == 0) {
				/*
				 * All cports successfully locked.
				 * Reset main SATA controller only for now -
				 * no PMult.
				 */
				sata_device.satadev_addr.qual =
				    SATA_ADDR_CNTRL;

				if ((*SATA_RESET_DPORT_FUNC(sata_hba_inst))
				    (dip, &sata_device) != SATA_SUCCESS) {
					SATA_LOG_D((sata_hba_inst, CE_WARN,
					    "sata_hba_ioctl: reset controller "
					    "failed"));
					rv = EIO;
				}

				/*
				 * Since ports were reset, they should be
				 * re-probed and attached devices
				 * reinitialized.
				 * At this point port states are unknown,
				 * Re-probe ports to get their state -
				 * cports only for now.
				 */
				for (tcport = 0;
				    tcport < SATA_NUM_CPORTS(sata_hba_inst);
				    tcport++) {
					sata_device.satadev_addr.cport =
					    tcport;
					sata_device.satadev_addr.qual =
					    SATA_ADDR_CPORT;

					if (sata_reprobe_port(sata_hba_inst,
					    &sata_device,
					    SATA_DEV_IDENTIFY_RETRY) !=
					    SATA_SUCCESS)
						rv = EIO;

				}
			}
			/*
			 * Unlock all ports
			 */
			for (tcport = 0;
			    tcport < SATA_NUM_CPORTS(sata_hba_inst);
			    tcport++) {
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    tcport)->cport_mutex);
				SATA_CPORT_INFO(sata_hba_inst, tcport)->
				    cport_event_flags &=
				    ~SATA_APCTL_LOCK_PORT_BUSY;
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    tcport)->cport_mutex);
			}

			/*
			 * This operation returns EFAULT if either reset
			 * controller failed or a re-probing of any ports
			 * failed.
			 * We return here, because common return is for
			 * a single cport operation.
			 */
			return (rv);
		}

		case SATA_CFGA_PORT_DEACTIVATE:
			/* Sanity check */
			if (SATA_PORT_DEACTIVATE_FUNC(sata_hba_inst) == NULL) {
				rv = ENOTSUP;
				break;
			}
			/*
			 * Arbitrarily unconfigure attached device, if any.
			 * Even if the unconfigure fails, proceed with the
			 * port deactivation.
			 */

			/* Handle only device attached to cports, for now */
			sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;

			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			cportinfo->cport_state &= ~SATA_STATE_READY;
			if (cportinfo->cport_dev_type != SATA_DTYPE_NONE) {
				/*
				 * Handle only device attached to cports,
				 * for now
				 */
				sata_device.satadev_addr.qual =
				    SATA_ADDR_DCPORT;
				sdinfo = sata_get_device_info(sata_hba_inst,
				    &sata_device);
				if (sdinfo != NULL &&
				    (sdinfo->satadrv_type &
				    SATA_VALID_DEV_TYPE)) {
					/*
					 * If a target node exists, try to
					 * offline a device and remove target
					 * node.
					 */
					mutex_exit(&SATA_CPORT_INFO(
					    sata_hba_inst, cport)->cport_mutex);
					tdip = sata_get_target_dip(dip, cport);
					if (tdip != NULL) {
						/* target node exist */
						SATADBG1(SATA_DBG_IOCTL_IF,
						    sata_hba_inst,
						    "sata_hba_ioctl: "
						    "port deactivate: "
						    "target node exists.",
						    NULL);

						if (ndi_devi_offline(tdip,
						    NDI_DEVI_REMOVE) !=
						    NDI_SUCCESS) {
							SATA_LOG_D((
							    sata_hba_inst,
							    CE_WARN,
							    "sata_hba_ioctl:"
							    "port deactivate: "
							    "failed to "
							    "unconfigure "
							    "device at port "
							    "%d before "
							    "deactivating "
							    "the port", cport));
							/*
							 * Set DEVICE REMOVED
							 * state in the target
							 * node. It will
							 * prevent access to
							 * the device even when
							 * a new device is
							 * attached, until the
							 * old target node is
							 * released, removed and
							 * recreated for a new
							 * device.
							 */
							sata_set_device_removed
							    (tdip);
							/*
							 * Instruct event
							 * daemon to try the
							 * target node cleanup
							 * later.
							 */
						sata_set_target_node_cleanup(
						    sata_hba_inst, cport);
						}
					}
					mutex_enter(&SATA_CPORT_INFO(
					    sata_hba_inst, cport)->cport_mutex);
					/*
					 * In any case,
					 * remove and release sata_drive_info
					 * structure.
					 * (cport attached device ony, for now)
					 */
					SATA_CPORTINFO_DRV_INFO(cportinfo) =
					    NULL;
					(void) kmem_free((void *)sdinfo,
					    sizeof (sata_drive_info_t));
					cportinfo->cport_dev_type =
					    SATA_DTYPE_NONE;
				}
				/*
				 * Note: PMult info requires different
				 * handling. This comment is a placeholder for
				 * a code handling PMult, to be implemented
				 * in phase 2.
				 */
			}
			cportinfo->cport_state &= ~(SATA_STATE_PROBED |
			    SATA_STATE_PROBING);
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			/* handle cport only for now */
			sata_device.satadev_addr.qual = SATA_ADDR_CPORT;
			/* Just let HBA driver to deactivate port */
			rval = (*SATA_PORT_DEACTIVATE_FUNC(sata_hba_inst))
			    (dip, &sata_device);
			/*
			 * Generate sysevent -
			 * EC_DR / ESC_DR_AP_STATE_CHANGE
			 * without the hint
			 */
			sata_gen_sysevent(sata_hba_inst,
			    &sata_device.satadev_addr, SE_NO_HINT);

			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			sata_update_port_info(sata_hba_inst, &sata_device);
			if (rval != SATA_SUCCESS) {
				/*
				 * Port deactivation failure - do not
				 * change port state unless the state
				 * returned by HBA indicates a port failure.
				 */
				if (sata_device.satadev_state &
				    SATA_PSTATE_FAILED) {
					SATA_CPORT_STATE(sata_hba_inst,
					    cport) = SATA_PSTATE_FAILED;
				}
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: port deactivate: "
				    "cannot deactivate SATA port %d",
				    cport));
				rv = EIO;
			} else {
				cportinfo->cport_state |= SATA_PSTATE_SHUTDOWN;
			}
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);

			break;

		case SATA_CFGA_PORT_ACTIVATE:
		{
			boolean_t dev_existed = TRUE;

			/* Sanity check */
			if (SATA_PORT_ACTIVATE_FUNC(sata_hba_inst) == NULL) {
				rv = ENOTSUP;
				break;
			}
			/* handle cport only for now */
			if (cportinfo->cport_state & SATA_PSTATE_SHUTDOWN ||
			    cportinfo->cport_dev_type == SATA_DTYPE_NONE)
				dev_existed = FALSE;

			sata_device.satadev_addr.qual = SATA_ADDR_CPORT;
			/* Just let HBA driver to activate port */
			if ((*SATA_PORT_ACTIVATE_FUNC(sata_hba_inst))
			    (dip, &sata_device) != SATA_SUCCESS) {
				/*
				 * Port activation failure - do not
				 * change port state unless the state
				 * returned by HBA indicates a port failure.
				 */
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				sata_update_port_info(sata_hba_inst,
				    &sata_device);
				if (sata_device.satadev_state &
				    SATA_PSTATE_FAILED) {
					SATA_CPORT_STATE(sata_hba_inst,
					    cport) = SATA_PSTATE_FAILED;
				}
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: port activate: "
				    "cannot activate SATA port %d",
				    cport));
				rv = EIO;
				break;
			}
			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			cportinfo->cport_state &= ~SATA_PSTATE_SHUTDOWN;
			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);

			/*
			 * Re-probe port to find its current state and
			 * possibly attached device.
			 * Port re-probing may change the cportinfo device
			 * type if device is found attached.
			 * If port probing failed, the device type would be
			 * set to SATA_DTYPE_NONE.
			 */
			(void) sata_reprobe_port(sata_hba_inst, &sata_device,
			    SATA_DEV_IDENTIFY_RETRY);

			/*
			 * Generate sysevent -
			 * EC_DR / ESC_DR_AP_STATE_CHANGE
			 * without the hint.
			 */
			sata_gen_sysevent(sata_hba_inst,
			    &sata_device.satadev_addr, SE_NO_HINT);

			if (dev_existed == FALSE &&
			    cportinfo->cport_dev_type != SATA_DTYPE_NONE) {
				/*
				 * That's the transition from "inactive" port
				 * state or active port without a device
				 * attached to the active port state with
				 * a device attached.
				 */
				sata_log(sata_hba_inst, CE_WARN,
				    "SATA device detected at port %d", cport);
			}

			break;
		}

		case SATA_CFGA_PORT_SELF_TEST:

			/* Sanity check */
			if (SATA_SELFTEST_FUNC(sata_hba_inst) == NULL) {
				rv = ENOTSUP;
				break;
			}
			/*
			 * There is no protection here for a configured
			 * device attached to this port.
			 */

			/* only handle cport for now */
			sata_device.satadev_addr.qual = SATA_ADDR_CPORT;

			if ((*SATA_SELFTEST_FUNC(sata_hba_inst))
			    (dip, &sata_device) != SATA_SUCCESS) {
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "sata_hba_ioctl: port selftest: "
				    "failed cport %d pmport %d",
				    cport, pmport));
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				sata_update_port_info(sata_hba_inst,
				    &sata_device);
				SATA_CPORT_STATE(sata_hba_inst, cport) =
				    SATA_PSTATE_FAILED;
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				rv = EIO;
				break;
			}
			/*
			 * Since the port was reset, it should be probed and
			 * attached device reinitialized. At this point the
			 * port state is unknown - it's state is HBA-specific.
			 * Force port re-probing to get it into a known state.
			 */
			if (sata_reprobe_port(sata_hba_inst, &sata_device,
			    SATA_DEV_IDENTIFY_RETRY) != SATA_SUCCESS) {
				rv = EIO;
				break;
			}
			break;

		case SATA_CFGA_GET_DEVICE_PATH:
		{
			char		path[MAXPATHLEN];
			uint32_t	size;

			(void) strcpy(path, "/devices");
			if ((tdip = sata_get_target_dip(dip, ioc.port)) ==
			    NULL) {

				/*
				 * No such device.
				 * If this is a request for a size, do not
				 * return EINVAL for non-exisiting target,
				 * because cfgadm will indicate a meaningless
				 * ioctl failure.
				 * If this is a real request for a path,
				 * indicate invalid argument.
				 */
				if (!ioc.get_size) {
					rv = EINVAL;
					break;
				}
			} else {
				(void) ddi_pathname(tdip, path + strlen(path));
			}
			size = strlen(path) + 1;

			if (ioc.get_size) {
				if (ddi_copyout((void *)&size,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
				}
			} else {
				if (ioc.bufsiz != size) {
					rv = EINVAL;
				} else if (ddi_copyout((void *)&path,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
				}
			}
			break;
		}

		case SATA_CFGA_GET_AP_TYPE:
		{
			uint32_t	type_len;
			const char	*ap_type;

			/* cport only, no port multiplier support */
			switch (SATA_CPORT_DEV_TYPE(sata_hba_inst, cport)) {
			case SATA_DTYPE_NONE:
				ap_type = "port";
				break;

			case SATA_DTYPE_ATADISK:
				ap_type = "disk";
				break;

			case SATA_DTYPE_ATAPICD:
				ap_type = "cd/dvd";
				break;

			case SATA_DTYPE_PMULT:
				ap_type = "pmult";
				break;

			case SATA_DTYPE_UNKNOWN:
				ap_type = "unknown";
				break;

			default:
				ap_type = "unsupported";
				break;

			} /* end of dev_type switch */

			type_len = strlen(ap_type) + 1;

			if (ioc.get_size) {
				if (ddi_copyout((void *)&type_len,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
					break;
				}
			} else {
				if (ioc.bufsiz != type_len) {
					rv = EINVAL;
					break;
				}
				if (ddi_copyout((void *)ap_type, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
					break;
				}
			}

			break;
		}

		case SATA_CFGA_GET_MODEL_INFO:
		{
			uint32_t info_len;
			char ap_info[sizeof (sdinfo->satadrv_id.ai_model) + 1];

			/*
			 * This operation should return to cfgadm the
			 * device model information string
			 */
			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			/* only handle device connected to cport for now */
			sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;
			sdinfo = sata_get_device_info(sata_hba_inst,
			    &sata_device);
			if (sdinfo == NULL) {
				rv = EINVAL;
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				break;
			}
			bcopy(sdinfo->satadrv_id.ai_model, ap_info,
			    sizeof (sdinfo->satadrv_id.ai_model));
			swab(ap_info, ap_info,
			    sizeof (sdinfo->satadrv_id.ai_model));
			ap_info[sizeof (sdinfo->satadrv_id.ai_model)] = '\0';

			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);

			info_len = strlen(ap_info) + 1;

			if (ioc.get_size) {
				if (ddi_copyout((void *)&info_len,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
					break;
				}
			} else {
				if (ioc.bufsiz < info_len) {
					rv = EINVAL;
					break;
				}
				if (ddi_copyout((void *)ap_info, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
					break;
				}
			}

			break;
		}

		case SATA_CFGA_GET_REVFIRMWARE_INFO:
		{
			uint32_t info_len;
			char ap_info[
			    sizeof (sdinfo->satadrv_id.ai_fw) + 1];

			/*
			 * This operation should return to cfgadm the
			 * device firmware revision information string
			 */
			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			/* only handle device connected to cport for now */
			sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;

			sdinfo = sata_get_device_info(sata_hba_inst,
			    &sata_device);
			if (sdinfo == NULL) {
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				rv = EINVAL;
				break;
			}
			bcopy(sdinfo->satadrv_id.ai_fw, ap_info,
			    sizeof (sdinfo->satadrv_id.ai_fw));
			swab(ap_info, ap_info,
			    sizeof (sdinfo->satadrv_id.ai_fw));
			ap_info[sizeof (sdinfo->satadrv_id.ai_fw)] = '\0';

			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);

			info_len = strlen(ap_info) + 1;

			if (ioc.get_size) {
				if (ddi_copyout((void *)&info_len,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
					break;
				}
			} else {
				if (ioc.bufsiz < info_len) {
					rv = EINVAL;
					break;
				}
				if (ddi_copyout((void *)ap_info, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
					break;
				}
			}

			break;
		}

		case SATA_CFGA_GET_SERIALNUMBER_INFO:
		{
			uint32_t info_len;
			char ap_info[
			    sizeof (sdinfo->satadrv_id.ai_drvser) + 1];

			/*
			 * This operation should return to cfgadm the
			 * device serial number information string
			 */
			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);
			/* only handle device connected to cport for now */
			sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;

			sdinfo = sata_get_device_info(sata_hba_inst,
			    &sata_device);
			if (sdinfo == NULL) {
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    cport)->cport_mutex);
				rv = EINVAL;
				break;
			}
			bcopy(sdinfo->satadrv_id.ai_drvser, ap_info,
			    sizeof (sdinfo->satadrv_id.ai_drvser));
			swab(ap_info, ap_info,
			    sizeof (sdinfo->satadrv_id.ai_drvser));
			ap_info[sizeof (sdinfo->satadrv_id.ai_drvser)] = '\0';

			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->
			    cport_mutex);

			info_len = strlen(ap_info) + 1;

			if (ioc.get_size) {
				if (ddi_copyout((void *)&info_len,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
					break;
				}
			} else {
				if (ioc.bufsiz < info_len) {
					rv = EINVAL;
					break;
				}
				if (ddi_copyout((void *)ap_info, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					rv = EFAULT;
					break;
				}
			}

			break;
		}

		default:
			rv = EINVAL;
			break;

		} /* End of DEVCTL_AP_CONTROL cmd switch */

		break;
	}

	default:
	{
		/*
		 * If we got here, we got an IOCTL that SATA HBA Framework
		 * does not recognize. Pass ioctl to HBA driver, in case
		 * it could process it.
		 */
		sata_hba_tran_t *sata_tran = sata_hba_inst->satahba_tran;
		dev_info_t	*mydip = SATA_DIP(sata_hba_inst);

		SATADBG1(SATA_DBG_IOCTL_IF, sata_hba_inst,
		    "IOCTL 0x%2x not supported in SATA framework, "
		    "passthrough to HBA", cmd);

		if (sata_tran->sata_tran_ioctl == NULL) {
			rv = EINVAL;
			break;
		}
		rval = (*sata_tran->sata_tran_ioctl)(mydip, cmd, arg);
		if (rval != 0) {
			SATADBG1(SATA_DBG_IOCTL_IF, sata_hba_inst,
			    "IOCTL 0x%2x failed in HBA", cmd);
			rv = rval;
		}
		break;
	}

	} /* End of main IOCTL switch */

	if (dcp) {
		ndi_dc_freehdl(dcp);
	}
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
	cportinfo->cport_event_flags &= ~SATA_APCTL_LOCK_PORT_BUSY;
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);

	return (rv);
}


/*
 * Create error retrieval sata packet
 *
 * A sata packet is allocated and set-up to contain specified error retrieval
 * command and appropriate dma-able data buffer.
 * No association with any scsi packet is made and no callback routine is
 * specified.
 *
 * Returns a pointer to sata packet upon successfull packet creation.
 * Returns NULL, if packet cannot be created.
 */
sata_pkt_t *
sata_get_error_retrieval_pkt(dev_info_t *dip, sata_device_t *sata_device,
    int pkt_type)
{
	sata_hba_inst_t	*sata_hba_inst;
	sata_pkt_txlate_t *spx;
	sata_pkt_t *spkt;
	sata_drive_info_t *sdinfo;

	mutex_enter(&sata_mutex);
	for (sata_hba_inst = sata_hba_list; sata_hba_inst != NULL;
	    sata_hba_inst = sata_hba_inst->satahba_next) {
		if (SATA_DIP(sata_hba_inst) == dip)
			break;
	}
	mutex_exit(&sata_mutex);
	ASSERT(sata_hba_inst != NULL);

	sdinfo = sata_get_device_info(sata_hba_inst, sata_device);
	if (sdinfo == NULL) {
		sata_log(sata_hba_inst, CE_WARN,
		    "sata: error recovery request for non-attached device at "
		    "cport %d", sata_device->satadev_addr.cport);
		return (NULL);
	}

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, NULL);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (NULL);
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = sata_device->satadev_addr;

	switch (pkt_type) {
	case SATA_ERR_RETR_PKT_TYPE_NCQ:
		if (sata_ncq_err_ret_cmd_setup(spx, sdinfo) == SATA_SUCCESS)
			return (spkt);
		break;

	case SATA_ERR_RETR_PKT_TYPE_ATAPI:
		if (sata_atapi_err_ret_cmd_setup(spx, sdinfo) == SATA_SUCCESS)
			return (spkt);
		break;

	default:
		break;
	}

	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));
	return (NULL);

}


/*
 * Free error retrieval sata packet
 *
 * Free sata packet and any associated resources allocated previously by
 * sata_get_error_retrieval_pkt().
 *
 * Void return.
 */
void
sata_free_error_retrieval_pkt(sata_pkt_t *sata_pkt)
{
	sata_pkt_txlate_t *spx =
	    (sata_pkt_txlate_t *)sata_pkt->satapkt_framework_private;

	ASSERT(sata_pkt != NULL);

	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));

}


/* ****************** SCSA required entry points *********************** */

/*
 * Implementation of scsi tran_tgt_init.
 * sata_scsi_tgt_init() initializes scsi_device structure
 *
 * If successful, DDI_SUCCESS is returned.
 * DDI_FAILURE is returned if addressed device does not exist
 */

static int
sata_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(hba_dip))
	_NOTE(ARGUNUSED(tgt_dip))
#endif
	sata_device_t		sata_device;
	sata_drive_info_t	*sdinfo;
	struct sata_id		*sid;
	sata_hba_inst_t		*sata_hba_inst;
	char			model[SATA_ID_MODEL_LEN + 1];
	char			fw[SATA_ID_FW_LEN + 1];
	char			*vid, *pid;
	int			i;

	sata_hba_inst = (sata_hba_inst_t *)(hba_tran->tran_hba_private);

	/* Validate scsi device address */
	if (sata_validate_scsi_address(sata_hba_inst, &sd->sd_address,
	    &sata_device) != 0)
		return (DDI_FAILURE);

	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));

	/* sata_device now contains a valid sata address */
	sdinfo = sata_get_device_info(sata_hba_inst, &sata_device);
	if (sdinfo == NULL) {
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device.satadev_addr.cport)));
		return (DDI_FAILURE);
	}
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));

	/*
	 * Check if we need to create a legacy devid (i.e cmdk style) for
	 * the target disks.
	 *
	 * HBA devinfo node will have the property "use-cmdk-devid-format"
	 * if we need to create cmdk-style devid for all the disk devices
	 * attached to this controller. This property may have been set
	 * from HBA driver's .conf file or by the HBA driver in its
	 * attach(9F) function.
	 */
	if ((sdinfo->satadrv_type == SATA_DTYPE_ATADISK) &&
	    (ddi_getprop(DDI_DEV_T_ANY, hba_dip, DDI_PROP_DONTPASS,
	    "use-cmdk-devid-format", 0) == 1)) {
		/* register a legacy devid for this target node */
		sata_target_devid_register(tgt_dip, sdinfo);
	}


	/*
	 * 'Identify Device Data' does not always fit in standard SCSI
	 * INQUIRY data, so establish INQUIRY_* properties with full-form
	 * of information.
	 */
	sid = &sdinfo->satadrv_id;
#ifdef	_LITTLE_ENDIAN
	swab(sid->ai_model, model, SATA_ID_MODEL_LEN);
	swab(sid->ai_fw, fw, SATA_ID_FW_LEN);
#else	/* _LITTLE_ENDIAN */
	bcopy(sid->ai_model, model, SATA_ID_MODEL_LEN);
	bcopy(sid->ai_fw, fw, SATA_ID_FW_LEN);
#endif	/* _LITTLE_ENDIAN */
	model[SATA_ID_MODEL_LEN] = 0;
	fw[SATA_ID_FW_LEN] = 0;

	/* split model into into vid/pid */
	for (i = 0, pid = model; i < SATA_ID_MODEL_LEN; i++, pid++)
		if ((*pid == ' ') || (*pid == '\t'))
			break;
	if (i < SATA_ID_MODEL_LEN) {
		vid = model;
		*pid++ = 0;		/* terminate vid, establish pid */
	} else {
		vid = NULL;		/* vid will stay "ATA     " */
		pid = model;		/* model is all pid */
	}

	if (vid)
		(void) scsi_hba_prop_update_inqstring(sd, INQUIRY_VENDOR_ID,
		    vid, strlen(vid));
	if (pid)
		(void) scsi_hba_prop_update_inqstring(sd, INQUIRY_PRODUCT_ID,
		    pid, strlen(pid));
	(void) scsi_hba_prop_update_inqstring(sd, INQUIRY_REVISION_ID,
	    fw, strlen(fw));

	return (DDI_SUCCESS);
}

/*
 * Implementation of scsi tran_tgt_probe.
 * Probe target, by calling default scsi routine scsi_hba_probe()
 */
static int
sata_scsi_tgt_probe(struct scsi_device *sd, int (*callback)(void))
{
	sata_hba_inst_t *sata_hba_inst =
	    (sata_hba_inst_t *)(sd->sd_address.a_hba_tran->tran_hba_private);
	int rval;

	rval = scsi_hba_probe(sd, callback);

	if (rval == SCSIPROBE_EXISTS) {
		/*
		 * Set property "pm-capable" on the target device node, so that
		 * the target driver will not try to fetch scsi cycle counters
		 * before enabling device power-management.
		 */
		if ((ddi_prop_update_int(DDI_DEV_T_NONE, sd->sd_dev,
		    "pm-capable", 1)) != DDI_PROP_SUCCESS) {
			sata_log(sata_hba_inst, CE_WARN,
			    "SATA device at port %d: "
			    "will not be power-managed ",
			    SCSI_TO_SATA_CPORT(sd->sd_address.a_target));
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "failure updating pm-capable property"));
		}
	}
	return (rval);
}

/*
 * Implementation of scsi tran_tgt_free.
 * Release all resources allocated for scsi_device
 */
static void
sata_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(hba_dip))
#endif
	sata_device_t		sata_device;
	sata_drive_info_t	*sdinfo;
	sata_hba_inst_t		*sata_hba_inst;
	ddi_devid_t		devid;

	sata_hba_inst = (sata_hba_inst_t *)(hba_tran->tran_hba_private);

	/* Validate scsi device address */
	if (sata_validate_scsi_address(sata_hba_inst, &sd->sd_address,
	    &sata_device) != 0)
		return;

	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));

	/* sata_device now should contain a valid sata address */
	sdinfo = sata_get_device_info(sata_hba_inst, &sata_device);
	if (sdinfo == NULL) {
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device.satadev_addr.cport)));
		return;
	}
	/*
	 * We did not allocate any resources in sata_scsi_tgt_init()
	 * other than few properties.
	 * Free them.
	 */
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	if (ndi_prop_remove(DDI_DEV_T_NONE, tgt_dip, "pm-capable") !=
	    DDI_PROP_SUCCESS)
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_scsi_tgt_free: pm-capable "
		    "property could not be removed"));

	/*
	 * If devid was previously created but not freed up from
	 * sd(7D) driver (i.e during detach(9F)) then do it here.
	 */
	if ((sdinfo->satadrv_type == SATA_DTYPE_ATADISK) &&
	    (ddi_getprop(DDI_DEV_T_ANY, hba_dip, DDI_PROP_DONTPASS,
	    "use-cmdk-devid-format", 0) == 1) &&
	    (ddi_devid_get(tgt_dip, &devid) == DDI_SUCCESS)) {
		ddi_devid_unregister(tgt_dip);
		ddi_devid_free(devid);
	}
}

/*
 * Implementation of scsi tran_init_pkt
 * Upon successful return, scsi pkt buffer has DMA resources allocated.
 *
 * It seems that we should always allocate pkt, even if the address is
 * for non-existing device - just use some default for dma_attr.
 * The reason is that there is no way to communicate this to a caller here.
 * Subsequent call to sata_scsi_start may fail appropriately.
 * Simply returning NULL does not seem to discourage a target driver...
 *
 * Returns a pointer to initialized scsi_pkt, or NULL otherwise.
 */
static struct scsi_pkt *
sata_scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
    int (*callback)(caddr_t), caddr_t arg)
{
	sata_hba_inst_t *sata_hba_inst =
	    (sata_hba_inst_t *)(ap->a_hba_tran->tran_hba_private);
	dev_info_t *dip = SATA_DIP(sata_hba_inst);
	sata_device_t sata_device;
	sata_drive_info_t *sdinfo;
	sata_pkt_txlate_t *spx;
	ddi_dma_attr_t cur_dma_attr;
	int rval;
	boolean_t new_pkt = TRUE;

	ASSERT(ap->a_hba_tran->tran_hba_dip == dip);

	/*
	 * We need to translate the address, even if it could be
	 * a bogus one, for a non-existing device
	 */
	sata_device.satadev_addr.qual = SCSI_TO_SATA_ADDR_QUAL(ap->a_target);
	sata_device.satadev_addr.cport = SCSI_TO_SATA_CPORT(ap->a_target);
	sata_device.satadev_addr.pmport = SCSI_TO_SATA_PMPORT(ap->a_target);
	sata_device.satadev_rev = SATA_DEVICE_REV;

	if (pkt == NULL) {
		/*
		 * Have to allocate a brand new scsi packet.
		 * We need to operate with auto request sense enabled.
		 */
		pkt = scsi_hba_pkt_alloc(dip, ap, cmdlen,
		    MAX(statuslen, sizeof (struct scsi_arq_status)),
		    tgtlen, sizeof (sata_pkt_txlate_t), callback, arg);

		if (pkt == NULL)
			return (NULL);

		/* Fill scsi packet structure */
		pkt->pkt_comp		= (void (*)())NULL;
		pkt->pkt_time		= 0;
		pkt->pkt_resid		= 0;
		pkt->pkt_statistics	= 0;
		pkt->pkt_reason		= 0;

		/*
		 * pkt_hba_private will point to sata pkt txlate structure
		 */
		spx = (sata_pkt_txlate_t *)pkt->pkt_ha_private;
		bzero(spx, sizeof (sata_pkt_txlate_t));

		spx->txlt_scsi_pkt = pkt;
		spx->txlt_sata_hba_inst = sata_hba_inst;

		/* Allocate sata_pkt */
		spx->txlt_sata_pkt = sata_pkt_alloc(spx, callback);
		if (spx->txlt_sata_pkt == NULL) {
			/* Could not allocate sata pkt */
			scsi_hba_pkt_free(ap, pkt);
			return (NULL);
		}
		/* Set sata address */
		spx->txlt_sata_pkt->satapkt_device.satadev_addr =
		    sata_device.satadev_addr;
		spx->txlt_sata_pkt->satapkt_device.satadev_rev =
		    sata_device.satadev_rev;

		if ((bp == NULL) || (bp->b_bcount == 0))
			return (pkt);

		spx->txlt_total_residue = bp->b_bcount;
	} else {
		new_pkt = FALSE;
		/*
		 * Packet was preallocated/initialized by previous call
		 */
		spx = (sata_pkt_txlate_t *)pkt->pkt_ha_private;

		if ((bp == NULL) || (bp->b_bcount == 0)) {
			return (pkt);
		}
		ASSERT(spx->txlt_buf_dma_handle != NULL);

		/* Pkt is available already: spx->txlt_scsi_pkt == pkt; */
	}

	spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp = bp;

	/*
	 * We use an adjusted version of the dma_attr, to account
	 * for device addressing limitations.
	 * sata_adjust_dma_attr() will handle sdinfo == NULL which may
	 * happen when a device is not yet configured.
	 */
	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);
	/* NULL sdinfo may be passsed to sata_adjust_dma_attr() */
	sata_adjust_dma_attr(sdinfo,
	    SATA_DMA_ATTR(spx->txlt_sata_hba_inst), &cur_dma_attr);
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	/*
	 * Allocate necessary DMA resources for the packet's data buffer
	 * NOTE:
	 * In case of read/write commands, DMA resource allocation here is
	 * based on the premise that the transfer length specified in
	 * the read/write scsi cdb will match exactly DMA resources -
	 * returning correct packet residue is crucial.
	 */
	if ((rval = sata_dma_buf_setup(spx, flags, callback, arg,
	    &cur_dma_attr)) != DDI_SUCCESS) {
		spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp = NULL;
		sata_pkt_free(spx);
		/*
		 * If a DMA allocation request fails with
		 * DDI_DMA_NOMAPPING, indicate the error by calling
		 * bioerror(9F) with bp and an error code of EFAULT.
		 * If a DMA allocation request fails with
		 * DDI_DMA_TOOBIG, indicate the error by calling
		 * bioerror(9F) with bp and an error code of EINVAL.
		 */
		switch (rval) {
		case DDI_DMA_NORESOURCES:
			bioerror(bp, 0);
			break;
		case DDI_DMA_NOMAPPING:
		case DDI_DMA_BADATTR:
			bioerror(bp, EFAULT);
			break;
		case DDI_DMA_TOOBIG:
		default:
			bioerror(bp, EINVAL);
			break;
		}
		if (new_pkt == TRUE)
			scsi_hba_pkt_free(ap, pkt);
		return (NULL);
	}
	/* Set number of bytes that are not yet accounted for */
	pkt->pkt_resid = spx->txlt_total_residue;
	ASSERT(pkt->pkt_resid >= 0);

	return (pkt);
}

/*
 * Implementation of scsi tran_start.
 * Translate scsi cmd into sata operation and return status.
 * ATAPI CDBs are passed to ATAPI devices - the device determines what commands
 * are supported.
 * For SATA hard disks, supported scsi commands:
 * SCMD_INQUIRY
 * SCMD_TEST_UNIT_READY
 * SCMD_START_STOP
 * SCMD_READ_CAPACITY
 * SCMD_REQUEST_SENSE
 * SCMD_LOG_SENSE_G1
 * SCMD_LOG_SELECT_G1
 * SCMD_MODE_SENSE	(specific pages)
 * SCMD_MODE_SENSE_G1	(specific pages)
 * SCMD_MODE_SELECT	(specific pages)
 * SCMD_MODE_SELECT_G1	(specific pages)
 * SCMD_SYNCHRONIZE_CACHE
 * SCMD_SYNCHRONIZE_CACHE_G1
 * SCMD_READ
 * SCMD_READ_G1
 * SCMD_READ_G4
 * SCMD_READ_G5
 * SCMD_WRITE
 * SCMD_WRITE_BUFFER
 * SCMD_WRITE_G1
 * SCMD_WRITE_G4
 * SCMD_WRITE_G5
 * SCMD_SEEK		(noop)
 * SCMD_SDIAG
 *
 * All other commands are rejected as unsupported.
 *
 * Returns:
 * TRAN_ACCEPT if command was executed successfully or accepted by HBA driver
 * for execution. TRAN_ACCEPT may be returned also if device was removed but
 * a callback could be scheduled.
 * TRAN_BADPKT if cmd was directed to invalid address.
 * TRAN_FATAL_ERROR is command was rejected due to hardware error, including
 * some unspecified error. TRAN_FATAL_ERROR may be also returned if a device
 * was removed and there was no callback specified in scsi pkt.
 * TRAN_BUSY if command could not be executed becasue HBA driver or SATA
 * framework was busy performing some other operation(s).
 *
 */
static int
sata_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	sata_hba_inst_t *sata_hba_inst =
	    (sata_hba_inst_t *)(ap->a_hba_tran->tran_hba_private);
	sata_pkt_txlate_t *spx = (sata_pkt_txlate_t *)pkt->pkt_ha_private;
	sata_drive_info_t *sdinfo;
	struct buf *bp;
	int cport;
	int rval;

	SATADBG1(SATA_DBG_SCSI_IF, sata_hba_inst,
	    "sata_scsi_start: cmd 0x%02x\n", pkt->pkt_cdbp[0]);

	ASSERT(spx != NULL &&
	    spx->txlt_scsi_pkt == pkt && spx->txlt_sata_pkt != NULL);

	cport = SCSI_TO_SATA_CPORT(ap->a_target);

	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));
	sdinfo = sata_get_device_info(sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);
	if (sdinfo == NULL ||
	    SATA_CPORT_INFO(sata_hba_inst, cport)->cport_tgtnode_clean ==
	    B_FALSE) {
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));
		pkt->pkt_reason = CMD_DEV_GONE;
		/*
		 * The sd target driver is checking CMD_DEV_GONE pkt_reason
		 * only in callback function (for normal requests) and
		 * in the dump code path.
		 * So, if the callback is available, we need to do
		 * the callback rather than returning TRAN_FATAL_ERROR here.
		 */
		if (pkt->pkt_comp != NULL) {
			/* scsi callback required */
			if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
			    (task_func_t *)pkt->pkt_comp,
			    (void *)pkt, TQ_SLEEP) == NULL)
				/* Scheduling the callback failed */
				return (TRAN_BUSY);
			return (TRAN_ACCEPT);
		}
		/* No callback available */
		return (TRAN_FATAL_ERROR);
	}

	if (sdinfo->satadrv_type == SATA_DTYPE_ATAPICD) {
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));
		rval = sata_txlt_atapi(spx);
		SATADBG1(SATA_DBG_SCSI_IF, sata_hba_inst,
		    "sata_scsi_start atapi: rval %d\n", rval);
		return (rval);
	}
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));

	/* ATA Disk commands processing starts here */

	bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;

	switch (pkt->pkt_cdbp[0]) {

	case SCMD_INQUIRY:
		/* Mapped to identify device */
		if (bp != NULL && (bp->b_flags & (B_PHYS | B_PAGEIO)))
			bp_mapin(bp);
		rval = sata_txlt_inquiry(spx);
		break;

	case SCMD_TEST_UNIT_READY:
		/*
		 * SAT "SATA to ATA Translation" doc specifies translation
		 * to ATA CHECK POWER MODE.
		 */
		rval = sata_txlt_test_unit_ready(spx);
		break;

	case SCMD_START_STOP:
		/* Mapping depends on the command */
		rval = sata_txlt_start_stop_unit(spx);
		break;

	case SCMD_READ_CAPACITY:
		if (bp != NULL && (bp->b_flags & (B_PHYS | B_PAGEIO)))
			bp_mapin(bp);
		rval = sata_txlt_read_capacity(spx);
		break;

	case SCMD_REQUEST_SENSE:
		/*
		 * Always No Sense, since we force ARQ
		 */
		if (bp != NULL && (bp->b_flags & (B_PHYS | B_PAGEIO)))
			bp_mapin(bp);
		rval = sata_txlt_request_sense(spx);
		break;

	case SCMD_LOG_SENSE_G1:
		if (bp != NULL && (bp->b_flags & (B_PHYS | B_PAGEIO)))
			bp_mapin(bp);
		rval = sata_txlt_log_sense(spx);
		break;

	case SCMD_LOG_SELECT_G1:
		if (bp != NULL && (bp->b_flags & (B_PHYS | B_PAGEIO)))
			bp_mapin(bp);
		rval = sata_txlt_log_select(spx);
		break;

	case SCMD_MODE_SENSE:
	case SCMD_MODE_SENSE_G1:
		if (bp != NULL && (bp->b_flags & (B_PHYS | B_PAGEIO)))
			bp_mapin(bp);
		rval = sata_txlt_mode_sense(spx);
		break;


	case SCMD_MODE_SELECT:
	case SCMD_MODE_SELECT_G1:
		if (bp != NULL && (bp->b_flags & (B_PHYS | B_PAGEIO)))
			bp_mapin(bp);
		rval = sata_txlt_mode_select(spx);
		break;

	case SCMD_SYNCHRONIZE_CACHE:
	case SCMD_SYNCHRONIZE_CACHE_G1:
		rval = sata_txlt_synchronize_cache(spx);
		break;

	case SCMD_READ:
	case SCMD_READ_G1:
	case SCMD_READ_G4:
	case SCMD_READ_G5:
		rval = sata_txlt_read(spx);
		break;
	case SCMD_WRITE_BUFFER:
		if (bp != NULL && (bp->b_flags & (B_PHYS | B_PAGEIO)))
			bp_mapin(bp);
		rval = sata_txlt_write_buffer(spx);
		break;

	case SCMD_WRITE:
	case SCMD_WRITE_G1:
	case SCMD_WRITE_G4:
	case SCMD_WRITE_G5:
		rval = sata_txlt_write(spx);
		break;

	case SCMD_SEEK:
		rval = sata_txlt_nodata_cmd_immediate(spx);
		break;

		/* Other cases will be filed later */
		/* postponed until phase 2 of the development */
	default:
		rval = sata_txlt_invalid_command(spx);
		break;
	}

	SATADBG1(SATA_DBG_SCSI_IF, sata_hba_inst,
	    "sata_scsi_start: rval %d\n", rval);

	return (rval);
}

/*
 * Implementation of scsi tran_abort.
 * Abort specific pkt or all packets.
 *
 * Returns 1 if one or more packets were aborted, returns 0 otherwise
 *
 * May be called from an interrupt level.
 */
static int
sata_scsi_abort(struct scsi_address *ap, struct scsi_pkt *scsi_pkt)
{
	sata_hba_inst_t *sata_hba_inst =
	    (sata_hba_inst_t *)(ap->a_hba_tran->tran_hba_private);
	sata_device_t	sata_device;
	sata_pkt_t	*sata_pkt;

	SATADBG2(SATA_DBG_SCSI_IF, sata_hba_inst,
	    "sata_scsi_abort: %s at target: 0x%x\n",
	    scsi_pkt == NULL ? "all packets" : "one pkt", ap->a_target);

	/* Validate address */
	if (sata_validate_scsi_address(sata_hba_inst, ap, &sata_device) != 0)
		/* Invalid address */
		return (0);

	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	if (sata_get_device_info(sata_hba_inst, &sata_device) == NULL) {
		/* invalid address */
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device.satadev_addr.cport)));
		return (0);
	}
	if (scsi_pkt == NULL) {
		/*
		 * Abort all packets.
		 * Although we do not have specific packet, we still need
		 * dummy packet structure to pass device address to HBA.
		 * Allocate one, without sleeping. Fail if pkt cannot be
		 * allocated.
		 */
		sata_pkt = kmem_zalloc(sizeof (sata_pkt_t), KM_NOSLEEP);
		if (sata_pkt == NULL) {
			mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
			    sata_device.satadev_addr.cport)));
			SATA_LOG_D((sata_hba_inst, CE_WARN, "sata_pkt_abort: "
			    "could not allocate sata_pkt"));
			return (0);
		}
		sata_pkt->satapkt_rev = SATA_PKT_REV;
		sata_pkt->satapkt_device = sata_device;
		sata_pkt->satapkt_device.satadev_rev = SATA_DEVICE_REV;
	} else {
		if (scsi_pkt->pkt_ha_private == NULL) {
			mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
			    sata_device.satadev_addr.cport)));
			return (0); /* Bad scsi pkt */
		}
		/* extract pointer to sata pkt */
		sata_pkt = ((sata_pkt_txlate_t *)scsi_pkt->pkt_ha_private)->
		    txlt_sata_pkt;
	}

	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	/* Send abort request to HBA */
	if ((*SATA_ABORT_FUNC(sata_hba_inst))
	    (SATA_DIP(sata_hba_inst), sata_pkt,
	    scsi_pkt == NULL ? SATA_ABORT_ALL_PACKETS : SATA_ABORT_PACKET) ==
	    SATA_SUCCESS) {
		if (scsi_pkt == NULL)
			kmem_free(sata_pkt, sizeof (sata_pkt_t));
		/* Success */
		return (1);
	}
	/* Else, something did not go right */
	if (scsi_pkt == NULL)
		kmem_free(sata_pkt, sizeof (sata_pkt_t));
	/* Failure */
	return (0);
}


/*
 * Implementation of scsi tran_reset.
 * RESET_ALL request is translated into port reset.
 * RESET_TARGET requests is translated into a device reset,
 * RESET_LUN request is accepted only for LUN 0 and translated into
 * device reset.
 * The target reset should cause all HBA active and queued packets to
 * be terminated and returned with pkt reason SATA_PKT_RESET prior to
 * the return. HBA should report reset event for the device.
 *
 * Returns 1 upon success, 0 upon failure.
 */
static int
sata_scsi_reset(struct scsi_address *ap, int level)
{
	sata_hba_inst_t	*sata_hba_inst =
	    (sata_hba_inst_t *)(ap->a_hba_tran->tran_hba_private);
	sata_device_t	sata_device;
	int		val;

	SATADBG2(SATA_DBG_SCSI_IF, sata_hba_inst,
	    "sata_scsi_reset: level %d target: 0x%x\n",
	    level, ap->a_target);

	/* Validate address */
	val = sata_validate_scsi_address(sata_hba_inst, ap, &sata_device);
	if (val == -1)
		/* Invalid address */
		return (0);

	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	if (sata_get_device_info(sata_hba_inst, &sata_device) == NULL) {
		/* invalid address */
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device.satadev_addr.cport)));
		return (0);
	}
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	if (level == RESET_ALL) {
		/* port reset - cport only */
		sata_device.satadev_addr.qual = SATA_ADDR_CPORT;
		if ((*SATA_RESET_DPORT_FUNC(sata_hba_inst))
		    (SATA_DIP(sata_hba_inst), &sata_device) == SATA_SUCCESS)
			return (1);
		else
			return (0);

	} else if (val == 0 &&
	    (level == RESET_TARGET || level == RESET_LUN)) {
		/* reset device (device attached) */
		if ((*SATA_RESET_DPORT_FUNC(sata_hba_inst))
		    (SATA_DIP(sata_hba_inst), &sata_device) == SATA_SUCCESS)
			return (1);
		else
			return (0);
	}
	return (0);
}


/*
 * Implementation of scsi tran_getcap (get transport/device capabilities).
 * Supported capabilities for SATA hard disks:
 * auto-rqsense		(always supported)
 * tagged-qing		(supported if HBA supports it)
 * untagged-qing	(could be supported if disk supports it, but because
 *			 caching behavior allowing untagged queuing actually
 *			 results in reduced performance.  sd tries to throttle
 *			 back to only 3 outstanding commands, which may
 *			 work for real SCSI disks, but with read ahead
 *			 caching, having more than 1 outstanding command
 *			 results in cache thrashing.)
 * sector_size
 * dma_max
 * interconnect-type	(INTERCONNECT_SATA)
 *
 * Supported capabilities for ATAPI devices (CD/DVD):
 * auto-rqsense		(always supported)
 * sector_size
 * dma_max
 * interconnect-type	(INTERCONNECT_SATA)
 *
 * Request for other capabilities is rejected as unsupported.
 *
 * Returns supported capability value, or -1 if capability is unsuppported or
 * the address is invalid - no device.
 */

static int
sata_scsi_getcap(struct scsi_address *ap, char *cap, int whom)
{

	sata_hba_inst_t 	*sata_hba_inst =
	    (sata_hba_inst_t *)(ap->a_hba_tran->tran_hba_private);
	sata_device_t		sata_device;
	sata_drive_info_t	*sdinfo;
	ddi_dma_attr_t		adj_dma_attr;
	int 			rval;

	SATADBG2(SATA_DBG_SCSI_IF, sata_hba_inst,
	    "sata_scsi_getcap: target: 0x%x, cap: %s\n",
	    ap->a_target, cap);

	/*
	 * We want to process the capabilities on per port granularity.
	 * So, we are specifically restricting ourselves to whom != 0
	 * to exclude the controller wide handling.
	 */
	if (cap == NULL || whom == 0)
		return (-1);

	if (sata_validate_scsi_address(sata_hba_inst, ap, &sata_device) != 0) {
		/* Invalid address */
		return (-1);
	}
	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	if ((sdinfo = sata_get_device_info(sata_hba_inst, &sata_device)) ==
	    NULL) {
		/* invalid address */
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device.satadev_addr.cport)));
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		rval = 1;		/* ARQ supported, turned on */
		break;

	case SCSI_CAP_SECTOR_SIZE:
		if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK)
			rval = SATA_DISK_SECTOR_SIZE;	/* fixed size */
		else if (sdinfo->satadrv_type == SATA_DTYPE_ATAPICD)
			rval = SATA_ATAPI_SECTOR_SIZE;
		else rval = -1;
		break;

	/*
	 * untagged queuing cause a performance inversion because of
	 * the way sd operates.  Because of this reason we do not
	 * use it when available.
	 */
	case SCSI_CAP_UNTAGGED_QING:
		if (sdinfo->satadrv_features_enabled &
		    SATA_DEV_F_E_UNTAGGED_QING)
			rval = 1;	/* Untagged queuing available */
		else
			rval = -1;	/* Untagged queuing not available */
		break;

	case SCSI_CAP_TAGGED_QING:
		if ((sdinfo->satadrv_features_enabled &
		    SATA_DEV_F_E_TAGGED_QING) &&
		    (sdinfo->satadrv_max_queue_depth > 1))
			rval = 1;	/* Tagged queuing available */
		else
			rval = -1;	/* Tagged queuing not available */
		break;

	case SCSI_CAP_DMA_MAX:
		sata_adjust_dma_attr(sdinfo, SATA_DMA_ATTR(sata_hba_inst),
		    &adj_dma_attr);
		rval = (int)adj_dma_attr.dma_attr_maxxfer;
		/* We rely on the fact that dma_attr_maxxfer < 0x80000000 */
		break;

	case SCSI_CAP_INTERCONNECT_TYPE:
		rval = INTERCONNECT_SATA;	/* SATA interconnect type */
		break;

	default:
		rval = -1;
		break;
	}
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	return (rval);
}

/*
 * Implementation of scsi tran_setcap
 *
 * Only SCSI_CAP_UNTAGGED_QING and  SCSI_CAP_TAGGED_QING are changeable.
 *
 */
static int
sata_scsi_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	sata_hba_inst_t	*sata_hba_inst =
	    (sata_hba_inst_t *)(ap->a_hba_tran->tran_hba_private);
	sata_device_t	sata_device;
	sata_drive_info_t	*sdinfo;
	int		rval;

	SATADBG2(SATA_DBG_SCSI_IF, sata_hba_inst,
	    "sata_scsi_setcap: target: 0x%x, cap: %s\n", ap->a_target, cap);

	/*
	 * We want to process the capabilities on per port granularity.
	 * So, we are specifically restricting ourselves to whom != 0
	 * to exclude the controller wide handling.
	 */
	if (cap == NULL || whom == 0) {
		return (-1);
	}

	if (sata_validate_scsi_address(sata_hba_inst, ap, &sata_device) != 0) {
		/* Invalid address */
		return (-1);
	}
	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));
	if ((sdinfo = sata_get_device_info(sata_hba_inst,
	    &sata_device)) == NULL) {
		/* invalid address */
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device.satadev_addr.cport)));
		return (-1);
	}
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device.satadev_addr.cport)));

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
	case SCSI_CAP_SECTOR_SIZE:
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_INTERCONNECT_TYPE:
		rval = 0;
		break;
	case SCSI_CAP_UNTAGGED_QING:
		if (SATA_QDEPTH(sata_hba_inst) > 1) {
			rval = 1;
			if (value == 1) {
				sdinfo->satadrv_features_enabled |=
				    SATA_DEV_F_E_UNTAGGED_QING;
			} else if (value == 0) {
				sdinfo->satadrv_features_enabled &=
				    ~SATA_DEV_F_E_UNTAGGED_QING;
			} else {
				rval = -1;
			}
		} else {
			rval = 0;
		}
		break;
	case SCSI_CAP_TAGGED_QING:
		/* This can TCQ or NCQ */
		if (sata_func_enable & SATA_ENABLE_QUEUING &&
		    ((sdinfo->satadrv_features_support & SATA_DEV_F_TCQ &&
		    SATA_FEATURES(sata_hba_inst) & SATA_CTLF_QCMD) ||
		    (sata_func_enable & SATA_ENABLE_NCQ &&
		    sdinfo->satadrv_features_support & SATA_DEV_F_NCQ &&
		    SATA_FEATURES(sata_hba_inst) & SATA_CTLF_NCQ)) &&
		    (sdinfo->satadrv_max_queue_depth > 1)) {
			rval = 1;
			if (value == 1) {
				sdinfo->satadrv_features_enabled |=
				    SATA_DEV_F_E_TAGGED_QING;
			} else if (value == 0) {
				sdinfo->satadrv_features_enabled &=
				    ~SATA_DEV_F_E_TAGGED_QING;
			} else {
				rval = -1;
			}
		} else {
			rval = 0;
		}
		break;
	default:
		rval = -1;
		break;
	}
	return (rval);
}

/*
 * Implementations of scsi tran_destroy_pkt.
 * Free resources allocated by sata_scsi_init_pkt()
 */
static void
sata_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	sata_pkt_txlate_t *spx;

	spx = (sata_pkt_txlate_t *)pkt->pkt_ha_private;

	if (spx->txlt_buf_dma_handle != NULL) {
		if (spx->txlt_tmp_buf != NULL)  {
			ASSERT(spx->txlt_tmp_buf_handle != 0);
			/*
			 * Intermediate DMA buffer was allocated.
			 * Free allocated buffer and associated access handle.
			 */
			ddi_dma_mem_free(&spx->txlt_tmp_buf_handle);
			spx->txlt_tmp_buf = NULL;
		}
		/*
		 * Free DMA resources - cookies and handles
		 */
		if (spx->txlt_dma_cookie_list != NULL) {
			if (spx->txlt_dma_cookie_list !=
			    &spx->txlt_dma_cookie) {
				(void) kmem_free(spx->txlt_dma_cookie_list,
				    spx->txlt_dma_cookie_list_len *
				    sizeof (ddi_dma_cookie_t));
				spx->txlt_dma_cookie_list = NULL;
			}
		}
		(void) ddi_dma_unbind_handle(spx->txlt_buf_dma_handle);
		(void) ddi_dma_free_handle(&spx->txlt_buf_dma_handle);
	}
	spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp = NULL;
	sata_pkt_free(spx);

	scsi_hba_pkt_free(ap, pkt);
}

/*
 * Implementation of scsi tran_dmafree.
 * Free DMA resources allocated by sata_scsi_init_pkt()
 */

static void
sata_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	sata_pkt_txlate_t *spx;

	ASSERT(pkt != NULL);
	spx = (sata_pkt_txlate_t *)pkt->pkt_ha_private;

	if (spx->txlt_buf_dma_handle != NULL) {
		if (spx->txlt_tmp_buf != NULL)  {
			/*
			 * Intermediate DMA buffer was allocated.
			 * Free allocated buffer and associated access handle.
			 */
			ddi_dma_mem_free(&spx->txlt_tmp_buf_handle);
			spx->txlt_tmp_buf = NULL;
		}
		/*
		 * Free DMA resources - cookies and handles
		 */
		/* ASSERT(spx->txlt_dma_cookie_list != NULL); */
		if (spx->txlt_dma_cookie_list != NULL) {
			if (spx->txlt_dma_cookie_list !=
			    &spx->txlt_dma_cookie) {
				(void) kmem_free(spx->txlt_dma_cookie_list,
				    spx->txlt_dma_cookie_list_len *
				    sizeof (ddi_dma_cookie_t));
				spx->txlt_dma_cookie_list = NULL;
			}
		}
		(void) ddi_dma_unbind_handle(spx->txlt_buf_dma_handle);
		(void) ddi_dma_free_handle(&spx->txlt_buf_dma_handle);
		spx->txlt_buf_dma_handle = NULL;
	}
}

/*
 * Implementation of scsi tran_sync_pkt.
 *
 * The assumption below is that pkt is unique - there is no need to check ap
 *
 * Synchronize DMA buffer and, if the intermediate buffer is used, copy data
 * into/from the real buffer.
 */
static void
sata_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	int rval;
	sata_pkt_txlate_t *spx = (sata_pkt_txlate_t *)pkt->pkt_ha_private;
	struct buf *bp;
	int direction;

	ASSERT(spx != NULL);
	if (spx->txlt_buf_dma_handle != NULL) {
		direction = spx->txlt_sata_pkt->
		    satapkt_cmd.satacmd_flags.sata_data_direction;
		if (spx->txlt_sata_pkt != NULL &&
		    direction != SATA_DIR_NODATA_XFER) {
			if (spx->txlt_tmp_buf != NULL) {
				/* Intermediate DMA buffer used */
				bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;

				if (direction & SATA_DIR_WRITE) {
					bcopy(bp->b_un.b_addr,
					    spx->txlt_tmp_buf, bp->b_bcount);
				}
			}
			/* Sync the buffer for device or for CPU */
			rval = ddi_dma_sync(spx->txlt_buf_dma_handle,   0, 0,
			    (direction & SATA_DIR_WRITE) ?
			    DDI_DMA_SYNC_FORDEV :  DDI_DMA_SYNC_FORCPU);
			ASSERT(rval == DDI_SUCCESS);
			if (spx->txlt_tmp_buf != NULL &&
			    !(direction & SATA_DIR_WRITE)) {
				/* Intermediate DMA buffer used for read */
				bcopy(spx->txlt_tmp_buf,
				    bp->b_un.b_addr, bp->b_bcount);
			}

		}
	}
}



/* *******************  SATA - SCSI Translation functions **************** */
/*
 * SCSI to SATA pkt and command translation and SATA to SCSI status/error
 * translation.
 */

/*
 * Checks if a device exists and can be access and translates common
 * scsi_pkt data to sata_pkt data.
 *
 * Returns TRAN_ACCEPT and scsi pkt_reason CMD_CMPLT if device exists and
 * sata_pkt was set-up.
 * Returns TRAN_ACCEPT and scsi pkt_reason CMD_DEV_GONE if device does not
 * exist and pkt_comp callback was scheduled.
 * Returns other TRAN_XXXXX values when error occured and command should be
 * rejected with the returned TRAN_XXXXX value.
 *
 * This function should be called with port mutex held.
 */
static int
sata_txlt_generic_pkt_info(sata_pkt_txlate_t *spx)
{
	sata_drive_info_t *sdinfo;
	sata_device_t sata_device;
	const struct sata_cmd_flags sata_initial_cmd_flags = {
		SATA_DIR_NODATA_XFER,
		/* all other values to 0/FALSE */
	};
	/*
	 * Pkt_reason has to be set if the pkt_comp callback is invoked,
	 * and that implies TRAN_ACCEPT return value. Any other returned value
	 * indicates that the scsi packet was not accepted (the reason will not
	 * be checked by the scsi traget driver).
	 * To make debugging easier, we set pkt_reason to know value here.
	 * It may be changed later when different completion reason is
	 * determined.
	 */
	spx->txlt_scsi_pkt->pkt_reason = CMD_TRAN_ERR;

	/* Validate address */
	switch (sata_validate_scsi_address(spx->txlt_sata_hba_inst,
	    &spx->txlt_scsi_pkt->pkt_address, &sata_device)) {

	case -1:
		/* Invalid address or invalid device type */
		return (TRAN_BADPKT);
	case 1:
		/* valid address but no device - it has disappeared ? */
		spx->txlt_scsi_pkt->pkt_reason = CMD_DEV_GONE;
		/*
		 * The sd target driver is checking CMD_DEV_GONE pkt_reason
		 * only in callback function (for normal requests) and
		 * in the dump code path.
		 * So, if the callback is available, we need to do
		 * the callback rather than returning TRAN_FATAL_ERROR here.
		 */
		if (spx->txlt_scsi_pkt->pkt_comp != NULL) {
			/* scsi callback required */
			if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
			    (task_func_t *)spx->txlt_scsi_pkt->pkt_comp,
			    (void *)spx->txlt_scsi_pkt,
			    TQ_SLEEP) == NULL)
				/* Scheduling the callback failed */
				return (TRAN_BUSY);

			return (TRAN_ACCEPT);
		}
		return (TRAN_FATAL_ERROR);
	default:
		/* all OK */
		break;
	}
	sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);

	/*
	 * If device is in reset condition, reject the packet with
	 * TRAN_BUSY, unless:
	 * 1. system is panicking (dumping)
	 * In such case only one thread is running and there is no way to
	 * process reset.
	 * 2. cfgadm operation is is progress (internal APCTL lock is set)
	 * Some cfgadm operations involve drive commands, so reset condition
	 * needs to be ignored for IOCTL operations.
	 */
	if ((sdinfo->satadrv_event_flags &
	    (SATA_EVNT_DEVICE_RESET | SATA_EVNT_INPROC_DEVICE_RESET)) != 0) {

		if (!ddi_in_panic() &&
		    ((SATA_CPORT_EVENT_FLAGS(spx->txlt_sata_hba_inst,
		    sata_device.satadev_addr.cport) &
		    SATA_APCTL_LOCK_PORT_BUSY) == 0)) {
			spx->txlt_scsi_pkt->pkt_reason = CMD_INCOMPLETE;
			SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
			    "sata_scsi_start: rejecting command because "
			    "of device reset state\n", NULL);
			return (TRAN_BUSY);
		}
	}

	/*
	 * Fix the dev_type in the sata_pkt->satapkt_device. It was not set by
	 * sata_scsi_pkt_init() because pkt init had to work also with
	 * non-existing devices.
	 * Now we know that the packet was set-up for a real device, so its
	 * type is known.
	 */
	spx->txlt_sata_pkt->satapkt_device.satadev_type = sdinfo->satadrv_type;

	spx->txlt_sata_pkt->satapkt_cmd.satacmd_flags = sata_initial_cmd_flags;
	if ((SATA_CPORT_INFO(spx->txlt_sata_hba_inst,
	    sata_device.satadev_addr.cport)->cport_event_flags &
	    SATA_APCTL_LOCK_PORT_BUSY) != 0) {
		spx->txlt_sata_pkt->satapkt_cmd.satacmd_flags.
		    sata_ignore_dev_reset = B_TRUE;
	}
	/*
	 * At this point the generic translation routine determined that the
	 * scsi packet should be accepted. Packet completion reason may be
	 * changed later when a different completion reason is determined.
	 */
	spx->txlt_scsi_pkt->pkt_reason = CMD_CMPLT;

	if ((spx->txlt_scsi_pkt->pkt_flags & FLAG_NOINTR) != 0) {
		/* Synchronous execution */
		spx->txlt_sata_pkt->satapkt_op_mode = SATA_OPMODE_SYNCH |
		    SATA_OPMODE_POLLING;
		spx->txlt_sata_pkt->satapkt_cmd.satacmd_flags.
		    sata_ignore_dev_reset = ddi_in_panic();
	} else {
		/* Asynchronous execution */
		spx->txlt_sata_pkt->satapkt_op_mode = SATA_OPMODE_ASYNCH |
		    SATA_OPMODE_INTERRUPTS;
	}
	/* Convert queuing information */
	if (spx->txlt_scsi_pkt->pkt_flags & FLAG_STAG)
		spx->txlt_sata_pkt->satapkt_cmd.satacmd_flags.sata_queue_stag =
		    B_TRUE;
	else if (spx->txlt_scsi_pkt->pkt_flags &
	    (FLAG_OTAG | FLAG_HTAG | FLAG_HEAD))
		spx->txlt_sata_pkt->satapkt_cmd.satacmd_flags.sata_queue_otag =
		    B_TRUE;

	/* Always limit pkt time */
	if (spx->txlt_scsi_pkt->pkt_time == 0)
		spx->txlt_sata_pkt->satapkt_time = sata_default_pkt_time;
	else
		/* Pass on scsi_pkt time */
		spx->txlt_sata_pkt->satapkt_time =
		    spx->txlt_scsi_pkt->pkt_time;

	return (TRAN_ACCEPT);
}


/*
 * Translate ATA Identify Device data to SCSI Inquiry data.
 * This function may be called only for ATA devices.
 * This function should not be called for ATAPI devices - they
 * respond directly to SCSI Inquiry command.
 *
 * SATA Identify Device data has to be valid in sata_rive_info.
 * Buffer has to accomodate the inquiry length (36 bytes).
 *
 * This function should be called with a port mutex held.
 */
static	void
sata_identdev_to_inquiry(sata_hba_inst_t *sata_hba_inst,
    sata_drive_info_t *sdinfo, uint8_t *buf)
{

	struct scsi_inquiry *inq = (struct scsi_inquiry *)buf;
	struct sata_id *sid = &sdinfo->satadrv_id;

	/* Start with a nice clean slate */
	bzero((void *)inq, sizeof (struct scsi_inquiry));

	/*
	 * Rely on the dev_type for setting paripheral qualifier.
	 * Assume that  DTYPE_RODIRECT applies to CD/DVD R/W devices.
	 * It could be that DTYPE_OPTICAL could also qualify in the future.
	 * ATAPI Inquiry may provide more data to the target driver.
	 */
	inq->inq_dtype = sdinfo->satadrv_type == SATA_DTYPE_ATADISK ?
	    DTYPE_DIRECT : DTYPE_RODIRECT; /* DTYPE_UNKNOWN; */

	inq->inq_rmb = sid->ai_config & SATA_REM_MEDIA ? 1 : 0;
	inq->inq_qual = 0;	/* Device type qualifier (obsolete in SCSI3? */
	inq->inq_iso = 0;	/* ISO version */
	inq->inq_ecma = 0;	/* ECMA version */
	inq->inq_ansi = 3;	/* ANSI version - SCSI 3 */
	inq->inq_aenc = 0;	/* Async event notification cap. */
	inq->inq_trmiop = 0;	/* Supports TERMINATE I/O PROC msg - NO */
	inq->inq_normaca = 0;	/* setting NACA bit supported - NO */
	inq->inq_rdf = RDF_SCSI2; /* Response data format- SPC-3 */
	inq->inq_len = 31;	/* Additional length */
	inq->inq_dualp = 0;	/* dual port device - NO */
	inq->inq_reladdr = 0;	/* Supports relative addressing - NO */
	inq->inq_sync = 0;	/* Supports synchronous data xfers - NO */
	inq->inq_linked = 0;	/* Supports linked commands - NO */
				/*
				 * Queuing support - controller has to
				 * support some sort of command queuing.
				 */
	if (SATA_QDEPTH(sata_hba_inst) > 1)
		inq->inq_cmdque = 1; /* Supports command queueing - YES */
	else
		inq->inq_cmdque = 0; /* Supports command queueing - NO */
	inq->inq_sftre = 0;	/* Supports Soft Reset option - NO ??? */
	inq->inq_wbus32 = 0;	/* Supports 32 bit wide data xfers - NO */
	inq->inq_wbus16 = 0;	/* Supports 16 bit wide data xfers - NO */

#ifdef	_LITTLE_ENDIAN
	/* Swap text fields to match SCSI format */
	bcopy("ATA     ", inq->inq_vid, 8);		/* Vendor ID */
	swab(sid->ai_model, inq->inq_pid, 16);		/* Product ID */
	if (strncmp(&sid->ai_fw[4], "    ", 4) == 0)
		swab(sid->ai_fw, inq->inq_revision, 4);	/* Revision level */
	else
		swab(&sid->ai_fw[4], inq->inq_revision, 4);	/* Rev. level */
#else	/* _LITTLE_ENDIAN */
	bcopy("ATA     ", inq->inq_vid, 8);		/* Vendor ID */
	bcopy(sid->ai_model, inq->inq_pid, 16);		/* Product ID */
	if (strncmp(&sid->ai_fw[4], "    ", 4) == 0)
		bcopy(sid->ai_fw, inq->inq_revision, 4); /* Revision level */
	else
		bcopy(&sid->ai_fw[4], inq->inq_revision, 4); /* Rev. level */
#endif	/* _LITTLE_ENDIAN */
}


/*
 * Scsi response set up for invalid command (command not supported)
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */
static int
sata_txlt_invalid_command(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense *sense;

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;

	*scsipkt->pkt_scbp = STATUS_CHECK;

	sense = sata_arq_sense(spx);
	sense->es_key = KEY_ILLEGAL_REQUEST;
	sense->es_add_code = SD_SCSI_ASC_INVALID_COMMAND_CODE;

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)spx->txlt_scsi_pkt->pkt_comp,
		    (void *)spx->txlt_scsi_pkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);
	return (TRAN_ACCEPT);
}

/*
 * Scsi response setup for
 * emulated non-data command that requires no action/return data
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */
static 	int
sata_txlt_nodata_cmd_immediate(sata_pkt_txlate_t *spx)
{
	int rval;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));

	spx->txlt_scsi_pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;
	spx->txlt_scsi_pkt->pkt_reason = CMD_CMPLT;
	*(spx->txlt_scsi_pkt->pkt_scbp) = STATUS_GOOD;

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n",
	    spx->txlt_scsi_pkt->pkt_reason);

	if ((spx->txlt_scsi_pkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    spx->txlt_scsi_pkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)spx->txlt_scsi_pkt->pkt_comp,
		    (void *)spx->txlt_scsi_pkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);
	return (TRAN_ACCEPT);
}


/*
 * SATA translate command: Inquiry / Identify Device
 * Use cached Identify Device data for now, rather than issuing actual
 * Device Identify cmd request. If device is detached and re-attached,
 * asynchromous event processing should fetch and refresh Identify Device
 * data.
 * Two VPD pages are supported now:
 * Vital Product Data page
 * Unit Serial Number page
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */

#define	EVPD			1	/* Extended Vital Product Data flag */
#define	CMDDT			2	/* Command Support Data - Obsolete */
#define	INQUIRY_SUP_VPD_PAGE	0	/* Supported VDP Pages Page COde */
#define	INQUIRY_USN_PAGE	0x80	/* Unit Serial Number Page Code */
#define	INQUIRY_DEV_IDENTIFICATION_PAGE 0x83 /* Not needed yet */

static int
sata_txlt_inquiry(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct buf *bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	sata_drive_info_t *sdinfo;
	struct scsi_extended_sense *sense;
	int count;
	uint8_t *p;
	int i, j;
	uint8_t page_buf[0xff]; /* Max length */
	int rval;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);

	ASSERT(sdinfo != NULL);

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;

	/* Reject not supported request */
	if (scsipkt->pkt_cdbp[1] & CMDDT) { /* No support for this bit */
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
		goto done;
	}

	/* Valid Inquiry request */
	*scsipkt->pkt_scbp = STATUS_GOOD;

	if (bp != NULL && bp->b_un.b_addr && bp->b_bcount) {

		/*
		 * Because it is fully emulated command storing data
		 * programatically in the specified buffer, release
		 * preallocated DMA resources before storing data in the buffer,
		 * so no unwanted DMA sync would take place.
		 */
		sata_scsi_dmafree(NULL, scsipkt);

		if (!(scsipkt->pkt_cdbp[1] & EVPD)) {
			/* Standard Inquiry Data request */
			struct scsi_inquiry inq;
			unsigned int bufsize;

			sata_identdev_to_inquiry(spx->txlt_sata_hba_inst,
			    sdinfo, (uint8_t *)&inq);
			/* Copy no more than requested */
			count = MIN(bp->b_bcount,
			    sizeof (struct scsi_inquiry));
			bufsize = scsipkt->pkt_cdbp[4];
			bufsize |= scsipkt->pkt_cdbp[3] << 8;
			count = MIN(count, bufsize);
			bcopy(&inq, bp->b_un.b_addr, count);

			scsipkt->pkt_state |= STATE_XFERRED_DATA;
			scsipkt->pkt_resid = scsipkt->pkt_cdbp[4] > count ?
			    bufsize - count : 0;
		} else {
			/*
			 * peripheral_qualifier = 0;
			 *
			 * We are dealing only with HD and will be
			 * dealing with CD/DVD devices soon
			 */
			uint8_t peripheral_device_type =
			    sdinfo->satadrv_type == SATA_DTYPE_ATADISK ?
			    DTYPE_DIRECT : DTYPE_RODIRECT;

			switch ((uint_t)scsipkt->pkt_cdbp[2]) {
			case INQUIRY_SUP_VPD_PAGE:
				/*
				 * Request for suported Vital Product Data
				 * pages - assuming only 2 page codes
				 * supported
				 */
				page_buf[0] = peripheral_device_type;
				page_buf[1] = INQUIRY_SUP_VPD_PAGE;
				page_buf[2] = 0;
				page_buf[3] = 2; /* page length */
				page_buf[4] = INQUIRY_SUP_VPD_PAGE;
				page_buf[5] = INQUIRY_USN_PAGE;
				/* Copy no more than requested */
				count = MIN(bp->b_bcount, 6);
				bcopy(page_buf, bp->b_un.b_addr, count);
				break;
			case INQUIRY_USN_PAGE:
				/*
				 * Request for Unit Serial Number page
				 */
				page_buf[0] = peripheral_device_type;
				page_buf[1] = INQUIRY_USN_PAGE;
				page_buf[2] = 0;
				page_buf[3] = 20; /* remaining page length */
				p = (uint8_t *)(sdinfo->satadrv_id.ai_drvser);
#ifdef	_LITTLE_ENDIAN
				swab(p, &page_buf[4], 20);
#else
				bcopy(p, &page_buf[4], 20);
#endif
				for (i = 0; i < 20; i++) {
					if (page_buf[4 + i] == '\0' ||
					    page_buf[4 + i] == '\040') {
						break;
					}
				}
				/*
				 * 'i' contains string length.
				 *
				 * Least significant character of the serial
				 * number shall appear as the last byte,
				 * according to SBC-3 spec.
				 */
				p = &page_buf[20 + 4 - 1];
				for (j = i; j > 0; j--, p--) {
					*p = *(p - 20 + i);
				}
				p = &page_buf[4];
				for (j = 20 - i; j > 0; j--) {
					*p++ = '\040';
				}
				count = MIN(bp->b_bcount, 24);
				bcopy(page_buf, bp->b_un.b_addr, count);
				break;

			case INQUIRY_DEV_IDENTIFICATION_PAGE:
				/*
				 * We may want to implement this page, when
				 * identifiers are common for SATA devices
				 * But not now.
				 */
				/*FALLTHROUGH*/

			default:
				/* Request for unsupported VPD page */
				*scsipkt->pkt_scbp = STATUS_CHECK;
				sense = sata_arq_sense(spx);
				sense->es_key = KEY_ILLEGAL_REQUEST;
				sense->es_add_code =
				    SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
				goto done;
			}
		}
		scsipkt->pkt_state |= STATE_XFERRED_DATA;
		scsipkt->pkt_resid = scsipkt->pkt_cdbp[4] > count ?
		    scsipkt->pkt_cdbp[4] - count : 0;
	}
done:
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n",
	    scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL) {
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);
	}
	return (TRAN_ACCEPT);
}

/*
 * SATA translate command: Request Sense.
 * Emulated command (ATA version for SATA hard disks)
 * Always NO SENSE, because any sense data should be reported by ARQ sense.
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */
static int
sata_txlt_request_sense(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense sense;
	struct buf *bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	int rval;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));


	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;
	*scsipkt->pkt_scbp = STATUS_GOOD;

	if (bp != NULL && bp->b_un.b_addr && bp->b_bcount) {
		/*
		 * Because it is fully emulated command storing data
		 * programatically in the specified buffer, release
		 * preallocated DMA resources before storing data in the buffer,
		 * so no unwanted DMA sync would take place.
		 */
		int count = MIN(bp->b_bcount,
		    sizeof (struct scsi_extended_sense));
		sata_scsi_dmafree(NULL, scsipkt);
		bzero(&sense, sizeof (struct scsi_extended_sense));
		sense.es_valid = 0;	/* Valid LBA */
		sense.es_class = 7;	/* Response code 0x70 - current err */
		sense.es_key = KEY_NO_SENSE;
		sense.es_add_len = 6;	/* Additional length */
		/* Copy no more than requested */
		bcopy(&sense, bp->b_un.b_addr, count);
		scsipkt->pkt_state |= STATE_XFERRED_DATA;
		scsipkt->pkt_resid = 0;
	}

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n",
	    scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);
	return (TRAN_ACCEPT);
}

/*
 * SATA translate command: Test Unit Ready
 * At the moment this is an emulated command (ATA version for SATA hard disks).
 * May be translated into Check Power Mode command in the future
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */
static int
sata_txlt_test_unit_ready(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense *sense;
	int power_state;
	int rval;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));

	/* At this moment, emulate it rather than execute anything */
	power_state = SATA_PWRMODE_ACTIVE;

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;

	switch (power_state) {
	case SATA_PWRMODE_ACTIVE:
	case SATA_PWRMODE_IDLE:
		*scsipkt->pkt_scbp = STATUS_GOOD;
		break;
	default:
		/* PWR mode standby */
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_NOT_READY;
		sense->es_add_code = SD_SCSI_ASC_LU_NOT_READY;
		break;
	}

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);

	return (TRAN_ACCEPT);
}


/*
 * SATA translate command: Start Stop Unit
 * Translation depends on a command:
 *	Start Unit translated into Idle Immediate
 *	Stop Unit translated into Standby Immediate
 *	Unload Media / NOT SUPPORTED YET
 *	Load Media / NOT SUPPROTED YET
 * Power condition bits are ignored, so is Immediate bit
 * Requesting synchronous execution.
 *
 * Returns TRAN_ACCEPT or code returned by sata_hba_start() and
 * appropriate values in scsi_pkt fields.
 */
static int
sata_txlt_start_stop_unit(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	struct scsi_extended_sense *sense;
	sata_hba_inst_t *shi = SATA_TXLT_HBA_INST(spx);
	int cport = SATA_TXLT_CPORT(spx);
	int rval;
	int synch;

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_start_stop_unit: %d\n", scsipkt->pkt_scbp[4] & 1);

	mutex_enter(&SATA_CPORT_MUTEX(shi, cport));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	if (scsipkt->pkt_cdbp[4] & 2) {
		/* Load/Unload Media - invalid request */
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));

		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
		    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

		if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
		    scsipkt->pkt_comp != NULL)
			/* scsi callback required */
			if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
			    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
			    TQ_SLEEP) == NULL)
				/* Scheduling the callback failed */
				return (TRAN_BUSY);

		return (TRAN_ACCEPT);
	}
	scmd->satacmd_addr_type = 0;
	scmd->satacmd_sec_count_lsb = 0;
	scmd->satacmd_lba_low_lsb = 0;
	scmd->satacmd_lba_mid_lsb = 0;
	scmd->satacmd_lba_high_lsb = 0;
	scmd->satacmd_features_reg = 0;
	scmd->satacmd_device_reg = 0;
	scmd->satacmd_status_reg = 0;
	if (scsipkt->pkt_cdbp[4] & 1) {
		/* Start Unit */
		scmd->satacmd_cmd_reg = SATAC_IDLE_IM;
	} else {
		/* Stop Unit */
		scmd->satacmd_cmd_reg = SATAC_STANDBY_IM;
	}

	if (!(spx->txlt_sata_pkt->satapkt_op_mode & SATA_OPMODE_SYNCH)) {
		/* Need to set-up a callback function */
		spx->txlt_sata_pkt->satapkt_comp =
		    sata_txlt_nodata_cmd_completion;
		synch = FALSE;
	} else {
		spx->txlt_sata_pkt->satapkt_op_mode = SATA_OPMODE_SYNCH;
		synch = TRUE;
	}

	/* Transfer command to HBA */
	if (sata_hba_start(spx, &rval) != 0) {
		/* Pkt not accepted for execution */
		mutex_exit(&SATA_CPORT_MUTEX(shi, cport));
		return (rval);
	}

	/*
	 * If execution is non-synchronous,
	 * a callback function will handle potential errors, translate
	 * the response and will do a callback to a target driver.
	 * If it was synchronous, check execution status using the same
	 * framework callback.
	 */
	mutex_exit(&SATA_CPORT_MUTEX(shi, cport));
	if (synch) {
		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
		    "synchronous execution status %x\n",
		    spx->txlt_sata_pkt->satapkt_reason);

		sata_txlt_nodata_cmd_completion(spx->txlt_sata_pkt);
	}
	return (TRAN_ACCEPT);

}


/*
 * SATA translate command:  Read Capacity.
 * Emulated command for SATA disks.
 * Capacity is retrieved from cached Idenifty Device data.
 * Identify Device data shows effective disk capacity, not the native
 * capacity, which may be limitted by Set Max Address command.
 * This is ATA version for SATA hard disks.
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */
static int
sata_txlt_read_capacity(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct buf *bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	sata_drive_info_t *sdinfo;
	uint64_t val;
	uchar_t *rbuf;
	int rval;

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_read_capacity: ", NULL);

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;
	*scsipkt->pkt_scbp = STATUS_GOOD;
	if (bp != NULL && bp->b_un.b_addr && bp->b_bcount) {
		/*
		 * Because it is fully emulated command storing data
		 * programatically in the specified buffer, release
		 * preallocated DMA resources before storing data in the buffer,
		 * so no unwanted DMA sync would take place.
		 */
		sata_scsi_dmafree(NULL, scsipkt);

		sdinfo = sata_get_device_info(
		    spx->txlt_sata_hba_inst,
		    &spx->txlt_sata_pkt->satapkt_device);
		/* Last logical block address */
		val = sdinfo->satadrv_capacity - 1;
		rbuf = (uchar_t *)bp->b_un.b_addr;
		/* Need to swap endians to match scsi format */
		rbuf[0] = (val >> 24) & 0xff;
		rbuf[1] = (val >> 16) & 0xff;
		rbuf[2] = (val >> 8) & 0xff;
		rbuf[3] = val & 0xff;
		/* block size - always 512 bytes, for now */
		rbuf[4] = 0;
		rbuf[5] = 0;
		rbuf[6] = 0x02;
		rbuf[7] = 0;
		scsipkt->pkt_state |= STATE_XFERRED_DATA;
		scsipkt->pkt_resid = 0;

		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst, "%d\n",
		    sdinfo->satadrv_capacity -1);
	}
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
	/*
	 * If a callback was requested, do it now.
	 */
	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);

	return (TRAN_ACCEPT);
}

/*
 * SATA translate command: Mode Sense.
 * Translated into appropriate SATA command or emulated.
 * Saved Values Page Control (03) are not supported.
 *
 * NOTE: only caching mode sense page is currently implemented.
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */

static int
sata_txlt_mode_sense(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt	*scsipkt = spx->txlt_scsi_pkt;
	struct buf	*bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	sata_drive_info_t *sdinfo;
	sata_id_t *sata_id;
	struct scsi_extended_sense *sense;
	int 		len, bdlen, count, alc_len;
	int		pc;	/* Page Control code */
	uint8_t		*buf;	/* mode sense buffer */
	int		rval;

	SATADBG2(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_mode_sense, pc %x page code 0x%02x\n",
	    spx->txlt_scsi_pkt->pkt_cdbp[2] >> 6,
	    spx->txlt_scsi_pkt->pkt_cdbp[2] & 0x3f);

	buf = kmem_zalloc(1024, KM_SLEEP);

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		kmem_free(buf, 1024);
		return (rval);
	}

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;

	pc = scsipkt->pkt_cdbp[2] >> 6;

	if (bp != NULL && bp->b_un.b_addr && bp->b_bcount) {
		/*
		 * Because it is fully emulated command storing data
		 * programatically in the specified buffer, release
		 * preallocated DMA resources before storing data in the buffer,
		 * so no unwanted DMA sync would take place.
		 */
		sata_scsi_dmafree(NULL, scsipkt);

		len = 0;
		bdlen = 0;
		if (!(scsipkt->pkt_cdbp[1] & 8)) {
			if (scsipkt->pkt_cdbp[0] == SCMD_MODE_SENSE_G1 &&
			    (scsipkt->pkt_cdbp[0] & 0x10))
				bdlen = 16;
			else
				bdlen = 8;
		}
		/* Build mode parameter header */
		if (spx->txlt_scsi_pkt->pkt_cdbp[0] == SCMD_MODE_SENSE) {
			/* 4-byte mode parameter header */
			buf[len++] = 0;   	/* mode data length */
			buf[len++] = 0;		/* medium type */
			buf[len++] = 0;		/* dev-specific param */
			buf[len++] = bdlen;	/* Block Descriptor length */
		} else {
			/* 8-byte mode parameter header */
			buf[len++] = 0;		/* mode data length */
			buf[len++] = 0;
			buf[len++] = 0;		/* medium type */
			buf[len++] = 0;		/* dev-specific param */
			if (bdlen == 16)
				buf[len++] = 1;	/* long lba descriptor */
			else
				buf[len++] = 0;
			buf[len++] = 0;
			buf[len++] = 0;		/* Block Descriptor length */
			buf[len++] = bdlen;
		}

		sdinfo = sata_get_device_info(
		    spx->txlt_sata_hba_inst,
		    &spx->txlt_sata_pkt->satapkt_device);

		/* Build block descriptor only if not disabled (DBD) */
		if ((scsipkt->pkt_cdbp[1] & 0x08) == 0) {
			/* Block descriptor - direct-access device format */
			if (bdlen == 8) {
				/* build regular block descriptor */
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 24) & 0xff;
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 16) & 0xff;
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 8) & 0xff;
				buf[len++] = sdinfo->satadrv_capacity & 0xff;
				buf[len++] = 0; /* density code */
				buf[len++] = 0;
				if (sdinfo->satadrv_type ==
				    SATA_DTYPE_ATADISK)
					buf[len++] = 2;
				else
					/* ATAPI */
					buf[len++] = 8;
				buf[len++] = 0;
			} else if (bdlen == 16) {
				/* Long LBA Accepted */
				/* build long lba block descriptor */
#ifndef __lock_lint
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 56) & 0xff;
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 48) & 0xff;
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 40) & 0xff;
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 32) & 0xff;
#endif
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 24) & 0xff;
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 16) & 0xff;
				buf[len++] =
				    (sdinfo->satadrv_capacity >> 8) & 0xff;
				buf[len++] = sdinfo->satadrv_capacity & 0xff;
				buf[len++] = 0;
				buf[len++] = 0; /* density code */
				buf[len++] = 0;
				buf[len++] = 0;
				if (sdinfo->satadrv_type ==
				    SATA_DTYPE_ATADISK)
					buf[len++] = 2;
				else
					/* ATAPI */
					buf[len++] = 8;
				buf[len++] = 0;
			}
		}

		sata_id = &sdinfo->satadrv_id;

		/*
		 * Add requested pages.
		 * Page 3 and 4 are obsolete and we are not supporting them.
		 * We deal now with:
		 * caching (read/write cache control).
		 * We should eventually deal with following mode pages:
		 * error recovery  (0x01),
		 * power condition (0x1a),
		 * exception control page (enables SMART) (0x1c),
		 * enclosure management (ses),
		 * protocol-specific port mode (port control).
		 */
		switch (scsipkt->pkt_cdbp[2] & 0x3f) {
		case MODEPAGE_RW_ERRRECOV:
			/* DAD_MODE_ERR_RECOV */
			/* R/W recovery */
			len += sata_build_msense_page_1(sdinfo, pc, buf+len);
			break;
		case MODEPAGE_CACHING:
			/* DAD_MODE_CACHE */
			/* Reject not supported request for saved parameters */
			if (pc == 3) {
				*scsipkt->pkt_scbp = STATUS_CHECK;
				sense = sata_arq_sense(spx);
				sense->es_key = KEY_ILLEGAL_REQUEST;
				sense->es_add_code =
				    SD_SCSI_ASC_SAVING_PARAMS_NOT_SUPPORTED;
				goto done;
			}

			/* caching */
			len += sata_build_msense_page_8(sdinfo, pc, buf+len);
			break;
		case MODEPAGE_INFO_EXCPT:
			/* exception cntrl */
			if (sata_id->ai_cmdset82 & SATA_SMART_SUPPORTED) {
				len += sata_build_msense_page_1c(sdinfo, pc,
				    buf+len);
			}
			else
				goto err;
			break;
		case MODEPAGE_POWER_COND:
			/* DAD_MODE_POWER_COND */
			/* power condition */
			len += sata_build_msense_page_1a(sdinfo, pc, buf+len);
			break;

		case MODEPAGE_ACOUSTIC_MANAG:
			/* acoustic management */
			len += sata_build_msense_page_30(sdinfo, pc, buf+len);
			break;
		case MODEPAGE_ALLPAGES:
			/* all pages */
			len += sata_build_msense_page_1(sdinfo, pc, buf+len);
			len += sata_build_msense_page_8(sdinfo, pc, buf+len);
			len += sata_build_msense_page_1a(sdinfo, pc, buf+len);
			if (sata_id->ai_cmdset82 & SATA_SMART_SUPPORTED) {
				len += sata_build_msense_page_1c(sdinfo, pc,
				    buf+len);
			}
			len += sata_build_msense_page_30(sdinfo, pc, buf+len);
			break;
		default:
		err:
			/* Invalid request */
			*scsipkt->pkt_scbp = STATUS_CHECK;
			sense = sata_arq_sense(spx);
			sense->es_key = KEY_ILLEGAL_REQUEST;
			sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
			goto done;
		}

		/* fix total mode data length */
		if (spx->txlt_scsi_pkt->pkt_cdbp[0] == SCMD_MODE_SENSE) {
			/* 4-byte mode parameter header */
			buf[0] = len - 1;   	/* mode data length */
		} else {
			buf[0] = (len -2) >> 8;
			buf[1] = (len -2) & 0xff;
		}


		/* Check allocation length */
		if (scsipkt->pkt_cdbp[0] == SCMD_MODE_SENSE) {
			alc_len = scsipkt->pkt_cdbp[4];
		} else {
			alc_len = scsipkt->pkt_cdbp[7];
			alc_len = (len << 8) | scsipkt->pkt_cdbp[8];
		}
		/*
		 * We do not check for possible parameters truncation
		 * (alc_len < len) assuming that the target driver works
		 * correctly. Just avoiding overrun.
		 * Copy no more than requested and possible, buffer-wise.
		 */
		count = MIN(alc_len, len);
		count = MIN(bp->b_bcount, count);
		bcopy(buf, bp->b_un.b_addr, count);

		scsipkt->pkt_state |= STATE_XFERRED_DATA;
		scsipkt->pkt_resid = alc_len > count ? alc_len - count : 0;
	}
	*scsipkt->pkt_scbp = STATUS_GOOD;
done:
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
	(void) kmem_free(buf, 1024);

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);

	return (TRAN_ACCEPT);
}


/*
 * SATA translate command: Mode Select.
 * Translated into appropriate SATA command or emulated.
 * Saving parameters is not supported.
 * Changing device capacity is not supported (although theoretically
 * possible by executing SET FEATURES/SET MAX ADDRESS)
 *
 * Assumption is that the target driver is working correctly.
 *
 * More than one SATA command may be executed to perform operations specified
 * by mode select pages. The first error terminates further execution.
 * Operations performed successully are not backed-up in such case.
 *
 * NOTE: only caching mode select page is implemented.
 * Caching setup is remembered so it could be re-stored in case of
 * an unexpected device reset.
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */

static int
sata_txlt_mode_select(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct buf *bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	struct scsi_extended_sense *sense;
	int len, pagelen, count, pllen;
	uint8_t *buf;	/* mode select buffer */
	int rval, stat;
	uint_t nointr_flag;
	int dmod = 0;

	SATADBG2(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_mode_select, pc %x page code 0x%02x\n",
	    spx->txlt_scsi_pkt->pkt_cdbp[2] >> 6,
	    spx->txlt_scsi_pkt->pkt_cdbp[2] & 0x3f);

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	rval = TRAN_ACCEPT;

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;

	/* Reject not supported request */
	if (! (scsipkt->pkt_cdbp[1] & 0x10)) { /* No support for PF bit = 0 */
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
		goto done;
	}

	if (scsipkt->pkt_cdbp[0] == SCMD_MODE_SELECT) {
		pllen = scsipkt->pkt_cdbp[4];
	} else {
		pllen = scsipkt->pkt_cdbp[7];
		pllen = (pllen << 8) | scsipkt->pkt_cdbp[7];
	}

	*scsipkt->pkt_scbp = STATUS_GOOD;	/* Presumed outcome */

	if (bp != NULL && bp->b_un.b_addr && bp->b_bcount && pllen != 0) {
		buf = (uint8_t *)bp->b_un.b_addr;
		count = MIN(bp->b_bcount, pllen);
		scsipkt->pkt_state |= STATE_XFERRED_DATA;
		scsipkt->pkt_resid = 0;
		pllen = count;

		/*
		 * Check the header to skip the block descriptor(s) - we
		 * do not support setting device capacity.
		 * Existing macros do not recognize long LBA dscriptor,
		 * hence manual calculation.
		 */
		if (scsipkt->pkt_cdbp[0] == SCMD_MODE_SELECT) {
			/* 6-bytes CMD, 4 bytes header */
			if (count <= 4)
				goto done;		/* header only */
			len = buf[3] + 4;
		} else {
			/* 10-bytes CMD, 8 bytes header */
			if (count <= 8)
				goto done;		/* header only */
			len = buf[6];
			len = (len << 8) + buf[7] + 8;
		}
		if (len >= count)
			goto done;	/* header + descriptor(s) only */

		pllen -= len;		/* remaining data length */

		/*
		 * We may be executing SATA command and want to execute it
		 * in SYNCH mode, regardless of scsi_pkt setting.
		 * Save scsi_pkt setting and indicate SYNCH mode
		 */
		nointr_flag = scsipkt->pkt_flags & FLAG_NOINTR;
		if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
		    scsipkt->pkt_comp != NULL) {
			scsipkt->pkt_flags |= FLAG_NOINTR;
		}
		spx->txlt_sata_pkt->satapkt_op_mode = SATA_OPMODE_SYNCH;

		/*
		 * len is now the offset to a first mode select page
		 * Process all pages
		 */
		while (pllen > 0) {
			switch ((int)buf[len]) {
			case MODEPAGE_CACHING:
				/* No support for SP (saving) */
				if (scsipkt->pkt_cdbp[1] & 0x01) {
					*scsipkt->pkt_scbp = STATUS_CHECK;
					sense = sata_arq_sense(spx);
					sense->es_key = KEY_ILLEGAL_REQUEST;
					sense->es_add_code =
					    SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
					goto done;
				}
				stat = sata_mode_select_page_8(spx,
				    (struct mode_cache_scsi3 *)&buf[len],
				    pllen, &pagelen, &rval, &dmod);
				/*
				 * The pagelen value indicates the number of
				 * parameter bytes already processed.
				 * The rval is the return value from
				 * sata_tran_start().
				 * The stat indicates the overall status of
				 * the operation(s).
				 */
				if (stat != SATA_SUCCESS)
					/*
					 * Page processing did not succeed -
					 * all error info is already set-up,
					 * just return
					 */
					pllen = 0; /* this breaks the loop */
				else {
					len += pagelen;
					pllen -= pagelen;
				}
				break;

			case MODEPAGE_INFO_EXCPT:
				stat = sata_mode_select_page_1c(spx,
				    (struct mode_info_excpt_page *)&buf[len],
				    pllen, &pagelen, &rval, &dmod);
				/*
				 * The pagelen value indicates the number of
				 * parameter bytes already processed.
				 * The rval is the return value from
				 * sata_tran_start().
				 * The stat indicates the overall status of
				 * the operation(s).
				 */
				if (stat != SATA_SUCCESS)
					/*
					 * Page processing did not succeed -
					 * all error info is already set-up,
					 * just return
					 */
					pllen = 0; /* this breaks the loop */
				else {
					len += pagelen;
					pllen -= pagelen;
				}
				break;

			case MODEPAGE_ACOUSTIC_MANAG:
				stat = sata_mode_select_page_30(spx,
				    (struct mode_acoustic_management *)
				    &buf[len], pllen, &pagelen, &rval, &dmod);
				/*
				 * The pagelen value indicates the number of
				 * parameter bytes already processed.
				 * The rval is the return value from
				 * sata_tran_start().
				 * The stat indicates the overall status of
				 * the operation(s).
				 */
				if (stat != SATA_SUCCESS)
					/*
					 * Page processing did not succeed -
					 * all error info is already set-up,
					 * just return
					 */
					pllen = 0; /* this breaks the loop */
				else {
					len += pagelen;
					pllen -= pagelen;
				}

				break;
			default:
				*scsipkt->pkt_scbp = STATUS_CHECK;
				sense = sata_arq_sense(spx);
				sense->es_key = KEY_ILLEGAL_REQUEST;
				sense->es_add_code =
				    SD_SCSI_ASC_INVALID_FIELD_IN_PARAMS_LIST;
				goto done;
			}
		}
	}
done:
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
	/*
	 * If device parameters were modified, fetch and store the new
	 * Identify Device data. Since port mutex could have been released
	 * for accessing HBA driver, we need to re-check device existence.
	 */
	if (dmod != 0) {
		sata_drive_info_t new_sdinfo, *sdinfo;
		int rv;

		new_sdinfo.satadrv_addr =
		    spx->txlt_sata_pkt->satapkt_device.satadev_addr;
		rv = sata_fetch_device_identify_data(spx->txlt_sata_hba_inst,
		    &new_sdinfo);

		mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));
		/*
		 * Since port mutex could have been released when
		 * accessing HBA driver, we need to re-check that the
		 * framework still holds the device info structure.
		 */
		sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
		    &spx->txlt_sata_pkt->satapkt_device);
		if (sdinfo != NULL) {
			/*
			 * Device still has info structure in the
			 * sata framework. Copy newly fetched info
			 */
			if (rv == 0) {
				sdinfo->satadrv_id = new_sdinfo.satadrv_id;
				sata_save_drive_settings(sdinfo);
			} else {
				/*
				 * Could not fetch new data - invalidate
				 * sata_drive_info. That makes device
				 * unusable.
				 */
				sdinfo->satadrv_type = SATA_DTYPE_UNKNOWN;
				sdinfo->satadrv_state = SATA_STATE_UNKNOWN;
			}
		}
		if (rv != 0 || sdinfo == NULL) {
			/*
			 * This changes the overall mode select completion
			 * reason to a failed one !!!!!
			 */
			*scsipkt->pkt_scbp = STATUS_CHECK;
			sense = sata_arq_sense(spx);
			scsipkt->pkt_reason = CMD_INCOMPLETE;
			rval = TRAN_ACCEPT;
		}
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
	}
	/* Restore the scsi pkt flags */
	scsipkt->pkt_flags &= ~FLAG_NOINTR;
	scsipkt->pkt_flags |= nointr_flag;

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);

	return (rval);
}



/*
 * Translate command: Log Sense
 */
static 	int
sata_txlt_log_sense(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt	*scsipkt = spx->txlt_scsi_pkt;
	struct buf	*bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	sata_drive_info_t *sdinfo;
	struct scsi_extended_sense *sense;
	int 		len, count, alc_len;
	int		pc;	/* Page Control code */
	int		page_code;	/* Page code */
	uint8_t		*buf;	/* log sense buffer */
	int		rval;
#define	MAX_LOG_SENSE_PAGE_SIZE	512

	SATADBG2(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_log_sense, pc 0x%x, page code 0x%x\n",
	    spx->txlt_scsi_pkt->pkt_cdbp[2] >> 6,
	    spx->txlt_scsi_pkt->pkt_cdbp[2] & 0x3f);

	buf = kmem_zalloc(MAX_LOG_SENSE_PAGE_SIZE, KM_SLEEP);

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		kmem_free(buf, MAX_LOG_SENSE_PAGE_SIZE);
		return (rval);
	}

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;

	pc = scsipkt->pkt_cdbp[2] >> 6;
	page_code = scsipkt->pkt_cdbp[2] & 0x3f;

	/* Reject not supported request for all but cumulative values */
	switch (pc) {
	case PC_CUMULATIVE_VALUES:
		break;
	default:
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
		goto done;
	}

	switch (page_code) {
	case PAGE_CODE_GET_SUPPORTED_LOG_PAGES:
	case PAGE_CODE_SELF_TEST_RESULTS:
	case PAGE_CODE_INFORMATION_EXCEPTIONS:
	case PAGE_CODE_SMART_READ_DATA:
		break;
	default:
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
		goto done;
	}

	if (bp != NULL && bp->b_un.b_addr && bp->b_bcount) {
		/*
		 * Because log sense uses local buffers for data retrieval from
		 * the devices and sets the data programatically in the
		 * original specified buffer, release preallocated DMA
		 * resources before storing data in the original buffer,
		 * so no unwanted DMA sync would take place.
		 */
		sata_id_t *sata_id;

		sata_scsi_dmafree(NULL, scsipkt);

		len = 0;

		/* Build log parameter header */
		buf[len++] = page_code;	/* page code as in the CDB */
		buf[len++] = 0;		/* reserved */
		buf[len++] = 0;		/* Zero out page length for now (MSB) */
		buf[len++] = 0;		/* (LSB) */

		sdinfo = sata_get_device_info(
		    spx->txlt_sata_hba_inst,
		    &spx->txlt_sata_pkt->satapkt_device);


		/*
		 * Add requested pages.
		 */
		switch (page_code) {
		case PAGE_CODE_GET_SUPPORTED_LOG_PAGES:
			len = sata_build_lsense_page_0(sdinfo, buf + len);
			break;
		case PAGE_CODE_SELF_TEST_RESULTS:
			sata_id = &sdinfo->satadrv_id;
			if ((! (sata_id->ai_cmdset84 &
			    SATA_SMART_SELF_TEST_SUPPORTED)) ||
			    (! (sata_id->ai_features87 &
			    SATA_SMART_SELF_TEST_SUPPORTED))) {
				*scsipkt->pkt_scbp = STATUS_CHECK;
				sense = sata_arq_sense(spx);
				sense->es_key = KEY_ILLEGAL_REQUEST;
				sense->es_add_code =
				    SD_SCSI_ASC_INVALID_FIELD_IN_CDB;

				goto done;
			}
			len = sata_build_lsense_page_10(sdinfo, buf + len,
			    spx->txlt_sata_hba_inst);
			break;
		case PAGE_CODE_INFORMATION_EXCEPTIONS:
			sata_id = &sdinfo->satadrv_id;
			if (! (sata_id->ai_cmdset82 & SATA_SMART_SUPPORTED)) {
				*scsipkt->pkt_scbp = STATUS_CHECK;
				sense = sata_arq_sense(spx);
				sense->es_key = KEY_ILLEGAL_REQUEST;
				sense->es_add_code =
				    SD_SCSI_ASC_INVALID_FIELD_IN_CDB;

				goto done;
			}
			if (! (sata_id->ai_features85 & SATA_SMART_ENABLED)) {
				*scsipkt->pkt_scbp = STATUS_CHECK;
				sense = sata_arq_sense(spx);
				sense->es_key = KEY_ABORTED_COMMAND;
				sense->es_add_code =
				    SCSI_ASC_ATA_DEV_FEAT_NOT_ENABLED;
				sense->es_qual_code =
				    SCSI_ASCQ_ATA_DEV_FEAT_NOT_ENABLED;

				goto done;
			}

			len = sata_build_lsense_page_2f(sdinfo, buf + len,
			    spx->txlt_sata_hba_inst);
			break;
		case PAGE_CODE_SMART_READ_DATA:
			sata_id = &sdinfo->satadrv_id;
			if (! (sata_id->ai_cmdset82 & SATA_SMART_SUPPORTED)) {
				*scsipkt->pkt_scbp = STATUS_CHECK;
				sense = sata_arq_sense(spx);
				sense->es_key = KEY_ILLEGAL_REQUEST;
				sense->es_add_code =
				    SD_SCSI_ASC_INVALID_FIELD_IN_CDB;

				goto done;
			}
			if (! (sata_id->ai_features85 & SATA_SMART_ENABLED)) {
				*scsipkt->pkt_scbp = STATUS_CHECK;
				sense = sata_arq_sense(spx);
				sense->es_key = KEY_ABORTED_COMMAND;
				sense->es_add_code =
				    SCSI_ASC_ATA_DEV_FEAT_NOT_ENABLED;
				sense->es_qual_code =
				    SCSI_ASCQ_ATA_DEV_FEAT_NOT_ENABLED;

				goto done;
			}

			/* This page doesn't include a page header */
			len = sata_build_lsense_page_30(sdinfo, buf,
			    spx->txlt_sata_hba_inst);
			goto no_header;
		default:
			/* Invalid request */
			*scsipkt->pkt_scbp = STATUS_CHECK;
			sense = sata_arq_sense(spx);
			sense->es_key = KEY_ILLEGAL_REQUEST;
			sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
			goto done;
		}

		/* set parameter log sense data length */
		buf[2] = len >> 8;	/* log sense length (MSB) */
		buf[3] = len & 0xff;	/* log sense length (LSB) */

		len += SCSI_LOG_PAGE_HDR_LEN;
		ASSERT(len <= MAX_LOG_SENSE_PAGE_SIZE);

no_header:
		/* Check allocation length */
		alc_len = scsipkt->pkt_cdbp[7];
		alc_len = (len << 8) | scsipkt->pkt_cdbp[8];

		/*
		 * We do not check for possible parameters truncation
		 * (alc_len < len) assuming that the target driver works
		 * correctly. Just avoiding overrun.
		 * Copy no more than requested and possible, buffer-wise.
		 */
		count = MIN(alc_len, len);
		count = MIN(bp->b_bcount, count);
		bcopy(buf, bp->b_un.b_addr, count);

		scsipkt->pkt_state |= STATE_XFERRED_DATA;
		scsipkt->pkt_resid = alc_len > count ? alc_len - count : 0;
	}
	*scsipkt->pkt_scbp = STATUS_GOOD;
done:
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
	(void) kmem_free(buf, MAX_LOG_SENSE_PAGE_SIZE);

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);

	return (TRAN_ACCEPT);
}

/*
 * Translate command: Log Select
 * Not implemented at this time - returns invalid command response.
 */
static 	int
sata_txlt_log_select(sata_pkt_txlate_t *spx)
{
	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_log_select\n", NULL);

	return (sata_txlt_invalid_command(spx));
}


/*
 * Translate command: Read (various types).
 * Translated into appropriate type of ATA READ command
 * for SATA hard disks.
 * Both the device capabilities and requested operation mode are
 * considered.
 *
 * Following scsi cdb fields are ignored:
 * rdprotect, dpo, fua, fua_nv, group_number.
 *
 * If SATA_ENABLE_QUEUING flag is set (in the global SATA HBA framework
 * enable variable sata_func_enable), the capability of the controller and
 * capability of a device are checked and if both support queueing, read
 * request will be translated to READ_DMA_QUEUEING or READ_DMA_QUEUEING_EXT
 * command rather than plain READ_XXX command.
 * If SATA_ENABLE_NCQ flag is set in addition to SATA_ENABLE_QUEUING flag and
 * both the controller and device suport such functionality, the read
 * request will be translated to READ_FPDMA_QUEUED command.
 * In both cases the maximum queue depth is derived as minimum of:
 * HBA capability,device capability and sata_max_queue_depth variable setting.
 * The value passed to HBA driver is decremented by 1, because only 5 bits are
 * used to pass max queue depth value, and the maximum possible queue depth
 * is 32.
 *
 * Returns TRAN_ACCEPT or code returned by sata_hba_start() and
 * appropriate values in scsi_pkt fields.
 */
static int
sata_txlt_read(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	sata_drive_info_t *sdinfo;
	sata_hba_inst_t *shi = SATA_TXLT_HBA_INST(spx);
	int cport = SATA_TXLT_CPORT(spx);
	uint16_t sec_count;
	uint64_t lba;
	int rval;
	int synch;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);

	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;
	/*
	 * Extract LBA and sector count from scsi CDB.
	 */
	switch ((uint_t)scsipkt->pkt_cdbp[0]) {
	case SCMD_READ:
		/* 6-byte scsi read cmd : 0x08 */
		lba = (scsipkt->pkt_cdbp[1] & 0x1f);
		lba = (lba << 8) | scsipkt->pkt_cdbp[2];
		lba = (lba << 8) | scsipkt->pkt_cdbp[3];
		sec_count = scsipkt->pkt_cdbp[4];
		/* sec_count 0 will be interpreted as 256 by a device */
		break;
	case SCMD_READ_G1:
		/* 10-bytes scsi read command : 0x28 */
		lba = scsipkt->pkt_cdbp[2];
		lba = (lba << 8) | scsipkt->pkt_cdbp[3];
		lba = (lba << 8) | scsipkt->pkt_cdbp[4];
		lba = (lba << 8) | scsipkt->pkt_cdbp[5];
		sec_count = scsipkt->pkt_cdbp[7];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[8];
		break;
	case SCMD_READ_G5:
		/* 12-bytes scsi read command : 0xA8 */
		lba = scsipkt->pkt_cdbp[2];
		lba = (lba << 8) | scsipkt->pkt_cdbp[3];
		lba = (lba << 8) | scsipkt->pkt_cdbp[4];
		lba = (lba << 8) | scsipkt->pkt_cdbp[5];
		sec_count = scsipkt->pkt_cdbp[6];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[7];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[8];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[9];
		break;
	case SCMD_READ_G4:
		/* 16-bytes scsi read command : 0x88 */
		lba = scsipkt->pkt_cdbp[2];
		lba = (lba << 8) | scsipkt->pkt_cdbp[3];
		lba = (lba << 8) | scsipkt->pkt_cdbp[4];
		lba = (lba << 8) | scsipkt->pkt_cdbp[5];
		lba = (lba << 8) | scsipkt->pkt_cdbp[6];
		lba = (lba << 8) | scsipkt->pkt_cdbp[7];
		lba = (lba << 8) | scsipkt->pkt_cdbp[8];
		lba = (lba << 8) | scsipkt->pkt_cdbp[9];
		sec_count = scsipkt->pkt_cdbp[10];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[11];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[12];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[13];
		break;
	default:
		/* Unsupported command */
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (sata_txlt_invalid_command(spx));
	}

	/*
	 * Check if specified address exceeds device capacity
	 */
	if ((lba >= sdinfo->satadrv_capacity) ||
	    ((lba + sec_count) > sdinfo->satadrv_capacity)) {
		/* LBA out of range */
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (sata_txlt_lba_out_of_range(spx));
	}

	/*
	 * For zero-length transfer, emulate good completion of the command
	 * (reasons for rejecting the command were already checked).
	 * No DMA resources were allocated.
	 */
	if (spx->txlt_dma_cookie_list == NULL) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (sata_emul_rw_completion(spx));
	}

	/*
	 * Build cmd block depending on the device capability and
	 * requested operation mode.
	 * Do not bother with non-dma mode - we are working only with
	 * devices supporting DMA.
	 */
	scmd->satacmd_addr_type = ATA_ADDR_LBA;
	scmd->satacmd_device_reg = SATA_ADH_LBA;
	scmd->satacmd_cmd_reg = SATAC_READ_DMA;
	if (sdinfo->satadrv_features_support & SATA_DEV_F_LBA48) {
		scmd->satacmd_addr_type = ATA_ADDR_LBA48;
		scmd->satacmd_cmd_reg = SATAC_READ_DMA_EXT;
		scmd->satacmd_sec_count_msb = sec_count >> 8;
#ifndef __lock_lint
		scmd->satacmd_lba_low_msb = (lba >> 24) & 0xff;
		scmd->satacmd_lba_mid_msb = (lba >> 32) & 0xff;
		scmd->satacmd_lba_high_msb = lba >> 40;
#endif
	} else if (sdinfo->satadrv_features_support & SATA_DEV_F_LBA28) {
		scmd->satacmd_addr_type = ATA_ADDR_LBA28;
		scmd->satacmd_device_reg = SATA_ADH_LBA | ((lba >> 24) & 0xf);
	}
	scmd->satacmd_sec_count_lsb = sec_count & 0xff;
	scmd->satacmd_lba_low_lsb = lba & 0xff;
	scmd->satacmd_lba_mid_lsb = (lba >> 8) & 0xff;
	scmd->satacmd_lba_high_lsb = (lba >> 16) & 0xff;
	scmd->satacmd_features_reg = 0;
	scmd->satacmd_status_reg = 0;
	scmd->satacmd_error_reg = 0;

	/*
	 * Check if queueing commands should be used and switch
	 * to appropriate command if possible
	 */
	if (sata_func_enable & SATA_ENABLE_QUEUING) {
		boolean_t using_queuing;

		/* Queuing supported by controller and device? */
		if ((sata_func_enable & SATA_ENABLE_NCQ) &&
		    (sdinfo->satadrv_features_support &
		    SATA_DEV_F_NCQ) &&
		    (SATA_FEATURES(spx->txlt_sata_hba_inst) &
		    SATA_CTLF_NCQ)) {
			using_queuing = B_TRUE;

			/* NCQ supported - use FPDMA READ */
			scmd->satacmd_cmd_reg =
			    SATAC_READ_FPDMA_QUEUED;
			scmd->satacmd_features_reg_ext =
			    scmd->satacmd_sec_count_msb;
			scmd->satacmd_sec_count_msb = 0;
		} else if ((sdinfo->satadrv_features_support &
		    SATA_DEV_F_TCQ) &&
		    (SATA_FEATURES(spx->txlt_sata_hba_inst) &
		    SATA_CTLF_QCMD)) {
			using_queuing = B_TRUE;

			/* Legacy queueing */
			if (sdinfo->satadrv_features_support &
			    SATA_DEV_F_LBA48) {
				scmd->satacmd_cmd_reg =
				    SATAC_READ_DMA_QUEUED_EXT;
				scmd->satacmd_features_reg_ext =
				    scmd->satacmd_sec_count_msb;
				scmd->satacmd_sec_count_msb = 0;
			} else {
				scmd->satacmd_cmd_reg =
				    SATAC_READ_DMA_QUEUED;
			}
		} else	/* NCQ nor legacy queuing not supported */
			using_queuing = B_FALSE;

		/*
		 * If queuing, the sector count goes in the features register
		 * and the secount count will contain the tag.
		 */
		if (using_queuing) {
			scmd->satacmd_features_reg =
			    scmd->satacmd_sec_count_lsb;
			scmd->satacmd_sec_count_lsb = 0;
			scmd->satacmd_flags.sata_queued = B_TRUE;

			/* Set-up maximum queue depth */
			scmd->satacmd_flags.sata_max_queue_depth =
			    sdinfo->satadrv_max_queue_depth - 1;
		} else if (sdinfo->satadrv_features_enabled &
		    SATA_DEV_F_E_UNTAGGED_QING) {
			/*
			 * Although NCQ/TCQ is not enabled, untagged queuing
			 * may be still used.
			 * Set-up the maximum untagged queue depth.
			 * Use controller's queue depth from sata_hba_tran.
			 * SATA HBA drivers may ignore this value and rely on
			 * the internal limits.For drivers that do not
			 * ignore untaged queue depth, limit the value to
			 * SATA_MAX_QUEUE_DEPTH (32), as this is the
			 * largest value that can be passed via
			 * satacmd_flags.sata_max_queue_depth.
			 */
			scmd->satacmd_flags.sata_max_queue_depth =
			    SATA_QDEPTH(shi) <= SATA_MAX_QUEUE_DEPTH ?
			    SATA_QDEPTH(shi) - 1: SATA_MAX_QUEUE_DEPTH - 1;

		} else {
			scmd->satacmd_flags.sata_max_queue_depth = 0;
		}
	} else
		scmd->satacmd_flags.sata_max_queue_depth = 0;

	SATADBG3(SATA_DBG_HBA_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_read cmd 0x%2x, lba %llx, sec count %x\n",
	    scmd->satacmd_cmd_reg, lba, sec_count);

	if (!(spx->txlt_sata_pkt->satapkt_op_mode & SATA_OPMODE_SYNCH)) {
		/* Need callback function */
		spx->txlt_sata_pkt->satapkt_comp = sata_txlt_rw_completion;
		synch = FALSE;
	} else
		synch = TRUE;

	/* Transfer command to HBA */
	if (sata_hba_start(spx, &rval) != 0) {
		/* Pkt not accepted for execution */
		mutex_exit(&SATA_CPORT_MUTEX(shi, cport));
		return (rval);
	}
	mutex_exit(&SATA_CPORT_MUTEX(shi, cport));
	/*
	 * If execution is non-synchronous,
	 * a callback function will handle potential errors, translate
	 * the response and will do a callback to a target driver.
	 * If it was synchronous, check execution status using the same
	 * framework callback.
	 */
	if (synch) {
		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
		    "synchronous execution status %x\n",
		    spx->txlt_sata_pkt->satapkt_reason);
		sata_txlt_rw_completion(spx->txlt_sata_pkt);
	}
	return (TRAN_ACCEPT);
}


/*
 * SATA translate command: Write (various types)
 * Translated into appropriate type of ATA WRITE command
 * for SATA hard disks.
 * Both the device capabilities and requested operation mode are
 * considered.
 *
 * Following scsi cdb fields are ignored:
 * rwprotect, dpo, fua, fua_nv, group_number.
 *
 * If SATA_ENABLE_QUEUING flag is set (in the global SATA HBA framework
 * enable variable sata_func_enable), the capability of the controller and
 * capability of a device are checked and if both support queueing, write
 * request will be translated to WRITE_DMA_QUEUEING or WRITE_DMA_QUEUEING_EXT
 * command rather than plain WRITE_XXX command.
 * If SATA_ENABLE_NCQ flag is set in addition to SATA_ENABLE_QUEUING flag and
 * both the controller and device suport such functionality, the write
 * request will be translated to WRITE_FPDMA_QUEUED command.
 * In both cases the maximum queue depth is derived as minimum of:
 * HBA capability,device capability and sata_max_queue_depth variable setting.
 * The value passed to HBA driver is decremented by 1, because only 5 bits are
 * used to pass max queue depth value, and the maximum possible queue depth
 * is 32.
 *
 * Returns TRAN_ACCEPT or code returned by sata_hba_start() and
 * appropriate values in scsi_pkt fields.
 */
static int
sata_txlt_write(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	sata_drive_info_t *sdinfo;
	sata_hba_inst_t *shi = SATA_TXLT_HBA_INST(spx);
	int cport = SATA_TXLT_CPORT(spx);
	uint16_t sec_count;
	uint64_t lba;
	int rval;
	int synch;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);

	scmd->satacmd_flags.sata_data_direction = SATA_DIR_WRITE;
	/*
	 * Extract LBA and sector count from scsi CDB
	 */
	switch ((uint_t)scsipkt->pkt_cdbp[0]) {
	case SCMD_WRITE:
		/* 6-byte scsi read cmd : 0x0A */
		lba = (scsipkt->pkt_cdbp[1] & 0x1f);
		lba = (lba << 8) | scsipkt->pkt_cdbp[2];
		lba = (lba << 8) | scsipkt->pkt_cdbp[3];
		sec_count = scsipkt->pkt_cdbp[4];
		/* sec_count 0 will be interpreted as 256 by a device */
		break;
	case SCMD_WRITE_G1:
		/* 10-bytes scsi write command : 0x2A */
		lba = scsipkt->pkt_cdbp[2];
		lba = (lba << 8) | scsipkt->pkt_cdbp[3];
		lba = (lba << 8) | scsipkt->pkt_cdbp[4];
		lba = (lba << 8) | scsipkt->pkt_cdbp[5];
		sec_count = scsipkt->pkt_cdbp[7];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[8];
		break;
	case SCMD_WRITE_G5:
		/* 12-bytes scsi read command : 0xAA */
		lba = scsipkt->pkt_cdbp[2];
		lba = (lba << 8) | scsipkt->pkt_cdbp[3];
		lba = (lba << 8) | scsipkt->pkt_cdbp[4];
		lba = (lba << 8) | scsipkt->pkt_cdbp[5];
		sec_count = scsipkt->pkt_cdbp[6];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[7];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[8];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[9];
		break;
	case SCMD_WRITE_G4:
		/* 16-bytes scsi write command : 0x8A */
		lba = scsipkt->pkt_cdbp[2];
		lba = (lba << 8) | scsipkt->pkt_cdbp[3];
		lba = (lba << 8) | scsipkt->pkt_cdbp[4];
		lba = (lba << 8) | scsipkt->pkt_cdbp[5];
		lba = (lba << 8) | scsipkt->pkt_cdbp[6];
		lba = (lba << 8) | scsipkt->pkt_cdbp[7];
		lba = (lba << 8) | scsipkt->pkt_cdbp[8];
		lba = (lba << 8) | scsipkt->pkt_cdbp[9];
		sec_count = scsipkt->pkt_cdbp[10];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[11];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[12];
		sec_count = (sec_count << 8) | scsipkt->pkt_cdbp[13];
		break;
	default:
		/* Unsupported command */
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (sata_txlt_invalid_command(spx));
	}

	/*
	 * Check if specified address and length exceeds device capacity
	 */
	if ((lba >= sdinfo->satadrv_capacity) ||
	    ((lba + sec_count) > sdinfo->satadrv_capacity)) {
		/* LBA out of range */
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (sata_txlt_lba_out_of_range(spx));
	}

	/*
	 * For zero-length transfer, emulate good completion of the command
	 * (reasons for rejecting the command were already checked).
	 * No DMA resources were allocated.
	 */
	if (spx->txlt_dma_cookie_list == NULL) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (sata_emul_rw_completion(spx));
	}

	/*
	 * Build cmd block depending on the device capability and
	 * requested operation mode.
	 * Do not bother with non-dma mode- we are working only with
	 * devices supporting DMA.
	 */
	scmd->satacmd_addr_type = ATA_ADDR_LBA;
	scmd->satacmd_device_reg = SATA_ADH_LBA;
	scmd->satacmd_cmd_reg = SATAC_WRITE_DMA;
	if (sdinfo->satadrv_features_support & SATA_DEV_F_LBA48) {
		scmd->satacmd_addr_type = ATA_ADDR_LBA48;
		scmd->satacmd_cmd_reg = SATAC_WRITE_DMA_EXT;
		scmd->satacmd_sec_count_msb = sec_count >> 8;
		scmd->satacmd_lba_low_msb = (lba >> 24) & 0xff;
#ifndef __lock_lint
		scmd->satacmd_lba_mid_msb = (lba >> 32) & 0xff;
		scmd->satacmd_lba_high_msb = lba >> 40;
#endif
	} else if (sdinfo->satadrv_features_support & SATA_DEV_F_LBA28) {
		scmd->satacmd_addr_type = ATA_ADDR_LBA28;
		scmd->satacmd_device_reg = SATA_ADH_LBA | ((lba >> 24) & 0xf);
	}
	scmd->satacmd_sec_count_lsb = sec_count & 0xff;
	scmd->satacmd_lba_low_lsb = lba & 0xff;
	scmd->satacmd_lba_mid_lsb = (lba >> 8) & 0xff;
	scmd->satacmd_lba_high_lsb = (lba >> 16) & 0xff;
	scmd->satacmd_features_reg = 0;
	scmd->satacmd_status_reg = 0;
	scmd->satacmd_error_reg = 0;

	/*
	 * Check if queueing commands should be used and switch
	 * to appropriate command if possible
	 */
	if (sata_func_enable & SATA_ENABLE_QUEUING) {
		boolean_t using_queuing;

		/* Queuing supported by controller and device? */
		if ((sata_func_enable & SATA_ENABLE_NCQ) &&
		    (sdinfo->satadrv_features_support &
		    SATA_DEV_F_NCQ) &&
		    (SATA_FEATURES(spx->txlt_sata_hba_inst) &
		    SATA_CTLF_NCQ)) {
			using_queuing = B_TRUE;

			/* NCQ supported - use FPDMA WRITE */
			scmd->satacmd_cmd_reg =
			    SATAC_WRITE_FPDMA_QUEUED;
			scmd->satacmd_features_reg_ext =
			    scmd->satacmd_sec_count_msb;
			scmd->satacmd_sec_count_msb = 0;
		} else if ((sdinfo->satadrv_features_support &
		    SATA_DEV_F_TCQ) &&
		    (SATA_FEATURES(spx->txlt_sata_hba_inst) &
		    SATA_CTLF_QCMD)) {
			using_queuing = B_TRUE;

			/* Legacy queueing */
			if (sdinfo->satadrv_features_support &
			    SATA_DEV_F_LBA48) {
				scmd->satacmd_cmd_reg =
				    SATAC_WRITE_DMA_QUEUED_EXT;
				scmd->satacmd_features_reg_ext =
				    scmd->satacmd_sec_count_msb;
				scmd->satacmd_sec_count_msb = 0;
			} else {
				scmd->satacmd_cmd_reg =
				    SATAC_WRITE_DMA_QUEUED;
			}
		} else	/*  NCQ nor legacy queuing not supported */
			using_queuing = B_FALSE;

		if (using_queuing) {
			scmd->satacmd_features_reg =
			    scmd->satacmd_sec_count_lsb;
			scmd->satacmd_sec_count_lsb = 0;
			scmd->satacmd_flags.sata_queued = B_TRUE;
			/* Set-up maximum queue depth */
			scmd->satacmd_flags.sata_max_queue_depth =
			    sdinfo->satadrv_max_queue_depth - 1;
		} else if (sdinfo->satadrv_features_enabled &
		    SATA_DEV_F_E_UNTAGGED_QING) {
			/*
			 * Although NCQ/TCQ is not enabled, untagged queuing
			 * may be still used.
			 * Set-up the maximum untagged queue depth.
			 * Use controller's queue depth from sata_hba_tran.
			 * SATA HBA drivers may ignore this value and rely on
			 * the internal limits. For drivera that do not
			 * ignore untaged queue depth, limit the value to
			 * SATA_MAX_QUEUE_DEPTH (32), as this is the
			 * largest value that can be passed via
			 * satacmd_flags.sata_max_queue_depth.
			 */
			scmd->satacmd_flags.sata_max_queue_depth =
			    SATA_QDEPTH(shi) <= SATA_MAX_QUEUE_DEPTH ?
			    SATA_QDEPTH(shi) - 1: SATA_MAX_QUEUE_DEPTH - 1;

		} else {
			scmd->satacmd_flags.sata_max_queue_depth = 0;
		}
	} else
		scmd->satacmd_flags.sata_max_queue_depth = 0;

	SATADBG3(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_write cmd 0x%2x, lba %llx, sec count %x\n",
	    scmd->satacmd_cmd_reg, lba, sec_count);

	if (!(spx->txlt_sata_pkt->satapkt_op_mode & SATA_OPMODE_SYNCH)) {
		/* Need callback function */
		spx->txlt_sata_pkt->satapkt_comp = sata_txlt_rw_completion;
		synch = FALSE;
	} else
		synch = TRUE;

	/* Transfer command to HBA */
	if (sata_hba_start(spx, &rval) != 0) {
		/* Pkt not accepted for execution */
		mutex_exit(&SATA_CPORT_MUTEX(shi, cport));
		return (rval);
	}
	mutex_exit(&SATA_CPORT_MUTEX(shi, cport));

	/*
	 * If execution is non-synchronous,
	 * a callback function will handle potential errors, translate
	 * the response and will do a callback to a target driver.
	 * If it was synchronous, check execution status using the same
	 * framework callback.
	 */
	if (synch) {
		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
		    "synchronous execution status %x\n",
		    spx->txlt_sata_pkt->satapkt_reason);
		sata_txlt_rw_completion(spx->txlt_sata_pkt);
	}
	return (TRAN_ACCEPT);
}


/*
 * Implements SCSI SBC WRITE BUFFER command download microcode option
 */
static int
sata_txlt_write_buffer(sata_pkt_txlate_t *spx)
{
#define	WB_DOWNLOAD_MICROCODE_AND_REVERT_MODE			4
#define	WB_DOWNLOAD_MICROCODE_AND_SAVE_MODE			5

	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	struct buf *bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	struct scsi_extended_sense *sense;
	int rval, mode, sector_count;
	sata_hba_inst_t *shi = SATA_TXLT_HBA_INST(spx);
	int cport = SATA_TXLT_CPORT(spx);
	boolean_t synch;

	synch = (spx->txlt_sata_pkt->satapkt_op_mode & SATA_OPMODE_SYNCH) != 0;
	mode = scsipkt->pkt_cdbp[1] & 0x1f;

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_write_buffer, mode 0x%x\n", mode);

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if ((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	scmd->satacmd_flags.sata_data_direction = SATA_DIR_WRITE;

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;

	/*
	 * The SCSI to ATA translation specification only calls
	 * for WB_DOWNLOAD_MICROCODE_AND_SAVE_MODE.
	 * WB_DOWNLOAD_MICROC_AND_REVERT_MODE is implemented, but
	 * ATA 8 (draft) got rid of download microcode for temp
	 * and it is even optional for ATA 7, so it may be aborted.
	 * WB_DOWNLOAD_MICROCODE_WITH_OFFSET is not implemented as
	 * it is not specified and the buffer offset for SCSI is a 16-bit
	 * value in bytes, but for ATA it is a 16-bit offset in 512 byte
	 * sectors.  Thus the offset really doesn't buy us anything.
	 * If and when ATA 8 is stabilized and the SCSI to ATA specification
	 * is revised, this can be revisisted.
	 */
	/* Reject not supported request */
	switch (mode) {
	case WB_DOWNLOAD_MICROCODE_AND_REVERT_MODE:
		scmd->satacmd_features_reg = SATA_DOWNLOAD_MCODE_TEMP;
		break;
	case WB_DOWNLOAD_MICROCODE_AND_SAVE_MODE:
		scmd->satacmd_features_reg = SATA_DOWNLOAD_MCODE_SAVE;
		break;
	default:
		goto bad_param;
	}

	*scsipkt->pkt_scbp = STATUS_GOOD;	/* Presumed outcome */

	scmd->satacmd_cmd_reg = SATAC_DOWNLOAD_MICROCODE;
	if ((bp->b_bcount % SATA_DISK_SECTOR_SIZE) != 0)
		goto bad_param;
	sector_count = bp->b_bcount / SATA_DISK_SECTOR_SIZE;
	scmd->satacmd_sec_count_lsb = (uint8_t)sector_count;
	scmd->satacmd_lba_low_lsb = ((uint16_t)sector_count) >> 8;
	scmd->satacmd_lba_mid_lsb = 0;
	scmd->satacmd_lba_high_lsb = 0;
	scmd->satacmd_device_reg = 0;
	spx->txlt_sata_pkt->satapkt_comp =
	    sata_txlt_download_mcode_cmd_completion;
	scmd->satacmd_addr_type = 0;

	/* Transfer command to HBA */
	if (sata_hba_start(spx, &rval) != 0) {
		/* Pkt not accepted for execution */
		mutex_exit(&SATA_CPORT_MUTEX(shi, cport));
		return (rval);
	}

	mutex_exit(&SATA_CPORT_MUTEX(shi, cport));
	/*
	 * If execution is non-synchronous,
	 * a callback function will handle potential errors, translate
	 * the response and will do a callback to a target driver.
	 * If it was synchronous, check execution status using the same
	 * framework callback.
	 */
	if (synch) {
		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
		    "synchronous execution\n", NULL);
		/* Calling pre-set completion routine */
		(*spx->txlt_sata_pkt->satapkt_comp)(spx->txlt_sata_pkt);
	}
	return (TRAN_ACCEPT);

bad_param:
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
	*scsipkt->pkt_scbp = STATUS_CHECK;
	sense = sata_arq_sense(spx);
	sense->es_key = KEY_ILLEGAL_REQUEST;
	sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL) {
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == 0) {
			/* Scheduling the callback failed */
			rval = TRAN_BUSY;
		}
	}
	return (rval);
}


/*
 * Retry identify device when command returns SATA_INCOMPLETE_DATA
 * after doing a firmware download.
 */
static void
sata_retry_identify_device(void *arg)
{
#define	DOWNLOAD_WAIT_TIME_SECS	60
#define	DOWNLOAD_WAIT_INTERVAL_SECS	1
	int rval;
	int retry_cnt;
	sata_pkt_t *sata_pkt = (sata_pkt_t *)arg;
	sata_pkt_txlate_t *spx =
	    (sata_pkt_txlate_t *)sata_pkt->satapkt_framework_private;
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_hba_inst_t *sata_hba_inst = spx->txlt_sata_hba_inst;
	sata_device_t sata_device = spx->txlt_sata_pkt->satapkt_device;
	sata_drive_info_t *sdinfo;

	/*
	 * Before returning good status, probe device.
	 * Device probing will get IDENTIFY DEVICE data, if possible.
	 * The assumption is that the new microcode is applied by the
	 * device. It is a caller responsibility to verify this.
	 */
	for (retry_cnt = 0;
	    retry_cnt < DOWNLOAD_WAIT_TIME_SECS / DOWNLOAD_WAIT_INTERVAL_SECS;
	    retry_cnt++) {
		rval = sata_probe_device(sata_hba_inst, &sata_device);

		if (rval == SATA_SUCCESS) { /* Set default features */
			sdinfo = sata_get_device_info(sata_hba_inst,
			    &sata_device);
			if (sata_initialize_device(sata_hba_inst, sdinfo) !=
			    SATA_SUCCESS) {
				/* retry */
				(void) sata_initialize_device(sata_hba_inst,
				    sdinfo);
			}
			if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
			    scsipkt->pkt_comp != NULL)
				(*scsipkt->pkt_comp)(scsipkt);
			return;
		} else if (rval == SATA_RETRY) {
			delay(drv_usectohz(1000000 *
			    DOWNLOAD_WAIT_INTERVAL_SECS));
			continue;
		} else	/* failed - no reason to retry */
			break;
	}

	/*
	 * Something went wrong, device probing failed.
	 */
	SATA_LOG_D((sata_hba_inst, CE_WARN,
	    "Cannot probe device after downloading microcode\n"));

	/* Reset device to force retrying the probe. */
	(void) (*SATA_RESET_DPORT_FUNC(sata_hba_inst))
	    (SATA_DIP(sata_hba_inst), &sata_device);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		(*scsipkt->pkt_comp)(scsipkt);
}

/*
 * Translate completion status of download microcode command.
 * pkt completion_reason is checked to determine the completion status.
 * Do scsi callback if necessary (FLAG_NOINTR == 0)
 *
 * Note: this function may be called also for synchronously executed
 * command.
 * This function may be used only if scsi_pkt is non-NULL.
 */
static void
sata_txlt_download_mcode_cmd_completion(sata_pkt_t *sata_pkt)
{
	sata_pkt_txlate_t *spx =
	    (sata_pkt_txlate_t *)sata_pkt->satapkt_framework_private;
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense *sense;
	sata_drive_info_t *sdinfo;
	sata_hba_inst_t *sata_hba_inst = spx->txlt_sata_hba_inst;
	sata_device_t sata_device = spx->txlt_sata_pkt->satapkt_device;
	int rval;

	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
	if (sata_pkt->satapkt_reason == SATA_PKT_COMPLETED) {
		scsipkt->pkt_reason = CMD_CMPLT;

		rval = sata_probe_device(sata_hba_inst, &sata_device);

		if (rval == SATA_SUCCESS) { /* Set default features */
			sdinfo = sata_get_device_info(sata_hba_inst,
			    &sata_device);
			if (sata_initialize_device(sata_hba_inst, sdinfo) !=
			    SATA_SUCCESS) {
				/* retry */
				(void) sata_initialize_device(sata_hba_inst,
				    sdinfo);
			}
			if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
			    scsipkt->pkt_comp != NULL)
				(*scsipkt->pkt_comp)(scsipkt);
		} else {
			(void) ddi_taskq_dispatch(
			    (ddi_taskq_t *)SATA_TXLT_TASKQ(spx),
			    sata_retry_identify_device,
			    (void *)sata_pkt, TQ_NOSLEEP);
		}


	} else {
		/* Something went wrong, microcode download command failed */
		scsipkt->pkt_reason = CMD_INCOMPLETE;
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		switch (sata_pkt->satapkt_reason) {
		case SATA_PKT_PORT_ERROR:
			/*
			 * We have no device data. Assume no data transfered.
			 */
			sense->es_key = KEY_HARDWARE_ERROR;
			break;

		case SATA_PKT_DEV_ERROR:
			if (sata_pkt->satapkt_cmd.satacmd_status_reg &
			    SATA_STATUS_ERR) {
				/*
				 * determine dev error reason from error
				 * reg content
				 */
				sata_decode_device_error(spx, sense);
				break;
			}
			/* No extended sense key - no info available */
			break;

		case SATA_PKT_TIMEOUT:
			/* scsipkt->pkt_reason = CMD_TIMEOUT; */
			scsipkt->pkt_reason = CMD_INCOMPLETE;
			/* No extended sense key ? */
			break;

		case SATA_PKT_ABORTED:
			scsipkt->pkt_reason = CMD_ABORTED;
			/* No extended sense key ? */
			break;

		case SATA_PKT_RESET:
			/* pkt aborted by an explicit reset from a host */
			scsipkt->pkt_reason = CMD_RESET;
			break;

		default:
			SATA_LOG_D((spx->txlt_sata_hba_inst, CE_WARN,
			    "sata_txlt_nodata_cmd_completion: "
			    "invalid packet completion reason %d",
			    sata_pkt->satapkt_reason));
			scsipkt->pkt_reason = CMD_TRAN_ERR;
			break;
		}

		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
		    "scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

		if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
		    scsipkt->pkt_comp != NULL)
			/* scsi callback required */
			(*scsipkt->pkt_comp)(scsipkt);
	}
}




/*
 * Translate command: Synchronize Cache.
 * Translates into Flush Cache command for SATA hard disks.
 *
 * Returns TRAN_ACCEPT or code returned by sata_hba_start() and
 * appropriate values in scsi_pkt fields.
 */
static 	int
sata_txlt_synchronize_cache(sata_pkt_txlate_t *spx)
{
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	sata_hba_inst_t *shi = SATA_TXLT_HBA_INST(spx);
	int cport = SATA_TXLT_CPORT(spx);
	int rval;
	int synch;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	scmd->satacmd_addr_type = 0;
	scmd->satacmd_cmd_reg = SATAC_FLUSH_CACHE;
	scmd->satacmd_device_reg = 0;
	scmd->satacmd_sec_count_lsb = 0;
	scmd->satacmd_lba_low_lsb = 0;
	scmd->satacmd_lba_mid_lsb = 0;
	scmd->satacmd_lba_high_lsb = 0;
	scmd->satacmd_features_reg = 0;
	scmd->satacmd_status_reg = 0;
	scmd->satacmd_error_reg = 0;

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "sata_txlt_synchronize_cache\n", NULL);

	if (!(spx->txlt_sata_pkt->satapkt_op_mode & SATA_OPMODE_SYNCH)) {
		/* Need to set-up a callback function */
		spx->txlt_sata_pkt->satapkt_comp =
		    sata_txlt_nodata_cmd_completion;
		synch = FALSE;
	} else
		synch = TRUE;

	/* Transfer command to HBA */
	if (sata_hba_start(spx, &rval) != 0) {
		/* Pkt not accepted for execution */
		mutex_exit(&SATA_CPORT_MUTEX(shi, cport));
		return (rval);
	}
	mutex_exit(&SATA_CPORT_MUTEX(shi, cport));

	/*
	 * If execution non-synchronous, it had to be completed
	 * a callback function will handle potential errors, translate
	 * the response and will do a callback to a target driver.
	 * If it was synchronous, check status, using the same
	 * framework callback.
	 */
	if (synch) {
		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
		    "synchronous execution status %x\n",
		    spx->txlt_sata_pkt->satapkt_reason);
		sata_txlt_nodata_cmd_completion(spx->txlt_sata_pkt);
	}
	return (TRAN_ACCEPT);
}


/*
 * Send pkt to SATA HBA driver
 *
 * This function may be called only if the operation is requested by scsi_pkt,
 * i.e. scsi_pkt is not NULL.
 *
 * This function has to be called with cport mutex held. It does release
 * the mutex when it calls HBA driver sata_tran_start function and
 * re-acquires it afterwards.
 *
 * If return value is 0, pkt was accepted, -1 otherwise
 * rval is set to appropriate sata_scsi_start return value.
 *
 * Note 1:If HBA driver returns value other than TRAN_ACCEPT, it should not
 * have called the sata_pkt callback function for this packet.
 *
 * The scsi callback has to be performed by the caller of this routine.
 *
 * Note 2: No port multiplier support for now.
 */
static int
sata_hba_start(sata_pkt_txlate_t *spx, int *rval)
{
	int stat, cport;
	sata_hba_inst_t *sata_hba_inst = spx->txlt_sata_hba_inst;
	sata_drive_info_t *sdinfo;
	sata_device_t *sata_device;
	uint8_t cmd;
	struct sata_cmd_flags cmd_flags;

	ASSERT(spx->txlt_sata_pkt != NULL);

	cport = SATA_TXLT_CPORT(spx);
	ASSERT(mutex_owned(&SATA_CPORT_MUTEX(sata_hba_inst, cport)));

	sdinfo = sata_get_device_info(sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);
	ASSERT(sdinfo != NULL);

	/* Clear device reset state? */
	if (sdinfo->satadrv_event_flags & SATA_EVNT_CLEAR_DEVICE_RESET) {
		spx->txlt_sata_pkt->satapkt_cmd.satacmd_flags.
		    sata_clear_dev_reset = B_TRUE;
		sdinfo->satadrv_event_flags &= ~SATA_EVNT_CLEAR_DEVICE_RESET;
		SATADBG1(SATA_DBG_EVENTS, sata_hba_inst,
		    "sata_hba_start: clearing device reset state\n", NULL);
	}
	cmd = spx->txlt_sata_pkt->satapkt_cmd.satacmd_cmd_reg;
	cmd_flags = spx->txlt_sata_pkt->satapkt_cmd.satacmd_flags;
	sata_device = &spx->txlt_sata_pkt->satapkt_device;

	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Sata cmd 0x%2x\n", cmd);

	stat = (*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst),
	    spx->txlt_sata_pkt);

	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));
	sdinfo = sata_get_device_info(sata_hba_inst, sata_device);
	/*
	 * If sata pkt was accepted and executed in asynchronous mode, i.e.
	 * with the sata callback, the sata_pkt could be already destroyed
	 * by the time we check ther return status from the hba_start()
	 * function, because sata_scsi_destroy_pkt() could have been already
	 * called (perhaps in the interrupt context). So, in such case, there
	 * should be no references to it. In other cases, sata_pkt still
	 * exists.
	 */
	switch (stat) {
	case SATA_TRAN_ACCEPTED:
		/*
		 * pkt accepted for execution.
		 * If it was executed synchronously, it is already completed
		 * and pkt completion_reason indicates completion status.
		 */
		*rval = TRAN_ACCEPT;
		return (0);

	case SATA_TRAN_QUEUE_FULL:
		/*
		 * Controller detected queue full condition.
		 */
		SATADBG1(SATA_DBG_HBA_IF, sata_hba_inst,
		    "sata_hba_start: queue full\n", NULL);

		spx->txlt_scsi_pkt->pkt_reason = CMD_INCOMPLETE;
		*spx->txlt_scsi_pkt->pkt_scbp = STATUS_QFULL;

		*rval = TRAN_BUSY;
		break;

	case SATA_TRAN_PORT_ERROR:
		/*
		 * Communication/link with device or general port error
		 * detected before pkt execution begun.
		 */
		if (spx->txlt_sata_pkt->satapkt_device.satadev_addr.qual ==
		    SATA_ADDR_CPORT ||
		    spx->txlt_sata_pkt->satapkt_device.satadev_addr.qual ==
		    SATA_ADDR_DCPORT)
			sata_log(sata_hba_inst, CE_CONT,
			    "SATA port %d error",
			    sata_device->satadev_addr.cport);
		else
			sata_log(sata_hba_inst, CE_CONT,
			    "SATA port %d pmport %d error\n",
			    sata_device->satadev_addr.cport,
			    sata_device->satadev_addr.pmport);

		/*
		 * Update the port/device structure.
		 * sata_pkt should be still valid. Since port error is
		 * returned, sata_device content should reflect port
		 * state - it means, that sata address have been changed,
		 * because original packet's sata address refered to a device
		 * attached to some port.
		 */
		sata_update_port_info(sata_hba_inst, sata_device);
		spx->txlt_scsi_pkt->pkt_reason = CMD_TRAN_ERR;
		*rval = TRAN_FATAL_ERROR;
		break;

	case SATA_TRAN_CMD_UNSUPPORTED:
		/*
		 * Command rejected by HBA as unsupported. It was HBA driver
		 * that rejected the command, command was not sent to
		 * an attached device.
		 */
		if ((sdinfo != NULL) &&
		    (sdinfo->satadrv_state & SATA_DSTATE_RESET))
			SATADBG1(SATA_DBG_EVENTS, sata_hba_inst,
			    "sat_hba_start: cmd 0x%2x rejected "
			    "with SATA_TRAN_CMD_UNSUPPORTED status\n", cmd);

		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));
		(void) sata_txlt_invalid_command(spx);
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));

		*rval = TRAN_ACCEPT;
		break;

	case SATA_TRAN_BUSY:
		/*
		 * Command rejected by HBA because other operation prevents
		 * accepting the packet, or device is in RESET condition.
		 */
		if (sdinfo != NULL) {
			sdinfo->satadrv_state =
			    spx->txlt_sata_pkt->satapkt_device.satadev_state;

			if (sdinfo->satadrv_state & SATA_DSTATE_RESET) {
				SATADBG1(SATA_DBG_EVENTS, sata_hba_inst,
				    "sata_hba_start: cmd 0x%2x rejected "
				    "because of device reset condition\n",
				    cmd);
			} else {
				SATADBG1(SATA_DBG_EVENTS, sata_hba_inst,
				    "sata_hba_start: cmd 0x%2x rejected "
				    "with SATA_TRAN_BUSY status\n",
				    cmd);
			}
		}
		spx->txlt_scsi_pkt->pkt_reason = CMD_INCOMPLETE;
		*rval = TRAN_BUSY;
		break;

	default:
		/* Unrecognized HBA response */
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_hba_start: unrecognized HBA response "
		    "to cmd : 0x%2x resp 0x%x", cmd, rval));
		spx->txlt_scsi_pkt->pkt_reason = CMD_TRAN_ERR;
		*rval = TRAN_FATAL_ERROR;
		break;
	}

	/*
	 * If we got here, the packet was rejected.
	 * Check if we need to remember reset state clearing request
	 */
	if (cmd_flags.sata_clear_dev_reset) {
		/*
		 * Check if device is still configured - it may have
		 * disapeared from the configuration
		 */
		sdinfo = sata_get_device_info(sata_hba_inst, sata_device);
		if (sdinfo != NULL) {
			/*
			 * Restore the flag that requests clearing of
			 * the device reset state,
			 * so the next sata packet may carry it to HBA.
			 */
			sdinfo->satadrv_event_flags |=
			    SATA_EVNT_CLEAR_DEVICE_RESET;
		}
	}
	return (-1);
}

/*
 * Scsi response setup for invalid LBA
 *
 * Returns TRAN_ACCEPT and appropriate values in scsi_pkt fields.
 */
static int
sata_txlt_lba_out_of_range(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense *sense;

	scsipkt->pkt_reason = CMD_CMPLT;
	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;
	*scsipkt->pkt_scbp = STATUS_CHECK;

	*scsipkt->pkt_scbp = STATUS_CHECK;
	sense = sata_arq_sense(spx);
	sense->es_key = KEY_ILLEGAL_REQUEST;
	sense->es_add_code = SD_SCSI_ASC_LBA_OUT_OF_RANGE;

	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp, (void *) scsipkt,
		    TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);
	return (TRAN_ACCEPT);
}


/*
 * Analyze device status and error registers and translate them into
 * appropriate scsi sense codes.
 * NOTE: non-packet commands only for now
 */
static void
sata_decode_device_error(sata_pkt_txlate_t *spx,
    struct scsi_extended_sense *sense)
{
	uint8_t err_reg = spx->txlt_sata_pkt->satapkt_cmd.satacmd_error_reg;

	ASSERT(sense != NULL);
	ASSERT(spx->txlt_sata_pkt->satapkt_cmd.satacmd_status_reg &
	    SATA_STATUS_ERR);


	if (err_reg & SATA_ERROR_ICRC) {
		sense->es_key = KEY_ABORTED_COMMAND;
		sense->es_add_code = 0x08; /* Communication failure */
		return;
	}

	if (err_reg & SATA_ERROR_UNC) {
		sense->es_key = KEY_MEDIUM_ERROR;
		/* Information bytes (LBA) need to be set by a caller */
		return;
	}

	/* ADD HERE: MC error bit handling for ATAPI CD/DVD */
	if (err_reg & (SATA_ERROR_MCR | SATA_ERROR_NM)) {
		sense->es_key = KEY_UNIT_ATTENTION;
		sense->es_add_code = 0x3a; /* No media present */
		return;
	}

	if (err_reg & SATA_ERROR_IDNF) {
		if (err_reg & SATA_ERROR_ABORT) {
			sense->es_key = KEY_ABORTED_COMMAND;
		} else {
			sense->es_key = KEY_ILLEGAL_REQUEST;
			sense->es_add_code = 0x21; /* LBA out of range */
		}
		return;
	}

	if (err_reg & SATA_ERROR_ABORT) {
		ASSERT(spx->txlt_sata_pkt != NULL);
		sense->es_key = KEY_ABORTED_COMMAND;
		return;
	}
}

/*
 * Extract error LBA from sata_pkt.satapkt_cmd register fields
 */
static void
sata_extract_error_lba(sata_pkt_txlate_t *spx, uint64_t *lba)
{
	sata_cmd_t *sata_cmd = &spx->txlt_sata_pkt->satapkt_cmd;

	*lba = 0;
	if (sata_cmd->satacmd_addr_type == ATA_ADDR_LBA48) {
		*lba = sata_cmd->satacmd_lba_high_msb;
		*lba = (*lba << 8) | sata_cmd->satacmd_lba_mid_msb;
		*lba = (*lba << 8) | sata_cmd->satacmd_lba_low_msb;
	} else if (sata_cmd->satacmd_addr_type == ATA_ADDR_LBA28) {
		*lba = sata_cmd->satacmd_device_reg & 0xf;
	}
	*lba = (*lba << 8) | sata_cmd->satacmd_lba_high_lsb;
	*lba = (*lba << 8) | sata_cmd->satacmd_lba_mid_lsb;
	*lba = (*lba << 8) | sata_cmd->satacmd_lba_low_lsb;
}

/*
 * This is fixed sense format - if LBA exceeds the info field size,
 * no valid info will be returned (valid bit in extended sense will
 * be set to 0).
 */
static struct scsi_extended_sense *
sata_arq_sense(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_arq_status *arqs;
	struct scsi_extended_sense *sense;

	/* Fill ARQ sense data */
	scsipkt->pkt_state |= STATE_ARQ_DONE;
	arqs = (struct scsi_arq_status *)scsipkt->pkt_scbp;
	*(uchar_t *)&arqs->sts_status = STATUS_CHECK;
	*(uchar_t *)&arqs->sts_rqpkt_status = STATUS_GOOD;
	arqs->sts_rqpkt_reason = CMD_CMPLT;
	arqs->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_XFERRED_DATA | STATE_SENT_CMD | STATE_GOT_STATUS;
	arqs->sts_rqpkt_resid = 0;
	sense = &arqs->sts_sensedata;
	bzero(sense, sizeof (struct scsi_extended_sense));
	sata_fixed_sense_data_preset(sense);
	return (sense);
}


/*
 * Emulated SATA Read/Write command completion for zero-length requests.
 * This request always succedes, so in synchronous mode it always returns
 * TRAN_ACCEPT, and in non-synchronous mode it may return TRAN_BUSY if the
 * callback cannot be scheduled.
 */
static int
sata_emul_rw_completion(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;

	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;
	scsipkt->pkt_reason = CMD_CMPLT;
	*scsipkt->pkt_scbp = STATUS_GOOD;
	if (!(spx->txlt_sata_pkt->satapkt_op_mode & SATA_OPMODE_SYNCH)) {
		/* scsi callback required - have to schedule it */
		if (taskq_dispatch(SATA_TXLT_TASKQ(spx),
		    (task_func_t *)scsipkt->pkt_comp,
		    (void *)scsipkt, TQ_SLEEP) == NULL)
			/* Scheduling the callback failed */
			return (TRAN_BUSY);
	}
	return (TRAN_ACCEPT);
}


/*
 * Translate completion status of SATA read/write commands into scsi response.
 * pkt completion_reason is checked to determine the completion status.
 * Do scsi callback if necessary.
 *
 * Note: this function may be called also for synchronously executed
 * commands.
 * This function may be used only if scsi_pkt is non-NULL.
 */
static void
sata_txlt_rw_completion(sata_pkt_t *sata_pkt)
{
	sata_pkt_txlate_t *spx =
	    (sata_pkt_txlate_t *)sata_pkt->satapkt_framework_private;
	sata_cmd_t *scmd = &sata_pkt->satapkt_cmd;
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense *sense;
	uint64_t lba;
	struct buf *bp;
	int rval;
	if (sata_pkt->satapkt_reason == SATA_PKT_COMPLETED) {
		/* Normal completion */
		scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
		scsipkt->pkt_reason = CMD_CMPLT;
		*scsipkt->pkt_scbp = STATUS_GOOD;
		if (spx->txlt_tmp_buf != NULL) {
			/* Temporary buffer was used */
			bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
			if (bp->b_flags & B_READ) {
				rval = ddi_dma_sync(
				    spx->txlt_buf_dma_handle, 0, 0,
				    DDI_DMA_SYNC_FORCPU);
				ASSERT(rval == DDI_SUCCESS);
				bcopy(spx->txlt_tmp_buf, bp->b_un.b_addr,
				    bp->b_bcount);
			}
		}
	} else {
		/*
		 * Something went wrong - analyze return
		 */
		scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;
		scsipkt->pkt_reason = CMD_INCOMPLETE;
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		ASSERT(sense != NULL);

		/*
		 * SATA_PKT_DEV_ERROR is the only case where we may be able to
		 * extract from device registers the failing LBA.
		 */
		if (sata_pkt->satapkt_reason == SATA_PKT_DEV_ERROR) {
			if ((scmd->satacmd_addr_type == ATA_ADDR_LBA48) &&
			    (scmd->satacmd_lba_mid_msb != 0 ||
			    scmd->satacmd_lba_high_msb != 0)) {
				/*
				 * We have problem reporting this cmd LBA
				 * in fixed sense data format, because of
				 * the size of the scsi LBA fields.
				 */
				sense->es_valid = 0;
			} else {
				sata_extract_error_lba(spx, &lba);
				sense->es_info_1 = (lba & 0xFF000000) >> 24;
				sense->es_info_2 = (lba & 0xFF0000) >> 16;
				sense->es_info_3 = (lba & 0xFF00) >> 8;
				sense->es_info_4 = lba & 0xFF;
			}
		} else {
			/* Invalid extended sense info */
			sense->es_valid = 0;
		}

		switch (sata_pkt->satapkt_reason) {
		case SATA_PKT_PORT_ERROR:
			/* We may want to handle DEV GONE state as well */
			/*
			 * We have no device data. Assume no data transfered.
			 */
			sense->es_key = KEY_HARDWARE_ERROR;
			break;

		case SATA_PKT_DEV_ERROR:
			if (sata_pkt->satapkt_cmd.satacmd_status_reg &
			    SATA_STATUS_ERR) {
				/*
				 * determine dev error reason from error
				 * reg content
				 */
				sata_decode_device_error(spx, sense);
				if (sense->es_key == KEY_MEDIUM_ERROR) {
					switch (scmd->satacmd_cmd_reg) {
					case SATAC_READ_DMA:
					case SATAC_READ_DMA_EXT:
					case SATAC_READ_DMA_QUEUED:
					case SATAC_READ_DMA_QUEUED_EXT:
					case SATAC_READ_FPDMA_QUEUED:
						/* Unrecovered read error */
						sense->es_add_code =
						SD_SCSI_ASC_UNREC_READ_ERROR;
						break;
					case SATAC_WRITE_DMA:
					case SATAC_WRITE_DMA_EXT:
					case SATAC_WRITE_DMA_QUEUED:
					case SATAC_WRITE_DMA_QUEUED_EXT:
					case SATAC_WRITE_FPDMA_QUEUED:
						/* Write error */
						sense->es_add_code =
						    SD_SCSI_ASC_WRITE_ERROR;
						break;
					default:
						/* Internal error */
						SATA_LOG_D((
						    spx->txlt_sata_hba_inst,
						    CE_WARN,
						    "sata_txlt_rw_completion :"
						    "internal error - invalid "
						    "command 0x%2x",
						    scmd->satacmd_cmd_reg));
						break;
					}
				}
				break;
			}
			/* No extended sense key - no info available */
			scsipkt->pkt_reason = CMD_INCOMPLETE;
			break;

		case SATA_PKT_TIMEOUT:
			/* scsipkt->pkt_reason = CMD_TIMEOUT; */
			scsipkt->pkt_reason = CMD_INCOMPLETE;
			/* No extended sense key ? */
			break;

		case SATA_PKT_ABORTED:
			scsipkt->pkt_reason = CMD_ABORTED;
			/* No extended sense key ? */
			break;

		case SATA_PKT_RESET:
			scsipkt->pkt_reason = CMD_RESET;
			break;

		default:
			SATA_LOG_D((spx->txlt_sata_hba_inst, CE_WARN,
			    "sata_txlt_rw_completion: "
			    "invalid packet completion reason"));
			scsipkt->pkt_reason = CMD_TRAN_ERR;
			break;
		}
	}
	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		(*scsipkt->pkt_comp)(scsipkt);
}


/*
 * Translate completion status of non-data commands (i.e. commands returning
 * no data).
 * pkt completion_reason is checked to determine the completion status.
 * Do scsi callback if necessary (FLAG_NOINTR == 0)
 *
 * Note: this function may be called also for synchronously executed
 * commands.
 * This function may be used only if scsi_pkt is non-NULL.
 */

static 	void
sata_txlt_nodata_cmd_completion(sata_pkt_t *sata_pkt)
{
	sata_pkt_txlate_t *spx =
	    (sata_pkt_txlate_t *)sata_pkt->satapkt_framework_private;
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense *sense;

	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;
	if (sata_pkt->satapkt_reason == SATA_PKT_COMPLETED) {
		/* Normal completion */
		scsipkt->pkt_reason = CMD_CMPLT;
		*scsipkt->pkt_scbp = STATUS_GOOD;
	} else {
		/* Something went wrong */
		scsipkt->pkt_reason = CMD_INCOMPLETE;
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		switch (sata_pkt->satapkt_reason) {
		case SATA_PKT_PORT_ERROR:
			/*
			 * We have no device data. Assume no data transfered.
			 */
			sense->es_key = KEY_HARDWARE_ERROR;
			break;

		case SATA_PKT_DEV_ERROR:
			if (sata_pkt->satapkt_cmd.satacmd_status_reg &
			    SATA_STATUS_ERR) {
				/*
				 * determine dev error reason from error
				 * reg content
				 */
				sata_decode_device_error(spx, sense);
				break;
			}
			/* No extended sense key - no info available */
			break;

		case SATA_PKT_TIMEOUT:
			/* scsipkt->pkt_reason = CMD_TIMEOUT; */
			scsipkt->pkt_reason = CMD_INCOMPLETE;
			/* No extended sense key ? */
			break;

		case SATA_PKT_ABORTED:
			scsipkt->pkt_reason = CMD_ABORTED;
			/* No extended sense key ? */
			break;

		case SATA_PKT_RESET:
			/* pkt aborted by an explicit reset from a host */
			scsipkt->pkt_reason = CMD_RESET;
			break;

		default:
			SATA_LOG_D((spx->txlt_sata_hba_inst, CE_WARN,
			    "sata_txlt_nodata_cmd_completion: "
			    "invalid packet completion reason %d",
			    sata_pkt->satapkt_reason));
			scsipkt->pkt_reason = CMD_TRAN_ERR;
			break;
		}

	}
	SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
	    "Scsi_pkt completion reason %x\n", scsipkt->pkt_reason);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL)
		/* scsi callback required */
		(*scsipkt->pkt_comp)(scsipkt);
}


/*
 * Build Mode sense R/W recovery page
 * NOT IMPLEMENTED
 */

static int
sata_build_msense_page_1(sata_drive_info_t *sdinfo, int pcntrl, uint8_t *buf)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(sdinfo))
	_NOTE(ARGUNUSED(pcntrl))
	_NOTE(ARGUNUSED(buf))
#endif
	return (0);
}

/*
 * Build Mode sense caching page  -  scsi-3 implementation.
 * Page length distinguishes previous format from scsi-3 format.
 * buf must have space for 0x12 bytes.
 * Only DRA (disable read ahead ) and WCE (write cache enable) are changeable.
 *
 */
static int
sata_build_msense_page_8(sata_drive_info_t *sdinfo, int pcntrl, uint8_t *buf)
{
	struct mode_cache_scsi3 *page = (struct mode_cache_scsi3 *)buf;
	sata_id_t *sata_id = &sdinfo->satadrv_id;

	/*
	 * Most of the fields are set to 0, being not supported and/or disabled
	 */
	bzero(buf, PAGELENGTH_DAD_MODE_CACHE_SCSI3);

	/* Saved paramters not supported */
	if (pcntrl == 3)
		return (0);
	if (pcntrl == 0 || pcntrl == 2) {
		/*
		 * For now treat current and default parameters as same
		 * That may have to change, if target driver will complain
		 */
		page->mode_page.code = MODEPAGE_CACHING;	/* PS = 0 */
		page->mode_page.length = PAGELENGTH_DAD_MODE_CACHE_SCSI3;

		if ((sata_id->ai_cmdset82 & SATA_LOOK_AHEAD) &&
		    !(sata_id->ai_features85 & SATA_LOOK_AHEAD)) {
			page->dra = 1;		/* Read Ahead disabled */
			page->rcd = 1;		/* Read Cache disabled */
		}
		if ((sata_id->ai_cmdset82 & SATA_WRITE_CACHE) &&
		    (sata_id->ai_features85 & SATA_WRITE_CACHE))
			page->wce = 1;		/* Write Cache enabled */
	} else {
		/* Changeable parameters */
		page->mode_page.code = MODEPAGE_CACHING;
		page->mode_page.length = PAGELENGTH_DAD_MODE_CACHE_SCSI3;
		if (sata_id->ai_cmdset82 & SATA_LOOK_AHEAD) {
			page->dra = 1;
			page->rcd = 1;
		}
		if (sata_id->ai_cmdset82 & SATA_WRITE_CACHE)
			page->wce = 1;
	}
	return (PAGELENGTH_DAD_MODE_CACHE_SCSI3 +
	    sizeof (struct mode_page));
}

/*
 * Build Mode sense exception cntrl page
 */
static int
sata_build_msense_page_1c(sata_drive_info_t *sdinfo, int pcntrl, uint8_t *buf)
{
	struct mode_info_excpt_page *page = (struct mode_info_excpt_page *)buf;
	sata_id_t *sata_id = &sdinfo->satadrv_id;

	/*
	 * Most of the fields are set to 0, being not supported and/or disabled
	 */
	bzero(buf, PAGELENGTH_INFO_EXCPT);

	page->mode_page.code = MODEPAGE_INFO_EXCPT;
	page->mode_page.length = PAGELENGTH_INFO_EXCPT;

	/* Indicate that this is page is saveable */
	page->mode_page.ps = 1;

	/*
	 * We will return the same data for default, current and saved page.
	 * The only changeable bit is dexcpt and that bit is required
	 * by the ATA specification to be preserved across power cycles.
	 */
	if (pcntrl != 1) {
		page->dexcpt = !(sata_id->ai_features85 & SATA_SMART_SUPPORTED);
		page->mrie = MRIE_ONLY_ON_REQUEST;
	}
	else
		page->dexcpt = 1;	/* Only changeable parameter */

	return (PAGELENGTH_INFO_EXCPT + sizeof (struct mode_info_excpt_page));
}


static int
sata_build_msense_page_30(sata_drive_info_t *sdinfo, int pcntrl, uint8_t *buf)
{
	struct mode_acoustic_management *page =
	    (struct mode_acoustic_management *)buf;
	sata_id_t *sata_id = &sdinfo->satadrv_id;

	/*
	 * Most of the fields are set to 0, being not supported and/or disabled
	 */
	bzero(buf, PAGELENGTH_DAD_MODE_ACOUSTIC_MANAGEMENT);

	switch (pcntrl) {
	case P_CNTRL_DEFAULT:
		/*  default paramters not supported */
		return (0);

	case P_CNTRL_CURRENT:
	case P_CNTRL_SAVED:
		/* Saved and current are supported and are identical */
		page->mode_page.code = MODEPAGE_ACOUSTIC_MANAG;
		page->mode_page.length =
		    PAGELENGTH_DAD_MODE_ACOUSTIC_MANAGEMENT;
		page->mode_page.ps = 1;

		/* Word 83 indicates if feature is supported */
		/* If feature is not supported */
		if (!(sata_id->ai_cmdset83 & SATA_ACOUSTIC_MGMT)) {
			page->acoustic_manag_enable =
			    ACOUSTIC_DISABLED;
		} else {
			page->acoustic_manag_enable =
			    ((sata_id->ai_features86 & SATA_ACOUSTIC_MGMT)
			    != 0);
			/* Word 94 inidicates the value */
#ifdef	_LITTLE_ENDIAN
			page->acoustic_manag_level =
			    (uchar_t)sata_id->ai_acoustic;
			page->vendor_recommended_value =
			    sata_id->ai_acoustic >> 8;
#else
			page->acoustic_manag_level =
			    sata_id->ai_acoustic >> 8;
			page->vendor_recommended_value =
			    (uchar_t)sata_id->ai_acoustic;
#endif
		}
		break;

	case P_CNTRL_CHANGEABLE:
		page->mode_page.code = MODEPAGE_ACOUSTIC_MANAG;
		page->mode_page.length =
		    PAGELENGTH_DAD_MODE_ACOUSTIC_MANAGEMENT;
		page->mode_page.ps = 1;

		/* Word 83 indicates if the feature is supported */
		if (sata_id->ai_cmdset83 & SATA_ACOUSTIC_MGMT) {
			page->acoustic_manag_enable =
			    ACOUSTIC_ENABLED;
			page->acoustic_manag_level = 0xff;
		}
		break;
	}
	return (PAGELENGTH_DAD_MODE_ACOUSTIC_MANAGEMENT +
	    sizeof (struct mode_page));
}


/*
 * Build Mode sense power condition page
 * NOT IMPLEMENTED.
 */
static int
sata_build_msense_page_1a(sata_drive_info_t *sdinfo, int pcntrl, uint8_t *buf)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(sdinfo))
	_NOTE(ARGUNUSED(pcntrl))
	_NOTE(ARGUNUSED(buf))
#endif
	return (0);
}


/*
 * Process mode select caching page 8 (scsi3 format only).
 * Read Ahead (same as read cache) and Write Cache may be turned on and off
 * if these features are supported by the device. If these features are not
 * supported, quietly ignore them.
 * This function fails only if the SET FEATURE command sent to
 * the device fails. The page format is not varified, assuming that the
 * target driver operates correctly - if parameters length is too short,
 * we just drop the page.
 * Two command may be sent if both Read Cache/Read Ahead and Write Cache
 * setting have to be changed.
 * SET FEATURE command is executed synchronously, i.e. we wait here until
 * it is completed, regardless of the scsi pkt directives.
 *
 * Note: Mode Select Caching page RCD and DRA bits are tied together, i.e.
 * changing DRA will change RCD.
 *
 * More than one SATA command may be executed to perform operations specified
 * by mode select pages. The first error terminates further execution.
 * Operations performed successully are not backed-up in such case.
 *
 * Return SATA_SUCCESS if operation succeeded, SATA_FAILURE otherwise.
 * If operation resulted in changing device setup, dmod flag should be set to
 * one (1). If parameters were not changed, dmod flag should be set to 0.
 * Upon return, if operation required sending command to the device, the rval
 * should be set to the value returned by sata_hba_start. If operation
 * did not require device access, rval should be set to TRAN_ACCEPT.
 * The pagelen should be set to the length of the page.
 *
 * This function has to be called with a port mutex held.
 *
 * Returns SATA_SUCCESS if operation was successful, SATA_FAILURE otherwise.
 */
int
sata_mode_select_page_8(sata_pkt_txlate_t *spx, struct mode_cache_scsi3 *page,
    int parmlen, int *pagelen, int *rval, int *dmod)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_drive_info_t *sdinfo;
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	sata_id_t *sata_id;
	struct scsi_extended_sense *sense;
	int wce, dra;	/* Current settings */

	sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);
	sata_id = &sdinfo->satadrv_id;
	*dmod = 0;

	/* Verify parameters length. If too short, drop it */
	if (PAGELENGTH_DAD_MODE_CACHE_SCSI3 +
	    sizeof (struct mode_page) < parmlen) {
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_PARAMS_LIST;
		*pagelen = parmlen;
		*rval = TRAN_ACCEPT;
		return (SATA_FAILURE);
	}

	*pagelen = PAGELENGTH_DAD_MODE_CACHE_SCSI3 + sizeof (struct mode_page);

	/*
	 * We can manipulate only write cache and read ahead
	 * (read cache) setting.
	 */
	if (!(sata_id->ai_cmdset82 & SATA_LOOK_AHEAD) &&
	    !(sata_id->ai_cmdset82 & SATA_WRITE_CACHE)) {
		/*
		 * None of the features is supported - ignore
		 */
		*rval = TRAN_ACCEPT;
		return (SATA_SUCCESS);
	}

	/* Current setting of Read Ahead (and Read Cache) */
	if (sata_id->ai_features85 & SATA_LOOK_AHEAD)
		dra = 0;	/* 0 == not disabled */
	else
		dra = 1;
	/* Current setting of Write Cache */
	if (sata_id->ai_features85 & SATA_WRITE_CACHE)
		wce = 1;
	else
		wce = 0;

	if (page->dra == dra && page->wce == wce && page->rcd == dra) {
		/* nothing to do */
		*rval = TRAN_ACCEPT;
		return (SATA_SUCCESS);
	}
	/*
	 * Need to flip some setting
	 * Set-up Internal SET FEATURES command(s)
	 */
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_NODATA_XFER;
	scmd->satacmd_addr_type = 0;
	scmd->satacmd_device_reg = 0;
	scmd->satacmd_status_reg = 0;
	scmd->satacmd_error_reg = 0;
	scmd->satacmd_cmd_reg = SATAC_SET_FEATURES;
	if (page->dra != dra || page->rcd != dra) {
		/* Need to flip read ahead setting */
		if (dra == 0)
			/* Disable read ahead / read cache */
			scmd->satacmd_features_reg =
			    SATAC_SF_DISABLE_READ_AHEAD;
		else
			/* Enable read ahead  / read cache */
			scmd->satacmd_features_reg =
			    SATAC_SF_ENABLE_READ_AHEAD;

		/* Transfer command to HBA */
		if (sata_hba_start(spx, rval) != 0)
			/*
			 * Pkt not accepted for execution.
			 */
			return (SATA_FAILURE);

		*dmod = 1;

		/* Now process return */
		if (spx->txlt_sata_pkt->satapkt_reason !=
		    SATA_PKT_COMPLETED) {
			goto failure;	/* Terminate */
		}
	}

	/* Note that the packet is not removed, so it could be re-used */
	if (page->wce != wce) {
		/* Need to flip Write Cache setting */
		if (page->wce == 1)
			/* Enable write cache */
			scmd->satacmd_features_reg =
			    SATAC_SF_ENABLE_WRITE_CACHE;
		else
			/* Disable write cache */
			scmd->satacmd_features_reg =
			    SATAC_SF_DISABLE_WRITE_CACHE;

		/* Transfer command to HBA */
		if (sata_hba_start(spx, rval) != 0)
			/*
			 * Pkt not accepted for execution.
			 */
			return (SATA_FAILURE);

		*dmod = 1;

		/* Now process return */
		if (spx->txlt_sata_pkt->satapkt_reason !=
		    SATA_PKT_COMPLETED) {
			goto failure;
		}
	}
	return (SATA_SUCCESS);

failure:
	sata_xlate_errors(spx);

	return (SATA_FAILURE);
}

/*
 * Process mode select informational exceptions control page 0x1c
 *
 * The only changeable bit is dexcpt (disable exceptions).
 * MRIE (method of reporting informational exceptions) must be
 * "only on request".
 *
 * Return SATA_SUCCESS if operation succeeded, SATA_FAILURE otherwise.
 * If operation resulted in changing device setup, dmod flag should be set to
 * one (1). If parameters were not changed, dmod flag should be set to 0.
 * Upon return, if operation required sending command to the device, the rval
 * should be set to the value returned by sata_hba_start. If operation
 * did not require device access, rval should be set to TRAN_ACCEPT.
 * The pagelen should be set to the length of the page.
 *
 * This function has to be called with a port mutex held.
 *
 * Returns SATA_SUCCESS if operation was successful, SATA_FAILURE otherwise.
 */
static	int
sata_mode_select_page_1c(
	sata_pkt_txlate_t *spx,
	struct mode_info_excpt_page *page,
	int parmlen,
	int *pagelen,
	int *rval,
	int *dmod)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	sata_drive_info_t *sdinfo;
	sata_id_t *sata_id;
	struct scsi_extended_sense *sense;

	sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);
	sata_id = &sdinfo->satadrv_id;

	*dmod = 0;

	/* Verify parameters length. If too short, drop it */
	if (((PAGELENGTH_INFO_EXCPT + sizeof (struct mode_page)) < parmlen) ||
	    page->perf || page->test || (page->mrie != MRIE_ONLY_ON_REQUEST)) {
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_PARAMS_LIST;
		*pagelen = parmlen;
		*rval = TRAN_ACCEPT;
		return (SATA_FAILURE);
	}

	*pagelen = PAGELENGTH_INFO_EXCPT + sizeof (struct mode_page);

	if (! (sata_id->ai_cmdset82 & SATA_SMART_SUPPORTED)) {
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_CDB;
		*pagelen = parmlen;
		*rval = TRAN_ACCEPT;
		return (SATA_FAILURE);
	}

	/* If already in the state requested, we are done */
	if (page->dexcpt == ! (sata_id->ai_features85 & SATA_SMART_ENABLED)) {
		/* nothing to do */
		*rval = TRAN_ACCEPT;
		return (SATA_SUCCESS);
	}

	scmd->satacmd_flags.sata_data_direction = SATA_DIR_NODATA_XFER;

	/* Build SMART_ENABLE or SMART_DISABLE command */
	scmd->satacmd_addr_type = 0;		/* N/A */
	scmd->satacmd_lba_mid_lsb = SMART_MAGIC_VAL_1;
	scmd->satacmd_lba_high_lsb = SMART_MAGIC_VAL_2;
	scmd->satacmd_features_reg = page->dexcpt ?
	    SATA_SMART_DISABLE_OPS : SATA_SMART_ENABLE_OPS;
	scmd->satacmd_device_reg = 0;		/* Always device 0 */
	scmd->satacmd_cmd_reg = SATAC_SMART;

	/* Transfer command to HBA */
	if (sata_hba_start(spx, rval) != 0)
		/*
		 * Pkt not accepted for execution.
		 */
		return (SATA_FAILURE);

	*dmod = 1;	/* At least may have been modified */

	/* Now process return */
	if (spx->txlt_sata_pkt->satapkt_reason == SATA_PKT_COMPLETED)
		return (SATA_SUCCESS);

	/* Packet did not complete successfully */
	sata_xlate_errors(spx);

	return (SATA_FAILURE);
}

int
sata_mode_select_page_30(sata_pkt_txlate_t *spx, struct
    mode_acoustic_management *page, int parmlen, int *pagelen,
    int *rval, int *dmod)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_drive_info_t *sdinfo;
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	sata_id_t *sata_id;
	struct scsi_extended_sense *sense;

	sdinfo = sata_get_device_info(spx->txlt_sata_hba_inst,
	    &spx->txlt_sata_pkt->satapkt_device);
	sata_id = &sdinfo->satadrv_id;
	*dmod = 0;

	/* If parmlen is too short or the feature is not supported, drop it */
	if (((PAGELENGTH_DAD_MODE_ACOUSTIC_MANAGEMENT +
	    sizeof (struct mode_page)) < parmlen) ||
	    (! (sata_id->ai_cmdset83 & SATA_ACOUSTIC_MGMT))) {
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);
		sense->es_key = KEY_ILLEGAL_REQUEST;
		sense->es_add_code = SD_SCSI_ASC_INVALID_FIELD_IN_PARAMS_LIST;
		*pagelen = parmlen;
		*rval = TRAN_ACCEPT;
		return (SATA_FAILURE);
	}

	*pagelen = PAGELENGTH_DAD_MODE_ACOUSTIC_MANAGEMENT +
	    sizeof (struct mode_page);

	/*
	 * We can enable and disable acoustice management and
	 * set the acoustic management level.
	 */

	/*
	 * Set-up Internal SET FEATURES command(s)
	 */
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_NODATA_XFER;
	scmd->satacmd_addr_type = 0;
	scmd->satacmd_device_reg = 0;
	scmd->satacmd_status_reg = 0;
	scmd->satacmd_error_reg = 0;
	scmd->satacmd_cmd_reg = SATAC_SET_FEATURES;
	if (page->acoustic_manag_enable) {
		scmd->satacmd_features_reg = SATAC_SF_ENABLE_ACOUSTIC;
		scmd->satacmd_sec_count_lsb = page->acoustic_manag_level;
	} else {	/* disabling acoustic management */
		scmd->satacmd_features_reg = SATAC_SF_DISABLE_ACOUSTIC;
	}

	/* Transfer command to HBA */
	if (sata_hba_start(spx, rval) != 0)
		/*
		 * Pkt not accepted for execution.
		 */
		return (SATA_FAILURE);

	/* Now process return */
	if (spx->txlt_sata_pkt->satapkt_reason != SATA_PKT_COMPLETED) {
		sata_xlate_errors(spx);
		return (SATA_FAILURE);
	}

	*dmod = 1;

	return (SATA_SUCCESS);
}




/*
 * sata_build_lsense_page0() is used to create the
 * SCSI LOG SENSE page 0 (supported log pages)
 *
 * Currently supported pages are 0, 0x10, 0x2f and 0x30
 * (supported log pages, self-test results, informational exceptions
 *  and Sun vendor specific ATA SMART data).
 *
 * Takes a sata_drive_info t * and the address of a buffer
 * in which to create the page information.
 *
 * Returns the number of bytes valid in the buffer.
 */
static	int
sata_build_lsense_page_0(sata_drive_info_t *sdinfo, uint8_t *buf)
{
	struct log_parameter *lpp = (struct log_parameter *)buf;
	uint8_t *page_ptr = (uint8_t *)lpp->param_values;
	int num_pages_supported = 1; /* Always have GET_SUPPORTED_LOG_PAGES */
	sata_id_t *sata_id = &sdinfo->satadrv_id;

	lpp->param_code[0] = 0;
	lpp->param_code[1] = 0;
	lpp->param_ctrl_flags = LOG_CTRL_LP | LOG_CTRL_LBIN;
	*page_ptr++ = PAGE_CODE_GET_SUPPORTED_LOG_PAGES;

	if (sata_id->ai_cmdset82 & SATA_SMART_SUPPORTED) {
		if (sata_id->ai_cmdset84 & SATA_SMART_SELF_TEST_SUPPORTED) {
			*page_ptr++ = PAGE_CODE_SELF_TEST_RESULTS;
			++num_pages_supported;
		}
		*page_ptr++ = PAGE_CODE_INFORMATION_EXCEPTIONS;
		++num_pages_supported;
		*page_ptr++ = PAGE_CODE_SMART_READ_DATA;
		++num_pages_supported;
	}

	lpp->param_len = num_pages_supported;

	return ((&lpp->param_values[0] - (uint8_t *)lpp) +
	    num_pages_supported);
}

/*
 * sata_build_lsense_page_10() is used to create the
 * SCSI LOG SENSE page 0x10 (self-test results)
 *
 * Takes a sata_drive_info t * and the address of a buffer
 * in which to create the page information as well as a sata_hba_inst_t *.
 *
 * Returns the number of bytes valid in the buffer.
 */
static	int
sata_build_lsense_page_10(
	sata_drive_info_t *sdinfo,
	uint8_t *buf,
	sata_hba_inst_t *sata_hba_inst)
{
	struct log_parameter *lpp = (struct log_parameter *)buf;
	int rval;

	if (sdinfo->satadrv_features_support & SATA_DEV_F_LBA48) {
		struct smart_ext_selftest_log *ext_selftest_log;

		ext_selftest_log = kmem_zalloc(
		    sizeof (struct smart_ext_selftest_log), KM_SLEEP);

		rval = sata_ext_smart_selftest_read_log(sata_hba_inst, sdinfo,
		    ext_selftest_log, 0);
		if (rval == 0) {
			int index, start_index;
			struct smart_ext_selftest_log_entry *entry;
			static const struct smart_ext_selftest_log_entry empty =
			    {0};
			uint16_t block_num;
			int count;
			boolean_t only_one_block = B_FALSE;

			index = ext_selftest_log->
			    smart_ext_selftest_log_index[0];
			index |= ext_selftest_log->
			    smart_ext_selftest_log_index[1] << 8;
			if (index == 0)
				goto out;

			--index;	/* Correct for 0 origin */
			start_index = index;	/* remember where we started */
			block_num = index / ENTRIES_PER_EXT_SELFTEST_LOG_BLK;
			if (block_num != 0) {
				rval = sata_ext_smart_selftest_read_log(
				    sata_hba_inst, sdinfo, ext_selftest_log,
				    block_num);
				if (rval != 0)
					goto out;
			}
			index %= ENTRIES_PER_EXT_SELFTEST_LOG_BLK;
			entry =
			    &ext_selftest_log->
			    smart_ext_selftest_log_entries[index];

			for (count = 1;
			    count <= SCSI_ENTRIES_IN_LOG_SENSE_SELFTEST_RESULTS;
			    ++count) {
				uint8_t status;
				uint8_t code;
				uint8_t sense_key;
				uint8_t add_sense_code;
				uint8_t add_sense_code_qual;

				/* If this is an unused entry, we are done */
				if (bcmp(entry, &empty, sizeof (empty)) == 0) {
					/* Broken firmware on some disks */
					if (index + 1 ==
					    ENTRIES_PER_EXT_SELFTEST_LOG_BLK) {
						--entry;
						--index;
						if (bcmp(entry, &empty,
						    sizeof (empty)) == 0)
							goto out;
					} else
						goto out;
				}

				if (only_one_block &&
				    start_index == index)
					goto out;

				lpp->param_code[0] = 0;
				lpp->param_code[1] = count;
				lpp->param_ctrl_flags =
				    LOG_CTRL_LP | LOG_CTRL_LBIN;
				lpp->param_len =
				    SCSI_LOG_SENSE_SELFTEST_PARAM_LEN;

				status = entry->smart_ext_selftest_log_status;
				status >>= 4;
				switch (status) {
				case 0:
				default:
					sense_key = KEY_NO_SENSE;
					add_sense_code =
					    SD_SCSI_ASC_NO_ADD_SENSE;
					add_sense_code_qual = 0;
					break;
				case 1:
					sense_key = KEY_ABORTED_COMMAND;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_81;
					break;
				case 2:
					sense_key = KEY_ABORTED_COMMAND;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_82;
					break;
				case 3:
					sense_key = KEY_ABORTED_COMMAND;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_83;
					break;
				case 4:
					sense_key = KEY_HARDWARE_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_84;
					break;
				case 5:
					sense_key = KEY_HARDWARE_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_85;
					break;
				case 6:
					sense_key = KEY_HARDWARE_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_86;
					break;
				case 7:
					sense_key = KEY_MEDIUM_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_87;
					break;
				case 8:
					sense_key = KEY_HARDWARE_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_88;
					break;
				}
				code = 0;	/* unspecified */
				status |= (code << 4);
				lpp->param_values[0] = status;
				lpp->param_values[1] = 0; /* unspecified */
				lpp->param_values[2] = entry->
				    smart_ext_selftest_log_timestamp[1];
				lpp->param_values[3] = entry->
				    smart_ext_selftest_log_timestamp[0];
				if (status != 0) {
					lpp->param_values[4] = 0;
					lpp->param_values[5] = 0;
					lpp->param_values[6] = entry->
					    smart_ext_selftest_log_failing_lba
					    [5];
					lpp->param_values[7] = entry->
					    smart_ext_selftest_log_failing_lba
					    [4];
					lpp->param_values[8] = entry->
					    smart_ext_selftest_log_failing_lba
					    [3];
					lpp->param_values[9] = entry->
					    smart_ext_selftest_log_failing_lba
					    [2];
					lpp->param_values[10] = entry->
					    smart_ext_selftest_log_failing_lba
					    [1];
					lpp->param_values[11] = entry->
					    smart_ext_selftest_log_failing_lba
					    [0];
				} else {	/* No bad block address */
					lpp->param_values[4] = 0xff;
					lpp->param_values[5] = 0xff;
					lpp->param_values[6] = 0xff;
					lpp->param_values[7] = 0xff;
					lpp->param_values[8] = 0xff;
					lpp->param_values[9] = 0xff;
					lpp->param_values[10] = 0xff;
					lpp->param_values[11] = 0xff;
				}

				lpp->param_values[12] = sense_key;
				lpp->param_values[13] = add_sense_code;
				lpp->param_values[14] = add_sense_code_qual;
				lpp->param_values[15] = 0; /* undefined */

				lpp = (struct log_parameter *)
				    (((uint8_t *)lpp) +
				    SCSI_LOG_PARAM_HDR_LEN +
				    SCSI_LOG_SENSE_SELFTEST_PARAM_LEN);

				--index;	/* Back up to previous entry */
				if (index < 0) {
					if (block_num > 0) {
						--block_num;
					} else {
						struct read_log_ext_directory
						    logdir;

						rval =
						    sata_read_log_ext_directory(
						    sata_hba_inst, sdinfo,
						    &logdir);
						if (rval == -1)
							goto out;
						if ((logdir.read_log_ext_vers
						    [0] == 0) &&
						    (logdir.read_log_ext_vers
						    [1] == 0))
							goto out;
						block_num =
						    logdir.read_log_ext_nblks
						    [EXT_SMART_SELFTEST_LOG_PAGE
						    - 1][0];
						block_num |= logdir.
						    read_log_ext_nblks
						    [EXT_SMART_SELFTEST_LOG_PAGE
						    - 1][1] << 8;
						--block_num;
						only_one_block =
						    (block_num == 0);
					}
					rval = sata_ext_smart_selftest_read_log(
					    sata_hba_inst, sdinfo,
					    ext_selftest_log, block_num);
					if (rval != 0)
						goto out;

					index =
					    ENTRIES_PER_EXT_SELFTEST_LOG_BLK -
					    1;
				}
				index %= ENTRIES_PER_EXT_SELFTEST_LOG_BLK;
				entry = &ext_selftest_log->
				    smart_ext_selftest_log_entries[index];
			}
		}
out:
		kmem_free(ext_selftest_log,
		    sizeof (struct smart_ext_selftest_log));
	} else {
		struct smart_selftest_log *selftest_log;

		selftest_log = kmem_zalloc(sizeof (struct smart_selftest_log),
		    KM_SLEEP);

		rval = sata_smart_selftest_log(sata_hba_inst, sdinfo,
		    selftest_log);

		if (rval == 0) {
			int index;
			int count;
			struct smart_selftest_log_entry *entry;
			static const struct smart_selftest_log_entry empty =
			    { 0 };

			index = selftest_log->smart_selftest_log_index;
			if (index == 0)
				goto done;
			--index;	/* Correct for 0 origin */
			entry = &selftest_log->
			    smart_selftest_log_entries[index];
			for (count = 1;
			    count <= SCSI_ENTRIES_IN_LOG_SENSE_SELFTEST_RESULTS;
			    ++count) {
				uint8_t status;
				uint8_t code;
				uint8_t sense_key;
				uint8_t add_sense_code;
				uint8_t add_sense_code_qual;

				if (bcmp(entry, &empty, sizeof (empty)) == 0)
					goto done;

				lpp->param_code[0] = 0;
				lpp->param_code[1] = count;
				lpp->param_ctrl_flags =
				    LOG_CTRL_LP | LOG_CTRL_LBIN;
				lpp->param_len =
				    SCSI_LOG_SENSE_SELFTEST_PARAM_LEN;

				status = entry->smart_selftest_log_status;
				status >>= 4;
				switch (status) {
				case 0:
				default:
					sense_key = KEY_NO_SENSE;
					add_sense_code =
					    SD_SCSI_ASC_NO_ADD_SENSE;
					break;
				case 1:
					sense_key = KEY_ABORTED_COMMAND;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_81;
					break;
				case 2:
					sense_key = KEY_ABORTED_COMMAND;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_82;
					break;
				case 3:
					sense_key = KEY_ABORTED_COMMAND;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_83;
					break;
				case 4:
					sense_key = KEY_HARDWARE_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_84;
					break;
				case 5:
					sense_key = KEY_HARDWARE_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_85;
					break;
				case 6:
					sense_key = KEY_HARDWARE_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_86;
					break;
				case 7:
					sense_key = KEY_MEDIUM_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_87;
					break;
				case 8:
					sense_key = KEY_HARDWARE_ERROR;
					add_sense_code =
					    DIAGNOSTIC_FAILURE_ON_COMPONENT;
					add_sense_code_qual = SCSI_COMPONENT_88;
					break;
				}
				code = 0;	/* unspecified */
				status |= (code << 4);
				lpp->param_values[0] = status;
				lpp->param_values[1] = 0; /* unspecified */
				lpp->param_values[2] = entry->
				    smart_selftest_log_timestamp[1];
				lpp->param_values[3] = entry->
				    smart_selftest_log_timestamp[0];
				if (status != 0) {
					lpp->param_values[4] = 0;
					lpp->param_values[5] = 0;
					lpp->param_values[6] = 0;
					lpp->param_values[7] = 0;
					lpp->param_values[8] = entry->
					    smart_selftest_log_failing_lba[3];
					lpp->param_values[9] = entry->
					    smart_selftest_log_failing_lba[2];
					lpp->param_values[10] = entry->
					    smart_selftest_log_failing_lba[1];
					lpp->param_values[11] = entry->
					    smart_selftest_log_failing_lba[0];
				} else {	/* No block address */
					lpp->param_values[4] = 0xff;
					lpp->param_values[5] = 0xff;
					lpp->param_values[6] = 0xff;
					lpp->param_values[7] = 0xff;
					lpp->param_values[8] = 0xff;
					lpp->param_values[9] = 0xff;
					lpp->param_values[10] = 0xff;
					lpp->param_values[11] = 0xff;
				}
				lpp->param_values[12] = sense_key;
				lpp->param_values[13] = add_sense_code;
				lpp->param_values[14] = add_sense_code_qual;
				lpp->param_values[15] = 0; /* undefined */

				lpp = (struct log_parameter *)
				    (((uint8_t *)lpp) +
				    SCSI_LOG_PARAM_HDR_LEN +
				    SCSI_LOG_SENSE_SELFTEST_PARAM_LEN);
				--index;	/* back up to previous entry */
				if (index < 0) {
					index =
					    NUM_SMART_SELFTEST_LOG_ENTRIES - 1;
				}
				entry = &selftest_log->
				    smart_selftest_log_entries[index];
			}
		}
done:
		kmem_free(selftest_log, sizeof (struct smart_selftest_log));
	}

	return ((SCSI_LOG_PARAM_HDR_LEN + SCSI_LOG_SENSE_SELFTEST_PARAM_LEN) *
	    SCSI_ENTRIES_IN_LOG_SENSE_SELFTEST_RESULTS);
}

/*
 * sata_build_lsense_page_2f() is used to create the
 * SCSI LOG SENSE page 0x10 (informational exceptions)
 *
 * Takes a sata_drive_info t * and the address of a buffer
 * in which to create the page information as well as a sata_hba_inst_t *.
 *
 * Returns the number of bytes valid in the buffer.
 */
static	int
sata_build_lsense_page_2f(
	sata_drive_info_t *sdinfo,
	uint8_t *buf,
	sata_hba_inst_t *sata_hba_inst)
{
	struct log_parameter *lpp = (struct log_parameter *)buf;
	int rval;
	uint8_t *smart_data;
	uint8_t temp;
	sata_id_t *sata_id;
#define	SMART_NO_TEMP	0xff

	lpp->param_code[0] = 0;
	lpp->param_code[1] = 0;
	lpp->param_ctrl_flags = LOG_CTRL_LP | LOG_CTRL_LBIN;

	/* Now get the SMART status w.r.t. threshold exceeded */
	rval = sata_fetch_smart_return_status(sata_hba_inst, sdinfo);
	switch (rval) {
	case 1:
		lpp->param_values[0] = SCSI_PREDICTED_FAILURE;
		lpp->param_values[1] = SCSI_GENERAL_HD_FAILURE;
		break;
	case 0:
	case -1:	/* failed to get data */
		lpp->param_values[0] = 0;	/* No failure predicted */
		lpp->param_values[1] = 0;
		break;
#if defined(SATA_DEBUG)
	default:
		cmn_err(CE_PANIC, "sata_build_lsense_page_2f bad return value");
		/* NOTREACHED */
#endif
	}

	sata_id = &sdinfo->satadrv_id;
	if (! (sata_id->ai_sctsupport & SATA_SCT_CMD_TRANS_SUP))
		temp = SMART_NO_TEMP;
	else {
		/* Now get the temperature */
		smart_data = kmem_zalloc(512, KM_SLEEP);
		rval = sata_smart_read_log(sata_hba_inst, sdinfo, smart_data,
		    SCT_STATUS_LOG_PAGE, 1);
		if (rval == -1)
			temp = SMART_NO_TEMP;
		else {
			temp = smart_data[200];
			if (temp & 0x80) {
				if (temp & 0x7f)
					temp = 0;
				else
					temp = SMART_NO_TEMP;
			}
		}
		kmem_free(smart_data, 512);
	}

	lpp->param_values[2] = temp;	/* most recent temperature */
	lpp->param_values[3] = 0;	/* required vendor specific byte */

	lpp->param_len = SCSI_INFO_EXCEPTIONS_PARAM_LEN;


	return (SCSI_INFO_EXCEPTIONS_PARAM_LEN + SCSI_LOG_PARAM_HDR_LEN);
}

/*
 * sata_build_lsense_page_30() is used to create the
 * SCSI LOG SENSE page 0x30 (Sun's vendor specific page for ATA SMART data).
 *
 * Takes a sata_drive_info t * and the address of a buffer
 * in which to create the page information as well as a sata_hba_inst_t *.
 *
 * Returns the number of bytes valid in the buffer.
 */
static int
sata_build_lsense_page_30(
	sata_drive_info_t *sdinfo,
	uint8_t *buf,
	sata_hba_inst_t *sata_hba_inst)
{
	struct smart_data *smart_data = (struct smart_data *)buf;
	int rval;

	/* Now do the SMART READ DATA */
	rval = sata_fetch_smart_data(sata_hba_inst, sdinfo, smart_data);
	if (rval == -1)
		return (0);

	return (sizeof (struct smart_data));
}

/* ************************** ATAPI-SPECIFIC FUNCTIONS ********************** */

/*
 * Start command for ATAPI device.
 * This function processes scsi_pkt requests.
 * Only CD/DVD devices are supported.
 * Most commands are packet without any translation into Packet Command.
 * Some may be trapped and executed as SATA commands (not clear which one).
 *
 * Returns TRAN_ACCEPT if command is accepted for execution (or completed
 * execution).
 * Returns other TRAN_XXXX codes if command is not accepted or completed
 * (see return values for sata_hba_start()).
 *
 * Note:
 * Inquiry cdb format differs between transport version 2 and 3.
 * However, the transport version 3 devices that were checked did not adhere
 * to the specification (ignored MSB of the allocation length). Therefore,
 * the transport version is not checked, but Inquiry allocation length is
 * truncated to 255 bytes if the original allocation length set-up by the
 * target driver is greater than 255 bytes.
 */
static int
sata_txlt_atapi(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	sata_cmd_t *scmd = &spx->txlt_sata_pkt->satapkt_cmd;
	struct buf *bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	sata_hba_inst_t *sata_hba = SATA_TXLT_HBA_INST(spx);
	sata_drive_info_t *sdinfo = sata_get_device_info(sata_hba,
	    &spx->txlt_sata_pkt->satapkt_device);
	int cport = SATA_TXLT_CPORT(spx);
	int cdblen;
	int rval;
	int synch;
	union scsi_cdb *cdbp = (union scsi_cdb *)scsipkt->pkt_cdbp;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (((rval = sata_txlt_generic_pkt_info(spx)) != TRAN_ACCEPT) ||
	    (spx->txlt_scsi_pkt->pkt_reason == CMD_DEV_GONE)) {
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (rval);
	}

	/*
	 * ATAPI device executes some ATA commands in addition to MMC command
	 * set. These ATA commands may be executed by the regular SATA
	 * translation functions. None needs to be captured now.
	 * Other commands belong to MMC command set and are delivered
	 * to ATAPI device via Packet Command.
	 */

	/* Check the size of cdb */
	cdblen = scsi_cdb_size[GETGROUP(cdbp)];
	if (cdblen > sdinfo->satadrv_atapi_cdb_len) {
		sata_log(NULL, CE_WARN,
		    "sata: invalid ATAPI cdb length %d",
		    scsipkt->pkt_cdblen);
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		return (TRAN_BADPKT);
	}

	SATAATAPITRACE(spx, cdblen);

	/*
	 * For non-read/write commands we need to
	 * map buffer
	 */
	switch ((uint_t)scsipkt->pkt_cdbp[0]) {
	case SCMD_READ:
	case SCMD_READ_G1:
	case SCMD_READ_G5:
	case SCMD_READ_G4:
	case SCMD_WRITE:
	case SCMD_WRITE_G1:
	case SCMD_WRITE_G5:
	case SCMD_WRITE_G4:
		break;
	default:
		if (bp != NULL) {
			if (bp->b_flags & (B_PHYS | B_PAGEIO))
				bp_mapin(bp);
		}
		break;
	}
	/*
	 * scmd->satacmd_flags.sata_data_direction default -
	 * SATA_DIR_NODATA_XFER - is set by
	 * sata_txlt_generic_pkt_info().
	 */
	if (scmd->satacmd_bp) {
		if (scmd->satacmd_bp->b_flags & B_READ) {
			scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;
		} else {
			scmd->satacmd_flags.sata_data_direction =
			    SATA_DIR_WRITE;
		}
	}

	/*
	 * Set up ATAPI packet command.
	 */

	sata_atapi_packet_cmd_setup(scmd, sdinfo);

	/* Copy cdb into sata_cmd */
	scmd->satacmd_acdb_len = sdinfo->satadrv_atapi_cdb_len;
	bzero(scmd->satacmd_acdb, SATA_ATAPI_MAX_CDB_LEN);
	bcopy(cdbp, scmd->satacmd_acdb, cdblen);

	/* See note in the command header */
	if (scmd->satacmd_acdb[0] == SCMD_INQUIRY) {
		if (scmd->satacmd_acdb[3] != 0)
			scmd->satacmd_acdb[4] = 255;
	}

#ifdef SATA_DEBUG
	if (sata_debug_flags & SATA_DBG_ATAPI) {
		uint8_t *p = scmd->satacmd_acdb;
		char buf[3 * SATA_ATAPI_MAX_CDB_LEN];

		(void) snprintf(buf, SATA_ATAPI_MAX_CDB_LEN,
		    "%02x %02x %02x %02x %02x %02x %02x %02x "
		    "%2x %02x %02x %02x %02x %02x %02x %02x",
		    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		    p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		buf[(3 * SATA_ATAPI_MAX_CDB_LEN) - 1] = '\0';
		cmn_err(CE_NOTE, "ATAPI cdb: %s\n", buf);
	}
#endif

	/*
	 * Preset request sense data to NO SENSE.
	 * If there is no way to get error information via Request Sense,
	 * the packet request sense data would not have to be modified by HBA,
	 * but it could be returned as is.
	 */
	bzero(scmd->satacmd_rqsense, SATA_ATAPI_RQSENSE_LEN);
	sata_fixed_sense_data_preset(
	    (struct scsi_extended_sense *)scmd->satacmd_rqsense);

	if (!(spx->txlt_sata_pkt->satapkt_op_mode & SATA_OPMODE_SYNCH)) {
		/* Need callback function */
		spx->txlt_sata_pkt->satapkt_comp = sata_txlt_atapi_completion;
		synch = FALSE;
	} else
		synch = TRUE;

	/* Transfer command to HBA */
	if (sata_hba_start(spx, &rval) != 0) {
		/* Pkt not accepted for execution */
		mutex_exit(&SATA_CPORT_MUTEX(sata_hba, cport));
		return (rval);
	}
	mutex_exit(&SATA_CPORT_MUTEX(sata_hba, cport));
	/*
	 * If execution is non-synchronous,
	 * a callback function will handle potential errors, translate
	 * the response and will do a callback to a target driver.
	 * If it was synchronous, use the same framework callback to check
	 * an execution status.
	 */
	if (synch) {
		SATADBG1(SATA_DBG_SCSI_IF, spx->txlt_sata_hba_inst,
		    "synchronous execution status %x\n",
		    spx->txlt_sata_pkt->satapkt_reason);
		sata_txlt_atapi_completion(spx->txlt_sata_pkt);
	}
	return (TRAN_ACCEPT);
}


/*
 * ATAPI Packet command completion.
 *
 * Failure of the command passed via Packet command are considered device
 * error. SATA HBA driver would have to retrieve error data (via Request
 * Sense command delivered via error retrieval sata packet) and copy it
 * to satacmd_rqsense array. From there, it is moved into scsi pkt sense data.
 */
static void
sata_txlt_atapi_completion(sata_pkt_t *sata_pkt)
{
	sata_pkt_txlate_t *spx =
	    (sata_pkt_txlate_t *)sata_pkt->satapkt_framework_private;
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense *sense;
	struct buf *bp;
	int rval;

#ifdef SATA_DEBUG
	uint8_t *rqsp = sata_pkt->satapkt_cmd.satacmd_rqsense;
#endif

	scsipkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;

	if (sata_pkt->satapkt_reason == SATA_PKT_COMPLETED) {
		/* Normal completion */
		if (sata_pkt->satapkt_cmd.satacmd_bp != NULL)
			scsipkt->pkt_state |= STATE_XFERRED_DATA;
		scsipkt->pkt_reason = CMD_CMPLT;
		*scsipkt->pkt_scbp = STATUS_GOOD;
		if (spx->txlt_tmp_buf != NULL) {
			/* Temporary buffer was used */
			bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
			if (bp->b_flags & B_READ) {
				rval = ddi_dma_sync(
				    spx->txlt_buf_dma_handle, 0, 0,
				    DDI_DMA_SYNC_FORCPU);
				ASSERT(rval == DDI_SUCCESS);
				bcopy(spx->txlt_tmp_buf, bp->b_un.b_addr,
				    bp->b_bcount);
			}
		}
	} else {
		/*
		 * Something went wrong - analyze return
		 */
		*scsipkt->pkt_scbp = STATUS_CHECK;
		sense = sata_arq_sense(spx);

		if (sata_pkt->satapkt_reason == SATA_PKT_DEV_ERROR) {
			scsipkt->pkt_reason = CMD_INCOMPLETE;
			/*
			 * We may not have ARQ data if there was a double
			 * error. But sense data in sata packet was pre-set
			 * with NO SENSE so it is valid even if HBA could
			 * not retrieve a real sense data.
			 * Just copy this sense data into scsi pkt sense area.
			 */
			bcopy(sata_pkt->satapkt_cmd.satacmd_rqsense, sense,
			    SATA_ATAPI_MIN_RQSENSE_LEN);
#ifdef SATA_DEBUG
			if (sata_debug_flags & SATA_DBG_SCSI_IF) {
				sata_log(spx->txlt_sata_hba_inst, CE_WARN,
				    "sata_txlt_atapi_completion: %02x\n"
				    "RQSENSE:  %02x %02x %02x %02x %02x %02x "
				    "          %02x %02x %02x %02x %02x %02x "
				    "          %02x %02x %02x %02x %02x %02x\n",
				    scsipkt->pkt_reason,
				    rqsp[0], rqsp[1], rqsp[2], rqsp[3],
				    rqsp[4], rqsp[5], rqsp[6], rqsp[7],
				    rqsp[8], rqsp[9], rqsp[10], rqsp[11],
				    rqsp[12], rqsp[13], rqsp[14], rqsp[15],
				    rqsp[16], rqsp[17]);
			}
#endif
		} else {
			switch (sata_pkt->satapkt_reason) {
			case SATA_PKT_PORT_ERROR:
				/*
				 * We have no device data.
				 */
				scsipkt->pkt_reason = CMD_INCOMPLETE;
				scsipkt->pkt_state &= ~(STATE_GOT_BUS |
				    STATE_GOT_TARGET | STATE_SENT_CMD |
				    STATE_GOT_STATUS);
				sense->es_key = KEY_HARDWARE_ERROR;

				/* No extended sense key - no info available */
				scsipkt->pkt_reason = CMD_INCOMPLETE;
				break;

			case SATA_PKT_TIMEOUT:
				/* scsipkt->pkt_reason = CMD_TIMEOUT; */
				/* No extended sense key */
				/*
				 * Need to check if HARDWARE_ERROR/
				 * TIMEOUT_ON_LOGICAL_UNIT 4/3E/2 would be more
				 * appropriate.
				 */
				break;

			case SATA_PKT_ABORTED:
				scsipkt->pkt_reason = CMD_ABORTED;
				/* Should we set key COMMAND_ABPRTED? */
				break;

			case SATA_PKT_RESET:
				scsipkt->pkt_reason = CMD_RESET;
				/*
				 * May be we should set Unit Attention /
				 * Reset. Perhaps the same should be
				 * returned for disks....
				 */
				sense->es_key = KEY_UNIT_ATTENTION;
				sense->es_add_code = SD_SCSI_ASC_RESET;
				break;

			default:
				SATA_LOG_D((spx->txlt_sata_hba_inst, CE_WARN,
				    "sata_txlt_atapi_completion: "
				    "invalid packet completion reason"));
				scsipkt->pkt_reason = CMD_TRAN_ERR;
				scsipkt->pkt_state &= ~(STATE_GOT_BUS |
				    STATE_GOT_TARGET | STATE_SENT_CMD |
				    STATE_GOT_STATUS);
				break;
			}
		}
	}

	SATAATAPITRACE(spx, 0);

	if ((scsipkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    scsipkt->pkt_comp != NULL) {
		/* scsi callback required */
		(*scsipkt->pkt_comp)(scsipkt);
	}
}

/*
 * Set up error retrieval sata command for ATAPI Packet Command error data
 * recovery.
 *
 * Returns SATA_SUCCESS when data buffer is allocated and packet set-up,
 * returns SATA_FAILURE otherwise.
 */

static int
sata_atapi_err_ret_cmd_setup(sata_pkt_txlate_t *spx, sata_drive_info_t *sdinfo)
{
	sata_pkt_t *spkt = spx->txlt_sata_pkt;
	sata_cmd_t *scmd;
	struct buf *bp;

	/*
	 * Allocate dma-able buffer error data.
	 * Buffer allocation will take care of buffer alignment and other DMA
	 * attributes.
	 */
	bp = sata_alloc_local_buffer(spx, SATA_ATAPI_MIN_RQSENSE_LEN);
	if (bp == NULL) {
		SATADBG1(SATA_DBG_ATAPI, spx->txlt_sata_hba_inst,
		    "sata_get_err_retrieval_pkt: "
		    "cannot allocate buffer for error data", NULL);
		return (SATA_FAILURE);
	}
	bp_mapin(bp); /* make data buffer accessible */

	/* Operation modes are up to the caller */
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;

	/* Synchronous mode, no callback - may be changed by the caller */
	spkt->satapkt_comp = NULL;
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;
	scmd->satacmd_flags.sata_ignore_dev_reset = B_TRUE;

	sata_atapi_packet_cmd_setup(scmd, sdinfo);

	/*
	 * Set-up acdb. Request Sense CDB (packet command content) is
	 * not in DMA-able buffer. Its handling is HBA-specific (how
	 * it is transfered into packet FIS).
	 */
	scmd->satacmd_acdb_len = sdinfo->satadrv_atapi_cdb_len;
	bcopy(sata_rqsense_cdb, scmd->satacmd_acdb, SATA_ATAPI_RQSENSE_CDB_LEN);
	/* Following zeroing of pad bytes may not be necessary */
	bzero(&scmd->satacmd_acdb[SATA_ATAPI_RQSENSE_CDB_LEN],
	    sdinfo->satadrv_atapi_cdb_len - SATA_ATAPI_RQSENSE_CDB_LEN);

	/*
	 * Set-up pointer to the buffer handle, so HBA can sync buffer
	 * before accessing it. Handle is in usual place in translate struct.
	 */
	scmd->satacmd_err_ret_buf_handle = &spx->txlt_buf_dma_handle;

	/*
	 * Preset request sense data to NO SENSE.
	 * Here it is redundant, only for a symetry with scsi-originated
	 * packets. It should not be used for anything but debugging.
	 */
	bzero(scmd->satacmd_rqsense, SATA_ATAPI_RQSENSE_LEN);
	sata_fixed_sense_data_preset(
	    (struct scsi_extended_sense *)scmd->satacmd_rqsense);

	ASSERT(scmd->satacmd_num_dma_cookies != 0);
	ASSERT(scmd->satacmd_dma_cookie_list != NULL);

	return (SATA_SUCCESS);
}

/*
 * Set-up ATAPI packet command.
 * Data transfer direction has to be set-up in sata_cmd structure prior to
 * calling this function.
 *
 * Returns void
 */

static void
sata_atapi_packet_cmd_setup(sata_cmd_t *scmd, sata_drive_info_t *sdinfo)
{
	scmd->satacmd_addr_type = 0;		/* N/A */
	scmd->satacmd_sec_count_lsb = 0;	/* no tag */
	scmd->satacmd_lba_low_lsb = 0;		/* N/A */
	scmd->satacmd_lba_mid_lsb = (uint8_t)SATA_ATAPI_MAX_BYTES_PER_DRQ;
	scmd->satacmd_lba_high_lsb =
	    (uint8_t)(SATA_ATAPI_MAX_BYTES_PER_DRQ >> 8);
	scmd->satacmd_cmd_reg = SATAC_PACKET;	/* Command */

	/*
	 * We want all data to be transfered via DMA.
	 * But specify it only if drive supports DMA and DMA mode is
	 * selected - some drives are sensitive about it.
	 * Hopefully it wil work for all drives....
	 */
	if (sdinfo->satadrv_settings & SATA_DEV_DMA)
		scmd->satacmd_features_reg = SATA_ATAPI_F_DMA;

	/*
	 * Features register requires special care for devices that use
	 * Serial ATA bridge - they need an explicit specification of
	 * the data transfer direction for Packet DMA commands.
	 * Setting this bit is harmless if DMA is not used.
	 *
	 * Many drives do not implement word 80, specifying what ATA/ATAPI
	 * spec they follow.
	 * We are arbitrarily following the latest SerialATA 2.6 spec,
	 * which uses ATA/ATAPI 6 specification for Identify Data, unless
	 * ATA/ATAPI-7 support is explicitly indicated.
	 */
	if (sdinfo->satadrv_id.ai_majorversion != 0 &&
	    sdinfo->satadrv_id.ai_majorversion != 0xffff &&
	    (sdinfo->satadrv_id.ai_majorversion & SATA_MAJVER_7) != 0) {
		/*
		 * Specification of major version is valid and version 7
		 * is supported. It does automatically imply that all
		 * spec features are supported. For now, we assume that
		 * DMADIR setting is valid. ATA/ATAPI7 spec is incomplete.
		 */
		if ((sdinfo->satadrv_id.ai_dirdma &
		    SATA_ATAPI_ID_DMADIR_REQ) != 0) {
			if (scmd->satacmd_flags.sata_data_direction ==
			    SATA_DIR_READ)
			scmd->satacmd_features_reg |=
			    SATA_ATAPI_F_DATA_DIR_READ;
		}
	}
}


#ifdef SATA_DEBUG

/* Display 18 bytes of Inquiry data */
static void
sata_show_inqry_data(uint8_t *buf)
{
	struct scsi_inquiry *inq = (struct scsi_inquiry *)buf;
	uint8_t *p;

	cmn_err(CE_NOTE, "Inquiry data:");
	cmn_err(CE_NOTE, "device type %x", inq->inq_dtype);
	cmn_err(CE_NOTE, "removable media %x", inq->inq_rmb);
	cmn_err(CE_NOTE, "version %x", inq->inq_ansi);
	cmn_err(CE_NOTE, "ATAPI transport version %d",
	    SATA_ATAPI_TRANS_VERSION(inq));
	cmn_err(CE_NOTE, "response data format %d, aenc %d",
	    inq->inq_rdf, inq->inq_aenc);
	cmn_err(CE_NOTE, " additional length %d", inq->inq_len);
	cmn_err(CE_NOTE, "tpgs %d", inq->inq_tpgs);
	p = (uint8_t *)inq->inq_vid;
	cmn_err(CE_NOTE, "vendor id (binary): %02x %02x %02x %02x "
	    "%02x %02x %02x %02x",
	    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
	p = (uint8_t *)inq->inq_vid;
	cmn_err(CE_NOTE, "vendor id: %c %c %c %c %c %c %c %c",
	    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

	p = (uint8_t *)inq->inq_pid;
	cmn_err(CE_NOTE, "product id (binary): %02x %02x %02x %02x "
	    "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
	    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
	    p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
	p = (uint8_t *)inq->inq_pid;
	cmn_err(CE_NOTE, "product id: %c %c %c %c %c %c %c %c "
	    "%c %c %c %c %c %c %c %c",
	    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
	    p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

	p = (uint8_t *)inq->inq_revision;
	cmn_err(CE_NOTE, "revision (binary): %02x %02x %02x %02x",
	    p[0], p[1], p[2], p[3]);
	p = (uint8_t *)inq->inq_revision;
	cmn_err(CE_NOTE, "revision: %c %c %c %c",
	    p[0], p[1], p[2], p[3]);

}


static void
sata_save_atapi_trace(sata_pkt_txlate_t *spx, int count)
{
	struct scsi_pkt *scsi_pkt = spx->txlt_scsi_pkt;

	if (scsi_pkt == NULL)
		return;
	if (count != 0) {
		/* saving cdb */
		bzero(sata_atapi_trace[sata_atapi_trace_index].acdb,
		    SATA_ATAPI_MAX_CDB_LEN);
		bcopy(scsi_pkt->pkt_cdbp,
		    sata_atapi_trace[sata_atapi_trace_index].acdb, count);
	} else {
		bcopy(&((struct scsi_arq_status *)scsi_pkt->pkt_scbp)->
		    sts_sensedata,
		    sata_atapi_trace[sata_atapi_trace_index].arqs,
		    SATA_ATAPI_MIN_RQSENSE_LEN);
		sata_atapi_trace[sata_atapi_trace_index].scsi_pkt_reason =
		    scsi_pkt->pkt_reason;
		sata_atapi_trace[sata_atapi_trace_index].sata_pkt_reason =
		    spx->txlt_sata_pkt->satapkt_reason;

		if (++sata_atapi_trace_index >= 64)
			sata_atapi_trace_index = 0;
	}
}

#endif

/*
 * Fetch inquiry data from ATAPI device
 * Returns SATA_SUCCESS if operation was successfull, SATA_FAILURE otherwise.
 *
 * Note:
 * inqb pointer does not point to a DMA-able buffer. It is a local buffer
 * where the caller expects to see the inquiry data.
 *
 */

static int
sata_get_atapi_inquiry_data(sata_hba_inst_t *sata_hba,
    sata_address_t *saddr, struct scsi_inquiry *inq)
{
	sata_pkt_txlate_t *spx;
	sata_pkt_t *spkt;
	struct buf *bp;
	sata_drive_info_t *sdinfo;
	sata_cmd_t *scmd;
	int rval;
	uint8_t *rqsp;
#ifdef SATA_DEBUG
	char msg_buf[MAXPATHLEN];
#endif

	ASSERT(sata_hba != NULL);

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, NULL);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (SATA_FAILURE);
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = *saddr;

	/* scsi_inquiry size buffer */
	bp = sata_alloc_local_buffer(spx, sizeof (struct scsi_inquiry));
	if (bp == NULL) {
		sata_pkt_free(spx);
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		SATA_LOG_D((sata_hba, CE_WARN,
		    "sata_get_atapi_inquiry_data: "
		    "cannot allocate data buffer"));
		return (SATA_FAILURE);
	}
	bp_mapin(bp); /* make data buffer accessible */

	scmd = &spkt->satapkt_cmd;
	ASSERT(scmd->satacmd_num_dma_cookies != 0);
	ASSERT(scmd->satacmd_dma_cookie_list != NULL);

	/* Use synchronous mode */
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	spkt->satapkt_comp = NULL;
	spkt->satapkt_time = sata_default_pkt_time;

	/* Issue inquiry command - 6 bytes cdb, data transfer, read */

	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;
	scmd->satacmd_flags.sata_ignore_dev_reset = B_TRUE;

	mutex_enter(&(SATA_TXLT_CPORT_MUTEX(spx)));
	sdinfo = sata_get_device_info(sata_hba,
	    &spx->txlt_sata_pkt->satapkt_device);
	if (sdinfo == NULL) {
		/* we have to be carefull about the disapearing device */
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		rval = SATA_FAILURE;
		goto cleanup;
	}
	sata_atapi_packet_cmd_setup(scmd, sdinfo);

	/*
	 * Set-up acdb. This works for atapi transport version 2 and later.
	 */
	scmd->satacmd_acdb_len = sdinfo->satadrv_atapi_cdb_len;
	bzero(scmd->satacmd_acdb, SATA_ATAPI_MAX_CDB_LEN);
	scmd->satacmd_acdb[0] = 0x12;	/* Inquiry */
	scmd->satacmd_acdb[1] = 0x00;
	scmd->satacmd_acdb[2] = 0x00;
	scmd->satacmd_acdb[3] = 0x00;
	scmd->satacmd_acdb[4] = sizeof (struct scsi_inquiry);
	scmd->satacmd_acdb[5] = 0x00;

	sata_fixed_sense_data_preset(
	    (struct scsi_extended_sense *)scmd->satacmd_rqsense);

	/* Transfer command to HBA */
	if (sata_hba_start(spx, &rval) != 0) {
		/* Pkt not accepted for execution */
		SATADBG1(SATA_DBG_ATAPI, sata_hba,
		    "sata_get_atapi_inquiry_data: "
		    "Packet not accepted for execution - ret: %02x", rval);
		mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));
		rval = SATA_FAILURE;
		goto cleanup;
	}
	mutex_exit(&(SATA_TXLT_CPORT_MUTEX(spx)));

	if (spkt->satapkt_reason == SATA_PKT_COMPLETED) {
		SATADBG1(SATA_DBG_ATAPI, sata_hba,
		    "sata_get_atapi_inquiry_data: "
		    "Packet completed successfully - ret: %02x", rval);
		/*
		 * Sync buffer. Handle is in usual place in translate struct.
		 * Normal completion - copy data into caller's buffer
		 */
		rval = ddi_dma_sync(spx->txlt_buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		ASSERT(rval == DDI_SUCCESS);
		bcopy(bp->b_un.b_addr, (uint8_t *)inq,
		    sizeof (struct scsi_inquiry));
#ifdef SATA_DEBUG
		if (sata_debug_flags & SATA_DBG_ATAPI) {
			sata_show_inqry_data((uint8_t *)inq);
		}
#endif
		rval = SATA_SUCCESS;
	} else {
		/*
		 * Something went wrong - analyze return - check rqsense data
		 */
		rval = SATA_FAILURE;
		if (spkt->satapkt_reason == SATA_PKT_DEV_ERROR) {
			/*
			 * ARQ data hopefull show something other than NO SENSE
			 */
			rqsp = scmd->satacmd_rqsense;
#ifdef SATA_DEBUG
			if (sata_debug_flags & SATA_DBG_ATAPI) {
				msg_buf[0] = '\0';
				(void) snprintf(msg_buf, MAXPATHLEN,
				    "ATAPI packet completion reason: %02x\n"
				    "RQSENSE:  %02x %02x %02x %02x %02x %02x\n"
				    "          %02x %02x %02x %02x %02x %02x\n"
				    "          %02x %02x %02x %02x %02x %02x",
				    spkt->satapkt_reason,
				    rqsp[0], rqsp[1], rqsp[2], rqsp[3],
				    rqsp[4], rqsp[5], rqsp[6], rqsp[7],
				    rqsp[8], rqsp[9], rqsp[10], rqsp[11],
				    rqsp[12], rqsp[13], rqsp[14], rqsp[15],
				    rqsp[16], rqsp[17]);
				sata_log(spx->txlt_sata_hba_inst, CE_WARN,
				    "%s", msg_buf);
			}
#endif
		} else {
			switch (spkt->satapkt_reason) {
			case SATA_PKT_PORT_ERROR:
				SATADBG1(SATA_DBG_ATAPI, sata_hba,
				    "sata_get_atapi_inquiry_data: "
				    "packet reason: port error", NULL);
				break;

			case SATA_PKT_TIMEOUT:
				SATADBG1(SATA_DBG_ATAPI, sata_hba,
				    "sata_get_atapi_inquiry_data: "
				    "packet reason: timeout", NULL);
				break;

			case SATA_PKT_ABORTED:
				SATADBG1(SATA_DBG_ATAPI, sata_hba,
				    "sata_get_atapi_inquiry_data: "
				    "packet reason: aborted", NULL);
				break;

			case SATA_PKT_RESET:
				SATADBG1(SATA_DBG_ATAPI, sata_hba,
				    "sata_get_atapi_inquiry_data: "
				    "packet reason: reset\n", NULL);
				break;
			default:
				SATADBG1(SATA_DBG_ATAPI, sata_hba,
				    "sata_get_atapi_inquiry_data: "
				    "invalid packet reason: %02x\n",
				    spkt->satapkt_reason);
				break;
			}
		}
	}
cleanup:
	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));
	return (rval);
}





#if 0
#ifdef SATA_DEBUG

/*
 * Test ATAPI packet command.
 * Single threaded test: send packet command in synch mode, process completion
 *
 */
static void
sata_test_atapi_packet_command(sata_hba_inst_t *sata_hba_inst, int cport)
{
	sata_pkt_txlate_t *spx;
	sata_pkt_t *spkt;
	struct buf *bp;
	sata_device_t sata_device;
	sata_drive_info_t *sdinfo;
	sata_cmd_t *scmd;
	int rval;
	uint8_t *rqsp;

	ASSERT(sata_hba_inst != NULL);
	sata_device.satadev_addr.cport = cport;
	sata_device.satadev_addr.pmport = 0;
	sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;
	sata_device.satadev_rev = SATA_DEVICE_REV;
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
	sdinfo = sata_get_device_info(sata_hba_inst, &sata_device);
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
	if (sdinfo == NULL) {
		sata_log(sata_hba_inst, CE_WARN,
		    "sata_test_atapi_packet_command: "
		    "no device info for cport %d",
		    sata_device.satadev_addr.cport);
		return;
	}

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, NULL);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return;
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = sata_device.satadev_addr;

	/* 1024k buffer */
	bp = sata_alloc_local_buffer(spx, 1024);
	if (bp == NULL) {
		sata_pkt_free(spx);
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		sata_log(sata_hba_inst, CE_WARN,
		    "sata_test_atapi_packet_command: "
		    "cannot allocate data buffer");
		return;
	}
	bp_mapin(bp); /* make data buffer accessible */

	scmd = &spkt->satapkt_cmd;
	ASSERT(scmd->satacmd_num_dma_cookies != 0);
	ASSERT(scmd->satacmd_dma_cookie_list != NULL);

	/* Use synchronous mode */
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;

	/* Synchronous mode, no callback - may be changed by the caller */
	spkt->satapkt_comp = NULL;
	spkt->satapkt_time = sata_default_pkt_time;

	/* Issue inquiry command - 6 bytes cdb, data transfer, read */

	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;
	scmd->satacmd_flags.sata_ignore_dev_reset = B_TRUE;

	sata_atapi_packet_cmd_setup(scmd, sdinfo);

	/* Set-up acdb. */
	scmd->satacmd_acdb_len = sdinfo->satadrv_atapi_cdb_len;
	bzero(scmd->satacmd_acdb, SATA_ATAPI_MAX_CDB_LEN);
	scmd->satacmd_acdb[0] = 0x12;	/* Inquiry */
	scmd->satacmd_acdb[1] = 0x00;
	scmd->satacmd_acdb[2] = 0x00;
	scmd->satacmd_acdb[3] = 0x00;
	scmd->satacmd_acdb[4] = sizeof (struct scsi_inquiry);
	scmd->satacmd_acdb[5] = 0x00;

	sata_fixed_sense_data_preset(
	    (struct scsi_extended_sense *)scmd->satacmd_rqsense);

	/* Transfer command to HBA */
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
	if (sata_hba_start(spx, &rval) != 0) {
		/* Pkt not accepted for execution */
		sata_log(sata_hba_inst, CE_WARN,
		    "sata_test_atapi_packet_command: "
		    "Packet not accepted for execution - ret: %02x", rval);
		mutex_exit(
		    &SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
		goto cleanup;
	}
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);

	/*
	 * Sync buffer. Handle is in usual place in translate struct.
	 */
	rval = ddi_dma_sync(spx->txlt_buf_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORCPU);
	ASSERT(rval == DDI_SUCCESS);
	if (spkt->satapkt_reason == SATA_PKT_COMPLETED) {
		sata_log(sata_hba_inst, CE_WARN,
		    "sata_test_atapi_packet_command: "
		    "Packet completed successfully");
		/*
		 * Normal completion - show inquiry data
		 */
		sata_show_inqry_data((uint8_t *)bp->b_un.b_addr);
	} else {
		/*
		 * Something went wrong - analyze return - check rqsense data
		 */
		if (spkt->satapkt_reason == SATA_PKT_DEV_ERROR) {
			/*
			 * ARQ data hopefull show something other than NO SENSE
			 */
			rqsp = scmd->satacmd_rqsense;
			sata_log(spx->txlt_sata_hba_inst, CE_WARN,
			    "ATAPI packet completion reason: %02x\n"
			    "RQSENSE:  %02x %02x %02x %02x %02x %02x "
			    "          %02x %02x %02x %02x %02x %02x "
			    "          %02x %02x %02x %02x %02x %02x\n",
			    spkt->satapkt_reason,
			    rqsp[0], rqsp[1], rqsp[2], rqsp[3],
			    rqsp[4], rqsp[5], rqsp[6], rqsp[7],
			    rqsp[8], rqsp[9], rqsp[10], rqsp[11],
			    rqsp[12], rqsp[13], rqsp[14], rqsp[15],
			    rqsp[16], rqsp[17]);
		} else {
			switch (spkt->satapkt_reason) {
			case SATA_PKT_PORT_ERROR:
				sata_log(sata_hba_inst, CE_WARN,
				    "sata_test_atapi_packet_command: "
				    "packet reason: port error\n");
				break;

			case SATA_PKT_TIMEOUT:
				sata_log(sata_hba_inst, CE_WARN,
				    "sata_test_atapi_packet_command: "
				    "packet reason: timeout\n");
				break;

			case SATA_PKT_ABORTED:
				sata_log(sata_hba_inst, CE_WARN,
				    "sata_test_atapi_packet_command: "
				    "packet reason: aborted\n");
				break;

			case SATA_PKT_RESET:
				sata_log(sata_hba_inst, CE_WARN,
				    "sata_test_atapi_packet_command: "
				    "packet reason: reset\n");
				break;
			default:
				sata_log(sata_hba_inst, CE_WARN,
				    "sata_test_atapi_packet_command: "
				    "invalid packet reason: %02x\n",
				    spkt->satapkt_reason);
				break;
			}
		}
	}
cleanup:
	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));
}

#endif /* SATA_DEBUG */
#endif /* 1 */


/* ************************** LOCAL HELPER FUNCTIONS *********************** */

/*
 * Validate sata_tran info
 * SATA_FAILURE returns if structure is inconsistent or structure revision
 * does not match one used by the framework.
 *
 * Returns SATA_SUCCESS if sata_hba_tran has matching revision and contains
 * required function pointers.
 * Returns SATA_FAILURE otherwise.
 */
static int
sata_validate_sata_hba_tran(dev_info_t *dip, sata_hba_tran_t *sata_tran)
{
	/*
	 * SATA_TRAN_HBA_REV is the current (highest) revision number
	 * of the SATA interface.
	 */
	if (sata_tran->sata_tran_hba_rev > SATA_TRAN_HBA_REV) {
		sata_log(NULL, CE_WARN,
		    "sata: invalid sata_hba_tran version %d for driver %s",
		    sata_tran->sata_tran_hba_rev, ddi_driver_name(dip));
		return (SATA_FAILURE);
	}

	if (dip != sata_tran->sata_tran_hba_dip) {
		SATA_LOG_D((NULL, CE_WARN,
		    "sata: inconsistent sata_tran_hba_dip "
		    "%p / %p", sata_tran->sata_tran_hba_dip, dip));
		return (SATA_FAILURE);
	}

	if (sata_tran->sata_tran_probe_port == NULL ||
	    sata_tran->sata_tran_start == NULL ||
	    sata_tran->sata_tran_abort == NULL ||
	    sata_tran->sata_tran_reset_dport == NULL ||
	    sata_tran->sata_tran_hotplug_ops == NULL ||
	    sata_tran->sata_tran_hotplug_ops->sata_tran_port_activate == NULL ||
	    sata_tran->sata_tran_hotplug_ops->sata_tran_port_deactivate ==
	    NULL) {
		SATA_LOG_D((NULL, CE_WARN, "sata: sata_hba_tran missing "
		    "required functions"));
	}
	return (SATA_SUCCESS);
}

/*
 * Remove HBA instance from sata_hba_list.
 */
static void
sata_remove_hba_instance(dev_info_t *dip)
{
	sata_hba_inst_t	*sata_hba_inst;

	mutex_enter(&sata_mutex);
	for (sata_hba_inst = sata_hba_list;
	    sata_hba_inst != (struct sata_hba_inst *)NULL;
	    sata_hba_inst = sata_hba_inst->satahba_next) {
		if (sata_hba_inst->satahba_dip == dip)
			break;
	}

	if (sata_hba_inst == (struct sata_hba_inst *)NULL) {
#ifdef SATA_DEBUG
		cmn_err(CE_WARN, "sata_remove_hba_instance: "
		    "unknown HBA instance\n");
#endif
		ASSERT(FALSE);
	}
	if (sata_hba_inst == sata_hba_list) {
		sata_hba_list = sata_hba_inst->satahba_next;
		if (sata_hba_list) {
			sata_hba_list->satahba_prev =
			    (struct sata_hba_inst *)NULL;
		}
		if (sata_hba_inst == sata_hba_list_tail) {
			sata_hba_list_tail = NULL;
		}
	} else if (sata_hba_inst == sata_hba_list_tail) {
		sata_hba_list_tail = sata_hba_inst->satahba_prev;
		if (sata_hba_list_tail) {
			sata_hba_list_tail->satahba_next =
			    (struct sata_hba_inst *)NULL;
		}
	} else {
		sata_hba_inst->satahba_prev->satahba_next =
		    sata_hba_inst->satahba_next;
		sata_hba_inst->satahba_next->satahba_prev =
		    sata_hba_inst->satahba_prev;
	}
	mutex_exit(&sata_mutex);
}





/*
 * Probe all SATA ports of the specified HBA instance.
 * The assumption is that there are no target and attachment point minor nodes
 * created by the boot subsystems, so we do not need to prune device tree.
 *
 * This function is called only from sata_hba_attach(). It does not have to
 * be protected by controller mutex, because the hba_attached flag is not set
 * yet and no one would be touching this HBA instance other than this thread.
 * Determines if port is active and what type of the device is attached
 * (if any). Allocates necessary structures for each port.
 *
 * An AP (Attachement Point) node is created for each SATA device port even
 * when there is no device attached.
 */

static 	void
sata_probe_ports(sata_hba_inst_t *sata_hba_inst)
{
	dev_info_t		*dip = SATA_DIP(sata_hba_inst);
	int			ncport, npmport;
	sata_cport_info_t 	*cportinfo;
	sata_drive_info_t	*drive;
	sata_pmult_info_t	*pminfo;
	sata_pmport_info_t 	*pmportinfo;
	sata_device_t		sata_device;
	int			rval;
	dev_t			minor_number;
	char			name[16];
	clock_t			start_time, cur_time;

	/*
	 * Probe controller ports first, to find port status and
	 * any port multiplier attached.
	 */
	for (ncport = 0; ncport < SATA_NUM_CPORTS(sata_hba_inst); ncport++) {
		/* allocate cport structure */
		cportinfo = kmem_zalloc(sizeof (sata_cport_info_t), KM_SLEEP);
		ASSERT(cportinfo != NULL);
		mutex_init(&cportinfo->cport_mutex, NULL, MUTEX_DRIVER, NULL);

		mutex_enter(&cportinfo->cport_mutex);

		cportinfo->cport_addr.cport = ncport;
		cportinfo->cport_addr.pmport = 0;
		cportinfo->cport_addr.qual = SATA_ADDR_CPORT;
		cportinfo->cport_state &= ~SATA_PORT_STATE_CLEAR_MASK;
		cportinfo->cport_state |= SATA_STATE_PROBING;
		SATA_CPORT_INFO(sata_hba_inst, ncport) = cportinfo;

		/*
		 * Regardless if a port is usable or not, create
		 * an attachment point
		 */
		mutex_exit(&cportinfo->cport_mutex);
		minor_number =
		    SATA_MAKE_AP_MINOR(ddi_get_instance(dip), ncport, 0, 0);
		(void) sprintf(name, "%d", ncport);
		if (ddi_create_minor_node(dip, name, S_IFCHR,
		    minor_number, DDI_NT_SATA_ATTACHMENT_POINT, 0) !=
		    DDI_SUCCESS) {
			sata_log(sata_hba_inst, CE_WARN, "sata_hba_attach: "
			    "cannot create SATA attachment point for port %d",
			    ncport);
		}

		/* Probe port */
		start_time = ddi_get_lbolt();
	reprobe_cport:
		sata_device.satadev_addr.cport = ncport;
		sata_device.satadev_addr.pmport = 0;
		sata_device.satadev_addr.qual = SATA_ADDR_CPORT;
		sata_device.satadev_rev = SATA_DEVICE_REV;

		rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
		    (dip, &sata_device);

		mutex_enter(&cportinfo->cport_mutex);
		sata_update_port_scr(&cportinfo->cport_scr, &sata_device);
		if (rval != SATA_SUCCESS) {
			/* Something went wrong? Fail the port */
			cportinfo->cport_state = SATA_PSTATE_FAILED;
			mutex_exit(&cportinfo->cport_mutex);
			continue;
		}
		cportinfo->cport_state &= ~SATA_STATE_PROBING;
		cportinfo->cport_state |= SATA_STATE_PROBED;
		cportinfo->cport_dev_type = sata_device.satadev_type;

		cportinfo->cport_state |= SATA_STATE_READY;
		if (cportinfo->cport_dev_type == SATA_DTYPE_NONE) {
			mutex_exit(&cportinfo->cport_mutex);
			continue;
		}
		if (cportinfo->cport_dev_type != SATA_DTYPE_PMULT) {
			/*
			 * There is some device attached.
			 * Allocate device info structure
			 */
			if (SATA_CPORTINFO_DRV_INFO(cportinfo) == NULL) {
				mutex_exit(&cportinfo->cport_mutex);
				SATA_CPORTINFO_DRV_INFO(cportinfo) =
				    kmem_zalloc(sizeof (sata_drive_info_t),
				    KM_SLEEP);
				mutex_enter(&cportinfo->cport_mutex);
			}
			drive = SATA_CPORTINFO_DRV_INFO(cportinfo);
			drive->satadrv_addr = cportinfo->cport_addr;
			drive->satadrv_addr.qual = SATA_ADDR_DCPORT;
			drive->satadrv_type = cportinfo->cport_dev_type;
			drive->satadrv_state = SATA_STATE_UNKNOWN;

			mutex_exit(&cportinfo->cport_mutex);
			if (sata_add_device(dip, sata_hba_inst, ncport, 0) !=
			    SATA_SUCCESS) {
				/*
				 * Plugged device was not correctly identified.
				 * Retry, within a SATA_DEV_IDENTIFY_TIMEOUT
				 */
				cur_time = ddi_get_lbolt();
				if ((cur_time - start_time) <
				    drv_usectohz(SATA_DEV_IDENTIFY_TIMEOUT)) {
					/* sleep for a while */
					delay(drv_usectohz(
					    SATA_DEV_IDENTIFY_RETRY_DELAY));
					goto reprobe_cport;
				}
			}
		} else {
			mutex_exit(&cportinfo->cport_mutex);
			ASSERT(cportinfo->cport_dev_type == SATA_DTYPE_PMULT);
			pminfo = kmem_zalloc(sizeof (sata_pmult_info_t),
			    KM_SLEEP);
			mutex_enter(&cportinfo->cport_mutex);
			ASSERT(pminfo != NULL);
			SATA_CPORTINFO_PMULT_INFO(cportinfo) = pminfo;
			pminfo->pmult_addr.cport = cportinfo->cport_addr.cport;
			pminfo->pmult_addr.pmport = SATA_PMULT_HOSTPORT;
			pminfo->pmult_addr.qual = SATA_ADDR_PMPORT;
			pminfo->pmult_num_dev_ports =
			    sata_device.satadev_add_info;
			mutex_init(&pminfo->pmult_mutex, NULL, MUTEX_DRIVER,
			    NULL);
			pminfo->pmult_state = SATA_STATE_PROBING;
			mutex_exit(&cportinfo->cport_mutex);

			/* Probe Port Multiplier ports */
			for (npmport = 0;
			    npmport < pminfo->pmult_num_dev_ports;
			    npmport++) {
				pmportinfo = kmem_zalloc(
				    sizeof (sata_pmport_info_t), KM_SLEEP);
				mutex_enter(&cportinfo->cport_mutex);
				ASSERT(pmportinfo != NULL);
				pmportinfo->pmport_addr.cport = ncport;
				pmportinfo->pmport_addr.pmport = npmport;
				pmportinfo->pmport_addr.qual =
				    SATA_ADDR_PMPORT;
				pminfo->pmult_dev_port[npmport] = pmportinfo;

				mutex_init(&pmportinfo->pmport_mutex, NULL,
				    MUTEX_DRIVER, NULL);

				mutex_exit(&cportinfo->cport_mutex);

				/* Create an attachment point */
				minor_number = SATA_MAKE_AP_MINOR(
				    ddi_get_instance(dip), ncport, npmport, 1);
				(void) sprintf(name, "%d.%d", ncport, npmport);
				if (ddi_create_minor_node(dip, name, S_IFCHR,
				    minor_number, DDI_NT_SATA_ATTACHMENT_POINT,
				    0) != DDI_SUCCESS) {
					sata_log(sata_hba_inst, CE_WARN,
					    "sata_hba_attach: "
					    "cannot create SATA attachment "
					    "point for port %d pmult port %d",
					    ncport, npmport);
				}

				start_time = ddi_get_lbolt();
			reprobe_pmport:
				sata_device.satadev_addr.pmport = npmport;
				sata_device.satadev_addr.qual =
				    SATA_ADDR_PMPORT;

				rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
				    (dip, &sata_device);
				mutex_enter(&cportinfo->cport_mutex);

				/* sata_update_port_info() */
				sata_update_port_scr(&pmportinfo->pmport_scr,
				    &sata_device);

				if (rval != SATA_SUCCESS) {
					pmportinfo->pmport_state =
					    SATA_PSTATE_FAILED;
					mutex_exit(&cportinfo->cport_mutex);
					continue;
				}
				pmportinfo->pmport_state &=
				    ~SATA_STATE_PROBING;
				pmportinfo->pmport_state |= SATA_STATE_PROBED;
				pmportinfo->pmport_dev_type =
				    sata_device.satadev_type;

				pmportinfo->pmport_state |= SATA_STATE_READY;
				if (pmportinfo->pmport_dev_type ==
				    SATA_DTYPE_NONE) {
					mutex_exit(&cportinfo->cport_mutex);
					continue;
				}
				/* Port multipliers cannot be chained */
				ASSERT(pmportinfo->pmport_dev_type !=
				    SATA_DTYPE_PMULT);
				/*
				 * There is something attached to Port
				 * Multiplier device port
				 * Allocate device info structure
				 */
				if (pmportinfo->pmport_sata_drive == NULL) {
					mutex_exit(&cportinfo->cport_mutex);
					pmportinfo->pmport_sata_drive =
					    kmem_zalloc(
					    sizeof (sata_drive_info_t),
					    KM_SLEEP);
					mutex_enter(&cportinfo->cport_mutex);
				}
				drive = pmportinfo->pmport_sata_drive;
				drive->satadrv_addr.cport =
				    pmportinfo->pmport_addr.cport;
				drive->satadrv_addr.pmport = npmport;
				drive->satadrv_addr.qual = SATA_ADDR_DPMPORT;
				drive->satadrv_type = pmportinfo->
				    pmport_dev_type;
				drive->satadrv_state = SATA_STATE_UNKNOWN;

				mutex_exit(&cportinfo->cport_mutex);
				if (sata_add_device(dip, sata_hba_inst, ncport,
				    npmport) != SATA_SUCCESS) {
					/*
					 * Plugged device was not correctly
					 * identified. Retry, within the
					 * SATA_DEV_IDENTIFY_TIMEOUT
					 */
					cur_time = ddi_get_lbolt();
					if ((cur_time - start_time) <
					    drv_usectohz(
					    SATA_DEV_IDENTIFY_TIMEOUT)) {
						/* sleep for a while */
						delay(drv_usectohz(
						SATA_DEV_IDENTIFY_RETRY_DELAY));
						goto reprobe_pmport;
					}
				}
			}
			pmportinfo->pmport_state =
			    SATA_STATE_PROBED | SATA_STATE_READY;
		}
	}
}

/*
 * Add SATA device for specified HBA instance & port (SCSI target
 * device nodes).
 * This function is called (indirectly) only from sata_hba_attach().
 * A target node is created when there is a supported type device attached,
 * but may be removed if it cannot be put online.
 *
 * This function cannot be called from an interrupt context.
 *
 * ONLY DISK TARGET NODES ARE CREATED NOW
 *
 * Returns SATA_SUCCESS when port/device was fully processed, SATA_FAILURE when
 * device identification failed - adding a device could be retried.
 *
 */
static 	int
sata_add_device(dev_info_t *pdip, sata_hba_inst_t *sata_hba_inst, int cport,
    int pmport)
{
	sata_cport_info_t 	*cportinfo;
	sata_pmult_info_t	*pminfo;
	sata_pmport_info_t	*pmportinfo;
	dev_info_t		*cdip;		/* child dip */
	sata_device_t		sata_device;
	int			rval;



	cportinfo = SATA_CPORT_INFO(sata_hba_inst, cport);
	ASSERT(cportinfo->cport_dev_type != SATA_DTYPE_NONE);
	mutex_enter(&cportinfo->cport_mutex);
	/*
	 * Some device is attached to a controller port.
	 * We rely on controllers distinquishing between no-device,
	 * attached port multiplier and other kind of attached device.
	 * We need to get Identify Device data and determine
	 * positively the dev type before trying to attach
	 * the target driver.
	 */
	sata_device.satadev_rev = SATA_DEVICE_REV;
	if (cportinfo->cport_dev_type != SATA_DTYPE_PMULT) {
		/*
		 * Not port multiplier.
		 */
		sata_device.satadev_addr = cportinfo->cport_addr;
		sata_device.satadev_addr.qual = SATA_ADDR_DCPORT;
		mutex_exit(&cportinfo->cport_mutex);

		rval = sata_probe_device(sata_hba_inst, &sata_device);
		if (rval != SATA_SUCCESS ||
		    sata_device.satadev_type == SATA_DTYPE_UNKNOWN)
			return (SATA_FAILURE);

		mutex_enter(&cportinfo->cport_mutex);
		sata_show_drive_info(sata_hba_inst,
		    SATA_CPORTINFO_DRV_INFO(cportinfo));

		if ((sata_device.satadev_type & SATA_VALID_DEV_TYPE) == 0) {
			/*
			 * Could not determine device type or
			 * a device is not supported.
			 * Degrade this device to unknown.
			 */
			cportinfo->cport_dev_type = SATA_DTYPE_UNKNOWN;
			mutex_exit(&cportinfo->cport_mutex);
			return (SATA_SUCCESS);
		}
		cportinfo->cport_dev_type = sata_device.satadev_type;
		cportinfo->cport_tgtnode_clean = B_TRUE;
		mutex_exit(&cportinfo->cport_mutex);

		/*
		 * Initialize device to the desired state. Even if it
		 * fails, the device will still attach but syslog
		 * will show the warning.
		 */
		if (sata_initialize_device(sata_hba_inst,
		    SATA_CPORTINFO_DRV_INFO(cportinfo)) != SATA_SUCCESS)
			/* Retry */
			(void) sata_initialize_device(sata_hba_inst,
			    SATA_CPORTINFO_DRV_INFO(cportinfo));

		cdip = sata_create_target_node(pdip, sata_hba_inst,
		    &sata_device.satadev_addr);
		mutex_enter(&cportinfo->cport_mutex);
		if (cdip == NULL) {
			/*
			 * Attaching target node failed.
			 * We retain sata_drive_info structure...
			 */
			mutex_exit(&cportinfo->cport_mutex);
			return (SATA_SUCCESS);
		}
		(SATA_CPORTINFO_DRV_INFO(cportinfo))->
		    satadrv_state = SATA_STATE_READY;
	} else {
		/* This must be Port Multiplier type */
		if (cportinfo->cport_dev_type != SATA_DTYPE_PMULT) {
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "sata_add_device: "
			    "unrecognized dev type %x",
			    cportinfo->cport_dev_type));
			mutex_exit(&cportinfo->cport_mutex);
			return (SATA_SUCCESS);
		}
		pminfo = SATA_CPORTINFO_PMULT_INFO(cportinfo);
		pmportinfo = pminfo->pmult_dev_port[pmport];
		sata_device.satadev_addr = pmportinfo->pmport_addr;
		sata_device.satadev_addr.qual = SATA_ADDR_DPMPORT;
		mutex_exit(&cportinfo->cport_mutex);

		rval = sata_probe_device(sata_hba_inst, &sata_device);
		if (rval != SATA_SUCCESS ||
		    sata_device.satadev_type == SATA_DTYPE_UNKNOWN) {
			return (SATA_FAILURE);
		}
		mutex_enter(&cportinfo->cport_mutex);
		sata_show_drive_info(sata_hba_inst,
		    SATA_CPORTINFO_DRV_INFO(cportinfo));

		if ((sata_device.satadev_type & SATA_VALID_DEV_TYPE) == 0) {
			/*
			 * Could not determine device type.
			 * Degrade this device to unknown.
			 */
			pmportinfo->pmport_dev_type = SATA_DTYPE_UNKNOWN;
			mutex_exit(&cportinfo->cport_mutex);
			return (SATA_SUCCESS);
		}
		pmportinfo->pmport_dev_type = sata_device.satadev_type;
		pmportinfo->pmport_tgtnode_clean = B_TRUE;
		mutex_exit(&cportinfo->cport_mutex);

		/*
		 * Initialize device to the desired state.
		 * Even if it fails, the device will still
		 * attach but syslog will show the warning.
		 */
		if (sata_initialize_device(sata_hba_inst,
		    pmportinfo->pmport_sata_drive) != SATA_SUCCESS)
			/* Retry */
			(void) sata_initialize_device(sata_hba_inst,
			    pmportinfo->pmport_sata_drive);

		cdip = sata_create_target_node(pdip, sata_hba_inst,
		    &sata_device.satadev_addr);
		mutex_enter(&cportinfo->cport_mutex);
		if (cdip == NULL) {
			/*
			 * Attaching target node failed.
			 * We retain sata_drive_info structure...
			 */
			mutex_exit(&cportinfo->cport_mutex);
			return (SATA_SUCCESS);
		}
		pmportinfo->pmport_sata_drive->satadrv_state |=
		    SATA_STATE_READY;
	}
	mutex_exit(&cportinfo->cport_mutex);
	return (SATA_SUCCESS);
}



/*
 * Create scsi target node for attached device, create node properties and
 * attach the node.
 * The node could be removed if the device onlining fails.
 *
 * A dev_info_t pointer is returned if operation is successful, NULL is
 * returned otherwise.
 *
 * No port multiplier support.
 */

static dev_info_t *
sata_create_target_node(dev_info_t *dip, sata_hba_inst_t *sata_hba_inst,
			sata_address_t *sata_addr)
{
	dev_info_t *cdip = NULL;
	int rval;
	char *nname = NULL;
	char **compatible = NULL;
	int ncompatible;
	struct scsi_inquiry inq;
	sata_device_t sata_device;
	sata_drive_info_t *sdinfo;
	int target;
	int i;

	sata_device.satadev_rev = SATA_DEVICE_REV;
	sata_device.satadev_addr = *sata_addr;

	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst, sata_addr->cport)));

	sdinfo = sata_get_device_info(sata_hba_inst, &sata_device);

	target = SATA_TO_SCSI_TARGET(sata_addr->cport,
	    sata_addr->pmport, sata_addr->qual);

	if (sdinfo == NULL) {
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_addr->cport)));
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_create_target_node: no sdinfo for target %x",
		    target));
		return (NULL);
	}

	/*
	 * create or get scsi inquiry data, expected by
	 * scsi_hba_nodename_compatible_get()
	 * SATA hard disks get Identify Data translated into Inguiry Data.
	 * ATAPI devices respond directly to Inquiry request.
	 */
	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
		sata_identdev_to_inquiry(sata_hba_inst, sdinfo,
		    (uint8_t *)&inq);
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_addr->cport)));
	} else { /* Assume supported ATAPI device */
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_addr->cport)));
		if (sata_get_atapi_inquiry_data(sata_hba_inst, sata_addr,
		    &inq) == SATA_FAILURE)
			return (NULL);
		/*
		 * Save supported ATAPI transport version
		 */
		sdinfo->satadrv_atapi_trans_ver =
		    SATA_ATAPI_TRANS_VERSION(&inq);
	}

	/* determine the node name and compatible */
	scsi_hba_nodename_compatible_get(&inq, NULL,
	    inq.inq_dtype, NULL, &nname, &compatible, &ncompatible);

#ifdef SATA_DEBUG
	if (sata_debug_flags & SATA_DBG_NODES) {
		if (nname == NULL) {
			cmn_err(CE_NOTE, "sata_create_target_node: "
			    "cannot determine nodename for target %d\n",
			    target);
		} else {
			cmn_err(CE_WARN, "sata_create_target_node: "
			    "target %d nodename: %s\n", target, nname);
		}
		if (compatible == NULL) {
			cmn_err(CE_WARN,
			    "sata_create_target_node: no compatible name\n");
		} else {
			for (i = 0; i < ncompatible; i++) {
				cmn_err(CE_WARN, "sata_create_target_node: "
				    "compatible name: %s\n", compatible[i]);
			}
		}
	}
#endif

	/* if nodename can't be determined, log error and exit */
	if (nname == NULL) {
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_create_target_node: cannot determine nodename "
		    "for target %d\n", target));
		scsi_hba_nodename_compatible_free(nname, compatible);
		return (NULL);
	}
	/*
	 * Create scsi target node
	 */
	ndi_devi_alloc_sleep(dip, nname, (pnode_t)DEVI_SID_NODEID, &cdip);
	rval = ndi_prop_update_string(DDI_DEV_T_NONE, cdip,
	    "device-type", "scsi");

	if (rval != DDI_PROP_SUCCESS) {
		SATA_LOG_D((sata_hba_inst, CE_WARN, "sata_create_target_node: "
		    "updating device_type prop failed %d", rval));
		goto fail;
	}

	/*
	 * Create target node properties: target & lun
	 */
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, cdip, "target", target);
	if (rval != DDI_PROP_SUCCESS) {
		SATA_LOG_D((sata_hba_inst, CE_WARN, "sata_create_target_node: "
		    "updating target prop failed %d", rval));
		goto fail;
	}
	rval = ndi_prop_update_int(DDI_DEV_T_NONE, cdip, "lun", 0);
	if (rval != DDI_PROP_SUCCESS) {
		SATA_LOG_D((sata_hba_inst, CE_WARN, "sata_create_target_node: "
		    "updating target prop failed %d", rval));
		goto fail;
	}

	if (sdinfo->satadrv_type == SATA_DTYPE_ATAPICD) {
		/*
		 * Add "variant" property
		 */
		rval = ndi_prop_update_string(DDI_DEV_T_NONE, cdip,
		    "variant", "atapi");
		if (rval != DDI_PROP_SUCCESS) {
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "sata_create_target_node: variant atapi "
			    "property could not be created: %d", rval));
			goto fail;
		}
	}
	/* decorate the node with compatible */
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, cdip, "compatible",
	    compatible, ncompatible) != DDI_PROP_SUCCESS) {
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_create_target_node: FAIL compatible props cdip 0x%p",
		    (void *)cdip));
		goto fail;
	}


	/*
	 * Now, try to attach the driver. If probing of the device fails,
	 * the target node may be removed
	 */
	rval = ndi_devi_online(cdip, NDI_ONLINE_ATTACH);

	scsi_hba_nodename_compatible_free(nname, compatible);

	if (rval == NDI_SUCCESS)
		return (cdip);

	/* target node was removed - are we sure? */
	return (NULL);

fail:
	scsi_hba_nodename_compatible_free(nname, compatible);
	ddi_prop_remove_all(cdip);
	rval = ndi_devi_free(cdip);
	if (rval != NDI_SUCCESS) {
		SATA_LOG_D((sata_hba_inst, CE_WARN, "sata_create_target_node: "
		    "node removal failed %d", rval));
	}
	sata_log(sata_hba_inst, CE_WARN, "sata_create_target_node: "
	    "cannot create target node for SATA device at port %d",
	    sata_addr->cport);
	return (NULL);
}



/*
 * Re-probe sata port, check for a device and attach info
 * structures when necessary. Identify Device data is fetched, if possible.
 * Assumption: sata address is already validated.
 * SATA_SUCCESS is returned if port is re-probed sucessfully, regardless of
 * the presence of a device and its type.
 *
 * flag arg specifies that the function should try multiple times to identify
 * device type and to initialize it, or it should return immediately on failure.
 * SATA_DEV_IDENTIFY_RETRY - retry
 * SATA_DEV_IDENTIFY_NORETRY - no retry
 *
 * SATA_FAILURE is returned if one of the operations failed.
 *
 * This function cannot be called in interrupt context - it may sleep.
 */
static int
sata_reprobe_port(sata_hba_inst_t *sata_hba_inst, sata_device_t *sata_device,
    int flag)
{
	sata_cport_info_t *cportinfo;
	sata_drive_info_t *sdinfo;
	boolean_t init_device = B_FALSE;
	int prev_device_type = SATA_DTYPE_NONE;
	int prev_device_settings = 0;
	clock_t start_time;
	int retry = B_FALSE;
	int rval;

	/* We only care about host sata cport for now */
	cportinfo = SATA_CPORT_INFO(sata_hba_inst,
	    sata_device->satadev_addr.cport);
	sdinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);
	if (sdinfo != NULL) {
		/*
		 * We are re-probing port with a previously attached device.
		 * Save previous device type and settings
		 */
		prev_device_type = cportinfo->cport_dev_type;
		prev_device_settings = sdinfo->satadrv_settings;
	}
	if (flag == SATA_DEV_IDENTIFY_RETRY) {
		start_time = ddi_get_lbolt();
		retry = B_TRUE;
	}
retry_probe:

	/* probe port */
	mutex_enter(&cportinfo->cport_mutex);
	cportinfo->cport_state &= ~SATA_PORT_STATE_CLEAR_MASK;
	cportinfo->cport_state |= SATA_STATE_PROBING;
	mutex_exit(&cportinfo->cport_mutex);

	rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
	    (SATA_DIP(sata_hba_inst), sata_device);

	mutex_enter(&cportinfo->cport_mutex);
	if (rval != SATA_SUCCESS) {
		cportinfo->cport_state = SATA_PSTATE_FAILED;
		mutex_exit(&cportinfo->cport_mutex);
		SATA_LOG_D((sata_hba_inst, CE_WARN, "sata_reprobe_port: "
		    "SATA port %d probing failed",
		    cportinfo->cport_addr.cport));
		return (SATA_FAILURE);
	}

	/*
	 * update sata port state and set device type
	 */
	sata_update_port_info(sata_hba_inst, sata_device);
	cportinfo->cport_state &= ~SATA_STATE_PROBING;

	/*
	 * Sanity check - Port is active? Is the link active?
	 * Is there any device attached?
	 */
	if ((cportinfo->cport_state &
	    (SATA_PSTATE_SHUTDOWN | SATA_PSTATE_FAILED)) ||
	    (cportinfo->cport_scr.sstatus & SATA_PORT_DEVLINK_UP_MASK) !=
	    SATA_PORT_DEVLINK_UP) {
		/*
		 * Port in non-usable state or no link active/no device.
		 * Free info structure if necessary (direct attached drive
		 * only, for now!
		 */
		sdinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);
		SATA_CPORTINFO_DRV_INFO(cportinfo) = NULL;
		/* Add here differentiation for device attached or not */
		cportinfo->cport_dev_type = SATA_DTYPE_NONE;
		mutex_exit(&cportinfo->cport_mutex);
		if (sdinfo != NULL)
			kmem_free(sdinfo, sizeof (sata_drive_info_t));
		return (SATA_SUCCESS);
	}

	cportinfo->cport_state |= SATA_STATE_READY;
	cportinfo->cport_dev_type = sata_device->satadev_type;
	sdinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);

	/*
	 * If we are re-probing the port, there may be
	 * sata_drive_info structure attached
	 * (or sata_pm_info, if PMult is supported).
	 */
	if (sata_device->satadev_type == SATA_DTYPE_NONE) {
		/*
		 * There is no device, so remove device info structure,
		 * if necessary. Direct attached drive only!
		 */
		SATA_CPORTINFO_DRV_INFO(cportinfo) = NULL;
		cportinfo->cport_dev_type = SATA_DTYPE_NONE;
		if (sdinfo != NULL) {
			kmem_free(sdinfo, sizeof (sata_drive_info_t));
			sata_log(sata_hba_inst, CE_WARN,
			    "SATA device detached "
			    "from port %d", cportinfo->cport_addr.cport);
		}
		mutex_exit(&cportinfo->cport_mutex);
		return (SATA_SUCCESS);
	}

	if (sata_device->satadev_type != SATA_DTYPE_PMULT) {
		if (sdinfo == NULL) {
			/*
			 * There is some device attached, but there is
			 * no sata_drive_info structure - allocate one
			 */
			mutex_exit(&cportinfo->cport_mutex);
			sdinfo = kmem_zalloc(
			    sizeof (sata_drive_info_t), KM_SLEEP);
			mutex_enter(&cportinfo->cport_mutex);
			/*
			 * Recheck, that the port state did not change when we
			 * released mutex.
			 */
			if (cportinfo->cport_state & SATA_STATE_READY) {
				SATA_CPORTINFO_DRV_INFO(cportinfo) = sdinfo;
				sdinfo->satadrv_addr = cportinfo->cport_addr;
				sdinfo->satadrv_addr.qual = SATA_ADDR_DCPORT;
				sdinfo->satadrv_type = SATA_DTYPE_UNKNOWN;
				sdinfo->satadrv_state = SATA_STATE_UNKNOWN;
			} else {
				/*
				 * Port is not in ready state, we
				 * cannot attach a device.
				 */
				mutex_exit(&cportinfo->cport_mutex);
				kmem_free(sdinfo, sizeof (sata_drive_info_t));
				return (SATA_SUCCESS);
			}
			/*
			 * Since we are adding device, presumably new one,
			 * indicate that it  should be initalized,
			 * as well as some internal framework states).
			 */
			init_device = B_TRUE;
		}
		cportinfo->cport_dev_type = SATA_DTYPE_UNKNOWN;
		sata_device->satadev_addr.qual = sdinfo->satadrv_addr.qual;
	} else {
		/*
		 * The device is a port multiplier - not handled now.
		 */
		cportinfo->cport_dev_type = SATA_DTYPE_UNKNOWN;
		mutex_exit(&cportinfo->cport_mutex);
		return (SATA_SUCCESS);
	}
	mutex_exit(&cportinfo->cport_mutex);
	/*
	 * Figure out what kind of device we are really
	 * dealing with.
	 */
	rval = sata_probe_device(sata_hba_inst, sata_device);

	if (rval == SATA_SUCCESS) {
		/*
		 * If we are dealing with the same type of a device as before,
		 * restore its settings flags.
		 */
		if (sata_device->satadev_type == prev_device_type)
			sdinfo->satadrv_settings = prev_device_settings;

		/* Set initial device features, if necessary */
		if (init_device == B_TRUE) {
			rval = sata_initialize_device(sata_hba_inst, sdinfo);
		}
		if (rval == SATA_SUCCESS)
			return (rval);
	}

	if (retry) {
		clock_t cur_time = ddi_get_lbolt();
		/*
		 * A device was not successfully identified or initialized.
		 * Track retry time for device identification.
		 */
		if ((cur_time - start_time) <
		    drv_usectohz(SATA_DEV_IDENTIFY_TIMEOUT)) {
			/* sleep for a while */
			delay(drv_usectohz(SATA_DEV_IDENTIFY_RETRY_DELAY));
			goto retry_probe;
		}
	}
	return (rval);
}

/*
 * Initialize device
 * Specified device is initialized to a default state.
 *
 * Returns SATA_SUCCESS if all device features are set successfully,
 * SATA_FAILURE otherwise
 */
static int
sata_initialize_device(sata_hba_inst_t *sata_hba_inst,
    sata_drive_info_t *sdinfo)
{
	int rval;

	sata_save_drive_settings(sdinfo);

	sdinfo->satadrv_settings |= SATA_DEV_READ_AHEAD;

	sata_init_write_cache_mode(sdinfo);

	rval = sata_set_drive_features(sata_hba_inst, sdinfo, 0);

	/* Determine current data transfer mode */
	if ((sdinfo->satadrv_id.ai_cap & SATA_DMA_SUPPORT) == 0) {
		sdinfo->satadrv_settings &= ~SATA_DEV_DMA;
	} else if ((sdinfo->satadrv_id.ai_validinfo &
	    SATA_VALIDINFO_88) != 0 &&
	    (sdinfo->satadrv_id.ai_ultradma & SATA_UDMA_SEL_MASK) != 0) {
		sdinfo->satadrv_settings |= SATA_DEV_DMA;
	} else if ((sdinfo->satadrv_id.ai_dworddma &
	    SATA_MDMA_SEL_MASK) != 0) {
		sdinfo->satadrv_settings |= SATA_DEV_DMA;
	} else
		/* DMA supported, not no DMA transfer mode is selected !? */
		sdinfo->satadrv_settings &= ~SATA_DEV_DMA;

	return (rval);
}


/*
 * Initialize write cache mode.
 *
 * The default write cache setting for SATA HDD is provided by sata_write_cache
 * static variable. ATAPI CD/DVDs devices have write cache default is
 * determined by sata_atapicdvd_write_cache static variable.
 * 1 - enable
 * 0 - disable
 * any other value - current drive setting
 *
 * Although there is not reason to disable write cache on CD/DVD devices,
 * the default setting control is provided for the maximun flexibility.
 *
 * In the future, it may be overridden by the
 * disk-write-cache-enable property setting, if it is defined.
 * Returns SATA_SUCCESS if all device features are set successfully,
 * SATA_FAILURE otherwise.
 */
static void
sata_init_write_cache_mode(sata_drive_info_t *sdinfo)
{
	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
		if (sata_write_cache == 1)
			sdinfo->satadrv_settings |= SATA_DEV_WRITE_CACHE;
		else if (sata_write_cache == 0)
			sdinfo->satadrv_settings &= ~SATA_DEV_WRITE_CACHE;
		/*
		 * When sata_write_cache value is not 0 or 1,
		 * a current setting of the drive's write cache is used.
		 */
	} else { /* Assume ATAPI CD/DVD device */
		if (sata_atapicdvd_write_cache == 1)
			sdinfo->satadrv_settings |= SATA_DEV_WRITE_CACHE;
		else if (sata_atapicdvd_write_cache == 0)
			sdinfo->satadrv_settings &= ~SATA_DEV_WRITE_CACHE;
		/*
		 * When sata_write_cache value is not 0 or 1,
		 * a current setting of the drive's write cache is used.
		 */
	}
}


/*
 * Validate sata address.
 * Specified cport, pmport and qualifier has to match
 * passed sata_scsi configuration info.
 * The presence of an attached device is not verified.
 *
 * Returns 0 when address is valid, -1 otherwise.
 */
static int
sata_validate_sata_address(sata_hba_inst_t *sata_hba_inst, int cport,
	int pmport, int qual)
{
	if (qual == SATA_ADDR_DCPORT && pmport != 0)
		goto invalid_address;
	if (cport >= SATA_NUM_CPORTS(sata_hba_inst))
		goto invalid_address;
	if ((qual == SATA_ADDR_DPMPORT || qual == SATA_ADDR_PMPORT) &&
	    ((SATA_CPORT_DEV_TYPE(sata_hba_inst, cport) != SATA_DTYPE_PMULT) ||
	    (SATA_PMULT_INFO(sata_hba_inst, cport) == NULL) ||
	    (pmport >= SATA_NUM_PMPORTS(sata_hba_inst, cport))))
		goto invalid_address;

	return (0);

invalid_address:
	return (-1);

}

/*
 * Validate scsi address
 * SCSI target address is translated into SATA cport/pmport and compared
 * with a controller port/device configuration. LUN has to be 0.
 * Returns 0 if a scsi target refers to an attached device,
 * returns 1 if address is valid but device is not attached,
 * returns -1 if bad address or device is of an unsupported type.
 * Upon return sata_device argument is set.
 */
static int
sata_validate_scsi_address(sata_hba_inst_t *sata_hba_inst,
	struct scsi_address *ap, sata_device_t *sata_device)
{
	int cport, pmport, qual, rval;

	rval = -1;	/* Invalid address */
	if (ap->a_lun != 0)
		goto out;

	qual = SCSI_TO_SATA_ADDR_QUAL(ap->a_target);
	cport = SCSI_TO_SATA_CPORT(ap->a_target);
	pmport = SCSI_TO_SATA_PMPORT(ap->a_target);

	if (qual != SATA_ADDR_DCPORT && qual != SATA_ADDR_DPMPORT)
		goto out;

	if (sata_validate_sata_address(sata_hba_inst, cport, pmport, qual) ==
	    0) {

		sata_cport_info_t *cportinfo;
		sata_pmult_info_t *pmultinfo;
		sata_drive_info_t *sdinfo = NULL;

		rval = 1;	/* Valid sata address */

		cportinfo = SATA_CPORT_INFO(sata_hba_inst, cport);
		if (qual == SATA_ADDR_DCPORT) {
			if (cportinfo == NULL ||
			    cportinfo->cport_dev_type == SATA_DTYPE_NONE)
				goto out;

			if (cportinfo->cport_dev_type == SATA_DTYPE_PMULT ||
			    (cportinfo->cport_dev_type &
			    SATA_VALID_DEV_TYPE) == 0) {
				rval = -1;
				goto out;
			}
			sdinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);

		} else if (qual == SATA_ADDR_DPMPORT) {
			pmultinfo = SATA_CPORTINFO_PMULT_INFO(cportinfo);
			if (pmultinfo == NULL) {
				rval = -1;
				goto out;
			}
			if (SATA_PMPORT_INFO(sata_hba_inst, cport, pmport) ==
			    NULL ||
			    SATA_PMPORT_DEV_TYPE(sata_hba_inst, cport,
			    pmport) == SATA_DTYPE_NONE)
				goto out;

			sdinfo = SATA_PMPORT_DRV_INFO(sata_hba_inst, cport,
			    pmport);
		} else {
			rval = -1;
			goto out;
		}
		if ((sdinfo == NULL) ||
		    (sdinfo->satadrv_type & SATA_VALID_DEV_TYPE) == 0)
			goto out;

		sata_device->satadev_type = sdinfo->satadrv_type;
		sata_device->satadev_addr.qual = qual;
		sata_device->satadev_addr.cport = cport;
		sata_device->satadev_addr.pmport = pmport;
		sata_device->satadev_rev = SATA_DEVICE_REV_1;
		return (0);
	}
out:
	if (rval == 1) {
		SATADBG2(SATA_DBG_SCSI_IF, sata_hba_inst,
		    "sata_validate_scsi_address: no valid target %x lun %x",
		    ap->a_target, ap->a_lun);
	}
	return (rval);
}

/*
 * Find dip corresponding to passed device number
 *
 * Returns NULL if invalid device number is passed or device cannot be found,
 * Returns dip is device is found.
 */
static dev_info_t *
sata_devt_to_devinfo(dev_t dev)
{
	dev_info_t *dip;
#ifndef __lock_lint
	struct devnames *dnp;
	major_t major = getmajor(dev);
	int instance = SATA_MINOR2INSTANCE(getminor(dev));

	if (major >= devcnt)
		return (NULL);

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&(dnp->dn_lock));
	dip = dnp->dn_head;
	while (dip && (ddi_get_instance(dip) != instance)) {
		dip = ddi_get_next(dip);
	}
	UNLOCK_DEV_OPS(&(dnp->dn_lock));
#endif

	return (dip);
}


/*
 * Probe device.
 * This function issues Identify Device command and initializes local
 * sata_drive_info structure if the device can be identified.
 * The device type is determined by examining Identify Device
 * command response.
 * If the sata_hba_inst has linked drive info structure for this
 * device address, the Identify Device data is stored into sata_drive_info
 * structure linked to the port info structure.
 *
 * sata_device has to refer to the valid sata port(s) for HBA described
 * by sata_hba_inst structure.
 *
 * Returns:
 *	SATA_SUCCESS if device type was successfully probed and port-linked
 *		drive info structure was updated;
 * 	SATA_FAILURE if there is no device, or device was not probed
 *		successully;
 *	SATA_RETRY if device probe can be retried later.
 * If a device cannot be identified, sata_device's dev_state and dev_type
 * fields are set to unknown.
 * There are no retries in this function. Any retries should be managed by
 * the caller.
 */


static int
sata_probe_device(sata_hba_inst_t *sata_hba_inst, sata_device_t *sata_device)
{
	sata_drive_info_t *sdinfo;
	sata_drive_info_t new_sdinfo;	/* local drive info struct */
	int rval;

	ASSERT((SATA_CPORT_STATE(sata_hba_inst,
	    sata_device->satadev_addr.cport) &
	    (SATA_STATE_PROBED | SATA_STATE_READY)) != 0);

	sata_device->satadev_type = SATA_DTYPE_NONE;

	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device->satadev_addr.cport)));

	/* Get pointer to port-linked sata device info structure */
	sdinfo = sata_get_device_info(sata_hba_inst, sata_device);
	if (sdinfo != NULL) {
		sdinfo->satadrv_state &=
		    ~(SATA_STATE_PROBED | SATA_STATE_READY);
		sdinfo->satadrv_state |= SATA_STATE_PROBING;
	} else {
		/* No device to probe */
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device->satadev_addr.cport)));
		sata_device->satadev_type = SATA_DTYPE_NONE;
		sata_device->satadev_state = SATA_STATE_UNKNOWN;
		return (SATA_FAILURE);
	}
	/*
	 * Need to issue both types of identify device command and
	 * determine device type by examining retreived data/status.
	 * First, ATA Identify Device.
	 */
	bzero(&new_sdinfo, sizeof (sata_drive_info_t));
	new_sdinfo.satadrv_addr = sata_device->satadev_addr;
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device->satadev_addr.cport)));
	new_sdinfo.satadrv_type = SATA_DTYPE_ATADISK;
	rval = sata_identify_device(sata_hba_inst, &new_sdinfo);
	if (rval == SATA_RETRY) {
		/* We may try to check for ATAPI device */
		if (SATA_FEATURES(sata_hba_inst) & SATA_CTLF_ATAPI) {
			/*
			 * HBA supports ATAPI - try to issue Identify Packet
			 * Device command.
			 */
			new_sdinfo.satadrv_type = SATA_DTYPE_ATAPICD;
			rval = sata_identify_device(sata_hba_inst, &new_sdinfo);
		}
	}
	if (rval == SATA_SUCCESS) {
		/*
		 * Got something responding positively to ATA Identify Device
		 * or to Identify Packet Device cmd.
		 * Save last used device type.
		 */
		sata_device->satadev_type = new_sdinfo.satadrv_type;

		/* save device info, if possible */
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device->satadev_addr.cport)));
		sdinfo = sata_get_device_info(sata_hba_inst, sata_device);
		if (sdinfo == NULL) {
			mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
			    sata_device->satadev_addr.cport)));
			return (SATA_FAILURE);
		}
		/*
		 * Copy drive info into the port-linked drive info structure.
		 */
		*sdinfo = new_sdinfo;
		sdinfo->satadrv_state &= ~SATA_STATE_PROBING;
		sdinfo->satadrv_state |= SATA_STATE_PROBED;
		if (sata_device->satadev_addr.qual == SATA_ADDR_DCPORT)
			SATA_CPORT_DEV_TYPE(sata_hba_inst,
			    sata_device->satadev_addr.cport) =
			    sdinfo->satadrv_type;
		else /* SATA_ADDR_DPMPORT */
			SATA_PMPORT_DEV_TYPE(sata_hba_inst,
			    sata_device->satadev_addr.cport,
			    sata_device->satadev_addr.pmport) =
			    sdinfo->satadrv_type;
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sata_device->satadev_addr.cport)));
		return (SATA_SUCCESS);
	}

	/*
	 * It may be SATA_RETRY or SATA_FAILURE return.
	 * Looks like we cannot determine the device type at this time.
	 */
	mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device->satadev_addr.cport)));
	sdinfo = sata_get_device_info(sata_hba_inst, sata_device);
	if (sdinfo != NULL) {
		sata_device->satadev_type = SATA_DTYPE_UNKNOWN;
		sdinfo->satadrv_type = SATA_DTYPE_UNKNOWN;
		sdinfo->satadrv_state &= ~SATA_STATE_PROBING;
		sdinfo->satadrv_state = SATA_STATE_PROBED;
		if (sata_device->satadev_addr.qual == SATA_ADDR_DCPORT)
			SATA_CPORT_DEV_TYPE(sata_hba_inst,
			    sata_device->satadev_addr.cport) =
			    SATA_DTYPE_UNKNOWN;
		else {
			/* SATA_ADDR_DPMPORT */
			if ((SATA_PMULT_INFO(sata_hba_inst,
			    sata_device->satadev_addr.cport) != NULL) &&
			    (SATA_PMPORT_INFO(sata_hba_inst,
			    sata_device->satadev_addr.cport,
			    sata_device->satadev_addr.pmport) != NULL))
				SATA_PMPORT_DEV_TYPE(sata_hba_inst,
				    sata_device->satadev_addr.cport,
				    sata_device->satadev_addr.pmport) =
				    SATA_DTYPE_UNKNOWN;
		}
	}
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device->satadev_addr.cport)));
	return (rval);
}


/*
 * Get pointer to sata_drive_info structure.
 *
 * The sata_device has to contain address (cport, pmport and qualifier) for
 * specified sata_scsi structure.
 *
 * Returns NULL if device address is not valid for this HBA configuration.
 * Otherwise, returns a pointer to sata_drive_info structure.
 *
 * This function should be called with a port mutex held.
 */
static sata_drive_info_t *
sata_get_device_info(sata_hba_inst_t *sata_hba_inst,
    sata_device_t *sata_device)
{
	uint8_t cport = sata_device->satadev_addr.cport;
	uint8_t pmport = sata_device->satadev_addr.pmport;
	uint8_t qual = sata_device->satadev_addr.qual;

	if (cport >= SATA_NUM_CPORTS(sata_hba_inst))
		return (NULL);

	if (!(SATA_CPORT_STATE(sata_hba_inst, cport) &
	    (SATA_STATE_PROBED | SATA_STATE_READY)))
		/* Port not probed yet */
		return (NULL);

	if (SATA_CPORT_DEV_TYPE(sata_hba_inst, cport) == SATA_DTYPE_NONE)
		return (NULL);

	if (qual == SATA_ADDR_DCPORT) {
		/* Request for a device on a controller port */
		if (SATA_CPORT_DEV_TYPE(sata_hba_inst, cport) ==
		    SATA_DTYPE_PMULT)
			/* Port multiplier attached */
			return (NULL);
		return (SATA_CPORT_DRV_INFO(sata_hba_inst, cport));
	}
	if (qual == SATA_ADDR_DPMPORT) {
		if (SATA_CPORT_DEV_TYPE(sata_hba_inst, cport) !=
		    SATA_DTYPE_PMULT)
			return (NULL);

		if (pmport > SATA_NUM_PMPORTS(sata_hba_inst, cport))
			return (NULL);

		return (SATA_PMPORT_DRV_INFO(sata_hba_inst, cport, pmport));
	}

	/* we should not get here */
	return (NULL);
}


/*
 * sata_identify_device.
 * Send Identify Device command to SATA HBA driver.
 * If command executes successfully, update sata_drive_info structure pointed
 * to by sdinfo argument, including Identify Device data.
 * If command fails, invalidate data in sata_drive_info.
 *
 * Cannot be called from interrupt level.
 *
 * Returns:
 * SATA_SUCCESS if the device was identified as a supported device,
 * SATA_RETRY if the device was not identified but could be retried,
 * SATA_FAILURE if the device was not identified and identify attempt
 *	should not be retried.
 */
static int
sata_identify_device(sata_hba_inst_t *sata_hba_inst,
    sata_drive_info_t *sdinfo)
{
	uint16_t cfg_word;
	int rval;

	/* fetch device identify data */
	if ((rval = sata_fetch_device_identify_data(sata_hba_inst,
	    sdinfo)) != 0)
		goto fail_unknown;

	cfg_word = sdinfo->satadrv_id.ai_config;
	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK &&
	    (cfg_word & SATA_ATA_TYPE_MASK) != SATA_ATA_TYPE) {
		/* Change device type to reflect Identify Device data */
		if (((cfg_word & SATA_ATAPI_TYPE_MASK) ==
		    SATA_ATAPI_TYPE) &&
		    ((cfg_word & SATA_ATAPI_ID_DEV_TYPE) ==
		    SATA_ATAPI_CDROM_DEV)) {
			sdinfo->satadrv_type = SATA_DTYPE_ATAPICD;
		} else {
			sdinfo->satadrv_type = SATA_DTYPE_UNKNOWN;
		}
	} else if (sdinfo->satadrv_type == SATA_DTYPE_ATAPICD &&
	    (((cfg_word & SATA_ATAPI_TYPE_MASK) != SATA_ATAPI_TYPE) ||
	    ((cfg_word & SATA_ATAPI_ID_DEV_TYPE) != SATA_ATAPI_CDROM_DEV))) {
		/* Change device type to reflect Identify Device data ! */
		if ((sdinfo->satadrv_id.ai_config & SATA_ATA_TYPE_MASK) ==
		    SATA_ATA_TYPE) {
			sdinfo->satadrv_type = SATA_DTYPE_ATADISK;
		} else {
			sdinfo->satadrv_type = SATA_DTYPE_UNKNOWN;
		}
	}
	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
		if (sdinfo->satadrv_capacity == 0) {
			/* Non-LBA disk. Too bad... */
			sata_log(sata_hba_inst, CE_WARN,
			    "SATA disk device at port %d does not support LBA",
			    sdinfo->satadrv_addr.cport);
			rval = SATA_FAILURE;
			goto fail_unknown;
		}
	}
#if 0
	/* Left for historical reason */
	/*
	 * Some initial version of SATA spec indicated that at least
	 * UDMA mode 4 has to be supported. It is not metioned in
	 * SerialATA 2.6, so this restriction is removed.
	 */
	/* Check for Ultra DMA modes 6 through 0 being supported */
	for (i = 6; i >= 0; --i) {
		if (sdinfo->satadrv_id.ai_ultradma & (1 << i))
			break;
	}

	/*
	 * At least UDMA 4 mode has to be supported. If mode 4 or
	 * higher are not supported by the device, fail this
	 * device.
	 */
	if (i < 4) {
		/* No required Ultra DMA mode supported */
		sata_log(sata_hba_inst, CE_WARN,
		    "SATA disk device at port %d does not support UDMA "
		    "mode 4 or higher", sdinfo->satadrv_addr.cport);
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "mode 4 or higher required, %d supported", i));
		rval = SATA_FAILURE;
		goto fail_unknown;
	}
#endif

	return (SATA_SUCCESS);

fail_unknown:
	/* Invalidate sata_drive_info ? */
	sdinfo->satadrv_type = SATA_DTYPE_UNKNOWN;
	sdinfo->satadrv_state = SATA_STATE_UNKNOWN;
	return (rval);
}

/*
 * Log/display device information
 */
static void
sata_show_drive_info(sata_hba_inst_t *sata_hba_inst,
    sata_drive_info_t *sdinfo)
{
	int valid_version;
	char msg_buf[MAXPATHLEN];
	int i;

	/* Show HBA path */
	(void) ddi_pathname(SATA_DIP(sata_hba_inst), msg_buf);

	cmn_err(CE_CONT, "?%s :\n", msg_buf);

	if (sdinfo->satadrv_type == SATA_DTYPE_UNKNOWN) {
		(void) sprintf(msg_buf,
		    "Unsupported SATA device type (cfg 0x%x) at ",
		    sdinfo->satadrv_id.ai_config);
	} else {
		(void) sprintf(msg_buf, "SATA %s device at",
		    sdinfo->satadrv_type == SATA_DTYPE_ATADISK ?
		    "disk":"CD/DVD (ATAPI)");
	}
	if (sdinfo->satadrv_addr.qual == SATA_ADDR_DCPORT)
		cmn_err(CE_CONT, "?\t%s port %d\n",
		    msg_buf, sdinfo->satadrv_addr.cport);
	else
		cmn_err(CE_CONT, "?\t%s port %d pmport %d\n",
		    msg_buf, sdinfo->satadrv_addr.cport,
		    sdinfo->satadrv_addr.pmport);

	bcopy(&sdinfo->satadrv_id.ai_model, msg_buf,
	    sizeof (sdinfo->satadrv_id.ai_model));
	swab(msg_buf, msg_buf, sizeof (sdinfo->satadrv_id.ai_model));
	msg_buf[sizeof (sdinfo->satadrv_id.ai_model)] = '\0';
	cmn_err(CE_CONT, "?\tmodel %s\n", msg_buf);

	bcopy(&sdinfo->satadrv_id.ai_fw, msg_buf,
	    sizeof (sdinfo->satadrv_id.ai_fw));
	swab(msg_buf, msg_buf, sizeof (sdinfo->satadrv_id.ai_fw));
	msg_buf[sizeof (sdinfo->satadrv_id.ai_fw)] = '\0';
	cmn_err(CE_CONT, "?\tfirmware %s\n", msg_buf);

	bcopy(&sdinfo->satadrv_id.ai_drvser, msg_buf,
	    sizeof (sdinfo->satadrv_id.ai_drvser));
	swab(msg_buf, msg_buf, sizeof (sdinfo->satadrv_id.ai_drvser));
	msg_buf[sizeof (sdinfo->satadrv_id.ai_drvser)] = '\0';
	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
		cmn_err(CE_CONT, "?\tserial number %s\n", msg_buf);
	} else {
		/* Assuming ATAPI CD/DVD */
		/*
		 * SOme drives do not implement serial number and may
		 * violate the spec by provinding spaces rather than zeros
		 * in serial number field. Scan the buffer to detect it.
		 */
		for (i = 0; i < sizeof (sdinfo->satadrv_id.ai_drvser); i++) {
			if (msg_buf[i] != '\0' && msg_buf[i] != ' ')
				break;
		}
		if (i == sizeof (sdinfo->satadrv_id.ai_drvser)) {
			cmn_err(CE_CONT, "?\tserial number - none\n");
		} else {
			cmn_err(CE_CONT, "?\tserial number %s\n", msg_buf);
		}
	}

#ifdef SATA_DEBUG
	if (sdinfo->satadrv_id.ai_majorversion != 0 &&
	    sdinfo->satadrv_id.ai_majorversion != 0xffff) {
		int i;
		for (i = 14; i >= 2; i--) {
			if (sdinfo->satadrv_id.ai_majorversion & (1 << i)) {
				valid_version = i;
				break;
			}
		}
		cmn_err(CE_CONT,
		    "?\tATA/ATAPI-%d supported, majver 0x%x minver 0x%x\n",
		    valid_version,
		    sdinfo->satadrv_id.ai_majorversion,
		    sdinfo->satadrv_id.ai_minorversion);
	}
#endif
	/* Log some info */
	cmn_err(CE_CONT, "?\tsupported features:\n");
	msg_buf[0] = '\0';
	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
		if (sdinfo->satadrv_features_support & SATA_DEV_F_LBA48)
			(void) strlcat(msg_buf, "48-bit LBA, ", MAXPATHLEN);
		else if (sdinfo->satadrv_features_support & SATA_DEV_F_LBA28)
			(void) strlcat(msg_buf, "28-bit LBA, ", MAXPATHLEN);
	}
	if (sdinfo->satadrv_features_support & SATA_DEV_F_DMA)
		(void) strlcat(msg_buf, "DMA", MAXPATHLEN);
	if (sdinfo->satadrv_features_support & SATA_DEV_F_NCQ)
		(void) strlcat(msg_buf, ", Native Command Queueing",
		    MAXPATHLEN);
	if (sdinfo->satadrv_features_support & SATA_DEV_F_TCQ)
		(void) strlcat(msg_buf, ", Legacy Tagged Queuing", MAXPATHLEN);
	if ((sdinfo->satadrv_id.ai_cmdset82 & SATA_SMART_SUPPORTED) &&
	    (sdinfo->satadrv_id.ai_features85 & SATA_SMART_ENABLED))
		(void) strlcat(msg_buf, ", SMART", MAXPATHLEN);
	if ((sdinfo->satadrv_id.ai_cmdset84 & SATA_SMART_SELF_TEST_SUPPORTED) &&
	    (sdinfo->satadrv_id.ai_features87 & SATA_SMART_SELF_TEST_SUPPORTED))
		(void) strlcat(msg_buf, ", SMART self-test", MAXPATHLEN);
	cmn_err(CE_CONT, "?\t %s\n", msg_buf);
	if (sdinfo->satadrv_features_support & SATA_DEV_F_SATA2)
		cmn_err(CE_CONT, "?\tSATA Gen2 signaling speed (3.0Gbps)\n");
	else if (sdinfo->satadrv_features_support & SATA_DEV_F_SATA1)
		cmn_err(CE_CONT, "?\tSATA Gen1 signaling speed (1.5Gbps)\n");
	if (sdinfo->satadrv_features_support &
	    (SATA_DEV_F_TCQ | SATA_DEV_F_NCQ)) {
		msg_buf[0] = '\0';
		(void) snprintf(msg_buf, MAXPATHLEN,
		    "Supported queue depth %d",
		    sdinfo->satadrv_queue_depth);
		if (!(sata_func_enable &
		    (SATA_ENABLE_QUEUING | SATA_ENABLE_NCQ)))
			(void) strlcat(msg_buf,
			    " - queueing disabled globally", MAXPATHLEN);
		else if (sdinfo->satadrv_queue_depth >
		    sdinfo->satadrv_max_queue_depth) {
			(void) snprintf(&msg_buf[strlen(msg_buf)],
			    MAXPATHLEN - strlen(msg_buf), ", limited to %d",
			    (int)sdinfo->satadrv_max_queue_depth);
		}
		cmn_err(CE_CONT, "?\t%s\n", msg_buf);
	}

	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
#ifdef __i386
		(void) sprintf(msg_buf, "\tcapacity = %llu sectors\n",
		    sdinfo->satadrv_capacity);
#else
		(void) sprintf(msg_buf, "\tcapacity = %lu sectors\n",
		    sdinfo->satadrv_capacity);
#endif
		cmn_err(CE_CONT, "?%s", msg_buf);
	}
}


/*
 * sata_save_drive_settings extracts current setting of the device and stores
 * it for future reference, in case the device setup would need to be restored
 * after the device reset.
 *
 * For all devices read ahead and write cache settings are saved, if the
 * device supports these features at all.
 * For ATAPI devices the Removable Media Status Notification setting is saved.
 */
static void
sata_save_drive_settings(sata_drive_info_t *sdinfo)
{
	if ((sdinfo->satadrv_id.ai_cmdset82 & SATA_LOOK_AHEAD) ||
	    (sdinfo->satadrv_id.ai_cmdset82 & SATA_WRITE_CACHE)) {

		/* Current setting of Read Ahead (and Read Cache) */
		if (sdinfo->satadrv_id.ai_features85 & SATA_LOOK_AHEAD)
			sdinfo->satadrv_settings |= SATA_DEV_READ_AHEAD;
		else
			sdinfo->satadrv_settings &= ~SATA_DEV_READ_AHEAD;

		/* Current setting of Write Cache */
		if (sdinfo->satadrv_id.ai_features85 & SATA_WRITE_CACHE)
			sdinfo->satadrv_settings |= SATA_DEV_WRITE_CACHE;
		else
			sdinfo->satadrv_settings &= ~SATA_DEV_WRITE_CACHE;
	}

	if (sdinfo->satadrv_type == SATA_DTYPE_ATAPICD) {
		if (sdinfo->satadrv_id.ai_cmdset83 & SATA_RM_STATUS_NOTIFIC)
			sdinfo->satadrv_settings |= SATA_DEV_RMSN;
		else
			sdinfo->satadrv_settings &= ~SATA_DEV_RMSN;
	}
}


/*
 * sata_check_capacity function determines a disk capacity
 * and addressing mode (LBA28/LBA48) by examining a disk identify device data.
 *
 * NOTE: CHS mode is not supported! If a device does not support LBA,
 * this function is not called.
 *
 * Returns device capacity in number of blocks, i.e. largest addressable LBA+1
 */
static uint64_t
sata_check_capacity(sata_drive_info_t *sdinfo)
{
	uint64_t capacity = 0;
	int i;

	if (sdinfo->satadrv_type != SATA_DTYPE_ATADISK ||
	    !sdinfo->satadrv_id.ai_cap & SATA_LBA_SUPPORT)
		/* Capacity valid only for LBA-addressable disk devices */
		return (0);

	if ((sdinfo->satadrv_id.ai_validinfo & SATA_VALIDINFO_88) &&
	    (sdinfo->satadrv_id.ai_cmdset83 & SATA_EXT48) &&
	    (sdinfo->satadrv_id.ai_features86 & SATA_EXT48)) {
		/* LBA48 mode supported and enabled */
		sdinfo->satadrv_features_support |= SATA_DEV_F_LBA48 |
		    SATA_DEV_F_LBA28;
		for (i = 3;  i >= 0;  --i) {
			capacity <<= 16;
			capacity += sdinfo->satadrv_id.ai_addrsecxt[i];
		}
	} else {
		capacity = sdinfo->satadrv_id.ai_addrsec[1];
		capacity <<= 16;
		capacity += sdinfo->satadrv_id.ai_addrsec[0];
		if (capacity >= 0x1000000)
			/* LBA28 mode */
			sdinfo->satadrv_features_support |= SATA_DEV_F_LBA28;
	}
	return (capacity);
}


/*
 * Allocate consistent buffer for DMA transfer
 *
 * Cannot be called from interrupt level or with mutex held - it may sleep.
 *
 * Returns pointer to allocated buffer structure, or NULL if allocation failed.
 */
static struct buf *
sata_alloc_local_buffer(sata_pkt_txlate_t *spx, int len)
{
	struct scsi_address ap;
	struct buf *bp;
	ddi_dma_attr_t	cur_dma_attr;

	ASSERT(spx->txlt_sata_pkt != NULL);
	ap.a_hba_tran = spx->txlt_sata_hba_inst->satahba_scsi_tran;
	ap.a_target = SATA_TO_SCSI_TARGET(
	    spx->txlt_sata_pkt->satapkt_device.satadev_addr.cport,
	    spx->txlt_sata_pkt->satapkt_device.satadev_addr.pmport,
	    spx->txlt_sata_pkt->satapkt_device.satadev_addr.qual);
	ap.a_lun = 0;

	bp = scsi_alloc_consistent_buf(&ap, NULL, len,
	    B_READ, SLEEP_FUNC, NULL);

	if (bp != NULL) {
		/* Allocate DMA resources for this buffer */
		spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp = bp;
		/*
		 * We use a local version of the dma_attr, to account
		 * for a device addressing limitations.
		 * sata_adjust_dma_attr() will handle sdinfo == NULL which
		 * will cause dma attributes to be adjusted to a lowest
		 * acceptable level.
		 */
		sata_adjust_dma_attr(NULL,
		    SATA_DMA_ATTR(spx->txlt_sata_hba_inst), &cur_dma_attr);

		if (sata_dma_buf_setup(spx, PKT_CONSISTENT,
		    SLEEP_FUNC, NULL, &cur_dma_attr) != DDI_SUCCESS) {
			scsi_free_consistent_buf(bp);
			spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp = NULL;
			bp = NULL;
		}
	}
	return (bp);
}

/*
 * Release local buffer (consistent buffer for DMA transfer) allocated
 * via sata_alloc_local_buffer().
 */
static void
sata_free_local_buffer(sata_pkt_txlate_t *spx)
{
	ASSERT(spx->txlt_sata_pkt != NULL);
	ASSERT(spx->txlt_dma_cookie_list != NULL);
	ASSERT(spx->txlt_dma_cookie_list_len != 0);
	ASSERT(spx->txlt_buf_dma_handle != NULL);
	ASSERT(spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp != NULL);

	spx->txlt_sata_pkt->satapkt_cmd.satacmd_num_dma_cookies = 0;
	spx->txlt_sata_pkt->satapkt_cmd.satacmd_dma_cookie_list = NULL;

	/* Free DMA resources */
	(void) ddi_dma_unbind_handle(spx->txlt_buf_dma_handle);
	ddi_dma_free_handle(&spx->txlt_buf_dma_handle);
	spx->txlt_buf_dma_handle = 0;

	if (spx->txlt_dma_cookie_list != &spx->txlt_dma_cookie) {
		kmem_free(spx->txlt_dma_cookie_list,
		    spx->txlt_dma_cookie_list_len * sizeof (ddi_dma_cookie_t));
		spx->txlt_dma_cookie_list = NULL;
		spx->txlt_dma_cookie_list_len = 0;
	}
	/* Free buffer */
	scsi_free_consistent_buf(spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp);
	spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp = NULL;
}




/*
 * Allocate sata_pkt
 * Pkt structure version and embedded strcutures version are initialized.
 * sata_pkt and sata_pkt_txlate structures are cross-linked.
 *
 * Since this may be called in interrupt context by sata_scsi_init_pkt,
 * callback argument determines if it can sleep or not.
 * Hence, it should not be called from interrupt context.
 *
 * If successful, non-NULL pointer to a sata pkt is returned.
 * Upon failure, NULL pointer is returned.
 */
static sata_pkt_t *
sata_pkt_alloc(sata_pkt_txlate_t *spx, int (*callback)(caddr_t))
{
	sata_pkt_t *spkt;
	int kmsflag;

	kmsflag = (callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP;
	spkt = kmem_zalloc(sizeof (sata_pkt_t), kmsflag);
	if (spkt == NULL) {
		SATA_LOG_D((spx->txlt_sata_hba_inst, CE_WARN,
		    "sata_pkt_alloc: failed"));
		return (NULL);
	}
	spkt->satapkt_rev = SATA_PKT_REV;
	spkt->satapkt_cmd.satacmd_rev = SATA_CMD_REV;
	spkt->satapkt_device.satadev_rev = SATA_DEVICE_REV;
	spkt->satapkt_framework_private = spx;
	spx->txlt_sata_pkt = spkt;
	return (spkt);
}

/*
 * Free sata pkt allocated via sata_pkt_alloc()
 */
static void
sata_pkt_free(sata_pkt_txlate_t *spx)
{
	ASSERT(spx->txlt_sata_pkt != NULL);
	ASSERT(spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp == NULL);
	kmem_free(spx->txlt_sata_pkt, sizeof (sata_pkt_t));
	spx->txlt_sata_pkt = NULL;
}


/*
 * Adjust DMA attributes.
 * SCSI cmds block count is up to 24 bits, SATA cmd block count vary
 * from 8 bits to 16 bits, depending on a command being used.
 * Limiting max block count arbitrarily to 256 for all read/write
 * commands may affects performance, so check both the device and
 * controller capability before adjusting dma attributes.
 */
void
sata_adjust_dma_attr(sata_drive_info_t *sdinfo, ddi_dma_attr_t *dma_attr,
    ddi_dma_attr_t *adj_dma_attr)
{
	uint32_t count_max;

	/* Copy original attributes */
	*adj_dma_attr = *dma_attr;
	/*
	 * Things to consider: device addressing capability,
	 * "excessive" controller DMA capabilities.
	 * If a device is being probed/initialized, there are
	 * no device info - use default limits then.
	 */
	if (sdinfo == NULL) {
		count_max = dma_attr->dma_attr_granular * 0x100;
		if (dma_attr->dma_attr_count_max > count_max)
			adj_dma_attr->dma_attr_count_max = count_max;
		if (dma_attr->dma_attr_maxxfer > count_max)
			adj_dma_attr->dma_attr_maxxfer = count_max;
		return;
	}

	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
		if (sdinfo->satadrv_features_support & (SATA_DEV_F_LBA48)) {
			/*
			 * 16-bit sector count may be used - we rely on
			 * the assumption that only read and write cmds
			 * will request more than 256 sectors worth of data
			 */
			count_max = adj_dma_attr->dma_attr_granular * 0x10000;
		} else {
			/*
			 * 8-bit sector count will be used - default limits
			 * for dma attributes
			 */
			count_max = adj_dma_attr->dma_attr_granular * 0x100;
		}
		/*
		 * Adjust controler dma attributes, if necessary
		 */
		if (dma_attr->dma_attr_count_max > count_max)
			adj_dma_attr->dma_attr_count_max = count_max;
		if (dma_attr->dma_attr_maxxfer > count_max)
			adj_dma_attr->dma_attr_maxxfer = count_max;
	}
}


/*
 * Allocate DMA resources for the buffer
 * This function handles initial DMA resource allocation as well as
 * DMA window shift and may be called repeatedly for the same DMA window
 * until all DMA cookies in the DMA window are processed.
 * To guarantee that there is always a coherent set of cookies to process
 * by SATA HBA driver (observing alignment, device granularity, etc.),
 * the number of slots for DMA cookies is equal to lesser of  a number of
 * cookies in a DMA window and a max number of scatter/gather entries.
 *
 * Returns DDI_SUCCESS upon successful operation.
 * Return failure code of a failing command or DDI_FAILURE when
 * internal cleanup failed.
 */
static int
sata_dma_buf_setup(sata_pkt_txlate_t *spx, int flags,
    int (*callback)(caddr_t), caddr_t arg,
    ddi_dma_attr_t *cur_dma_attr)
{
	int	rval;
	off_t	offset;
	size_t	size;
	int	max_sg_len, req_len, i;
	uint_t	dma_flags;
	struct buf	*bp;
	uint64_t	cur_txfer_len;


	ASSERT(spx->txlt_sata_pkt != NULL);
	bp = spx->txlt_sata_pkt->satapkt_cmd.satacmd_bp;
	ASSERT(bp != NULL);


	if (spx->txlt_buf_dma_handle == NULL) {
		/*
		 * No DMA resources allocated so far - this is a first call
		 * for this sata pkt.
		 */
		rval = ddi_dma_alloc_handle(SATA_DIP(spx->txlt_sata_hba_inst),
		    cur_dma_attr, callback, arg, &spx->txlt_buf_dma_handle);

		if (rval != DDI_SUCCESS) {
			SATA_LOG_D((spx->txlt_sata_hba_inst, CE_WARN,
			    "sata_dma_buf_setup: no buf DMA resources %x",
			    rval));
			return (rval);
		}

		if (bp->b_flags & B_READ)
			dma_flags = DDI_DMA_READ;
		else
			dma_flags = DDI_DMA_WRITE;

		if (flags & PKT_CONSISTENT)
			dma_flags |= DDI_DMA_CONSISTENT;

		if (flags & PKT_DMA_PARTIAL)
			dma_flags |= DDI_DMA_PARTIAL;

		/*
		 * Check buffer alignment and size against dma attributes
		 * Consider dma_attr_align only. There may be requests
		 * with the size lower than device granularity, but they
		 * will not read/write from/to the device, so no adjustment
		 * is necessary. The dma_attr_minxfer theoretically should
		 * be considered, but no HBA driver is checking it.
		 */
		if (IS_P2ALIGNED(bp->b_un.b_addr,
		    cur_dma_attr->dma_attr_align)) {
			rval = ddi_dma_buf_bind_handle(
			    spx->txlt_buf_dma_handle,
			    bp, dma_flags, callback, arg,
			    &spx->txlt_dma_cookie,
			    &spx->txlt_curwin_num_dma_cookies);
		} else { /* Buffer is not aligned */

			int	(*ddicallback)(caddr_t);
			size_t	bufsz;

			/* Check id sleeping is allowed */
			ddicallback = (callback == NULL_FUNC) ?
			    DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

			SATADBG2(SATA_DBG_DMA_SETUP, spx->txlt_sata_hba_inst,
			    "mis-aligned buffer: addr=0x%p, cnt=%lu",
			    (void *)bp->b_un.b_addr, bp->b_bcount);

			if (bp->b_flags & (B_PAGEIO|B_PHYS))
				/*
				 * CPU will need to access data in the buffer
				 * (for copying) so map it.
				 */
				bp_mapin(bp);

			ASSERT(spx->txlt_tmp_buf == NULL);

			/* Buffer may be padded by ddi_dma_mem_alloc()! */
			rval = ddi_dma_mem_alloc(
			    spx->txlt_buf_dma_handle,
			    bp->b_bcount,
			    &sata_acc_attr,
			    DDI_DMA_STREAMING,
			    ddicallback, NULL,
			    &spx->txlt_tmp_buf,
			    &bufsz,
			    &spx->txlt_tmp_buf_handle);

			if (rval != DDI_SUCCESS) {
				/* DMA mapping failed */
				(void) ddi_dma_free_handle(
				    &spx->txlt_buf_dma_handle);
				spx->txlt_buf_dma_handle = NULL;
#ifdef SATA_DEBUG
				mbuffail_count++;
#endif
				SATADBG1(SATA_DBG_DMA_SETUP,
				    spx->txlt_sata_hba_inst,
				    "sata_dma_buf_setup: "
				    "buf dma mem alloc failed %x\n", rval);
				return (rval);
			}
			ASSERT(IS_P2ALIGNED(spx->txlt_tmp_buf,
			    cur_dma_attr->dma_attr_align));

#ifdef SATA_DEBUG
			mbuf_count++;

			if (bp->b_bcount != bufsz)
				/*
				 * This will require special handling, because
				 * DMA cookies will be based on the temporary
				 * buffer size, not the original buffer
				 * b_bcount, so the residue may have to
				 * be counted differently.
				 */
				SATADBG2(SATA_DBG_DMA_SETUP,
				    spx->txlt_sata_hba_inst,
				    "sata_dma_buf_setup: bp size %x != "
				    "bufsz %x\n", bp->b_bcount, bufsz);
#endif
			if (dma_flags & DDI_DMA_WRITE) {
				/*
				 * Write operation - copy data into
				 * an aligned temporary buffer. Buffer will be
				 * synced for device by ddi_dma_addr_bind_handle
				 */
				bcopy(bp->b_un.b_addr, spx->txlt_tmp_buf,
				    bp->b_bcount);
			}

			rval = ddi_dma_addr_bind_handle(
			    spx->txlt_buf_dma_handle,
			    NULL,
			    spx->txlt_tmp_buf,
			    bufsz, dma_flags, ddicallback, 0,
			    &spx->txlt_dma_cookie,
			    &spx->txlt_curwin_num_dma_cookies);
		}

		switch (rval) {
		case DDI_DMA_PARTIAL_MAP:
			SATADBG1(SATA_DBG_DMA_SETUP, spx->txlt_sata_hba_inst,
			    "sata_dma_buf_setup: DMA Partial Map\n", NULL);
			/*
			 * Partial DMA mapping.
			 * Retrieve number of DMA windows for this request.
			 */
			if (ddi_dma_numwin(spx->txlt_buf_dma_handle,
			    &spx->txlt_num_dma_win) != DDI_SUCCESS) {
				if (spx->txlt_tmp_buf != NULL) {
					ddi_dma_mem_free(
					    &spx->txlt_tmp_buf_handle);
					spx->txlt_tmp_buf = NULL;
				}
				(void) ddi_dma_unbind_handle(
				    spx->txlt_buf_dma_handle);
				(void) ddi_dma_free_handle(
				    &spx->txlt_buf_dma_handle);
				spx->txlt_buf_dma_handle = NULL;
				SATA_LOG_D((spx->txlt_sata_hba_inst, CE_WARN,
				    "sata_dma_buf_setup: numwin failed\n"));
				return (DDI_FAILURE);
			}
			SATADBG2(SATA_DBG_DMA_SETUP,
			    spx->txlt_sata_hba_inst,
			    "sata_dma_buf_setup: windows: %d, cookies: %d\n",
			    spx->txlt_num_dma_win,
			    spx->txlt_curwin_num_dma_cookies);
			spx->txlt_cur_dma_win = 0;
			break;

		case DDI_DMA_MAPPED:
			/* DMA fully mapped */
			spx->txlt_num_dma_win = 1;
			spx->txlt_cur_dma_win = 0;
			SATADBG1(SATA_DBG_DMA_SETUP,
			    spx->txlt_sata_hba_inst,
			    "sata_dma_buf_setup: windows: 1 "
			    "cookies: %d\n", spx->txlt_curwin_num_dma_cookies);
			break;

		default:
			/* DMA mapping failed */
			if (spx->txlt_tmp_buf != NULL) {
				ddi_dma_mem_free(
				    &spx->txlt_tmp_buf_handle);
				spx->txlt_tmp_buf = NULL;
			}
			(void) ddi_dma_free_handle(&spx->txlt_buf_dma_handle);
			spx->txlt_buf_dma_handle = NULL;
			SATA_LOG_D((spx->txlt_sata_hba_inst, CE_WARN,
			    "sata_dma_buf_setup: buf dma handle binding "
			    "failed %x\n", rval));
			return (rval);
		}
		spx->txlt_curwin_processed_dma_cookies = 0;
		spx->txlt_dma_cookie_list = NULL;
	} else {
		/*
		 * DMA setup is reused. Check if we need to process more
		 * cookies in current window, or to get next window, if any.
		 */

		ASSERT(spx->txlt_curwin_processed_dma_cookies <=
		    spx->txlt_curwin_num_dma_cookies);

		if (spx->txlt_curwin_processed_dma_cookies ==
		    spx->txlt_curwin_num_dma_cookies) {
			/*
			 * All cookies from current DMA window were processed.
			 * Get next DMA window.
			 */
			spx->txlt_cur_dma_win++;
			if (spx->txlt_cur_dma_win < spx->txlt_num_dma_win) {
				(void) ddi_dma_getwin(spx->txlt_buf_dma_handle,
				    spx->txlt_cur_dma_win, &offset, &size,
				    &spx->txlt_dma_cookie,
				    &spx->txlt_curwin_num_dma_cookies);
				spx->txlt_curwin_processed_dma_cookies = 0;
			} else {
				/* No more windows! End of request! */
				/* What to do? - panic for now */
				ASSERT(spx->txlt_cur_dma_win >=
				    spx->txlt_num_dma_win);

				spx->txlt_curwin_num_dma_cookies = 0;
				spx->txlt_curwin_processed_dma_cookies = 0;
				spx->txlt_sata_pkt->
				    satapkt_cmd.satacmd_num_dma_cookies = 0;
				return (DDI_SUCCESS);
			}
		}
	}
	/* There better be at least one DMA cookie outstanding */
	ASSERT((spx->txlt_curwin_num_dma_cookies -
	    spx->txlt_curwin_processed_dma_cookies) > 0);

	if (spx->txlt_dma_cookie_list == &spx->txlt_dma_cookie) {
		/* The default cookie slot was used in previous run */
		ASSERT(spx->txlt_curwin_processed_dma_cookies == 0);
		spx->txlt_dma_cookie_list = NULL;
		spx->txlt_dma_cookie_list_len = 0;
	}
	if (spx->txlt_curwin_processed_dma_cookies == 0) {
		/*
		 * Processing a new DMA window - set-up dma cookies list.
		 * We may reuse previously allocated cookie array if it is
		 * possible.
		 */
		if (spx->txlt_dma_cookie_list != NULL &&
		    spx->txlt_dma_cookie_list_len <
		    spx->txlt_curwin_num_dma_cookies) {
			/*
			 * New DMA window contains more cookies than
			 * the previous one. We need larger cookie list - free
			 * the old one.
			 */
			(void) kmem_free(spx->txlt_dma_cookie_list,
			    spx->txlt_dma_cookie_list_len *
			    sizeof (ddi_dma_cookie_t));
			spx->txlt_dma_cookie_list = NULL;
			spx->txlt_dma_cookie_list_len = 0;
		}
		if (spx->txlt_dma_cookie_list == NULL) {
			/*
			 * Calculate lesser of number of cookies in this
			 * DMA window and number of s/g entries.
			 */
			max_sg_len = cur_dma_attr->dma_attr_sgllen;
			req_len = MIN(max_sg_len,
			    spx->txlt_curwin_num_dma_cookies);

			/* Allocate new dma cookie array if necessary */
			if (req_len == 1) {
				/* Only one cookie - no need for a list */
				spx->txlt_dma_cookie_list =
				    &spx->txlt_dma_cookie;
				spx->txlt_dma_cookie_list_len = 1;
			} else {
				/*
				 * More than one cookie - try to allocate space.
				 */
				spx->txlt_dma_cookie_list = kmem_zalloc(
				    sizeof (ddi_dma_cookie_t) * req_len,
				    callback == NULL_FUNC ? KM_NOSLEEP :
				    KM_SLEEP);
				if (spx->txlt_dma_cookie_list == NULL) {
					SATADBG1(SATA_DBG_DMA_SETUP,
					    spx->txlt_sata_hba_inst,
					    "sata_dma_buf_setup: cookie list "
					    "allocation failed\n", NULL);
					/*
					 * We could not allocate space for
					 * neccessary number of dma cookies in
					 * this window, so we fail this request.
					 * Next invocation would try again to
					 * allocate space for cookie list.
					 * Note:Packet residue was not modified.
					 */
					return (DDI_DMA_NORESOURCES);
				} else {
					spx->txlt_dma_cookie_list_len = req_len;
				}
			}
		}
		/*
		 * Fetch DMA cookies into cookie list in sata_pkt_txlate.
		 * First cookie was already fetched.
		 */
		*(&spx->txlt_dma_cookie_list[0]) = spx->txlt_dma_cookie;
		cur_txfer_len =
		    (uint64_t)spx->txlt_dma_cookie_list[0].dmac_size;
		spx->txlt_sata_pkt->satapkt_cmd.satacmd_num_dma_cookies = 1;
		spx->txlt_curwin_processed_dma_cookies++;
		for (i = 1; (i < spx->txlt_dma_cookie_list_len) &&
		    (i < spx->txlt_curwin_num_dma_cookies); i++) {
			ddi_dma_nextcookie(spx->txlt_buf_dma_handle,
			    &spx->txlt_dma_cookie_list[i]);
			cur_txfer_len +=
			    (uint64_t)spx->txlt_dma_cookie_list[i].dmac_size;
			spx->txlt_curwin_processed_dma_cookies++;
			spx->txlt_sata_pkt->
			    satapkt_cmd.satacmd_num_dma_cookies += 1;
		}
	} else {
		SATADBG2(SATA_DBG_DMA_SETUP, spx->txlt_sata_hba_inst,
		    "sata_dma_buf_setup: sliding within DMA window, "
		    "cur cookie %d, total cookies %d\n",
		    spx->txlt_curwin_processed_dma_cookies,
		    spx->txlt_curwin_num_dma_cookies);

		/*
		 * Not all cookies from the current dma window were used because
		 * of s/g limitation.
		 * There is no need to re-size the list - it was set at
		 * optimal size, or only default entry is used (s/g = 1).
		 */
		if (spx->txlt_dma_cookie_list == NULL) {
			spx->txlt_dma_cookie_list = &spx->txlt_dma_cookie;
			spx->txlt_dma_cookie_list_len = 1;
		}
		/*
		 * Since we are processing remaining cookies in a DMA window,
		 * there may be less of them than the number of entries in the
		 * current dma cookie list.
		 */
		req_len = MIN(spx->txlt_dma_cookie_list_len,
		    (spx->txlt_curwin_num_dma_cookies -
		    spx->txlt_curwin_processed_dma_cookies));

		/* Fetch the next batch of cookies */
		for (i = 0, cur_txfer_len = 0; i < req_len; i++) {
			ddi_dma_nextcookie(spx->txlt_buf_dma_handle,
			    &spx->txlt_dma_cookie_list[i]);
			cur_txfer_len +=
			    (uint64_t)spx->txlt_dma_cookie_list[i].dmac_size;
			spx->txlt_sata_pkt->
			    satapkt_cmd.satacmd_num_dma_cookies++;
			spx->txlt_curwin_processed_dma_cookies++;
		}
	}

	ASSERT(spx->txlt_sata_pkt->satapkt_cmd.satacmd_num_dma_cookies > 0);

	/* Point sata_cmd to the cookie list */
	spx->txlt_sata_pkt->satapkt_cmd.satacmd_dma_cookie_list =
	    &spx->txlt_dma_cookie_list[0];

	/* Remember number of DMA cookies passed in sata packet */
	spx->txlt_num_dma_cookies =
	    spx->txlt_sata_pkt->satapkt_cmd.satacmd_num_dma_cookies;

	ASSERT(cur_txfer_len != 0);
	if (cur_txfer_len <= bp->b_bcount)
		spx->txlt_total_residue -= cur_txfer_len;
	else {
		/*
		 * Temporary DMA buffer has been padded by
		 * ddi_dma_mem_alloc()!
		 * This requires special handling, because DMA cookies are
		 * based on the temporary buffer size, not the b_bcount,
		 * and we have extra bytes to transfer - but the packet
		 * residue has to stay correct because we will copy only
		 * the requested number of bytes.
		 */
		spx->txlt_total_residue -= bp->b_bcount;
	}

	return (DDI_SUCCESS);
}


/*
 * Fetch Device Identify data.
 * Send DEVICE IDENTIFY or IDENTIFY PACKET DEVICE (depending on a device type)
 * command to a device and get the device identify data.
 * The device_info structure has to be set to device type (for selecting proper
 * device identify command).
 *
 * Returns:
 * SATA_SUCCESS if cmd succeeded
 * SATA_RETRY if cmd was rejected and could be retried,
 * SATA_FAILURE if cmd failed and should not be retried (port error)
 *
 * Cannot be called in an interrupt context.
 */

static int
sata_fetch_device_identify_data(sata_hba_inst_t *sata_hba_inst,
    sata_drive_info_t *sdinfo)
{
	struct buf *bp;
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_pkt_txlate_t *spx;
	int rval;

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (SATA_RETRY); /* may retry later */
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;

	/*
	 * Allocate buffer for Identify Data return data
	 */
	bp = sata_alloc_local_buffer(spx, sizeof (sata_id_t));
	if (bp == NULL) {
		sata_pkt_free(spx);
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_fetch_device_identify_data: "
		    "cannot allocate buffer for ID"));
		return (SATA_RETRY); /* may retry later */
	}

	/* Fill sata_pkt */
	sdinfo->satadrv_state = SATA_STATE_PROBING;
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	/* Synchronous mode, no callback */
	spkt->satapkt_comp = NULL;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_bp = bp;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;
	scmd->satacmd_flags.sata_ignore_dev_reset = B_TRUE;

	/* Build Identify Device cmd in the sata_pkt */
	scmd->satacmd_addr_type = 0;		/* N/A */
	scmd->satacmd_sec_count_lsb = 0;	/* N/A */
	scmd->satacmd_lba_low_lsb = 0;		/* N/A */
	scmd->satacmd_lba_mid_lsb = 0;		/* N/A */
	scmd->satacmd_lba_high_lsb = 0;		/* N/A */
	scmd->satacmd_features_reg = 0;		/* N/A */
	scmd->satacmd_device_reg = 0;		/* Always device 0 */
	if (sdinfo->satadrv_type == SATA_DTYPE_ATAPICD) {
		/* Identify Packet Device cmd */
		scmd->satacmd_cmd_reg = SATAC_ID_PACKET_DEVICE;
	} else {
		/* Identify Device cmd - mandatory for all other devices */
		scmd->satacmd_cmd_reg = SATAC_ID_DEVICE;
	}

	/* Send pkt to SATA HBA driver */
	rval = (*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst), spkt);
	if (rval == SATA_TRAN_ACCEPTED &&
	    spkt->satapkt_reason == SATA_PKT_COMPLETED) {
		if ((sdinfo->satadrv_id.ai_config & SATA_INCOMPLETE_DATA) ==
		    SATA_INCOMPLETE_DATA) {
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "SATA disk device at port %d - "
			    "partial Identify Data",
			    sdinfo->satadrv_addr.cport));
			rval = SATA_RETRY; /* may retry later */
			goto fail;
		}
		/* Update sata_drive_info */
		rval = ddi_dma_sync(spx->txlt_buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		ASSERT(rval == DDI_SUCCESS);
		bcopy(bp->b_un.b_addr, &sdinfo->satadrv_id,
		    sizeof (sata_id_t));

		sdinfo->satadrv_features_support = 0;
		if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
			/*
			 * Retrieve capacity (disks only) and addressing mode
			 */
			sdinfo->satadrv_capacity = sata_check_capacity(sdinfo);
		} else {
			/*
			 * For ATAPI devices one would have to issue
			 * Get Capacity cmd for media capacity. Not here.
			 */
			sdinfo->satadrv_capacity = 0;
			/*
			 * Check what cdb length is supported
			 */
			if ((sdinfo->satadrv_id.ai_config &
			    SATA_ATAPI_ID_PKT_SZ) == SATA_ATAPI_ID_PKT_16B)
				sdinfo->satadrv_atapi_cdb_len = 16;
			else
				sdinfo->satadrv_atapi_cdb_len = 12;
		}
		/* Setup supported features flags */
		if (sdinfo->satadrv_id.ai_cap & SATA_DMA_SUPPORT)
			sdinfo->satadrv_features_support |= SATA_DEV_F_DMA;

		/* Check for SATA GEN and NCQ support */
		if (sdinfo->satadrv_id.ai_satacap != 0 &&
		    sdinfo->satadrv_id.ai_satacap != 0xffff) {
			/* SATA compliance */
			if (sdinfo->satadrv_id.ai_satacap & SATA_NCQ)
				sdinfo->satadrv_features_support |=
				    SATA_DEV_F_NCQ;
			if (sdinfo->satadrv_id.ai_satacap &
			    (SATA_1_SPEED | SATA_2_SPEED)) {
				if (sdinfo->satadrv_id.ai_satacap &
				    SATA_2_SPEED)
					sdinfo->satadrv_features_support |=
					    SATA_DEV_F_SATA2;
				if (sdinfo->satadrv_id.ai_satacap &
				    SATA_1_SPEED)
					sdinfo->satadrv_features_support |=
					    SATA_DEV_F_SATA1;
			} else {
				sdinfo->satadrv_features_support |=
				    SATA_DEV_F_SATA1;
			}
		}
		if ((sdinfo->satadrv_id.ai_cmdset83 & SATA_RW_DMA_QUEUED_CMD) &&
		    (sdinfo->satadrv_id.ai_features86 & SATA_RW_DMA_QUEUED_CMD))
			sdinfo->satadrv_features_support |= SATA_DEV_F_TCQ;

		sdinfo->satadrv_queue_depth = sdinfo->satadrv_id.ai_qdepth;
		if ((sdinfo->satadrv_features_support & SATA_DEV_F_NCQ) ||
		    (sdinfo->satadrv_features_support & SATA_DEV_F_TCQ)) {
			++sdinfo->satadrv_queue_depth;
			/* Adjust according to controller capabilities */
			sdinfo->satadrv_max_queue_depth = MIN(
			    sdinfo->satadrv_queue_depth,
			    SATA_QDEPTH(sata_hba_inst));
			/* Adjust according to global queue depth limit */
			sdinfo->satadrv_max_queue_depth = MIN(
			    sdinfo->satadrv_max_queue_depth,
			    sata_current_max_qdepth);
			if (sdinfo->satadrv_max_queue_depth == 0)
				sdinfo->satadrv_max_queue_depth = 1;
		} else
			sdinfo->satadrv_max_queue_depth = 1;

		rval = SATA_SUCCESS;
	} else {
		/*
		 * Woops, no Identify Data.
		 */
		if (rval == SATA_TRAN_BUSY || rval == SATA_TRAN_QUEUE_FULL) {
			rval = SATA_RETRY; /* may retry later */
		} else if (rval == SATA_TRAN_ACCEPTED) {
			if (spkt->satapkt_reason == SATA_PKT_DEV_ERROR ||
			    spkt->satapkt_reason == SATA_PKT_ABORTED ||
			    spkt->satapkt_reason == SATA_PKT_TIMEOUT ||
			    spkt->satapkt_reason == SATA_PKT_RESET)
				rval = SATA_RETRY; /* may retry later */
			else
				rval = SATA_FAILURE;
		} else {
			rval = SATA_FAILURE;
		}
	}
fail:
	/* Free allocated resources */
	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));

	return (rval);
}


/*
 * Some devices may not come-up with default DMA mode (UDMA or MWDMA).
 * UDMA mode is checked first, followed by MWDMA mode.
 * set correctly, so this function is setting it to the highest supported level.
 * Older SATA spec required that the device supports at least DMA 4 mode and
 * UDMA mode is selected.  It is not mentioned in SerialATA 2.6, so this
 * restriction has been removed.
 *
 * Returns SATA_SUCCESS if proper DMA mode is selected or no DMA is supported.
 * Returns SATA_FAILURE if proper DMA mode could not be selected.
 *
 * NOTE: This function should be called only if DMA mode is supported.
 */
static int
sata_set_dma_mode(sata_hba_inst_t *sata_hba_inst, sata_drive_info_t *sdinfo)
{
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_pkt_txlate_t *spx;
	int i, mode;
	uint8_t subcmd;
	int rval = SATA_SUCCESS;

	ASSERT(sdinfo != NULL);
	ASSERT(sata_hba_inst != NULL);

	if ((sdinfo->satadrv_id.ai_validinfo & SATA_VALIDINFO_88) != 0 &&
	    (sdinfo->satadrv_id.ai_ultradma & SATA_UDMA_SUP_MASK) != 0) {
		/* Find highest Ultra DMA mode supported */
		for (mode = 6; mode >= 0; --mode) {
			if (sdinfo->satadrv_id.ai_ultradma & (1 << mode))
				break;
		}
#if 0
		/* Left for historical reasons */
		/*
		 * Some initial version of SATA spec indicated that at least
		 * UDMA mode 4 has to be supported. It is not mentioned in
		 * SerialATA 2.6, so this restriction is removed.
		 */
		if (mode < 4)
			return (SATA_FAILURE);
#endif
		/* Find UDMA mode currently selected */
		for (i = 6; i >= 0; --i) {
			if (sdinfo->satadrv_id.ai_ultradma & (1 << (i + 8)))
				break;
		}
		if (i >= mode)
			/* Nothing to do */
			return (SATA_SUCCESS);

		subcmd = SATAC_TRANSFER_MODE_ULTRA_DMA;

	} else if ((sdinfo->satadrv_id.ai_dworddma & SATA_MDMA_SUP_MASK) != 0) {
		/* Find highest MultiWord DMA mode supported */
		for (mode = 2; mode >= 0; --mode) {
			if (sdinfo->satadrv_id.ai_dworddma & (1 << mode))
				break;
		}
		/* Find highest MultiWord DMA mode selected */
		for (i = 2; i >= 0; --i) {
			if (sdinfo->satadrv_id.ai_dworddma & (1 << (i + 8)))
				break;
		}
		if (i >= mode)
			/* Nothing to do */
			return (SATA_SUCCESS);

		subcmd = SATAC_TRANSFER_MODE_MULTI_WORD_DMA;
	} else
		return (SATA_SUCCESS);

	/*
	 * Set DMA mode via SET FEATURES COMMAND.
	 * Prepare packet for SET FEATURES COMMAND.
	 */
	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;	/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_set_dma_mode: could not set DMA mode %", mode));
		rval = SATA_FAILURE;
		goto done;
	}
	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;
	/* Synchronous mode, no callback, interrupts */
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	spkt->satapkt_comp = NULL;
	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_NODATA_XFER;
	scmd->satacmd_flags.sata_ignore_dev_reset = B_TRUE;
	scmd->satacmd_addr_type = 0;
	scmd->satacmd_device_reg = 0;
	scmd->satacmd_status_reg = 0;
	scmd->satacmd_error_reg = 0;
	scmd->satacmd_cmd_reg = SATAC_SET_FEATURES;
	scmd->satacmd_features_reg = SATAC_SF_TRANSFER_MODE;
	scmd->satacmd_sec_count_lsb = subcmd | mode;

	/* Transfer command to HBA */
	if ((*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst),
	    spkt) != SATA_TRAN_ACCEPTED ||
	    spkt->satapkt_reason != SATA_PKT_COMPLETED) {
		/* Pkt execution failed */
		rval = SATA_FAILURE;
	}
done:

	/* Free allocated resources */
	if (spkt != NULL)
		sata_pkt_free(spx);
	(void) kmem_free(spx, sizeof (sata_pkt_txlate_t));

	return (rval);
}


/*
 * Set device caching mode.
 * One of the following operations should be specified:
 * SATAC_SF_ENABLE_READ_AHEAD
 * SATAC_SF_DISABLE_READ_AHEAD
 * SATAC_SF_ENABLE_WRITE_CACHE
 * SATAC_SF_DISABLE_WRITE_CACHE
 *
 * If operation fails, system log messgage is emitted.
 * Returns SATA_SUCCESS when the operation succeeds, SATA_FAILURE otherwise.
 */

static int
sata_set_cache_mode(sata_hba_inst_t *sata_hba_inst, sata_drive_info_t *sdinfo,
    int cache_op)
{
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_pkt_txlate_t *spx;
	int rval = SATA_SUCCESS;
	char *infop;

	ASSERT(sdinfo != NULL);
	ASSERT(sata_hba_inst != NULL);
	ASSERT(cache_op == SATAC_SF_ENABLE_READ_AHEAD ||
	    cache_op == SATAC_SF_DISABLE_READ_AHEAD ||
	    cache_op == SATAC_SF_ENABLE_WRITE_CACHE ||
	    cache_op == SATAC_SF_DISABLE_WRITE_CACHE);


	/* Prepare packet for SET FEATURES COMMAND */
	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;	/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		rval = SATA_FAILURE;
		goto failure;
	}
	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;
	/* Synchronous mode, no callback, interrupts */
	spkt->satapkt_op_mode =
	    SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	spkt->satapkt_comp = NULL;
	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_NODATA_XFER;
	scmd->satacmd_flags.sata_ignore_dev_reset = B_TRUE;
	scmd->satacmd_addr_type = 0;
	scmd->satacmd_device_reg = 0;
	scmd->satacmd_status_reg = 0;
	scmd->satacmd_error_reg = 0;
	scmd->satacmd_cmd_reg = SATAC_SET_FEATURES;
	scmd->satacmd_features_reg = cache_op;

	/* Transfer command to HBA */
	if (((*SATA_START_FUNC(sata_hba_inst))(
	    SATA_DIP(sata_hba_inst), spkt) != SATA_TRAN_ACCEPTED) ||
	    (spkt->satapkt_reason != SATA_PKT_COMPLETED)) {
		/* Pkt execution failed */
		switch (cache_op) {
		case SATAC_SF_ENABLE_READ_AHEAD:
			infop = "enabling read ahead failed";
			break;
		case SATAC_SF_DISABLE_READ_AHEAD:
			infop = "disabling read ahead failed";
			break;
		case SATAC_SF_ENABLE_WRITE_CACHE:
			infop = "enabling write cache failed";
			break;
		case SATAC_SF_DISABLE_WRITE_CACHE:
			infop = "disabling write cache failed";
			break;
		}
		SATA_LOG_D((sata_hba_inst, CE_WARN, "%s", infop));
		rval = SATA_FAILURE;
	}
failure:
	/* Free allocated resources */
	if (spkt != NULL)
		sata_pkt_free(spx);
	(void) kmem_free(spx, sizeof (sata_pkt_txlate_t));
	return (rval);
}

/*
 * Set Removable Media Status Notification (enable/disable)
 * state == 0 , disable
 * state != 0 , enable
 *
 * If operation fails, system log messgage is emitted.
 * Returns SATA_SUCCESS when the operation succeeds, SATA_FAILURE otherwise.
 */

static int
sata_set_rmsn(sata_hba_inst_t *sata_hba_inst, sata_drive_info_t *sdinfo,
    int state)
{
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_pkt_txlate_t *spx;
	int rval = SATA_SUCCESS;
	char *infop;

	ASSERT(sdinfo != NULL);
	ASSERT(sata_hba_inst != NULL);

	/* Prepare packet for SET FEATURES COMMAND */
	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;	/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		rval = SATA_FAILURE;
		goto failure;
	}
	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;
	/* Synchronous mode, no callback, interrupts */
	spkt->satapkt_op_mode =
	    SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	spkt->satapkt_comp = NULL;
	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_NODATA_XFER;
	scmd->satacmd_flags.sata_ignore_dev_reset = B_TRUE;
	scmd->satacmd_addr_type = 0;
	scmd->satacmd_device_reg = 0;
	scmd->satacmd_status_reg = 0;
	scmd->satacmd_error_reg = 0;
	scmd->satacmd_cmd_reg = SATAC_SET_FEATURES;
	if (state == 0)
		scmd->satacmd_features_reg = SATAC_SF_DISABLE_RMSN;
	else
		scmd->satacmd_features_reg = SATAC_SF_ENABLE_RMSN;

	/* Transfer command to HBA */
	if (((*SATA_START_FUNC(sata_hba_inst))(
	    SATA_DIP(sata_hba_inst), spkt) != SATA_TRAN_ACCEPTED) ||
	    (spkt->satapkt_reason != SATA_PKT_COMPLETED)) {
		/* Pkt execution failed */
		if (state == 0)
			infop = "disabling Removable Media Status "
			    "Notification failed";
		else
			infop = "enabling Removable Media Status "
			    "Notification failed";

		SATA_LOG_D((sata_hba_inst, CE_WARN, "%s", infop));
		rval = SATA_FAILURE;
	}
failure:
	/* Free allocated resources */
	if (spkt != NULL)
		sata_pkt_free(spx);
	(void) kmem_free(spx, sizeof (sata_pkt_txlate_t));
	return (rval);
}


/*
 * Update port SCR block
 */
static void
sata_update_port_scr(sata_port_scr_t *port_scr, sata_device_t *device)
{
	port_scr->sstatus = device->satadev_scr.sstatus;
	port_scr->serror = device->satadev_scr.serror;
	port_scr->scontrol = device->satadev_scr.scontrol;
	port_scr->sactive = device->satadev_scr.sactive;
	port_scr->snotific = device->satadev_scr.snotific;
}

/*
 * Update state and copy port ss* values from passed sata_device structure.
 * sata_address is validated - if not valid, nothing is changed in sata_scsi
 * configuration struct.
 *
 * SATA_PSTATE_SHUTDOWN in port state is not reset to 0 by this function
 * regardless of the state in device argument.
 *
 * Port mutex should be held while calling this function.
 */
static void
sata_update_port_info(sata_hba_inst_t *sata_hba_inst,
	sata_device_t *sata_device)
{
	ASSERT(mutex_owned(&SATA_CPORT_MUTEX(sata_hba_inst,
	    sata_device->satadev_addr.cport)));

	if (sata_device->satadev_addr.qual == SATA_ADDR_CPORT ||
	    sata_device->satadev_addr.qual == SATA_ADDR_DCPORT) {

		sata_cport_info_t *cportinfo;

		if (SATA_NUM_CPORTS(sata_hba_inst) <=
		    sata_device->satadev_addr.cport)
			return;

		cportinfo = SATA_CPORT_INFO(sata_hba_inst,
		    sata_device->satadev_addr.cport);
		sata_update_port_scr(&cportinfo->cport_scr, sata_device);

		/* Preserve SATA_PSTATE_SHUTDOWN flag */
		cportinfo->cport_state &= ~(SATA_PSTATE_PWRON |
		    SATA_PSTATE_PWROFF | SATA_PSTATE_FAILED);
		cportinfo->cport_state |=
		    sata_device->satadev_state & SATA_PSTATE_VALID;
	} else {
		sata_pmport_info_t *pmportinfo;

		if ((sata_device->satadev_addr.qual != SATA_ADDR_PMPORT) ||
		    (sata_device->satadev_addr.qual != SATA_ADDR_DPMPORT) ||
		    SATA_NUM_PMPORTS(sata_hba_inst,
		    sata_device->satadev_addr.cport) <
		    sata_device->satadev_addr.pmport)
			return;

		pmportinfo = SATA_PMPORT_INFO(sata_hba_inst,
		    sata_device->satadev_addr.cport,
		    sata_device->satadev_addr.pmport);
		sata_update_port_scr(&pmportinfo->pmport_scr, sata_device);

		/* Preserve SATA_PSTATE_SHUTDOWN flag */
		pmportinfo->pmport_state &=
		    ~(SATA_PSTATE_PWRON | SATA_PSTATE_PWROFF |
		    SATA_PSTATE_FAILED);
		pmportinfo->pmport_state |=
		    sata_device->satadev_state & SATA_PSTATE_VALID;
	}
}



/*
 * Extract SATA port specification from an IOCTL argument.
 *
 * This function return the port the user land send us as is, unless it
 * cannot retrieve port spec, then -1 is returned.
 *
 * Note: Only cport  - no port multiplier port.
 */
static int32_t
sata_get_port_num(sata_hba_inst_t *sata_hba_inst, struct devctl_iocdata *dcp)
{
	int32_t port;

	/* Extract port number from nvpair in dca structure  */
	if (nvlist_lookup_int32(ndi_dc_get_ap_data(dcp), "port", &port) != 0) {
		SATA_LOG_D((sata_hba_inst, CE_NOTE,
		    "sata_get_port_num: invalid port spec 0x%x in ioctl",
		    port));
		port = -1;
	}

	return (port);
}

/*
 * Get dev_info_t pointer to the device node pointed to by port argument.
 * NOTE: target argument is a value used in ioctls to identify
 * the AP - it is not a sata_address.
 * It is a combination of cport, pmport and address qualifier, encodded same
 * way as a scsi target number.
 * At this moment it carries only cport number.
 *
 * No PMult hotplug support.
 *
 * Returns dev_info_t pointer if target device was found, NULL otherwise.
 */

static dev_info_t *
sata_get_target_dip(dev_info_t *dip, int32_t port)
{
	dev_info_t	*cdip = NULL;
	int		target, tgt;
	int		ncport;
	int 		circ;

	ncport = port & SATA_CFGA_CPORT_MASK;
	target = SATA_TO_SCSI_TARGET(ncport, 0, SATA_ADDR_DCPORT);

	ndi_devi_enter(dip, &circ);
	for (cdip = ddi_get_child(dip); cdip != NULL; ) {
		dev_info_t *next = ddi_get_next_sibling(cdip);

		tgt = ddi_prop_get_int(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, "target", -1);
		if (tgt == -1) {
			/*
			 * This is actually an error condition, but not
			 * a fatal one. Just continue the search.
			 */
			cdip = next;
			continue;
		}

		if (tgt == target)
			break;

		cdip = next;
	}
	ndi_devi_exit(dip, circ);

	return (cdip);
}


/*
 * sata_cfgadm_state:
 * Use the sata port state and state of the target node to figure out
 * the cfgadm_state.
 *
 * The port argument is a value with encoded cport,
 * pmport and address qualifier, in the same manner as a scsi target number.
 * SCSI_TO_SATA_CPORT macro extracts cport number,
 * SCSI_TO_SATA_PMPORT extracts pmport number and
 * SCSI_TO_SATA_ADDR_QUAL extracts port mulitplier qualifier flag.
 *
 * For now, support is for cports only - no port multiplier device ports.
 */

static void
sata_cfgadm_state(sata_hba_inst_t *sata_hba_inst, int32_t port,
    devctl_ap_state_t *ap_state)
{
	uint16_t	cport;
	int		port_state;

	/* Cport only */
	cport = SCSI_TO_SATA_CPORT(port);

	port_state = SATA_CPORT_STATE(sata_hba_inst, cport);
	if (port_state & SATA_PSTATE_SHUTDOWN ||
	    port_state & SATA_PSTATE_FAILED) {
		ap_state->ap_rstate = AP_RSTATE_DISCONNECTED;
		ap_state->ap_ostate = AP_OSTATE_UNCONFIGURED;
		if (port_state & SATA_PSTATE_FAILED)
			ap_state->ap_condition = AP_COND_FAILED;
		else
			ap_state->ap_condition = AP_COND_UNKNOWN;

		return;
	}

	/* Need to check pmult device port here as well, when supported */

	/* Port is enabled and ready */

	switch (SATA_CPORT_DEV_TYPE(sata_hba_inst, cport)) {
	case SATA_DTYPE_NONE:
	{
		ap_state->ap_ostate = AP_OSTATE_UNCONFIGURED;
		ap_state->ap_condition = AP_COND_OK;
		/* No device attached */
		ap_state->ap_rstate = AP_RSTATE_EMPTY;
		break;
	}
	case SATA_DTYPE_UNKNOWN:
	case SATA_DTYPE_ATAPINONCD:
	case SATA_DTYPE_PMULT:	/* Until PMult is supported */
	case SATA_DTYPE_ATADISK:
	case SATA_DTYPE_ATAPICD:
	{
		dev_info_t *tdip = NULL;
		dev_info_t *dip = NULL;
		int circ;

		dip = SATA_DIP(sata_hba_inst);
		tdip = sata_get_target_dip(dip, port);
		ap_state->ap_rstate = AP_RSTATE_CONNECTED;
		if (tdip != NULL) {
			ndi_devi_enter(dip, &circ);
			mutex_enter(&(DEVI(tdip)->devi_lock));
			if (DEVI_IS_DEVICE_REMOVED(tdip)) {
				/*
				 * There could be the case where previously
				 * configured and opened device was removed
				 * and unknown device was plugged.
				 * In such case we want to show a device, and
				 * its configured or unconfigured state but
				 * indicate unusable condition untill the
				 * old target node is released and removed.
				 */
				ap_state->ap_condition = AP_COND_UNUSABLE;
			} else {
				ap_state->ap_condition = AP_COND_OK;
			}
			if ((DEVI_IS_DEVICE_OFFLINE(tdip)) ||
			    (DEVI_IS_DEVICE_DOWN(tdip))) {
				ap_state->ap_ostate =
				    AP_OSTATE_UNCONFIGURED;
			} else {
				ap_state->ap_ostate =
				    AP_OSTATE_CONFIGURED;
			}
			mutex_exit(&(DEVI(tdip)->devi_lock));
			ndi_devi_exit(dip, circ);
		} else {
			ap_state->ap_ostate = AP_OSTATE_UNCONFIGURED;
			ap_state->ap_condition = AP_COND_UNKNOWN;
		}
		break;
	}
	default:
		ap_state->ap_rstate = AP_RSTATE_CONNECTED;
		ap_state->ap_ostate = AP_OSTATE_UNCONFIGURED;
		ap_state->ap_condition = AP_COND_UNKNOWN;
		/*
		 * This is actually internal error condition (non fatal),
		 * because we have already checked all defined device types.
		 */
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_cfgadm_state: Internal error: "
		    "unknown device type"));
		break;
	}
}


/*
 * Preset scsi extended sense data (to NO SENSE)
 * First 18 bytes of the sense data are preset to current valid sense
 * with a key NO SENSE data.
 *
 * Returns void
 */
static void
sata_fixed_sense_data_preset(struct scsi_extended_sense *sense)
{
	sense->es_valid = 1;		/* Valid sense */
	sense->es_class = CLASS_EXTENDED_SENSE;	/* 0x70 - current err */
	sense->es_key = KEY_NO_SENSE;
	sense->es_info_1 = 0;
	sense->es_info_2 = 0;
	sense->es_info_3 = 0;
	sense->es_info_4 = 0;
	sense->es_add_len = 10;	/* Additional length - replace with a def */
	sense->es_cmd_info[0] = 0;
	sense->es_cmd_info[1] = 0;
	sense->es_cmd_info[2] = 0;
	sense->es_cmd_info[3] = 0;
	sense->es_add_code = 0;
	sense->es_qual_code = 0;
}

/*
 * Register a legacy cmdk-style devid for the target (disk) device.
 *
 * Note: This function is called only when the HBA devinfo node has the
 * property "use-cmdk-devid-format" set. This property indicates that
 * devid compatible with old cmdk (target) driver is to be generated
 * for any target device attached to this controller. This will take
 * precedence over the devid generated by sd (target) driver.
 * This function is derived from cmdk_devid_setup() function in cmdk.c.
 */
static void
sata_target_devid_register(dev_info_t *dip, sata_drive_info_t *sdinfo)
{
	char	*hwid;
	int	modlen;
	int	serlen;
	int	rval;
	ddi_devid_t	devid;

	/*
	 * device ID is a concatanation of model number, "=", serial number.
	 */
	hwid = kmem_zalloc(LEGACY_HWID_LEN, KM_SLEEP);
	bcopy(&sdinfo->satadrv_id.ai_model, hwid,
	    sizeof (sdinfo->satadrv_id.ai_model));
	swab(hwid, hwid, sizeof (sdinfo->satadrv_id.ai_model));
	modlen = sata_check_modser(hwid, sizeof (sdinfo->satadrv_id.ai_model));
	if (modlen == 0)
		goto err;
	hwid[modlen++] = '=';
	bcopy(&sdinfo->satadrv_id.ai_drvser, &hwid[modlen],
	    sizeof (sdinfo->satadrv_id.ai_drvser));
	swab(&hwid[modlen], &hwid[modlen],
	    sizeof (sdinfo->satadrv_id.ai_drvser));
	serlen = sata_check_modser(&hwid[modlen],
	    sizeof (sdinfo->satadrv_id.ai_drvser));
	if (serlen == 0)
		goto err;
	hwid[modlen + serlen] = 0; /* terminate the hwid string */

	/* initialize/register devid */
	if ((rval = ddi_devid_init(dip, DEVID_ATA_SERIAL,
	    (ushort_t)(modlen + serlen), hwid, &devid)) == DDI_SUCCESS)
		rval = ddi_devid_register(dip, devid);

	if (rval != DDI_SUCCESS)
		cmn_err(CE_WARN, "sata: failed to create devid for the disk"
		    " on port %d", sdinfo->satadrv_addr.cport);
err:
	kmem_free(hwid, LEGACY_HWID_LEN);
}

/*
 * valid model/serial string must contain a non-zero non-space characters.
 * trim trailing spaces/NULLs.
 */
static int
sata_check_modser(char *buf, int buf_len)
{
	boolean_t ret;
	char *s;
	int i;
	int tb;
	char ch;

	ret = B_FALSE;
	s = buf;
	for (i = 0; i < buf_len; i++) {
		ch = *s++;
		if (ch != ' ' && ch != '\0')
			tb = i + 1;
		if (ch != ' ' && ch != '\0' && ch != '0')
			ret = B_TRUE;
	}

	if (ret == B_FALSE)
		return (0); /* invalid string */

	return (tb); /* return length */
}

/*
 * sata_set_drive_features function compares current device features setting
 * with the saved device features settings and, if there is a difference,
 * it restores device features setting to the previously saved state.
 * It also arbitrarily tries to select the highest supported DMA mode.
 * Device Identify or Identify Packet Device data has to be current.
 * At the moment read ahead and write cache are considered for all devices.
 * For atapi devices, Removable Media Status Notification is set in addition
 * to common features.
 *
 * This function cannot be called in the interrupt context (it may sleep).
 *
 * The input argument sdinfo should point to the drive info structure
 * to be updated after features are set. Note, that only
 * device (packet) identify data is updated, not the flags indicating the
 * supported features.
 *
 * Returns TRUE if successful or there was nothing to do. Device Identify data
 * in the drive info structure pointed to by the sdinfo argumens is updated
 * even when no features were set or changed.
 *
 * Returns FALSE if device features could not be set.
 *
 * Note: This function may fail the port, making it inaccessible.
 * In such case the explicit port disconnect/connect or physical device
 * detach/attach is required to re-evaluate port state again.
 */

static int
sata_set_drive_features(sata_hba_inst_t *sata_hba_inst,
    sata_drive_info_t *sdinfo, int restore)
{
	int rval = SATA_SUCCESS;
	sata_drive_info_t new_sdinfo;
	char *finfo = "sata_set_drive_features: cannot";
	char *finfox;
	int cache_op;

	bzero(&new_sdinfo, sizeof (sata_drive_info_t));
	new_sdinfo.satadrv_addr = sdinfo->satadrv_addr;
	new_sdinfo.satadrv_type = sdinfo->satadrv_type;
	if (sata_fetch_device_identify_data(sata_hba_inst, &new_sdinfo) != 0) {
		/*
		 * Cannot get device identification - retry later
		 */
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "%s fetch device identify data\n", finfo));
		return (SATA_FAILURE);
	}
	finfox = (restore != 0) ? " restore device features" :
	    " initialize device features\n";

	if (sdinfo->satadrv_type == SATA_DTYPE_ATADISK) {
		/* Arbitrarily set UDMA mode */
		if (sata_set_dma_mode(sata_hba_inst, &new_sdinfo) !=
		    SATA_SUCCESS) {
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "%s set UDMA mode\n", finfo));
			return (SATA_FAILURE);
		}
	} else { /* Assume SATA ATAPI CD/DVD */
		/*  Set Removable Media Status Notification, if necessary */
		if ((new_sdinfo.satadrv_id.ai_cmdset83 &
		    SATA_RM_STATUS_NOTIFIC) != 0 && restore != 0) {
			if (((sdinfo->satadrv_settings & SATA_DEV_RMSN) &&
			    (!(new_sdinfo.satadrv_id.ai_features86 &
			    SATA_RM_STATUS_NOTIFIC))) ||
			    ((!(sdinfo->satadrv_settings & SATA_DEV_RMSN)) &&
			    (new_sdinfo.satadrv_id.ai_features86 &
			    SATA_RM_STATUS_NOTIFIC))) {
				/* Current setting does not match saved one */
				if (sata_set_rmsn(sata_hba_inst, sdinfo,
				    sdinfo->satadrv_settings &
				    SATA_DEV_RMSN) != SATA_SUCCESS)
					rval = SATA_FAILURE;
			}
		}
		/*
		 * We have to set Multiword DMA or UDMA, if it is supported, as
		 * we want to use DMA transfer mode whenever possible.
		 * Some devices require explicit setting of the DMA mode.
		 */
		if (new_sdinfo.satadrv_id.ai_cap & SATA_DMA_SUPPORT) {
			/* Set highest supported DMA mode */
			if (sata_set_dma_mode(sata_hba_inst, &new_sdinfo) !=
			    SATA_SUCCESS) {
				SATA_LOG_D((sata_hba_inst, CE_WARN,
				    "%s set UDMA mode\n", finfo));
				rval = SATA_FAILURE;
			}
		}
	}

	if (!(new_sdinfo.satadrv_id.ai_cmdset82 & SATA_LOOK_AHEAD) &&
	    !(new_sdinfo.satadrv_id.ai_cmdset82 & SATA_WRITE_CACHE)) {
		/* None of the features is supported - do nothing */
		SATADBG1(SATA_DBG_DEV_SETTINGS, sata_hba_inst,
		    "settable features not supported\n", NULL);
		goto update_sdinfo;
	}

	if (((new_sdinfo.satadrv_id.ai_features85 & SATA_LOOK_AHEAD) &&
	    (sdinfo->satadrv_settings & SATA_DEV_READ_AHEAD)) &&
	    ((new_sdinfo.satadrv_id.ai_features85 & SATA_WRITE_CACHE) &&
	    (sdinfo->satadrv_settings & SATA_DEV_WRITE_CACHE))) {
		/* Nothing to do */
		SATADBG1(SATA_DBG_DEV_SETTINGS, sata_hba_inst,
		    "no device features to set\n", NULL);
		goto update_sdinfo;
	}

	if (!((new_sdinfo.satadrv_id.ai_features85 & SATA_LOOK_AHEAD) &&
	    (sdinfo->satadrv_settings & SATA_DEV_READ_AHEAD))) {
		if (sdinfo->satadrv_settings & SATA_DEV_READ_AHEAD) {
			/* Enable read ahead / read cache */
			cache_op = SATAC_SF_ENABLE_READ_AHEAD;
			SATADBG1(SATA_DBG_DEV_SETTINGS, sata_hba_inst,
			    "enabling read cache\n", NULL);
		} else {
			/* Disable read ahead  / read cache */
			cache_op = SATAC_SF_DISABLE_READ_AHEAD;
			SATADBG1(SATA_DBG_DEV_SETTINGS, sata_hba_inst,
			    "disabling read cache\n", NULL);
		}

		/* Try to set read cache mode */
		if (sata_set_cache_mode(sata_hba_inst, &new_sdinfo,
		    cache_op) != SATA_SUCCESS) {
			/* Pkt execution failed */
			rval = SATA_FAILURE;
		}
	}

	if (!((new_sdinfo.satadrv_id.ai_features85 & SATA_WRITE_CACHE) &&
	    (sdinfo->satadrv_settings & SATA_DEV_WRITE_CACHE))) {
		if (sdinfo->satadrv_settings & SATA_DEV_WRITE_CACHE) {
			/* Enable write cache */
			cache_op = SATAC_SF_ENABLE_WRITE_CACHE;
			SATADBG1(SATA_DBG_DEV_SETTINGS, sata_hba_inst,
			    "enabling write cache\n", NULL);
		} else {
			/* Disable write cache */
			cache_op = SATAC_SF_DISABLE_WRITE_CACHE;
			SATADBG1(SATA_DBG_DEV_SETTINGS, sata_hba_inst,
			    "disabling write cache\n", NULL);
		}
		/* Try to set write cache mode */
		if (sata_set_cache_mode(sata_hba_inst, &new_sdinfo,
		    cache_op) != SATA_SUCCESS) {
			/* Pkt execution failed */
			rval = SATA_FAILURE;
		}
	}

	if (rval == SATA_FAILURE)
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "%s %s", finfo, finfox));
update_sdinfo:
	/*
	 * We need to fetch Device Identify data again
	 */
	if (sata_fetch_device_identify_data(sata_hba_inst, &new_sdinfo) != 0) {
		/*
		 * Cannot get device identification - retry later
		 */
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "%s cannot re-fetch device identify data\n"));
		rval = SATA_FAILURE;
	}
	/* Copy device sata info. */
	sdinfo->satadrv_id = new_sdinfo.satadrv_id;

	return (rval);
}


/*
 *
 * Returns 1 if threshold exceeded, 0 if threshold not exceeded, -1 if
 * unable to determine.
 *
 * Cannot be called in an interrupt context.
 *
 * Called by sata_build_lsense_page_2f()
 */

static int
sata_fetch_smart_return_status(sata_hba_inst_t *sata_hba_inst,
    sata_drive_info_t *sdinfo)
{
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_pkt_txlate_t *spx;
	int rval;

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (-1);
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;


	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	/* Synchronous mode, no callback */
	spkt->satapkt_comp = NULL;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_special_regs = B_TRUE;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_NODATA_XFER;

	/* Set up which registers need to be returned */
	scmd->satacmd_flags.sata_copy_out_lba_mid_lsb = B_TRUE;
	scmd->satacmd_flags.sata_copy_out_lba_high_lsb = B_TRUE;

	/* Build SMART_RETURN_STATUS cmd in the sata_pkt */
	scmd->satacmd_addr_type = 0;		/* N/A */
	scmd->satacmd_sec_count_lsb = 0;	/* N/A */
	scmd->satacmd_lba_low_lsb = 0;		/* N/A */
	scmd->satacmd_lba_mid_lsb = SMART_MAGIC_VAL_1;
	scmd->satacmd_lba_high_lsb = SMART_MAGIC_VAL_2;
	scmd->satacmd_features_reg = SATA_SMART_RETURN_STATUS;
	scmd->satacmd_device_reg = 0;		/* Always device 0 */
	scmd->satacmd_cmd_reg = SATAC_SMART;
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sdinfo->satadrv_addr.cport)));


	/* Send pkt to SATA HBA driver */
	if ((*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst), spkt) !=
	    SATA_TRAN_ACCEPTED ||
	    spkt->satapkt_reason != SATA_PKT_COMPLETED) {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));
		/*
		 * Whoops, no SMART RETURN STATUS
		 */
		rval = -1;
	} else {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));
		if (scmd->satacmd_error_reg & SATA_ERROR_ABORT) {
			rval = -1;
			goto fail;
		}
		if (scmd->satacmd_status_reg & SATA_STATUS_ERR) {
			rval = -1;
			goto fail;
		}
		if ((scmd->satacmd_lba_mid_lsb == SMART_MAGIC_VAL_1) &&
		    (scmd->satacmd_lba_high_lsb == SMART_MAGIC_VAL_2))
			rval = 0;
		else if ((scmd->satacmd_lba_mid_lsb == SMART_MAGIC_VAL_3) &&
		    (scmd->satacmd_lba_high_lsb == SMART_MAGIC_VAL_4))
			rval = 1;
		else {
			rval = -1;
			goto fail;
		}
	}
fail:
	/* Free allocated resources */
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));

	return (rval);
}

/*
 *
 * Returns 0 if succeeded, -1 otherwise
 *
 * Cannot be called in an interrupt context.
 *
 */
static int
sata_fetch_smart_data(
	sata_hba_inst_t *sata_hba_inst,
	sata_drive_info_t *sdinfo,
	struct smart_data *smart_data)
{
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_pkt_txlate_t *spx;
	int rval;

#if ! defined(lint)
	ASSERT(sizeof (struct smart_data) == 512);
#endif

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (-1);
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;


	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	/* Synchronous mode, no callback */
	spkt->satapkt_comp = NULL;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;

	/*
	 * Allocate buffer for SMART data
	 */
	scmd->satacmd_bp = sata_alloc_local_buffer(spx,
	    sizeof (struct smart_data));
	if (scmd->satacmd_bp == NULL) {
		sata_pkt_free(spx);
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_fetch_smart_data: "
		    "cannot allocate buffer"));
		return (-1);
	}


	/* Build SMART_READ_DATA cmd in the sata_pkt */
	scmd->satacmd_addr_type = 0;		/* N/A */
	scmd->satacmd_sec_count_lsb = 0;	/* N/A */
	scmd->satacmd_lba_low_lsb = 0;		/* N/A */
	scmd->satacmd_lba_mid_lsb = SMART_MAGIC_VAL_1;
	scmd->satacmd_lba_high_lsb = SMART_MAGIC_VAL_2;
	scmd->satacmd_features_reg = SATA_SMART_READ_DATA;
	scmd->satacmd_device_reg = 0;		/* Always device 0 */
	scmd->satacmd_cmd_reg = SATAC_SMART;
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sdinfo->satadrv_addr.cport)));

	/* Send pkt to SATA HBA driver */
	if ((*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst), spkt) !=
	    SATA_TRAN_ACCEPTED ||
	    spkt->satapkt_reason != SATA_PKT_COMPLETED) {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));
		/*
		 * Whoops, no SMART DATA available
		 */
		rval = -1;
		goto fail;
	} else {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));
		rval = ddi_dma_sync(spx->txlt_buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		ASSERT(rval == DDI_SUCCESS);
		bcopy(scmd->satacmd_bp->b_un.b_addr, (uint8_t *)smart_data,
		    sizeof (struct smart_data));
	}

fail:
	/* Free allocated resources */
	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));

	return (rval);
}

/*
 * Used by LOG SENSE page 0x10
 *
 * return 0 for success, -1 otherwise
 *
 */
static int
sata_ext_smart_selftest_read_log(
	sata_hba_inst_t *sata_hba_inst,
	sata_drive_info_t *sdinfo,
	struct smart_ext_selftest_log *ext_selftest_log,
	uint16_t block_num)
{
	sata_pkt_txlate_t *spx;
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	int rval;

#if ! defined(lint)
	ASSERT(sizeof (struct smart_ext_selftest_log) == 512);
#endif

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (-1);
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;


	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	/* Synchronous mode, no callback */
	spkt->satapkt_comp = NULL;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;

	/*
	 * Allocate buffer for SMART extended self-test log
	 */
	scmd->satacmd_bp = sata_alloc_local_buffer(spx,
	    sizeof (struct smart_ext_selftest_log));
	if (scmd->satacmd_bp == NULL) {
		sata_pkt_free(spx);
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_ext_smart_selftest_log: "
		    "cannot allocate buffer"));
		return (-1);
	}

	/* Build READ LOG EXT w/ extended self-test log cmd in the sata_pkt */
	scmd->satacmd_addr_type = ATA_ADDR_LBA48;
	scmd->satacmd_sec_count_lsb = 1;	/* One sector of selftest log */
	scmd->satacmd_sec_count_msb = 0;	/* One sector of selftest log */
	scmd->satacmd_lba_low_lsb = EXT_SMART_SELFTEST_LOG_PAGE;
	scmd->satacmd_lba_low_msb = 0;
	scmd->satacmd_lba_mid_lsb = block_num & 0xff;
	scmd->satacmd_lba_mid_msb = block_num >> 8;
	scmd->satacmd_device_reg = 0;		/* Always device 0 */
	scmd->satacmd_cmd_reg = SATAC_READ_LOG_EXT;

	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sdinfo->satadrv_addr.cport)));

	/* Send pkt to SATA HBA driver */
	if ((*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst), spkt) !=
	    SATA_TRAN_ACCEPTED ||
	    spkt->satapkt_reason != SATA_PKT_COMPLETED) {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));

		/*
		 * Whoops, no SMART selftest log info available
		 */
		rval = -1;
		goto fail;
	} else {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));

		rval = ddi_dma_sync(spx->txlt_buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		ASSERT(rval == DDI_SUCCESS);
		bcopy(scmd->satacmd_bp->b_un.b_addr,
		    (uint8_t *)ext_selftest_log,
		    sizeof (struct smart_ext_selftest_log));
		rval = 0;
	}

fail:
	/* Free allocated resources */
	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));

	return (rval);
}

/*
 * Returns 0 for success, -1 otherwise
 *
 * SMART self-test log data is returned in buffer pointed to by selftest_log
 */
static int
sata_smart_selftest_log(
	sata_hba_inst_t *sata_hba_inst,
	sata_drive_info_t *sdinfo,
	struct smart_selftest_log *selftest_log)
{
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_pkt_txlate_t *spx;
	int rval;

#if ! defined(lint)
	ASSERT(sizeof (struct smart_selftest_log) == 512);
#endif

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (-1);
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;


	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	/* Synchronous mode, no callback */
	spkt->satapkt_comp = NULL;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;

	/*
	 * Allocate buffer for SMART SELFTEST LOG
	 */
	scmd->satacmd_bp = sata_alloc_local_buffer(spx,
	    sizeof (struct smart_selftest_log));
	if (scmd->satacmd_bp == NULL) {
		sata_pkt_free(spx);
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_smart_selftest_log: "
		    "cannot allocate buffer"));
		return (-1);
	}

	/* Build SMART_READ_LOG cmd in the sata_pkt */
	scmd->satacmd_addr_type = 0;		/* N/A */
	scmd->satacmd_sec_count_lsb = 1;	/* One sector of SMART log */
	scmd->satacmd_lba_low_lsb = SMART_SELFTEST_LOG_PAGE;
	scmd->satacmd_lba_mid_lsb = SMART_MAGIC_VAL_1;
	scmd->satacmd_lba_high_lsb = SMART_MAGIC_VAL_2;
	scmd->satacmd_features_reg = SATA_SMART_READ_LOG;
	scmd->satacmd_device_reg = 0;		/* Always device 0 */
	scmd->satacmd_cmd_reg = SATAC_SMART;
	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sdinfo->satadrv_addr.cport)));

	/* Send pkt to SATA HBA driver */
	if ((*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst), spkt) !=
	    SATA_TRAN_ACCEPTED ||
	    spkt->satapkt_reason != SATA_PKT_COMPLETED) {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));
		/*
		 * Whoops, no SMART DATA available
		 */
		rval = -1;
		goto fail;
	} else {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));
		rval = ddi_dma_sync(spx->txlt_buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		ASSERT(rval == DDI_SUCCESS);
		bcopy(scmd->satacmd_bp->b_un.b_addr, (uint8_t *)selftest_log,
		    sizeof (struct smart_selftest_log));
		rval = 0;
	}

fail:
	/* Free allocated resources */
	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));

	return (rval);
}


/*
 * Returns 0 for success, -1 otherwise
 *
 * SMART READ LOG data is returned in buffer pointed to by smart_log
 */
static int
sata_smart_read_log(
	sata_hba_inst_t *sata_hba_inst,
	sata_drive_info_t *sdinfo,
	uint8_t *smart_log,		/* where the data should be returned */
	uint8_t which_log,		/* which log should be returned */
	uint8_t log_size)		/* # of 512 bytes in log */
{
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_pkt_txlate_t *spx;
	int rval;

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (-1);
	}
	/* address is needed now */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;


	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	/* Synchronous mode, no callback */
	spkt->satapkt_comp = NULL;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;

	/*
	 * Allocate buffer for SMART READ LOG
	 */
	scmd->satacmd_bp = sata_alloc_local_buffer(spx, log_size * 512);
	if (scmd->satacmd_bp == NULL) {
		sata_pkt_free(spx);
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_smart_read_log: " "cannot allocate buffer"));
		return (-1);
	}

	/* Build SMART_READ_LOG cmd in the sata_pkt */
	scmd->satacmd_addr_type = 0;		/* N/A */
	scmd->satacmd_sec_count_lsb = log_size;	/* what the caller asked for */
	scmd->satacmd_lba_low_lsb = which_log;	/* which log page */
	scmd->satacmd_lba_mid_lsb = SMART_MAGIC_VAL_1;
	scmd->satacmd_lba_high_lsb = SMART_MAGIC_VAL_2;
	scmd->satacmd_features_reg = SATA_SMART_READ_LOG;
	scmd->satacmd_device_reg = 0;		/* Always device 0 */
	scmd->satacmd_cmd_reg = SATAC_SMART;

	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sdinfo->satadrv_addr.cport)));

	/* Send pkt to SATA HBA driver */
	if ((*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst), spkt) !=
	    SATA_TRAN_ACCEPTED ||
	    spkt->satapkt_reason != SATA_PKT_COMPLETED) {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));

		/*
		 * Whoops, no SMART DATA available
		 */
		rval = -1;
		goto fail;
	} else {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));

		rval = ddi_dma_sync(spx->txlt_buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		ASSERT(rval == DDI_SUCCESS);
		bcopy(scmd->satacmd_bp->b_un.b_addr, smart_log, log_size * 512);
		rval = 0;
	}

fail:
	/* Free allocated resources */
	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));

	return (rval);
}

/*
 * Used by LOG SENSE page 0x10
 *
 * return 0 for success, -1 otherwise
 *
 */
static int
sata_read_log_ext_directory(
	sata_hba_inst_t *sata_hba_inst,
	sata_drive_info_t *sdinfo,
	struct read_log_ext_directory *logdir)
{
	sata_pkt_txlate_t *spx;
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	int rval;

#if ! defined(lint)
	ASSERT(sizeof (struct read_log_ext_directory) == 512);
#endif

	spx = kmem_zalloc(sizeof (sata_pkt_txlate_t), KM_SLEEP);
	spx->txlt_sata_hba_inst = sata_hba_inst;
	spx->txlt_scsi_pkt = NULL;		/* No scsi pkt involved */
	spkt = sata_pkt_alloc(spx, SLEEP_FUNC);
	if (spkt == NULL) {
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		return (-1);
	}

	/* Fill sata_pkt */
	spkt->satapkt_device.satadev_addr = sdinfo->satadrv_addr;
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;
	/* Synchronous mode, no callback */
	spkt->satapkt_comp = NULL;
	/* Timeout 30s */
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	scmd->satacmd_flags.sata_data_direction = SATA_DIR_READ;

	/*
	 * Allocate buffer for SMART READ LOG EXTENDED command
	 */
	scmd->satacmd_bp = sata_alloc_local_buffer(spx,
	    sizeof (struct read_log_ext_directory));
	if (scmd->satacmd_bp == NULL) {
		sata_pkt_free(spx);
		kmem_free(spx, sizeof (sata_pkt_txlate_t));
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_read_log_ext_directory: "
		    "cannot allocate buffer"));
		return (-1);
	}

	/* Build READ LOG EXT w/ log directory cmd in the  sata_pkt */
	scmd->satacmd_addr_type = ATA_ADDR_LBA48;
	scmd->satacmd_sec_count_lsb = 1;	/* One sector of directory */
	scmd->satacmd_sec_count_msb = 0;	/* One sector of directory */
	scmd->satacmd_lba_low_lsb = READ_LOG_EXT_LOG_DIRECTORY;
	scmd->satacmd_lba_low_msb = 0;
	scmd->satacmd_lba_mid_lsb = 0;
	scmd->satacmd_lba_mid_msb = 0;
	scmd->satacmd_device_reg = 0;		/* Always device 0 */
	scmd->satacmd_cmd_reg = SATAC_READ_LOG_EXT;

	mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst,
	    sdinfo->satadrv_addr.cport)));

	/* Send pkt to SATA HBA driver */
	if ((*SATA_START_FUNC(sata_hba_inst))(SATA_DIP(sata_hba_inst), spkt) !=
	    SATA_TRAN_ACCEPTED ||
	    spkt->satapkt_reason != SATA_PKT_COMPLETED) {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));
		/*
		 * Whoops, no SMART selftest log info available
		 */
		rval = -1;
		goto fail;
	} else {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst,
		    sdinfo->satadrv_addr.cport)));
		rval = ddi_dma_sync(spx->txlt_buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		ASSERT(rval == DDI_SUCCESS);
		bcopy(scmd->satacmd_bp->b_un.b_addr, (uint8_t *)logdir,
		    sizeof (struct read_log_ext_directory));
		rval = 0;
	}

fail:
	/* Free allocated resources */
	sata_free_local_buffer(spx);
	sata_pkt_free(spx);
	kmem_free(spx, sizeof (sata_pkt_txlate_t));

	return (rval);
}

/*
 * Set up error retrieval sata command for NCQ command error data
 * recovery.
 *
 * Returns SATA_SUCCESS when data buffer is allocated and packet set-up,
 * returns SATA_FAILURE otherwise.
 */
static int
sata_ncq_err_ret_cmd_setup(sata_pkt_txlate_t *spx, sata_drive_info_t *sdinfo)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(sdinfo))
#endif

	sata_pkt_t *spkt = spx->txlt_sata_pkt;
	sata_cmd_t *scmd;
	struct buf *bp;

	/* Operation modes are up to the caller */
	spkt->satapkt_op_mode = SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS;

	/* Synchronous mode, no callback - may be changed by the caller */
	spkt->satapkt_comp = NULL;
	spkt->satapkt_time = sata_default_pkt_time;

	scmd = &spkt->satapkt_cmd;
	bcopy(&sata_rle_cmd, scmd, sizeof (sata_cmd_t));
	scmd->satacmd_flags.sata_ignore_dev_reset = B_TRUE;

	/*
	 * Allocate dma_able buffer error data.
	 * Buffer allocation will take care of buffer alignment and other DMA
	 * attributes.
	 */
	bp = sata_alloc_local_buffer(spx,
	    sizeof (struct sata_ncq_error_recovery_page));
	if (bp == NULL)
		return (SATA_FAILURE);

	bp_mapin(bp); /* make data buffer accessible */
	scmd->satacmd_bp = bp;

	/*
	 * Set-up pointer to the buffer handle, so HBA can sync buffer
	 * before accessing it. Handle is in usual place in translate struct.
	 */
	scmd->satacmd_err_ret_buf_handle = &spx->txlt_buf_dma_handle;

	ASSERT(scmd->satacmd_num_dma_cookies != 0);
	ASSERT(scmd->satacmd_dma_cookie_list != NULL);

	return (SATA_SUCCESS);
}

/*
 * sata_xlate_errors() is used to translate (S)ATA error
 * information to SCSI information returned in the SCSI
 * packet.
 */
static void
sata_xlate_errors(sata_pkt_txlate_t *spx)
{
	struct scsi_pkt *scsipkt = spx->txlt_scsi_pkt;
	struct scsi_extended_sense *sense;

	scsipkt->pkt_reason = CMD_INCOMPLETE;
	*scsipkt->pkt_scbp = STATUS_CHECK;
	sense = sata_arq_sense(spx);

	switch (spx->txlt_sata_pkt->satapkt_reason) {
	case SATA_PKT_PORT_ERROR:
		/*
		 * We have no device data. Assume no data transfered.
		 */
		sense->es_key = KEY_HARDWARE_ERROR;
		break;

	case SATA_PKT_DEV_ERROR:
		if (spx->txlt_sata_pkt->satapkt_cmd.satacmd_status_reg &
		    SATA_STATUS_ERR) {
			/*
			 * determine dev error reason from error
			 * reg content
			 */
			sata_decode_device_error(spx, sense);
			break;
		}
		/* No extended sense key - no info available */
		break;

	case SATA_PKT_TIMEOUT:
		/*
		 * scsipkt->pkt_reason = CMD_TIMEOUT; This causes problems.
		 */
		scsipkt->pkt_reason = CMD_INCOMPLETE;
		/* No extended sense key */
		break;

	case SATA_PKT_ABORTED:
		scsipkt->pkt_reason = CMD_ABORTED;
		/* No extended sense key */
		break;

	case SATA_PKT_RESET:
		/*
		 * pkt aborted either by an explicit reset request from
		 * a host, or due to error recovery
		 */
		scsipkt->pkt_reason = CMD_RESET;
		break;

	default:
		scsipkt->pkt_reason = CMD_TRAN_ERR;
		break;
	}
}




/*
 * Log sata message
 * dev pathname msg line preceeds the logged message.
 */

static	void
sata_log(sata_hba_inst_t *sata_hba_inst, uint_t level, char *fmt, ...)
{
	char pathname[128];
	dev_info_t *dip;
	va_list ap;

	mutex_enter(&sata_log_mutex);

	va_start(ap, fmt);
	(void) vsprintf(sata_log_buf, fmt, ap);
	va_end(ap);

	if (sata_hba_inst != NULL) {
		dip = SATA_DIP(sata_hba_inst);
		(void) ddi_pathname(dip, pathname);
	} else {
		pathname[0] = 0;
	}
	if (level == CE_CONT) {
		if (sata_debug_flags == 0)
			cmn_err(level, "?%s:\n %s\n", pathname, sata_log_buf);
		else
			cmn_err(level, "%s:\n %s\n", pathname, sata_log_buf);
	} else
		cmn_err(level, "%s:\n %s", pathname, sata_log_buf);

	mutex_exit(&sata_log_mutex);
}


/* ******** Asynchronous HBA events handling & hotplugging support ******** */

/*
 * Start or terminate the thread, depending on flag arg and current state
 */
static void
sata_event_thread_control(int startstop)
{
	static 	int sata_event_thread_terminating = 0;
	static 	int sata_event_thread_starting = 0;
	int i;

	mutex_enter(&sata_event_mutex);

	if (startstop == 0 && (sata_event_thread_starting == 1 ||
	    sata_event_thread_terminating == 1)) {
		mutex_exit(&sata_event_mutex);
		return;
	}
	if (startstop == 1 && sata_event_thread_starting == 1) {
		mutex_exit(&sata_event_mutex);
		return;
	}
	if (startstop == 1 && sata_event_thread_terminating == 1) {
		sata_event_thread_starting = 1;
		/* wait til terminate operation completes */
		i = SATA_EVNT_DAEMON_TERM_WAIT/SATA_EVNT_DAEMON_TERM_TIMEOUT;
		while (sata_event_thread_terminating == 1) {
			if (i-- <= 0) {
				sata_event_thread_starting = 0;
				mutex_exit(&sata_event_mutex);
#ifdef SATA_DEBUG
				cmn_err(CE_WARN, "sata_event_thread_control: "
				    "timeout waiting for thread to terminate");
#endif
				return;
			}
			mutex_exit(&sata_event_mutex);
			delay(drv_usectohz(SATA_EVNT_DAEMON_TERM_TIMEOUT));
			mutex_enter(&sata_event_mutex);
		}
	}
	if (startstop == 1) {
		if (sata_event_thread == NULL) {
			sata_event_thread = thread_create(NULL, 0,
			    (void (*)())sata_event_daemon,
			    &sata_hba_list, 0, &p0, TS_RUN, minclsyspri);
		}
		sata_event_thread_starting = 0;
		mutex_exit(&sata_event_mutex);
		return;
	}

	/*
	 * If we got here, thread may need to be terminated
	 */
	if (sata_event_thread != NULL) {
		int i;
		/* Signal event thread to go away */
		sata_event_thread_terminating = 1;
		sata_event_thread_terminate = 1;
		cv_signal(&sata_event_cv);
		/*
		 * Wait til daemon terminates.
		 */
		i = SATA_EVNT_DAEMON_TERM_WAIT/SATA_EVNT_DAEMON_TERM_TIMEOUT;
		while (sata_event_thread_terminate == 1) {
			mutex_exit(&sata_event_mutex);
			if (i-- <= 0) {
				/* Daemon did not go away !!! */
#ifdef SATA_DEBUG
				cmn_err(CE_WARN, "sata_event_thread_control: "
				    "cannot terminate event daemon thread");
#endif
				mutex_enter(&sata_event_mutex);
				break;
			}
			delay(drv_usectohz(SATA_EVNT_DAEMON_TERM_TIMEOUT));
			mutex_enter(&sata_event_mutex);
		}
		sata_event_thread_terminating = 0;
	}
	ASSERT(sata_event_thread_terminating == 0);
	ASSERT(sata_event_thread_starting == 0);
	mutex_exit(&sata_event_mutex);
}


/*
 * SATA HBA event notification function.
 * Events reported by SATA HBA drivers per HBA instance relate to a change in
 * a port and/or device state or a controller itself.
 * Events for different addresses/addr types cannot be combined.
 * A warning message is generated for each event type.
 * Events are not processed by this function, so only the
 * event flag(s)is set for an affected entity and the event thread is
 * waken up. Event daemon thread processes all events.
 *
 * NOTE: Since more than one event may be reported at the same time, one
 * cannot determine a sequence of events when opposite event are reported, eg.
 * LINK_LOST and LINK_ESTABLISHED. Actual port status during event processing
 * is taking precedence over reported events, i.e. may cause ignoring some
 * events.
 */
#define	SATA_EVENT_MAX_MSG_LENGTH	79

void
sata_hba_event_notify(dev_info_t *dip, sata_device_t *sata_device, int event)
{
	sata_hba_inst_t *sata_hba_inst = NULL;
	sata_address_t *saddr;
	sata_drive_info_t *sdinfo;
	sata_port_stats_t *pstats;
	int cport, pmport;
	char buf1[SATA_EVENT_MAX_MSG_LENGTH + 1];
	char buf2[SATA_EVENT_MAX_MSG_LENGTH + 1];
	char *lcp;
	static char *err_msg_evnt_1 =
	    "sata_hba_event_notify: invalid port event 0x%x ";
	static char *err_msg_evnt_2 =
	    "sata_hba_event_notify: invalid device event 0x%x ";
	int linkevent;

	/*
	 * There is a possibility that an event will be generated on HBA
	 * that has not completed attachment or is detaching.
	 * HBA driver should prevent this, but just in case it does not,
	 * we need to ignore events for such HBA.
	 */
	mutex_enter(&sata_mutex);
	for (sata_hba_inst = sata_hba_list; sata_hba_inst != NULL;
	    sata_hba_inst = sata_hba_inst->satahba_next) {
		if (SATA_DIP(sata_hba_inst) == dip)
			if (sata_hba_inst->satahba_attached == 1)
				break;
	}
	mutex_exit(&sata_mutex);
	if (sata_hba_inst == NULL)
		/* HBA not attached */
		return;

	ASSERT(sata_device != NULL);

	/*
	 * Validate address before - do not proceed with invalid address.
	 */
	saddr = &sata_device->satadev_addr;
	if (saddr->cport >= SATA_NUM_CPORTS(sata_hba_inst))
		return;
	if (saddr->qual == SATA_ADDR_PMPORT ||
	    saddr->qual == SATA_ADDR_DPMPORT)
		/* Port Multiplier not supported yet */
		return;

	cport = saddr->cport;
	pmport = saddr->pmport;

	buf1[0] = buf2[0] = '\0';

	/*
	 * Events refer to devices, ports and controllers - each has
	 * unique address. Events for different addresses cannot be combined.
	 */
	if (saddr->qual & (SATA_ADDR_CPORT | SATA_ADDR_PMPORT)) {

		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));

		/* qualify this event(s) */
		if ((event & SATA_EVNT_PORT_EVENTS) == 0) {
			/* Invalid event for the device port */
			(void) sprintf(buf2, err_msg_evnt_1,
			    event & SATA_EVNT_PORT_EVENTS);
			mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));
			goto event_info;
		}
		if (saddr->qual == SATA_ADDR_CPORT) {
			/* Controller's device port event */

			(SATA_CPORT_INFO(sata_hba_inst, cport))->
			    cport_event_flags |=
			    event & SATA_EVNT_PORT_EVENTS;
			pstats =
			    &(SATA_CPORT_INFO(sata_hba_inst, cport))->
			    cport_stats;
		} else {
			/* Port multiplier's device port event */
			(SATA_PMPORT_INFO(sata_hba_inst, cport, pmport))->
			    pmport_event_flags |=
			    event & SATA_EVNT_PORT_EVENTS;
			pstats =
			    &(SATA_PMPORT_INFO(sata_hba_inst, cport, pmport))->
			    pmport_stats;
		}

		/*
		 * Add to statistics and log the message. We have to do it
		 * here rather than in the event daemon, because there may be
		 * multiple events occuring before they are processed.
		 */
		linkevent = event &
		    (SATA_EVNT_LINK_LOST | SATA_EVNT_LINK_ESTABLISHED);
		if (linkevent) {
			if (linkevent == (SATA_EVNT_LINK_LOST |
			    SATA_EVNT_LINK_ESTABLISHED)) {
				/* This is likely event combination */
				(void) strlcat(buf1, "link lost/established, ",
				    SATA_EVENT_MAX_MSG_LENGTH);

				if (pstats->link_lost < 0xffffffffffffffffULL)
					pstats->link_lost++;
				if (pstats->link_established <
				    0xffffffffffffffffULL)
					pstats->link_established++;
				linkevent = 0;
			} else if (linkevent & SATA_EVNT_LINK_LOST) {
				(void) strlcat(buf1, "link lost, ",
				    SATA_EVENT_MAX_MSG_LENGTH);

				if (pstats->link_lost < 0xffffffffffffffffULL)
					pstats->link_lost++;
			} else {
				(void) strlcat(buf1, "link established, ",
				    SATA_EVENT_MAX_MSG_LENGTH);
				if (pstats->link_established <
				    0xffffffffffffffffULL)
					pstats->link_established++;
			}
		}
		if (event & SATA_EVNT_DEVICE_ATTACHED) {
			(void) strlcat(buf1, "device attached, ",
			    SATA_EVENT_MAX_MSG_LENGTH);
			if (pstats->device_attached < 0xffffffffffffffffULL)
				pstats->device_attached++;
		}
		if (event & SATA_EVNT_DEVICE_DETACHED) {
			(void) strlcat(buf1, "device detached, ",
			    SATA_EVENT_MAX_MSG_LENGTH);
			if (pstats->device_detached < 0xffffffffffffffffULL)
				pstats->device_detached++;
		}
		if (event & SATA_EVNT_PWR_LEVEL_CHANGED) {
			SATADBG1(SATA_DBG_EVENTS, sata_hba_inst,
			    "port %d power level changed", cport);
			if (pstats->port_pwr_changed < 0xffffffffffffffffULL)
				pstats->port_pwr_changed++;
		}

		if ((event & ~SATA_EVNT_PORT_EVENTS) != 0) {
			/* There should be no other events for this address */
			(void) sprintf(buf2, err_msg_evnt_1,
			    event & ~SATA_EVNT_PORT_EVENTS);
		}
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));

	} else if (saddr->qual & (SATA_ADDR_DCPORT | SATA_ADDR_DPMPORT)) {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));

		/* qualify this event */
		if ((event & SATA_EVNT_DEVICE_RESET) == 0) {
			/* Invalid event for a device */
			(void) sprintf(buf2, err_msg_evnt_2,
			    event & SATA_EVNT_DEVICE_RESET);
			mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));
			goto event_info;
		}
		/* drive event */
		sdinfo = sata_get_device_info(sata_hba_inst, sata_device);
		if (sdinfo != NULL) {
			if (event & SATA_EVNT_DEVICE_RESET) {
				(void) strlcat(buf1, "device reset, ",
				    SATA_EVENT_MAX_MSG_LENGTH);
				if (sdinfo->satadrv_stats.drive_reset <
				    0xffffffffffffffffULL)
					sdinfo->satadrv_stats.drive_reset++;
				sdinfo->satadrv_event_flags |=
				    SATA_EVNT_DEVICE_RESET;
			}
		}
		if ((event & ~SATA_EVNT_DEVICE_RESET) != 0) {
			/* Invalid event for a device */
			(void) sprintf(buf2, err_msg_evnt_2,
			    event & ~SATA_EVNT_DRIVE_EVENTS);
		}
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, cport)));
	} else {
		if (saddr->qual != SATA_ADDR_NULL) {
			/* Wrong address qualifier */
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "sata_hba_event_notify: invalid address 0x%x",
			    *(uint32_t *)saddr));
			return;
		}
		if ((event & SATA_EVNT_CONTROLLER_EVENTS) == 0 ||
		    (event & ~SATA_EVNT_CONTROLLER_EVENTS) != 0) {
			/* Invalid event for the controller */
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "sata_hba_event_notify: invalid event 0x%x for "
			    "controller",
			    event & SATA_EVNT_CONTROLLER_EVENTS));
			return;
		}
		buf1[0] = '\0';
		/* This may be a frequent and not interesting event */
		SATADBG1(SATA_DBG_EVENTS, sata_hba_inst,
		    "controller power level changed\n", NULL);

		mutex_enter(&sata_hba_inst->satahba_mutex);
		if (sata_hba_inst->satahba_stats.ctrl_pwr_change <
		    0xffffffffffffffffULL)
			sata_hba_inst->satahba_stats.ctrl_pwr_change++;

		sata_hba_inst->satahba_event_flags |=
		    SATA_EVNT_PWR_LEVEL_CHANGED;
		mutex_exit(&sata_hba_inst->satahba_mutex);
	}
	/*
	 * If we got here, there is something to do with this HBA
	 * instance.
	 */
	mutex_enter(&sata_hba_inst->satahba_mutex);
	sata_hba_inst->satahba_event_flags |= SATA_EVNT_MAIN;
	mutex_exit(&sata_hba_inst->satahba_mutex);
	mutex_enter(&sata_mutex);
	sata_event_pending |= SATA_EVNT_MAIN;	/* global event indicator */
	mutex_exit(&sata_mutex);

	/* Tickle event thread */
	mutex_enter(&sata_event_mutex);
	if (sata_event_thread_active == 0)
		cv_signal(&sata_event_cv);
	mutex_exit(&sata_event_mutex);

event_info:
	if (buf1[0] != '\0') {
		lcp = strrchr(buf1, ',');
		if (lcp != NULL)
			*lcp = '\0';
	}
	if (saddr->qual == SATA_ADDR_CPORT ||
	    saddr->qual == SATA_ADDR_DCPORT) {
		if (buf1[0] != '\0') {
			sata_log(sata_hba_inst, CE_NOTE, "port %d: %s\n",
			    cport, buf1);
		}
		if (buf2[0] != '\0') {
			sata_log(sata_hba_inst, CE_NOTE, "port %d: %s\n",
			    cport, buf2);
		}
	} else if (saddr->qual == SATA_ADDR_PMPORT ||
	    saddr->qual == SATA_ADDR_DPMPORT) {
		if (buf1[0] != '\0') {
			sata_log(sata_hba_inst, CE_NOTE,
			    "port %d pmport %d: %s\n", cport, pmport, buf1);
		}
		if (buf2[0] != '\0') {
			sata_log(sata_hba_inst, CE_NOTE,
			    "port %d pmport %d: %s\n", cport, pmport, buf2);
		}
	}
}


/*
 * Event processing thread.
 * Arg is a pointer to the sata_hba_list pointer.
 * It is not really needed, because sata_hba_list is global and static
 */
static void
sata_event_daemon(void *arg)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(arg))
#endif
	sata_hba_inst_t *sata_hba_inst;
	clock_t lbolt;

	SATADBG1(SATA_DBG_EVENTS_DAEMON, NULL,
	    "SATA event daemon started\n", NULL);
loop:
	/*
	 * Process events here. Walk through all registered HBAs
	 */
	mutex_enter(&sata_mutex);
	for (sata_hba_inst = sata_hba_list; sata_hba_inst != NULL;
	    sata_hba_inst = sata_hba_inst->satahba_next) {
		ASSERT(sata_hba_inst != NULL);
		mutex_enter(&sata_hba_inst->satahba_mutex);
		if (sata_hba_inst->satahba_attached != 1 ||
		    (sata_hba_inst->satahba_event_flags &
		    SATA_EVNT_SKIP) != 0) {
			mutex_exit(&sata_hba_inst->satahba_mutex);
			continue;
		}
		if (sata_hba_inst->satahba_event_flags & SATA_EVNT_MAIN) {
			sata_hba_inst->satahba_event_flags |= SATA_EVNT_SKIP;
			mutex_exit(&sata_hba_inst->satahba_mutex);
			mutex_exit(&sata_mutex);
			/* Got the controller with pending event */
			sata_process_controller_events(sata_hba_inst);
			/*
			 * Since global mutex was released, there is a
			 * possibility that HBA list has changed, so start
			 * over from the top. Just processed controller
			 * will be passed-over because of the SKIP flag.
			 */
			goto loop;
		}
		mutex_exit(&sata_hba_inst->satahba_mutex);
	}
	/* Clear SKIP flag in all controllers */
	for (sata_hba_inst = sata_hba_list; sata_hba_inst != NULL;
	    sata_hba_inst = sata_hba_inst->satahba_next) {
		mutex_enter(&sata_hba_inst->satahba_mutex);
		sata_hba_inst->satahba_event_flags &= ~SATA_EVNT_SKIP;
		mutex_exit(&sata_hba_inst->satahba_mutex);
	}
	mutex_exit(&sata_mutex);

	SATADBG1(SATA_DBG_EVENTS_DAEMON, NULL,
	    "SATA EVENT DAEMON suspending itself", NULL);

#ifdef SATA_DEBUG
	if ((sata_func_enable & SATA_ENABLE_PROCESS_EVENTS) == 0) {
		sata_log(sata_hba_inst, CE_WARN,
		    "SATA EVENTS PROCESSING DISABLED\n");
		thread_exit(); /* Daemon will not run again */
	}
#endif
	mutex_enter(&sata_event_mutex);
	sata_event_thread_active = 0;
	mutex_exit(&sata_event_mutex);
	/*
	 * Go to sleep/suspend itself and wake up either because new event or
	 * wait timeout. Exit if there is a termination request (driver
	 * unload).
	 */
	do {
		lbolt = ddi_get_lbolt();
		lbolt += drv_usectohz(SATA_EVNT_DAEMON_SLEEP_TIME);
		mutex_enter(&sata_event_mutex);
		(void) cv_timedwait(&sata_event_cv, &sata_event_mutex, lbolt);

		if (sata_event_thread_active != 0) {
			mutex_exit(&sata_event_mutex);
			continue;
		}

		/* Check if it is time to go away */
		if (sata_event_thread_terminate == 1) {
			/*
			 * It is up to the thread setting above flag to make
			 * sure that this thread is not killed prematurely.
			 */
			sata_event_thread_terminate = 0;
			sata_event_thread = NULL;
			mutex_exit(&sata_event_mutex);
			SATADBG1(SATA_DBG_EVENTS_DAEMON, NULL,
			    "SATA_EVENT_DAEMON_TERMINATING", NULL);
			thread_exit();  { _NOTE(NOT_REACHED) }
		}
		mutex_exit(&sata_event_mutex);
	} while (!(sata_event_pending & SATA_EVNT_MAIN));

	mutex_enter(&sata_event_mutex);
	sata_event_thread_active = 1;
	mutex_exit(&sata_event_mutex);

	mutex_enter(&sata_mutex);
	sata_event_pending &= ~SATA_EVNT_MAIN;
	mutex_exit(&sata_mutex);

	SATADBG1(SATA_DBG_EVENTS_DAEMON, NULL,
	    "SATA EVENT DAEMON READY TO PROCESS EVENT", NULL);

	goto loop;
}

/*
 * Specific HBA instance event processing.
 *
 * NOTE: At the moment, device event processing is limited to hard disks
 * only.
 * cports only are supported - no pmports.
 */
static void
sata_process_controller_events(sata_hba_inst_t *sata_hba_inst)
{
	int ncport;
	uint32_t event_flags;
	sata_address_t *saddr;

	SATADBG1(SATA_DBG_EVENTS_CNTRL, sata_hba_inst,
	    "Processing controller %d event(s)",
	    ddi_get_instance(SATA_DIP(sata_hba_inst)));

	mutex_enter(&sata_hba_inst->satahba_mutex);
	sata_hba_inst->satahba_event_flags &= ~SATA_EVNT_MAIN;
	event_flags = sata_hba_inst->satahba_event_flags;
	mutex_exit(&sata_hba_inst->satahba_mutex);
	/*
	 * Process controller power change first
	 * HERE
	 */
	if (event_flags & SATA_EVNT_PWR_LEVEL_CHANGED)
		sata_process_cntrl_pwr_level_change(sata_hba_inst);

	/*
	 * Search through ports/devices to identify affected port/device.
	 * We may have to process events for more than one port/device.
	 */
	for (ncport = 0; ncport < SATA_NUM_CPORTS(sata_hba_inst); ncport++) {
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst, ncport)));
		event_flags = (SATA_CPORT_INFO(sata_hba_inst, ncport))->
		    cport_event_flags;
		/* Check if port was locked by IOCTL processing */
		if (event_flags & SATA_APCTL_LOCK_PORT_BUSY) {
			/*
			 * We ignore port events because port is busy
			 * with AP control processing. Set again
			 * controller and main event flag, so that
			 * events may be processed by the next daemon
			 * run.
			 */
			mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, ncport)));
			mutex_enter(&sata_hba_inst->satahba_mutex);
			sata_hba_inst->satahba_event_flags |= SATA_EVNT_MAIN;
			mutex_exit(&sata_hba_inst->satahba_mutex);
			mutex_enter(&sata_mutex);
			sata_event_pending |= SATA_EVNT_MAIN;
			mutex_exit(&sata_mutex);
			SATADBG1(SATA_DBG_EVENTS_PROCPST, sata_hba_inst,
			    "Event processing postponed until "
			    "AP control processing completes",
			    NULL);
			/* Check other ports */
			continue;
		} else {
			/*
			 * Set BSY flag so that AP control would not
			 * interfere with events processing for
			 * this port.
			 */
			(SATA_CPORT_INFO(sata_hba_inst, ncport))->
			    cport_event_flags |= SATA_EVNT_LOCK_PORT_BUSY;
		}
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, ncport)));

		saddr = &(SATA_CPORT_INFO(sata_hba_inst, ncport))->cport_addr;

		if ((event_flags &
		    (SATA_EVNT_PORT_EVENTS | SATA_EVNT_DRIVE_EVENTS)) != 0) {
			/*
			 * Got port event.
			 * We need some hierarchy of event processing as they
			 * are affecting each other:
			 * 1. port failed
			 * 2. device detached/attached
			 * 3. link events - link events may trigger device
			 *    detached or device attached events in some
			 *    circumstances.
			 * 4. port power level changed
			 */
			if (event_flags & SATA_EVNT_PORT_FAILED) {
				sata_process_port_failed_event(sata_hba_inst,
				    saddr);
			}
			if (event_flags & SATA_EVNT_DEVICE_DETACHED) {
				sata_process_device_detached(sata_hba_inst,
				    saddr);
			}
			if (event_flags & SATA_EVNT_DEVICE_ATTACHED) {
				sata_process_device_attached(sata_hba_inst,
				    saddr);
			}
			if (event_flags &
			    (SATA_EVNT_LINK_ESTABLISHED |
			    SATA_EVNT_LINK_LOST)) {
				sata_process_port_link_events(sata_hba_inst,
				    saddr);
			}
			if (event_flags & SATA_EVNT_PWR_LEVEL_CHANGED) {
				sata_process_port_pwr_change(sata_hba_inst,
				    saddr);
			}
			if (event_flags & SATA_EVNT_TARGET_NODE_CLEANUP) {
				sata_process_target_node_cleanup(
				    sata_hba_inst, saddr);
			}
		}
		if (SATA_CPORT_DEV_TYPE(sata_hba_inst, ncport) !=
		    SATA_DTYPE_NONE) {
			/* May have device event */
			sata_process_device_reset(sata_hba_inst, saddr);
		}
		mutex_enter(&(SATA_CPORT_MUTEX(sata_hba_inst, ncport)));
		/* Release PORT_BUSY flag */
		(SATA_CPORT_INFO(sata_hba_inst, ncport))->
		    cport_event_flags &= ~SATA_EVNT_LOCK_PORT_BUSY;
		mutex_exit(&(SATA_CPORT_MUTEX(sata_hba_inst, ncport)));

	} /* End of loop through the controller SATA ports */
}

/*
 * Process HBA power level change reported by HBA driver.
 * Not implemented at this time - event is ignored.
 */
static void
sata_process_cntrl_pwr_level_change(sata_hba_inst_t *sata_hba_inst)
{
	SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
	    "Processing controller power level change", NULL);

	/* Ignoring it for now */
	mutex_enter(&sata_hba_inst->satahba_mutex);
	sata_hba_inst->satahba_event_flags &= ~SATA_EVNT_PWR_LEVEL_CHANGED;
	mutex_exit(&sata_hba_inst->satahba_mutex);
}

/*
 * Process port power level change reported by HBA driver.
 * Not implemented at this time - event is ignored.
 */
static void
sata_process_port_pwr_change(sata_hba_inst_t *sata_hba_inst,
    sata_address_t *saddr)
{
	sata_cport_info_t *cportinfo;

	SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
	    "Processing port power level change", NULL);

	cportinfo = SATA_CPORT_INFO(sata_hba_inst, saddr->cport);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	/* Reset event flag */
	cportinfo->cport_event_flags &= ~SATA_EVNT_PWR_LEVEL_CHANGED;
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
}

/*
 * Process port failure reported by HBA driver.
 * cports support only - no pmports.
 */
static void
sata_process_port_failed_event(sata_hba_inst_t *sata_hba_inst,
    sata_address_t *saddr)
{
	sata_cport_info_t *cportinfo;

	cportinfo = SATA_CPORT_INFO(sata_hba_inst, saddr->cport);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	/* Reset event flag first */
	cportinfo->cport_event_flags &= ~SATA_EVNT_PORT_FAILED;
	/* If the port is in SHUTDOWN or FAILED state, ignore this event. */
	if ((cportinfo->cport_state &
	    (SATA_PSTATE_SHUTDOWN | SATA_PSTATE_FAILED)) == 0) {
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}
	/* Fail the port */
	cportinfo->cport_state = SATA_PSTATE_FAILED;
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	sata_log(sata_hba_inst, CE_WARN, "SATA port %d failed", saddr->cport);
}

/*
 * Device Reset Event processing.
 * The seqeunce is managed by 3 stage flags:
 * - reset event reported,
 * - reset event being processed,
 * - request to clear device reset state.
 */
static void
sata_process_device_reset(sata_hba_inst_t *sata_hba_inst,
    sata_address_t *saddr)
{
	sata_drive_info_t old_sdinfo; /* local copy of the drive info */
	sata_drive_info_t *sdinfo;
	sata_cport_info_t *cportinfo;
	sata_device_t sata_device;
	int rval;

	/* We only care about host sata cport for now */
	cportinfo = SATA_CPORT_INFO(sata_hba_inst, saddr->cport);

	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);

	/* If the port is in SHUTDOWN or FAILED state, ignore reset event. */
	if ((cportinfo->cport_state &
	    (SATA_PSTATE_SHUTDOWN | SATA_PSTATE_FAILED)) != 0) {
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}

	if ((SATA_CPORT_DEV_TYPE(sata_hba_inst, saddr->cport) &
	    SATA_VALID_DEV_TYPE) == 0) {
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}
	sdinfo = SATA_CPORT_DRV_INFO(sata_hba_inst, saddr->cport);
	if (sdinfo == NULL) {
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}

	if ((sdinfo->satadrv_event_flags &
	    (SATA_EVNT_DEVICE_RESET | SATA_EVNT_INPROC_DEVICE_RESET)) == 0) {
		/* Nothing to do */
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}
#ifdef SATA_DEBUG
	if ((sdinfo->satadrv_event_flags &
	    (SATA_EVNT_DEVICE_RESET | SATA_EVNT_INPROC_DEVICE_RESET)) ==
	    (SATA_EVNT_DEVICE_RESET | SATA_EVNT_INPROC_DEVICE_RESET)) {
		/* Something is weird - new device reset event */
		SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
		    "Overlapping device reset events!", NULL);
	}
#endif
	SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
	    "Processing port %d device reset", saddr->cport);

	/* Clear event flag */
	sdinfo->satadrv_event_flags &= ~SATA_EVNT_DEVICE_RESET;

	/* It seems that we always need to check the port state first */
	sata_device.satadev_rev = SATA_DEVICE_REV;
	sata_device.satadev_addr = *saddr;
	/*
	 * We have to exit mutex, because the HBA probe port function may
	 * block on its own mutex.
	 */
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
	    (SATA_DIP(sata_hba_inst), &sata_device);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	sata_update_port_info(sata_hba_inst, &sata_device);
	if (rval != SATA_SUCCESS) {
		/* Something went wrong? Fail the port */
		cportinfo->cport_state = SATA_PSTATE_FAILED;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "SATA port %d probing failed",
		    saddr->cport));
		return;
	}
	if ((sata_device.satadev_scr.sstatus  &
	    SATA_PORT_DEVLINK_UP_MASK) !=
	    SATA_PORT_DEVLINK_UP ||
	    sata_device.satadev_type == SATA_DTYPE_NONE) {
		/*
		 * No device to process, anymore. Some other event processing
		 * would or have already performed port info cleanup.
		 * To be safe (HBA may need it), request clearing device
		 * reset condition.
		 */
		sdinfo->satadrv_event_flags = 0;
		sdinfo->satadrv_event_flags |= SATA_EVNT_CLEAR_DEVICE_RESET;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}

	/* Mark device reset processing as active */
	sdinfo->satadrv_event_flags |= SATA_EVNT_INPROC_DEVICE_RESET;

	old_sdinfo = *sdinfo;	/* local copy of the drive info */
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);

	if (sata_set_drive_features(sata_hba_inst, &old_sdinfo, 1) ==
	    SATA_FAILURE) {
		/*
		 * Restoring drive setting failed.
		 * Probe the port first, to check if the port state has changed
		 */
		sata_device.satadev_rev = SATA_DEVICE_REV;
		sata_device.satadev_addr = *saddr;
		sata_device.satadev_addr.qual = SATA_ADDR_CPORT;
		/* probe port */
		rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
		    (SATA_DIP(sata_hba_inst), &sata_device);
		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		if (rval == SATA_SUCCESS &&
		    (sata_device.satadev_state &
		    (SATA_PSTATE_SHUTDOWN | SATA_PSTATE_FAILED)) == 0 &&
		    (sata_device.satadev_scr.sstatus  &
		    SATA_PORT_DEVLINK_UP_MASK) == SATA_PORT_DEVLINK_UP &&
		    sata_device.satadev_type != SATA_DTYPE_NONE) {
			/*
			 * We may retry this a bit later - in-process reset
			 * condition should be already set.
			 */
			if ((cportinfo->cport_dev_type &
			    SATA_VALID_DEV_TYPE) != 0 &&
			    SATA_CPORTINFO_DRV_INFO(cportinfo) != NULL) {
				sdinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    saddr->cport)->cport_mutex);
				mutex_enter(&sata_hba_inst->satahba_mutex);
				sata_hba_inst->satahba_event_flags |=
				    SATA_EVNT_MAIN;
				mutex_exit(&sata_hba_inst->satahba_mutex);
				mutex_enter(&sata_mutex);
				sata_event_pending |= SATA_EVNT_MAIN;
				mutex_exit(&sata_mutex);
				return;
			}
		} else {
			/*
			 * No point of retrying - some other event processing
			 * would or already did port info cleanup.
			 * To be safe (HBA may need it),
			 * request clearing device reset condition.
			 */
			sdinfo->satadrv_event_flags = 0;
			sdinfo->satadrv_event_flags |=
			    SATA_EVNT_CLEAR_DEVICE_RESET;
		}
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}

	/*
	 * Raise the flag indicating that the next sata command could
	 * be sent with SATA_CLEAR_DEV_RESET_STATE flag, if no new device
	 * reset is reported.
	 */
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	if ((cportinfo->cport_dev_type & SATA_VALID_DEV_TYPE) != 0 &&
	    SATA_CPORTINFO_DRV_INFO(cportinfo) != NULL) {
		sdinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);
		sdinfo->satadrv_event_flags &= ~SATA_EVNT_INPROC_DEVICE_RESET;
		sdinfo->satadrv_event_flags |= SATA_EVNT_CLEAR_DEVICE_RESET;
	}
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
}


/*
 * Port Link Events processing.
 * Every link established event may involve device reset (due to
 * COMRESET signal, equivalent of the hard reset) so arbitrarily
 * set device reset event for an attached device (if any).
 * If the port is in SHUTDOWN or FAILED state, ignore link events.
 *
 * The link established event processing varies, depending on the state
 * of the target node, HBA hotplugging capabilities, state of the port.
 * If the link is not active, the link established event is ignored.
 * If HBA cannot detect device attachment and there is no target node,
 * the link established event triggers device attach event processing.
 * Else, link established event triggers device reset event processing.
 *
 * The link lost event processing varies, depending on a HBA hotplugging
 * capability and the state of the port (link active or not active).
 * If the link is active, the lost link event is ignored.
 * If HBA cannot detect device removal, the lost link event triggers
 * device detached event processing after link lost timeout.
 * Else, the event is ignored.
 *
 * NOTE: Only cports are processed for now, i.e. no port multiplier ports
 */
static void
sata_process_port_link_events(sata_hba_inst_t *sata_hba_inst,
    sata_address_t *saddr)
{
	sata_device_t sata_device;
	sata_cport_info_t *cportinfo;
	sata_drive_info_t *sdinfo;
	uint32_t event_flags;
	int rval;

	SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
	    "Processing port %d link event(s)", saddr->cport);

	cportinfo = SATA_CPORT_INFO(sata_hba_inst, saddr->cport);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	event_flags = cportinfo->cport_event_flags;

	/* Reset event flags first */
	cportinfo->cport_event_flags &=
	    ~(SATA_EVNT_LINK_ESTABLISHED | SATA_EVNT_LINK_LOST);

	/* If the port is in SHUTDOWN or FAILED state, ignore link events. */
	if ((cportinfo->cport_state &
	    (SATA_PSTATE_SHUTDOWN | SATA_PSTATE_FAILED)) != 0) {
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}

	/*
	 * For the sanity sake get current port state.
	 * Set device address only. Other sata_device fields should be
	 * set by HBA driver.
	 */
	sata_device.satadev_rev = SATA_DEVICE_REV;
	sata_device.satadev_addr = *saddr;
	/*
	 * We have to exit mutex, because the HBA probe port function may
	 * block on its own mutex.
	 */
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
	    (SATA_DIP(sata_hba_inst), &sata_device);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	sata_update_port_info(sata_hba_inst, &sata_device);
	if (rval != SATA_SUCCESS) {
		/* Something went wrong? Fail the port */
		cportinfo->cport_state = SATA_PSTATE_FAILED;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "SATA port %d probing failed",
		    saddr->cport));
		/*
		 * We may want to release device info structure, but
		 * it is not necessary.
		 */
		return;
	} else {
		/* port probed successfully */
		cportinfo->cport_state |= SATA_STATE_PROBED | SATA_STATE_READY;
	}
	if (event_flags & SATA_EVNT_LINK_ESTABLISHED) {

		if ((sata_device.satadev_scr.sstatus &
		    SATA_PORT_DEVLINK_UP_MASK) != SATA_PORT_DEVLINK_UP) {
			/* Ignore event */
			SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
			    "Ignoring port %d link established event - "
			    "link down",
			    saddr->cport);
			goto linklost;
		}

		SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
		    "Processing port %d link established event",
		    saddr->cport);

		/*
		 * For the sanity sake check if a device is attached - check
		 * return state of a port probing.
		 */
		if (sata_device.satadev_type != SATA_DTYPE_NONE &&
		    sata_device.satadev_type != SATA_DTYPE_PMULT) {
			/*
			 * HBA port probe indicated that there is a device
			 * attached. Check if the framework had device info
			 * structure attached for this device.
			 */
			if (cportinfo->cport_dev_type != SATA_DTYPE_NONE) {
				ASSERT(SATA_CPORTINFO_DRV_INFO(cportinfo) !=
				    NULL);

				sdinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);
				if ((sdinfo->satadrv_type &
				    SATA_VALID_DEV_TYPE) != 0) {
					/*
					 * Dev info structure is present.
					 * If dev_type is set to known type in
					 * the framework's drive info struct
					 * then the device existed before and
					 * the link was probably lost
					 * momentarily - in such case
					 * we may want to check device
					 * identity.
					 * Identity check is not supported now.
					 *
					 * Link established event
					 * triggers device reset event.
					 */
					(SATA_CPORTINFO_DRV_INFO(cportinfo))->
					    satadrv_event_flags |=
					    SATA_EVNT_DEVICE_RESET;
				}
			} else if (cportinfo->cport_dev_type ==
			    SATA_DTYPE_NONE) {
				/*
				 * We got new device attached! If HBA does not
				 * generate device attached events, trigger it
				 * here.
				 */
				if (!(SATA_FEATURES(sata_hba_inst) &
				    SATA_CTLF_HOTPLUG)) {
					cportinfo->cport_event_flags |=
					    SATA_EVNT_DEVICE_ATTACHED;
				}
			}
			/* Reset link lost timeout */
			cportinfo->cport_link_lost_time = 0;
		}
	}
linklost:
	if (event_flags & SATA_EVNT_LINK_LOST) {
		if ((sata_device.satadev_scr.sstatus &
		    SATA_PORT_DEVLINK_UP_MASK) == SATA_PORT_DEVLINK_UP) {
			/* Ignore event */
			SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
			    "Ignoring port %d link lost event - link is up",
			    saddr->cport);
			goto done;
		}
#ifdef SATA_DEBUG
		if (cportinfo->cport_link_lost_time == 0) {
			SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
			    "Processing port %d link lost event",
			    saddr->cport);
		}
#endif
		/*
		 * When HBA cannot generate device attached/detached events,
		 * we need to track link lost time and eventually generate
		 * device detach event.
		 */
		if (!(SATA_FEATURES(sata_hba_inst) & SATA_CTLF_HOTPLUG)) {
			/* We are tracking link lost time */
			if (cportinfo->cport_link_lost_time == 0) {
				/* save current time (lbolt value) */
				cportinfo->cport_link_lost_time =
				    ddi_get_lbolt();
				/* just keep link lost event */
				cportinfo->cport_event_flags |=
				    SATA_EVNT_LINK_LOST;
			} else {
				clock_t cur_time = ddi_get_lbolt();
				if ((cur_time -
				    cportinfo->cport_link_lost_time) >=
				    drv_usectohz(
				    SATA_EVNT_LINK_LOST_TIMEOUT)) {
					/* trigger device detach event */
					cportinfo->cport_event_flags |=
					    SATA_EVNT_DEVICE_DETACHED;
					cportinfo->cport_link_lost_time = 0;
					SATADBG1(SATA_DBG_EVENTS,
					    sata_hba_inst,
					    "Triggering port %d "
					    "device detached event",
					    saddr->cport);
				} else {
					/* keep link lost event */
					cportinfo->cport_event_flags |=
					    SATA_EVNT_LINK_LOST;
				}
			}
		}
		/*
		 * We could change port state to disable/delay access to
		 * the attached device until the link is recovered.
		 */
	}
done:
	event_flags = cportinfo->cport_event_flags;
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	if (event_flags != 0) {
		mutex_enter(&sata_hba_inst->satahba_mutex);
		sata_hba_inst->satahba_event_flags |= SATA_EVNT_MAIN;
		mutex_exit(&sata_hba_inst->satahba_mutex);
		mutex_enter(&sata_mutex);
		sata_event_pending |= SATA_EVNT_MAIN;
		mutex_exit(&sata_mutex);
	}
}

/*
 * Device Detached Event processing.
 * Port is probed to find if a device is really gone. If so,
 * the device info structure is detached from the SATA port info structure
 * and released.
 * Port status is updated.
 *
 * NOTE: Process cports event only, no port multiplier ports.
 */
static void
sata_process_device_detached(sata_hba_inst_t *sata_hba_inst,
    sata_address_t *saddr)
{
	sata_cport_info_t *cportinfo;
	sata_drive_info_t *sdevinfo;
	sata_device_t sata_device;
	dev_info_t *tdip;
	int rval;

	SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
	    "Processing port %d device detached", saddr->cport);

	cportinfo = SATA_CPORT_INFO(sata_hba_inst, saddr->cport);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	/* Clear event flag */
	cportinfo->cport_event_flags &= ~SATA_EVNT_DEVICE_DETACHED;

	/* If the port is in SHUTDOWN or FAILED state, ignore detach event. */
	if ((cportinfo->cport_state &
	    (SATA_PSTATE_SHUTDOWN | SATA_PSTATE_FAILED)) != 0) {
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}
	/* For sanity, re-probe the port */
	sata_device.satadev_rev = SATA_DEVICE_REV;
	sata_device.satadev_addr = *saddr;

	/*
	 * We have to exit mutex, because the HBA probe port function may
	 * block on its own mutex.
	 */
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
	    (SATA_DIP(sata_hba_inst), &sata_device);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	sata_update_port_info(sata_hba_inst, &sata_device);
	if (rval != SATA_SUCCESS) {
		/* Something went wrong? Fail the port */
		cportinfo->cport_state = SATA_PSTATE_FAILED;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "SATA port %d probing failed",
		    saddr->cport));
		/*
		 * We may want to release device info structure, but
		 * it is not necessary.
		 */
		return;
	} else {
		/* port probed successfully */
		cportinfo->cport_state |= SATA_STATE_PROBED | SATA_STATE_READY;
	}
	/*
	 * Check if a device is still attached. For sanity, check also
	 * link status - if no link, there is no device.
	 */
	if ((sata_device.satadev_scr.sstatus & SATA_PORT_DEVLINK_UP_MASK) ==
	    SATA_PORT_DEVLINK_UP && sata_device.satadev_type !=
	    SATA_DTYPE_NONE) {
		/*
		 * Device is still attached - ignore detach event.
		 */
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
		    "Ignoring detach - device still attached to port %d",
		    sata_device.satadev_addr.cport);
		return;
	}
	/*
	 * We need to detach and release device info structure here
	 */
	if (SATA_CPORTINFO_DRV_INFO(cportinfo) != NULL) {
		sdevinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);
		SATA_CPORTINFO_DRV_INFO(cportinfo) = NULL;
		(void) kmem_free((void *)sdevinfo,
		    sizeof (sata_drive_info_t));
	}
	cportinfo->cport_dev_type = SATA_DTYPE_NONE;
	/*
	 * Device cannot be reached anymore, even if the target node may be
	 * still present.
	 */

	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	sata_log(sata_hba_inst, CE_WARN, "SATA device detached at port %d",
	    sata_device.satadev_addr.cport);

	/*
	 * Try to offline a device and remove target node if it still exists
	 */
	tdip = sata_get_target_dip(SATA_DIP(sata_hba_inst), saddr->cport);
	if (tdip != NULL) {
		/*
		 * Target node exists.  Unconfigure device then remove
		 * the target node (one ndi operation).
		 */
		if (ndi_devi_offline(tdip, NDI_DEVI_REMOVE) != NDI_SUCCESS) {
			/*
			 * PROBLEM - no device, but target node remained
			 * This happens when the file was open or node was
			 * waiting for resources.
			 */
			SATA_LOG_D((sata_hba_inst, CE_WARN,
			    "sata_process_device_detached: "
			    "Failed to remove target node for "
			    "detached SATA device."));
			/*
			 * Set target node state to DEVI_DEVICE_REMOVED.
			 * But re-check first that the node still exists.
			 */
			tdip = sata_get_target_dip(SATA_DIP(sata_hba_inst),
			    saddr->cport);
			if (tdip != NULL) {
				sata_set_device_removed(tdip);
				/*
				 * Instruct event daemon to retry the
				 * cleanup later.
				 */
				sata_set_target_node_cleanup(sata_hba_inst,
				    saddr->cport);
			}
		}
	}
	/*
	 * Generate sysevent - EC_DR / ESC_DR_AP_STATE_CHANGE
	 * with the hint: SE_HINT_REMOVE
	 */
	sata_gen_sysevent(sata_hba_inst, saddr, SE_HINT_REMOVE);
}


/*
 * Device Attached Event processing.
 * Port state is checked to verify that a device is really attached. If so,
 * the device info structure is created and attached to the SATA port info
 * structure.
 *
 * If attached device cannot be identified or set-up, the retry for the
 * attach processing is set-up. Subsequent daemon run would try again to
 * identify the device, until the time limit is reached
 * (SATA_DEV_IDENTIFY_TIMEOUT).
 *
 * This function cannot be called in interrupt context (it may sleep).
 *
 * NOTE: Process cports event only, no port multiplier ports.
 */
static void
sata_process_device_attached(sata_hba_inst_t *sata_hba_inst,
    sata_address_t *saddr)
{
	sata_cport_info_t *cportinfo;
	sata_drive_info_t *sdevinfo;
	sata_device_t sata_device;
	dev_info_t *tdip;
	uint32_t event_flags;
	int rval;

	SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
	    "Processing port %d device attached", saddr->cport);

	cportinfo = SATA_CPORT_INFO(sata_hba_inst, saddr->cport);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);

	/* Clear attach event flag first */
	cportinfo->cport_event_flags &= ~SATA_EVNT_DEVICE_ATTACHED;

	/* If the port is in SHUTDOWN or FAILED state, ignore event. */
	if ((cportinfo->cport_state &
	    (SATA_PSTATE_SHUTDOWN | SATA_PSTATE_FAILED)) != 0) {
		cportinfo->cport_dev_attach_time = 0;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		return;
	}

	/*
	 * If the sata_drive_info structure is found attached to the port info,
	 * despite the fact the device was removed and now it is re-attached,
	 * the old drive info structure was not removed.
	 * Arbitrarily release device info structure.
	 */
	if (SATA_CPORTINFO_DRV_INFO(cportinfo) != NULL) {
		sdevinfo = SATA_CPORTINFO_DRV_INFO(cportinfo);
		SATA_CPORTINFO_DRV_INFO(cportinfo) = NULL;
		(void) kmem_free((void *)sdevinfo,
		    sizeof (sata_drive_info_t));
		SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
		    "Arbitrarily detaching old device info.", NULL);
	}
	cportinfo->cport_dev_type = SATA_DTYPE_NONE;

	/* For sanity, re-probe the port */
	sata_device.satadev_rev = SATA_DEVICE_REV;
	sata_device.satadev_addr = *saddr;

	/*
	 * We have to exit mutex, because the HBA probe port function may
	 * block on its own mutex.
	 */
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	rval = (*SATA_PROBE_PORT_FUNC(sata_hba_inst))
	    (SATA_DIP(sata_hba_inst), &sata_device);
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	sata_update_port_info(sata_hba_inst, &sata_device);
	if (rval != SATA_SUCCESS) {
		/* Something went wrong? Fail the port */
		cportinfo->cport_state = SATA_PSTATE_FAILED;
		cportinfo->cport_dev_attach_time = 0;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "SATA port %d probing failed",
		    saddr->cport));
		return;
	} else {
		/* port probed successfully */
		cportinfo->cport_state |= SATA_STATE_PROBED | SATA_STATE_READY;
	}
	/*
	 * Check if a device is still attached. For sanity, check also
	 * link status - if no link, there is no device.
	 */
	if ((sata_device.satadev_scr.sstatus & SATA_PORT_DEVLINK_UP_MASK) !=
	    SATA_PORT_DEVLINK_UP || sata_device.satadev_type ==
	    SATA_DTYPE_NONE) {
		/*
		 * No device - ignore attach event.
		 */
		cportinfo->cport_dev_attach_time = 0;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
		    cport_mutex);
		SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
		    "Ignoring attach - no device connected to port %d",
		    sata_device.satadev_addr.cport);
		return;
	}

	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	/*
	 * Generate sysevent - EC_DR / ESC_DR_AP_STATE_CHANGE
	 * with the hint: SE_HINT_INSERT
	 */
	sata_gen_sysevent(sata_hba_inst, saddr, SE_HINT_INSERT);

	/*
	 * Port reprobing will take care of the creation of the device
	 * info structure and determination of the device type.
	 */
	sata_device.satadev_addr = *saddr;
	(void) sata_reprobe_port(sata_hba_inst, &sata_device,
	    SATA_DEV_IDENTIFY_NORETRY);

	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->
	    cport_mutex);
	if ((cportinfo->cport_state & SATA_STATE_READY) &&
	    (cportinfo->cport_dev_type != SATA_DTYPE_NONE)) {
		/* Some device is attached to the port */
		if (cportinfo->cport_dev_type == SATA_DTYPE_UNKNOWN) {
			/*
			 * A device was not successfully attached.
			 * Track retry time for device identification.
			 */
			if (cportinfo->cport_dev_attach_time != 0) {
				clock_t cur_time = ddi_get_lbolt();
				/*
				 * If the retry time limit was not exceeded,
				 * reinstate attach event.
				 */
				if ((cur_time -
				    cportinfo->cport_dev_attach_time) <
				    drv_usectohz(
				    SATA_DEV_IDENTIFY_TIMEOUT)) {
					/* OK, restore attach event */
					cportinfo->cport_event_flags |=
					    SATA_EVNT_DEVICE_ATTACHED;
				} else {
					/* Timeout - cannot identify device */
					cportinfo->cport_dev_attach_time = 0;
					sata_log(sata_hba_inst,
					    CE_WARN,
					    "Cannot identify SATA device "
					    "at port %d - device will not be "
					    "attached.",
					    saddr->cport);
				}
			} else {
				/*
				 * Start tracking time for device
				 * identification.
				 * Save current time (lbolt value).
				 */
				cportinfo->cport_dev_attach_time =
				    ddi_get_lbolt();
				/* Restore attach event */
				cportinfo->cport_event_flags |=
				    SATA_EVNT_DEVICE_ATTACHED;
			}
		} else {
			/*
			 * If device was successfully attached, an explicit
			 * 'configure' command will be needed to configure it.
			 * Log the message indicating that a device
			 * was attached.
			 */
			cportinfo->cport_dev_attach_time = 0;
			sata_log(sata_hba_inst, CE_WARN,
			    "SATA device detected at port %d", saddr->cport);

			if (SATA_CPORTINFO_DRV_INFO(cportinfo) != NULL) {
				sata_drive_info_t new_sdinfo;

				/* Log device info data */
				new_sdinfo = *(SATA_CPORTINFO_DRV_INFO(
				    cportinfo));
				sata_show_drive_info(sata_hba_inst,
				    &new_sdinfo);
			}

			mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
			    saddr->cport)->cport_mutex);

			/*
			 * Make sure that there is no target node for that
			 * device. If so, release it. It should not happen,
			 * unless we had problem removing the node when
			 * device was detached.
			 */
			tdip = sata_get_target_dip(SATA_DIP(sata_hba_inst),
			    saddr->cport);
			mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
			    saddr->cport)->cport_mutex);
			if (tdip != NULL) {

#ifdef SATA_DEBUG
				if ((cportinfo->cport_event_flags &
				    SATA_EVNT_TARGET_NODE_CLEANUP) == 0)
					sata_log(sata_hba_inst, CE_WARN,
					    "sata_process_device_attached: "
					    "old device target node exists!");
#endif
				/*
				 * target node exists - try to unconfigure
				 * device and remove the node.
				 */
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    saddr->cport)->cport_mutex);
				rval = ndi_devi_offline(tdip,
				    NDI_DEVI_REMOVE);
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    saddr->cport)->cport_mutex);

				if (rval == NDI_SUCCESS) {
					cportinfo->cport_event_flags &=
					    ~SATA_EVNT_TARGET_NODE_CLEANUP;
					cportinfo->cport_tgtnode_clean = B_TRUE;
				} else {
					/*
					 * PROBLEM - the target node remained
					 * and it belongs to a previously
					 * attached device.
					 * This happens when the file was open
					 * or the node was waiting for
					 * resources at the time the
					 * associated device was removed.
					 * Instruct event daemon to retry the
					 * cleanup later.
					 */
					sata_log(sata_hba_inst,
					    CE_WARN,
					    "Application(s) accessing "
					    "previously attached SATA "
					    "device have to release "
					    "it before newly inserted "
					    "device can be made accessible.",
					    saddr->cport);
					cportinfo->cport_event_flags |=
					    SATA_EVNT_TARGET_NODE_CLEANUP;
					cportinfo->cport_tgtnode_clean =
					    B_FALSE;
				}
			}

		}
	} else {
		cportinfo->cport_dev_attach_time = 0;
	}

	event_flags = cportinfo->cport_event_flags;
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, saddr->cport)->cport_mutex);
	if (event_flags != 0) {
		mutex_enter(&sata_hba_inst->satahba_mutex);
		sata_hba_inst->satahba_event_flags |= SATA_EVNT_MAIN;
		mutex_exit(&sata_hba_inst->satahba_mutex);
		mutex_enter(&sata_mutex);
		sata_event_pending |= SATA_EVNT_MAIN;
		mutex_exit(&sata_mutex);
	}
}


/*
 * Device Target Node Cleanup Event processing.
 * If the target node associated with a sata port device is in
 * DEVI_DEVICE_REMOVED state, an attempt is made to remove it.
 * If the target node cannot be removed, the event flag is left intact,
 * so that event daemon may re-run this function later.
 *
 * This function cannot be called in interrupt context (it may sleep).
 *
 * NOTE: Processes cport events only, not port multiplier ports.
 */
static void
sata_process_target_node_cleanup(sata_hba_inst_t *sata_hba_inst,
    sata_address_t *saddr)
{
	sata_cport_info_t *cportinfo;
	dev_info_t *tdip;

	SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
	    "Processing port %d device target node cleanup", saddr->cport);

	cportinfo = SATA_CPORT_INFO(sata_hba_inst, saddr->cport);

	/*
	 * Check if there is target node for that device and it is in the
	 * DEVI_DEVICE_REMOVED state. If so, release it.
	 */
	tdip = sata_get_target_dip(SATA_DIP(sata_hba_inst), saddr->cport);
	if (tdip != NULL) {
		/*
		 * target node exists - check if it is target node of
		 * a removed device.
		 */
		if (sata_check_device_removed(tdip) == B_TRUE) {
			SATADBG1(SATA_DBG_EVENTS_PROC, sata_hba_inst,
			    "sata_process_target_node_cleanup: "
			    "old device target node exists!", NULL);
			/*
			 * Unconfigure and remove the target node
			 */
			if (ndi_devi_offline(tdip, NDI_DEVI_REMOVE) ==
			    NDI_SUCCESS) {
				mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
				    saddr->cport)->cport_mutex);
				cportinfo->cport_event_flags &=
				    ~SATA_EVNT_TARGET_NODE_CLEANUP;
				mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
				    saddr->cport)->cport_mutex);
				return;
			}
			/*
			 * Event daemon will retry the cleanup later.
			 */
			mutex_enter(&sata_hba_inst->satahba_mutex);
			sata_hba_inst->satahba_event_flags |= SATA_EVNT_MAIN;
			mutex_exit(&sata_hba_inst->satahba_mutex);
			mutex_enter(&sata_mutex);
			sata_event_pending |= SATA_EVNT_MAIN;
			mutex_exit(&sata_mutex);
		}
	} else {
		mutex_enter(&SATA_CPORT_INFO(sata_hba_inst,
		    saddr->cport)->cport_mutex);
		cportinfo->cport_event_flags &=
		    ~SATA_EVNT_TARGET_NODE_CLEANUP;
		mutex_exit(&SATA_CPORT_INFO(sata_hba_inst,
		    saddr->cport)->cport_mutex);
	}
}

static void
sata_gen_sysevent(sata_hba_inst_t *sata_hba_inst, sata_address_t *saddr,
    int hint)
{
	char ap[MAXPATHLEN];
	nvlist_t *ev_attr_list = NULL;
	int err;

	/* Allocate and build sysevent attribute list */
	err = nvlist_alloc(&ev_attr_list, NV_UNIQUE_NAME_TYPE, DDI_NOSLEEP);
	if (err != 0) {
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_gen_sysevent: "
		    "cannot allocate memory for sysevent attributes\n"));
		return;
	}
	/* Add hint attribute */
	err = nvlist_add_string(ev_attr_list, DR_HINT, SE_HINT2STR(hint));
	if (err != 0) {
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_gen_sysevent: "
		    "failed to add DR_HINT attr for sysevent"));
		nvlist_free(ev_attr_list);
		return;
	}
	/*
	 * Add AP attribute.
	 * Get controller pathname and convert it into AP pathname by adding
	 * a target number.
	 */
	(void) snprintf(ap, MAXPATHLEN, "/devices");
	(void) ddi_pathname(SATA_DIP(sata_hba_inst), ap + strlen(ap));
	(void) snprintf(ap + strlen(ap), MAXPATHLEN - strlen(ap), ":%d",
	    SATA_MAKE_AP_NUMBER(saddr->cport, saddr->pmport, saddr->qual));

	err = nvlist_add_string(ev_attr_list, DR_AP_ID, ap);
	if (err != 0) {
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_gen_sysevent: "
		    "failed to add DR_AP_ID attr for sysevent"));
		nvlist_free(ev_attr_list);
		return;
	}

	/* Generate/log sysevent */
	err = ddi_log_sysevent(SATA_DIP(sata_hba_inst), DDI_VENDOR_SUNW, EC_DR,
	    ESC_DR_AP_STATE_CHANGE, ev_attr_list, NULL, DDI_NOSLEEP);
	if (err != DDI_SUCCESS) {
		SATA_LOG_D((sata_hba_inst, CE_WARN,
		    "sata_gen_sysevent: "
		    "cannot log sysevent, err code %x\n", err));
	}

	nvlist_free(ev_attr_list);
}




/*
 * Set DEVI_DEVICE_REMOVED state in the SATA device target node.
 */
static void
sata_set_device_removed(dev_info_t *tdip)
{
	int circ;

	ASSERT(tdip != NULL);

	ndi_devi_enter(tdip, &circ);
	mutex_enter(&DEVI(tdip)->devi_lock);
	DEVI_SET_DEVICE_REMOVED(tdip);
	mutex_exit(&DEVI(tdip)->devi_lock);
	ndi_devi_exit(tdip, circ);
}


/*
 * Set internal event instructing event daemon to try
 * to perform the target node cleanup.
 */
static void
sata_set_target_node_cleanup(sata_hba_inst_t *sata_hba_inst, int cport)
{
	mutex_enter(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
	SATA_CPORT_EVENT_FLAGS(sata_hba_inst, cport) |=
	    SATA_EVNT_TARGET_NODE_CLEANUP;
	SATA_CPORT_INFO(sata_hba_inst, cport)->cport_tgtnode_clean = B_FALSE;
	mutex_exit(&SATA_CPORT_INFO(sata_hba_inst, cport)->cport_mutex);
	mutex_enter(&sata_hba_inst->satahba_mutex);
	sata_hba_inst->satahba_event_flags |= SATA_EVNT_MAIN;
	mutex_exit(&sata_hba_inst->satahba_mutex);
	mutex_enter(&sata_mutex);
	sata_event_pending |= SATA_EVNT_MAIN;
	mutex_exit(&sata_mutex);
}


/*
 * Check if the SATA device target node is in DEVI_DEVICE_REMOVED state,
 * i.e. check if the target node state indicates that it belongs to a removed
 * device.
 *
 * Returns B_TRUE if the target node is in DEVI_DEVICE_REMOVED state,
 * B_FALSE otherwise.
 *
 * NOTE: No port multiplier support.
 */
static boolean_t
sata_check_device_removed(dev_info_t *tdip)
{
	ASSERT(tdip != NULL);

	if (DEVI_IS_DEVICE_REMOVED(tdip))
		return (B_TRUE);
	else
		return (B_FALSE);
}
