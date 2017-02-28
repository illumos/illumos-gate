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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2011 Bayard G. Bell.  All rights reserved.
 * Copyright (c) 2012, 2016 by Delphix. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2011 cyril.galibern@opensvc.com
 */

/*
 * SCSI disk target driver.
 */
#include <sys/scsi/scsi.h>
#include <sys/dkbad.h>
#include <sys/dklabel.h>
#include <sys/dkio.h>
#include <sys/fdio.h>
#include <sys/cdio.h>
#include <sys/mhd.h>
#include <sys/vtoc.h>
#include <sys/dktp/fdisk.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/note.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/efi_partition.h>
#include <sys/var.h>
#include <sys/aio_req.h>

#ifdef __lock_lint
#define	_LP64
#define	__amd64
#endif

#if (defined(__fibre))
/* Note: is there a leadville version of the following? */
#include <sys/fc4/fcal_linkapp.h>
#endif
#include <sys/taskq.h>
#include <sys/uuid.h>
#include <sys/byteorder.h>
#include <sys/sdt.h>

#include "sd_xbuf.h"

#include <sys/scsi/targets/sddef.h>
#include <sys/cmlb.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dev.h>

#include <sys/fm/protocol.h>

/*
 * Loadable module info.
 */
#if (defined(__fibre))
#define	SD_MODULE_NAME	"SCSI SSA/FCAL Disk Driver"
#else /* !__fibre */
#define	SD_MODULE_NAME	"SCSI Disk Driver"
#endif /* !__fibre */

/*
 * Define the interconnect type, to allow the driver to distinguish
 * between parallel SCSI (sd) and fibre channel (ssd) behaviors.
 *
 * This is really for backward compatibility. In the future, the driver
 * should actually check the "interconnect-type" property as reported by
 * the HBA; however at present this property is not defined by all HBAs,
 * so we will use this #define (1) to permit the driver to run in
 * backward-compatibility mode; and (2) to print a notification message
 * if an FC HBA does not support the "interconnect-type" property.  The
 * behavior of the driver will be to assume parallel SCSI behaviors unless
 * the "interconnect-type" property is defined by the HBA **AND** has a
 * value of either INTERCONNECT_FIBRE, INTERCONNECT_SSA, or
 * INTERCONNECT_FABRIC, in which case the driver will assume Fibre
 * Channel behaviors (as per the old ssd).  (Note that the
 * INTERCONNECT_1394 and INTERCONNECT_USB types are not supported and
 * will result in the driver assuming parallel SCSI behaviors.)
 *
 * (see common/sys/scsi/impl/services.h)
 *
 * Note: For ssd semantics, don't use INTERCONNECT_FABRIC as the default
 * since some FC HBAs may already support that, and there is some code in
 * the driver that already looks for it.  Using INTERCONNECT_FABRIC as the
 * default would confuse that code, and besides things should work fine
 * anyways if the FC HBA already reports INTERCONNECT_FABRIC for the
 * "interconnect_type" property.
 *
 */
#if (defined(__fibre))
#define	SD_DEFAULT_INTERCONNECT_TYPE	SD_INTERCONNECT_FIBRE
#else
#define	SD_DEFAULT_INTERCONNECT_TYPE	SD_INTERCONNECT_PARALLEL
#endif

/*
 * The name of the driver, established from the module name in _init.
 */
static	char *sd_label			= NULL;

/*
 * Driver name is unfortunately prefixed on some driver.conf properties.
 */
#if (defined(__fibre))
#define	sd_max_xfer_size		ssd_max_xfer_size
#define	sd_config_list			ssd_config_list
static	char *sd_max_xfer_size		= "ssd_max_xfer_size";
static	char *sd_config_list		= "ssd-config-list";
#else
static	char *sd_max_xfer_size		= "sd_max_xfer_size";
static	char *sd_config_list		= "sd-config-list";
#endif

/*
 * Driver global variables
 */

#if (defined(__fibre))
/*
 * These #defines are to avoid namespace collisions that occur because this
 * code is currently used to compile two separate driver modules: sd and ssd.
 * All global variables need to be treated this way (even if declared static)
 * in order to allow the debugger to resolve the names properly.
 * It is anticipated that in the near future the ssd module will be obsoleted,
 * at which time this namespace issue should go away.
 */
#define	sd_state			ssd_state
#define	sd_io_time			ssd_io_time
#define	sd_failfast_enable		ssd_failfast_enable
#define	sd_ua_retry_count		ssd_ua_retry_count
#define	sd_report_pfa			ssd_report_pfa
#define	sd_max_throttle			ssd_max_throttle
#define	sd_min_throttle			ssd_min_throttle
#define	sd_rot_delay			ssd_rot_delay

#define	sd_retry_on_reservation_conflict	\
					ssd_retry_on_reservation_conflict
#define	sd_reinstate_resv_delay		ssd_reinstate_resv_delay
#define	sd_resv_conflict_name		ssd_resv_conflict_name

#define	sd_component_mask		ssd_component_mask
#define	sd_level_mask			ssd_level_mask
#define	sd_debug_un			ssd_debug_un
#define	sd_error_level			ssd_error_level

#define	sd_xbuf_active_limit		ssd_xbuf_active_limit
#define	sd_xbuf_reserve_limit		ssd_xbuf_reserve_limit

#define	sd_tr				ssd_tr
#define	sd_reset_throttle_timeout	ssd_reset_throttle_timeout
#define	sd_qfull_throttle_timeout	ssd_qfull_throttle_timeout
#define	sd_qfull_throttle_enable	ssd_qfull_throttle_enable
#define	sd_check_media_time		ssd_check_media_time
#define	sd_wait_cmds_complete		ssd_wait_cmds_complete
#define	sd_label_mutex			ssd_label_mutex
#define	sd_detach_mutex			ssd_detach_mutex
#define	sd_log_buf			ssd_log_buf
#define	sd_log_mutex			ssd_log_mutex

#define	sd_disk_table			ssd_disk_table
#define	sd_disk_table_size		ssd_disk_table_size
#define	sd_sense_mutex			ssd_sense_mutex
#define	sd_cdbtab			ssd_cdbtab

#define	sd_cb_ops			ssd_cb_ops
#define	sd_ops				ssd_ops
#define	sd_additional_codes		ssd_additional_codes
#define	sd_tgops			ssd_tgops

#define	sd_minor_data			ssd_minor_data
#define	sd_minor_data_efi		ssd_minor_data_efi

#define	sd_tq				ssd_tq
#define	sd_wmr_tq			ssd_wmr_tq
#define	sd_taskq_name			ssd_taskq_name
#define	sd_wmr_taskq_name		ssd_wmr_taskq_name
#define	sd_taskq_minalloc		ssd_taskq_minalloc
#define	sd_taskq_maxalloc		ssd_taskq_maxalloc

#define	sd_dump_format_string		ssd_dump_format_string

#define	sd_iostart_chain		ssd_iostart_chain
#define	sd_iodone_chain			ssd_iodone_chain

#define	sd_pm_idletime			ssd_pm_idletime

#define	sd_force_pm_supported		ssd_force_pm_supported

#define	sd_dtype_optical_bind		ssd_dtype_optical_bind

#define	sd_ssc_init			ssd_ssc_init
#define	sd_ssc_send			ssd_ssc_send
#define	sd_ssc_fini			ssd_ssc_fini
#define	sd_ssc_assessment		ssd_ssc_assessment
#define	sd_ssc_post			ssd_ssc_post
#define	sd_ssc_print			ssd_ssc_print
#define	sd_ssc_ereport_post		ssd_ssc_ereport_post
#define	sd_ssc_set_info			ssd_ssc_set_info
#define	sd_ssc_extract_info		ssd_ssc_extract_info

#endif

#ifdef	SDDEBUG
int	sd_force_pm_supported		= 0;
#endif	/* SDDEBUG */

void *sd_state				= NULL;
int sd_io_time				= SD_IO_TIME;
int sd_failfast_enable			= 1;
int sd_ua_retry_count			= SD_UA_RETRY_COUNT;
int sd_report_pfa			= 1;
int sd_max_throttle			= SD_MAX_THROTTLE;
int sd_min_throttle			= SD_MIN_THROTTLE;
int sd_rot_delay			= 4; /* Default 4ms Rotation delay */
int sd_qfull_throttle_enable		= TRUE;

int sd_retry_on_reservation_conflict	= 1;
int sd_reinstate_resv_delay		= SD_REINSTATE_RESV_DELAY;
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", sd_reinstate_resv_delay))

static int sd_dtype_optical_bind	= -1;

/* Note: the following is not a bug, it really is "sd_" and not "ssd_" */
static	char *sd_resv_conflict_name	= "sd_retry_on_reservation_conflict";

/*
 * Global data for debug logging. To enable debug printing, sd_component_mask
 * and sd_level_mask should be set to the desired bit patterns as outlined in
 * sddef.h.
 */
uint_t	sd_component_mask		= 0x0;
uint_t	sd_level_mask			= 0x0;
struct	sd_lun *sd_debug_un		= NULL;
uint_t	sd_error_level			= SCSI_ERR_RETRYABLE;

/* Note: these may go away in the future... */
static uint32_t	sd_xbuf_active_limit	= 512;
static uint32_t sd_xbuf_reserve_limit	= 16;

static struct sd_resv_reclaim_request	sd_tr = { NULL, NULL, NULL, 0, 0, 0 };

/*
 * Timer value used to reset the throttle after it has been reduced
 * (typically in response to TRAN_BUSY or STATUS_QFULL)
 */
static int sd_reset_throttle_timeout	= SD_RESET_THROTTLE_TIMEOUT;
static int sd_qfull_throttle_timeout	= SD_QFULL_THROTTLE_TIMEOUT;

/*
 * Interval value associated with the media change scsi watch.
 */
static int sd_check_media_time		= 3000000;

/*
 * Wait value used for in progress operations during a DDI_SUSPEND
 */
static int sd_wait_cmds_complete	= SD_WAIT_CMDS_COMPLETE;

/*
 * sd_label_mutex protects a static buffer used in the disk label
 * component of the driver
 */
static kmutex_t sd_label_mutex;

/*
 * sd_detach_mutex protects un_layer_count, un_detach_count, and
 * un_opens_in_progress in the sd_lun structure.
 */
static kmutex_t sd_detach_mutex;

_NOTE(MUTEX_PROTECTS_DATA(sd_detach_mutex,
	sd_lun::{un_layer_count un_detach_count un_opens_in_progress}))

/*
 * Global buffer and mutex for debug logging
 */
static char	sd_log_buf[1024];
static kmutex_t	sd_log_mutex;

/*
 * Structs and globals for recording attached lun information.
 * This maintains a chain. Each node in the chain represents a SCSI controller.
 * The structure records the number of luns attached to each target connected
 * with the controller.
 * For parallel scsi device only.
 */
struct sd_scsi_hba_tgt_lun {
	struct sd_scsi_hba_tgt_lun	*next;
	dev_info_t			*pdip;
	int				nlun[NTARGETS_WIDE];
};

/*
 * Flag to indicate the lun is attached or detached
 */
#define	SD_SCSI_LUN_ATTACH	0
#define	SD_SCSI_LUN_DETACH	1

static kmutex_t	sd_scsi_target_lun_mutex;
static struct sd_scsi_hba_tgt_lun	*sd_scsi_target_lun_head = NULL;

_NOTE(MUTEX_PROTECTS_DATA(sd_scsi_target_lun_mutex,
    sd_scsi_hba_tgt_lun::next sd_scsi_hba_tgt_lun::pdip))

_NOTE(MUTEX_PROTECTS_DATA(sd_scsi_target_lun_mutex,
    sd_scsi_target_lun_head))

/*
 * "Smart" Probe Caching structs, globals, #defines, etc.
 * For parallel scsi and non-self-identify device only.
 */

/*
 * The following resources and routines are implemented to support
 * "smart" probing, which caches the scsi_probe() results in an array,
 * in order to help avoid long probe times.
 */
struct sd_scsi_probe_cache {
	struct	sd_scsi_probe_cache	*next;
	dev_info_t	*pdip;
	int		cache[NTARGETS_WIDE];
};

static kmutex_t	sd_scsi_probe_cache_mutex;
static struct	sd_scsi_probe_cache *sd_scsi_probe_cache_head = NULL;

/*
 * Really we only need protection on the head of the linked list, but
 * better safe than sorry.
 */
_NOTE(MUTEX_PROTECTS_DATA(sd_scsi_probe_cache_mutex,
    sd_scsi_probe_cache::next sd_scsi_probe_cache::pdip))

_NOTE(MUTEX_PROTECTS_DATA(sd_scsi_probe_cache_mutex,
    sd_scsi_probe_cache_head))

/*
 * Power attribute table
 */
static sd_power_attr_ss sd_pwr_ss = {
	{ "NAME=spindle-motor", "0=off", "1=on", NULL },
	{0, 100},
	{30, 0},
	{20000, 0}
};

static sd_power_attr_pc sd_pwr_pc = {
	{ "NAME=spindle-motor", "0=stopped", "1=standby", "2=idle",
		"3=active", NULL },
	{0, 0, 0, 100},
	{90, 90, 20, 0},
	{15000, 15000, 1000, 0}
};

/*
 * Power level to power condition
 */
static int sd_pl2pc[] = {
	SD_TARGET_START_VALID,
	SD_TARGET_STANDBY,
	SD_TARGET_IDLE,
	SD_TARGET_ACTIVE
};

/*
 * Vendor specific data name property declarations
 */

#if defined(__fibre) || defined(__i386) ||defined(__amd64)

static sd_tunables seagate_properties = {
	SEAGATE_THROTTLE_VALUE,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0
};


static sd_tunables fujitsu_properties = {
	FUJITSU_THROTTLE_VALUE,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0
};

static sd_tunables ibm_properties = {
	IBM_THROTTLE_VALUE,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0
};

static sd_tunables purple_properties = {
	PURPLE_THROTTLE_VALUE,
	0,
	0,
	PURPLE_BUSY_RETRIES,
	PURPLE_RESET_RETRY_COUNT,
	PURPLE_RESERVE_RELEASE_TIME,
	0,
	0,
	0
};

static sd_tunables sve_properties = {
	SVE_THROTTLE_VALUE,
	0,
	0,
	SVE_BUSY_RETRIES,
	SVE_RESET_RETRY_COUNT,
	SVE_RESERVE_RELEASE_TIME,
	SVE_MIN_THROTTLE_VALUE,
	SVE_DISKSORT_DISABLED_FLAG,
	0
};

static sd_tunables maserati_properties = {
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	MASERATI_DISKSORT_DISABLED_FLAG,
	MASERATI_LUN_RESET_ENABLED_FLAG
};

static sd_tunables pirus_properties = {
	PIRUS_THROTTLE_VALUE,
	0,
	PIRUS_NRR_COUNT,
	PIRUS_BUSY_RETRIES,
	PIRUS_RESET_RETRY_COUNT,
	0,
	PIRUS_MIN_THROTTLE_VALUE,
	PIRUS_DISKSORT_DISABLED_FLAG,
	PIRUS_LUN_RESET_ENABLED_FLAG
};

#endif

#if (defined(__sparc) && !defined(__fibre)) || \
	(defined(__i386) || defined(__amd64))


static sd_tunables elite_properties = {
	ELITE_THROTTLE_VALUE,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0
};

static sd_tunables st31200n_properties = {
	ST31200N_THROTTLE_VALUE,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0
};

#endif /* Fibre or not */

static sd_tunables lsi_properties_scsi = {
	LSI_THROTTLE_VALUE,
	0,
	LSI_NOTREADY_RETRIES,
	0,
	0,
	0,
	0,
	0,
	0
};

static sd_tunables symbios_properties = {
	SYMBIOS_THROTTLE_VALUE,
	0,
	SYMBIOS_NOTREADY_RETRIES,
	0,
	0,
	0,
	0,
	0,
	0
};

static sd_tunables lsi_properties = {
	0,
	0,
	LSI_NOTREADY_RETRIES,
	0,
	0,
	0,
	0,
	0,
	0
};

static sd_tunables lsi_oem_properties = {
	0,
	0,
	LSI_OEM_NOTREADY_RETRIES,
	0,
	0,
	0,
	0,
	0,
	0,
	1
};



#if (defined(SD_PROP_TST))

#define	SD_TST_CTYPE_VAL	CTYPE_CDROM
#define	SD_TST_THROTTLE_VAL	16
#define	SD_TST_NOTREADY_VAL	12
#define	SD_TST_BUSY_VAL		60
#define	SD_TST_RST_RETRY_VAL	36
#define	SD_TST_RSV_REL_TIME	60

static sd_tunables tst_properties = {
	SD_TST_THROTTLE_VAL,
	SD_TST_CTYPE_VAL,
	SD_TST_NOTREADY_VAL,
	SD_TST_BUSY_VAL,
	SD_TST_RST_RETRY_VAL,
	SD_TST_RSV_REL_TIME,
	0,
	0,
	0
};
#endif

/* This is similar to the ANSI toupper implementation */
#define	SD_TOUPPER(C)	(((C) >= 'a' && (C) <= 'z') ? (C) - 'a' + 'A' : (C))

/*
 * Static Driver Configuration Table
 *
 * This is the table of disks which need throttle adjustment (or, perhaps
 * something else as defined by the flags at a future time.)  device_id
 * is a string consisting of concatenated vid (vendor), pid (product/model)
 * and revision strings as defined in the scsi_inquiry structure.  Offsets of
 * the parts of the string are as defined by the sizes in the scsi_inquiry
 * structure.  Device type is searched as far as the device_id string is
 * defined.  Flags defines which values are to be set in the driver from the
 * properties list.
 *
 * Entries below which begin and end with a "*" are a special case.
 * These do not have a specific vendor, and the string which follows
 * can appear anywhere in the 16 byte PID portion of the inquiry data.
 *
 * Entries below which begin and end with a " " (blank) are a special
 * case. The comparison function will treat multiple consecutive blanks
 * as equivalent to a single blank. For example, this causes a
 * sd_disk_table entry of " NEC CDROM " to match a device's id string
 * of  "NEC       CDROM".
 *
 * Note: The MD21 controller type has been obsoleted.
 *	 ST318202F is a Legacy device
 *	 MAM3182FC, MAM3364FC, MAM3738FC do not appear to have ever been
 *	 made with an FC connection. The entries here are a legacy.
 */
static sd_disk_config_t sd_disk_table[] = {
#if defined(__fibre) || defined(__i386) || defined(__amd64)
	{ "SEAGATE ST34371FC", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST19171FC", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST39102FC", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST39103FC", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST118273F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST318202F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST318203F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST136403F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST318304F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST336704F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST373405F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST336605F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST336752F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "SEAGATE ST318452F", SD_CONF_BSET_THROTTLE, &seagate_properties },
	{ "FUJITSU MAG3091F",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "FUJITSU MAG3182F",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "FUJITSU MAA3182F",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "FUJITSU MAF3364F",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "FUJITSU MAL3364F",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "FUJITSU MAL3738F",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "FUJITSU MAM3182FC",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "FUJITSU MAM3364FC",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "FUJITSU MAM3738FC",  SD_CONF_BSET_THROTTLE, &fujitsu_properties },
	{ "IBM     DDYFT1835",  SD_CONF_BSET_THROTTLE, &ibm_properties },
	{ "IBM     DDYFT3695",  SD_CONF_BSET_THROTTLE, &ibm_properties },
	{ "IBM     IC35LF2D2",  SD_CONF_BSET_THROTTLE, &ibm_properties },
	{ "IBM     IC35LF2PR",  SD_CONF_BSET_THROTTLE, &ibm_properties },
	{ "IBM     1724-100",   SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1726-2xx",   SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1726-22x",   SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1726-4xx",   SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1726-42x",   SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1726-3xx",   SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     3526",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     3542",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     3552",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1722",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1742",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1815",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     FAStT",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1814",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1814-200",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "IBM     1818",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "DELL    MD3000",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "DELL    MD3000i",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "LSI     INF",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "ENGENIO INF",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "SGI     TP",		SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "SGI     IS",		SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "*CSM100_*",		SD_CONF_BSET_NRR_COUNT |
			SD_CONF_BSET_CACHE_IS_NV, &lsi_oem_properties },
	{ "*CSM200_*",		SD_CONF_BSET_NRR_COUNT |
			SD_CONF_BSET_CACHE_IS_NV, &lsi_oem_properties },
	{ "Fujitsu SX300",	SD_CONF_BSET_THROTTLE,  &lsi_oem_properties },
	{ "LSI",		SD_CONF_BSET_NRR_COUNT, &lsi_properties },
	{ "SUN     T3", SD_CONF_BSET_THROTTLE |
			SD_CONF_BSET_BSY_RETRY_COUNT|
			SD_CONF_BSET_RST_RETRIES|
			SD_CONF_BSET_RSV_REL_TIME,
		&purple_properties },
	{ "SUN     SESS01", SD_CONF_BSET_THROTTLE |
		SD_CONF_BSET_BSY_RETRY_COUNT|
		SD_CONF_BSET_RST_RETRIES|
		SD_CONF_BSET_RSV_REL_TIME|
		SD_CONF_BSET_MIN_THROTTLE|
		SD_CONF_BSET_DISKSORT_DISABLED,
		&sve_properties },
	{ "SUN     T4", SD_CONF_BSET_THROTTLE |
			SD_CONF_BSET_BSY_RETRY_COUNT|
			SD_CONF_BSET_RST_RETRIES|
			SD_CONF_BSET_RSV_REL_TIME,
		&purple_properties },
	{ "SUN     SVE01", SD_CONF_BSET_DISKSORT_DISABLED |
		SD_CONF_BSET_LUN_RESET_ENABLED,
		&maserati_properties },
	{ "SUN     SE6920", SD_CONF_BSET_THROTTLE |
		SD_CONF_BSET_NRR_COUNT|
		SD_CONF_BSET_BSY_RETRY_COUNT|
		SD_CONF_BSET_RST_RETRIES|
		SD_CONF_BSET_MIN_THROTTLE|
		SD_CONF_BSET_DISKSORT_DISABLED|
		SD_CONF_BSET_LUN_RESET_ENABLED,
		&pirus_properties },
	{ "SUN     SE6940", SD_CONF_BSET_THROTTLE |
		SD_CONF_BSET_NRR_COUNT|
		SD_CONF_BSET_BSY_RETRY_COUNT|
		SD_CONF_BSET_RST_RETRIES|
		SD_CONF_BSET_MIN_THROTTLE|
		SD_CONF_BSET_DISKSORT_DISABLED|
		SD_CONF_BSET_LUN_RESET_ENABLED,
		&pirus_properties },
	{ "SUN     StorageTek 6920", SD_CONF_BSET_THROTTLE |
		SD_CONF_BSET_NRR_COUNT|
		SD_CONF_BSET_BSY_RETRY_COUNT|
		SD_CONF_BSET_RST_RETRIES|
		SD_CONF_BSET_MIN_THROTTLE|
		SD_CONF_BSET_DISKSORT_DISABLED|
		SD_CONF_BSET_LUN_RESET_ENABLED,
		&pirus_properties },
	{ "SUN     StorageTek 6940", SD_CONF_BSET_THROTTLE |
		SD_CONF_BSET_NRR_COUNT|
		SD_CONF_BSET_BSY_RETRY_COUNT|
		SD_CONF_BSET_RST_RETRIES|
		SD_CONF_BSET_MIN_THROTTLE|
		SD_CONF_BSET_DISKSORT_DISABLED|
		SD_CONF_BSET_LUN_RESET_ENABLED,
		&pirus_properties },
	{ "SUN     PSX1000", SD_CONF_BSET_THROTTLE |
		SD_CONF_BSET_NRR_COUNT|
		SD_CONF_BSET_BSY_RETRY_COUNT|
		SD_CONF_BSET_RST_RETRIES|
		SD_CONF_BSET_MIN_THROTTLE|
		SD_CONF_BSET_DISKSORT_DISABLED|
		SD_CONF_BSET_LUN_RESET_ENABLED,
		&pirus_properties },
	{ "SUN     SE6330", SD_CONF_BSET_THROTTLE |
		SD_CONF_BSET_NRR_COUNT|
		SD_CONF_BSET_BSY_RETRY_COUNT|
		SD_CONF_BSET_RST_RETRIES|
		SD_CONF_BSET_MIN_THROTTLE|
		SD_CONF_BSET_DISKSORT_DISABLED|
		SD_CONF_BSET_LUN_RESET_ENABLED,
		&pirus_properties },
	{ "SUN     STK6580_6780", SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "SUN     SUN_6180", SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "STK     OPENstorage", SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "STK     OpenStorage", SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "STK     BladeCtlr",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "STK     FLEXLINE",	SD_CONF_BSET_NRR_COUNT, &lsi_oem_properties },
	{ "SYMBIOS", SD_CONF_BSET_NRR_COUNT, &symbios_properties },
#endif /* fibre or NON-sparc platforms */
#if ((defined(__sparc) && !defined(__fibre)) ||\
	(defined(__i386) || defined(__amd64)))
	{ "SEAGATE ST42400N", SD_CONF_BSET_THROTTLE, &elite_properties },
	{ "SEAGATE ST31200N", SD_CONF_BSET_THROTTLE, &st31200n_properties },
	{ "SEAGATE ST41600N", SD_CONF_BSET_TUR_CHECK, NULL },
	{ "CONNER  CP30540",  SD_CONF_BSET_NOCACHE,  NULL },
	{ "*SUN0104*", SD_CONF_BSET_FAB_DEVID, NULL },
	{ "*SUN0207*", SD_CONF_BSET_FAB_DEVID, NULL },
	{ "*SUN0327*", SD_CONF_BSET_FAB_DEVID, NULL },
	{ "*SUN0340*", SD_CONF_BSET_FAB_DEVID, NULL },
	{ "*SUN0424*", SD_CONF_BSET_FAB_DEVID, NULL },
	{ "*SUN0669*", SD_CONF_BSET_FAB_DEVID, NULL },
	{ "*SUN1.0G*", SD_CONF_BSET_FAB_DEVID, NULL },
	{ "SYMBIOS INF-01-00       ", SD_CONF_BSET_FAB_DEVID, NULL },
	{ "SYMBIOS", SD_CONF_BSET_THROTTLE|SD_CONF_BSET_NRR_COUNT,
	    &symbios_properties },
	{ "LSI", SD_CONF_BSET_THROTTLE | SD_CONF_BSET_NRR_COUNT,
	    &lsi_properties_scsi },
#if defined(__i386) || defined(__amd64)
	{ " NEC CD-ROM DRIVE:260 ", (SD_CONF_BSET_PLAYMSF_BCD
				    | SD_CONF_BSET_READSUB_BCD
				    | SD_CONF_BSET_READ_TOC_ADDR_BCD
				    | SD_CONF_BSET_NO_READ_HEADER
				    | SD_CONF_BSET_READ_CD_XD4), NULL },

	{ " NEC CD-ROM DRIVE:270 ", (SD_CONF_BSET_PLAYMSF_BCD
				    | SD_CONF_BSET_READSUB_BCD
				    | SD_CONF_BSET_READ_TOC_ADDR_BCD
				    | SD_CONF_BSET_NO_READ_HEADER
				    | SD_CONF_BSET_READ_CD_XD4), NULL },
#endif /* __i386 || __amd64 */
#endif /* sparc NON-fibre or NON-sparc platforms */

#if (defined(SD_PROP_TST))
	{ "VENDOR  PRODUCT ", (SD_CONF_BSET_THROTTLE
				| SD_CONF_BSET_CTYPE
				| SD_CONF_BSET_NRR_COUNT
				| SD_CONF_BSET_FAB_DEVID
				| SD_CONF_BSET_NOCACHE
				| SD_CONF_BSET_BSY_RETRY_COUNT
				| SD_CONF_BSET_PLAYMSF_BCD
				| SD_CONF_BSET_READSUB_BCD
				| SD_CONF_BSET_READ_TOC_TRK_BCD
				| SD_CONF_BSET_READ_TOC_ADDR_BCD
				| SD_CONF_BSET_NO_READ_HEADER
				| SD_CONF_BSET_READ_CD_XD4
				| SD_CONF_BSET_RST_RETRIES
				| SD_CONF_BSET_RSV_REL_TIME
				| SD_CONF_BSET_TUR_CHECK), &tst_properties},
#endif
};

static const int sd_disk_table_size =
	sizeof (sd_disk_table)/ sizeof (sd_disk_config_t);

/*
 * Emulation mode disk drive VID/PID table
 */
static char sd_flash_dev_table[][25] = {
	"ATA     MARVELL SD88SA02",
	"MARVELL SD88SA02",
	"TOSHIBA THNSNV05",
};

static const int sd_flash_dev_table_size =
	sizeof (sd_flash_dev_table) / sizeof (sd_flash_dev_table[0]);

#define	SD_INTERCONNECT_PARALLEL	0
#define	SD_INTERCONNECT_FABRIC		1
#define	SD_INTERCONNECT_FIBRE		2
#define	SD_INTERCONNECT_SSA		3
#define	SD_INTERCONNECT_SATA		4
#define	SD_INTERCONNECT_SAS		5

#define	SD_IS_PARALLEL_SCSI(un)		\
	((un)->un_interconnect_type == SD_INTERCONNECT_PARALLEL)
#define	SD_IS_SERIAL(un)		\
	(((un)->un_interconnect_type == SD_INTERCONNECT_SATA) ||\
	((un)->un_interconnect_type == SD_INTERCONNECT_SAS))

/*
 * Definitions used by device id registration routines
 */
#define	VPD_HEAD_OFFSET		3	/* size of head for vpd page */
#define	VPD_PAGE_LENGTH		3	/* offset for pge length data */
#define	VPD_MODE_PAGE		1	/* offset into vpd pg for "page code" */

static kmutex_t sd_sense_mutex = {0};

/*
 * Macros for updates of the driver state
 */
#define	New_state(un, s)        \
	(un)->un_last_state = (un)->un_state, (un)->un_state = (s)
#define	Restore_state(un)	\
	{ uchar_t tmp = (un)->un_last_state; New_state((un), tmp); }

static struct sd_cdbinfo sd_cdbtab[] = {
	{ CDB_GROUP0, 0x00,	   0x1FFFFF,   0xFF,	    },
	{ CDB_GROUP1, SCMD_GROUP1, 0xFFFFFFFF, 0xFFFF,	    },
	{ CDB_GROUP5, SCMD_GROUP5, 0xFFFFFFFF, 0xFFFFFFFF,  },
	{ CDB_GROUP4, SCMD_GROUP4, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, },
};

/*
 * Specifies the number of seconds that must have elapsed since the last
 * cmd. has completed for a device to be declared idle to the PM framework.
 */
static int sd_pm_idletime = 1;

/*
 * Internal function prototypes
 */

#if (defined(__fibre))
/*
 * These #defines are to avoid namespace collisions that occur because this
 * code is currently used to compile two separate driver modules: sd and ssd.
 * All function names need to be treated this way (even if declared static)
 * in order to allow the debugger to resolve the names properly.
 * It is anticipated that in the near future the ssd module will be obsoleted,
 * at which time this ugliness should go away.
 */
#define	sd_log_trace			ssd_log_trace
#define	sd_log_info			ssd_log_info
#define	sd_log_err			ssd_log_err
#define	sdprobe				ssdprobe
#define	sdinfo				ssdinfo
#define	sd_prop_op			ssd_prop_op
#define	sd_scsi_probe_cache_init	ssd_scsi_probe_cache_init
#define	sd_scsi_probe_cache_fini	ssd_scsi_probe_cache_fini
#define	sd_scsi_clear_probe_cache	ssd_scsi_clear_probe_cache
#define	sd_scsi_probe_with_cache	ssd_scsi_probe_with_cache
#define	sd_scsi_target_lun_init		ssd_scsi_target_lun_init
#define	sd_scsi_target_lun_fini		ssd_scsi_target_lun_fini
#define	sd_scsi_get_target_lun_count	ssd_scsi_get_target_lun_count
#define	sd_scsi_update_lun_on_target	ssd_scsi_update_lun_on_target
#define	sd_spin_up_unit			ssd_spin_up_unit
#define	sd_enable_descr_sense		ssd_enable_descr_sense
#define	sd_reenable_dsense_task		ssd_reenable_dsense_task
#define	sd_set_mmc_caps			ssd_set_mmc_caps
#define	sd_read_unit_properties		ssd_read_unit_properties
#define	sd_process_sdconf_file		ssd_process_sdconf_file
#define	sd_process_sdconf_table		ssd_process_sdconf_table
#define	sd_sdconf_id_match		ssd_sdconf_id_match
#define	sd_blank_cmp			ssd_blank_cmp
#define	sd_chk_vers1_data		ssd_chk_vers1_data
#define	sd_set_vers1_properties		ssd_set_vers1_properties
#define	sd_check_solid_state		ssd_check_solid_state
#define	sd_check_emulation_mode		ssd_check_emulation_mode

#define	sd_get_physical_geometry	ssd_get_physical_geometry
#define	sd_get_virtual_geometry		ssd_get_virtual_geometry
#define	sd_update_block_info		ssd_update_block_info
#define	sd_register_devid		ssd_register_devid
#define	sd_get_devid			ssd_get_devid
#define	sd_create_devid			ssd_create_devid
#define	sd_write_deviceid		ssd_write_deviceid
#define	sd_check_vpd_page_support	ssd_check_vpd_page_support
#define	sd_setup_pm			ssd_setup_pm
#define	sd_create_pm_components		ssd_create_pm_components
#define	sd_ddi_suspend			ssd_ddi_suspend
#define	sd_ddi_resume			ssd_ddi_resume
#define	sd_pm_state_change		ssd_pm_state_change
#define	sdpower				ssdpower
#define	sdattach			ssdattach
#define	sddetach			ssddetach
#define	sd_unit_attach			ssd_unit_attach
#define	sd_unit_detach			ssd_unit_detach
#define	sd_set_unit_attributes		ssd_set_unit_attributes
#define	sd_create_errstats		ssd_create_errstats
#define	sd_set_errstats			ssd_set_errstats
#define	sd_set_pstats			ssd_set_pstats
#define	sddump				ssddump
#define	sd_scsi_poll			ssd_scsi_poll
#define	sd_send_polled_RQS		ssd_send_polled_RQS
#define	sd_ddi_scsi_poll		ssd_ddi_scsi_poll
#define	sd_init_event_callbacks		ssd_init_event_callbacks
#define	sd_event_callback		ssd_event_callback
#define	sd_cache_control		ssd_cache_control
#define	sd_get_write_cache_enabled	ssd_get_write_cache_enabled
#define	sd_get_nv_sup			ssd_get_nv_sup
#define	sd_make_device			ssd_make_device
#define	sdopen				ssdopen
#define	sdclose				ssdclose
#define	sd_ready_and_valid		ssd_ready_and_valid
#define	sdmin				ssdmin
#define	sdread				ssdread
#define	sdwrite				ssdwrite
#define	sdaread				ssdaread
#define	sdawrite			ssdawrite
#define	sdstrategy			ssdstrategy
#define	sdioctl				ssdioctl
#define	sd_mapblockaddr_iostart		ssd_mapblockaddr_iostart
#define	sd_mapblocksize_iostart		ssd_mapblocksize_iostart
#define	sd_checksum_iostart		ssd_checksum_iostart
#define	sd_checksum_uscsi_iostart	ssd_checksum_uscsi_iostart
#define	sd_pm_iostart			ssd_pm_iostart
#define	sd_core_iostart			ssd_core_iostart
#define	sd_mapblockaddr_iodone		ssd_mapblockaddr_iodone
#define	sd_mapblocksize_iodone		ssd_mapblocksize_iodone
#define	sd_checksum_iodone		ssd_checksum_iodone
#define	sd_checksum_uscsi_iodone	ssd_checksum_uscsi_iodone
#define	sd_pm_iodone			ssd_pm_iodone
#define	sd_initpkt_for_buf		ssd_initpkt_for_buf
#define	sd_destroypkt_for_buf		ssd_destroypkt_for_buf
#define	sd_setup_rw_pkt			ssd_setup_rw_pkt
#define	sd_setup_next_rw_pkt		ssd_setup_next_rw_pkt
#define	sd_buf_iodone			ssd_buf_iodone
#define	sd_uscsi_strategy		ssd_uscsi_strategy
#define	sd_initpkt_for_uscsi		ssd_initpkt_for_uscsi
#define	sd_destroypkt_for_uscsi		ssd_destroypkt_for_uscsi
#define	sd_uscsi_iodone			ssd_uscsi_iodone
#define	sd_xbuf_strategy		ssd_xbuf_strategy
#define	sd_xbuf_init			ssd_xbuf_init
#define	sd_pm_entry			ssd_pm_entry
#define	sd_pm_exit			ssd_pm_exit

#define	sd_pm_idletimeout_handler	ssd_pm_idletimeout_handler
#define	sd_pm_timeout_handler		ssd_pm_timeout_handler

#define	sd_add_buf_to_waitq		ssd_add_buf_to_waitq
#define	sdintr				ssdintr
#define	sd_start_cmds			ssd_start_cmds
#define	sd_send_scsi_cmd		ssd_send_scsi_cmd
#define	sd_bioclone_alloc		ssd_bioclone_alloc
#define	sd_bioclone_free		ssd_bioclone_free
#define	sd_shadow_buf_alloc		ssd_shadow_buf_alloc
#define	sd_shadow_buf_free		ssd_shadow_buf_free
#define	sd_print_transport_rejected_message	\
					ssd_print_transport_rejected_message
#define	sd_retry_command		ssd_retry_command
#define	sd_set_retry_bp			ssd_set_retry_bp
#define	sd_send_request_sense_command	ssd_send_request_sense_command
#define	sd_start_retry_command		ssd_start_retry_command
#define	sd_start_direct_priority_command	\
					ssd_start_direct_priority_command
#define	sd_return_failed_command	ssd_return_failed_command
#define	sd_return_failed_command_no_restart	\
					ssd_return_failed_command_no_restart
#define	sd_return_command		ssd_return_command
#define	sd_sync_with_callback		ssd_sync_with_callback
#define	sdrunout			ssdrunout
#define	sd_mark_rqs_busy		ssd_mark_rqs_busy
#define	sd_mark_rqs_idle		ssd_mark_rqs_idle
#define	sd_reduce_throttle		ssd_reduce_throttle
#define	sd_restore_throttle		ssd_restore_throttle
#define	sd_print_incomplete_msg		ssd_print_incomplete_msg
#define	sd_init_cdb_limits		ssd_init_cdb_limits
#define	sd_pkt_status_good		ssd_pkt_status_good
#define	sd_pkt_status_check_condition	ssd_pkt_status_check_condition
#define	sd_pkt_status_busy		ssd_pkt_status_busy
#define	sd_pkt_status_reservation_conflict	\
					ssd_pkt_status_reservation_conflict
#define	sd_pkt_status_qfull		ssd_pkt_status_qfull
#define	sd_handle_request_sense		ssd_handle_request_sense
#define	sd_handle_auto_request_sense	ssd_handle_auto_request_sense
#define	sd_print_sense_failed_msg	ssd_print_sense_failed_msg
#define	sd_validate_sense_data		ssd_validate_sense_data
#define	sd_decode_sense			ssd_decode_sense
#define	sd_print_sense_msg		ssd_print_sense_msg
#define	sd_sense_key_no_sense		ssd_sense_key_no_sense
#define	sd_sense_key_recoverable_error	ssd_sense_key_recoverable_error
#define	sd_sense_key_not_ready		ssd_sense_key_not_ready
#define	sd_sense_key_medium_or_hardware_error	\
					ssd_sense_key_medium_or_hardware_error
#define	sd_sense_key_illegal_request	ssd_sense_key_illegal_request
#define	sd_sense_key_unit_attention	ssd_sense_key_unit_attention
#define	sd_sense_key_fail_command	ssd_sense_key_fail_command
#define	sd_sense_key_blank_check	ssd_sense_key_blank_check
#define	sd_sense_key_aborted_command	ssd_sense_key_aborted_command
#define	sd_sense_key_default		ssd_sense_key_default
#define	sd_print_retry_msg		ssd_print_retry_msg
#define	sd_print_cmd_incomplete_msg	ssd_print_cmd_incomplete_msg
#define	sd_pkt_reason_cmd_incomplete	ssd_pkt_reason_cmd_incomplete
#define	sd_pkt_reason_cmd_tran_err	ssd_pkt_reason_cmd_tran_err
#define	sd_pkt_reason_cmd_reset		ssd_pkt_reason_cmd_reset
#define	sd_pkt_reason_cmd_aborted	ssd_pkt_reason_cmd_aborted
#define	sd_pkt_reason_cmd_timeout	ssd_pkt_reason_cmd_timeout
#define	sd_pkt_reason_cmd_unx_bus_free	ssd_pkt_reason_cmd_unx_bus_free
#define	sd_pkt_reason_cmd_tag_reject	ssd_pkt_reason_cmd_tag_reject
#define	sd_pkt_reason_default		ssd_pkt_reason_default
#define	sd_reset_target			ssd_reset_target
#define	sd_start_stop_unit_callback	ssd_start_stop_unit_callback
#define	sd_start_stop_unit_task		ssd_start_stop_unit_task
#define	sd_taskq_create			ssd_taskq_create
#define	sd_taskq_delete			ssd_taskq_delete
#define	sd_target_change_task		ssd_target_change_task
#define	sd_log_dev_status_event		ssd_log_dev_status_event
#define	sd_log_lun_expansion_event	ssd_log_lun_expansion_event
#define	sd_log_eject_request_event	ssd_log_eject_request_event
#define	sd_media_change_task		ssd_media_change_task
#define	sd_handle_mchange		ssd_handle_mchange
#define	sd_send_scsi_DOORLOCK		ssd_send_scsi_DOORLOCK
#define	sd_send_scsi_READ_CAPACITY	ssd_send_scsi_READ_CAPACITY
#define	sd_send_scsi_READ_CAPACITY_16	ssd_send_scsi_READ_CAPACITY_16
#define	sd_send_scsi_GET_CONFIGURATION	ssd_send_scsi_GET_CONFIGURATION
#define	sd_send_scsi_feature_GET_CONFIGURATION	\
					sd_send_scsi_feature_GET_CONFIGURATION
#define	sd_send_scsi_START_STOP_UNIT	ssd_send_scsi_START_STOP_UNIT
#define	sd_send_scsi_INQUIRY		ssd_send_scsi_INQUIRY
#define	sd_send_scsi_TEST_UNIT_READY	ssd_send_scsi_TEST_UNIT_READY
#define	sd_send_scsi_PERSISTENT_RESERVE_IN	\
					ssd_send_scsi_PERSISTENT_RESERVE_IN
#define	sd_send_scsi_PERSISTENT_RESERVE_OUT	\
					ssd_send_scsi_PERSISTENT_RESERVE_OUT
#define	sd_send_scsi_SYNCHRONIZE_CACHE	ssd_send_scsi_SYNCHRONIZE_CACHE
#define	sd_send_scsi_SYNCHRONIZE_CACHE_biodone	\
					ssd_send_scsi_SYNCHRONIZE_CACHE_biodone
#define	sd_send_scsi_MODE_SENSE		ssd_send_scsi_MODE_SENSE
#define	sd_send_scsi_MODE_SELECT	ssd_send_scsi_MODE_SELECT
#define	sd_send_scsi_RDWR		ssd_send_scsi_RDWR
#define	sd_send_scsi_LOG_SENSE		ssd_send_scsi_LOG_SENSE
#define	sd_send_scsi_GET_EVENT_STATUS_NOTIFICATION	\
				ssd_send_scsi_GET_EVENT_STATUS_NOTIFICATION
#define	sd_gesn_media_data_valid	ssd_gesn_media_data_valid
#define	sd_alloc_rqs			ssd_alloc_rqs
#define	sd_free_rqs			ssd_free_rqs
#define	sd_dump_memory			ssd_dump_memory
#define	sd_get_media_info_com		ssd_get_media_info_com
#define	sd_get_media_info		ssd_get_media_info
#define	sd_get_media_info_ext		ssd_get_media_info_ext
#define	sd_dkio_ctrl_info		ssd_dkio_ctrl_info
#define	sd_nvpair_str_decode		ssd_nvpair_str_decode
#define	sd_strtok_r			ssd_strtok_r
#define	sd_set_properties		ssd_set_properties
#define	sd_get_tunables_from_conf	ssd_get_tunables_from_conf
#define	sd_setup_next_xfer		ssd_setup_next_xfer
#define	sd_dkio_get_temp		ssd_dkio_get_temp
#define	sd_check_mhd			ssd_check_mhd
#define	sd_mhd_watch_cb			ssd_mhd_watch_cb
#define	sd_mhd_watch_incomplete		ssd_mhd_watch_incomplete
#define	sd_sname			ssd_sname
#define	sd_mhd_resvd_recover		ssd_mhd_resvd_recover
#define	sd_resv_reclaim_thread		ssd_resv_reclaim_thread
#define	sd_take_ownership		ssd_take_ownership
#define	sd_reserve_release		ssd_reserve_release
#define	sd_rmv_resv_reclaim_req		ssd_rmv_resv_reclaim_req
#define	sd_mhd_reset_notify_cb		ssd_mhd_reset_notify_cb
#define	sd_persistent_reservation_in_read_keys	\
					ssd_persistent_reservation_in_read_keys
#define	sd_persistent_reservation_in_read_resv	\
					ssd_persistent_reservation_in_read_resv
#define	sd_mhdioc_takeown		ssd_mhdioc_takeown
#define	sd_mhdioc_failfast		ssd_mhdioc_failfast
#define	sd_mhdioc_release		ssd_mhdioc_release
#define	sd_mhdioc_register_devid	ssd_mhdioc_register_devid
#define	sd_mhdioc_inkeys		ssd_mhdioc_inkeys
#define	sd_mhdioc_inresv		ssd_mhdioc_inresv
#define	sr_change_blkmode		ssr_change_blkmode
#define	sr_change_speed			ssr_change_speed
#define	sr_atapi_change_speed		ssr_atapi_change_speed
#define	sr_pause_resume			ssr_pause_resume
#define	sr_play_msf			ssr_play_msf
#define	sr_play_trkind			ssr_play_trkind
#define	sr_read_all_subcodes		ssr_read_all_subcodes
#define	sr_read_subchannel		ssr_read_subchannel
#define	sr_read_tocentry		ssr_read_tocentry
#define	sr_read_tochdr			ssr_read_tochdr
#define	sr_read_cdda			ssr_read_cdda
#define	sr_read_cdxa			ssr_read_cdxa
#define	sr_read_mode1			ssr_read_mode1
#define	sr_read_mode2			ssr_read_mode2
#define	sr_read_cd_mode2		ssr_read_cd_mode2
#define	sr_sector_mode			ssr_sector_mode
#define	sr_eject			ssr_eject
#define	sr_ejected			ssr_ejected
#define	sr_check_wp			ssr_check_wp
#define	sd_watch_request_submit		ssd_watch_request_submit
#define	sd_check_media			ssd_check_media
#define	sd_media_watch_cb		ssd_media_watch_cb
#define	sd_delayed_cv_broadcast		ssd_delayed_cv_broadcast
#define	sr_volume_ctrl			ssr_volume_ctrl
#define	sr_read_sony_session_offset	ssr_read_sony_session_offset
#define	sd_log_page_supported		ssd_log_page_supported
#define	sd_check_for_writable_cd	ssd_check_for_writable_cd
#define	sd_wm_cache_constructor		ssd_wm_cache_constructor
#define	sd_wm_cache_destructor		ssd_wm_cache_destructor
#define	sd_range_lock			ssd_range_lock
#define	sd_get_range			ssd_get_range
#define	sd_free_inlist_wmap		ssd_free_inlist_wmap
#define	sd_range_unlock			ssd_range_unlock
#define	sd_read_modify_write_task	ssd_read_modify_write_task
#define	sddump_do_read_of_rmw		ssddump_do_read_of_rmw

#define	sd_iostart_chain		ssd_iostart_chain
#define	sd_iodone_chain			ssd_iodone_chain
#define	sd_initpkt_map			ssd_initpkt_map
#define	sd_destroypkt_map		ssd_destroypkt_map
#define	sd_chain_type_map		ssd_chain_type_map
#define	sd_chain_index_map		ssd_chain_index_map

#define	sd_failfast_flushctl		ssd_failfast_flushctl
#define	sd_failfast_flushq		ssd_failfast_flushq
#define	sd_failfast_flushq_callback	ssd_failfast_flushq_callback

#define	sd_is_lsi			ssd_is_lsi
#define	sd_tg_rdwr			ssd_tg_rdwr
#define	sd_tg_getinfo			ssd_tg_getinfo
#define	sd_rmw_msg_print_handler	ssd_rmw_msg_print_handler

#endif	/* #if (defined(__fibre)) */


int _init(void);
int _fini(void);
int _info(struct modinfo *modinfop);

/*PRINTFLIKE3*/
static void sd_log_trace(uint_t comp, struct sd_lun *un, const char *fmt, ...);
/*PRINTFLIKE3*/
static void sd_log_info(uint_t comp, struct sd_lun *un, const char *fmt, ...);
/*PRINTFLIKE3*/
static void sd_log_err(uint_t comp, struct sd_lun *un, const char *fmt, ...);

static int sdprobe(dev_info_t *devi);
static int sdinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);
static int sd_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp);

/*
 * Smart probe for parallel scsi
 */
static void sd_scsi_probe_cache_init(void);
static void sd_scsi_probe_cache_fini(void);
static void sd_scsi_clear_probe_cache(void);
static int  sd_scsi_probe_with_cache(struct scsi_device *devp, int (*fn)());

/*
 * Attached luns on target for parallel scsi
 */
static void sd_scsi_target_lun_init(void);
static void sd_scsi_target_lun_fini(void);
static int  sd_scsi_get_target_lun_count(dev_info_t *dip, int target);
static void sd_scsi_update_lun_on_target(dev_info_t *dip, int target, int flag);

static int	sd_spin_up_unit(sd_ssc_t *ssc);

/*
 * Using sd_ssc_init to establish sd_ssc_t struct
 * Using sd_ssc_send to send uscsi internal command
 * Using sd_ssc_fini to free sd_ssc_t struct
 */
static sd_ssc_t *sd_ssc_init(struct sd_lun *un);
static int sd_ssc_send(sd_ssc_t *ssc, struct uscsi_cmd *incmd,
    int flag, enum uio_seg dataspace, int path_flag);
static void sd_ssc_fini(sd_ssc_t *ssc);

/*
 * Using sd_ssc_assessment to set correct type-of-assessment
 * Using sd_ssc_post to post ereport & system log
 *       sd_ssc_post will call sd_ssc_print to print system log
 *       sd_ssc_post will call sd_ssd_ereport_post to post ereport
 */
static void sd_ssc_assessment(sd_ssc_t *ssc,
    enum sd_type_assessment tp_assess);

static void sd_ssc_post(sd_ssc_t *ssc, enum sd_driver_assessment sd_assess);
static void sd_ssc_print(sd_ssc_t *ssc, int sd_severity);
static void sd_ssc_ereport_post(sd_ssc_t *ssc,
    enum sd_driver_assessment drv_assess);

/*
 * Using sd_ssc_set_info to mark an un-decodable-data error.
 * Using sd_ssc_extract_info to transfer information from internal
 *       data structures to sd_ssc_t.
 */
static void sd_ssc_set_info(sd_ssc_t *ssc, int ssc_flags, uint_t comp,
    const char *fmt, ...);
static void sd_ssc_extract_info(sd_ssc_t *ssc, struct sd_lun *un,
    struct scsi_pkt *pktp, struct buf *bp, struct sd_xbuf *xp);

static int sd_send_scsi_cmd(dev_t dev, struct uscsi_cmd *incmd, int flag,
    enum uio_seg dataspace, int path_flag);

#ifdef _LP64
static void	sd_enable_descr_sense(sd_ssc_t *ssc);
static void	sd_reenable_dsense_task(void *arg);
#endif /* _LP64 */

static void	sd_set_mmc_caps(sd_ssc_t *ssc);

static void sd_read_unit_properties(struct sd_lun *un);
static int  sd_process_sdconf_file(struct sd_lun *un);
static void sd_nvpair_str_decode(struct sd_lun *un, char *nvpair_str);
static char *sd_strtok_r(char *string, const char *sepset, char **lasts);
static void sd_set_properties(struct sd_lun *un, char *name, char *value);
static void sd_get_tunables_from_conf(struct sd_lun *un, int flags,
    int *data_list, sd_tunables *values);
static void sd_process_sdconf_table(struct sd_lun *un);
static int  sd_sdconf_id_match(struct sd_lun *un, char *id, int idlen);
static int  sd_blank_cmp(struct sd_lun *un, char *id, int idlen);
static int  sd_chk_vers1_data(struct sd_lun *un, int flags, int *prop_list,
	int list_len, char *dataname_ptr);
static void sd_set_vers1_properties(struct sd_lun *un, int flags,
    sd_tunables *prop_list);

static void sd_register_devid(sd_ssc_t *ssc, dev_info_t *devi,
    int reservation_flag);
static int  sd_get_devid(sd_ssc_t *ssc);
static ddi_devid_t sd_create_devid(sd_ssc_t *ssc);
static int  sd_write_deviceid(sd_ssc_t *ssc);
static int  sd_get_devid_page(struct sd_lun *un, uchar_t *wwn, int *len);
static int  sd_check_vpd_page_support(sd_ssc_t *ssc);

static void sd_setup_pm(sd_ssc_t *ssc, dev_info_t *devi);
static void sd_create_pm_components(dev_info_t *devi, struct sd_lun *un);

static int  sd_ddi_suspend(dev_info_t *devi);
static int  sd_ddi_resume(dev_info_t *devi);
static int  sd_pm_state_change(struct sd_lun *un, int level, int flag);
static int  sdpower(dev_info_t *devi, int component, int level);

static int  sdattach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int  sddetach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int  sd_unit_attach(dev_info_t *devi);
static int  sd_unit_detach(dev_info_t *devi);

static void sd_set_unit_attributes(struct sd_lun *un, dev_info_t *devi);
static void sd_create_errstats(struct sd_lun *un, int instance);
static void sd_set_errstats(struct sd_lun *un);
static void sd_set_pstats(struct sd_lun *un);

static int  sddump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk);
static int  sd_scsi_poll(struct sd_lun *un, struct scsi_pkt *pkt);
static int  sd_send_polled_RQS(struct sd_lun *un);
static int  sd_ddi_scsi_poll(struct scsi_pkt *pkt);

#if (defined(__fibre))
/*
 * Event callbacks (photon)
 */
static void sd_init_event_callbacks(struct sd_lun *un);
static void  sd_event_callback(dev_info_t *, ddi_eventcookie_t, void *, void *);
#endif

/*
 * Defines for sd_cache_control
 */

#define	SD_CACHE_ENABLE		1
#define	SD_CACHE_DISABLE	0
#define	SD_CACHE_NOCHANGE	-1

static int   sd_cache_control(sd_ssc_t *ssc, int rcd_flag, int wce_flag);
static int   sd_get_write_cache_enabled(sd_ssc_t *ssc, int *is_enabled);
static void  sd_get_nv_sup(sd_ssc_t *ssc);
static dev_t sd_make_device(dev_info_t *devi);
static void  sd_check_solid_state(sd_ssc_t *ssc);
static void  sd_check_emulation_mode(sd_ssc_t *ssc);
static void  sd_update_block_info(struct sd_lun *un, uint32_t lbasize,
	uint64_t capacity);

/*
 * Driver entry point functions.
 */
static int  sdopen(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int  sdclose(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int  sd_ready_and_valid(sd_ssc_t *ssc, int part);

static void sdmin(struct buf *bp);
static int sdread(dev_t dev, struct uio *uio, cred_t *cred_p);
static int sdwrite(dev_t dev, struct uio *uio, cred_t *cred_p);
static int sdaread(dev_t dev, struct aio_req *aio, cred_t *cred_p);
static int sdawrite(dev_t dev, struct aio_req *aio, cred_t *cred_p);

static int sdstrategy(struct buf *bp);
static int sdioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * Function prototypes for layering functions in the iostart chain.
 */
static void sd_mapblockaddr_iostart(int index, struct sd_lun *un,
	struct buf *bp);
static void sd_mapblocksize_iostart(int index, struct sd_lun *un,
	struct buf *bp);
static void sd_checksum_iostart(int index, struct sd_lun *un, struct buf *bp);
static void sd_checksum_uscsi_iostart(int index, struct sd_lun *un,
	struct buf *bp);
static void sd_pm_iostart(int index, struct sd_lun *un, struct buf *bp);
static void sd_core_iostart(int index, struct sd_lun *un, struct buf *bp);

/*
 * Function prototypes for layering functions in the iodone chain.
 */
static void sd_buf_iodone(int index, struct sd_lun *un, struct buf *bp);
static void sd_uscsi_iodone(int index, struct sd_lun *un, struct buf *bp);
static void sd_mapblockaddr_iodone(int index, struct sd_lun *un,
	struct buf *bp);
static void sd_mapblocksize_iodone(int index, struct sd_lun *un,
	struct buf *bp);
static void sd_checksum_iodone(int index, struct sd_lun *un, struct buf *bp);
static void sd_checksum_uscsi_iodone(int index, struct sd_lun *un,
	struct buf *bp);
static void sd_pm_iodone(int index, struct sd_lun *un, struct buf *bp);

/*
 * Prototypes for functions to support buf(9S) based IO.
 */
static void sd_xbuf_strategy(struct buf *bp, ddi_xbuf_t xp, void *arg);
static int sd_initpkt_for_buf(struct buf *, struct scsi_pkt **);
static void sd_destroypkt_for_buf(struct buf *);
static int sd_setup_rw_pkt(struct sd_lun *un, struct scsi_pkt **pktpp,
	struct buf *bp, int flags,
	int (*callback)(caddr_t), caddr_t callback_arg,
	diskaddr_t lba, uint32_t blockcount);
static int sd_setup_next_rw_pkt(struct sd_lun *un, struct scsi_pkt *pktp,
	struct buf *bp, diskaddr_t lba, uint32_t blockcount);

/*
 * Prototypes for functions to support USCSI IO.
 */
static int sd_uscsi_strategy(struct buf *bp);
static int sd_initpkt_for_uscsi(struct buf *, struct scsi_pkt **);
static void sd_destroypkt_for_uscsi(struct buf *);

static void sd_xbuf_init(struct sd_lun *un, struct buf *bp, struct sd_xbuf *xp,
	uchar_t chain_type, void *pktinfop);

static int  sd_pm_entry(struct sd_lun *un);
static void sd_pm_exit(struct sd_lun *un);

static void sd_pm_idletimeout_handler(void *arg);

/*
 * sd_core internal functions (used at the sd_core_io layer).
 */
static void sd_add_buf_to_waitq(struct sd_lun *un, struct buf *bp);
static void sdintr(struct scsi_pkt *pktp);
static void sd_start_cmds(struct sd_lun *un, struct buf *immed_bp);

static int sd_send_scsi_cmd(dev_t dev, struct uscsi_cmd *incmd, int flag,
	enum uio_seg dataspace, int path_flag);

static struct buf *sd_bioclone_alloc(struct buf *bp, size_t datalen,
	daddr_t blkno, int (*func)(struct buf *));
static struct buf *sd_shadow_buf_alloc(struct buf *bp, size_t datalen,
	uint_t bflags, daddr_t blkno, int (*func)(struct buf *));
static void sd_bioclone_free(struct buf *bp);
static void sd_shadow_buf_free(struct buf *bp);

static void sd_print_transport_rejected_message(struct sd_lun *un,
	struct sd_xbuf *xp, int code);
static void sd_print_incomplete_msg(struct sd_lun *un, struct buf *bp,
    void *arg, int code);
static void sd_print_sense_failed_msg(struct sd_lun *un, struct buf *bp,
    void *arg, int code);
static void sd_print_cmd_incomplete_msg(struct sd_lun *un, struct buf *bp,
    void *arg, int code);

static void sd_retry_command(struct sd_lun *un, struct buf *bp,
	int retry_check_flag,
	void (*user_funcp)(struct sd_lun *un, struct buf *bp, void *argp,
		int c),
	void *user_arg, int failure_code,  clock_t retry_delay,
	void (*statp)(kstat_io_t *));

static void sd_set_retry_bp(struct sd_lun *un, struct buf *bp,
	clock_t retry_delay, void (*statp)(kstat_io_t *));

static void sd_send_request_sense_command(struct sd_lun *un, struct buf *bp,
	struct scsi_pkt *pktp);
static void sd_start_retry_command(void *arg);
static void sd_start_direct_priority_command(void *arg);
static void sd_return_failed_command(struct sd_lun *un, struct buf *bp,
	int errcode);
static void sd_return_failed_command_no_restart(struct sd_lun *un,
	struct buf *bp, int errcode);
static void sd_return_command(struct sd_lun *un, struct buf *bp);
static void sd_sync_with_callback(struct sd_lun *un);
static int sdrunout(caddr_t arg);

static void sd_mark_rqs_busy(struct sd_lun *un, struct buf *bp);
static struct buf *sd_mark_rqs_idle(struct sd_lun *un, struct sd_xbuf *xp);

static void sd_reduce_throttle(struct sd_lun *un, int throttle_type);
static void sd_restore_throttle(void *arg);

static void sd_init_cdb_limits(struct sd_lun *un);

static void sd_pkt_status_good(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);

/*
 * Error handling functions
 */
static void sd_pkt_status_check_condition(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_status_busy(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_status_reservation_conflict(struct sd_lun *un,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_status_qfull(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);

static void sd_handle_request_sense(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_handle_auto_request_sense(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static int sd_validate_sense_data(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, size_t actual_len);
static void sd_decode_sense(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);

static void sd_print_sense_msg(struct sd_lun *un, struct buf *bp,
	void *arg, int code);

static void sd_sense_key_no_sense(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_recoverable_error(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_not_ready(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_medium_or_hardware_error(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_illegal_request(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_unit_attention(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_fail_command(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_blank_check(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_aborted_command(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_sense_key_default(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp);

static void sd_print_retry_msg(struct sd_lun *un, struct buf *bp,
	void *arg, int flag);

static void sd_pkt_reason_cmd_incomplete(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_reason_cmd_tran_err(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_reason_cmd_reset(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_reason_cmd_aborted(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_reason_cmd_timeout(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_reason_cmd_unx_bus_free(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_reason_cmd_tag_reject(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);
static void sd_pkt_reason_default(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp);

static void sd_reset_target(struct sd_lun *un, struct scsi_pkt *pktp);

static void sd_start_stop_unit_callback(void *arg);
static void sd_start_stop_unit_task(void *arg);

static void sd_taskq_create(void);
static void sd_taskq_delete(void);
static void sd_target_change_task(void *arg);
static void sd_log_dev_status_event(struct sd_lun *un, char *esc, int km_flag);
static void sd_log_lun_expansion_event(struct sd_lun *un, int km_flag);
static void sd_log_eject_request_event(struct sd_lun *un, int km_flag);
static void sd_media_change_task(void *arg);

static int sd_handle_mchange(struct sd_lun *un);
static int sd_send_scsi_DOORLOCK(sd_ssc_t *ssc, int flag, int path_flag);
static int sd_send_scsi_READ_CAPACITY(sd_ssc_t *ssc, uint64_t *capp,
	uint32_t *lbap, int path_flag);
static int sd_send_scsi_READ_CAPACITY_16(sd_ssc_t *ssc, uint64_t *capp,
	uint32_t *lbap, uint32_t *psp, int path_flag);
static int sd_send_scsi_START_STOP_UNIT(sd_ssc_t *ssc, int pc_flag,
	int flag, int path_flag);
static int sd_send_scsi_INQUIRY(sd_ssc_t *ssc, uchar_t *bufaddr,
	size_t buflen, uchar_t evpd, uchar_t page_code, size_t *residp);
static int sd_send_scsi_TEST_UNIT_READY(sd_ssc_t *ssc, int flag);
static int sd_send_scsi_PERSISTENT_RESERVE_IN(sd_ssc_t *ssc,
	uchar_t usr_cmd, uint16_t data_len, uchar_t *data_bufp);
static int sd_send_scsi_PERSISTENT_RESERVE_OUT(sd_ssc_t *ssc,
	uchar_t usr_cmd, uchar_t *usr_bufp);
static int sd_send_scsi_SYNCHRONIZE_CACHE(struct sd_lun *un,
	struct dk_callback *dkc);
static int sd_send_scsi_SYNCHRONIZE_CACHE_biodone(struct buf *bp);
static int sd_send_scsi_GET_CONFIGURATION(sd_ssc_t *ssc,
	struct uscsi_cmd *ucmdbuf, uchar_t *rqbuf, uint_t rqbuflen,
	uchar_t *bufaddr, uint_t buflen, int path_flag);
static int sd_send_scsi_feature_GET_CONFIGURATION(sd_ssc_t *ssc,
	struct uscsi_cmd *ucmdbuf, uchar_t *rqbuf, uint_t rqbuflen,
	uchar_t *bufaddr, uint_t buflen, char feature, int path_flag);
static int sd_send_scsi_MODE_SENSE(sd_ssc_t *ssc, int cdbsize,
	uchar_t *bufaddr, size_t buflen, uchar_t page_code, int path_flag);
static int sd_send_scsi_MODE_SELECT(sd_ssc_t *ssc, int cdbsize,
	uchar_t *bufaddr, size_t buflen, uchar_t save_page, int path_flag);
static int sd_send_scsi_RDWR(sd_ssc_t *ssc, uchar_t cmd, void *bufaddr,
	size_t buflen, daddr_t start_block, int path_flag);
#define	sd_send_scsi_READ(ssc, bufaddr, buflen, start_block, path_flag)	\
	sd_send_scsi_RDWR(ssc, SCMD_READ, bufaddr, buflen, start_block, \
	path_flag)
#define	sd_send_scsi_WRITE(ssc, bufaddr, buflen, start_block, path_flag)\
	sd_send_scsi_RDWR(ssc, SCMD_WRITE, bufaddr, buflen, start_block,\
	path_flag)

static int sd_send_scsi_LOG_SENSE(sd_ssc_t *ssc, uchar_t *bufaddr,
	uint16_t buflen, uchar_t page_code, uchar_t page_control,
	uint16_t param_ptr, int path_flag);
static int sd_send_scsi_GET_EVENT_STATUS_NOTIFICATION(sd_ssc_t *ssc,
	uchar_t *bufaddr, size_t buflen, uchar_t class_req);
static boolean_t sd_gesn_media_data_valid(uchar_t *data);

static int  sd_alloc_rqs(struct scsi_device *devp, struct sd_lun *un);
static void sd_free_rqs(struct sd_lun *un);

static void sd_dump_memory(struct sd_lun *un, uint_t comp, char *title,
	uchar_t *data, int len, int fmt);
static void sd_panic_for_res_conflict(struct sd_lun *un);

/*
 * Disk Ioctl Function Prototypes
 */
static int sd_get_media_info(dev_t dev, caddr_t arg, int flag);
static int sd_get_media_info_ext(dev_t dev, caddr_t arg, int flag);
static int sd_dkio_ctrl_info(dev_t dev, caddr_t arg, int flag);
static int sd_dkio_get_temp(dev_t dev, caddr_t arg, int flag);

/*
 * Multi-host Ioctl Prototypes
 */
static int sd_check_mhd(dev_t dev, int interval);
static int sd_mhd_watch_cb(caddr_t arg, struct scsi_watch_result *resultp);
static void sd_mhd_watch_incomplete(struct sd_lun *un, struct scsi_pkt *pkt);
static char *sd_sname(uchar_t status);
static void sd_mhd_resvd_recover(void *arg);
static void sd_resv_reclaim_thread();
static int sd_take_ownership(dev_t dev, struct mhioctkown *p);
static int sd_reserve_release(dev_t dev, int cmd);
static void sd_rmv_resv_reclaim_req(dev_t dev);
static void sd_mhd_reset_notify_cb(caddr_t arg);
static int sd_persistent_reservation_in_read_keys(struct sd_lun *un,
	mhioc_inkeys_t *usrp, int flag);
static int sd_persistent_reservation_in_read_resv(struct sd_lun *un,
	mhioc_inresvs_t *usrp, int flag);
static int sd_mhdioc_takeown(dev_t dev, caddr_t arg, int flag);
static int sd_mhdioc_failfast(dev_t dev, caddr_t arg, int flag);
static int sd_mhdioc_release(dev_t dev);
static int sd_mhdioc_register_devid(dev_t dev);
static int sd_mhdioc_inkeys(dev_t dev, caddr_t arg, int flag);
static int sd_mhdioc_inresv(dev_t dev, caddr_t arg, int flag);

/*
 * SCSI removable prototypes
 */
static int sr_change_blkmode(dev_t dev, int cmd, intptr_t data, int flag);
static int sr_change_speed(dev_t dev, int cmd, intptr_t data, int flag);
static int sr_atapi_change_speed(dev_t dev, int cmd, intptr_t data, int flag);
static int sr_pause_resume(dev_t dev, int mode);
static int sr_play_msf(dev_t dev, caddr_t data, int flag);
static int sr_play_trkind(dev_t dev, caddr_t data, int flag);
static int sr_read_all_subcodes(dev_t dev, caddr_t data, int flag);
static int sr_read_subchannel(dev_t dev, caddr_t data, int flag);
static int sr_read_tocentry(dev_t dev, caddr_t data, int flag);
static int sr_read_tochdr(dev_t dev, caddr_t data, int flag);
static int sr_read_cdda(dev_t dev, caddr_t data, int flag);
static int sr_read_cdxa(dev_t dev, caddr_t data, int flag);
static int sr_read_mode1(dev_t dev, caddr_t data, int flag);
static int sr_read_mode2(dev_t dev, caddr_t data, int flag);
static int sr_read_cd_mode2(dev_t dev, caddr_t data, int flag);
static int sr_sector_mode(dev_t dev, uint32_t blksize);
static int sr_eject(dev_t dev);
static void sr_ejected(register struct sd_lun *un);
static int sr_check_wp(dev_t dev);
static opaque_t sd_watch_request_submit(struct sd_lun *un);
static int sd_check_media(dev_t dev, enum dkio_state state);
static int sd_media_watch_cb(caddr_t arg, struct scsi_watch_result *resultp);
static void sd_delayed_cv_broadcast(void *arg);
static int sr_volume_ctrl(dev_t dev, caddr_t data, int flag);
static int sr_read_sony_session_offset(dev_t dev, caddr_t data, int flag);

static int sd_log_page_supported(sd_ssc_t *ssc, int log_page);

/*
 * Function Prototype for the non-512 support (DVDRAM, MO etc.) functions.
 */
static void sd_check_for_writable_cd(sd_ssc_t *ssc, int path_flag);
static int sd_wm_cache_constructor(void *wm, void *un, int flags);
static void sd_wm_cache_destructor(void *wm, void *un);
static struct sd_w_map *sd_range_lock(struct sd_lun *un, daddr_t startb,
	daddr_t endb, ushort_t typ);
static struct sd_w_map *sd_get_range(struct sd_lun *un, daddr_t startb,
	daddr_t endb);
static void sd_free_inlist_wmap(struct sd_lun *un, struct sd_w_map *wmp);
static void sd_range_unlock(struct sd_lun *un, struct sd_w_map *wm);
static void sd_read_modify_write_task(void * arg);
static int
sddump_do_read_of_rmw(struct sd_lun *un, uint64_t blkno, uint64_t nblk,
	struct buf **bpp);


/*
 * Function prototypes for failfast support.
 */
static void sd_failfast_flushq(struct sd_lun *un);
static int sd_failfast_flushq_callback(struct buf *bp);

/*
 * Function prototypes to check for lsi devices
 */
static void sd_is_lsi(struct sd_lun *un);

/*
 * Function prototypes for partial DMA support
 */
static int sd_setup_next_xfer(struct sd_lun *un, struct buf *bp,
		struct scsi_pkt *pkt, struct sd_xbuf *xp);


/* Function prototypes for cmlb */
static int sd_tg_rdwr(dev_info_t *devi, uchar_t cmd, void *bufaddr,
    diskaddr_t start_block, size_t reqlength, void *tg_cookie);

static int sd_tg_getinfo(dev_info_t *devi, int cmd, void *arg, void *tg_cookie);

/*
 * For printing RMW warning message timely
 */
static void sd_rmw_msg_print_handler(void *arg);

/*
 * Constants for failfast support:
 *
 * SD_FAILFAST_INACTIVE: Instance is currently in a normal state, with NO
 * failfast processing being performed.
 *
 * SD_FAILFAST_ACTIVE: Instance is in the failfast state and is performing
 * failfast processing on all bufs with B_FAILFAST set.
 */

#define	SD_FAILFAST_INACTIVE		0
#define	SD_FAILFAST_ACTIVE		1

/*
 * Bitmask to control behavior of buf(9S) flushes when a transition to
 * the failfast state occurs. Optional bits include:
 *
 * SD_FAILFAST_FLUSH_ALL_BUFS: When set, flush ALL bufs including those that
 * do NOT have B_FAILFAST set. When clear, only bufs with B_FAILFAST will
 * be flushed.
 *
 * SD_FAILFAST_FLUSH_ALL_QUEUES: When set, flush any/all other queues in the
 * driver, in addition to the regular wait queue. This includes the xbuf
 * queues. When clear, only the driver's wait queue will be flushed.
 */
#define	SD_FAILFAST_FLUSH_ALL_BUFS	0x01
#define	SD_FAILFAST_FLUSH_ALL_QUEUES	0x02

/*
 * The default behavior is to only flush bufs that have B_FAILFAST set, but
 * to flush all queues within the driver.
 */
static int sd_failfast_flushctl = SD_FAILFAST_FLUSH_ALL_QUEUES;


/*
 * SD Testing Fault Injection
 */
#ifdef SD_FAULT_INJECTION
static void sd_faultinjection_ioctl(int cmd, intptr_t arg, struct sd_lun *un);
static void sd_faultinjection(struct scsi_pkt *pktp);
static void sd_injection_log(char *buf, struct sd_lun *un);
#endif

/*
 * Device driver ops vector
 */
static struct cb_ops sd_cb_ops = {
	sdopen,			/* open */
	sdclose,		/* close */
	sdstrategy,		/* strategy */
	nodev,			/* print */
	sddump,			/* dump */
	sdread,			/* read */
	sdwrite,		/* write */
	sdioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	sd_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_64BIT | D_MP | D_NEW | D_HOTPLUG, /* Driver compatibility flags */
	CB_REV,			/* cb_rev */
	sdaread, 		/* async I/O read entry point */
	sdawrite		/* async I/O write entry point */
};

struct dev_ops sd_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sdinfo,			/* info */
	nulldev,		/* identify */
	sdprobe,		/* probe */
	sdattach,		/* attach */
	sddetach,		/* detach */
	nodev,			/* reset */
	&sd_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	sdpower,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

#ifndef XPV_HVM_DRIVER
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	SD_MODULE_NAME,		/* Module name. */
	&sd_ops			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

#else /* XPV_HVM_DRIVER */
static struct modlmisc modlmisc = {
	&mod_miscops,		/* Type of module. This one is a misc */
	"HVM " SD_MODULE_NAME,		/* Module name. */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};

#endif /* XPV_HVM_DRIVER */

static cmlb_tg_ops_t sd_tgops = {
	TG_DK_OPS_VERSION_1,
	sd_tg_rdwr,
	sd_tg_getinfo
};

static struct scsi_asq_key_strings sd_additional_codes[] = {
	0x81, 0, "Logical Unit is Reserved",
	0x85, 0, "Audio Address Not Valid",
	0xb6, 0, "Media Load Mechanism Failed",
	0xB9, 0, "Audio Play Operation Aborted",
	0xbf, 0, "Buffer Overflow for Read All Subcodes Command",
	0x53, 2, "Medium removal prevented",
	0x6f, 0, "Authentication failed during key exchange",
	0x6f, 1, "Key not present",
	0x6f, 2, "Key not established",
	0x6f, 3, "Read without proper authentication",
	0x6f, 4, "Mismatched region to this logical unit",
	0x6f, 5, "Region reset count error",
	0xffff, 0x0, NULL
};


/*
 * Struct for passing printing information for sense data messages
 */
struct sd_sense_info {
	int	ssi_severity;
	int	ssi_pfa_flag;
};

/*
 * Table of function pointers for iostart-side routines. Separate "chains"
 * of layered function calls are formed by placing the function pointers
 * sequentially in the desired order. Functions are called according to an
 * incrementing table index ordering. The last function in each chain must
 * be sd_core_iostart(). The corresponding iodone-side routines are expected
 * in the sd_iodone_chain[] array.
 *
 * Note: It may seem more natural to organize both the iostart and iodone
 * functions together, into an array of structures (or some similar
 * organization) with a common index, rather than two separate arrays which
 * must be maintained in synchronization. The purpose of this division is
 * to achieve improved performance: individual arrays allows for more
 * effective cache line utilization on certain platforms.
 */

typedef void (*sd_chain_t)(int index, struct sd_lun *un, struct buf *bp);


static sd_chain_t sd_iostart_chain[] = {

	/* Chain for buf IO for disk drive targets (PM enabled) */
	sd_mapblockaddr_iostart,	/* Index: 0 */
	sd_pm_iostart,			/* Index: 1 */
	sd_core_iostart,		/* Index: 2 */

	/* Chain for buf IO for disk drive targets (PM disabled) */
	sd_mapblockaddr_iostart,	/* Index: 3 */
	sd_core_iostart,		/* Index: 4 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets with RMW needed (PM enabled)
	 */
	sd_mapblockaddr_iostart,	/* Index: 5 */
	sd_mapblocksize_iostart,	/* Index: 6 */
	sd_pm_iostart,			/* Index: 7 */
	sd_core_iostart,		/* Index: 8 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets with RMW needed (PM disabled)
	 */
	sd_mapblockaddr_iostart,	/* Index: 9 */
	sd_mapblocksize_iostart,	/* Index: 10 */
	sd_core_iostart,		/* Index: 11 */

	/* Chain for buf IO for disk drives with checksumming (PM enabled) */
	sd_mapblockaddr_iostart,	/* Index: 12 */
	sd_checksum_iostart,		/* Index: 13 */
	sd_pm_iostart,			/* Index: 14 */
	sd_core_iostart,		/* Index: 15 */

	/* Chain for buf IO for disk drives with checksumming (PM disabled) */
	sd_mapblockaddr_iostart,	/* Index: 16 */
	sd_checksum_iostart,		/* Index: 17 */
	sd_core_iostart,		/* Index: 18 */

	/* Chain for USCSI commands (all targets) */
	sd_pm_iostart,			/* Index: 19 */
	sd_core_iostart,		/* Index: 20 */

	/* Chain for checksumming USCSI commands (all targets) */
	sd_checksum_uscsi_iostart,	/* Index: 21 */
	sd_pm_iostart,			/* Index: 22 */
	sd_core_iostart,		/* Index: 23 */

	/* Chain for "direct" USCSI commands (all targets) */
	sd_core_iostart,		/* Index: 24 */

	/* Chain for "direct priority" USCSI commands (all targets) */
	sd_core_iostart,		/* Index: 25 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with RMW needed with checksumming (PM enabled)
	 */
	sd_mapblockaddr_iostart,	/* Index: 26 */
	sd_mapblocksize_iostart,	/* Index: 27 */
	sd_checksum_iostart,		/* Index: 28 */
	sd_pm_iostart,			/* Index: 29 */
	sd_core_iostart,		/* Index: 30 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with RMW needed with checksumming (PM disabled)
	 */
	sd_mapblockaddr_iostart,	/* Index: 31 */
	sd_mapblocksize_iostart,	/* Index: 32 */
	sd_checksum_iostart,		/* Index: 33 */
	sd_core_iostart,		/* Index: 34 */

};

/*
 * Macros to locate the first function of each iostart chain in the
 * sd_iostart_chain[] array. These are located by the index in the array.
 */
#define	SD_CHAIN_DISK_IOSTART			0
#define	SD_CHAIN_DISK_IOSTART_NO_PM		3
#define	SD_CHAIN_MSS_DISK_IOSTART		5
#define	SD_CHAIN_RMMEDIA_IOSTART		5
#define	SD_CHAIN_MSS_DISK_IOSTART_NO_PM		9
#define	SD_CHAIN_RMMEDIA_IOSTART_NO_PM		9
#define	SD_CHAIN_CHKSUM_IOSTART			12
#define	SD_CHAIN_CHKSUM_IOSTART_NO_PM		16
#define	SD_CHAIN_USCSI_CMD_IOSTART		19
#define	SD_CHAIN_USCSI_CHKSUM_IOSTART		21
#define	SD_CHAIN_DIRECT_CMD_IOSTART		24
#define	SD_CHAIN_PRIORITY_CMD_IOSTART		25
#define	SD_CHAIN_MSS_CHKSUM_IOSTART		26
#define	SD_CHAIN_MSS_CHKSUM_IOSTART_NO_PM	31


/*
 * Table of function pointers for the iodone-side routines for the driver-
 * internal layering mechanism.  The calling sequence for iodone routines
 * uses a decrementing table index, so the last routine called in a chain
 * must be at the lowest array index location for that chain.  The last
 * routine for each chain must be either sd_buf_iodone() (for buf(9S) IOs)
 * or sd_uscsi_iodone() (for uscsi IOs).  Other than this, the ordering
 * of the functions in an iodone side chain must correspond to the ordering
 * of the iostart routines for that chain.  Note that there is no iodone
 * side routine that corresponds to sd_core_iostart(), so there is no
 * entry in the table for this.
 */

static sd_chain_t sd_iodone_chain[] = {

	/* Chain for buf IO for disk drive targets (PM enabled) */
	sd_buf_iodone,			/* Index: 0 */
	sd_mapblockaddr_iodone,		/* Index: 1 */
	sd_pm_iodone,			/* Index: 2 */

	/* Chain for buf IO for disk drive targets (PM disabled) */
	sd_buf_iodone,			/* Index: 3 */
	sd_mapblockaddr_iodone,		/* Index: 4 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets with RMW needed (PM enabled)
	 */
	sd_buf_iodone,			/* Index: 5 */
	sd_mapblockaddr_iodone,		/* Index: 6 */
	sd_mapblocksize_iodone,		/* Index: 7 */
	sd_pm_iodone,			/* Index: 8 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets with RMW needed (PM disabled)
	 */
	sd_buf_iodone,			/* Index: 9 */
	sd_mapblockaddr_iodone,		/* Index: 10 */
	sd_mapblocksize_iodone,		/* Index: 11 */

	/* Chain for buf IO for disk drives with checksumming (PM enabled) */
	sd_buf_iodone,			/* Index: 12 */
	sd_mapblockaddr_iodone,		/* Index: 13 */
	sd_checksum_iodone,		/* Index: 14 */
	sd_pm_iodone,			/* Index: 15 */

	/* Chain for buf IO for disk drives with checksumming (PM disabled) */
	sd_buf_iodone,			/* Index: 16 */
	sd_mapblockaddr_iodone,		/* Index: 17 */
	sd_checksum_iodone,		/* Index: 18 */

	/* Chain for USCSI commands (non-checksum targets) */
	sd_uscsi_iodone,		/* Index: 19 */
	sd_pm_iodone,			/* Index: 20 */

	/* Chain for USCSI commands (checksum targets) */
	sd_uscsi_iodone,		/* Index: 21 */
	sd_checksum_uscsi_iodone,	/* Index: 22 */
	sd_pm_iodone,			/* Index: 22 */

	/* Chain for "direct" USCSI commands (all targets) */
	sd_uscsi_iodone,		/* Index: 24 */

	/* Chain for "direct priority" USCSI commands (all targets) */
	sd_uscsi_iodone,		/* Index: 25 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with checksumming (PM enabled)
	 */
	sd_buf_iodone,			/* Index: 26 */
	sd_mapblockaddr_iodone,		/* Index: 27 */
	sd_mapblocksize_iodone,		/* Index: 28 */
	sd_checksum_iodone,		/* Index: 29 */
	sd_pm_iodone,			/* Index: 30 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with checksumming (PM disabled)
	 */
	sd_buf_iodone,			/* Index: 31 */
	sd_mapblockaddr_iodone,		/* Index: 32 */
	sd_mapblocksize_iodone,		/* Index: 33 */
	sd_checksum_iodone,		/* Index: 34 */
};


/*
 * Macros to locate the "first" function in the sd_iodone_chain[] array for
 * each iodone-side chain. These are located by the array index, but as the
 * iodone side functions are called in a decrementing-index order, the
 * highest index number in each chain must be specified (as these correspond
 * to the first function in the iodone chain that will be called by the core
 * at IO completion time).
 */

#define	SD_CHAIN_DISK_IODONE			2
#define	SD_CHAIN_DISK_IODONE_NO_PM		4
#define	SD_CHAIN_RMMEDIA_IODONE			8
#define	SD_CHAIN_MSS_DISK_IODONE		8
#define	SD_CHAIN_RMMEDIA_IODONE_NO_PM		11
#define	SD_CHAIN_MSS_DISK_IODONE_NO_PM		11
#define	SD_CHAIN_CHKSUM_IODONE			15
#define	SD_CHAIN_CHKSUM_IODONE_NO_PM		18
#define	SD_CHAIN_USCSI_CMD_IODONE		20
#define	SD_CHAIN_USCSI_CHKSUM_IODONE		22
#define	SD_CHAIN_DIRECT_CMD_IODONE		24
#define	SD_CHAIN_PRIORITY_CMD_IODONE		25
#define	SD_CHAIN_MSS_CHKSUM_IODONE		30
#define	SD_CHAIN_MSS_CHKSUM_IODONE_NO_PM	34



/*
 * Array to map a layering chain index to the appropriate initpkt routine.
 * The redundant entries are present so that the index used for accessing
 * the above sd_iostart_chain and sd_iodone_chain tables can be used directly
 * with this table as well.
 */
typedef int (*sd_initpkt_t)(struct buf *, struct scsi_pkt **);

static sd_initpkt_t	sd_initpkt_map[] = {

	/* Chain for buf IO for disk drive targets (PM enabled) */
	sd_initpkt_for_buf,		/* Index: 0 */
	sd_initpkt_for_buf,		/* Index: 1 */
	sd_initpkt_for_buf,		/* Index: 2 */

	/* Chain for buf IO for disk drive targets (PM disabled) */
	sd_initpkt_for_buf,		/* Index: 3 */
	sd_initpkt_for_buf,		/* Index: 4 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets (PM enabled)
	 */
	sd_initpkt_for_buf,		/* Index: 5 */
	sd_initpkt_for_buf,		/* Index: 6 */
	sd_initpkt_for_buf,		/* Index: 7 */
	sd_initpkt_for_buf,		/* Index: 8 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets (PM disabled)
	 */
	sd_initpkt_for_buf,		/* Index: 9 */
	sd_initpkt_for_buf,		/* Index: 10 */
	sd_initpkt_for_buf,		/* Index: 11 */

	/* Chain for buf IO for disk drives with checksumming (PM enabled) */
	sd_initpkt_for_buf,		/* Index: 12 */
	sd_initpkt_for_buf,		/* Index: 13 */
	sd_initpkt_for_buf,		/* Index: 14 */
	sd_initpkt_for_buf,		/* Index: 15 */

	/* Chain for buf IO for disk drives with checksumming (PM disabled) */
	sd_initpkt_for_buf,		/* Index: 16 */
	sd_initpkt_for_buf,		/* Index: 17 */
	sd_initpkt_for_buf,		/* Index: 18 */

	/* Chain for USCSI commands (non-checksum targets) */
	sd_initpkt_for_uscsi,		/* Index: 19 */
	sd_initpkt_for_uscsi,		/* Index: 20 */

	/* Chain for USCSI commands (checksum targets) */
	sd_initpkt_for_uscsi,		/* Index: 21 */
	sd_initpkt_for_uscsi,		/* Index: 22 */
	sd_initpkt_for_uscsi,		/* Index: 22 */

	/* Chain for "direct" USCSI commands (all targets) */
	sd_initpkt_for_uscsi,		/* Index: 24 */

	/* Chain for "direct priority" USCSI commands (all targets) */
	sd_initpkt_for_uscsi,		/* Index: 25 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with checksumming (PM enabled)
	 */
	sd_initpkt_for_buf,		/* Index: 26 */
	sd_initpkt_for_buf,		/* Index: 27 */
	sd_initpkt_for_buf,		/* Index: 28 */
	sd_initpkt_for_buf,		/* Index: 29 */
	sd_initpkt_for_buf,		/* Index: 30 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with checksumming (PM disabled)
	 */
	sd_initpkt_for_buf,		/* Index: 31 */
	sd_initpkt_for_buf,		/* Index: 32 */
	sd_initpkt_for_buf,		/* Index: 33 */
	sd_initpkt_for_buf,		/* Index: 34 */
};


/*
 * Array to map a layering chain index to the appropriate destroypktpkt routine.
 * The redundant entries are present so that the index used for accessing
 * the above sd_iostart_chain and sd_iodone_chain tables can be used directly
 * with this table as well.
 */
typedef void (*sd_destroypkt_t)(struct buf *);

static sd_destroypkt_t	sd_destroypkt_map[] = {

	/* Chain for buf IO for disk drive targets (PM enabled) */
	sd_destroypkt_for_buf,		/* Index: 0 */
	sd_destroypkt_for_buf,		/* Index: 1 */
	sd_destroypkt_for_buf,		/* Index: 2 */

	/* Chain for buf IO for disk drive targets (PM disabled) */
	sd_destroypkt_for_buf,		/* Index: 3 */
	sd_destroypkt_for_buf,		/* Index: 4 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets (PM enabled)
	 */
	sd_destroypkt_for_buf,		/* Index: 5 */
	sd_destroypkt_for_buf,		/* Index: 6 */
	sd_destroypkt_for_buf,		/* Index: 7 */
	sd_destroypkt_for_buf,		/* Index: 8 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets (PM disabled)
	 */
	sd_destroypkt_for_buf,		/* Index: 9 */
	sd_destroypkt_for_buf,		/* Index: 10 */
	sd_destroypkt_for_buf,		/* Index: 11 */

	/* Chain for buf IO for disk drives with checksumming (PM enabled) */
	sd_destroypkt_for_buf,		/* Index: 12 */
	sd_destroypkt_for_buf,		/* Index: 13 */
	sd_destroypkt_for_buf,		/* Index: 14 */
	sd_destroypkt_for_buf,		/* Index: 15 */

	/* Chain for buf IO for disk drives with checksumming (PM disabled) */
	sd_destroypkt_for_buf,		/* Index: 16 */
	sd_destroypkt_for_buf,		/* Index: 17 */
	sd_destroypkt_for_buf,		/* Index: 18 */

	/* Chain for USCSI commands (non-checksum targets) */
	sd_destroypkt_for_uscsi,	/* Index: 19 */
	sd_destroypkt_for_uscsi,	/* Index: 20 */

	/* Chain for USCSI commands (checksum targets) */
	sd_destroypkt_for_uscsi,	/* Index: 21 */
	sd_destroypkt_for_uscsi,	/* Index: 22 */
	sd_destroypkt_for_uscsi,	/* Index: 22 */

	/* Chain for "direct" USCSI commands (all targets) */
	sd_destroypkt_for_uscsi,	/* Index: 24 */

	/* Chain for "direct priority" USCSI commands (all targets) */
	sd_destroypkt_for_uscsi,	/* Index: 25 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with checksumming (PM disabled)
	 */
	sd_destroypkt_for_buf,		/* Index: 26 */
	sd_destroypkt_for_buf,		/* Index: 27 */
	sd_destroypkt_for_buf,		/* Index: 28 */
	sd_destroypkt_for_buf,		/* Index: 29 */
	sd_destroypkt_for_buf,		/* Index: 30 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with checksumming (PM enabled)
	 */
	sd_destroypkt_for_buf,		/* Index: 31 */
	sd_destroypkt_for_buf,		/* Index: 32 */
	sd_destroypkt_for_buf,		/* Index: 33 */
	sd_destroypkt_for_buf,		/* Index: 34 */
};



/*
 * Array to map a layering chain index to the appropriate chain "type".
 * The chain type indicates a specific property/usage of the chain.
 * The redundant entries are present so that the index used for accessing
 * the above sd_iostart_chain and sd_iodone_chain tables can be used directly
 * with this table as well.
 */

#define	SD_CHAIN_NULL			0	/* for the special RQS cmd */
#define	SD_CHAIN_BUFIO			1	/* regular buf IO */
#define	SD_CHAIN_USCSI			2	/* regular USCSI commands */
#define	SD_CHAIN_DIRECT			3	/* uscsi, w/ bypass power mgt */
#define	SD_CHAIN_DIRECT_PRIORITY	4	/* uscsi, w/ bypass power mgt */
						/* (for error recovery) */

static int sd_chain_type_map[] = {

	/* Chain for buf IO for disk drive targets (PM enabled) */
	SD_CHAIN_BUFIO,			/* Index: 0 */
	SD_CHAIN_BUFIO,			/* Index: 1 */
	SD_CHAIN_BUFIO,			/* Index: 2 */

	/* Chain for buf IO for disk drive targets (PM disabled) */
	SD_CHAIN_BUFIO,			/* Index: 3 */
	SD_CHAIN_BUFIO,			/* Index: 4 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets (PM enabled)
	 */
	SD_CHAIN_BUFIO,			/* Index: 5 */
	SD_CHAIN_BUFIO,			/* Index: 6 */
	SD_CHAIN_BUFIO,			/* Index: 7 */
	SD_CHAIN_BUFIO,			/* Index: 8 */

	/*
	 * Chain for buf IO for removable-media or large sector size
	 * disk drive targets (PM disabled)
	 */
	SD_CHAIN_BUFIO,			/* Index: 9 */
	SD_CHAIN_BUFIO,			/* Index: 10 */
	SD_CHAIN_BUFIO,			/* Index: 11 */

	/* Chain for buf IO for disk drives with checksumming (PM enabled) */
	SD_CHAIN_BUFIO,			/* Index: 12 */
	SD_CHAIN_BUFIO,			/* Index: 13 */
	SD_CHAIN_BUFIO,			/* Index: 14 */
	SD_CHAIN_BUFIO,			/* Index: 15 */

	/* Chain for buf IO for disk drives with checksumming (PM disabled) */
	SD_CHAIN_BUFIO,			/* Index: 16 */
	SD_CHAIN_BUFIO,			/* Index: 17 */
	SD_CHAIN_BUFIO,			/* Index: 18 */

	/* Chain for USCSI commands (non-checksum targets) */
	SD_CHAIN_USCSI,			/* Index: 19 */
	SD_CHAIN_USCSI,			/* Index: 20 */

	/* Chain for USCSI commands (checksum targets) */
	SD_CHAIN_USCSI,			/* Index: 21 */
	SD_CHAIN_USCSI,			/* Index: 22 */
	SD_CHAIN_USCSI,			/* Index: 23 */

	/* Chain for "direct" USCSI commands (all targets) */
	SD_CHAIN_DIRECT,		/* Index: 24 */

	/* Chain for "direct priority" USCSI commands (all targets) */
	SD_CHAIN_DIRECT_PRIORITY,	/* Index: 25 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with checksumming (PM enabled)
	 */
	SD_CHAIN_BUFIO,			/* Index: 26 */
	SD_CHAIN_BUFIO,			/* Index: 27 */
	SD_CHAIN_BUFIO,			/* Index: 28 */
	SD_CHAIN_BUFIO,			/* Index: 29 */
	SD_CHAIN_BUFIO,			/* Index: 30 */

	/*
	 * Chain for buf IO for large sector size disk drive targets
	 * with checksumming (PM disabled)
	 */
	SD_CHAIN_BUFIO,			/* Index: 31 */
	SD_CHAIN_BUFIO,			/* Index: 32 */
	SD_CHAIN_BUFIO,			/* Index: 33 */
	SD_CHAIN_BUFIO,			/* Index: 34 */
};


/* Macro to return TRUE if the IO has come from the sd_buf_iostart() chain. */
#define	SD_IS_BUFIO(xp)			\
	(sd_chain_type_map[(xp)->xb_chain_iostart] == SD_CHAIN_BUFIO)

/* Macro to return TRUE if the IO has come from the "direct priority" chain. */
#define	SD_IS_DIRECT_PRIORITY(xp)	\
	(sd_chain_type_map[(xp)->xb_chain_iostart] == SD_CHAIN_DIRECT_PRIORITY)



/*
 * Struct, array, and macros to map a specific chain to the appropriate
 * layering indexes in the sd_iostart_chain[] and sd_iodone_chain[] arrays.
 *
 * The sd_chain_index_map[] array is used at attach time to set the various
 * un_xxx_chain type members of the sd_lun softstate to the specific layering
 * chain to be used with the instance. This allows different instances to use
 * different chain for buf IO, uscsi IO, etc.. Also, since the xb_chain_iostart
 * and xb_chain_iodone index values in the sd_xbuf are initialized to these
 * values at sd_xbuf init time, this allows (1) layering chains may be changed
 * dynamically & without the use of locking; and (2) a layer may update the
 * xb_chain_io[start|done] member in a given xbuf with its current index value,
 * to allow for deferred processing of an IO within the same chain from a
 * different execution context.
 */

struct sd_chain_index {
	int	sci_iostart_index;
	int	sci_iodone_index;
};

static struct sd_chain_index	sd_chain_index_map[] = {
	{ SD_CHAIN_DISK_IOSTART,		SD_CHAIN_DISK_IODONE },
	{ SD_CHAIN_DISK_IOSTART_NO_PM,		SD_CHAIN_DISK_IODONE_NO_PM },
	{ SD_CHAIN_RMMEDIA_IOSTART,		SD_CHAIN_RMMEDIA_IODONE },
	{ SD_CHAIN_RMMEDIA_IOSTART_NO_PM,	SD_CHAIN_RMMEDIA_IODONE_NO_PM },
	{ SD_CHAIN_CHKSUM_IOSTART,		SD_CHAIN_CHKSUM_IODONE },
	{ SD_CHAIN_CHKSUM_IOSTART_NO_PM,	SD_CHAIN_CHKSUM_IODONE_NO_PM },
	{ SD_CHAIN_USCSI_CMD_IOSTART,		SD_CHAIN_USCSI_CMD_IODONE },
	{ SD_CHAIN_USCSI_CHKSUM_IOSTART,	SD_CHAIN_USCSI_CHKSUM_IODONE },
	{ SD_CHAIN_DIRECT_CMD_IOSTART,		SD_CHAIN_DIRECT_CMD_IODONE },
	{ SD_CHAIN_PRIORITY_CMD_IOSTART,	SD_CHAIN_PRIORITY_CMD_IODONE },
	{ SD_CHAIN_MSS_CHKSUM_IOSTART,		SD_CHAIN_MSS_CHKSUM_IODONE },
	{ SD_CHAIN_MSS_CHKSUM_IOSTART_NO_PM, SD_CHAIN_MSS_CHKSUM_IODONE_NO_PM },

};


/*
 * The following are indexes into the sd_chain_index_map[] array.
 */

/* un->un_buf_chain_type must be set to one of these */
#define	SD_CHAIN_INFO_DISK		0
#define	SD_CHAIN_INFO_DISK_NO_PM	1
#define	SD_CHAIN_INFO_RMMEDIA		2
#define	SD_CHAIN_INFO_MSS_DISK		2
#define	SD_CHAIN_INFO_RMMEDIA_NO_PM	3
#define	SD_CHAIN_INFO_MSS_DSK_NO_PM	3
#define	SD_CHAIN_INFO_CHKSUM		4
#define	SD_CHAIN_INFO_CHKSUM_NO_PM	5
#define	SD_CHAIN_INFO_MSS_DISK_CHKSUM	10
#define	SD_CHAIN_INFO_MSS_DISK_CHKSUM_NO_PM	11

/* un->un_uscsi_chain_type must be set to one of these */
#define	SD_CHAIN_INFO_USCSI_CMD		6
/* USCSI with PM disabled is the same as DIRECT */
#define	SD_CHAIN_INFO_USCSI_CMD_NO_PM	8
#define	SD_CHAIN_INFO_USCSI_CHKSUM	7

/* un->un_direct_chain_type must be set to one of these */
#define	SD_CHAIN_INFO_DIRECT_CMD	8

/* un->un_priority_chain_type must be set to one of these */
#define	SD_CHAIN_INFO_PRIORITY_CMD	9

/* size for devid inquiries */
#define	MAX_INQUIRY_SIZE		0xF0

/*
 * Macros used by functions to pass a given buf(9S) struct along to the
 * next function in the layering chain for further processing.
 *
 * In the following macros, passing more than three arguments to the called
 * routines causes the optimizer for the SPARC compiler to stop doing tail
 * call elimination which results in significant performance degradation.
 */
#define	SD_BEGIN_IOSTART(index, un, bp)	\
	((*(sd_iostart_chain[index]))(index, un, bp))

#define	SD_BEGIN_IODONE(index, un, bp)	\
	((*(sd_iodone_chain[index]))(index, un, bp))

#define	SD_NEXT_IOSTART(index, un, bp)				\
	((*(sd_iostart_chain[(index) + 1]))((index) + 1, un, bp))

#define	SD_NEXT_IODONE(index, un, bp)				\
	((*(sd_iodone_chain[(index) - 1]))((index) - 1, un, bp))

/*
 *    Function: _init
 *
 * Description: This is the driver _init(9E) entry point.
 *
 * Return Code: Returns the value from mod_install(9F) or
 *		ddi_soft_state_init(9F) as appropriate.
 *
 *     Context: Called when driver module loaded.
 */

int
_init(void)
{
	int	err;

	/* establish driver name from module name */
	sd_label = (char *)mod_modname(&modlinkage);

#ifndef XPV_HVM_DRIVER
	err = ddi_soft_state_init(&sd_state, sizeof (struct sd_lun),
	    SD_MAXUNIT);
	if (err != 0) {
		return (err);
	}

#else /* XPV_HVM_DRIVER */
	/* Remove the leading "hvm_" from the module name */
	ASSERT(strncmp(sd_label, "hvm_", strlen("hvm_")) == 0);
	sd_label += strlen("hvm_");

#endif /* XPV_HVM_DRIVER */

	mutex_init(&sd_detach_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sd_log_mutex,    NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sd_label_mutex,  NULL, MUTEX_DRIVER, NULL);

	mutex_init(&sd_tr.srq_resv_reclaim_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sd_tr.srq_resv_reclaim_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sd_tr.srq_inprocess_cv, NULL, CV_DRIVER, NULL);

	/*
	 * it's ok to init here even for fibre device
	 */
	sd_scsi_probe_cache_init();

	sd_scsi_target_lun_init();

	/*
	 * Creating taskq before mod_install ensures that all callers (threads)
	 * that enter the module after a successful mod_install encounter
	 * a valid taskq.
	 */
	sd_taskq_create();

	err = mod_install(&modlinkage);
	if (err != 0) {
		/* delete taskq if install fails */
		sd_taskq_delete();

		mutex_destroy(&sd_detach_mutex);
		mutex_destroy(&sd_log_mutex);
		mutex_destroy(&sd_label_mutex);

		mutex_destroy(&sd_tr.srq_resv_reclaim_mutex);
		cv_destroy(&sd_tr.srq_resv_reclaim_cv);
		cv_destroy(&sd_tr.srq_inprocess_cv);

		sd_scsi_probe_cache_fini();

		sd_scsi_target_lun_fini();

#ifndef XPV_HVM_DRIVER
		ddi_soft_state_fini(&sd_state);
#endif /* !XPV_HVM_DRIVER */
		return (err);
	}

	return (err);
}


/*
 *    Function: _fini
 *
 * Description: This is the driver _fini(9E) entry point.
 *
 * Return Code: Returns the value from mod_remove(9F)
 *
 *     Context: Called when driver module is unloaded.
 */

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0) {
		return (err);
	}

	sd_taskq_delete();

	mutex_destroy(&sd_detach_mutex);
	mutex_destroy(&sd_log_mutex);
	mutex_destroy(&sd_label_mutex);
	mutex_destroy(&sd_tr.srq_resv_reclaim_mutex);

	sd_scsi_probe_cache_fini();

	sd_scsi_target_lun_fini();

	cv_destroy(&sd_tr.srq_resv_reclaim_cv);
	cv_destroy(&sd_tr.srq_inprocess_cv);

#ifndef XPV_HVM_DRIVER
	ddi_soft_state_fini(&sd_state);
#endif /* !XPV_HVM_DRIVER */

	return (err);
}


/*
 *    Function: _info
 *
 * Description: This is the driver _info(9E) entry point.
 *
 *   Arguments: modinfop - pointer to the driver modinfo structure
 *
 * Return Code: Returns the value from mod_info(9F).
 *
 *     Context: Kernel thread context
 */

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * The following routines implement the driver message logging facility.
 * They provide component- and level- based debug output filtering.
 * Output may also be restricted to messages for a single instance by
 * specifying a soft state pointer in sd_debug_un. If sd_debug_un is set
 * to NULL, then messages for all instances are printed.
 *
 * These routines have been cloned from each other due to the language
 * constraints of macros and variable argument list processing.
 */


/*
 *    Function: sd_log_err
 *
 * Description: This routine is called by the SD_ERROR macro for debug
 *		logging of error conditions.
 *
 *   Arguments: comp - driver component being logged
 *		dev  - pointer to driver info structure
 *		fmt  - error string and format to be logged
 */

static void
sd_log_err(uint_t comp, struct sd_lun *un, const char *fmt, ...)
{
	va_list		ap;
	dev_info_t	*dev;

	ASSERT(un != NULL);
	dev = SD_DEVINFO(un);
	ASSERT(dev != NULL);

	/*
	 * Filter messages based on the global component and level masks.
	 * Also print if un matches the value of sd_debug_un, or if
	 * sd_debug_un is set to NULL.
	 */
	if ((sd_component_mask & comp) && (sd_level_mask & SD_LOGMASK_ERROR) &&
	    ((sd_debug_un == NULL) || (sd_debug_un == un))) {
		mutex_enter(&sd_log_mutex);
		va_start(ap, fmt);
		(void) vsprintf(sd_log_buf, fmt, ap);
		va_end(ap);
		scsi_log(dev, sd_label, CE_CONT, "%s", sd_log_buf);
		mutex_exit(&sd_log_mutex);
	}
#ifdef SD_FAULT_INJECTION
	_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::sd_injection_mask));
	if (un->sd_injection_mask & comp) {
		mutex_enter(&sd_log_mutex);
		va_start(ap, fmt);
		(void) vsprintf(sd_log_buf, fmt, ap);
		va_end(ap);
		sd_injection_log(sd_log_buf, un);
		mutex_exit(&sd_log_mutex);
	}
#endif
}


/*
 *    Function: sd_log_info
 *
 * Description: This routine is called by the SD_INFO macro for debug
 *		logging of general purpose informational conditions.
 *
 *   Arguments: comp - driver component being logged
 *		dev  - pointer to driver info structure
 *		fmt  - info string and format to be logged
 */

static void
sd_log_info(uint_t component, struct sd_lun *un, const char *fmt, ...)
{
	va_list		ap;
	dev_info_t	*dev;

	ASSERT(un != NULL);
	dev = SD_DEVINFO(un);
	ASSERT(dev != NULL);

	/*
	 * Filter messages based on the global component and level masks.
	 * Also print if un matches the value of sd_debug_un, or if
	 * sd_debug_un is set to NULL.
	 */
	if ((sd_component_mask & component) &&
	    (sd_level_mask & SD_LOGMASK_INFO) &&
	    ((sd_debug_un == NULL) || (sd_debug_un == un))) {
		mutex_enter(&sd_log_mutex);
		va_start(ap, fmt);
		(void) vsprintf(sd_log_buf, fmt, ap);
		va_end(ap);
		scsi_log(dev, sd_label, CE_CONT, "%s", sd_log_buf);
		mutex_exit(&sd_log_mutex);
	}
#ifdef SD_FAULT_INJECTION
	_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::sd_injection_mask));
	if (un->sd_injection_mask & component) {
		mutex_enter(&sd_log_mutex);
		va_start(ap, fmt);
		(void) vsprintf(sd_log_buf, fmt, ap);
		va_end(ap);
		sd_injection_log(sd_log_buf, un);
		mutex_exit(&sd_log_mutex);
	}
#endif
}


/*
 *    Function: sd_log_trace
 *
 * Description: This routine is called by the SD_TRACE macro for debug
 *		logging of trace conditions (i.e. function entry/exit).
 *
 *   Arguments: comp - driver component being logged
 *		dev  - pointer to driver info structure
 *		fmt  - trace string and format to be logged
 */

static void
sd_log_trace(uint_t component, struct sd_lun *un, const char *fmt, ...)
{
	va_list		ap;
	dev_info_t	*dev;

	ASSERT(un != NULL);
	dev = SD_DEVINFO(un);
	ASSERT(dev != NULL);

	/*
	 * Filter messages based on the global component and level masks.
	 * Also print if un matches the value of sd_debug_un, or if
	 * sd_debug_un is set to NULL.
	 */
	if ((sd_component_mask & component) &&
	    (sd_level_mask & SD_LOGMASK_TRACE) &&
	    ((sd_debug_un == NULL) || (sd_debug_un == un))) {
		mutex_enter(&sd_log_mutex);
		va_start(ap, fmt);
		(void) vsprintf(sd_log_buf, fmt, ap);
		va_end(ap);
		scsi_log(dev, sd_label, CE_CONT, "%s", sd_log_buf);
		mutex_exit(&sd_log_mutex);
	}
#ifdef SD_FAULT_INJECTION
	_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::sd_injection_mask));
	if (un->sd_injection_mask & component) {
		mutex_enter(&sd_log_mutex);
		va_start(ap, fmt);
		(void) vsprintf(sd_log_buf, fmt, ap);
		va_end(ap);
		sd_injection_log(sd_log_buf, un);
		mutex_exit(&sd_log_mutex);
	}
#endif
}


/*
 *    Function: sdprobe
 *
 * Description: This is the driver probe(9e) entry point function.
 *
 *   Arguments: devi - opaque device info handle
 *
 * Return Code: DDI_PROBE_SUCCESS: If the probe was successful.
 *              DDI_PROBE_FAILURE: If the probe failed.
 *              DDI_PROBE_PARTIAL: If the instance is not present now,
 *				   but may be present in the future.
 */

static int
sdprobe(dev_info_t *devi)
{
	struct scsi_device	*devp;
	int			rval;
#ifndef XPV_HVM_DRIVER
	int			instance = ddi_get_instance(devi);
#endif /* !XPV_HVM_DRIVER */

	/*
	 * if it wasn't for pln, sdprobe could actually be nulldev
	 * in the "__fibre" case.
	 */
	if (ddi_dev_is_sid(devi) == DDI_SUCCESS) {
		return (DDI_PROBE_DONTCARE);
	}

	devp = ddi_get_driver_private(devi);

	if (devp == NULL) {
		/* Ooops... nexus driver is mis-configured... */
		return (DDI_PROBE_FAILURE);
	}

#ifndef XPV_HVM_DRIVER
	if (ddi_get_soft_state(sd_state, instance) != NULL) {
		return (DDI_PROBE_PARTIAL);
	}
#endif /* !XPV_HVM_DRIVER */

	/*
	 * Call the SCSA utility probe routine to see if we actually
	 * have a target at this SCSI nexus.
	 */
	switch (sd_scsi_probe_with_cache(devp, NULL_FUNC)) {
	case SCSIPROBE_EXISTS:
		switch (devp->sd_inq->inq_dtype) {
		case DTYPE_DIRECT:
			rval = DDI_PROBE_SUCCESS;
			break;
		case DTYPE_RODIRECT:
			/* CDs etc. Can be removable media */
			rval = DDI_PROBE_SUCCESS;
			break;
		case DTYPE_OPTICAL:
			/*
			 * Rewritable optical driver HP115AA
			 * Can also be removable media
			 */

			/*
			 * Do not attempt to bind to  DTYPE_OPTICAL if
			 * pre solaris 9 sparc sd behavior is required
			 *
			 * If first time through and sd_dtype_optical_bind
			 * has not been set in /etc/system check properties
			 */

			if (sd_dtype_optical_bind  < 0) {
				sd_dtype_optical_bind = ddi_prop_get_int
				    (DDI_DEV_T_ANY, devi, 0,
				    "optical-device-bind", 1);
			}

			if (sd_dtype_optical_bind == 0) {
				rval = DDI_PROBE_FAILURE;
			} else {
				rval = DDI_PROBE_SUCCESS;
			}
			break;

		case DTYPE_NOTPRESENT:
		default:
			rval = DDI_PROBE_FAILURE;
			break;
		}
		break;
	default:
		rval = DDI_PROBE_PARTIAL;
		break;
	}

	/*
	 * This routine checks for resource allocation prior to freeing,
	 * so it will take care of the "smart probing" case where a
	 * scsi_probe() may or may not have been issued and will *not*
	 * free previously-freed resources.
	 */
	scsi_unprobe(devp);
	return (rval);
}


/*
 *    Function: sdinfo
 *
 * Description: This is the driver getinfo(9e) entry point function.
 * 		Given the device number, return the devinfo pointer from
 *		the scsi_device structure or the instance number
 *		associated with the dev_t.
 *
 *   Arguments: dip     - pointer to device info structure
 *		infocmd - command argument (DDI_INFO_DEVT2DEVINFO,
 *			  DDI_INFO_DEVT2INSTANCE)
 *		arg     - driver dev_t
 *		resultp - user buffer for request response
 *
 * Return Code: DDI_SUCCESS
 *              DDI_FAILURE
 */
/* ARGSUSED */
static int
sdinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	struct sd_lun	*un;
	dev_t		dev;
	int		instance;
	int		error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = SDUNIT(dev);
		if ((un = ddi_get_soft_state(sd_state, instance)) == NULL) {
			return (DDI_FAILURE);
		}
		*result = (void *) SD_DEVINFO(un);
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = SDUNIT(dev);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 *    Function: sd_prop_op
 *
 * Description: This is the driver prop_op(9e) entry point function.
 *		Return the number of blocks for the partition in question
 *		or forward the request to the property facilities.
 *
 *   Arguments: dev       - device number
 *		dip       - pointer to device info structure
 *		prop_op   - property operator
 *		mod_flags - DDI_PROP_DONTPASS, don't pass to parent
 *		name      - pointer to property name
 *		valuep    - pointer or address of the user buffer
 *		lengthp   - property length
 *
 * Return Code: DDI_PROP_SUCCESS
 *              DDI_PROP_NOT_FOUND
 *              DDI_PROP_UNDEFINED
 *              DDI_PROP_NO_MEMORY
 *              DDI_PROP_BUF_TOO_SMALL
 */

static int
sd_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
	char *name, caddr_t valuep, int *lengthp)
{
	struct sd_lun	*un;

	if ((un = ddi_get_soft_state(sd_state, ddi_get_instance(dip))) == NULL)
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));

	return (cmlb_prop_op(un->un_cmlbhandle,
	    dev, dip, prop_op, mod_flags, name, valuep, lengthp,
	    SDPART(dev), (void *)SD_PATH_DIRECT));
}

/*
 * The following functions are for smart probing:
 * sd_scsi_probe_cache_init()
 * sd_scsi_probe_cache_fini()
 * sd_scsi_clear_probe_cache()
 * sd_scsi_probe_with_cache()
 */

/*
 *    Function: sd_scsi_probe_cache_init
 *
 * Description: Initializes the probe response cache mutex and head pointer.
 *
 *     Context: Kernel thread context
 */

static void
sd_scsi_probe_cache_init(void)
{
	mutex_init(&sd_scsi_probe_cache_mutex, NULL, MUTEX_DRIVER, NULL);
	sd_scsi_probe_cache_head = NULL;
}


/*
 *    Function: sd_scsi_probe_cache_fini
 *
 * Description: Frees all resources associated with the probe response cache.
 *
 *     Context: Kernel thread context
 */

static void
sd_scsi_probe_cache_fini(void)
{
	struct sd_scsi_probe_cache *cp;
	struct sd_scsi_probe_cache *ncp;

	/* Clean up our smart probing linked list */
	for (cp = sd_scsi_probe_cache_head; cp != NULL; cp = ncp) {
		ncp = cp->next;
		kmem_free(cp, sizeof (struct sd_scsi_probe_cache));
	}
	sd_scsi_probe_cache_head = NULL;
	mutex_destroy(&sd_scsi_probe_cache_mutex);
}


/*
 *    Function: sd_scsi_clear_probe_cache
 *
 * Description: This routine clears the probe response cache. This is
 *		done when open() returns ENXIO so that when deferred
 *		attach is attempted (possibly after a device has been
 *		turned on) we will retry the probe. Since we don't know
 *		which target we failed to open, we just clear the
 *		entire cache.
 *
 *     Context: Kernel thread context
 */

static void
sd_scsi_clear_probe_cache(void)
{
	struct sd_scsi_probe_cache	*cp;
	int				i;

	mutex_enter(&sd_scsi_probe_cache_mutex);
	for (cp = sd_scsi_probe_cache_head; cp != NULL; cp = cp->next) {
		/*
		 * Reset all entries to SCSIPROBE_EXISTS.  This will
		 * force probing to be performed the next time
		 * sd_scsi_probe_with_cache is called.
		 */
		for (i = 0; i < NTARGETS_WIDE; i++) {
			cp->cache[i] = SCSIPROBE_EXISTS;
		}
	}
	mutex_exit(&sd_scsi_probe_cache_mutex);
}


/*
 *    Function: sd_scsi_probe_with_cache
 *
 * Description: This routine implements support for a scsi device probe
 *		with cache. The driver maintains a cache of the target
 *		responses to scsi probes. If we get no response from a
 *		target during a probe inquiry, we remember that, and we
 *		avoid additional calls to scsi_probe on non-zero LUNs
 *		on the same target until the cache is cleared. By doing
 *		so we avoid the 1/4 sec selection timeout for nonzero
 *		LUNs. lun0 of a target is always probed.
 *
 *   Arguments: devp     - Pointer to a scsi_device(9S) structure
 *              waitfunc - indicates what the allocator routines should
 *			   do when resources are not available. This value
 *			   is passed on to scsi_probe() when that routine
 *			   is called.
 *
 * Return Code: SCSIPROBE_NORESP if a NORESP in probe response cache;
 *		otherwise the value returned by scsi_probe(9F).
 *
 *     Context: Kernel thread context
 */

static int
sd_scsi_probe_with_cache(struct scsi_device *devp, int (*waitfn)())
{
	struct sd_scsi_probe_cache	*cp;
	dev_info_t	*pdip = ddi_get_parent(devp->sd_dev);
	int		lun, tgt;

	lun = ddi_prop_get_int(DDI_DEV_T_ANY, devp->sd_dev, DDI_PROP_DONTPASS,
	    SCSI_ADDR_PROP_LUN, 0);
	tgt = ddi_prop_get_int(DDI_DEV_T_ANY, devp->sd_dev, DDI_PROP_DONTPASS,
	    SCSI_ADDR_PROP_TARGET, -1);

	/* Make sure caching enabled and target in range */
	if ((tgt < 0) || (tgt >= NTARGETS_WIDE)) {
		/* do it the old way (no cache) */
		return (scsi_probe(devp, waitfn));
	}

	mutex_enter(&sd_scsi_probe_cache_mutex);

	/* Find the cache for this scsi bus instance */
	for (cp = sd_scsi_probe_cache_head; cp != NULL; cp = cp->next) {
		if (cp->pdip == pdip) {
			break;
		}
	}

	/* If we can't find a cache for this pdip, create one */
	if (cp == NULL) {
		int i;

		cp = kmem_zalloc(sizeof (struct sd_scsi_probe_cache),
		    KM_SLEEP);
		cp->pdip = pdip;
		cp->next = sd_scsi_probe_cache_head;
		sd_scsi_probe_cache_head = cp;
		for (i = 0; i < NTARGETS_WIDE; i++) {
			cp->cache[i] = SCSIPROBE_EXISTS;
		}
	}

	mutex_exit(&sd_scsi_probe_cache_mutex);

	/* Recompute the cache for this target if LUN zero */
	if (lun == 0) {
		cp->cache[tgt] = SCSIPROBE_EXISTS;
	}

	/* Don't probe if cache remembers a NORESP from a previous LUN. */
	if (cp->cache[tgt] != SCSIPROBE_EXISTS) {
		return (SCSIPROBE_NORESP);
	}

	/* Do the actual probe; save & return the result */
	return (cp->cache[tgt] = scsi_probe(devp, waitfn));
}


/*
 *    Function: sd_scsi_target_lun_init
 *
 * Description: Initializes the attached lun chain mutex and head pointer.
 *
 *     Context: Kernel thread context
 */

static void
sd_scsi_target_lun_init(void)
{
	mutex_init(&sd_scsi_target_lun_mutex, NULL, MUTEX_DRIVER, NULL);
	sd_scsi_target_lun_head = NULL;
}


/*
 *    Function: sd_scsi_target_lun_fini
 *
 * Description: Frees all resources associated with the attached lun
 *              chain
 *
 *     Context: Kernel thread context
 */

static void
sd_scsi_target_lun_fini(void)
{
	struct sd_scsi_hba_tgt_lun	*cp;
	struct sd_scsi_hba_tgt_lun	*ncp;

	for (cp = sd_scsi_target_lun_head; cp != NULL; cp = ncp) {
		ncp = cp->next;
		kmem_free(cp, sizeof (struct sd_scsi_hba_tgt_lun));
	}
	sd_scsi_target_lun_head = NULL;
	mutex_destroy(&sd_scsi_target_lun_mutex);
}


/*
 *    Function: sd_scsi_get_target_lun_count
 *
 * Description: This routine will check in the attached lun chain to see
 * 		how many luns are attached on the required SCSI controller
 * 		and target. Currently, some capabilities like tagged queue
 *		are supported per target based by HBA. So all luns in a
 *		target have the same capabilities. Based on this assumption,
 * 		sd should only set these capabilities once per target. This
 *		function is called when sd needs to decide how many luns
 *		already attached on a target.
 *
 *   Arguments: dip	- Pointer to the system's dev_info_t for the SCSI
 *			  controller device.
 *              target	- The target ID on the controller's SCSI bus.
 *
 * Return Code: The number of luns attached on the required target and
 *		controller.
 *		-1 if target ID is not in parallel SCSI scope or the given
 * 		dip is not in the chain.
 *
 *     Context: Kernel thread context
 */

static int
sd_scsi_get_target_lun_count(dev_info_t *dip, int target)
{
	struct sd_scsi_hba_tgt_lun	*cp;

	if ((target < 0) || (target >= NTARGETS_WIDE)) {
		return (-1);
	}

	mutex_enter(&sd_scsi_target_lun_mutex);

	for (cp = sd_scsi_target_lun_head; cp != NULL; cp = cp->next) {
		if (cp->pdip == dip) {
			break;
		}
	}

	mutex_exit(&sd_scsi_target_lun_mutex);

	if (cp == NULL) {
		return (-1);
	}

	return (cp->nlun[target]);
}


/*
 *    Function: sd_scsi_update_lun_on_target
 *
 * Description: This routine is used to update the attached lun chain when a
 *		lun is attached or detached on a target.
 *
 *   Arguments: dip     - Pointer to the system's dev_info_t for the SCSI
 *                        controller device.
 *              target  - The target ID on the controller's SCSI bus.
 *		flag	- Indicate the lun is attached or detached.
 *
 *     Context: Kernel thread context
 */

static void
sd_scsi_update_lun_on_target(dev_info_t *dip, int target, int flag)
{
	struct sd_scsi_hba_tgt_lun	*cp;

	mutex_enter(&sd_scsi_target_lun_mutex);

	for (cp = sd_scsi_target_lun_head; cp != NULL; cp = cp->next) {
		if (cp->pdip == dip) {
			break;
		}
	}

	if ((cp == NULL) && (flag == SD_SCSI_LUN_ATTACH)) {
		cp = kmem_zalloc(sizeof (struct sd_scsi_hba_tgt_lun),
		    KM_SLEEP);
		cp->pdip = dip;
		cp->next = sd_scsi_target_lun_head;
		sd_scsi_target_lun_head = cp;
	}

	mutex_exit(&sd_scsi_target_lun_mutex);

	if (cp != NULL) {
		if (flag == SD_SCSI_LUN_ATTACH) {
			cp->nlun[target] ++;
		} else {
			cp->nlun[target] --;
		}
	}
}


/*
 *    Function: sd_spin_up_unit
 *
 * Description: Issues the following commands to spin-up the device:
 *		START STOP UNIT, and INQUIRY.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *
 * Return Code: 0 - success
 *		EIO - failure
 *		EACCES - reservation conflict
 *
 *     Context: Kernel thread context
 */

static int
sd_spin_up_unit(sd_ssc_t *ssc)
{
	size_t	resid		= 0;
	int	has_conflict	= FALSE;
	uchar_t *bufaddr;
	int 	status;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	/*
	 * Send a throwaway START UNIT command.
	 *
	 * If we fail on this, we don't care presently what precisely
	 * is wrong.  EMC's arrays will also fail this with a check
	 * condition (0x2/0x4/0x3) if the device is "inactive," but
	 * we don't want to fail the attach because it may become
	 * "active" later.
	 * We don't know if power condition is supported or not at
	 * this stage, use START STOP bit.
	 */
	status = sd_send_scsi_START_STOP_UNIT(ssc, SD_START_STOP,
	    SD_TARGET_START, SD_PATH_DIRECT);

	if (status != 0) {
		if (status == EACCES)
			has_conflict = TRUE;
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}

	/*
	 * Send another INQUIRY command to the target. This is necessary for
	 * non-removable media direct access devices because their INQUIRY data
	 * may not be fully qualified until they are spun up (perhaps via the
	 * START command above).  Note: This seems to be needed for some
	 * legacy devices only.) The INQUIRY command should succeed even if a
	 * Reservation Conflict is present.
	 */
	bufaddr = kmem_zalloc(SUN_INQSIZE, KM_SLEEP);

	if (sd_send_scsi_INQUIRY(ssc, bufaddr, SUN_INQSIZE, 0, 0, &resid)
	    != 0) {
		kmem_free(bufaddr, SUN_INQSIZE);
		sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
		return (EIO);
	}

	/*
	 * If we got enough INQUIRY data, copy it over the old INQUIRY data.
	 * Note that this routine does not return a failure here even if the
	 * INQUIRY command did not return any data.  This is a legacy behavior.
	 */
	if ((SUN_INQSIZE - resid) >= SUN_MIN_INQLEN) {
		bcopy(bufaddr, SD_INQUIRY(un), SUN_INQSIZE);
	}

	kmem_free(bufaddr, SUN_INQSIZE);

	/* If we hit a reservation conflict above, tell the caller. */
	if (has_conflict == TRUE) {
		return (EACCES);
	}

	return (0);
}

#ifdef _LP64
/*
 *    Function: sd_enable_descr_sense
 *
 * Description: This routine attempts to select descriptor sense format
 *		using the Control mode page.  Devices that support 64 bit
 *		LBAs (for >2TB luns) should also implement descriptor
 *		sense data so we will call this function whenever we see
 *		a lun larger than 2TB.  If for some reason the device
 *		supports 64 bit LBAs but doesn't support descriptor sense
 *		presumably the mode select will fail.  Everything will
 *		continue to work normally except that we will not get
 *		complete sense data for commands that fail with an LBA
 *		larger than 32 bits.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *
 *     Context: Kernel thread context only
 */

static void
sd_enable_descr_sense(sd_ssc_t *ssc)
{
	uchar_t			*header;
	struct mode_control_scsi3 *ctrl_bufp;
	size_t			buflen;
	size_t			bd_len;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	/*
	 * Read MODE SENSE page 0xA, Control Mode Page
	 */
	buflen = MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH +
	    sizeof (struct mode_control_scsi3);
	header = kmem_zalloc(buflen, KM_SLEEP);

	status = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP0, header, buflen,
	    MODEPAGE_CTRL_MODE, SD_PATH_DIRECT);

	if (status != 0) {
		SD_ERROR(SD_LOG_COMMON, un,
		    "sd_enable_descr_sense: mode sense ctrl page failed\n");
		goto eds_exit;
	}

	/*
	 * Determine size of Block Descriptors in order to locate
	 * the mode page data. ATAPI devices return 0, SCSI devices
	 * should return MODE_BLK_DESC_LENGTH.
	 */
	bd_len  = ((struct mode_header *)header)->bdesc_length;

	/* Clear the mode data length field for MODE SELECT */
	((struct mode_header *)header)->length = 0;

	ctrl_bufp = (struct mode_control_scsi3 *)
	    (header + MODE_HEADER_LENGTH + bd_len);

	/*
	 * If the page length is smaller than the expected value,
	 * the target device doesn't support D_SENSE. Bail out here.
	 */
	if (ctrl_bufp->mode_page.length <
	    sizeof (struct mode_control_scsi3) - 2) {
		SD_ERROR(SD_LOG_COMMON, un,
		    "sd_enable_descr_sense: enable D_SENSE failed\n");
		goto eds_exit;
	}

	/*
	 * Clear PS bit for MODE SELECT
	 */
	ctrl_bufp->mode_page.ps = 0;

	/*
	 * Set D_SENSE to enable descriptor sense format.
	 */
	ctrl_bufp->d_sense = 1;

	sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	/*
	 * Use MODE SELECT to commit the change to the D_SENSE bit
	 */
	status = sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP0, header,
	    buflen, SD_DONTSAVE_PAGE, SD_PATH_DIRECT);

	if (status != 0) {
		SD_INFO(SD_LOG_COMMON, un,
		    "sd_enable_descr_sense: mode select ctrl page failed\n");
	} else {
		kmem_free(header, buflen);
		return;
	}

eds_exit:
	sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	kmem_free(header, buflen);
}

/*
 *    Function: sd_reenable_dsense_task
 *
 * Description: Re-enable descriptor sense after device or bus reset
 *
 *     Context: Executes in a taskq() thread context
 */
static void
sd_reenable_dsense_task(void *arg)
{
	struct	sd_lun	*un = arg;
	sd_ssc_t	*ssc;

	ASSERT(un != NULL);

	ssc = sd_ssc_init(un);
	sd_enable_descr_sense(ssc);
	sd_ssc_fini(ssc);
}
#endif /* _LP64 */

/*
 *    Function: sd_set_mmc_caps
 *
 * Description: This routine determines if the device is MMC compliant and if
 *		the device supports CDDA via a mode sense of the CDVD
 *		capabilities mode page. Also checks if the device is a
 *		dvdram writable device.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *
 *     Context: Kernel thread context only
 */

static void
sd_set_mmc_caps(sd_ssc_t *ssc)
{
	struct mode_header_grp2		*sense_mhp;
	uchar_t				*sense_page;
	caddr_t				buf;
	int				bd_len;
	int				status;
	struct uscsi_cmd		com;
	int				rtn;
	uchar_t				*out_data_rw, *out_data_hd;
	uchar_t				*rqbuf_rw, *rqbuf_hd;
	uchar_t				*out_data_gesn;
	int				gesn_len;
	struct sd_lun			*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	/*
	 * The flags which will be set in this function are - mmc compliant,
	 * dvdram writable device, cdda support. Initialize them to FALSE
	 * and if a capability is detected - it will be set to TRUE.
	 */
	un->un_f_mmc_cap = FALSE;
	un->un_f_dvdram_writable_device = FALSE;
	un->un_f_cfg_cdda = FALSE;

	buf = kmem_zalloc(BUFLEN_MODE_CDROM_CAP, KM_SLEEP);
	status = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP1, (uchar_t *)buf,
	    BUFLEN_MODE_CDROM_CAP, MODEPAGE_CDROM_CAP, SD_PATH_DIRECT);

	sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	if (status != 0) {
		/* command failed; just return */
		kmem_free(buf, BUFLEN_MODE_CDROM_CAP);
		return;
	}
	/*
	 * If the mode sense request for the CDROM CAPABILITIES
	 * page (0x2A) succeeds the device is assumed to be MMC.
	 */
	un->un_f_mmc_cap = TRUE;

	/* See if GET STATUS EVENT NOTIFICATION is supported */
	if (un->un_f_mmc_gesn_polling) {
		gesn_len = SD_GESN_HEADER_LEN + SD_GESN_MEDIA_DATA_LEN;
		out_data_gesn = kmem_zalloc(gesn_len, KM_SLEEP);

		rtn = sd_send_scsi_GET_EVENT_STATUS_NOTIFICATION(ssc,
		    out_data_gesn, gesn_len, 1 << SD_GESN_MEDIA_CLASS);

		sd_ssc_assessment(ssc, SD_FMT_IGNORE);

		if ((rtn != 0) || !sd_gesn_media_data_valid(out_data_gesn)) {
			un->un_f_mmc_gesn_polling = FALSE;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_set_mmc_caps: gesn not supported "
			    "%d %x %x %x %x\n", rtn,
			    out_data_gesn[0], out_data_gesn[1],
			    out_data_gesn[2], out_data_gesn[3]);
		}

		kmem_free(out_data_gesn, gesn_len);
	}

	/* Get to the page data */
	sense_mhp = (struct mode_header_grp2 *)buf;
	bd_len = (sense_mhp->bdesc_length_hi << 8) |
	    sense_mhp->bdesc_length_lo;
	if (bd_len > MODE_BLK_DESC_LENGTH) {
		/*
		 * We did not get back the expected block descriptor
		 * length so we cannot determine if the device supports
		 * CDDA. However, we still indicate the device is MMC
		 * according to the successful response to the page
		 * 0x2A mode sense request.
		 */
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sd_set_mmc_caps: Mode Sense returned "
		    "invalid block descriptor length\n");
		kmem_free(buf, BUFLEN_MODE_CDROM_CAP);
		return;
	}

	/* See if read CDDA is supported */
	sense_page = (uchar_t *)(buf + MODE_HEADER_LENGTH_GRP2 +
	    bd_len);
	un->un_f_cfg_cdda = (sense_page[5] & 0x01) ? TRUE : FALSE;

	/* See if writing DVD RAM is supported. */
	un->un_f_dvdram_writable_device = (sense_page[3] & 0x20) ? TRUE : FALSE;
	if (un->un_f_dvdram_writable_device == TRUE) {
		kmem_free(buf, BUFLEN_MODE_CDROM_CAP);
		return;
	}

	/*
	 * If the device presents DVD or CD capabilities in the mode
	 * page, we can return here since a RRD will not have
	 * these capabilities.
	 */
	if ((sense_page[2] & 0x3f) || (sense_page[3] & 0x3f)) {
		kmem_free(buf, BUFLEN_MODE_CDROM_CAP);
		return;
	}
	kmem_free(buf, BUFLEN_MODE_CDROM_CAP);

	/*
	 * If un->un_f_dvdram_writable_device is still FALSE,
	 * check for a Removable Rigid Disk (RRD).  A RRD
	 * device is identified by the features RANDOM_WRITABLE and
	 * HARDWARE_DEFECT_MANAGEMENT.
	 */
	out_data_rw = kmem_zalloc(SD_CURRENT_FEATURE_LEN, KM_SLEEP);
	rqbuf_rw = kmem_zalloc(SENSE_LENGTH, KM_SLEEP);

	rtn = sd_send_scsi_feature_GET_CONFIGURATION(ssc, &com, rqbuf_rw,
	    SENSE_LENGTH, out_data_rw, SD_CURRENT_FEATURE_LEN,
	    RANDOM_WRITABLE, SD_PATH_STANDARD);

	sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	if (rtn != 0) {
		kmem_free(out_data_rw, SD_CURRENT_FEATURE_LEN);
		kmem_free(rqbuf_rw, SENSE_LENGTH);
		return;
	}

	out_data_hd = kmem_zalloc(SD_CURRENT_FEATURE_LEN, KM_SLEEP);
	rqbuf_hd = kmem_zalloc(SENSE_LENGTH, KM_SLEEP);

	rtn = sd_send_scsi_feature_GET_CONFIGURATION(ssc, &com, rqbuf_hd,
	    SENSE_LENGTH, out_data_hd, SD_CURRENT_FEATURE_LEN,
	    HARDWARE_DEFECT_MANAGEMENT, SD_PATH_STANDARD);

	sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	if (rtn == 0) {
		/*
		 * We have good information, check for random writable
		 * and hardware defect features.
		 */
		if ((out_data_rw[9] & RANDOM_WRITABLE) &&
		    (out_data_hd[9] & HARDWARE_DEFECT_MANAGEMENT)) {
			un->un_f_dvdram_writable_device = TRUE;
		}
	}

	kmem_free(out_data_rw, SD_CURRENT_FEATURE_LEN);
	kmem_free(rqbuf_rw, SENSE_LENGTH);
	kmem_free(out_data_hd, SD_CURRENT_FEATURE_LEN);
	kmem_free(rqbuf_hd, SENSE_LENGTH);
}

/*
 *    Function: sd_check_for_writable_cd
 *
 * Description: This routine determines if the media in the device is
 *		writable or not. It uses the get configuration command (0x46)
 *		to determine if the media is writable
 *
 *   Arguments: un - driver soft state (unit) structure
 *              path_flag - SD_PATH_DIRECT to use the USCSI "direct"
 *                           chain and the normal command waitq, or
 *                           SD_PATH_DIRECT_PRIORITY to use the USCSI
 *                           "direct" chain and bypass the normal command
 *                           waitq.
 *
 *     Context: Never called at interrupt context.
 */

static void
sd_check_for_writable_cd(sd_ssc_t *ssc, int path_flag)
{
	struct uscsi_cmd		com;
	uchar_t				*out_data;
	uchar_t				*rqbuf;
	int				rtn;
	uchar_t				*out_data_rw, *out_data_hd;
	uchar_t				*rqbuf_rw, *rqbuf_hd;
	struct mode_header_grp2		*sense_mhp;
	uchar_t				*sense_page;
	caddr_t				buf;
	int				bd_len;
	int				status;
	struct sd_lun			*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	/*
	 * Initialize the writable media to false, if configuration info.
	 * tells us otherwise then only we will set it.
	 */
	un->un_f_mmc_writable_media = FALSE;
	mutex_exit(SD_MUTEX(un));

	out_data = kmem_zalloc(SD_PROFILE_HEADER_LEN, KM_SLEEP);
	rqbuf = kmem_zalloc(SENSE_LENGTH, KM_SLEEP);

	rtn = sd_send_scsi_GET_CONFIGURATION(ssc, &com, rqbuf, SENSE_LENGTH,
	    out_data, SD_PROFILE_HEADER_LEN, path_flag);

	if (rtn != 0)
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	mutex_enter(SD_MUTEX(un));
	if (rtn == 0) {
		/*
		 * We have good information, check for writable DVD.
		 */
		if ((out_data[6] == 0) && (out_data[7] == 0x12)) {
			un->un_f_mmc_writable_media = TRUE;
			kmem_free(out_data, SD_PROFILE_HEADER_LEN);
			kmem_free(rqbuf, SENSE_LENGTH);
			return;
		}
	}

	kmem_free(out_data, SD_PROFILE_HEADER_LEN);
	kmem_free(rqbuf, SENSE_LENGTH);

	/*
	 * Determine if this is a RRD type device.
	 */
	mutex_exit(SD_MUTEX(un));
	buf = kmem_zalloc(BUFLEN_MODE_CDROM_CAP, KM_SLEEP);
	status = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP1, (uchar_t *)buf,
	    BUFLEN_MODE_CDROM_CAP, MODEPAGE_CDROM_CAP, path_flag);

	sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	mutex_enter(SD_MUTEX(un));
	if (status != 0) {
		/* command failed; just return */
		kmem_free(buf, BUFLEN_MODE_CDROM_CAP);
		return;
	}

	/* Get to the page data */
	sense_mhp = (struct mode_header_grp2 *)buf;
	bd_len = (sense_mhp->bdesc_length_hi << 8) | sense_mhp->bdesc_length_lo;
	if (bd_len > MODE_BLK_DESC_LENGTH) {
		/*
		 * We did not get back the expected block descriptor length so
		 * we cannot check the mode page.
		 */
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sd_check_for_writable_cd: Mode Sense returned "
		    "invalid block descriptor length\n");
		kmem_free(buf, BUFLEN_MODE_CDROM_CAP);
		return;
	}

	/*
	 * If the device presents DVD or CD capabilities in the mode
	 * page, we can return here since a RRD device will not have
	 * these capabilities.
	 */
	sense_page = (uchar_t *)(buf + MODE_HEADER_LENGTH_GRP2 + bd_len);
	if ((sense_page[2] & 0x3f) || (sense_page[3] & 0x3f)) {
		kmem_free(buf, BUFLEN_MODE_CDROM_CAP);
		return;
	}
	kmem_free(buf, BUFLEN_MODE_CDROM_CAP);

	/*
	 * If un->un_f_mmc_writable_media is still FALSE,
	 * check for RRD type media.  A RRD device is identified
	 * by the features RANDOM_WRITABLE and HARDWARE_DEFECT_MANAGEMENT.
	 */
	mutex_exit(SD_MUTEX(un));
	out_data_rw = kmem_zalloc(SD_CURRENT_FEATURE_LEN, KM_SLEEP);
	rqbuf_rw = kmem_zalloc(SENSE_LENGTH, KM_SLEEP);

	rtn = sd_send_scsi_feature_GET_CONFIGURATION(ssc, &com, rqbuf_rw,
	    SENSE_LENGTH, out_data_rw, SD_CURRENT_FEATURE_LEN,
	    RANDOM_WRITABLE, path_flag);

	sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	if (rtn != 0) {
		kmem_free(out_data_rw, SD_CURRENT_FEATURE_LEN);
		kmem_free(rqbuf_rw, SENSE_LENGTH);
		mutex_enter(SD_MUTEX(un));
		return;
	}

	out_data_hd = kmem_zalloc(SD_CURRENT_FEATURE_LEN, KM_SLEEP);
	rqbuf_hd = kmem_zalloc(SENSE_LENGTH, KM_SLEEP);

	rtn = sd_send_scsi_feature_GET_CONFIGURATION(ssc, &com, rqbuf_hd,
	    SENSE_LENGTH, out_data_hd, SD_CURRENT_FEATURE_LEN,
	    HARDWARE_DEFECT_MANAGEMENT, path_flag);

	sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	mutex_enter(SD_MUTEX(un));
	if (rtn == 0) {
		/*
		 * We have good information, check for random writable
		 * and hardware defect features as current.
		 */
		if ((out_data_rw[9] & RANDOM_WRITABLE) &&
		    (out_data_rw[10] & 0x1) &&
		    (out_data_hd[9] & HARDWARE_DEFECT_MANAGEMENT) &&
		    (out_data_hd[10] & 0x1)) {
			un->un_f_mmc_writable_media = TRUE;
		}
	}

	kmem_free(out_data_rw, SD_CURRENT_FEATURE_LEN);
	kmem_free(rqbuf_rw, SENSE_LENGTH);
	kmem_free(out_data_hd, SD_CURRENT_FEATURE_LEN);
	kmem_free(rqbuf_hd, SENSE_LENGTH);
}

/*
 *    Function: sd_read_unit_properties
 *
 * Description: The following implements a property lookup mechanism.
 *		Properties for particular disks (keyed on vendor, model
 *		and rev numbers) are sought in the sd.conf file via
 *		sd_process_sdconf_file(), and if not found there, are
 *		looked for in a list hardcoded in this driver via
 *		sd_process_sdconf_table() Once located the properties
 *		are used to update the driver unit structure.
 *
 *   Arguments: un - driver soft state (unit) structure
 */

static void
sd_read_unit_properties(struct sd_lun *un)
{
	/*
	 * sd_process_sdconf_file returns SD_FAILURE if it cannot find
	 * the "sd-config-list" property (from the sd.conf file) or if
	 * there was not a match for the inquiry vid/pid. If this event
	 * occurs the static driver configuration table is searched for
	 * a match.
	 */
	ASSERT(un != NULL);
	if (sd_process_sdconf_file(un) == SD_FAILURE) {
		sd_process_sdconf_table(un);
	}

	/* check for LSI device */
	sd_is_lsi(un);


}


/*
 *    Function: sd_process_sdconf_file
 *
 * Description: Use ddi_prop_lookup(9F) to obtain the properties from the
 *		driver's config file (ie, sd.conf) and update the driver
 *		soft state structure accordingly.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: SD_SUCCESS - The properties were successfully set according
 *			     to the driver configuration file.
 *		SD_FAILURE - The driver config list was not obtained or
 *			     there was no vid/pid match. This indicates that
 *			     the static config table should be used.
 *
 * The config file has a property, "sd-config-list". Currently we support
 * two kinds of formats. For both formats, the value of this property
 * is a list of duplets:
 *
 *  sd-config-list=
 *	<duplet>,
 *	[,<duplet>]*;
 *
 * For the improved format, where
 *
 *     <duplet>:= "<vid+pid>","<tunable-list>"
 *
 * and
 *
 *     <tunable-list>:=   <tunable> [, <tunable> ]*;
 *     <tunable> =        <name> : <value>
 *
 * The <vid+pid> is the string that is returned by the target device on a
 * SCSI inquiry command, the <tunable-list> contains one or more tunables
 * to apply to all target devices with the specified <vid+pid>.
 *
 * Each <tunable> is a "<name> : <value>" pair.
 *
 * For the old format, the structure of each duplet is as follows:
 *
 *  <duplet>:= "<vid+pid>","<data-property-name_list>"
 *
 * The first entry of the duplet is the device ID string (the concatenated
 * vid & pid; not to be confused with a device_id).  This is defined in
 * the same way as in the sd_disk_table.
 *
 * The second part of the duplet is a string that identifies a
 * data-property-name-list. The data-property-name-list is defined as
 * follows:
 *
 *  <data-property-name-list>:=<data-property-name> [<data-property-name>]
 *
 * The syntax of <data-property-name> depends on the <version> field.
 *
 * If version = SD_CONF_VERSION_1 we have the following syntax:
 *
 * 	<data-property-name>:=<version>,<flags>,<prop0>,<prop1>,.....<propN>
 *
 * where the prop0 value will be used to set prop0 if bit0 set in the
 * flags, prop1 if bit1 set, etc. and N = SD_CONF_MAX_ITEMS -1
 *
 */

static int
sd_process_sdconf_file(struct sd_lun *un)
{
	char	**config_list = NULL;
	uint_t	nelements;
	char	*vidptr;
	int	vidlen;
	char	*dnlist_ptr;
	char	*dataname_ptr;
	char	*dataname_lasts;
	int	*data_list = NULL;
	uint_t	data_list_len;
	int	rval = SD_FAILURE;
	int	i;

	ASSERT(un != NULL);

	/* Obtain the configuration list associated with the .conf file */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, SD_DEVINFO(un),
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, sd_config_list,
	    &config_list, &nelements) != DDI_PROP_SUCCESS) {
		return (SD_FAILURE);
	}

	/*
	 * Compare vids in each duplet to the inquiry vid - if a match is
	 * made, get the data value and update the soft state structure
	 * accordingly.
	 *
	 * Each duplet should show as a pair of strings, return SD_FAILURE
	 * otherwise.
	 */
	if (nelements & 1) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sd-config-list should show as pairs of strings.\n");
		if (config_list)
			ddi_prop_free(config_list);
		return (SD_FAILURE);
	}

	for (i = 0; i < nelements; i += 2) {
		/*
		 * Note: The assumption here is that each vid entry is on
		 * a unique line from its associated duplet.
		 */
		vidptr = config_list[i];
		vidlen = (int)strlen(vidptr);
		if (sd_sdconf_id_match(un, vidptr, vidlen) != SD_SUCCESS) {
			continue;
		}

		/*
		 * dnlist contains 1 or more blank separated
		 * data-property-name entries
		 */
		dnlist_ptr = config_list[i + 1];

		if (strchr(dnlist_ptr, ':') != NULL) {
			/*
			 * Decode the improved format sd-config-list.
			 */
			sd_nvpair_str_decode(un, dnlist_ptr);
		} else {
			/*
			 * The old format sd-config-list, loop through all
			 * data-property-name entries in the
			 * data-property-name-list
			 * setting the properties for each.
			 */
			for (dataname_ptr = sd_strtok_r(dnlist_ptr, " \t",
			    &dataname_lasts); dataname_ptr != NULL;
			    dataname_ptr = sd_strtok_r(NULL, " \t",
			    &dataname_lasts)) {
				int version;

				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_process_sdconf_file: disk:%s, "
				    "data:%s\n", vidptr, dataname_ptr);

				/* Get the data list */
				if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
				    SD_DEVINFO(un), 0, dataname_ptr, &data_list,
				    &data_list_len) != DDI_PROP_SUCCESS) {
					SD_INFO(SD_LOG_ATTACH_DETACH, un,
					    "sd_process_sdconf_file: data "
					    "property (%s) has no value\n",
					    dataname_ptr);
					continue;
				}

				version = data_list[0];

				if (version == SD_CONF_VERSION_1) {
					sd_tunables values;

					/* Set the properties */
					if (sd_chk_vers1_data(un, data_list[1],
					    &data_list[2], data_list_len,
					    dataname_ptr) == SD_SUCCESS) {
						sd_get_tunables_from_conf(un,
						    data_list[1], &data_list[2],
						    &values);
						sd_set_vers1_properties(un,
						    data_list[1], &values);
						rval = SD_SUCCESS;
					} else {
						rval = SD_FAILURE;
					}
				} else {
					scsi_log(SD_DEVINFO(un), sd_label,
					    CE_WARN, "data property %s version "
					    "0x%x is invalid.",
					    dataname_ptr, version);
					rval = SD_FAILURE;
				}
				if (data_list)
					ddi_prop_free(data_list);
			}
		}
	}

	/* free up the memory allocated by ddi_prop_lookup_string_array(). */
	if (config_list) {
		ddi_prop_free(config_list);
	}

	return (rval);
}

/*
 *    Function: sd_nvpair_str_decode()
 *
 * Description: Parse the improved format sd-config-list to get
 *    each entry of tunable, which includes a name-value pair.
 *    Then call sd_set_properties() to set the property.
 *
 *   Arguments: un - driver soft state (unit) structure
 *    nvpair_str - the tunable list
 */
static void
sd_nvpair_str_decode(struct sd_lun *un, char *nvpair_str)
{
	char	*nv, *name, *value, *token;
	char	*nv_lasts, *v_lasts, *x_lasts;

	for (nv = sd_strtok_r(nvpair_str, ",", &nv_lasts); nv != NULL;
	    nv = sd_strtok_r(NULL, ",", &nv_lasts)) {
		token = sd_strtok_r(nv, ":", &v_lasts);
		name  = sd_strtok_r(token, " \t", &x_lasts);
		token = sd_strtok_r(NULL, ":", &v_lasts);
		value = sd_strtok_r(token, " \t", &x_lasts);
		if (name == NULL || value == NULL) {
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_nvpair_str_decode: "
			    "name or value is not valid!\n");
		} else {
			sd_set_properties(un, name, value);
		}
	}
}

/*
 *    Function: sd_strtok_r()
 *
 * Description: This function uses strpbrk and strspn to break
 *    string into tokens on sequentially subsequent calls. Return
 *    NULL when no non-separator characters remain. The first
 *    argument is NULL for subsequent calls.
 */
static char *
sd_strtok_r(char *string, const char *sepset, char **lasts)
{
	char	*q, *r;

	/* First or subsequent call */
	if (string == NULL)
		string = *lasts;

	if (string == NULL)
		return (NULL);

	/* Skip leading separators */
	q = string + strspn(string, sepset);

	if (*q == '\0')
		return (NULL);

	if ((r = strpbrk(q, sepset)) == NULL)
		*lasts = NULL;
	else {
		*r = '\0';
		*lasts = r + 1;
	}
	return (q);
}

/*
 *    Function: sd_set_properties()
 *
 * Description: Set device properties based on the improved
 *    format sd-config-list.
 *
 *   Arguments: un - driver soft state (unit) structure
 *    name  - supported tunable name
 *    value - tunable value
 */
static void
sd_set_properties(struct sd_lun *un, char *name, char *value)
{
	char	*endptr = NULL;
	long	val = 0;

	if (strcasecmp(name, "cache-nonvolatile") == 0) {
		if (strcasecmp(value, "true") == 0) {
			un->un_f_suppress_cache_flush = TRUE;
		} else if (strcasecmp(value, "false") == 0) {
			un->un_f_suppress_cache_flush = FALSE;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "suppress_cache_flush flag set to %d\n",
		    un->un_f_suppress_cache_flush);
		return;
	}

	if (strcasecmp(name, "controller-type") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_ctype = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "ctype set to %d\n", un->un_ctype);
		return;
	}

	if (strcasecmp(name, "delay-busy") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_busy_timeout = drv_usectohz(val / 1000);
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "busy_timeout set to %d\n", un->un_busy_timeout);
		return;
	}

	if (strcasecmp(name, "disksort") == 0) {
		if (strcasecmp(value, "true") == 0) {
			un->un_f_disksort_disabled = FALSE;
		} else if (strcasecmp(value, "false") == 0) {
			un->un_f_disksort_disabled = TRUE;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "disksort disabled flag set to %d\n",
		    un->un_f_disksort_disabled);
		return;
	}

	if (strcasecmp(name, "power-condition") == 0) {
		if (strcasecmp(value, "true") == 0) {
			un->un_f_power_condition_disabled = FALSE;
		} else if (strcasecmp(value, "false") == 0) {
			un->un_f_power_condition_disabled = TRUE;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "power condition disabled flag set to %d\n",
		    un->un_f_power_condition_disabled);
		return;
	}

	if (strcasecmp(name, "timeout-releasereservation") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_reserve_release_time = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "reservation release timeout set to %d\n",
		    un->un_reserve_release_time);
		return;
	}

	if (strcasecmp(name, "reset-lun") == 0) {
		if (strcasecmp(value, "true") == 0) {
			un->un_f_lun_reset_enabled = TRUE;
		} else if (strcasecmp(value, "false") == 0) {
			un->un_f_lun_reset_enabled = FALSE;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "lun reset enabled flag set to %d\n",
		    un->un_f_lun_reset_enabled);
		return;
	}

	if (strcasecmp(name, "retries-busy") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_busy_retry_count = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "busy retry count set to %d\n", un->un_busy_retry_count);
		return;
	}

	if (strcasecmp(name, "retries-timeout") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_retry_count = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "timeout retry count set to %d\n", un->un_retry_count);
		return;
	}

	if (strcasecmp(name, "retries-notready") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_notready_retry_count = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "notready retry count set to %d\n",
		    un->un_notready_retry_count);
		return;
	}

	if (strcasecmp(name, "retries-reset") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_reset_retry_count = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "reset retry count set to %d\n",
		    un->un_reset_retry_count);
		return;
	}

	if (strcasecmp(name, "throttle-max") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_saved_throttle = un->un_throttle = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "throttle set to %d\n", un->un_throttle);
	}

	if (strcasecmp(name, "throttle-min") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_min_throttle = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "min throttle set to %d\n", un->un_min_throttle);
	}

	if (strcasecmp(name, "rmw-type") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_f_rmw_type = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "RMW type set to %d\n", un->un_f_rmw_type);
	}

	if (strcasecmp(name, "physical-block-size") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0 &&
		    ISP2(val) && val >= un->un_tgt_blocksize &&
		    val >= un->un_sys_blocksize) {
			un->un_phy_blocksize = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "physical block size set to %d\n", un->un_phy_blocksize);
	}

	if (strcasecmp(name, "retries-victim") == 0) {
		if (ddi_strtol(value, &endptr, 0, &val) == 0) {
			un->un_victim_retry_count = val;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "victim retry count set to %d\n",
		    un->un_victim_retry_count);
		return;
	}

	/*
	 * Validate the throttle values.
	 * If any of the numbers are invalid, set everything to defaults.
	 */
	if ((un->un_throttle < SD_LOWEST_VALID_THROTTLE) ||
	    (un->un_min_throttle < SD_LOWEST_VALID_THROTTLE) ||
	    (un->un_min_throttle > un->un_throttle)) {
		un->un_saved_throttle = un->un_throttle = sd_max_throttle;
		un->un_min_throttle = sd_min_throttle;
	}

	if (strcasecmp(name, "mmc-gesn-polling") == 0) {
		if (strcasecmp(value, "true") == 0) {
			un->un_f_mmc_gesn_polling = TRUE;
		} else if (strcasecmp(value, "false") == 0) {
			un->un_f_mmc_gesn_polling = FALSE;
		} else {
			goto value_invalid;
		}
		SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
		    "mmc-gesn-polling set to %d\n",
		    un->un_f_mmc_gesn_polling);
	}

	return;

value_invalid:
	SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_set_properties: "
	    "value of prop %s is invalid\n", name);
}

/*
 *    Function: sd_get_tunables_from_conf()
 *
 *
 *    This function reads the data list from the sd.conf file and pulls
 *    the values that can have numeric values as arguments and places
 *    the values in the appropriate sd_tunables member.
 *    Since the order of the data list members varies across platforms
 *    This function reads them from the data list in a platform specific
 *    order and places them into the correct sd_tunable member that is
 *    consistent across all platforms.
 */
static void
sd_get_tunables_from_conf(struct sd_lun *un, int flags, int *data_list,
    sd_tunables *values)
{
	int i;
	int mask;

	bzero(values, sizeof (sd_tunables));

	for (i = 0; i < SD_CONF_MAX_ITEMS; i++) {

		mask = 1 << i;
		if (mask > flags) {
			break;
		}

		switch (mask & flags) {
		case 0:	/* This mask bit not set in flags */
			continue;
		case SD_CONF_BSET_THROTTLE:
			values->sdt_throttle = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: throttle = %d\n",
			    values->sdt_throttle);
			break;
		case SD_CONF_BSET_CTYPE:
			values->sdt_ctype = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: ctype = %d\n",
			    values->sdt_ctype);
			break;
		case SD_CONF_BSET_NRR_COUNT:
			values->sdt_not_rdy_retries = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: not_rdy_retries = %d\n",
			    values->sdt_not_rdy_retries);
			break;
		case SD_CONF_BSET_BSY_RETRY_COUNT:
			values->sdt_busy_retries = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: busy_retries = %d\n",
			    values->sdt_busy_retries);
			break;
		case SD_CONF_BSET_RST_RETRIES:
			values->sdt_reset_retries = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: reset_retries = %d\n",
			    values->sdt_reset_retries);
			break;
		case SD_CONF_BSET_RSV_REL_TIME:
			values->sdt_reserv_rel_time = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: reserv_rel_time = %d\n",
			    values->sdt_reserv_rel_time);
			break;
		case SD_CONF_BSET_MIN_THROTTLE:
			values->sdt_min_throttle = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: min_throttle = %d\n",
			    values->sdt_min_throttle);
			break;
		case SD_CONF_BSET_DISKSORT_DISABLED:
			values->sdt_disk_sort_dis = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: disk_sort_dis = %d\n",
			    values->sdt_disk_sort_dis);
			break;
		case SD_CONF_BSET_LUN_RESET_ENABLED:
			values->sdt_lun_reset_enable = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: lun_reset_enable = %d"
			    "\n", values->sdt_lun_reset_enable);
			break;
		case SD_CONF_BSET_CACHE_IS_NV:
			values->sdt_suppress_cache_flush = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: \
			    suppress_cache_flush = %d"
			    "\n", values->sdt_suppress_cache_flush);
			break;
		case SD_CONF_BSET_PC_DISABLED:
			values->sdt_disk_sort_dis = data_list[i];
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_get_tunables_from_conf: power_condition_dis = "
			    "%d\n", values->sdt_power_condition_dis);
			break;
		}
	}
}

/*
 *    Function: sd_process_sdconf_table
 *
 * Description: Search the static configuration table for a match on the
 *		inquiry vid/pid and update the driver soft state structure
 *		according to the table property values for the device.
 *
 *		The form of a configuration table entry is:
 *		  <vid+pid>,<flags>,<property-data>
 *		  "SEAGATE ST42400N",1,0x40000,
 *		  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1;
 *
 *   Arguments: un - driver soft state (unit) structure
 */

static void
sd_process_sdconf_table(struct sd_lun *un)
{
	char	*id = NULL;
	int	table_index;
	int	idlen;

	ASSERT(un != NULL);
	for (table_index = 0; table_index < sd_disk_table_size;
	    table_index++) {
		id = sd_disk_table[table_index].device_id;
		idlen = strlen(id);

		/*
		 * The static configuration table currently does not
		 * implement version 10 properties. Additionally,
		 * multiple data-property-name entries are not
		 * implemented in the static configuration table.
		 */
		if (sd_sdconf_id_match(un, id, idlen) == SD_SUCCESS) {
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_process_sdconf_table: disk %s\n", id);
			sd_set_vers1_properties(un,
			    sd_disk_table[table_index].flags,
			    sd_disk_table[table_index].properties);
			break;
		}
	}
}


/*
 *    Function: sd_sdconf_id_match
 *
 * Description: This local function implements a case sensitive vid/pid
 *		comparison as well as the boundary cases of wild card and
 *		multiple blanks.
 *
 *		Note: An implicit assumption made here is that the scsi
 *		inquiry structure will always keep the vid, pid and
 *		revision strings in consecutive sequence, so they can be
 *		read as a single string. If this assumption is not the
 *		case, a separate string, to be used for the check, needs
 *		to be built with these strings concatenated.
 *
 *   Arguments: un - driver soft state (unit) structure
 *		id - table or config file vid/pid
 *		idlen  - length of the vid/pid (bytes)
 *
 * Return Code: SD_SUCCESS - Indicates a match with the inquiry vid/pid
 *		SD_FAILURE - Indicates no match with the inquiry vid/pid
 */

static int
sd_sdconf_id_match(struct sd_lun *un, char *id, int idlen)
{
	struct scsi_inquiry	*sd_inq;
	int 			rval = SD_SUCCESS;

	ASSERT(un != NULL);
	sd_inq = un->un_sd->sd_inq;
	ASSERT(id != NULL);

	/*
	 * We use the inq_vid as a pointer to a buffer containing the
	 * vid and pid and use the entire vid/pid length of the table
	 * entry for the comparison. This works because the inq_pid
	 * data member follows inq_vid in the scsi_inquiry structure.
	 */
	if (strncasecmp(sd_inq->inq_vid, id, idlen) != 0) {
		/*
		 * The user id string is compared to the inquiry vid/pid
		 * using a case insensitive comparison and ignoring
		 * multiple spaces.
		 */
		rval = sd_blank_cmp(un, id, idlen);
		if (rval != SD_SUCCESS) {
			/*
			 * User id strings that start and end with a "*"
			 * are a special case. These do not have a
			 * specific vendor, and the product string can
			 * appear anywhere in the 16 byte PID portion of
			 * the inquiry data. This is a simple strstr()
			 * type search for the user id in the inquiry data.
			 */
			if ((id[0] == '*') && (id[idlen - 1] == '*')) {
				char	*pidptr = &id[1];
				int	i;
				int	j;
				int	pidstrlen = idlen - 2;
				j = sizeof (SD_INQUIRY(un)->inq_pid) -
				    pidstrlen;

				if (j < 0) {
					return (SD_FAILURE);
				}
				for (i = 0; i < j; i++) {
					if (bcmp(&SD_INQUIRY(un)->inq_pid[i],
					    pidptr, pidstrlen) == 0) {
						rval = SD_SUCCESS;
						break;
					}
				}
			}
		}
	}
	return (rval);
}


/*
 *    Function: sd_blank_cmp
 *
 * Description: If the id string starts and ends with a space, treat
 *		multiple consecutive spaces as equivalent to a single
 *		space. For example, this causes a sd_disk_table entry
 *		of " NEC CDROM " to match a device's id string of
 *		"NEC       CDROM".
 *
 *		Note: The success exit condition for this routine is if
 *		the pointer to the table entry is '\0' and the cnt of
 *		the inquiry length is zero. This will happen if the inquiry
 *		string returned by the device is padded with spaces to be
 *		exactly 24 bytes in length (8 byte vid + 16 byte pid). The
 *		SCSI spec states that the inquiry string is to be padded with
 *		spaces.
 *
 *   Arguments: un - driver soft state (unit) structure
 *		id - table or config file vid/pid
 *		idlen  - length of the vid/pid (bytes)
 *
 * Return Code: SD_SUCCESS - Indicates a match with the inquiry vid/pid
 *		SD_FAILURE - Indicates no match with the inquiry vid/pid
 */

static int
sd_blank_cmp(struct sd_lun *un, char *id, int idlen)
{
	char		*p1;
	char		*p2;
	int		cnt;
	cnt = sizeof (SD_INQUIRY(un)->inq_vid) +
	    sizeof (SD_INQUIRY(un)->inq_pid);

	ASSERT(un != NULL);
	p2 = un->un_sd->sd_inq->inq_vid;
	ASSERT(id != NULL);
	p1 = id;

	if ((id[0] == ' ') && (id[idlen - 1] == ' ')) {
		/*
		 * Note: string p1 is terminated by a NUL but string p2
		 * isn't.  The end of p2 is determined by cnt.
		 */
		for (;;) {
			/* skip over any extra blanks in both strings */
			while ((*p1 != '\0') && (*p1 == ' ')) {
				p1++;
			}
			while ((cnt != 0) && (*p2 == ' ')) {
				p2++;
				cnt--;
			}

			/* compare the two strings */
			if ((cnt == 0) ||
			    (SD_TOUPPER(*p1) != SD_TOUPPER(*p2))) {
				break;
			}
			while ((cnt > 0) &&
			    (SD_TOUPPER(*p1) == SD_TOUPPER(*p2))) {
				p1++;
				p2++;
				cnt--;
			}
		}
	}

	/* return SD_SUCCESS if both strings match */
	return (((*p1 == '\0') && (cnt == 0)) ? SD_SUCCESS : SD_FAILURE);
}


/*
 *    Function: sd_chk_vers1_data
 *
 * Description: Verify the version 1 device properties provided by the
 *		user via the configuration file
 *
 *   Arguments: un	     - driver soft state (unit) structure
 *		flags	     - integer mask indicating properties to be set
 *		prop_list    - integer list of property values
 *		list_len     - number of the elements
 *
 * Return Code: SD_SUCCESS - Indicates the user provided data is valid
 *		SD_FAILURE - Indicates the user provided data is invalid
 */

static int
sd_chk_vers1_data(struct sd_lun *un, int flags, int *prop_list,
    int list_len, char *dataname_ptr)
{
	int i;
	int mask = 1;
	int index = 0;

	ASSERT(un != NULL);

	/* Check for a NULL property name and list */
	if (dataname_ptr == NULL) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sd_chk_vers1_data: NULL data property name.");
		return (SD_FAILURE);
	}
	if (prop_list == NULL) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sd_chk_vers1_data: %s NULL data property list.",
		    dataname_ptr);
		return (SD_FAILURE);
	}

	/* Display a warning if undefined bits are set in the flags */
	if (flags & ~SD_CONF_BIT_MASK) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sd_chk_vers1_data: invalid bits 0x%x in data list %s. "
		    "Properties not set.",
		    (flags & ~SD_CONF_BIT_MASK), dataname_ptr);
		return (SD_FAILURE);
	}

	/*
	 * Verify the length of the list by identifying the highest bit set
	 * in the flags and validating that the property list has a length
	 * up to the index of this bit.
	 */
	for (i = 0; i < SD_CONF_MAX_ITEMS; i++) {
		if (flags & mask) {
			index++;
		}
		mask = 1 << i;
	}
	if (list_len < (index + 2)) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sd_chk_vers1_data: "
		    "Data property list %s size is incorrect. "
		    "Properties not set.", dataname_ptr);
		scsi_log(SD_DEVINFO(un), sd_label, CE_CONT, "Size expected: "
		    "version + 1 flagword + %d properties", SD_CONF_MAX_ITEMS);
		return (SD_FAILURE);
	}
	return (SD_SUCCESS);
}


/*
 *    Function: sd_set_vers1_properties
 *
 * Description: Set version 1 device properties based on a property list
 *		retrieved from the driver configuration file or static
 *		configuration table. Version 1 properties have the format:
 *
 * 	<data-property-name>:=<version>,<flags>,<prop0>,<prop1>,.....<propN>
 *
 *		where the prop0 value will be used to set prop0 if bit0
 *		is set in the flags
 *
 *   Arguments: un	     - driver soft state (unit) structure
 *		flags	     - integer mask indicating properties to be set
 *		prop_list    - integer list of property values
 */

static void
sd_set_vers1_properties(struct sd_lun *un, int flags, sd_tunables *prop_list)
{
	ASSERT(un != NULL);

	/*
	 * Set the flag to indicate cache is to be disabled. An attempt
	 * to disable the cache via sd_cache_control() will be made
	 * later during attach once the basic initialization is complete.
	 */
	if (flags & SD_CONF_BSET_NOCACHE) {
		un->un_f_opt_disable_cache = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: caching disabled flag set\n");
	}

	/* CD-specific configuration parameters */
	if (flags & SD_CONF_BSET_PLAYMSF_BCD) {
		un->un_f_cfg_playmsf_bcd = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: playmsf_bcd set\n");
	}
	if (flags & SD_CONF_BSET_READSUB_BCD) {
		un->un_f_cfg_readsub_bcd = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: readsub_bcd set\n");
	}
	if (flags & SD_CONF_BSET_READ_TOC_TRK_BCD) {
		un->un_f_cfg_read_toc_trk_bcd = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: read_toc_trk_bcd set\n");
	}
	if (flags & SD_CONF_BSET_READ_TOC_ADDR_BCD) {
		un->un_f_cfg_read_toc_addr_bcd = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: read_toc_addr_bcd set\n");
	}
	if (flags & SD_CONF_BSET_NO_READ_HEADER) {
		un->un_f_cfg_no_read_header = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: no_read_header set\n");
	}
	if (flags & SD_CONF_BSET_READ_CD_XD4) {
		un->un_f_cfg_read_cd_xd4 = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: read_cd_xd4 set\n");
	}

	/* Support for devices which do not have valid/unique serial numbers */
	if (flags & SD_CONF_BSET_FAB_DEVID) {
		un->un_f_opt_fab_devid = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: fab_devid bit set\n");
	}

	/* Support for user throttle configuration */
	if (flags & SD_CONF_BSET_THROTTLE) {
		ASSERT(prop_list != NULL);
		un->un_saved_throttle = un->un_throttle =
		    prop_list->sdt_throttle;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: throttle set to %d\n",
		    prop_list->sdt_throttle);
	}

	/* Set the per disk retry count according to the conf file or table. */
	if (flags & SD_CONF_BSET_NRR_COUNT) {
		ASSERT(prop_list != NULL);
		if (prop_list->sdt_not_rdy_retries) {
			un->un_notready_retry_count =
			    prop_list->sdt_not_rdy_retries;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_set_vers1_properties: not ready retry count"
			    " set to %d\n", un->un_notready_retry_count);
		}
	}

	/* The controller type is reported for generic disk driver ioctls */
	if (flags & SD_CONF_BSET_CTYPE) {
		ASSERT(prop_list != NULL);
		switch (prop_list->sdt_ctype) {
		case CTYPE_CDROM:
			un->un_ctype = prop_list->sdt_ctype;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_set_vers1_properties: ctype set to "
			    "CTYPE_CDROM\n");
			break;
		case CTYPE_CCS:
			un->un_ctype = prop_list->sdt_ctype;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_set_vers1_properties: ctype set to "
			    "CTYPE_CCS\n");
			break;
		case CTYPE_ROD:		/* RW optical */
			un->un_ctype = prop_list->sdt_ctype;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_set_vers1_properties: ctype set to "
			    "CTYPE_ROD\n");
			break;
		default:
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sd_set_vers1_properties: Could not set "
			    "invalid ctype value (%d)",
			    prop_list->sdt_ctype);
		}
	}

	/* Purple failover timeout */
	if (flags & SD_CONF_BSET_BSY_RETRY_COUNT) {
		ASSERT(prop_list != NULL);
		un->un_busy_retry_count =
		    prop_list->sdt_busy_retries;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: "
		    "busy retry count set to %d\n",
		    un->un_busy_retry_count);
	}

	/* Purple reset retry count */
	if (flags & SD_CONF_BSET_RST_RETRIES) {
		ASSERT(prop_list != NULL);
		un->un_reset_retry_count =
		    prop_list->sdt_reset_retries;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: "
		    "reset retry count set to %d\n",
		    un->un_reset_retry_count);
	}

	/* Purple reservation release timeout */
	if (flags & SD_CONF_BSET_RSV_REL_TIME) {
		ASSERT(prop_list != NULL);
		un->un_reserve_release_time =
		    prop_list->sdt_reserv_rel_time;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: "
		    "reservation release timeout set to %d\n",
		    un->un_reserve_release_time);
	}

	/*
	 * Driver flag telling the driver to verify that no commands are pending
	 * for a device before issuing a Test Unit Ready. This is a workaround
	 * for a firmware bug in some Seagate eliteI drives.
	 */
	if (flags & SD_CONF_BSET_TUR_CHECK) {
		un->un_f_cfg_tur_check = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: tur queue check set\n");
	}

	if (flags & SD_CONF_BSET_MIN_THROTTLE) {
		un->un_min_throttle = prop_list->sdt_min_throttle;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: min throttle set to %d\n",
		    un->un_min_throttle);
	}

	if (flags & SD_CONF_BSET_DISKSORT_DISABLED) {
		un->un_f_disksort_disabled =
		    (prop_list->sdt_disk_sort_dis != 0) ?
		    TRUE : FALSE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: disksort disabled "
		    "flag set to %d\n",
		    prop_list->sdt_disk_sort_dis);
	}

	if (flags & SD_CONF_BSET_LUN_RESET_ENABLED) {
		un->un_f_lun_reset_enabled =
		    (prop_list->sdt_lun_reset_enable != 0) ?
		    TRUE : FALSE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: lun reset enabled "
		    "flag set to %d\n",
		    prop_list->sdt_lun_reset_enable);
	}

	if (flags & SD_CONF_BSET_CACHE_IS_NV) {
		un->un_f_suppress_cache_flush =
		    (prop_list->sdt_suppress_cache_flush != 0) ?
		    TRUE : FALSE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: suppress_cache_flush "
		    "flag set to %d\n",
		    prop_list->sdt_suppress_cache_flush);
	}

	if (flags & SD_CONF_BSET_PC_DISABLED) {
		un->un_f_power_condition_disabled =
		    (prop_list->sdt_power_condition_dis != 0) ?
		    TRUE : FALSE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_set_vers1_properties: power_condition_disabled "
		    "flag set to %d\n",
		    prop_list->sdt_power_condition_dis);
	}

	/*
	 * Validate the throttle values.
	 * If any of the numbers are invalid, set everything to defaults.
	 */
	if ((un->un_throttle < SD_LOWEST_VALID_THROTTLE) ||
	    (un->un_min_throttle < SD_LOWEST_VALID_THROTTLE) ||
	    (un->un_min_throttle > un->un_throttle)) {
		un->un_saved_throttle = un->un_throttle = sd_max_throttle;
		un->un_min_throttle = sd_min_throttle;
	}
}

/*
 *   Function: sd_is_lsi()
 *
 *   Description: Check for lsi devices, step through the static device
 *	table to match vid/pid.
 *
 *   Args: un - ptr to sd_lun
 *
 *   Notes:  When creating new LSI property, need to add the new LSI property
 *		to this function.
 */
static void
sd_is_lsi(struct sd_lun *un)
{
	char	*id = NULL;
	int	table_index;
	int	idlen;
	void	*prop;

	ASSERT(un != NULL);
	for (table_index = 0; table_index < sd_disk_table_size;
	    table_index++) {
		id = sd_disk_table[table_index].device_id;
		idlen = strlen(id);
		if (idlen == 0) {
			continue;
		}

		if (sd_sdconf_id_match(un, id, idlen) == SD_SUCCESS) {
			prop = sd_disk_table[table_index].properties;
			if (prop == &lsi_properties ||
			    prop == &lsi_oem_properties ||
			    prop == &lsi_properties_scsi ||
			    prop == &symbios_properties) {
				un->un_f_cfg_is_lsi = TRUE;
			}
			break;
		}
	}
}

/*
 *    Function: sd_get_physical_geometry
 *
 * Description: Retrieve the MODE SENSE page 3 (Format Device Page) and
 *		MODE SENSE page 4 (Rigid Disk Drive Geometry Page) from the
 *		target, and use this information to initialize the physical
 *		geometry cache specified by pgeom_p.
 *
 *		MODE SENSE is an optional command, so failure in this case
 *		does not necessarily denote an error. We want to use the
 *		MODE SENSE commands to derive the physical geometry of the
 *		device, but if either command fails, the logical geometry is
 *		used as the fallback for disk label geometry in cmlb.
 *
 *		This requires that un->un_blockcount and un->un_tgt_blocksize
 *		have already been initialized for the current target and
 *		that the current values be passed as args so that we don't
 *		end up ever trying to use -1 as a valid value. This could
 *		happen if either value is reset while we're not holding
 *		the mutex.
 *
 *   Arguments: un - driver soft state (unit) structure
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq.
 *
 *     Context: Kernel thread only (can sleep).
 */

static int
sd_get_physical_geometry(struct sd_lun *un, cmlb_geom_t *pgeom_p,
	diskaddr_t capacity, int lbasize, int path_flag)
{
	struct	mode_format	*page3p;
	struct	mode_geometry	*page4p;
	struct	mode_header	*headerp;
	int	sector_size;
	int	nsect;
	int	nhead;
	int	ncyl;
	int	intrlv;
	int	spc;
	diskaddr_t	modesense_capacity;
	int	rpm;
	int	bd_len;
	int	mode_header_length;
	uchar_t	*p3bufp;
	uchar_t	*p4bufp;
	int	cdbsize;
	int 	ret = EIO;
	sd_ssc_t *ssc;
	int	status;

	ASSERT(un != NULL);

	if (lbasize == 0) {
		if (ISCD(un)) {
			lbasize = 2048;
		} else {
			lbasize = un->un_sys_blocksize;
		}
	}
	pgeom_p->g_secsize = (unsigned short)lbasize;

	/*
	 * If the unit is a cd/dvd drive MODE SENSE page three
	 * and MODE SENSE page four are reserved (see SBC spec
	 * and MMC spec). To prevent soft errors just return
	 * using the default LBA size.
	 *
	 * Since SATA MODE SENSE function (sata_txlt_mode_sense()) does not
	 * implement support for mode pages 3 and 4 return here to prevent
	 * illegal requests on SATA drives.
	 *
	 * These pages are also reserved in SBC-2 and later.  We assume SBC-2
	 * or later for a direct-attached block device if the SCSI version is
	 * at least SPC-3.
	 */

	if (ISCD(un) ||
	    un->un_interconnect_type == SD_INTERCONNECT_SATA ||
	    (un->un_ctype == CTYPE_CCS && SD_INQUIRY(un)->inq_ansi >= 5))
		return (ret);

	cdbsize = (un->un_f_cfg_is_atapi == TRUE) ? CDB_GROUP2 : CDB_GROUP0;

	/*
	 * Retrieve MODE SENSE page 3 - Format Device Page
	 */
	p3bufp = kmem_zalloc(SD_MODE_SENSE_PAGE3_LENGTH, KM_SLEEP);
	ssc = sd_ssc_init(un);
	status = sd_send_scsi_MODE_SENSE(ssc, cdbsize, p3bufp,
	    SD_MODE_SENSE_PAGE3_LENGTH, SD_MODE_SENSE_PAGE3_CODE, path_flag);
	if (status != 0) {
		SD_ERROR(SD_LOG_COMMON, un,
		    "sd_get_physical_geometry: mode sense page 3 failed\n");
		goto page3_exit;
	}

	/*
	 * Determine size of Block Descriptors in order to locate the mode
	 * page data.  ATAPI devices return 0, SCSI devices should return
	 * MODE_BLK_DESC_LENGTH.
	 */
	headerp = (struct mode_header *)p3bufp;
	if (un->un_f_cfg_is_atapi == TRUE) {
		struct mode_header_grp2 *mhp =
		    (struct mode_header_grp2 *)headerp;
		mode_header_length = MODE_HEADER_LENGTH_GRP2;
		bd_len = (mhp->bdesc_length_hi << 8) | mhp->bdesc_length_lo;
	} else {
		mode_header_length = MODE_HEADER_LENGTH;
		bd_len = ((struct mode_header *)headerp)->bdesc_length;
	}

	if (bd_len > MODE_BLK_DESC_LENGTH) {
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, SD_LOG_COMMON,
		    "sd_get_physical_geometry: received unexpected bd_len "
		    "of %d, page3\n", bd_len);
		status = EIO;
		goto page3_exit;
	}

	page3p = (struct mode_format *)
	    ((caddr_t)headerp + mode_header_length + bd_len);

	if (page3p->mode_page.code != SD_MODE_SENSE_PAGE3_CODE) {
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, SD_LOG_COMMON,
		    "sd_get_physical_geometry: mode sense pg3 code mismatch "
		    "%d\n", page3p->mode_page.code);
		status = EIO;
		goto page3_exit;
	}

	/*
	 * Use this physical geometry data only if BOTH MODE SENSE commands
	 * complete successfully; otherwise, revert to the logical geometry.
	 * So, we need to save everything in temporary variables.
	 */
	sector_size = BE_16(page3p->data_bytes_sect);

	/*
	 * 1243403: The NEC D38x7 drives do not support MODE SENSE sector size
	 */
	if (sector_size == 0) {
		sector_size = un->un_sys_blocksize;
	} else {
		sector_size &= ~(un->un_sys_blocksize - 1);
	}

	nsect  = BE_16(page3p->sect_track);
	intrlv = BE_16(page3p->interleave);

	SD_INFO(SD_LOG_COMMON, un,
	    "sd_get_physical_geometry: Format Parameters (page 3)\n");
	SD_INFO(SD_LOG_COMMON, un,
	    "   mode page: %d; nsect: %d; sector size: %d;\n",
	    page3p->mode_page.code, nsect, sector_size);
	SD_INFO(SD_LOG_COMMON, un,
	    "   interleave: %d; track skew: %d; cylinder skew: %d;\n", intrlv,
	    BE_16(page3p->track_skew),
	    BE_16(page3p->cylinder_skew));

	sd_ssc_assessment(ssc, SD_FMT_STANDARD);

	/*
	 * Retrieve MODE SENSE page 4 - Rigid Disk Drive Geometry Page
	 */
	p4bufp = kmem_zalloc(SD_MODE_SENSE_PAGE4_LENGTH, KM_SLEEP);
	status = sd_send_scsi_MODE_SENSE(ssc, cdbsize, p4bufp,
	    SD_MODE_SENSE_PAGE4_LENGTH, SD_MODE_SENSE_PAGE4_CODE, path_flag);
	if (status != 0) {
		SD_ERROR(SD_LOG_COMMON, un,
		    "sd_get_physical_geometry: mode sense page 4 failed\n");
		goto page4_exit;
	}

	/*
	 * Determine size of Block Descriptors in order to locate the mode
	 * page data.  ATAPI devices return 0, SCSI devices should return
	 * MODE_BLK_DESC_LENGTH.
	 */
	headerp = (struct mode_header *)p4bufp;
	if (un->un_f_cfg_is_atapi == TRUE) {
		struct mode_header_grp2 *mhp =
		    (struct mode_header_grp2 *)headerp;
		bd_len = (mhp->bdesc_length_hi << 8) | mhp->bdesc_length_lo;
	} else {
		bd_len = ((struct mode_header *)headerp)->bdesc_length;
	}

	if (bd_len > MODE_BLK_DESC_LENGTH) {
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, SD_LOG_COMMON,
		    "sd_get_physical_geometry: received unexpected bd_len of "
		    "%d, page4\n", bd_len);
		status = EIO;
		goto page4_exit;
	}

	page4p = (struct mode_geometry *)
	    ((caddr_t)headerp + mode_header_length + bd_len);

	if (page4p->mode_page.code != SD_MODE_SENSE_PAGE4_CODE) {
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, SD_LOG_COMMON,
		    "sd_get_physical_geometry: mode sense pg4 code mismatch "
		    "%d\n", page4p->mode_page.code);
		status = EIO;
		goto page4_exit;
	}

	/*
	 * Stash the data now, after we know that both commands completed.
	 */


	nhead = (int)page4p->heads;	/* uchar, so no conversion needed */
	spc   = nhead * nsect;
	ncyl  = (page4p->cyl_ub << 16) + (page4p->cyl_mb << 8) + page4p->cyl_lb;
	rpm   = BE_16(page4p->rpm);

	modesense_capacity = spc * ncyl;

	SD_INFO(SD_LOG_COMMON, un,
	    "sd_get_physical_geometry: Geometry Parameters (page 4)\n");
	SD_INFO(SD_LOG_COMMON, un,
	    "   cylinders: %d; heads: %d; rpm: %d;\n", ncyl, nhead, rpm);
	SD_INFO(SD_LOG_COMMON, un,
	    "   computed capacity(h*s*c): %d;\n", modesense_capacity);
	SD_INFO(SD_LOG_COMMON, un, "   pgeom_p: %p; read cap: %d\n",
	    (void *)pgeom_p, capacity);

	/*
	 * Compensate if the drive's geometry is not rectangular, i.e.,
	 * the product of C * H * S returned by MODE SENSE >= that returned
	 * by read capacity. This is an idiosyncrasy of the original x86
	 * disk subsystem.
	 */
	if (modesense_capacity >= capacity) {
		SD_INFO(SD_LOG_COMMON, un,
		    "sd_get_physical_geometry: adjusting acyl; "
		    "old: %d; new: %d\n", pgeom_p->g_acyl,
		    (modesense_capacity - capacity + spc - 1) / spc);
		if (sector_size != 0) {
			/* 1243403: NEC D38x7 drives don't support sec size */
			pgeom_p->g_secsize = (unsigned short)sector_size;
		}
		pgeom_p->g_nsect    = (unsigned short)nsect;
		pgeom_p->g_nhead    = (unsigned short)nhead;
		pgeom_p->g_capacity = capacity;
		pgeom_p->g_acyl	    =
		    (modesense_capacity - pgeom_p->g_capacity + spc - 1) / spc;
		pgeom_p->g_ncyl	    = ncyl - pgeom_p->g_acyl;
	}

	pgeom_p->g_rpm    = (unsigned short)rpm;
	pgeom_p->g_intrlv = (unsigned short)intrlv;
	ret = 0;

	SD_INFO(SD_LOG_COMMON, un,
	    "sd_get_physical_geometry: mode sense geometry:\n");
	SD_INFO(SD_LOG_COMMON, un,
	    "   nsect: %d; sector size: %d; interlv: %d\n",
	    nsect, sector_size, intrlv);
	SD_INFO(SD_LOG_COMMON, un,
	    "   nhead: %d; ncyl: %d; rpm: %d; capacity(ms): %d\n",
	    nhead, ncyl, rpm, modesense_capacity);
	SD_INFO(SD_LOG_COMMON, un,
	    "sd_get_physical_geometry: (cached)\n");
	SD_INFO(SD_LOG_COMMON, un,
	    "   ncyl: %ld; acyl: %d; nhead: %d; nsect: %d\n",
	    pgeom_p->g_ncyl,  pgeom_p->g_acyl,
	    pgeom_p->g_nhead, pgeom_p->g_nsect);
	SD_INFO(SD_LOG_COMMON, un,
	    "   lbasize: %d; capacity: %ld; intrlv: %d; rpm: %d\n",
	    pgeom_p->g_secsize, pgeom_p->g_capacity,
	    pgeom_p->g_intrlv, pgeom_p->g_rpm);
	sd_ssc_assessment(ssc, SD_FMT_STANDARD);

page4_exit:
	kmem_free(p4bufp, SD_MODE_SENSE_PAGE4_LENGTH);

page3_exit:
	kmem_free(p3bufp, SD_MODE_SENSE_PAGE3_LENGTH);

	if (status != 0) {
		if (status == EIO) {
			/*
			 * Some disks do not support mode sense(6), we
			 * should ignore this kind of error(sense key is
			 * 0x5 - illegal request).
			 */
			uint8_t *sensep;
			int senlen;

			sensep = (uint8_t *)ssc->ssc_uscsi_cmd->uscsi_rqbuf;
			senlen = (int)(ssc->ssc_uscsi_cmd->uscsi_rqlen -
			    ssc->ssc_uscsi_cmd->uscsi_rqresid);

			if (senlen > 0 &&
			    scsi_sense_key(sensep) == KEY_ILLEGAL_REQUEST) {
				sd_ssc_assessment(ssc,
				    SD_FMT_IGNORE_COMPROMISE);
			} else {
				sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
			}
		} else {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		}
	}
	sd_ssc_fini(ssc);
	return (ret);
}

/*
 *    Function: sd_get_virtual_geometry
 *
 * Description: Ask the controller to tell us about the target device.
 *
 *   Arguments: un - pointer to softstate
 *		capacity - disk capacity in #blocks
 *		lbasize - disk block size in bytes
 *
 *     Context: Kernel thread only
 */

static int
sd_get_virtual_geometry(struct sd_lun *un, cmlb_geom_t *lgeom_p,
    diskaddr_t capacity, int lbasize)
{
	uint_t	geombuf;
	int	spc;

	ASSERT(un != NULL);

	/* Set sector size, and total number of sectors */
	(void) scsi_ifsetcap(SD_ADDRESS(un), "sector-size",   lbasize,  1);
	(void) scsi_ifsetcap(SD_ADDRESS(un), "total-sectors", capacity, 1);

	/* Let the HBA tell us its geometry */
	geombuf = (uint_t)scsi_ifgetcap(SD_ADDRESS(un), "geometry", 1);

	/* A value of -1 indicates an undefined "geometry" property */
	if (geombuf == (-1)) {
		return (EINVAL);
	}

	/* Initialize the logical geometry cache. */
	lgeom_p->g_nhead   = (geombuf >> 16) & 0xffff;
	lgeom_p->g_nsect   = geombuf & 0xffff;
	lgeom_p->g_secsize = un->un_sys_blocksize;

	spc = lgeom_p->g_nhead * lgeom_p->g_nsect;

	/*
	 * Note: The driver originally converted the capacity value from
	 * target blocks to system blocks. However, the capacity value passed
	 * to this routine is already in terms of system blocks (this scaling
	 * is done when the READ CAPACITY command is issued and processed).
	 * This 'error' may have gone undetected because the usage of g_ncyl
	 * (which is based upon g_capacity) is very limited within the driver
	 */
	lgeom_p->g_capacity = capacity;

	/*
	 * Set ncyl to zero if the hba returned a zero nhead or nsect value. The
	 * hba may return zero values if the device has been removed.
	 */
	if (spc == 0) {
		lgeom_p->g_ncyl = 0;
	} else {
		lgeom_p->g_ncyl = lgeom_p->g_capacity / spc;
	}
	lgeom_p->g_acyl = 0;

	SD_INFO(SD_LOG_COMMON, un, "sd_get_virtual_geometry: (cached)\n");
	return (0);

}
/*
 *    Function: sd_update_block_info
 *
 * Description: Calculate a byte count to sector count bitshift value
 *		from sector size.
 *
 *   Arguments: un: unit struct.
 *		lbasize: new target sector size
 *		capacity: new target capacity, ie. block count
 *
 *     Context: Kernel thread context
 */

static void
sd_update_block_info(struct sd_lun *un, uint32_t lbasize, uint64_t capacity)
{
	if (lbasize != 0) {
		un->un_tgt_blocksize = lbasize;
		un->un_f_tgt_blocksize_is_valid = TRUE;
		if (!un->un_f_has_removable_media) {
			un->un_sys_blocksize = lbasize;
		}
	}

	if (capacity != 0) {
		un->un_blockcount		= capacity;
		un->un_f_blockcount_is_valid	= TRUE;

		/*
		 * The capacity has changed so update the errstats.
		 */
		if (un->un_errstats != NULL) {
			struct sd_errstats *stp;

			capacity *= un->un_sys_blocksize;
			stp = (struct sd_errstats *)un->un_errstats->ks_data;
			if (stp->sd_capacity.value.ui64 < capacity)
				stp->sd_capacity.value.ui64 = capacity;
		}
	}
}


/*
 *    Function: sd_register_devid
 *
 * Description: This routine will obtain the device id information from the
 *		target, obtain the serial number, and register the device
 *		id with the ddi framework.
 *
 *   Arguments: devi - the system's dev_info_t for the device.
 *		un - driver soft state (unit) structure
 *		reservation_flag - indicates if a reservation conflict
 *		occurred during attach
 *
 *     Context: Kernel Thread
 */
static void
sd_register_devid(sd_ssc_t *ssc, dev_info_t *devi, int reservation_flag)
{
	int		rval		= 0;
	uchar_t		*inq80		= NULL;
	size_t		inq80_len	= MAX_INQUIRY_SIZE;
	size_t		inq80_resid	= 0;
	uchar_t		*inq83		= NULL;
	size_t		inq83_len	= MAX_INQUIRY_SIZE;
	size_t		inq83_resid	= 0;
	int		dlen, len;
	char		*sn;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT((SD_DEVINFO(un)) == devi);


	/*
	 * We check the availability of the World Wide Name (0x83) and Unit
	 * Serial Number (0x80) pages in sd_check_vpd_page_support(), and using
	 * un_vpd_page_mask from them, we decide which way to get the WWN.  If
	 * 0x83 is available, that is the best choice.  Our next choice is
	 * 0x80.  If neither are available, we munge the devid from the device
	 * vid/pid/serial # for Sun qualified disks, or use the ddi framework
	 * to fabricate a devid for non-Sun qualified disks.
	 */
	if (sd_check_vpd_page_support(ssc) == 0) {
		/* collect page 80 data if available */
		if (un->un_vpd_page_mask & SD_VPD_UNIT_SERIAL_PG) {

			mutex_exit(SD_MUTEX(un));
			inq80 = kmem_zalloc(inq80_len, KM_SLEEP);

			rval = sd_send_scsi_INQUIRY(ssc, inq80, inq80_len,
			    0x01, 0x80, &inq80_resid);

			if (rval != 0) {
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);
				kmem_free(inq80, inq80_len);
				inq80 = NULL;
				inq80_len = 0;
			} else if (ddi_prop_exists(
			    DDI_DEV_T_NONE, SD_DEVINFO(un),
			    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
			    INQUIRY_SERIAL_NO) == 0) {
				/*
				 * If we don't already have a serial number
				 * property, do quick verify of data returned
				 * and define property.
				 */
				dlen = inq80_len - inq80_resid;
				len = (size_t)inq80[3];
				if ((dlen >= 4) && ((len + 4) <= dlen)) {
					/*
					 * Ensure sn termination, skip leading
					 * blanks, and create property
					 * 'inquiry-serial-no'.
					 */
					sn = (char *)&inq80[4];
					sn[len] = 0;
					while (*sn && (*sn == ' '))
						sn++;
					if (*sn) {
						(void) ddi_prop_update_string(
						    DDI_DEV_T_NONE,
						    SD_DEVINFO(un),
						    INQUIRY_SERIAL_NO, sn);
					}
				}
			}
			mutex_enter(SD_MUTEX(un));
		}

		/* collect page 83 data if available */
		if (un->un_vpd_page_mask & SD_VPD_DEVID_WWN_PG) {
			mutex_exit(SD_MUTEX(un));
			inq83 = kmem_zalloc(inq83_len, KM_SLEEP);

			rval = sd_send_scsi_INQUIRY(ssc, inq83, inq83_len,
			    0x01, 0x83, &inq83_resid);

			if (rval != 0) {
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);
				kmem_free(inq83, inq83_len);
				inq83 = NULL;
				inq83_len = 0;
			}
			mutex_enter(SD_MUTEX(un));
		}
	}

	/*
	 * If transport has already registered a devid for this target
	 * then that takes precedence over the driver's determination
	 * of the devid.
	 *
	 * NOTE: The reason this check is done here instead of at the beginning
	 * of the function is to allow the code above to create the
	 * 'inquiry-serial-no' property.
	 */
	if (ddi_devid_get(SD_DEVINFO(un), &un->un_devid) == DDI_SUCCESS) {
		ASSERT(un->un_devid);
		un->un_f_devid_transport_defined = TRUE;
		goto cleanup; /* use devid registered by the transport */
	}

	/*
	 * This is the case of antiquated Sun disk drives that have the
	 * FAB_DEVID property set in the disk_table.  These drives
	 * manage the devid's by storing them in last 2 available sectors
	 * on the drive and have them fabricated by the ddi layer by calling
	 * ddi_devid_init and passing the DEVID_FAB flag.
	 */
	if (un->un_f_opt_fab_devid == TRUE) {
		/*
		 * Depending on EINVAL isn't reliable, since a reserved disk
		 * may result in invalid geometry, so check to make sure a
		 * reservation conflict did not occur during attach.
		 */
		if ((sd_get_devid(ssc) == EINVAL) &&
		    (reservation_flag != SD_TARGET_IS_RESERVED)) {
			/*
			 * The devid is invalid AND there is no reservation
			 * conflict.  Fabricate a new devid.
			 */
			(void) sd_create_devid(ssc);
		}

		/* Register the devid if it exists */
		if (un->un_devid != NULL) {
			(void) ddi_devid_register(SD_DEVINFO(un),
			    un->un_devid);
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_register_devid: Devid Fabricated\n");
		}
		goto cleanup;
	}

	/* encode best devid possible based on data available */
	if (ddi_devid_scsi_encode(DEVID_SCSI_ENCODE_VERSION_LATEST,
	    (char *)ddi_driver_name(SD_DEVINFO(un)),
	    (uchar_t *)SD_INQUIRY(un), sizeof (*SD_INQUIRY(un)),
	    inq80, inq80_len - inq80_resid, inq83, inq83_len -
	    inq83_resid, &un->un_devid) == DDI_SUCCESS) {

		/* devid successfully encoded, register devid */
		(void) ddi_devid_register(SD_DEVINFO(un), un->un_devid);

	} else {
		/*
		 * Unable to encode a devid based on data available.
		 * This is not a Sun qualified disk.  Older Sun disk
		 * drives that have the SD_FAB_DEVID property
		 * set in the disk_table and non Sun qualified
		 * disks are treated in the same manner.  These
		 * drives manage the devid's by storing them in
		 * last 2 available sectors on the drive and
		 * have them fabricated by the ddi layer by
		 * calling ddi_devid_init and passing the
		 * DEVID_FAB flag.
		 * Create a fabricate devid only if there's no
		 * fabricate devid existed.
		 */
		if (sd_get_devid(ssc) == EINVAL) {
			(void) sd_create_devid(ssc);
		}
		un->un_f_opt_fab_devid = TRUE;

		/* Register the devid if it exists */
		if (un->un_devid != NULL) {
			(void) ddi_devid_register(SD_DEVINFO(un),
			    un->un_devid);
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_register_devid: devid fabricated using "
			    "ddi framework\n");
		}
	}

cleanup:
	/* clean up resources */
	if (inq80 != NULL) {
		kmem_free(inq80, inq80_len);
	}
	if (inq83 != NULL) {
		kmem_free(inq83, inq83_len);
	}
}



/*
 *    Function: sd_get_devid
 *
 * Description: This routine will return 0 if a valid device id has been
 *		obtained from the target and stored in the soft state. If a
 *		valid device id has not been previously read and stored, a
 *		read attempt will be made.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: 0 if we successfully get the device id
 *
 *     Context: Kernel Thread
 */

static int
sd_get_devid(sd_ssc_t *ssc)
{
	struct dk_devid		*dkdevid;
	ddi_devid_t		tmpid;
	uint_t			*ip;
	size_t			sz;
	diskaddr_t		blk;
	int			status;
	int			chksum;
	int			i;
	size_t			buffer_size;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_ATTACH_DETACH, un, "sd_get_devid: entry: un: 0x%p\n",
	    un);

	if (un->un_devid != NULL) {
		return (0);
	}

	mutex_exit(SD_MUTEX(un));
	if (cmlb_get_devid_block(un->un_cmlbhandle, &blk,
	    (void *)SD_PATH_DIRECT) != 0) {
		mutex_enter(SD_MUTEX(un));
		return (EINVAL);
	}

	/*
	 * Read and verify device id, stored in the reserved cylinders at the
	 * end of the disk. Backup label is on the odd sectors of the last
	 * track of the last cylinder. Device id will be on track of the next
	 * to last cylinder.
	 */
	mutex_enter(SD_MUTEX(un));
	buffer_size = SD_REQBYTES2TGTBYTES(un, sizeof (struct dk_devid));
	mutex_exit(SD_MUTEX(un));
	dkdevid = kmem_alloc(buffer_size, KM_SLEEP);
	status = sd_send_scsi_READ(ssc, dkdevid, buffer_size, blk,
	    SD_PATH_DIRECT);

	if (status != 0) {
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		goto error;
	}

	/* Validate the revision */
	if ((dkdevid->dkd_rev_hi != DK_DEVID_REV_MSB) ||
	    (dkdevid->dkd_rev_lo != DK_DEVID_REV_LSB)) {
		status = EINVAL;
		goto error;
	}

	/* Calculate the checksum */
	chksum = 0;
	ip = (uint_t *)dkdevid;
	for (i = 0; i < ((DEV_BSIZE - sizeof (int)) / sizeof (int));
	    i++) {
		chksum ^= ip[i];
	}

	/* Compare the checksums */
	if (DKD_GETCHKSUM(dkdevid) != chksum) {
		status = EINVAL;
		goto error;
	}

	/* Validate the device id */
	if (ddi_devid_valid((ddi_devid_t)&dkdevid->dkd_devid) != DDI_SUCCESS) {
		status = EINVAL;
		goto error;
	}

	/*
	 * Store the device id in the driver soft state
	 */
	sz = ddi_devid_sizeof((ddi_devid_t)&dkdevid->dkd_devid);
	tmpid = kmem_alloc(sz, KM_SLEEP);

	mutex_enter(SD_MUTEX(un));

	un->un_devid = tmpid;
	bcopy(&dkdevid->dkd_devid, un->un_devid, sz);

	kmem_free(dkdevid, buffer_size);

	SD_TRACE(SD_LOG_ATTACH_DETACH, un, "sd_get_devid: exit: un:0x%p\n", un);

	return (status);
error:
	mutex_enter(SD_MUTEX(un));
	kmem_free(dkdevid, buffer_size);
	return (status);
}


/*
 *    Function: sd_create_devid
 *
 * Description: This routine will fabricate the device id and write it
 *		to the disk.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: value of the fabricated device id
 *
 *     Context: Kernel Thread
 */

static ddi_devid_t
sd_create_devid(sd_ssc_t *ssc)
{
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	/* Fabricate the devid */
	if (ddi_devid_init(SD_DEVINFO(un), DEVID_FAB, 0, NULL, &un->un_devid)
	    == DDI_FAILURE) {
		return (NULL);
	}

	/* Write the devid to disk */
	if (sd_write_deviceid(ssc) != 0) {
		ddi_devid_free(un->un_devid);
		un->un_devid = NULL;
	}

	return (un->un_devid);
}


/*
 *    Function: sd_write_deviceid
 *
 * Description: This routine will write the device id to the disk
 *		reserved sector.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: EINVAL
 *		value returned by sd_send_scsi_cmd
 *
 *     Context: Kernel Thread
 */

static int
sd_write_deviceid(sd_ssc_t *ssc)
{
	struct dk_devid		*dkdevid;
	uchar_t			*buf;
	diskaddr_t		blk;
	uint_t			*ip, chksum;
	int			status;
	int			i;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	mutex_exit(SD_MUTEX(un));
	if (cmlb_get_devid_block(un->un_cmlbhandle, &blk,
	    (void *)SD_PATH_DIRECT) != 0) {
		mutex_enter(SD_MUTEX(un));
		return (-1);
	}


	/* Allocate the buffer */
	buf = kmem_zalloc(un->un_sys_blocksize, KM_SLEEP);
	dkdevid = (struct dk_devid *)buf;

	/* Fill in the revision */
	dkdevid->dkd_rev_hi = DK_DEVID_REV_MSB;
	dkdevid->dkd_rev_lo = DK_DEVID_REV_LSB;

	/* Copy in the device id */
	mutex_enter(SD_MUTEX(un));
	bcopy(un->un_devid, &dkdevid->dkd_devid,
	    ddi_devid_sizeof(un->un_devid));
	mutex_exit(SD_MUTEX(un));

	/* Calculate the checksum */
	chksum = 0;
	ip = (uint_t *)dkdevid;
	for (i = 0; i < ((DEV_BSIZE - sizeof (int)) / sizeof (int));
	    i++) {
		chksum ^= ip[i];
	}

	/* Fill-in checksum */
	DKD_FORMCHKSUM(chksum, dkdevid);

	/* Write the reserved sector */
	status = sd_send_scsi_WRITE(ssc, buf, un->un_sys_blocksize, blk,
	    SD_PATH_DIRECT);
	if (status != 0)
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	kmem_free(buf, un->un_sys_blocksize);

	mutex_enter(SD_MUTEX(un));
	return (status);
}


/*
 *    Function: sd_check_vpd_page_support
 *
 * Description: This routine sends an inquiry command with the EVPD bit set and
 *		a page code of 0x00 to the device. It is used to determine which
 *		vital product pages are available to find the devid. We are
 *		looking for pages 0x83 0x80 or 0xB1.  If we return a negative 1,
 *		the device does not support that command.
 *
 *   Arguments: un  - driver soft state (unit) structure
 *
 * Return Code: 0 - success
 *		1 - check condition
 *
 *     Context: This routine can sleep.
 */

static int
sd_check_vpd_page_support(sd_ssc_t *ssc)
{
	uchar_t	*page_list	= NULL;
	uchar_t	page_length	= 0xff;	/* Use max possible length */
	uchar_t	evpd		= 0x01;	/* Set the EVPD bit */
	uchar_t	page_code	= 0x00;	/* Supported VPD Pages */
	int    	rval		= 0;
	int	counter;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	mutex_exit(SD_MUTEX(un));

	/*
	 * We'll set the page length to the maximum to save figuring it out
	 * with an additional call.
	 */
	page_list =  kmem_zalloc(page_length, KM_SLEEP);

	rval = sd_send_scsi_INQUIRY(ssc, page_list, page_length, evpd,
	    page_code, NULL);

	if (rval != 0)
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	mutex_enter(SD_MUTEX(un));

	/*
	 * Now we must validate that the device accepted the command, as some
	 * drives do not support it.  If the drive does support it, we will
	 * return 0, and the supported pages will be in un_vpd_page_mask.  If
	 * not, we return -1.
	 */
	if ((rval == 0) && (page_list[VPD_MODE_PAGE] == 0x00)) {
		/* Loop to find one of the 2 pages we need */
		counter = 4;  /* Supported pages start at byte 4, with 0x00 */

		/*
		 * Pages are returned in ascending order, and 0x83 is what we
		 * are hoping for.
		 */
		while ((page_list[counter] <= 0xB1) &&
		    (counter <= (page_list[VPD_PAGE_LENGTH] +
		    VPD_HEAD_OFFSET))) {
			/*
			 * Add 3 because page_list[3] is the number of
			 * pages minus 3
			 */

			switch (page_list[counter]) {
			case 0x00:
				un->un_vpd_page_mask |= SD_VPD_SUPPORTED_PG;
				break;
			case 0x80:
				un->un_vpd_page_mask |= SD_VPD_UNIT_SERIAL_PG;
				break;
			case 0x81:
				un->un_vpd_page_mask |= SD_VPD_OPERATING_PG;
				break;
			case 0x82:
				un->un_vpd_page_mask |= SD_VPD_ASCII_OP_PG;
				break;
			case 0x83:
				un->un_vpd_page_mask |= SD_VPD_DEVID_WWN_PG;
				break;
			case 0x86:
				un->un_vpd_page_mask |= SD_VPD_EXTENDED_DATA_PG;
				break;
			case 0xB1:
				un->un_vpd_page_mask |= SD_VPD_DEV_CHARACTER_PG;
				break;
			}
			counter++;
		}

	} else {
		rval = -1;

		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_check_vpd_page_support: This drive does not implement "
		    "VPD pages.\n");
	}

	kmem_free(page_list, page_length);

	return (rval);
}


/*
 *    Function: sd_setup_pm
 *
 * Description: Initialize Power Management on the device
 *
 *     Context: Kernel Thread
 */

static void
sd_setup_pm(sd_ssc_t *ssc, dev_info_t *devi)
{
	uint_t		log_page_size;
	uchar_t		*log_page_data;
	int		rval = 0;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	/*
	 * Since we are called from attach, holding a mutex for
	 * un is unnecessary. Because some of the routines called
	 * from here require SD_MUTEX to not be held, assert this
	 * right up front.
	 */
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	/*
	 * Since the sd device does not have the 'reg' property,
	 * cpr will not call its DDI_SUSPEND/DDI_RESUME entries.
	 * The following code is to tell cpr that this device
	 * DOES need to be suspended and resumed.
	 */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "pm-hardware-state", "needs-suspend-resume");

	/*
	 * This complies with the new power management framework
	 * for certain desktop machines. Create the pm_components
	 * property as a string array property.
	 * If un_f_pm_supported is TRUE, that means the disk
	 * attached HBA has set the "pm-capable" property and
	 * the value of this property is bigger than 0.
	 */
	if (un->un_f_pm_supported) {
		/*
		 * not all devices have a motor, try it first.
		 * some devices may return ILLEGAL REQUEST, some
		 * will hang
		 * The following START_STOP_UNIT is used to check if target
		 * device has a motor.
		 */
		un->un_f_start_stop_supported = TRUE;

		if (un->un_f_power_condition_supported) {
			rval = sd_send_scsi_START_STOP_UNIT(ssc,
			    SD_POWER_CONDITION, SD_TARGET_ACTIVE,
			    SD_PATH_DIRECT);
			if (rval != 0) {
				un->un_f_power_condition_supported = FALSE;
			}
		}
		if (!un->un_f_power_condition_supported) {
			rval = sd_send_scsi_START_STOP_UNIT(ssc,
			    SD_START_STOP, SD_TARGET_START, SD_PATH_DIRECT);
		}
		if (rval != 0) {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
			un->un_f_start_stop_supported = FALSE;
		}

		/*
		 * create pm properties anyways otherwise the parent can't
		 * go to sleep
		 */
		un->un_f_pm_is_enabled = TRUE;
		(void) sd_create_pm_components(devi, un);

		/*
		 * If it claims that log sense is supported, check it out.
		 */
		if (un->un_f_log_sense_supported) {
			rval = sd_log_page_supported(ssc,
			    START_STOP_CYCLE_PAGE);
			if (rval == 1) {
				/* Page found, use it. */
				un->un_start_stop_cycle_page =
				    START_STOP_CYCLE_PAGE;
			} else {
				/*
				 * Page not found or log sense is not
				 * supported.
				 * Notice we do not check the old style
				 * START_STOP_CYCLE_VU_PAGE because this
				 * code path does not apply to old disks.
				 */
				un->un_f_log_sense_supported = FALSE;
				un->un_f_pm_log_sense_smart = FALSE;
			}
		}

		return;
	}

	/*
	 * For the disk whose attached HBA has not set the "pm-capable"
	 * property, check if it supports the power management.
	 */
	if (!un->un_f_log_sense_supported) {
		un->un_power_level = SD_SPINDLE_ON;
		un->un_f_pm_is_enabled = FALSE;
		return;
	}

	rval = sd_log_page_supported(ssc, START_STOP_CYCLE_PAGE);

#ifdef	SDDEBUG
	if (sd_force_pm_supported) {
		/* Force a successful result */
		rval = 1;
	}
#endif

	/*
	 * If the start-stop cycle counter log page is not supported
	 * or if the pm-capable property is set to be false (0),
	 * then we should not create the pm_components property.
	 */
	if (rval == -1) {
		/*
		 * Error.
		 * Reading log sense failed, most likely this is
		 * an older drive that does not support log sense.
		 * If this fails auto-pm is not supported.
		 */
		un->un_power_level = SD_SPINDLE_ON;
		un->un_f_pm_is_enabled = FALSE;

	} else if (rval == 0) {
		/*
		 * Page not found.
		 * The start stop cycle counter is implemented as page
		 * START_STOP_CYCLE_PAGE_VU_PAGE (0x31) in older disks. For
		 * newer disks it is implemented as START_STOP_CYCLE_PAGE (0xE).
		 */
		if (sd_log_page_supported(ssc, START_STOP_CYCLE_VU_PAGE) == 1) {
			/*
			 * Page found, use this one.
			 */
			un->un_start_stop_cycle_page = START_STOP_CYCLE_VU_PAGE;
			un->un_f_pm_is_enabled = TRUE;
		} else {
			/*
			 * Error or page not found.
			 * auto-pm is not supported for this device.
			 */
			un->un_power_level = SD_SPINDLE_ON;
			un->un_f_pm_is_enabled = FALSE;
		}
	} else {
		/*
		 * Page found, use it.
		 */
		un->un_start_stop_cycle_page = START_STOP_CYCLE_PAGE;
		un->un_f_pm_is_enabled = TRUE;
	}


	if (un->un_f_pm_is_enabled == TRUE) {
		log_page_size = START_STOP_CYCLE_COUNTER_PAGE_SIZE;
		log_page_data = kmem_zalloc(log_page_size, KM_SLEEP);

		rval = sd_send_scsi_LOG_SENSE(ssc, log_page_data,
		    log_page_size, un->un_start_stop_cycle_page,
		    0x01, 0, SD_PATH_DIRECT);

		if (rval != 0) {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		}

#ifdef	SDDEBUG
		if (sd_force_pm_supported) {
			/* Force a successful result */
			rval = 0;
		}
#endif

		/*
		 * If the Log sense for Page( Start/stop cycle counter page)
		 * succeeds, then power management is supported and we can
		 * enable auto-pm.
		 */
		if (rval == 0)  {
			(void) sd_create_pm_components(devi, un);
		} else {
			un->un_power_level = SD_SPINDLE_ON;
			un->un_f_pm_is_enabled = FALSE;
		}

		kmem_free(log_page_data, log_page_size);
	}
}


/*
 *    Function: sd_create_pm_components
 *
 * Description: Initialize PM property.
 *
 *     Context: Kernel thread context
 */

static void
sd_create_pm_components(dev_info_t *devi, struct sd_lun *un)
{
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	if (un->un_f_power_condition_supported) {
		if (ddi_prop_update_string_array(DDI_DEV_T_NONE, devi,
		    "pm-components", sd_pwr_pc.pm_comp, 5)
		    != DDI_PROP_SUCCESS) {
			un->un_power_level = SD_SPINDLE_ACTIVE;
			un->un_f_pm_is_enabled = FALSE;
			return;
		}
	} else {
		if (ddi_prop_update_string_array(DDI_DEV_T_NONE, devi,
		    "pm-components", sd_pwr_ss.pm_comp, 3)
		    != DDI_PROP_SUCCESS) {
			un->un_power_level = SD_SPINDLE_ON;
			un->un_f_pm_is_enabled = FALSE;
			return;
		}
	}
	/*
	 * When components are initially created they are idle,
	 * power up any non-removables.
	 * Note: the return value of pm_raise_power can't be used
	 * for determining if PM should be enabled for this device.
	 * Even if you check the return values and remove this
	 * property created above, the PM framework will not honor the
	 * change after the first call to pm_raise_power. Hence,
	 * removal of that property does not help if pm_raise_power
	 * fails. In the case of removable media, the start/stop
	 * will fail if the media is not present.
	 */
	if (un->un_f_attach_spinup && (pm_raise_power(SD_DEVINFO(un), 0,
	    SD_PM_STATE_ACTIVE(un)) == DDI_SUCCESS)) {
		mutex_enter(SD_MUTEX(un));
		un->un_power_level = SD_PM_STATE_ACTIVE(un);
		mutex_enter(&un->un_pm_mutex);
		/* Set to on and not busy. */
		un->un_pm_count = 0;
	} else {
		mutex_enter(SD_MUTEX(un));
		un->un_power_level = SD_PM_STATE_STOPPED(un);
		mutex_enter(&un->un_pm_mutex);
		/* Set to off. */
		un->un_pm_count = -1;
	}
	mutex_exit(&un->un_pm_mutex);
	mutex_exit(SD_MUTEX(un));
}


/*
 *    Function: sd_ddi_suspend
 *
 * Description: Performs system power-down operations. This includes
 *		setting the drive state to indicate its suspended so
 *		that no new commands will be accepted. Also, wait for
 *		all commands that are in transport or queued to a timer
 *		for retry to complete. All timeout threads are cancelled.
 *
 * Return Code: DDI_FAILURE or DDI_SUCCESS
 *
 *     Context: Kernel thread context
 */

static int
sd_ddi_suspend(dev_info_t *devi)
{
	struct	sd_lun	*un;
	clock_t		wait_cmds_complete;

	un = ddi_get_soft_state(sd_state, ddi_get_instance(devi));
	if (un == NULL) {
		return (DDI_FAILURE);
	}

	SD_TRACE(SD_LOG_IO_PM, un, "sd_ddi_suspend: entry\n");

	mutex_enter(SD_MUTEX(un));

	/* Return success if the device is already suspended. */
	if (un->un_state == SD_STATE_SUSPENDED) {
		mutex_exit(SD_MUTEX(un));
		SD_TRACE(SD_LOG_IO_PM, un, "sd_ddi_suspend: "
		    "device already suspended, exiting\n");
		return (DDI_SUCCESS);
	}

	/* Return failure if the device is being used by HA */
	if (un->un_resvd_status &
	    (SD_RESERVE | SD_WANT_RESERVE | SD_LOST_RESERVE)) {
		mutex_exit(SD_MUTEX(un));
		SD_TRACE(SD_LOG_IO_PM, un, "sd_ddi_suspend: "
		    "device in use by HA, exiting\n");
		return (DDI_FAILURE);
	}

	/*
	 * Return failure if the device is in a resource wait
	 * or power changing state.
	 */
	if ((un->un_state == SD_STATE_RWAIT) ||
	    (un->un_state == SD_STATE_PM_CHANGING)) {
		mutex_exit(SD_MUTEX(un));
		SD_TRACE(SD_LOG_IO_PM, un, "sd_ddi_suspend: "
		    "device in resource wait state, exiting\n");
		return (DDI_FAILURE);
	}


	un->un_save_state = un->un_last_state;
	New_state(un, SD_STATE_SUSPENDED);

	/*
	 * Wait for all commands that are in transport or queued to a timer
	 * for retry to complete.
	 *
	 * While waiting, no new commands will be accepted or sent because of
	 * the new state we set above.
	 *
	 * Wait till current operation has completed. If we are in the resource
	 * wait state (with an intr outstanding) then we need to wait till the
	 * intr completes and starts the next cmd. We want to wait for
	 * SD_WAIT_CMDS_COMPLETE seconds before failing the DDI_SUSPEND.
	 */
	wait_cmds_complete = ddi_get_lbolt() +
	    (sd_wait_cmds_complete * drv_usectohz(1000000));

	while (un->un_ncmds_in_transport != 0) {
		/*
		 * Fail if commands do not finish in the specified time.
		 */
		if (cv_timedwait(&un->un_disk_busy_cv, SD_MUTEX(un),
		    wait_cmds_complete) == -1) {
			/*
			 * Undo the state changes made above. Everything
			 * must go back to it's original value.
			 */
			Restore_state(un);
			un->un_last_state = un->un_save_state;
			/* Wake up any threads that might be waiting. */
			cv_broadcast(&un->un_suspend_cv);
			mutex_exit(SD_MUTEX(un));
			SD_ERROR(SD_LOG_IO_PM, un,
			    "sd_ddi_suspend: failed due to outstanding cmds\n");
			SD_TRACE(SD_LOG_IO_PM, un, "sd_ddi_suspend: exiting\n");
			return (DDI_FAILURE);
		}
	}

	/*
	 * Cancel SCSI watch thread and timeouts, if any are active
	 */

	if (SD_OK_TO_SUSPEND_SCSI_WATCHER(un)) {
		opaque_t temp_token = un->un_swr_token;
		mutex_exit(SD_MUTEX(un));
		scsi_watch_suspend(temp_token);
		mutex_enter(SD_MUTEX(un));
	}

	if (un->un_reset_throttle_timeid != NULL) {
		timeout_id_t temp_id = un->un_reset_throttle_timeid;
		un->un_reset_throttle_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	if (un->un_dcvb_timeid != NULL) {
		timeout_id_t temp_id = un->un_dcvb_timeid;
		un->un_dcvb_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	mutex_enter(&un->un_pm_mutex);
	if (un->un_pm_timeid != NULL) {
		timeout_id_t temp_id = un->un_pm_timeid;
		un->un_pm_timeid = NULL;
		mutex_exit(&un->un_pm_mutex);
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	} else {
		mutex_exit(&un->un_pm_mutex);
	}

	if (un->un_rmw_msg_timeid != NULL) {
		timeout_id_t temp_id = un->un_rmw_msg_timeid;
		un->un_rmw_msg_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	if (un->un_retry_timeid != NULL) {
		timeout_id_t temp_id = un->un_retry_timeid;
		un->un_retry_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));

		if (un->un_retry_bp != NULL) {
			un->un_retry_bp->av_forw = un->un_waitq_headp;
			un->un_waitq_headp = un->un_retry_bp;
			if (un->un_waitq_tailp == NULL) {
				un->un_waitq_tailp = un->un_retry_bp;
			}
			un->un_retry_bp = NULL;
			un->un_retry_statp = NULL;
		}
	}

	if (un->un_direct_priority_timeid != NULL) {
		timeout_id_t temp_id = un->un_direct_priority_timeid;
		un->un_direct_priority_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	if (un->un_f_is_fibre == TRUE) {
		/*
		 * Remove callbacks for insert and remove events
		 */
		if (un->un_insert_event != NULL) {
			mutex_exit(SD_MUTEX(un));
			(void) ddi_remove_event_handler(un->un_insert_cb_id);
			mutex_enter(SD_MUTEX(un));
			un->un_insert_event = NULL;
		}

		if (un->un_remove_event != NULL) {
			mutex_exit(SD_MUTEX(un));
			(void) ddi_remove_event_handler(un->un_remove_cb_id);
			mutex_enter(SD_MUTEX(un));
			un->un_remove_event = NULL;
		}
	}

	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_PM, un, "sd_ddi_suspend: exit\n");

	return (DDI_SUCCESS);
}


/*
 *    Function: sd_ddi_resume
 *
 * Description: Performs system power-up operations..
 *
 * Return Code: DDI_SUCCESS
 *		DDI_FAILURE
 *
 *     Context: Kernel thread context
 */

static int
sd_ddi_resume(dev_info_t *devi)
{
	struct	sd_lun	*un;

	un = ddi_get_soft_state(sd_state, ddi_get_instance(devi));
	if (un == NULL) {
		return (DDI_FAILURE);
	}

	SD_TRACE(SD_LOG_IO_PM, un, "sd_ddi_resume: entry\n");

	mutex_enter(SD_MUTEX(un));
	Restore_state(un);

	/*
	 * Restore the state which was saved to give the
	 * the right state in un_last_state
	 */
	un->un_last_state = un->un_save_state;
	/*
	 * Note: throttle comes back at full.
	 * Also note: this MUST be done before calling pm_raise_power
	 * otherwise the system can get hung in biowait. The scenario where
	 * this'll happen is under cpr suspend. Writing of the system
	 * state goes through sddump, which writes 0 to un_throttle. If
	 * writing the system state then fails, example if the partition is
	 * too small, then cpr attempts a resume. If throttle isn't restored
	 * from the saved value until after calling pm_raise_power then
	 * cmds sent in sdpower are not transported and sd_send_scsi_cmd hangs
	 * in biowait.
	 */
	un->un_throttle = un->un_saved_throttle;

	/*
	 * The chance of failure is very rare as the only command done in power
	 * entry point is START command when you transition from 0->1 or
	 * unknown->1. Put it to SPINDLE ON state irrespective of the state at
	 * which suspend was done. Ignore the return value as the resume should
	 * not be failed. In the case of removable media the media need not be
	 * inserted and hence there is a chance that raise power will fail with
	 * media not present.
	 */
	if (un->un_f_attach_spinup) {
		mutex_exit(SD_MUTEX(un));
		(void) pm_raise_power(SD_DEVINFO(un), 0,
		    SD_PM_STATE_ACTIVE(un));
		mutex_enter(SD_MUTEX(un));
	}

	/*
	 * Don't broadcast to the suspend cv and therefore possibly
	 * start I/O until after power has been restored.
	 */
	cv_broadcast(&un->un_suspend_cv);
	cv_broadcast(&un->un_state_cv);

	/* restart thread */
	if (SD_OK_TO_RESUME_SCSI_WATCHER(un)) {
		scsi_watch_resume(un->un_swr_token);
	}

#if (defined(__fibre))
	if (un->un_f_is_fibre == TRUE) {
		/*
		 * Add callbacks for insert and remove events
		 */
		if (strcmp(un->un_node_type, DDI_NT_BLOCK_CHAN)) {
			sd_init_event_callbacks(un);
		}
	}
#endif

	/*
	 * Transport any pending commands to the target.
	 *
	 * If this is a low-activity device commands in queue will have to wait
	 * until new commands come in, which may take awhile. Also, we
	 * specifically don't check un_ncmds_in_transport because we know that
	 * there really are no commands in progress after the unit was
	 * suspended and we could have reached the throttle level, been
	 * suspended, and have no new commands coming in for awhile. Highly
	 * unlikely, but so is the low-activity disk scenario.
	 */
	ddi_xbuf_dispatch(un->un_xbuf_attr);

	sd_start_cmds(un, NULL);
	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_PM, un, "sd_ddi_resume: exit\n");

	return (DDI_SUCCESS);
}


/*
 *    Function: sd_pm_state_change
 *
 * Description: Change the driver power state.
 * 		Someone else is required to actually change the driver
 * 		power level.
 *
 *   Arguments: un - driver soft state (unit) structure
 *              level - the power level that is changed to
 *              flag - to decide how to change the power state
 *
 * Return Code: DDI_SUCCESS
 *
 *     Context: Kernel thread context
 */
static int
sd_pm_state_change(struct sd_lun *un, int level, int flag)
{
	ASSERT(un != NULL);
	SD_TRACE(SD_LOG_POWER, un, "sd_pm_state_change: entry\n");

	ASSERT(!mutex_owned(SD_MUTEX(un)));
	mutex_enter(SD_MUTEX(un));

	if (flag == SD_PM_STATE_ROLLBACK || SD_PM_IS_IO_CAPABLE(un, level)) {
		un->un_power_level = level;
		ASSERT(!mutex_owned(&un->un_pm_mutex));
		mutex_enter(&un->un_pm_mutex);
		if (SD_DEVICE_IS_IN_LOW_POWER(un)) {
			un->un_pm_count++;
			ASSERT(un->un_pm_count == 0);
		}
		mutex_exit(&un->un_pm_mutex);
	} else {
		/*
		 * Exit if power management is not enabled for this device,
		 * or if the device is being used by HA.
		 */
		if ((un->un_f_pm_is_enabled == FALSE) || (un->un_resvd_status &
		    (SD_RESERVE | SD_WANT_RESERVE | SD_LOST_RESERVE))) {
			mutex_exit(SD_MUTEX(un));
			SD_TRACE(SD_LOG_POWER, un,
			    "sd_pm_state_change: exiting\n");
			return (DDI_FAILURE);
		}

		SD_INFO(SD_LOG_POWER, un, "sd_pm_state_change: "
		    "un_ncmds_in_driver=%ld\n", un->un_ncmds_in_driver);

		/*
		 * See if the device is not busy, ie.:
		 *    - we have no commands in the driver for this device
		 *    - not waiting for resources
		 */
		if ((un->un_ncmds_in_driver == 0) &&
		    (un->un_state != SD_STATE_RWAIT)) {
			/*
			 * The device is not busy, so it is OK to go to low
			 * power state. Indicate low power, but rely on someone
			 * else to actually change it.
			 */
			mutex_enter(&un->un_pm_mutex);
			un->un_pm_count = -1;
			mutex_exit(&un->un_pm_mutex);
			un->un_power_level = level;
		}
	}

	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_POWER, un, "sd_pm_state_change: exit\n");

	return (DDI_SUCCESS);
}


/*
 *    Function: sd_pm_idletimeout_handler
 *
 * Description: A timer routine that's active only while a device is busy.
 *		The purpose is to extend slightly the pm framework's busy
 *		view of the device to prevent busy/idle thrashing for
 *		back-to-back commands. Do this by comparing the current time
 *		to the time at which the last command completed and when the
 *		difference is greater than sd_pm_idletime, call
 *		pm_idle_component. In addition to indicating idle to the pm
 *		framework, update the chain type to again use the internal pm
 *		layers of the driver.
 *
 *   Arguments: arg - driver soft state (unit) structure
 *
 *     Context: Executes in a timeout(9F) thread context
 */

static void
sd_pm_idletimeout_handler(void *arg)
{
	const hrtime_t idletime = sd_pm_idletime * NANOSEC;
	struct sd_lun *un = arg;

	mutex_enter(&sd_detach_mutex);
	if (un->un_detach_count != 0) {
		/* Abort if the instance is detaching */
		mutex_exit(&sd_detach_mutex);
		return;
	}
	mutex_exit(&sd_detach_mutex);

	/*
	 * Grab both mutexes, in the proper order, since we're accessing
	 * both PM and softstate variables.
	 */
	mutex_enter(SD_MUTEX(un));
	mutex_enter(&un->un_pm_mutex);
	if (((gethrtime() - un->un_pm_idle_time) > idletime) &&
	    (un->un_ncmds_in_driver == 0) && (un->un_pm_count == 0)) {
		/*
		 * Update the chain types.
		 * This takes affect on the next new command received.
		 */
		if (un->un_f_non_devbsize_supported) {
			un->un_buf_chain_type = SD_CHAIN_INFO_RMMEDIA;
		} else {
			un->un_buf_chain_type = SD_CHAIN_INFO_DISK;
		}
		un->un_uscsi_chain_type = SD_CHAIN_INFO_USCSI_CMD;

		SD_TRACE(SD_LOG_IO_PM, un,
		    "sd_pm_idletimeout_handler: idling device\n");
		(void) pm_idle_component(SD_DEVINFO(un), 0);
		un->un_pm_idle_timeid = NULL;
	} else {
		un->un_pm_idle_timeid =
		    timeout(sd_pm_idletimeout_handler, un,
		    (drv_usectohz((clock_t)300000))); /* 300 ms. */
	}
	mutex_exit(&un->un_pm_mutex);
	mutex_exit(SD_MUTEX(un));
}


/*
 *    Function: sd_pm_timeout_handler
 *
 * Description: Callback to tell framework we are idle.
 *
 *     Context: timeout(9f) thread context.
 */

static void
sd_pm_timeout_handler(void *arg)
{
	struct sd_lun *un = arg;

	(void) pm_idle_component(SD_DEVINFO(un), 0);
	mutex_enter(&un->un_pm_mutex);
	un->un_pm_timeid = NULL;
	mutex_exit(&un->un_pm_mutex);
}


/*
 *    Function: sdpower
 *
 * Description: PM entry point.
 *
 * Return Code: DDI_SUCCESS
 *		DDI_FAILURE
 *
 *     Context: Kernel thread context
 */

static int
sdpower(dev_info_t *devi, int component, int level)
{
	struct sd_lun	*un;
	int		instance;
	int		rval = DDI_SUCCESS;
	uint_t		i, log_page_size, maxcycles, ncycles;
	uchar_t		*log_page_data;
	int		log_sense_page;
	int		medium_present;
	time_t		intvlp;
	struct pm_trans_data	sd_pm_tran_data;
	uchar_t		save_state;
	int		sval;
	uchar_t		state_before_pm;
	int		got_semaphore_here;
	sd_ssc_t	*ssc;
	int	last_power_level;

	instance = ddi_get_instance(devi);

	if (((un = ddi_get_soft_state(sd_state, instance)) == NULL) ||
	    !SD_PM_IS_LEVEL_VALID(un, level) || component != 0) {
		return (DDI_FAILURE);
	}

	ssc = sd_ssc_init(un);

	SD_TRACE(SD_LOG_IO_PM, un, "sdpower: entry, level = %d\n", level);

	/*
	 * Must synchronize power down with close.
	 * Attempt to decrement/acquire the open/close semaphore,
	 * but do NOT wait on it. If it's not greater than zero,
	 * ie. it can't be decremented without waiting, then
	 * someone else, either open or close, already has it
	 * and the try returns 0. Use that knowledge here to determine
	 * if it's OK to change the device power level.
	 * Also, only increment it on exit if it was decremented, ie. gotten,
	 * here.
	 */
	got_semaphore_here = sema_tryp(&un->un_semoclose);

	mutex_enter(SD_MUTEX(un));

	SD_INFO(SD_LOG_POWER, un, "sdpower: un_ncmds_in_driver = %ld\n",
	    un->un_ncmds_in_driver);

	/*
	 * If un_ncmds_in_driver is non-zero it indicates commands are
	 * already being processed in the driver, or if the semaphore was
	 * not gotten here it indicates an open or close is being processed.
	 * At the same time somebody is requesting to go to a lower power
	 * that can't perform I/O, which can't happen, therefore we need to
	 * return failure.
	 */
	if ((!SD_PM_IS_IO_CAPABLE(un, level)) &&
	    ((un->un_ncmds_in_driver != 0) || (got_semaphore_here == 0))) {
		mutex_exit(SD_MUTEX(un));

		if (got_semaphore_here != 0) {
			sema_v(&un->un_semoclose);
		}
		SD_TRACE(SD_LOG_IO_PM, un,
		    "sdpower: exit, device has queued cmds.\n");

		goto sdpower_failed;
	}

	/*
	 * if it is OFFLINE that means the disk is completely dead
	 * in our case we have to put the disk in on or off by sending commands
	 * Of course that will fail anyway so return back here.
	 *
	 * Power changes to a device that's OFFLINE or SUSPENDED
	 * are not allowed.
	 */
	if ((un->un_state == SD_STATE_OFFLINE) ||
	    (un->un_state == SD_STATE_SUSPENDED)) {
		mutex_exit(SD_MUTEX(un));

		if (got_semaphore_here != 0) {
			sema_v(&un->un_semoclose);
		}
		SD_TRACE(SD_LOG_IO_PM, un,
		    "sdpower: exit, device is off-line.\n");

		goto sdpower_failed;
	}

	/*
	 * Change the device's state to indicate it's power level
	 * is being changed. Do this to prevent a power off in the
	 * middle of commands, which is especially bad on devices
	 * that are really powered off instead of just spun down.
	 */
	state_before_pm = un->un_state;
	un->un_state = SD_STATE_PM_CHANGING;

	mutex_exit(SD_MUTEX(un));

	/*
	 * If log sense command is not supported, bypass the
	 * following checking, otherwise, check the log sense
	 * information for this device.
	 */
	if (SD_PM_STOP_MOTOR_NEEDED(un, level) &&
	    un->un_f_log_sense_supported) {
		/*
		 * Get the log sense information to understand whether the
		 * the powercycle counts have gone beyond the threshhold.
		 */
		log_page_size = START_STOP_CYCLE_COUNTER_PAGE_SIZE;
		log_page_data = kmem_zalloc(log_page_size, KM_SLEEP);

		mutex_enter(SD_MUTEX(un));
		log_sense_page = un->un_start_stop_cycle_page;
		mutex_exit(SD_MUTEX(un));

		rval = sd_send_scsi_LOG_SENSE(ssc, log_page_data,
		    log_page_size, log_sense_page, 0x01, 0, SD_PATH_DIRECT);

		if (rval != 0) {
			if (rval == EIO)
				sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
			else
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		}

#ifdef	SDDEBUG
		if (sd_force_pm_supported) {
			/* Force a successful result */
			rval = 0;
		}
#endif
		if (rval != 0) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "Log Sense Failed\n");

			kmem_free(log_page_data, log_page_size);
			/* Cannot support power management on those drives */

			if (got_semaphore_here != 0) {
				sema_v(&un->un_semoclose);
			}
			/*
			 * On exit put the state back to it's original value
			 * and broadcast to anyone waiting for the power
			 * change completion.
			 */
			mutex_enter(SD_MUTEX(un));
			un->un_state = state_before_pm;
			cv_broadcast(&un->un_suspend_cv);
			mutex_exit(SD_MUTEX(un));
			SD_TRACE(SD_LOG_IO_PM, un,
			    "sdpower: exit, Log Sense Failed.\n");

			goto sdpower_failed;
		}

		/*
		 * From the page data - Convert the essential information to
		 * pm_trans_data
		 */
		maxcycles =
		    (log_page_data[0x1c] << 24) | (log_page_data[0x1d] << 16) |
		    (log_page_data[0x1E] << 8)  | log_page_data[0x1F];

		ncycles =
		    (log_page_data[0x24] << 24) | (log_page_data[0x25] << 16) |
		    (log_page_data[0x26] << 8)  | log_page_data[0x27];

		if (un->un_f_pm_log_sense_smart) {
			sd_pm_tran_data.un.smart_count.allowed = maxcycles;
			sd_pm_tran_data.un.smart_count.consumed = ncycles;
			sd_pm_tran_data.un.smart_count.flag = 0;
			sd_pm_tran_data.format = DC_SMART_FORMAT;
		} else {
			sd_pm_tran_data.un.scsi_cycles.lifemax = maxcycles;
			sd_pm_tran_data.un.scsi_cycles.ncycles = ncycles;
			for (i = 0; i < DC_SCSI_MFR_LEN; i++) {
				sd_pm_tran_data.un.scsi_cycles.svc_date[i] =
				    log_page_data[8+i];
			}
			sd_pm_tran_data.un.scsi_cycles.flag = 0;
			sd_pm_tran_data.format = DC_SCSI_FORMAT;
		}

		kmem_free(log_page_data, log_page_size);

		/*
		 * Call pm_trans_check routine to get the Ok from
		 * the global policy
		 */
		rval = pm_trans_check(&sd_pm_tran_data, &intvlp);
#ifdef	SDDEBUG
		if (sd_force_pm_supported) {
			/* Force a successful result */
			rval = 1;
		}
#endif
		switch (rval) {
		case 0:
			/*
			 * Not Ok to Power cycle or error in parameters passed
			 * Would have given the advised time to consider power
			 * cycle. Based on the new intvlp parameter we are
			 * supposed to pretend we are busy so that pm framework
			 * will never call our power entry point. Because of
			 * that install a timeout handler and wait for the
			 * recommended time to elapse so that power management
			 * can be effective again.
			 *
			 * To effect this behavior, call pm_busy_component to
			 * indicate to the framework this device is busy.
			 * By not adjusting un_pm_count the rest of PM in
			 * the driver will function normally, and independent
			 * of this but because the framework is told the device
			 * is busy it won't attempt powering down until it gets
			 * a matching idle. The timeout handler sends this.
			 * Note: sd_pm_entry can't be called here to do this
			 * because sdpower may have been called as a result
			 * of a call to pm_raise_power from within sd_pm_entry.
			 *
			 * If a timeout handler is already active then
			 * don't install another.
			 */
			mutex_enter(&un->un_pm_mutex);
			if (un->un_pm_timeid == NULL) {
				un->un_pm_timeid =
				    timeout(sd_pm_timeout_handler,
				    un, intvlp * drv_usectohz(1000000));
				mutex_exit(&un->un_pm_mutex);
				(void) pm_busy_component(SD_DEVINFO(un), 0);
			} else {
				mutex_exit(&un->un_pm_mutex);
			}
			if (got_semaphore_here != 0) {
				sema_v(&un->un_semoclose);
			}
			/*
			 * On exit put the state back to it's original value
			 * and broadcast to anyone waiting for the power
			 * change completion.
			 */
			mutex_enter(SD_MUTEX(un));
			un->un_state = state_before_pm;
			cv_broadcast(&un->un_suspend_cv);
			mutex_exit(SD_MUTEX(un));

			SD_TRACE(SD_LOG_IO_PM, un, "sdpower: exit, "
			    "trans check Failed, not ok to power cycle.\n");

			goto sdpower_failed;
		case -1:
			if (got_semaphore_here != 0) {
				sema_v(&un->un_semoclose);
			}
			/*
			 * On exit put the state back to it's original value
			 * and broadcast to anyone waiting for the power
			 * change completion.
			 */
			mutex_enter(SD_MUTEX(un));
			un->un_state = state_before_pm;
			cv_broadcast(&un->un_suspend_cv);
			mutex_exit(SD_MUTEX(un));
			SD_TRACE(SD_LOG_IO_PM, un,
			    "sdpower: exit, trans check command Failed.\n");

			goto sdpower_failed;
		}
	}

	if (!SD_PM_IS_IO_CAPABLE(un, level)) {
		/*
		 * Save the last state... if the STOP FAILS we need it
		 * for restoring
		 */
		mutex_enter(SD_MUTEX(un));
		save_state = un->un_last_state;
		last_power_level = un->un_power_level;
		/*
		 * There must not be any cmds. getting processed
		 * in the driver when we get here. Power to the
		 * device is potentially going off.
		 */
		ASSERT(un->un_ncmds_in_driver == 0);
		mutex_exit(SD_MUTEX(un));

		/*
		 * For now PM suspend the device completely before spindle is
		 * turned off
		 */
		if ((rval = sd_pm_state_change(un, level, SD_PM_STATE_CHANGE))
		    == DDI_FAILURE) {
			if (got_semaphore_here != 0) {
				sema_v(&un->un_semoclose);
			}
			/*
			 * On exit put the state back to it's original value
			 * and broadcast to anyone waiting for the power
			 * change completion.
			 */
			mutex_enter(SD_MUTEX(un));
			un->un_state = state_before_pm;
			un->un_power_level = last_power_level;
			cv_broadcast(&un->un_suspend_cv);
			mutex_exit(SD_MUTEX(un));
			SD_TRACE(SD_LOG_IO_PM, un,
			    "sdpower: exit, PM suspend Failed.\n");

			goto sdpower_failed;
		}
	}

	/*
	 * The transition from SPINDLE_OFF to SPINDLE_ON can happen in open,
	 * close, or strategy. Dump no long uses this routine, it uses it's
	 * own code so it can be done in polled mode.
	 */

	medium_present = TRUE;

	/*
	 * When powering up, issue a TUR in case the device is at unit
	 * attention.  Don't do retries. Bypass the PM layer, otherwise
	 * a deadlock on un_pm_busy_cv will occur.
	 */
	if (SD_PM_IS_IO_CAPABLE(un, level)) {
		sval = sd_send_scsi_TEST_UNIT_READY(ssc,
		    SD_DONT_RETRY_TUR | SD_BYPASS_PM);
		if (sval != 0)
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}

	if (un->un_f_power_condition_supported) {
		char *pm_condition_name[] = {"STOPPED", "STANDBY",
		    "IDLE", "ACTIVE"};
		SD_TRACE(SD_LOG_IO_PM, un,
		    "sdpower: sending \'%s\' power condition",
		    pm_condition_name[level]);
		sval = sd_send_scsi_START_STOP_UNIT(ssc, SD_POWER_CONDITION,
		    sd_pl2pc[level], SD_PATH_DIRECT);
	} else {
		SD_TRACE(SD_LOG_IO_PM, un, "sdpower: sending \'%s\' unit\n",
		    ((level == SD_SPINDLE_ON) ? "START" : "STOP"));
		sval = sd_send_scsi_START_STOP_UNIT(ssc, SD_START_STOP,
		    ((level == SD_SPINDLE_ON) ? SD_TARGET_START :
		    SD_TARGET_STOP), SD_PATH_DIRECT);
	}
	if (sval != 0) {
		if (sval == EIO)
			sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
		else
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}

	/* Command failed, check for media present. */
	if ((sval == ENXIO) && un->un_f_has_removable_media) {
		medium_present = FALSE;
	}

	/*
	 * The conditions of interest here are:
	 *   if a spindle off with media present fails,
	 *	then restore the state and return an error.
	 *   else if a spindle on fails,
	 *	then return an error (there's no state to restore).
	 * In all other cases we setup for the new state
	 * and return success.
	 */
	if (!SD_PM_IS_IO_CAPABLE(un, level)) {
		if ((medium_present == TRUE) && (sval != 0)) {
			/* The stop command from above failed */
			rval = DDI_FAILURE;
			/*
			 * The stop command failed, and we have media
			 * present. Put the level back by calling the
			 * sd_pm_resume() and set the state back to
			 * it's previous value.
			 */
			(void) sd_pm_state_change(un, last_power_level,
			    SD_PM_STATE_ROLLBACK);
			mutex_enter(SD_MUTEX(un));
			un->un_last_state = save_state;
			mutex_exit(SD_MUTEX(un));
		} else if (un->un_f_monitor_media_state) {
			/*
			 * The stop command from above succeeded.
			 * Terminate watch thread in case of removable media
			 * devices going into low power state. This is as per
			 * the requirements of pm framework, otherwise commands
			 * will be generated for the device (through watch
			 * thread), even when the device is in low power state.
			 */
			mutex_enter(SD_MUTEX(un));
			un->un_f_watcht_stopped = FALSE;
			if (un->un_swr_token != NULL) {
				opaque_t temp_token = un->un_swr_token;
				un->un_f_watcht_stopped = TRUE;
				un->un_swr_token = NULL;
				mutex_exit(SD_MUTEX(un));
				(void) scsi_watch_request_terminate(temp_token,
				    SCSI_WATCH_TERMINATE_ALL_WAIT);
			} else {
				mutex_exit(SD_MUTEX(un));
			}
		}
	} else {
		/*
		 * The level requested is I/O capable.
		 * Legacy behavior: return success on a failed spinup
		 * if there is no media in the drive.
		 * Do this by looking at medium_present here.
		 */
		if ((sval != 0) && medium_present) {
			/* The start command from above failed */
			rval = DDI_FAILURE;
		} else {
			/*
			 * The start command from above succeeded
			 * PM resume the devices now that we have
			 * started the disks
			 */
			(void) sd_pm_state_change(un, level,
			    SD_PM_STATE_CHANGE);

			/*
			 * Resume the watch thread since it was suspended
			 * when the device went into low power mode.
			 */
			if (un->un_f_monitor_media_state) {
				mutex_enter(SD_MUTEX(un));
				if (un->un_f_watcht_stopped == TRUE) {
					opaque_t temp_token;

					un->un_f_watcht_stopped = FALSE;
					mutex_exit(SD_MUTEX(un));
					temp_token =
					    sd_watch_request_submit(un);
					mutex_enter(SD_MUTEX(un));
					un->un_swr_token = temp_token;
				}
				mutex_exit(SD_MUTEX(un));
			}
		}
	}

	if (got_semaphore_here != 0) {
		sema_v(&un->un_semoclose);
	}
	/*
	 * On exit put the state back to it's original value
	 * and broadcast to anyone waiting for the power
	 * change completion.
	 */
	mutex_enter(SD_MUTEX(un));
	un->un_state = state_before_pm;
	cv_broadcast(&un->un_suspend_cv);
	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_PM, un, "sdpower: exit, status = 0x%x\n", rval);

	sd_ssc_fini(ssc);
	return (rval);

sdpower_failed:

	sd_ssc_fini(ssc);
	return (DDI_FAILURE);
}



/*
 *    Function: sdattach
 *
 * Description: Driver's attach(9e) entry point function.
 *
 *   Arguments: devi - opaque device info handle
 *		cmd  - attach  type
 *
 * Return Code: DDI_SUCCESS
 *		DDI_FAILURE
 *
 *     Context: Kernel thread context
 */

static int
sdattach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (sd_unit_attach(devi));
	case DDI_RESUME:
		return (sd_ddi_resume(devi));
	default:
		break;
	}
	return (DDI_FAILURE);
}


/*
 *    Function: sddetach
 *
 * Description: Driver's detach(9E) entry point function.
 *
 *   Arguments: devi - opaque device info handle
 *		cmd  - detach  type
 *
 * Return Code: DDI_SUCCESS
 *		DDI_FAILURE
 *
 *     Context: Kernel thread context
 */

static int
sddetach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (sd_unit_detach(devi));
	case DDI_SUSPEND:
		return (sd_ddi_suspend(devi));
	default:
		break;
	}
	return (DDI_FAILURE);
}


/*
 *     Function: sd_sync_with_callback
 *
 *  Description: Prevents sd_unit_attach or sd_unit_detach from freeing the soft
 *		 state while the callback routine is active.
 *
 *    Arguments: un: softstate structure for the instance
 *
 *	Context: Kernel thread context
 */

static void
sd_sync_with_callback(struct sd_lun *un)
{
	ASSERT(un != NULL);

	mutex_enter(SD_MUTEX(un));

	ASSERT(un->un_in_callback >= 0);

	while (un->un_in_callback > 0) {
		mutex_exit(SD_MUTEX(un));
		delay(2);
		mutex_enter(SD_MUTEX(un));
	}

	mutex_exit(SD_MUTEX(un));
}

/*
 *    Function: sd_unit_attach
 *
 * Description: Performs DDI_ATTACH processing for sdattach(). Allocates
 *		the soft state structure for the device and performs
 *		all necessary structure and device initializations.
 *
 *   Arguments: devi: the system's dev_info_t for the device.
 *
 * Return Code: DDI_SUCCESS if attach is successful.
 *		DDI_FAILURE if any part of the attach fails.
 *
 *     Context: Called at attach(9e) time for the DDI_ATTACH flag.
 *		Kernel thread context only.  Can sleep.
 */

static int
sd_unit_attach(dev_info_t *devi)
{
	struct	scsi_device	*devp;
	struct	sd_lun		*un;
	char			*variantp;
	char			name_str[48];
	int	reservation_flag = SD_TARGET_IS_UNRESERVED;
	int	instance;
	int	rval;
	int	wc_enabled;
	int	tgt;
	uint64_t	capacity;
	uint_t		lbasize = 0;
	dev_info_t	*pdip = ddi_get_parent(devi);
	int		offbyone = 0;
	int		geom_label_valid = 0;
	sd_ssc_t	*ssc;
	int		status;
	struct sd_fm_internal	*sfip = NULL;
	int		max_xfer_size;

	/*
	 * Retrieve the target driver's private data area. This was set
	 * up by the HBA.
	 */
	devp = ddi_get_driver_private(devi);

	/*
	 * Retrieve the target ID of the device.
	 */
	tgt = ddi_prop_get_int(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    SCSI_ADDR_PROP_TARGET, -1);

	/*
	 * Since we have no idea what state things were left in by the last
	 * user of the device, set up some 'default' settings, ie. turn 'em
	 * off. The scsi_ifsetcap calls force re-negotiations with the drive.
	 * Do this before the scsi_probe, which sends an inquiry.
	 * This is a fix for bug (4430280).
	 * Of special importance is wide-xfer. The drive could have been left
	 * in wide transfer mode by the last driver to communicate with it,
	 * this includes us. If that's the case, and if the following is not
	 * setup properly or we don't re-negotiate with the drive prior to
	 * transferring data to/from the drive, it causes bus parity errors,
	 * data overruns, and unexpected interrupts. This first occurred when
	 * the fix for bug (4378686) was made.
	 */
	(void) scsi_ifsetcap(&devp->sd_address, "lun-reset", 0, 1);
	(void) scsi_ifsetcap(&devp->sd_address, "wide-xfer", 0, 1);
	(void) scsi_ifsetcap(&devp->sd_address, "auto-rqsense", 0, 1);

	/*
	 * Currently, scsi_ifsetcap sets tagged-qing capability for all LUNs
	 * on a target. Setting it per lun instance actually sets the
	 * capability of this target, which affects those luns already
	 * attached on the same target. So during attach, we can only disable
	 * this capability only when no other lun has been attached on this
	 * target. By doing this, we assume a target has the same tagged-qing
	 * capability for every lun. The condition can be removed when HBA
	 * is changed to support per lun based tagged-qing capability.
	 */
	if (sd_scsi_get_target_lun_count(pdip, tgt) < 1) {
		(void) scsi_ifsetcap(&devp->sd_address, "tagged-qing", 0, 1);
	}

	/*
	 * Use scsi_probe() to issue an INQUIRY command to the device.
	 * This call will allocate and fill in the scsi_inquiry structure
	 * and point the sd_inq member of the scsi_device structure to it.
	 * If the attach succeeds, then this memory will not be de-allocated
	 * (via scsi_unprobe()) until the instance is detached.
	 */
	if (scsi_probe(devp, SLEEP_FUNC) != SCSIPROBE_EXISTS) {
		goto probe_failed;
	}

	/*
	 * Check the device type as specified in the inquiry data and
	 * claim it if it is of a type that we support.
	 */
	switch (devp->sd_inq->inq_dtype) {
	case DTYPE_DIRECT:
		break;
	case DTYPE_RODIRECT:
		break;
	case DTYPE_OPTICAL:
		break;
	case DTYPE_NOTPRESENT:
	default:
		/* Unsupported device type; fail the attach. */
		goto probe_failed;
	}

	/*
	 * Allocate the soft state structure for this unit.
	 *
	 * We rely upon this memory being set to all zeroes by
	 * ddi_soft_state_zalloc().  We assume that any member of the
	 * soft state structure that is not explicitly initialized by
	 * this routine will have a value of zero.
	 */
	instance = ddi_get_instance(devp->sd_dev);
#ifndef XPV_HVM_DRIVER
	if (ddi_soft_state_zalloc(sd_state, instance) != DDI_SUCCESS) {
		goto probe_failed;
	}
#endif /* !XPV_HVM_DRIVER */

	/*
	 * Retrieve a pointer to the newly-allocated soft state.
	 *
	 * This should NEVER fail if the ddi_soft_state_zalloc() call above
	 * was successful, unless something has gone horribly wrong and the
	 * ddi's soft state internals are corrupt (in which case it is
	 * probably better to halt here than just fail the attach....)
	 */
	if ((un = ddi_get_soft_state(sd_state, instance)) == NULL) {
		panic("sd_unit_attach: NULL soft state on instance:0x%x",
		    instance);
		/*NOTREACHED*/
	}

	/*
	 * Link the back ptr of the driver soft state to the scsi_device
	 * struct for this lun.
	 * Save a pointer to the softstate in the driver-private area of
	 * the scsi_device struct.
	 * Note: We cannot call SD_INFO, SD_TRACE, SD_ERROR, or SD_DIAG until
	 * we first set un->un_sd below.
	 */
	un->un_sd = devp;
	devp->sd_private = (opaque_t)un;

	/*
	 * The following must be after devp is stored in the soft state struct.
	 */
#ifdef SDDEBUG
	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "%s_unit_attach: un:0x%p instance:%d\n",
	    ddi_driver_name(devi), un, instance);
#endif

	/*
	 * Set up the device type and node type (for the minor nodes).
	 * By default we assume that the device can at least support the
	 * Common Command Set. Call it a CD-ROM if it reports itself
	 * as a RODIRECT device.
	 */
	switch (devp->sd_inq->inq_dtype) {
	case DTYPE_RODIRECT:
		un->un_node_type = DDI_NT_CD_CHAN;
		un->un_ctype	 = CTYPE_CDROM;
		break;
	case DTYPE_OPTICAL:
		un->un_node_type = DDI_NT_BLOCK_CHAN;
		un->un_ctype	 = CTYPE_ROD;
		break;
	default:
		un->un_node_type = DDI_NT_BLOCK_CHAN;
		un->un_ctype	 = CTYPE_CCS;
		break;
	}

	/*
	 * Try to read the interconnect type from the HBA.
	 *
	 * Note: This driver is currently compiled as two binaries, a parallel
	 * scsi version (sd) and a fibre channel version (ssd). All functional
	 * differences are determined at compile time. In the future a single
	 * binary will be provided and the interconnect type will be used to
	 * differentiate between fibre and parallel scsi behaviors. At that time
	 * it will be necessary for all fibre channel HBAs to support this
	 * property.
	 *
	 * set un_f_is_fiber to TRUE ( default fiber )
	 */
	un->un_f_is_fibre = TRUE;
	switch (scsi_ifgetcap(SD_ADDRESS(un), "interconnect-type", -1)) {
	case INTERCONNECT_SSA:
		un->un_interconnect_type = SD_INTERCONNECT_SSA;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p SD_INTERCONNECT_SSA\n", un);
		break;
	case INTERCONNECT_PARALLEL:
		un->un_f_is_fibre = FALSE;
		un->un_interconnect_type = SD_INTERCONNECT_PARALLEL;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p SD_INTERCONNECT_PARALLEL\n", un);
		break;
	case INTERCONNECT_SAS:
		un->un_f_is_fibre = FALSE;
		un->un_interconnect_type = SD_INTERCONNECT_SAS;
		un->un_node_type = DDI_NT_BLOCK_SAS;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p SD_INTERCONNECT_SAS\n", un);
		break;
	case INTERCONNECT_SATA:
		un->un_f_is_fibre = FALSE;
		un->un_interconnect_type = SD_INTERCONNECT_SATA;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p SD_INTERCONNECT_SATA\n", un);
		break;
	case INTERCONNECT_FIBRE:
		un->un_interconnect_type = SD_INTERCONNECT_FIBRE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p SD_INTERCONNECT_FIBRE\n", un);
		break;
	case INTERCONNECT_FABRIC:
		un->un_interconnect_type = SD_INTERCONNECT_FABRIC;
		un->un_node_type = DDI_NT_BLOCK_FABRIC;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p SD_INTERCONNECT_FABRIC\n", un);
		break;
	default:
#ifdef SD_DEFAULT_INTERCONNECT_TYPE
		/*
		 * The HBA does not support the "interconnect-type" property
		 * (or did not provide a recognized type).
		 *
		 * Note: This will be obsoleted when a single fibre channel
		 * and parallel scsi driver is delivered. In the meantime the
		 * interconnect type will be set to the platform default.If that
		 * type is not parallel SCSI, it means that we should be
		 * assuming "ssd" semantics. However, here this also means that
		 * the FC HBA is not supporting the "interconnect-type" property
		 * like we expect it to, so log this occurrence.
		 */
		un->un_interconnect_type = SD_DEFAULT_INTERCONNECT_TYPE;
		if (!SD_IS_PARALLEL_SCSI(un)) {
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p Assuming "
			    "INTERCONNECT_FIBRE\n", un);
		} else {
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p Assuming "
			    "INTERCONNECT_PARALLEL\n", un);
			un->un_f_is_fibre = FALSE;
		}
#else
		/*
		 * Note: This source will be implemented when a single fibre
		 * channel and parallel scsi driver is delivered. The default
		 * will be to assume that if a device does not support the
		 * "interconnect-type" property it is a parallel SCSI HBA and
		 * we will set the interconnect type for parallel scsi.
		 */
		un->un_interconnect_type = SD_INTERCONNECT_PARALLEL;
		un->un_f_is_fibre = FALSE;
#endif
		break;
	}

	if (un->un_f_is_fibre == TRUE) {
		if (scsi_ifgetcap(SD_ADDRESS(un), "scsi-version", 1) ==
		    SCSI_VERSION_3) {
			switch (un->un_interconnect_type) {
			case SD_INTERCONNECT_FIBRE:
			case SD_INTERCONNECT_SSA:
				un->un_node_type = DDI_NT_BLOCK_WWN;
				break;
			default:
				break;
			}
		}
	}

	/*
	 * Initialize the Request Sense command for the target
	 */
	if (sd_alloc_rqs(devp, un) != DDI_SUCCESS) {
		goto alloc_rqs_failed;
	}

	/*
	 * Set un_retry_count with SD_RETRY_COUNT, this is ok for Sparc
	 * with separate binary for sd and ssd.
	 *
	 * x86 has 1 binary, un_retry_count is set base on connection type.
	 * The hardcoded values will go away when Sparc uses 1 binary
	 * for sd and ssd.  This hardcoded values need to match
	 * SD_RETRY_COUNT in sddef.h
	 * The value used is base on interconnect type.
	 * fibre = 3, parallel = 5
	 */
#if defined(__i386) || defined(__amd64)
	un->un_retry_count = un->un_f_is_fibre ? 3 : 5;
#else
	un->un_retry_count = SD_RETRY_COUNT;
#endif

	/*
	 * Set the per disk retry count to the default number of retries
	 * for disks and CDROMs. This value can be overridden by the
	 * disk property list or an entry in sd.conf.
	 */
	un->un_notready_retry_count =
	    ISCD(un) ? CD_NOT_READY_RETRY_COUNT(un)
	    : DISK_NOT_READY_RETRY_COUNT(un);

	/*
	 * Set the busy retry count to the default value of un_retry_count.
	 * This can be overridden by entries in sd.conf or the device
	 * config table.
	 */
	un->un_busy_retry_count = un->un_retry_count;

	/*
	 * Init the reset threshold for retries.  This number determines
	 * how many retries must be performed before a reset can be issued
	 * (for certain error conditions). This can be overridden by entries
	 * in sd.conf or the device config table.
	 */
	un->un_reset_retry_count = (un->un_retry_count / 2);

	/*
	 * Set the victim_retry_count to the default un_retry_count
	 */
	un->un_victim_retry_count = (2 * un->un_retry_count);

	/*
	 * Set the reservation release timeout to the default value of
	 * 5 seconds. This can be overridden by entries in ssd.conf or the
	 * device config table.
	 */
	un->un_reserve_release_time = 5;

	/*
	 * Set up the default maximum transfer size. Note that this may
	 * get updated later in the attach, when setting up default wide
	 * operations for disks.
	 */
#if defined(__i386) || defined(__amd64)
	un->un_max_xfer_size = (uint_t)SD_DEFAULT_MAX_XFER_SIZE;
	un->un_partial_dma_supported = 1;
#else
	un->un_max_xfer_size = (uint_t)maxphys;
#endif

	/*
	 * Get "allow bus device reset" property (defaults to "enabled" if
	 * the property was not defined). This is to disable bus resets for
	 * certain kinds of error recovery. Note: In the future when a run-time
	 * fibre check is available the soft state flag should default to
	 * enabled.
	 */
	if (un->un_f_is_fibre == TRUE) {
		un->un_f_allow_bus_device_reset = TRUE;
	} else {
		if (ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
		    "allow-bus-device-reset", 1) != 0) {
			un->un_f_allow_bus_device_reset = TRUE;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p Bus device reset "
			    "enabled\n", un);
		} else {
			un->un_f_allow_bus_device_reset = FALSE;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p Bus device reset "
			    "disabled\n", un);
		}
	}

	/*
	 * Check if this is an ATAPI device. ATAPI devices use Group 1
	 * Read/Write commands and Group 2 Mode Sense/Select commands.
	 *
	 * Note: The "obsolete" way of doing this is to check for the "atapi"
	 * property. The new "variant" property with a value of "atapi" has been
	 * introduced so that future 'variants' of standard SCSI behavior (like
	 * atapi) could be specified by the underlying HBA drivers by supplying
	 * a new value for the "variant" property, instead of having to define a
	 * new property.
	 */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, devi, 0, "atapi", -1) != -1) {
		un->un_f_cfg_is_atapi = TRUE;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p Atapi device\n", un);
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi, 0, "variant",
	    &variantp) == DDI_PROP_SUCCESS) {
		if (strcmp(variantp, "atapi") == 0) {
			un->un_f_cfg_is_atapi = TRUE;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p Atapi device\n", un);
		}
		ddi_prop_free(variantp);
	}

	un->un_cmd_timeout	= SD_IO_TIME;

	un->un_busy_timeout  = SD_BSY_TIMEOUT;

	/* Info on current states, statuses, etc. (Updated frequently) */
	un->un_state		= SD_STATE_NORMAL;
	un->un_last_state	= SD_STATE_NORMAL;

	/* Control & status info for command throttling */
	un->un_throttle		= sd_max_throttle;
	un->un_saved_throttle	= sd_max_throttle;
	un->un_min_throttle	= sd_min_throttle;

	if (un->un_f_is_fibre == TRUE) {
		un->un_f_use_adaptive_throttle = TRUE;
	} else {
		un->un_f_use_adaptive_throttle = FALSE;
	}

	/* Removable media support. */
	cv_init(&un->un_state_cv, NULL, CV_DRIVER, NULL);
	un->un_mediastate		= DKIO_NONE;
	un->un_specified_mediastate	= DKIO_NONE;

	/* CVs for suspend/resume (PM or DR) */
	cv_init(&un->un_suspend_cv,   NULL, CV_DRIVER, NULL);
	cv_init(&un->un_disk_busy_cv, NULL, CV_DRIVER, NULL);

	/* Power management support. */
	un->un_power_level = SD_SPINDLE_UNINIT;

	cv_init(&un->un_wcc_cv,   NULL, CV_DRIVER, NULL);
	un->un_f_wcc_inprog = 0;

	/*
	 * The open/close semaphore is used to serialize threads executing
	 * in the driver's open & close entry point routines for a given
	 * instance.
	 */
	(void) sema_init(&un->un_semoclose, 1, NULL, SEMA_DRIVER, NULL);

	/*
	 * The conf file entry and softstate variable is a forceful override,
	 * meaning a non-zero value must be entered to change the default.
	 */
	un->un_f_disksort_disabled = FALSE;
	un->un_f_rmw_type = SD_RMW_TYPE_DEFAULT;
	un->un_f_enable_rmw = FALSE;

	/*
	 * GET EVENT STATUS NOTIFICATION media polling enabled by default, but
	 * can be overridden via [s]sd-config-list "mmc-gesn-polling" property.
	 */
	un->un_f_mmc_gesn_polling = TRUE;

	/*
	 * physical sector size defaults to DEV_BSIZE currently. We can
	 * override this value via the driver configuration file so we must
	 * set it before calling sd_read_unit_properties().
	 */
	un->un_phy_blocksize = DEV_BSIZE;

	/*
	 * Retrieve the properties from the static driver table or the driver
	 * configuration file (.conf) for this unit and update the soft state
	 * for the device as needed for the indicated properties.
	 * Note: the property configuration needs to occur here as some of the
	 * following routines may have dependencies on soft state flags set
	 * as part of the driver property configuration.
	 */
	sd_read_unit_properties(un);
	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_unit_attach: un:0x%p property configuration complete.\n", un);

	/*
	 * Only if a device has "hotpluggable" property, it is
	 * treated as hotpluggable device. Otherwise, it is
	 * regarded as non-hotpluggable one.
	 */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, devi, 0, "hotpluggable",
	    -1) != -1) {
		un->un_f_is_hotpluggable = TRUE;
	}

	/*
	 * set unit's attributes(flags) according to "hotpluggable" and
	 * RMB bit in INQUIRY data.
	 */
	sd_set_unit_attributes(un, devi);

	/*
	 * By default, we mark the capacity, lbasize, and geometry
	 * as invalid. Only if we successfully read a valid capacity
	 * will we update the un_blockcount and un_tgt_blocksize with the
	 * valid values (the geometry will be validated later).
	 */
	un->un_f_blockcount_is_valid	= FALSE;
	un->un_f_tgt_blocksize_is_valid	= FALSE;

	/*
	 * Use DEV_BSIZE and DEV_BSHIFT as defaults, until we can determine
	 * otherwise.
	 */
	un->un_tgt_blocksize  = un->un_sys_blocksize  = DEV_BSIZE;
	un->un_blockcount = 0;

	/*
	 * Set up the per-instance info needed to determine the correct
	 * CDBs and other info for issuing commands to the target.
	 */
	sd_init_cdb_limits(un);

	/*
	 * Set up the IO chains to use, based upon the target type.
	 */
	if (un->un_f_non_devbsize_supported) {
		un->un_buf_chain_type = SD_CHAIN_INFO_RMMEDIA;
	} else {
		un->un_buf_chain_type = SD_CHAIN_INFO_DISK;
	}
	un->un_uscsi_chain_type  = SD_CHAIN_INFO_USCSI_CMD;
	un->un_direct_chain_type = SD_CHAIN_INFO_DIRECT_CMD;
	un->un_priority_chain_type = SD_CHAIN_INFO_PRIORITY_CMD;

	un->un_xbuf_attr = ddi_xbuf_attr_create(sizeof (struct sd_xbuf),
	    sd_xbuf_strategy, un, sd_xbuf_active_limit,  sd_xbuf_reserve_limit,
	    ddi_driver_major(devi), DDI_XBUF_QTHREAD_DRIVER);
	ddi_xbuf_attr_register_devinfo(un->un_xbuf_attr, devi);


	if (ISCD(un)) {
		un->un_additional_codes = sd_additional_codes;
	} else {
		un->un_additional_codes = NULL;
	}

	/*
	 * Create the kstats here so they can be available for attach-time
	 * routines that send commands to the unit (either polled or via
	 * sd_send_scsi_cmd).
	 *
	 * Note: This is a critical sequence that needs to be maintained:
	 *	1) Instantiate the kstats here, before any routines using the
	 *	   iopath (i.e. sd_send_scsi_cmd).
	 *	2) Instantiate and initialize the partition stats
	 *	   (sd_set_pstats).
	 *	3) Initialize the error stats (sd_set_errstats), following
	 *	   sd_validate_geometry(),sd_register_devid(),
	 *	   and sd_cache_control().
	 */

	un->un_stats = kstat_create(sd_label, instance,
	    NULL, "disk", KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT);
	if (un->un_stats != NULL) {
		un->un_stats->ks_lock = SD_MUTEX(un);
		kstat_install(un->un_stats);
	}
	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_unit_attach: un:0x%p un_stats created\n", un);

	sd_create_errstats(un, instance);
	if (un->un_errstats == NULL) {
		goto create_errstats_failed;
	}
	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_unit_attach: un:0x%p errstats created\n", un);

	/*
	 * The following if/else code was relocated here from below as part
	 * of the fix for bug (4430280). However with the default setup added
	 * on entry to this routine, it's no longer absolutely necessary for
	 * this to be before the call to sd_spin_up_unit.
	 */
	if (SD_IS_PARALLEL_SCSI(un) || SD_IS_SERIAL(un)) {
		int tq_trigger_flag = (((devp->sd_inq->inq_ansi == 4) ||
		    (devp->sd_inq->inq_ansi == 5)) &&
		    devp->sd_inq->inq_bque) || devp->sd_inq->inq_cmdque;

		/*
		 * If tagged queueing is supported by the target
		 * and by the host adapter then we will enable it
		 */
		un->un_tagflags = 0;
		if ((devp->sd_inq->inq_rdf == RDF_SCSI2) && tq_trigger_flag &&
		    (un->un_f_arq_enabled == TRUE)) {
			if (scsi_ifsetcap(SD_ADDRESS(un), "tagged-qing",
			    1, 1) == 1) {
				un->un_tagflags = FLAG_STAG;
				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_unit_attach: un:0x%p tag queueing "
				    "enabled\n", un);
			} else if (scsi_ifgetcap(SD_ADDRESS(un),
			    "untagged-qing", 0) == 1) {
				un->un_f_opt_queueing = TRUE;
				un->un_saved_throttle = un->un_throttle =
				    min(un->un_throttle, 3);
			} else {
				un->un_f_opt_queueing = FALSE;
				un->un_saved_throttle = un->un_throttle = 1;
			}
		} else if ((scsi_ifgetcap(SD_ADDRESS(un), "untagged-qing", 0)
		    == 1) && (un->un_f_arq_enabled == TRUE)) {
			/* The Host Adapter supports internal queueing. */
			un->un_f_opt_queueing = TRUE;
			un->un_saved_throttle = un->un_throttle =
			    min(un->un_throttle, 3);
		} else {
			un->un_f_opt_queueing = FALSE;
			un->un_saved_throttle = un->un_throttle = 1;
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p no tag queueing\n", un);
		}

		/*
		 * Enable large transfers for SATA/SAS drives
		 */
		if (SD_IS_SERIAL(un)) {
			un->un_max_xfer_size =
			    ddi_getprop(DDI_DEV_T_ANY, devi, 0,
			    sd_max_xfer_size, SD_MAX_XFER_SIZE);
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p max transfer "
			    "size=0x%x\n", un, un->un_max_xfer_size);

		}

		/* Setup or tear down default wide operations for disks */

		/*
		 * Note: Legacy: it may be possible for both "sd_max_xfer_size"
		 * and "ssd_max_xfer_size" to exist simultaneously on the same
		 * system and be set to different values. In the future this
		 * code may need to be updated when the ssd module is
		 * obsoleted and removed from the system. (4299588)
		 */
		if (SD_IS_PARALLEL_SCSI(un) &&
		    (devp->sd_inq->inq_rdf == RDF_SCSI2) &&
		    (devp->sd_inq->inq_wbus16 || devp->sd_inq->inq_wbus32)) {
			if (scsi_ifsetcap(SD_ADDRESS(un), "wide-xfer",
			    1, 1) == 1) {
				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_unit_attach: un:0x%p Wide Transfer "
				    "enabled\n", un);
			}

			/*
			 * If tagged queuing has also been enabled, then
			 * enable large xfers
			 */
			if (un->un_saved_throttle == sd_max_throttle) {
				un->un_max_xfer_size =
				    ddi_getprop(DDI_DEV_T_ANY, devi, 0,
				    sd_max_xfer_size, SD_MAX_XFER_SIZE);
				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_unit_attach: un:0x%p max transfer "
				    "size=0x%x\n", un, un->un_max_xfer_size);
			}
		} else {
			if (scsi_ifsetcap(SD_ADDRESS(un), "wide-xfer",
			    0, 1) == 1) {
				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_unit_attach: un:0x%p "
				    "Wide Transfer disabled\n", un);
			}
		}
	} else {
		un->un_tagflags = FLAG_STAG;
		un->un_max_xfer_size = ddi_getprop(DDI_DEV_T_ANY,
		    devi, 0, sd_max_xfer_size, SD_MAX_XFER_SIZE);
	}

	/*
	 * If this target supports LUN reset, try to enable it.
	 */
	if (un->un_f_lun_reset_enabled) {
		if (scsi_ifsetcap(SD_ADDRESS(un), "lun-reset", 1, 1) == 1) {
			SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_unit_attach: "
			    "un:0x%p lun_reset capability set\n", un);
		} else {
			SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_unit_attach: "
			    "un:0x%p lun-reset capability not set\n", un);
		}
	}

	/*
	 * Adjust the maximum transfer size. This is to fix
	 * the problem of partial DMA support on SPARC. Some
	 * HBA driver, like aac, has very small dma_attr_maxxfer
	 * size, which requires partial DMA support on SPARC.
	 * In the future the SPARC pci nexus driver may solve
	 * the problem instead of this fix.
	 */
	max_xfer_size = scsi_ifgetcap(SD_ADDRESS(un), "dma-max", 1);
	if ((max_xfer_size > 0) && (max_xfer_size < un->un_max_xfer_size)) {
		/* We need DMA partial even on sparc to ensure sddump() works */
		un->un_max_xfer_size = max_xfer_size;
		if (un->un_partial_dma_supported == 0)
			un->un_partial_dma_supported = 1;
	}
	if (ddi_prop_get_int(DDI_DEV_T_ANY, SD_DEVINFO(un),
	    DDI_PROP_DONTPASS, "buf_break", 0) == 1) {
		if (ddi_xbuf_attr_setup_brk(un->un_xbuf_attr,
		    un->un_max_xfer_size) == 1) {
			un->un_buf_breakup_supported = 1;
			SD_INFO(SD_LOG_ATTACH_DETACH, un, "sd_unit_attach: "
			    "un:0x%p Buf breakup enabled\n", un);
		}
	}

	/*
	 * Set PKT_DMA_PARTIAL flag.
	 */
	if (un->un_partial_dma_supported == 1) {
		un->un_pkt_flags = PKT_DMA_PARTIAL;
	} else {
		un->un_pkt_flags = 0;
	}

	/* Initialize sd_ssc_t for internal uscsi commands */
	ssc = sd_ssc_init(un);
	scsi_fm_init(devp);

	/*
	 * Allocate memory for SCSI FMA stuffs.
	 */
	un->un_fm_private =
	    kmem_zalloc(sizeof (struct sd_fm_internal), KM_SLEEP);
	sfip = (struct sd_fm_internal *)un->un_fm_private;
	sfip->fm_ssc.ssc_uscsi_cmd = &sfip->fm_ucmd;
	sfip->fm_ssc.ssc_uscsi_info = &sfip->fm_uinfo;
	sfip->fm_ssc.ssc_un = un;

	if (ISCD(un) ||
	    un->un_f_has_removable_media ||
	    devp->sd_fm_capable == DDI_FM_NOT_CAPABLE) {
		/*
		 * We don't touch CDROM or the DDI_FM_NOT_CAPABLE device.
		 * Their log are unchanged.
		 */
		sfip->fm_log_level = SD_FM_LOG_NSUP;
	} else {
		/*
		 * If enter here, it should be non-CDROM and FM-capable
		 * device, and it will not keep the old scsi_log as before
		 * in /var/adm/messages. However, the property
		 * "fm-scsi-log" will control whether the FM telemetry will
		 * be logged in /var/adm/messages.
		 */
		int fm_scsi_log;
		fm_scsi_log = ddi_prop_get_int(DDI_DEV_T_ANY, SD_DEVINFO(un),
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "fm-scsi-log", 0);

		if (fm_scsi_log)
			sfip->fm_log_level = SD_FM_LOG_EREPORT;
		else
			sfip->fm_log_level = SD_FM_LOG_SILENT;
	}

	/*
	 * At this point in the attach, we have enough info in the
	 * soft state to be able to issue commands to the target.
	 *
	 * All command paths used below MUST issue their commands as
	 * SD_PATH_DIRECT. This is important as intermediate layers
	 * are not all initialized yet (such as PM).
	 */

	/*
	 * Send a TEST UNIT READY command to the device. This should clear
	 * any outstanding UNIT ATTENTION that may be present.
	 *
	 * Note: Don't check for success, just track if there is a reservation,
	 * this is a throw away command to clear any unit attentions.
	 *
	 * Note: This MUST be the first command issued to the target during
	 * attach to ensure power on UNIT ATTENTIONS are cleared.
	 * Pass in flag SD_DONT_RETRY_TUR to prevent the long delays associated
	 * with attempts at spinning up a device with no media.
	 */
	status = sd_send_scsi_TEST_UNIT_READY(ssc, SD_DONT_RETRY_TUR);
	if (status != 0) {
		if (status == EACCES)
			reservation_flag = SD_TARGET_IS_RESERVED;
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}

	/*
	 * If the device is NOT a removable media device, attempt to spin
	 * it up (using the START_STOP_UNIT command) and read its capacity
	 * (using the READ CAPACITY command).  Note, however, that either
	 * of these could fail and in some cases we would continue with
	 * the attach despite the failure (see below).
	 */
	if (un->un_f_descr_format_supported) {

		switch (sd_spin_up_unit(ssc)) {
		case 0:
			/*
			 * Spin-up was successful; now try to read the
			 * capacity.  If successful then save the results
			 * and mark the capacity & lbasize as valid.
			 */
			SD_TRACE(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p spin-up successful\n", un);

			status = sd_send_scsi_READ_CAPACITY(ssc, &capacity,
			    &lbasize, SD_PATH_DIRECT);

			switch (status) {
			case 0: {
				if (capacity > DK_MAX_BLOCKS) {
#ifdef _LP64
					if ((capacity + 1) >
					    SD_GROUP1_MAX_ADDRESS) {
						/*
						 * Enable descriptor format
						 * sense data so that we can
						 * get 64 bit sense data
						 * fields.
						 */
						sd_enable_descr_sense(ssc);
					}
#else
					/* 32-bit kernels can't handle this */
					scsi_log(SD_DEVINFO(un),
					    sd_label, CE_WARN,
					    "disk has %llu blocks, which "
					    "is too large for a 32-bit "
					    "kernel", capacity);

#if defined(__i386) || defined(__amd64)
					/*
					 * 1TB disk was treated as (1T - 512)B
					 * in the past, so that it might have
					 * valid VTOC and solaris partitions,
					 * we have to allow it to continue to
					 * work.
					 */
					if (capacity -1 > DK_MAX_BLOCKS)
#endif
					goto spinup_failed;
#endif
				}

				/*
				 * Here it's not necessary to check the case:
				 * the capacity of the device is bigger than
				 * what the max hba cdb can support. Because
				 * sd_send_scsi_READ_CAPACITY will retrieve
				 * the capacity by sending USCSI command, which
				 * is constrained by the max hba cdb. Actually,
				 * sd_send_scsi_READ_CAPACITY will return
				 * EINVAL when using bigger cdb than required
				 * cdb length. Will handle this case in
				 * "case EINVAL".
				 */

				/*
				 * The following relies on
				 * sd_send_scsi_READ_CAPACITY never
				 * returning 0 for capacity and/or lbasize.
				 */
				sd_update_block_info(un, lbasize, capacity);

				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_unit_attach: un:0x%p capacity = %ld "
				    "blocks; lbasize= %ld.\n", un,
				    un->un_blockcount, un->un_tgt_blocksize);

				break;
			}
			case EINVAL:
				/*
				 * In the case where the max-cdb-length property
				 * is smaller than the required CDB length for
				 * a SCSI device, a target driver can fail to
				 * attach to that device.
				 */
				scsi_log(SD_DEVINFO(un),
				    sd_label, CE_WARN,
				    "disk capacity is too large "
				    "for current cdb length");
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);

				goto spinup_failed;
			case EACCES:
				/*
				 * Should never get here if the spin-up
				 * succeeded, but code it in anyway.
				 * From here, just continue with the attach...
				 */
				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_unit_attach: un:0x%p "
				    "sd_send_scsi_READ_CAPACITY "
				    "returned reservation conflict\n", un);
				reservation_flag = SD_TARGET_IS_RESERVED;
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);
				break;
			default:
				/*
				 * Likewise, should never get here if the
				 * spin-up succeeded. Just continue with
				 * the attach...
				 */
				if (status == EIO)
					sd_ssc_assessment(ssc,
					    SD_FMT_STATUS_CHECK);
				else
					sd_ssc_assessment(ssc,
					    SD_FMT_IGNORE);
				break;
			}
			break;
		case EACCES:
			/*
			 * Device is reserved by another host.  In this case
			 * we could not spin it up or read the capacity, but
			 * we continue with the attach anyway.
			 */
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p spin-up reservation "
			    "conflict.\n", un);
			reservation_flag = SD_TARGET_IS_RESERVED;
			break;
		default:
			/* Fail the attach if the spin-up failed. */
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p spin-up failed.", un);
			goto spinup_failed;
		}

	}

	/*
	 * Check to see if this is a MMC drive
	 */
	if (ISCD(un)) {
		sd_set_mmc_caps(ssc);
	}

	/*
	 * Add a zero-length attribute to tell the world we support
	 * kernel ioctls (for layered drivers)
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);

	/*
	 * Add a boolean property to tell the world we support
	 * the B_FAILFAST flag (for layered drivers)
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    "ddi-failfast-supported", NULL, 0);

	/*
	 * Initialize power management
	 */
	mutex_init(&un->un_pm_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&un->un_pm_busy_cv, NULL, CV_DRIVER, NULL);
	sd_setup_pm(ssc, devi);
	if (un->un_f_pm_is_enabled == FALSE) {
		/*
		 * For performance, point to a jump table that does
		 * not include pm.
		 * The direct and priority chains don't change with PM.
		 *
		 * Note: this is currently done based on individual device
		 * capabilities. When an interface for determining system
		 * power enabled state becomes available, or when additional
		 * layers are added to the command chain, these values will
		 * have to be re-evaluated for correctness.
		 */
		if (un->un_f_non_devbsize_supported) {
			un->un_buf_chain_type = SD_CHAIN_INFO_RMMEDIA_NO_PM;
		} else {
			un->un_buf_chain_type = SD_CHAIN_INFO_DISK_NO_PM;
		}
		un->un_uscsi_chain_type  = SD_CHAIN_INFO_USCSI_CMD_NO_PM;
	}

	/*
	 * This property is set to 0 by HA software to avoid retries
	 * on a reserved disk. (The preferred property name is
	 * "retry-on-reservation-conflict") (1189689)
	 *
	 * Note: The use of a global here can have unintended consequences. A
	 * per instance variable is preferable to match the capabilities of
	 * different underlying hba's (4402600)
	 */
	sd_retry_on_reservation_conflict = ddi_getprop(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS, "retry-on-reservation-conflict",
	    sd_retry_on_reservation_conflict);
	if (sd_retry_on_reservation_conflict != 0) {
		sd_retry_on_reservation_conflict = ddi_getprop(DDI_DEV_T_ANY,
		    devi, DDI_PROP_DONTPASS, sd_resv_conflict_name,
		    sd_retry_on_reservation_conflict);
	}

	/* Set up options for QFULL handling. */
	if ((rval = ddi_getprop(DDI_DEV_T_ANY, devi, 0,
	    "qfull-retries", -1)) != -1) {
		(void) scsi_ifsetcap(SD_ADDRESS(un), "qfull-retries",
		    rval, 1);
	}
	if ((rval = ddi_getprop(DDI_DEV_T_ANY, devi, 0,
	    "qfull-retry-interval", -1)) != -1) {
		(void) scsi_ifsetcap(SD_ADDRESS(un), "qfull-retry-interval",
		    rval, 1);
	}

	/*
	 * This just prints a message that announces the existence of the
	 * device. The message is always printed in the system logfile, but
	 * only appears on the console if the system is booted with the
	 * -v (verbose) argument.
	 */
	ddi_report_dev(devi);

	un->un_mediastate = DKIO_NONE;

	/*
	 * Check if this is a SSD(Solid State Drive).
	 */
	sd_check_solid_state(ssc);

	/*
	 * Check whether the drive is in emulation mode.
	 */
	sd_check_emulation_mode(ssc);

	cmlb_alloc_handle(&un->un_cmlbhandle);

#if defined(__i386) || defined(__amd64)
	/*
	 * On x86, compensate for off-by-1 legacy error
	 */
	if (!un->un_f_has_removable_media && !un->un_f_is_hotpluggable &&
	    (lbasize == un->un_sys_blocksize))
		offbyone = CMLB_OFF_BY_ONE;
#endif

	if (cmlb_attach(devi, &sd_tgops, (int)devp->sd_inq->inq_dtype,
	    VOID2BOOLEAN(un->un_f_has_removable_media != 0),
	    VOID2BOOLEAN(un->un_f_is_hotpluggable != 0),
	    un->un_node_type, offbyone, un->un_cmlbhandle,
	    (void *)SD_PATH_DIRECT) != 0) {
		goto cmlb_attach_failed;
	}


	/*
	 * Read and validate the device's geometry (ie, disk label)
	 * A new unformatted drive will not have a valid geometry, but
	 * the driver needs to successfully attach to this device so
	 * the drive can be formatted via ioctls.
	 */
	geom_label_valid = (cmlb_validate(un->un_cmlbhandle, 0,
	    (void *)SD_PATH_DIRECT) == 0) ? 1: 0;

	mutex_enter(SD_MUTEX(un));

	/*
	 * Read and initialize the devid for the unit.
	 */
	if (un->un_f_devid_supported) {
		sd_register_devid(ssc, devi, reservation_flag);
	}
	mutex_exit(SD_MUTEX(un));

#if (defined(__fibre))
	/*
	 * Register callbacks for fibre only.  You can't do this solely
	 * on the basis of the devid_type because this is hba specific.
	 * We need to query our hba capabilities to find out whether to
	 * register or not.
	 */
	if (un->un_f_is_fibre) {
		if (strcmp(un->un_node_type, DDI_NT_BLOCK_CHAN)) {
			sd_init_event_callbacks(un);
			SD_TRACE(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p event callbacks inserted",
			    un);
		}
	}
#endif

	if (un->un_f_opt_disable_cache == TRUE) {
		/*
		 * Disable both read cache and write cache.  This is
		 * the historic behavior of the keywords in the config file.
		 */
		if (sd_cache_control(ssc, SD_CACHE_DISABLE, SD_CACHE_DISABLE) !=
		    0) {
			SD_ERROR(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p Could not disable "
			    "caching", un);
			goto devid_failed;
		}
	}

	/*
	 * Check the value of the WCE bit now and
	 * set un_f_write_cache_enabled accordingly.
	 */
	(void) sd_get_write_cache_enabled(ssc, &wc_enabled);
	mutex_enter(SD_MUTEX(un));
	un->un_f_write_cache_enabled = (wc_enabled != 0);
	mutex_exit(SD_MUTEX(un));

	if ((un->un_f_rmw_type != SD_RMW_TYPE_RETURN_ERROR &&
	    un->un_tgt_blocksize != DEV_BSIZE) ||
	    un->un_f_enable_rmw) {
		if (!(un->un_wm_cache)) {
			(void) snprintf(name_str, sizeof (name_str),
			    "%s%d_cache",
			    ddi_driver_name(SD_DEVINFO(un)),
			    ddi_get_instance(SD_DEVINFO(un)));
			un->un_wm_cache = kmem_cache_create(
			    name_str, sizeof (struct sd_w_map),
			    8, sd_wm_cache_constructor,
			    sd_wm_cache_destructor, NULL,
			    (void *)un, NULL, 0);
			if (!(un->un_wm_cache)) {
				goto wm_cache_failed;
			}
		}
	}

	/*
	 * Check the value of the NV_SUP bit and set
	 * un_f_suppress_cache_flush accordingly.
	 */
	sd_get_nv_sup(ssc);

	/*
	 * Find out what type of reservation this disk supports.
	 */
	status = sd_send_scsi_PERSISTENT_RESERVE_IN(ssc, SD_READ_KEYS, 0, NULL);

	switch (status) {
	case 0:
		/*
		 * SCSI-3 reservations are supported.
		 */
		un->un_reservation_type = SD_SCSI3_RESERVATION;
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p SCSI-3 reservations\n", un);
		break;
	case ENOTSUP:
		/*
		 * The PERSISTENT RESERVE IN command would not be recognized by
		 * a SCSI-2 device, so assume the reservation type is SCSI-2.
		 */
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p SCSI-2 reservations\n", un);
		un->un_reservation_type = SD_SCSI2_RESERVATION;

		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		break;
	default:
		/*
		 * default to SCSI-3 reservations
		 */
		SD_INFO(SD_LOG_ATTACH_DETACH, un,
		    "sd_unit_attach: un:0x%p default SCSI3 reservations\n", un);
		un->un_reservation_type = SD_SCSI3_RESERVATION;

		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		break;
	}

	/*
	 * Set the pstat and error stat values here, so data obtained during the
	 * previous attach-time routines is available.
	 *
	 * Note: This is a critical sequence that needs to be maintained:
	 *	1) Instantiate the kstats before any routines using the iopath
	 *	   (i.e. sd_send_scsi_cmd).
	 *	2) Initialize the error stats (sd_set_errstats) and partition
	 *	   stats (sd_set_pstats)here, following
	 *	   cmlb_validate_geometry(), sd_register_devid(), and
	 *	   sd_cache_control().
	 */

	if (un->un_f_pkstats_enabled && geom_label_valid) {
		sd_set_pstats(un);
		SD_TRACE(SD_LOG_IO_PARTITION, un,
		    "sd_unit_attach: un:0x%p pstats created and set\n", un);
	}

	sd_set_errstats(un);
	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_unit_attach: un:0x%p errstats set\n", un);


	/*
	 * After successfully attaching an instance, we record the information
	 * of how many luns have been attached on the relative target and
	 * controller for parallel SCSI. This information is used when sd tries
	 * to set the tagged queuing capability in HBA.
	 */
	if (SD_IS_PARALLEL_SCSI(un) && (tgt >= 0) && (tgt < NTARGETS_WIDE)) {
		sd_scsi_update_lun_on_target(pdip, tgt, SD_SCSI_LUN_ATTACH);
	}

	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_unit_attach: un:0x%p exit success\n", un);

	/* Uninitialize sd_ssc_t pointer */
	sd_ssc_fini(ssc);

	return (DDI_SUCCESS);

	/*
	 * An error occurred during the attach; clean up & return failure.
	 */
wm_cache_failed:
devid_failed:

setup_pm_failed:
	ddi_remove_minor_node(devi, NULL);

cmlb_attach_failed:
	/*
	 * Cleanup from the scsi_ifsetcap() calls (437868)
	 */
	(void) scsi_ifsetcap(SD_ADDRESS(un), "lun-reset", 0, 1);
	(void) scsi_ifsetcap(SD_ADDRESS(un), "wide-xfer", 0, 1);

	/*
	 * Refer to the comments of setting tagged-qing in the beginning of
	 * sd_unit_attach. We can only disable tagged queuing when there is
	 * no lun attached on the target.
	 */
	if (sd_scsi_get_target_lun_count(pdip, tgt) < 1) {
		(void) scsi_ifsetcap(SD_ADDRESS(un), "tagged-qing", 0, 1);
	}

	if (un->un_f_is_fibre == FALSE) {
		(void) scsi_ifsetcap(SD_ADDRESS(un), "auto-rqsense", 0, 1);
	}

spinup_failed:

	/* Uninitialize sd_ssc_t pointer */
	sd_ssc_fini(ssc);

	mutex_enter(SD_MUTEX(un));

	/* Deallocate SCSI FMA memory spaces */
	kmem_free(un->un_fm_private, sizeof (struct sd_fm_internal));

	/* Cancel callback for SD_PATH_DIRECT_PRIORITY cmd. restart */
	if (un->un_direct_priority_timeid != NULL) {
		timeout_id_t temp_id = un->un_direct_priority_timeid;
		un->un_direct_priority_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	/* Cancel any pending start/stop timeouts */
	if (un->un_startstop_timeid != NULL) {
		timeout_id_t temp_id = un->un_startstop_timeid;
		un->un_startstop_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	/* Cancel any pending reset-throttle timeouts */
	if (un->un_reset_throttle_timeid != NULL) {
		timeout_id_t temp_id = un->un_reset_throttle_timeid;
		un->un_reset_throttle_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	/* Cancel rmw warning message timeouts */
	if (un->un_rmw_msg_timeid != NULL) {
		timeout_id_t temp_id = un->un_rmw_msg_timeid;
		un->un_rmw_msg_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	/* Cancel any pending retry timeouts */
	if (un->un_retry_timeid != NULL) {
		timeout_id_t temp_id = un->un_retry_timeid;
		un->un_retry_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	/* Cancel any pending delayed cv broadcast timeouts */
	if (un->un_dcvb_timeid != NULL) {
		timeout_id_t temp_id = un->un_dcvb_timeid;
		un->un_dcvb_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	mutex_exit(SD_MUTEX(un));

	/* There should not be any in-progress I/O so ASSERT this check */
	ASSERT(un->un_ncmds_in_transport == 0);
	ASSERT(un->un_ncmds_in_driver == 0);

	/* Do not free the softstate if the callback routine is active */
	sd_sync_with_callback(un);

	/*
	 * Partition stats apparently are not used with removables. These would
	 * not have been created during attach, so no need to clean them up...
	 */
	if (un->un_errstats != NULL) {
		kstat_delete(un->un_errstats);
		un->un_errstats = NULL;
	}

create_errstats_failed:

	if (un->un_stats != NULL) {
		kstat_delete(un->un_stats);
		un->un_stats = NULL;
	}

	ddi_xbuf_attr_unregister_devinfo(un->un_xbuf_attr, devi);
	ddi_xbuf_attr_destroy(un->un_xbuf_attr);

	ddi_prop_remove_all(devi);
	sema_destroy(&un->un_semoclose);
	cv_destroy(&un->un_state_cv);

getrbuf_failed:

	sd_free_rqs(un);

alloc_rqs_failed:

	devp->sd_private = NULL;
	bzero(un, sizeof (struct sd_lun));	/* Clear any stale data! */

get_softstate_failed:
	/*
	 * Note: the man pages are unclear as to whether or not doing a
	 * ddi_soft_state_free(sd_state, instance) is the right way to
	 * clean up after the ddi_soft_state_zalloc() if the subsequent
	 * ddi_get_soft_state() fails.  The implication seems to be
	 * that the get_soft_state cannot fail if the zalloc succeeds.
	 */
#ifndef XPV_HVM_DRIVER
	ddi_soft_state_free(sd_state, instance);
#endif /* !XPV_HVM_DRIVER */

probe_failed:
	scsi_unprobe(devp);

	return (DDI_FAILURE);
}


/*
 *    Function: sd_unit_detach
 *
 * Description: Performs DDI_DETACH processing for sddetach().
 *
 * Return Code: DDI_SUCCESS
 *		DDI_FAILURE
 *
 *     Context: Kernel thread context
 */

static int
sd_unit_detach(dev_info_t *devi)
{
	struct scsi_device	*devp;
	struct sd_lun		*un;
	int			i;
	int			tgt;
	dev_t			dev;
	dev_info_t		*pdip = ddi_get_parent(devi);
#ifndef XPV_HVM_DRIVER
	int			instance = ddi_get_instance(devi);
#endif /* !XPV_HVM_DRIVER */

	mutex_enter(&sd_detach_mutex);

	/*
	 * Fail the detach for any of the following:
	 *  - Unable to get the sd_lun struct for the instance
	 *  - A layered driver has an outstanding open on the instance
	 *  - Another thread is already detaching this instance
	 *  - Another thread is currently performing an open
	 */
	devp = ddi_get_driver_private(devi);
	if ((devp == NULL) ||
	    ((un = (struct sd_lun *)devp->sd_private) == NULL) ||
	    (un->un_ncmds_in_driver != 0) || (un->un_layer_count != 0) ||
	    (un->un_detach_count != 0) || (un->un_opens_in_progress != 0)) {
		mutex_exit(&sd_detach_mutex);
		return (DDI_FAILURE);
	}

	SD_TRACE(SD_LOG_ATTACH_DETACH, un, "sd_unit_detach: entry 0x%p\n", un);

	/*
	 * Mark this instance as currently in a detach, to inhibit any
	 * opens from a layered driver.
	 */
	un->un_detach_count++;
	mutex_exit(&sd_detach_mutex);

	tgt = ddi_prop_get_int(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    SCSI_ADDR_PROP_TARGET, -1);

	dev = sd_make_device(SD_DEVINFO(un));

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	mutex_enter(SD_MUTEX(un));

	/*
	 * Fail the detach if there are any outstanding layered
	 * opens on this device.
	 */
	for (i = 0; i < NDKMAP; i++) {
		if (un->un_ocmap.lyropen[i] != 0) {
			goto err_notclosed;
		}
	}

	/*
	 * Verify there are NO outstanding commands issued to this device.
	 * ie, un_ncmds_in_transport == 0.
	 * It's possible to have outstanding commands through the physio
	 * code path, even though everything's closed.
	 */
	if ((un->un_ncmds_in_transport != 0) || (un->un_retry_timeid != NULL) ||
	    (un->un_direct_priority_timeid != NULL) ||
	    (un->un_state == SD_STATE_RWAIT)) {
		mutex_exit(SD_MUTEX(un));
		SD_ERROR(SD_LOG_ATTACH_DETACH, un,
		    "sd_dr_detach: Detach failure due to outstanding cmds\n");
		goto err_stillbusy;
	}

	/*
	 * If we have the device reserved, release the reservation.
	 */
	if ((un->un_resvd_status & SD_RESERVE) &&
	    !(un->un_resvd_status & SD_LOST_RESERVE)) {
		mutex_exit(SD_MUTEX(un));
		/*
		 * Note: sd_reserve_release sends a command to the device
		 * via the sd_ioctlcmd() path, and can sleep.
		 */
		if (sd_reserve_release(dev, SD_RELEASE) != 0) {
			SD_ERROR(SD_LOG_ATTACH_DETACH, un,
			    "sd_dr_detach: Cannot release reservation \n");
		}
	} else {
		mutex_exit(SD_MUTEX(un));
	}

	/*
	 * Untimeout any reserve recover, throttle reset, restart unit
	 * and delayed broadcast timeout threads. Protect the timeout pointer
	 * from getting nulled by their callback functions.
	 */
	mutex_enter(SD_MUTEX(un));
	if (un->un_resvd_timeid != NULL) {
		timeout_id_t temp_id = un->un_resvd_timeid;
		un->un_resvd_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	if (un->un_reset_throttle_timeid != NULL) {
		timeout_id_t temp_id = un->un_reset_throttle_timeid;
		un->un_reset_throttle_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	if (un->un_startstop_timeid != NULL) {
		timeout_id_t temp_id = un->un_startstop_timeid;
		un->un_startstop_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	if (un->un_rmw_msg_timeid != NULL) {
		timeout_id_t temp_id = un->un_rmw_msg_timeid;
		un->un_rmw_msg_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	if (un->un_dcvb_timeid != NULL) {
		timeout_id_t temp_id = un->un_dcvb_timeid;
		un->un_dcvb_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
	} else {
		mutex_exit(SD_MUTEX(un));
	}

	/* Remove any pending reservation reclaim requests for this device */
	sd_rmv_resv_reclaim_req(dev);

	mutex_enter(SD_MUTEX(un));

	/* Cancel any pending callbacks for SD_PATH_DIRECT_PRIORITY cmd. */
	if (un->un_direct_priority_timeid != NULL) {
		timeout_id_t temp_id = un->un_direct_priority_timeid;
		un->un_direct_priority_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(temp_id);
		mutex_enter(SD_MUTEX(un));
	}

	/* Cancel any active multi-host disk watch thread requests */
	if (un->un_mhd_token != NULL) {
		mutex_exit(SD_MUTEX(un));
		 _NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_mhd_token));
		if (scsi_watch_request_terminate(un->un_mhd_token,
		    SCSI_WATCH_TERMINATE_NOWAIT)) {
			SD_ERROR(SD_LOG_ATTACH_DETACH, un,
			    "sd_dr_detach: Cannot cancel mhd watch request\n");
			/*
			 * Note: We are returning here after having removed
			 * some driver timeouts above. This is consistent with
			 * the legacy implementation but perhaps the watch
			 * terminate call should be made with the wait flag set.
			 */
			goto err_stillbusy;
		}
		mutex_enter(SD_MUTEX(un));
		un->un_mhd_token = NULL;
	}

	if (un->un_swr_token != NULL) {
		mutex_exit(SD_MUTEX(un));
		_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_swr_token));
		if (scsi_watch_request_terminate(un->un_swr_token,
		    SCSI_WATCH_TERMINATE_NOWAIT)) {
			SD_ERROR(SD_LOG_ATTACH_DETACH, un,
			    "sd_dr_detach: Cannot cancel swr watch request\n");
			/*
			 * Note: We are returning here after having removed
			 * some driver timeouts above. This is consistent with
			 * the legacy implementation but perhaps the watch
			 * terminate call should be made with the wait flag set.
			 */
			goto err_stillbusy;
		}
		mutex_enter(SD_MUTEX(un));
		un->un_swr_token = NULL;
	}

	mutex_exit(SD_MUTEX(un));

	/*
	 * Clear any scsi_reset_notifies. We clear the reset notifies
	 * if we have not registered one.
	 * Note: The sd_mhd_reset_notify_cb() fn tries to acquire SD_MUTEX!
	 */
	(void) scsi_reset_notify(SD_ADDRESS(un), SCSI_RESET_CANCEL,
	    sd_mhd_reset_notify_cb, (caddr_t)un);

	/*
	 * protect the timeout pointers from getting nulled by
	 * their callback functions during the cancellation process.
	 * In such a scenario untimeout can be invoked with a null value.
	 */
	_NOTE(NO_COMPETING_THREADS_NOW);

	mutex_enter(&un->un_pm_mutex);
	if (un->un_pm_idle_timeid != NULL) {
		timeout_id_t temp_id = un->un_pm_idle_timeid;
		un->un_pm_idle_timeid = NULL;
		mutex_exit(&un->un_pm_mutex);

		/*
		 * Timeout is active; cancel it.
		 * Note that it'll never be active on a device
		 * that does not support PM therefore we don't
		 * have to check before calling pm_idle_component.
		 */
		(void) untimeout(temp_id);
		(void) pm_idle_component(SD_DEVINFO(un), 0);
		mutex_enter(&un->un_pm_mutex);
	}

	/*
	 * Check whether there is already a timeout scheduled for power
	 * management. If yes then don't lower the power here, that's.
	 * the timeout handler's job.
	 */
	if (un->un_pm_timeid != NULL) {
		timeout_id_t temp_id = un->un_pm_timeid;
		un->un_pm_timeid = NULL;
		mutex_exit(&un->un_pm_mutex);
		/*
		 * Timeout is active; cancel it.
		 * Note that it'll never be active on a device
		 * that does not support PM therefore we don't
		 * have to check before calling pm_idle_component.
		 */
		(void) untimeout(temp_id);
		(void) pm_idle_component(SD_DEVINFO(un), 0);

	} else {
		mutex_exit(&un->un_pm_mutex);
		if ((un->un_f_pm_is_enabled == TRUE) &&
		    (pm_lower_power(SD_DEVINFO(un), 0, SD_PM_STATE_STOPPED(un))
		    != DDI_SUCCESS)) {
			SD_ERROR(SD_LOG_ATTACH_DETACH, un,
		    "sd_dr_detach: Lower power request failed, ignoring.\n");
			/*
			 * Fix for bug: 4297749, item # 13
			 * The above test now includes a check to see if PM is
			 * supported by this device before call
			 * pm_lower_power().
			 * Note, the following is not dead code. The call to
			 * pm_lower_power above will generate a call back into
			 * our sdpower routine which might result in a timeout
			 * handler getting activated. Therefore the following
			 * code is valid and necessary.
			 */
			mutex_enter(&un->un_pm_mutex);
			if (un->un_pm_timeid != NULL) {
				timeout_id_t temp_id = un->un_pm_timeid;
				un->un_pm_timeid = NULL;
				mutex_exit(&un->un_pm_mutex);
				(void) untimeout(temp_id);
				(void) pm_idle_component(SD_DEVINFO(un), 0);
			} else {
				mutex_exit(&un->un_pm_mutex);
			}
		}
	}

	/*
	 * Cleanup from the scsi_ifsetcap() calls (437868)
	 * Relocated here from above to be after the call to
	 * pm_lower_power, which was getting errors.
	 */
	(void) scsi_ifsetcap(SD_ADDRESS(un), "lun-reset", 0, 1);
	(void) scsi_ifsetcap(SD_ADDRESS(un), "wide-xfer", 0, 1);

	/*
	 * Currently, tagged queuing is supported per target based by HBA.
	 * Setting this per lun instance actually sets the capability of this
	 * target in HBA, which affects those luns already attached on the
	 * same target. So during detach, we can only disable this capability
	 * only when this is the only lun left on this target. By doing
	 * this, we assume a target has the same tagged queuing capability
	 * for every lun. The condition can be removed when HBA is changed to
	 * support per lun based tagged queuing capability.
	 */
	if (sd_scsi_get_target_lun_count(pdip, tgt) <= 1) {
		(void) scsi_ifsetcap(SD_ADDRESS(un), "tagged-qing", 0, 1);
	}

	if (un->un_f_is_fibre == FALSE) {
		(void) scsi_ifsetcap(SD_ADDRESS(un), "auto-rqsense", 0, 1);
	}

	/*
	 * Remove any event callbacks, fibre only
	 */
	if (un->un_f_is_fibre == TRUE) {
		if ((un->un_insert_event != NULL) &&
		    (ddi_remove_event_handler(un->un_insert_cb_id) !=
		    DDI_SUCCESS)) {
			/*
			 * Note: We are returning here after having done
			 * substantial cleanup above. This is consistent
			 * with the legacy implementation but this may not
			 * be the right thing to do.
			 */
			SD_ERROR(SD_LOG_ATTACH_DETACH, un,
			    "sd_dr_detach: Cannot cancel insert event\n");
			goto err_remove_event;
		}
		un->un_insert_event = NULL;

		if ((un->un_remove_event != NULL) &&
		    (ddi_remove_event_handler(un->un_remove_cb_id) !=
		    DDI_SUCCESS)) {
			/*
			 * Note: We are returning here after having done
			 * substantial cleanup above. This is consistent
			 * with the legacy implementation but this may not
			 * be the right thing to do.
			 */
			SD_ERROR(SD_LOG_ATTACH_DETACH, un,
			    "sd_dr_detach: Cannot cancel remove event\n");
			goto err_remove_event;
		}
		un->un_remove_event = NULL;
	}

	/* Do not free the softstate if the callback routine is active */
	sd_sync_with_callback(un);

	cmlb_detach(un->un_cmlbhandle, (void *)SD_PATH_DIRECT);
	cmlb_free_handle(&un->un_cmlbhandle);

	/*
	 * Hold the detach mutex here, to make sure that no other threads ever
	 * can access a (partially) freed soft state structure.
	 */
	mutex_enter(&sd_detach_mutex);

	/*
	 * Clean up the soft state struct.
	 * Cleanup is done in reverse order of allocs/inits.
	 * At this point there should be no competing threads anymore.
	 */

	scsi_fm_fini(devp);

	/*
	 * Deallocate memory for SCSI FMA.
	 */
	kmem_free(un->un_fm_private, sizeof (struct sd_fm_internal));

	/*
	 * Unregister and free device id if it was not registered
	 * by the transport.
	 */
	if (un->un_f_devid_transport_defined == FALSE)
		ddi_devid_unregister(devi);

	/*
	 * free the devid structure if allocated before (by ddi_devid_init()
	 * or ddi_devid_get()).
	 */
	if (un->un_devid) {
		ddi_devid_free(un->un_devid);
		un->un_devid = NULL;
	}

	/*
	 * Destroy wmap cache if it exists.
	 */
	if (un->un_wm_cache != NULL) {
		kmem_cache_destroy(un->un_wm_cache);
		un->un_wm_cache = NULL;
	}

	/*
	 * kstat cleanup is done in detach for all device types (4363169).
	 * We do not want to fail detach if the device kstats are not deleted
	 * since there is a confusion about the devo_refcnt for the device.
	 * We just delete the kstats and let detach complete successfully.
	 */
	if (un->un_stats != NULL) {
		kstat_delete(un->un_stats);
		un->un_stats = NULL;
	}
	if (un->un_errstats != NULL) {
		kstat_delete(un->un_errstats);
		un->un_errstats = NULL;
	}

	/* Remove partition stats */
	if (un->un_f_pkstats_enabled) {
		for (i = 0; i < NSDMAP; i++) {
			if (un->un_pstats[i] != NULL) {
				kstat_delete(un->un_pstats[i]);
				un->un_pstats[i] = NULL;
			}
		}
	}

	/* Remove xbuf registration */
	ddi_xbuf_attr_unregister_devinfo(un->un_xbuf_attr, devi);
	ddi_xbuf_attr_destroy(un->un_xbuf_attr);

	/* Remove driver properties */
	ddi_prop_remove_all(devi);

	mutex_destroy(&un->un_pm_mutex);
	cv_destroy(&un->un_pm_busy_cv);

	cv_destroy(&un->un_wcc_cv);

	/* Open/close semaphore */
	sema_destroy(&un->un_semoclose);

	/* Removable media condvar. */
	cv_destroy(&un->un_state_cv);

	/* Suspend/resume condvar. */
	cv_destroy(&un->un_suspend_cv);
	cv_destroy(&un->un_disk_busy_cv);

	sd_free_rqs(un);

	/* Free up soft state */
	devp->sd_private = NULL;

	bzero(un, sizeof (struct sd_lun));
#ifndef XPV_HVM_DRIVER
	ddi_soft_state_free(sd_state, instance);
#endif /* !XPV_HVM_DRIVER */

	mutex_exit(&sd_detach_mutex);

	/* This frees up the INQUIRY data associated with the device. */
	scsi_unprobe(devp);

	/*
	 * After successfully detaching an instance, we update the information
	 * of how many luns have been attached in the relative target and
	 * controller for parallel SCSI. This information is used when sd tries
	 * to set the tagged queuing capability in HBA.
	 * Since un has been released, we can't use SD_IS_PARALLEL_SCSI(un) to
	 * check if the device is parallel SCSI. However, we don't need to
	 * check here because we've already checked during attach. No device
	 * that is not parallel SCSI is in the chain.
	 */
	if ((tgt >= 0) && (tgt < NTARGETS_WIDE)) {
		sd_scsi_update_lun_on_target(pdip, tgt, SD_SCSI_LUN_DETACH);
	}

	return (DDI_SUCCESS);

err_notclosed:
	mutex_exit(SD_MUTEX(un));

err_stillbusy:
	_NOTE(NO_COMPETING_THREADS_NOW);

err_remove_event:
	mutex_enter(&sd_detach_mutex);
	un->un_detach_count--;
	mutex_exit(&sd_detach_mutex);

	SD_TRACE(SD_LOG_ATTACH_DETACH, un, "sd_unit_detach: exit failure\n");
	return (DDI_FAILURE);
}


/*
 *    Function: sd_create_errstats
 *
 * Description: This routine instantiates the device error stats.
 *
 *		Note: During attach the stats are instantiated first so they are
 *		available for attach-time routines that utilize the driver
 *		iopath to send commands to the device. The stats are initialized
 *		separately so data obtained during some attach-time routines is
 *		available. (4362483)
 *
 *   Arguments: un - driver soft state (unit) structure
 *		instance - driver instance
 *
 *     Context: Kernel thread context
 */

static void
sd_create_errstats(struct sd_lun *un, int instance)
{
	struct	sd_errstats	*stp;
	char	kstatmodule_err[KSTAT_STRLEN];
	char	kstatname[KSTAT_STRLEN];
	int	ndata = (sizeof (struct sd_errstats) / sizeof (kstat_named_t));

	ASSERT(un != NULL);

	if (un->un_errstats != NULL) {
		return;
	}

	(void) snprintf(kstatmodule_err, sizeof (kstatmodule_err),
	    "%serr", sd_label);
	(void) snprintf(kstatname, sizeof (kstatname),
	    "%s%d,err", sd_label, instance);

	un->un_errstats = kstat_create(kstatmodule_err, instance, kstatname,
	    "device_error", KSTAT_TYPE_NAMED, ndata, KSTAT_FLAG_PERSISTENT);

	if (un->un_errstats == NULL) {
		SD_ERROR(SD_LOG_ATTACH_DETACH, un,
		    "sd_create_errstats: Failed kstat_create\n");
		return;
	}

	stp = (struct sd_errstats *)un->un_errstats->ks_data;
	kstat_named_init(&stp->sd_softerrs,	"Soft Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sd_harderrs,	"Hard Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sd_transerrs,	"Transport Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sd_vid,		"Vendor",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&stp->sd_pid,		"Product",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&stp->sd_revision,	"Revision",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&stp->sd_serial,	"Serial No",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&stp->sd_capacity,	"Size",
	    KSTAT_DATA_ULONGLONG);
	kstat_named_init(&stp->sd_rq_media_err,	"Media Error",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sd_rq_ntrdy_err,	"Device Not Ready",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sd_rq_nodev_err,	"No Device",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sd_rq_recov_err,	"Recoverable",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sd_rq_illrq_err,	"Illegal Request",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sd_rq_pfa_err,	"Predictive Failure Analysis",
	    KSTAT_DATA_UINT32);

	un->un_errstats->ks_private = un;
	un->un_errstats->ks_update  = nulldev;

	kstat_install(un->un_errstats);
}


/*
 *    Function: sd_set_errstats
 *
 * Description: This routine sets the value of the vendor id, product id,
 *		revision, serial number, and capacity device error stats.
 *
 *		Note: During attach the stats are instantiated first so they are
 *		available for attach-time routines that utilize the driver
 *		iopath to send commands to the device. The stats are initialized
 *		separately so data obtained during some attach-time routines is
 *		available. (4362483)
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 *     Context: Kernel thread context
 */

static void
sd_set_errstats(struct sd_lun *un)
{
	struct	sd_errstats	*stp;
	char 			*sn;

	ASSERT(un != NULL);
	ASSERT(un->un_errstats != NULL);
	stp = (struct sd_errstats *)un->un_errstats->ks_data;
	ASSERT(stp != NULL);
	(void) strncpy(stp->sd_vid.value.c, un->un_sd->sd_inq->inq_vid, 8);
	(void) strncpy(stp->sd_pid.value.c, un->un_sd->sd_inq->inq_pid, 16);
	(void) strncpy(stp->sd_revision.value.c,
	    un->un_sd->sd_inq->inq_revision, 4);

	/*
	 * All the errstats are persistent across detach/attach,
	 * so reset all the errstats here in case of the hot
	 * replacement of disk drives, except for not changed
	 * Sun qualified drives.
	 */
	if ((bcmp(&SD_INQUIRY(un)->inq_pid[9], "SUN", 3) != 0) ||
	    (bcmp(&SD_INQUIRY(un)->inq_serial, stp->sd_serial.value.c,
	    sizeof (SD_INQUIRY(un)->inq_serial)) != 0)) {
		stp->sd_softerrs.value.ui32 = 0;
		stp->sd_harderrs.value.ui32 = 0;
		stp->sd_transerrs.value.ui32 = 0;
		stp->sd_rq_media_err.value.ui32 = 0;
		stp->sd_rq_ntrdy_err.value.ui32 = 0;
		stp->sd_rq_nodev_err.value.ui32 = 0;
		stp->sd_rq_recov_err.value.ui32 = 0;
		stp->sd_rq_illrq_err.value.ui32 = 0;
		stp->sd_rq_pfa_err.value.ui32 = 0;
	}

	/*
	 * Set the "Serial No" kstat for Sun qualified drives (indicated by
	 * "SUN" in bytes 25-27 of the inquiry data (bytes 9-11 of the pid)
	 * (4376302))
	 */
	if (bcmp(&SD_INQUIRY(un)->inq_pid[9], "SUN", 3) == 0) {
		bcopy(&SD_INQUIRY(un)->inq_serial, stp->sd_serial.value.c,
		    sizeof (SD_INQUIRY(un)->inq_serial));
	} else {
		/*
		 * Set the "Serial No" kstat for non-Sun qualified drives
		 */
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, SD_DEVINFO(un),
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
		    INQUIRY_SERIAL_NO, &sn) == DDI_SUCCESS) {
			(void) strlcpy(stp->sd_serial.value.c, sn,
			    sizeof (stp->sd_serial.value.c));
			ddi_prop_free(sn);
		}
	}

	if (un->un_f_blockcount_is_valid != TRUE) {
		/*
		 * Set capacity error stat to 0 for no media. This ensures
		 * a valid capacity is displayed in response to 'iostat -E'
		 * when no media is present in the device.
		 */
		stp->sd_capacity.value.ui64 = 0;
	} else {
		/*
		 * Multiply un_blockcount by un->un_sys_blocksize to get
		 * capacity.
		 *
		 * Note: for non-512 blocksize devices "un_blockcount" has been
		 * "scaled" in sd_send_scsi_READ_CAPACITY by multiplying by
		 * (un_tgt_blocksize / un->un_sys_blocksize).
		 */
		stp->sd_capacity.value.ui64 = (uint64_t)
		    ((uint64_t)un->un_blockcount * un->un_sys_blocksize);
	}
}


/*
 *    Function: sd_set_pstats
 *
 * Description: This routine instantiates and initializes the partition
 *              stats for each partition with more than zero blocks.
 *		(4363169)
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 *     Context: Kernel thread context
 */

static void
sd_set_pstats(struct sd_lun *un)
{
	char	kstatname[KSTAT_STRLEN];
	int	instance;
	int	i;
	diskaddr_t	nblks = 0;
	char	*partname = NULL;

	ASSERT(un != NULL);

	instance = ddi_get_instance(SD_DEVINFO(un));

	/* Note:x86: is this a VTOC8/VTOC16 difference? */
	for (i = 0; i < NSDMAP; i++) {

		if (cmlb_partinfo(un->un_cmlbhandle, i,
		    &nblks, NULL, &partname, NULL, (void *)SD_PATH_DIRECT) != 0)
			continue;
		mutex_enter(SD_MUTEX(un));

		if ((un->un_pstats[i] == NULL) &&
		    (nblks != 0)) {

			(void) snprintf(kstatname, sizeof (kstatname),
			    "%s%d,%s", sd_label, instance,
			    partname);

			un->un_pstats[i] = kstat_create(sd_label,
			    instance, kstatname, "partition", KSTAT_TYPE_IO,
			    1, KSTAT_FLAG_PERSISTENT);
			if (un->un_pstats[i] != NULL) {
				un->un_pstats[i]->ks_lock = SD_MUTEX(un);
				kstat_install(un->un_pstats[i]);
			}
		}
		mutex_exit(SD_MUTEX(un));
	}
}


#if (defined(__fibre))
/*
 *    Function: sd_init_event_callbacks
 *
 * Description: This routine initializes the insertion and removal event
 *		callbacks. (fibre only)
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 *     Context: Kernel thread context
 */

static void
sd_init_event_callbacks(struct sd_lun *un)
{
	ASSERT(un != NULL);

	if ((un->un_insert_event == NULL) &&
	    (ddi_get_eventcookie(SD_DEVINFO(un), FCAL_INSERT_EVENT,
	    &un->un_insert_event) == DDI_SUCCESS)) {
		/*
		 * Add the callback for an insertion event
		 */
		(void) ddi_add_event_handler(SD_DEVINFO(un),
		    un->un_insert_event, sd_event_callback, (void *)un,
		    &(un->un_insert_cb_id));
	}

	if ((un->un_remove_event == NULL) &&
	    (ddi_get_eventcookie(SD_DEVINFO(un), FCAL_REMOVE_EVENT,
	    &un->un_remove_event) == DDI_SUCCESS)) {
		/*
		 * Add the callback for a removal event
		 */
		(void) ddi_add_event_handler(SD_DEVINFO(un),
		    un->un_remove_event, sd_event_callback, (void *)un,
		    &(un->un_remove_cb_id));
	}
}


/*
 *    Function: sd_event_callback
 *
 * Description: This routine handles insert/remove events (photon). The
 *		state is changed to OFFLINE which can be used to supress
 *		error msgs. (fibre only)
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 *     Context: Callout thread context
 */
/* ARGSUSED */
static void
sd_event_callback(dev_info_t *dip, ddi_eventcookie_t event, void *arg,
    void *bus_impldata)
{
	struct sd_lun *un = (struct sd_lun *)arg;

	_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_insert_event));
	if (event == un->un_insert_event) {
		SD_TRACE(SD_LOG_COMMON, un, "sd_event_callback: insert event");
		mutex_enter(SD_MUTEX(un));
		if (un->un_state == SD_STATE_OFFLINE) {
			if (un->un_last_state != SD_STATE_SUSPENDED) {
				un->un_state = un->un_last_state;
			} else {
				/*
				 * We have gone through SUSPEND/RESUME while
				 * we were offline. Restore the last state
				 */
				un->un_state = un->un_save_state;
			}
		}
		mutex_exit(SD_MUTEX(un));

	_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_remove_event));
	} else if (event == un->un_remove_event) {
		SD_TRACE(SD_LOG_COMMON, un, "sd_event_callback: remove event");
		mutex_enter(SD_MUTEX(un));
		/*
		 * We need to handle an event callback that occurs during
		 * the suspend operation, since we don't prevent it.
		 */
		if (un->un_state != SD_STATE_OFFLINE) {
			if (un->un_state != SD_STATE_SUSPENDED) {
				New_state(un, SD_STATE_OFFLINE);
			} else {
				un->un_last_state = SD_STATE_OFFLINE;
			}
		}
		mutex_exit(SD_MUTEX(un));
	} else {
		scsi_log(SD_DEVINFO(un), sd_label, CE_NOTE,
		    "!Unknown event\n");
	}

}
#endif

/*
 *    Function: sd_cache_control()
 *
 * Description: This routine is the driver entry point for setting
 *		read and write caching by modifying the WCE (write cache
 *		enable) and RCD (read cache disable) bits of mode
 *		page 8 (MODEPAGE_CACHING).
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		rcd_flag - flag for controlling the read cache
 *		wce_flag - flag for controlling the write cache
 *
 * Return Code: EIO
 *		code returned by sd_send_scsi_MODE_SENSE and
 *		sd_send_scsi_MODE_SELECT
 *
 *     Context: Kernel Thread
 */

static int
sd_cache_control(sd_ssc_t *ssc, int rcd_flag, int wce_flag)
{
	struct mode_caching	*mode_caching_page;
	uchar_t			*header;
	size_t			buflen;
	int			hdrlen;
	int			bd_len;
	int			rval = 0;
	struct mode_header_grp2	*mhp;
	struct sd_lun		*un;
	int			status;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	/*
	 * Do a test unit ready, otherwise a mode sense may not work if this
	 * is the first command sent to the device after boot.
	 */
	status = sd_send_scsi_TEST_UNIT_READY(ssc, 0);
	if (status != 0)
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	if (un->un_f_cfg_is_atapi == TRUE) {
		hdrlen = MODE_HEADER_LENGTH_GRP2;
	} else {
		hdrlen = MODE_HEADER_LENGTH;
	}

	/*
	 * Allocate memory for the retrieved mode page and its headers.  Set
	 * a pointer to the page itself.  Use mode_cache_scsi3 to insure
	 * we get all of the mode sense data otherwise, the mode select
	 * will fail.  mode_cache_scsi3 is a superset of mode_caching.
	 */
	buflen = hdrlen + MODE_BLK_DESC_LENGTH +
	    sizeof (struct mode_cache_scsi3);

	header = kmem_zalloc(buflen, KM_SLEEP);

	/* Get the information from the device. */
	if (un->un_f_cfg_is_atapi == TRUE) {
		rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP1, header, buflen,
		    MODEPAGE_CACHING, SD_PATH_DIRECT);
	} else {
		rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP0, header, buflen,
		    MODEPAGE_CACHING, SD_PATH_DIRECT);
	}

	if (rval != 0) {
		SD_ERROR(SD_LOG_IOCTL_RMMEDIA, un,
		    "sd_cache_control: Mode Sense Failed\n");
		goto mode_sense_failed;
	}

	/*
	 * Determine size of Block Descriptors in order to locate
	 * the mode page data. ATAPI devices return 0, SCSI devices
	 * should return MODE_BLK_DESC_LENGTH.
	 */
	if (un->un_f_cfg_is_atapi == TRUE) {
		mhp	= (struct mode_header_grp2 *)header;
		bd_len  = (mhp->bdesc_length_hi << 8) | mhp->bdesc_length_lo;
	} else {
		bd_len  = ((struct mode_header *)header)->bdesc_length;
	}

	if (bd_len > MODE_BLK_DESC_LENGTH) {
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, 0,
		    "sd_cache_control: Mode Sense returned invalid block "
		    "descriptor length\n");
		rval = EIO;
		goto mode_sense_failed;
	}

	mode_caching_page = (struct mode_caching *)(header + hdrlen + bd_len);
	if (mode_caching_page->mode_page.code != MODEPAGE_CACHING) {
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, SD_LOG_COMMON,
		    "sd_cache_control: Mode Sense caching page code mismatch "
		    "%d\n", mode_caching_page->mode_page.code);
		rval = EIO;
		goto mode_sense_failed;
	}

	/* Check the relevant bits on successful mode sense. */
	if ((mode_caching_page->rcd && rcd_flag == SD_CACHE_ENABLE) ||
	    (!mode_caching_page->rcd && rcd_flag == SD_CACHE_DISABLE) ||
	    (mode_caching_page->wce && wce_flag == SD_CACHE_DISABLE) ||
	    (!mode_caching_page->wce && wce_flag == SD_CACHE_ENABLE)) {

		size_t sbuflen;
		uchar_t save_pg;

		/*
		 * Construct select buffer length based on the
		 * length of the sense data returned.
		 */
		sbuflen =  hdrlen + bd_len +
		    sizeof (struct mode_page) +
		    (int)mode_caching_page->mode_page.length;

		/*
		 * Set the caching bits as requested.
		 */
		if (rcd_flag == SD_CACHE_ENABLE)
			mode_caching_page->rcd = 0;
		else if (rcd_flag == SD_CACHE_DISABLE)
			mode_caching_page->rcd = 1;

		if (wce_flag == SD_CACHE_ENABLE)
			mode_caching_page->wce = 1;
		else if (wce_flag == SD_CACHE_DISABLE)
			mode_caching_page->wce = 0;

		/*
		 * Save the page if the mode sense says the
		 * drive supports it.
		 */
		save_pg = mode_caching_page->mode_page.ps ?
		    SD_SAVE_PAGE : SD_DONTSAVE_PAGE;

		/* Clear reserved bits before mode select. */
		mode_caching_page->mode_page.ps = 0;

		/*
		 * Clear out mode header for mode select.
		 * The rest of the retrieved page will be reused.
		 */
		bzero(header, hdrlen);

		if (un->un_f_cfg_is_atapi == TRUE) {
			mhp = (struct mode_header_grp2 *)header;
			mhp->bdesc_length_hi = bd_len >> 8;
			mhp->bdesc_length_lo = (uchar_t)bd_len & 0xff;
		} else {
			((struct mode_header *)header)->bdesc_length = bd_len;
		}

		sd_ssc_assessment(ssc, SD_FMT_IGNORE);

		/* Issue mode select to change the cache settings */
		if (un->un_f_cfg_is_atapi == TRUE) {
			rval = sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP1, header,
			    sbuflen, save_pg, SD_PATH_DIRECT);
		} else {
			rval = sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP0, header,
			    sbuflen, save_pg, SD_PATH_DIRECT);
		}

	}


mode_sense_failed:

	kmem_free(header, buflen);

	if (rval != 0) {
		if (rval == EIO)
			sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
		else
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}
	return (rval);
}


/*
 *    Function: sd_get_write_cache_enabled()
 *
 * Description: This routine is the driver entry point for determining if
 *		write caching is enabled.  It examines the WCE (write cache
 *		enable) bits of mode page 8 (MODEPAGE_CACHING).
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		is_enabled - pointer to int where write cache enabled state
 *		is returned (non-zero -> write cache enabled)
 *
 *
 * Return Code: EIO
 *		code returned by sd_send_scsi_MODE_SENSE
 *
 *     Context: Kernel Thread
 *
 * NOTE: If ioctl is added to disable write cache, this sequence should
 * be followed so that no locking is required for accesses to
 * un->un_f_write_cache_enabled:
 * 	do mode select to clear wce
 * 	do synchronize cache to flush cache
 * 	set un->un_f_write_cache_enabled = FALSE
 *
 * Conversely, an ioctl to enable the write cache should be done
 * in this order:
 * 	set un->un_f_write_cache_enabled = TRUE
 * 	do mode select to set wce
 */

static int
sd_get_write_cache_enabled(sd_ssc_t *ssc, int *is_enabled)
{
	struct mode_caching	*mode_caching_page;
	uchar_t			*header;
	size_t			buflen;
	int			hdrlen;
	int			bd_len;
	int			rval = 0;
	struct sd_lun		*un;
	int			status;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(is_enabled != NULL);

	/* in case of error, flag as enabled */
	*is_enabled = TRUE;

	/*
	 * Do a test unit ready, otherwise a mode sense may not work if this
	 * is the first command sent to the device after boot.
	 */
	status = sd_send_scsi_TEST_UNIT_READY(ssc, 0);

	if (status != 0)
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);

	if (un->un_f_cfg_is_atapi == TRUE) {
		hdrlen = MODE_HEADER_LENGTH_GRP2;
	} else {
		hdrlen = MODE_HEADER_LENGTH;
	}

	/*
	 * Allocate memory for the retrieved mode page and its headers.  Set
	 * a pointer to the page itself.
	 */
	buflen = hdrlen + MODE_BLK_DESC_LENGTH + sizeof (struct mode_caching);
	header = kmem_zalloc(buflen, KM_SLEEP);

	/* Get the information from the device. */
	if (un->un_f_cfg_is_atapi == TRUE) {
		rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP1, header, buflen,
		    MODEPAGE_CACHING, SD_PATH_DIRECT);
	} else {
		rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP0, header, buflen,
		    MODEPAGE_CACHING, SD_PATH_DIRECT);
	}

	if (rval != 0) {
		SD_ERROR(SD_LOG_IOCTL_RMMEDIA, un,
		    "sd_get_write_cache_enabled: Mode Sense Failed\n");
		goto mode_sense_failed;
	}

	/*
	 * Determine size of Block Descriptors in order to locate
	 * the mode page data. ATAPI devices return 0, SCSI devices
	 * should return MODE_BLK_DESC_LENGTH.
	 */
	if (un->un_f_cfg_is_atapi == TRUE) {
		struct mode_header_grp2	*mhp;
		mhp	= (struct mode_header_grp2 *)header;
		bd_len  = (mhp->bdesc_length_hi << 8) | mhp->bdesc_length_lo;
	} else {
		bd_len  = ((struct mode_header *)header)->bdesc_length;
	}

	if (bd_len > MODE_BLK_DESC_LENGTH) {
		/* FMA should make upset complain here */
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, 0,
		    "sd_get_write_cache_enabled: Mode Sense returned invalid "
		    "block descriptor length\n");
		rval = EIO;
		goto mode_sense_failed;
	}

	mode_caching_page = (struct mode_caching *)(header + hdrlen + bd_len);
	if (mode_caching_page->mode_page.code != MODEPAGE_CACHING) {
		/* FMA could make upset complain here */
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, SD_LOG_COMMON,
		    "sd_get_write_cache_enabled: Mode Sense caching page "
		    "code mismatch %d\n", mode_caching_page->mode_page.code);
		rval = EIO;
		goto mode_sense_failed;
	}
	*is_enabled = mode_caching_page->wce;

mode_sense_failed:
	if (rval == 0) {
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);
	} else if (rval == EIO) {
		/*
		 * Some disks do not support mode sense(6), we
		 * should ignore this kind of error(sense key is
		 * 0x5 - illegal request).
		 */
		uint8_t *sensep;
		int senlen;

		sensep = (uint8_t *)ssc->ssc_uscsi_cmd->uscsi_rqbuf;
		senlen = (int)(ssc->ssc_uscsi_cmd->uscsi_rqlen -
		    ssc->ssc_uscsi_cmd->uscsi_rqresid);

		if (senlen > 0 &&
		    scsi_sense_key(sensep) == KEY_ILLEGAL_REQUEST) {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE_COMPROMISE);
		} else {
			sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
		}
	} else {
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}
	kmem_free(header, buflen);
	return (rval);
}

/*
 *    Function: sd_get_nv_sup()
 *
 * Description: This routine is the driver entry point for
 * determining whether non-volatile cache is supported. This
 * determination process works as follows:
 *
 * 1. sd first queries sd.conf on whether
 * suppress_cache_flush bit is set for this device.
 *
 * 2. if not there, then queries the internal disk table.
 *
 * 3. if either sd.conf or internal disk table specifies
 * cache flush be suppressed, we don't bother checking
 * NV_SUP bit.
 *
 * If SUPPRESS_CACHE_FLUSH bit is not set to 1, sd queries
 * the optional INQUIRY VPD page 0x86. If the device
 * supports VPD page 0x86, sd examines the NV_SUP
 * (non-volatile cache support) bit in the INQUIRY VPD page
 * 0x86:
 *   o If NV_SUP bit is set, sd assumes the device has a
 *   non-volatile cache and set the
 *   un_f_sync_nv_supported to TRUE.
 *   o Otherwise cache is not non-volatile,
 *   un_f_sync_nv_supported is set to FALSE.
 *
 * Arguments: un - driver soft state (unit) structure
 *
 * Return Code:
 *
 *     Context: Kernel Thread
 */

static void
sd_get_nv_sup(sd_ssc_t *ssc)
{
	int		rval		= 0;
	uchar_t		*inq86		= NULL;
	size_t		inq86_len	= MAX_INQUIRY_SIZE;
	size_t		inq86_resid	= 0;
	struct		dk_callback *dkc;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	mutex_enter(SD_MUTEX(un));

	/*
	 * Be conservative on the device's support of
	 * SYNC_NV bit: un_f_sync_nv_supported is
	 * initialized to be false.
	 */
	un->un_f_sync_nv_supported = FALSE;

	/*
	 * If either sd.conf or internal disk table
	 * specifies cache flush be suppressed, then
	 * we don't bother checking NV_SUP bit.
	 */
	if (un->un_f_suppress_cache_flush == TRUE) {
		mutex_exit(SD_MUTEX(un));
		return;
	}

	if (sd_check_vpd_page_support(ssc) == 0 &&
	    un->un_vpd_page_mask & SD_VPD_EXTENDED_DATA_PG) {
		mutex_exit(SD_MUTEX(un));
		/* collect page 86 data if available */
		inq86 = kmem_zalloc(inq86_len, KM_SLEEP);

		rval = sd_send_scsi_INQUIRY(ssc, inq86, inq86_len,
		    0x01, 0x86, &inq86_resid);

		if (rval == 0 && (inq86_len - inq86_resid > 6)) {
			SD_TRACE(SD_LOG_COMMON, un,
			    "sd_get_nv_sup: \
			    successfully get VPD page: %x \
			    PAGE LENGTH: %x BYTE 6: %x\n",
			    inq86[1], inq86[3], inq86[6]);

			mutex_enter(SD_MUTEX(un));
			/*
			 * check the value of NV_SUP bit: only if the device
			 * reports NV_SUP bit to be 1, the
			 * un_f_sync_nv_supported bit will be set to true.
			 */
			if (inq86[6] & SD_VPD_NV_SUP) {
				un->un_f_sync_nv_supported = TRUE;
			}
			mutex_exit(SD_MUTEX(un));
		} else if (rval != 0) {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		}

		kmem_free(inq86, inq86_len);
	} else {
		mutex_exit(SD_MUTEX(un));
	}

	/*
	 * Send a SYNC CACHE command to check whether
	 * SYNC_NV bit is supported. This command should have
	 * un_f_sync_nv_supported set to correct value.
	 */
	mutex_enter(SD_MUTEX(un));
	if (un->un_f_sync_nv_supported) {
		mutex_exit(SD_MUTEX(un));
		dkc = kmem_zalloc(sizeof (struct dk_callback), KM_SLEEP);
		dkc->dkc_flag = FLUSH_VOLATILE;
		(void) sd_send_scsi_SYNCHRONIZE_CACHE(un, dkc);

		/*
		 * Send a TEST UNIT READY command to the device. This should
		 * clear any outstanding UNIT ATTENTION that may be present.
		 */
		rval = sd_send_scsi_TEST_UNIT_READY(ssc, SD_DONT_RETRY_TUR);
		if (rval != 0)
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);

		kmem_free(dkc, sizeof (struct dk_callback));
	} else {
		mutex_exit(SD_MUTEX(un));
	}

	SD_TRACE(SD_LOG_COMMON, un, "sd_get_nv_sup: \
	    un_f_suppress_cache_flush is set to %d\n",
	    un->un_f_suppress_cache_flush);
}

/*
 *    Function: sd_make_device
 *
 * Description: Utility routine to return the Solaris device number from
 *		the data in the device's dev_info structure.
 *
 * Return Code: The Solaris device number
 *
 *     Context: Any
 */

static dev_t
sd_make_device(dev_info_t *devi)
{
	return (makedevice(ddi_driver_major(devi),
	    ddi_get_instance(devi) << SDUNIT_SHIFT));
}


/*
 *    Function: sd_pm_entry
 *
 * Description: Called at the start of a new command to manage power
 *		and busy status of a device. This includes determining whether
 *		the current power state of the device is sufficient for
 *		performing the command or whether it must be changed.
 *		The PM framework is notified appropriately.
 *		Only with a return status of DDI_SUCCESS will the
 *		component be busy to the framework.
 *
 *		All callers of sd_pm_entry must check the return status
 *		and only call sd_pm_exit it it was DDI_SUCCESS. A status
 *		of DDI_FAILURE indicates the device failed to power up.
 *		In this case un_pm_count has been adjusted so the result
 *		on exit is still powered down, ie. count is less than 0.
 *		Calling sd_pm_exit with this count value hits an ASSERT.
 *
 * Return Code: DDI_SUCCESS or DDI_FAILURE
 *
 *     Context: Kernel thread context.
 */

static int
sd_pm_entry(struct sd_lun *un)
{
	int return_status = DDI_SUCCESS;

	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(!mutex_owned(&un->un_pm_mutex));

	SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_entry: entry\n");

	if (un->un_f_pm_is_enabled == FALSE) {
		SD_TRACE(SD_LOG_IO_PM, un,
		    "sd_pm_entry: exiting, PM not enabled\n");
		return (return_status);
	}

	/*
	 * Just increment a counter if PM is enabled. On the transition from
	 * 0 ==> 1, mark the device as busy.  The iodone side will decrement
	 * the count with each IO and mark the device as idle when the count
	 * hits 0.
	 *
	 * If the count is less than 0 the device is powered down. If a powered
	 * down device is successfully powered up then the count must be
	 * incremented to reflect the power up. Note that it'll get incremented
	 * a second time to become busy.
	 *
	 * Because the following has the potential to change the device state
	 * and must release the un_pm_mutex to do so, only one thread can be
	 * allowed through at a time.
	 */

	mutex_enter(&un->un_pm_mutex);
	while (un->un_pm_busy == TRUE) {
		cv_wait(&un->un_pm_busy_cv, &un->un_pm_mutex);
	}
	un->un_pm_busy = TRUE;

	if (un->un_pm_count < 1) {

		SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_entry: busy component\n");

		/*
		 * Indicate we are now busy so the framework won't attempt to
		 * power down the device. This call will only fail if either
		 * we passed a bad component number or the device has no
		 * components. Neither of these should ever happen.
		 */
		mutex_exit(&un->un_pm_mutex);
		return_status = pm_busy_component(SD_DEVINFO(un), 0);
		ASSERT(return_status == DDI_SUCCESS);

		mutex_enter(&un->un_pm_mutex);

		if (un->un_pm_count < 0) {
			mutex_exit(&un->un_pm_mutex);

			SD_TRACE(SD_LOG_IO_PM, un,
			    "sd_pm_entry: power up component\n");

			/*
			 * pm_raise_power will cause sdpower to be called
			 * which brings the device power level to the
			 * desired state, If successful, un_pm_count and
			 * un_power_level will be updated appropriately.
			 */
			return_status = pm_raise_power(SD_DEVINFO(un), 0,
			    SD_PM_STATE_ACTIVE(un));

			mutex_enter(&un->un_pm_mutex);

			if (return_status != DDI_SUCCESS) {
				/*
				 * Power up failed.
				 * Idle the device and adjust the count
				 * so the result on exit is that we're
				 * still powered down, ie. count is less than 0.
				 */
				SD_TRACE(SD_LOG_IO_PM, un,
				    "sd_pm_entry: power up failed,"
				    " idle the component\n");

				(void) pm_idle_component(SD_DEVINFO(un), 0);
				un->un_pm_count--;
			} else {
				/*
				 * Device is powered up, verify the
				 * count is non-negative.
				 * This is debug only.
				 */
				ASSERT(un->un_pm_count == 0);
			}
		}

		if (return_status == DDI_SUCCESS) {
			/*
			 * For performance, now that the device has been tagged
			 * as busy, and it's known to be powered up, update the
			 * chain types to use jump tables that do not include
			 * pm. This significantly lowers the overhead and
			 * therefore improves performance.
			 */

			mutex_exit(&un->un_pm_mutex);
			mutex_enter(SD_MUTEX(un));
			SD_TRACE(SD_LOG_IO_PM, un,
			    "sd_pm_entry: changing uscsi_chain_type from %d\n",
			    un->un_uscsi_chain_type);

			if (un->un_f_non_devbsize_supported) {
				un->un_buf_chain_type =
				    SD_CHAIN_INFO_RMMEDIA_NO_PM;
			} else {
				un->un_buf_chain_type =
				    SD_CHAIN_INFO_DISK_NO_PM;
			}
			un->un_uscsi_chain_type = SD_CHAIN_INFO_USCSI_CMD_NO_PM;

			SD_TRACE(SD_LOG_IO_PM, un,
			    "             changed  uscsi_chain_type to   %d\n",
			    un->un_uscsi_chain_type);
			mutex_exit(SD_MUTEX(un));
			mutex_enter(&un->un_pm_mutex);

			if (un->un_pm_idle_timeid == NULL) {
				/* 300 ms. */
				un->un_pm_idle_timeid =
				    timeout(sd_pm_idletimeout_handler, un,
				    (drv_usectohz((clock_t)300000)));
				/*
				 * Include an extra call to busy which keeps the
				 * device busy with-respect-to the PM layer
				 * until the timer fires, at which time it'll
				 * get the extra idle call.
				 */
				(void) pm_busy_component(SD_DEVINFO(un), 0);
			}
		}
	}
	un->un_pm_busy = FALSE;
	/* Next... */
	cv_signal(&un->un_pm_busy_cv);

	un->un_pm_count++;

	SD_TRACE(SD_LOG_IO_PM, un,
	    "sd_pm_entry: exiting, un_pm_count = %d\n", un->un_pm_count);

	mutex_exit(&un->un_pm_mutex);

	return (return_status);
}


/*
 *    Function: sd_pm_exit
 *
 * Description: Called at the completion of a command to manage busy
 *		status for the device. If the device becomes idle the
 *		PM framework is notified.
 *
 *     Context: Kernel thread context
 */

static void
sd_pm_exit(struct sd_lun *un)
{
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(!mutex_owned(&un->un_pm_mutex));

	SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_exit: entry\n");

	/*
	 * After attach the following flag is only read, so don't
	 * take the penalty of acquiring a mutex for it.
	 */
	if (un->un_f_pm_is_enabled == TRUE) {

		mutex_enter(&un->un_pm_mutex);
		un->un_pm_count--;

		SD_TRACE(SD_LOG_IO_PM, un,
		    "sd_pm_exit: un_pm_count = %d\n", un->un_pm_count);

		ASSERT(un->un_pm_count >= 0);
		if (un->un_pm_count == 0) {
			mutex_exit(&un->un_pm_mutex);

			SD_TRACE(SD_LOG_IO_PM, un,
			    "sd_pm_exit: idle component\n");

			(void) pm_idle_component(SD_DEVINFO(un), 0);

		} else {
			mutex_exit(&un->un_pm_mutex);
		}
	}

	SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_exit: exiting\n");
}


/*
 *    Function: sdopen
 *
 * Description: Driver's open(9e) entry point function.
 *
 *   Arguments: dev_i   - pointer to device number
 *		flag    - how to open file (FEXCL, FNDELAY, FREAD, FWRITE)
 *		otyp    - open type (OTYP_BLK, OTYP_CHR, OTYP_LYR)
 *		cred_p  - user credential pointer
 *
 * Return Code: EINVAL
 *		ENXIO
 *		EIO
 *		EROFS
 *		EBUSY
 *
 *     Context: Kernel thread context
 */
/* ARGSUSED */
static int
sdopen(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	struct sd_lun	*un;
	int		nodelay;
	int		part;
	uint64_t	partmask;
	int		instance;
	dev_t		dev;
	int		rval = EIO;
	diskaddr_t	nblks = 0;
	diskaddr_t	label_cap;

	/* Validate the open type */
	if (otyp >= OTYPCNT) {
		return (EINVAL);
	}

	dev = *dev_p;
	instance = SDUNIT(dev);
	mutex_enter(&sd_detach_mutex);

	/*
	 * Fail the open if there is no softstate for the instance, or
	 * if another thread somewhere is trying to detach the instance.
	 */
	if (((un = ddi_get_soft_state(sd_state, instance)) == NULL) ||
	    (un->un_detach_count != 0)) {
		mutex_exit(&sd_detach_mutex);
		/*
		 * The probe cache only needs to be cleared when open (9e) fails
		 * with ENXIO (4238046).
		 */
		/*
		 * un-conditionally clearing probe cache is ok with
		 * separate sd/ssd binaries
		 * x86 platform can be an issue with both parallel
		 * and fibre in 1 binary
		 */
		sd_scsi_clear_probe_cache();
		return (ENXIO);
	}

	/*
	 * The un_layer_count is to prevent another thread in specfs from
	 * trying to detach the instance, which can happen when we are
	 * called from a higher-layer driver instead of thru specfs.
	 * This will not be needed when DDI provides a layered driver
	 * interface that allows specfs to know that an instance is in
	 * use by a layered driver & should not be detached.
	 *
	 * Note: the semantics for layered driver opens are exactly one
	 * close for every open.
	 */
	if (otyp == OTYP_LYR) {
		un->un_layer_count++;
	}

	/*
	 * Keep a count of the current # of opens in progress. This is because
	 * some layered drivers try to call us as a regular open. This can
	 * cause problems that we cannot prevent, however by keeping this count
	 * we can at least keep our open and detach routines from racing against
	 * each other under such conditions.
	 */
	un->un_opens_in_progress++;
	mutex_exit(&sd_detach_mutex);

	nodelay  = (flag & (FNDELAY | FNONBLOCK));
	part	 = SDPART(dev);
	partmask = 1 << part;

	/*
	 * We use a semaphore here in order to serialize
	 * open and close requests on the device.
	 */
	sema_p(&un->un_semoclose);

	mutex_enter(SD_MUTEX(un));

	/*
	 * All device accesses go thru sdstrategy() where we check
	 * on suspend status but there could be a scsi_poll command,
	 * which bypasses sdstrategy(), so we need to check pm
	 * status.
	 */

	if (!nodelay) {
		while ((un->un_state == SD_STATE_SUSPENDED) ||
		    (un->un_state == SD_STATE_PM_CHANGING)) {
			cv_wait(&un->un_suspend_cv, SD_MUTEX(un));
		}

		mutex_exit(SD_MUTEX(un));
		if (sd_pm_entry(un) != DDI_SUCCESS) {
			rval = EIO;
			SD_ERROR(SD_LOG_OPEN_CLOSE, un,
			    "sdopen: sd_pm_entry failed\n");
			goto open_failed_with_pm;
		}
		mutex_enter(SD_MUTEX(un));
	}

	/* check for previous exclusive open */
	SD_TRACE(SD_LOG_OPEN_CLOSE, un, "sdopen: un=%p\n", (void *)un);
	SD_TRACE(SD_LOG_OPEN_CLOSE, un,
	    "sdopen: exclopen=%x, flag=%x, regopen=%x\n",
	    un->un_exclopen, flag, un->un_ocmap.regopen[otyp]);

	if (un->un_exclopen & (partmask)) {
		goto excl_open_fail;
	}

	if (flag & FEXCL) {
		int i;
		if (un->un_ocmap.lyropen[part]) {
			goto excl_open_fail;
		}
		for (i = 0; i < (OTYPCNT - 1); i++) {
			if (un->un_ocmap.regopen[i] & (partmask)) {
				goto excl_open_fail;
			}
		}
	}

	/*
	 * Check the write permission if this is a removable media device,
	 * NDELAY has not been set, and writable permission is requested.
	 *
	 * Note: If NDELAY was set and this is write-protected media the WRITE
	 * attempt will fail with EIO as part of the I/O processing. This is a
	 * more permissive implementation that allows the open to succeed and
	 * WRITE attempts to fail when appropriate.
	 */
	if (un->un_f_chk_wp_open) {
		if ((flag & FWRITE) && (!nodelay)) {
			mutex_exit(SD_MUTEX(un));
			/*
			 * Defer the check for write permission on writable
			 * DVD drive till sdstrategy and will not fail open even
			 * if FWRITE is set as the device can be writable
			 * depending upon the media and the media can change
			 * after the call to open().
			 */
			if (un->un_f_dvdram_writable_device == FALSE) {
				if (ISCD(un) || sr_check_wp(dev)) {
				rval = EROFS;
				mutex_enter(SD_MUTEX(un));
				SD_ERROR(SD_LOG_OPEN_CLOSE, un, "sdopen: "
				    "write to cd or write protected media\n");
				goto open_fail;
				}
			}
			mutex_enter(SD_MUTEX(un));
		}
	}

	/*
	 * If opening in NDELAY/NONBLOCK mode, just return.
	 * Check if disk is ready and has a valid geometry later.
	 */
	if (!nodelay) {
		sd_ssc_t	*ssc;

		mutex_exit(SD_MUTEX(un));
		ssc = sd_ssc_init(un);
		rval = sd_ready_and_valid(ssc, part);
		sd_ssc_fini(ssc);
		mutex_enter(SD_MUTEX(un));
		/*
		 * Fail if device is not ready or if the number of disk
		 * blocks is zero or negative for non CD devices.
		 */

		nblks = 0;

		if (rval == SD_READY_VALID && (!ISCD(un))) {
			/* if cmlb_partinfo fails, nblks remains 0 */
			mutex_exit(SD_MUTEX(un));
			(void) cmlb_partinfo(un->un_cmlbhandle, part, &nblks,
			    NULL, NULL, NULL, (void *)SD_PATH_DIRECT);
			mutex_enter(SD_MUTEX(un));
		}

		if ((rval != SD_READY_VALID) ||
		    (!ISCD(un) && nblks <= 0)) {
			rval = un->un_f_has_removable_media ? ENXIO : EIO;
			SD_ERROR(SD_LOG_OPEN_CLOSE, un, "sdopen: "
			    "device not ready or invalid disk block value\n");
			goto open_fail;
		}
#if defined(__i386) || defined(__amd64)
	} else {
		uchar_t *cp;
		/*
		 * x86 requires special nodelay handling, so that p0 is
		 * always defined and accessible.
		 * Invalidate geometry only if device is not already open.
		 */
		cp = &un->un_ocmap.chkd[0];
		while (cp < &un->un_ocmap.chkd[OCSIZE]) {
			if (*cp != (uchar_t)0) {
				break;
			}
			cp++;
		}
		if (cp == &un->un_ocmap.chkd[OCSIZE]) {
			mutex_exit(SD_MUTEX(un));
			cmlb_invalidate(un->un_cmlbhandle,
			    (void *)SD_PATH_DIRECT);
			mutex_enter(SD_MUTEX(un));
		}

#endif
	}

	if (otyp == OTYP_LYR) {
		un->un_ocmap.lyropen[part]++;
	} else {
		un->un_ocmap.regopen[otyp] |= partmask;
	}

	/* Set up open and exclusive open flags */
	if (flag & FEXCL) {
		un->un_exclopen |= (partmask);
	}

	/*
	 * If the lun is EFI labeled and lun capacity is greater than the
	 * capacity contained in the label, log a sys-event to notify the
	 * interested module.
	 * To avoid an infinite loop of logging sys-event, we only log the
	 * event when the lun is not opened in NDELAY mode. The event handler
	 * should open the lun in NDELAY mode.
	 */
	if (!nodelay) {
		mutex_exit(SD_MUTEX(un));
		if (cmlb_efi_label_capacity(un->un_cmlbhandle, &label_cap,
		    (void*)SD_PATH_DIRECT) == 0) {
			mutex_enter(SD_MUTEX(un));
			if (un->un_f_blockcount_is_valid &&
			    un->un_blockcount > label_cap &&
			    un->un_f_expnevent == B_FALSE) {
				un->un_f_expnevent = B_TRUE;
				mutex_exit(SD_MUTEX(un));
				sd_log_lun_expansion_event(un,
				    (nodelay ? KM_NOSLEEP : KM_SLEEP));
				mutex_enter(SD_MUTEX(un));
			}
		} else {
			mutex_enter(SD_MUTEX(un));
		}
	}

	SD_TRACE(SD_LOG_OPEN_CLOSE, un, "sdopen: "
	    "open of part %d type %d\n", part, otyp);

	mutex_exit(SD_MUTEX(un));
	if (!nodelay) {
		sd_pm_exit(un);
	}

	sema_v(&un->un_semoclose);

	mutex_enter(&sd_detach_mutex);
	un->un_opens_in_progress--;
	mutex_exit(&sd_detach_mutex);

	SD_TRACE(SD_LOG_OPEN_CLOSE, un, "sdopen: exit success\n");
	return (DDI_SUCCESS);

excl_open_fail:
	SD_ERROR(SD_LOG_OPEN_CLOSE, un, "sdopen: fail exclusive open\n");
	rval = EBUSY;

open_fail:
	mutex_exit(SD_MUTEX(un));

	/*
	 * On a failed open we must exit the pm management.
	 */
	if (!nodelay) {
		sd_pm_exit(un);
	}
open_failed_with_pm:
	sema_v(&un->un_semoclose);

	mutex_enter(&sd_detach_mutex);
	un->un_opens_in_progress--;
	if (otyp == OTYP_LYR) {
		un->un_layer_count--;
	}
	mutex_exit(&sd_detach_mutex);

	return (rval);
}


/*
 *    Function: sdclose
 *
 * Description: Driver's close(9e) entry point function.
 *
 *   Arguments: dev    - device number
 *		flag   - file status flag, informational only
 *		otyp   - close type (OTYP_BLK, OTYP_CHR, OTYP_LYR)
 *		cred_p - user credential pointer
 *
 * Return Code: ENXIO
 *
 *     Context: Kernel thread context
 */
/* ARGSUSED */
static int
sdclose(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	struct sd_lun	*un;
	uchar_t		*cp;
	int		part;
	int		nodelay;
	int		rval = 0;

	/* Validate the open type */
	if (otyp >= OTYPCNT) {
		return (ENXIO);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	part = SDPART(dev);
	nodelay = flag & (FNDELAY | FNONBLOCK);

	SD_TRACE(SD_LOG_OPEN_CLOSE, un,
	    "sdclose: close of part %d type %d\n", part, otyp);

	/*
	 * We use a semaphore here in order to serialize
	 * open and close requests on the device.
	 */
	sema_p(&un->un_semoclose);

	mutex_enter(SD_MUTEX(un));

	/* Don't proceed if power is being changed. */
	while (un->un_state == SD_STATE_PM_CHANGING) {
		cv_wait(&un->un_suspend_cv, SD_MUTEX(un));
	}

	if (un->un_exclopen & (1 << part)) {
		un->un_exclopen &= ~(1 << part);
	}

	/* Update the open partition map */
	if (otyp == OTYP_LYR) {
		un->un_ocmap.lyropen[part] -= 1;
	} else {
		un->un_ocmap.regopen[otyp] &= ~(1 << part);
	}

	cp = &un->un_ocmap.chkd[0];
	while (cp < &un->un_ocmap.chkd[OCSIZE]) {
		if (*cp != NULL) {
			break;
		}
		cp++;
	}

	if (cp == &un->un_ocmap.chkd[OCSIZE]) {
		SD_TRACE(SD_LOG_OPEN_CLOSE, un, "sdclose: last close\n");

		/*
		 * We avoid persistance upon the last close, and set
		 * the throttle back to the maximum.
		 */
		un->un_throttle = un->un_saved_throttle;

		if (un->un_state == SD_STATE_OFFLINE) {
			if (un->un_f_is_fibre == FALSE) {
				scsi_log(SD_DEVINFO(un), sd_label,
				    CE_WARN, "offline\n");
			}
			mutex_exit(SD_MUTEX(un));
			cmlb_invalidate(un->un_cmlbhandle,
			    (void *)SD_PATH_DIRECT);
			mutex_enter(SD_MUTEX(un));

		} else {
			/*
			 * Flush any outstanding writes in NVRAM cache.
			 * Note: SYNCHRONIZE CACHE is an optional SCSI-2
			 * cmd, it may not work for non-Pluto devices.
			 * SYNCHRONIZE CACHE is not required for removables,
			 * except DVD-RAM drives.
			 *
			 * Also note: because SYNCHRONIZE CACHE is currently
			 * the only command issued here that requires the
			 * drive be powered up, only do the power up before
			 * sending the Sync Cache command. If additional
			 * commands are added which require a powered up
			 * drive, the following sequence may have to change.
			 *
			 * And finally, note that parallel SCSI on SPARC
			 * only issues a Sync Cache to DVD-RAM, a newly
			 * supported device.
			 */
#if defined(__i386) || defined(__amd64)
			if ((un->un_f_sync_cache_supported &&
			    un->un_f_sync_cache_required) ||
			    un->un_f_dvdram_writable_device == TRUE) {
#else
			if (un->un_f_dvdram_writable_device == TRUE) {
#endif
				mutex_exit(SD_MUTEX(un));
				if (sd_pm_entry(un) == DDI_SUCCESS) {
					rval =
					    sd_send_scsi_SYNCHRONIZE_CACHE(un,
					    NULL);
					/* ignore error if not supported */
					if (rval == ENOTSUP) {
						rval = 0;
					} else if (rval != 0) {
						rval = EIO;
					}
					sd_pm_exit(un);
				} else {
					rval = EIO;
				}
				mutex_enter(SD_MUTEX(un));
			}

			/*
			 * For devices which supports DOOR_LOCK, send an ALLOW
			 * MEDIA REMOVAL command, but don't get upset if it
			 * fails. We need to raise the power of the drive before
			 * we can call sd_send_scsi_DOORLOCK()
			 */
			if (un->un_f_doorlock_supported) {
				mutex_exit(SD_MUTEX(un));
				if (sd_pm_entry(un) == DDI_SUCCESS) {
					sd_ssc_t	*ssc;

					ssc = sd_ssc_init(un);
					rval = sd_send_scsi_DOORLOCK(ssc,
					    SD_REMOVAL_ALLOW, SD_PATH_DIRECT);
					if (rval != 0)
						sd_ssc_assessment(ssc,
						    SD_FMT_IGNORE);
					sd_ssc_fini(ssc);

					sd_pm_exit(un);
					if (ISCD(un) && (rval != 0) &&
					    (nodelay != 0)) {
						rval = ENXIO;
					}
				} else {
					rval = EIO;
				}
				mutex_enter(SD_MUTEX(un));
			}

			/*
			 * If a device has removable media, invalidate all
			 * parameters related to media, such as geometry,
			 * blocksize, and blockcount.
			 */
			if (un->un_f_has_removable_media) {
				sr_ejected(un);
			}

			/*
			 * Destroy the cache (if it exists) which was
			 * allocated for the write maps since this is
			 * the last close for this media.
			 */
			if (un->un_wm_cache) {
				/*
				 * Check if there are pending commands.
				 * and if there are give a warning and
				 * do not destroy the cache.
				 */
				if (un->un_ncmds_in_driver > 0) {
					scsi_log(SD_DEVINFO(un),
					    sd_label, CE_WARN,
					    "Unable to clean up memory "
					    "because of pending I/O\n");
				} else {
					kmem_cache_destroy(
					    un->un_wm_cache);
					un->un_wm_cache = NULL;
				}
			}
		}
	}

	mutex_exit(SD_MUTEX(un));
	sema_v(&un->un_semoclose);

	if (otyp == OTYP_LYR) {
		mutex_enter(&sd_detach_mutex);
		/*
		 * The detach routine may run when the layer count
		 * drops to zero.
		 */
		un->un_layer_count--;
		mutex_exit(&sd_detach_mutex);
	}

	return (rval);
}


/*
 *    Function: sd_ready_and_valid
 *
 * Description: Test if device is ready and has a valid geometry.
 *
 *   Arguments: ssc - sd_ssc_t will contain un
 *		un  - driver soft state (unit) structure
 *
 * Return Code: SD_READY_VALID		ready and valid label
 *		SD_NOT_READY_VALID	not ready, no label
 *		SD_RESERVED_BY_OTHERS	reservation conflict
 *
 *     Context: Never called at interrupt context.
 */

static int
sd_ready_and_valid(sd_ssc_t *ssc, int part)
{
	struct sd_errstats	*stp;
	uint64_t		capacity;
	uint_t			lbasize;
	int			rval = SD_READY_VALID;
	char			name_str[48];
	boolean_t		is_valid;
	struct sd_lun		*un;
	int			status;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	mutex_enter(SD_MUTEX(un));
	/*
	 * If a device has removable media, we must check if media is
	 * ready when checking if this device is ready and valid.
	 */
	if (un->un_f_has_removable_media) {
		mutex_exit(SD_MUTEX(un));
		status = sd_send_scsi_TEST_UNIT_READY(ssc, 0);

		if (status != 0) {
			rval = SD_NOT_READY_VALID;
			mutex_enter(SD_MUTEX(un));

			/* Ignore all failed status for removalbe media */
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);

			goto done;
		}

		is_valid = SD_IS_VALID_LABEL(un);
		mutex_enter(SD_MUTEX(un));
		if (!is_valid ||
		    (un->un_f_blockcount_is_valid == FALSE) ||
		    (un->un_f_tgt_blocksize_is_valid == FALSE)) {

			/* capacity has to be read every open. */
			mutex_exit(SD_MUTEX(un));
			status = sd_send_scsi_READ_CAPACITY(ssc, &capacity,
			    &lbasize, SD_PATH_DIRECT);

			if (status != 0) {
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);

				cmlb_invalidate(un->un_cmlbhandle,
				    (void *)SD_PATH_DIRECT);
				mutex_enter(SD_MUTEX(un));
				rval = SD_NOT_READY_VALID;

				goto done;
			} else {
				mutex_enter(SD_MUTEX(un));
				sd_update_block_info(un, lbasize, capacity);
			}
		}

		/*
		 * Check if the media in the device is writable or not.
		 */
		if (!is_valid && ISCD(un)) {
			sd_check_for_writable_cd(ssc, SD_PATH_DIRECT);
		}

	} else {
		/*
		 * Do a test unit ready to clear any unit attention from non-cd
		 * devices.
		 */
		mutex_exit(SD_MUTEX(un));

		status = sd_send_scsi_TEST_UNIT_READY(ssc, 0);
		if (status != 0) {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		}

		mutex_enter(SD_MUTEX(un));
	}


	/*
	 * If this is a non 512 block device, allocate space for
	 * the wmap cache. This is being done here since every time
	 * a media is changed this routine will be called and the
	 * block size is a function of media rather than device.
	 */
	if (((un->un_f_rmw_type != SD_RMW_TYPE_RETURN_ERROR ||
	    un->un_f_non_devbsize_supported) &&
	    un->un_tgt_blocksize != DEV_BSIZE) ||
	    un->un_f_enable_rmw) {
		if (!(un->un_wm_cache)) {
			(void) snprintf(name_str, sizeof (name_str),
			    "%s%d_cache",
			    ddi_driver_name(SD_DEVINFO(un)),
			    ddi_get_instance(SD_DEVINFO(un)));
			un->un_wm_cache = kmem_cache_create(
			    name_str, sizeof (struct sd_w_map),
			    8, sd_wm_cache_constructor,
			    sd_wm_cache_destructor, NULL,
			    (void *)un, NULL, 0);
			if (!(un->un_wm_cache)) {
				rval = ENOMEM;
				goto done;
			}
		}
	}

	if (un->un_state == SD_STATE_NORMAL) {
		/*
		 * If the target is not yet ready here (defined by a TUR
		 * failure), invalidate the geometry and print an 'offline'
		 * message. This is a legacy message, as the state of the
		 * target is not actually changed to SD_STATE_OFFLINE.
		 *
		 * If the TUR fails for EACCES (Reservation Conflict),
		 * SD_RESERVED_BY_OTHERS will be returned to indicate
		 * reservation conflict. If the TUR fails for other
		 * reasons, SD_NOT_READY_VALID will be returned.
		 */
		int err;

		mutex_exit(SD_MUTEX(un));
		err = sd_send_scsi_TEST_UNIT_READY(ssc, 0);
		mutex_enter(SD_MUTEX(un));

		if (err != 0) {
			mutex_exit(SD_MUTEX(un));
			cmlb_invalidate(un->un_cmlbhandle,
			    (void *)SD_PATH_DIRECT);
			mutex_enter(SD_MUTEX(un));
			if (err == EACCES) {
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				    "reservation conflict\n");
				rval = SD_RESERVED_BY_OTHERS;
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);
			} else {
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				    "drive offline\n");
				rval = SD_NOT_READY_VALID;
				sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
			}
			goto done;
		}
	}

	if (un->un_f_format_in_progress == FALSE) {
		mutex_exit(SD_MUTEX(un));

		(void) cmlb_validate(un->un_cmlbhandle, 0,
		    (void *)SD_PATH_DIRECT);
		if (cmlb_partinfo(un->un_cmlbhandle, part, NULL, NULL, NULL,
		    NULL, (void *) SD_PATH_DIRECT) != 0) {
			rval = SD_NOT_READY_VALID;
			mutex_enter(SD_MUTEX(un));

			goto done;
		}
		if (un->un_f_pkstats_enabled) {
			sd_set_pstats(un);
			SD_TRACE(SD_LOG_IO_PARTITION, un,
			    "sd_ready_and_valid: un:0x%p pstats created and "
			    "set\n", un);
		}
		mutex_enter(SD_MUTEX(un));
	}

	/*
	 * If this device supports DOOR_LOCK command, try and send
	 * this command to PREVENT MEDIA REMOVAL, but don't get upset
	 * if it fails. For a CD, however, it is an error
	 */
	if (un->un_f_doorlock_supported) {
		mutex_exit(SD_MUTEX(un));
		status = sd_send_scsi_DOORLOCK(ssc, SD_REMOVAL_PREVENT,
		    SD_PATH_DIRECT);

		if ((status != 0) && ISCD(un)) {
			rval = SD_NOT_READY_VALID;
			mutex_enter(SD_MUTEX(un));

			sd_ssc_assessment(ssc, SD_FMT_IGNORE);

			goto done;
		} else if (status != 0)
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		mutex_enter(SD_MUTEX(un));
	}

	/* The state has changed, inform the media watch routines */
	un->un_mediastate = DKIO_INSERTED;
	cv_broadcast(&un->un_state_cv);
	rval = SD_READY_VALID;

done:

	/*
	 * Initialize the capacity kstat value, if no media previously
	 * (capacity kstat is 0) and a media has been inserted
	 * (un_blockcount > 0).
	 */
	if (un->un_errstats != NULL) {
		stp = (struct sd_errstats *)un->un_errstats->ks_data;
		if ((stp->sd_capacity.value.ui64 == 0) &&
		    (un->un_f_blockcount_is_valid == TRUE)) {
			stp->sd_capacity.value.ui64 =
			    (uint64_t)((uint64_t)un->un_blockcount *
			    un->un_sys_blocksize);
		}
	}

	mutex_exit(SD_MUTEX(un));
	return (rval);
}


/*
 *    Function: sdmin
 *
 * Description: Routine to limit the size of a data transfer. Used in
 *		conjunction with physio(9F).
 *
 *   Arguments: bp - pointer to the indicated buf(9S) struct.
 *
 *     Context: Kernel thread context.
 */

static void
sdmin(struct buf *bp)
{
	struct sd_lun	*un;
	int		instance;

	instance = SDUNIT(bp->b_edev);

	un = ddi_get_soft_state(sd_state, instance);
	ASSERT(un != NULL);

	/*
	 * We depend on buf breakup to restrict
	 * IO size if it is enabled.
	 */
	if (un->un_buf_breakup_supported) {
		return;
	}

	if (bp->b_bcount > un->un_max_xfer_size) {
		bp->b_bcount = un->un_max_xfer_size;
	}
}


/*
 *    Function: sdread
 *
 * Description: Driver's read(9e) entry point function.
 *
 *   Arguments: dev   - device number
 *		uio   - structure pointer describing where data is to be stored
 *			in user's space
 *		cred_p  - user credential pointer
 *
 * Return Code: ENXIO
 *		EIO
 *		EINVAL
 *		value returned by physio
 *
 *     Context: Kernel thread context.
 */
/* ARGSUSED */
static int
sdread(dev_t dev, struct uio *uio, cred_t *cred_p)
{
	struct sd_lun	*un = NULL;
	int		secmask;
	int		err = 0;
	sd_ssc_t	*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	ASSERT(!mutex_owned(SD_MUTEX(un)));


	if (!SD_IS_VALID_LABEL(un) && !ISCD(un)) {
		mutex_enter(SD_MUTEX(un));
		/*
		 * Because the call to sd_ready_and_valid will issue I/O we
		 * must wait here if either the device is suspended or
		 * if it's power level is changing.
		 */
		while ((un->un_state == SD_STATE_SUSPENDED) ||
		    (un->un_state == SD_STATE_PM_CHANGING)) {
			cv_wait(&un->un_suspend_cv, SD_MUTEX(un));
		}
		un->un_ncmds_in_driver++;
		mutex_exit(SD_MUTEX(un));

		/* Initialize sd_ssc_t for internal uscsi commands */
		ssc = sd_ssc_init(un);
		if ((sd_ready_and_valid(ssc, SDPART(dev))) != SD_READY_VALID) {
			err = EIO;
		} else {
			err = 0;
		}
		sd_ssc_fini(ssc);

		mutex_enter(SD_MUTEX(un));
		un->un_ncmds_in_driver--;
		ASSERT(un->un_ncmds_in_driver >= 0);
		mutex_exit(SD_MUTEX(un));
		if (err != 0)
			return (err);
	}

	/*
	 * Read requests are restricted to multiples of the system block size.
	 */
	if (un->un_f_rmw_type == SD_RMW_TYPE_RETURN_ERROR &&
	    !un->un_f_enable_rmw)
		secmask = un->un_tgt_blocksize - 1;
	else
		secmask = DEV_BSIZE - 1;

	if (uio->uio_loffset & ((offset_t)(secmask))) {
		SD_ERROR(SD_LOG_READ_WRITE, un,
		    "sdread: file offset not modulo %d\n",
		    secmask + 1);
		err = EINVAL;
	} else if (uio->uio_iov->iov_len & (secmask)) {
		SD_ERROR(SD_LOG_READ_WRITE, un,
		    "sdread: transfer length not modulo %d\n",
		    secmask + 1);
		err = EINVAL;
	} else {
		err = physio(sdstrategy, NULL, dev, B_READ, sdmin, uio);
	}

	return (err);
}


/*
 *    Function: sdwrite
 *
 * Description: Driver's write(9e) entry point function.
 *
 *   Arguments: dev   - device number
 *		uio   - structure pointer describing where data is stored in
 *			user's space
 *		cred_p  - user credential pointer
 *
 * Return Code: ENXIO
 *		EIO
 *		EINVAL
 *		value returned by physio
 *
 *     Context: Kernel thread context.
 */
/* ARGSUSED */
static int
sdwrite(dev_t dev, struct uio *uio, cred_t *cred_p)
{
	struct sd_lun	*un = NULL;
	int		secmask;
	int		err = 0;
	sd_ssc_t	*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	ASSERT(!mutex_owned(SD_MUTEX(un)));

	if (!SD_IS_VALID_LABEL(un) && !ISCD(un)) {
		mutex_enter(SD_MUTEX(un));
		/*
		 * Because the call to sd_ready_and_valid will issue I/O we
		 * must wait here if either the device is suspended or
		 * if it's power level is changing.
		 */
		while ((un->un_state == SD_STATE_SUSPENDED) ||
		    (un->un_state == SD_STATE_PM_CHANGING)) {
			cv_wait(&un->un_suspend_cv, SD_MUTEX(un));
		}
		un->un_ncmds_in_driver++;
		mutex_exit(SD_MUTEX(un));

		/* Initialize sd_ssc_t for internal uscsi commands */
		ssc = sd_ssc_init(un);
		if ((sd_ready_and_valid(ssc, SDPART(dev))) != SD_READY_VALID) {
			err = EIO;
		} else {
			err = 0;
		}
		sd_ssc_fini(ssc);

		mutex_enter(SD_MUTEX(un));
		un->un_ncmds_in_driver--;
		ASSERT(un->un_ncmds_in_driver >= 0);
		mutex_exit(SD_MUTEX(un));
		if (err != 0)
			return (err);
	}

	/*
	 * Write requests are restricted to multiples of the system block size.
	 */
	if (un->un_f_rmw_type == SD_RMW_TYPE_RETURN_ERROR &&
	    !un->un_f_enable_rmw)
		secmask = un->un_tgt_blocksize - 1;
	else
		secmask = DEV_BSIZE - 1;

	if (uio->uio_loffset & ((offset_t)(secmask))) {
		SD_ERROR(SD_LOG_READ_WRITE, un,
		    "sdwrite: file offset not modulo %d\n",
		    secmask + 1);
		err = EINVAL;
	} else if (uio->uio_iov->iov_len & (secmask)) {
		SD_ERROR(SD_LOG_READ_WRITE, un,
		    "sdwrite: transfer length not modulo %d\n",
		    secmask + 1);
		err = EINVAL;
	} else {
		err = physio(sdstrategy, NULL, dev, B_WRITE, sdmin, uio);
	}

	return (err);
}


/*
 *    Function: sdaread
 *
 * Description: Driver's aread(9e) entry point function.
 *
 *   Arguments: dev   - device number
 *		aio   - structure pointer describing where data is to be stored
 *		cred_p  - user credential pointer
 *
 * Return Code: ENXIO
 *		EIO
 *		EINVAL
 *		value returned by aphysio
 *
 *     Context: Kernel thread context.
 */
/* ARGSUSED */
static int
sdaread(dev_t dev, struct aio_req *aio, cred_t *cred_p)
{
	struct sd_lun	*un = NULL;
	struct uio	*uio = aio->aio_uio;
	int		secmask;
	int		err = 0;
	sd_ssc_t	*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	ASSERT(!mutex_owned(SD_MUTEX(un)));

	if (!SD_IS_VALID_LABEL(un) && !ISCD(un)) {
		mutex_enter(SD_MUTEX(un));
		/*
		 * Because the call to sd_ready_and_valid will issue I/O we
		 * must wait here if either the device is suspended or
		 * if it's power level is changing.
		 */
		while ((un->un_state == SD_STATE_SUSPENDED) ||
		    (un->un_state == SD_STATE_PM_CHANGING)) {
			cv_wait(&un->un_suspend_cv, SD_MUTEX(un));
		}
		un->un_ncmds_in_driver++;
		mutex_exit(SD_MUTEX(un));

		/* Initialize sd_ssc_t for internal uscsi commands */
		ssc = sd_ssc_init(un);
		if ((sd_ready_and_valid(ssc, SDPART(dev))) != SD_READY_VALID) {
			err = EIO;
		} else {
			err = 0;
		}
		sd_ssc_fini(ssc);

		mutex_enter(SD_MUTEX(un));
		un->un_ncmds_in_driver--;
		ASSERT(un->un_ncmds_in_driver >= 0);
		mutex_exit(SD_MUTEX(un));
		if (err != 0)
			return (err);
	}

	/*
	 * Read requests are restricted to multiples of the system block size.
	 */
	if (un->un_f_rmw_type == SD_RMW_TYPE_RETURN_ERROR &&
	    !un->un_f_enable_rmw)
		secmask = un->un_tgt_blocksize - 1;
	else
		secmask = DEV_BSIZE - 1;

	if (uio->uio_loffset & ((offset_t)(secmask))) {
		SD_ERROR(SD_LOG_READ_WRITE, un,
		    "sdaread: file offset not modulo %d\n",
		    secmask + 1);
		err = EINVAL;
	} else if (uio->uio_iov->iov_len & (secmask)) {
		SD_ERROR(SD_LOG_READ_WRITE, un,
		    "sdaread: transfer length not modulo %d\n",
		    secmask + 1);
		err = EINVAL;
	} else {
		err = aphysio(sdstrategy, anocancel, dev, B_READ, sdmin, aio);
	}

	return (err);
}


/*
 *    Function: sdawrite
 *
 * Description: Driver's awrite(9e) entry point function.
 *
 *   Arguments: dev   - device number
 *		aio   - structure pointer describing where data is stored
 *		cred_p  - user credential pointer
 *
 * Return Code: ENXIO
 *		EIO
 *		EINVAL
 *		value returned by aphysio
 *
 *     Context: Kernel thread context.
 */
/* ARGSUSED */
static int
sdawrite(dev_t dev, struct aio_req *aio, cred_t *cred_p)
{
	struct sd_lun	*un = NULL;
	struct uio	*uio = aio->aio_uio;
	int		secmask;
	int		err = 0;
	sd_ssc_t	*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	ASSERT(!mutex_owned(SD_MUTEX(un)));

	if (!SD_IS_VALID_LABEL(un) && !ISCD(un)) {
		mutex_enter(SD_MUTEX(un));
		/*
		 * Because the call to sd_ready_and_valid will issue I/O we
		 * must wait here if either the device is suspended or
		 * if it's power level is changing.
		 */
		while ((un->un_state == SD_STATE_SUSPENDED) ||
		    (un->un_state == SD_STATE_PM_CHANGING)) {
			cv_wait(&un->un_suspend_cv, SD_MUTEX(un));
		}
		un->un_ncmds_in_driver++;
		mutex_exit(SD_MUTEX(un));

		/* Initialize sd_ssc_t for internal uscsi commands */
		ssc = sd_ssc_init(un);
		if ((sd_ready_and_valid(ssc, SDPART(dev))) != SD_READY_VALID) {
			err = EIO;
		} else {
			err = 0;
		}
		sd_ssc_fini(ssc);

		mutex_enter(SD_MUTEX(un));
		un->un_ncmds_in_driver--;
		ASSERT(un->un_ncmds_in_driver >= 0);
		mutex_exit(SD_MUTEX(un));
		if (err != 0)
			return (err);
	}

	/*
	 * Write requests are restricted to multiples of the system block size.
	 */
	if (un->un_f_rmw_type == SD_RMW_TYPE_RETURN_ERROR &&
	    !un->un_f_enable_rmw)
		secmask = un->un_tgt_blocksize - 1;
	else
		secmask = DEV_BSIZE - 1;

	if (uio->uio_loffset & ((offset_t)(secmask))) {
		SD_ERROR(SD_LOG_READ_WRITE, un,
		    "sdawrite: file offset not modulo %d\n",
		    secmask + 1);
		err = EINVAL;
	} else if (uio->uio_iov->iov_len & (secmask)) {
		SD_ERROR(SD_LOG_READ_WRITE, un,
		    "sdawrite: transfer length not modulo %d\n",
		    secmask + 1);
		err = EINVAL;
	} else {
		err = aphysio(sdstrategy, anocancel, dev, B_WRITE, sdmin, aio);
	}

	return (err);
}





/*
 * Driver IO processing follows the following sequence:
 *
 *     sdioctl(9E)     sdstrategy(9E)         biodone(9F)
 *         |                |                     ^
 *         v                v                     |
 * sd_send_scsi_cmd()  ddi_xbuf_qstrategy()       +-------------------+
 *         |                |                     |                   |
 *         v                |                     |                   |
 * sd_uscsi_strategy() sd_xbuf_strategy()   sd_buf_iodone()   sd_uscsi_iodone()
 *         |                |                     ^                   ^
 *         v                v                     |                   |
 * SD_BEGIN_IOSTART()  SD_BEGIN_IOSTART()         |                   |
 *         |                |                     |                   |
 *     +---+                |                     +------------+      +-------+
 *     |                    |                                  |              |
 *     |   SD_NEXT_IOSTART()|                  SD_NEXT_IODONE()|              |
 *     |                    v                                  |              |
 *     |         sd_mapblockaddr_iostart()           sd_mapblockaddr_iodone() |
 *     |                    |                                  ^              |
 *     |   SD_NEXT_IOSTART()|                  SD_NEXT_IODONE()|              |
 *     |                    v                                  |              |
 *     |         sd_mapblocksize_iostart()           sd_mapblocksize_iodone() |
 *     |                    |                                  ^              |
 *     |   SD_NEXT_IOSTART()|                  SD_NEXT_IODONE()|              |
 *     |                    v                                  |              |
 *     |           sd_checksum_iostart()               sd_checksum_iodone()   |
 *     |                    |                                  ^              |
 *     +-> SD_NEXT_IOSTART()|                  SD_NEXT_IODONE()+------------->+
 *     |                    v                                  |              |
 *     |              sd_pm_iostart()                     sd_pm_iodone()      |
 *     |                    |                                  ^              |
 *     |                    |                                  |              |
 *     +-> SD_NEXT_IOSTART()|               SD_BEGIN_IODONE()--+--------------+
 *                          |                           ^
 *                          v                           |
 *                   sd_core_iostart()                  |
 *                          |                           |
 *                          |                           +------>(*destroypkt)()
 *                          +-> sd_start_cmds() <-+     |           |
 *                          |                     |     |           v
 *                          |                     |     |  scsi_destroy_pkt(9F)
 *                          |                     |     |
 *                          +->(*initpkt)()       +- sdintr()
 *                          |  |                        |  |
 *                          |  +-> scsi_init_pkt(9F)    |  +-> sd_handle_xxx()
 *                          |  +-> scsi_setup_cdb(9F)   |
 *                          |                           |
 *                          +--> scsi_transport(9F)     |
 *                                     |                |
 *                                     +----> SCSA ---->+
 *
 *
 * This code is based upon the following presumptions:
 *
 *   - iostart and iodone functions operate on buf(9S) structures. These
 *     functions perform the necessary operations on the buf(9S) and pass
 *     them along to the next function in the chain by using the macros
 *     SD_NEXT_IOSTART() (for iostart side functions) and SD_NEXT_IODONE()
 *     (for iodone side functions).
 *
 *   - The iostart side functions may sleep. The iodone side functions
 *     are called under interrupt context and may NOT sleep. Therefore
 *     iodone side functions also may not call iostart side functions.
 *     (NOTE: iostart side functions should NOT sleep for memory, as
 *     this could result in deadlock.)
 *
 *   - An iostart side function may call its corresponding iodone side
 *     function directly (if necessary).
 *
 *   - In the event of an error, an iostart side function can return a buf(9S)
 *     to its caller by calling SD_BEGIN_IODONE() (after setting B_ERROR and
 *     b_error in the usual way of course).
 *
 *   - The taskq mechanism may be used by the iodone side functions to dispatch
 *     requests to the iostart side functions.  The iostart side functions in
 *     this case would be called under the context of a taskq thread, so it's
 *     OK for them to block/sleep/spin in this case.
 *
 *   - iostart side functions may allocate "shadow" buf(9S) structs and
 *     pass them along to the next function in the chain.  The corresponding
 *     iodone side functions must coalesce the "shadow" bufs and return
 *     the "original" buf to the next higher layer.
 *
 *   - The b_private field of the buf(9S) struct holds a pointer to
 *     an sd_xbuf struct, which contains information needed to
 *     construct the scsi_pkt for the command.
 *
 *   - The SD_MUTEX(un) is NOT held across calls to the next layer. Each
 *     layer must acquire & release the SD_MUTEX(un) as needed.
 */


/*
 * Create taskq for all targets in the system. This is created at
 * _init(9E) and destroyed at _fini(9E).
 *
 * Note: here we set the minalloc to a reasonably high number to ensure that
 * we will have an adequate supply of task entries available at interrupt time.
 * This is used in conjunction with the TASKQ_PREPOPULATE flag in
 * sd_create_taskq().  Since we do not want to sleep for allocations at
 * interrupt time, set maxalloc equal to minalloc. That way we will just fail
 * the command if we ever try to dispatch more than SD_TASKQ_MAXALLOC taskq
 * requests any one instant in time.
 */
#define	SD_TASKQ_NUMTHREADS	8
#define	SD_TASKQ_MINALLOC	256
#define	SD_TASKQ_MAXALLOC	256

static taskq_t	*sd_tq = NULL;
_NOTE(SCHEME_PROTECTS_DATA("stable data", sd_tq))

static int	sd_taskq_minalloc = SD_TASKQ_MINALLOC;
static int	sd_taskq_maxalloc = SD_TASKQ_MAXALLOC;

/*
 * The following task queue is being created for the write part of
 * read-modify-write of non-512 block size devices.
 * Limit the number of threads to 1 for now. This number has been chosen
 * considering the fact that it applies only to dvd ram drives/MO drives
 * currently. Performance for which is not main criteria at this stage.
 * Note: It needs to be explored if we can use a single taskq in future
 */
#define	SD_WMR_TASKQ_NUMTHREADS	1
static taskq_t	*sd_wmr_tq = NULL;
_NOTE(SCHEME_PROTECTS_DATA("stable data", sd_wmr_tq))

/*
 *    Function: sd_taskq_create
 *
 * Description: Create taskq thread(s) and preallocate task entries
 *
 * Return Code: Returns a pointer to the allocated taskq_t.
 *
 *     Context: Can sleep. Requires blockable context.
 *
 *       Notes: - The taskq() facility currently is NOT part of the DDI.
 *		  (definitely NOT recommeded for 3rd-party drivers!) :-)
 *		- taskq_create() will block for memory, also it will panic
 *		  if it cannot create the requested number of threads.
 *		- Currently taskq_create() creates threads that cannot be
 *		  swapped.
 *		- We use TASKQ_PREPOPULATE to ensure we have an adequate
 *		  supply of taskq entries at interrupt time (ie, so that we
 *		  do not have to sleep for memory)
 */

static void
sd_taskq_create(void)
{
	char	taskq_name[TASKQ_NAMELEN];

	ASSERT(sd_tq == NULL);
	ASSERT(sd_wmr_tq == NULL);

	(void) snprintf(taskq_name, sizeof (taskq_name),
	    "%s_drv_taskq", sd_label);
	sd_tq = (taskq_create(taskq_name, SD_TASKQ_NUMTHREADS,
	    (v.v_maxsyspri - 2), sd_taskq_minalloc, sd_taskq_maxalloc,
	    TASKQ_PREPOPULATE));

	(void) snprintf(taskq_name, sizeof (taskq_name),
	    "%s_rmw_taskq", sd_label);
	sd_wmr_tq = (taskq_create(taskq_name, SD_WMR_TASKQ_NUMTHREADS,
	    (v.v_maxsyspri - 2), sd_taskq_minalloc, sd_taskq_maxalloc,
	    TASKQ_PREPOPULATE));
}


/*
 *    Function: sd_taskq_delete
 *
 * Description: Complementary cleanup routine for sd_taskq_create().
 *
 *     Context: Kernel thread context.
 */

static void
sd_taskq_delete(void)
{
	ASSERT(sd_tq != NULL);
	ASSERT(sd_wmr_tq != NULL);
	taskq_destroy(sd_tq);
	taskq_destroy(sd_wmr_tq);
	sd_tq = NULL;
	sd_wmr_tq = NULL;
}


/*
 *    Function: sdstrategy
 *
 * Description: Driver's strategy (9E) entry point function.
 *
 *   Arguments: bp - pointer to buf(9S)
 *
 * Return Code: Always returns zero
 *
 *     Context: Kernel thread context.
 */

static int
sdstrategy(struct buf *bp)
{
	struct sd_lun *un;

	un = ddi_get_soft_state(sd_state, SD_GET_INSTANCE_FROM_BUF(bp));
	if (un == NULL) {
		bioerror(bp, EIO);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	/* As was done in the past, fail new cmds. if state is dumping. */
	if (un->un_state == SD_STATE_DUMPING) {
		bioerror(bp, ENXIO);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	ASSERT(!mutex_owned(SD_MUTEX(un)));

	/*
	 * Commands may sneak in while we released the mutex in
	 * DDI_SUSPEND, we should block new commands. However, old
	 * commands that are still in the driver at this point should
	 * still be allowed to drain.
	 */
	mutex_enter(SD_MUTEX(un));
	/*
	 * Must wait here if either the device is suspended or
	 * if it's power level is changing.
	 */
	while ((un->un_state == SD_STATE_SUSPENDED) ||
	    (un->un_state == SD_STATE_PM_CHANGING)) {
		cv_wait(&un->un_suspend_cv, SD_MUTEX(un));
	}

	un->un_ncmds_in_driver++;

	/*
	 * atapi: Since we are running the CD for now in PIO mode we need to
	 * call bp_mapin here to avoid bp_mapin called interrupt context under
	 * the HBA's init_pkt routine.
	 */
	if (un->un_f_cfg_is_atapi == TRUE) {
		mutex_exit(SD_MUTEX(un));
		bp_mapin(bp);
		mutex_enter(SD_MUTEX(un));
	}
	SD_INFO(SD_LOG_IO, un, "sdstrategy: un_ncmds_in_driver = %ld\n",
	    un->un_ncmds_in_driver);

	if (bp->b_flags & B_WRITE)
		un->un_f_sync_cache_required = TRUE;

	mutex_exit(SD_MUTEX(un));

	/*
	 * This will (eventually) allocate the sd_xbuf area and
	 * call sd_xbuf_strategy().  We just want to return the
	 * result of ddi_xbuf_qstrategy so that we have an opt-
	 * imized tail call which saves us a stack frame.
	 */
	return (ddi_xbuf_qstrategy(bp, un->un_xbuf_attr));
}


/*
 *    Function: sd_xbuf_strategy
 *
 * Description: Function for initiating IO operations via the
 *		ddi_xbuf_qstrategy() mechanism.
 *
 *     Context: Kernel thread context.
 */

static void
sd_xbuf_strategy(struct buf *bp, ddi_xbuf_t xp, void *arg)
{
	struct sd_lun *un = arg;

	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	/*
	 * Initialize the fields in the xbuf and save a pointer to the
	 * xbuf in bp->b_private.
	 */
	sd_xbuf_init(un, bp, xp, SD_CHAIN_BUFIO, NULL);

	/* Send the buf down the iostart chain */
	SD_BEGIN_IOSTART(((struct sd_xbuf *)xp)->xb_chain_iostart, un, bp);
}


/*
 *    Function: sd_xbuf_init
 *
 * Description: Prepare the given sd_xbuf struct for use.
 *
 *   Arguments: un - ptr to softstate
 *		bp - ptr to associated buf(9S)
 *		xp - ptr to associated sd_xbuf
 *		chain_type - IO chain type to use:
 *			SD_CHAIN_NULL
 *			SD_CHAIN_BUFIO
 *			SD_CHAIN_USCSI
 *			SD_CHAIN_DIRECT
 *			SD_CHAIN_DIRECT_PRIORITY
 *		pktinfop - ptr to private data struct for scsi_pkt(9S)
 *			initialization; may be NULL if none.
 *
 *     Context: Kernel thread context
 */

static void
sd_xbuf_init(struct sd_lun *un, struct buf *bp, struct sd_xbuf *xp,
	uchar_t chain_type, void *pktinfop)
{
	int index;

	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);

	SD_INFO(SD_LOG_IO, un, "sd_xbuf_init: buf:0x%p chain type:0x%x\n",
	    bp, chain_type);

	xp->xb_un	= un;
	xp->xb_pktp	= NULL;
	xp->xb_pktinfo	= pktinfop;
	xp->xb_private	= bp->b_private;
	xp->xb_blkno	= (daddr_t)bp->b_blkno;

	/*
	 * Set up the iostart and iodone chain indexes in the xbuf, based
	 * upon the specified chain type to use.
	 */
	switch (chain_type) {
	case SD_CHAIN_NULL:
		/*
		 * Fall thru to just use the values for the buf type, even
		 * tho for the NULL chain these values will never be used.
		 */
		/* FALLTHRU */
	case SD_CHAIN_BUFIO:
		index = un->un_buf_chain_type;
		if ((!un->un_f_has_removable_media) &&
		    (un->un_tgt_blocksize != 0) &&
		    (un->un_tgt_blocksize != DEV_BSIZE ||
		    un->un_f_enable_rmw)) {
			int secmask = 0, blknomask = 0;
			if (un->un_f_enable_rmw) {
				blknomask =
				    (un->un_phy_blocksize / DEV_BSIZE) - 1;
				secmask = un->un_phy_blocksize - 1;
			} else {
				blknomask =
				    (un->un_tgt_blocksize / DEV_BSIZE) - 1;
				secmask = un->un_tgt_blocksize - 1;
			}

			if ((bp->b_lblkno & (blknomask)) ||
			    (bp->b_bcount & (secmask))) {
				if ((un->un_f_rmw_type !=
				    SD_RMW_TYPE_RETURN_ERROR) ||
				    un->un_f_enable_rmw) {
					if (un->un_f_pm_is_enabled == FALSE)
						index =
						    SD_CHAIN_INFO_MSS_DSK_NO_PM;
					else
						index =
						    SD_CHAIN_INFO_MSS_DISK;
				}
			}
		}
		break;
	case SD_CHAIN_USCSI:
		index = un->un_uscsi_chain_type;
		break;
	case SD_CHAIN_DIRECT:
		index = un->un_direct_chain_type;
		break;
	case SD_CHAIN_DIRECT_PRIORITY:
		index = un->un_priority_chain_type;
		break;
	default:
		/* We're really broken if we ever get here... */
		panic("sd_xbuf_init: illegal chain type!");
		/*NOTREACHED*/
	}

	xp->xb_chain_iostart = sd_chain_index_map[index].sci_iostart_index;
	xp->xb_chain_iodone = sd_chain_index_map[index].sci_iodone_index;

	/*
	 * It might be a bit easier to simply bzero the entire xbuf above,
	 * but it turns out that since we init a fair number of members anyway,
	 * we save a fair number cycles by doing explicit assignment of zero.
	 */
	xp->xb_pkt_flags	= 0;
	xp->xb_dma_resid	= 0;
	xp->xb_retry_count	= 0;
	xp->xb_victim_retry_count = 0;
	xp->xb_ua_retry_count	= 0;
	xp->xb_nr_retry_count	= 0;
	xp->xb_sense_bp		= NULL;
	xp->xb_sense_status	= 0;
	xp->xb_sense_state	= 0;
	xp->xb_sense_resid	= 0;
	xp->xb_ena		= 0;

	bp->b_private	= xp;
	bp->b_flags	&= ~(B_DONE | B_ERROR);
	bp->b_resid	= 0;
	bp->av_forw	= NULL;
	bp->av_back	= NULL;
	bioerror(bp, 0);

	SD_INFO(SD_LOG_IO, un, "sd_xbuf_init: done.\n");
}


/*
 *    Function: sd_uscsi_strategy
 *
 * Description: Wrapper for calling into the USCSI chain via physio(9F)
 *
 *   Arguments: bp - buf struct ptr
 *
 * Return Code: Always returns 0
 *
 *     Context: Kernel thread context
 */

static int
sd_uscsi_strategy(struct buf *bp)
{
	struct sd_lun		*un;
	struct sd_uscsi_info	*uip;
	struct sd_xbuf		*xp;
	uchar_t			chain_type;
	uchar_t			cmd;

	ASSERT(bp != NULL);

	un = ddi_get_soft_state(sd_state, SD_GET_INSTANCE_FROM_BUF(bp));
	if (un == NULL) {
		bioerror(bp, EIO);
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO, un, "sd_uscsi_strategy: entry: buf:0x%p\n", bp);

	/*
	 * A pointer to a struct sd_uscsi_info is expected in bp->b_private
	 */
	ASSERT(bp->b_private != NULL);
	uip = (struct sd_uscsi_info *)bp->b_private;
	cmd = ((struct uscsi_cmd *)(uip->ui_cmdp))->uscsi_cdb[0];

	mutex_enter(SD_MUTEX(un));
	/*
	 * atapi: Since we are running the CD for now in PIO mode we need to
	 * call bp_mapin here to avoid bp_mapin called interrupt context under
	 * the HBA's init_pkt routine.
	 */
	if (un->un_f_cfg_is_atapi == TRUE) {
		mutex_exit(SD_MUTEX(un));
		bp_mapin(bp);
		mutex_enter(SD_MUTEX(un));
	}
	un->un_ncmds_in_driver++;
	SD_INFO(SD_LOG_IO, un, "sd_uscsi_strategy: un_ncmds_in_driver = %ld\n",
	    un->un_ncmds_in_driver);

	if ((bp->b_flags & B_WRITE) && (bp->b_bcount != 0) &&
	    (cmd != SCMD_MODE_SELECT) && (cmd != SCMD_MODE_SELECT_G1))
		un->un_f_sync_cache_required = TRUE;

	mutex_exit(SD_MUTEX(un));

	switch (uip->ui_flags) {
	case SD_PATH_DIRECT:
		chain_type = SD_CHAIN_DIRECT;
		break;
	case SD_PATH_DIRECT_PRIORITY:
		chain_type = SD_CHAIN_DIRECT_PRIORITY;
		break;
	default:
		chain_type = SD_CHAIN_USCSI;
		break;
	}

	/*
	 * We may allocate extra buf for external USCSI commands. If the
	 * application asks for bigger than 20-byte sense data via USCSI,
	 * SCSA layer will allocate 252 bytes sense buf for that command.
	 */
	if (((struct uscsi_cmd *)(uip->ui_cmdp))->uscsi_rqlen >
	    SENSE_LENGTH) {
		xp = kmem_zalloc(sizeof (struct sd_xbuf) - SENSE_LENGTH +
		    MAX_SENSE_LENGTH, KM_SLEEP);
	} else {
		xp = kmem_zalloc(sizeof (struct sd_xbuf), KM_SLEEP);
	}

	sd_xbuf_init(un, bp, xp, chain_type, uip->ui_cmdp);

	/* Use the index obtained within xbuf_init */
	SD_BEGIN_IOSTART(xp->xb_chain_iostart, un, bp);

	SD_TRACE(SD_LOG_IO, un, "sd_uscsi_strategy: exit: buf:0x%p\n", bp);

	return (0);
}

/*
 *    Function: sd_send_scsi_cmd
 *
 * Description: Runs a USCSI command for user (when called thru sdioctl),
 *		or for the driver
 *
 *   Arguments: dev - the dev_t for the device
 *		incmd - ptr to a valid uscsi_cmd struct
 *		flag - bit flag, indicating open settings, 32/64 bit type
 *		dataspace - UIO_USERSPACE or UIO_SYSSPACE
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq.
 *
 * Return Code: 0 -  successful completion of the given command
 *		EIO - scsi_uscsi_handle_command() failed
 *		ENXIO  - soft state not found for specified dev
 *		EINVAL
 *		EFAULT - copyin/copyout error
 *		return code of scsi_uscsi_handle_command():
 *			EIO
 *			ENXIO
 *			EACCES
 *
 *     Context: Waits for command to complete. Can sleep.
 */

static int
sd_send_scsi_cmd(dev_t dev, struct uscsi_cmd *incmd, int flag,
	enum uio_seg dataspace, int path_flag)
{
	struct sd_lun	*un;
	sd_ssc_t	*ssc;
	int		rval;

	un = ddi_get_soft_state(sd_state, SDUNIT(dev));
	if (un == NULL) {
		return (ENXIO);
	}

	/*
	 * Using sd_ssc_send to handle uscsi cmd
	 */
	ssc = sd_ssc_init(un);
	rval = sd_ssc_send(ssc, incmd, flag, dataspace, path_flag);
	sd_ssc_fini(ssc);

	return (rval);
}

/*
 *    Function: sd_ssc_init
 *
 * Description: Uscsi end-user call this function to initialize necessary
 *              fields, such as uscsi_cmd and sd_uscsi_info struct.
 *
 *              The return value of sd_send_scsi_cmd will be treated as a
 *              fault in various conditions. Even it is not Zero, some
 *              callers may ignore the return value. That is to say, we can
 *              not make an accurate assessment in sdintr, since if a
 *              command is failed in sdintr it does not mean the caller of
 *              sd_send_scsi_cmd will treat it as a real failure.
 *
 *              To avoid printing too many error logs for a failed uscsi
 *              packet that the caller may not treat it as a failure, the
 *              sd will keep silent for handling all uscsi commands.
 *
 *              During detach->attach and attach-open, for some types of
 *              problems, the driver should be providing information about
 *              the problem encountered. Device use USCSI_SILENT, which
 *              suppresses all driver information. The result is that no
 *              information about the problem is available. Being
 *              completely silent during this time is inappropriate. The
 *              driver needs a more selective filter than USCSI_SILENT, so
 *              that information related to faults is provided.
 *
 *              To make the accurate accessment, the caller  of
 *              sd_send_scsi_USCSI_CMD should take the ownership and
 *              get necessary information to print error messages.
 *
 *              If we want to print necessary info of uscsi command, we need to
 *              keep the uscsi_cmd and sd_uscsi_info till we can make the
 *              assessment. We use sd_ssc_init to alloc necessary
 *              structs for sending an uscsi command and we are also
 *              responsible for free the memory by calling
 *              sd_ssc_fini.
 *
 *              The calling secquences will look like:
 *              sd_ssc_init->
 *
 *                  ...
 *
 *                  sd_send_scsi_USCSI_CMD->
 *                      sd_ssc_send-> - - - sdintr
 *                  ...
 *
 *                  if we think the return value should be treated as a
 *                  failure, we make the accessment here and print out
 *                  necessary by retrieving uscsi_cmd and sd_uscsi_info'
 *
 *                  ...
 *
 *              sd_ssc_fini
 *
 *
 *   Arguments: un - pointer to driver soft state (unit) structure for this
 *                   target.
 *
 * Return code: sd_ssc_t - pointer to allocated sd_ssc_t struct, it contains
 *                         uscsi_cmd and sd_uscsi_info.
 *                  NULL - if can not alloc memory for sd_ssc_t struct
 *
 *     Context: Kernel Thread.
 */
static sd_ssc_t *
sd_ssc_init(struct sd_lun *un)
{
	sd_ssc_t		*ssc;
	struct uscsi_cmd	*ucmdp;
	struct sd_uscsi_info	*uip;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	/*
	 * Allocate sd_ssc_t structure
	 */
	ssc = kmem_zalloc(sizeof (sd_ssc_t), KM_SLEEP);

	/*
	 * Allocate uscsi_cmd by calling scsi_uscsi_alloc common routine
	 */
	ucmdp = scsi_uscsi_alloc();

	/*
	 * Allocate sd_uscsi_info structure
	 */
	uip = kmem_zalloc(sizeof (struct sd_uscsi_info), KM_SLEEP);

	ssc->ssc_uscsi_cmd = ucmdp;
	ssc->ssc_uscsi_info = uip;
	ssc->ssc_un = un;

	return (ssc);
}

/*
 * Function: sd_ssc_fini
 *
 * Description: To free sd_ssc_t and it's hanging off
 *
 * Arguments: ssc - struct pointer of sd_ssc_t.
 */
static void
sd_ssc_fini(sd_ssc_t *ssc)
{
	scsi_uscsi_free(ssc->ssc_uscsi_cmd);

	if (ssc->ssc_uscsi_info != NULL) {
		kmem_free(ssc->ssc_uscsi_info, sizeof (struct sd_uscsi_info));
		ssc->ssc_uscsi_info = NULL;
	}

	kmem_free(ssc, sizeof (sd_ssc_t));
	ssc = NULL;
}

/*
 * Function: sd_ssc_send
 *
 * Description: Runs a USCSI command for user when called through sdioctl,
 *              or for the driver.
 *
 *   Arguments: ssc - the struct of sd_ssc_t will bring uscsi_cmd and
 *                    sd_uscsi_info in.
 *		incmd - ptr to a valid uscsi_cmd struct
 *		flag - bit flag, indicating open settings, 32/64 bit type
 *		dataspace - UIO_USERSPACE or UIO_SYSSPACE
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq.
 *
 * Return Code: 0 -  successful completion of the given command
 *		EIO - scsi_uscsi_handle_command() failed
 *		ENXIO  - soft state not found for specified dev
 *		ECANCELED - command cancelled due to low power
 *		EINVAL
 *		EFAULT - copyin/copyout error
 *		return code of scsi_uscsi_handle_command():
 *			EIO
 *			ENXIO
 *			EACCES
 *
 *     Context: Kernel Thread;
 *              Waits for command to complete. Can sleep.
 */
static int
sd_ssc_send(sd_ssc_t *ssc, struct uscsi_cmd *incmd, int flag,
	enum uio_seg dataspace, int path_flag)
{
	struct sd_uscsi_info	*uip;
	struct uscsi_cmd	*uscmd;
	struct sd_lun		*un;
	dev_t			dev;

	int	format = 0;
	int	rval;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	uscmd = ssc->ssc_uscsi_cmd;
	ASSERT(uscmd != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	if (ssc->ssc_flags & SSC_FLAGS_NEED_ASSESSMENT) {
		/*
		 * If enter here, it indicates that the previous uscsi
		 * command has not been processed by sd_ssc_assessment.
		 * This is violating our rules of FMA telemetry processing.
		 * We should print out this message and the last undisposed
		 * uscsi command.
		 */
		if (uscmd->uscsi_cdb != NULL) {
			SD_INFO(SD_LOG_SDTEST, un,
			    "sd_ssc_send is missing the alternative "
			    "sd_ssc_assessment when running command 0x%x.\n",
			    uscmd->uscsi_cdb[0]);
		}
		/*
		 * Set the ssc_flags to SSC_FLAGS_UNKNOWN, which should be
		 * the initial status.
		 */
		ssc->ssc_flags = SSC_FLAGS_UNKNOWN;
	}

	/*
	 * We need to make sure sd_ssc_send will have sd_ssc_assessment
	 * followed to avoid missing FMA telemetries.
	 */
	ssc->ssc_flags |= SSC_FLAGS_NEED_ASSESSMENT;

	/*
	 * if USCSI_PMFAILFAST is set and un is in low power, fail the
	 * command immediately.
	 */
	mutex_enter(SD_MUTEX(un));
	mutex_enter(&un->un_pm_mutex);
	if ((uscmd->uscsi_flags & USCSI_PMFAILFAST) &&
	    SD_DEVICE_IS_IN_LOW_POWER(un)) {
		SD_TRACE(SD_LOG_IO, un, "sd_ssc_send:"
		    "un:0x%p is in low power\n", un);
		mutex_exit(&un->un_pm_mutex);
		mutex_exit(SD_MUTEX(un));
		return (ECANCELED);
	}
	mutex_exit(&un->un_pm_mutex);
	mutex_exit(SD_MUTEX(un));

#ifdef SDDEBUG
	switch (dataspace) {
	case UIO_USERSPACE:
		SD_TRACE(SD_LOG_IO, un,
		    "sd_ssc_send: entry: un:0x%p UIO_USERSPACE\n", un);
		break;
	case UIO_SYSSPACE:
		SD_TRACE(SD_LOG_IO, un,
		    "sd_ssc_send: entry: un:0x%p UIO_SYSSPACE\n", un);
		break;
	default:
		SD_TRACE(SD_LOG_IO, un,
		    "sd_ssc_send: entry: un:0x%p UNEXPECTED SPACE\n", un);
		break;
	}
#endif

	rval = scsi_uscsi_copyin((intptr_t)incmd, flag,
	    SD_ADDRESS(un), &uscmd);
	if (rval != 0) {
		SD_TRACE(SD_LOG_IO, un, "sd_sense_scsi_cmd: "
		    "scsi_uscsi_alloc_and_copyin failed\n", un);
		return (rval);
	}

	if ((uscmd->uscsi_cdb != NULL) &&
	    (uscmd->uscsi_cdb[0] == SCMD_FORMAT)) {
		mutex_enter(SD_MUTEX(un));
		un->un_f_format_in_progress = TRUE;
		mutex_exit(SD_MUTEX(un));
		format = 1;
	}

	/*
	 * Allocate an sd_uscsi_info struct and fill it with the info
	 * needed by sd_initpkt_for_uscsi().  Then put the pointer into
	 * b_private in the buf for sd_initpkt_for_uscsi().  Note that
	 * since we allocate the buf here in this function, we do not
	 * need to preserve the prior contents of b_private.
	 * The sd_uscsi_info struct is also used by sd_uscsi_strategy()
	 */
	uip = ssc->ssc_uscsi_info;
	uip->ui_flags = path_flag;
	uip->ui_cmdp = uscmd;

	/*
	 * Commands sent with priority are intended for error recovery
	 * situations, and do not have retries performed.
	 */
	if (path_flag == SD_PATH_DIRECT_PRIORITY) {
		uscmd->uscsi_flags |= USCSI_DIAGNOSE;
	}
	uscmd->uscsi_flags &= ~USCSI_NOINTR;

	dev = SD_GET_DEV(un);
	rval = scsi_uscsi_handle_cmd(dev, dataspace, uscmd,
	    sd_uscsi_strategy, NULL, uip);

	/*
	 * mark ssc_flags right after handle_cmd to make sure
	 * the uscsi has been sent
	 */
	ssc->ssc_flags |= SSC_FLAGS_CMD_ISSUED;

#ifdef SDDEBUG
	SD_INFO(SD_LOG_IO, un, "sd_ssc_send: "
	    "uscsi_status: 0x%02x  uscsi_resid:0x%x\n",
	    uscmd->uscsi_status, uscmd->uscsi_resid);
	if (uscmd->uscsi_bufaddr != NULL) {
		SD_INFO(SD_LOG_IO, un, "sd_ssc_send: "
		    "uscmd->uscsi_bufaddr: 0x%p  uscmd->uscsi_buflen:%d\n",
		    uscmd->uscsi_bufaddr, uscmd->uscsi_buflen);
		if (dataspace == UIO_SYSSPACE) {
			SD_DUMP_MEMORY(un, SD_LOG_IO,
			    "data", (uchar_t *)uscmd->uscsi_bufaddr,
			    uscmd->uscsi_buflen, SD_LOG_HEX);
		}
	}
#endif

	if (format == 1) {
		mutex_enter(SD_MUTEX(un));
		un->un_f_format_in_progress = FALSE;
		mutex_exit(SD_MUTEX(un));
	}

	(void) scsi_uscsi_copyout((intptr_t)incmd, uscmd);

	return (rval);
}

/*
 *     Function: sd_ssc_print
 *
 * Description: Print information available to the console.
 *
 * Arguments: ssc - the struct of sd_ssc_t will bring uscsi_cmd and
 *                    sd_uscsi_info in.
 *            sd_severity - log level.
 *     Context: Kernel thread or interrupt context.
 */
static void
sd_ssc_print(sd_ssc_t *ssc, int sd_severity)
{
	struct uscsi_cmd	*ucmdp;
	struct scsi_device	*devp;
	dev_info_t 		*devinfo;
	uchar_t			*sensep;
	int			senlen;
	union scsi_cdb		*cdbp;
	uchar_t			com;
	extern struct scsi_key_strings scsi_cmds[];

	ASSERT(ssc != NULL);
	ASSERT(ssc->ssc_un != NULL);

	if (SD_FM_LOG(ssc->ssc_un) != SD_FM_LOG_EREPORT)
		return;
	ucmdp = ssc->ssc_uscsi_cmd;
	devp = SD_SCSI_DEVP(ssc->ssc_un);
	devinfo = SD_DEVINFO(ssc->ssc_un);
	ASSERT(ucmdp != NULL);
	ASSERT(devp != NULL);
	ASSERT(devinfo != NULL);
	sensep = (uint8_t *)ucmdp->uscsi_rqbuf;
	senlen = ucmdp->uscsi_rqlen - ucmdp->uscsi_rqresid;
	cdbp = (union scsi_cdb *)ucmdp->uscsi_cdb;

	/* In certain case (like DOORLOCK), the cdb could be NULL. */
	if (cdbp == NULL)
		return;
	/* We don't print log if no sense data available. */
	if (senlen == 0)
		sensep = NULL;
	com = cdbp->scc_cmd;
	scsi_generic_errmsg(devp, sd_label, sd_severity, 0, 0, com,
	    scsi_cmds, sensep, ssc->ssc_un->un_additional_codes, NULL);
}

/*
 *     Function: sd_ssc_assessment
 *
 * Description: We use this function to make an assessment at the point
 *              where SD driver may encounter a potential error.
 *
 * Arguments: ssc - the struct of sd_ssc_t will bring uscsi_cmd and
 *                  sd_uscsi_info in.
 *            tp_assess - a hint of strategy for ereport posting.
 *            Possible values of tp_assess include:
 *                SD_FMT_IGNORE - we don't post any ereport because we're
 *                sure that it is ok to ignore the underlying problems.
 *                SD_FMT_IGNORE_COMPROMISE - we don't post any ereport for now
 *                but it might be not correct to ignore the underlying hardware
 *                error.
 *                SD_FMT_STATUS_CHECK - we will post an ereport with the
 *                payload driver-assessment of value "fail" or
 *                "fatal"(depending on what information we have here). This
 *                assessment value is usually set when SD driver think there
 *                is a potential error occurred(Typically, when return value
 *                of the SCSI command is EIO).
 *                SD_FMT_STANDARD - we will post an ereport with the payload
 *                driver-assessment of value "info". This assessment value is
 *                set when the SCSI command returned successfully and with
 *                sense data sent back.
 *
 *     Context: Kernel thread.
 */
static void
sd_ssc_assessment(sd_ssc_t *ssc, enum sd_type_assessment tp_assess)
{
	int senlen = 0;
	struct uscsi_cmd *ucmdp = NULL;
	struct sd_lun *un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ucmdp = ssc->ssc_uscsi_cmd;
	ASSERT(ucmdp != NULL);

	if (ssc->ssc_flags & SSC_FLAGS_NEED_ASSESSMENT) {
		ssc->ssc_flags &= ~SSC_FLAGS_NEED_ASSESSMENT;
	} else {
		/*
		 * If enter here, it indicates that we have a wrong
		 * calling sequence of sd_ssc_send and sd_ssc_assessment,
		 * both of which should be called in a pair in case of
		 * loss of FMA telemetries.
		 */
		if (ucmdp->uscsi_cdb != NULL) {
			SD_INFO(SD_LOG_SDTEST, un,
			    "sd_ssc_assessment is missing the "
			    "alternative sd_ssc_send when running 0x%x, "
			    "or there are superfluous sd_ssc_assessment for "
			    "the same sd_ssc_send.\n",
			    ucmdp->uscsi_cdb[0]);
		}
		/*
		 * Set the ssc_flags to the initial value to avoid passing
		 * down dirty flags to the following sd_ssc_send function.
		 */
		ssc->ssc_flags = SSC_FLAGS_UNKNOWN;
		return;
	}

	/*
	 * Only handle an issued command which is waiting for assessment.
	 * A command which is not issued will not have
	 * SSC_FLAGS_INVALID_DATA set, so it'ok we just return here.
	 */
	if (!(ssc->ssc_flags & SSC_FLAGS_CMD_ISSUED)) {
		sd_ssc_print(ssc, SCSI_ERR_INFO);
		return;
	} else {
		/*
		 * For an issued command, we should clear this flag in
		 * order to make the sd_ssc_t structure be used off
		 * multiple uscsi commands.
		 */
		ssc->ssc_flags &= ~SSC_FLAGS_CMD_ISSUED;
	}

	/*
	 * We will not deal with non-retryable(flag USCSI_DIAGNOSE set)
	 * commands here. And we should clear the ssc_flags before return.
	 */
	if (ucmdp->uscsi_flags & USCSI_DIAGNOSE) {
		ssc->ssc_flags = SSC_FLAGS_UNKNOWN;
		return;
	}

	switch (tp_assess) {
	case SD_FMT_IGNORE:
	case SD_FMT_IGNORE_COMPROMISE:
		break;
	case SD_FMT_STATUS_CHECK:
		/*
		 * For a failed command(including the succeeded command
		 * with invalid data sent back).
		 */
		sd_ssc_post(ssc, SD_FM_DRV_FATAL);
		break;
	case SD_FMT_STANDARD:
		/*
		 * Always for the succeeded commands probably with sense
		 * data sent back.
		 * Limitation:
		 *	We can only handle a succeeded command with sense
		 *	data sent back when auto-request-sense is enabled.
		 */
		senlen = ssc->ssc_uscsi_cmd->uscsi_rqlen -
		    ssc->ssc_uscsi_cmd->uscsi_rqresid;
		if ((ssc->ssc_uscsi_info->ui_pkt_state & STATE_ARQ_DONE) &&
		    (un->un_f_arq_enabled == TRUE) &&
		    senlen > 0 &&
		    ssc->ssc_uscsi_cmd->uscsi_rqbuf != NULL) {
			sd_ssc_post(ssc, SD_FM_DRV_NOTICE);
		}
		break;
	default:
		/*
		 * Should not have other type of assessment.
		 */
		scsi_log(SD_DEVINFO(un), sd_label, CE_CONT,
		    "sd_ssc_assessment got wrong "
		    "sd_type_assessment %d.\n", tp_assess);
		break;
	}
	/*
	 * Clear up the ssc_flags before return.
	 */
	ssc->ssc_flags = SSC_FLAGS_UNKNOWN;
}

/*
 *    Function: sd_ssc_post
 *
 * Description: 1. read the driver property to get fm-scsi-log flag.
 *              2. print log if fm_log_capable is non-zero.
 *              3. call sd_ssc_ereport_post to post ereport if possible.
 *
 *    Context: May be called from kernel thread or interrupt context.
 */
static void
sd_ssc_post(sd_ssc_t *ssc, enum sd_driver_assessment sd_assess)
{
	struct sd_lun	*un;
	int		sd_severity;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	/*
	 * We may enter here from sd_ssc_assessment(for USCSI command) or
	 * by directly called from sdintr context.
	 * We don't handle a non-disk drive(CD-ROM, removable media).
	 * Clear the ssc_flags before return in case we've set
	 * SSC_FLAGS_INVALID_XXX which should be skipped for a non-disk
	 * driver.
	 */
	if (ISCD(un) || un->un_f_has_removable_media) {
		ssc->ssc_flags = SSC_FLAGS_UNKNOWN;
		return;
	}

	switch (sd_assess) {
		case SD_FM_DRV_FATAL:
			sd_severity = SCSI_ERR_FATAL;
			break;
		case SD_FM_DRV_RECOVERY:
			sd_severity = SCSI_ERR_RECOVERED;
			break;
		case SD_FM_DRV_RETRY:
			sd_severity = SCSI_ERR_RETRYABLE;
			break;
		case SD_FM_DRV_NOTICE:
			sd_severity = SCSI_ERR_INFO;
			break;
		default:
			sd_severity = SCSI_ERR_UNKNOWN;
	}
	/* print log */
	sd_ssc_print(ssc, sd_severity);

	/* always post ereport */
	sd_ssc_ereport_post(ssc, sd_assess);
}

/*
 *    Function: sd_ssc_set_info
 *
 * Description: Mark ssc_flags and set ssc_info which would be the
 *              payload of uderr ereport. This function will cause
 *              sd_ssc_ereport_post to post uderr ereport only.
 *              Besides, when ssc_flags == SSC_FLAGS_INVALID_DATA(USCSI),
 *              the function will also call SD_ERROR or scsi_log for a
 *              CDROM/removable-media/DDI_FM_NOT_CAPABLE device.
 *
 * Arguments: ssc - the struct of sd_ssc_t will bring uscsi_cmd and
 *                  sd_uscsi_info in.
 *            ssc_flags - indicate the sub-category of a uderr.
 *            comp - this argument is meaningful only when
 *                   ssc_flags == SSC_FLAGS_INVALID_DATA, and its possible
 *                   values include:
 *                   > 0, SD_ERROR is used with comp as the driver logging
 *                   component;
 *                   = 0, scsi-log is used to log error telemetries;
 *                   < 0, no log available for this telemetry.
 *
 *    Context: Kernel thread or interrupt context
 */
static void
sd_ssc_set_info(sd_ssc_t *ssc, int ssc_flags, uint_t comp, const char *fmt, ...)
{
	va_list	ap;

	ASSERT(ssc != NULL);
	ASSERT(ssc->ssc_un != NULL);

	ssc->ssc_flags |= ssc_flags;
	va_start(ap, fmt);
	(void) vsnprintf(ssc->ssc_info, sizeof (ssc->ssc_info), fmt, ap);
	va_end(ap);

	/*
	 * If SSC_FLAGS_INVALID_DATA is set, it should be a uscsi command
	 * with invalid data sent back. For non-uscsi command, the
	 * following code will be bypassed.
	 */
	if (ssc_flags & SSC_FLAGS_INVALID_DATA) {
		if (SD_FM_LOG(ssc->ssc_un) == SD_FM_LOG_NSUP) {
			/*
			 * If the error belong to certain component and we
			 * do not want it to show up on the console, we
			 * will use SD_ERROR, otherwise scsi_log is
			 * preferred.
			 */
			if (comp > 0) {
				SD_ERROR(comp, ssc->ssc_un, ssc->ssc_info);
			} else if (comp == 0) {
				scsi_log(SD_DEVINFO(ssc->ssc_un), sd_label,
				    CE_WARN, ssc->ssc_info);
			}
		}
	}
}

/*
 *    Function: sd_buf_iodone
 *
 * Description: Frees the sd_xbuf & returns the buf to its originator.
 *
 *     Context: May be called from interrupt context.
 */
/* ARGSUSED */
static void
sd_buf_iodone(int index, struct sd_lun *un, struct buf *bp)
{
	struct sd_xbuf *xp;

	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_buf_iodone: entry.\n");

	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

	/* xbuf is gone after this */
	if (ddi_xbuf_done(bp, un->un_xbuf_attr)) {
		mutex_enter(SD_MUTEX(un));

		/*
		 * Grab time when the cmd completed.
		 * This is used for determining if the system has been
		 * idle long enough to make it idle to the PM framework.
		 * This is for lowering the overhead, and therefore improving
		 * performance per I/O operation.
		 */
		un->un_pm_idle_time = gethrtime();

		un->un_ncmds_in_driver--;
		ASSERT(un->un_ncmds_in_driver >= 0);
		SD_INFO(SD_LOG_IO, un,
		    "sd_buf_iodone: un_ncmds_in_driver = %ld\n",
		    un->un_ncmds_in_driver);

		mutex_exit(SD_MUTEX(un));
	}

	biodone(bp);				/* bp is gone after this */

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_buf_iodone: exit.\n");
}


/*
 *    Function: sd_uscsi_iodone
 *
 * Description: Frees the sd_xbuf & returns the buf to its originator.
 *
 *     Context: May be called from interrupt context.
 */
/* ARGSUSED */
static void
sd_uscsi_iodone(int index, struct sd_lun *un, struct buf *bp)
{
	struct sd_xbuf *xp;

	ASSERT(un != NULL);
	ASSERT(bp != NULL);

	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_INFO(SD_LOG_IO, un, "sd_uscsi_iodone: entry.\n");

	bp->b_private = xp->xb_private;

	mutex_enter(SD_MUTEX(un));

	/*
	 * Grab time when the cmd completed.
	 * This is used for determining if the system has been
	 * idle long enough to make it idle to the PM framework.
	 * This is for lowering the overhead, and therefore improving
	 * performance per I/O operation.
	 */
	un->un_pm_idle_time = gethrtime();

	un->un_ncmds_in_driver--;
	ASSERT(un->un_ncmds_in_driver >= 0);
	SD_INFO(SD_LOG_IO, un, "sd_uscsi_iodone: un_ncmds_in_driver = %ld\n",
	    un->un_ncmds_in_driver);

	mutex_exit(SD_MUTEX(un));

	if (((struct uscsi_cmd *)(xp->xb_pktinfo))->uscsi_rqlen >
	    SENSE_LENGTH) {
		kmem_free(xp, sizeof (struct sd_xbuf) - SENSE_LENGTH +
		    MAX_SENSE_LENGTH);
	} else {
		kmem_free(xp, sizeof (struct sd_xbuf));
	}

	biodone(bp);

	SD_INFO(SD_LOG_IO, un, "sd_uscsi_iodone: exit.\n");
}


/*
 *    Function: sd_mapblockaddr_iostart
 *
 * Description: Verify request lies within the partition limits for
 *		the indicated minor device.  Issue "overrun" buf if
 *		request would exceed partition range.  Converts
 *		partition-relative block address to absolute.
 *
 *              Upon exit of this function:
 *              1.I/O is aligned
 *                 xp->xb_blkno represents the absolute sector address
 *              2.I/O is misaligned
 *                 xp->xb_blkno represents the absolute logical block address
 *                 based on DEV_BSIZE. The logical block address will be
 *                 converted to physical sector address in sd_mapblocksize_\
 *                 iostart.
 *              3.I/O is misaligned but is aligned in "overrun" buf
 *                 xp->xb_blkno represents the absolute logical block address
 *                 based on DEV_BSIZE. The logical block address will be
 *                 converted to physical sector address in sd_mapblocksize_\
 *                 iostart. But no RMW will be issued in this case.
 *
 *     Context: Can sleep
 *
 *      Issues: This follows what the old code did, in terms of accessing
 *		some of the partition info in the unit struct without holding
 *		the mutext.  This is a general issue, if the partition info
 *		can be altered while IO is in progress... as soon as we send
 *		a buf, its partitioning can be invalid before it gets to the
 *		device.  Probably the right fix is to move partitioning out
 *		of the driver entirely.
 */

static void
sd_mapblockaddr_iostart(int index, struct sd_lun *un, struct buf *bp)
{
	diskaddr_t	nblocks;	/* #blocks in the given partition */
	daddr_t	blocknum;	/* Block number specified by the buf */
	size_t	requested_nblocks;
	size_t	available_nblocks;
	int	partition;
	diskaddr_t	partition_offset;
	struct sd_xbuf *xp;
	int secmask = 0, blknomask = 0;
	ushort_t is_aligned = TRUE;

	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_PARTITION, un,
	    "sd_mapblockaddr_iostart: entry: buf:0x%p\n", bp);

	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

	/*
	 * If the geometry is not indicated as valid, attempt to access
	 * the unit & verify the geometry/label. This can be the case for
	 * removable-media devices, of if the device was opened in
	 * NDELAY/NONBLOCK mode.
	 */
	partition = SDPART(bp->b_edev);

	if (!SD_IS_VALID_LABEL(un)) {
		sd_ssc_t *ssc;
		/*
		 * Initialize sd_ssc_t for internal uscsi commands
		 * In case of potential porformance issue, we need
		 * to alloc memory only if there is invalid label
		 */
		ssc = sd_ssc_init(un);

		if (sd_ready_and_valid(ssc, partition) != SD_READY_VALID) {
			/*
			 * For removable devices it is possible to start an
			 * I/O without a media by opening the device in nodelay
			 * mode. Also for writable CDs there can be many
			 * scenarios where there is no geometry yet but volume
			 * manager is trying to issue a read() just because
			 * it can see TOC on the CD. So do not print a message
			 * for removables.
			 */
			if (!un->un_f_has_removable_media) {
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				    "i/o to invalid geometry\n");
			}
			bioerror(bp, EIO);
			bp->b_resid = bp->b_bcount;
			SD_BEGIN_IODONE(index, un, bp);

			sd_ssc_fini(ssc);
			return;
		}
		sd_ssc_fini(ssc);
	}

	nblocks = 0;
	(void) cmlb_partinfo(un->un_cmlbhandle, partition,
	    &nblocks, &partition_offset, NULL, NULL, (void *)SD_PATH_DIRECT);

	if (un->un_f_enable_rmw) {
		blknomask = (un->un_phy_blocksize / DEV_BSIZE) - 1;
		secmask = un->un_phy_blocksize - 1;
	} else {
		blknomask = (un->un_tgt_blocksize / DEV_BSIZE) - 1;
		secmask = un->un_tgt_blocksize - 1;
	}

	if ((bp->b_lblkno & (blknomask)) || (bp->b_bcount & (secmask))) {
		is_aligned = FALSE;
	}

	if (!(NOT_DEVBSIZE(un)) || un->un_f_enable_rmw) {
		/*
		 * If I/O is aligned, no need to involve RMW(Read Modify Write)
		 * Convert the logical block number to target's physical sector
		 * number.
		 */
		if (is_aligned) {
			xp->xb_blkno = SD_SYS2TGTBLOCK(un, xp->xb_blkno);
		} else {
			/*
			 * There is no RMW if we're just reading, so don't
			 * warn or error out because of it.
			 */
			if (bp->b_flags & B_READ) {
				/*EMPTY*/
			} else if (!un->un_f_enable_rmw &&
			    un->un_f_rmw_type == SD_RMW_TYPE_RETURN_ERROR) {
				bp->b_flags |= B_ERROR;
				goto error_exit;
			} else if (un->un_f_rmw_type == SD_RMW_TYPE_DEFAULT) {
				mutex_enter(SD_MUTEX(un));
				if (!un->un_f_enable_rmw &&
				    un->un_rmw_msg_timeid == NULL) {
					scsi_log(SD_DEVINFO(un), sd_label,
					    CE_WARN, "I/O request is not "
					    "aligned with %d disk sector size. "
					    "It is handled through Read Modify "
					    "Write but the performance is "
					    "very low.\n",
					    un->un_tgt_blocksize);
					un->un_rmw_msg_timeid =
					    timeout(sd_rmw_msg_print_handler,
					    un, SD_RMW_MSG_PRINT_TIMEOUT);
				} else {
					un->un_rmw_incre_count ++;
				}
				mutex_exit(SD_MUTEX(un));
			}

			nblocks = SD_TGT2SYSBLOCK(un, nblocks);
			partition_offset = SD_TGT2SYSBLOCK(un,
			    partition_offset);
		}
	}

	/*
	 * blocknum is the starting block number of the request. At this
	 * point it is still relative to the start of the minor device.
	 */
	blocknum = xp->xb_blkno;

	/*
	 * Legacy: If the starting block number is one past the last block
	 * in the partition, do not set B_ERROR in the buf.
	 */
	if (blocknum == nblocks)  {
		goto error_exit;
	}

	/*
	 * Confirm that the first block of the request lies within the
	 * partition limits. Also the requested number of bytes must be
	 * a multiple of the system block size.
	 */
	if ((blocknum < 0) || (blocknum >= nblocks) ||
	    ((bp->b_bcount & (DEV_BSIZE - 1)) != 0)) {
		bp->b_flags |= B_ERROR;
		goto error_exit;
	}

	/*
	 * If the requsted # blocks exceeds the available # blocks, that
	 * is an overrun of the partition.
	 */
	if ((!NOT_DEVBSIZE(un)) && is_aligned) {
		requested_nblocks = SD_BYTES2TGTBLOCKS(un, bp->b_bcount);
	} else {
		requested_nblocks = SD_BYTES2SYSBLOCKS(bp->b_bcount);
	}

	available_nblocks = (size_t)(nblocks - blocknum);
	ASSERT(nblocks >= blocknum);

	if (requested_nblocks > available_nblocks) {
		size_t resid;

		/*
		 * Allocate an "overrun" buf to allow the request to proceed
		 * for the amount of space available in the partition. The
		 * amount not transferred will be added into the b_resid
		 * when the operation is complete. The overrun buf
		 * replaces the original buf here, and the original buf
		 * is saved inside the overrun buf, for later use.
		 */
		if ((!NOT_DEVBSIZE(un)) && is_aligned) {
			resid = SD_TGTBLOCKS2BYTES(un,
			    (offset_t)(requested_nblocks - available_nblocks));
		} else {
			resid = SD_SYSBLOCKS2BYTES(
			    (offset_t)(requested_nblocks - available_nblocks));
		}

		size_t count = bp->b_bcount - resid;
		/*
		 * Note: count is an unsigned entity thus it'll NEVER
		 * be less than 0 so ASSERT the original values are
		 * correct.
		 */
		ASSERT(bp->b_bcount >= resid);

		bp = sd_bioclone_alloc(bp, count, blocknum,
		    (int (*)(struct buf *)) sd_mapblockaddr_iodone);
		xp = SD_GET_XBUF(bp); /* Update for 'new' bp! */
		ASSERT(xp != NULL);
	}

	/* At this point there should be no residual for this buf. */
	ASSERT(bp->b_resid == 0);

	/* Convert the block number to an absolute address. */
	xp->xb_blkno += partition_offset;

	SD_NEXT_IOSTART(index, un, bp);

	SD_TRACE(SD_LOG_IO_PARTITION, un,
	    "sd_mapblockaddr_iostart: exit 0: buf:0x%p\n", bp);

	return;

error_exit:
	bp->b_resid = bp->b_bcount;
	SD_BEGIN_IODONE(index, un, bp);
	SD_TRACE(SD_LOG_IO_PARTITION, un,
	    "sd_mapblockaddr_iostart: exit 1: buf:0x%p\n", bp);
}


/*
 *    Function: sd_mapblockaddr_iodone
 *
 * Description: Completion-side processing for partition management.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_mapblockaddr_iodone(int index, struct sd_lun *un, struct buf *bp)
{
	/* int	partition; */	/* Not used, see below. */
	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_PARTITION, un,
	    "sd_mapblockaddr_iodone: entry: buf:0x%p\n", bp);

	if (bp->b_iodone == (int (*)(struct buf *)) sd_mapblockaddr_iodone) {
		/*
		 * We have an "overrun" buf to deal with...
		 */
		struct sd_xbuf	*xp;
		struct buf	*obp;	/* ptr to the original buf */

		xp = SD_GET_XBUF(bp);
		ASSERT(xp != NULL);

		/* Retrieve the pointer to the original buf */
		obp = (struct buf *)xp->xb_private;
		ASSERT(obp != NULL);

		obp->b_resid = obp->b_bcount - (bp->b_bcount - bp->b_resid);
		bioerror(obp, bp->b_error);

		sd_bioclone_free(bp);

		/*
		 * Get back the original buf.
		 * Note that since the restoration of xb_blkno below
		 * was removed, the sd_xbuf is not needed.
		 */
		bp = obp;
		/*
		 * xp = SD_GET_XBUF(bp);
		 * ASSERT(xp != NULL);
		 */
	}

	/*
	 * Convert sd->xb_blkno back to a minor-device relative value.
	 * Note: this has been commented out, as it is not needed in the
	 * current implementation of the driver (ie, since this function
	 * is at the top of the layering chains, so the info will be
	 * discarded) and it is in the "hot" IO path.
	 *
	 * partition = getminor(bp->b_edev) & SDPART_MASK;
	 * xp->xb_blkno -= un->un_offset[partition];
	 */

	SD_NEXT_IODONE(index, un, bp);

	SD_TRACE(SD_LOG_IO_PARTITION, un,
	    "sd_mapblockaddr_iodone: exit: buf:0x%p\n", bp);
}


/*
 *    Function: sd_mapblocksize_iostart
 *
 * Description: Convert between system block size (un->un_sys_blocksize)
 *		and target block size (un->un_tgt_blocksize).
 *
 *     Context: Can sleep to allocate resources.
 *
 * Assumptions: A higher layer has already performed any partition validation,
 *		and converted the xp->xb_blkno to an absolute value relative
 *		to the start of the device.
 *
 *		It is also assumed that the higher layer has implemented
 *		an "overrun" mechanism for the case where the request would
 *		read/write beyond the end of a partition.  In this case we
 *		assume (and ASSERT) that bp->b_resid == 0.
 *
 *		Note: The implementation for this routine assumes the target
 *		block size remains constant between allocation and transport.
 */

static void
sd_mapblocksize_iostart(int index, struct sd_lun *un, struct buf *bp)
{
	struct sd_mapblocksize_info	*bsp;
	struct sd_xbuf			*xp;
	offset_t first_byte;
	daddr_t	start_block, end_block;
	daddr_t	request_bytes;
	ushort_t is_aligned = FALSE;

	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bp->b_resid == 0);

	SD_TRACE(SD_LOG_IO_RMMEDIA, un,
	    "sd_mapblocksize_iostart: entry: buf:0x%p\n", bp);

	/*
	 * For a non-writable CD, a write request is an error
	 */
	if (ISCD(un) && ((bp->b_flags & B_READ) == 0) &&
	    (un->un_f_mmc_writable_media == FALSE)) {
		bioerror(bp, EIO);
		bp->b_resid = bp->b_bcount;
		SD_BEGIN_IODONE(index, un, bp);
		return;
	}

	/*
	 * We do not need a shadow buf if the device is using
	 * un->un_sys_blocksize as its block size or if bcount == 0.
	 * In this case there is no layer-private data block allocated.
	 */
	if ((un->un_tgt_blocksize == DEV_BSIZE && !un->un_f_enable_rmw) ||
	    (bp->b_bcount == 0)) {
		goto done;
	}

#if defined(__i386) || defined(__amd64)
	/* We do not support non-block-aligned transfers for ROD devices */
	ASSERT(!ISROD(un));
#endif

	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

	SD_INFO(SD_LOG_IO_RMMEDIA, un, "sd_mapblocksize_iostart: "
	    "tgt_blocksize:0x%x sys_blocksize: 0x%x\n",
	    un->un_tgt_blocksize, DEV_BSIZE);
	SD_INFO(SD_LOG_IO_RMMEDIA, un, "sd_mapblocksize_iostart: "
	    "request start block:0x%x\n", xp->xb_blkno);
	SD_INFO(SD_LOG_IO_RMMEDIA, un, "sd_mapblocksize_iostart: "
	    "request len:0x%x\n", bp->b_bcount);

	/*
	 * Allocate the layer-private data area for the mapblocksize layer.
	 * Layers are allowed to use the xp_private member of the sd_xbuf
	 * struct to store the pointer to their layer-private data block, but
	 * each layer also has the responsibility of restoring the prior
	 * contents of xb_private before returning the buf/xbuf to the
	 * higher layer that sent it.
	 *
	 * Here we save the prior contents of xp->xb_private into the
	 * bsp->mbs_oprivate field of our layer-private data area. This value
	 * is restored by sd_mapblocksize_iodone() just prior to freeing up
	 * the layer-private area and returning the buf/xbuf to the layer
	 * that sent it.
	 *
	 * Note that here we use kmem_zalloc for the allocation as there are
	 * parts of the mapblocksize code that expect certain fields to be
	 * zero unless explicitly set to a required value.
	 */
	bsp = kmem_zalloc(sizeof (struct sd_mapblocksize_info), KM_SLEEP);
	bsp->mbs_oprivate = xp->xb_private;
	xp->xb_private = bsp;

	/*
	 * This treats the data on the disk (target) as an array of bytes.
	 * first_byte is the byte offset, from the beginning of the device,
	 * to the location of the request. This is converted from a
	 * un->un_sys_blocksize block address to a byte offset, and then back
	 * to a block address based upon a un->un_tgt_blocksize block size.
	 *
	 * xp->xb_blkno should be absolute upon entry into this function,
	 * but, but it is based upon partitions that use the "system"
	 * block size. It must be adjusted to reflect the block size of
	 * the target.
	 *
	 * Note that end_block is actually the block that follows the last
	 * block of the request, but that's what is needed for the computation.
	 */
	first_byte  = SD_SYSBLOCKS2BYTES((offset_t)xp->xb_blkno);
	if (un->un_f_enable_rmw) {
		start_block = xp->xb_blkno =
		    (first_byte / un->un_phy_blocksize) *
		    (un->un_phy_blocksize / DEV_BSIZE);
		end_block   = ((first_byte + bp->b_bcount +
		    un->un_phy_blocksize - 1) / un->un_phy_blocksize) *
		    (un->un_phy_blocksize / DEV_BSIZE);
	} else {
		start_block = xp->xb_blkno = first_byte / un->un_tgt_blocksize;
		end_block   = (first_byte + bp->b_bcount +
		    un->un_tgt_blocksize - 1) / un->un_tgt_blocksize;
	}

	/* request_bytes is rounded up to a multiple of the target block size */
	request_bytes = (end_block - start_block) * un->un_tgt_blocksize;

	/*
	 * See if the starting address of the request and the request
	 * length are aligned on a un->un_tgt_blocksize boundary. If aligned
	 * then we do not need to allocate a shadow buf to handle the request.
	 */
	if (un->un_f_enable_rmw) {
		if (((first_byte % un->un_phy_blocksize) == 0) &&
		    ((bp->b_bcount % un->un_phy_blocksize) == 0)) {
			is_aligned = TRUE;
		}
	} else {
		if (((first_byte % un->un_tgt_blocksize) == 0) &&
		    ((bp->b_bcount % un->un_tgt_blocksize) == 0)) {
			is_aligned = TRUE;
		}
	}

	if ((bp->b_flags & B_READ) == 0) {
		/*
		 * Lock the range for a write operation. An aligned request is
		 * considered a simple write; otherwise the request must be a
		 * read-modify-write.
		 */
		bsp->mbs_wmp = sd_range_lock(un, start_block, end_block - 1,
		    (is_aligned == TRUE) ? SD_WTYPE_SIMPLE : SD_WTYPE_RMW);
	}

	/*
	 * Alloc a shadow buf if the request is not aligned. Also, this is
	 * where the READ command is generated for a read-modify-write. (The
	 * write phase is deferred until after the read completes.)
	 */
	if (is_aligned == FALSE) {

		struct sd_mapblocksize_info	*shadow_bsp;
		struct sd_xbuf	*shadow_xp;
		struct buf	*shadow_bp;

		/*
		 * Allocate the shadow buf and it associated xbuf. Note that
		 * after this call the xb_blkno value in both the original
		 * buf's sd_xbuf _and_ the shadow buf's sd_xbuf will be the
		 * same: absolute relative to the start of the device, and
		 * adjusted for the target block size. The b_blkno in the
		 * shadow buf will also be set to this value. We should never
		 * change b_blkno in the original bp however.
		 *
		 * Note also that the shadow buf will always need to be a
		 * READ command, regardless of whether the incoming command
		 * is a READ or a WRITE.
		 */
		shadow_bp = sd_shadow_buf_alloc(bp, request_bytes, B_READ,
		    xp->xb_blkno,
		    (int (*)(struct buf *)) sd_mapblocksize_iodone);

		shadow_xp = SD_GET_XBUF(shadow_bp);

		/*
		 * Allocate the layer-private data for the shadow buf.
		 * (No need to preserve xb_private in the shadow xbuf.)
		 */
		shadow_xp->xb_private = shadow_bsp =
		    kmem_zalloc(sizeof (struct sd_mapblocksize_info), KM_SLEEP);

		/*
		 * bsp->mbs_copy_offset is used later by sd_mapblocksize_iodone
		 * to figure out where the start of the user data is (based upon
		 * the system block size) in the data returned by the READ
		 * command (which will be based upon the target blocksize). Note
		 * that this is only really used if the request is unaligned.
		 */
		if (un->un_f_enable_rmw) {
			bsp->mbs_copy_offset = (ssize_t)(first_byte -
			    ((offset_t)xp->xb_blkno * un->un_sys_blocksize));
			ASSERT((bsp->mbs_copy_offset >= 0) &&
			    (bsp->mbs_copy_offset < un->un_phy_blocksize));
		} else {
			bsp->mbs_copy_offset = (ssize_t)(first_byte -
			    ((offset_t)xp->xb_blkno * un->un_tgt_blocksize));
			ASSERT((bsp->mbs_copy_offset >= 0) &&
			    (bsp->mbs_copy_offset < un->un_tgt_blocksize));
		}

		shadow_bsp->mbs_copy_offset = bsp->mbs_copy_offset;

		shadow_bsp->mbs_layer_index = bsp->mbs_layer_index = index;

		/* Transfer the wmap (if any) to the shadow buf */
		shadow_bsp->mbs_wmp = bsp->mbs_wmp;
		bsp->mbs_wmp = NULL;

		/*
		 * The shadow buf goes on from here in place of the
		 * original buf.
		 */
		shadow_bsp->mbs_orig_bp = bp;
		bp = shadow_bp;
	}

	SD_INFO(SD_LOG_IO_RMMEDIA, un,
	    "sd_mapblocksize_iostart: tgt start block:0x%x\n", xp->xb_blkno);
	SD_INFO(SD_LOG_IO_RMMEDIA, un,
	    "sd_mapblocksize_iostart: tgt request len:0x%x\n",
	    request_bytes);
	SD_INFO(SD_LOG_IO_RMMEDIA, un,
	    "sd_mapblocksize_iostart: shadow buf:0x%x\n", bp);

done:
	SD_NEXT_IOSTART(index, un, bp);

	SD_TRACE(SD_LOG_IO_RMMEDIA, un,
	    "sd_mapblocksize_iostart: exit: buf:0x%p\n", bp);
}


/*
 *    Function: sd_mapblocksize_iodone
 *
 * Description: Completion side processing for block-size mapping.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_mapblocksize_iodone(int index, struct sd_lun *un, struct buf *bp)
{
	struct sd_mapblocksize_info	*bsp;
	struct sd_xbuf	*xp;
	struct sd_xbuf	*orig_xp;	/* sd_xbuf for the original buf */
	struct buf	*orig_bp;	/* ptr to the original buf */
	offset_t	shadow_end;
	offset_t	request_end;
	offset_t	shadow_start;
	ssize_t		copy_offset;
	size_t		copy_length;
	size_t		shortfall;
	uint_t		is_write;	/* TRUE if this bp is a WRITE */
	uint_t		has_wmap;	/* TRUE is this bp has a wmap */

	ASSERT(un != NULL);
	ASSERT(bp != NULL);

	SD_TRACE(SD_LOG_IO_RMMEDIA, un,
	    "sd_mapblocksize_iodone: entry: buf:0x%p\n", bp);

	/*
	 * There is no shadow buf or layer-private data if the target is
	 * using un->un_sys_blocksize as its block size or if bcount == 0.
	 */
	if ((un->un_tgt_blocksize == DEV_BSIZE && !un->un_f_enable_rmw) ||
	    (bp->b_bcount == 0)) {
		goto exit;
	}

	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

	/* Retrieve the pointer to the layer-private data area from the xbuf. */
	bsp = xp->xb_private;

	is_write = ((bp->b_flags & B_READ) == 0) ? TRUE : FALSE;
	has_wmap = (bsp->mbs_wmp != NULL) ? TRUE : FALSE;

	if (is_write) {
		/*
		 * For a WRITE request we must free up the block range that
		 * we have locked up.  This holds regardless of whether this is
		 * an aligned write request or a read-modify-write request.
		 */
		sd_range_unlock(un, bsp->mbs_wmp);
		bsp->mbs_wmp = NULL;
	}

	if ((bp->b_iodone != (int(*)(struct buf *))sd_mapblocksize_iodone)) {
		/*
		 * An aligned read or write command will have no shadow buf;
		 * there is not much else to do with it.
		 */
		goto done;
	}

	orig_bp = bsp->mbs_orig_bp;
	ASSERT(orig_bp != NULL);
	orig_xp = SD_GET_XBUF(orig_bp);
	ASSERT(orig_xp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	if (!is_write && has_wmap) {
		/*
		 * A READ with a wmap means this is the READ phase of a
		 * read-modify-write. If an error occurred on the READ then
		 * we do not proceed with the WRITE phase or copy any data.
		 * Just release the write maps and return with an error.
		 */
		if ((bp->b_resid != 0) || (bp->b_error != 0)) {
			orig_bp->b_resid = orig_bp->b_bcount;
			bioerror(orig_bp, bp->b_error);
			sd_range_unlock(un, bsp->mbs_wmp);
			goto freebuf_done;
		}
	}

	/*
	 * Here is where we set up to copy the data from the shadow buf
	 * into the space associated with the original buf.
	 *
	 * To deal with the conversion between block sizes, these
	 * computations treat the data as an array of bytes, with the
	 * first byte (byte 0) corresponding to the first byte in the
	 * first block on the disk.
	 */

	/*
	 * shadow_start and shadow_len indicate the location and size of
	 * the data returned with the shadow IO request.
	 */
	if (un->un_f_enable_rmw) {
		shadow_start  = SD_SYSBLOCKS2BYTES((offset_t)xp->xb_blkno);
	} else {
		shadow_start  = SD_TGTBLOCKS2BYTES(un, (offset_t)xp->xb_blkno);
	}
	shadow_end    = shadow_start + bp->b_bcount - bp->b_resid;

	/*
	 * copy_offset gives the offset (in bytes) from the start of the first
	 * block of the READ request to the beginning of the data.  We retrieve
	 * this value from xb_pktp in the ORIGINAL xbuf, as it has been saved
	 * there by sd_mapblockize_iostart(). copy_length gives the amount of
	 * data to be copied (in bytes).
	 */
	copy_offset  = bsp->mbs_copy_offset;
	if (un->un_f_enable_rmw) {
		ASSERT((copy_offset >= 0) &&
		    (copy_offset < un->un_phy_blocksize));
	} else {
		ASSERT((copy_offset >= 0) &&
		    (copy_offset < un->un_tgt_blocksize));
	}

	copy_length  = orig_bp->b_bcount;
	request_end  = shadow_start + copy_offset + orig_bp->b_bcount;

	/*
	 * Set up the resid and error fields of orig_bp as appropriate.
	 */
	if (shadow_end >= request_end) {
		/* We got all the requested data; set resid to zero */
		orig_bp->b_resid = 0;
	} else {
		/*
		 * We failed to get enough data to fully satisfy the original
		 * request. Just copy back whatever data we got and set
		 * up the residual and error code as required.
		 *
		 * 'shortfall' is the amount by which the data received with the
		 * shadow buf has "fallen short" of the requested amount.
		 */
		shortfall = (size_t)(request_end - shadow_end);

		if (shortfall > orig_bp->b_bcount) {
			/*
			 * We did not get enough data to even partially
			 * fulfill the original request.  The residual is
			 * equal to the amount requested.
			 */
			orig_bp->b_resid = orig_bp->b_bcount;
		} else {
			/*
			 * We did not get all the data that we requested
			 * from the device, but we will try to return what
			 * portion we did get.
			 */
			orig_bp->b_resid = shortfall;
		}
		ASSERT(copy_length >= orig_bp->b_resid);
		copy_length  -= orig_bp->b_resid;
	}

	/* Propagate the error code from the shadow buf to the original buf */
	bioerror(orig_bp, bp->b_error);

	if (is_write) {
		goto freebuf_done;	/* No data copying for a WRITE */
	}

	if (has_wmap) {
		/*
		 * This is a READ command from the READ phase of a
		 * read-modify-write request. We have to copy the data given
		 * by the user OVER the data returned by the READ command,
		 * then convert the command from a READ to a WRITE and send
		 * it back to the target.
		 */
		bcopy(orig_bp->b_un.b_addr, bp->b_un.b_addr + copy_offset,
		    copy_length);

		bp->b_flags &= ~((int)B_READ);	/* Convert to a WRITE */

		/*
		 * Dispatch the WRITE command to the taskq thread, which
		 * will in turn send the command to the target. When the
		 * WRITE command completes, we (sd_mapblocksize_iodone())
		 * will get called again as part of the iodone chain
		 * processing for it. Note that we will still be dealing
		 * with the shadow buf at that point.
		 */
		if (taskq_dispatch(sd_wmr_tq, sd_read_modify_write_task, bp,
		    KM_NOSLEEP) != 0) {
			/*
			 * Dispatch was successful so we are done. Return
			 * without going any higher up the iodone chain. Do
			 * not free up any layer-private data until after the
			 * WRITE completes.
			 */
			return;
		}

		/*
		 * Dispatch of the WRITE command failed; set up the error
		 * condition and send this IO back up the iodone chain.
		 */
		bioerror(orig_bp, EIO);
		orig_bp->b_resid = orig_bp->b_bcount;

	} else {
		/*
		 * This is a regular READ request (ie, not a RMW). Copy the
		 * data from the shadow buf into the original buf. The
		 * copy_offset compensates for any "misalignment" between the
		 * shadow buf (with its un->un_tgt_blocksize blocks) and the
		 * original buf (with its un->un_sys_blocksize blocks).
		 */
		bcopy(bp->b_un.b_addr + copy_offset, orig_bp->b_un.b_addr,
		    copy_length);
	}

freebuf_done:

	/*
	 * At this point we still have both the shadow buf AND the original
	 * buf to deal with, as well as the layer-private data area in each.
	 * Local variables are as follows:
	 *
	 * bp -- points to shadow buf
	 * xp -- points to xbuf of shadow buf
	 * bsp -- points to layer-private data area of shadow buf
	 * orig_bp -- points to original buf
	 *
	 * First free the shadow buf and its associated xbuf, then free the
	 * layer-private data area from the shadow buf. There is no need to
	 * restore xb_private in the shadow xbuf.
	 */
	sd_shadow_buf_free(bp);
	kmem_free(bsp, sizeof (struct sd_mapblocksize_info));

	/*
	 * Now update the local variables to point to the original buf, xbuf,
	 * and layer-private area.
	 */
	bp = orig_bp;
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	ASSERT(xp == orig_xp);
	bsp = xp->xb_private;
	ASSERT(bsp != NULL);

done:
	/*
	 * Restore xb_private to whatever it was set to by the next higher
	 * layer in the chain, then free the layer-private data area.
	 */
	xp->xb_private = bsp->mbs_oprivate;
	kmem_free(bsp, sizeof (struct sd_mapblocksize_info));

exit:
	SD_TRACE(SD_LOG_IO_RMMEDIA, SD_GET_UN(bp),
	    "sd_mapblocksize_iodone: calling SD_NEXT_IODONE: buf:0x%p\n", bp);

	SD_NEXT_IODONE(index, un, bp);
}


/*
 *    Function: sd_checksum_iostart
 *
 * Description: A stub function for a layer that's currently not used.
 *		For now just a placeholder.
 *
 *     Context: Kernel thread context
 */

static void
sd_checksum_iostart(int index, struct sd_lun *un, struct buf *bp)
{
	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	SD_NEXT_IOSTART(index, un, bp);
}


/*
 *    Function: sd_checksum_iodone
 *
 * Description: A stub function for a layer that's currently not used.
 *		For now just a placeholder.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_checksum_iodone(int index, struct sd_lun *un, struct buf *bp)
{
	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	SD_NEXT_IODONE(index, un, bp);
}


/*
 *    Function: sd_checksum_uscsi_iostart
 *
 * Description: A stub function for a layer that's currently not used.
 *		For now just a placeholder.
 *
 *     Context: Kernel thread context
 */

static void
sd_checksum_uscsi_iostart(int index, struct sd_lun *un, struct buf *bp)
{
	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	SD_NEXT_IOSTART(index, un, bp);
}


/*
 *    Function: sd_checksum_uscsi_iodone
 *
 * Description: A stub function for a layer that's currently not used.
 *		For now just a placeholder.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_checksum_uscsi_iodone(int index, struct sd_lun *un, struct buf *bp)
{
	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	SD_NEXT_IODONE(index, un, bp);
}


/*
 *    Function: sd_pm_iostart
 *
 * Description: iostart-side routine for Power mangement.
 *
 *     Context: Kernel thread context
 */

static void
sd_pm_iostart(int index, struct sd_lun *un, struct buf *bp)
{
	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(!mutex_owned(&un->un_pm_mutex));

	SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_iostart: entry\n");

	if (sd_pm_entry(un) != DDI_SUCCESS) {
		/*
		 * Set up to return the failed buf back up the 'iodone'
		 * side of the calling chain.
		 */
		bioerror(bp, EIO);
		bp->b_resid = bp->b_bcount;

		SD_BEGIN_IODONE(index, un, bp);

		SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_iostart: exit\n");
		return;
	}

	SD_NEXT_IOSTART(index, un, bp);

	SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_iostart: exit\n");
}


/*
 *    Function: sd_pm_iodone
 *
 * Description: iodone-side routine for power mangement.
 *
 *     Context: may be called from interrupt context
 */

static void
sd_pm_iodone(int index, struct sd_lun *un, struct buf *bp)
{
	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(&un->un_pm_mutex));

	SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_iodone: entry\n");

	/*
	 * After attach the following flag is only read, so don't
	 * take the penalty of acquiring a mutex for it.
	 */
	if (un->un_f_pm_is_enabled == TRUE) {
		sd_pm_exit(un);
	}

	SD_NEXT_IODONE(index, un, bp);

	SD_TRACE(SD_LOG_IO_PM, un, "sd_pm_iodone: exit\n");
}


/*
 *    Function: sd_core_iostart
 *
 * Description: Primary driver function for enqueuing buf(9S) structs from
 *		the system and initiating IO to the target device
 *
 *     Context: Kernel thread context. Can sleep.
 *
 * Assumptions:  - The given xp->xb_blkno is absolute
 *		   (ie, relative to the start of the device).
 *		 - The IO is to be done using the native blocksize of
 *		   the device, as specified in un->un_tgt_blocksize.
 */
/* ARGSUSED */
static void
sd_core_iostart(int index, struct sd_lun *un, struct buf *bp)
{
	struct sd_xbuf *xp;

	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bp->b_resid == 0);

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_core_iostart: entry: bp:0x%p\n", bp);

	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

	mutex_enter(SD_MUTEX(un));

	/*
	 * If we are currently in the failfast state, fail any new IO
	 * that has B_FAILFAST set, then return.
	 */
	if ((bp->b_flags & B_FAILFAST) &&
	    (un->un_failfast_state == SD_FAILFAST_ACTIVE)) {
		mutex_exit(SD_MUTEX(un));
		bioerror(bp, EIO);
		bp->b_resid = bp->b_bcount;
		SD_BEGIN_IODONE(index, un, bp);
		return;
	}

	if (SD_IS_DIRECT_PRIORITY(xp)) {
		/*
		 * Priority command -- transport it immediately.
		 *
		 * Note: We may want to assert that USCSI_DIAGNOSE is set,
		 * because all direct priority commands should be associated
		 * with error recovery actions which we don't want to retry.
		 */
		sd_start_cmds(un, bp);
	} else {
		/*
		 * Normal command -- add it to the wait queue, then start
		 * transporting commands from the wait queue.
		 */
		sd_add_buf_to_waitq(un, bp);
		SD_UPDATE_KSTATS(un, kstat_waitq_enter, bp);
		sd_start_cmds(un, NULL);
	}

	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_core_iostart: exit: bp:0x%p\n", bp);
}


/*
 *    Function: sd_init_cdb_limits
 *
 * Description: This is to handle scsi_pkt initialization differences
 *		between the driver platforms.
 *
 *		Legacy behaviors:
 *
 *		If the block number or the sector count exceeds the
 *		capabilities of a Group 0 command, shift over to a
 *		Group 1 command. We don't blindly use Group 1
 *		commands because a) some drives (CDC Wren IVs) get a
 *		bit confused, and b) there is probably a fair amount
 *		of speed difference for a target to receive and decode
 *		a 10 byte command instead of a 6 byte command.
 *
 *		The xfer time difference of 6 vs 10 byte CDBs is
 *		still significant so this code is still worthwhile.
 *		10 byte CDBs are very inefficient with the fas HBA driver
 *		and older disks. Each CDB byte took 1 usec with some
 *		popular disks.
 *
 *     Context: Must be called at attach time
 */

static void
sd_init_cdb_limits(struct sd_lun *un)
{
	int hba_cdb_limit;

	/*
	 * Use CDB_GROUP1 commands for most devices except for
	 * parallel SCSI fixed drives in which case we get better
	 * performance using CDB_GROUP0 commands (where applicable).
	 */
	un->un_mincdb = SD_CDB_GROUP1;
#if !defined(__fibre)
	if (!un->un_f_is_fibre && !un->un_f_cfg_is_atapi && !ISROD(un) &&
	    !un->un_f_has_removable_media) {
		un->un_mincdb = SD_CDB_GROUP0;
	}
#endif

	/*
	 * Try to read the max-cdb-length supported by HBA.
	 */
	un->un_max_hba_cdb = scsi_ifgetcap(SD_ADDRESS(un), "max-cdb-length", 1);
	if (0 >= un->un_max_hba_cdb) {
		un->un_max_hba_cdb = CDB_GROUP4;
		hba_cdb_limit = SD_CDB_GROUP4;
	} else if (0 < un->un_max_hba_cdb &&
	    un->un_max_hba_cdb < CDB_GROUP1) {
		hba_cdb_limit = SD_CDB_GROUP0;
	} else if (CDB_GROUP1 <= un->un_max_hba_cdb &&
	    un->un_max_hba_cdb < CDB_GROUP5) {
		hba_cdb_limit = SD_CDB_GROUP1;
	} else if (CDB_GROUP5 <= un->un_max_hba_cdb &&
	    un->un_max_hba_cdb < CDB_GROUP4) {
		hba_cdb_limit = SD_CDB_GROUP5;
	} else {
		hba_cdb_limit = SD_CDB_GROUP4;
	}

	/*
	 * Use CDB_GROUP5 commands for removable devices.  Use CDB_GROUP4
	 * commands for fixed disks unless we are building for a 32 bit
	 * kernel.
	 */
#ifdef _LP64
	un->un_maxcdb = (un->un_f_has_removable_media) ? SD_CDB_GROUP5 :
	    min(hba_cdb_limit, SD_CDB_GROUP4);
#else
	un->un_maxcdb = (un->un_f_has_removable_media) ? SD_CDB_GROUP5 :
	    min(hba_cdb_limit, SD_CDB_GROUP1);
#endif

	un->un_status_len = (int)((un->un_f_arq_enabled == TRUE)
	    ? sizeof (struct scsi_arq_status) : 1);
	if (!ISCD(un))
		un->un_cmd_timeout = (ushort_t)sd_io_time;
	un->un_uscsi_timeout = ((ISCD(un)) ? 2 : 1) * un->un_cmd_timeout;
}


/*
 *    Function: sd_initpkt_for_buf
 *
 * Description: Allocate and initialize for transport a scsi_pkt struct,
 *		based upon the info specified in the given buf struct.
 *
 *		Assumes the xb_blkno in the request is absolute (ie,
 *		relative to the start of the device (NOT partition!).
 *		Also assumes that the request is using the native block
 *		size of the device (as returned by the READ CAPACITY
 *		command).
 *
 * Return Code: SD_PKT_ALLOC_SUCCESS
 *		SD_PKT_ALLOC_FAILURE
 *		SD_PKT_ALLOC_FAILURE_NO_DMA
 *		SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL
 *
 *     Context: Kernel thread and may be called from software interrupt context
 *		as part of a sdrunout callback. This function may not block or
 *		call routines that block
 */

static int
sd_initpkt_for_buf(struct buf *bp, struct scsi_pkt **pktpp)
{
	struct sd_xbuf	*xp;
	struct scsi_pkt *pktp = NULL;
	struct sd_lun	*un;
	size_t		blockcount;
	daddr_t		startblock;
	int		rval;
	int		cmd_flags;

	ASSERT(bp != NULL);
	ASSERT(pktpp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	un = SD_GET_UN(bp);
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp->b_resid == 0);

	SD_TRACE(SD_LOG_IO_CORE, un,
	    "sd_initpkt_for_buf: entry: buf:0x%p\n", bp);

	mutex_exit(SD_MUTEX(un));

#if defined(__i386) || defined(__amd64)	/* DMAFREE for x86 only */
	if (xp->xb_pkt_flags & SD_XB_DMA_FREED) {
		/*
		 * Already have a scsi_pkt -- just need DMA resources.
		 * We must recompute the CDB in case the mapping returns
		 * a nonzero pkt_resid.
		 * Note: if this is a portion of a PKT_DMA_PARTIAL transfer
		 * that is being retried, the unmap/remap of the DMA resouces
		 * will result in the entire transfer starting over again
		 * from the very first block.
		 */
		ASSERT(xp->xb_pktp != NULL);
		pktp = xp->xb_pktp;
	} else {
		pktp = NULL;
	}
#endif /* __i386 || __amd64 */

	startblock = xp->xb_blkno;	/* Absolute block num. */
	blockcount = SD_BYTES2TGTBLOCKS(un, bp->b_bcount);

	cmd_flags = un->un_pkt_flags | (xp->xb_pkt_flags & SD_XB_INITPKT_MASK);

	/*
	 * sd_setup_rw_pkt will determine the appropriate CDB group to use,
	 * call scsi_init_pkt, and build the CDB.
	 */
	rval = sd_setup_rw_pkt(un, &pktp, bp,
	    cmd_flags, sdrunout, (caddr_t)un,
	    startblock, blockcount);

	if (rval == 0) {
		/*
		 * Success.
		 *
		 * If partial DMA is being used and required for this transfer.
		 * set it up here.
		 */
		if ((un->un_pkt_flags & PKT_DMA_PARTIAL) != 0 &&
		    (pktp->pkt_resid != 0)) {

			/*
			 * Save the CDB length and pkt_resid for the
			 * next xfer
			 */
			xp->xb_dma_resid = pktp->pkt_resid;

			/* rezero resid */
			pktp->pkt_resid = 0;

		} else {
			xp->xb_dma_resid = 0;
		}

		pktp->pkt_flags = un->un_tagflags;
		pktp->pkt_time  = un->un_cmd_timeout;
		pktp->pkt_comp  = sdintr;

		pktp->pkt_private = bp;
		*pktpp = pktp;

		SD_TRACE(SD_LOG_IO_CORE, un,
		    "sd_initpkt_for_buf: exit: buf:0x%p\n", bp);

#if defined(__i386) || defined(__amd64)	/* DMAFREE for x86 only */
		xp->xb_pkt_flags &= ~SD_XB_DMA_FREED;
#endif

		mutex_enter(SD_MUTEX(un));
		return (SD_PKT_ALLOC_SUCCESS);

	}

	/*
	 * SD_PKT_ALLOC_FAILURE is the only expected failure code
	 * from sd_setup_rw_pkt.
	 */
	ASSERT(rval == SD_PKT_ALLOC_FAILURE);

	if (rval == SD_PKT_ALLOC_FAILURE) {
		*pktpp = NULL;
		/*
		 * Set the driver state to RWAIT to indicate the driver
		 * is waiting on resource allocations. The driver will not
		 * suspend, pm_suspend, or detatch while the state is RWAIT.
		 */
		mutex_enter(SD_MUTEX(un));
		New_state(un, SD_STATE_RWAIT);

		SD_ERROR(SD_LOG_IO_CORE, un,
		    "sd_initpkt_for_buf: No pktp. exit bp:0x%p\n", bp);

		if ((bp->b_flags & B_ERROR) != 0) {
			return (SD_PKT_ALLOC_FAILURE_NO_DMA);
		}
		return (SD_PKT_ALLOC_FAILURE);
	} else {
		/*
		 * PKT_ALLOC_FAILURE_CDB_TOO_SMALL
		 *
		 * This should never happen.  Maybe someone messed with the
		 * kernel's minphys?
		 */
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "Request rejected: too large for CDB: "
		    "lba:0x%08lx  len:0x%08lx\n", startblock, blockcount);
		SD_ERROR(SD_LOG_IO_CORE, un,
		    "sd_initpkt_for_buf: No cp. exit bp:0x%p\n", bp);
		mutex_enter(SD_MUTEX(un));
		return (SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL);

	}
}


/*
 *    Function: sd_destroypkt_for_buf
 *
 * Description: Free the scsi_pkt(9S) for the given bp (buf IO processing).
 *
 *     Context: Kernel thread or interrupt context
 */

static void
sd_destroypkt_for_buf(struct buf *bp)
{
	ASSERT(bp != NULL);
	ASSERT(SD_GET_UN(bp) != NULL);

	SD_TRACE(SD_LOG_IO_CORE, SD_GET_UN(bp),
	    "sd_destroypkt_for_buf: entry: buf:0x%p\n", bp);

	ASSERT(SD_GET_PKTP(bp) != NULL);
	scsi_destroy_pkt(SD_GET_PKTP(bp));

	SD_TRACE(SD_LOG_IO_CORE, SD_GET_UN(bp),
	    "sd_destroypkt_for_buf: exit: buf:0x%p\n", bp);
}

/*
 *    Function: sd_setup_rw_pkt
 *
 * Description: Determines appropriate CDB group for the requested LBA
 *		and transfer length, calls scsi_init_pkt, and builds
 *		the CDB.  Do not use for partial DMA transfers except
 *		for the initial transfer since the CDB size must
 *		remain constant.
 *
 *     Context: Kernel thread and may be called from software interrupt
 *		context as part of a sdrunout callback. This function may not
 *		block or call routines that block
 */


int
sd_setup_rw_pkt(struct sd_lun *un,
    struct scsi_pkt **pktpp, struct buf *bp, int flags,
    int (*callback)(caddr_t), caddr_t callback_arg,
    diskaddr_t lba, uint32_t blockcount)
{
	struct scsi_pkt *return_pktp;
	union scsi_cdb *cdbp;
	struct sd_cdbinfo *cp = NULL;
	int i;

	/*
	 * See which size CDB to use, based upon the request.
	 */
	for (i = un->un_mincdb; i <= un->un_maxcdb; i++) {

		/*
		 * Check lba and block count against sd_cdbtab limits.
		 * In the partial DMA case, we have to use the same size
		 * CDB for all the transfers.  Check lba + blockcount
		 * against the max LBA so we know that segment of the
		 * transfer can use the CDB we select.
		 */
		if ((lba + blockcount - 1 <= sd_cdbtab[i].sc_maxlba) &&
		    (blockcount <= sd_cdbtab[i].sc_maxlen)) {

			/*
			 * The command will fit into the CDB type
			 * specified by sd_cdbtab[i].
			 */
			cp = sd_cdbtab + i;

			/*
			 * Call scsi_init_pkt so we can fill in the
			 * CDB.
			 */
			return_pktp = scsi_init_pkt(SD_ADDRESS(un), *pktpp,
			    bp, cp->sc_grpcode, un->un_status_len, 0,
			    flags, callback, callback_arg);

			if (return_pktp != NULL) {

				/*
				 * Return new value of pkt
				 */
				*pktpp = return_pktp;

				/*
				 * To be safe, zero the CDB insuring there is
				 * no leftover data from a previous command.
				 */
				bzero(return_pktp->pkt_cdbp, cp->sc_grpcode);

				/*
				 * Handle partial DMA mapping
				 */
				if (return_pktp->pkt_resid != 0) {

					/*
					 * Not going to xfer as many blocks as
					 * originally expected
					 */
					blockcount -=
					    SD_BYTES2TGTBLOCKS(un,
					    return_pktp->pkt_resid);
				}

				cdbp = (union scsi_cdb *)return_pktp->pkt_cdbp;

				/*
				 * Set command byte based on the CDB
				 * type we matched.
				 */
				cdbp->scc_cmd = cp->sc_grpmask |
				    ((bp->b_flags & B_READ) ?
				    SCMD_READ : SCMD_WRITE);

				SD_FILL_SCSI1_LUN(un, return_pktp);

				/*
				 * Fill in LBA and length
				 */
				ASSERT((cp->sc_grpcode == CDB_GROUP1) ||
				    (cp->sc_grpcode == CDB_GROUP4) ||
				    (cp->sc_grpcode == CDB_GROUP0) ||
				    (cp->sc_grpcode == CDB_GROUP5));

				if (cp->sc_grpcode == CDB_GROUP1) {
					FORMG1ADDR(cdbp, lba);
					FORMG1COUNT(cdbp, blockcount);
					return (0);
				} else if (cp->sc_grpcode == CDB_GROUP4) {
					FORMG4LONGADDR(cdbp, lba);
					FORMG4COUNT(cdbp, blockcount);
					return (0);
				} else if (cp->sc_grpcode == CDB_GROUP0) {
					FORMG0ADDR(cdbp, lba);
					FORMG0COUNT(cdbp, blockcount);
					return (0);
				} else if (cp->sc_grpcode == CDB_GROUP5) {
					FORMG5ADDR(cdbp, lba);
					FORMG5COUNT(cdbp, blockcount);
					return (0);
				}

				/*
				 * It should be impossible to not match one
				 * of the CDB types above, so we should never
				 * reach this point.  Set the CDB command byte
				 * to test-unit-ready to avoid writing
				 * to somewhere we don't intend.
				 */
				cdbp->scc_cmd = SCMD_TEST_UNIT_READY;
				return (SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL);
			} else {
				/*
				 * Couldn't get scsi_pkt
				 */
				return (SD_PKT_ALLOC_FAILURE);
			}
		}
	}

	/*
	 * None of the available CDB types were suitable.  This really
	 * should never happen:  on a 64 bit system we support
	 * READ16/WRITE16 which will hold an entire 64 bit disk address
	 * and on a 32 bit system we will refuse to bind to a device
	 * larger than 2TB so addresses will never be larger than 32 bits.
	 */
	return (SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL);
}

/*
 *    Function: sd_setup_next_rw_pkt
 *
 * Description: Setup packet for partial DMA transfers, except for the
 * 		initial transfer.  sd_setup_rw_pkt should be used for
 *		the initial transfer.
 *
 *     Context: Kernel thread and may be called from interrupt context.
 */

int
sd_setup_next_rw_pkt(struct sd_lun *un,
    struct scsi_pkt *pktp, struct buf *bp,
    diskaddr_t lba, uint32_t blockcount)
{
	uchar_t com;
	union scsi_cdb *cdbp;
	uchar_t cdb_group_id;

	ASSERT(pktp != NULL);
	ASSERT(pktp->pkt_cdbp != NULL);

	cdbp = (union scsi_cdb *)pktp->pkt_cdbp;
	com = cdbp->scc_cmd;
	cdb_group_id = CDB_GROUPID(com);

	ASSERT((cdb_group_id == CDB_GROUPID_0) ||
	    (cdb_group_id == CDB_GROUPID_1) ||
	    (cdb_group_id == CDB_GROUPID_4) ||
	    (cdb_group_id == CDB_GROUPID_5));

	/*
	 * Move pkt to the next portion of the xfer.
	 * func is NULL_FUNC so we do not have to release
	 * the disk mutex here.
	 */
	if (scsi_init_pkt(SD_ADDRESS(un), pktp, bp, 0, 0, 0, 0,
	    NULL_FUNC, NULL) == pktp) {
		/* Success.  Handle partial DMA */
		if (pktp->pkt_resid != 0) {
			blockcount -=
			    SD_BYTES2TGTBLOCKS(un, pktp->pkt_resid);
		}

		cdbp->scc_cmd = com;
		SD_FILL_SCSI1_LUN(un, pktp);
		if (cdb_group_id == CDB_GROUPID_1) {
			FORMG1ADDR(cdbp, lba);
			FORMG1COUNT(cdbp, blockcount);
			return (0);
		} else if (cdb_group_id == CDB_GROUPID_4) {
			FORMG4LONGADDR(cdbp, lba);
			FORMG4COUNT(cdbp, blockcount);
			return (0);
		} else if (cdb_group_id == CDB_GROUPID_0) {
			FORMG0ADDR(cdbp, lba);
			FORMG0COUNT(cdbp, blockcount);
			return (0);
		} else if (cdb_group_id == CDB_GROUPID_5) {
			FORMG5ADDR(cdbp, lba);
			FORMG5COUNT(cdbp, blockcount);
			return (0);
		}

		/* Unreachable */
		return (SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL);
	}

	/*
	 * Error setting up next portion of cmd transfer.
	 * Something is definitely very wrong and this
	 * should not happen.
	 */
	return (SD_PKT_ALLOC_FAILURE);
}

/*
 *    Function: sd_initpkt_for_uscsi
 *
 * Description: Allocate and initialize for transport a scsi_pkt struct,
 *		based upon the info specified in the given uscsi_cmd struct.
 *
 * Return Code: SD_PKT_ALLOC_SUCCESS
 *		SD_PKT_ALLOC_FAILURE
 *		SD_PKT_ALLOC_FAILURE_NO_DMA
 *		SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL
 *
 *     Context: Kernel thread and may be called from software interrupt context
 *		as part of a sdrunout callback. This function may not block or
 *		call routines that block
 */

static int
sd_initpkt_for_uscsi(struct buf *bp, struct scsi_pkt **pktpp)
{
	struct uscsi_cmd *uscmd;
	struct sd_xbuf	*xp;
	struct scsi_pkt	*pktp;
	struct sd_lun	*un;
	uint32_t	flags = 0;

	ASSERT(bp != NULL);
	ASSERT(pktpp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	un = SD_GET_UN(bp);
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	/* The pointer to the uscsi_cmd struct is expected in xb_pktinfo */
	uscmd = (struct uscsi_cmd *)xp->xb_pktinfo;
	ASSERT(uscmd != NULL);

	SD_TRACE(SD_LOG_IO_CORE, un,
	    "sd_initpkt_for_uscsi: entry: buf:0x%p\n", bp);

	/*
	 * Allocate the scsi_pkt for the command.
	 * Note: If PKT_DMA_PARTIAL flag is set, scsi_vhci binds a path
	 *	 during scsi_init_pkt time and will continue to use the
	 *	 same path as long as the same scsi_pkt is used without
	 *	 intervening scsi_dma_free(). Since uscsi command does
	 *	 not call scsi_dmafree() before retry failed command, it
	 *	 is necessary to make sure PKT_DMA_PARTIAL flag is NOT
	 *	 set such that scsi_vhci can use other available path for
	 *	 retry. Besides, ucsci command does not allow DMA breakup,
	 *	 so there is no need to set PKT_DMA_PARTIAL flag.
	 */
	if (uscmd->uscsi_rqlen > SENSE_LENGTH) {
		pktp = scsi_init_pkt(SD_ADDRESS(un), NULL,
		    ((bp->b_bcount != 0) ? bp : NULL), uscmd->uscsi_cdblen,
		    ((int)(uscmd->uscsi_rqlen) + sizeof (struct scsi_arq_status)
		    - sizeof (struct scsi_extended_sense)), 0,
		    (un->un_pkt_flags & ~PKT_DMA_PARTIAL) | PKT_XARQ,
		    sdrunout, (caddr_t)un);
	} else {
		pktp = scsi_init_pkt(SD_ADDRESS(un), NULL,
		    ((bp->b_bcount != 0) ? bp : NULL), uscmd->uscsi_cdblen,
		    sizeof (struct scsi_arq_status), 0,
		    (un->un_pkt_flags & ~PKT_DMA_PARTIAL),
		    sdrunout, (caddr_t)un);
	}

	if (pktp == NULL) {
		*pktpp = NULL;
		/*
		 * Set the driver state to RWAIT to indicate the driver
		 * is waiting on resource allocations. The driver will not
		 * suspend, pm_suspend, or detatch while the state is RWAIT.
		 */
		New_state(un, SD_STATE_RWAIT);

		SD_ERROR(SD_LOG_IO_CORE, un,
		    "sd_initpkt_for_uscsi: No pktp. exit bp:0x%p\n", bp);

		if ((bp->b_flags & B_ERROR) != 0) {
			return (SD_PKT_ALLOC_FAILURE_NO_DMA);
		}
		return (SD_PKT_ALLOC_FAILURE);
	}

	/*
	 * We do not do DMA breakup for USCSI commands, so return failure
	 * here if all the needed DMA resources were not allocated.
	 */
	if ((un->un_pkt_flags & PKT_DMA_PARTIAL) &&
	    (bp->b_bcount != 0) && (pktp->pkt_resid != 0)) {
		scsi_destroy_pkt(pktp);
		SD_ERROR(SD_LOG_IO_CORE, un, "sd_initpkt_for_uscsi: "
		    "No partial DMA for USCSI. exit: buf:0x%p\n", bp);
		return (SD_PKT_ALLOC_FAILURE_PKT_TOO_SMALL);
	}

	/* Init the cdb from the given uscsi struct */
	(void) scsi_setup_cdb((union scsi_cdb *)pktp->pkt_cdbp,
	    uscmd->uscsi_cdb[0], 0, 0, 0);

	SD_FILL_SCSI1_LUN(un, pktp);

	/*
	 * Set up the optional USCSI flags. See the uscsi (7I) man page
	 * for listing of the supported flags.
	 */

	if (uscmd->uscsi_flags & USCSI_SILENT) {
		flags |= FLAG_SILENT;
	}

	if (uscmd->uscsi_flags & USCSI_DIAGNOSE) {
		flags |= FLAG_DIAGNOSE;
	}

	if (uscmd->uscsi_flags & USCSI_ISOLATE) {
		flags |= FLAG_ISOLATE;
	}

	if (un->un_f_is_fibre == FALSE) {
		if (uscmd->uscsi_flags & USCSI_RENEGOT) {
			flags |= FLAG_RENEGOTIATE_WIDE_SYNC;
		}
	}

	/*
	 * Set the pkt flags here so we save time later.
	 * Note: These flags are NOT in the uscsi man page!!!
	 */
	if (uscmd->uscsi_flags & USCSI_HEAD) {
		flags |= FLAG_HEAD;
	}

	if (uscmd->uscsi_flags & USCSI_NOINTR) {
		flags |= FLAG_NOINTR;
	}

	/*
	 * For tagged queueing, things get a bit complicated.
	 * Check first for head of queue and last for ordered queue.
	 * If neither head nor order, use the default driver tag flags.
	 */
	if ((uscmd->uscsi_flags & USCSI_NOTAG) == 0) {
		if (uscmd->uscsi_flags & USCSI_HTAG) {
			flags |= FLAG_HTAG;
		} else if (uscmd->uscsi_flags & USCSI_OTAG) {
			flags |= FLAG_OTAG;
		} else {
			flags |= un->un_tagflags & FLAG_TAGMASK;
		}
	}

	if (uscmd->uscsi_flags & USCSI_NODISCON) {
		flags = (flags & ~FLAG_TAGMASK) | FLAG_NODISCON;
	}

	pktp->pkt_flags = flags;

	/* Transfer uscsi information to scsi_pkt */
	(void) scsi_uscsi_pktinit(uscmd, pktp);

	/* Copy the caller's CDB into the pkt... */
	bcopy(uscmd->uscsi_cdb, pktp->pkt_cdbp, uscmd->uscsi_cdblen);

	if (uscmd->uscsi_timeout == 0) {
		pktp->pkt_time = un->un_uscsi_timeout;
	} else {
		pktp->pkt_time = uscmd->uscsi_timeout;
	}

	/* need it later to identify USCSI request in sdintr */
	xp->xb_pkt_flags |= SD_XB_USCSICMD;

	xp->xb_sense_resid = uscmd->uscsi_rqresid;

	pktp->pkt_private = bp;
	pktp->pkt_comp = sdintr;
	*pktpp = pktp;

	SD_TRACE(SD_LOG_IO_CORE, un,
	    "sd_initpkt_for_uscsi: exit: buf:0x%p\n", bp);

	return (SD_PKT_ALLOC_SUCCESS);
}


/*
 *    Function: sd_destroypkt_for_uscsi
 *
 * Description: Free the scsi_pkt(9S) struct for the given bp, for uscsi
 *		IOs.. Also saves relevant info into the associated uscsi_cmd
 *		struct.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_destroypkt_for_uscsi(struct buf *bp)
{
	struct uscsi_cmd *uscmd;
	struct sd_xbuf	*xp;
	struct scsi_pkt	*pktp;
	struct sd_lun	*un;
	struct sd_uscsi_info *suip;

	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	un = SD_GET_UN(bp);
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	pktp = SD_GET_PKTP(bp);
	ASSERT(pktp != NULL);

	SD_TRACE(SD_LOG_IO_CORE, un,
	    "sd_destroypkt_for_uscsi: entry: buf:0x%p\n", bp);

	/* The pointer to the uscsi_cmd struct is expected in xb_pktinfo */
	uscmd = (struct uscsi_cmd *)xp->xb_pktinfo;
	ASSERT(uscmd != NULL);

	/* Save the status and the residual into the uscsi_cmd struct */
	uscmd->uscsi_status = ((*(pktp)->pkt_scbp) & STATUS_MASK);
	uscmd->uscsi_resid  = bp->b_resid;

	/* Transfer scsi_pkt information to uscsi */
	(void) scsi_uscsi_pktfini(pktp, uscmd);

	/*
	 * If enabled, copy any saved sense data into the area specified
	 * by the uscsi command.
	 */
	if (((uscmd->uscsi_flags & USCSI_RQENABLE) != 0) &&
	    (uscmd->uscsi_rqlen != 0) && (uscmd->uscsi_rqbuf != NULL)) {
		/*
		 * Note: uscmd->uscsi_rqbuf should always point to a buffer
		 * at least SENSE_LENGTH bytes in size (see sd_send_scsi_cmd())
		 */
		uscmd->uscsi_rqstatus = xp->xb_sense_status;
		uscmd->uscsi_rqresid  = xp->xb_sense_resid;
		if (uscmd->uscsi_rqlen > SENSE_LENGTH) {
			bcopy(xp->xb_sense_data, uscmd->uscsi_rqbuf,
			    MAX_SENSE_LENGTH);
		} else {
			bcopy(xp->xb_sense_data, uscmd->uscsi_rqbuf,
			    SENSE_LENGTH);
		}
	}
	/*
	 * The following assignments are for SCSI FMA.
	 */
	ASSERT(xp->xb_private != NULL);
	suip = (struct sd_uscsi_info *)xp->xb_private;
	suip->ui_pkt_reason = pktp->pkt_reason;
	suip->ui_pkt_state = pktp->pkt_state;
	suip->ui_pkt_statistics = pktp->pkt_statistics;
	suip->ui_lba = (uint64_t)SD_GET_BLKNO(bp);

	/* We are done with the scsi_pkt; free it now */
	ASSERT(SD_GET_PKTP(bp) != NULL);
	scsi_destroy_pkt(SD_GET_PKTP(bp));

	SD_TRACE(SD_LOG_IO_CORE, un,
	    "sd_destroypkt_for_uscsi: exit: buf:0x%p\n", bp);
}


/*
 *    Function: sd_bioclone_alloc
 *
 * Description: Allocate a buf(9S) and init it as per the given buf
 *		and the various arguments.  The associated sd_xbuf
 *		struct is (nearly) duplicated.  The struct buf *bp
 *		argument is saved in new_xp->xb_private.
 *
 *   Arguments: bp - ptr the the buf(9S) to be "shadowed"
 *		datalen - size of data area for the shadow bp
 *		blkno - starting LBA
 *		func - function pointer for b_iodone in the shadow buf. (May
 *			be NULL if none.)
 *
 * Return Code: Pointer to allocates buf(9S) struct
 *
 *     Context: Can sleep.
 */

static struct buf *
sd_bioclone_alloc(struct buf *bp, size_t datalen,
	daddr_t blkno, int (*func)(struct buf *))
{
	struct	sd_lun	*un;
	struct	sd_xbuf	*xp;
	struct	sd_xbuf	*new_xp;
	struct	buf	*new_bp;

	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	un = SD_GET_UN(bp);
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	new_bp = bioclone(bp, 0, datalen, SD_GET_DEV(un), blkno, func,
	    NULL, KM_SLEEP);

	new_bp->b_lblkno	= blkno;

	/*
	 * Allocate an xbuf for the shadow bp and copy the contents of the
	 * original xbuf into it.
	 */
	new_xp = kmem_alloc(sizeof (struct sd_xbuf), KM_SLEEP);
	bcopy(xp, new_xp, sizeof (struct sd_xbuf));

	/*
	 * The given bp is automatically saved in the xb_private member
	 * of the new xbuf.  Callers are allowed to depend on this.
	 */
	new_xp->xb_private = bp;

	new_bp->b_private  = new_xp;

	return (new_bp);
}

/*
 *    Function: sd_shadow_buf_alloc
 *
 * Description: Allocate a buf(9S) and init it as per the given buf
 *		and the various arguments.  The associated sd_xbuf
 *		struct is (nearly) duplicated.  The struct buf *bp
 *		argument is saved in new_xp->xb_private.
 *
 *   Arguments: bp - ptr the the buf(9S) to be "shadowed"
 *		datalen - size of data area for the shadow bp
 *		bflags - B_READ or B_WRITE (pseudo flag)
 *		blkno - starting LBA
 *		func - function pointer for b_iodone in the shadow buf. (May
 *			be NULL if none.)
 *
 * Return Code: Pointer to allocates buf(9S) struct
 *
 *     Context: Can sleep.
 */

static struct buf *
sd_shadow_buf_alloc(struct buf *bp, size_t datalen, uint_t bflags,
	daddr_t blkno, int (*func)(struct buf *))
{
	struct	sd_lun	*un;
	struct	sd_xbuf	*xp;
	struct	sd_xbuf	*new_xp;
	struct	buf	*new_bp;

	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	un = SD_GET_UN(bp);
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	if (bp->b_flags & (B_PAGEIO | B_PHYS)) {
		bp_mapin(bp);
	}

	bflags &= (B_READ | B_WRITE);
#if defined(__i386) || defined(__amd64)
	new_bp = getrbuf(KM_SLEEP);
	new_bp->b_un.b_addr = kmem_zalloc(datalen, KM_SLEEP);
	new_bp->b_bcount = datalen;
	new_bp->b_flags = bflags |
	    (bp->b_flags & ~(B_PAGEIO | B_PHYS | B_REMAPPED | B_SHADOW));
#else
	new_bp = scsi_alloc_consistent_buf(SD_ADDRESS(un), NULL,
	    datalen, bflags, SLEEP_FUNC, NULL);
#endif
	new_bp->av_forw	= NULL;
	new_bp->av_back	= NULL;
	new_bp->b_dev	= bp->b_dev;
	new_bp->b_blkno	= blkno;
	new_bp->b_iodone = func;
	new_bp->b_edev	= bp->b_edev;
	new_bp->b_resid	= 0;

	/* We need to preserve the B_FAILFAST flag */
	if (bp->b_flags & B_FAILFAST) {
		new_bp->b_flags |= B_FAILFAST;
	}

	/*
	 * Allocate an xbuf for the shadow bp and copy the contents of the
	 * original xbuf into it.
	 */
	new_xp = kmem_alloc(sizeof (struct sd_xbuf), KM_SLEEP);
	bcopy(xp, new_xp, sizeof (struct sd_xbuf));

	/* Need later to copy data between the shadow buf & original buf! */
	new_xp->xb_pkt_flags |= PKT_CONSISTENT;

	/*
	 * The given bp is automatically saved in the xb_private member
	 * of the new xbuf.  Callers are allowed to depend on this.
	 */
	new_xp->xb_private = bp;

	new_bp->b_private  = new_xp;

	return (new_bp);
}

/*
 *    Function: sd_bioclone_free
 *
 * Description: Deallocate a buf(9S) that was used for 'shadow' IO operations
 *		in the larger than partition operation.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_bioclone_free(struct buf *bp)
{
	struct sd_xbuf	*xp;

	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

	/*
	 * Call bp_mapout() before freeing the buf,  in case a lower
	 * layer or HBA  had done a bp_mapin().  we must do this here
	 * as we are the "originator" of the shadow buf.
	 */
	bp_mapout(bp);

	/*
	 * Null out b_iodone before freeing the bp, to ensure that the driver
	 * never gets confused by a stale value in this field. (Just a little
	 * extra defensiveness here.)
	 */
	bp->b_iodone = NULL;

	freerbuf(bp);

	kmem_free(xp, sizeof (struct sd_xbuf));
}

/*
 *    Function: sd_shadow_buf_free
 *
 * Description: Deallocate a buf(9S) that was used for 'shadow' IO operations.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_shadow_buf_free(struct buf *bp)
{
	struct sd_xbuf	*xp;

	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

#if defined(__sparc)
	/*
	 * Call bp_mapout() before freeing the buf,  in case a lower
	 * layer or HBA  had done a bp_mapin().  we must do this here
	 * as we are the "originator" of the shadow buf.
	 */
	bp_mapout(bp);
#endif

	/*
	 * Null out b_iodone before freeing the bp, to ensure that the driver
	 * never gets confused by a stale value in this field. (Just a little
	 * extra defensiveness here.)
	 */
	bp->b_iodone = NULL;

#if defined(__i386) || defined(__amd64)
	kmem_free(bp->b_un.b_addr, bp->b_bcount);
	freerbuf(bp);
#else
	scsi_free_consistent_buf(bp);
#endif

	kmem_free(xp, sizeof (struct sd_xbuf));
}


/*
 *    Function: sd_print_transport_rejected_message
 *
 * Description: This implements the ludicrously complex rules for printing
 *		a "transport rejected" message.  This is to address the
 *		specific problem of having a flood of this error message
 *		produced when a failover occurs.
 *
 *     Context: Any.
 */

static void
sd_print_transport_rejected_message(struct sd_lun *un, struct sd_xbuf *xp,
	int code)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(xp != NULL);

	/*
	 * Print the "transport rejected" message under the following
	 * conditions:
	 *
	 * - Whenever the SD_LOGMASK_DIAG bit of sd_level_mask is set
	 * - The error code from scsi_transport() is NOT a TRAN_FATAL_ERROR.
	 * - If the error code IS a TRAN_FATAL_ERROR, then the message is
	 *   printed the FIRST time a TRAN_FATAL_ERROR is returned from
	 *   scsi_transport(9F) (which indicates that the target might have
	 *   gone off-line).  This uses the un->un_tran_fatal_count
	 *   count, which is incremented whenever a TRAN_FATAL_ERROR is
	 *   received, and reset to zero whenver a TRAN_ACCEPT is returned
	 *   from scsi_transport().
	 *
	 * The FLAG_SILENT in the scsi_pkt must be CLEARED in ALL of
	 * the preceeding cases in order for the message to be printed.
	 */
	if (((xp->xb_pktp->pkt_flags & FLAG_SILENT) == 0) &&
	    (SD_FM_LOG(un) == SD_FM_LOG_NSUP)) {
		if ((sd_level_mask & SD_LOGMASK_DIAG) ||
		    (code != TRAN_FATAL_ERROR) ||
		    (un->un_tran_fatal_count == 1)) {
			switch (code) {
			case TRAN_BADPKT:
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				    "transport rejected bad packet\n");
				break;
			case TRAN_FATAL_ERROR:
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				    "transport rejected fatal error\n");
				break;
			default:
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				    "transport rejected (%d)\n", code);
				break;
			}
		}
	}
}


/*
 *    Function: sd_add_buf_to_waitq
 *
 * Description: Add the given buf(9S) struct to the wait queue for the
 *		instance.  If sorting is enabled, then the buf is added
 *		to the queue via an elevator sort algorithm (a la
 *		disksort(9F)).  The SD_GET_BLKNO(bp) is used as the sort key.
 *		If sorting is not enabled, then the buf is just added
 *		to the end of the wait queue.
 *
 * Return Code: void
 *
 *     Context: Does not sleep/block, therefore technically can be called
 *		from any context.  However if sorting is enabled then the
 *		execution time is indeterminate, and may take long if
 *		the wait queue grows large.
 */

static void
sd_add_buf_to_waitq(struct sd_lun *un, struct buf *bp)
{
	struct buf *ap;

	ASSERT(bp != NULL);
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	/* If the queue is empty, add the buf as the only entry & return. */
	if (un->un_waitq_headp == NULL) {
		ASSERT(un->un_waitq_tailp == NULL);
		un->un_waitq_headp = un->un_waitq_tailp = bp;
		bp->av_forw = NULL;
		return;
	}

	ASSERT(un->un_waitq_tailp != NULL);

	/*
	 * If sorting is disabled, just add the buf to the tail end of
	 * the wait queue and return.
	 */
	if (un->un_f_disksort_disabled || un->un_f_enable_rmw) {
		un->un_waitq_tailp->av_forw = bp;
		un->un_waitq_tailp = bp;
		bp->av_forw = NULL;
		return;
	}

	/*
	 * Sort thru the list of requests currently on the wait queue
	 * and add the new buf request at the appropriate position.
	 *
	 * The un->un_waitq_headp is an activity chain pointer on which
	 * we keep two queues, sorted in ascending SD_GET_BLKNO() order. The
	 * first queue holds those requests which are positioned after
	 * the current SD_GET_BLKNO() (in the first request); the second holds
	 * requests which came in after their SD_GET_BLKNO() number was passed.
	 * Thus we implement a one way scan, retracting after reaching
	 * the end of the drive to the first request on the second
	 * queue, at which time it becomes the first queue.
	 * A one-way scan is natural because of the way UNIX read-ahead
	 * blocks are allocated.
	 *
	 * If we lie after the first request, then we must locate the
	 * second request list and add ourselves to it.
	 */
	ap = un->un_waitq_headp;
	if (SD_GET_BLKNO(bp) < SD_GET_BLKNO(ap)) {
		while (ap->av_forw != NULL) {
			/*
			 * Look for an "inversion" in the (normally
			 * ascending) block numbers. This indicates
			 * the start of the second request list.
			 */
			if (SD_GET_BLKNO(ap->av_forw) < SD_GET_BLKNO(ap)) {
				/*
				 * Search the second request list for the
				 * first request at a larger block number.
				 * We go before that; however if there is
				 * no such request, we go at the end.
				 */
				do {
					if (SD_GET_BLKNO(bp) <
					    SD_GET_BLKNO(ap->av_forw)) {
						goto insert;
					}
					ap = ap->av_forw;
				} while (ap->av_forw != NULL);
				goto insert;		/* after last */
			}
			ap = ap->av_forw;
		}

		/*
		 * No inversions... we will go after the last, and
		 * be the first request in the second request list.
		 */
		goto insert;
	}

	/*
	 * Request is at/after the current request...
	 * sort in the first request list.
	 */
	while (ap->av_forw != NULL) {
		/*
		 * We want to go after the current request (1) if
		 * there is an inversion after it (i.e. it is the end
		 * of the first request list), or (2) if the next
		 * request is a larger block no. than our request.
		 */
		if ((SD_GET_BLKNO(ap->av_forw) < SD_GET_BLKNO(ap)) ||
		    (SD_GET_BLKNO(bp) < SD_GET_BLKNO(ap->av_forw))) {
			goto insert;
		}
		ap = ap->av_forw;
	}

	/*
	 * Neither a second list nor a larger request, therefore
	 * we go at the end of the first list (which is the same
	 * as the end of the whole schebang).
	 */
insert:
	bp->av_forw = ap->av_forw;
	ap->av_forw = bp;

	/*
	 * If we inserted onto the tail end of the waitq, make sure the
	 * tail pointer is updated.
	 */
	if (ap == un->un_waitq_tailp) {
		un->un_waitq_tailp = bp;
	}
}


/*
 *    Function: sd_start_cmds
 *
 * Description: Remove and transport cmds from the driver queues.
 *
 *   Arguments: un - pointer to the unit (soft state) struct for the target.
 *
 *		immed_bp - ptr to a buf to be transported immediately. Only
 *		the immed_bp is transported; bufs on the waitq are not
 *		processed and the un_retry_bp is not checked.  If immed_bp is
 *		NULL, then normal queue processing is performed.
 *
 *     Context: May be called from kernel thread context, interrupt context,
 *		or runout callback context. This function may not block or
 *		call routines that block.
 */

static void
sd_start_cmds(struct sd_lun *un, struct buf *immed_bp)
{
	struct	sd_xbuf	*xp;
	struct	buf	*bp;
	void	(*statp)(kstat_io_t *);
#if defined(__i386) || defined(__amd64)	/* DMAFREE for x86 only */
	void	(*saved_statp)(kstat_io_t *);
#endif
	int	rval;
	struct sd_fm_internal *sfip = NULL;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(un->un_ncmds_in_transport >= 0);
	ASSERT(un->un_throttle >= 0);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_start_cmds: entry\n");

	do {
#if defined(__i386) || defined(__amd64)	/* DMAFREE for x86 only */
		saved_statp = NULL;
#endif

		/*
		 * If we are syncing or dumping, fail the command to
		 * avoid recursively calling back into scsi_transport().
		 * The dump I/O itself uses a separate code path so this
		 * only prevents non-dump I/O from being sent while dumping.
		 * File system sync takes place before dumping begins.
		 * During panic, filesystem I/O is allowed provided
		 * un_in_callback is <= 1.  This is to prevent recursion
		 * such as sd_start_cmds -> scsi_transport -> sdintr ->
		 * sd_start_cmds and so on.  See panic.c for more information
		 * about the states the system can be in during panic.
		 */
		if ((un->un_state == SD_STATE_DUMPING) ||
		    (ddi_in_panic() && (un->un_in_callback > 1))) {
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_start_cmds: panicking\n");
			goto exit;
		}

		if ((bp = immed_bp) != NULL) {
			/*
			 * We have a bp that must be transported immediately.
			 * It's OK to transport the immed_bp here without doing
			 * the throttle limit check because the immed_bp is
			 * always used in a retry/recovery case. This means
			 * that we know we are not at the throttle limit by
			 * virtue of the fact that to get here we must have
			 * already gotten a command back via sdintr(). This also
			 * relies on (1) the command on un_retry_bp preventing
			 * further commands from the waitq from being issued;
			 * and (2) the code in sd_retry_command checking the
			 * throttle limit before issuing a delayed or immediate
			 * retry. This holds even if the throttle limit is
			 * currently ratcheted down from its maximum value.
			 */
			statp = kstat_runq_enter;
			if (bp == un->un_retry_bp) {
				ASSERT((un->un_retry_statp == NULL) ||
				    (un->un_retry_statp == kstat_waitq_enter) ||
				    (un->un_retry_statp ==
				    kstat_runq_back_to_waitq));
				/*
				 * If the waitq kstat was incremented when
				 * sd_set_retry_bp() queued this bp for a retry,
				 * then we must set up statp so that the waitq
				 * count will get decremented correctly below.
				 * Also we must clear un->un_retry_statp to
				 * ensure that we do not act on a stale value
				 * in this field.
				 */
				if ((un->un_retry_statp == kstat_waitq_enter) ||
				    (un->un_retry_statp ==
				    kstat_runq_back_to_waitq)) {
					statp = kstat_waitq_to_runq;
				}
#if defined(__i386) || defined(__amd64)	/* DMAFREE for x86 only */
				saved_statp = un->un_retry_statp;
#endif
				un->un_retry_statp = NULL;

				SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un,
				    "sd_start_cmds: un:0x%p: GOT retry_bp:0x%p "
				    "un_throttle:%d un_ncmds_in_transport:%d\n",
				    un, un->un_retry_bp, un->un_throttle,
				    un->un_ncmds_in_transport);
			} else {
				SD_TRACE(SD_LOG_IO_CORE, un, "sd_start_cmds: "
				    "processing priority bp:0x%p\n", bp);
			}

		} else if ((bp = un->un_waitq_headp) != NULL) {
			/*
			 * A command on the waitq is ready to go, but do not
			 * send it if:
			 *
			 * (1) the throttle limit has been reached, or
			 * (2) a retry is pending, or
			 * (3) a START_STOP_UNIT callback pending, or
			 * (4) a callback for a SD_PATH_DIRECT_PRIORITY
			 *	command is pending.
			 *
			 * For all of these conditions, IO processing will
			 * restart after the condition is cleared.
			 */
			if (un->un_ncmds_in_transport >= un->un_throttle) {
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: exiting, "
				    "throttle limit reached!\n");
				goto exit;
			}
			if (un->un_retry_bp != NULL) {
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: exiting, retry pending!\n");
				goto exit;
			}
			if (un->un_startstop_timeid != NULL) {
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: exiting, "
				    "START_STOP pending!\n");
				goto exit;
			}
			if (un->un_direct_priority_timeid != NULL) {
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: exiting, "
				    "SD_PATH_DIRECT_PRIORITY cmd. pending!\n");
				goto exit;
			}

			/* Dequeue the command */
			un->un_waitq_headp = bp->av_forw;
			if (un->un_waitq_headp == NULL) {
				un->un_waitq_tailp = NULL;
			}
			bp->av_forw = NULL;
			statp = kstat_waitq_to_runq;
			SD_TRACE(SD_LOG_IO_CORE, un,
			    "sd_start_cmds: processing waitq bp:0x%p\n", bp);

		} else {
			/* No work to do so bail out now */
			SD_TRACE(SD_LOG_IO_CORE, un,
			    "sd_start_cmds: no more work, exiting!\n");
			goto exit;
		}

		/*
		 * Reset the state to normal. This is the mechanism by which
		 * the state transitions from either SD_STATE_RWAIT or
		 * SD_STATE_OFFLINE to SD_STATE_NORMAL.
		 * If state is SD_STATE_PM_CHANGING then this command is
		 * part of the device power control and the state must
		 * not be put back to normal. Doing so would would
		 * allow new commands to proceed when they shouldn't,
		 * the device may be going off.
		 */
		if ((un->un_state != SD_STATE_SUSPENDED) &&
		    (un->un_state != SD_STATE_PM_CHANGING)) {
			New_state(un, SD_STATE_NORMAL);
		}

		xp = SD_GET_XBUF(bp);
		ASSERT(xp != NULL);

#if defined(__i386) || defined(__amd64)	/* DMAFREE for x86 only */
		/*
		 * Allocate the scsi_pkt if we need one, or attach DMA
		 * resources if we have a scsi_pkt that needs them. The
		 * latter should only occur for commands that are being
		 * retried.
		 */
		if ((xp->xb_pktp == NULL) ||
		    ((xp->xb_pkt_flags & SD_XB_DMA_FREED) != 0)) {
#else
		if (xp->xb_pktp == NULL) {
#endif
			/*
			 * There is no scsi_pkt allocated for this buf. Call
			 * the initpkt function to allocate & init one.
			 *
			 * The scsi_init_pkt runout callback functionality is
			 * implemented as follows:
			 *
			 * 1) The initpkt function always calls
			 *    scsi_init_pkt(9F) with sdrunout specified as the
			 *    callback routine.
			 * 2) A successful packet allocation is initialized and
			 *    the I/O is transported.
			 * 3) The I/O associated with an allocation resource
			 *    failure is left on its queue to be retried via
			 *    runout or the next I/O.
			 * 4) The I/O associated with a DMA error is removed
			 *    from the queue and failed with EIO. Processing of
			 *    the transport queues is also halted to be
			 *    restarted via runout or the next I/O.
			 * 5) The I/O associated with a CDB size or packet
			 *    size error is removed from the queue and failed
			 *    with EIO. Processing of the transport queues is
			 *    continued.
			 *
			 * Note: there is no interface for canceling a runout
			 * callback. To prevent the driver from detaching or
			 * suspending while a runout is pending the driver
			 * state is set to SD_STATE_RWAIT
			 *
			 * Note: using the scsi_init_pkt callback facility can
			 * result in an I/O request persisting at the head of
			 * the list which cannot be satisfied even after
			 * multiple retries. In the future the driver may
			 * implement some kind of maximum runout count before
			 * failing an I/O.
			 *
			 * Note: the use of funcp below may seem superfluous,
			 * but it helps warlock figure out the correct
			 * initpkt function calls (see [s]sd.wlcmd).
			 */
			struct scsi_pkt	*pktp;
			int (*funcp)(struct buf *bp, struct scsi_pkt **pktp);

			ASSERT(bp != un->un_rqs_bp);

			funcp = sd_initpkt_map[xp->xb_chain_iostart];
			switch ((*funcp)(bp, &pktp)) {
			case  SD_PKT_ALLOC_SUCCESS:
				xp->xb_pktp = pktp;
				SD_TRACE(SD_LOG_IO_CORE, un,
				    "sd_start_cmd: SD_PKT_ALLOC_SUCCESS 0x%p\n",
				    pktp);
				goto got_pkt;

			case SD_PKT_ALLOC_FAILURE:
				/*
				 * Temporary (hopefully) resource depletion.
				 * Since retries and RQS commands always have a
				 * scsi_pkt allocated, these cases should never
				 * get here. So the only cases this needs to
				 * handle is a bp from the waitq (which we put
				 * back onto the waitq for sdrunout), or a bp
				 * sent as an immed_bp (which we just fail).
				 */
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: SD_PKT_ALLOC_FAILURE\n");

#if defined(__i386) || defined(__amd64)	/* DMAFREE for x86 only */

				if (bp == immed_bp) {
					/*
					 * If SD_XB_DMA_FREED is clear, then
					 * this is a failure to allocate a
					 * scsi_pkt, and we must fail the
					 * command.
					 */
					if ((xp->xb_pkt_flags &
					    SD_XB_DMA_FREED) == 0) {
						break;
					}

					/*
					 * If this immediate command is NOT our
					 * un_retry_bp, then we must fail it.
					 */
					if (bp != un->un_retry_bp) {
						break;
					}

					/*
					 * We get here if this cmd is our
					 * un_retry_bp that was DMAFREED, but
					 * scsi_init_pkt() failed to reallocate
					 * DMA resources when we attempted to
					 * retry it. This can happen when an
					 * mpxio failover is in progress, but
					 * we don't want to just fail the
					 * command in this case.
					 *
					 * Use timeout(9F) to restart it after
					 * a 100ms delay.  We don't want to
					 * let sdrunout() restart it, because
					 * sdrunout() is just supposed to start
					 * commands that are sitting on the
					 * wait queue.  The un_retry_bp stays
					 * set until the command completes, but
					 * sdrunout can be called many times
					 * before that happens.  Since sdrunout
					 * cannot tell if the un_retry_bp is
					 * already in the transport, it could
					 * end up calling scsi_transport() for
					 * the un_retry_bp multiple times.
					 *
					 * Also: don't schedule the callback
					 * if some other callback is already
					 * pending.
					 */
					if (un->un_retry_statp == NULL) {
						/*
						 * restore the kstat pointer to
						 * keep kstat counts coherent
						 * when we do retry the command.
						 */
						un->un_retry_statp =
						    saved_statp;
					}

					if ((un->un_startstop_timeid == NULL) &&
					    (un->un_retry_timeid == NULL) &&
					    (un->un_direct_priority_timeid ==
					    NULL)) {

						un->un_retry_timeid =
						    timeout(
						    sd_start_retry_command,
						    un, SD_RESTART_TIMEOUT);
					}
					goto exit;
				}

#else
				if (bp == immed_bp) {
					break;	/* Just fail the command */
				}
#endif

				/* Add the buf back to the head of the waitq */
				bp->av_forw = un->un_waitq_headp;
				un->un_waitq_headp = bp;
				if (un->un_waitq_tailp == NULL) {
					un->un_waitq_tailp = bp;
				}
				goto exit;

			case SD_PKT_ALLOC_FAILURE_NO_DMA:
				/*
				 * HBA DMA resource failure. Fail the command
				 * and continue processing of the queues.
				 */
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: "
				    "SD_PKT_ALLOC_FAILURE_NO_DMA\n");
				break;

			case SD_PKT_ALLOC_FAILURE_PKT_TOO_SMALL:
				/*
				 * Note:x86: Partial DMA mapping not supported
				 * for USCSI commands, and all the needed DMA
				 * resources were not allocated.
				 */
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: "
				    "SD_PKT_ALLOC_FAILURE_PKT_TOO_SMALL\n");
				break;

			case SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL:
				/*
				 * Note:x86: Request cannot fit into CDB based
				 * on lba and len.
				 */
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: "
				    "SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL\n");
				break;

			default:
				/* Should NEVER get here! */
				panic("scsi_initpkt error");
				/*NOTREACHED*/
			}

			/*
			 * Fatal error in allocating a scsi_pkt for this buf.
			 * Update kstats & return the buf with an error code.
			 * We must use sd_return_failed_command_no_restart() to
			 * avoid a recursive call back into sd_start_cmds().
			 * However this also means that we must keep processing
			 * the waitq here in order to avoid stalling.
			 */
			if (statp == kstat_waitq_to_runq) {
				SD_UPDATE_KSTATS(un, kstat_waitq_exit, bp);
			}
			sd_return_failed_command_no_restart(un, bp, EIO);
			if (bp == immed_bp) {
				/* immed_bp is gone by now, so clear this */
				immed_bp = NULL;
			}
			continue;
		}
got_pkt:
		if (bp == immed_bp) {
			/* goto the head of the class.... */
			xp->xb_pktp->pkt_flags |= FLAG_HEAD;
		}

		un->un_ncmds_in_transport++;
		SD_UPDATE_KSTATS(un, statp, bp);

		/*
		 * Call scsi_transport() to send the command to the target.
		 * According to SCSA architecture, we must drop the mutex here
		 * before calling scsi_transport() in order to avoid deadlock.
		 * Note that the scsi_pkt's completion routine can be executed
		 * (from interrupt context) even before the call to
		 * scsi_transport() returns.
		 */
		SD_TRACE(SD_LOG_IO_CORE, un,
		    "sd_start_cmds: calling scsi_transport()\n");
		DTRACE_PROBE1(scsi__transport__dispatch, struct buf *, bp);

		mutex_exit(SD_MUTEX(un));
		rval = scsi_transport(xp->xb_pktp);
		mutex_enter(SD_MUTEX(un));

		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_start_cmds: scsi_transport() returned %d\n", rval);

		switch (rval) {
		case TRAN_ACCEPT:
			/* Clear this with every pkt accepted by the HBA */
			un->un_tran_fatal_count = 0;
			break;	/* Success; try the next cmd (if any) */

		case TRAN_BUSY:
			un->un_ncmds_in_transport--;
			ASSERT(un->un_ncmds_in_transport >= 0);

			/*
			 * Don't retry request sense, the sense data
			 * is lost when another request is sent.
			 * Free up the rqs buf and retry
			 * the original failed cmd.  Update kstat.
			 */
			if (bp == un->un_rqs_bp) {
				SD_UPDATE_KSTATS(un, kstat_runq_exit, bp);
				bp = sd_mark_rqs_idle(un, xp);
				sd_retry_command(un, bp, SD_RETRIES_STANDARD,
				    NULL, NULL, EIO, un->un_busy_timeout / 500,
				    kstat_waitq_enter);
				goto exit;
			}

#if defined(__i386) || defined(__amd64)	/* DMAFREE for x86 only */
			/*
			 * Free the DMA resources for the  scsi_pkt. This will
			 * allow mpxio to select another path the next time
			 * we call scsi_transport() with this scsi_pkt.
			 * See sdintr() for the rationalization behind this.
			 */
			if ((un->un_f_is_fibre == TRUE) &&
			    ((xp->xb_pkt_flags & SD_XB_USCSICMD) == 0) &&
			    ((xp->xb_pktp->pkt_flags & FLAG_SENSING) == 0)) {
				scsi_dmafree(xp->xb_pktp);
				xp->xb_pkt_flags |= SD_XB_DMA_FREED;
			}
#endif

			if (SD_IS_DIRECT_PRIORITY(SD_GET_XBUF(bp))) {
				/*
				 * Commands that are SD_PATH_DIRECT_PRIORITY
				 * are for error recovery situations. These do
				 * not use the normal command waitq, so if they
				 * get a TRAN_BUSY we cannot put them back onto
				 * the waitq for later retry. One possible
				 * problem is that there could already be some
				 * other command on un_retry_bp that is waiting
				 * for this one to complete, so we would be
				 * deadlocked if we put this command back onto
				 * the waitq for later retry (since un_retry_bp
				 * must complete before the driver gets back to
				 * commands on the waitq).
				 *
				 * To avoid deadlock we must schedule a callback
				 * that will restart this command after a set
				 * interval.  This should keep retrying for as
				 * long as the underlying transport keeps
				 * returning TRAN_BUSY (just like for other
				 * commands).  Use the same timeout interval as
				 * for the ordinary TRAN_BUSY retry.
				 */
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_start_cmds: scsi_transport() returned "
				    "TRAN_BUSY for DIRECT_PRIORITY cmd!\n");

				SD_UPDATE_KSTATS(un, kstat_runq_exit, bp);
				un->un_direct_priority_timeid =
				    timeout(sd_start_direct_priority_command,
				    bp, un->un_busy_timeout / 500);

				goto exit;
			}

			/*
			 * For TRAN_BUSY, we want to reduce the throttle value,
			 * unless we are retrying a command.
			 */
			if (bp != un->un_retry_bp) {
				sd_reduce_throttle(un, SD_THROTTLE_TRAN_BUSY);
			}

			/*
			 * Set up the bp to be tried again 10 ms later.
			 * Note:x86: Is there a timeout value in the sd_lun
			 * for this condition?
			 */
			sd_set_retry_bp(un, bp, un->un_busy_timeout / 500,
			    kstat_runq_back_to_waitq);
			goto exit;

		case TRAN_FATAL_ERROR:
			un->un_tran_fatal_count++;
			/* FALLTHRU */

		case TRAN_BADPKT:
		default:
			un->un_ncmds_in_transport--;
			ASSERT(un->un_ncmds_in_transport >= 0);

			/*
			 * If this is our REQUEST SENSE command with a
			 * transport error, we must get back the pointers
			 * to the original buf, and mark the REQUEST
			 * SENSE command as "available".
			 */
			if (bp == un->un_rqs_bp) {
				bp = sd_mark_rqs_idle(un, xp);
				xp = SD_GET_XBUF(bp);
			} else {
				/*
				 * Legacy behavior: do not update transport
				 * error count for request sense commands.
				 */
				SD_UPDATE_ERRSTATS(un, sd_transerrs);
			}

			SD_UPDATE_KSTATS(un, kstat_runq_exit, bp);
			sd_print_transport_rejected_message(un, xp, rval);

			/*
			 * This command will be terminated by SD driver due
			 * to a fatal transport error. We should post
			 * ereport.io.scsi.cmd.disk.tran with driver-assessment
			 * of "fail" for any command to indicate this
			 * situation.
			 */
			if (xp->xb_ena > 0) {
				ASSERT(un->un_fm_private != NULL);
				sfip = un->un_fm_private;
				sfip->fm_ssc.ssc_flags |= SSC_FLAGS_TRAN_ABORT;
				sd_ssc_extract_info(&sfip->fm_ssc, un,
				    xp->xb_pktp, bp, xp);
				sd_ssc_post(&sfip->fm_ssc, SD_FM_DRV_FATAL);
			}

			/*
			 * We must use sd_return_failed_command_no_restart() to
			 * avoid a recursive call back into sd_start_cmds().
			 * However this also means that we must keep processing
			 * the waitq here in order to avoid stalling.
			 */
			sd_return_failed_command_no_restart(un, bp, EIO);

			/*
			 * Notify any threads waiting in sd_ddi_suspend() that
			 * a command completion has occurred.
			 */
			if (un->un_state == SD_STATE_SUSPENDED) {
				cv_broadcast(&un->un_disk_busy_cv);
			}

			if (bp == immed_bp) {
				/* immed_bp is gone by now, so clear this */
				immed_bp = NULL;
			}
			break;
		}

	} while (immed_bp == NULL);

exit:
	ASSERT(mutex_owned(SD_MUTEX(un)));
	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_start_cmds: exit\n");
}


/*
 *    Function: sd_return_command
 *
 * Description: Returns a command to its originator (with or without an
 *		error).  Also starts commands waiting to be transported
 *		to the target.
 *
 *     Context: May be called from interrupt, kernel, or timeout context
 */

static void
sd_return_command(struct sd_lun *un, struct buf *bp)
{
	struct sd_xbuf *xp;
	struct scsi_pkt *pktp;
	struct sd_fm_internal *sfip;

	ASSERT(bp != NULL);
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != un->un_rqs_bp);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

	pktp = SD_GET_PKTP(bp);
	sfip = (struct sd_fm_internal *)un->un_fm_private;
	ASSERT(sfip != NULL);

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_return_command: entry\n");

	/*
	 * Note: check for the "sdrestart failed" case.
	 */
	if ((un->un_partial_dma_supported == 1) &&
	    ((xp->xb_pkt_flags & SD_XB_USCSICMD) != SD_XB_USCSICMD) &&
	    (geterror(bp) == 0) && (xp->xb_dma_resid != 0) &&
	    (xp->xb_pktp->pkt_resid == 0)) {

		if (sd_setup_next_xfer(un, bp, pktp, xp) != 0) {
			/*
			 * Successfully set up next portion of cmd
			 * transfer, try sending it
			 */
			sd_retry_command(un, bp, SD_RETRIES_NOCHECK,
			    NULL, NULL, 0, (clock_t)0, NULL);
			sd_start_cmds(un, NULL);
			return;	/* Note:x86: need a return here? */
		}
	}

	/*
	 * If this is the failfast bp, clear it from un_failfast_bp. This
	 * can happen if upon being re-tried the failfast bp either
	 * succeeded or encountered another error (possibly even a different
	 * error than the one that precipitated the failfast state, but in
	 * that case it would have had to exhaust retries as well). Regardless,
	 * this should not occur whenever the instance is in the active
	 * failfast state.
	 */
	if (bp == un->un_failfast_bp) {
		ASSERT(un->un_failfast_state == SD_FAILFAST_INACTIVE);
		un->un_failfast_bp = NULL;
	}

	/*
	 * Clear the failfast state upon successful completion of ANY cmd.
	 */
	if (bp->b_error == 0) {
		un->un_failfast_state = SD_FAILFAST_INACTIVE;
		/*
		 * If this is a successful command, but used to be retried,
		 * we will take it as a recovered command and post an
		 * ereport with driver-assessment of "recovered".
		 */
		if (xp->xb_ena > 0) {
			sd_ssc_extract_info(&sfip->fm_ssc, un, pktp, bp, xp);
			sd_ssc_post(&sfip->fm_ssc, SD_FM_DRV_RECOVERY);
		}
	} else {
		/*
		 * If this is a failed non-USCSI command we will post an
		 * ereport with driver-assessment set accordingly("fail" or
		 * "fatal").
		 */
		if (!(xp->xb_pkt_flags & SD_XB_USCSICMD)) {
			sd_ssc_extract_info(&sfip->fm_ssc, un, pktp, bp, xp);
			sd_ssc_post(&sfip->fm_ssc, SD_FM_DRV_FATAL);
		}
	}

	/*
	 * This is used if the command was retried one or more times. Show that
	 * we are done with it, and allow processing of the waitq to resume.
	 */
	if (bp == un->un_retry_bp) {
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_return_command: un:0x%p: "
		    "RETURNING retry_bp:0x%p\n", un, un->un_retry_bp);
		un->un_retry_bp = NULL;
		un->un_retry_statp = NULL;
	}

	SD_UPDATE_RDWR_STATS(un, bp);
	SD_UPDATE_PARTITION_STATS(un, bp);

	switch (un->un_state) {
	case SD_STATE_SUSPENDED:
		/*
		 * Notify any threads waiting in sd_ddi_suspend() that
		 * a command completion has occurred.
		 */
		cv_broadcast(&un->un_disk_busy_cv);
		break;
	default:
		sd_start_cmds(un, NULL);
		break;
	}

	/* Return this command up the iodone chain to its originator. */
	mutex_exit(SD_MUTEX(un));

	(*(sd_destroypkt_map[xp->xb_chain_iodone]))(bp);
	xp->xb_pktp = NULL;

	SD_BEGIN_IODONE(xp->xb_chain_iodone, un, bp);

	ASSERT(!mutex_owned(SD_MUTEX(un)));
	mutex_enter(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_return_command: exit\n");
}


/*
 *    Function: sd_return_failed_command
 *
 * Description: Command completion when an error occurred.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_return_failed_command(struct sd_lun *un, struct buf *bp, int errcode)
{
	ASSERT(bp != NULL);
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_return_failed_command: entry\n");

	/*
	 * b_resid could already be nonzero due to a partial data
	 * transfer, so do not change it here.
	 */
	SD_BIOERROR(bp, errcode);

	sd_return_command(un, bp);
	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_return_failed_command: exit\n");
}


/*
 *    Function: sd_return_failed_command_no_restart
 *
 * Description: Same as sd_return_failed_command, but ensures that no
 *		call back into sd_start_cmds will be issued.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_return_failed_command_no_restart(struct sd_lun *un, struct buf *bp,
	int errcode)
{
	struct sd_xbuf *xp;

	ASSERT(bp != NULL);
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	ASSERT(errcode != 0);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_return_failed_command_no_restart: entry\n");

	/*
	 * b_resid could already be nonzero due to a partial data
	 * transfer, so do not change it here.
	 */
	SD_BIOERROR(bp, errcode);

	/*
	 * If this is the failfast bp, clear it. This can happen if the
	 * failfast bp encounterd a fatal error when we attempted to
	 * re-try it (such as a scsi_transport(9F) failure).  However
	 * we should NOT be in an active failfast state if the failfast
	 * bp is not NULL.
	 */
	if (bp == un->un_failfast_bp) {
		ASSERT(un->un_failfast_state == SD_FAILFAST_INACTIVE);
		un->un_failfast_bp = NULL;
	}

	if (bp == un->un_retry_bp) {
		/*
		 * This command was retried one or more times. Show that we are
		 * done with it, and allow processing of the waitq to resume.
		 */
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_return_failed_command_no_restart: "
		    " un:0x%p: RETURNING retry_bp:0x%p\n", un, un->un_retry_bp);
		un->un_retry_bp = NULL;
		un->un_retry_statp = NULL;
	}

	SD_UPDATE_RDWR_STATS(un, bp);
	SD_UPDATE_PARTITION_STATS(un, bp);

	mutex_exit(SD_MUTEX(un));

	if (xp->xb_pktp != NULL) {
		(*(sd_destroypkt_map[xp->xb_chain_iodone]))(bp);
		xp->xb_pktp = NULL;
	}

	SD_BEGIN_IODONE(xp->xb_chain_iodone, un, bp);

	mutex_enter(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_return_failed_command_no_restart: exit\n");
}


/*
 *    Function: sd_retry_command
 *
 * Description: queue up a command for retry, or (optionally) fail it
 *		if retry counts are exhausted.
 *
 *   Arguments: un - Pointer to the sd_lun struct for the target.
 *
 *		bp - Pointer to the buf for the command to be retried.
 *
 *		retry_check_flag - Flag to see which (if any) of the retry
 *		   counts should be decremented/checked. If the indicated
 *		   retry count is exhausted, then the command will not be
 *		   retried; it will be failed instead. This should use a
 *		   value equal to one of the following:
 *
 *			SD_RETRIES_NOCHECK
 *			SD_RESD_RETRIES_STANDARD
 *			SD_RETRIES_VICTIM
 *
 *		   Optionally may be bitwise-OR'ed with SD_RETRIES_ISOLATE
 *		   if the check should be made to see of FLAG_ISOLATE is set
 *		   in the pkt. If FLAG_ISOLATE is set, then the command is
 *		   not retried, it is simply failed.
 *
 *		user_funcp - Ptr to function to call before dispatching the
 *		   command. May be NULL if no action needs to be performed.
 *		   (Primarily intended for printing messages.)
 *
 *		user_arg - Optional argument to be passed along to
 *		   the user_funcp call.
 *
 *		failure_code - errno return code to set in the bp if the
 *		   command is going to be failed.
 *
 *		retry_delay - Retry delay interval in (clock_t) units. May
 *		   be zero which indicates that the retry should be retried
 *		   immediately (ie, without an intervening delay).
 *
 *		statp - Ptr to kstat function to be updated if the command
 *		   is queued for a delayed retry. May be NULL if no kstat
 *		   update is desired.
 *
 *     Context: May be called from interrupt context.
 */

static void
sd_retry_command(struct sd_lun *un, struct buf *bp, int retry_check_flag,
	void (*user_funcp)(struct sd_lun *un, struct buf *bp, void *argp, int
	code), void *user_arg, int failure_code,  clock_t retry_delay,
	void (*statp)(kstat_io_t *))
{
	struct sd_xbuf	*xp;
	struct scsi_pkt	*pktp;
	struct sd_fm_internal *sfip;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	pktp = SD_GET_PKTP(bp);
	ASSERT(pktp != NULL);

	sfip = (struct sd_fm_internal *)un->un_fm_private;
	ASSERT(sfip != NULL);

	SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un,
	    "sd_retry_command: entry: bp:0x%p xp:0x%p\n", bp, xp);

	/*
	 * If we are syncing or dumping, fail the command to avoid
	 * recursively calling back into scsi_transport().
	 */
	if (ddi_in_panic()) {
		goto fail_command_no_log;
	}

	/*
	 * We should never be be retrying a command with FLAG_DIAGNOSE set, so
	 * log an error and fail the command.
	 */
	if ((pktp->pkt_flags & FLAG_DIAGNOSE) != 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_NOTE,
		    "ERROR, retrying FLAG_DIAGNOSE command.\n");
		sd_dump_memory(un, SD_LOG_IO, "CDB",
		    (uchar_t *)pktp->pkt_cdbp, CDB_SIZE, SD_LOG_HEX);
		sd_dump_memory(un, SD_LOG_IO, "Sense Data",
		    (uchar_t *)xp->xb_sense_data, SENSE_LENGTH, SD_LOG_HEX);
		goto fail_command;
	}

	/*
	 * If we are suspended, then put the command onto head of the
	 * wait queue since we don't want to start more commands, and
	 * clear the un_retry_bp. Next time when we are resumed, will
	 * handle the command in the wait queue.
	 */
	switch (un->un_state) {
	case SD_STATE_SUSPENDED:
	case SD_STATE_DUMPING:
		bp->av_forw = un->un_waitq_headp;
		un->un_waitq_headp = bp;
		if (un->un_waitq_tailp == NULL) {
			un->un_waitq_tailp = bp;
		}
		if (bp == un->un_retry_bp) {
			un->un_retry_bp = NULL;
			un->un_retry_statp = NULL;
		}
		SD_UPDATE_KSTATS(un, kstat_waitq_enter, bp);
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_retry_command: "
		    "exiting; cmd bp:0x%p requeued for SUSPEND/DUMP\n", bp);
		return;
	default:
		break;
	}

	/*
	 * If the caller wants us to check FLAG_ISOLATE, then see if that
	 * is set; if it is then we do not want to retry the command.
	 * Normally, FLAG_ISOLATE is only used with USCSI cmds.
	 */
	if ((retry_check_flag & SD_RETRIES_ISOLATE) != 0) {
		if ((pktp->pkt_flags & FLAG_ISOLATE) != 0) {
			goto fail_command;
		}
	}


	/*
	 * If SD_RETRIES_FAILFAST is set, it indicates that either a
	 * command timeout or a selection timeout has occurred. This means
	 * that we were unable to establish an kind of communication with
	 * the target, and subsequent retries and/or commands are likely
	 * to encounter similar results and take a long time to complete.
	 *
	 * If this is a failfast error condition, we need to update the
	 * failfast state, even if this bp does not have B_FAILFAST set.
	 */
	if (retry_check_flag & SD_RETRIES_FAILFAST) {
		if (un->un_failfast_state == SD_FAILFAST_ACTIVE) {
			ASSERT(un->un_failfast_bp == NULL);
			/*
			 * If we are already in the active failfast state, and
			 * another failfast error condition has been detected,
			 * then fail this command if it has B_FAILFAST set.
			 * If B_FAILFAST is clear, then maintain the legacy
			 * behavior of retrying heroically, even tho this will
			 * take a lot more time to fail the command.
			 */
			if (bp->b_flags & B_FAILFAST) {
				goto fail_command;
			}
		} else {
			/*
			 * We're not in the active failfast state, but we
			 * have a failfast error condition, so we must begin
			 * transition to the next state. We do this regardless
			 * of whether or not this bp has B_FAILFAST set.
			 */
			if (un->un_failfast_bp == NULL) {
				/*
				 * This is the first bp to meet a failfast
				 * condition so save it on un_failfast_bp &
				 * do normal retry processing. Do not enter
				 * active failfast state yet. This marks
				 * entry into the "failfast pending" state.
				 */
				un->un_failfast_bp = bp;

			} else if (un->un_failfast_bp == bp) {
				/*
				 * This is the second time *this* bp has
				 * encountered a failfast error condition,
				 * so enter active failfast state & flush
				 * queues as appropriate.
				 */
				un->un_failfast_state = SD_FAILFAST_ACTIVE;
				un->un_failfast_bp = NULL;
				sd_failfast_flushq(un);

				/*
				 * Fail this bp now if B_FAILFAST set;
				 * otherwise continue with retries. (It would
				 * be pretty ironic if this bp succeeded on a
				 * subsequent retry after we just flushed all
				 * the queues).
				 */
				if (bp->b_flags & B_FAILFAST) {
					goto fail_command;
				}

#if !defined(lint) && !defined(__lint)
			} else {
				/*
				 * If neither of the preceeding conditionals
				 * was true, it means that there is some
				 * *other* bp that has met an inital failfast
				 * condition and is currently either being
				 * retried or is waiting to be retried. In
				 * that case we should perform normal retry
				 * processing on *this* bp, since there is a
				 * chance that the current failfast condition
				 * is transient and recoverable. If that does
				 * not turn out to be the case, then retries
				 * will be cleared when the wait queue is
				 * flushed anyway.
				 */
#endif
			}
		}
	} else {
		/*
		 * SD_RETRIES_FAILFAST is clear, which indicates that we
		 * likely were able to at least establish some level of
		 * communication with the target and subsequent commands
		 * and/or retries are likely to get through to the target,
		 * In this case we want to be aggressive about clearing
		 * the failfast state. Note that this does not affect
		 * the "failfast pending" condition.
		 */
		un->un_failfast_state = SD_FAILFAST_INACTIVE;
	}


	/*
	 * Check the specified retry count to see if we can still do
	 * any retries with this pkt before we should fail it.
	 */
	switch (retry_check_flag & SD_RETRIES_MASK) {
	case SD_RETRIES_VICTIM:
		/*
		 * Check the victim retry count. If exhausted, then fall
		 * thru & check against the standard retry count.
		 */
		if (xp->xb_victim_retry_count < un->un_victim_retry_count) {
			/* Increment count & proceed with the retry */
			xp->xb_victim_retry_count++;
			break;
		}
		/* Victim retries exhausted, fall back to std. retries... */
		/* FALLTHRU */

	case SD_RETRIES_STANDARD:
		if (xp->xb_retry_count >= un->un_retry_count) {
			/* Retries exhausted, fail the command */
			SD_TRACE(SD_LOG_IO_CORE, un,
			    "sd_retry_command: retries exhausted!\n");
			/*
			 * update b_resid for failed SCMD_READ & SCMD_WRITE
			 * commands with nonzero pkt_resid.
			 */
			if ((pktp->pkt_reason == CMD_CMPLT) &&
			    (SD_GET_PKT_STATUS(pktp) == STATUS_GOOD) &&
			    (pktp->pkt_resid != 0)) {
				uchar_t op = SD_GET_PKT_OPCODE(pktp) & 0x1F;
				if ((op == SCMD_READ) || (op == SCMD_WRITE)) {
					SD_UPDATE_B_RESID(bp, pktp);
				}
			}
			goto fail_command;
		}
		xp->xb_retry_count++;
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_retry_command: retry count:%d\n", xp->xb_retry_count);
		break;

	case SD_RETRIES_UA:
		if (xp->xb_ua_retry_count >= sd_ua_retry_count) {
			/* Retries exhausted, fail the command */
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "Unit Attention retries exhausted. "
			    "Check the target.\n");
			goto fail_command;
		}
		xp->xb_ua_retry_count++;
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_retry_command: retry count:%d\n",
		    xp->xb_ua_retry_count);
		break;

	case SD_RETRIES_BUSY:
		if (xp->xb_retry_count >= un->un_busy_retry_count) {
			/* Retries exhausted, fail the command */
			SD_TRACE(SD_LOG_IO_CORE, un,
			    "sd_retry_command: retries exhausted!\n");
			goto fail_command;
		}
		xp->xb_retry_count++;
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_retry_command: retry count:%d\n", xp->xb_retry_count);
		break;

	case SD_RETRIES_NOCHECK:
	default:
		/* No retry count to check. Just proceed with the retry */
		break;
	}

	xp->xb_pktp->pkt_flags |= FLAG_HEAD;

	/*
	 * If this is a non-USCSI command being retried
	 * during execution last time, we should post an ereport with
	 * driver-assessment of the value "retry".
	 * For partial DMA, request sense and STATUS_QFULL, there are no
	 * hardware errors, we bypass ereport posting.
	 */
	if (failure_code != 0) {
		if (!(xp->xb_pkt_flags & SD_XB_USCSICMD)) {
			sd_ssc_extract_info(&sfip->fm_ssc, un, pktp, bp, xp);
			sd_ssc_post(&sfip->fm_ssc, SD_FM_DRV_RETRY);
		}
	}

	/*
	 * If we were given a zero timeout, we must attempt to retry the
	 * command immediately (ie, without a delay).
	 */
	if (retry_delay == 0) {
		/*
		 * Check some limiting conditions to see if we can actually
		 * do the immediate retry.  If we cannot, then we must
		 * fall back to queueing up a delayed retry.
		 */
		if (un->un_ncmds_in_transport >= un->un_throttle) {
			/*
			 * We are at the throttle limit for the target,
			 * fall back to delayed retry.
			 */
			retry_delay = un->un_busy_timeout;
			statp = kstat_waitq_enter;
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_retry_command: immed. retry hit "
			    "throttle!\n");
		} else {
			/*
			 * We're clear to proceed with the immediate retry.
			 * First call the user-provided function (if any)
			 */
			if (user_funcp != NULL) {
				(*user_funcp)(un, bp, user_arg,
				    SD_IMMEDIATE_RETRY_ISSUED);
#ifdef __lock_lint
				sd_print_incomplete_msg(un, bp, user_arg,
				    SD_IMMEDIATE_RETRY_ISSUED);
				sd_print_cmd_incomplete_msg(un, bp, user_arg,
				    SD_IMMEDIATE_RETRY_ISSUED);
				sd_print_sense_failed_msg(un, bp, user_arg,
				    SD_IMMEDIATE_RETRY_ISSUED);
#endif
			}

			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_retry_command: issuing immediate retry\n");

			/*
			 * Call sd_start_cmds() to transport the command to
			 * the target.
			 */
			sd_start_cmds(un, bp);

			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_retry_command exit\n");
			return;
		}
	}

	/*
	 * Set up to retry the command after a delay.
	 * First call the user-provided function (if any)
	 */
	if (user_funcp != NULL) {
		(*user_funcp)(un, bp, user_arg, SD_DELAYED_RETRY_ISSUED);
	}

	sd_set_retry_bp(un, bp, retry_delay, statp);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_retry_command: exit\n");
	return;

fail_command:

	if (user_funcp != NULL) {
		(*user_funcp)(un, bp, user_arg, SD_NO_RETRY_ISSUED);
	}

fail_command_no_log:

	SD_INFO(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_retry_command: returning failed command\n");

	sd_return_failed_command(un, bp, failure_code);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_retry_command: exit\n");
}


/*
 *    Function: sd_set_retry_bp
 *
 * Description: Set up the given bp for retry.
 *
 *   Arguments: un - ptr to associated softstate
 *		bp - ptr to buf(9S) for the command
 *		retry_delay - time interval before issuing retry (may be 0)
 *		statp - optional pointer to kstat function
 *
 *     Context: May be called under interrupt context
 */

static void
sd_set_retry_bp(struct sd_lun *un, struct buf *bp, clock_t retry_delay,
	void (*statp)(kstat_io_t *))
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);

	SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un,
	    "sd_set_retry_bp: entry: un:0x%p bp:0x%p\n", un, bp);

	/*
	 * Indicate that the command is being retried. This will not allow any
	 * other commands on the wait queue to be transported to the target
	 * until this command has been completed (success or failure). The
	 * "retry command" is not transported to the target until the given
	 * time delay expires, unless the user specified a 0 retry_delay.
	 *
	 * Note: the timeout(9F) callback routine is what actually calls
	 * sd_start_cmds() to transport the command, with the exception of a
	 * zero retry_delay. The only current implementor of a zero retry delay
	 * is the case where a START_STOP_UNIT is sent to spin-up a device.
	 */
	if (un->un_retry_bp == NULL) {
		ASSERT(un->un_retry_statp == NULL);
		un->un_retry_bp = bp;

		/*
		 * If the user has not specified a delay the command should
		 * be queued and no timeout should be scheduled.
		 */
		if (retry_delay == 0) {
			/*
			 * Save the kstat pointer that will be used in the
			 * call to SD_UPDATE_KSTATS() below, so that
			 * sd_start_cmds() can correctly decrement the waitq
			 * count when it is time to transport this command.
			 */
			un->un_retry_statp = statp;
			goto done;
		}
	}

	if (un->un_retry_bp == bp) {
		/*
		 * Save the kstat pointer that will be used in the call to
		 * SD_UPDATE_KSTATS() below, so that sd_start_cmds() can
		 * correctly decrement the waitq count when it is time to
		 * transport this command.
		 */
		un->un_retry_statp = statp;

		/*
		 * Schedule a timeout if:
		 *   1) The user has specified a delay.
		 *   2) There is not a START_STOP_UNIT callback pending.
		 *
		 * If no delay has been specified, then it is up to the caller
		 * to ensure that IO processing continues without stalling.
		 * Effectively, this means that the caller will issue the
		 * required call to sd_start_cmds(). The START_STOP_UNIT
		 * callback does this after the START STOP UNIT command has
		 * completed. In either of these cases we should not schedule
		 * a timeout callback here.  Also don't schedule the timeout if
		 * an SD_PATH_DIRECT_PRIORITY command is waiting to restart.
		 */
		if ((retry_delay != 0) && (un->un_startstop_timeid == NULL) &&
		    (un->un_direct_priority_timeid == NULL)) {
			un->un_retry_timeid =
			    timeout(sd_start_retry_command, un, retry_delay);
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_set_retry_bp: setting timeout: un: 0x%p"
			    " bp:0x%p un_retry_timeid:0x%p\n",
			    un, bp, un->un_retry_timeid);
		}
	} else {
		/*
		 * We only get in here if there is already another command
		 * waiting to be retried.  In this case, we just put the
		 * given command onto the wait queue, so it can be transported
		 * after the current retry command has completed.
		 *
		 * Also we have to make sure that if the command at the head
		 * of the wait queue is the un_failfast_bp, that we do not
		 * put ahead of it any other commands that are to be retried.
		 */
		if ((un->un_failfast_bp != NULL) &&
		    (un->un_failfast_bp == un->un_waitq_headp)) {
			/*
			 * Enqueue this command AFTER the first command on
			 * the wait queue (which is also un_failfast_bp).
			 */
			bp->av_forw = un->un_waitq_headp->av_forw;
			un->un_waitq_headp->av_forw = bp;
			if (un->un_waitq_headp == un->un_waitq_tailp) {
				un->un_waitq_tailp = bp;
			}
		} else {
			/* Enqueue this command at the head of the waitq. */
			bp->av_forw = un->un_waitq_headp;
			un->un_waitq_headp = bp;
			if (un->un_waitq_tailp == NULL) {
				un->un_waitq_tailp = bp;
			}
		}

		if (statp == NULL) {
			statp = kstat_waitq_enter;
		}
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_set_retry_bp: un:0x%p already delayed retry\n", un);
	}

done:
	if (statp != NULL) {
		SD_UPDATE_KSTATS(un, statp, bp);
	}

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_set_retry_bp: exit un:0x%p\n", un);
}


/*
 *    Function: sd_start_retry_command
 *
 * Description: Start the command that has been waiting on the target's
 *		retry queue.  Called from timeout(9F) context after the
 *		retry delay interval has expired.
 *
 *   Arguments: arg - pointer to associated softstate for the device.
 *
 *     Context: timeout(9F) thread context.  May not sleep.
 */

static void
sd_start_retry_command(void *arg)
{
	struct sd_lun *un = arg;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_start_retry_command: entry\n");

	mutex_enter(SD_MUTEX(un));

	un->un_retry_timeid = NULL;

	if (un->un_retry_bp != NULL) {
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_start_retry_command: un:0x%p STARTING bp:0x%p\n",
		    un, un->un_retry_bp);
		sd_start_cmds(un, un->un_retry_bp);
	}

	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_start_retry_command: exit\n");
}

/*
 *    Function: sd_rmw_msg_print_handler
 *
 * Description: If RMW mode is enabled and warning message is triggered
 *              print I/O count during a fixed interval.
 *
 *   Arguments: arg - pointer to associated softstate for the device.
 *
 *     Context: timeout(9F) thread context. May not sleep.
 */
static void
sd_rmw_msg_print_handler(void *arg)
{
	struct sd_lun *un = arg;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_rmw_msg_print_handler: entry\n");

	mutex_enter(SD_MUTEX(un));

	if (un->un_rmw_incre_count > 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "%"PRIu64" I/O requests are not aligned with %d disk "
		    "sector size in %ld seconds. They are handled through "
		    "Read Modify Write but the performance is very low!\n",
		    un->un_rmw_incre_count, un->un_tgt_blocksize,
		    drv_hztousec(SD_RMW_MSG_PRINT_TIMEOUT) / 1000000);
		un->un_rmw_incre_count = 0;
		un->un_rmw_msg_timeid = timeout(sd_rmw_msg_print_handler,
		    un, SD_RMW_MSG_PRINT_TIMEOUT);
	} else {
		un->un_rmw_msg_timeid = NULL;
	}

	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_rmw_msg_print_handler: exit\n");
}

/*
 *    Function: sd_start_direct_priority_command
 *
 * Description: Used to re-start an SD_PATH_DIRECT_PRIORITY command that had
 *		received TRAN_BUSY when we called scsi_transport() to send it
 *		to the underlying HBA. This function is called from timeout(9F)
 *		context after the delay interval has expired.
 *
 *   Arguments: arg - pointer to associated buf(9S) to be restarted.
 *
 *     Context: timeout(9F) thread context.  May not sleep.
 */

static void
sd_start_direct_priority_command(void *arg)
{
	struct buf	*priority_bp = arg;
	struct sd_lun	*un;

	ASSERT(priority_bp != NULL);
	un = SD_GET_UN(priority_bp);
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_start_direct_priority_command: entry\n");

	mutex_enter(SD_MUTEX(un));
	un->un_direct_priority_timeid = NULL;
	sd_start_cmds(un, priority_bp);
	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_start_direct_priority_command: exit\n");
}


/*
 *    Function: sd_send_request_sense_command
 *
 * Description: Sends a REQUEST SENSE command to the target
 *
 *     Context: May be called from interrupt context.
 */

static void
sd_send_request_sense_command(struct sd_lun *un, struct buf *bp,
	struct scsi_pkt *pktp)
{
	ASSERT(bp != NULL);
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un, "sd_send_request_sense_command: "
	    "entry: buf:0x%p\n", bp);

	/*
	 * If we are syncing or dumping, then fail the command to avoid a
	 * recursive callback into scsi_transport(). Also fail the command
	 * if we are suspended (legacy behavior).
	 */
	if (ddi_in_panic() || (un->un_state == SD_STATE_SUSPENDED) ||
	    (un->un_state == SD_STATE_DUMPING)) {
		sd_return_failed_command(un, bp, EIO);
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_send_request_sense_command: syncing/dumping, exit\n");
		return;
	}

	/*
	 * Retry the failed command and don't issue the request sense if:
	 *    1) the sense buf is busy
	 *    2) we have 1 or more outstanding commands on the target
	 *    (the sense data will be cleared or invalidated any way)
	 *
	 * Note: There could be an issue with not checking a retry limit here,
	 * the problem is determining which retry limit to check.
	 */
	if ((un->un_sense_isbusy != 0) || (un->un_ncmds_in_transport > 0)) {
		/* Don't retry if the command is flagged as non-retryable */
		if ((pktp->pkt_flags & FLAG_DIAGNOSE) == 0) {
			sd_retry_command(un, bp, SD_RETRIES_NOCHECK,
			    NULL, NULL, 0, un->un_busy_timeout,
			    kstat_waitq_enter);
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_send_request_sense_command: "
			    "at full throttle, retrying exit\n");
		} else {
			sd_return_failed_command(un, bp, EIO);
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_send_request_sense_command: "
			    "at full throttle, non-retryable exit\n");
		}
		return;
	}

	sd_mark_rqs_busy(un, bp);
	sd_start_cmds(un, un->un_rqs_bp);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_send_request_sense_command: exit\n");
}


/*
 *    Function: sd_mark_rqs_busy
 *
 * Description: Indicate that the request sense bp for this instance is
 *		in use.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_mark_rqs_busy(struct sd_lun *un, struct buf *bp)
{
	struct sd_xbuf	*sense_xp;

	ASSERT(un != NULL);
	ASSERT(bp != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(un->un_sense_isbusy == 0);

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_mark_rqs_busy: entry: "
	    "buf:0x%p xp:0x%p un:0x%p\n", bp, SD_GET_XBUF(bp), un);

	sense_xp = SD_GET_XBUF(un->un_rqs_bp);
	ASSERT(sense_xp != NULL);

	SD_INFO(SD_LOG_IO, un,
	    "sd_mark_rqs_busy: entry: sense_xp:0x%p\n", sense_xp);

	ASSERT(sense_xp->xb_pktp != NULL);
	ASSERT((sense_xp->xb_pktp->pkt_flags & (FLAG_SENSING | FLAG_HEAD))
	    == (FLAG_SENSING | FLAG_HEAD));

	un->un_sense_isbusy = 1;
	un->un_rqs_bp->b_resid = 0;
	sense_xp->xb_pktp->pkt_resid  = 0;
	sense_xp->xb_pktp->pkt_reason = 0;

	/* So we can get back the bp at interrupt time! */
	sense_xp->xb_sense_bp = bp;

	bzero(un->un_rqs_bp->b_un.b_addr, SENSE_LENGTH);

	/*
	 * Mark this buf as awaiting sense data. (This is already set in
	 * the pkt_flags for the RQS packet.)
	 */
	((SD_GET_XBUF(bp))->xb_pktp)->pkt_flags |= FLAG_SENSING;

	/* Request sense down same path */
	if (scsi_pkt_allocated_correctly((SD_GET_XBUF(bp))->xb_pktp) &&
	    ((SD_GET_XBUF(bp))->xb_pktp)->pkt_path_instance)
		sense_xp->xb_pktp->pkt_path_instance =
		    ((SD_GET_XBUF(bp))->xb_pktp)->pkt_path_instance;

	sense_xp->xb_retry_count	= 0;
	sense_xp->xb_victim_retry_count = 0;
	sense_xp->xb_ua_retry_count	= 0;
	sense_xp->xb_nr_retry_count 	= 0;
	sense_xp->xb_dma_resid  = 0;

	/* Clean up the fields for auto-request sense */
	sense_xp->xb_sense_status = 0;
	sense_xp->xb_sense_state  = 0;
	sense_xp->xb_sense_resid  = 0;
	bzero(sense_xp->xb_sense_data, sizeof (sense_xp->xb_sense_data));

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_mark_rqs_busy: exit\n");
}


/*
 *    Function: sd_mark_rqs_idle
 *
 * Description: SD_MUTEX must be held continuously through this routine
 *		to prevent reuse of the rqs struct before the caller can
 *		complete it's processing.
 *
 * Return Code: Pointer to the RQS buf
 *
 *     Context: May be called under interrupt context
 */

static struct buf *
sd_mark_rqs_idle(struct sd_lun *un, struct sd_xbuf *sense_xp)
{
	struct buf *bp;
	ASSERT(un != NULL);
	ASSERT(sense_xp != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(un->un_sense_isbusy != 0);

	un->un_sense_isbusy = 0;
	bp = sense_xp->xb_sense_bp;
	sense_xp->xb_sense_bp = NULL;

	/* This pkt is no longer interested in getting sense data */
	((SD_GET_XBUF(bp))->xb_pktp)->pkt_flags &= ~FLAG_SENSING;

	return (bp);
}



/*
 *    Function: sd_alloc_rqs
 *
 * Description: Set up the unit to receive auto request sense data
 *
 * Return Code: DDI_SUCCESS or DDI_FAILURE
 *
 *     Context: Called under attach(9E) context
 */

static int
sd_alloc_rqs(struct scsi_device *devp, struct sd_lun *un)
{
	struct sd_xbuf *xp;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(un->un_rqs_bp == NULL);
	ASSERT(un->un_rqs_pktp == NULL);

	/*
	 * First allocate the required buf and scsi_pkt structs, then set up
	 * the CDB in the scsi_pkt for a REQUEST SENSE command.
	 */
	un->un_rqs_bp = scsi_alloc_consistent_buf(&devp->sd_address, NULL,
	    MAX_SENSE_LENGTH, B_READ, SLEEP_FUNC, NULL);
	if (un->un_rqs_bp == NULL) {
		return (DDI_FAILURE);
	}

	un->un_rqs_pktp = scsi_init_pkt(&devp->sd_address, NULL, un->un_rqs_bp,
	    CDB_GROUP0, 1, 0, PKT_CONSISTENT, SLEEP_FUNC, NULL);

	if (un->un_rqs_pktp == NULL) {
		sd_free_rqs(un);
		return (DDI_FAILURE);
	}

	/* Set up the CDB in the scsi_pkt for a REQUEST SENSE command. */
	(void) scsi_setup_cdb((union scsi_cdb *)un->un_rqs_pktp->pkt_cdbp,
	    SCMD_REQUEST_SENSE, 0, MAX_SENSE_LENGTH, 0);

	SD_FILL_SCSI1_LUN(un, un->un_rqs_pktp);

	/* Set up the other needed members in the ARQ scsi_pkt. */
	un->un_rqs_pktp->pkt_comp   = sdintr;
	un->un_rqs_pktp->pkt_time   = sd_io_time;
	un->un_rqs_pktp->pkt_flags |=
	    (FLAG_SENSING | FLAG_HEAD);	/* (1222170) */

	/*
	 * Allocate  & init the sd_xbuf struct for the RQS command. Do not
	 * provide any intpkt, destroypkt routines as we take care of
	 * scsi_pkt allocation/freeing here and in sd_free_rqs().
	 */
	xp = kmem_alloc(sizeof (struct sd_xbuf), KM_SLEEP);
	sd_xbuf_init(un, un->un_rqs_bp, xp, SD_CHAIN_NULL, NULL);
	xp->xb_pktp = un->un_rqs_pktp;
	SD_INFO(SD_LOG_ATTACH_DETACH, un,
	    "sd_alloc_rqs: un 0x%p, rqs  xp 0x%p,  pkt 0x%p,  buf 0x%p\n",
	    un, xp, un->un_rqs_pktp, un->un_rqs_bp);

	/*
	 * Save the pointer to the request sense private bp so it can
	 * be retrieved in sdintr.
	 */
	un->un_rqs_pktp->pkt_private = un->un_rqs_bp;
	ASSERT(un->un_rqs_bp->b_private == xp);

	/*
	 * See if the HBA supports auto-request sense for the specified
	 * target/lun. If it does, then try to enable it (if not already
	 * enabled).
	 *
	 * Note: For some HBAs (ifp & sf), scsi_ifsetcap will always return
	 * failure, while for other HBAs (pln) scsi_ifsetcap will always
	 * return success.  However, in both of these cases ARQ is always
	 * enabled and scsi_ifgetcap will always return true. The best approach
	 * is to issue the scsi_ifgetcap() first, then try the scsi_ifsetcap().
	 *
	 * The 3rd case is the HBA (adp) always return enabled on
	 * scsi_ifgetgetcap even when it's not enable, the best approach
	 * is issue a scsi_ifsetcap then a scsi_ifgetcap
	 * Note: this case is to circumvent the Adaptec bug. (x86 only)
	 */

	if (un->un_f_is_fibre == TRUE) {
		un->un_f_arq_enabled = TRUE;
	} else {
#if defined(__i386) || defined(__amd64)
		/*
		 * Circumvent the Adaptec bug, remove this code when
		 * the bug is fixed
		 */
		(void) scsi_ifsetcap(SD_ADDRESS(un), "auto-rqsense", 1, 1);
#endif
		switch (scsi_ifgetcap(SD_ADDRESS(un), "auto-rqsense", 1)) {
		case 0:
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_alloc_rqs: HBA supports ARQ\n");
			/*
			 * ARQ is supported by this HBA but currently is not
			 * enabled. Attempt to enable it and if successful then
			 * mark this instance as ARQ enabled.
			 */
			if (scsi_ifsetcap(SD_ADDRESS(un), "auto-rqsense", 1, 1)
			    == 1) {
				/* Successfully enabled ARQ in the HBA */
				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_alloc_rqs: ARQ enabled\n");
				un->un_f_arq_enabled = TRUE;
			} else {
				/* Could not enable ARQ in the HBA */
				SD_INFO(SD_LOG_ATTACH_DETACH, un,
				    "sd_alloc_rqs: failed ARQ enable\n");
				un->un_f_arq_enabled = FALSE;
			}
			break;
		case 1:
			/*
			 * ARQ is supported by this HBA and is already enabled.
			 * Just mark ARQ as enabled for this instance.
			 */
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_alloc_rqs: ARQ already enabled\n");
			un->un_f_arq_enabled = TRUE;
			break;
		default:
			/*
			 * ARQ is not supported by this HBA; disable it for this
			 * instance.
			 */
			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_alloc_rqs: HBA does not support ARQ\n");
			un->un_f_arq_enabled = FALSE;
			break;
		}
	}

	return (DDI_SUCCESS);
}


/*
 *    Function: sd_free_rqs
 *
 * Description: Cleanup for the pre-instance RQS command.
 *
 *     Context: Kernel thread context
 */

static void
sd_free_rqs(struct sd_lun *un)
{
	ASSERT(un != NULL);

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_free_rqs: entry\n");

	/*
	 * If consistent memory is bound to a scsi_pkt, the pkt
	 * has to be destroyed *before* freeing the consistent memory.
	 * Don't change the sequence of this operations.
	 * scsi_destroy_pkt() might access memory, which isn't allowed,
	 * after it was freed in scsi_free_consistent_buf().
	 */
	if (un->un_rqs_pktp != NULL) {
		scsi_destroy_pkt(un->un_rqs_pktp);
		un->un_rqs_pktp = NULL;
	}

	if (un->un_rqs_bp != NULL) {
		struct sd_xbuf *xp = SD_GET_XBUF(un->un_rqs_bp);
		if (xp != NULL) {
			kmem_free(xp, sizeof (struct sd_xbuf));
		}
		scsi_free_consistent_buf(un->un_rqs_bp);
		un->un_rqs_bp = NULL;
	}
	SD_TRACE(SD_LOG_IO_CORE, un, "sd_free_rqs: exit\n");
}



/*
 *    Function: sd_reduce_throttle
 *
 * Description: Reduces the maximum # of outstanding commands on a
 *		target to the current number of outstanding commands.
 *		Queues a tiemout(9F) callback to restore the limit
 *		after a specified interval has elapsed.
 *		Typically used when we get a TRAN_BUSY return code
 *		back from scsi_transport().
 *
 *   Arguments: un - ptr to the sd_lun softstate struct
 *		throttle_type: SD_THROTTLE_TRAN_BUSY or SD_THROTTLE_QFULL
 *
 *     Context: May be called from interrupt context
 */

static void
sd_reduce_throttle(struct sd_lun *un, int throttle_type)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(un->un_ncmds_in_transport >= 0);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_reduce_throttle: "
	    "entry: un:0x%p un_throttle:%d un_ncmds_in_transport:%d\n",
	    un, un->un_throttle, un->un_ncmds_in_transport);

	if (un->un_throttle > 1) {
		if (un->un_f_use_adaptive_throttle == TRUE) {
			switch (throttle_type) {
			case SD_THROTTLE_TRAN_BUSY:
				if (un->un_busy_throttle == 0) {
					un->un_busy_throttle = un->un_throttle;
				}
				break;
			case SD_THROTTLE_QFULL:
				un->un_busy_throttle = 0;
				break;
			default:
				ASSERT(FALSE);
			}

			if (un->un_ncmds_in_transport > 0) {
				un->un_throttle = un->un_ncmds_in_transport;
			}

		} else {
			if (un->un_ncmds_in_transport == 0) {
				un->un_throttle = 1;
			} else {
				un->un_throttle = un->un_ncmds_in_transport;
			}
		}
	}

	/* Reschedule the timeout if none is currently active */
	if (un->un_reset_throttle_timeid == NULL) {
		un->un_reset_throttle_timeid = timeout(sd_restore_throttle,
		    un, SD_THROTTLE_RESET_INTERVAL);
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_reduce_throttle: timeout scheduled!\n");
	}

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_reduce_throttle: "
	    "exit: un:0x%p un_throttle:%d\n", un, un->un_throttle);
}



/*
 *    Function: sd_restore_throttle
 *
 * Description: Callback function for timeout(9F).  Resets the current
 *		value of un->un_throttle to its default.
 *
 *   Arguments: arg - pointer to associated softstate for the device.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_restore_throttle(void *arg)
{
	struct sd_lun	*un = arg;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	mutex_enter(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un, "sd_restore_throttle: "
	    "entry: un:0x%p un_throttle:%d\n", un, un->un_throttle);

	un->un_reset_throttle_timeid = NULL;

	if (un->un_f_use_adaptive_throttle == TRUE) {
		/*
		 * If un_busy_throttle is nonzero, then it contains the
		 * value that un_throttle was when we got a TRAN_BUSY back
		 * from scsi_transport(). We want to revert back to this
		 * value.
		 *
		 * In the QFULL case, the throttle limit will incrementally
		 * increase until it reaches max throttle.
		 */
		if (un->un_busy_throttle > 0) {
			un->un_throttle = un->un_busy_throttle;
			un->un_busy_throttle = 0;
		} else {
			/*
			 * increase throttle by 10% open gate slowly, schedule
			 * another restore if saved throttle has not been
			 * reached
			 */
			short throttle;
			if (sd_qfull_throttle_enable) {
				throttle = un->un_throttle +
				    max((un->un_throttle / 10), 1);
				un->un_throttle =
				    (throttle < un->un_saved_throttle) ?
				    throttle : un->un_saved_throttle;
				if (un->un_throttle < un->un_saved_throttle) {
					un->un_reset_throttle_timeid =
					    timeout(sd_restore_throttle,
					    un,
					    SD_QFULL_THROTTLE_RESET_INTERVAL);
				}
			}
		}

		/*
		 * If un_throttle has fallen below the low-water mark, we
		 * restore the maximum value here (and allow it to ratchet
		 * down again if necessary).
		 */
		if (un->un_throttle < un->un_min_throttle) {
			un->un_throttle = un->un_saved_throttle;
		}
	} else {
		SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un, "sd_restore_throttle: "
		    "restoring limit from 0x%x to 0x%x\n",
		    un->un_throttle, un->un_saved_throttle);
		un->un_throttle = un->un_saved_throttle;
	}

	SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un,
	    "sd_restore_throttle: calling sd_start_cmds!\n");

	sd_start_cmds(un, NULL);

	SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un,
	    "sd_restore_throttle: exit: un:0x%p un_throttle:%d\n",
	    un, un->un_throttle);

	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un, "sd_restore_throttle: exit\n");
}

/*
 *    Function: sdrunout
 *
 * Description: Callback routine for scsi_init_pkt when a resource allocation
 *		fails.
 *
 *   Arguments: arg - a pointer to the sd_lun unit struct for the particular
 *		soft state instance.
 *
 * Return Code: The scsi_init_pkt routine allows for the callback function to
 *		return a 0 indicating the callback should be rescheduled or a 1
 *		indicating not to reschedule. This routine always returns 1
 *		because the driver always provides a callback function to
 *		scsi_init_pkt. This results in a callback always being scheduled
 *		(via the scsi_init_pkt callback implementation) if a resource
 *		failure occurs.
 *
 *     Context: This callback function may not block or call routines that block
 *
 *        Note: Using the scsi_init_pkt callback facility can result in an I/O
 *		request persisting at the head of the list which cannot be
 *		satisfied even after multiple retries. In the future the driver
 *		may implement some time of maximum runout count before failing
 *		an I/O.
 */

static int
sdrunout(caddr_t arg)
{
	struct sd_lun	*un = (struct sd_lun *)arg;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sdrunout: entry\n");

	mutex_enter(SD_MUTEX(un));
	sd_start_cmds(un, NULL);
	mutex_exit(SD_MUTEX(un));
	/*
	 * This callback routine always returns 1 (i.e. do not reschedule)
	 * because we always specify sdrunout as the callback handler for
	 * scsi_init_pkt inside the call to sd_start_cmds.
	 */
	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sdrunout: exit\n");
	return (1);
}


/*
 *    Function: sdintr
 *
 * Description: Completion callback routine for scsi_pkt(9S) structs
 *		sent to the HBA driver via scsi_transport(9F).
 *
 *     Context: Interrupt context
 */

static void
sdintr(struct scsi_pkt *pktp)
{
	struct buf	*bp;
	struct sd_xbuf	*xp;
	struct sd_lun	*un;
	size_t		actual_len;
	sd_ssc_t	*sscp;

	ASSERT(pktp != NULL);
	bp = (struct buf *)pktp->pkt_private;
	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	ASSERT(xp->xb_pktp != NULL);
	un = SD_GET_UN(bp);
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

#ifdef SD_FAULT_INJECTION

	SD_INFO(SD_LOG_IOERR, un, "sdintr: sdintr calling Fault injection\n");
	/* SD FaultInjection */
	sd_faultinjection(pktp);

#endif /* SD_FAULT_INJECTION */

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sdintr: entry: buf:0x%p,"
	    " xp:0x%p, un:0x%p\n", bp, xp, un);

	mutex_enter(SD_MUTEX(un));

	ASSERT(un->un_fm_private != NULL);
	sscp = &((struct sd_fm_internal *)(un->un_fm_private))->fm_ssc;
	ASSERT(sscp != NULL);

	/* Reduce the count of the #commands currently in transport */
	un->un_ncmds_in_transport--;
	ASSERT(un->un_ncmds_in_transport >= 0);

	/* Increment counter to indicate that the callback routine is active */
	un->un_in_callback++;

	SD_UPDATE_KSTATS(un, kstat_runq_exit, bp);

#ifdef	SDDEBUG
	if (bp == un->un_retry_bp) {
		SD_TRACE(SD_LOG_IO | SD_LOG_ERROR, un, "sdintr: "
		    "un:0x%p: GOT retry_bp:0x%p un_ncmds_in_transport:%d\n",
		    un, un->un_retry_bp, un->un_ncmds_in_transport);
	}
#endif

	/*
	 * If pkt_reason is CMD_DEV_GONE, fail the command, and update the media
	 * state if needed.
	 */
	if (pktp->pkt_reason == CMD_DEV_GONE) {
		/* Prevent multiple console messages for the same failure. */
		if (un->un_last_pkt_reason != CMD_DEV_GONE) {
			un->un_last_pkt_reason = CMD_DEV_GONE;
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "Command failed to complete...Device is gone\n");
		}
		if (un->un_mediastate != DKIO_DEV_GONE) {
			un->un_mediastate = DKIO_DEV_GONE;
			cv_broadcast(&un->un_state_cv);
		}
		/*
		 * If the command happens to be the REQUEST SENSE command,
		 * free up the rqs buf and fail the original command.
		 */
		if (bp == un->un_rqs_bp) {
			bp = sd_mark_rqs_idle(un, xp);
		}
		sd_return_failed_command(un, bp, EIO);
		goto exit;
	}

	if (pktp->pkt_state & STATE_XARQ_DONE) {
		SD_TRACE(SD_LOG_COMMON, un,
		    "sdintr: extra sense data received. pkt=%p\n", pktp);
	}

	/*
	 * First see if the pkt has auto-request sense data with it....
	 * Look at the packet state first so we don't take a performance
	 * hit looking at the arq enabled flag unless absolutely necessary.
	 */
	if ((pktp->pkt_state & STATE_ARQ_DONE) &&
	    (un->un_f_arq_enabled == TRUE)) {
		/*
		 * The HBA did an auto request sense for this command so check
		 * for FLAG_DIAGNOSE. If set this indicates a uscsi or internal
		 * driver command that should not be retried.
		 */
		if ((pktp->pkt_flags & FLAG_DIAGNOSE) != 0) {
			/*
			 * Save the relevant sense info into the xp for the
			 * original cmd.
			 */
			struct scsi_arq_status *asp;
			asp = (struct scsi_arq_status *)(pktp->pkt_scbp);
			xp->xb_sense_status =
			    *((uchar_t *)(&(asp->sts_rqpkt_status)));
			xp->xb_sense_state  = asp->sts_rqpkt_state;
			xp->xb_sense_resid  = asp->sts_rqpkt_resid;
			if (pktp->pkt_state & STATE_XARQ_DONE) {
				actual_len = MAX_SENSE_LENGTH -
				    xp->xb_sense_resid;
				bcopy(&asp->sts_sensedata, xp->xb_sense_data,
				    MAX_SENSE_LENGTH);
			} else {
				if (xp->xb_sense_resid > SENSE_LENGTH) {
					actual_len = MAX_SENSE_LENGTH -
					    xp->xb_sense_resid;
				} else {
					actual_len = SENSE_LENGTH -
					    xp->xb_sense_resid;
				}
				if (xp->xb_pkt_flags & SD_XB_USCSICMD) {
					if ((((struct uscsi_cmd *)
					    (xp->xb_pktinfo))->uscsi_rqlen) >
					    actual_len) {
						xp->xb_sense_resid =
						    (((struct uscsi_cmd *)
						    (xp->xb_pktinfo))->
						    uscsi_rqlen) - actual_len;
					} else {
						xp->xb_sense_resid = 0;
					}
				}
				bcopy(&asp->sts_sensedata, xp->xb_sense_data,
				    SENSE_LENGTH);
			}

			/* fail the command */
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: arq done and FLAG_DIAGNOSE set\n");
			sd_return_failed_command(un, bp, EIO);
			goto exit;
		}

#if (defined(__i386) || defined(__amd64))	/* DMAFREE for x86 only */
		/*
		 * We want to either retry or fail this command, so free
		 * the DMA resources here.  If we retry the command then
		 * the DMA resources will be reallocated in sd_start_cmds().
		 * Note that when PKT_DMA_PARTIAL is used, this reallocation
		 * causes the *entire* transfer to start over again from the
		 * beginning of the request, even for PARTIAL chunks that
		 * have already transferred successfully.
		 */
		if ((un->un_f_is_fibre == TRUE) &&
		    ((xp->xb_pkt_flags & SD_XB_USCSICMD) == 0) &&
		    ((pktp->pkt_flags & FLAG_SENSING) == 0))  {
			scsi_dmafree(pktp);
			xp->xb_pkt_flags |= SD_XB_DMA_FREED;
		}
#endif

		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: arq done, sd_handle_auto_request_sense\n");

		sd_handle_auto_request_sense(un, bp, xp, pktp);
		goto exit;
	}

	/* Next see if this is the REQUEST SENSE pkt for the instance */
	if (pktp->pkt_flags & FLAG_SENSING)  {
		/* This pktp is from the unit's REQUEST_SENSE command */
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: sd_handle_request_sense\n");
		sd_handle_request_sense(un, bp, xp, pktp);
		goto exit;
	}

	/*
	 * Check to see if the command successfully completed as requested;
	 * this is the most common case (and also the hot performance path).
	 *
	 * Requirements for successful completion are:
	 * pkt_reason is CMD_CMPLT and packet status is status good.
	 * In addition:
	 * - A residual of zero indicates successful completion no matter what
	 *   the command is.
	 * - If the residual is not zero and the command is not a read or
	 *   write, then it's still defined as successful completion. In other
	 *   words, if the command is a read or write the residual must be
	 *   zero for successful completion.
	 * - If the residual is not zero and the command is a read or
	 *   write, and it's a USCSICMD, then it's still defined as
	 *   successful completion.
	 */
	if ((pktp->pkt_reason == CMD_CMPLT) &&
	    (SD_GET_PKT_STATUS(pktp) == STATUS_GOOD)) {

		/*
		 * Since this command is returned with a good status, we
		 * can reset the count for Sonoma failover.
		 */
		un->un_sonoma_failure_count = 0;

		/*
		 * Return all USCSI commands on good status
		 */
		if (pktp->pkt_resid == 0) {
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: returning command for resid == 0\n");
		} else if (((SD_GET_PKT_OPCODE(pktp) & 0x1F) != SCMD_READ) &&
		    ((SD_GET_PKT_OPCODE(pktp) & 0x1F) != SCMD_WRITE)) {
			SD_UPDATE_B_RESID(bp, pktp);
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: returning command for resid != 0\n");
		} else if (xp->xb_pkt_flags & SD_XB_USCSICMD) {
			SD_UPDATE_B_RESID(bp, pktp);
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: returning uscsi command\n");
		} else {
			goto not_successful;
		}
		sd_return_command(un, bp);

		/*
		 * Decrement counter to indicate that the callback routine
		 * is done.
		 */
		un->un_in_callback--;
		ASSERT(un->un_in_callback >= 0);
		mutex_exit(SD_MUTEX(un));

		return;
	}

not_successful:

#if (defined(__i386) || defined(__amd64))	/* DMAFREE for x86 only */
	/*
	 * The following is based upon knowledge of the underlying transport
	 * and its use of DMA resources.  This code should be removed when
	 * PKT_DMA_PARTIAL support is taken out of the disk driver in favor
	 * of the new PKT_CMD_BREAKUP protocol. See also sd_initpkt_for_buf()
	 * and sd_start_cmds().
	 *
	 * Free any DMA resources associated with this command if there
	 * is a chance it could be retried or enqueued for later retry.
	 * If we keep the DMA binding then mpxio cannot reissue the
	 * command on another path whenever a path failure occurs.
	 *
	 * Note that when PKT_DMA_PARTIAL is used, free/reallocation
	 * causes the *entire* transfer to start over again from the
	 * beginning of the request, even for PARTIAL chunks that
	 * have already transferred successfully.
	 *
	 * This is only done for non-uscsi commands (and also skipped for the
	 * driver's internal RQS command). Also just do this for Fibre Channel
	 * devices as these are the only ones that support mpxio.
	 */
	if ((un->un_f_is_fibre == TRUE) &&
	    ((xp->xb_pkt_flags & SD_XB_USCSICMD) == 0) &&
	    ((pktp->pkt_flags & FLAG_SENSING) == 0))  {
		scsi_dmafree(pktp);
		xp->xb_pkt_flags |= SD_XB_DMA_FREED;
	}
#endif

	/*
	 * The command did not successfully complete as requested so check
	 * for FLAG_DIAGNOSE. If set this indicates a uscsi or internal
	 * driver command that should not be retried so just return. If
	 * FLAG_DIAGNOSE is not set the error will be processed below.
	 */
	if ((pktp->pkt_flags & FLAG_DIAGNOSE) != 0) {
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: FLAG_DIAGNOSE: sd_return_failed_command\n");
		/*
		 * Issue a request sense if a check condition caused the error
		 * (we handle the auto request sense case above), otherwise
		 * just fail the command.
		 */
		if ((pktp->pkt_reason == CMD_CMPLT) &&
		    (SD_GET_PKT_STATUS(pktp) == STATUS_CHECK)) {
			sd_send_request_sense_command(un, bp, pktp);
		} else {
			sd_return_failed_command(un, bp, EIO);
		}
		goto exit;
	}

	/*
	 * The command did not successfully complete as requested so process
	 * the error, retry, and/or attempt recovery.
	 */
	switch (pktp->pkt_reason) {
	case CMD_CMPLT:
		switch (SD_GET_PKT_STATUS(pktp)) {
		case STATUS_GOOD:
			/*
			 * The command completed successfully with a non-zero
			 * residual
			 */
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: STATUS_GOOD \n");
			sd_pkt_status_good(un, bp, xp, pktp);
			break;

		case STATUS_CHECK:
		case STATUS_TERMINATED:
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: STATUS_TERMINATED | STATUS_CHECK\n");
			sd_pkt_status_check_condition(un, bp, xp, pktp);
			break;

		case STATUS_BUSY:
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: STATUS_BUSY\n");
			sd_pkt_status_busy(un, bp, xp, pktp);
			break;

		case STATUS_RESERVATION_CONFLICT:
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: STATUS_RESERVATION_CONFLICT\n");
			sd_pkt_status_reservation_conflict(un, bp, xp, pktp);
			break;

		case STATUS_QFULL:
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sdintr: STATUS_QFULL\n");
			sd_pkt_status_qfull(un, bp, xp, pktp);
			break;

		case STATUS_MET:
		case STATUS_INTERMEDIATE:
		case STATUS_SCSI2:
		case STATUS_INTERMEDIATE_MET:
		case STATUS_ACA_ACTIVE:
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "Unexpected SCSI status received: 0x%x\n",
			    SD_GET_PKT_STATUS(pktp));
			/*
			 * Mark the ssc_flags when detected invalid status
			 * code for non-USCSI command.
			 */
			if (!(xp->xb_pkt_flags & SD_XB_USCSICMD)) {
				sd_ssc_set_info(sscp, SSC_FLAGS_INVALID_STATUS,
				    0, "stat-code");
			}
			sd_return_failed_command(un, bp, EIO);
			break;

		default:
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "Invalid SCSI status received: 0x%x\n",
			    SD_GET_PKT_STATUS(pktp));
			if (!(xp->xb_pkt_flags & SD_XB_USCSICMD)) {
				sd_ssc_set_info(sscp, SSC_FLAGS_INVALID_STATUS,
				    0, "stat-code");
			}
			sd_return_failed_command(un, bp, EIO);
			break;

		}
		break;

	case CMD_INCOMPLETE:
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr:  CMD_INCOMPLETE\n");
		sd_pkt_reason_cmd_incomplete(un, bp, xp, pktp);
		break;
	case CMD_TRAN_ERR:
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: CMD_TRAN_ERR\n");
		sd_pkt_reason_cmd_tran_err(un, bp, xp, pktp);
		break;
	case CMD_RESET:
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: CMD_RESET \n");
		sd_pkt_reason_cmd_reset(un, bp, xp, pktp);
		break;
	case CMD_ABORTED:
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: CMD_ABORTED \n");
		sd_pkt_reason_cmd_aborted(un, bp, xp, pktp);
		break;
	case CMD_TIMEOUT:
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: CMD_TIMEOUT\n");
		sd_pkt_reason_cmd_timeout(un, bp, xp, pktp);
		break;
	case CMD_UNX_BUS_FREE:
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: CMD_UNX_BUS_FREE \n");
		sd_pkt_reason_cmd_unx_bus_free(un, bp, xp, pktp);
		break;
	case CMD_TAG_REJECT:
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: CMD_TAG_REJECT\n");
		sd_pkt_reason_cmd_tag_reject(un, bp, xp, pktp);
		break;
	default:
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sdintr: default\n");
		/*
		 * Mark the ssc_flags for detecting invliad pkt_reason.
		 */
		if (!(xp->xb_pkt_flags & SD_XB_USCSICMD)) {
			sd_ssc_set_info(sscp, SSC_FLAGS_INVALID_PKT_REASON,
			    0, "pkt-reason");
		}
		sd_pkt_reason_default(un, bp, xp, pktp);
		break;
	}

exit:
	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sdintr: exit\n");

	/* Decrement counter to indicate that the callback routine is done. */
	un->un_in_callback--;
	ASSERT(un->un_in_callback >= 0);

	/*
	 * At this point, the pkt has been dispatched, ie, it is either
	 * being re-tried or has been returned to its caller and should
	 * not be referenced.
	 */

	mutex_exit(SD_MUTEX(un));
}


/*
 *    Function: sd_print_incomplete_msg
 *
 * Description: Prints the error message for a CMD_INCOMPLETE error.
 *
 *   Arguments: un - ptr to associated softstate for the device.
 *		bp - ptr to the buf(9S) for the command.
 *		arg - message string ptr
 *		code - SD_DELAYED_RETRY_ISSUED, SD_IMMEDIATE_RETRY_ISSUED,
 *			or SD_NO_RETRY_ISSUED.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_print_incomplete_msg(struct sd_lun *un, struct buf *bp, void *arg, int code)
{
	struct scsi_pkt	*pktp;
	char	*msgp;
	char	*cmdp = arg;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(arg != NULL);
	pktp = SD_GET_PKTP(bp);
	ASSERT(pktp != NULL);

	switch (code) {
	case SD_DELAYED_RETRY_ISSUED:
	case SD_IMMEDIATE_RETRY_ISSUED:
		msgp = "retrying";
		break;
	case SD_NO_RETRY_ISSUED:
	default:
		msgp = "giving up";
		break;
	}

	if ((pktp->pkt_flags & FLAG_SILENT) == 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "incomplete %s- %s\n", cmdp, msgp);
	}
}



/*
 *    Function: sd_pkt_status_good
 *
 * Description: Processing for a STATUS_GOOD code in pkt_status.
 *
 *     Context: May be called under interrupt context
 */

static void
sd_pkt_status_good(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	char	*cmdp;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);
	ASSERT(pktp->pkt_reason == CMD_CMPLT);
	ASSERT(SD_GET_PKT_STATUS(pktp) == STATUS_GOOD);
	ASSERT(pktp->pkt_resid != 0);

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_pkt_status_good: entry\n");

	SD_UPDATE_ERRSTATS(un, sd_harderrs);
	switch (SD_GET_PKT_OPCODE(pktp) & 0x1F) {
	case SCMD_READ:
		cmdp = "read";
		break;
	case SCMD_WRITE:
		cmdp = "write";
		break;
	default:
		SD_UPDATE_B_RESID(bp, pktp);
		sd_return_command(un, bp);
		SD_TRACE(SD_LOG_IO_CORE, un, "sd_pkt_status_good: exit\n");
		return;
	}

	/*
	 * See if we can retry the read/write, preferrably immediately.
	 * If retries are exhaused, then sd_retry_command() will update
	 * the b_resid count.
	 */
	sd_retry_command(un, bp, SD_RETRIES_STANDARD, sd_print_incomplete_msg,
	    cmdp, EIO, (clock_t)0, NULL);

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_pkt_status_good: exit\n");
}





/*
 *    Function: sd_handle_request_sense
 *
 * Description: Processing for non-auto Request Sense command.
 *
 *   Arguments: un - ptr to associated softstate
 *		sense_bp - ptr to buf(9S) for the RQS command
 *		sense_xp - ptr to the sd_xbuf for the RQS command
 *		sense_pktp - ptr to the scsi_pkt(9S) for the RQS command
 *
 *     Context: May be called under interrupt context
 */

static void
sd_handle_request_sense(struct sd_lun *un, struct buf *sense_bp,
	struct sd_xbuf *sense_xp, struct scsi_pkt *sense_pktp)
{
	struct buf	*cmd_bp;	/* buf for the original command */
	struct sd_xbuf	*cmd_xp;	/* sd_xbuf for the original command */
	struct scsi_pkt *cmd_pktp;	/* pkt for the original command */
	size_t		actual_len;	/* actual sense data length */

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(sense_bp != NULL);
	ASSERT(sense_xp != NULL);
	ASSERT(sense_pktp != NULL);

	/*
	 * Note the sense_bp, sense_xp, and sense_pktp here are for the
	 * RQS command and not the original command.
	 */
	ASSERT(sense_pktp == un->un_rqs_pktp);
	ASSERT(sense_bp   == un->un_rqs_bp);
	ASSERT((sense_pktp->pkt_flags & (FLAG_SENSING | FLAG_HEAD)) ==
	    (FLAG_SENSING | FLAG_HEAD));
	ASSERT((((SD_GET_XBUF(sense_xp->xb_sense_bp))->xb_pktp->pkt_flags) &
	    FLAG_SENSING) == FLAG_SENSING);

	/* These are the bp, xp, and pktp for the original command */
	cmd_bp = sense_xp->xb_sense_bp;
	cmd_xp = SD_GET_XBUF(cmd_bp);
	cmd_pktp = SD_GET_PKTP(cmd_bp);

	if (sense_pktp->pkt_reason != CMD_CMPLT) {
		/*
		 * The REQUEST SENSE command failed.  Release the REQUEST
		 * SENSE command for re-use, get back the bp for the original
		 * command, and attempt to re-try the original command if
		 * FLAG_DIAGNOSE is not set in the original packet.
		 */
		SD_UPDATE_ERRSTATS(un, sd_harderrs);
		if ((cmd_pktp->pkt_flags & FLAG_DIAGNOSE) == 0) {
			cmd_bp = sd_mark_rqs_idle(un, sense_xp);
			sd_retry_command(un, cmd_bp, SD_RETRIES_STANDARD,
			    NULL, NULL, EIO, (clock_t)0, NULL);
			return;
		}
	}

	/*
	 * Save the relevant sense info into the xp for the original cmd.
	 *
	 * Note: if the request sense failed the state info will be zero
	 * as set in sd_mark_rqs_busy()
	 */
	cmd_xp->xb_sense_status = *(sense_pktp->pkt_scbp);
	cmd_xp->xb_sense_state  = sense_pktp->pkt_state;
	actual_len = MAX_SENSE_LENGTH - sense_pktp->pkt_resid;
	if ((cmd_xp->xb_pkt_flags & SD_XB_USCSICMD) &&
	    (((struct uscsi_cmd *)cmd_xp->xb_pktinfo)->uscsi_rqlen >
	    SENSE_LENGTH)) {
		bcopy(sense_bp->b_un.b_addr, cmd_xp->xb_sense_data,
		    MAX_SENSE_LENGTH);
		cmd_xp->xb_sense_resid = sense_pktp->pkt_resid;
	} else {
		bcopy(sense_bp->b_un.b_addr, cmd_xp->xb_sense_data,
		    SENSE_LENGTH);
		if (actual_len < SENSE_LENGTH) {
			cmd_xp->xb_sense_resid = SENSE_LENGTH - actual_len;
		} else {
			cmd_xp->xb_sense_resid = 0;
		}
	}

	/*
	 *  Free up the RQS command....
	 *  NOTE:
	 *	Must do this BEFORE calling sd_validate_sense_data!
	 *	sd_validate_sense_data may return the original command in
	 *	which case the pkt will be freed and the flags can no
	 *	longer be touched.
	 *	SD_MUTEX is held through this process until the command
	 *	is dispatched based upon the sense data, so there are
	 *	no race conditions.
	 */
	(void) sd_mark_rqs_idle(un, sense_xp);

	/*
	 * For a retryable command see if we have valid sense data, if so then
	 * turn it over to sd_decode_sense() to figure out the right course of
	 * action. Just fail a non-retryable command.
	 */
	if ((cmd_pktp->pkt_flags & FLAG_DIAGNOSE) == 0) {
		if (sd_validate_sense_data(un, cmd_bp, cmd_xp, actual_len) ==
		    SD_SENSE_DATA_IS_VALID) {
			sd_decode_sense(un, cmd_bp, cmd_xp, cmd_pktp);
		}
	} else {
		SD_DUMP_MEMORY(un, SD_LOG_IO_CORE, "Failed CDB",
		    (uchar_t *)cmd_pktp->pkt_cdbp, CDB_SIZE, SD_LOG_HEX);
		SD_DUMP_MEMORY(un, SD_LOG_IO_CORE, "Sense Data",
		    (uchar_t *)cmd_xp->xb_sense_data, SENSE_LENGTH, SD_LOG_HEX);
		sd_return_failed_command(un, cmd_bp, EIO);
	}
}




/*
 *    Function: sd_handle_auto_request_sense
 *
 * Description: Processing for auto-request sense information.
 *
 *   Arguments: un - ptr to associated softstate
 *		bp - ptr to buf(9S) for the command
 *		xp - ptr to the sd_xbuf for the command
 *		pktp - ptr to the scsi_pkt(9S) for the command
 *
 *     Context: May be called under interrupt context
 */

static void
sd_handle_auto_request_sense(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct scsi_arq_status *asp;
	size_t actual_len;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);
	ASSERT(pktp != un->un_rqs_pktp);
	ASSERT(bp   != un->un_rqs_bp);

	/*
	 * For auto-request sense, we get a scsi_arq_status back from
	 * the HBA, with the sense data in the sts_sensedata member.
	 * The pkt_scbp of the packet points to this scsi_arq_status.
	 */
	asp = (struct scsi_arq_status *)(pktp->pkt_scbp);

	if (asp->sts_rqpkt_reason != CMD_CMPLT) {
		/*
		 * The auto REQUEST SENSE failed; see if we can re-try
		 * the original command.
		 */
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "auto request sense failed (reason=%s)\n",
		    scsi_rname(asp->sts_rqpkt_reason));

		sd_reset_target(un, pktp);

		sd_retry_command(un, bp, SD_RETRIES_STANDARD,
		    NULL, NULL, EIO, (clock_t)0, NULL);
		return;
	}

	/* Save the relevant sense info into the xp for the original cmd. */
	xp->xb_sense_status = *((uchar_t *)(&(asp->sts_rqpkt_status)));
	xp->xb_sense_state  = asp->sts_rqpkt_state;
	xp->xb_sense_resid  = asp->sts_rqpkt_resid;
	if (xp->xb_sense_state & STATE_XARQ_DONE) {
		actual_len = MAX_SENSE_LENGTH - xp->xb_sense_resid;
		bcopy(&asp->sts_sensedata, xp->xb_sense_data,
		    MAX_SENSE_LENGTH);
	} else {
		if (xp->xb_sense_resid > SENSE_LENGTH) {
			actual_len = MAX_SENSE_LENGTH - xp->xb_sense_resid;
		} else {
			actual_len = SENSE_LENGTH - xp->xb_sense_resid;
		}
		if (xp->xb_pkt_flags & SD_XB_USCSICMD) {
			if ((((struct uscsi_cmd *)
			    (xp->xb_pktinfo))->uscsi_rqlen) > actual_len) {
				xp->xb_sense_resid = (((struct uscsi_cmd *)
				    (xp->xb_pktinfo))->uscsi_rqlen) -
				    actual_len;
			} else {
				xp->xb_sense_resid = 0;
			}
		}
		bcopy(&asp->sts_sensedata, xp->xb_sense_data, SENSE_LENGTH);
	}

	/*
	 * See if we have valid sense data, if so then turn it over to
	 * sd_decode_sense() to figure out the right course of action.
	 */
	if (sd_validate_sense_data(un, bp, xp, actual_len) ==
	    SD_SENSE_DATA_IS_VALID) {
		sd_decode_sense(un, bp, xp, pktp);
	}
}


/*
 *    Function: sd_print_sense_failed_msg
 *
 * Description: Print log message when RQS has failed.
 *
 *   Arguments: un - ptr to associated softstate
 *		bp - ptr to buf(9S) for the command
 *		arg - generic message string ptr
 *		code - SD_IMMEDIATE_RETRY_ISSUED, SD_DELAYED_RETRY_ISSUED,
 *			or SD_NO_RETRY_ISSUED
 *
 *     Context: May be called from interrupt context
 */

static void
sd_print_sense_failed_msg(struct sd_lun *un, struct buf *bp, void *arg,
	int code)
{
	char	*msgp = arg;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);

	if ((code == SD_NO_RETRY_ISSUED) && (msgp != NULL)) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN, msgp);
	}
}


/*
 *    Function: sd_validate_sense_data
 *
 * Description: Check the given sense data for validity.
 *		If the sense data is not valid, the command will
 *		be either failed or retried!
 *
 * Return Code: SD_SENSE_DATA_IS_INVALID
 *		SD_SENSE_DATA_IS_VALID
 *
 *     Context: May be called from interrupt context
 */

static int
sd_validate_sense_data(struct sd_lun *un, struct buf *bp, struct sd_xbuf *xp,
	size_t actual_len)
{
	struct scsi_extended_sense *esp;
	struct	scsi_pkt *pktp;
	char	*msgp = NULL;
	sd_ssc_t *sscp;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(bp != un->un_rqs_bp);
	ASSERT(xp != NULL);
	ASSERT(un->un_fm_private != NULL);

	pktp = SD_GET_PKTP(bp);
	ASSERT(pktp != NULL);

	sscp = &((struct sd_fm_internal *)(un->un_fm_private))->fm_ssc;
	ASSERT(sscp != NULL);

	/*
	 * Check the status of the RQS command (auto or manual).
	 */
	switch (xp->xb_sense_status & STATUS_MASK) {
	case STATUS_GOOD:
		break;

	case STATUS_RESERVATION_CONFLICT:
		sd_pkt_status_reservation_conflict(un, bp, xp, pktp);
		return (SD_SENSE_DATA_IS_INVALID);

	case STATUS_BUSY:
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "Busy Status on REQUEST SENSE\n");
		sd_retry_command(un, bp, SD_RETRIES_BUSY, NULL,
		    NULL, EIO, un->un_busy_timeout / 500, kstat_waitq_enter);
		return (SD_SENSE_DATA_IS_INVALID);

	case STATUS_QFULL:
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "QFULL Status on REQUEST SENSE\n");
		sd_retry_command(un, bp, SD_RETRIES_STANDARD, NULL,
		    NULL, EIO, un->un_busy_timeout / 500, kstat_waitq_enter);
		return (SD_SENSE_DATA_IS_INVALID);

	case STATUS_CHECK:
	case STATUS_TERMINATED:
		msgp = "Check Condition on REQUEST SENSE\n";
		goto sense_failed;

	default:
		msgp = "Not STATUS_GOOD on REQUEST_SENSE\n";
		goto sense_failed;
	}

	/*
	 * See if we got the minimum required amount of sense data.
	 * Note: We are assuming the returned sense data is SENSE_LENGTH bytes
	 * or less.
	 */
	if (((xp->xb_sense_state & STATE_XFERRED_DATA) == 0) ||
	    (actual_len == 0)) {
		msgp = "Request Sense couldn't get sense data\n";
		goto sense_failed;
	}

	if (actual_len < SUN_MIN_SENSE_LENGTH) {
		msgp = "Not enough sense information\n";
		/* Mark the ssc_flags for detecting invalid sense data */
		if (!(xp->xb_pkt_flags & SD_XB_USCSICMD)) {
			sd_ssc_set_info(sscp, SSC_FLAGS_INVALID_SENSE, 0,
			    "sense-data");
		}
		goto sense_failed;
	}

	/*
	 * We require the extended sense data
	 */
	esp = (struct scsi_extended_sense *)xp->xb_sense_data;
	if (esp->es_class != CLASS_EXTENDED_SENSE) {
		if ((pktp->pkt_flags & FLAG_SILENT) == 0) {
			static char tmp[8];
			static char buf[148];
			char *p = (char *)(xp->xb_sense_data);
			int i;

			mutex_enter(&sd_sense_mutex);
			(void) strcpy(buf, "undecodable sense information:");
			for (i = 0; i < actual_len; i++) {
				(void) sprintf(tmp, " 0x%x", *(p++)&0xff);
				(void) strcpy(&buf[strlen(buf)], tmp);
			}
			i = strlen(buf);
			(void) strcpy(&buf[i], "-(assumed fatal)\n");

			if (SD_FM_LOG(un) == SD_FM_LOG_NSUP) {
				scsi_log(SD_DEVINFO(un), sd_label,
				    CE_WARN, buf);
			}
			mutex_exit(&sd_sense_mutex);
		}

		/* Mark the ssc_flags for detecting invalid sense data */
		if (!(xp->xb_pkt_flags & SD_XB_USCSICMD)) {
			sd_ssc_set_info(sscp, SSC_FLAGS_INVALID_SENSE, 0,
			    "sense-data");
		}

		/* Note: Legacy behavior, fail the command with no retry */
		sd_return_failed_command(un, bp, EIO);
		return (SD_SENSE_DATA_IS_INVALID);
	}

	/*
	 * Check that es_code is valid (es_class concatenated with es_code
	 * make up the "response code" field.  es_class will always be 7, so
	 * make sure es_code is 0, 1, 2, 3 or 0xf.  es_code will indicate the
	 * format.
	 */
	if ((esp->es_code != CODE_FMT_FIXED_CURRENT) &&
	    (esp->es_code != CODE_FMT_FIXED_DEFERRED) &&
	    (esp->es_code != CODE_FMT_DESCR_CURRENT) &&
	    (esp->es_code != CODE_FMT_DESCR_DEFERRED) &&
	    (esp->es_code != CODE_FMT_VENDOR_SPECIFIC)) {
		/* Mark the ssc_flags for detecting invalid sense data */
		if (!(xp->xb_pkt_flags & SD_XB_USCSICMD)) {
			sd_ssc_set_info(sscp, SSC_FLAGS_INVALID_SENSE, 0,
			    "sense-data");
		}
		goto sense_failed;
	}

	return (SD_SENSE_DATA_IS_VALID);

sense_failed:
	/*
	 * If the request sense failed (for whatever reason), attempt
	 * to retry the original command.
	 */
#if defined(__i386) || defined(__amd64)
	/*
	 * SD_RETRY_DELAY is conditionally compile (#if fibre) in
	 * sddef.h for Sparc platform, and x86 uses 1 binary
	 * for both SCSI/FC.
	 * The SD_RETRY_DELAY value need to be adjusted here
	 * when SD_RETRY_DELAY change in sddef.h
	 */
	sd_retry_command(un, bp, SD_RETRIES_STANDARD,
	    sd_print_sense_failed_msg, msgp, EIO,
	    un->un_f_is_fibre?drv_usectohz(100000):(clock_t)0, NULL);
#else
	sd_retry_command(un, bp, SD_RETRIES_STANDARD,
	    sd_print_sense_failed_msg, msgp, EIO, SD_RETRY_DELAY, NULL);
#endif

	return (SD_SENSE_DATA_IS_INVALID);
}

/*
 *    Function: sd_decode_sense
 *
 * Description: Take recovery action(s) when SCSI Sense Data is received.
 *
 *     Context: Interrupt context.
 */

static void
sd_decode_sense(struct sd_lun *un, struct buf *bp, struct sd_xbuf *xp,
	struct scsi_pkt *pktp)
{
	uint8_t sense_key;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(bp != un->un_rqs_bp);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	sense_key = scsi_sense_key(xp->xb_sense_data);

	switch (sense_key) {
	case KEY_NO_SENSE:
		sd_sense_key_no_sense(un, bp, xp, pktp);
		break;
	case KEY_RECOVERABLE_ERROR:
		sd_sense_key_recoverable_error(un, xp->xb_sense_data,
		    bp, xp, pktp);
		break;
	case KEY_NOT_READY:
		sd_sense_key_not_ready(un, xp->xb_sense_data,
		    bp, xp, pktp);
		break;
	case KEY_MEDIUM_ERROR:
	case KEY_HARDWARE_ERROR:
		sd_sense_key_medium_or_hardware_error(un,
		    xp->xb_sense_data, bp, xp, pktp);
		break;
	case KEY_ILLEGAL_REQUEST:
		sd_sense_key_illegal_request(un, bp, xp, pktp);
		break;
	case KEY_UNIT_ATTENTION:
		sd_sense_key_unit_attention(un, xp->xb_sense_data,
		    bp, xp, pktp);
		break;
	case KEY_WRITE_PROTECT:
	case KEY_VOLUME_OVERFLOW:
	case KEY_MISCOMPARE:
		sd_sense_key_fail_command(un, bp, xp, pktp);
		break;
	case KEY_BLANK_CHECK:
		sd_sense_key_blank_check(un, bp, xp, pktp);
		break;
	case KEY_ABORTED_COMMAND:
		sd_sense_key_aborted_command(un, bp, xp, pktp);
		break;
	case KEY_VENDOR_UNIQUE:
	case KEY_COPY_ABORTED:
	case KEY_EQUAL:
	case KEY_RESERVED:
	default:
		sd_sense_key_default(un, xp->xb_sense_data,
		    bp, xp, pktp);
		break;
	}
}


/*
 *    Function: sd_dump_memory
 *
 * Description: Debug logging routine to print the contents of a user provided
 *		buffer. The output of the buffer is broken up into 256 byte
 *		segments due to a size constraint of the scsi_log.
 *		implementation.
 *
 *   Arguments: un - ptr to softstate
 *		comp - component mask
 *		title - "title" string to preceed data when printed
 *		data - ptr to data block to be printed
 *		len - size of data block to be printed
 *		fmt - SD_LOG_HEX (use 0x%02x format) or SD_LOG_CHAR (use %c)
 *
 *     Context: May be called from interrupt context
 */

#define	SD_DUMP_MEMORY_BUF_SIZE	256

static char *sd_dump_format_string[] = {
		" 0x%02x",
		" %c"
};

static void
sd_dump_memory(struct sd_lun *un, uint_t comp, char *title, uchar_t *data,
    int len, int fmt)
{
	int	i, j;
	int	avail_count;
	int	start_offset;
	int	end_offset;
	size_t	entry_len;
	char	*bufp;
	char	*local_buf;
	char	*format_string;

	ASSERT((fmt == SD_LOG_HEX) || (fmt == SD_LOG_CHAR));

	/*
	 * In the debug version of the driver, this function is called from a
	 * number of places which are NOPs in the release driver.
	 * The debug driver therefore has additional methods of filtering
	 * debug output.
	 */
#ifdef SDDEBUG
	/*
	 * In the debug version of the driver we can reduce the amount of debug
	 * messages by setting sd_error_level to something other than
	 * SCSI_ERR_ALL and clearing bits in sd_level_mask and
	 * sd_component_mask.
	 */
	if (((sd_level_mask & (SD_LOGMASK_DUMP_MEM | SD_LOGMASK_DIAG)) == 0) ||
	    (sd_error_level != SCSI_ERR_ALL)) {
		return;
	}
	if (((sd_component_mask & comp) == 0) ||
	    (sd_error_level != SCSI_ERR_ALL)) {
		return;
	}
#else
	if (sd_error_level != SCSI_ERR_ALL) {
		return;
	}
#endif

	local_buf = kmem_zalloc(SD_DUMP_MEMORY_BUF_SIZE, KM_SLEEP);
	bufp = local_buf;
	/*
	 * Available length is the length of local_buf[], minus the
	 * length of the title string, minus one for the ":", minus
	 * one for the newline, minus one for the NULL terminator.
	 * This gives the #bytes available for holding the printed
	 * values from the given data buffer.
	 */
	if (fmt == SD_LOG_HEX) {
		format_string = sd_dump_format_string[0];
	} else /* SD_LOG_CHAR */ {
		format_string = sd_dump_format_string[1];
	}
	/*
	 * Available count is the number of elements from the given
	 * data buffer that we can fit into the available length.
	 * This is based upon the size of the format string used.
	 * Make one entry and find it's size.
	 */
	(void) sprintf(bufp, format_string, data[0]);
	entry_len = strlen(bufp);
	avail_count = (SD_DUMP_MEMORY_BUF_SIZE - strlen(title) - 3) / entry_len;

	j = 0;
	while (j < len) {
		bufp = local_buf;
		bzero(bufp, SD_DUMP_MEMORY_BUF_SIZE);
		start_offset = j;

		end_offset = start_offset + avail_count;

		(void) sprintf(bufp, "%s:", title);
		bufp += strlen(bufp);
		for (i = start_offset; ((i < end_offset) && (j < len));
		    i++, j++) {
			(void) sprintf(bufp, format_string, data[i]);
			bufp += entry_len;
		}
		(void) sprintf(bufp, "\n");

		scsi_log(SD_DEVINFO(un), sd_label, CE_NOTE, "%s", local_buf);
	}
	kmem_free(local_buf, SD_DUMP_MEMORY_BUF_SIZE);
}

/*
 *    Function: sd_print_sense_msg
 *
 * Description: Log a message based upon the given sense data.
 *
 *   Arguments: un - ptr to associated softstate
 *		bp - ptr to buf(9S) for the command
 *		arg - ptr to associate sd_sense_info struct
 *		code - SD_IMMEDIATE_RETRY_ISSUED, SD_DELAYED_RETRY_ISSUED,
 *			or SD_NO_RETRY_ISSUED
 *
 *     Context: May be called from interrupt context
 */

static void
sd_print_sense_msg(struct sd_lun *un, struct buf *bp, void *arg, int code)
{
	struct sd_xbuf	*xp;
	struct scsi_pkt	*pktp;
	uint8_t *sensep;
	daddr_t request_blkno;
	diskaddr_t err_blkno;
	int severity;
	int pfa_flag;
	extern struct scsi_key_strings scsi_cmds[];

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	pktp = SD_GET_PKTP(bp);
	ASSERT(pktp != NULL);
	ASSERT(arg != NULL);

	severity = ((struct sd_sense_info *)(arg))->ssi_severity;
	pfa_flag = ((struct sd_sense_info *)(arg))->ssi_pfa_flag;

	if ((code == SD_DELAYED_RETRY_ISSUED) ||
	    (code == SD_IMMEDIATE_RETRY_ISSUED)) {
		severity = SCSI_ERR_RETRYABLE;
	}

	/* Use absolute block number for the request block number */
	request_blkno = xp->xb_blkno;

	/*
	 * Now try to get the error block number from the sense data
	 */
	sensep = xp->xb_sense_data;

	if (scsi_sense_info_uint64(sensep, SENSE_LENGTH,
	    (uint64_t *)&err_blkno)) {
		/*
		 * We retrieved the error block number from the information
		 * portion of the sense data.
		 *
		 * For USCSI commands we are better off using the error
		 * block no. as the requested block no. (This is the best
		 * we can estimate.)
		 */
		if ((SD_IS_BUFIO(xp) == FALSE) &&
		    ((pktp->pkt_flags & FLAG_SILENT) == 0)) {
			request_blkno = err_blkno;
		}
	} else {
		/*
		 * Without the es_valid bit set (for fixed format) or an
		 * information descriptor (for descriptor format) we cannot
		 * be certain of the error blkno, so just use the
		 * request_blkno.
		 */
		err_blkno = (diskaddr_t)request_blkno;
	}

	/*
	 * The following will log the buffer contents for the release driver
	 * if the SD_LOGMASK_DIAG bit of sd_level_mask is set, or the error
	 * level is set to verbose.
	 */
	sd_dump_memory(un, SD_LOG_IO, "Failed CDB",
	    (uchar_t *)pktp->pkt_cdbp, CDB_SIZE, SD_LOG_HEX);
	sd_dump_memory(un, SD_LOG_IO, "Sense Data",
	    (uchar_t *)sensep, SENSE_LENGTH, SD_LOG_HEX);

	if (pfa_flag == FALSE) {
		/* This is normally only set for USCSI */
		if ((pktp->pkt_flags & FLAG_SILENT) != 0) {
			return;
		}

		if ((SD_IS_BUFIO(xp) == TRUE) &&
		    (((sd_level_mask & SD_LOGMASK_DIAG) == 0) &&
		    (severity < sd_error_level))) {
			return;
		}
	}
	/*
	 * Check for Sonoma Failover and keep a count of how many failed I/O's
	 */
	if ((SD_IS_LSI(un)) &&
	    (scsi_sense_key(sensep) == KEY_ILLEGAL_REQUEST) &&
	    (scsi_sense_asc(sensep) == 0x94) &&
	    (scsi_sense_ascq(sensep) == 0x01)) {
		un->un_sonoma_failure_count++;
		if (un->un_sonoma_failure_count > 1) {
			return;
		}
	}

	if (SD_FM_LOG(un) == SD_FM_LOG_NSUP ||
	    ((scsi_sense_key(sensep) == KEY_RECOVERABLE_ERROR) &&
	    (pktp->pkt_resid == 0))) {
		scsi_vu_errmsg(SD_SCSI_DEVP(un), pktp, sd_label, severity,
		    request_blkno, err_blkno, scsi_cmds,
		    (struct scsi_extended_sense *)sensep,
		    un->un_additional_codes, NULL);
	}
}

/*
 *    Function: sd_sense_key_no_sense
 *
 * Description: Recovery action when sense data was not received.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_no_sense(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	si.ssi_severity = SCSI_ERR_FATAL;
	si.ssi_pfa_flag = FALSE;

	SD_UPDATE_ERRSTATS(un, sd_softerrs);

	sd_retry_command(un, bp, SD_RETRIES_STANDARD, sd_print_sense_msg,
	    &si, EIO, (clock_t)0, NULL);
}


/*
 *    Function: sd_sense_key_recoverable_error
 *
 * Description: Recovery actions for a SCSI "Recovered Error" sense key.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_recoverable_error(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;
	uint8_t asc = scsi_sense_asc(sense_datap);
	uint8_t ascq = scsi_sense_ascq(sense_datap);

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	/*
	 * 0x00, 0x1D: ATA PASSTHROUGH INFORMATION AVAILABLE
	 */
	if (asc == 0x00 && ascq == 0x1D) {
		sd_return_command(un, bp);
		return;
	}

	/*
	 * 0x5D: FAILURE PREDICTION THRESHOLD EXCEEDED
	 */
	if ((asc == 0x5D) && (sd_report_pfa != 0)) {
		SD_UPDATE_ERRSTATS(un, sd_rq_pfa_err);
		si.ssi_severity = SCSI_ERR_INFO;
		si.ssi_pfa_flag = TRUE;
	} else {
		SD_UPDATE_ERRSTATS(un, sd_softerrs);
		SD_UPDATE_ERRSTATS(un, sd_rq_recov_err);
		si.ssi_severity = SCSI_ERR_RECOVERED;
		si.ssi_pfa_flag = FALSE;
	}

	if (pktp->pkt_resid == 0) {
		sd_print_sense_msg(un, bp, &si, SD_NO_RETRY_ISSUED);
		sd_return_command(un, bp);
		return;
	}

	sd_retry_command(un, bp, SD_RETRIES_STANDARD, sd_print_sense_msg,
	    &si, EIO, (clock_t)0, NULL);
}




/*
 *    Function: sd_sense_key_not_ready
 *
 * Description: Recovery actions for a SCSI "Not Ready" sense key.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_not_ready(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;
	uint8_t asc = scsi_sense_asc(sense_datap);
	uint8_t ascq = scsi_sense_ascq(sense_datap);

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	si.ssi_severity = SCSI_ERR_FATAL;
	si.ssi_pfa_flag = FALSE;

	/*
	 * Update error stats after first NOT READY error. Disks may have
	 * been powered down and may need to be restarted.  For CDROMs,
	 * report NOT READY errors only if media is present.
	 */
	if ((ISCD(un) && (asc == 0x3A)) ||
	    (xp->xb_nr_retry_count > 0)) {
		SD_UPDATE_ERRSTATS(un, sd_harderrs);
		SD_UPDATE_ERRSTATS(un, sd_rq_ntrdy_err);
	}

	/*
	 * Just fail if the "not ready" retry limit has been reached.
	 */
	if (xp->xb_nr_retry_count >= un->un_notready_retry_count) {
		/* Special check for error message printing for removables. */
		if (un->un_f_has_removable_media && (asc == 0x04) &&
		    (ascq >= 0x04)) {
			si.ssi_severity = SCSI_ERR_ALL;
		}
		goto fail_command;
	}

	/*
	 * Check the ASC and ASCQ in the sense data as needed, to determine
	 * what to do.
	 */
	switch (asc) {
	case 0x04:	/* LOGICAL UNIT NOT READY */
		/*
		 * disk drives that don't spin up result in a very long delay
		 * in format without warning messages. We will log a message
		 * if the error level is set to verbose.
		 */
		if (sd_error_level < SCSI_ERR_RETRYABLE) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "logical unit not ready, resetting disk\n");
		}

		/*
		 * There are different requirements for CDROMs and disks for
		 * the number of retries.  If a CD-ROM is giving this, it is
		 * probably reading TOC and is in the process of getting
		 * ready, so we should keep on trying for a long time to make
		 * sure that all types of media are taken in account (for
		 * some media the drive takes a long time to read TOC).  For
		 * disks we do not want to retry this too many times as this
		 * can cause a long hang in format when the drive refuses to
		 * spin up (a very common failure).
		 */
		switch (ascq) {
		case 0x00:  /* LUN NOT READY, CAUSE NOT REPORTABLE */
			/*
			 * Disk drives frequently refuse to spin up which
			 * results in a very long hang in format without
			 * warning messages.
			 *
			 * Note: This code preserves the legacy behavior of
			 * comparing xb_nr_retry_count against zero for fibre
			 * channel targets instead of comparing against the
			 * un_reset_retry_count value.  The reason for this
			 * discrepancy has been so utterly lost beneath the
			 * Sands of Time that even Indiana Jones could not
			 * find it.
			 */
			if (un->un_f_is_fibre == TRUE) {
				if (((sd_level_mask & SD_LOGMASK_DIAG) ||
				    (xp->xb_nr_retry_count > 0)) &&
				    (un->un_startstop_timeid == NULL)) {
					scsi_log(SD_DEVINFO(un), sd_label,
					    CE_WARN, "logical unit not ready, "
					    "resetting disk\n");
					sd_reset_target(un, pktp);
				}
			} else {
				if (((sd_level_mask & SD_LOGMASK_DIAG) ||
				    (xp->xb_nr_retry_count >
				    un->un_reset_retry_count)) &&
				    (un->un_startstop_timeid == NULL)) {
					scsi_log(SD_DEVINFO(un), sd_label,
					    CE_WARN, "logical unit not ready, "
					    "resetting disk\n");
					sd_reset_target(un, pktp);
				}
			}
			break;

		case 0x01:  /* LUN IS IN PROCESS OF BECOMING READY */
			/*
			 * If the target is in the process of becoming
			 * ready, just proceed with the retry. This can
			 * happen with CD-ROMs that take a long time to
			 * read TOC after a power cycle or reset.
			 */
			goto do_retry;

		case 0x02:  /* LUN NOT READY, INITITIALIZING CMD REQUIRED */
			break;

		case 0x03:  /* LUN NOT READY, MANUAL INTERVENTION REQUIRED */
			/*
			 * Retries cannot help here so just fail right away.
			 */
			goto fail_command;

		case 0x88:
			/*
			 * Vendor-unique code for T3/T4: it indicates a
			 * path problem in a mutipathed config, but as far as
			 * the target driver is concerned it equates to a fatal
			 * error, so we should just fail the command right away
			 * (without printing anything to the console). If this
			 * is not a T3/T4, fall thru to the default recovery
			 * action.
			 * T3/T4 is FC only, don't need to check is_fibre
			 */
			if (SD_IS_T3(un) || SD_IS_T4(un)) {
				sd_return_failed_command(un, bp, EIO);
				return;
			}
			/* FALLTHRU */

		case 0x04:  /* LUN NOT READY, FORMAT IN PROGRESS */
		case 0x05:  /* LUN NOT READY, REBUILD IN PROGRESS */
		case 0x06:  /* LUN NOT READY, RECALCULATION IN PROGRESS */
		case 0x07:  /* LUN NOT READY, OPERATION IN PROGRESS */
		case 0x08:  /* LUN NOT READY, LONG WRITE IN PROGRESS */
		default:    /* Possible future codes in SCSI spec? */
			/*
			 * For removable-media devices, do not retry if
			 * ASCQ > 2 as these result mostly from USCSI commands
			 * on MMC devices issued to check status of an
			 * operation initiated in immediate mode.  Also for
			 * ASCQ >= 4 do not print console messages as these
			 * mainly represent a user-initiated operation
			 * instead of a system failure.
			 */
			if (un->un_f_has_removable_media) {
				si.ssi_severity = SCSI_ERR_ALL;
				goto fail_command;
			}
			break;
		}

		/*
		 * As part of our recovery attempt for the NOT READY
		 * condition, we issue a START STOP UNIT command. However
		 * we want to wait for a short delay before attempting this
		 * as there may still be more commands coming back from the
		 * target with the check condition. To do this we use
		 * timeout(9F) to call sd_start_stop_unit_callback() after
		 * the delay interval expires. (sd_start_stop_unit_callback()
		 * dispatches sd_start_stop_unit_task(), which will issue
		 * the actual START STOP UNIT command. The delay interval
		 * is one-half of the delay that we will use to retry the
		 * command that generated the NOT READY condition.
		 *
		 * Note that we could just dispatch sd_start_stop_unit_task()
		 * from here and allow it to sleep for the delay interval,
		 * but then we would be tying up the taskq thread
		 * uncesessarily for the duration of the delay.
		 *
		 * Do not issue the START STOP UNIT if the current command
		 * is already a START STOP UNIT.
		 */
		if (pktp->pkt_cdbp[0] == SCMD_START_STOP) {
			break;
		}

		/*
		 * Do not schedule the timeout if one is already pending.
		 */
		if (un->un_startstop_timeid != NULL) {
			SD_INFO(SD_LOG_ERROR, un,
			    "sd_sense_key_not_ready: restart already issued to"
			    " %s%d\n", ddi_driver_name(SD_DEVINFO(un)),
			    ddi_get_instance(SD_DEVINFO(un)));
			break;
		}

		/*
		 * Schedule the START STOP UNIT command, then queue the command
		 * for a retry.
		 *
		 * Note: A timeout is not scheduled for this retry because we
		 * want the retry to be serial with the START_STOP_UNIT. The
		 * retry will be started when the START_STOP_UNIT is completed
		 * in sd_start_stop_unit_task.
		 */
		un->un_startstop_timeid = timeout(sd_start_stop_unit_callback,
		    un, un->un_busy_timeout / 2);
		xp->xb_nr_retry_count++;
		sd_set_retry_bp(un, bp, 0, kstat_waitq_enter);
		return;

	case 0x05:	/* LOGICAL UNIT DOES NOT RESPOND TO SELECTION */
		if (sd_error_level < SCSI_ERR_RETRYABLE) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "unit does not respond to selection\n");
		}
		break;

	case 0x3A:	/* MEDIUM NOT PRESENT */
		if (sd_error_level >= SCSI_ERR_FATAL) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "Caddy not inserted in drive\n");
		}

		sr_ejected(un);
		un->un_mediastate = DKIO_EJECTED;
		/* The state has changed, inform the media watch routines */
		cv_broadcast(&un->un_state_cv);
		/* Just fail if no media is present in the drive. */
		goto fail_command;

	default:
		if (sd_error_level < SCSI_ERR_RETRYABLE) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_NOTE,
			    "Unit not Ready. Additional sense code 0x%x\n",
			    asc);
		}
		break;
	}

do_retry:

	/*
	 * Retry the command, as some targets may report NOT READY for
	 * several seconds after being reset.
	 */
	xp->xb_nr_retry_count++;
	si.ssi_severity = SCSI_ERR_RETRYABLE;
	sd_retry_command(un, bp, SD_RETRIES_NOCHECK, sd_print_sense_msg,
	    &si, EIO, un->un_busy_timeout, NULL);

	return;

fail_command:
	sd_print_sense_msg(un, bp, &si, SD_NO_RETRY_ISSUED);
	sd_return_failed_command(un, bp, EIO);
}



/*
 *    Function: sd_sense_key_medium_or_hardware_error
 *
 * Description: Recovery actions for a SCSI "Medium Error" or "Hardware Error"
 *		sense key.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_medium_or_hardware_error(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;
	uint8_t sense_key = scsi_sense_key(sense_datap);
	uint8_t asc = scsi_sense_asc(sense_datap);

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	si.ssi_severity = SCSI_ERR_FATAL;
	si.ssi_pfa_flag = FALSE;

	if (sense_key == KEY_MEDIUM_ERROR) {
		SD_UPDATE_ERRSTATS(un, sd_rq_media_err);
	}

	SD_UPDATE_ERRSTATS(un, sd_harderrs);

	if ((un->un_reset_retry_count != 0) &&
	    (xp->xb_retry_count == un->un_reset_retry_count)) {
		mutex_exit(SD_MUTEX(un));
		/* Do NOT do a RESET_ALL here: too intrusive. (4112858) */
		if (un->un_f_allow_bus_device_reset == TRUE) {

			boolean_t try_resetting_target = B_TRUE;

			/*
			 * We need to be able to handle specific ASC when we are
			 * handling a KEY_HARDWARE_ERROR. In particular
			 * taking the default action of resetting the target may
			 * not be the appropriate way to attempt recovery.
			 * Resetting a target because of a single LUN failure
			 * victimizes all LUNs on that target.
			 *
			 * This is true for the LSI arrays, if an LSI
			 * array controller returns an ASC of 0x84 (LUN Dead) we
			 * should trust it.
			 */

			if (sense_key == KEY_HARDWARE_ERROR) {
				switch (asc) {
				case 0x84:
					if (SD_IS_LSI(un)) {
						try_resetting_target = B_FALSE;
					}
					break;
				default:
					break;
				}
			}

			if (try_resetting_target == B_TRUE) {
				int reset_retval = 0;
				if (un->un_f_lun_reset_enabled == TRUE) {
					SD_TRACE(SD_LOG_IO_CORE, un,
					    "sd_sense_key_medium_or_hardware_"
					    "error: issuing RESET_LUN\n");
					reset_retval =
					    scsi_reset(SD_ADDRESS(un),
					    RESET_LUN);
				}
				if (reset_retval == 0) {
					SD_TRACE(SD_LOG_IO_CORE, un,
					    "sd_sense_key_medium_or_hardware_"
					    "error: issuing RESET_TARGET\n");
					(void) scsi_reset(SD_ADDRESS(un),
					    RESET_TARGET);
				}
			}
		}
		mutex_enter(SD_MUTEX(un));
	}

	/*
	 * This really ought to be a fatal error, but we will retry anyway
	 * as some drives report this as a spurious error.
	 */
	sd_retry_command(un, bp, SD_RETRIES_STANDARD, sd_print_sense_msg,
	    &si, EIO, (clock_t)0, NULL);
}



/*
 *    Function: sd_sense_key_illegal_request
 *
 * Description: Recovery actions for a SCSI "Illegal Request" sense key.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_illegal_request(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	SD_UPDATE_ERRSTATS(un, sd_rq_illrq_err);

	si.ssi_severity = SCSI_ERR_INFO;
	si.ssi_pfa_flag = FALSE;

	/* Pointless to retry if the target thinks it's an illegal request */
	sd_print_sense_msg(un, bp, &si, SD_NO_RETRY_ISSUED);
	sd_return_failed_command(un, bp, EIO);
}




/*
 *    Function: sd_sense_key_unit_attention
 *
 * Description: Recovery actions for a SCSI "Unit Attention" sense key.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_unit_attention(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	/*
	 * For UNIT ATTENTION we allow retries for one minute. Devices
	 * like Sonoma can return UNIT ATTENTION close to a minute
	 * under certain conditions.
	 */
	int	retry_check_flag = SD_RETRIES_UA;
	boolean_t	kstat_updated = B_FALSE;
	struct	sd_sense_info		si;
	uint8_t asc = scsi_sense_asc(sense_datap);
	uint8_t	ascq = scsi_sense_ascq(sense_datap);

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	si.ssi_severity = SCSI_ERR_INFO;
	si.ssi_pfa_flag = FALSE;


	switch (asc) {
	case 0x5D:  /* FAILURE PREDICTION THRESHOLD EXCEEDED */
		if (sd_report_pfa != 0) {
			SD_UPDATE_ERRSTATS(un, sd_rq_pfa_err);
			si.ssi_pfa_flag = TRUE;
			retry_check_flag = SD_RETRIES_STANDARD;
			goto do_retry;
		}

		break;

	case 0x29:  /* POWER ON, RESET, OR BUS DEVICE RESET OCCURRED */
		if ((un->un_resvd_status & SD_RESERVE) == SD_RESERVE) {
			un->un_resvd_status |=
			    (SD_LOST_RESERVE | SD_WANT_RESERVE);
		}
#ifdef _LP64
		if (un->un_blockcount + 1 > SD_GROUP1_MAX_ADDRESS) {
			if (taskq_dispatch(sd_tq, sd_reenable_dsense_task,
			    un, KM_NOSLEEP) == 0) {
				/*
				 * If we can't dispatch the task we'll just
				 * live without descriptor sense.  We can
				 * try again on the next "unit attention"
				 */
				SD_ERROR(SD_LOG_ERROR, un,
				    "sd_sense_key_unit_attention: "
				    "Could not dispatch "
				    "sd_reenable_dsense_task\n");
			}
		}
#endif /* _LP64 */
		/* FALLTHRU */

	case 0x28: /* NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED */
		if (!un->un_f_has_removable_media) {
			break;
		}

		/*
		 * When we get a unit attention from a removable-media device,
		 * it may be in a state that will take a long time to recover
		 * (e.g., from a reset).  Since we are executing in interrupt
		 * context here, we cannot wait around for the device to come
		 * back. So hand this command off to sd_media_change_task()
		 * for deferred processing under taskq thread context. (Note
		 * that the command still may be failed if a problem is
		 * encountered at a later time.)
		 */
		if (taskq_dispatch(sd_tq, sd_media_change_task, pktp,
		    KM_NOSLEEP) == 0) {
			/*
			 * Cannot dispatch the request so fail the command.
			 */
			SD_UPDATE_ERRSTATS(un, sd_harderrs);
			SD_UPDATE_ERRSTATS(un, sd_rq_nodev_err);
			si.ssi_severity = SCSI_ERR_FATAL;
			sd_print_sense_msg(un, bp, &si, SD_NO_RETRY_ISSUED);
			sd_return_failed_command(un, bp, EIO);
		}

		/*
		 * If failed to dispatch sd_media_change_task(), we already
		 * updated kstat. If succeed to dispatch sd_media_change_task(),
		 * we should update kstat later if it encounters an error. So,
		 * we update kstat_updated flag here.
		 */
		kstat_updated = B_TRUE;

		/*
		 * Either the command has been successfully dispatched to a
		 * task Q for retrying, or the dispatch failed. In either case
		 * do NOT retry again by calling sd_retry_command. This sets up
		 * two retries of the same command and when one completes and
		 * frees the resources the other will access freed memory,
		 * a bad thing.
		 */
		return;

	default:
		break;
	}

	/*
	 * ASC  ASCQ
	 *  2A   09	Capacity data has changed
	 *  2A   01	Mode parameters changed
	 *  3F   0E	Reported luns data has changed
	 * Arrays that support logical unit expansion should report
	 * capacity changes(2Ah/09). Mode parameters changed and
	 * reported luns data has changed are the approximation.
	 */
	if (((asc == 0x2a) && (ascq == 0x09)) ||
	    ((asc == 0x2a) && (ascq == 0x01)) ||
	    ((asc == 0x3f) && (ascq == 0x0e))) {
		if (taskq_dispatch(sd_tq, sd_target_change_task, un,
		    KM_NOSLEEP) == 0) {
			SD_ERROR(SD_LOG_ERROR, un,
			    "sd_sense_key_unit_attention: "
			    "Could not dispatch sd_target_change_task\n");
		}
	}

	/*
	 * Update kstat if we haven't done that.
	 */
	if (!kstat_updated) {
		SD_UPDATE_ERRSTATS(un, sd_harderrs);
		SD_UPDATE_ERRSTATS(un, sd_rq_nodev_err);
	}

do_retry:
	sd_retry_command(un, bp, retry_check_flag, sd_print_sense_msg, &si,
	    EIO, SD_UA_RETRY_DELAY, NULL);
}



/*
 *    Function: sd_sense_key_fail_command
 *
 * Description: Use to fail a command when we don't like the sense key that
 *		was returned.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_fail_command(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	si.ssi_severity = SCSI_ERR_FATAL;
	si.ssi_pfa_flag = FALSE;

	sd_print_sense_msg(un, bp, &si, SD_NO_RETRY_ISSUED);
	sd_return_failed_command(un, bp, EIO);
}



/*
 *    Function: sd_sense_key_blank_check
 *
 * Description: Recovery actions for a SCSI "Blank Check" sense key.
 *		Has no monetary connotation.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_blank_check(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	/*
	 * Blank check is not fatal for removable devices, therefore
	 * it does not require a console message.
	 */
	si.ssi_severity = (un->un_f_has_removable_media) ? SCSI_ERR_ALL :
	    SCSI_ERR_FATAL;
	si.ssi_pfa_flag = FALSE;

	sd_print_sense_msg(un, bp, &si, SD_NO_RETRY_ISSUED);
	sd_return_failed_command(un, bp, EIO);
}




/*
 *    Function: sd_sense_key_aborted_command
 *
 * Description: Recovery actions for a SCSI "Aborted Command" sense key.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_aborted_command(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	si.ssi_severity = SCSI_ERR_FATAL;
	si.ssi_pfa_flag = FALSE;

	SD_UPDATE_ERRSTATS(un, sd_harderrs);

	/*
	 * This really ought to be a fatal error, but we will retry anyway
	 * as some drives report this as a spurious error.
	 */
	sd_retry_command(un, bp, SD_RETRIES_STANDARD, sd_print_sense_msg,
	    &si, EIO, drv_usectohz(100000), NULL);
}



/*
 *    Function: sd_sense_key_default
 *
 * Description: Default recovery action for several SCSI sense keys (basically
 *		attempts a retry).
 *
 *     Context: May be called from interrupt context
 */

static void
sd_sense_key_default(struct sd_lun *un,
	uint8_t *sense_datap,
	struct buf *bp, struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	struct sd_sense_info	si;
	uint8_t sense_key = scsi_sense_key(sense_datap);

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	SD_UPDATE_ERRSTATS(un, sd_harderrs);

	/*
	 * Undecoded sense key.	Attempt retries and hope that will fix
	 * the problem.  Otherwise, we're dead.
	 */
	if ((pktp->pkt_flags & FLAG_SILENT) == 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "Unhandled Sense Key '%s'\n", sense_keys[sense_key]);
	}

	si.ssi_severity = SCSI_ERR_FATAL;
	si.ssi_pfa_flag = FALSE;

	sd_retry_command(un, bp, SD_RETRIES_STANDARD, sd_print_sense_msg,
	    &si, EIO, (clock_t)0, NULL);
}



/*
 *    Function: sd_print_retry_msg
 *
 * Description: Print a message indicating the retry action being taken.
 *
 *   Arguments: un - ptr to associated softstate
 *		bp - ptr to buf(9S) for the command
 *		arg - not used.
 *		flag - SD_IMMEDIATE_RETRY_ISSUED, SD_DELAYED_RETRY_ISSUED,
 *			or SD_NO_RETRY_ISSUED
 *
 *     Context: May be called from interrupt context
 */
/* ARGSUSED */
static void
sd_print_retry_msg(struct sd_lun *un, struct buf *bp, void *arg, int flag)
{
	struct sd_xbuf	*xp;
	struct scsi_pkt *pktp;
	char *reasonp;
	char *msgp;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	pktp = SD_GET_PKTP(bp);
	ASSERT(pktp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);

	ASSERT(!mutex_owned(&un->un_pm_mutex));
	mutex_enter(&un->un_pm_mutex);
	if ((un->un_state == SD_STATE_SUSPENDED) ||
	    (SD_DEVICE_IS_IN_LOW_POWER(un)) ||
	    (pktp->pkt_flags & FLAG_SILENT)) {
		mutex_exit(&un->un_pm_mutex);
		goto update_pkt_reason;
	}
	mutex_exit(&un->un_pm_mutex);

	/*
	 * Suppress messages if they are all the same pkt_reason; with
	 * TQ, many (up to 256) are returned with the same pkt_reason.
	 * If we are in panic, then suppress the retry messages.
	 */
	switch (flag) {
	case SD_NO_RETRY_ISSUED:
		msgp = "giving up";
		break;
	case SD_IMMEDIATE_RETRY_ISSUED:
	case SD_DELAYED_RETRY_ISSUED:
		if (ddi_in_panic() || (un->un_state == SD_STATE_OFFLINE) ||
		    ((pktp->pkt_reason == un->un_last_pkt_reason) &&
		    (sd_error_level != SCSI_ERR_ALL))) {
			return;
		}
		msgp = "retrying command";
		break;
	default:
		goto update_pkt_reason;
	}

	reasonp = (((pktp->pkt_statistics & STAT_PERR) != 0) ? "parity error" :
	    scsi_rname(pktp->pkt_reason));

	if (SD_FM_LOG(un) == SD_FM_LOG_NSUP) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "SCSI transport failed: reason '%s': %s\n", reasonp, msgp);
	}

update_pkt_reason:
	/*
	 * Update un->un_last_pkt_reason with the value in pktp->pkt_reason.
	 * This is to prevent multiple console messages for the same failure
	 * condition.  Note that un->un_last_pkt_reason is NOT restored if &
	 * when the command is retried successfully because there still may be
	 * more commands coming back with the same value of pktp->pkt_reason.
	 */
	if ((pktp->pkt_reason != CMD_CMPLT) || (xp->xb_retry_count == 0)) {
		un->un_last_pkt_reason = pktp->pkt_reason;
	}
}


/*
 *    Function: sd_print_cmd_incomplete_msg
 *
 * Description: Message logging fn. for a SCSA "CMD_INCOMPLETE" pkt_reason.
 *
 *   Arguments: un - ptr to associated softstate
 *		bp - ptr to buf(9S) for the command
 *		arg - passed to sd_print_retry_msg()
 *		code - SD_IMMEDIATE_RETRY_ISSUED, SD_DELAYED_RETRY_ISSUED,
 *			or SD_NO_RETRY_ISSUED
 *
 *     Context: May be called from interrupt context
 */

static void
sd_print_cmd_incomplete_msg(struct sd_lun *un, struct buf *bp, void *arg,
	int code)
{
	dev_info_t	*dip;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);

	switch (code) {
	case SD_NO_RETRY_ISSUED:
		/* Command was failed. Someone turned off this target? */
		if (un->un_state != SD_STATE_OFFLINE) {
			/*
			 * Suppress message if we are detaching and
			 * device has been disconnected
			 * Note that DEVI_IS_DEVICE_REMOVED is a consolidation
			 * private interface and not part of the DDI
			 */
			dip = un->un_sd->sd_dev;
			if (!(DEVI_IS_DETACHING(dip) &&
			    DEVI_IS_DEVICE_REMOVED(dip))) {
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				"disk not responding to selection\n");
			}
			New_state(un, SD_STATE_OFFLINE);
		}
		break;

	case SD_DELAYED_RETRY_ISSUED:
	case SD_IMMEDIATE_RETRY_ISSUED:
	default:
		/* Command was successfully queued for retry */
		sd_print_retry_msg(un, bp, arg, code);
		break;
	}
}


/*
 *    Function: sd_pkt_reason_cmd_incomplete
 *
 * Description: Recovery actions for a SCSA "CMD_INCOMPLETE" pkt_reason.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_reason_cmd_incomplete(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	int flag = SD_RETRIES_STANDARD | SD_RETRIES_ISOLATE;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	/* Do not do a reset if selection did not complete */
	/* Note: Should this not just check the bit? */
	if (pktp->pkt_state != STATE_GOT_BUS) {
		SD_UPDATE_ERRSTATS(un, sd_transerrs);
		sd_reset_target(un, pktp);
	}

	/*
	 * If the target was not successfully selected, then set
	 * SD_RETRIES_FAILFAST to indicate that we lost communication
	 * with the target, and further retries and/or commands are
	 * likely to take a long time.
	 */
	if ((pktp->pkt_state & STATE_GOT_TARGET) == 0) {
		flag |= SD_RETRIES_FAILFAST;
	}

	SD_UPDATE_RESERVATION_STATUS(un, pktp);

	sd_retry_command(un, bp, flag,
	    sd_print_cmd_incomplete_msg, NULL, EIO, SD_RESTART_TIMEOUT, NULL);
}



/*
 *    Function: sd_pkt_reason_cmd_tran_err
 *
 * Description: Recovery actions for a SCSA "CMD_TRAN_ERR" pkt_reason.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_reason_cmd_tran_err(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	/*
	 * Do not reset if we got a parity error, or if
	 * selection did not complete.
	 */
	SD_UPDATE_ERRSTATS(un, sd_harderrs);
	/* Note: Should this not just check the bit for pkt_state? */
	if (((pktp->pkt_statistics & STAT_PERR) == 0) &&
	    (pktp->pkt_state != STATE_GOT_BUS)) {
		SD_UPDATE_ERRSTATS(un, sd_transerrs);
		sd_reset_target(un, pktp);
	}

	SD_UPDATE_RESERVATION_STATUS(un, pktp);

	sd_retry_command(un, bp, (SD_RETRIES_STANDARD | SD_RETRIES_ISOLATE),
	    sd_print_retry_msg, NULL, EIO, SD_RESTART_TIMEOUT, NULL);
}



/*
 *    Function: sd_pkt_reason_cmd_reset
 *
 * Description: Recovery actions for a SCSA "CMD_RESET" pkt_reason.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_reason_cmd_reset(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	/* The target may still be running the command, so try to reset. */
	SD_UPDATE_ERRSTATS(un, sd_transerrs);
	sd_reset_target(un, pktp);

	SD_UPDATE_RESERVATION_STATUS(un, pktp);

	/*
	 * If pkt_reason is CMD_RESET chances are that this pkt got
	 * reset because another target on this bus caused it. The target
	 * that caused it should get CMD_TIMEOUT with pkt_statistics
	 * of STAT_TIMEOUT/STAT_DEV_RESET.
	 */

	sd_retry_command(un, bp, (SD_RETRIES_VICTIM | SD_RETRIES_ISOLATE),
	    sd_print_retry_msg, NULL, EIO, SD_RESTART_TIMEOUT, NULL);
}




/*
 *    Function: sd_pkt_reason_cmd_aborted
 *
 * Description: Recovery actions for a SCSA "CMD_ABORTED" pkt_reason.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_reason_cmd_aborted(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	/* The target may still be running the command, so try to reset. */
	SD_UPDATE_ERRSTATS(un, sd_transerrs);
	sd_reset_target(un, pktp);

	SD_UPDATE_RESERVATION_STATUS(un, pktp);

	/*
	 * If pkt_reason is CMD_ABORTED chances are that this pkt got
	 * aborted because another target on this bus caused it. The target
	 * that caused it should get CMD_TIMEOUT with pkt_statistics
	 * of STAT_TIMEOUT/STAT_DEV_RESET.
	 */

	sd_retry_command(un, bp, (SD_RETRIES_VICTIM | SD_RETRIES_ISOLATE),
	    sd_print_retry_msg, NULL, EIO, SD_RESTART_TIMEOUT, NULL);
}



/*
 *    Function: sd_pkt_reason_cmd_timeout
 *
 * Description: Recovery actions for a SCSA "CMD_TIMEOUT" pkt_reason.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_reason_cmd_timeout(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);


	SD_UPDATE_ERRSTATS(un, sd_transerrs);
	sd_reset_target(un, pktp);

	SD_UPDATE_RESERVATION_STATUS(un, pktp);

	/*
	 * A command timeout indicates that we could not establish
	 * communication with the target, so set SD_RETRIES_FAILFAST
	 * as further retries/commands are likely to take a long time.
	 */
	sd_retry_command(un, bp,
	    (SD_RETRIES_STANDARD | SD_RETRIES_ISOLATE | SD_RETRIES_FAILFAST),
	    sd_print_retry_msg, NULL, EIO, SD_RESTART_TIMEOUT, NULL);
}



/*
 *    Function: sd_pkt_reason_cmd_unx_bus_free
 *
 * Description: Recovery actions for a SCSA "CMD_UNX_BUS_FREE" pkt_reason.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_reason_cmd_unx_bus_free(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	void (*funcp)(struct sd_lun *un, struct buf *bp, void *arg, int code);

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	SD_UPDATE_ERRSTATS(un, sd_harderrs);
	SD_UPDATE_RESERVATION_STATUS(un, pktp);

	funcp = ((pktp->pkt_statistics & STAT_PERR) == 0) ?
	    sd_print_retry_msg : NULL;

	sd_retry_command(un, bp, (SD_RETRIES_STANDARD | SD_RETRIES_ISOLATE),
	    funcp, NULL, EIO, SD_RESTART_TIMEOUT, NULL);
}


/*
 *    Function: sd_pkt_reason_cmd_tag_reject
 *
 * Description: Recovery actions for a SCSA "CMD_TAG_REJECT" pkt_reason.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_reason_cmd_tag_reject(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	SD_UPDATE_ERRSTATS(un, sd_harderrs);
	pktp->pkt_flags = 0;
	un->un_tagflags = 0;
	if (un->un_f_opt_queueing == TRUE) {
		un->un_throttle = min(un->un_throttle, 3);
	} else {
		un->un_throttle = 1;
	}
	mutex_exit(SD_MUTEX(un));
	(void) scsi_ifsetcap(SD_ADDRESS(un), "tagged-qing", 0, 1);
	mutex_enter(SD_MUTEX(un));

	SD_UPDATE_RESERVATION_STATUS(un, pktp);

	/* Legacy behavior not to check retry counts here. */
	sd_retry_command(un, bp, (SD_RETRIES_NOCHECK | SD_RETRIES_ISOLATE),
	    sd_print_retry_msg, NULL, EIO, SD_RESTART_TIMEOUT, NULL);
}


/*
 *    Function: sd_pkt_reason_default
 *
 * Description: Default recovery actions for SCSA pkt_reason values that
 *		do not have more explicit recovery actions.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_reason_default(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	SD_UPDATE_ERRSTATS(un, sd_transerrs);
	sd_reset_target(un, pktp);

	SD_UPDATE_RESERVATION_STATUS(un, pktp);

	sd_retry_command(un, bp, (SD_RETRIES_STANDARD | SD_RETRIES_ISOLATE),
	    sd_print_retry_msg, NULL, EIO, SD_RESTART_TIMEOUT, NULL);
}



/*
 *    Function: sd_pkt_status_check_condition
 *
 * Description: Recovery actions for a "STATUS_CHECK" SCSI command status.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_status_check_condition(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	SD_TRACE(SD_LOG_IO, un, "sd_pkt_status_check_condition: "
	    "entry: buf:0x%p xp:0x%p\n", bp, xp);

	/*
	 * If ARQ is NOT enabled, then issue a REQUEST SENSE command (the
	 * command will be retried after the request sense). Otherwise, retry
	 * the command. Note: we are issuing the request sense even though the
	 * retry limit may have been reached for the failed command.
	 */
	if (un->un_f_arq_enabled == FALSE) {
		SD_INFO(SD_LOG_IO_CORE, un, "sd_pkt_status_check_condition: "
		    "no ARQ, sending request sense command\n");
		sd_send_request_sense_command(un, bp, pktp);
	} else {
		SD_INFO(SD_LOG_IO_CORE, un, "sd_pkt_status_check_condition: "
		    "ARQ,retrying request sense command\n");
#if defined(__i386) || defined(__amd64)
		/*
		 * The SD_RETRY_DELAY value need to be adjusted here
		 * when SD_RETRY_DELAY change in sddef.h
		 */
		sd_retry_command(un, bp, SD_RETRIES_STANDARD, NULL, NULL, EIO,
		    un->un_f_is_fibre?drv_usectohz(100000):(clock_t)0,
		    NULL);
#else
		sd_retry_command(un, bp, SD_RETRIES_STANDARD, NULL, NULL,
		    EIO, SD_RETRY_DELAY, NULL);
#endif
	}

	SD_TRACE(SD_LOG_IO_CORE, un, "sd_pkt_status_check_condition: exit\n");
}


/*
 *    Function: sd_pkt_status_busy
 *
 * Description: Recovery actions for a "STATUS_BUSY" SCSI command status.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_status_busy(struct sd_lun *un, struct buf *bp, struct sd_xbuf *xp,
	struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_pkt_status_busy: entry\n");

	/* If retries are exhausted, just fail the command. */
	if (xp->xb_retry_count >= un->un_busy_retry_count) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "device busy too long\n");
		sd_return_failed_command(un, bp, EIO);
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_pkt_status_busy: exit\n");
		return;
	}
	xp->xb_retry_count++;

	/*
	 * Try to reset the target. However, we do not want to perform
	 * more than one reset if the device continues to fail. The reset
	 * will be performed when the retry count reaches the reset
	 * threshold.  This threshold should be set such that at least
	 * one retry is issued before the reset is performed.
	 */
	if (xp->xb_retry_count ==
	    ((un->un_reset_retry_count < 2) ? 2 : un->un_reset_retry_count)) {
		int rval = 0;
		mutex_exit(SD_MUTEX(un));
		if (un->un_f_allow_bus_device_reset == TRUE) {
			/*
			 * First try to reset the LUN; if we cannot then
			 * try to reset the target.
			 */
			if (un->un_f_lun_reset_enabled == TRUE) {
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_pkt_status_busy: RESET_LUN\n");
				rval = scsi_reset(SD_ADDRESS(un), RESET_LUN);
			}
			if (rval == 0) {
				SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
				    "sd_pkt_status_busy: RESET_TARGET\n");
				rval = scsi_reset(SD_ADDRESS(un), RESET_TARGET);
			}
		}
		if (rval == 0) {
			/*
			 * If the RESET_LUN and/or RESET_TARGET failed,
			 * try RESET_ALL
			 */
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_pkt_status_busy: RESET_ALL\n");
			rval = scsi_reset(SD_ADDRESS(un), RESET_ALL);
		}
		mutex_enter(SD_MUTEX(un));
		if (rval == 0) {
			/*
			 * The RESET_LUN, RESET_TARGET, and/or RESET_ALL failed.
			 * At this point we give up & fail the command.
			 */
			sd_return_failed_command(un, bp, EIO);
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_pkt_status_busy: exit (failed cmd)\n");
			return;
		}
	}

	/*
	 * Retry the command. Be sure to specify SD_RETRIES_NOCHECK as
	 * we have already checked the retry counts above.
	 */
	sd_retry_command(un, bp, SD_RETRIES_NOCHECK, NULL, NULL,
	    EIO, un->un_busy_timeout, NULL);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_pkt_status_busy: exit\n");
}


/*
 *    Function: sd_pkt_status_reservation_conflict
 *
 * Description: Recovery actions for a "STATUS_RESERVATION_CONFLICT" SCSI
 *		command status.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_status_reservation_conflict(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	/*
	 * If the command was PERSISTENT_RESERVATION_[IN|OUT] then reservation
	 * conflict could be due to various reasons like incorrect keys, not
	 * registered or not reserved etc. So, we return EACCES to the caller.
	 */
	if (un->un_reservation_type == SD_SCSI3_RESERVATION) {
		int cmd = SD_GET_PKT_OPCODE(pktp);
		if ((cmd == SCMD_PERSISTENT_RESERVE_IN) ||
		    (cmd == SCMD_PERSISTENT_RESERVE_OUT)) {
			sd_return_failed_command(un, bp, EACCES);
			return;
		}
	}

	un->un_resvd_status |= SD_RESERVATION_CONFLICT;

	if ((un->un_resvd_status & SD_FAILFAST) != 0) {
		if (sd_failfast_enable != 0) {
			/* By definition, we must panic here.... */
			sd_panic_for_res_conflict(un);
			/*NOTREACHED*/
		}
		SD_ERROR(SD_LOG_IO, un,
		    "sd_handle_resv_conflict: Disk Reserved\n");
		sd_return_failed_command(un, bp, EACCES);
		return;
	}

	/*
	 * 1147670: retry only if sd_retry_on_reservation_conflict
	 * property is set (default is 1). Retries will not succeed
	 * on a disk reserved by another initiator. HA systems
	 * may reset this via sd.conf to avoid these retries.
	 *
	 * Note: The legacy return code for this failure is EIO, however EACCES
	 * seems more appropriate for a reservation conflict.
	 */
	if (sd_retry_on_reservation_conflict == 0) {
		SD_ERROR(SD_LOG_IO, un,
		    "sd_handle_resv_conflict: Device Reserved\n");
		sd_return_failed_command(un, bp, EIO);
		return;
	}

	/*
	 * Retry the command if we can.
	 *
	 * Note: The legacy return code for this failure is EIO, however EACCES
	 * seems more appropriate for a reservation conflict.
	 */
	sd_retry_command(un, bp, SD_RETRIES_STANDARD, NULL, NULL, EIO,
	    (clock_t)2, NULL);
}



/*
 *    Function: sd_pkt_status_qfull
 *
 * Description: Handle a QUEUE FULL condition from the target.  This can
 *		occur if the HBA does not handle the queue full condition.
 *		(Basically this means third-party HBAs as Sun HBAs will
 *		handle the queue full condition.)  Note that if there are
 *		some commands already in the transport, then the queue full
 *		has occurred because the queue for this nexus is actually
 *		full. If there are no commands in the transport, then the
 *		queue full is resulting from some other initiator or lun
 *		consuming all the resources at the target.
 *
 *     Context: May be called from interrupt context
 */

static void
sd_pkt_status_qfull(struct sd_lun *un, struct buf *bp,
	struct sd_xbuf *xp, struct scsi_pkt *pktp)
{
	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(pktp != NULL);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_pkt_status_qfull: entry\n");

	/*
	 * Just lower the QFULL throttle and retry the command.  Note that
	 * we do not limit the number of retries here.
	 */
	sd_reduce_throttle(un, SD_THROTTLE_QFULL);
	sd_retry_command(un, bp, SD_RETRIES_NOCHECK, NULL, NULL, 0,
	    SD_RESTART_TIMEOUT, NULL);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_pkt_status_qfull: exit\n");
}


/*
 *    Function: sd_reset_target
 *
 * Description: Issue a scsi_reset(9F), with either RESET_LUN,
 *		RESET_TARGET, or RESET_ALL.
 *
 *     Context: May be called under interrupt context.
 */

static void
sd_reset_target(struct sd_lun *un, struct scsi_pkt *pktp)
{
	int rval = 0;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(pktp != NULL);

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_reset_target: entry\n");

	/*
	 * No need to reset if the transport layer has already done so.
	 */
	if ((pktp->pkt_statistics &
	    (STAT_BUS_RESET | STAT_DEV_RESET | STAT_ABORTED)) != 0) {
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_reset_target: no reset\n");
		return;
	}

	mutex_exit(SD_MUTEX(un));

	if (un->un_f_allow_bus_device_reset == TRUE) {
		if (un->un_f_lun_reset_enabled == TRUE) {
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_reset_target: RESET_LUN\n");
			rval = scsi_reset(SD_ADDRESS(un), RESET_LUN);
		}
		if (rval == 0) {
			SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
			    "sd_reset_target: RESET_TARGET\n");
			rval = scsi_reset(SD_ADDRESS(un), RESET_TARGET);
		}
	}

	if (rval == 0) {
		SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
		    "sd_reset_target: RESET_ALL\n");
		(void) scsi_reset(SD_ADDRESS(un), RESET_ALL);
	}

	mutex_enter(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un, "sd_reset_target: exit\n");
}

/*
 *    Function: sd_target_change_task
 *
 * Description: Handle dynamic target change
 *
 *     Context: Executes in a taskq() thread context
 */
static void
sd_target_change_task(void *arg)
{
	struct sd_lun		*un = arg;
	uint64_t		capacity;
	diskaddr_t		label_cap;
	uint_t			lbasize;
	sd_ssc_t		*ssc;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	if ((un->un_f_blockcount_is_valid == FALSE) ||
	    (un->un_f_tgt_blocksize_is_valid == FALSE)) {
		return;
	}

	ssc = sd_ssc_init(un);

	if (sd_send_scsi_READ_CAPACITY(ssc, &capacity,
	    &lbasize, SD_PATH_DIRECT) != 0) {
		SD_ERROR(SD_LOG_ERROR, un,
		    "sd_target_change_task: fail to read capacity\n");
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		goto task_exit;
	}

	mutex_enter(SD_MUTEX(un));
	if (capacity <= un->un_blockcount) {
		mutex_exit(SD_MUTEX(un));
		goto task_exit;
	}

	sd_update_block_info(un, lbasize, capacity);
	mutex_exit(SD_MUTEX(un));

	/*
	 * If lun is EFI labeled and lun capacity is greater than the
	 * capacity contained in the label, log a sys event.
	 */
	if (cmlb_efi_label_capacity(un->un_cmlbhandle, &label_cap,
	    (void*)SD_PATH_DIRECT) == 0) {
		mutex_enter(SD_MUTEX(un));
		if (un->un_f_blockcount_is_valid &&
		    un->un_blockcount > label_cap) {
			mutex_exit(SD_MUTEX(un));
			sd_log_lun_expansion_event(un, KM_SLEEP);
		} else {
			mutex_exit(SD_MUTEX(un));
		}
	}

task_exit:
	sd_ssc_fini(ssc);
}


/*
 *    Function: sd_log_dev_status_event
 *
 * Description: Log EC_dev_status sysevent
 *
 *     Context: Never called from interrupt context
 */
static void
sd_log_dev_status_event(struct sd_lun *un, char *esc, int km_flag)
{
	int err;
	char			*path;
	nvlist_t		*attr_list;

	/* Allocate and build sysevent attribute list */
	err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, km_flag);
	if (err != 0) {
		SD_ERROR(SD_LOG_ERROR, un,
		    "sd_log_dev_status_event: fail to allocate space\n");
		return;
	}

	path = kmem_alloc(MAXPATHLEN, km_flag);
	if (path == NULL) {
		nvlist_free(attr_list);
		SD_ERROR(SD_LOG_ERROR, un,
		    "sd_log_dev_status_event: fail to allocate space\n");
		return;
	}
	/*
	 * Add path attribute to identify the lun.
	 * We are using minor node 'a' as the sysevent attribute.
	 */
	(void) snprintf(path, MAXPATHLEN, "/devices");
	(void) ddi_pathname(SD_DEVINFO(un), path + strlen(path));
	(void) snprintf(path + strlen(path), MAXPATHLEN - strlen(path),
	    ":a");

	err = nvlist_add_string(attr_list, DEV_PHYS_PATH, path);
	if (err != 0) {
		nvlist_free(attr_list);
		kmem_free(path, MAXPATHLEN);
		SD_ERROR(SD_LOG_ERROR, un,
		    "sd_log_dev_status_event: fail to add attribute\n");
		return;
	}

	/* Log dynamic lun expansion sysevent */
	err = ddi_log_sysevent(SD_DEVINFO(un), SUNW_VENDOR, EC_DEV_STATUS,
	    esc, attr_list, NULL, km_flag);
	if (err != DDI_SUCCESS) {
		SD_ERROR(SD_LOG_ERROR, un,
		    "sd_log_dev_status_event: fail to log sysevent\n");
	}

	nvlist_free(attr_list);
	kmem_free(path, MAXPATHLEN);
}


/*
 *    Function: sd_log_lun_expansion_event
 *
 * Description: Log lun expansion sys event
 *
 *     Context: Never called from interrupt context
 */
static void
sd_log_lun_expansion_event(struct sd_lun *un, int km_flag)
{
	sd_log_dev_status_event(un, ESC_DEV_DLE, km_flag);
}


/*
 *    Function: sd_log_eject_request_event
 *
 * Description: Log eject request sysevent
 *
 *     Context: Never called from interrupt context
 */
static void
sd_log_eject_request_event(struct sd_lun *un, int km_flag)
{
	sd_log_dev_status_event(un, ESC_DEV_EJECT_REQUEST, km_flag);
}


/*
 *    Function: sd_media_change_task
 *
 * Description: Recovery action for CDROM to become available.
 *
 *     Context: Executes in a taskq() thread context
 */

static void
sd_media_change_task(void *arg)
{
	struct	scsi_pkt	*pktp = arg;
	struct	sd_lun		*un;
	struct	buf		*bp;
	struct	sd_xbuf		*xp;
	int	err		= 0;
	int	retry_count	= 0;
	int	retry_limit	= SD_UNIT_ATTENTION_RETRY/10;
	struct	sd_sense_info	si;

	ASSERT(pktp != NULL);
	bp = (struct buf *)pktp->pkt_private;
	ASSERT(bp != NULL);
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	un = SD_GET_UN(bp);
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(un->un_f_monitor_media_state);

	si.ssi_severity = SCSI_ERR_INFO;
	si.ssi_pfa_flag = FALSE;

	/*
	 * When a reset is issued on a CDROM, it takes a long time to
	 * recover. First few attempts to read capacity and other things
	 * related to handling unit attention fail (with a ASC 0x4 and
	 * ASCQ 0x1). In that case we want to do enough retries and we want
	 * to limit the retries in other cases of genuine failures like
	 * no media in drive.
	 */
	while (retry_count++ < retry_limit) {
		if ((err = sd_handle_mchange(un)) == 0) {
			break;
		}
		if (err == EAGAIN) {
			retry_limit = SD_UNIT_ATTENTION_RETRY;
		}
		/* Sleep for 0.5 sec. & try again */
		delay(drv_usectohz(500000));
	}

	/*
	 * Dispatch (retry or fail) the original command here,
	 * along with appropriate console messages....
	 *
	 * Must grab the mutex before calling sd_retry_command,
	 * sd_print_sense_msg and sd_return_failed_command.
	 */
	mutex_enter(SD_MUTEX(un));
	if (err != SD_CMD_SUCCESS) {
		SD_UPDATE_ERRSTATS(un, sd_harderrs);
		SD_UPDATE_ERRSTATS(un, sd_rq_nodev_err);
		si.ssi_severity = SCSI_ERR_FATAL;
		sd_print_sense_msg(un, bp, &si, SD_NO_RETRY_ISSUED);
		sd_return_failed_command(un, bp, EIO);
	} else {
		sd_retry_command(un, bp, SD_RETRIES_UA, sd_print_sense_msg,
		    &si, EIO, (clock_t)0, NULL);
	}
	mutex_exit(SD_MUTEX(un));
}



/*
 *    Function: sd_handle_mchange
 *
 * Description: Perform geometry validation & other recovery when CDROM
 *		has been removed from drive.
 *
 * Return Code: 0 for success
 *		errno-type return code of either sd_send_scsi_DOORLOCK() or
 *		sd_send_scsi_READ_CAPACITY()
 *
 *     Context: Executes in a taskq() thread context
 */

static int
sd_handle_mchange(struct sd_lun *un)
{
	uint64_t	capacity;
	uint32_t	lbasize;
	int		rval;
	sd_ssc_t	*ssc;

	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(un->un_f_monitor_media_state);

	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_READ_CAPACITY(ssc, &capacity, &lbasize,
	    SD_PATH_DIRECT_PRIORITY);

	if (rval != 0)
		goto failed;

	mutex_enter(SD_MUTEX(un));
	sd_update_block_info(un, lbasize, capacity);

	if (un->un_errstats != NULL) {
		struct	sd_errstats *stp =
		    (struct sd_errstats *)un->un_errstats->ks_data;
		stp->sd_capacity.value.ui64 = (uint64_t)
		    ((uint64_t)un->un_blockcount *
		    (uint64_t)un->un_tgt_blocksize);
	}

	/*
	 * Check if the media in the device is writable or not
	 */
	if (ISCD(un)) {
		sd_check_for_writable_cd(ssc, SD_PATH_DIRECT_PRIORITY);
	}

	/*
	 * Note: Maybe let the strategy/partitioning chain worry about getting
	 * valid geometry.
	 */
	mutex_exit(SD_MUTEX(un));
	cmlb_invalidate(un->un_cmlbhandle, (void *)SD_PATH_DIRECT_PRIORITY);


	if (cmlb_validate(un->un_cmlbhandle, 0,
	    (void *)SD_PATH_DIRECT_PRIORITY) != 0) {
		sd_ssc_fini(ssc);
		return (EIO);
	} else {
		if (un->un_f_pkstats_enabled) {
			sd_set_pstats(un);
			SD_TRACE(SD_LOG_IO_PARTITION, un,
			    "sd_handle_mchange: un:0x%p pstats created and "
			    "set\n", un);
		}
	}

	/*
	 * Try to lock the door
	 */
	rval = sd_send_scsi_DOORLOCK(ssc, SD_REMOVAL_PREVENT,
	    SD_PATH_DIRECT_PRIORITY);
failed:
	if (rval != 0)
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	sd_ssc_fini(ssc);
	return (rval);
}


/*
 *    Function: sd_send_scsi_DOORLOCK
 *
 * Description: Issue the scsi DOOR LOCK command
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		flag  - SD_REMOVAL_ALLOW
 *			SD_REMOVAL_PREVENT
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq. SD_PATH_DIRECT_PRIORITY is used when this
 *			command is issued as part of an error recovery action.
 *
 * Return Code: 0   - Success
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep.
 */

static int
sd_send_scsi_DOORLOCK(sd_ssc_t *ssc, int flag, int path_flag)
{
	struct scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_DOORLOCK: entry: un:0x%p\n", un);

	/* already determined doorlock is not supported, fake success */
	if (un->un_f_doorlock_supported == FALSE) {
		return (0);
	}

	/*
	 * If we are ejecting and see an SD_REMOVAL_PREVENT
	 * ignore the command so we can complete the eject
	 * operation.
	 */
	if (flag == SD_REMOVAL_PREVENT) {
		mutex_enter(SD_MUTEX(un));
		if (un->un_f_ejecting == TRUE) {
			mutex_exit(SD_MUTEX(un));
			return (EAGAIN);
		}
		mutex_exit(SD_MUTEX(un));
	}

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));

	cdb.scc_cmd = SCMD_DOORLOCK;
	cdb.cdb_opaque[4] = (uchar_t)flag;

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP0;
	ucmd_buf.uscsi_bufaddr	= NULL;
	ucmd_buf.uscsi_buflen	= 0;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (sense_buf);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 15;

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_DOORLOCK: returning sd_ssc_send\n");

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	if (status == 0)
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);

	if ((status == EIO) && (ucmd_buf.uscsi_status == STATUS_CHECK) &&
	    (ucmd_buf.uscsi_rqstatus == STATUS_GOOD) &&
	    (scsi_sense_key((uint8_t *)&sense_buf) == KEY_ILLEGAL_REQUEST)) {
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);

		/* fake success and skip subsequent doorlock commands */
		un->un_f_doorlock_supported = FALSE;
		return (0);
	}

	return (status);
}

/*
 *    Function: sd_send_scsi_READ_CAPACITY
 *
 * Description: This routine uses the scsi READ CAPACITY command to determine
 *		the device capacity in number of blocks and the device native
 *		block size. If this function returns a failure, then the
 *		values in *capp and *lbap are undefined.  If the capacity
 *		returned is 0xffffffff then the lun is too large for a
 *		normal READ CAPACITY command and the results of a
 *		READ CAPACITY 16 will be used instead.
 *
 *   Arguments: ssc   - ssc contains ptr to soft state struct for the target
 *		capp - ptr to unsigned 64-bit variable to receive the
 *			capacity value from the command.
 *		lbap - ptr to unsigned 32-bit varaible to receive the
 *			block size value from the command
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq. SD_PATH_DIRECT_PRIORITY is used when this
 *			command is issued as part of an error recovery action.
 *
 * Return Code: 0   - Success
 *		EIO - IO error
 *		EACCES - Reservation conflict detected
 *		EAGAIN - Device is becoming ready
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep.  Blocks until command completes.
 */

#define	SD_CAPACITY_SIZE	sizeof (struct scsi_capacity)

static int
sd_send_scsi_READ_CAPACITY(sd_ssc_t *ssc, uint64_t *capp, uint32_t *lbap,
	int path_flag)
{
	struct	scsi_extended_sense	sense_buf;
	struct	uscsi_cmd	ucmd_buf;
	union	scsi_cdb	cdb;
	uint32_t		*capacity_buf;
	uint64_t		capacity;
	uint32_t		lbasize;
	uint32_t		pbsize;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);

	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(capp != NULL);
	ASSERT(lbap != NULL);

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_READ_CAPACITY: entry: un:0x%p\n", un);

	/*
	 * First send a READ_CAPACITY command to the target.
	 * (This command is mandatory under SCSI-2.)
	 *
	 * Set up the CDB for the READ_CAPACITY command.  The Partial
	 * Medium Indicator bit is cleared.  The address field must be
	 * zero if the PMI bit is zero.
	 */
	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));

	capacity_buf = kmem_zalloc(SD_CAPACITY_SIZE, KM_SLEEP);

	cdb.scc_cmd = SCMD_READ_CAPACITY;

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP1;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)capacity_buf;
	ucmd_buf.uscsi_buflen	= SD_CAPACITY_SIZE;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (sense_buf);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:
		/* Return failure if we did not get valid capacity data. */
		if (ucmd_buf.uscsi_resid != 0) {
			sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, -1,
			    "sd_send_scsi_READ_CAPACITY received invalid "
			    "capacity data");
			kmem_free(capacity_buf, SD_CAPACITY_SIZE);
			return (EIO);
		}
		/*
		 * Read capacity and block size from the READ CAPACITY 10 data.
		 * This data may be adjusted later due to device specific
		 * issues.
		 *
		 * According to the SCSI spec, the READ CAPACITY 10
		 * command returns the following:
		 *
		 *  bytes 0-3: Maximum logical block address available.
		 *		(MSB in byte:0 & LSB in byte:3)
		 *
		 *  bytes 4-7: Block length in bytes
		 *		(MSB in byte:4 & LSB in byte:7)
		 *
		 */
		capacity = BE_32(capacity_buf[0]);
		lbasize = BE_32(capacity_buf[1]);

		/*
		 * Done with capacity_buf
		 */
		kmem_free(capacity_buf, SD_CAPACITY_SIZE);

		/*
		 * if the reported capacity is set to all 0xf's, then
		 * this disk is too large and requires SBC-2 commands.
		 * Reissue the request using READ CAPACITY 16.
		 */
		if (capacity == 0xffffffff) {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
			status = sd_send_scsi_READ_CAPACITY_16(ssc, &capacity,
			    &lbasize, &pbsize, path_flag);
			if (status != 0) {
				return (status);
			} else {
				goto rc16_done;
			}
		}
		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		case STATUS_CHECK:
			/*
			 * Check condition; look for ASC/ASCQ of 0x04/0x01
			 * (LOGICAL UNIT IS IN PROCESS OF BECOMING READY)
			 */
			if ((ucmd_buf.uscsi_rqstatus == STATUS_GOOD) &&
			    (scsi_sense_asc((uint8_t *)&sense_buf) == 0x04) &&
			    (scsi_sense_ascq((uint8_t *)&sense_buf) == 0x01)) {
				kmem_free(capacity_buf, SD_CAPACITY_SIZE);
				return (EAGAIN);
			}
			break;
		default:
			break;
		}
		/* FALLTHRU */
	default:
		kmem_free(capacity_buf, SD_CAPACITY_SIZE);
		return (status);
	}

	/*
	 * Some ATAPI CD-ROM drives report inaccurate LBA size values
	 * (2352 and 0 are common) so for these devices always force the value
	 * to 2048 as required by the ATAPI specs.
	 */
	if ((un->un_f_cfg_is_atapi == TRUE) && (ISCD(un))) {
		lbasize = 2048;
	}

	/*
	 * Get the maximum LBA value from the READ CAPACITY data.
	 * Here we assume that the Partial Medium Indicator (PMI) bit
	 * was cleared when issuing the command. This means that the LBA
	 * returned from the device is the LBA of the last logical block
	 * on the logical unit.  The actual logical block count will be
	 * this value plus one.
	 */
	capacity += 1;

	/*
	 * Currently, for removable media, the capacity is saved in terms
	 * of un->un_sys_blocksize, so scale the capacity value to reflect this.
	 */
	if (un->un_f_has_removable_media)
		capacity *= (lbasize / un->un_sys_blocksize);

rc16_done:

	/*
	 * Copy the values from the READ CAPACITY command into the space
	 * provided by the caller.
	 */
	*capp = capacity;
	*lbap = lbasize;

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_READ_CAPACITY: "
	    "capacity:0x%llx  lbasize:0x%x\n", capacity, lbasize);

	/*
	 * Both the lbasize and capacity from the device must be nonzero,
	 * otherwise we assume that the values are not valid and return
	 * failure to the caller. (4203735)
	 */
	if ((capacity == 0) || (lbasize == 0)) {
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, -1,
		    "sd_send_scsi_READ_CAPACITY received invalid value "
		    "capacity %llu lbasize %d", capacity, lbasize);
		return (EIO);
	}
	sd_ssc_assessment(ssc, SD_FMT_STANDARD);
	return (0);
}

/*
 *    Function: sd_send_scsi_READ_CAPACITY_16
 *
 * Description: This routine uses the scsi READ CAPACITY 16 command to
 *		determine the device capacity in number of blocks and the
 *		device native block size.  If this function returns a failure,
 *		then the values in *capp and *lbap are undefined.
 *		This routine should be called by sd_send_scsi_READ_CAPACITY
 *              which will apply any device specific adjustments to capacity
 *              and lbasize. One exception is it is also called by
 *              sd_get_media_info_ext. In that function, there is no need to
 *              adjust the capacity and lbasize.
 *
 *   Arguments: ssc   - ssc contains ptr to soft state struct for the target
 *		capp - ptr to unsigned 64-bit variable to receive the
 *			capacity value from the command.
 *		lbap - ptr to unsigned 32-bit varaible to receive the
 *			block size value from the command
 *              psp  - ptr to unsigned 32-bit variable to receive the
 *                      physical block size value from the command
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq. SD_PATH_DIRECT_PRIORITY is used when
 *			this command is issued as part of an error recovery
 *			action.
 *
 * Return Code: 0   - Success
 *		EIO - IO error
 *		EACCES - Reservation conflict detected
 *		EAGAIN - Device is becoming ready
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep.  Blocks until command completes.
 */

#define	SD_CAPACITY_16_SIZE	sizeof (struct scsi_capacity_16)

static int
sd_send_scsi_READ_CAPACITY_16(sd_ssc_t *ssc, uint64_t *capp,
	uint32_t *lbap, uint32_t *psp, int path_flag)
{
	struct	scsi_extended_sense	sense_buf;
	struct	uscsi_cmd	ucmd_buf;
	union	scsi_cdb	cdb;
	uint64_t		*capacity16_buf;
	uint64_t		capacity;
	uint32_t		lbasize;
	uint32_t		pbsize;
	uint32_t		lbpb_exp;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);

	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(capp != NULL);
	ASSERT(lbap != NULL);

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_READ_CAPACITY: entry: un:0x%p\n", un);

	/*
	 * First send a READ_CAPACITY_16 command to the target.
	 *
	 * Set up the CDB for the READ_CAPACITY_16 command.  The Partial
	 * Medium Indicator bit is cleared.  The address field must be
	 * zero if the PMI bit is zero.
	 */
	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));

	capacity16_buf = kmem_zalloc(SD_CAPACITY_16_SIZE, KM_SLEEP);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP4;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)capacity16_buf;
	ucmd_buf.uscsi_buflen	= SD_CAPACITY_16_SIZE;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (sense_buf);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;

	/*
	 * Read Capacity (16) is a Service Action In command.  One
	 * command byte (0x9E) is overloaded for multiple operations,
	 * with the second CDB byte specifying the desired operation
	 */
	cdb.scc_cmd = SCMD_SVC_ACTION_IN_G4;
	cdb.cdb_opaque[1] = SSVC_ACTION_READ_CAPACITY_G4;

	/*
	 * Fill in allocation length field
	 */
	FORMG4COUNT(&cdb, ucmd_buf.uscsi_buflen);

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:
		/* Return failure if we did not get valid capacity data. */
		if (ucmd_buf.uscsi_resid > 20) {
			sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, -1,
			    "sd_send_scsi_READ_CAPACITY_16 received invalid "
			    "capacity data");
			kmem_free(capacity16_buf, SD_CAPACITY_16_SIZE);
			return (EIO);
		}

		/*
		 * Read capacity and block size from the READ CAPACITY 16 data.
		 * This data may be adjusted later due to device specific
		 * issues.
		 *
		 * According to the SCSI spec, the READ CAPACITY 16
		 * command returns the following:
		 *
		 *  bytes 0-7: Maximum logical block address available.
		 *		(MSB in byte:0 & LSB in byte:7)
		 *
		 *  bytes 8-11: Block length in bytes
		 *		(MSB in byte:8 & LSB in byte:11)
		 *
		 *  byte 13: LOGICAL BLOCKS PER PHYSICAL BLOCK EXPONENT
		 */
		capacity = BE_64(capacity16_buf[0]);
		lbasize = BE_32(*(uint32_t *)&capacity16_buf[1]);
		lbpb_exp = (BE_64(capacity16_buf[1]) >> 16) & 0x0f;

		pbsize = lbasize << lbpb_exp;

		/*
		 * Done with capacity16_buf
		 */
		kmem_free(capacity16_buf, SD_CAPACITY_16_SIZE);

		/*
		 * if the reported capacity is set to all 0xf's, then
		 * this disk is too large.  This could only happen with
		 * a device that supports LBAs larger than 64 bits which
		 * are not defined by any current T10 standards.
		 */
		if (capacity == 0xffffffffffffffff) {
			sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, -1,
			    "disk is too large");
			return (EIO);
		}
		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		case STATUS_CHECK:
			/*
			 * Check condition; look for ASC/ASCQ of 0x04/0x01
			 * (LOGICAL UNIT IS IN PROCESS OF BECOMING READY)
			 */
			if ((ucmd_buf.uscsi_rqstatus == STATUS_GOOD) &&
			    (scsi_sense_asc((uint8_t *)&sense_buf) == 0x04) &&
			    (scsi_sense_ascq((uint8_t *)&sense_buf) == 0x01)) {
				kmem_free(capacity16_buf, SD_CAPACITY_16_SIZE);
				return (EAGAIN);
			}
			break;
		default:
			break;
		}
		/* FALLTHRU */
	default:
		kmem_free(capacity16_buf, SD_CAPACITY_16_SIZE);
		return (status);
	}

	/*
	 * Some ATAPI CD-ROM drives report inaccurate LBA size values
	 * (2352 and 0 are common) so for these devices always force the value
	 * to 2048 as required by the ATAPI specs.
	 */
	if ((un->un_f_cfg_is_atapi == TRUE) && (ISCD(un))) {
		lbasize = 2048;
	}

	/*
	 * Get the maximum LBA value from the READ CAPACITY 16 data.
	 * Here we assume that the Partial Medium Indicator (PMI) bit
	 * was cleared when issuing the command. This means that the LBA
	 * returned from the device is the LBA of the last logical block
	 * on the logical unit.  The actual logical block count will be
	 * this value plus one.
	 */
	capacity += 1;

	/*
	 * Currently, for removable media, the capacity is saved in terms
	 * of un->un_sys_blocksize, so scale the capacity value to reflect this.
	 */
	if (un->un_f_has_removable_media)
		capacity *= (lbasize / un->un_sys_blocksize);

	*capp = capacity;
	*lbap = lbasize;
	*psp = pbsize;

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_READ_CAPACITY_16: "
	    "capacity:0x%llx  lbasize:0x%x, pbsize: 0x%x\n",
	    capacity, lbasize, pbsize);

	if ((capacity == 0) || (lbasize == 0) || (pbsize == 0)) {
		sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, -1,
		    "sd_send_scsi_READ_CAPACITY_16 received invalid value "
		    "capacity %llu lbasize %d pbsize %d", capacity, lbasize);
		return (EIO);
	}

	sd_ssc_assessment(ssc, SD_FMT_STANDARD);
	return (0);
}


/*
 *    Function: sd_send_scsi_START_STOP_UNIT
 *
 * Description: Issue a scsi START STOP UNIT command to the target.
 *
 *   Arguments: ssc    - ssc contatins pointer to driver soft state (unit)
 *                       structure for this target.
 *      pc_flag - SD_POWER_CONDITION
 *                SD_START_STOP
 *		flag  - SD_TARGET_START
 *			SD_TARGET_STOP
 *			SD_TARGET_EJECT
 *			SD_TARGET_CLOSE
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq. SD_PATH_DIRECT_PRIORITY is used when this
 *			command is issued as part of an error recovery action.
 *
 * Return Code: 0   - Success
 *		EIO - IO error
 *		EACCES - Reservation conflict detected
 *		ENXIO  - Not Ready, medium not present
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep.
 */

static int
sd_send_scsi_START_STOP_UNIT(sd_ssc_t *ssc, int pc_flag, int flag,
    int path_flag)
{
	struct	scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_START_STOP_UNIT: entry: un:0x%p\n", un);

	if (un->un_f_check_start_stop &&
	    (pc_flag == SD_START_STOP) &&
	    ((flag == SD_TARGET_START) || (flag == SD_TARGET_STOP)) &&
	    (un->un_f_start_stop_supported != TRUE)) {
		return (0);
	}

	/*
	 * If we are performing an eject operation and
	 * we receive any command other than SD_TARGET_EJECT
	 * we should immediately return.
	 */
	if (flag != SD_TARGET_EJECT) {
		mutex_enter(SD_MUTEX(un));
		if (un->un_f_ejecting == TRUE) {
			mutex_exit(SD_MUTEX(un));
			return (EAGAIN);
		}
		mutex_exit(SD_MUTEX(un));
	}

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (struct scsi_extended_sense));

	cdb.scc_cmd = SCMD_START_STOP;
	cdb.cdb_opaque[4] = (pc_flag == SD_POWER_CONDITION) ?
	    (uchar_t)(flag << 4) : (uchar_t)flag;

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP0;
	ucmd_buf.uscsi_bufaddr	= NULL;
	ucmd_buf.uscsi_buflen	= 0;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 200;

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);
		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		case STATUS_CHECK:
			if (ucmd_buf.uscsi_rqstatus == STATUS_GOOD) {
				switch (scsi_sense_key(
				    (uint8_t *)&sense_buf)) {
				case KEY_ILLEGAL_REQUEST:
					status = ENOTSUP;
					break;
				case KEY_NOT_READY:
					if (scsi_sense_asc(
					    (uint8_t *)&sense_buf)
					    == 0x3A) {
						status = ENXIO;
					}
					break;
				default:
					break;
				}
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_START_STOP_UNIT: exit\n");

	return (status);
}


/*
 *    Function: sd_start_stop_unit_callback
 *
 * Description: timeout(9F) callback to begin recovery process for a
 *		device that has spun down.
 *
 *   Arguments: arg - pointer to associated softstate struct.
 *
 *     Context: Executes in a timeout(9F) thread context
 */

static void
sd_start_stop_unit_callback(void *arg)
{
	struct sd_lun	*un = arg;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO, un, "sd_start_stop_unit_callback: entry\n");

	(void) taskq_dispatch(sd_tq, sd_start_stop_unit_task, un, KM_NOSLEEP);
}


/*
 *    Function: sd_start_stop_unit_task
 *
 * Description: Recovery procedure when a drive is spun down.
 *
 *   Arguments: arg - pointer to associated softstate struct.
 *
 *     Context: Executes in a taskq() thread context
 */

static void
sd_start_stop_unit_task(void *arg)
{
	struct sd_lun	*un = arg;
	sd_ssc_t	*ssc;
	int		power_level;
	int		rval;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO, un, "sd_start_stop_unit_task: entry\n");

	/*
	 * Some unformatted drives report not ready error, no need to
	 * restart if format has been initiated.
	 */
	mutex_enter(SD_MUTEX(un));
	if (un->un_f_format_in_progress == TRUE) {
		mutex_exit(SD_MUTEX(un));
		return;
	}
	mutex_exit(SD_MUTEX(un));

	ssc = sd_ssc_init(un);
	/*
	 * When a START STOP command is issued from here, it is part of a
	 * failure recovery operation and must be issued before any other
	 * commands, including any pending retries. Thus it must be sent
	 * using SD_PATH_DIRECT_PRIORITY. It doesn't matter if the spin up
	 * succeeds or not, we will start I/O after the attempt.
	 * If power condition is supported and the current power level
	 * is capable of performing I/O, we should set the power condition
	 * to that level. Otherwise, set the power condition to ACTIVE.
	 */
	if (un->un_f_power_condition_supported) {
		mutex_enter(SD_MUTEX(un));
		ASSERT(SD_PM_IS_LEVEL_VALID(un, un->un_power_level));
		power_level = sd_pwr_pc.ran_perf[un->un_power_level]
		    > 0 ? un->un_power_level : SD_SPINDLE_ACTIVE;
		mutex_exit(SD_MUTEX(un));
		rval = sd_send_scsi_START_STOP_UNIT(ssc, SD_POWER_CONDITION,
		    sd_pl2pc[power_level], SD_PATH_DIRECT_PRIORITY);
	} else {
		rval = sd_send_scsi_START_STOP_UNIT(ssc, SD_START_STOP,
		    SD_TARGET_START, SD_PATH_DIRECT_PRIORITY);
	}

	if (rval != 0)
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	sd_ssc_fini(ssc);
	/*
	 * The above call blocks until the START_STOP_UNIT command completes.
	 * Now that it has completed, we must re-try the original IO that
	 * received the NOT READY condition in the first place. There are
	 * three possible conditions here:
	 *
	 *  (1) The original IO is on un_retry_bp.
	 *  (2) The original IO is on the regular wait queue, and un_retry_bp
	 *	is NULL.
	 *  (3) The original IO is on the regular wait queue, and un_retry_bp
	 *	points to some other, unrelated bp.
	 *
	 * For each case, we must call sd_start_cmds() with un_retry_bp
	 * as the argument. If un_retry_bp is NULL, this will initiate
	 * processing of the regular wait queue.  If un_retry_bp is not NULL,
	 * then this will process the bp on un_retry_bp. That may or may not
	 * be the original IO, but that does not matter: the important thing
	 * is to keep the IO processing going at this point.
	 *
	 * Note: This is a very specific error recovery sequence associated
	 * with a drive that is not spun up. We attempt a START_STOP_UNIT and
	 * serialize the I/O with completion of the spin-up.
	 */
	mutex_enter(SD_MUTEX(un));
	SD_TRACE(SD_LOG_IO_CORE | SD_LOG_ERROR, un,
	    "sd_start_stop_unit_task: un:0x%p starting bp:0x%p\n",
	    un, un->un_retry_bp);
	un->un_startstop_timeid = NULL;	/* Timeout is no longer pending */
	sd_start_cmds(un, un->un_retry_bp);
	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_IO, un, "sd_start_stop_unit_task: exit\n");
}


/*
 *    Function: sd_send_scsi_INQUIRY
 *
 * Description: Issue the scsi INQUIRY command.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		bufaddr
 *		buflen
 *		evpd
 *		page_code
 *		page_length
 *
 * Return Code: 0   - Success
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_INQUIRY(sd_ssc_t *ssc, uchar_t *bufaddr, size_t buflen,
	uchar_t evpd, uchar_t page_code, size_t *residp)
{
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bufaddr != NULL);

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_INQUIRY: entry: un:0x%p\n", un);

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(bufaddr, buflen);

	cdb.scc_cmd = SCMD_INQUIRY;
	cdb.cdb_opaque[1] = evpd;
	cdb.cdb_opaque[2] = page_code;
	FORMG0COUNT(&cdb, buflen);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP0;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)bufaddr;
	ucmd_buf.uscsi_buflen	= buflen;
	ucmd_buf.uscsi_rqbuf	= NULL;
	ucmd_buf.uscsi_rqlen	= 0;
	ucmd_buf.uscsi_flags	= USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 200;	/* Excessive legacy value */

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, SD_PATH_DIRECT);

	/*
	 * Only handle status == 0, the upper-level caller
	 * will put different assessment based on the context.
	 */
	if (status == 0)
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);

	if ((status == 0) && (residp != NULL)) {
		*residp = ucmd_buf.uscsi_resid;
	}

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_INQUIRY: exit\n");

	return (status);
}


/*
 *    Function: sd_send_scsi_TEST_UNIT_READY
 *
 * Description: Issue the scsi TEST UNIT READY command.
 *		This routine can be told to set the flag USCSI_DIAGNOSE to
 *		prevent retrying failed commands. Use this when the intent
 *		is either to check for device readiness, to clear a Unit
 *		Attention, or to clear any outstanding sense data.
 *		However under specific conditions the expected behavior
 *		is for retries to bring a device ready, so use the flag
 *		with caution.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		flag:   SD_CHECK_FOR_MEDIA: return ENXIO if no media present
 *			SD_DONT_RETRY_TUR: include uscsi flag USCSI_DIAGNOSE.
 *			0: dont check for media present, do retries on cmd.
 *
 * Return Code: 0   - Success
 *		EIO - IO error
 *		EACCES - Reservation conflict detected
 *		ENXIO  - Not Ready, medium not present
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_TEST_UNIT_READY(sd_ssc_t *ssc, int flag)
{
	struct	scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_TEST_UNIT_READY: entry: un:0x%p\n", un);

	/*
	 * Some Seagate elite1 TQ devices get hung with disconnect/reconnect
	 * timeouts when they receive a TUR and the queue is not empty. Check
	 * the configuration flag set during attach (indicating the drive has
	 * this firmware bug) and un_ncmds_in_transport before issuing the
	 * TUR. If there are
	 * pending commands return success, this is a bit arbitrary but is ok
	 * for non-removables (i.e. the eliteI disks) and non-clustering
	 * configurations.
	 */
	if (un->un_f_cfg_tur_check == TRUE) {
		mutex_enter(SD_MUTEX(un));
		if (un->un_ncmds_in_transport != 0) {
			mutex_exit(SD_MUTEX(un));
			return (0);
		}
		mutex_exit(SD_MUTEX(un));
	}

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (struct scsi_extended_sense));

	cdb.scc_cmd = SCMD_TEST_UNIT_READY;

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP0;
	ucmd_buf.uscsi_bufaddr	= NULL;
	ucmd_buf.uscsi_buflen	= 0;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_SILENT;

	/* Use flag USCSI_DIAGNOSE to prevent retries if it fails. */
	if ((flag & SD_DONT_RETRY_TUR) != 0) {
		ucmd_buf.uscsi_flags |= USCSI_DIAGNOSE;
	}
	ucmd_buf.uscsi_timeout	= 60;

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, ((flag & SD_BYPASS_PM) ? SD_PATH_DIRECT :
	    SD_PATH_STANDARD));

	switch (status) {
	case 0:
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);
		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		case STATUS_CHECK:
			if ((flag & SD_CHECK_FOR_MEDIA) == 0) {
				break;
			}
			if ((ucmd_buf.uscsi_rqstatus == STATUS_GOOD) &&
			    (scsi_sense_key((uint8_t *)&sense_buf) ==
			    KEY_NOT_READY) &&
			    (scsi_sense_asc((uint8_t *)&sense_buf) == 0x3A)) {
				status = ENXIO;
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_TEST_UNIT_READY: exit\n");

	return (status);
}

/*
 *    Function: sd_send_scsi_PERSISTENT_RESERVE_IN
 *
 * Description: Issue the scsi PERSISTENT RESERVE IN command.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *
 * Return Code: 0   - Success
 *		EACCES
 *		ENOTSUP
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_PERSISTENT_RESERVE_IN(sd_ssc_t *ssc, uchar_t  usr_cmd,
	uint16_t data_len, uchar_t *data_bufp)
{
	struct scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	int			no_caller_buf = FALSE;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT((usr_cmd == SD_READ_KEYS) || (usr_cmd == SD_READ_RESV));

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_PERSISTENT_RESERVE_IN: entry: un:0x%p\n", un);

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (struct scsi_extended_sense));
	if (data_bufp == NULL) {
		/* Allocate a default buf if the caller did not give one */
		ASSERT(data_len == 0);
		data_len  = MHIOC_RESV_KEY_SIZE;
		data_bufp = kmem_zalloc(MHIOC_RESV_KEY_SIZE, KM_SLEEP);
		no_caller_buf = TRUE;
	}

	cdb.scc_cmd = SCMD_PERSISTENT_RESERVE_IN;
	cdb.cdb_opaque[1] = usr_cmd;
	FORMG1COUNT(&cdb, data_len);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP1;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)data_bufp;
	ucmd_buf.uscsi_buflen	= data_len;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, SD_PATH_STANDARD);

	switch (status) {
	case 0:
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);

		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		case STATUS_CHECK:
			if ((ucmd_buf.uscsi_rqstatus == STATUS_GOOD) &&
			    (scsi_sense_key((uint8_t *)&sense_buf) ==
			    KEY_ILLEGAL_REQUEST)) {
				status = ENOTSUP;
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_PERSISTENT_RESERVE_IN: exit\n");

	if (no_caller_buf == TRUE) {
		kmem_free(data_bufp, data_len);
	}

	return (status);
}


/*
 *    Function: sd_send_scsi_PERSISTENT_RESERVE_OUT
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		multi-host persistent reservation requests (MHIOCGRP_INKEYS,
 *		MHIOCGRP_INRESV) by sending the SCSI-3 PROUT commands to the
 *		device.
 *
 *   Arguments: ssc  -  ssc contains un - pointer to soft state struct
 *                      for the target.
 *		usr_cmd SCSI-3 reservation facility command (one of
 *			SD_SCSI3_REGISTER, SD_SCSI3_RESERVE, SD_SCSI3_RELEASE,
 *			SD_SCSI3_PREEMPTANDABORT, SD_SCSI3_CLEAR)
 *		usr_bufp - user provided pointer register, reserve descriptor or
 *			preempt and abort structure (mhioc_register_t,
 *                      mhioc_resv_desc_t, mhioc_preemptandabort_t)
 *
 * Return Code: 0   - Success
 *		EACCES
 *		ENOTSUP
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_PERSISTENT_RESERVE_OUT(sd_ssc_t *ssc, uchar_t usr_cmd,
	uchar_t	*usr_bufp)
{
	struct scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	uchar_t			data_len = sizeof (sd_prout_t);
	sd_prout_t		*prp;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(data_len == 24);	/* required by scsi spec */

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_PERSISTENT_RESERVE_OUT: entry: un:0x%p\n", un);

	if (usr_bufp == NULL) {
		return (EINVAL);
	}

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (struct scsi_extended_sense));
	prp = kmem_zalloc(data_len, KM_SLEEP);

	cdb.scc_cmd = SCMD_PERSISTENT_RESERVE_OUT;
	cdb.cdb_opaque[1] = usr_cmd;
	FORMG1COUNT(&cdb, data_len);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP1;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)prp;
	ucmd_buf.uscsi_buflen	= data_len;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_WRITE | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;

	switch (usr_cmd) {
	case SD_SCSI3_REGISTER: {
		mhioc_register_t *ptr = (mhioc_register_t *)usr_bufp;

		bcopy(ptr->oldkey.key, prp->res_key, MHIOC_RESV_KEY_SIZE);
		bcopy(ptr->newkey.key, prp->service_key,
		    MHIOC_RESV_KEY_SIZE);
		prp->aptpl = ptr->aptpl;
		break;
	}
	case SD_SCSI3_CLEAR: {
		mhioc_resv_desc_t *ptr = (mhioc_resv_desc_t *)usr_bufp;

		bcopy(ptr->key.key, prp->res_key, MHIOC_RESV_KEY_SIZE);
		break;
	}
	case SD_SCSI3_RESERVE:
	case SD_SCSI3_RELEASE: {
		mhioc_resv_desc_t *ptr = (mhioc_resv_desc_t *)usr_bufp;

		bcopy(ptr->key.key, prp->res_key, MHIOC_RESV_KEY_SIZE);
		prp->scope_address = BE_32(ptr->scope_specific_addr);
		cdb.cdb_opaque[2] = ptr->type;
		break;
	}
	case SD_SCSI3_PREEMPTANDABORT: {
		mhioc_preemptandabort_t *ptr =
		    (mhioc_preemptandabort_t *)usr_bufp;

		bcopy(ptr->resvdesc.key.key, prp->res_key, MHIOC_RESV_KEY_SIZE);
		bcopy(ptr->victim_key.key, prp->service_key,
		    MHIOC_RESV_KEY_SIZE);
		prp->scope_address = BE_32(ptr->resvdesc.scope_specific_addr);
		cdb.cdb_opaque[2] = ptr->resvdesc.type;
		ucmd_buf.uscsi_flags |= USCSI_HEAD;
		break;
	}
	case SD_SCSI3_REGISTERANDIGNOREKEY:
	{
		mhioc_registerandignorekey_t *ptr;
		ptr = (mhioc_registerandignorekey_t *)usr_bufp;
		bcopy(ptr->newkey.key,
		    prp->service_key, MHIOC_RESV_KEY_SIZE);
		prp->aptpl = ptr->aptpl;
		break;
	}
	default:
		ASSERT(FALSE);
		break;
	}

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, SD_PATH_STANDARD);

	switch (status) {
	case 0:
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);
		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		case STATUS_CHECK:
			if ((ucmd_buf.uscsi_rqstatus == STATUS_GOOD) &&
			    (scsi_sense_key((uint8_t *)&sense_buf) ==
			    KEY_ILLEGAL_REQUEST)) {
				status = ENOTSUP;
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	kmem_free(prp, data_len);
	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_PERSISTENT_RESERVE_OUT: exit\n");
	return (status);
}


/*
 *    Function: sd_send_scsi_SYNCHRONIZE_CACHE
 *
 * Description: Issues a scsi SYNCHRONIZE CACHE command to the target
 *
 *   Arguments: un - pointer to the target's soft state struct
 *              dkc - pointer to the callback structure
 *
 * Return Code: 0 - success
 *		errno-type error code
 *
 *     Context: kernel thread context only.
 *
 *  _______________________________________________________________
 * | dkc_flag &   | dkc_callback | DKIOCFLUSHWRITECACHE            |
 * |FLUSH_VOLATILE|              | operation                       |
 * |______________|______________|_________________________________|
 * | 0            | NULL         | Synchronous flush on both       |
 * |              |              | volatile and non-volatile cache |
 * |______________|______________|_________________________________|
 * | 1            | NULL         | Synchronous flush on volatile   |
 * |              |              | cache; disk drivers may suppress|
 * |              |              | flush if disk table indicates   |
 * |              |              | non-volatile cache              |
 * |______________|______________|_________________________________|
 * | 0            | !NULL        | Asynchronous flush on both      |
 * |              |              | volatile and non-volatile cache;|
 * |______________|______________|_________________________________|
 * | 1            | !NULL        | Asynchronous flush on volatile  |
 * |              |              | cache; disk drivers may suppress|
 * |              |              | flush if disk table indicates   |
 * |              |              | non-volatile cache              |
 * |______________|______________|_________________________________|
 *
 */

static int
sd_send_scsi_SYNCHRONIZE_CACHE(struct sd_lun *un, struct dk_callback *dkc)
{
	struct sd_uscsi_info	*uip;
	struct uscsi_cmd	*uscmd;
	union scsi_cdb		*cdb;
	struct buf		*bp;
	int			rval = 0;
	int			is_async;

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_SYNCHRONIZE_CACHE: entry: un:0x%p\n", un);

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	if (dkc == NULL || dkc->dkc_callback == NULL) {
		is_async = FALSE;
	} else {
		is_async = TRUE;
	}

	mutex_enter(SD_MUTEX(un));
	/* check whether cache flush should be suppressed */
	if (un->un_f_suppress_cache_flush == TRUE) {
		mutex_exit(SD_MUTEX(un));
		/*
		 * suppress the cache flush if the device is told to do
		 * so by sd.conf or disk table
		 */
		SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_SYNCHRONIZE_CACHE: \
		    skip the cache flush since suppress_cache_flush is %d!\n",
		    un->un_f_suppress_cache_flush);

		if (is_async == TRUE) {
			/* invoke callback for asynchronous flush */
			(*dkc->dkc_callback)(dkc->dkc_cookie, 0);
		}
		return (rval);
	}
	mutex_exit(SD_MUTEX(un));

	/*
	 * check dkc_flag & FLUSH_VOLATILE so SYNC_NV bit can be
	 * set properly
	 */
	cdb = kmem_zalloc(CDB_GROUP1, KM_SLEEP);
	cdb->scc_cmd = SCMD_SYNCHRONIZE_CACHE;

	mutex_enter(SD_MUTEX(un));
	if (dkc != NULL && un->un_f_sync_nv_supported &&
	    (dkc->dkc_flag & FLUSH_VOLATILE)) {
		/*
		 * if the device supports SYNC_NV bit, turn on
		 * the SYNC_NV bit to only flush volatile cache
		 */
		cdb->cdb_un.tag |= SD_SYNC_NV_BIT;
	}
	mutex_exit(SD_MUTEX(un));

	/*
	 * First get some memory for the uscsi_cmd struct and cdb
	 * and initialize for SYNCHRONIZE_CACHE cmd.
	 */
	uscmd = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);
	uscmd->uscsi_cdblen = CDB_GROUP1;
	uscmd->uscsi_cdb = (caddr_t)cdb;
	uscmd->uscsi_bufaddr = NULL;
	uscmd->uscsi_buflen = 0;
	uscmd->uscsi_rqbuf = kmem_zalloc(SENSE_LENGTH, KM_SLEEP);
	uscmd->uscsi_rqlen = SENSE_LENGTH;
	uscmd->uscsi_rqresid = SENSE_LENGTH;
	uscmd->uscsi_flags = USCSI_RQENABLE | USCSI_SILENT;
	uscmd->uscsi_timeout = sd_io_time;

	/*
	 * Allocate an sd_uscsi_info struct and fill it with the info
	 * needed by sd_initpkt_for_uscsi().  Then put the pointer into
	 * b_private in the buf for sd_initpkt_for_uscsi().  Note that
	 * since we allocate the buf here in this function, we do not
	 * need to preserve the prior contents of b_private.
	 * The sd_uscsi_info struct is also used by sd_uscsi_strategy()
	 */
	uip = kmem_zalloc(sizeof (struct sd_uscsi_info), KM_SLEEP);
	uip->ui_flags = SD_PATH_DIRECT;
	uip->ui_cmdp  = uscmd;

	bp = getrbuf(KM_SLEEP);
	bp->b_private = uip;

	/*
	 * Setup buffer to carry uscsi request.
	 */
	bp->b_flags  = B_BUSY;
	bp->b_bcount = 0;
	bp->b_blkno  = 0;

	if (is_async == TRUE) {
		bp->b_iodone = sd_send_scsi_SYNCHRONIZE_CACHE_biodone;
		uip->ui_dkc = *dkc;
	}

	bp->b_edev = SD_GET_DEV(un);
	bp->b_dev = cmpdev(bp->b_edev);	/* maybe unnecessary? */

	/*
	 * Unset un_f_sync_cache_required flag
	 */
	mutex_enter(SD_MUTEX(un));
	un->un_f_sync_cache_required = FALSE;
	mutex_exit(SD_MUTEX(un));

	(void) sd_uscsi_strategy(bp);

	/*
	 * If synchronous request, wait for completion
	 * If async just return and let b_iodone callback
	 * cleanup.
	 * NOTE: On return, u_ncmds_in_driver will be decremented,
	 * but it was also incremented in sd_uscsi_strategy(), so
	 * we should be ok.
	 */
	if (is_async == FALSE) {
		(void) biowait(bp);
		rval = sd_send_scsi_SYNCHRONIZE_CACHE_biodone(bp);
	}

	return (rval);
}


static int
sd_send_scsi_SYNCHRONIZE_CACHE_biodone(struct buf *bp)
{
	struct sd_uscsi_info *uip;
	struct uscsi_cmd *uscmd;
	uint8_t *sense_buf;
	struct sd_lun *un;
	int status;
	union scsi_cdb *cdb;

	uip = (struct sd_uscsi_info *)(bp->b_private);
	ASSERT(uip != NULL);

	uscmd = uip->ui_cmdp;
	ASSERT(uscmd != NULL);

	sense_buf = (uint8_t *)uscmd->uscsi_rqbuf;
	ASSERT(sense_buf != NULL);

	un = ddi_get_soft_state(sd_state, SD_GET_INSTANCE_FROM_BUF(bp));
	ASSERT(un != NULL);

	cdb = (union scsi_cdb *)uscmd->uscsi_cdb;

	status = geterror(bp);
	switch (status) {
	case 0:
		break;	/* Success! */
	case EIO:
		switch (uscmd->uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			/* Ignore reservation conflict */
			status = 0;
			goto done;

		case STATUS_CHECK:
			if ((uscmd->uscsi_rqstatus == STATUS_GOOD) &&
			    (scsi_sense_key(sense_buf) ==
			    KEY_ILLEGAL_REQUEST)) {
				/* Ignore Illegal Request error */
				if (cdb->cdb_un.tag&SD_SYNC_NV_BIT) {
					mutex_enter(SD_MUTEX(un));
					un->un_f_sync_nv_supported = FALSE;
					mutex_exit(SD_MUTEX(un));
					status = 0;
					SD_TRACE(SD_LOG_IO, un,
					    "un_f_sync_nv_supported \
					    is set to false.\n");
					goto done;
				}

				mutex_enter(SD_MUTEX(un));
				un->un_f_sync_cache_supported = FALSE;
				mutex_exit(SD_MUTEX(un));
				SD_TRACE(SD_LOG_IO, un,
				    "sd_send_scsi_SYNCHRONIZE_CACHE_biodone: \
				    un_f_sync_cache_supported set to false \
				    with asc = %x, ascq = %x\n",
				    scsi_sense_asc(sense_buf),
				    scsi_sense_ascq(sense_buf));
				status = ENOTSUP;
				goto done;
			}
			break;
		default:
			break;
		}
		/* FALLTHRU */
	default:
		/*
		 * Turn on the un_f_sync_cache_required flag
		 * since the SYNC CACHE command failed
		 */
		mutex_enter(SD_MUTEX(un));
		un->un_f_sync_cache_required = TRUE;
		mutex_exit(SD_MUTEX(un));

		/*
		 * Don't log an error message if this device
		 * has removable media.
		 */
		if (!un->un_f_has_removable_media) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "SYNCHRONIZE CACHE command failed (%d)\n", status);
		}
		break;
	}

done:
	if (uip->ui_dkc.dkc_callback != NULL) {
		(*uip->ui_dkc.dkc_callback)(uip->ui_dkc.dkc_cookie, status);
	}

	ASSERT((bp->b_flags & B_REMAPPED) == 0);
	freerbuf(bp);
	kmem_free(uip, sizeof (struct sd_uscsi_info));
	kmem_free(uscmd->uscsi_rqbuf, SENSE_LENGTH);
	kmem_free(uscmd->uscsi_cdb, (size_t)uscmd->uscsi_cdblen);
	kmem_free(uscmd, sizeof (struct uscsi_cmd));

	return (status);
}


/*
 *    Function: sd_send_scsi_GET_CONFIGURATION
 *
 * Description: Issues the get configuration command to the device.
 *		Called from sd_check_for_writable_cd & sd_get_media_info
 *		caller needs to ensure that buflen = SD_PROFILE_HEADER_LEN
 *   Arguments: ssc
 *		ucmdbuf
 *		rqbuf
 *		rqbuflen
 *		bufaddr
 *		buflen
 *		path_flag
 *
 * Return Code: 0   - Success
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 *
 */

static int
sd_send_scsi_GET_CONFIGURATION(sd_ssc_t *ssc, struct uscsi_cmd *ucmdbuf,
	uchar_t *rqbuf, uint_t rqbuflen, uchar_t *bufaddr, uint_t buflen,
	int path_flag)
{
	char	cdb[CDB_GROUP1];
	int	status;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bufaddr != NULL);
	ASSERT(ucmdbuf != NULL);
	ASSERT(rqbuf != NULL);

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_GET_CONFIGURATION: entry: un:0x%p\n", un);

	bzero(cdb, sizeof (cdb));
	bzero(ucmdbuf, sizeof (struct uscsi_cmd));
	bzero(rqbuf, rqbuflen);
	bzero(bufaddr, buflen);

	/*
	 * Set up cdb field for the get configuration command.
	 */
	cdb[0] = SCMD_GET_CONFIGURATION;
	cdb[1] = 0x02;  /* Requested Type */
	cdb[8] = SD_PROFILE_HEADER_LEN;
	ucmdbuf->uscsi_cdb = cdb;
	ucmdbuf->uscsi_cdblen = CDB_GROUP1;
	ucmdbuf->uscsi_bufaddr = (caddr_t)bufaddr;
	ucmdbuf->uscsi_buflen = buflen;
	ucmdbuf->uscsi_timeout = sd_io_time;
	ucmdbuf->uscsi_rqbuf = (caddr_t)rqbuf;
	ucmdbuf->uscsi_rqlen = rqbuflen;
	ucmdbuf->uscsi_flags = USCSI_RQENABLE|USCSI_SILENT|USCSI_READ;

	status = sd_ssc_send(ssc, ucmdbuf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);
		break;  /* Success! */
	case EIO:
		switch (ucmdbuf->uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (status == 0) {
		SD_DUMP_MEMORY(un, SD_LOG_IO,
		    "sd_send_scsi_GET_CONFIGURATION: data",
		    (uchar_t *)bufaddr, SD_PROFILE_HEADER_LEN, SD_LOG_HEX);
	}

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_GET_CONFIGURATION: exit\n");

	return (status);
}

/*
 *    Function: sd_send_scsi_feature_GET_CONFIGURATION
 *
 * Description: Issues the get configuration command to the device to
 *              retrieve a specific feature. Called from
 *		sd_check_for_writable_cd & sd_set_mmc_caps.
 *   Arguments: ssc
 *              ucmdbuf
 *              rqbuf
 *              rqbuflen
 *              bufaddr
 *              buflen
 *		feature
 *
 * Return Code: 0   - Success
 *              errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 *
 */
static int
sd_send_scsi_feature_GET_CONFIGURATION(sd_ssc_t *ssc,
	struct uscsi_cmd *ucmdbuf, uchar_t *rqbuf, uint_t rqbuflen,
	uchar_t *bufaddr, uint_t buflen, char feature, int path_flag)
{
	char    cdb[CDB_GROUP1];
	int	status;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bufaddr != NULL);
	ASSERT(ucmdbuf != NULL);
	ASSERT(rqbuf != NULL);

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_feature_GET_CONFIGURATION: entry: un:0x%p\n", un);

	bzero(cdb, sizeof (cdb));
	bzero(ucmdbuf, sizeof (struct uscsi_cmd));
	bzero(rqbuf, rqbuflen);
	bzero(bufaddr, buflen);

	/*
	 * Set up cdb field for the get configuration command.
	 */
	cdb[0] = SCMD_GET_CONFIGURATION;
	cdb[1] = 0x02;  /* Requested Type */
	cdb[3] = feature;
	cdb[8] = buflen;
	ucmdbuf->uscsi_cdb = cdb;
	ucmdbuf->uscsi_cdblen = CDB_GROUP1;
	ucmdbuf->uscsi_bufaddr = (caddr_t)bufaddr;
	ucmdbuf->uscsi_buflen = buflen;
	ucmdbuf->uscsi_timeout = sd_io_time;
	ucmdbuf->uscsi_rqbuf = (caddr_t)rqbuf;
	ucmdbuf->uscsi_rqlen = rqbuflen;
	ucmdbuf->uscsi_flags = USCSI_RQENABLE|USCSI_SILENT|USCSI_READ;

	status = sd_ssc_send(ssc, ucmdbuf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:

		break;  /* Success! */
	case EIO:
		switch (ucmdbuf->uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (status == 0) {
		SD_DUMP_MEMORY(un, SD_LOG_IO,
		    "sd_send_scsi_feature_GET_CONFIGURATION: data",
		    (uchar_t *)bufaddr, SD_PROFILE_HEADER_LEN, SD_LOG_HEX);
	}

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_feature_GET_CONFIGURATION: exit\n");

	return (status);
}


/*
 *    Function: sd_send_scsi_MODE_SENSE
 *
 * Description: Utility function for issuing a scsi MODE SENSE command.
 *		Note: This routine uses a consistent implementation for Group0,
 *		Group1, and Group2 commands across all platforms. ATAPI devices
 *		use Group 1 Read/Write commands and Group 2 Mode Sense/Select
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		cdbsize - size CDB to be used (CDB_GROUP0 (6 byte), or
 *			  CDB_GROUP[1|2] (10 byte).
 *		bufaddr - buffer for page data retrieved from the target.
 *		buflen - size of page to be retrieved.
 *		page_code - page code of data to be retrieved from the target.
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq.
 *
 * Return Code: 0   - Success
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_MODE_SENSE(sd_ssc_t *ssc, int cdbsize, uchar_t *bufaddr,
	size_t buflen,  uchar_t page_code, int path_flag)
{
	struct	scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	int			headlen;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bufaddr != NULL);
	ASSERT((cdbsize == CDB_GROUP0) || (cdbsize == CDB_GROUP1) ||
	    (cdbsize == CDB_GROUP2));

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_MODE_SENSE: entry: un:0x%p\n", un);

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (struct scsi_extended_sense));
	bzero(bufaddr, buflen);

	if (cdbsize == CDB_GROUP0) {
		cdb.scc_cmd = SCMD_MODE_SENSE;
		cdb.cdb_opaque[2] = page_code;
		FORMG0COUNT(&cdb, buflen);
		headlen = MODE_HEADER_LENGTH;
	} else {
		cdb.scc_cmd = SCMD_MODE_SENSE_G1;
		cdb.cdb_opaque[2] = page_code;
		FORMG1COUNT(&cdb, buflen);
		headlen = MODE_HEADER_LENGTH_GRP2;
	}

	ASSERT(headlen <= buflen);
	SD_FILL_SCSI1_LUN_CDB(un, &cdb);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= (uchar_t)cdbsize;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)bufaddr;
	ucmd_buf.uscsi_buflen	= buflen;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:
		/*
		 * sr_check_wp() uses 0x3f page code and check the header of
		 * mode page to determine if target device is write-protected.
		 * But some USB devices return 0 bytes for 0x3f page code. For
		 * this case, make sure that mode page header is returned at
		 * least.
		 */
		if (buflen - ucmd_buf.uscsi_resid <  headlen) {
			status = EIO;
			sd_ssc_set_info(ssc, SSC_FLAGS_INVALID_DATA, -1,
			    "mode page header is not returned");
		}
		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (status == 0) {
		SD_DUMP_MEMORY(un, SD_LOG_IO, "sd_send_scsi_MODE_SENSE: data",
		    (uchar_t *)bufaddr, buflen, SD_LOG_HEX);
	}
	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_MODE_SENSE: exit\n");

	return (status);
}


/*
 *    Function: sd_send_scsi_MODE_SELECT
 *
 * Description: Utility function for issuing a scsi MODE SELECT command.
 *		Note: This routine uses a consistent implementation for Group0,
 *		Group1, and Group2 commands across all platforms. ATAPI devices
 *		use Group 1 Read/Write commands and Group 2 Mode Sense/Select
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		cdbsize - size CDB to be used (CDB_GROUP0 (6 byte), or
 *			  CDB_GROUP[1|2] (10 byte).
 *		bufaddr - buffer for page data retrieved from the target.
 *		buflen - size of page to be retrieved.
 *		save_page - boolean to determin if SP bit should be set.
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq.
 *
 * Return Code: 0   - Success
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_MODE_SELECT(sd_ssc_t *ssc, int cdbsize, uchar_t *bufaddr,
	size_t buflen,  uchar_t save_page, int path_flag)
{
	struct	scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bufaddr != NULL);
	ASSERT((cdbsize == CDB_GROUP0) || (cdbsize == CDB_GROUP1) ||
	    (cdbsize == CDB_GROUP2));

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_MODE_SELECT: entry: un:0x%p\n", un);

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (struct scsi_extended_sense));

	/* Set the PF bit for many third party drives */
	cdb.cdb_opaque[1] = 0x10;

	/* Set the savepage(SP) bit if given */
	if (save_page == SD_SAVE_PAGE) {
		cdb.cdb_opaque[1] |= 0x01;
	}

	if (cdbsize == CDB_GROUP0) {
		cdb.scc_cmd = SCMD_MODE_SELECT;
		FORMG0COUNT(&cdb, buflen);
	} else {
		cdb.scc_cmd = SCMD_MODE_SELECT_G1;
		FORMG1COUNT(&cdb, buflen);
	}

	SD_FILL_SCSI1_LUN_CDB(un, &cdb);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= (uchar_t)cdbsize;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)bufaddr;
	ucmd_buf.uscsi_buflen	= buflen;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_WRITE | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);
		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (status == 0) {
		SD_DUMP_MEMORY(un, SD_LOG_IO, "sd_send_scsi_MODE_SELECT: data",
		    (uchar_t *)bufaddr, buflen, SD_LOG_HEX);
	}
	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_MODE_SELECT: exit\n");

	return (status);
}


/*
 *    Function: sd_send_scsi_RDWR
 *
 * Description: Issue a scsi READ or WRITE command with the given parameters.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		cmd:	 SCMD_READ or SCMD_WRITE
 *		bufaddr: Address of caller's buffer to receive the RDWR data
 *		buflen:  Length of caller's buffer receive the RDWR data.
 *		start_block: Block number for the start of the RDWR operation.
 *			 (Assumes target-native block size.)
 *		residp:  Pointer to variable to receive the redisual of the
 *			 RDWR operation (may be NULL of no residual requested).
 *		path_flag - SD_PATH_DIRECT to use the USCSI "direct" chain and
 *			the normal command waitq, or SD_PATH_DIRECT_PRIORITY
 *			to use the USCSI "direct" chain and bypass the normal
 *			command waitq.
 *
 * Return Code: 0   - Success
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_RDWR(sd_ssc_t *ssc, uchar_t cmd, void *bufaddr,
	size_t buflen, daddr_t start_block, int path_flag)
{
	struct	scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	uint32_t		block_count;
	int			status;
	int			cdbsize;
	uchar_t			flag;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bufaddr != NULL);
	ASSERT((cmd == SCMD_READ) || (cmd == SCMD_WRITE));

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_RDWR: entry: un:0x%p\n", un);

	if (un->un_f_tgt_blocksize_is_valid != TRUE) {
		return (EINVAL);
	}

	mutex_enter(SD_MUTEX(un));
	block_count = SD_BYTES2TGTBLOCKS(un, buflen);
	mutex_exit(SD_MUTEX(un));

	flag = (cmd == SCMD_READ) ? USCSI_READ : USCSI_WRITE;

	SD_INFO(SD_LOG_IO, un, "sd_send_scsi_RDWR: "
	    "bufaddr:0x%p buflen:0x%x start_block:0x%p block_count:0x%x\n",
	    bufaddr, buflen, start_block, block_count);

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (struct scsi_extended_sense));

	/* Compute CDB size to use */
	if (start_block > 0xffffffff)
		cdbsize = CDB_GROUP4;
	else if ((start_block & 0xFFE00000) ||
	    (un->un_f_cfg_is_atapi == TRUE))
		cdbsize = CDB_GROUP1;
	else
		cdbsize = CDB_GROUP0;

	switch (cdbsize) {
	case CDB_GROUP0:	/* 6-byte CDBs */
		cdb.scc_cmd = cmd;
		FORMG0ADDR(&cdb, start_block);
		FORMG0COUNT(&cdb, block_count);
		break;
	case CDB_GROUP1:	/* 10-byte CDBs */
		cdb.scc_cmd = cmd | SCMD_GROUP1;
		FORMG1ADDR(&cdb, start_block);
		FORMG1COUNT(&cdb, block_count);
		break;
	case CDB_GROUP4:	/* 16-byte CDBs */
		cdb.scc_cmd = cmd | SCMD_GROUP4;
		FORMG4LONGADDR(&cdb, (uint64_t)start_block);
		FORMG4COUNT(&cdb, block_count);
		break;
	case CDB_GROUP5:	/* 12-byte CDBs (currently unsupported) */
	default:
		/* All others reserved */
		return (EINVAL);
	}

	/* Set LUN bit(s) in CDB if this is a SCSI-1 device */
	SD_FILL_SCSI1_LUN_CDB(un, &cdb);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= (uchar_t)cdbsize;
	ucmd_buf.uscsi_bufaddr	= bufaddr;
	ucmd_buf.uscsi_buflen	= buflen;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags	= flag | USCSI_RQENABLE | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;
	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);
		break;	/* Success! */
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (status == 0) {
		SD_DUMP_MEMORY(un, SD_LOG_IO, "sd_send_scsi_RDWR: data",
		    (uchar_t *)bufaddr, buflen, SD_LOG_HEX);
	}

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_RDWR: exit\n");

	return (status);
}


/*
 *    Function: sd_send_scsi_LOG_SENSE
 *
 * Description: Issue a scsi LOG_SENSE command with the given parameters.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *
 * Return Code: 0   - Success
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_LOG_SENSE(sd_ssc_t *ssc, uchar_t *bufaddr, uint16_t buflen,
	uchar_t page_code, uchar_t page_control, uint16_t param_ptr,
	int path_flag)

{
	struct scsi_extended_sense	sense_buf;
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_LOG_SENSE: entry: un:0x%p\n", un);

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (struct scsi_extended_sense));

	cdb.scc_cmd = SCMD_LOG_SENSE_G1;
	cdb.cdb_opaque[2] = (page_control << 6) | page_code;
	cdb.cdb_opaque[5] = (uchar_t)((param_ptr & 0xFF00) >> 8);
	cdb.cdb_opaque[6] = (uchar_t)(param_ptr  & 0x00FF);
	FORMG1COUNT(&cdb, buflen);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP1;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)bufaddr;
	ucmd_buf.uscsi_buflen	= buflen;
	ucmd_buf.uscsi_rqbuf	= (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen	= sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags	= USCSI_RQENABLE | USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, path_flag);

	switch (status) {
	case 0:
		break;
	case EIO:
		switch (ucmd_buf.uscsi_status) {
		case STATUS_RESERVATION_CONFLICT:
			status = EACCES;
			break;
		case STATUS_CHECK:
			if ((ucmd_buf.uscsi_rqstatus == STATUS_GOOD) &&
			    (scsi_sense_key((uint8_t *)&sense_buf) ==
				KEY_ILLEGAL_REQUEST) &&
			    (scsi_sense_asc((uint8_t *)&sense_buf) == 0x24)) {
				/*
				 * ASC 0x24: INVALID FIELD IN CDB
				 */
				switch (page_code) {
				case START_STOP_CYCLE_PAGE:
					/*
					 * The start stop cycle counter is
					 * implemented as page 0x31 in earlier
					 * generation disks. In new generation
					 * disks the start stop cycle counter is
					 * implemented as page 0xE. To properly
					 * handle this case if an attempt for
					 * log page 0xE is made and fails we
					 * will try again using page 0x31.
					 *
					 * Network storage BU committed to
					 * maintain the page 0x31 for this
					 * purpose and will not have any other
					 * page implemented with page code 0x31
					 * until all disks transition to the
					 * standard page.
					 */
					mutex_enter(SD_MUTEX(un));
					un->un_start_stop_cycle_page =
					    START_STOP_CYCLE_VU_PAGE;
					cdb.cdb_opaque[2] =
					    (char)(page_control << 6) |
					    un->un_start_stop_cycle_page;
					mutex_exit(SD_MUTEX(un));
					sd_ssc_assessment(ssc, SD_FMT_IGNORE);
					status = sd_ssc_send(
					    ssc, &ucmd_buf, FKIOCTL,
					    UIO_SYSSPACE, path_flag);

					break;
				case TEMPERATURE_PAGE:
					status = ENOTTY;
					break;
				default:
					break;
				}
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (status == 0) {
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);
		SD_DUMP_MEMORY(un, SD_LOG_IO, "sd_send_scsi_LOG_SENSE: data",
		    (uchar_t *)bufaddr, buflen, SD_LOG_HEX);
	}

	SD_TRACE(SD_LOG_IO, un, "sd_send_scsi_LOG_SENSE: exit\n");

	return (status);
}


/*
 *    Function: sd_send_scsi_GET_EVENT_STATUS_NOTIFICATION
 *
 * Description: Issue the scsi GET EVENT STATUS NOTIFICATION command.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		bufaddr
 *		buflen
 *		class_req
 *
 * Return Code: 0   - Success
 *		errno return code from sd_ssc_send()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_send_scsi_GET_EVENT_STATUS_NOTIFICATION(sd_ssc_t *ssc, uchar_t *bufaddr,
	size_t buflen, uchar_t class_req)
{
	union scsi_cdb		cdb;
	struct uscsi_cmd	ucmd_buf;
	int			status;
	struct sd_lun		*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(bufaddr != NULL);

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_GET_EVENT_STATUS_NOTIFICATION: entry: un:0x%p\n", un);

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(bufaddr, buflen);

	cdb.scc_cmd = SCMD_GET_EVENT_STATUS_NOTIFICATION;
	cdb.cdb_opaque[1] = 1; /* polled */
	cdb.cdb_opaque[4] = class_req;
	FORMG1COUNT(&cdb, buflen);

	ucmd_buf.uscsi_cdb	= (char *)&cdb;
	ucmd_buf.uscsi_cdblen	= CDB_GROUP1;
	ucmd_buf.uscsi_bufaddr	= (caddr_t)bufaddr;
	ucmd_buf.uscsi_buflen	= buflen;
	ucmd_buf.uscsi_rqbuf	= NULL;
	ucmd_buf.uscsi_rqlen	= 0;
	ucmd_buf.uscsi_flags	= USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout	= 60;

	status = sd_ssc_send(ssc, &ucmd_buf, FKIOCTL,
	    UIO_SYSSPACE, SD_PATH_DIRECT);

	/*
	 * Only handle status == 0, the upper-level caller
	 * will put different assessment based on the context.
	 */
	if (status == 0) {
		sd_ssc_assessment(ssc, SD_FMT_STANDARD);

		if (ucmd_buf.uscsi_resid != 0) {
			status = EIO;
		}
	}

	SD_TRACE(SD_LOG_IO, un,
	    "sd_send_scsi_GET_EVENT_STATUS_NOTIFICATION: exit\n");

	return (status);
}


static boolean_t
sd_gesn_media_data_valid(uchar_t *data)
{
	uint16_t			len;

	len = (data[1] << 8) | data[0];
	return ((len >= 6) &&
	    ((data[2] & SD_GESN_HEADER_NEA) == 0) &&
	    ((data[2] & SD_GESN_HEADER_CLASS) == SD_GESN_MEDIA_CLASS) &&
	    ((data[3] & (1 << SD_GESN_MEDIA_CLASS)) != 0));
}


/*
 *    Function: sdioctl
 *
 * Description: Driver's ioctl(9e) entry point function.
 *
 *   Arguments: dev     - device number
 *		cmd     - ioctl operation to be performed
 *		arg     - user argument, contains data to be set or reference
 *			  parameter for get
 *		flag    - bit flag, indicating open settings, 32/64 bit type
 *		cred_p  - user credential pointer
 *		rval_p  - calling process return value (OPT)
 *
 * Return Code: EINVAL
 *		ENOTTY
 *		ENXIO
 *		EIO
 *		EFAULT
 *		ENOTSUP
 *		EPERM
 *
 *     Context: Called from the device switch at normal priority.
 */

static int
sdioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p, int *rval_p)
{
	struct sd_lun	*un = NULL;
	int		err = 0;
	int		i = 0;
	cred_t		*cr;
	int		tmprval = EINVAL;
	boolean_t	is_valid;
	sd_ssc_t	*ssc;

	/*
	 * All device accesses go thru sdstrategy where we check on suspend
	 * status
	 */
	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	ASSERT(!mutex_owned(SD_MUTEX(un)));

	/* Initialize sd_ssc_t for internal uscsi commands */
	ssc = sd_ssc_init(un);

	is_valid = SD_IS_VALID_LABEL(un);

	/*
	 * Moved this wait from sd_uscsi_strategy to here for
	 * reasons of deadlock prevention. Internal driver commands,
	 * specifically those to change a devices power level, result
	 * in a call to sd_uscsi_strategy.
	 */
	mutex_enter(SD_MUTEX(un));
	while ((un->un_state == SD_STATE_SUSPENDED) ||
	    (un->un_state == SD_STATE_PM_CHANGING)) {
		cv_wait(&un->un_suspend_cv, SD_MUTEX(un));
	}
	/*
	 * Twiddling the counter here protects commands from now
	 * through to the top of sd_uscsi_strategy. Without the
	 * counter inc. a power down, for example, could get in
	 * after the above check for state is made and before
	 * execution gets to the top of sd_uscsi_strategy.
	 * That would cause problems.
	 */
	un->un_ncmds_in_driver++;

	if (!is_valid &&
	    (flag & (FNDELAY | FNONBLOCK))) {
		switch (cmd) {
		case DKIOCGGEOM:	/* SD_PATH_DIRECT */
		case DKIOCGVTOC:
		case DKIOCGEXTVTOC:
		case DKIOCGAPART:
		case DKIOCPARTINFO:
		case DKIOCEXTPARTINFO:
		case DKIOCSGEOM:
		case DKIOCSAPART:
		case DKIOCGETEFI:
		case DKIOCPARTITION:
		case DKIOCSVTOC:
		case DKIOCSEXTVTOC:
		case DKIOCSETEFI:
		case DKIOCGMBOOT:
		case DKIOCSMBOOT:
		case DKIOCG_PHYGEOM:
		case DKIOCG_VIRTGEOM:
#if defined(__i386) || defined(__amd64)
		case DKIOCSETEXTPART:
#endif
			/* let cmlb handle it */
			goto skip_ready_valid;

		case CDROMPAUSE:
		case CDROMRESUME:
		case CDROMPLAYMSF:
		case CDROMPLAYTRKIND:
		case CDROMREADTOCHDR:
		case CDROMREADTOCENTRY:
		case CDROMSTOP:
		case CDROMSTART:
		case CDROMVOLCTRL:
		case CDROMSUBCHNL:
		case CDROMREADMODE2:
		case CDROMREADMODE1:
		case CDROMREADOFFSET:
		case CDROMSBLKMODE:
		case CDROMGBLKMODE:
		case CDROMGDRVSPEED:
		case CDROMSDRVSPEED:
		case CDROMCDDA:
		case CDROMCDXA:
		case CDROMSUBCODE:
			if (!ISCD(un)) {
				un->un_ncmds_in_driver--;
				ASSERT(un->un_ncmds_in_driver >= 0);
				mutex_exit(SD_MUTEX(un));
				err = ENOTTY;
				goto done_without_assess;
			}
			break;
		case FDEJECT:
		case DKIOCEJECT:
		case CDROMEJECT:
			if (!un->un_f_eject_media_supported) {
				un->un_ncmds_in_driver--;
				ASSERT(un->un_ncmds_in_driver >= 0);
				mutex_exit(SD_MUTEX(un));
				err = ENOTTY;
				goto done_without_assess;
			}
			break;
		case DKIOCFLUSHWRITECACHE:
			mutex_exit(SD_MUTEX(un));
			err = sd_send_scsi_TEST_UNIT_READY(ssc, 0);
			if (err != 0) {
				mutex_enter(SD_MUTEX(un));
				un->un_ncmds_in_driver--;
				ASSERT(un->un_ncmds_in_driver >= 0);
				mutex_exit(SD_MUTEX(un));
				err = EIO;
				goto done_quick_assess;
			}
			mutex_enter(SD_MUTEX(un));
			/* FALLTHROUGH */
		case DKIOCREMOVABLE:
		case DKIOCHOTPLUGGABLE:
		case DKIOCINFO:
		case DKIOCGMEDIAINFO:
		case DKIOCGMEDIAINFOEXT:
		case DKIOCSOLIDSTATE:
		case MHIOCENFAILFAST:
		case MHIOCSTATUS:
		case MHIOCTKOWN:
		case MHIOCRELEASE:
		case MHIOCGRP_INKEYS:
		case MHIOCGRP_INRESV:
		case MHIOCGRP_REGISTER:
		case MHIOCGRP_CLEAR:
		case MHIOCGRP_RESERVE:
		case MHIOCGRP_PREEMPTANDABORT:
		case MHIOCGRP_REGISTERANDIGNOREKEY:
		case CDROMCLOSETRAY:
		case USCSICMD:
			goto skip_ready_valid;
		default:
			break;
		}

		mutex_exit(SD_MUTEX(un));
		err = sd_ready_and_valid(ssc, SDPART(dev));
		mutex_enter(SD_MUTEX(un));

		if (err != SD_READY_VALID) {
			switch (cmd) {
			case DKIOCSTATE:
			case CDROMGDRVSPEED:
			case CDROMSDRVSPEED:
			case FDEJECT:	/* for eject command */
			case DKIOCEJECT:
			case CDROMEJECT:
			case DKIOCREMOVABLE:
			case DKIOCHOTPLUGGABLE:
				break;
			default:
				if (un->un_f_has_removable_media) {
					err = ENXIO;
				} else {
				/* Do not map SD_RESERVED_BY_OTHERS to EIO */
					if (err == SD_RESERVED_BY_OTHERS) {
						err = EACCES;
					} else {
						err = EIO;
					}
				}
				un->un_ncmds_in_driver--;
				ASSERT(un->un_ncmds_in_driver >= 0);
				mutex_exit(SD_MUTEX(un));

				goto done_without_assess;
			}
		}
	}

skip_ready_valid:
	mutex_exit(SD_MUTEX(un));

	switch (cmd) {
	case DKIOCINFO:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCINFO\n");
		err = sd_dkio_ctrl_info(dev, (caddr_t)arg, flag);
		break;

	case DKIOCGMEDIAINFO:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCGMEDIAINFO\n");
		err = sd_get_media_info(dev, (caddr_t)arg, flag);
		break;

	case DKIOCGMEDIAINFOEXT:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCGMEDIAINFOEXT\n");
		err = sd_get_media_info_ext(dev, (caddr_t)arg, flag);
		break;

	case DKIOCGGEOM:
	case DKIOCGVTOC:
	case DKIOCGEXTVTOC:
	case DKIOCGAPART:
	case DKIOCPARTINFO:
	case DKIOCEXTPARTINFO:
	case DKIOCSGEOM:
	case DKIOCSAPART:
	case DKIOCGETEFI:
	case DKIOCPARTITION:
	case DKIOCSVTOC:
	case DKIOCSEXTVTOC:
	case DKIOCSETEFI:
	case DKIOCGMBOOT:
	case DKIOCSMBOOT:
	case DKIOCG_PHYGEOM:
	case DKIOCG_VIRTGEOM:
#if defined(__i386) || defined(__amd64)
	case DKIOCSETEXTPART:
#endif
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOC %d\n", cmd);

		/* TUR should spin up */

		if (un->un_f_has_removable_media)
			err = sd_send_scsi_TEST_UNIT_READY(ssc,
			    SD_CHECK_FOR_MEDIA);

		else
			err = sd_send_scsi_TEST_UNIT_READY(ssc, 0);

		if (err != 0)
			goto done_with_assess;

		err = cmlb_ioctl(un->un_cmlbhandle, dev,
		    cmd, arg, flag, cred_p, rval_p, (void *)SD_PATH_DIRECT);

		if ((err == 0) &&
		    ((cmd == DKIOCSETEFI) ||
		    (un->un_f_pkstats_enabled) &&
		    (cmd == DKIOCSAPART || cmd == DKIOCSVTOC ||
		    cmd == DKIOCSEXTVTOC))) {

			tmprval = cmlb_validate(un->un_cmlbhandle, CMLB_SILENT,
			    (void *)SD_PATH_DIRECT);
			if ((tmprval == 0) && un->un_f_pkstats_enabled) {
				sd_set_pstats(un);
				SD_TRACE(SD_LOG_IO_PARTITION, un,
				    "sd_ioctl: un:0x%p pstats created and "
				    "set\n", un);
			}
		}

		if ((cmd == DKIOCSVTOC || cmd == DKIOCSEXTVTOC) ||
		    ((cmd == DKIOCSETEFI) && (tmprval == 0))) {

			mutex_enter(SD_MUTEX(un));
			if (un->un_f_devid_supported &&
			    (un->un_f_opt_fab_devid == TRUE)) {
				if (un->un_devid == NULL) {
					sd_register_devid(ssc, SD_DEVINFO(un),
					    SD_TARGET_IS_UNRESERVED);
				} else {
					/*
					 * The device id for this disk
					 * has been fabricated. The
					 * device id must be preserved
					 * by writing it back out to
					 * disk.
					 */
					if (sd_write_deviceid(ssc) != 0) {
						ddi_devid_free(un->un_devid);
						un->un_devid = NULL;
					}
				}
			}
			mutex_exit(SD_MUTEX(un));
		}

		break;

	case DKIOCLOCK:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCLOCK\n");
		err = sd_send_scsi_DOORLOCK(ssc, SD_REMOVAL_PREVENT,
		    SD_PATH_STANDARD);
		goto done_with_assess;

	case DKIOCUNLOCK:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCUNLOCK\n");
		err = sd_send_scsi_DOORLOCK(ssc, SD_REMOVAL_ALLOW,
		    SD_PATH_STANDARD);
		goto done_with_assess;

	case DKIOCSTATE: {
		enum dkio_state		state;
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCSTATE\n");

		if (ddi_copyin((void *)arg, &state, sizeof (int), flag) != 0) {
			err = EFAULT;
		} else {
			err = sd_check_media(dev, state);
			if (err == 0) {
				if (ddi_copyout(&un->un_mediastate, (void *)arg,
				    sizeof (int), flag) != 0)
					err = EFAULT;
			}
		}
		break;
	}

	case DKIOCREMOVABLE:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCREMOVABLE\n");
		i = un->un_f_has_removable_media ? 1 : 0;
		if (ddi_copyout(&i, (void *)arg, sizeof (int), flag) != 0) {
			err = EFAULT;
		} else {
			err = 0;
		}
		break;

	case DKIOCSOLIDSTATE:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCSOLIDSTATE\n");
		i = un->un_f_is_solid_state ? 1 : 0;
		if (ddi_copyout(&i, (void *)arg, sizeof (int), flag) != 0) {
			err = EFAULT;
		} else {
			err = 0;
		}
		break;

	case DKIOCHOTPLUGGABLE:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCHOTPLUGGABLE\n");
		i = un->un_f_is_hotpluggable ? 1 : 0;
		if (ddi_copyout(&i, (void *)arg, sizeof (int), flag) != 0) {
			err = EFAULT;
		} else {
			err = 0;
		}
		break;

	case DKIOCREADONLY:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCREADONLY\n");
		i = 0;
		if ((ISCD(un) && !un->un_f_mmc_writable_media) ||
		    (sr_check_wp(dev) != 0)) {
			i = 1;
		}
		if (ddi_copyout(&i, (void *)arg, sizeof (int), flag) != 0) {
			err = EFAULT;
		} else {
			err = 0;
		}
		break;

	case DKIOCGTEMPERATURE:
		SD_TRACE(SD_LOG_IOCTL, un, "DKIOCGTEMPERATURE\n");
		err = sd_dkio_get_temp(dev, (caddr_t)arg, flag);
		break;

	case MHIOCENFAILFAST:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCENFAILFAST\n");
		if ((err = drv_priv(cred_p)) == 0) {
			err = sd_mhdioc_failfast(dev, (caddr_t)arg, flag);
		}
		break;

	case MHIOCTKOWN:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCTKOWN\n");
		if ((err = drv_priv(cred_p)) == 0) {
			err = sd_mhdioc_takeown(dev, (caddr_t)arg, flag);
		}
		break;

	case MHIOCRELEASE:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCRELEASE\n");
		if ((err = drv_priv(cred_p)) == 0) {
			err = sd_mhdioc_release(dev);
		}
		break;

	case MHIOCSTATUS:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCSTATUS\n");
		if ((err = drv_priv(cred_p)) == 0) {
			switch (sd_send_scsi_TEST_UNIT_READY(ssc, 0)) {
			case 0:
				err = 0;
				break;
			case EACCES:
				*rval_p = 1;
				err = 0;
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);
				break;
			default:
				err = EIO;
				goto done_with_assess;
			}
		}
		break;

	case MHIOCQRESERVE:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCQRESERVE\n");
		if ((err = drv_priv(cred_p)) == 0) {
			err = sd_reserve_release(dev, SD_RESERVE);
		}
		break;

	case MHIOCREREGISTERDEVID:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCREREGISTERDEVID\n");
		if (drv_priv(cred_p) == EPERM) {
			err = EPERM;
		} else if (!un->un_f_devid_supported) {
			err = ENOTTY;
		} else {
			err = sd_mhdioc_register_devid(dev);
		}
		break;

	case MHIOCGRP_INKEYS:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCGRP_INKEYS\n");
		if (((err = drv_priv(cred_p)) != EPERM) && arg != NULL) {
			if (un->un_reservation_type == SD_SCSI2_RESERVATION) {
				err = ENOTSUP;
			} else {
				err = sd_mhdioc_inkeys(dev, (caddr_t)arg,
				    flag);
			}
		}
		break;

	case MHIOCGRP_INRESV:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCGRP_INRESV\n");
		if (((err = drv_priv(cred_p)) != EPERM) && arg != NULL) {
			if (un->un_reservation_type == SD_SCSI2_RESERVATION) {
				err = ENOTSUP;
			} else {
				err = sd_mhdioc_inresv(dev, (caddr_t)arg, flag);
			}
		}
		break;

	case MHIOCGRP_REGISTER:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCGRP_REGISTER\n");
		if ((err = drv_priv(cred_p)) != EPERM) {
			if (un->un_reservation_type == SD_SCSI2_RESERVATION) {
				err = ENOTSUP;
			} else if (arg != NULL) {
				mhioc_register_t reg;
				if (ddi_copyin((void *)arg, &reg,
				    sizeof (mhioc_register_t), flag) != 0) {
					err = EFAULT;
				} else {
					err =
					    sd_send_scsi_PERSISTENT_RESERVE_OUT(
					    ssc, SD_SCSI3_REGISTER,
					    (uchar_t *)&reg);
					if (err != 0)
						goto done_with_assess;
				}
			}
		}
		break;

	case MHIOCGRP_CLEAR:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCGRP_CLEAR\n");
		if ((err = drv_priv(cred_p)) != EPERM) {
			if (un->un_reservation_type == SD_SCSI2_RESERVATION) {
				err = ENOTSUP;
			} else if (arg != NULL) {
				mhioc_register_t reg;
				if (ddi_copyin((void *)arg, &reg,
				    sizeof (mhioc_register_t), flag) != 0) {
					err = EFAULT;
				} else {
					err =
					    sd_send_scsi_PERSISTENT_RESERVE_OUT(
					    ssc, SD_SCSI3_CLEAR,
					    (uchar_t *)&reg);
					if (err != 0)
						goto done_with_assess;
				}
			}
		}
		break;

	case MHIOCGRP_RESERVE:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCGRP_RESERVE\n");
		if ((err = drv_priv(cred_p)) != EPERM) {
			if (un->un_reservation_type == SD_SCSI2_RESERVATION) {
				err = ENOTSUP;
			} else if (arg != NULL) {
				mhioc_resv_desc_t resv_desc;
				if (ddi_copyin((void *)arg, &resv_desc,
				    sizeof (mhioc_resv_desc_t), flag) != 0) {
					err = EFAULT;
				} else {
					err =
					    sd_send_scsi_PERSISTENT_RESERVE_OUT(
					    ssc, SD_SCSI3_RESERVE,
					    (uchar_t *)&resv_desc);
					if (err != 0)
						goto done_with_assess;
				}
			}
		}
		break;

	case MHIOCGRP_PREEMPTANDABORT:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCGRP_PREEMPTANDABORT\n");
		if ((err = drv_priv(cred_p)) != EPERM) {
			if (un->un_reservation_type == SD_SCSI2_RESERVATION) {
				err = ENOTSUP;
			} else if (arg != NULL) {
				mhioc_preemptandabort_t preempt_abort;
				if (ddi_copyin((void *)arg, &preempt_abort,
				    sizeof (mhioc_preemptandabort_t),
				    flag) != 0) {
					err = EFAULT;
				} else {
					err =
					    sd_send_scsi_PERSISTENT_RESERVE_OUT(
					    ssc, SD_SCSI3_PREEMPTANDABORT,
					    (uchar_t *)&preempt_abort);
					if (err != 0)
						goto done_with_assess;
				}
			}
		}
		break;

	case MHIOCGRP_REGISTERANDIGNOREKEY:
		SD_TRACE(SD_LOG_IOCTL, un, "MHIOCGRP_REGISTERANDIGNOREKEY\n");
		if ((err = drv_priv(cred_p)) != EPERM) {
			if (un->un_reservation_type == SD_SCSI2_RESERVATION) {
				err = ENOTSUP;
			} else if (arg != NULL) {
				mhioc_registerandignorekey_t r_and_i;
				if (ddi_copyin((void *)arg, (void *)&r_and_i,
				    sizeof (mhioc_registerandignorekey_t),
				    flag) != 0) {
					err = EFAULT;
				} else {
					err =
					    sd_send_scsi_PERSISTENT_RESERVE_OUT(
					    ssc, SD_SCSI3_REGISTERANDIGNOREKEY,
					    (uchar_t *)&r_and_i);
					if (err != 0)
						goto done_with_assess;
				}
			}
		}
		break;

	case USCSICMD:
		SD_TRACE(SD_LOG_IOCTL, un, "USCSICMD\n");
		cr = ddi_get_cred();
		if ((drv_priv(cred_p) != 0) && (drv_priv(cr) != 0)) {
			err = EPERM;
		} else {
			enum uio_seg	uioseg;

			uioseg = (flag & FKIOCTL) ? UIO_SYSSPACE :
			    UIO_USERSPACE;
			if (un->un_f_format_in_progress == TRUE) {
				err = EAGAIN;
				break;
			}

			err = sd_ssc_send(ssc,
			    (struct uscsi_cmd *)arg,
			    flag, uioseg, SD_PATH_STANDARD);
			if (err != 0)
				goto done_with_assess;
			else
				sd_ssc_assessment(ssc, SD_FMT_STANDARD);
		}
		break;

	case CDROMPAUSE:
	case CDROMRESUME:
		SD_TRACE(SD_LOG_IOCTL, un, "PAUSE-RESUME\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_pause_resume(dev, cmd);
		}
		break;

	case CDROMPLAYMSF:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMPLAYMSF\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_play_msf(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMPLAYTRKIND:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMPLAYTRKIND\n");
#if defined(__i386) || defined(__amd64)
		/*
		 * not supported on ATAPI CD drives, use CDROMPLAYMSF instead
		 */
		if (!ISCD(un) || (un->un_f_cfg_is_atapi == TRUE)) {
#else
		if (!ISCD(un)) {
#endif
			err = ENOTTY;
		} else {
			err = sr_play_trkind(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMREADTOCHDR:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMREADTOCHDR\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_read_tochdr(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMREADTOCENTRY:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMREADTOCENTRY\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_read_tocentry(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMSTOP:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMSTOP\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sd_send_scsi_START_STOP_UNIT(ssc, SD_START_STOP,
			    SD_TARGET_STOP, SD_PATH_STANDARD);
			goto done_with_assess;
		}
		break;

	case CDROMSTART:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMSTART\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sd_send_scsi_START_STOP_UNIT(ssc, SD_START_STOP,
			    SD_TARGET_START, SD_PATH_STANDARD);
			goto done_with_assess;
		}
		break;

	case CDROMCLOSETRAY:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMCLOSETRAY\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sd_send_scsi_START_STOP_UNIT(ssc, SD_START_STOP,
			    SD_TARGET_CLOSE, SD_PATH_STANDARD);
			goto done_with_assess;
		}
		break;

	case FDEJECT:	/* for eject command */
	case DKIOCEJECT:
	case CDROMEJECT:
		SD_TRACE(SD_LOG_IOCTL, un, "EJECT\n");
		if (!un->un_f_eject_media_supported) {
			err = ENOTTY;
		} else {
			err = sr_eject(dev);
		}
		break;

	case CDROMVOLCTRL:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMVOLCTRL\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_volume_ctrl(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMSUBCHNL:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMSUBCHNL\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_read_subchannel(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMREADMODE2:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMREADMODE2\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else if (un->un_f_cfg_is_atapi == TRUE) {
			/*
			 * If the drive supports READ CD, use that instead of
			 * switching the LBA size via a MODE SELECT
			 * Block Descriptor
			 */
			err = sr_read_cd_mode2(dev, (caddr_t)arg, flag);
		} else {
			err = sr_read_mode2(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMREADMODE1:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMREADMODE1\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_read_mode1(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMREADOFFSET:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMREADOFFSET\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_read_sony_session_offset(dev, (caddr_t)arg,
			    flag);
		}
		break;

	case CDROMSBLKMODE:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMSBLKMODE\n");
		/*
		 * There is no means of changing block size in case of atapi
		 * drives, thus return ENOTTY if drive type is atapi
		 */
		if (!ISCD(un) || (un->un_f_cfg_is_atapi == TRUE)) {
			err = ENOTTY;
		} else if (un->un_f_mmc_cap == TRUE) {

			/*
			 * MMC Devices do not support changing the
			 * logical block size
			 *
			 * Note: EINVAL is being returned instead of ENOTTY to
			 * maintain consistancy with the original mmc
			 * driver update.
			 */
			err = EINVAL;
		} else {
			mutex_enter(SD_MUTEX(un));
			if ((!(un->un_exclopen & (1<<SDPART(dev)))) ||
			    (un->un_ncmds_in_transport > 0)) {
				mutex_exit(SD_MUTEX(un));
				err = EINVAL;
			} else {
				mutex_exit(SD_MUTEX(un));
				err = sr_change_blkmode(dev, cmd, arg, flag);
			}
		}
		break;

	case CDROMGBLKMODE:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMGBLKMODE\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else if ((un->un_f_cfg_is_atapi != FALSE) &&
		    (un->un_f_blockcount_is_valid != FALSE)) {
			/*
			 * Drive is an ATAPI drive so return target block
			 * size for ATAPI drives since we cannot change the
			 * blocksize on ATAPI drives. Used primarily to detect
			 * if an ATAPI cdrom is present.
			 */
			if (ddi_copyout(&un->un_tgt_blocksize, (void *)arg,
			    sizeof (int), flag) != 0) {
				err = EFAULT;
			} else {
				err = 0;
			}

		} else {
			/*
			 * Drive supports changing block sizes via a Mode
			 * Select.
			 */
			err = sr_change_blkmode(dev, cmd, arg, flag);
		}
		break;

	case CDROMGDRVSPEED:
	case CDROMSDRVSPEED:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMXDRVSPEED\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else if (un->un_f_mmc_cap == TRUE) {
			/*
			 * Note: In the future the driver implementation
			 * for getting and
			 * setting cd speed should entail:
			 * 1) If non-mmc try the Toshiba mode page
			 *    (sr_change_speed)
			 * 2) If mmc but no support for Real Time Streaming try
			 *    the SET CD SPEED (0xBB) command
			 *   (sr_atapi_change_speed)
			 * 3) If mmc and support for Real Time Streaming
			 *    try the GET PERFORMANCE and SET STREAMING
			 *    commands (not yet implemented, 4380808)
			 */
			/*
			 * As per recent MMC spec, CD-ROM speed is variable
			 * and changes with LBA. Since there is no such
			 * things as drive speed now, fail this ioctl.
			 *
			 * Note: EINVAL is returned for consistancy of original
			 * implementation which included support for getting
			 * the drive speed of mmc devices but not setting
			 * the drive speed. Thus EINVAL would be returned
			 * if a set request was made for an mmc device.
			 * We no longer support get or set speed for
			 * mmc but need to remain consistent with regard
			 * to the error code returned.
			 */
			err = EINVAL;
		} else if (un->un_f_cfg_is_atapi == TRUE) {
			err = sr_atapi_change_speed(dev, cmd, arg, flag);
		} else {
			err = sr_change_speed(dev, cmd, arg, flag);
		}
		break;

	case CDROMCDDA:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMCDDA\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_read_cdda(dev, (void *)arg, flag);
		}
		break;

	case CDROMCDXA:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMCDXA\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_read_cdxa(dev, (caddr_t)arg, flag);
		}
		break;

	case CDROMSUBCODE:
		SD_TRACE(SD_LOG_IOCTL, un, "CDROMSUBCODE\n");
		if (!ISCD(un)) {
			err = ENOTTY;
		} else {
			err = sr_read_all_subcodes(dev, (caddr_t)arg, flag);
		}
		break;


#ifdef SDDEBUG
/* RESET/ABORTS testing ioctls */
	case DKIOCRESET: {
		int	reset_level;

		if (ddi_copyin((void *)arg, &reset_level, sizeof (int), flag)) {
			err = EFAULT;
		} else {
			SD_INFO(SD_LOG_IOCTL, un, "sdioctl: DKIOCRESET: "
			    "reset_level = 0x%lx\n", reset_level);
			if (scsi_reset(SD_ADDRESS(un), reset_level)) {
				err = 0;
			} else {
				err = EIO;
			}
		}
		break;
	}

	case DKIOCABORT:
		SD_INFO(SD_LOG_IOCTL, un, "sdioctl: DKIOCABORT:\n");
		if (scsi_abort(SD_ADDRESS(un), NULL)) {
			err = 0;
		} else {
			err = EIO;
		}
		break;
#endif

#ifdef SD_FAULT_INJECTION
/* SDIOC FaultInjection testing ioctls */
	case SDIOCSTART:
	case SDIOCSTOP:
	case SDIOCINSERTPKT:
	case SDIOCINSERTXB:
	case SDIOCINSERTUN:
	case SDIOCINSERTARQ:
	case SDIOCPUSH:
	case SDIOCRETRIEVE:
	case SDIOCRUN:
		SD_INFO(SD_LOG_SDTEST, un, "sdioctl:"
		    "SDIOC detected cmd:0x%X:\n", cmd);
		/* call error generator */
		sd_faultinjection_ioctl(cmd, arg, un);
		err = 0;
		break;

#endif /* SD_FAULT_INJECTION */

	case DKIOCFLUSHWRITECACHE:
		{
			struct dk_callback *dkc = (struct dk_callback *)arg;

			mutex_enter(SD_MUTEX(un));
			if (!un->un_f_sync_cache_supported ||
			    !un->un_f_write_cache_enabled) {
				err = un->un_f_sync_cache_supported ?
				    0 : ENOTSUP;
				mutex_exit(SD_MUTEX(un));
				if ((flag & FKIOCTL) && dkc != NULL &&
				    dkc->dkc_callback != NULL) {
					(*dkc->dkc_callback)(dkc->dkc_cookie,
					    err);
					/*
					 * Did callback and reported error.
					 * Since we did a callback, ioctl
					 * should return 0.
					 */
					err = 0;
				}
				break;
			}
			mutex_exit(SD_MUTEX(un));

			if ((flag & FKIOCTL) && dkc != NULL &&
			    dkc->dkc_callback != NULL) {
				/* async SYNC CACHE request */
				err = sd_send_scsi_SYNCHRONIZE_CACHE(un, dkc);
			} else {
				/* synchronous SYNC CACHE request */
				err = sd_send_scsi_SYNCHRONIZE_CACHE(un, NULL);
			}
		}
		break;

	case DKIOCGETWCE: {

		int wce;

		if ((err = sd_get_write_cache_enabled(ssc, &wce)) != 0) {
			break;
		}

		if (ddi_copyout(&wce, (void *)arg, sizeof (wce), flag)) {
			err = EFAULT;
		}
		break;
	}

	case DKIOCSETWCE: {

		int wce, sync_supported;
		int cur_wce = 0;

		if (ddi_copyin((void *)arg, &wce, sizeof (wce), flag)) {
			err = EFAULT;
			break;
		}

		/*
		 * Synchronize multiple threads trying to enable
		 * or disable the cache via the un_f_wcc_cv
		 * condition variable.
		 */
		mutex_enter(SD_MUTEX(un));

		/*
		 * Don't allow the cache to be enabled if the
		 * config file has it disabled.
		 */
		if (un->un_f_opt_disable_cache && wce) {
			mutex_exit(SD_MUTEX(un));
			err = EINVAL;
			break;
		}

		/*
		 * Wait for write cache change in progress
		 * bit to be clear before proceeding.
		 */
		while (un->un_f_wcc_inprog)
			cv_wait(&un->un_wcc_cv, SD_MUTEX(un));

		un->un_f_wcc_inprog = 1;

		mutex_exit(SD_MUTEX(un));

		/*
		 * Get the current write cache state
		 */
		if ((err = sd_get_write_cache_enabled(ssc, &cur_wce)) != 0) {
			mutex_enter(SD_MUTEX(un));
			un->un_f_wcc_inprog = 0;
			cv_broadcast(&un->un_wcc_cv);
			mutex_exit(SD_MUTEX(un));
			break;
		}

		mutex_enter(SD_MUTEX(un));
		un->un_f_write_cache_enabled = (cur_wce != 0);

		if (un->un_f_write_cache_enabled && wce == 0) {
			/*
			 * Disable the write cache.  Don't clear
			 * un_f_write_cache_enabled until after
			 * the mode select and flush are complete.
			 */
			sync_supported = un->un_f_sync_cache_supported;

			/*
			 * If cache flush is suppressed, we assume that the
			 * controller firmware will take care of managing the
			 * write cache for us: no need to explicitly
			 * disable it.
			 */
			if (!un->un_f_suppress_cache_flush) {
				mutex_exit(SD_MUTEX(un));
				if ((err = sd_cache_control(ssc,
				    SD_CACHE_NOCHANGE,
				    SD_CACHE_DISABLE)) == 0 &&
				    sync_supported) {
					err = sd_send_scsi_SYNCHRONIZE_CACHE(un,
					    NULL);
				}
			} else {
				mutex_exit(SD_MUTEX(un));
			}

			mutex_enter(SD_MUTEX(un));
			if (err == 0) {
				un->un_f_write_cache_enabled = 0;
			}

		} else if (!un->un_f_write_cache_enabled && wce != 0) {
			/*
			 * Set un_f_write_cache_enabled first, so there is
			 * no window where the cache is enabled, but the
			 * bit says it isn't.
			 */
			un->un_f_write_cache_enabled = 1;

			/*
			 * If cache flush is suppressed, we assume that the
			 * controller firmware will take care of managing the
			 * write cache for us: no need to explicitly
			 * enable it.
			 */
			if (!un->un_f_suppress_cache_flush) {
				mutex_exit(SD_MUTEX(un));
				err = sd_cache_control(ssc, SD_CACHE_NOCHANGE,
				    SD_CACHE_ENABLE);
			} else {
				mutex_exit(SD_MUTEX(un));
			}

			mutex_enter(SD_MUTEX(un));

			if (err) {
				un->un_f_write_cache_enabled = 0;
			}
		}

		un->un_f_wcc_inprog = 0;
		cv_broadcast(&un->un_wcc_cv);
		mutex_exit(SD_MUTEX(un));
		break;
	}

	default:
		err = ENOTTY;
		break;
	}
	mutex_enter(SD_MUTEX(un));
	un->un_ncmds_in_driver--;
	ASSERT(un->un_ncmds_in_driver >= 0);
	mutex_exit(SD_MUTEX(un));


done_without_assess:
	sd_ssc_fini(ssc);

	SD_TRACE(SD_LOG_IOCTL, un, "sdioctl: exit: %d\n", err);
	return (err);

done_with_assess:
	mutex_enter(SD_MUTEX(un));
	un->un_ncmds_in_driver--;
	ASSERT(un->un_ncmds_in_driver >= 0);
	mutex_exit(SD_MUTEX(un));

done_quick_assess:
	if (err != 0)
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	/* Uninitialize sd_ssc_t pointer */
	sd_ssc_fini(ssc);

	SD_TRACE(SD_LOG_IOCTL, un, "sdioctl: exit: %d\n", err);
	return (err);
}


/*
 *    Function: sd_dkio_ctrl_info
 *
 * Description: This routine is the driver entry point for handling controller
 *		information ioctl requests (DKIOCINFO).
 *
 *   Arguments: dev  - the device number
 *		arg  - pointer to user provided dk_cinfo structure
 *		       specifying the controller type and attributes.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 */

static int
sd_dkio_ctrl_info(dev_t dev, caddr_t arg, int flag)
{
	struct sd_lun	*un = NULL;
	struct dk_cinfo	*info;
	dev_info_t	*pdip;
	int		lun, tgt;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	info = (struct dk_cinfo *)
	    kmem_zalloc(sizeof (struct dk_cinfo), KM_SLEEP);

	switch (un->un_ctype) {
	case CTYPE_CDROM:
		info->dki_ctype = DKC_CDROM;
		break;
	default:
		info->dki_ctype = DKC_SCSI_CCS;
		break;
	}
	pdip = ddi_get_parent(SD_DEVINFO(un));
	info->dki_cnum = ddi_get_instance(pdip);
	if (strlen(ddi_get_name(pdip)) < DK_DEVLEN) {
		(void) strcpy(info->dki_cname, ddi_get_name(pdip));
	} else {
		(void) strncpy(info->dki_cname, ddi_node_name(pdip),
		    DK_DEVLEN - 1);
	}

	lun = ddi_prop_get_int(DDI_DEV_T_ANY, SD_DEVINFO(un),
	    DDI_PROP_DONTPASS, SCSI_ADDR_PROP_LUN, 0);
	tgt = ddi_prop_get_int(DDI_DEV_T_ANY, SD_DEVINFO(un),
	    DDI_PROP_DONTPASS, SCSI_ADDR_PROP_TARGET, 0);

	/* Unit Information */
	info->dki_unit = ddi_get_instance(SD_DEVINFO(un));
	info->dki_slave = ((tgt << 3) | lun);
	(void) strncpy(info->dki_dname, ddi_driver_name(SD_DEVINFO(un)),
	    DK_DEVLEN - 1);
	info->dki_flags = DKI_FMTVOL;
	info->dki_partition = SDPART(dev);

	/* Max Transfer size of this device in blocks */
	info->dki_maxtransfer = un->un_max_xfer_size / un->un_sys_blocksize;
	info->dki_addr = 0;
	info->dki_space = 0;
	info->dki_prio = 0;
	info->dki_vec = 0;

	if (ddi_copyout(info, arg, sizeof (struct dk_cinfo), flag) != 0) {
		kmem_free(info, sizeof (struct dk_cinfo));
		return (EFAULT);
	} else {
		kmem_free(info, sizeof (struct dk_cinfo));
		return (0);
	}
}

/*
 *    Function: sd_get_media_info_com
 *
 * Description: This routine returns the information required to populate
 *		the fields for the dk_minfo/dk_minfo_ext structures.
 *
 *   Arguments: dev		- the device number
 *		dki_media_type	- media_type
 *		dki_lbsize	- logical block size
 *		dki_capacity	- capacity in blocks
 *		dki_pbsize	- physical block size (if requested)
 *
 * Return Code: 0
 *		EACCESS
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
sd_get_media_info_com(dev_t dev, uint_t *dki_media_type, uint_t *dki_lbsize,
	diskaddr_t *dki_capacity, uint_t *dki_pbsize)
{
	struct sd_lun		*un = NULL;
	struct uscsi_cmd	com;
	struct scsi_inquiry	*sinq;
	u_longlong_t		media_capacity;
	uint64_t		capacity;
	uint_t			lbasize;
	uint_t			pbsize;
	uchar_t			*out_data;
	uchar_t			*rqbuf;
	int			rval = 0;
	int			rtn;
	sd_ssc_t		*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	SD_TRACE(SD_LOG_IOCTL_DKIO, un, "sd_get_media_info_com: entry\n");

	out_data = kmem_zalloc(SD_PROFILE_HEADER_LEN, KM_SLEEP);
	rqbuf = kmem_zalloc(SENSE_LENGTH, KM_SLEEP);
	ssc = sd_ssc_init(un);

	/* Issue a TUR to determine if the drive is ready with media present */
	rval = sd_send_scsi_TEST_UNIT_READY(ssc, SD_CHECK_FOR_MEDIA);
	if (rval == ENXIO) {
		goto done;
	} else if (rval != 0) {
		sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}

	/* Now get configuration data */
	if (ISCD(un)) {
		*dki_media_type = DK_CDROM;

		/* Allow SCMD_GET_CONFIGURATION to MMC devices only */
		if (un->un_f_mmc_cap == TRUE) {
			rtn = sd_send_scsi_GET_CONFIGURATION(ssc, &com, rqbuf,
			    SENSE_LENGTH, out_data, SD_PROFILE_HEADER_LEN,
			    SD_PATH_STANDARD);

			if (rtn) {
				/*
				 * We ignore all failures for CD and need to
				 * put the assessment before processing code
				 * to avoid missing assessment for FMA.
				 */
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);
				/*
				 * Failed for other than an illegal request
				 * or command not supported
				 */
				if ((com.uscsi_status == STATUS_CHECK) &&
				    (com.uscsi_rqstatus == STATUS_GOOD)) {
					if ((rqbuf[2] != KEY_ILLEGAL_REQUEST) ||
					    (rqbuf[12] != 0x20)) {
						rval = EIO;
						goto no_assessment;
					}
				}
			} else {
				/*
				 * The GET CONFIGURATION command succeeded
				 * so set the media type according to the
				 * returned data
				 */
				*dki_media_type = out_data[6];
				*dki_media_type <<= 8;
				*dki_media_type |= out_data[7];
			}
		}
	} else {
		/*
		 * The profile list is not available, so we attempt to identify
		 * the media type based on the inquiry data
		 */
		sinq = un->un_sd->sd_inq;
		if ((sinq->inq_dtype == DTYPE_DIRECT) ||
		    (sinq->inq_dtype == DTYPE_OPTICAL)) {
			/* This is a direct access device  or optical disk */
			*dki_media_type = DK_FIXED_DISK;

			if ((bcmp(sinq->inq_vid, "IOMEGA", 6) == 0) ||
			    (bcmp(sinq->inq_vid, "iomega", 6) == 0)) {
				if ((bcmp(sinq->inq_pid, "ZIP", 3) == 0)) {
					*dki_media_type = DK_ZIP;
				} else if (
				    (bcmp(sinq->inq_pid, "jaz", 3) == 0)) {
					*dki_media_type = DK_JAZ;
				}
			}
		} else {
			/*
			 * Not a CD, direct access or optical disk so return
			 * unknown media
			 */
			*dki_media_type = DK_UNKNOWN;
		}
	}

	/*
	 * Now read the capacity so we can provide the lbasize,
	 * pbsize and capacity.
	 */
	if (dki_pbsize && un->un_f_descr_format_supported) {
		rval = sd_send_scsi_READ_CAPACITY_16(ssc, &capacity, &lbasize,
		    &pbsize, SD_PATH_DIRECT);

		/*
		 * Override the physical blocksize if the instance already
		 * has a larger value.
		 */
		pbsize = MAX(pbsize, un->un_phy_blocksize);
	}

	if (dki_pbsize == NULL || rval != 0 ||
	    !un->un_f_descr_format_supported) {
		rval = sd_send_scsi_READ_CAPACITY(ssc, &capacity, &lbasize,
		    SD_PATH_DIRECT);

		switch (rval) {
		case 0:
			if (un->un_f_enable_rmw &&
			    un->un_phy_blocksize != 0) {
				pbsize = un->un_phy_blocksize;
			} else {
				pbsize = lbasize;
			}
			media_capacity = capacity;

			/*
			 * sd_send_scsi_READ_CAPACITY() reports capacity in
			 * un->un_sys_blocksize chunks. So we need to convert
			 * it into cap.lbsize chunks.
			 */
			if (un->un_f_has_removable_media) {
				media_capacity *= un->un_sys_blocksize;
				media_capacity /= lbasize;
			}
			break;
		case EACCES:
			rval = EACCES;
			goto done;
		default:
			rval = EIO;
			goto done;
		}
	} else {
		if (un->un_f_enable_rmw &&
		    !ISP2(pbsize % DEV_BSIZE)) {
			pbsize = SSD_SECSIZE;
		} else if (!ISP2(lbasize % DEV_BSIZE) ||
		    !ISP2(pbsize % DEV_BSIZE)) {
			pbsize = lbasize = DEV_BSIZE;
		}
		media_capacity = capacity;
	}

	/*
	 * If lun is expanded dynamically, update the un structure.
	 */
	mutex_enter(SD_MUTEX(un));
	if ((un->un_f_blockcount_is_valid == TRUE) &&
	    (un->un_f_tgt_blocksize_is_valid == TRUE) &&
	    (capacity > un->un_blockcount)) {
		un->un_f_expnevent = B_FALSE;
		sd_update_block_info(un, lbasize, capacity);
	}
	mutex_exit(SD_MUTEX(un));

	*dki_lbsize = lbasize;
	*dki_capacity = media_capacity;
	if (dki_pbsize)
		*dki_pbsize = pbsize;

done:
	if (rval != 0) {
		if (rval == EIO)
			sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
		else
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}
no_assessment:
	sd_ssc_fini(ssc);
	kmem_free(out_data, SD_PROFILE_HEADER_LEN);
	kmem_free(rqbuf, SENSE_LENGTH);
	return (rval);
}

/*
 *    Function: sd_get_media_info
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests for the media type or command set profile used by the
 *		drive to operate on the media (DKIOCGMEDIAINFO).
 *
 *   Arguments: dev	- the device number
 *		arg	- pointer to user provided dk_minfo structure
 *			  specifying the media type, logical block size and
 *			  drive capacity.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: returns the value from sd_get_media_info_com
 */
static int
sd_get_media_info(dev_t dev, caddr_t arg, int flag)
{
	struct dk_minfo		mi;
	int			rval;

	rval = sd_get_media_info_com(dev, &mi.dki_media_type,
	    &mi.dki_lbsize, &mi.dki_capacity, NULL);

	if (rval)
		return (rval);
	if (ddi_copyout(&mi, arg, sizeof (struct dk_minfo), flag))
		rval = EFAULT;
	return (rval);
}

/*
 *    Function: sd_get_media_info_ext
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests for the media type or command set profile used by the
 *		drive to operate on the media (DKIOCGMEDIAINFOEXT). The
 *		difference this ioctl and DKIOCGMEDIAINFO is the return value
 *		of this ioctl contains both logical block size and physical
 *		block size.
 *
 *
 *   Arguments: dev	- the device number
 *		arg	- pointer to user provided dk_minfo_ext structure
 *			  specifying the media type, logical block size,
 *			  physical block size and disk capacity.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: returns the value from sd_get_media_info_com
 */
static int
sd_get_media_info_ext(dev_t dev, caddr_t arg, int flag)
{
	struct dk_minfo_ext	mie;
	int			rval = 0;

	rval = sd_get_media_info_com(dev, &mie.dki_media_type,
	    &mie.dki_lbsize, &mie.dki_capacity, &mie.dki_pbsize);

	if (rval)
		return (rval);
	if (ddi_copyout(&mie, arg, sizeof (struct dk_minfo_ext), flag))
		rval = EFAULT;
	return (rval);

}

/*
 *    Function: sd_watch_request_submit
 *
 * Description: Call scsi_watch_request_submit or scsi_mmc_watch_request_submit
 *		depending on which is supported by device.
 */
static opaque_t
sd_watch_request_submit(struct sd_lun *un)
{
	dev_t			dev;

	/* All submissions are unified to use same device number */
	dev = sd_make_device(SD_DEVINFO(un));

	if (un->un_f_mmc_cap && un->un_f_mmc_gesn_polling) {
		return (scsi_mmc_watch_request_submit(SD_SCSI_DEVP(un),
		    sd_check_media_time, SENSE_LENGTH, sd_media_watch_cb,
		    (caddr_t)dev));
	} else {
		return (scsi_watch_request_submit(SD_SCSI_DEVP(un),
		    sd_check_media_time, SENSE_LENGTH, sd_media_watch_cb,
		    (caddr_t)dev));
	}
}


/*
 *    Function: sd_check_media
 *
 * Description: This utility routine implements the functionality for the
 *		DKIOCSTATE ioctl. This ioctl blocks the user thread until the
 *		driver state changes from that specified by the user
 *		(inserted or ejected). For example, if the user specifies
 *		DKIO_EJECTED and the current media state is inserted this
 *		routine will immediately return DKIO_INSERTED. However, if the
 *		current media state is not inserted the user thread will be
 *		blocked until the drive state changes. If DKIO_NONE is specified
 *		the user thread will block until a drive state change occurs.
 *
 *   Arguments: dev  - the device number
 *		state  - user pointer to a dkio_state, updated with the current
 *			drive state at return.
 *
 * Return Code: ENXIO
 *		EIO
 *		EAGAIN
 *		EINTR
 */

static int
sd_check_media(dev_t dev, enum dkio_state state)
{
	struct sd_lun		*un = NULL;
	enum dkio_state		prev_state;
	opaque_t		token = NULL;
	int			rval = 0;
	sd_ssc_t		*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	SD_TRACE(SD_LOG_COMMON, un, "sd_check_media: entry\n");

	ssc = sd_ssc_init(un);

	mutex_enter(SD_MUTEX(un));

	SD_TRACE(SD_LOG_COMMON, un, "sd_check_media: "
	    "state=%x, mediastate=%x\n", state, un->un_mediastate);

	prev_state = un->un_mediastate;

	/* is there anything to do? */
	if (state == un->un_mediastate || un->un_mediastate == DKIO_NONE) {
		/*
		 * submit the request to the scsi_watch service;
		 * scsi_media_watch_cb() does the real work
		 */
		mutex_exit(SD_MUTEX(un));

		/*
		 * This change handles the case where a scsi watch request is
		 * added to a device that is powered down. To accomplish this
		 * we power up the device before adding the scsi watch request,
		 * since the scsi watch sends a TUR directly to the device
		 * which the device cannot handle if it is powered down.
		 */
		if (sd_pm_entry(un) != DDI_SUCCESS) {
			mutex_enter(SD_MUTEX(un));
			goto done;
		}

		token = sd_watch_request_submit(un);

		sd_pm_exit(un);

		mutex_enter(SD_MUTEX(un));
		if (token == NULL) {
			rval = EAGAIN;
			goto done;
		}

		/*
		 * This is a special case IOCTL that doesn't return
		 * until the media state changes. Routine sdpower
		 * knows about and handles this so don't count it
		 * as an active cmd in the driver, which would
		 * keep the device busy to the pm framework.
		 * If the count isn't decremented the device can't
		 * be powered down.
		 */
		un->un_ncmds_in_driver--;
		ASSERT(un->un_ncmds_in_driver >= 0);

		/*
		 * if a prior request had been made, this will be the same
		 * token, as scsi_watch was designed that way.
		 */
		un->un_swr_token = token;
		un->un_specified_mediastate = state;

		/*
		 * now wait for media change
		 * we will not be signalled unless mediastate == state but it is
		 * still better to test for this condition, since there is a
		 * 2 sec cv_broadcast delay when mediastate == DKIO_INSERTED
		 */
		SD_TRACE(SD_LOG_COMMON, un,
		    "sd_check_media: waiting for media state change\n");
		while (un->un_mediastate == state) {
			if (cv_wait_sig(&un->un_state_cv, SD_MUTEX(un)) == 0) {
				SD_TRACE(SD_LOG_COMMON, un,
				    "sd_check_media: waiting for media state "
				    "was interrupted\n");
				un->un_ncmds_in_driver++;
				rval = EINTR;
				goto done;
			}
			SD_TRACE(SD_LOG_COMMON, un,
			    "sd_check_media: received signal, state=%x\n",
			    un->un_mediastate);
		}
		/*
		 * Inc the counter to indicate the device once again
		 * has an active outstanding cmd.
		 */
		un->un_ncmds_in_driver++;
	}

	/* invalidate geometry */
	if (prev_state == DKIO_INSERTED && un->un_mediastate == DKIO_EJECTED) {
		sr_ejected(un);
	}

	if (un->un_mediastate == DKIO_INSERTED && prev_state != DKIO_INSERTED) {
		uint64_t	capacity;
		uint_t		lbasize;

		SD_TRACE(SD_LOG_COMMON, un, "sd_check_media: media inserted\n");
		mutex_exit(SD_MUTEX(un));
		/*
		 * Since the following routines use SD_PATH_DIRECT, we must
		 * call PM directly before the upcoming disk accesses. This
		 * may cause the disk to be power/spin up.
		 */

		if (sd_pm_entry(un) == DDI_SUCCESS) {
			rval = sd_send_scsi_READ_CAPACITY(ssc,
			    &capacity, &lbasize, SD_PATH_DIRECT);
			if (rval != 0) {
				sd_pm_exit(un);
				if (rval == EIO)
					sd_ssc_assessment(ssc,
					    SD_FMT_STATUS_CHECK);
				else
					sd_ssc_assessment(ssc, SD_FMT_IGNORE);
				mutex_enter(SD_MUTEX(un));
				goto done;
			}
		} else {
			rval = EIO;
			mutex_enter(SD_MUTEX(un));
			goto done;
		}
		mutex_enter(SD_MUTEX(un));

		sd_update_block_info(un, lbasize, capacity);

		/*
		 *  Check if the media in the device is writable or not
		 */
		if (ISCD(un)) {
			sd_check_for_writable_cd(ssc, SD_PATH_DIRECT);
		}

		mutex_exit(SD_MUTEX(un));
		cmlb_invalidate(un->un_cmlbhandle, (void *)SD_PATH_DIRECT);
		if ((cmlb_validate(un->un_cmlbhandle, 0,
		    (void *)SD_PATH_DIRECT) == 0) && un->un_f_pkstats_enabled) {
			sd_set_pstats(un);
			SD_TRACE(SD_LOG_IO_PARTITION, un,
			    "sd_check_media: un:0x%p pstats created and "
			    "set\n", un);
		}

		rval = sd_send_scsi_DOORLOCK(ssc, SD_REMOVAL_PREVENT,
		    SD_PATH_DIRECT);

		sd_pm_exit(un);

		if (rval != 0) {
			if (rval == EIO)
				sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
			else
				sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		}

		mutex_enter(SD_MUTEX(un));
	}
done:
	sd_ssc_fini(ssc);
	un->un_f_watcht_stopped = FALSE;
	if (token != NULL && un->un_swr_token != NULL) {
		/*
		 * Use of this local token and the mutex ensures that we avoid
		 * some race conditions associated with terminating the
		 * scsi watch.
		 */
		token = un->un_swr_token;
		mutex_exit(SD_MUTEX(un));
		(void) scsi_watch_request_terminate(token,
		    SCSI_WATCH_TERMINATE_WAIT);
		if (scsi_watch_get_ref_count(token) == 0) {
			mutex_enter(SD_MUTEX(un));
			un->un_swr_token = (opaque_t)NULL;
		} else {
			mutex_enter(SD_MUTEX(un));
		}
	}

	/*
	 * Update the capacity kstat value, if no media previously
	 * (capacity kstat is 0) and a media has been inserted
	 * (un_f_blockcount_is_valid == TRUE)
	 */
	if (un->un_errstats) {
		struct sd_errstats	*stp = NULL;

		stp = (struct sd_errstats *)un->un_errstats->ks_data;
		if ((stp->sd_capacity.value.ui64 == 0) &&
		    (un->un_f_blockcount_is_valid == TRUE)) {
			stp->sd_capacity.value.ui64 =
			    (uint64_t)((uint64_t)un->un_blockcount *
			    un->un_sys_blocksize);
		}
	}
	mutex_exit(SD_MUTEX(un));
	SD_TRACE(SD_LOG_COMMON, un, "sd_check_media: done\n");
	return (rval);
}


/*
 *    Function: sd_delayed_cv_broadcast
 *
 * Description: Delayed cv_broadcast to allow for target to recover from media
 *		insertion.
 *
 *   Arguments: arg - driver soft state (unit) structure
 */

static void
sd_delayed_cv_broadcast(void *arg)
{
	struct sd_lun *un = arg;

	SD_TRACE(SD_LOG_COMMON, un, "sd_delayed_cv_broadcast\n");

	mutex_enter(SD_MUTEX(un));
	un->un_dcvb_timeid = NULL;
	cv_broadcast(&un->un_state_cv);
	mutex_exit(SD_MUTEX(un));
}


/*
 *    Function: sd_media_watch_cb
 *
 * Description: Callback routine used for support of the DKIOCSTATE ioctl. This
 *		routine processes the TUR sense data and updates the driver
 *		state if a transition has occurred. The user thread
 *		(sd_check_media) is then signalled.
 *
 *   Arguments: arg -   the device 'dev_t' is used for context to discriminate
 *			among multiple watches that share this callback function
 *		resultp - scsi watch facility result packet containing scsi
 *			  packet, status byte and sense data
 *
 * Return Code: 0 for success, -1 for failure
 */

static int
sd_media_watch_cb(caddr_t arg, struct scsi_watch_result *resultp)
{
	struct sd_lun			*un;
	struct scsi_status		*statusp = resultp->statusp;
	uint8_t				*sensep = (uint8_t *)resultp->sensep;
	enum dkio_state			state = DKIO_NONE;
	dev_t				dev = (dev_t)arg;
	uchar_t				actual_sense_length;
	uint8_t				skey, asc, ascq;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (-1);
	}
	actual_sense_length = resultp->actual_sense_length;

	mutex_enter(SD_MUTEX(un));
	SD_TRACE(SD_LOG_COMMON, un,
	    "sd_media_watch_cb: status=%x, sensep=%p, len=%x\n",
	    *((char *)statusp), (void *)sensep, actual_sense_length);

	if (resultp->pkt->pkt_reason == CMD_DEV_GONE) {
		un->un_mediastate = DKIO_DEV_GONE;
		cv_broadcast(&un->un_state_cv);
		mutex_exit(SD_MUTEX(un));

		return (0);
	}

	if (un->un_f_mmc_cap && un->un_f_mmc_gesn_polling) {
		if (sd_gesn_media_data_valid(resultp->mmc_data)) {
			if ((resultp->mmc_data[5] &
			    SD_GESN_MEDIA_EVENT_STATUS_PRESENT) != 0) {
				state = DKIO_INSERTED;
			} else {
				state = DKIO_EJECTED;
			}
			if ((resultp->mmc_data[4] & SD_GESN_MEDIA_EVENT_CODE) ==
			    SD_GESN_MEDIA_EVENT_EJECTREQUEST) {
				sd_log_eject_request_event(un, KM_NOSLEEP);
			}
		}
	} else if (sensep != NULL) {
		/*
		 * If there was a check condition then sensep points to valid
		 * sense data. If status was not a check condition but a
		 * reservation or busy status then the new state is DKIO_NONE.
		 */
		skey = scsi_sense_key(sensep);
		asc = scsi_sense_asc(sensep);
		ascq = scsi_sense_ascq(sensep);

		SD_INFO(SD_LOG_COMMON, un,
		    "sd_media_watch_cb: sense KEY=%x, ASC=%x, ASCQ=%x\n",
		    skey, asc, ascq);
		/* This routine only uses up to 13 bytes of sense data. */
		if (actual_sense_length >= 13) {
			if (skey == KEY_UNIT_ATTENTION) {
				if (asc == 0x28) {
					state = DKIO_INSERTED;
				}
			} else if (skey == KEY_NOT_READY) {
				/*
				 * Sense data of 02/06/00 means that the
				 * drive could not read the media (No
				 * reference position found). In this case
				 * to prevent a hang on the DKIOCSTATE IOCTL
				 * we set the media state to DKIO_INSERTED.
				 */
				if (asc == 0x06 && ascq == 0x00)
					state = DKIO_INSERTED;

				/*
				 * if 02/04/02  means that the host
				 * should send start command. Explicitly
				 * leave the media state as is
				 * (inserted) as the media is inserted
				 * and host has stopped device for PM
				 * reasons. Upon next true read/write
				 * to this media will bring the
				 * device to the right state good for
				 * media access.
				 */
				if (asc == 0x3a) {
					state = DKIO_EJECTED;
				} else {
					/*
					 * If the drive is busy with an
					 * operation or long write, keep the
					 * media in an inserted state.
					 */

					if ((asc == 0x04) &&
					    ((ascq == 0x02) ||
					    (ascq == 0x07) ||
					    (ascq == 0x08))) {
						state = DKIO_INSERTED;
					}
				}
			} else if (skey == KEY_NO_SENSE) {
				if ((asc == 0x00) && (ascq == 0x00)) {
					/*
					 * Sense Data 00/00/00 does not provide
					 * any information about the state of
					 * the media. Ignore it.
					 */
					mutex_exit(SD_MUTEX(un));
					return (0);
				}
			}
		}
	} else if ((*((char *)statusp) == STATUS_GOOD) &&
	    (resultp->pkt->pkt_reason == CMD_CMPLT)) {
		state = DKIO_INSERTED;
	}

	SD_TRACE(SD_LOG_COMMON, un,
	    "sd_media_watch_cb: state=%x, specified=%x\n",
	    state, un->un_specified_mediastate);

	/*
	 * now signal the waiting thread if this is *not* the specified state;
	 * delay the signal if the state is DKIO_INSERTED to allow the target
	 * to recover
	 */
	if (state != un->un_specified_mediastate) {
		un->un_mediastate = state;
		if (state == DKIO_INSERTED) {
			/*
			 * delay the signal to give the drive a chance
			 * to do what it apparently needs to do
			 */
			SD_TRACE(SD_LOG_COMMON, un,
			    "sd_media_watch_cb: delayed cv_broadcast\n");
			if (un->un_dcvb_timeid == NULL) {
				un->un_dcvb_timeid =
				    timeout(sd_delayed_cv_broadcast, un,
				    drv_usectohz((clock_t)MEDIA_ACCESS_DELAY));
			}
		} else {
			SD_TRACE(SD_LOG_COMMON, un,
			    "sd_media_watch_cb: immediate cv_broadcast\n");
			cv_broadcast(&un->un_state_cv);
		}
	}
	mutex_exit(SD_MUTEX(un));
	return (0);
}


/*
 *    Function: sd_dkio_get_temp
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests to get the disk temperature.
 *
 *   Arguments: dev  - the device number
 *		arg  - pointer to user provided dk_temperature structure.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EAGAIN
 */

static int
sd_dkio_get_temp(dev_t dev, caddr_t arg, int flag)
{
	struct sd_lun		*un = NULL;
	struct dk_temperature	*dktemp = NULL;
	uchar_t			*temperature_page;
	int			rval = 0;
	int			path_flag = SD_PATH_STANDARD;
	sd_ssc_t		*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	ssc = sd_ssc_init(un);
	dktemp = kmem_zalloc(sizeof (struct dk_temperature), KM_SLEEP);

	/* copyin the disk temp argument to get the user flags */
	if (ddi_copyin((void *)arg, dktemp,
	    sizeof (struct dk_temperature), flag) != 0) {
		rval = EFAULT;
		goto done;
	}

	/* Initialize the temperature to invalid. */
	dktemp->dkt_cur_temp = (short)DKT_INVALID_TEMP;
	dktemp->dkt_ref_temp = (short)DKT_INVALID_TEMP;

	/*
	 * Note: Investigate removing the "bypass pm" semantic.
	 * Can we just bypass PM always?
	 */
	if (dktemp->dkt_flags & DKT_BYPASS_PM) {
		path_flag = SD_PATH_DIRECT;
		ASSERT(!mutex_owned(&un->un_pm_mutex));
		mutex_enter(&un->un_pm_mutex);
		if (SD_DEVICE_IS_IN_LOW_POWER(un)) {
			/*
			 * If DKT_BYPASS_PM is set, and the drive happens to be
			 * in low power mode, we can not wake it up, Need to
			 * return EAGAIN.
			 */
			mutex_exit(&un->un_pm_mutex);
			rval = EAGAIN;
			goto done;
		} else {
			/*
			 * Indicate to PM the device is busy. This is required
			 * to avoid a race - i.e. the ioctl is issuing a
			 * command and the pm framework brings down the device
			 * to low power mode (possible power cut-off on some
			 * platforms).
			 */
			mutex_exit(&un->un_pm_mutex);
			if (sd_pm_entry(un) != DDI_SUCCESS) {
				rval = EAGAIN;
				goto done;
			}
		}
	}

	temperature_page = kmem_zalloc(TEMPERATURE_PAGE_SIZE, KM_SLEEP);

	rval = sd_send_scsi_LOG_SENSE(ssc, temperature_page,
	    TEMPERATURE_PAGE_SIZE, TEMPERATURE_PAGE, 1, 0, path_flag);
	if (rval != 0)
		goto done2;

	/*
	 * For the current temperature verify that the parameter length is 0x02
	 * and the parameter code is 0x00
	 */
	if ((temperature_page[7] == 0x02) && (temperature_page[4] == 0x00) &&
	    (temperature_page[5] == 0x00)) {
		if (temperature_page[9] == 0xFF) {
			dktemp->dkt_cur_temp = (short)DKT_INVALID_TEMP;
		} else {
			dktemp->dkt_cur_temp = (short)(temperature_page[9]);
		}
	}

	/*
	 * For the reference temperature verify that the parameter
	 * length is 0x02 and the parameter code is 0x01
	 */
	if ((temperature_page[13] == 0x02) && (temperature_page[10] == 0x00) &&
	    (temperature_page[11] == 0x01)) {
		if (temperature_page[15] == 0xFF) {
			dktemp->dkt_ref_temp = (short)DKT_INVALID_TEMP;
		} else {
			dktemp->dkt_ref_temp = (short)(temperature_page[15]);
		}
	}

	/* Do the copyout regardless of the temperature commands status. */
	if (ddi_copyout(dktemp, (void *)arg, sizeof (struct dk_temperature),
	    flag) != 0) {
		rval = EFAULT;
		goto done1;
	}

done2:
	if (rval != 0) {
		if (rval == EIO)
			sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
		else
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}
done1:
	if (path_flag == SD_PATH_DIRECT) {
		sd_pm_exit(un);
	}

	kmem_free(temperature_page, TEMPERATURE_PAGE_SIZE);
done:
	sd_ssc_fini(ssc);
	if (dktemp != NULL) {
		kmem_free(dktemp, sizeof (struct dk_temperature));
	}

	return (rval);
}


/*
 *    Function: sd_log_page_supported
 *
 * Description: This routine uses sd_send_scsi_LOG_SENSE to find the list of
 *		supported log pages.
 *
 *   Arguments: ssc   - ssc contains pointer to driver soft state (unit)
 *                      structure for this target.
 *		log_page -
 *
 * Return Code: -1 - on error (log sense is optional and may not be supported).
 *		0  - log page not found.
 *  		1  - log page found.
 */

static int
sd_log_page_supported(sd_ssc_t *ssc, int log_page)
{
	uchar_t *log_page_data;
	int	i;
	int	match = 0;
	int	log_size;
	int	status = 0;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);

	log_page_data = kmem_zalloc(0xFF, KM_SLEEP);

	status = sd_send_scsi_LOG_SENSE(ssc, log_page_data, 0xFF, 0, 0x01, 0,
	    SD_PATH_DIRECT);

	if (status != 0) {
		if (status == EIO) {
			/*
			 * Some disks do not support log sense, we
			 * should ignore this kind of error(sense key is
			 * 0x5 - illegal request).
			 */
			uint8_t *sensep;
			int senlen;

			sensep = (uint8_t *)ssc->ssc_uscsi_cmd->uscsi_rqbuf;
			senlen = (int)(ssc->ssc_uscsi_cmd->uscsi_rqlen -
			    ssc->ssc_uscsi_cmd->uscsi_rqresid);

			if (senlen > 0 &&
			    scsi_sense_key(sensep) == KEY_ILLEGAL_REQUEST) {
				sd_ssc_assessment(ssc,
				    SD_FMT_IGNORE_COMPROMISE);
			} else {
				sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
			}
		} else {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		}

		SD_ERROR(SD_LOG_COMMON, un,
		    "sd_log_page_supported: failed log page retrieval\n");
		kmem_free(log_page_data, 0xFF);
		return (-1);
	}

	log_size = log_page_data[3];

	/*
	 * The list of supported log pages start from the fourth byte. Check
	 * until we run out of log pages or a match is found.
	 */
	for (i = 4; (i < (log_size + 4)) && !match; i++) {
		if (log_page_data[i] == log_page) {
			match++;
		}
	}
	kmem_free(log_page_data, 0xFF);
	return (match);
}


/*
 *    Function: sd_mhdioc_failfast
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests to enable/disable the multihost failfast option.
 *		(MHIOCENFAILFAST)
 *
 *   Arguments: dev	- the device number
 *		arg	- user specified probing interval.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 */

static int
sd_mhdioc_failfast(dev_t dev, caddr_t arg, int flag)
{
	struct sd_lun	*un = NULL;
	int		mh_time;
	int		rval = 0;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	if (ddi_copyin((void *)arg, &mh_time, sizeof (int), flag))
		return (EFAULT);

	if (mh_time) {
		mutex_enter(SD_MUTEX(un));
		un->un_resvd_status |= SD_FAILFAST;
		mutex_exit(SD_MUTEX(un));
		/*
		 * If mh_time is INT_MAX, then this ioctl is being used for
		 * SCSI-3 PGR purposes, and we don't need to spawn watch thread.
		 */
		if (mh_time != INT_MAX) {
			rval = sd_check_mhd(dev, mh_time);
		}
	} else {
		(void) sd_check_mhd(dev, 0);
		mutex_enter(SD_MUTEX(un));
		un->un_resvd_status &= ~SD_FAILFAST;
		mutex_exit(SD_MUTEX(un));
	}
	return (rval);
}


/*
 *    Function: sd_mhdioc_takeown
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests to forcefully acquire exclusive access rights to the
 *		multihost disk (MHIOCTKOWN).
 *
 *   Arguments: dev	- the device number
 *		arg	- user provided structure specifying the delay
 *			  parameters in milliseconds
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 */

static int
sd_mhdioc_takeown(dev_t dev, caddr_t arg, int flag)
{
	struct sd_lun		*un = NULL;
	struct mhioctkown	*tkown = NULL;
	int			rval = 0;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	if (arg != NULL) {
		tkown = (struct mhioctkown *)
		    kmem_zalloc(sizeof (struct mhioctkown), KM_SLEEP);
		rval = ddi_copyin(arg, tkown, sizeof (struct mhioctkown), flag);
		if (rval != 0) {
			rval = EFAULT;
			goto error;
		}
	}

	rval = sd_take_ownership(dev, tkown);
	mutex_enter(SD_MUTEX(un));
	if (rval == 0) {
		un->un_resvd_status |= SD_RESERVE;
		if (tkown != NULL && tkown->reinstate_resv_delay != 0) {
			sd_reinstate_resv_delay =
			    tkown->reinstate_resv_delay * 1000;
		} else {
			sd_reinstate_resv_delay = SD_REINSTATE_RESV_DELAY;
		}
		/*
		 * Give the scsi_watch routine interval set by
		 * the MHIOCENFAILFAST ioctl precedence here.
		 */
		if ((un->un_resvd_status & SD_FAILFAST) == 0) {
			mutex_exit(SD_MUTEX(un));
			(void) sd_check_mhd(dev, sd_reinstate_resv_delay/1000);
			SD_TRACE(SD_LOG_IOCTL_MHD, un,
			    "sd_mhdioc_takeown : %d\n",
			    sd_reinstate_resv_delay);
		} else {
			mutex_exit(SD_MUTEX(un));
		}
		(void) scsi_reset_notify(SD_ADDRESS(un), SCSI_RESET_NOTIFY,
		    sd_mhd_reset_notify_cb, (caddr_t)un);
	} else {
		un->un_resvd_status &= ~SD_RESERVE;
		mutex_exit(SD_MUTEX(un));
	}

error:
	if (tkown != NULL) {
		kmem_free(tkown, sizeof (struct mhioctkown));
	}
	return (rval);
}


/*
 *    Function: sd_mhdioc_release
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests to release exclusive access rights to the multihost
 *		disk (MHIOCRELEASE).
 *
 *   Arguments: dev	- the device number
 *
 * Return Code: 0
 *		ENXIO
 */

static int
sd_mhdioc_release(dev_t dev)
{
	struct sd_lun		*un = NULL;
	timeout_id_t		resvd_timeid_save;
	int			resvd_status_save;
	int			rval = 0;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	mutex_enter(SD_MUTEX(un));
	resvd_status_save = un->un_resvd_status;
	un->un_resvd_status &=
	    ~(SD_RESERVE | SD_LOST_RESERVE | SD_WANT_RESERVE);
	if (un->un_resvd_timeid) {
		resvd_timeid_save = un->un_resvd_timeid;
		un->un_resvd_timeid = NULL;
		mutex_exit(SD_MUTEX(un));
		(void) untimeout(resvd_timeid_save);
	} else {
		mutex_exit(SD_MUTEX(un));
	}

	/*
	 * destroy any pending timeout thread that may be attempting to
	 * reinstate reservation on this device.
	 */
	sd_rmv_resv_reclaim_req(dev);

	if ((rval = sd_reserve_release(dev, SD_RELEASE)) == 0) {
		mutex_enter(SD_MUTEX(un));
		if ((un->un_mhd_token) &&
		    ((un->un_resvd_status & SD_FAILFAST) == 0)) {
			mutex_exit(SD_MUTEX(un));
			(void) sd_check_mhd(dev, 0);
		} else {
			mutex_exit(SD_MUTEX(un));
		}
		(void) scsi_reset_notify(SD_ADDRESS(un), SCSI_RESET_CANCEL,
		    sd_mhd_reset_notify_cb, (caddr_t)un);
	} else {
		/*
		 * sd_mhd_watch_cb will restart the resvd recover timeout thread
		 */
		mutex_enter(SD_MUTEX(un));
		un->un_resvd_status = resvd_status_save;
		mutex_exit(SD_MUTEX(un));
	}
	return (rval);
}


/*
 *    Function: sd_mhdioc_register_devid
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests to register the device id (MHIOCREREGISTERDEVID).
 *
 *		Note: The implementation for this ioctl has been updated to
 *		be consistent with the original PSARC case (1999/357)
 *		(4375899, 4241671, 4220005)
 *
 *   Arguments: dev	- the device number
 *
 * Return Code: 0
 *		ENXIO
 */

static int
sd_mhdioc_register_devid(dev_t dev)
{
	struct sd_lun	*un = NULL;
	int		rval = 0;
	sd_ssc_t	*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	ASSERT(!mutex_owned(SD_MUTEX(un)));

	mutex_enter(SD_MUTEX(un));

	/* If a devid already exists, de-register it */
	if (un->un_devid != NULL) {
		ddi_devid_unregister(SD_DEVINFO(un));
		/*
		 * After unregister devid, needs to free devid memory
		 */
		ddi_devid_free(un->un_devid);
		un->un_devid = NULL;
	}

	/* Check for reservation conflict */
	mutex_exit(SD_MUTEX(un));
	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_TEST_UNIT_READY(ssc, 0);
	mutex_enter(SD_MUTEX(un));

	switch (rval) {
	case 0:
		sd_register_devid(ssc, SD_DEVINFO(un), SD_TARGET_IS_UNRESERVED);
		break;
	case EACCES:
		break;
	default:
		rval = EIO;
	}

	mutex_exit(SD_MUTEX(un));
	if (rval != 0) {
		if (rval == EIO)
			sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
		else
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}
	sd_ssc_fini(ssc);
	return (rval);
}


/*
 *    Function: sd_mhdioc_inkeys
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests to issue the SCSI-3 Persistent In Read Keys command
 *		to the device (MHIOCGRP_INKEYS).
 *
 *   Arguments: dev	- the device number
 *		arg	- user provided in_keys structure
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: code returned by sd_persistent_reservation_in_read_keys()
 *		ENXIO
 *		EFAULT
 */

static int
sd_mhdioc_inkeys(dev_t dev, caddr_t arg, int flag)
{
	struct sd_lun		*un;
	mhioc_inkeys_t		inkeys;
	int			rval = 0;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct mhioc_inkeys32	inkeys32;

		if (ddi_copyin(arg, &inkeys32,
		    sizeof (struct mhioc_inkeys32), flag) != 0) {
			return (EFAULT);
		}
		inkeys.li = (mhioc_key_list_t *)(uintptr_t)inkeys32.li;
		if ((rval = sd_persistent_reservation_in_read_keys(un,
		    &inkeys, flag)) != 0) {
			return (rval);
		}
		inkeys32.generation = inkeys.generation;
		if (ddi_copyout(&inkeys32, arg, sizeof (struct mhioc_inkeys32),
		    flag) != 0) {
			return (EFAULT);
		}
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyin(arg, &inkeys, sizeof (mhioc_inkeys_t),
		    flag) != 0) {
			return (EFAULT);
		}
		if ((rval = sd_persistent_reservation_in_read_keys(un,
		    &inkeys, flag)) != 0) {
			return (rval);
		}
		if (ddi_copyout(&inkeys, arg, sizeof (mhioc_inkeys_t),
		    flag) != 0) {
			return (EFAULT);
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */

	if (ddi_copyin(arg, &inkeys, sizeof (mhioc_inkeys_t), flag) != 0) {
		return (EFAULT);
	}
	rval = sd_persistent_reservation_in_read_keys(un, &inkeys, flag);
	if (rval != 0) {
		return (rval);
	}
	if (ddi_copyout(&inkeys, arg, sizeof (mhioc_inkeys_t), flag) != 0) {
		return (EFAULT);
	}

#endif /* _MULTI_DATAMODEL */

	return (rval);
}


/*
 *    Function: sd_mhdioc_inresv
 *
 * Description: This routine is the driver entry point for handling ioctl
 *		requests to issue the SCSI-3 Persistent In Read Reservations
 *		command to the device (MHIOCGRP_INKEYS).
 *
 *   Arguments: dev	- the device number
 *		arg	- user provided in_resv structure
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: code returned by sd_persistent_reservation_in_read_resv()
 *		ENXIO
 *		EFAULT
 */

static int
sd_mhdioc_inresv(dev_t dev, caddr_t arg, int flag)
{
	struct sd_lun		*un;
	mhioc_inresvs_t		inresvs;
	int			rval = 0;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

#ifdef _MULTI_DATAMODEL

	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct mhioc_inresvs32	inresvs32;

		if (ddi_copyin(arg, &inresvs32,
		    sizeof (struct mhioc_inresvs32), flag) != 0) {
			return (EFAULT);
		}
		inresvs.li = (mhioc_resv_desc_list_t *)(uintptr_t)inresvs32.li;
		if ((rval = sd_persistent_reservation_in_read_resv(un,
		    &inresvs, flag)) != 0) {
			return (rval);
		}
		inresvs32.generation = inresvs.generation;
		if (ddi_copyout(&inresvs32, arg,
		    sizeof (struct mhioc_inresvs32), flag) != 0) {
			return (EFAULT);
		}
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyin(arg, &inresvs,
		    sizeof (mhioc_inresvs_t), flag) != 0) {
			return (EFAULT);
		}
		if ((rval = sd_persistent_reservation_in_read_resv(un,
		    &inresvs, flag)) != 0) {
			return (rval);
		}
		if (ddi_copyout(&inresvs, arg,
		    sizeof (mhioc_inresvs_t), flag) != 0) {
			return (EFAULT);
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */

	if (ddi_copyin(arg, &inresvs, sizeof (mhioc_inresvs_t), flag) != 0) {
		return (EFAULT);
	}
	rval = sd_persistent_reservation_in_read_resv(un, &inresvs, flag);
	if (rval != 0) {
		return (rval);
	}
	if (ddi_copyout(&inresvs, arg, sizeof (mhioc_inresvs_t), flag)) {
		return (EFAULT);
	}

#endif /* ! _MULTI_DATAMODEL */

	return (rval);
}


/*
 * The following routines support the clustering functionality described below
 * and implement lost reservation reclaim functionality.
 *
 * Clustering
 * ----------
 * The clustering code uses two different, independent forms of SCSI
 * reservation. Traditional SCSI-2 Reserve/Release and the newer SCSI-3
 * Persistent Group Reservations. For any particular disk, it will use either
 * SCSI-2 or SCSI-3 PGR but never both at the same time for the same disk.
 *
 * SCSI-2
 * The cluster software takes ownership of a multi-hosted disk by issuing the
 * MHIOCTKOWN ioctl to the disk driver. It releases ownership by issuing the
 * MHIOCRELEASE ioctl.  Closely related is the MHIOCENFAILFAST ioctl -- a
 * cluster, just after taking ownership of the disk with the MHIOCTKOWN ioctl
 * then issues the MHIOCENFAILFAST ioctl.  This ioctl "enables failfast" in the
 * driver. The meaning of failfast is that if the driver (on this host) ever
 * encounters the scsi error return code RESERVATION_CONFLICT from the device,
 * it should immediately panic the host. The motivation for this ioctl is that
 * if this host does encounter reservation conflict, the underlying cause is
 * that some other host of the cluster has decided that this host is no longer
 * in the cluster and has seized control of the disks for itself. Since this
 * host is no longer in the cluster, it ought to panic itself. The
 * MHIOCENFAILFAST ioctl does two things:
 *	(a) it sets a flag that will cause any returned RESERVATION_CONFLICT
 *      error to panic the host
 *      (b) it sets up a periodic timer to test whether this host still has
 *      "access" (in that no other host has reserved the device):  if the
 *      periodic timer gets RESERVATION_CONFLICT, the host is panicked. The
 *      purpose of that periodic timer is to handle scenarios where the host is
 *      otherwise temporarily quiescent, temporarily doing no real i/o.
 * The MHIOCTKOWN ioctl will "break" a reservation that is held by another host,
 * by issuing a SCSI Bus Device Reset.  It will then issue a SCSI Reserve for
 * the device itself.
 *
 * SCSI-3 PGR
 * A direct semantic implementation of the SCSI-3 Persistent Reservation
 * facility is supported through the shared multihost disk ioctls
 * (MHIOCGRP_INKEYS, MHIOCGRP_INRESV, MHIOCGRP_REGISTER, MHIOCGRP_RESERVE,
 * MHIOCGRP_PREEMPTANDABORT, MHIOCGRP_CLEAR)
 *
 * Reservation Reclaim:
 * --------------------
 * To support the lost reservation reclaim operations this driver creates a
 * single thread to handle reinstating reservations on all devices that have
 * lost reservations sd_resv_reclaim_requests are logged for all devices that
 * have LOST RESERVATIONS when the scsi watch facility callsback sd_mhd_watch_cb
 * and the reservation reclaim thread loops through the requests to regain the
 * lost reservations.
 */

/*
 *    Function: sd_check_mhd()
 *
 * Description: This function sets up and submits a scsi watch request or
 *		terminates an existing watch request. This routine is used in
 *		support of reservation reclaim.
 *
 *   Arguments: dev    - the device 'dev_t' is used for context to discriminate
 *			 among multiple watches that share the callback function
 *		interval - the number of microseconds specifying the watch
 *			   interval for issuing TEST UNIT READY commands. If
 *			   set to 0 the watch should be terminated. If the
 *			   interval is set to 0 and if the device is required
 *			   to hold reservation while disabling failfast, the
 *			   watch is restarted with an interval of
 *			   reinstate_resv_delay.
 *
 * Return Code: 0	   - Successful submit/terminate of scsi watch request
 *		ENXIO      - Indicates an invalid device was specified
 *		EAGAIN     - Unable to submit the scsi watch request
 */

static int
sd_check_mhd(dev_t dev, int interval)
{
	struct sd_lun	*un;
	opaque_t	token;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	/* is this a watch termination request? */
	if (interval == 0) {
		mutex_enter(SD_MUTEX(un));
		/* if there is an existing watch task then terminate it */
		if (un->un_mhd_token) {
			token = un->un_mhd_token;
			un->un_mhd_token = NULL;
			mutex_exit(SD_MUTEX(un));
			(void) scsi_watch_request_terminate(token,
			    SCSI_WATCH_TERMINATE_ALL_WAIT);
			mutex_enter(SD_MUTEX(un));
		} else {
			mutex_exit(SD_MUTEX(un));
			/*
			 * Note: If we return here we don't check for the
			 * failfast case. This is the original legacy
			 * implementation but perhaps we should be checking
			 * the failfast case.
			 */
			return (0);
		}
		/*
		 * If the device is required to hold reservation while
		 * disabling failfast, we need to restart the scsi_watch
		 * routine with an interval of reinstate_resv_delay.
		 */
		if (un->un_resvd_status & SD_RESERVE) {
			interval = sd_reinstate_resv_delay/1000;
		} else {
			/* no failfast so bail */
			mutex_exit(SD_MUTEX(un));
			return (0);
		}
		mutex_exit(SD_MUTEX(un));
	}

	/*
	 * adjust minimum time interval to 1 second,
	 * and convert from msecs to usecs
	 */
	if (interval > 0 && interval < 1000) {
		interval = 1000;
	}
	interval *= 1000;

	/*
	 * submit the request to the scsi_watch service
	 */
	token = scsi_watch_request_submit(SD_SCSI_DEVP(un), interval,
	    SENSE_LENGTH, sd_mhd_watch_cb, (caddr_t)dev);
	if (token == NULL) {
		return (EAGAIN);
	}

	/*
	 * save token for termination later on
	 */
	mutex_enter(SD_MUTEX(un));
	un->un_mhd_token = token;
	mutex_exit(SD_MUTEX(un));
	return (0);
}


/*
 *    Function: sd_mhd_watch_cb()
 *
 * Description: This function is the call back function used by the scsi watch
 *		facility. The scsi watch facility sends the "Test Unit Ready"
 *		and processes the status. If applicable (i.e. a "Unit Attention"
 *		status and automatic "Request Sense" not used) the scsi watch
 *		facility will send a "Request Sense" and retrieve the sense data
 *		to be passed to this callback function. In either case the
 *		automatic "Request Sense" or the facility submitting one, this
 *		callback is passed the status and sense data.
 *
 *   Arguments: arg -   the device 'dev_t' is used for context to discriminate
 *			among multiple watches that share this callback function
 *		resultp - scsi watch facility result packet containing scsi
 *			  packet, status byte and sense data
 *
 * Return Code: 0 - continue the watch task
 *		non-zero - terminate the watch task
 */

static int
sd_mhd_watch_cb(caddr_t arg, struct scsi_watch_result *resultp)
{
	struct sd_lun			*un;
	struct scsi_status		*statusp;
	uint8_t				*sensep;
	struct scsi_pkt			*pkt;
	uchar_t				actual_sense_length;
	dev_t  				dev = (dev_t)arg;

	ASSERT(resultp != NULL);
	statusp			= resultp->statusp;
	sensep			= (uint8_t *)resultp->sensep;
	pkt			= resultp->pkt;
	actual_sense_length	= resultp->actual_sense_length;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	SD_TRACE(SD_LOG_IOCTL_MHD, un,
	    "sd_mhd_watch_cb: reason '%s', status '%s'\n",
	    scsi_rname(pkt->pkt_reason), sd_sname(*((unsigned char *)statusp)));

	/* Begin processing of the status and/or sense data */
	if (pkt->pkt_reason != CMD_CMPLT) {
		/* Handle the incomplete packet */
		sd_mhd_watch_incomplete(un, pkt);
		return (0);
	} else if (*((unsigned char *)statusp) != STATUS_GOOD) {
		if (*((unsigned char *)statusp)
		    == STATUS_RESERVATION_CONFLICT) {
			/*
			 * Handle a reservation conflict by panicking if
			 * configured for failfast or by logging the conflict
			 * and updating the reservation status
			 */
			mutex_enter(SD_MUTEX(un));
			if ((un->un_resvd_status & SD_FAILFAST) &&
			    (sd_failfast_enable)) {
				sd_panic_for_res_conflict(un);
				/*NOTREACHED*/
			}
			SD_INFO(SD_LOG_IOCTL_MHD, un,
			    "sd_mhd_watch_cb: Reservation Conflict\n");
			un->un_resvd_status |= SD_RESERVATION_CONFLICT;
			mutex_exit(SD_MUTEX(un));
		}
	}

	if (sensep != NULL) {
		if (actual_sense_length >= (SENSE_LENGTH - 2)) {
			mutex_enter(SD_MUTEX(un));
			if ((scsi_sense_asc(sensep) ==
			    SD_SCSI_RESET_SENSE_CODE) &&
			    (un->un_resvd_status & SD_RESERVE)) {
				/*
				 * The additional sense code indicates a power
				 * on or bus device reset has occurred; update
				 * the reservation status.
				 */
				un->un_resvd_status |=
				    (SD_LOST_RESERVE | SD_WANT_RESERVE);
				SD_INFO(SD_LOG_IOCTL_MHD, un,
				    "sd_mhd_watch_cb: Lost Reservation\n");
			}
		} else {
			return (0);
		}
	} else {
		mutex_enter(SD_MUTEX(un));
	}

	if ((un->un_resvd_status & SD_RESERVE) &&
	    (un->un_resvd_status & SD_LOST_RESERVE)) {
		if (un->un_resvd_status & SD_WANT_RESERVE) {
			/*
			 * A reset occurred in between the last probe and this
			 * one so if a timeout is pending cancel it.
			 */
			if (un->un_resvd_timeid) {
				timeout_id_t temp_id = un->un_resvd_timeid;
				un->un_resvd_timeid = NULL;
				mutex_exit(SD_MUTEX(un));
				(void) untimeout(temp_id);
				mutex_enter(SD_MUTEX(un));
			}
			un->un_resvd_status &= ~SD_WANT_RESERVE;
		}
		if (un->un_resvd_timeid == 0) {
			/* Schedule a timeout to handle the lost reservation */
			un->un_resvd_timeid = timeout(sd_mhd_resvd_recover,
			    (void *)dev,
			    drv_usectohz(sd_reinstate_resv_delay));
		}
	}
	mutex_exit(SD_MUTEX(un));
	return (0);
}


/*
 *    Function: sd_mhd_watch_incomplete()
 *
 * Description: This function is used to find out why a scsi pkt sent by the
 *		scsi watch facility was not completed. Under some scenarios this
 *		routine will return. Otherwise it will send a bus reset to see
 *		if the drive is still online.
 *
 *   Arguments: un  - driver soft state (unit) structure
 *		pkt - incomplete scsi pkt
 */

static void
sd_mhd_watch_incomplete(struct sd_lun *un, struct scsi_pkt *pkt)
{
	int	be_chatty;
	int	perr;

	ASSERT(pkt != NULL);
	ASSERT(un != NULL);
	be_chatty	= (!(pkt->pkt_flags & FLAG_SILENT));
	perr		= (pkt->pkt_statistics & STAT_PERR);

	mutex_enter(SD_MUTEX(un));
	if (un->un_state == SD_STATE_DUMPING) {
		mutex_exit(SD_MUTEX(un));
		return;
	}

	switch (pkt->pkt_reason) {
	case CMD_UNX_BUS_FREE:
		/*
		 * If we had a parity error that caused the target to drop BSY*,
		 * don't be chatty about it.
		 */
		if (perr && be_chatty) {
			be_chatty = 0;
		}
		break;
	case CMD_TAG_REJECT:
		/*
		 * The SCSI-2 spec states that a tag reject will be sent by the
		 * target if tagged queuing is not supported. A tag reject may
		 * also be sent during certain initialization periods or to
		 * control internal resources. For the latter case the target
		 * may also return Queue Full.
		 *
		 * If this driver receives a tag reject from a target that is
		 * going through an init period or controlling internal
		 * resources tagged queuing will be disabled. This is a less
		 * than optimal behavior but the driver is unable to determine
		 * the target state and assumes tagged queueing is not supported
		 */
		pkt->pkt_flags = 0;
		un->un_tagflags = 0;

		if (un->un_f_opt_queueing == TRUE) {
			un->un_throttle = min(un->un_throttle, 3);
		} else {
			un->un_throttle = 1;
		}
		mutex_exit(SD_MUTEX(un));
		(void) scsi_ifsetcap(SD_ADDRESS(un), "tagged-qing", 0, 1);
		mutex_enter(SD_MUTEX(un));
		break;
	case CMD_INCOMPLETE:
		/*
		 * The transport stopped with an abnormal state, fallthrough and
		 * reset the target and/or bus unless selection did not complete
		 * (indicated by STATE_GOT_BUS) in which case we don't want to
		 * go through a target/bus reset
		 */
		if (pkt->pkt_state == STATE_GOT_BUS) {
			break;
		}
		/*FALLTHROUGH*/

	case CMD_TIMEOUT:
	default:
		/*
		 * The lun may still be running the command, so a lun reset
		 * should be attempted. If the lun reset fails or cannot be
		 * issued, than try a target reset. Lastly try a bus reset.
		 */
		if ((pkt->pkt_statistics &
		    (STAT_BUS_RESET|STAT_DEV_RESET|STAT_ABORTED)) == 0) {
			int reset_retval = 0;
			mutex_exit(SD_MUTEX(un));
			if (un->un_f_allow_bus_device_reset == TRUE) {
				if (un->un_f_lun_reset_enabled == TRUE) {
					reset_retval =
					    scsi_reset(SD_ADDRESS(un),
					    RESET_LUN);
				}
				if (reset_retval == 0) {
					reset_retval =
					    scsi_reset(SD_ADDRESS(un),
					    RESET_TARGET);
				}
			}
			if (reset_retval == 0) {
				(void) scsi_reset(SD_ADDRESS(un), RESET_ALL);
			}
			mutex_enter(SD_MUTEX(un));
		}
		break;
	}

	/* A device/bus reset has occurred; update the reservation status. */
	if ((pkt->pkt_reason == CMD_RESET) || (pkt->pkt_statistics &
	    (STAT_BUS_RESET | STAT_DEV_RESET))) {
		if ((un->un_resvd_status & SD_RESERVE) == SD_RESERVE) {
			un->un_resvd_status |=
			    (SD_LOST_RESERVE | SD_WANT_RESERVE);
			SD_INFO(SD_LOG_IOCTL_MHD, un,
			    "sd_mhd_watch_incomplete: Lost Reservation\n");
		}
	}

	/*
	 * The disk has been turned off; Update the device state.
	 *
	 * Note: Should we be offlining the disk here?
	 */
	if (pkt->pkt_state == STATE_GOT_BUS) {
		SD_INFO(SD_LOG_IOCTL_MHD, un, "sd_mhd_watch_incomplete: "
		    "Disk not responding to selection\n");
		if (un->un_state != SD_STATE_OFFLINE) {
			New_state(un, SD_STATE_OFFLINE);
		}
	} else if (be_chatty) {
		/*
		 * suppress messages if they are all the same pkt reason;
		 * with TQ, many (up to 256) are returned with the same
		 * pkt_reason
		 */
		if (pkt->pkt_reason != un->un_last_pkt_reason) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_mhd_watch_incomplete: "
			    "SCSI transport failed: reason '%s'\n",
			    scsi_rname(pkt->pkt_reason));
		}
	}
	un->un_last_pkt_reason = pkt->pkt_reason;
	mutex_exit(SD_MUTEX(un));
}


/*
 *    Function: sd_sname()
 *
 * Description: This is a simple little routine to return a string containing
 *		a printable description of command status byte for use in
 *		logging.
 *
 *   Arguments: status - pointer to a status byte
 *
 * Return Code: char * - string containing status description.
 */

static char *
sd_sname(uchar_t status)
{
	switch (status & STATUS_MASK) {
	case STATUS_GOOD:
		return ("good status");
	case STATUS_CHECK:
		return ("check condition");
	case STATUS_MET:
		return ("condition met");
	case STATUS_BUSY:
		return ("busy");
	case STATUS_INTERMEDIATE:
		return ("intermediate");
	case STATUS_INTERMEDIATE_MET:
		return ("intermediate - condition met");
	case STATUS_RESERVATION_CONFLICT:
		return ("reservation_conflict");
	case STATUS_TERMINATED:
		return ("command terminated");
	case STATUS_QFULL:
		return ("queue full");
	default:
		return ("<unknown status>");
	}
}


/*
 *    Function: sd_mhd_resvd_recover()
 *
 * Description: This function adds a reservation entry to the
 *		sd_resv_reclaim_request list and signals the reservation
 *		reclaim thread that there is work pending. If the reservation
 *		reclaim thread has not been previously created this function
 *		will kick it off.
 *
 *   Arguments: arg -   the device 'dev_t' is used for context to discriminate
 *			among multiple watches that share this callback function
 *
 *     Context: This routine is called by timeout() and is run in interrupt
 *		context. It must not sleep or call other functions which may
 *		sleep.
 */

static void
sd_mhd_resvd_recover(void *arg)
{
	dev_t			dev = (dev_t)arg;
	struct sd_lun		*un;
	struct sd_thr_request	*sd_treq = NULL;
	struct sd_thr_request	*sd_cur = NULL;
	struct sd_thr_request	*sd_prev = NULL;
	int			already_there = 0;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return;
	}

	mutex_enter(SD_MUTEX(un));
	un->un_resvd_timeid = NULL;
	if (un->un_resvd_status & SD_WANT_RESERVE) {
		/*
		 * There was a reset so don't issue the reserve, allow the
		 * sd_mhd_watch_cb callback function to notice this and
		 * reschedule the timeout for reservation.
		 */
		mutex_exit(SD_MUTEX(un));
		return;
	}
	mutex_exit(SD_MUTEX(un));

	/*
	 * Add this device to the sd_resv_reclaim_request list and the
	 * sd_resv_reclaim_thread should take care of the rest.
	 *
	 * Note: We can't sleep in this context so if the memory allocation
	 * fails allow the sd_mhd_watch_cb callback function to notice this and
	 * reschedule the timeout for reservation.  (4378460)
	 */
	sd_treq = (struct sd_thr_request *)
	    kmem_zalloc(sizeof (struct sd_thr_request), KM_NOSLEEP);
	if (sd_treq == NULL) {
		return;
	}

	sd_treq->sd_thr_req_next = NULL;
	sd_treq->dev = dev;
	mutex_enter(&sd_tr.srq_resv_reclaim_mutex);
	if (sd_tr.srq_thr_req_head == NULL) {
		sd_tr.srq_thr_req_head = sd_treq;
	} else {
		sd_cur = sd_prev = sd_tr.srq_thr_req_head;
		for (; sd_cur != NULL; sd_cur = sd_cur->sd_thr_req_next) {
			if (sd_cur->dev == dev) {
				/*
				 * already in Queue so don't log
				 * another request for the device
				 */
				already_there = 1;
				break;
			}
			sd_prev = sd_cur;
		}
		if (!already_there) {
			SD_INFO(SD_LOG_IOCTL_MHD, un, "sd_mhd_resvd_recover: "
			    "logging request for %lx\n", dev);
			sd_prev->sd_thr_req_next = sd_treq;
		} else {
			kmem_free(sd_treq, sizeof (struct sd_thr_request));
		}
	}

	/*
	 * Create a kernel thread to do the reservation reclaim and free up this
	 * thread. We cannot block this thread while we go away to do the
	 * reservation reclaim
	 */
	if (sd_tr.srq_resv_reclaim_thread == NULL)
		sd_tr.srq_resv_reclaim_thread = thread_create(NULL, 0,
		    sd_resv_reclaim_thread, NULL,
		    0, &p0, TS_RUN, v.v_maxsyspri - 2);

	/* Tell the reservation reclaim thread that it has work to do */
	cv_signal(&sd_tr.srq_resv_reclaim_cv);
	mutex_exit(&sd_tr.srq_resv_reclaim_mutex);
}

/*
 *    Function: sd_resv_reclaim_thread()
 *
 * Description: This function implements the reservation reclaim operations
 *
 *   Arguments: arg - the device 'dev_t' is used for context to discriminate
 *		      among multiple watches that share this callback function
 */

static void
sd_resv_reclaim_thread()
{
	struct sd_lun		*un;
	struct sd_thr_request	*sd_mhreq;

	/* Wait for work */
	mutex_enter(&sd_tr.srq_resv_reclaim_mutex);
	if (sd_tr.srq_thr_req_head == NULL) {
		cv_wait(&sd_tr.srq_resv_reclaim_cv,
		    &sd_tr.srq_resv_reclaim_mutex);
	}

	/* Loop while we have work */
	while ((sd_tr.srq_thr_cur_req = sd_tr.srq_thr_req_head) != NULL) {
		un = ddi_get_soft_state(sd_state,
		    SDUNIT(sd_tr.srq_thr_cur_req->dev));
		if (un == NULL) {
			/*
			 * softstate structure is NULL so just
			 * dequeue the request and continue
			 */
			sd_tr.srq_thr_req_head =
			    sd_tr.srq_thr_cur_req->sd_thr_req_next;
			kmem_free(sd_tr.srq_thr_cur_req,
			    sizeof (struct sd_thr_request));
			continue;
		}

		/* dequeue the request */
		sd_mhreq = sd_tr.srq_thr_cur_req;
		sd_tr.srq_thr_req_head =
		    sd_tr.srq_thr_cur_req->sd_thr_req_next;
		mutex_exit(&sd_tr.srq_resv_reclaim_mutex);

		/*
		 * Reclaim reservation only if SD_RESERVE is still set. There
		 * may have been a call to MHIOCRELEASE before we got here.
		 */
		mutex_enter(SD_MUTEX(un));
		if ((un->un_resvd_status & SD_RESERVE) == SD_RESERVE) {
			/*
			 * Note: The SD_LOST_RESERVE flag is cleared before
			 * reclaiming the reservation. If this is done after the
			 * call to sd_reserve_release a reservation loss in the
			 * window between pkt completion of reserve cmd and
			 * mutex_enter below may not be recognized
			 */
			un->un_resvd_status &= ~SD_LOST_RESERVE;
			mutex_exit(SD_MUTEX(un));

			if (sd_reserve_release(sd_mhreq->dev,
			    SD_RESERVE) == 0) {
				mutex_enter(SD_MUTEX(un));
				un->un_resvd_status |= SD_RESERVE;
				mutex_exit(SD_MUTEX(un));
				SD_INFO(SD_LOG_IOCTL_MHD, un,
				    "sd_resv_reclaim_thread: "
				    "Reservation Recovered\n");
			} else {
				mutex_enter(SD_MUTEX(un));
				un->un_resvd_status |= SD_LOST_RESERVE;
				mutex_exit(SD_MUTEX(un));
				SD_INFO(SD_LOG_IOCTL_MHD, un,
				    "sd_resv_reclaim_thread: Failed "
				    "Reservation Recovery\n");
			}
		} else {
			mutex_exit(SD_MUTEX(un));
		}
		mutex_enter(&sd_tr.srq_resv_reclaim_mutex);
		ASSERT(sd_mhreq == sd_tr.srq_thr_cur_req);
		kmem_free(sd_mhreq, sizeof (struct sd_thr_request));
		sd_mhreq = sd_tr.srq_thr_cur_req = NULL;
		/*
		 * wakeup the destroy thread if anyone is waiting on
		 * us to complete.
		 */
		cv_signal(&sd_tr.srq_inprocess_cv);
		SD_TRACE(SD_LOG_IOCTL_MHD, un,
		    "sd_resv_reclaim_thread: cv_signalling current request \n");
	}

	/*
	 * cleanup the sd_tr structure now that this thread will not exist
	 */
	ASSERT(sd_tr.srq_thr_req_head == NULL);
	ASSERT(sd_tr.srq_thr_cur_req == NULL);
	sd_tr.srq_resv_reclaim_thread = NULL;
	mutex_exit(&sd_tr.srq_resv_reclaim_mutex);
	thread_exit();
}


/*
 *    Function: sd_rmv_resv_reclaim_req()
 *
 * Description: This function removes any pending reservation reclaim requests
 *		for the specified device.
 *
 *   Arguments: dev - the device 'dev_t'
 */

static void
sd_rmv_resv_reclaim_req(dev_t dev)
{
	struct sd_thr_request *sd_mhreq;
	struct sd_thr_request *sd_prev;

	/* Remove a reservation reclaim request from the list */
	mutex_enter(&sd_tr.srq_resv_reclaim_mutex);
	if (sd_tr.srq_thr_cur_req && sd_tr.srq_thr_cur_req->dev == dev) {
		/*
		 * We are attempting to reinstate reservation for
		 * this device. We wait for sd_reserve_release()
		 * to return before we return.
		 */
		cv_wait(&sd_tr.srq_inprocess_cv,
		    &sd_tr.srq_resv_reclaim_mutex);
	} else {
		sd_prev = sd_mhreq = sd_tr.srq_thr_req_head;
		if (sd_mhreq && sd_mhreq->dev == dev) {
			sd_tr.srq_thr_req_head = sd_mhreq->sd_thr_req_next;
			kmem_free(sd_mhreq, sizeof (struct sd_thr_request));
			mutex_exit(&sd_tr.srq_resv_reclaim_mutex);
			return;
		}
		for (; sd_mhreq != NULL; sd_mhreq = sd_mhreq->sd_thr_req_next) {
			if (sd_mhreq && sd_mhreq->dev == dev) {
				break;
			}
			sd_prev = sd_mhreq;
		}
		if (sd_mhreq != NULL) {
			sd_prev->sd_thr_req_next = sd_mhreq->sd_thr_req_next;
			kmem_free(sd_mhreq, sizeof (struct sd_thr_request));
		}
	}
	mutex_exit(&sd_tr.srq_resv_reclaim_mutex);
}


/*
 *    Function: sd_mhd_reset_notify_cb()
 *
 * Description: This is a call back function for scsi_reset_notify. This
 *		function updates the softstate reserved status and logs the
 *		reset. The driver scsi watch facility callback function
 *		(sd_mhd_watch_cb) and reservation reclaim thread functionality
 *		will reclaim the reservation.
 *
 *   Arguments: arg  - driver soft state (unit) structure
 */

static void
sd_mhd_reset_notify_cb(caddr_t arg)
{
	struct sd_lun *un = (struct sd_lun *)arg;

	mutex_enter(SD_MUTEX(un));
	if ((un->un_resvd_status & SD_RESERVE) == SD_RESERVE) {
		un->un_resvd_status |= (SD_LOST_RESERVE | SD_WANT_RESERVE);
		SD_INFO(SD_LOG_IOCTL_MHD, un,
		    "sd_mhd_reset_notify_cb: Lost Reservation\n");
	}
	mutex_exit(SD_MUTEX(un));
}


/*
 *    Function: sd_take_ownership()
 *
 * Description: This routine implements an algorithm to achieve a stable
 *		reservation on disks which don't implement priority reserve,
 *		and makes sure that other host lose re-reservation attempts.
 *		This algorithm contains of a loop that keeps issuing the RESERVE
 *		for some period of time (min_ownership_delay, default 6 seconds)
 *		During that loop, it looks to see if there has been a bus device
 *		reset or bus reset (both of which cause an existing reservation
 *		to be lost). If the reservation is lost issue RESERVE until a
 *		period of min_ownership_delay with no resets has gone by, or
 *		until max_ownership_delay has expired. This loop ensures that
 *		the host really did manage to reserve the device, in spite of
 *		resets. The looping for min_ownership_delay (default six
 *		seconds) is important to early generation clustering products,
 *		Solstice HA 1.x and Sun Cluster 2.x. Those products use an
 *		MHIOCENFAILFAST periodic timer of two seconds. By having
 *		MHIOCTKOWN issue Reserves in a loop for six seconds, and having
 *		MHIOCENFAILFAST poll every two seconds, the idea is that by the
 *		time the MHIOCTKOWN ioctl returns, the other host (if any) will
 *		have already noticed, via the MHIOCENFAILFAST polling, that it
 *		no longer "owns" the disk and will have panicked itself.  Thus,
 *		the host issuing the MHIOCTKOWN is assured (with timing
 *		dependencies) that by the time it actually starts to use the
 *		disk for real work, the old owner is no longer accessing it.
 *
 *		min_ownership_delay is the minimum amount of time for which the
 *		disk must be reserved continuously devoid of resets before the
 *		MHIOCTKOWN ioctl will return success.
 *
 *		max_ownership_delay indicates the amount of time by which the
 *		take ownership should succeed or timeout with an error.
 *
 *   Arguments: dev - the device 'dev_t'
 *		*p  - struct containing timing info.
 *
 * Return Code: 0 for success or error code
 */

static int
sd_take_ownership(dev_t dev, struct mhioctkown *p)
{
	struct sd_lun	*un;
	int		rval;
	int		err;
	int		reservation_count   = 0;
	int		min_ownership_delay =  6000000; /* in usec */
	int		max_ownership_delay = 30000000; /* in usec */
	clock_t		start_time;	/* starting time of this algorithm */
	clock_t		end_time;	/* time limit for giving up */
	clock_t		ownership_time;	/* time limit for stable ownership */
	clock_t		current_time;
	clock_t		previous_current_time;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	/*
	 * Attempt a device reservation. A priority reservation is requested.
	 */
	if ((rval = sd_reserve_release(dev, SD_PRIORITY_RESERVE))
	    != SD_SUCCESS) {
		SD_ERROR(SD_LOG_IOCTL_MHD, un,
		    "sd_take_ownership: return(1)=%d\n", rval);
		return (rval);
	}

	/* Update the softstate reserved status to indicate the reservation */
	mutex_enter(SD_MUTEX(un));
	un->un_resvd_status |= SD_RESERVE;
	un->un_resvd_status &=
	    ~(SD_LOST_RESERVE | SD_WANT_RESERVE | SD_RESERVATION_CONFLICT);
	mutex_exit(SD_MUTEX(un));

	if (p != NULL) {
		if (p->min_ownership_delay != 0) {
			min_ownership_delay = p->min_ownership_delay * 1000;
		}
		if (p->max_ownership_delay != 0) {
			max_ownership_delay = p->max_ownership_delay * 1000;
		}
	}
	SD_INFO(SD_LOG_IOCTL_MHD, un,
	    "sd_take_ownership: min, max delays: %d, %d\n",
	    min_ownership_delay, max_ownership_delay);

	start_time = ddi_get_lbolt();
	current_time	= start_time;
	ownership_time	= current_time + drv_usectohz(min_ownership_delay);
	end_time	= start_time + drv_usectohz(max_ownership_delay);

	while (current_time - end_time < 0) {
		delay(drv_usectohz(500000));

		if ((err = sd_reserve_release(dev, SD_RESERVE)) != 0) {
			if ((sd_reserve_release(dev, SD_RESERVE)) != 0) {
				mutex_enter(SD_MUTEX(un));
				rval = (un->un_resvd_status &
				    SD_RESERVATION_CONFLICT) ? EACCES : EIO;
				mutex_exit(SD_MUTEX(un));
				break;
			}
		}
		previous_current_time = current_time;
		current_time = ddi_get_lbolt();
		mutex_enter(SD_MUTEX(un));
		if (err || (un->un_resvd_status & SD_LOST_RESERVE)) {
			ownership_time = ddi_get_lbolt() +
			    drv_usectohz(min_ownership_delay);
			reservation_count = 0;
		} else {
			reservation_count++;
		}
		un->un_resvd_status |= SD_RESERVE;
		un->un_resvd_status &= ~(SD_LOST_RESERVE | SD_WANT_RESERVE);
		mutex_exit(SD_MUTEX(un));

		SD_INFO(SD_LOG_IOCTL_MHD, un,
		    "sd_take_ownership: ticks for loop iteration=%ld, "
		    "reservation=%s\n", (current_time - previous_current_time),
		    reservation_count ? "ok" : "reclaimed");

		if (current_time - ownership_time >= 0 &&
		    reservation_count >= 4) {
			rval = 0; /* Achieved a stable ownership */
			break;
		}
		if (current_time - end_time >= 0) {
			rval = EACCES; /* No ownership in max possible time */
			break;
		}
	}
	SD_TRACE(SD_LOG_IOCTL_MHD, un,
	    "sd_take_ownership: return(2)=%d\n", rval);
	return (rval);
}


/*
 *    Function: sd_reserve_release()
 *
 * Description: This function builds and sends scsi RESERVE, RELEASE, and
 *		PRIORITY RESERVE commands based on a user specified command type
 *
 *   Arguments: dev - the device 'dev_t'
 *		cmd - user specified command type; one of SD_PRIORITY_RESERVE,
 *		      SD_RESERVE, SD_RELEASE
 *
 * Return Code: 0 or Error Code
 */

static int
sd_reserve_release(dev_t dev, int cmd)
{
	struct uscsi_cmd	*com = NULL;
	struct sd_lun		*un = NULL;
	char			cdb[CDB_GROUP0];
	int			rval;

	ASSERT((cmd == SD_RELEASE) || (cmd == SD_RESERVE) ||
	    (cmd == SD_PRIORITY_RESERVE));

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	/* instantiate and initialize the command and cdb */
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	bzero(cdb, CDB_GROUP0);
	com->uscsi_flags   = USCSI_SILENT;
	com->uscsi_timeout = un->un_reserve_release_time;
	com->uscsi_cdblen  = CDB_GROUP0;
	com->uscsi_cdb	   = cdb;
	if (cmd == SD_RELEASE) {
		cdb[0] = SCMD_RELEASE;
	} else {
		cdb[0] = SCMD_RESERVE;
	}

	/* Send the command. */
	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
	    SD_PATH_STANDARD);

	/*
	 * "break" a reservation that is held by another host, by issuing a
	 * reset if priority reserve is desired, and we could not get the
	 * device.
	 */
	if ((cmd == SD_PRIORITY_RESERVE) &&
	    (rval != 0) && (com->uscsi_status == STATUS_RESERVATION_CONFLICT)) {
		/*
		 * First try to reset the LUN. If we cannot, then try a target
		 * reset, followed by a bus reset if the target reset fails.
		 */
		int reset_retval = 0;
		if (un->un_f_lun_reset_enabled == TRUE) {
			reset_retval = scsi_reset(SD_ADDRESS(un), RESET_LUN);
		}
		if (reset_retval == 0) {
			/* The LUN reset either failed or was not issued */
			reset_retval = scsi_reset(SD_ADDRESS(un), RESET_TARGET);
		}
		if ((reset_retval == 0) &&
		    (scsi_reset(SD_ADDRESS(un), RESET_ALL) == 0)) {
			rval = EIO;
			kmem_free(com, sizeof (*com));
			return (rval);
		}

		bzero(com, sizeof (struct uscsi_cmd));
		com->uscsi_flags   = USCSI_SILENT;
		com->uscsi_cdb	   = cdb;
		com->uscsi_cdblen  = CDB_GROUP0;
		com->uscsi_timeout = 5;

		/*
		 * Reissue the last reserve command, this time without request
		 * sense.  Assume that it is just a regular reserve command.
		 */
		rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
		    SD_PATH_STANDARD);
	}

	/* Return an error if still getting a reservation conflict. */
	if ((rval != 0) && (com->uscsi_status == STATUS_RESERVATION_CONFLICT)) {
		rval = EACCES;
	}

	kmem_free(com, sizeof (*com));
	return (rval);
}


#define	SD_NDUMP_RETRIES	12
/*
 *	System Crash Dump routine
 */

static int
sddump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	int		instance;
	int		partition;
	int		i;
	int		err;
	struct sd_lun	*un;
	struct scsi_pkt *wr_pktp;
	struct buf	*wr_bp;
	struct buf	wr_buf;
	daddr_t		tgt_byte_offset; /* rmw - byte offset for target */
	daddr_t		tgt_blkno;	/* rmw - blkno for target */
	size_t		tgt_byte_count; /* rmw -  # of bytes to xfer */
	size_t		tgt_nblk; /* rmw -  # of tgt blks to xfer */
	size_t		io_start_offset;
	int		doing_rmw = FALSE;
	int		rval;
	ssize_t		dma_resid;
	daddr_t		oblkno;
	diskaddr_t	nblks = 0;
	diskaddr_t	start_block;

	instance = SDUNIT(dev);
	if (((un = ddi_get_soft_state(sd_state, instance)) == NULL) ||
	    !SD_IS_VALID_LABEL(un) || ISCD(un)) {
		return (ENXIO);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*un))

	SD_TRACE(SD_LOG_DUMP, un, "sddump: entry\n");

	partition = SDPART(dev);
	SD_INFO(SD_LOG_DUMP, un, "sddump: partition = %d\n", partition);

	if (!(NOT_DEVBSIZE(un))) {
		int secmask = 0;
		int blknomask = 0;

		blknomask = (un->un_tgt_blocksize / DEV_BSIZE) - 1;
		secmask = un->un_tgt_blocksize - 1;

		if (blkno & blknomask) {
			SD_TRACE(SD_LOG_DUMP, un,
			    "sddump: dump start block not modulo %d\n",
			    un->un_tgt_blocksize);
			return (EINVAL);
		}

		if ((nblk * DEV_BSIZE) & secmask) {
			SD_TRACE(SD_LOG_DUMP, un,
			    "sddump: dump length not modulo %d\n",
			    un->un_tgt_blocksize);
			return (EINVAL);
		}

	}

	/* Validate blocks to dump at against partition size. */

	(void) cmlb_partinfo(un->un_cmlbhandle, partition,
	    &nblks, &start_block, NULL, NULL, (void *)SD_PATH_DIRECT);

	if (NOT_DEVBSIZE(un)) {
		if ((blkno + nblk) > nblks) {
			SD_TRACE(SD_LOG_DUMP, un,
			    "sddump: dump range larger than partition: "
			    "blkno = 0x%x, nblk = 0x%x, dkl_nblk = 0x%x\n",
			    blkno, nblk, nblks);
			return (EINVAL);
		}
	} else {
		if (((blkno / (un->un_tgt_blocksize / DEV_BSIZE)) +
		    (nblk / (un->un_tgt_blocksize / DEV_BSIZE))) > nblks) {
			SD_TRACE(SD_LOG_DUMP, un,
			    "sddump: dump range larger than partition: "
			    "blkno = 0x%x, nblk = 0x%x, dkl_nblk = 0x%x\n",
			    blkno, nblk, nblks);
			return (EINVAL);
		}
	}

	mutex_enter(&un->un_pm_mutex);
	if (SD_DEVICE_IS_IN_LOW_POWER(un)) {
		struct scsi_pkt *start_pktp;

		mutex_exit(&un->un_pm_mutex);

		/*
		 * use pm framework to power on HBA 1st
		 */
		(void) pm_raise_power(SD_DEVINFO(un), 0,
		    SD_PM_STATE_ACTIVE(un));

		/*
		 * Dump no long uses sdpower to power on a device, it's
		 * in-line here so it can be done in polled mode.
		 */

		SD_INFO(SD_LOG_DUMP, un, "sddump: starting device\n");

		start_pktp = scsi_init_pkt(SD_ADDRESS(un), NULL, NULL,
		    CDB_GROUP0, un->un_status_len, 0, 0, NULL_FUNC, NULL);

		if (start_pktp == NULL) {
			/* We were not given a SCSI packet, fail. */
			return (EIO);
		}
		bzero(start_pktp->pkt_cdbp, CDB_GROUP0);
		start_pktp->pkt_cdbp[0] = SCMD_START_STOP;
		start_pktp->pkt_cdbp[4] = SD_TARGET_START;
		start_pktp->pkt_flags = FLAG_NOINTR;

		mutex_enter(SD_MUTEX(un));
		SD_FILL_SCSI1_LUN(un, start_pktp);
		mutex_exit(SD_MUTEX(un));
		/*
		 * Scsi_poll returns 0 (success) if the command completes and
		 * the status block is STATUS_GOOD.
		 */
		if (sd_scsi_poll(un, start_pktp) != 0) {
			scsi_destroy_pkt(start_pktp);
			return (EIO);
		}
		scsi_destroy_pkt(start_pktp);
		(void) sd_pm_state_change(un, SD_PM_STATE_ACTIVE(un),
		    SD_PM_STATE_CHANGE);
	} else {
		mutex_exit(&un->un_pm_mutex);
	}

	mutex_enter(SD_MUTEX(un));
	un->un_throttle = 0;

	/*
	 * The first time through, reset the specific target device.
	 * However, when cpr calls sddump we know that sd is in a
	 * a good state so no bus reset is required.
	 * Clear sense data via Request Sense cmd.
	 * In sddump we don't care about allow_bus_device_reset anymore
	 */

	if ((un->un_state != SD_STATE_SUSPENDED) &&
	    (un->un_state != SD_STATE_DUMPING)) {

		New_state(un, SD_STATE_DUMPING);

		if (un->un_f_is_fibre == FALSE) {
			mutex_exit(SD_MUTEX(un));
			/*
			 * Attempt a bus reset for parallel scsi.
			 *
			 * Note: A bus reset is required because on some host
			 * systems (i.e. E420R) a bus device reset is
			 * insufficient to reset the state of the target.
			 *
			 * Note: Don't issue the reset for fibre-channel,
			 * because this tends to hang the bus (loop) for
			 * too long while everyone is logging out and in
			 * and the deadman timer for dumping will fire
			 * before the dump is complete.
			 */
			if (scsi_reset(SD_ADDRESS(un), RESET_ALL) == 0) {
				mutex_enter(SD_MUTEX(un));
				Restore_state(un);
				mutex_exit(SD_MUTEX(un));
				return (EIO);
			}

			/* Delay to give the device some recovery time. */
			drv_usecwait(10000);

			if (sd_send_polled_RQS(un) == SD_FAILURE) {
				SD_INFO(SD_LOG_DUMP, un,
				    "sddump: sd_send_polled_RQS failed\n");
			}
			mutex_enter(SD_MUTEX(un));
		}
	}

	/*
	 * Convert the partition-relative block number to a
	 * disk physical block number.
	 */
	if (NOT_DEVBSIZE(un)) {
		blkno += start_block;
	} else {
		blkno = blkno / (un->un_tgt_blocksize / DEV_BSIZE);
		blkno += start_block;
	}

	SD_INFO(SD_LOG_DUMP, un, "sddump: disk blkno = 0x%x\n", blkno);


	/*
	 * Check if the device has a non-512 block size.
	 */
	wr_bp = NULL;
	if (NOT_DEVBSIZE(un)) {
		tgt_byte_offset = blkno * un->un_sys_blocksize;
		tgt_byte_count = nblk * un->un_sys_blocksize;
		if ((tgt_byte_offset % un->un_tgt_blocksize) ||
		    (tgt_byte_count % un->un_tgt_blocksize)) {
			doing_rmw = TRUE;
			/*
			 * Calculate the block number and number of block
			 * in terms of the media block size.
			 */
			tgt_blkno = tgt_byte_offset / un->un_tgt_blocksize;
			tgt_nblk =
			    ((tgt_byte_offset + tgt_byte_count +
			    (un->un_tgt_blocksize - 1)) /
			    un->un_tgt_blocksize) - tgt_blkno;

			/*
			 * Invoke the routine which is going to do read part
			 * of read-modify-write.
			 * Note that this routine returns a pointer to
			 * a valid bp in wr_bp.
			 */
			err = sddump_do_read_of_rmw(un, tgt_blkno, tgt_nblk,
			    &wr_bp);
			if (err) {
				mutex_exit(SD_MUTEX(un));
				return (err);
			}
			/*
			 * Offset is being calculated as -
			 * (original block # * system block size) -
			 * (new block # * target block size)
			 */
			io_start_offset =
			    ((uint64_t)(blkno * un->un_sys_blocksize)) -
			    ((uint64_t)(tgt_blkno * un->un_tgt_blocksize));

			ASSERT((io_start_offset >= 0) &&
			    (io_start_offset < un->un_tgt_blocksize));
			/*
			 * Do the modify portion of read modify write.
			 */
			bcopy(addr, &wr_bp->b_un.b_addr[io_start_offset],
			    (size_t)nblk * un->un_sys_blocksize);
		} else {
			doing_rmw = FALSE;
			tgt_blkno = tgt_byte_offset / un->un_tgt_blocksize;
			tgt_nblk = tgt_byte_count / un->un_tgt_blocksize;
		}

		/* Convert blkno and nblk to target blocks */
		blkno = tgt_blkno;
		nblk = tgt_nblk;
	} else {
		wr_bp = &wr_buf;
		bzero(wr_bp, sizeof (struct buf));
		wr_bp->b_flags		= B_BUSY;
		wr_bp->b_un.b_addr	= addr;
		wr_bp->b_bcount		= nblk << DEV_BSHIFT;
		wr_bp->b_resid		= 0;
	}

	mutex_exit(SD_MUTEX(un));

	/*
	 * Obtain a SCSI packet for the write command.
	 * It should be safe to call the allocator here without
	 * worrying about being locked for DVMA mapping because
	 * the address we're passed is already a DVMA mapping
	 *
	 * We are also not going to worry about semaphore ownership
	 * in the dump buffer. Dumping is single threaded at present.
	 */

	wr_pktp = NULL;

	dma_resid = wr_bp->b_bcount;
	oblkno = blkno;

	if (!(NOT_DEVBSIZE(un))) {
		nblk = nblk / (un->un_tgt_blocksize / DEV_BSIZE);
	}

	while (dma_resid != 0) {

	for (i = 0; i < SD_NDUMP_RETRIES; i++) {
		wr_bp->b_flags &= ~B_ERROR;

		if (un->un_partial_dma_supported == 1) {
			blkno = oblkno +
			    ((wr_bp->b_bcount - dma_resid) /
			    un->un_tgt_blocksize);
			nblk = dma_resid / un->un_tgt_blocksize;

			if (wr_pktp) {
				/*
				 * Partial DMA transfers after initial transfer
				 */
				rval = sd_setup_next_rw_pkt(un, wr_pktp, wr_bp,
				    blkno, nblk);
			} else {
				/* Initial transfer */
				rval = sd_setup_rw_pkt(un, &wr_pktp, wr_bp,
				    un->un_pkt_flags, NULL_FUNC, NULL,
				    blkno, nblk);
			}
		} else {
			rval = sd_setup_rw_pkt(un, &wr_pktp, wr_bp,
			    0, NULL_FUNC, NULL, blkno, nblk);
		}

		if (rval == 0) {
			/* We were given a SCSI packet, continue. */
			break;
		}

		if (i == 0) {
			if (wr_bp->b_flags & B_ERROR) {
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				    "no resources for dumping; "
				    "error code: 0x%x, retrying",
				    geterror(wr_bp));
			} else {
				scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
				    "no resources for dumping; retrying");
			}
		} else if (i != (SD_NDUMP_RETRIES - 1)) {
			if (wr_bp->b_flags & B_ERROR) {
				scsi_log(SD_DEVINFO(un), sd_label, CE_CONT,
				    "no resources for dumping; error code: "
				    "0x%x, retrying\n", geterror(wr_bp));
			}
		} else {
			if (wr_bp->b_flags & B_ERROR) {
				scsi_log(SD_DEVINFO(un), sd_label, CE_CONT,
				    "no resources for dumping; "
				    "error code: 0x%x, retries failed, "
				    "giving up.\n", geterror(wr_bp));
			} else {
				scsi_log(SD_DEVINFO(un), sd_label, CE_CONT,
				    "no resources for dumping; "
				    "retries failed, giving up.\n");
			}
			mutex_enter(SD_MUTEX(un));
			Restore_state(un);
			if (NOT_DEVBSIZE(un) && (doing_rmw == TRUE)) {
				mutex_exit(SD_MUTEX(un));
				scsi_free_consistent_buf(wr_bp);
			} else {
				mutex_exit(SD_MUTEX(un));
			}
			return (EIO);
		}
		drv_usecwait(10000);
	}

	if (un->un_partial_dma_supported == 1) {
		/*
		 * save the resid from PARTIAL_DMA
		 */
		dma_resid = wr_pktp->pkt_resid;
		if (dma_resid != 0)
			nblk -= SD_BYTES2TGTBLOCKS(un, dma_resid);
		wr_pktp->pkt_resid = 0;
	} else {
		dma_resid = 0;
	}

	/* SunBug 1222170 */
	wr_pktp->pkt_flags = FLAG_NOINTR;

	err = EIO;
	for (i = 0; i < SD_NDUMP_RETRIES; i++) {

		/*
		 * Scsi_poll returns 0 (success) if the command completes and
		 * the status block is STATUS_GOOD.  We should only check
		 * errors if this condition is not true.  Even then we should
		 * send our own request sense packet only if we have a check
		 * condition and auto request sense has not been performed by
		 * the hba.
		 */
		SD_TRACE(SD_LOG_DUMP, un, "sddump: sending write\n");

		if ((sd_scsi_poll(un, wr_pktp) == 0) &&
		    (wr_pktp->pkt_resid == 0)) {
			err = SD_SUCCESS;
			break;
		}

		/*
		 * Check CMD_DEV_GONE 1st, give up if device is gone.
		 */
		if (wr_pktp->pkt_reason == CMD_DEV_GONE) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "Error while dumping state...Device is gone\n");
			break;
		}

		if (SD_GET_PKT_STATUS(wr_pktp) == STATUS_CHECK) {
			SD_INFO(SD_LOG_DUMP, un,
			    "sddump: write failed with CHECK, try # %d\n", i);
			if (((wr_pktp->pkt_state & STATE_ARQ_DONE) == 0)) {
				(void) sd_send_polled_RQS(un);
			}

			continue;
		}

		if (SD_GET_PKT_STATUS(wr_pktp) == STATUS_BUSY) {
			int reset_retval = 0;

			SD_INFO(SD_LOG_DUMP, un,
			    "sddump: write failed with BUSY, try # %d\n", i);

			if (un->un_f_lun_reset_enabled == TRUE) {
				reset_retval = scsi_reset(SD_ADDRESS(un),
				    RESET_LUN);
			}
			if (reset_retval == 0) {
				(void) scsi_reset(SD_ADDRESS(un), RESET_TARGET);
			}
			(void) sd_send_polled_RQS(un);

		} else {
			SD_INFO(SD_LOG_DUMP, un,
			    "sddump: write failed with 0x%x, try # %d\n",
			    SD_GET_PKT_STATUS(wr_pktp), i);
			mutex_enter(SD_MUTEX(un));
			sd_reset_target(un, wr_pktp);
			mutex_exit(SD_MUTEX(un));
		}

		/*
		 * If we are not getting anywhere with lun/target resets,
		 * let's reset the bus.
		 */
		if (i == SD_NDUMP_RETRIES/2) {
			(void) scsi_reset(SD_ADDRESS(un), RESET_ALL);
			(void) sd_send_polled_RQS(un);
		}
	}
	}

	scsi_destroy_pkt(wr_pktp);
	mutex_enter(SD_MUTEX(un));
	if ((NOT_DEVBSIZE(un)) && (doing_rmw == TRUE)) {
		mutex_exit(SD_MUTEX(un));
		scsi_free_consistent_buf(wr_bp);
	} else {
		mutex_exit(SD_MUTEX(un));
	}
	SD_TRACE(SD_LOG_DUMP, un, "sddump: exit: err = %d\n", err);
	return (err);
}

/*
 *    Function: sd_scsi_poll()
 *
 * Description: This is a wrapper for the scsi_poll call.
 *
 *   Arguments: sd_lun - The unit structure
 *              scsi_pkt - The scsi packet being sent to the device.
 *
 * Return Code: 0 - Command completed successfully with good status
 *             -1 - Command failed.  This could indicate a check condition
 *                  or other status value requiring recovery action.
 *
 * NOTE: This code is only called off sddump().
 */

static int
sd_scsi_poll(struct sd_lun *un, struct scsi_pkt *pktp)
{
	int status;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));
	ASSERT(pktp != NULL);

	status = SD_SUCCESS;

	if (scsi_ifgetcap(&pktp->pkt_address, "tagged-qing", 1) == 1) {
		pktp->pkt_flags |= un->un_tagflags;
		pktp->pkt_flags &= ~FLAG_NODISCON;
	}

	status = sd_ddi_scsi_poll(pktp);
	/*
	 * Scsi_poll returns 0 (success) if the command completes and the
	 * status block is STATUS_GOOD.  We should only check errors if this
	 * condition is not true.  Even then we should send our own request
	 * sense packet only if we have a check condition and auto
	 * request sense has not been performed by the hba.
	 * Don't get RQS data if pkt_reason is CMD_DEV_GONE.
	 */
	if ((status != SD_SUCCESS) &&
	    (SD_GET_PKT_STATUS(pktp) == STATUS_CHECK) &&
	    (pktp->pkt_state & STATE_ARQ_DONE) == 0 &&
	    (pktp->pkt_reason != CMD_DEV_GONE))
		(void) sd_send_polled_RQS(un);

	return (status);
}

/*
 *    Function: sd_send_polled_RQS()
 *
 * Description: This sends the request sense command to a device.
 *
 *   Arguments: sd_lun - The unit structure
 *
 * Return Code: 0 - Command completed successfully with good status
 *             -1 - Command failed.
 *
 */

static int
sd_send_polled_RQS(struct sd_lun *un)
{
	int	ret_val;
	struct	scsi_pkt	*rqs_pktp;
	struct	buf		*rqs_bp;

	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	ret_val = SD_SUCCESS;

	rqs_pktp = un->un_rqs_pktp;
	rqs_bp	 = un->un_rqs_bp;

	mutex_enter(SD_MUTEX(un));

	if (un->un_sense_isbusy) {
		ret_val = SD_FAILURE;
		mutex_exit(SD_MUTEX(un));
		return (ret_val);
	}

	/*
	 * If the request sense buffer (and packet) is not in use,
	 * let's set the un_sense_isbusy and send our packet
	 */
	un->un_sense_isbusy 	= 1;
	rqs_pktp->pkt_resid  	= 0;
	rqs_pktp->pkt_reason 	= 0;
	rqs_pktp->pkt_flags |= FLAG_NOINTR;
	bzero(rqs_bp->b_un.b_addr, SENSE_LENGTH);

	mutex_exit(SD_MUTEX(un));

	SD_INFO(SD_LOG_COMMON, un, "sd_send_polled_RQS: req sense buf at"
	    " 0x%p\n", rqs_bp->b_un.b_addr);

	/*
	 * Can't send this to sd_scsi_poll, we wrap ourselves around the
	 * axle - it has a call into us!
	 */
	if ((ret_val = sd_ddi_scsi_poll(rqs_pktp)) != 0) {
		SD_INFO(SD_LOG_COMMON, un,
		    "sd_send_polled_RQS: RQS failed\n");
	}

	SD_DUMP_MEMORY(un, SD_LOG_COMMON, "sd_send_polled_RQS:",
	    (uchar_t *)rqs_bp->b_un.b_addr, SENSE_LENGTH, SD_LOG_HEX);

	mutex_enter(SD_MUTEX(un));
	un->un_sense_isbusy = 0;
	mutex_exit(SD_MUTEX(un));

	return (ret_val);
}

/*
 * Defines needed for localized version of the scsi_poll routine.
 */
#define	CSEC		10000			/* usecs */
#define	SEC_TO_CSEC	(1000000/CSEC)

/*
 *    Function: sd_ddi_scsi_poll()
 *
 * Description: Localized version of the scsi_poll routine.  The purpose is to
 *		send a scsi_pkt to a device as a polled command.  This version
 *		is to ensure more robust handling of transport errors.
 *		Specifically this routine cures not ready, coming ready
 *		transition for power up and reset of sonoma's.  This can take
 *		up to 45 seconds for power-on and 20 seconds for reset of a
 * 		sonoma lun.
 *
 *   Arguments: scsi_pkt - The scsi_pkt being sent to a device
 *
 * Return Code: 0 - Command completed successfully with good status
 *             -1 - Command failed.
 *
 * NOTE: This code is almost identical to scsi_poll, however before 6668774 can
 * be fixed (removing this code), we need to determine how to handle the
 * KEY_UNIT_ATTENTION condition below in conditions not as limited as sddump().
 *
 * NOTE: This code is only called off sddump().
 */
static int
sd_ddi_scsi_poll(struct scsi_pkt *pkt)
{
	int			rval = -1;
	int			savef;
	long			savet;
	void			(*savec)();
	int			timeout;
	int			busy_count;
	int			poll_delay;
	int			rc;
	uint8_t			*sensep;
	struct scsi_arq_status	*arqstat;
	extern int		do_polled_io;

	ASSERT(pkt->pkt_scbp);

	/*
	 * save old flags..
	 */
	savef = pkt->pkt_flags;
	savec = pkt->pkt_comp;
	savet = pkt->pkt_time;

	pkt->pkt_flags |= FLAG_NOINTR;

	/*
	 * XXX there is nothing in the SCSA spec that states that we should not
	 * do a callback for polled cmds; however, removing this will break sd
	 * and probably other target drivers
	 */
	pkt->pkt_comp = NULL;

	/*
	 * we don't like a polled command without timeout.
	 * 60 seconds seems long enough.
	 */
	if (pkt->pkt_time == 0)
		pkt->pkt_time = SCSI_POLL_TIMEOUT;

	/*
	 * Send polled cmd.
	 *
	 * We do some error recovery for various errors.  Tran_busy,
	 * queue full, and non-dispatched commands are retried every 10 msec.
	 * as they are typically transient failures.  Busy status and Not
	 * Ready are retried every second as this status takes a while to
	 * change.
	 */
	timeout = pkt->pkt_time * SEC_TO_CSEC;

	for (busy_count = 0; busy_count < timeout; busy_count++) {
		/*
		 * Initialize pkt status variables.
		 */
		*pkt->pkt_scbp = pkt->pkt_reason = pkt->pkt_state = 0;

		if ((rc = scsi_transport(pkt)) != TRAN_ACCEPT) {
			if (rc != TRAN_BUSY) {
				/* Transport failed - give up. */
				break;
			} else {
				/* Transport busy - try again. */
				poll_delay = 1 * CSEC;		/* 10 msec. */
			}
		} else {
			/*
			 * Transport accepted - check pkt status.
			 */
			rc = (*pkt->pkt_scbp) & STATUS_MASK;
			if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (rc == STATUS_CHECK) &&
			    (pkt->pkt_state & STATE_ARQ_DONE)) {
				arqstat =
				    (struct scsi_arq_status *)(pkt->pkt_scbp);
				sensep = (uint8_t *)&arqstat->sts_sensedata;
			} else {
				sensep = NULL;
			}

			if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (rc == STATUS_GOOD)) {
				/* No error - we're done */
				rval = 0;
				break;

			} else if (pkt->pkt_reason == CMD_DEV_GONE) {
				/* Lost connection - give up */
				break;

			} else if ((pkt->pkt_reason == CMD_INCOMPLETE) &&
			    (pkt->pkt_state == 0)) {
				/* Pkt not dispatched - try again. */
				poll_delay = 1 * CSEC;		/* 10 msec. */

			} else if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (rc == STATUS_QFULL)) {
				/* Queue full - try again. */
				poll_delay = 1 * CSEC;		/* 10 msec. */

			} else if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (rc == STATUS_BUSY)) {
				/* Busy - try again. */
				poll_delay = 100 * CSEC;	/* 1 sec. */
				busy_count += (SEC_TO_CSEC - 1);

			} else if ((sensep != NULL) &&
			    (scsi_sense_key(sensep) == KEY_UNIT_ATTENTION)) {
				/*
				 * Unit Attention - try again.
				 * Pretend it took 1 sec.
				 * NOTE: 'continue' avoids poll_delay
				 */
				busy_count += (SEC_TO_CSEC - 1);
				continue;

			} else if ((sensep != NULL) &&
			    (scsi_sense_key(sensep) == KEY_NOT_READY) &&
			    (scsi_sense_asc(sensep) == 0x04) &&
			    (scsi_sense_ascq(sensep) == 0x01)) {
				/*
				 * Not ready -> ready - try again.
				 * 04h/01h: LUN IS IN PROCESS OF BECOMING READY
				 * ...same as STATUS_BUSY
				 */
				poll_delay = 100 * CSEC;	/* 1 sec. */
				busy_count += (SEC_TO_CSEC - 1);

			} else {
				/* BAD status - give up. */
				break;
			}
		}

		if (((curthread->t_flag & T_INTR_THREAD) == 0) &&
		    !do_polled_io) {
			delay(drv_usectohz(poll_delay));
		} else {
			/* we busy wait during cpr_dump or interrupt threads */
			drv_usecwait(poll_delay);
		}
	}

	pkt->pkt_flags = savef;
	pkt->pkt_comp = savec;
	pkt->pkt_time = savet;

	/* return on error */
	if (rval)
		return (rval);

	/*
	 * This is not a performance critical code path.
	 *
	 * As an accommodation for scsi_poll callers, to avoid ddi_dma_sync()
	 * issues associated with looking at DMA memory prior to
	 * scsi_pkt_destroy(), we scsi_sync_pkt() prior to return.
	 */
	scsi_sync_pkt(pkt);
	return (0);
}



/*
 *    Function: sd_persistent_reservation_in_read_keys
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		multi-host persistent reservation requests (MHIOCGRP_INKEYS)
 *		by sending the SCSI-3 PRIN commands to the device.
 *		Processes the read keys command response by copying the
 *		reservation key information into the user provided buffer.
 *		Support for the 32/64 bit _MULTI_DATAMODEL is implemented.
 *
 *   Arguments: un   -  Pointer to soft state struct for the target.
 *		usrp -	user provided pointer to multihost Persistent In Read
 *			Keys structure (mhioc_inkeys_t)
 *		flag -	this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 * Return Code: 0   - Success
 *		EACCES
 *		ENOTSUP
 *		errno return code from sd_send_scsi_cmd()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_persistent_reservation_in_read_keys(struct sd_lun *un,
    mhioc_inkeys_t *usrp, int flag)
{
#ifdef _MULTI_DATAMODEL
	struct mhioc_key_list32	li32;
#endif
	sd_prin_readkeys_t	*in;
	mhioc_inkeys_t		*ptr;
	mhioc_key_list_t	li;
	uchar_t			*data_bufp;
	int 			data_len;
	int			rval = 0;
	size_t			copysz;
	sd_ssc_t		*ssc;

	if ((ptr = (mhioc_inkeys_t *)usrp) == NULL) {
		return (EINVAL);
	}
	bzero(&li, sizeof (mhioc_key_list_t));

	ssc = sd_ssc_init(un);

	/*
	 * Get the listsize from user
	 */
#ifdef _MULTI_DATAMODEL

	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		copysz = sizeof (struct mhioc_key_list32);
		if (ddi_copyin(ptr->li, &li32, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_keys: "
			    "failed ddi_copyin: mhioc_key_list32_t\n");
			rval = EFAULT;
			goto done;
		}
		li.listsize = li32.listsize;
		li.list = (mhioc_resv_key_t *)(uintptr_t)li32.list;
		break;

	case DDI_MODEL_NONE:
		copysz = sizeof (mhioc_key_list_t);
		if (ddi_copyin(ptr->li, &li, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_keys: "
			    "failed ddi_copyin: mhioc_key_list_t\n");
			rval = EFAULT;
			goto done;
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */
	copysz = sizeof (mhioc_key_list_t);
	if (ddi_copyin(ptr->li, &li, copysz, flag)) {
		SD_ERROR(SD_LOG_IOCTL_MHD, un,
		    "sd_persistent_reservation_in_read_keys: "
		    "failed ddi_copyin: mhioc_key_list_t\n");
		rval = EFAULT;
		goto done;
	}
#endif

	data_len  = li.listsize * MHIOC_RESV_KEY_SIZE;
	data_len += (sizeof (sd_prin_readkeys_t) - sizeof (caddr_t));
	data_bufp = kmem_zalloc(data_len, KM_SLEEP);

	rval = sd_send_scsi_PERSISTENT_RESERVE_IN(ssc, SD_READ_KEYS,
	    data_len, data_bufp);
	if (rval != 0) {
		if (rval == EIO)
			sd_ssc_assessment(ssc, SD_FMT_IGNORE_COMPROMISE);
		else
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		goto done;
	}
	in = (sd_prin_readkeys_t *)data_bufp;
	ptr->generation = BE_32(in->generation);
	li.listlen = BE_32(in->len) / MHIOC_RESV_KEY_SIZE;

	/*
	 * Return the min(listsize, listlen) keys
	 */
#ifdef _MULTI_DATAMODEL

	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		li32.listlen = li.listlen;
		if (ddi_copyout(&li32, ptr->li, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_keys: "
			    "failed ddi_copyout: mhioc_key_list32_t\n");
			rval = EFAULT;
			goto done;
		}
		break;

	case DDI_MODEL_NONE:
		if (ddi_copyout(&li, ptr->li, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_keys: "
			    "failed ddi_copyout: mhioc_key_list_t\n");
			rval = EFAULT;
			goto done;
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */

	if (ddi_copyout(&li, ptr->li, copysz, flag)) {
		SD_ERROR(SD_LOG_IOCTL_MHD, un,
		    "sd_persistent_reservation_in_read_keys: "
		    "failed ddi_copyout: mhioc_key_list_t\n");
		rval = EFAULT;
		goto done;
	}

#endif /* _MULTI_DATAMODEL */

	copysz = min(li.listlen * MHIOC_RESV_KEY_SIZE,
	    li.listsize * MHIOC_RESV_KEY_SIZE);
	if (ddi_copyout(&in->keylist, li.list, copysz, flag)) {
		SD_ERROR(SD_LOG_IOCTL_MHD, un,
		    "sd_persistent_reservation_in_read_keys: "
		    "failed ddi_copyout: keylist\n");
		rval = EFAULT;
	}
done:
	sd_ssc_fini(ssc);
	kmem_free(data_bufp, data_len);
	return (rval);
}


/*
 *    Function: sd_persistent_reservation_in_read_resv
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		multi-host persistent reservation requests (MHIOCGRP_INRESV)
 *		by sending the SCSI-3 PRIN commands to the device.
 *		Process the read persistent reservations command response by
 *		copying the reservation information into the user provided
 *		buffer. Support for the 32/64 _MULTI_DATAMODEL is implemented.
 *
 *   Arguments: un   -  Pointer to soft state struct for the target.
 *		usrp -	user provided pointer to multihost Persistent In Read
 *			Keys structure (mhioc_inkeys_t)
 *		flag -	this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 * Return Code: 0   - Success
 *		EACCES
 *		ENOTSUP
 *		errno return code from sd_send_scsi_cmd()
 *
 *     Context: Can sleep. Does not return until command is completed.
 */

static int
sd_persistent_reservation_in_read_resv(struct sd_lun *un,
    mhioc_inresvs_t *usrp, int flag)
{
#ifdef _MULTI_DATAMODEL
	struct mhioc_resv_desc_list32 resvlist32;
#endif
	sd_prin_readresv_t	*in;
	mhioc_inresvs_t		*ptr;
	sd_readresv_desc_t	*readresv_ptr;
	mhioc_resv_desc_list_t	resvlist;
	mhioc_resv_desc_t 	resvdesc;
	uchar_t			*data_bufp = NULL;
	int 			data_len;
	int			rval = 0;
	int			i;
	size_t			copysz;
	mhioc_resv_desc_t	*bufp;
	sd_ssc_t		*ssc;

	if ((ptr = usrp) == NULL) {
		return (EINVAL);
	}

	ssc = sd_ssc_init(un);

	/*
	 * Get the listsize from user
	 */
#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		copysz = sizeof (struct mhioc_resv_desc_list32);
		if (ddi_copyin(ptr->li, &resvlist32, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_resv: "
			    "failed ddi_copyin: mhioc_resv_desc_list_t\n");
			rval = EFAULT;
			goto done;
		}
		resvlist.listsize = resvlist32.listsize;
		resvlist.list = (mhioc_resv_desc_t *)(uintptr_t)resvlist32.list;
		break;

	case DDI_MODEL_NONE:
		copysz = sizeof (mhioc_resv_desc_list_t);
		if (ddi_copyin(ptr->li, &resvlist, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_resv: "
			    "failed ddi_copyin: mhioc_resv_desc_list_t\n");
			rval = EFAULT;
			goto done;
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	copysz = sizeof (mhioc_resv_desc_list_t);
	if (ddi_copyin(ptr->li, &resvlist, copysz, flag)) {
		SD_ERROR(SD_LOG_IOCTL_MHD, un,
		    "sd_persistent_reservation_in_read_resv: "
		    "failed ddi_copyin: mhioc_resv_desc_list_t\n");
		rval = EFAULT;
		goto done;
	}
#endif /* ! _MULTI_DATAMODEL */

	data_len  = resvlist.listsize * SCSI3_RESV_DESC_LEN;
	data_len += (sizeof (sd_prin_readresv_t) - sizeof (caddr_t));
	data_bufp = kmem_zalloc(data_len, KM_SLEEP);

	rval = sd_send_scsi_PERSISTENT_RESERVE_IN(ssc, SD_READ_RESV,
	    data_len, data_bufp);
	if (rval != 0) {
		if (rval == EIO)
			sd_ssc_assessment(ssc, SD_FMT_IGNORE_COMPROMISE);
		else
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		goto done;
	}
	in = (sd_prin_readresv_t *)data_bufp;
	ptr->generation = BE_32(in->generation);
	resvlist.listlen = BE_32(in->len) / SCSI3_RESV_DESC_LEN;

	/*
	 * Return the min(listsize, listlen( keys
	 */
#ifdef _MULTI_DATAMODEL

	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		resvlist32.listlen = resvlist.listlen;
		if (ddi_copyout(&resvlist32, ptr->li, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_resv: "
			    "failed ddi_copyout: mhioc_resv_desc_list_t\n");
			rval = EFAULT;
			goto done;
		}
		break;

	case DDI_MODEL_NONE:
		if (ddi_copyout(&resvlist, ptr->li, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_resv: "
			    "failed ddi_copyout: mhioc_resv_desc_list_t\n");
			rval = EFAULT;
			goto done;
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */

	if (ddi_copyout(&resvlist, ptr->li, copysz, flag)) {
		SD_ERROR(SD_LOG_IOCTL_MHD, un,
		    "sd_persistent_reservation_in_read_resv: "
		    "failed ddi_copyout: mhioc_resv_desc_list_t\n");
		rval = EFAULT;
		goto done;
	}

#endif /* ! _MULTI_DATAMODEL */

	readresv_ptr = (sd_readresv_desc_t *)&in->readresv_desc;
	bufp = resvlist.list;
	copysz = sizeof (mhioc_resv_desc_t);
	for (i = 0; i < min(resvlist.listlen, resvlist.listsize);
	    i++, readresv_ptr++, bufp++) {

		bcopy(&readresv_ptr->resvkey, &resvdesc.key,
		    MHIOC_RESV_KEY_SIZE);
		resvdesc.type  = readresv_ptr->type;
		resvdesc.scope = readresv_ptr->scope;
		resvdesc.scope_specific_addr =
		    BE_32(readresv_ptr->scope_specific_addr);

		if (ddi_copyout(&resvdesc, bufp, copysz, flag)) {
			SD_ERROR(SD_LOG_IOCTL_MHD, un,
			    "sd_persistent_reservation_in_read_resv: "
			    "failed ddi_copyout: resvlist\n");
			rval = EFAULT;
			goto done;
		}
	}
done:
	sd_ssc_fini(ssc);
	/* only if data_bufp is allocated, we need to free it */
	if (data_bufp) {
		kmem_free(data_bufp, data_len);
	}
	return (rval);
}


/*
 *    Function: sr_change_blkmode()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		block mode ioctl requests. Support for returning and changing
 *		the current block size in use by the device is implemented. The
 *		LBA size is changed via a MODE SELECT Block Descriptor.
 *
 *		This routine issues a mode sense with an allocation length of
 *		12 bytes for the mode page header and a single block descriptor.
 *
 *   Arguments: dev - the device 'dev_t'
 *		cmd - the request type; one of CDROMGBLKMODE (get) or
 *		      CDROMSBLKMODE (set)
 *		data - current block size or requested block size
 *		flag - this argument is a pass through to ddi_copyxxx() directly
 *		       from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EINVAL if invalid arguments are provided
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EIO if invalid mode sense block descriptor length
 *
 */

static int
sr_change_blkmode(dev_t dev, int cmd, intptr_t data, int flag)
{
	struct sd_lun			*un = NULL;
	struct mode_header		*sense_mhp, *select_mhp;
	struct block_descriptor		*sense_desc, *select_desc;
	int				current_bsize;
	int				rval = EINVAL;
	uchar_t				*sense = NULL;
	uchar_t				*select = NULL;
	sd_ssc_t			*ssc;

	ASSERT((cmd == CDROMGBLKMODE) || (cmd == CDROMSBLKMODE));

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	/*
	 * The block length is changed via the Mode Select block descriptor, the
	 * "Read/Write Error Recovery" mode page (0x1) contents are not actually
	 * required as part of this routine. Therefore the mode sense allocation
	 * length is specified to be the length of a mode page header and a
	 * block descriptor.
	 */
	sense = kmem_zalloc(BUFLEN_CHG_BLK_MODE, KM_SLEEP);

	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP0, sense,
	    BUFLEN_CHG_BLK_MODE, MODEPAGE_ERR_RECOV, SD_PATH_STANDARD);
	sd_ssc_fini(ssc);
	if (rval != 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_change_blkmode: Mode Sense Failed\n");
		kmem_free(sense, BUFLEN_CHG_BLK_MODE);
		return (rval);
	}

	/* Check the block descriptor len to handle only 1 block descriptor */
	sense_mhp = (struct mode_header *)sense;
	if ((sense_mhp->bdesc_length == 0) ||
	    (sense_mhp->bdesc_length > MODE_BLK_DESC_LENGTH)) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_change_blkmode: Mode Sense returned invalid block"
		    " descriptor length\n");
		kmem_free(sense, BUFLEN_CHG_BLK_MODE);
		return (EIO);
	}
	sense_desc = (struct block_descriptor *)(sense + MODE_HEADER_LENGTH);
	current_bsize = ((sense_desc->blksize_hi << 16) |
	    (sense_desc->blksize_mid << 8) | sense_desc->blksize_lo);

	/* Process command */
	switch (cmd) {
	case CDROMGBLKMODE:
		/* Return the block size obtained during the mode sense */
		if (ddi_copyout(&current_bsize, (void *)data,
		    sizeof (int), flag) != 0)
			rval = EFAULT;
		break;
	case CDROMSBLKMODE:
		/* Validate the requested block size */
		switch (data) {
		case CDROM_BLK_512:
		case CDROM_BLK_1024:
		case CDROM_BLK_2048:
		case CDROM_BLK_2056:
		case CDROM_BLK_2336:
		case CDROM_BLK_2340:
		case CDROM_BLK_2352:
		case CDROM_BLK_2368:
		case CDROM_BLK_2448:
		case CDROM_BLK_2646:
		case CDROM_BLK_2647:
			break;
		default:
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_change_blkmode: "
			    "Block Size '%ld' Not Supported\n", data);
			kmem_free(sense, BUFLEN_CHG_BLK_MODE);
			return (EINVAL);
		}

		/*
		 * The current block size matches the requested block size so
		 * there is no need to send the mode select to change the size
		 */
		if (current_bsize == data) {
			break;
		}

		/* Build the select data for the requested block size */
		select = kmem_zalloc(BUFLEN_CHG_BLK_MODE, KM_SLEEP);
		select_mhp = (struct mode_header *)select;
		select_desc =
		    (struct block_descriptor *)(select + MODE_HEADER_LENGTH);
		/*
		 * The LBA size is changed via the block descriptor, so the
		 * descriptor is built according to the user data
		 */
		select_mhp->bdesc_length = MODE_BLK_DESC_LENGTH;
		select_desc->blksize_hi  = (char)(((data) & 0x00ff0000) >> 16);
		select_desc->blksize_mid = (char)(((data) & 0x0000ff00) >> 8);
		select_desc->blksize_lo  = (char)((data) & 0x000000ff);

		/* Send the mode select for the requested block size */
		ssc = sd_ssc_init(un);
		rval = sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP0,
		    select, BUFLEN_CHG_BLK_MODE, SD_DONTSAVE_PAGE,
		    SD_PATH_STANDARD);
		sd_ssc_fini(ssc);
		if (rval != 0) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_change_blkmode: Mode Select Failed\n");
			/*
			 * The mode select failed for the requested block size,
			 * so reset the data for the original block size and
			 * send it to the target. The error is indicated by the
			 * return value for the failed mode select.
			 */
			select_desc->blksize_hi  = sense_desc->blksize_hi;
			select_desc->blksize_mid = sense_desc->blksize_mid;
			select_desc->blksize_lo  = sense_desc->blksize_lo;
			ssc = sd_ssc_init(un);
			(void) sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP0,
			    select, BUFLEN_CHG_BLK_MODE, SD_DONTSAVE_PAGE,
			    SD_PATH_STANDARD);
			sd_ssc_fini(ssc);
		} else {
			ASSERT(!mutex_owned(SD_MUTEX(un)));
			mutex_enter(SD_MUTEX(un));
			sd_update_block_info(un, (uint32_t)data, 0);
			mutex_exit(SD_MUTEX(un));
		}
		break;
	default:
		/* should not reach here, but check anyway */
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_change_blkmode: Command '%x' Not Supported\n", cmd);
		rval = EINVAL;
		break;
	}

	if (select) {
		kmem_free(select, BUFLEN_CHG_BLK_MODE);
	}
	if (sense) {
		kmem_free(sense, BUFLEN_CHG_BLK_MODE);
	}
	return (rval);
}


/*
 * Note: The following sr_change_speed() and sr_atapi_change_speed() routines
 * implement driver support for getting and setting the CD speed. The command
 * set used will be based on the device type. If the device has not been
 * identified as MMC the Toshiba vendor specific mode page will be used. If
 * the device is MMC but does not support the Real Time Streaming feature
 * the SET CD SPEED command will be used to set speed and mode page 0x2A will
 * be used to read the speed.
 */

/*
 *    Function: sr_change_speed()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		drive speed ioctl requests for devices supporting the Toshiba
 *		vendor specific drive speed mode page. Support for returning
 *		and changing the current drive speed in use by the device is
 *		implemented.
 *
 *   Arguments: dev - the device 'dev_t'
 *		cmd - the request type; one of CDROMGDRVSPEED (get) or
 *		      CDROMSDRVSPEED (set)
 *		data - current drive speed or requested drive speed
 *		flag - this argument is a pass through to ddi_copyxxx() directly
 *		       from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EINVAL if invalid arguments are provided
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EIO if invalid mode sense block descriptor length
 */

static int
sr_change_speed(dev_t dev, int cmd, intptr_t data, int flag)
{
	struct sd_lun			*un = NULL;
	struct mode_header		*sense_mhp, *select_mhp;
	struct mode_speed		*sense_page, *select_page;
	int				current_speed;
	int				rval = EINVAL;
	int				bd_len;
	uchar_t				*sense = NULL;
	uchar_t				*select = NULL;
	sd_ssc_t			*ssc;

	ASSERT((cmd == CDROMGDRVSPEED) || (cmd == CDROMSDRVSPEED));
	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	/*
	 * Note: The drive speed is being modified here according to a Toshiba
	 * vendor specific mode page (0x31).
	 */
	sense = kmem_zalloc(BUFLEN_MODE_CDROM_SPEED, KM_SLEEP);

	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP0, sense,
	    BUFLEN_MODE_CDROM_SPEED, CDROM_MODE_SPEED,
	    SD_PATH_STANDARD);
	sd_ssc_fini(ssc);
	if (rval != 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_change_speed: Mode Sense Failed\n");
		kmem_free(sense, BUFLEN_MODE_CDROM_SPEED);
		return (rval);
	}
	sense_mhp  = (struct mode_header *)sense;

	/* Check the block descriptor len to handle only 1 block descriptor */
	bd_len = sense_mhp->bdesc_length;
	if (bd_len > MODE_BLK_DESC_LENGTH) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_change_speed: Mode Sense returned invalid block "
		    "descriptor length\n");
		kmem_free(sense, BUFLEN_MODE_CDROM_SPEED);
		return (EIO);
	}

	sense_page = (struct mode_speed *)
	    (sense + MODE_HEADER_LENGTH + sense_mhp->bdesc_length);
	current_speed = sense_page->speed;

	/* Process command */
	switch (cmd) {
	case CDROMGDRVSPEED:
		/* Return the drive speed obtained during the mode sense */
		if (current_speed == 0x2) {
			current_speed = CDROM_TWELVE_SPEED;
		}
		if (ddi_copyout(&current_speed, (void *)data,
		    sizeof (int), flag) != 0) {
			rval = EFAULT;
		}
		break;
	case CDROMSDRVSPEED:
		/* Validate the requested drive speed */
		switch ((uchar_t)data) {
		case CDROM_TWELVE_SPEED:
			data = 0x2;
			/*FALLTHROUGH*/
		case CDROM_NORMAL_SPEED:
		case CDROM_DOUBLE_SPEED:
		case CDROM_QUAD_SPEED:
		case CDROM_MAXIMUM_SPEED:
			break;
		default:
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_change_speed: "
			    "Drive Speed '%d' Not Supported\n", (uchar_t)data);
			kmem_free(sense, BUFLEN_MODE_CDROM_SPEED);
			return (EINVAL);
		}

		/*
		 * The current drive speed matches the requested drive speed so
		 * there is no need to send the mode select to change the speed
		 */
		if (current_speed == data) {
			break;
		}

		/* Build the select data for the requested drive speed */
		select = kmem_zalloc(BUFLEN_MODE_CDROM_SPEED, KM_SLEEP);
		select_mhp = (struct mode_header *)select;
		select_mhp->bdesc_length = 0;
		select_page =
		    (struct mode_speed *)(select + MODE_HEADER_LENGTH);
		select_page =
		    (struct mode_speed *)(select + MODE_HEADER_LENGTH);
		select_page->mode_page.code = CDROM_MODE_SPEED;
		select_page->mode_page.length = 2;
		select_page->speed = (uchar_t)data;

		/* Send the mode select for the requested block size */
		ssc = sd_ssc_init(un);
		rval = sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP0, select,
		    MODEPAGE_CDROM_SPEED_LEN + MODE_HEADER_LENGTH,
		    SD_DONTSAVE_PAGE, SD_PATH_STANDARD);
		sd_ssc_fini(ssc);
		if (rval != 0) {
			/*
			 * The mode select failed for the requested drive speed,
			 * so reset the data for the original drive speed and
			 * send it to the target. The error is indicated by the
			 * return value for the failed mode select.
			 */
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_drive_speed: Mode Select Failed\n");
			select_page->speed = sense_page->speed;
			ssc = sd_ssc_init(un);
			(void) sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP0, select,
			    MODEPAGE_CDROM_SPEED_LEN + MODE_HEADER_LENGTH,
			    SD_DONTSAVE_PAGE, SD_PATH_STANDARD);
			sd_ssc_fini(ssc);
		}
		break;
	default:
		/* should not reach here, but check anyway */
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_change_speed: Command '%x' Not Supported\n", cmd);
		rval = EINVAL;
		break;
	}

	if (select) {
		kmem_free(select, BUFLEN_MODE_CDROM_SPEED);
	}
	if (sense) {
		kmem_free(sense, BUFLEN_MODE_CDROM_SPEED);
	}

	return (rval);
}


/*
 *    Function: sr_atapi_change_speed()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		drive speed ioctl requests for MMC devices that do not support
 *		the Real Time Streaming feature (0x107).
 *
 *		Note: This routine will use the SET SPEED command which may not
 *		be supported by all devices.
 *
 *   Arguments: dev- the device 'dev_t'
 *		cmd- the request type; one of CDROMGDRVSPEED (get) or
 *		     CDROMSDRVSPEED (set)
 *		data- current drive speed or requested drive speed
 *		flag- this argument is a pass through to ddi_copyxxx() directly
 *		      from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EINVAL if invalid arguments are provided
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EIO if invalid mode sense block descriptor length
 */

static int
sr_atapi_change_speed(dev_t dev, int cmd, intptr_t data, int flag)
{
	struct sd_lun			*un;
	struct uscsi_cmd		*com = NULL;
	struct mode_header_grp2		*sense_mhp;
	uchar_t				*sense_page;
	uchar_t				*sense = NULL;
	char				cdb[CDB_GROUP5];
	int				bd_len;
	int				current_speed = 0;
	int				max_speed = 0;
	int				rval;
	sd_ssc_t			*ssc;

	ASSERT((cmd == CDROMGDRVSPEED) || (cmd == CDROMSDRVSPEED));

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	sense = kmem_zalloc(BUFLEN_MODE_CDROM_CAP, KM_SLEEP);

	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP1, sense,
	    BUFLEN_MODE_CDROM_CAP, MODEPAGE_CDROM_CAP,
	    SD_PATH_STANDARD);
	sd_ssc_fini(ssc);
	if (rval != 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_atapi_change_speed: Mode Sense Failed\n");
		kmem_free(sense, BUFLEN_MODE_CDROM_CAP);
		return (rval);
	}

	/* Check the block descriptor len to handle only 1 block descriptor */
	sense_mhp = (struct mode_header_grp2 *)sense;
	bd_len = (sense_mhp->bdesc_length_hi << 8) | sense_mhp->bdesc_length_lo;
	if (bd_len > MODE_BLK_DESC_LENGTH) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_atapi_change_speed: Mode Sense returned invalid "
		    "block descriptor length\n");
		kmem_free(sense, BUFLEN_MODE_CDROM_CAP);
		return (EIO);
	}

	/* Calculate the current and maximum drive speeds */
	sense_page = (uchar_t *)(sense + MODE_HEADER_LENGTH_GRP2 + bd_len);
	current_speed = (sense_page[14] << 8) | sense_page[15];
	max_speed = (sense_page[8] << 8) | sense_page[9];

	/* Process the command */
	switch (cmd) {
	case CDROMGDRVSPEED:
		current_speed /= SD_SPEED_1X;
		if (ddi_copyout(&current_speed, (void *)data,
		    sizeof (int), flag) != 0)
			rval = EFAULT;
		break;
	case CDROMSDRVSPEED:
		/* Convert the speed code to KB/sec */
		switch ((uchar_t)data) {
		case CDROM_NORMAL_SPEED:
			current_speed = SD_SPEED_1X;
			break;
		case CDROM_DOUBLE_SPEED:
			current_speed = 2 * SD_SPEED_1X;
			break;
		case CDROM_QUAD_SPEED:
			current_speed = 4 * SD_SPEED_1X;
			break;
		case CDROM_TWELVE_SPEED:
			current_speed = 12 * SD_SPEED_1X;
			break;
		case CDROM_MAXIMUM_SPEED:
			current_speed = 0xffff;
			break;
		default:
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_atapi_change_speed: invalid drive speed %d\n",
			    (uchar_t)data);
			kmem_free(sense, BUFLEN_MODE_CDROM_CAP);
			return (EINVAL);
		}

		/* Check the request against the drive's max speed. */
		if (current_speed != 0xffff) {
			if (current_speed > max_speed) {
				kmem_free(sense, BUFLEN_MODE_CDROM_CAP);
				return (EINVAL);
			}
		}

		/*
		 * Build and send the SET SPEED command
		 *
		 * Note: The SET SPEED (0xBB) command used in this routine is
		 * obsolete per the SCSI MMC spec but still supported in the
		 * MT FUJI vendor spec. Most equipment is adhereing to MT FUJI
		 * therefore the command is still implemented in this routine.
		 */
		bzero(cdb, sizeof (cdb));
		cdb[0] = (char)SCMD_SET_CDROM_SPEED;
		cdb[2] = (uchar_t)(current_speed >> 8);
		cdb[3] = (uchar_t)current_speed;
		com = kmem_zalloc(sizeof (*com), KM_SLEEP);
		com->uscsi_cdb	   = (caddr_t)cdb;
		com->uscsi_cdblen  = CDB_GROUP5;
		com->uscsi_bufaddr = NULL;
		com->uscsi_buflen  = 0;
		com->uscsi_flags   = USCSI_DIAGNOSE|USCSI_SILENT;
		rval = sd_send_scsi_cmd(dev, com, FKIOCTL, 0, SD_PATH_STANDARD);
		break;
	default:
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_atapi_change_speed: Command '%x' Not Supported\n", cmd);
		rval = EINVAL;
	}

	if (sense) {
		kmem_free(sense, BUFLEN_MODE_CDROM_CAP);
	}
	if (com) {
		kmem_free(com, sizeof (*com));
	}
	return (rval);
}


/*
 *    Function: sr_pause_resume()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		pause/resume ioctl requests. This only affects the audio play
 *		operation.
 *
 *   Arguments: dev - the device 'dev_t'
 *		cmd - the request type; one of CDROMPAUSE or CDROMRESUME, used
 *		      for setting the resume bit of the cdb.
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EINVAL if invalid mode specified
 *
 */

static int
sr_pause_resume(dev_t dev, int cmd)
{
	struct sd_lun		*un;
	struct uscsi_cmd	*com;
	char			cdb[CDB_GROUP1];
	int			rval;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	bzero(cdb, CDB_GROUP1);
	cdb[0] = SCMD_PAUSE_RESUME;
	switch (cmd) {
	case CDROMRESUME:
		cdb[8] = 1;
		break;
	case CDROMPAUSE:
		cdb[8] = 0;
		break;
	default:
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN, "sr_pause_resume:"
		    " Command '%x' Not Supported\n", cmd);
		rval = EINVAL;
		goto done;
	}

	com->uscsi_cdb    = cdb;
	com->uscsi_cdblen = CDB_GROUP1;
	com->uscsi_flags  = USCSI_DIAGNOSE|USCSI_SILENT;

	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
	    SD_PATH_STANDARD);

done:
	kmem_free(com, sizeof (*com));
	return (rval);
}


/*
 *    Function: sr_play_msf()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl requests to output the audio signals at the specified
 *		starting address and continue the audio play until the specified
 *		ending address (CDROMPLAYMSF) The address is in Minute Second
 *		Frame (MSF) format.
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided audio msf structure,
 *		          specifying start/end addresses.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *		          directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_play_msf(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct uscsi_cmd	*com;
	struct cdrom_msf	msf_struct;
	struct cdrom_msf	*msf = &msf_struct;
	char			cdb[CDB_GROUP1];
	int			rval;

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	if (ddi_copyin(data, msf, sizeof (struct cdrom_msf), flag)) {
		return (EFAULT);
	}

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	bzero(cdb, CDB_GROUP1);
	cdb[0] = SCMD_PLAYAUDIO_MSF;
	if (un->un_f_cfg_playmsf_bcd == TRUE) {
		cdb[3] = BYTE_TO_BCD(msf->cdmsf_min0);
		cdb[4] = BYTE_TO_BCD(msf->cdmsf_sec0);
		cdb[5] = BYTE_TO_BCD(msf->cdmsf_frame0);
		cdb[6] = BYTE_TO_BCD(msf->cdmsf_min1);
		cdb[7] = BYTE_TO_BCD(msf->cdmsf_sec1);
		cdb[8] = BYTE_TO_BCD(msf->cdmsf_frame1);
	} else {
		cdb[3] = msf->cdmsf_min0;
		cdb[4] = msf->cdmsf_sec0;
		cdb[5] = msf->cdmsf_frame0;
		cdb[6] = msf->cdmsf_min1;
		cdb[7] = msf->cdmsf_sec1;
		cdb[8] = msf->cdmsf_frame1;
	}
	com->uscsi_cdb    = cdb;
	com->uscsi_cdblen = CDB_GROUP1;
	com->uscsi_flags  = USCSI_DIAGNOSE|USCSI_SILENT;
	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
	    SD_PATH_STANDARD);
	kmem_free(com, sizeof (*com));
	return (rval);
}


/*
 *    Function: sr_play_trkind()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl requests to output the audio signals at the specified
 *		starting address and continue the audio play until the specified
 *		ending address (CDROMPLAYTRKIND). The address is in Track Index
 *		format.
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided audio track/index structure,
 *		          specifying start/end addresses.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *		          directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_play_trkind(dev_t dev, caddr_t data, int flag)
{
	struct cdrom_ti		ti_struct;
	struct cdrom_ti		*ti = &ti_struct;
	struct uscsi_cmd	*com = NULL;
	char			cdb[CDB_GROUP1];
	int			rval;

	if (data == NULL) {
		return (EINVAL);
	}

	if (ddi_copyin(data, ti, sizeof (struct cdrom_ti), flag)) {
		return (EFAULT);
	}

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	bzero(cdb, CDB_GROUP1);
	cdb[0] = SCMD_PLAYAUDIO_TI;
	cdb[4] = ti->cdti_trk0;
	cdb[5] = ti->cdti_ind0;
	cdb[7] = ti->cdti_trk1;
	cdb[8] = ti->cdti_ind1;
	com->uscsi_cdb    = cdb;
	com->uscsi_cdblen = CDB_GROUP1;
	com->uscsi_flags  = USCSI_DIAGNOSE|USCSI_SILENT;
	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
	    SD_PATH_STANDARD);
	kmem_free(com, sizeof (*com));
	return (rval);
}


/*
 *    Function: sr_read_all_subcodes()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl requests to return raw subcode data while the target is
 *		playing audio (CDROMSUBCODE).
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided cdrom subcode structure,
 *		          specifying the transfer length and address.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *		          directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_read_all_subcodes(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un = NULL;
	struct uscsi_cmd	*com = NULL;
	struct cdrom_subcode	*subcode = NULL;
	int			rval;
	size_t			buflen;
	char			cdb[CDB_GROUP5];

#ifdef _MULTI_DATAMODEL
	/* To support ILP32 applications in an LP64 world */
	struct cdrom_subcode32		cdrom_subcode32;
	struct cdrom_subcode32		*cdsc32 = &cdrom_subcode32;
#endif
	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	subcode = kmem_zalloc(sizeof (struct cdrom_subcode), KM_SLEEP);

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin(data, cdsc32, sizeof (*cdsc32), flag)) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_read_all_subcodes: ddi_copyin Failed\n");
			kmem_free(subcode, sizeof (struct cdrom_subcode));
			return (EFAULT);
		}
		/* Convert the ILP32 uscsi data from the application to LP64 */
		cdrom_subcode32tocdrom_subcode(cdsc32, subcode);
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin(data, subcode,
		    sizeof (struct cdrom_subcode), flag)) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_read_all_subcodes: ddi_copyin Failed\n");
			kmem_free(subcode, sizeof (struct cdrom_subcode));
			return (EFAULT);
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin(data, subcode, sizeof (struct cdrom_subcode), flag)) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_read_all_subcodes: ddi_copyin Failed\n");
		kmem_free(subcode, sizeof (struct cdrom_subcode));
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	/*
	 * Since MMC-2 expects max 3 bytes for length, check if the
	 * length input is greater than 3 bytes
	 */
	if ((subcode->cdsc_length & 0xFF000000) != 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_read_all_subcodes: "
		    "cdrom transfer length too large: %d (limit %d)\n",
		    subcode->cdsc_length, 0xFFFFFF);
		kmem_free(subcode, sizeof (struct cdrom_subcode));
		return (EINVAL);
	}

	buflen = CDROM_BLK_SUBCODE * subcode->cdsc_length;
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	bzero(cdb, CDB_GROUP5);

	if (un->un_f_mmc_cap == TRUE) {
		cdb[0] = (char)SCMD_READ_CD;
		cdb[2] = (char)0xff;
		cdb[3] = (char)0xff;
		cdb[4] = (char)0xff;
		cdb[5] = (char)0xff;
		cdb[6] = (((subcode->cdsc_length) & 0x00ff0000) >> 16);
		cdb[7] = (((subcode->cdsc_length) & 0x0000ff00) >> 8);
		cdb[8] = ((subcode->cdsc_length) & 0x000000ff);
		cdb[10] = 1;
	} else {
		/*
		 * Note: A vendor specific command (0xDF) is being used here to
		 * request a read of all subcodes.
		 */
		cdb[0] = (char)SCMD_READ_ALL_SUBCODES;
		cdb[6] = (((subcode->cdsc_length) & 0xff000000) >> 24);
		cdb[7] = (((subcode->cdsc_length) & 0x00ff0000) >> 16);
		cdb[8] = (((subcode->cdsc_length) & 0x0000ff00) >> 8);
		cdb[9] = ((subcode->cdsc_length) & 0x000000ff);
	}
	com->uscsi_cdb	   = cdb;
	com->uscsi_cdblen  = CDB_GROUP5;
	com->uscsi_bufaddr = (caddr_t)subcode->cdsc_addr;
	com->uscsi_buflen  = buflen;
	com->uscsi_flags   = USCSI_DIAGNOSE|USCSI_SILENT|USCSI_READ;
	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_USERSPACE,
	    SD_PATH_STANDARD);
	kmem_free(subcode, sizeof (struct cdrom_subcode));
	kmem_free(com, sizeof (*com));
	return (rval);
}


/*
 *    Function: sr_read_subchannel()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl requests to return the Q sub-channel data of the CD
 *		current position block. (CDROMSUBCHNL) The data includes the
 *		track number, index number, absolute CD-ROM address (LBA or MSF
 *		format per the user) , track relative CD-ROM address (LBA or MSF
 *		format per the user), control data and audio status.
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided cdrom sub-channel structure
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *		          directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_read_subchannel(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct uscsi_cmd	*com;
	struct cdrom_subchnl	subchanel;
	struct cdrom_subchnl	*subchnl = &subchanel;
	char			cdb[CDB_GROUP1];
	caddr_t			buffer;
	int			rval;

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	if (ddi_copyin(data, subchnl, sizeof (struct cdrom_subchnl), flag)) {
		return (EFAULT);
	}

	buffer = kmem_zalloc((size_t)16, KM_SLEEP);
	bzero(cdb, CDB_GROUP1);
	cdb[0] = SCMD_READ_SUBCHANNEL;
	/* Set the MSF bit based on the user requested address format */
	cdb[1] = (subchnl->cdsc_format & CDROM_LBA) ? 0 : 0x02;
	/*
	 * Set the Q bit in byte 2 to indicate that Q sub-channel data be
	 * returned
	 */
	cdb[2] = 0x40;
	/*
	 * Set byte 3 to specify the return data format. A value of 0x01
	 * indicates that the CD-ROM current position should be returned.
	 */
	cdb[3] = 0x01;
	cdb[8] = 0x10;
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	com->uscsi_cdb	   = cdb;
	com->uscsi_cdblen  = CDB_GROUP1;
	com->uscsi_bufaddr = buffer;
	com->uscsi_buflen  = 16;
	com->uscsi_flags   = USCSI_DIAGNOSE|USCSI_SILENT|USCSI_READ;
	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
	    SD_PATH_STANDARD);
	if (rval != 0) {
		kmem_free(buffer, 16);
		kmem_free(com, sizeof (*com));
		return (rval);
	}

	/* Process the returned Q sub-channel data */
	subchnl->cdsc_audiostatus = buffer[1];
	subchnl->cdsc_adr	= (buffer[5] & 0xF0) >> 4;
	subchnl->cdsc_ctrl	= (buffer[5] & 0x0F);
	subchnl->cdsc_trk	= buffer[6];
	subchnl->cdsc_ind	= buffer[7];
	if (subchnl->cdsc_format & CDROM_LBA) {
		subchnl->cdsc_absaddr.lba =
		    ((uchar_t)buffer[8] << 24) + ((uchar_t)buffer[9] << 16) +
		    ((uchar_t)buffer[10] << 8) + ((uchar_t)buffer[11]);
		subchnl->cdsc_reladdr.lba =
		    ((uchar_t)buffer[12] << 24) + ((uchar_t)buffer[13] << 16) +
		    ((uchar_t)buffer[14] << 8) + ((uchar_t)buffer[15]);
	} else if (un->un_f_cfg_readsub_bcd == TRUE) {
		subchnl->cdsc_absaddr.msf.minute = BCD_TO_BYTE(buffer[9]);
		subchnl->cdsc_absaddr.msf.second = BCD_TO_BYTE(buffer[10]);
		subchnl->cdsc_absaddr.msf.frame  = BCD_TO_BYTE(buffer[11]);
		subchnl->cdsc_reladdr.msf.minute = BCD_TO_BYTE(buffer[13]);
		subchnl->cdsc_reladdr.msf.second = BCD_TO_BYTE(buffer[14]);
		subchnl->cdsc_reladdr.msf.frame  = BCD_TO_BYTE(buffer[15]);
	} else {
		subchnl->cdsc_absaddr.msf.minute = buffer[9];
		subchnl->cdsc_absaddr.msf.second = buffer[10];
		subchnl->cdsc_absaddr.msf.frame  = buffer[11];
		subchnl->cdsc_reladdr.msf.minute = buffer[13];
		subchnl->cdsc_reladdr.msf.second = buffer[14];
		subchnl->cdsc_reladdr.msf.frame  = buffer[15];
	}
	kmem_free(buffer, 16);
	kmem_free(com, sizeof (*com));
	if (ddi_copyout(subchnl, data, sizeof (struct cdrom_subchnl), flag)
	    != 0) {
		return (EFAULT);
	}
	return (rval);
}


/*
 *    Function: sr_read_tocentry()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl requests to read from the Table of Contents (TOC)
 *		(CDROMREADTOCENTRY). This routine provides the ADR and CTRL
 *		fields, the starting address (LBA or MSF format per the user)
 *		and the data mode if the user specified track is a data track.
 *
 *		Note: The READ HEADER (0x44) command used in this routine is
 *		obsolete per the SCSI MMC spec but still supported in the
 *		MT FUJI vendor spec. Most equipment is adhereing to MT FUJI
 *		therefore the command is still implemented in this routine.
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided toc entry structure,
 *			  specifying the track # and the address format
 *			  (LBA or MSF).
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *		          directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_read_tocentry(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un = NULL;
	struct uscsi_cmd	*com;
	struct cdrom_tocentry	toc_entry;
	struct cdrom_tocentry	*entry = &toc_entry;
	caddr_t			buffer;
	int			rval;
	char			cdb[CDB_GROUP1];

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	if (ddi_copyin(data, entry, sizeof (struct cdrom_tocentry), flag)) {
		return (EFAULT);
	}

	/* Validate the requested track and address format */
	if (!(entry->cdte_format & (CDROM_LBA | CDROM_MSF))) {
		return (EINVAL);
	}

	if (entry->cdte_track == 0) {
		return (EINVAL);
	}

	buffer = kmem_zalloc((size_t)12, KM_SLEEP);
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	bzero(cdb, CDB_GROUP1);

	cdb[0] = SCMD_READ_TOC;
	/* Set the MSF bit based on the user requested address format  */
	cdb[1] = ((entry->cdte_format & CDROM_LBA) ? 0 : 2);
	if (un->un_f_cfg_read_toc_trk_bcd == TRUE) {
		cdb[6] = BYTE_TO_BCD(entry->cdte_track);
	} else {
		cdb[6] = entry->cdte_track;
	}

	/*
	 * Bytes 7 & 8 are the 12 byte allocation length for a single entry.
	 * (4 byte TOC response header + 8 byte track descriptor)
	 */
	cdb[8] = 12;
	com->uscsi_cdb	   = cdb;
	com->uscsi_cdblen  = CDB_GROUP1;
	com->uscsi_bufaddr = buffer;
	com->uscsi_buflen  = 0x0C;
	com->uscsi_flags   = (USCSI_DIAGNOSE | USCSI_SILENT | USCSI_READ);
	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
	    SD_PATH_STANDARD);
	if (rval != 0) {
		kmem_free(buffer, 12);
		kmem_free(com, sizeof (*com));
		return (rval);
	}

	/* Process the toc entry */
	entry->cdte_adr		= (buffer[5] & 0xF0) >> 4;
	entry->cdte_ctrl	= (buffer[5] & 0x0F);
	if (entry->cdte_format & CDROM_LBA) {
		entry->cdte_addr.lba =
		    ((uchar_t)buffer[8] << 24) + ((uchar_t)buffer[9] << 16) +
		    ((uchar_t)buffer[10] << 8) + ((uchar_t)buffer[11]);
	} else if (un->un_f_cfg_read_toc_addr_bcd == TRUE) {
		entry->cdte_addr.msf.minute	= BCD_TO_BYTE(buffer[9]);
		entry->cdte_addr.msf.second	= BCD_TO_BYTE(buffer[10]);
		entry->cdte_addr.msf.frame	= BCD_TO_BYTE(buffer[11]);
		/*
		 * Send a READ TOC command using the LBA address format to get
		 * the LBA for the track requested so it can be used in the
		 * READ HEADER request
		 *
		 * Note: The MSF bit of the READ HEADER command specifies the
		 * output format. The block address specified in that command
		 * must be in LBA format.
		 */
		cdb[1] = 0;
		rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
		    SD_PATH_STANDARD);
		if (rval != 0) {
			kmem_free(buffer, 12);
			kmem_free(com, sizeof (*com));
			return (rval);
		}
	} else {
		entry->cdte_addr.msf.minute	= buffer[9];
		entry->cdte_addr.msf.second	= buffer[10];
		entry->cdte_addr.msf.frame	= buffer[11];
		/*
		 * Send a READ TOC command using the LBA address format to get
		 * the LBA for the track requested so it can be used in the
		 * READ HEADER request
		 *
		 * Note: The MSF bit of the READ HEADER command specifies the
		 * output format. The block address specified in that command
		 * must be in LBA format.
		 */
		cdb[1] = 0;
		rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
		    SD_PATH_STANDARD);
		if (rval != 0) {
			kmem_free(buffer, 12);
			kmem_free(com, sizeof (*com));
			return (rval);
		}
	}

	/*
	 * Build and send the READ HEADER command to determine the data mode of
	 * the user specified track.
	 */
	if ((entry->cdte_ctrl & CDROM_DATA_TRACK) &&
	    (entry->cdte_track != CDROM_LEADOUT)) {
		bzero(cdb, CDB_GROUP1);
		cdb[0] = SCMD_READ_HEADER;
		cdb[2] = buffer[8];
		cdb[3] = buffer[9];
		cdb[4] = buffer[10];
		cdb[5] = buffer[11];
		cdb[8] = 0x08;
		com->uscsi_buflen = 0x08;
		rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
		    SD_PATH_STANDARD);
		if (rval == 0) {
			entry->cdte_datamode = buffer[0];
		} else {
			/*
			 * READ HEADER command failed, since this is
			 * obsoleted in one spec, its better to return
			 * -1 for an invlid track so that we can still
			 * receive the rest of the TOC data.
			 */
			entry->cdte_datamode = (uchar_t)-1;
		}
	} else {
		entry->cdte_datamode = (uchar_t)-1;
	}

	kmem_free(buffer, 12);
	kmem_free(com, sizeof (*com));
	if (ddi_copyout(entry, data, sizeof (struct cdrom_tocentry), flag) != 0)
		return (EFAULT);

	return (rval);
}


/*
 *    Function: sr_read_tochdr()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 * 		ioctl requests to read the Table of Contents (TOC) header
 *		(CDROMREADTOHDR). The TOC header consists of the disk starting
 *		and ending track numbers
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided toc header structure,
 *			  specifying the starting and ending track numbers.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_read_tochdr(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct uscsi_cmd	*com;
	struct cdrom_tochdr	toc_header;
	struct cdrom_tochdr	*hdr = &toc_header;
	char			cdb[CDB_GROUP1];
	int			rval;
	caddr_t			buffer;

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	buffer = kmem_zalloc(4, KM_SLEEP);
	bzero(cdb, CDB_GROUP1);
	cdb[0] = SCMD_READ_TOC;
	/*
	 * Specifying a track number of 0x00 in the READ TOC command indicates
	 * that the TOC header should be returned
	 */
	cdb[6] = 0x00;
	/*
	 * Bytes 7 & 8 are the 4 byte allocation length for TOC header.
	 * (2 byte data len + 1 byte starting track # + 1 byte ending track #)
	 */
	cdb[8] = 0x04;
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	com->uscsi_cdb	   = cdb;
	com->uscsi_cdblen  = CDB_GROUP1;
	com->uscsi_bufaddr = buffer;
	com->uscsi_buflen  = 0x04;
	com->uscsi_timeout = 300;
	com->uscsi_flags   = USCSI_DIAGNOSE|USCSI_SILENT|USCSI_READ;

	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
	    SD_PATH_STANDARD);
	if (un->un_f_cfg_read_toc_trk_bcd == TRUE) {
		hdr->cdth_trk0 = BCD_TO_BYTE(buffer[2]);
		hdr->cdth_trk1 = BCD_TO_BYTE(buffer[3]);
	} else {
		hdr->cdth_trk0 = buffer[2];
		hdr->cdth_trk1 = buffer[3];
	}
	kmem_free(buffer, 4);
	kmem_free(com, sizeof (*com));
	if (ddi_copyout(hdr, data, sizeof (struct cdrom_tochdr), flag) != 0) {
		return (EFAULT);
	}
	return (rval);
}


/*
 * Note: The following sr_read_mode1(), sr_read_cd_mode2(), sr_read_mode2(),
 * sr_read_cdda(), sr_read_cdxa(), routines implement driver support for
 * handling CDROMREAD ioctl requests for mode 1 user data, mode 2 user data,
 * digital audio and extended architecture digital audio. These modes are
 * defined in the IEC908 (Red Book), ISO10149 (Yellow Book), and the SCSI3
 * MMC specs.
 *
 * In addition to support for the various data formats these routines also
 * include support for devices that implement only the direct access READ
 * commands (0x08, 0x28), devices that implement the READ_CD commands
 * (0xBE, 0xD4), and devices that implement the vendor unique READ CDDA and
 * READ CDXA commands (0xD8, 0xDB)
 */

/*
 *    Function: sr_read_mode1()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl read mode1 requests (CDROMREADMODE1).
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided cd read structure specifying
 *			  the lba buffer address and length.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_read_mode1(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct cdrom_read	mode1_struct;
	struct cdrom_read	*mode1 = &mode1_struct;
	int			rval;
	sd_ssc_t		*ssc;

#ifdef _MULTI_DATAMODEL
	/* To support ILP32 applications in an LP64 world */
	struct cdrom_read32	cdrom_read32;
	struct cdrom_read32	*cdrd32 = &cdrom_read32;
#endif /* _MULTI_DATAMODEL */

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_read_mode1: entry: un:0x%p\n", un);

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin(data, cdrd32, sizeof (*cdrd32), flag) != 0) {
			return (EFAULT);
		}
		/* Convert the ILP32 uscsi data from the application to LP64 */
		cdrom_read32tocdrom_read(cdrd32, mode1);
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin(data, mode1, sizeof (struct cdrom_read), flag)) {
			return (EFAULT);
		}
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin(data, mode1, sizeof (struct cdrom_read), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_READ(ssc, mode1->cdread_bufaddr,
	    mode1->cdread_buflen, mode1->cdread_lba, SD_PATH_STANDARD);
	sd_ssc_fini(ssc);

	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_read_mode1: exit: un:0x%p\n", un);

	return (rval);
}


/*
 *    Function: sr_read_cd_mode2()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl read mode2 requests (CDROMREADMODE2) for devices that
 *		support the READ CD (0xBE) command or the 1st generation
 *		READ CD (0xD4) command.
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided cd read structure specifying
 *			  the lba buffer address and length.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_read_cd_mode2(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct uscsi_cmd	*com;
	struct cdrom_read	mode2_struct;
	struct cdrom_read	*mode2 = &mode2_struct;
	uchar_t			cdb[CDB_GROUP5];
	int			nblocks;
	int			rval;
#ifdef _MULTI_DATAMODEL
	/*  To support ILP32 applications in an LP64 world */
	struct cdrom_read32	cdrom_read32;
	struct cdrom_read32	*cdrd32 = &cdrom_read32;
#endif /* _MULTI_DATAMODEL */

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin(data, cdrd32, sizeof (*cdrd32), flag) != 0) {
			return (EFAULT);
		}
		/* Convert the ILP32 uscsi data from the application to LP64 */
		cdrom_read32tocdrom_read(cdrd32, mode2);
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin(data, mode2, sizeof (*mode2), flag) != 0) {
			return (EFAULT);
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin(data, mode2, sizeof (*mode2), flag) != 0) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	bzero(cdb, sizeof (cdb));
	if (un->un_f_cfg_read_cd_xd4 == TRUE) {
		/* Read command supported by 1st generation atapi drives */
		cdb[0] = SCMD_READ_CDD4;
	} else {
		/* Universal CD Access Command */
		cdb[0] = SCMD_READ_CD;
	}

	/*
	 * Set expected sector type to: 2336s byte, Mode 2 Yellow Book
	 */
	cdb[1] = CDROM_SECTOR_TYPE_MODE2;

	/* set the start address */
	cdb[2] = (uchar_t)((mode2->cdread_lba >> 24) & 0XFF);
	cdb[3] = (uchar_t)((mode2->cdread_lba >> 16) & 0XFF);
	cdb[4] = (uchar_t)((mode2->cdread_lba >> 8) & 0xFF);
	cdb[5] = (uchar_t)(mode2->cdread_lba & 0xFF);

	/* set the transfer length */
	nblocks = mode2->cdread_buflen / 2336;
	cdb[6] = (uchar_t)(nblocks >> 16);
	cdb[7] = (uchar_t)(nblocks >> 8);
	cdb[8] = (uchar_t)nblocks;

	/* set the filter bits */
	cdb[9] = CDROM_READ_CD_USERDATA;

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	com->uscsi_cdb = (caddr_t)cdb;
	com->uscsi_cdblen = sizeof (cdb);
	com->uscsi_bufaddr = mode2->cdread_bufaddr;
	com->uscsi_buflen = mode2->cdread_buflen;
	com->uscsi_flags = USCSI_DIAGNOSE|USCSI_SILENT|USCSI_READ;

	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_USERSPACE,
	    SD_PATH_STANDARD);
	kmem_free(com, sizeof (*com));
	return (rval);
}


/*
 *    Function: sr_read_mode2()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl read mode2 requests (CDROMREADMODE2) for devices that
 *		do not support the READ CD (0xBE) command.
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided cd read structure specifying
 *			  the lba buffer address and length.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 *		EIO if fail to reset block size
 *		EAGAIN if commands are in progress in the driver
 */

static int
sr_read_mode2(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct cdrom_read	mode2_struct;
	struct cdrom_read	*mode2 = &mode2_struct;
	int			rval;
	uint32_t		restore_blksize;
	struct uscsi_cmd	*com;
	uchar_t			cdb[CDB_GROUP0];
	int			nblocks;

#ifdef _MULTI_DATAMODEL
	/* To support ILP32 applications in an LP64 world */
	struct cdrom_read32	cdrom_read32;
	struct cdrom_read32	*cdrd32 = &cdrom_read32;
#endif /* _MULTI_DATAMODEL */

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	/*
	 * Because this routine will update the device and driver block size
	 * being used we want to make sure there are no commands in progress.
	 * If commands are in progress the user will have to try again.
	 *
	 * We check for 1 instead of 0 because we increment un_ncmds_in_driver
	 * in sdioctl to protect commands from sdioctl through to the top of
	 * sd_uscsi_strategy. See sdioctl for details.
	 */
	mutex_enter(SD_MUTEX(un));
	if (un->un_ncmds_in_driver != 1) {
		mutex_exit(SD_MUTEX(un));
		return (EAGAIN);
	}
	mutex_exit(SD_MUTEX(un));

	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_read_mode2: entry: un:0x%p\n", un);

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin(data, cdrd32, sizeof (*cdrd32), flag) != 0) {
			return (EFAULT);
		}
		/* Convert the ILP32 uscsi data from the application to LP64 */
		cdrom_read32tocdrom_read(cdrd32, mode2);
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin(data, mode2, sizeof (*mode2), flag) != 0) {
			return (EFAULT);
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin(data, mode2, sizeof (*mode2), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	/* Store the current target block size for restoration later */
	restore_blksize = un->un_tgt_blocksize;

	/* Change the device and soft state target block size to 2336 */
	if (sr_sector_mode(dev, SD_MODE2_BLKSIZE) != 0) {
		rval = EIO;
		goto done;
	}


	bzero(cdb, sizeof (cdb));

	/* set READ operation */
	cdb[0] = SCMD_READ;

	/* adjust lba for 2kbyte blocks from 512 byte blocks */
	mode2->cdread_lba >>= 2;

	/* set the start address */
	cdb[1] = (uchar_t)((mode2->cdread_lba >> 16) & 0X1F);
	cdb[2] = (uchar_t)((mode2->cdread_lba >> 8) & 0xFF);
	cdb[3] = (uchar_t)(mode2->cdread_lba & 0xFF);

	/* set the transfer length */
	nblocks = mode2->cdread_buflen / 2336;
	cdb[4] = (uchar_t)nblocks & 0xFF;

	/* build command */
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	com->uscsi_cdb = (caddr_t)cdb;
	com->uscsi_cdblen = sizeof (cdb);
	com->uscsi_bufaddr = mode2->cdread_bufaddr;
	com->uscsi_buflen = mode2->cdread_buflen;
	com->uscsi_flags = USCSI_DIAGNOSE|USCSI_SILENT|USCSI_READ;

	/*
	 * Issue SCSI command with user space address for read buffer.
	 *
	 * This sends the command through main channel in the driver.
	 *
	 * Since this is accessed via an IOCTL call, we go through the
	 * standard path, so that if the device was powered down, then
	 * it would be 'awakened' to handle the command.
	 */
	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_USERSPACE,
	    SD_PATH_STANDARD);

	kmem_free(com, sizeof (*com));

	/* Restore the device and soft state target block size */
	if (sr_sector_mode(dev, restore_blksize) != 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "can't do switch back to mode 1\n");
		/*
		 * If sd_send_scsi_READ succeeded we still need to report
		 * an error because we failed to reset the block size
		 */
		if (rval == 0) {
			rval = EIO;
		}
	}

done:
	SD_TRACE(SD_LOG_ATTACH_DETACH, un,
	    "sd_read_mode2: exit: un:0x%p\n", un);

	return (rval);
}


/*
 *    Function: sr_sector_mode()
 *
 * Description: This utility function is used by sr_read_mode2 to set the target
 *		block size based on the user specified size. This is a legacy
 *		implementation based upon a vendor specific mode page
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- flag indicating if block size is being set to 2336 or
 *			  512.
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_sector_mode(dev_t dev, uint32_t blksize)
{
	struct sd_lun	*un;
	uchar_t		*sense;
	uchar_t		*select;
	int		rval;
	sd_ssc_t	*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	sense = kmem_zalloc(20, KM_SLEEP);

	/* Note: This is a vendor specific mode page (0x81) */
	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP0, sense, 20, 0x81,
	    SD_PATH_STANDARD);
	sd_ssc_fini(ssc);
	if (rval != 0) {
		SD_ERROR(SD_LOG_IOCTL_RMMEDIA, un,
		    "sr_sector_mode: Mode Sense failed\n");
		kmem_free(sense, 20);
		return (rval);
	}
	select = kmem_zalloc(20, KM_SLEEP);
	select[3] = 0x08;
	select[10] = ((blksize >> 8) & 0xff);
	select[11] = (blksize & 0xff);
	select[12] = 0x01;
	select[13] = 0x06;
	select[14] = sense[14];
	select[15] = sense[15];
	if (blksize == SD_MODE2_BLKSIZE) {
		select[14] |= 0x01;
	}

	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP0, select, 20,
	    SD_DONTSAVE_PAGE, SD_PATH_STANDARD);
	sd_ssc_fini(ssc);
	if (rval != 0) {
		SD_ERROR(SD_LOG_IOCTL_RMMEDIA, un,
		    "sr_sector_mode: Mode Select failed\n");
	} else {
		/*
		 * Only update the softstate block size if we successfully
		 * changed the device block mode.
		 */
		mutex_enter(SD_MUTEX(un));
		sd_update_block_info(un, blksize, 0);
		mutex_exit(SD_MUTEX(un));
	}
	kmem_free(sense, 20);
	kmem_free(select, 20);
	return (rval);
}


/*
 *    Function: sr_read_cdda()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl requests to return CD-DA or subcode data. (CDROMCDDA) If
 *		the target supports CDDA these requests are handled via a vendor
 *		specific command (0xD8) If the target does not support CDDA
 *		these requests are handled via the READ CD command (0xBE).
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided CD-DA structure specifying
 *			  the track starting address, transfer length, and
 *			  subcode options.
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if invalid arguments are provided
 *		ENOTTY
 */

static int
sr_read_cdda(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun			*un;
	struct uscsi_cmd		*com;
	struct cdrom_cdda		*cdda;
	int				rval;
	size_t				buflen;
	char				cdb[CDB_GROUP5];

#ifdef _MULTI_DATAMODEL
	/* To support ILP32 applications in an LP64 world */
	struct cdrom_cdda32	cdrom_cdda32;
	struct cdrom_cdda32	*cdda32 = &cdrom_cdda32;
#endif /* _MULTI_DATAMODEL */

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	cdda = kmem_zalloc(sizeof (struct cdrom_cdda), KM_SLEEP);

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin(data, cdda32, sizeof (*cdda32), flag)) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_read_cdda: ddi_copyin Failed\n");
			kmem_free(cdda, sizeof (struct cdrom_cdda));
			return (EFAULT);
		}
		/* Convert the ILP32 uscsi data from the application to LP64 */
		cdrom_cdda32tocdrom_cdda(cdda32, cdda);
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin(data, cdda, sizeof (struct cdrom_cdda), flag)) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_read_cdda: ddi_copyin Failed\n");
			kmem_free(cdda, sizeof (struct cdrom_cdda));
			return (EFAULT);
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin(data, cdda, sizeof (struct cdrom_cdda), flag)) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_read_cdda: ddi_copyin Failed\n");
		kmem_free(cdda, sizeof (struct cdrom_cdda));
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	/*
	 * Since MMC-2 expects max 3 bytes for length, check if the
	 * length input is greater than 3 bytes
	 */
	if ((cdda->cdda_length & 0xFF000000) != 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN, "sr_read_cdda: "
		    "cdrom transfer length too large: %d (limit %d)\n",
		    cdda->cdda_length, 0xFFFFFF);
		kmem_free(cdda, sizeof (struct cdrom_cdda));
		return (EINVAL);
	}

	switch (cdda->cdda_subcode) {
	case CDROM_DA_NO_SUBCODE:
		buflen = CDROM_BLK_2352 * cdda->cdda_length;
		break;
	case CDROM_DA_SUBQ:
		buflen = CDROM_BLK_2368 * cdda->cdda_length;
		break;
	case CDROM_DA_ALL_SUBCODE:
		buflen = CDROM_BLK_2448 * cdda->cdda_length;
		break;
	case CDROM_DA_SUBCODE_ONLY:
		buflen = CDROM_BLK_SUBCODE * cdda->cdda_length;
		break;
	default:
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_read_cdda: Subcode '0x%x' Not Supported\n",
		    cdda->cdda_subcode);
		kmem_free(cdda, sizeof (struct cdrom_cdda));
		return (EINVAL);
	}

	/* Build and send the command */
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	bzero(cdb, CDB_GROUP5);

	if (un->un_f_cfg_cdda == TRUE) {
		cdb[0] = (char)SCMD_READ_CD;
		cdb[1] = 0x04;
		cdb[2] = (((cdda->cdda_addr) & 0xff000000) >> 24);
		cdb[3] = (((cdda->cdda_addr) & 0x00ff0000) >> 16);
		cdb[4] = (((cdda->cdda_addr) & 0x0000ff00) >> 8);
		cdb[5] = ((cdda->cdda_addr) & 0x000000ff);
		cdb[6] = (((cdda->cdda_length) & 0x00ff0000) >> 16);
		cdb[7] = (((cdda->cdda_length) & 0x0000ff00) >> 8);
		cdb[8] = ((cdda->cdda_length) & 0x000000ff);
		cdb[9] = 0x10;
		switch (cdda->cdda_subcode) {
		case CDROM_DA_NO_SUBCODE :
			cdb[10] = 0x0;
			break;
		case CDROM_DA_SUBQ :
			cdb[10] = 0x2;
			break;
		case CDROM_DA_ALL_SUBCODE :
			cdb[10] = 0x1;
			break;
		case CDROM_DA_SUBCODE_ONLY :
			/* FALLTHROUGH */
		default :
			kmem_free(cdda, sizeof (struct cdrom_cdda));
			kmem_free(com, sizeof (*com));
			return (ENOTTY);
		}
	} else {
		cdb[0] = (char)SCMD_READ_CDDA;
		cdb[2] = (((cdda->cdda_addr) & 0xff000000) >> 24);
		cdb[3] = (((cdda->cdda_addr) & 0x00ff0000) >> 16);
		cdb[4] = (((cdda->cdda_addr) & 0x0000ff00) >> 8);
		cdb[5] = ((cdda->cdda_addr) & 0x000000ff);
		cdb[6] = (((cdda->cdda_length) & 0xff000000) >> 24);
		cdb[7] = (((cdda->cdda_length) & 0x00ff0000) >> 16);
		cdb[8] = (((cdda->cdda_length) & 0x0000ff00) >> 8);
		cdb[9] = ((cdda->cdda_length) & 0x000000ff);
		cdb[10] = cdda->cdda_subcode;
	}

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP5;
	com->uscsi_bufaddr = (caddr_t)cdda->cdda_data;
	com->uscsi_buflen = buflen;
	com->uscsi_flags = USCSI_DIAGNOSE|USCSI_SILENT|USCSI_READ;

	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_USERSPACE,
	    SD_PATH_STANDARD);

	kmem_free(cdda, sizeof (struct cdrom_cdda));
	kmem_free(com, sizeof (*com));
	return (rval);
}


/*
 *    Function: sr_read_cdxa()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl requests to return CD-XA (Extended Architecture) data.
 *		(CDROMCDXA).
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user provided CD-XA structure specifying
 *			  the data starting address, transfer length, and format
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_read_cdxa(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct uscsi_cmd	*com;
	struct cdrom_cdxa	*cdxa;
	int			rval;
	size_t			buflen;
	char			cdb[CDB_GROUP5];
	uchar_t			read_flags;

#ifdef _MULTI_DATAMODEL
	/* To support ILP32 applications in an LP64 world */
	struct cdrom_cdxa32		cdrom_cdxa32;
	struct cdrom_cdxa32		*cdxa32 = &cdrom_cdxa32;
#endif /* _MULTI_DATAMODEL */

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (ENXIO);
	}

	cdxa = kmem_zalloc(sizeof (struct cdrom_cdxa), KM_SLEEP);

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin(data, cdxa32, sizeof (*cdxa32), flag)) {
			kmem_free(cdxa, sizeof (struct cdrom_cdxa));
			return (EFAULT);
		}
		/*
		 * Convert the ILP32 uscsi data from the
		 * application to LP64 for internal use.
		 */
		cdrom_cdxa32tocdrom_cdxa(cdxa32, cdxa);
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin(data, cdxa, sizeof (struct cdrom_cdxa), flag)) {
			kmem_free(cdxa, sizeof (struct cdrom_cdxa));
			return (EFAULT);
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin(data, cdxa, sizeof (struct cdrom_cdxa), flag)) {
		kmem_free(cdxa, sizeof (struct cdrom_cdxa));
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	/*
	 * Since MMC-2 expects max 3 bytes for length, check if the
	 * length input is greater than 3 bytes
	 */
	if ((cdxa->cdxa_length & 0xFF000000) != 0) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN, "sr_read_cdxa: "
		    "cdrom transfer length too large: %d (limit %d)\n",
		    cdxa->cdxa_length, 0xFFFFFF);
		kmem_free(cdxa, sizeof (struct cdrom_cdxa));
		return (EINVAL);
	}

	switch (cdxa->cdxa_format) {
	case CDROM_XA_DATA:
		buflen = CDROM_BLK_2048 * cdxa->cdxa_length;
		read_flags = 0x10;
		break;
	case CDROM_XA_SECTOR_DATA:
		buflen = CDROM_BLK_2352 * cdxa->cdxa_length;
		read_flags = 0xf8;
		break;
	case CDROM_XA_DATA_W_ERROR:
		buflen = CDROM_BLK_2646 * cdxa->cdxa_length;
		read_flags = 0xfc;
		break;
	default:
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sr_read_cdxa: Format '0x%x' Not Supported\n",
		    cdxa->cdxa_format);
		kmem_free(cdxa, sizeof (struct cdrom_cdxa));
		return (EINVAL);
	}

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	bzero(cdb, CDB_GROUP5);
	if (un->un_f_mmc_cap == TRUE) {
		cdb[0] = (char)SCMD_READ_CD;
		cdb[2] = (((cdxa->cdxa_addr) & 0xff000000) >> 24);
		cdb[3] = (((cdxa->cdxa_addr) & 0x00ff0000) >> 16);
		cdb[4] = (((cdxa->cdxa_addr) & 0x0000ff00) >> 8);
		cdb[5] = ((cdxa->cdxa_addr) & 0x000000ff);
		cdb[6] = (((cdxa->cdxa_length) & 0x00ff0000) >> 16);
		cdb[7] = (((cdxa->cdxa_length) & 0x0000ff00) >> 8);
		cdb[8] = ((cdxa->cdxa_length) & 0x000000ff);
		cdb[9] = (char)read_flags;
	} else {
		/*
		 * Note: A vendor specific command (0xDB) is being used her to
		 * request a read of all subcodes.
		 */
		cdb[0] = (char)SCMD_READ_CDXA;
		cdb[2] = (((cdxa->cdxa_addr) & 0xff000000) >> 24);
		cdb[3] = (((cdxa->cdxa_addr) & 0x00ff0000) >> 16);
		cdb[4] = (((cdxa->cdxa_addr) & 0x0000ff00) >> 8);
		cdb[5] = ((cdxa->cdxa_addr) & 0x000000ff);
		cdb[6] = (((cdxa->cdxa_length) & 0xff000000) >> 24);
		cdb[7] = (((cdxa->cdxa_length) & 0x00ff0000) >> 16);
		cdb[8] = (((cdxa->cdxa_length) & 0x0000ff00) >> 8);
		cdb[9] = ((cdxa->cdxa_length) & 0x000000ff);
		cdb[10] = cdxa->cdxa_format;
	}
	com->uscsi_cdb	   = cdb;
	com->uscsi_cdblen  = CDB_GROUP5;
	com->uscsi_bufaddr = (caddr_t)cdxa->cdxa_data;
	com->uscsi_buflen  = buflen;
	com->uscsi_flags   = USCSI_DIAGNOSE|USCSI_SILENT|USCSI_READ;
	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_USERSPACE,
	    SD_PATH_STANDARD);
	kmem_free(cdxa, sizeof (struct cdrom_cdxa));
	kmem_free(com, sizeof (*com));
	return (rval);
}


/*
 *    Function: sr_eject()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		eject ioctl requests (FDEJECT, DKIOCEJECT, CDROMEJECT)
 *
 *   Arguments: dev	- the device 'dev_t'
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 */

static int
sr_eject(dev_t dev)
{
	struct sd_lun	*un;
	int		rval;
	sd_ssc_t	*ssc;

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	/*
	 * To prevent race conditions with the eject
	 * command, keep track of an eject command as
	 * it progresses. If we are already handling
	 * an eject command in the driver for the given
	 * unit and another request to eject is received
	 * immediately return EAGAIN so we don't lose
	 * the command if the current eject command fails.
	 */
	mutex_enter(SD_MUTEX(un));
	if (un->un_f_ejecting == TRUE) {
		mutex_exit(SD_MUTEX(un));
		return (EAGAIN);
	}
	un->un_f_ejecting = TRUE;
	mutex_exit(SD_MUTEX(un));

	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_DOORLOCK(ssc, SD_REMOVAL_ALLOW,
	    SD_PATH_STANDARD);
	sd_ssc_fini(ssc);

	if (rval != 0) {
		mutex_enter(SD_MUTEX(un));
		un->un_f_ejecting = FALSE;
		mutex_exit(SD_MUTEX(un));
		return (rval);
	}

	ssc = sd_ssc_init(un);
	rval = sd_send_scsi_START_STOP_UNIT(ssc, SD_START_STOP,
	    SD_TARGET_EJECT, SD_PATH_STANDARD);
	sd_ssc_fini(ssc);

	if (rval == 0) {
		mutex_enter(SD_MUTEX(un));
		sr_ejected(un);
		un->un_mediastate = DKIO_EJECTED;
		un->un_f_ejecting = FALSE;
		cv_broadcast(&un->un_state_cv);
		mutex_exit(SD_MUTEX(un));
	} else {
		mutex_enter(SD_MUTEX(un));
		un->un_f_ejecting = FALSE;
		mutex_exit(SD_MUTEX(un));
	}
	return (rval);
}


/*
 *    Function: sr_ejected()
 *
 * Description: This routine updates the soft state structure to invalidate the
 *		geometry information after the media has been ejected or a
 *		media eject has been detected.
 *
 *   Arguments: un - driver soft state (unit) structure
 */

static void
sr_ejected(struct sd_lun *un)
{
	struct sd_errstats *stp;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	un->un_f_blockcount_is_valid	= FALSE;
	un->un_f_tgt_blocksize_is_valid	= FALSE;
	mutex_exit(SD_MUTEX(un));
	cmlb_invalidate(un->un_cmlbhandle, (void *)SD_PATH_DIRECT_PRIORITY);
	mutex_enter(SD_MUTEX(un));

	if (un->un_errstats != NULL) {
		stp = (struct sd_errstats *)un->un_errstats->ks_data;
		stp->sd_capacity.value.ui64 = 0;
	}
}


/*
 *    Function: sr_check_wp()
 *
 * Description: This routine checks the write protection of a removable
 *      media disk and hotpluggable devices via the write protect bit of
 *      the Mode Page Header device specific field. Some devices choke
 *      on unsupported mode page. In order to workaround this issue,
 *      this routine has been implemented to use 0x3f mode page(request
 *      for all pages) for all device types.
 *
 *   Arguments: dev             - the device 'dev_t'
 *
 * Return Code: int indicating if the device is write protected (1) or not (0)
 *
 *     Context: Kernel thread.
 *
 */

static int
sr_check_wp(dev_t dev)
{
	struct sd_lun	*un;
	uchar_t		device_specific;
	uchar_t		*sense;
	int		hdrlen;
	int		rval = FALSE;
	int		status;
	sd_ssc_t	*ssc;

	/*
	 * Note: The return codes for this routine should be reworked to
	 * properly handle the case of a NULL softstate.
	 */
	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL) {
		return (FALSE);
	}

	if (un->un_f_cfg_is_atapi == TRUE) {
		/*
		 * The mode page contents are not required; set the allocation
		 * length for the mode page header only
		 */
		hdrlen = MODE_HEADER_LENGTH_GRP2;
		sense = kmem_zalloc(hdrlen, KM_SLEEP);
		ssc = sd_ssc_init(un);
		status = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP1, sense, hdrlen,
		    MODEPAGE_ALLPAGES, SD_PATH_STANDARD);
		sd_ssc_fini(ssc);
		if (status != 0)
			goto err_exit;
		device_specific =
		    ((struct mode_header_grp2 *)sense)->device_specific;
	} else {
		hdrlen = MODE_HEADER_LENGTH;
		sense = kmem_zalloc(hdrlen, KM_SLEEP);
		ssc = sd_ssc_init(un);
		status = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP0, sense, hdrlen,
		    MODEPAGE_ALLPAGES, SD_PATH_STANDARD);
		sd_ssc_fini(ssc);
		if (status != 0)
			goto err_exit;
		device_specific =
		    ((struct mode_header *)sense)->device_specific;
	}


	/*
	 * Write protect mode sense failed; not all disks
	 * understand this query. Return FALSE assuming that
	 * these devices are not writable.
	 */
	if (device_specific & WRITE_PROTECT) {
		rval = TRUE;
	}

err_exit:
	kmem_free(sense, hdrlen);
	return (rval);
}

/*
 *    Function: sr_volume_ctrl()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		audio output volume ioctl requests. (CDROMVOLCTRL)
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to user audio volume control structure
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 *
 */

static int
sr_volume_ctrl(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct cdrom_volctrl    volume;
	struct cdrom_volctrl    *vol = &volume;
	uchar_t			*sense_page;
	uchar_t			*select_page;
	uchar_t			*sense;
	uchar_t			*select;
	int			sense_buflen;
	int			select_buflen;
	int			rval;
	sd_ssc_t		*ssc;

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	if (ddi_copyin(data, vol, sizeof (struct cdrom_volctrl), flag)) {
		return (EFAULT);
	}

	if ((un->un_f_cfg_is_atapi == TRUE) || (un->un_f_mmc_cap == TRUE)) {
		struct mode_header_grp2		*sense_mhp;
		struct mode_header_grp2		*select_mhp;
		int				bd_len;

		sense_buflen = MODE_PARAM_LENGTH_GRP2 + MODEPAGE_AUDIO_CTRL_LEN;
		select_buflen = MODE_HEADER_LENGTH_GRP2 +
		    MODEPAGE_AUDIO_CTRL_LEN;
		sense  = kmem_zalloc(sense_buflen, KM_SLEEP);
		select = kmem_zalloc(select_buflen, KM_SLEEP);
		ssc = sd_ssc_init(un);
		rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP1, sense,
		    sense_buflen, MODEPAGE_AUDIO_CTRL,
		    SD_PATH_STANDARD);
		sd_ssc_fini(ssc);

		if (rval != 0) {
			SD_ERROR(SD_LOG_IOCTL_RMMEDIA, un,
			    "sr_volume_ctrl: Mode Sense Failed\n");
			kmem_free(sense, sense_buflen);
			kmem_free(select, select_buflen);
			return (rval);
		}
		sense_mhp = (struct mode_header_grp2 *)sense;
		select_mhp = (struct mode_header_grp2 *)select;
		bd_len = (sense_mhp->bdesc_length_hi << 8) |
		    sense_mhp->bdesc_length_lo;
		if (bd_len > MODE_BLK_DESC_LENGTH) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_volume_ctrl: Mode Sense returned invalid "
			    "block descriptor length\n");
			kmem_free(sense, sense_buflen);
			kmem_free(select, select_buflen);
			return (EIO);
		}
		sense_page = (uchar_t *)
		    (sense + MODE_HEADER_LENGTH_GRP2 + bd_len);
		select_page = (uchar_t *)(select + MODE_HEADER_LENGTH_GRP2);
		select_mhp->length_msb = 0;
		select_mhp->length_lsb = 0;
		select_mhp->bdesc_length_hi = 0;
		select_mhp->bdesc_length_lo = 0;
	} else {
		struct mode_header		*sense_mhp, *select_mhp;

		sense_buflen = MODE_PARAM_LENGTH + MODEPAGE_AUDIO_CTRL_LEN;
		select_buflen = MODE_HEADER_LENGTH + MODEPAGE_AUDIO_CTRL_LEN;
		sense  = kmem_zalloc(sense_buflen, KM_SLEEP);
		select = kmem_zalloc(select_buflen, KM_SLEEP);
		ssc = sd_ssc_init(un);
		rval = sd_send_scsi_MODE_SENSE(ssc, CDB_GROUP0, sense,
		    sense_buflen, MODEPAGE_AUDIO_CTRL,
		    SD_PATH_STANDARD);
		sd_ssc_fini(ssc);

		if (rval != 0) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_volume_ctrl: Mode Sense Failed\n");
			kmem_free(sense, sense_buflen);
			kmem_free(select, select_buflen);
			return (rval);
		}
		sense_mhp  = (struct mode_header *)sense;
		select_mhp = (struct mode_header *)select;
		if (sense_mhp->bdesc_length > MODE_BLK_DESC_LENGTH) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "sr_volume_ctrl: Mode Sense returned invalid "
			    "block descriptor length\n");
			kmem_free(sense, sense_buflen);
			kmem_free(select, select_buflen);
			return (EIO);
		}
		sense_page = (uchar_t *)
		    (sense + MODE_HEADER_LENGTH + sense_mhp->bdesc_length);
		select_page = (uchar_t *)(select + MODE_HEADER_LENGTH);
		select_mhp->length = 0;
		select_mhp->bdesc_length = 0;
	}
	/*
	 * Note: An audio control data structure could be created and overlayed
	 * on the following in place of the array indexing method implemented.
	 */

	/* Build the select data for the user volume data */
	select_page[0] = MODEPAGE_AUDIO_CTRL;
	select_page[1] = 0xE;
	/* Set the immediate bit */
	select_page[2] = 0x04;
	/* Zero out reserved fields */
	select_page[3] = 0x00;
	select_page[4] = 0x00;
	/* Return sense data for fields not to be modified */
	select_page[5] = sense_page[5];
	select_page[6] = sense_page[6];
	select_page[7] = sense_page[7];
	/* Set the user specified volume levels for channel 0 and 1 */
	select_page[8] = 0x01;
	select_page[9] = vol->channel0;
	select_page[10] = 0x02;
	select_page[11] = vol->channel1;
	/* Channel 2 and 3 are currently unsupported so return the sense data */
	select_page[12] = sense_page[12];
	select_page[13] = sense_page[13];
	select_page[14] = sense_page[14];
	select_page[15] = sense_page[15];

	ssc = sd_ssc_init(un);
	if ((un->un_f_cfg_is_atapi == TRUE) || (un->un_f_mmc_cap == TRUE)) {
		rval = sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP1, select,
		    select_buflen, SD_DONTSAVE_PAGE, SD_PATH_STANDARD);
	} else {
		rval = sd_send_scsi_MODE_SELECT(ssc, CDB_GROUP0, select,
		    select_buflen, SD_DONTSAVE_PAGE, SD_PATH_STANDARD);
	}
	sd_ssc_fini(ssc);

	kmem_free(sense, sense_buflen);
	kmem_free(select, select_buflen);
	return (rval);
}


/*
 *    Function: sr_read_sony_session_offset()
 *
 * Description: This routine is the driver entry point for handling CD-ROM
 *		ioctl requests for session offset information. (CDROMREADOFFSET)
 *		The address of the first track in the last session of a
 *		multi-session CD-ROM is returned
 *
 *		Note: This routine uses a vendor specific key value in the
 *		command control field without implementing any vendor check here
 *		or in the ioctl routine.
 *
 *   Arguments: dev	- the device 'dev_t'
 *		data	- pointer to an int to hold the requested address
 *		flag	- this argument is a pass through to ddi_copyxxx()
 *			  directly from the mode argument of ioctl().
 *
 * Return Code: the code returned by sd_send_scsi_cmd()
 *		EFAULT if ddi_copyxxx() fails
 *		ENXIO if fail ddi_get_soft_state
 *		EINVAL if data pointer is NULL
 */

static int
sr_read_sony_session_offset(dev_t dev, caddr_t data, int flag)
{
	struct sd_lun		*un;
	struct uscsi_cmd	*com;
	caddr_t			buffer;
	char			cdb[CDB_GROUP1];
	int			session_offset = 0;
	int			rval;

	if (data == NULL) {
		return (EINVAL);
	}

	if ((un = ddi_get_soft_state(sd_state, SDUNIT(dev))) == NULL ||
	    (un->un_state == SD_STATE_OFFLINE)) {
		return (ENXIO);
	}

	buffer = kmem_zalloc((size_t)SONY_SESSION_OFFSET_LEN, KM_SLEEP);
	bzero(cdb, CDB_GROUP1);
	cdb[0] = SCMD_READ_TOC;
	/*
	 * Bytes 7 & 8 are the 12 byte allocation length for a single entry.
	 * (4 byte TOC response header + 8 byte response data)
	 */
	cdb[8] = SONY_SESSION_OFFSET_LEN;
	/* Byte 9 is the control byte. A vendor specific value is used */
	cdb[9] = SONY_SESSION_OFFSET_KEY;
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP1;
	com->uscsi_bufaddr = buffer;
	com->uscsi_buflen = SONY_SESSION_OFFSET_LEN;
	com->uscsi_flags = USCSI_DIAGNOSE|USCSI_SILENT|USCSI_READ;

	rval = sd_send_scsi_cmd(dev, com, FKIOCTL, UIO_SYSSPACE,
	    SD_PATH_STANDARD);
	if (rval != 0) {
		kmem_free(buffer, SONY_SESSION_OFFSET_LEN);
		kmem_free(com, sizeof (*com));
		return (rval);
	}
	if (buffer[1] == SONY_SESSION_OFFSET_VALID) {
		session_offset =
		    ((uchar_t)buffer[8] << 24) + ((uchar_t)buffer[9] << 16) +
		    ((uchar_t)buffer[10] << 8) + ((uchar_t)buffer[11]);
		/*
		 * Offset returned offset in current lbasize block's. Convert to
		 * 2k block's to return to the user
		 */
		if (un->un_tgt_blocksize == CDROM_BLK_512) {
			session_offset >>= 2;
		} else if (un->un_tgt_blocksize == CDROM_BLK_1024) {
			session_offset >>= 1;
		}
	}

	if (ddi_copyout(&session_offset, data, sizeof (int), flag) != 0) {
		rval = EFAULT;
	}

	kmem_free(buffer, SONY_SESSION_OFFSET_LEN);
	kmem_free(com, sizeof (*com));
	return (rval);
}


/*
 *    Function: sd_wm_cache_constructor()
 *
 * Description: Cache Constructor for the wmap cache for the read/modify/write
 * 		devices.
 *
 *   Arguments: wm      - A pointer to the sd_w_map to be initialized.
 *		un	- sd_lun structure for the device.
 *		flag	- the km flags passed to constructor
 *
 * Return Code: 0 on success.
 *		-1 on failure.
 */

/*ARGSUSED*/
static int
sd_wm_cache_constructor(void *wm, void *un, int flags)
{
	bzero(wm, sizeof (struct sd_w_map));
	cv_init(&((struct sd_w_map *)wm)->wm_avail, NULL, CV_DRIVER, NULL);
	return (0);
}


/*
 *    Function: sd_wm_cache_destructor()
 *
 * Description: Cache destructor for the wmap cache for the read/modify/write
 * 		devices.
 *
 *   Arguments: wm      - A pointer to the sd_w_map to be initialized.
 *		un	- sd_lun structure for the device.
 */
/*ARGSUSED*/
static void
sd_wm_cache_destructor(void *wm, void *un)
{
	cv_destroy(&((struct sd_w_map *)wm)->wm_avail);
}


/*
 *    Function: sd_range_lock()
 *
 * Description: Lock the range of blocks specified as parameter to ensure
 *		that read, modify write is atomic and no other i/o writes
 *		to the same location. The range is specified in terms
 *		of start and end blocks. Block numbers are the actual
 *		media block numbers and not system.
 *
 *   Arguments: un	- sd_lun structure for the device.
 *		startb - The starting block number
 *		endb - The end block number
 *		typ - type of i/o - simple/read_modify_write
 *
 * Return Code: wm  - pointer to the wmap structure.
 *
 *     Context: This routine can sleep.
 */

static struct sd_w_map *
sd_range_lock(struct sd_lun *un, daddr_t startb, daddr_t endb, ushort_t typ)
{
	struct sd_w_map *wmp = NULL;
	struct sd_w_map *sl_wmp = NULL;
	struct sd_w_map *tmp_wmp;
	wm_state state = SD_WM_CHK_LIST;


	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	mutex_enter(SD_MUTEX(un));

	while (state != SD_WM_DONE) {

		switch (state) {
		case SD_WM_CHK_LIST:
			/*
			 * This is the starting state. Check the wmap list
			 * to see if the range is currently available.
			 */
			if (!(typ & SD_WTYPE_RMW) && !(un->un_rmw_count)) {
				/*
				 * If this is a simple write and no rmw
				 * i/o is pending then try to lock the
				 * range as the range should be available.
				 */
				state = SD_WM_LOCK_RANGE;
			} else {
				tmp_wmp = sd_get_range(un, startb, endb);
				if (tmp_wmp != NULL) {
					if ((wmp != NULL) && ONLIST(un, wmp)) {
						/*
						 * Should not keep onlist wmps
						 * while waiting this macro
						 * will also do wmp = NULL;
						 */
						FREE_ONLIST_WMAP(un, wmp);
					}
					/*
					 * sl_wmp is the wmap on which wait
					 * is done, since the tmp_wmp points
					 * to the inuse wmap, set sl_wmp to
					 * tmp_wmp and change the state to sleep
					 */
					sl_wmp = tmp_wmp;
					state = SD_WM_WAIT_MAP;
				} else {
					state = SD_WM_LOCK_RANGE;
				}

			}
			break;

		case SD_WM_LOCK_RANGE:
			ASSERT(un->un_wm_cache);
			/*
			 * The range need to be locked, try to get a wmap.
			 * First attempt it with NO_SLEEP, want to avoid a sleep
			 * if possible as we will have to release the sd mutex
			 * if we have to sleep.
			 */
			if (wmp == NULL)
				wmp = kmem_cache_alloc(un->un_wm_cache,
				    KM_NOSLEEP);
			if (wmp == NULL) {
				mutex_exit(SD_MUTEX(un));
				_NOTE(DATA_READABLE_WITHOUT_LOCK
				    (sd_lun::un_wm_cache))
				wmp = kmem_cache_alloc(un->un_wm_cache,
				    KM_SLEEP);
				mutex_enter(SD_MUTEX(un));
				/*
				 * we released the mutex so recheck and go to
				 * check list state.
				 */
				state = SD_WM_CHK_LIST;
			} else {
				/*
				 * We exit out of state machine since we
				 * have the wmap. Do the housekeeping first.
				 * place the wmap on the wmap list if it is not
				 * on it already and then set the state to done.
				 */
				wmp->wm_start = startb;
				wmp->wm_end = endb;
				wmp->wm_flags = typ | SD_WM_BUSY;
				if (typ & SD_WTYPE_RMW) {
					un->un_rmw_count++;
				}
				/*
				 * If not already on the list then link
				 */
				if (!ONLIST(un, wmp)) {
					wmp->wm_next = un->un_wm;
					wmp->wm_prev = NULL;
					if (wmp->wm_next)
						wmp->wm_next->wm_prev = wmp;
					un->un_wm = wmp;
				}
				state = SD_WM_DONE;
			}
			break;

		case SD_WM_WAIT_MAP:
			ASSERT(sl_wmp->wm_flags & SD_WM_BUSY);
			/*
			 * Wait is done on sl_wmp, which is set in the
			 * check_list state.
			 */
			sl_wmp->wm_wanted_count++;
			cv_wait(&sl_wmp->wm_avail, SD_MUTEX(un));
			sl_wmp->wm_wanted_count--;
			/*
			 * We can reuse the memory from the completed sl_wmp
			 * lock range for our new lock, but only if noone is
			 * waiting for it.
			 */
			ASSERT(!(sl_wmp->wm_flags & SD_WM_BUSY));
			if (sl_wmp->wm_wanted_count == 0) {
				if (wmp != NULL)
					CHK_N_FREEWMP(un, wmp);
				wmp = sl_wmp;
			}
			sl_wmp = NULL;
			/*
			 * After waking up, need to recheck for availability of
			 * range.
			 */
			state = SD_WM_CHK_LIST;
			break;

		default:
			panic("sd_range_lock: "
			    "Unknown state %d in sd_range_lock", state);
			/*NOTREACHED*/
		} /* switch(state) */

	} /* while(state != SD_WM_DONE) */

	mutex_exit(SD_MUTEX(un));

	ASSERT(wmp != NULL);

	return (wmp);
}


/*
 *    Function: sd_get_range()
 *
 * Description: Find if there any overlapping I/O to this one
 *		Returns the write-map of 1st such I/O, NULL otherwise.
 *
 *   Arguments: un	- sd_lun structure for the device.
 *		startb - The starting block number
 *		endb - The end block number
 *
 * Return Code: wm  - pointer to the wmap structure.
 */

static struct sd_w_map *
sd_get_range(struct sd_lun *un, daddr_t startb, daddr_t endb)
{
	struct sd_w_map *wmp;

	ASSERT(un != NULL);

	for (wmp = un->un_wm; wmp != NULL; wmp = wmp->wm_next) {
		if (!(wmp->wm_flags & SD_WM_BUSY)) {
			continue;
		}
		if ((startb >= wmp->wm_start) && (startb <= wmp->wm_end)) {
			break;
		}
		if ((endb >= wmp->wm_start) && (endb <= wmp->wm_end)) {
			break;
		}
	}

	return (wmp);
}


/*
 *    Function: sd_free_inlist_wmap()
 *
 * Description: Unlink and free a write map struct.
 *
 *   Arguments: un      - sd_lun structure for the device.
 *		wmp	- sd_w_map which needs to be unlinked.
 */

static void
sd_free_inlist_wmap(struct sd_lun *un, struct sd_w_map *wmp)
{
	ASSERT(un != NULL);

	if (un->un_wm == wmp) {
		un->un_wm = wmp->wm_next;
	} else {
		wmp->wm_prev->wm_next = wmp->wm_next;
	}

	if (wmp->wm_next) {
		wmp->wm_next->wm_prev = wmp->wm_prev;
	}

	wmp->wm_next = wmp->wm_prev = NULL;

	kmem_cache_free(un->un_wm_cache, wmp);
}


/*
 *    Function: sd_range_unlock()
 *
 * Description: Unlock the range locked by wm.
 *		Free write map if nobody else is waiting on it.
 *
 *   Arguments: un      - sd_lun structure for the device.
 *              wmp     - sd_w_map which needs to be unlinked.
 */

static void
sd_range_unlock(struct sd_lun *un, struct sd_w_map *wm)
{
	ASSERT(un != NULL);
	ASSERT(wm != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	mutex_enter(SD_MUTEX(un));

	if (wm->wm_flags & SD_WTYPE_RMW) {
		un->un_rmw_count--;
	}

	if (wm->wm_wanted_count) {
		wm->wm_flags = 0;
		/*
		 * Broadcast that the wmap is available now.
		 */
		cv_broadcast(&wm->wm_avail);
	} else {
		/*
		 * If no one is waiting on the map, it should be free'ed.
		 */
		sd_free_inlist_wmap(un, wm);
	}

	mutex_exit(SD_MUTEX(un));
}


/*
 *    Function: sd_read_modify_write_task
 *
 * Description: Called from a taskq thread to initiate the write phase of
 *		a read-modify-write request.  This is used for targets where
 *		un->un_sys_blocksize != un->un_tgt_blocksize.
 *
 *   Arguments: arg - a pointer to the buf(9S) struct for the write command.
 *
 *     Context: Called under taskq thread context.
 */

static void
sd_read_modify_write_task(void *arg)
{
	struct sd_mapblocksize_info	*bsp;
	struct buf	*bp;
	struct sd_xbuf	*xp;
	struct sd_lun	*un;

	bp = arg;	/* The bp is given in arg */
	ASSERT(bp != NULL);

	/* Get the pointer to the layer-private data struct */
	xp = SD_GET_XBUF(bp);
	ASSERT(xp != NULL);
	bsp = xp->xb_private;
	ASSERT(bsp != NULL);

	un = SD_GET_UN(bp);
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	SD_TRACE(SD_LOG_IO_RMMEDIA, un,
	    "sd_read_modify_write_task: entry: buf:0x%p\n", bp);

	/*
	 * This is the write phase of a read-modify-write request, called
	 * under the context of a taskq thread in response to the completion
	 * of the read portion of the rmw request completing under interrupt
	 * context. The write request must be sent from here down the iostart
	 * chain as if it were being sent from sd_mapblocksize_iostart(), so
	 * we use the layer index saved in the layer-private data area.
	 */
	SD_NEXT_IOSTART(bsp->mbs_layer_index, un, bp);

	SD_TRACE(SD_LOG_IO_RMMEDIA, un,
	    "sd_read_modify_write_task: exit: buf:0x%p\n", bp);
}


/*
 *    Function: sddump_do_read_of_rmw()
 *
 * Description: This routine will be called from sddump, If sddump is called
 *		with an I/O which not aligned on device blocksize boundary
 *		then the write has to be converted to read-modify-write.
 *		Do the read part here in order to keep sddump simple.
 *		Note - That the sd_mutex is held across the call to this
 *		routine.
 *
 *   Arguments: un	- sd_lun
 *		blkno	- block number in terms of media block size.
 *		nblk	- number of blocks.
 *		bpp	- pointer to pointer to the buf structure. On return
 *			from this function, *bpp points to the valid buffer
 *			to which the write has to be done.
 *
 * Return Code: 0 for success or errno-type return code
 */

static int
sddump_do_read_of_rmw(struct sd_lun *un, uint64_t blkno, uint64_t nblk,
	struct buf **bpp)
{
	int err;
	int i;
	int rval;
	struct buf *bp;
	struct scsi_pkt *pkt = NULL;
	uint32_t target_blocksize;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	target_blocksize = un->un_tgt_blocksize;

	mutex_exit(SD_MUTEX(un));

	bp = scsi_alloc_consistent_buf(SD_ADDRESS(un), (struct buf *)NULL,
	    (size_t)(nblk * target_blocksize), B_READ, NULL_FUNC, NULL);
	if (bp == NULL) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "no resources for dumping; giving up");
		err = ENOMEM;
		goto done;
	}

	rval = sd_setup_rw_pkt(un, &pkt, bp, 0, NULL_FUNC, NULL,
	    blkno, nblk);
	if (rval != 0) {
		scsi_free_consistent_buf(bp);
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "no resources for dumping; giving up");
		err = ENOMEM;
		goto done;
	}

	pkt->pkt_flags |= FLAG_NOINTR;

	err = EIO;
	for (i = 0; i < SD_NDUMP_RETRIES; i++) {

		/*
		 * Scsi_poll returns 0 (success) if the command completes and
		 * the status block is STATUS_GOOD.  We should only check
		 * errors if this condition is not true.  Even then we should
		 * send our own request sense packet only if we have a check
		 * condition and auto request sense has not been performed by
		 * the hba.
		 */
		SD_TRACE(SD_LOG_DUMP, un, "sddump: sending read\n");

		if ((sd_scsi_poll(un, pkt) == 0) && (pkt->pkt_resid == 0)) {
			err = 0;
			break;
		}

		/*
		 * Check CMD_DEV_GONE 1st, give up if device is gone,
		 * no need to read RQS data.
		 */
		if (pkt->pkt_reason == CMD_DEV_GONE) {
			scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
			    "Error while dumping state with rmw..."
			    "Device is gone\n");
			break;
		}

		if (SD_GET_PKT_STATUS(pkt) == STATUS_CHECK) {
			SD_INFO(SD_LOG_DUMP, un,
			    "sddump: read failed with CHECK, try # %d\n", i);
			if (((pkt->pkt_state & STATE_ARQ_DONE) == 0)) {
				(void) sd_send_polled_RQS(un);
			}

			continue;
		}

		if (SD_GET_PKT_STATUS(pkt) == STATUS_BUSY) {
			int reset_retval = 0;

			SD_INFO(SD_LOG_DUMP, un,
			    "sddump: read failed with BUSY, try # %d\n", i);

			if (un->un_f_lun_reset_enabled == TRUE) {
				reset_retval = scsi_reset(SD_ADDRESS(un),
				    RESET_LUN);
			}
			if (reset_retval == 0) {
				(void) scsi_reset(SD_ADDRESS(un), RESET_TARGET);
			}
			(void) sd_send_polled_RQS(un);

		} else {
			SD_INFO(SD_LOG_DUMP, un,
			    "sddump: read failed with 0x%x, try # %d\n",
			    SD_GET_PKT_STATUS(pkt), i);
			mutex_enter(SD_MUTEX(un));
			sd_reset_target(un, pkt);
			mutex_exit(SD_MUTEX(un));
		}

		/*
		 * If we are not getting anywhere with lun/target resets,
		 * let's reset the bus.
		 */
		if (i > SD_NDUMP_RETRIES/2) {
			(void) scsi_reset(SD_ADDRESS(un), RESET_ALL);
			(void) sd_send_polled_RQS(un);
		}

	}
	scsi_destroy_pkt(pkt);

	if (err != 0) {
		scsi_free_consistent_buf(bp);
		*bpp = NULL;
	} else {
		*bpp = bp;
	}

done:
	mutex_enter(SD_MUTEX(un));
	return (err);
}


/*
 *    Function: sd_failfast_flushq
 *
 * Description: Take all bp's on the wait queue that have B_FAILFAST set
 *		in b_flags and move them onto the failfast queue, then kick
 *		off a thread to return all bp's on the failfast queue to
 *		their owners with an error set.
 *
 *   Arguments: un - pointer to the soft state struct for the instance.
 *
 *     Context: may execute in interrupt context.
 */

static void
sd_failfast_flushq(struct sd_lun *un)
{
	struct buf *bp;
	struct buf *next_waitq_bp;
	struct buf *prev_waitq_bp = NULL;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));
	ASSERT(un->un_failfast_state == SD_FAILFAST_ACTIVE);
	ASSERT(un->un_failfast_bp == NULL);

	SD_TRACE(SD_LOG_IO_FAILFAST, un,
	    "sd_failfast_flushq: entry: un:0x%p\n", un);

	/*
	 * Check if we should flush all bufs when entering failfast state, or
	 * just those with B_FAILFAST set.
	 */
	if (sd_failfast_flushctl & SD_FAILFAST_FLUSH_ALL_BUFS) {
		/*
		 * Move *all* bp's on the wait queue to the failfast flush
		 * queue, including those that do NOT have B_FAILFAST set.
		 */
		if (un->un_failfast_headp == NULL) {
			ASSERT(un->un_failfast_tailp == NULL);
			un->un_failfast_headp = un->un_waitq_headp;
		} else {
			ASSERT(un->un_failfast_tailp != NULL);
			un->un_failfast_tailp->av_forw = un->un_waitq_headp;
		}

		un->un_failfast_tailp = un->un_waitq_tailp;

		/* update kstat for each bp moved out of the waitq */
		for (bp = un->un_waitq_headp; bp != NULL; bp = bp->av_forw) {
			SD_UPDATE_KSTATS(un, kstat_waitq_exit, bp);
		}

		/* empty the waitq */
		un->un_waitq_headp = un->un_waitq_tailp = NULL;

	} else {
		/*
		 * Go thru the wait queue, pick off all entries with
		 * B_FAILFAST set, and move these onto the failfast queue.
		 */
		for (bp = un->un_waitq_headp; bp != NULL; bp = next_waitq_bp) {
			/*
			 * Save the pointer to the next bp on the wait queue,
			 * so we get to it on the next iteration of this loop.
			 */
			next_waitq_bp = bp->av_forw;

			/*
			 * If this bp from the wait queue does NOT have
			 * B_FAILFAST set, just move on to the next element
			 * in the wait queue. Note, this is the only place
			 * where it is correct to set prev_waitq_bp.
			 */
			if ((bp->b_flags & B_FAILFAST) == 0) {
				prev_waitq_bp = bp;
				continue;
			}

			/*
			 * Remove the bp from the wait queue.
			 */
			if (bp == un->un_waitq_headp) {
				/* The bp is the first element of the waitq. */
				un->un_waitq_headp = next_waitq_bp;
				if (un->un_waitq_headp == NULL) {
					/* The wait queue is now empty */
					un->un_waitq_tailp = NULL;
				}
			} else {
				/*
				 * The bp is either somewhere in the middle
				 * or at the end of the wait queue.
				 */
				ASSERT(un->un_waitq_headp != NULL);
				ASSERT(prev_waitq_bp != NULL);
				ASSERT((prev_waitq_bp->b_flags & B_FAILFAST)
				    == 0);
				if (bp == un->un_waitq_tailp) {
					/* bp is the last entry on the waitq. */
					ASSERT(next_waitq_bp == NULL);
					un->un_waitq_tailp = prev_waitq_bp;
				}
				prev_waitq_bp->av_forw = next_waitq_bp;
			}
			bp->av_forw = NULL;

			/*
			 * update kstat since the bp is moved out of
			 * the waitq
			 */
			SD_UPDATE_KSTATS(un, kstat_waitq_exit, bp);

			/*
			 * Now put the bp onto the failfast queue.
			 */
			if (un->un_failfast_headp == NULL) {
				/* failfast queue is currently empty */
				ASSERT(un->un_failfast_tailp == NULL);
				un->un_failfast_headp =
				    un->un_failfast_tailp = bp;
			} else {
				/* Add the bp to the end of the failfast q */
				ASSERT(un->un_failfast_tailp != NULL);
				ASSERT(un->un_failfast_tailp->b_flags &
				    B_FAILFAST);
				un->un_failfast_tailp->av_forw = bp;
				un->un_failfast_tailp = bp;
			}
		}
	}

	/*
	 * Now return all bp's on the failfast queue to their owners.
	 */
	while ((bp = un->un_failfast_headp) != NULL) {

		un->un_failfast_headp = bp->av_forw;
		if (un->un_failfast_headp == NULL) {
			un->un_failfast_tailp = NULL;
		}

		/*
		 * We want to return the bp with a failure error code, but
		 * we do not want a call to sd_start_cmds() to occur here,
		 * so use sd_return_failed_command_no_restart() instead of
		 * sd_return_failed_command().
		 */
		sd_return_failed_command_no_restart(un, bp, EIO);
	}

	/* Flush the xbuf queues if required. */
	if (sd_failfast_flushctl & SD_FAILFAST_FLUSH_ALL_QUEUES) {
		ddi_xbuf_flushq(un->un_xbuf_attr, sd_failfast_flushq_callback);
	}

	SD_TRACE(SD_LOG_IO_FAILFAST, un,
	    "sd_failfast_flushq: exit: un:0x%p\n", un);
}


/*
 *    Function: sd_failfast_flushq_callback
 *
 * Description: Return TRUE if the given bp meets the criteria for failfast
 *		flushing. Used with ddi_xbuf_flushq(9F).
 *
 *   Arguments: bp - ptr to buf struct to be examined.
 *
 *     Context: Any
 */

static int
sd_failfast_flushq_callback(struct buf *bp)
{
	/*
	 * Return TRUE if (1) we want to flush ALL bufs when the failfast
	 * state is entered; OR (2) the given bp has B_FAILFAST set.
	 */
	return (((sd_failfast_flushctl & SD_FAILFAST_FLUSH_ALL_BUFS) ||
	    (bp->b_flags & B_FAILFAST)) ? TRUE : FALSE);
}



/*
 * Function: sd_setup_next_xfer
 *
 * Description: Prepare next I/O operation using DMA_PARTIAL
 *
 */

static int
sd_setup_next_xfer(struct sd_lun *un, struct buf *bp,
    struct scsi_pkt *pkt, struct sd_xbuf *xp)
{
	ssize_t	num_blks_not_xfered;
	daddr_t	strt_blk_num;
	ssize_t	bytes_not_xfered;
	int	rval;

	ASSERT(pkt->pkt_resid == 0);

	/*
	 * Calculate next block number and amount to be transferred.
	 *
	 * How much data NOT transfered to the HBA yet.
	 */
	bytes_not_xfered = xp->xb_dma_resid;

	/*
	 * figure how many blocks NOT transfered to the HBA yet.
	 */
	num_blks_not_xfered = SD_BYTES2TGTBLOCKS(un, bytes_not_xfered);

	/*
	 * set starting block number to the end of what WAS transfered.
	 */
	strt_blk_num = xp->xb_blkno +
	    SD_BYTES2TGTBLOCKS(un, bp->b_bcount - bytes_not_xfered);

	/*
	 * Move pkt to the next portion of the xfer.  sd_setup_next_rw_pkt
	 * will call scsi_initpkt with NULL_FUNC so we do not have to release
	 * the disk mutex here.
	 */
	rval = sd_setup_next_rw_pkt(un, pkt, bp,
	    strt_blk_num, num_blks_not_xfered);

	if (rval == 0) {

		/*
		 * Success.
		 *
		 * Adjust things if there are still more blocks to be
		 * transfered.
		 */
		xp->xb_dma_resid = pkt->pkt_resid;
		pkt->pkt_resid = 0;

		return (1);
	}

	/*
	 * There's really only one possible return value from
	 * sd_setup_next_rw_pkt which occurs when scsi_init_pkt
	 * returns NULL.
	 */
	ASSERT(rval == SD_PKT_ALLOC_FAILURE);

	bp->b_resid = bp->b_bcount;
	bp->b_flags |= B_ERROR;

	scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
	    "Error setting up next portion of DMA transfer\n");

	return (0);
}

/*
 *    Function: sd_panic_for_res_conflict
 *
 * Description: Call panic with a string formatted with "Reservation Conflict"
 *		and a human readable identifier indicating the SD instance
 *		that experienced the reservation conflict.
 *
 *   Arguments: un - pointer to the soft state struct for the instance.
 *
 *     Context: may execute in interrupt context.
 */

#define	SD_RESV_CONFLICT_FMT_LEN 40
void
sd_panic_for_res_conflict(struct sd_lun *un)
{
	char panic_str[SD_RESV_CONFLICT_FMT_LEN+MAXPATHLEN];
	char path_str[MAXPATHLEN];

	(void) snprintf(panic_str, sizeof (panic_str),
	    "Reservation Conflict\nDisk: %s",
	    ddi_pathname(SD_DEVINFO(un), path_str));

	panic(panic_str);
}

/*
 * Note: The following sd_faultinjection_ioctl( ) routines implement
 * driver support for handling fault injection for error analysis
 * causing faults in multiple layers of the driver.
 *
 */

#ifdef SD_FAULT_INJECTION
static uint_t   sd_fault_injection_on = 0;

/*
 *    Function: sd_faultinjection_ioctl()
 *
 * Description: This routine is the driver entry point for handling
 *              faultinjection ioctls to inject errors into the
 *              layer model
 *
 *   Arguments: cmd	- the ioctl cmd received
 *		arg	- the arguments from user and returns
 */

static void
sd_faultinjection_ioctl(int cmd, intptr_t arg,  struct sd_lun *un) {

	uint_t i = 0;
	uint_t rval;

	SD_TRACE(SD_LOG_IOERR, un, "sd_faultinjection_ioctl: entry\n");

	mutex_enter(SD_MUTEX(un));

	switch (cmd) {
	case SDIOCRUN:
		/* Allow pushed faults to be injected */
		SD_INFO(SD_LOG_SDTEST, un,
		    "sd_faultinjection_ioctl: Injecting Fault Run\n");

		sd_fault_injection_on = 1;

		SD_INFO(SD_LOG_IOERR, un,
		    "sd_faultinjection_ioctl: run finished\n");
		break;

	case SDIOCSTART:
		/* Start Injection Session */
		SD_INFO(SD_LOG_SDTEST, un,
		    "sd_faultinjection_ioctl: Injecting Fault Start\n");

		sd_fault_injection_on = 0;
		un->sd_injection_mask = 0xFFFFFFFF;
		for (i = 0; i < SD_FI_MAX_ERROR; i++) {
			un->sd_fi_fifo_pkt[i] = NULL;
			un->sd_fi_fifo_xb[i] = NULL;
			un->sd_fi_fifo_un[i] = NULL;
			un->sd_fi_fifo_arq[i] = NULL;
		}
		un->sd_fi_fifo_start = 0;
		un->sd_fi_fifo_end = 0;

		mutex_enter(&(un->un_fi_mutex));
		un->sd_fi_log[0] = '\0';
		un->sd_fi_buf_len = 0;
		mutex_exit(&(un->un_fi_mutex));

		SD_INFO(SD_LOG_IOERR, un,
		    "sd_faultinjection_ioctl: start finished\n");
		break;

	case SDIOCSTOP:
		/* Stop Injection Session */
		SD_INFO(SD_LOG_SDTEST, un,
		    "sd_faultinjection_ioctl: Injecting Fault Stop\n");
		sd_fault_injection_on = 0;
		un->sd_injection_mask = 0x0;

		/* Empty stray or unuseds structs from fifo */
		for (i = 0; i < SD_FI_MAX_ERROR; i++) {
			if (un->sd_fi_fifo_pkt[i] != NULL) {
				kmem_free(un->sd_fi_fifo_pkt[i],
				    sizeof (struct sd_fi_pkt));
			}
			if (un->sd_fi_fifo_xb[i] != NULL) {
				kmem_free(un->sd_fi_fifo_xb[i],
				    sizeof (struct sd_fi_xb));
			}
			if (un->sd_fi_fifo_un[i] != NULL) {
				kmem_free(un->sd_fi_fifo_un[i],
				    sizeof (struct sd_fi_un));
			}
			if (un->sd_fi_fifo_arq[i] != NULL) {
				kmem_free(un->sd_fi_fifo_arq[i],
				    sizeof (struct sd_fi_arq));
			}
			un->sd_fi_fifo_pkt[i] = NULL;
			un->sd_fi_fifo_un[i] = NULL;
			un->sd_fi_fifo_xb[i] = NULL;
			un->sd_fi_fifo_arq[i] = NULL;
		}
		un->sd_fi_fifo_start = 0;
		un->sd_fi_fifo_end = 0;

		SD_INFO(SD_LOG_IOERR, un,
		    "sd_faultinjection_ioctl: stop finished\n");
		break;

	case SDIOCINSERTPKT:
		/* Store a packet struct to be pushed onto fifo */
		SD_INFO(SD_LOG_SDTEST, un,
		    "sd_faultinjection_ioctl: Injecting Fault Insert Pkt\n");

		i = un->sd_fi_fifo_end % SD_FI_MAX_ERROR;

		sd_fault_injection_on = 0;

		/* No more that SD_FI_MAX_ERROR allowed in Queue */
		if (un->sd_fi_fifo_pkt[i] != NULL) {
			kmem_free(un->sd_fi_fifo_pkt[i],
			    sizeof (struct sd_fi_pkt));
		}
		if (arg != NULL) {
			un->sd_fi_fifo_pkt[i] =
			    kmem_alloc(sizeof (struct sd_fi_pkt), KM_NOSLEEP);
			if (un->sd_fi_fifo_pkt[i] == NULL) {
				/* Alloc failed don't store anything */
				break;
			}
			rval = ddi_copyin((void *)arg, un->sd_fi_fifo_pkt[i],
			    sizeof (struct sd_fi_pkt), 0);
			if (rval == -1) {
				kmem_free(un->sd_fi_fifo_pkt[i],
				    sizeof (struct sd_fi_pkt));
				un->sd_fi_fifo_pkt[i] = NULL;
			}
		} else {
			SD_INFO(SD_LOG_IOERR, un,
			    "sd_faultinjection_ioctl: pkt null\n");
		}
		break;

	case SDIOCINSERTXB:
		/* Store a xb struct to be pushed onto fifo */
		SD_INFO(SD_LOG_SDTEST, un,
		    "sd_faultinjection_ioctl: Injecting Fault Insert XB\n");

		i = un->sd_fi_fifo_end % SD_FI_MAX_ERROR;

		sd_fault_injection_on = 0;

		if (un->sd_fi_fifo_xb[i] != NULL) {
			kmem_free(un->sd_fi_fifo_xb[i],
			    sizeof (struct sd_fi_xb));
			un->sd_fi_fifo_xb[i] = NULL;
		}
		if (arg != NULL) {
			un->sd_fi_fifo_xb[i] =
			    kmem_alloc(sizeof (struct sd_fi_xb), KM_NOSLEEP);
			if (un->sd_fi_fifo_xb[i] == NULL) {
				/* Alloc failed don't store anything */
				break;
			}
			rval = ddi_copyin((void *)arg, un->sd_fi_fifo_xb[i],
			    sizeof (struct sd_fi_xb), 0);

			if (rval == -1) {
				kmem_free(un->sd_fi_fifo_xb[i],
				    sizeof (struct sd_fi_xb));
				un->sd_fi_fifo_xb[i] = NULL;
			}
		} else {
			SD_INFO(SD_LOG_IOERR, un,
			    "sd_faultinjection_ioctl: xb null\n");
		}
		break;

	case SDIOCINSERTUN:
		/* Store a un struct to be pushed onto fifo */
		SD_INFO(SD_LOG_SDTEST, un,
		    "sd_faultinjection_ioctl: Injecting Fault Insert UN\n");

		i = un->sd_fi_fifo_end % SD_FI_MAX_ERROR;

		sd_fault_injection_on = 0;

		if (un->sd_fi_fifo_un[i] != NULL) {
			kmem_free(un->sd_fi_fifo_un[i],
			    sizeof (struct sd_fi_un));
			un->sd_fi_fifo_un[i] = NULL;
		}
		if (arg != NULL) {
			un->sd_fi_fifo_un[i] =
			    kmem_alloc(sizeof (struct sd_fi_un), KM_NOSLEEP);
			if (un->sd_fi_fifo_un[i] == NULL) {
				/* Alloc failed don't store anything */
				break;
			}
			rval = ddi_copyin((void *)arg, un->sd_fi_fifo_un[i],
			    sizeof (struct sd_fi_un), 0);
			if (rval == -1) {
				kmem_free(un->sd_fi_fifo_un[i],
				    sizeof (struct sd_fi_un));
				un->sd_fi_fifo_un[i] = NULL;
			}

		} else {
			SD_INFO(SD_LOG_IOERR, un,
			    "sd_faultinjection_ioctl: un null\n");
		}

		break;

	case SDIOCINSERTARQ:
		/* Store a arq struct to be pushed onto fifo */
		SD_INFO(SD_LOG_SDTEST, un,
		    "sd_faultinjection_ioctl: Injecting Fault Insert ARQ\n");
		i = un->sd_fi_fifo_end % SD_FI_MAX_ERROR;

		sd_fault_injection_on = 0;

		if (un->sd_fi_fifo_arq[i] != NULL) {
			kmem_free(un->sd_fi_fifo_arq[i],
			    sizeof (struct sd_fi_arq));
			un->sd_fi_fifo_arq[i] = NULL;
		}
		if (arg != NULL) {
			un->sd_fi_fifo_arq[i] =
			    kmem_alloc(sizeof (struct sd_fi_arq), KM_NOSLEEP);
			if (un->sd_fi_fifo_arq[i] == NULL) {
				/* Alloc failed don't store anything */
				break;
			}
			rval = ddi_copyin((void *)arg, un->sd_fi_fifo_arq[i],
			    sizeof (struct sd_fi_arq), 0);
			if (rval == -1) {
				kmem_free(un->sd_fi_fifo_arq[i],
				    sizeof (struct sd_fi_arq));
				un->sd_fi_fifo_arq[i] = NULL;
			}

		} else {
			SD_INFO(SD_LOG_IOERR, un,
			    "sd_faultinjection_ioctl: arq null\n");
		}

		break;

	case SDIOCPUSH:
		/* Push stored xb, pkt, un, and arq onto fifo */
		sd_fault_injection_on = 0;

		if (arg != NULL) {
			rval = ddi_copyin((void *)arg, &i, sizeof (uint_t), 0);
			if (rval != -1 &&
			    un->sd_fi_fifo_end + i < SD_FI_MAX_ERROR) {
				un->sd_fi_fifo_end += i;
			}
		} else {
			SD_INFO(SD_LOG_IOERR, un,
			    "sd_faultinjection_ioctl: push arg null\n");
			if (un->sd_fi_fifo_end + i < SD_FI_MAX_ERROR) {
				un->sd_fi_fifo_end++;
			}
		}
		SD_INFO(SD_LOG_IOERR, un,
		    "sd_faultinjection_ioctl: push to end=%d\n",
		    un->sd_fi_fifo_end);
		break;

	case SDIOCRETRIEVE:
		/* Return buffer of log from Injection session */
		SD_INFO(SD_LOG_SDTEST, un,
		    "sd_faultinjection_ioctl: Injecting Fault Retreive");

		sd_fault_injection_on = 0;

		mutex_enter(&(un->un_fi_mutex));
		rval = ddi_copyout(un->sd_fi_log, (void *)arg,
		    un->sd_fi_buf_len+1, 0);
		mutex_exit(&(un->un_fi_mutex));

		if (rval == -1) {
			/*
			 * arg is possibly invalid setting
			 * it to NULL for return
			 */
			arg = NULL;
		}
		break;
	}

	mutex_exit(SD_MUTEX(un));
	SD_TRACE(SD_LOG_IOERR, un, "sd_faultinjection_ioctl:"
			    " exit\n");
}


/*
 *    Function: sd_injection_log()
 *
 * Description: This routine adds buff to the already existing injection log
 *              for retrieval via faultinjection_ioctl for use in fault
 *              detection and recovery
 *
 *   Arguments: buf - the string to add to the log
 */

static void
sd_injection_log(char *buf, struct sd_lun *un)
{
	uint_t len;

	ASSERT(un != NULL);
	ASSERT(buf != NULL);

	mutex_enter(&(un->un_fi_mutex));

	len = min(strlen(buf), 255);
	/* Add logged value to Injection log to be returned later */
	if (len + un->sd_fi_buf_len < SD_FI_MAX_BUF) {
		uint_t	offset = strlen((char *)un->sd_fi_log);
		char *destp = (char *)un->sd_fi_log + offset;
		int i;
		for (i = 0; i < len; i++) {
			*destp++ = *buf++;
		}
		un->sd_fi_buf_len += len;
		un->sd_fi_log[un->sd_fi_buf_len] = '\0';
	}

	mutex_exit(&(un->un_fi_mutex));
}


/*
 *    Function: sd_faultinjection()
 *
 * Description: This routine takes the pkt and changes its
 *		content based on error injection scenerio.
 *
 *   Arguments: pktp	- packet to be changed
 */

static void
sd_faultinjection(struct scsi_pkt *pktp)
{
	uint_t i;
	struct sd_fi_pkt *fi_pkt;
	struct sd_fi_xb *fi_xb;
	struct sd_fi_un *fi_un;
	struct sd_fi_arq *fi_arq;
	struct buf *bp;
	struct sd_xbuf *xb;
	struct sd_lun *un;

	ASSERT(pktp != NULL);

	/* pull bp xb and un from pktp */
	bp = (struct buf *)pktp->pkt_private;
	xb = SD_GET_XBUF(bp);
	un = SD_GET_UN(bp);

	ASSERT(un != NULL);

	mutex_enter(SD_MUTEX(un));

	SD_TRACE(SD_LOG_SDTEST, un,
	    "sd_faultinjection: entry Injection from sdintr\n");

	/* if injection is off return */
	if (sd_fault_injection_on == 0 ||
	    un->sd_fi_fifo_start == un->sd_fi_fifo_end) {
		mutex_exit(SD_MUTEX(un));
		return;
	}

	SD_INFO(SD_LOG_SDTEST, un,
	    "sd_faultinjection: is working for copying\n");

	/* take next set off fifo */
	i = un->sd_fi_fifo_start % SD_FI_MAX_ERROR;

	fi_pkt = un->sd_fi_fifo_pkt[i];
	fi_xb = un->sd_fi_fifo_xb[i];
	fi_un = un->sd_fi_fifo_un[i];
	fi_arq = un->sd_fi_fifo_arq[i];


	/* set variables accordingly */
	/* set pkt if it was on fifo */
	if (fi_pkt != NULL) {
		SD_CONDSET(pktp, pkt, pkt_flags, "pkt_flags");
		SD_CONDSET(*pktp, pkt, pkt_scbp, "pkt_scbp");
		if (fi_pkt->pkt_cdbp != 0xff)
			SD_CONDSET(*pktp, pkt, pkt_cdbp, "pkt_cdbp");
		SD_CONDSET(pktp, pkt, pkt_state, "pkt_state");
		SD_CONDSET(pktp, pkt, pkt_statistics, "pkt_statistics");
		SD_CONDSET(pktp, pkt, pkt_reason, "pkt_reason");

	}
	/* set xb if it was on fifo */
	if (fi_xb != NULL) {
		SD_CONDSET(xb, xb, xb_blkno, "xb_blkno");
		SD_CONDSET(xb, xb, xb_dma_resid, "xb_dma_resid");
		if (fi_xb->xb_retry_count != 0)
			SD_CONDSET(xb, xb, xb_retry_count, "xb_retry_count");
		SD_CONDSET(xb, xb, xb_victim_retry_count,
		    "xb_victim_retry_count");
		SD_CONDSET(xb, xb, xb_sense_status, "xb_sense_status");
		SD_CONDSET(xb, xb, xb_sense_state, "xb_sense_state");
		SD_CONDSET(xb, xb, xb_sense_resid, "xb_sense_resid");

		/* copy in block data from sense */
		/*
		 * if (fi_xb->xb_sense_data[0] != -1) {
		 *	bcopy(fi_xb->xb_sense_data, xb->xb_sense_data,
		 *	SENSE_LENGTH);
		 * }
		 */
		bcopy(fi_xb->xb_sense_data, xb->xb_sense_data, SENSE_LENGTH);

		/* copy in extended sense codes */
		SD_CONDSET(((struct scsi_extended_sense *)xb->xb_sense_data),
		    xb, es_code, "es_code");
		SD_CONDSET(((struct scsi_extended_sense *)xb->xb_sense_data),
		    xb, es_key, "es_key");
		SD_CONDSET(((struct scsi_extended_sense *)xb->xb_sense_data),
		    xb, es_add_code, "es_add_code");
		SD_CONDSET(((struct scsi_extended_sense *)xb->xb_sense_data),
		    xb, es_qual_code, "es_qual_code");
		struct scsi_extended_sense *esp;
		esp = (struct scsi_extended_sense *)xb->xb_sense_data;
		esp->es_class = CLASS_EXTENDED_SENSE;
	}

	/* set un if it was on fifo */
	if (fi_un != NULL) {
		SD_CONDSET(un->un_sd->sd_inq, un, inq_rmb, "inq_rmb");
		SD_CONDSET(un, un, un_ctype, "un_ctype");
		SD_CONDSET(un, un, un_reset_retry_count,
		    "un_reset_retry_count");
		SD_CONDSET(un, un, un_reservation_type, "un_reservation_type");
		SD_CONDSET(un, un, un_resvd_status, "un_resvd_status");
		SD_CONDSET(un, un, un_f_arq_enabled, "un_f_arq_enabled");
		SD_CONDSET(un, un, un_f_allow_bus_device_reset,
		    "un_f_allow_bus_device_reset");
		SD_CONDSET(un, un, un_f_opt_queueing, "un_f_opt_queueing");

	}

	/* copy in auto request sense if it was on fifo */
	if (fi_arq != NULL) {
		bcopy(fi_arq, pktp->pkt_scbp, sizeof (struct sd_fi_arq));
	}

	/* free structs */
	if (un->sd_fi_fifo_pkt[i] != NULL) {
		kmem_free(un->sd_fi_fifo_pkt[i], sizeof (struct sd_fi_pkt));
	}
	if (un->sd_fi_fifo_xb[i] != NULL) {
		kmem_free(un->sd_fi_fifo_xb[i], sizeof (struct sd_fi_xb));
	}
	if (un->sd_fi_fifo_un[i] != NULL) {
		kmem_free(un->sd_fi_fifo_un[i], sizeof (struct sd_fi_un));
	}
	if (un->sd_fi_fifo_arq[i] != NULL) {
		kmem_free(un->sd_fi_fifo_arq[i], sizeof (struct sd_fi_arq));
	}

	/*
	 * kmem_free does not gurantee to set to NULL
	 * since we uses these to determine if we set
	 * values or not lets confirm they are always
	 * NULL after free
	 */
	un->sd_fi_fifo_pkt[i] = NULL;
	un->sd_fi_fifo_un[i] = NULL;
	un->sd_fi_fifo_xb[i] = NULL;
	un->sd_fi_fifo_arq[i] = NULL;

	un->sd_fi_fifo_start++;

	mutex_exit(SD_MUTEX(un));

	SD_INFO(SD_LOG_SDTEST, un, "sd_faultinjection: exit\n");
}

#endif /* SD_FAULT_INJECTION */

/*
 * This routine is invoked in sd_unit_attach(). Before calling it, the
 * properties in conf file should be processed already, and "hotpluggable"
 * property was processed also.
 *
 * The sd driver distinguishes 3 different type of devices: removable media,
 * non-removable media, and hotpluggable. Below the differences are defined:
 *
 * 1. Device ID
 *
 *     The device ID of a device is used to identify this device. Refer to
 *     ddi_devid_register(9F).
 *
 *     For a non-removable media disk device which can provide 0x80 or 0x83
 *     VPD page (refer to INQUIRY command of SCSI SPC specification), a unique
 *     device ID is created to identify this device. For other non-removable
 *     media devices, a default device ID is created only if this device has
 *     at least 2 alter cylinders. Otherwise, this device has no devid.
 *
 *     -------------------------------------------------------
 *     removable media   hotpluggable  | Can Have Device ID
 *     -------------------------------------------------------
 *         false             false     |     Yes
 *         false             true      |     Yes
 *         true                x       |     No
 *     ------------------------------------------------------
 *
 *
 * 2. SCSI group 4 commands
 *
 *     In SCSI specs, only some commands in group 4 command set can use
 *     8-byte addresses that can be used to access >2TB storage spaces.
 *     Other commands have no such capability. Without supporting group4,
 *     it is impossible to make full use of storage spaces of a disk with
 *     capacity larger than 2TB.
 *
 *     -----------------------------------------------
 *     removable media   hotpluggable   LP64  |  Group
 *     -----------------------------------------------
 *           false          false       false |   1
 *           false          false       true  |   4
 *           false          true        false |   1
 *           false          true        true  |   4
 *           true             x           x   |   5
 *     -----------------------------------------------
 *
 *
 * 3. Check for VTOC Label
 *
 *     If a direct-access disk has no EFI label, sd will check if it has a
 *     valid VTOC label. Now, sd also does that check for removable media
 *     and hotpluggable devices.
 *
 *     --------------------------------------------------------------
 *     Direct-Access   removable media    hotpluggable |  Check Label
 *     -------------------------------------------------------------
 *         false          false           false        |   No
 *         false          false           true         |   No
 *         false          true            false        |   Yes
 *         false          true            true         |   Yes
 *         true            x                x          |   Yes
 *     --------------------------------------------------------------
 *
 *
 * 4. Building default VTOC label
 *
 *     As section 3 says, sd checks if some kinds of devices have VTOC label.
 *     If those devices have no valid VTOC label, sd(7d) will attempt to
 *     create default VTOC for them. Currently sd creates default VTOC label
 *     for all devices on x86 platform (VTOC_16), but only for removable
 *     media devices on SPARC (VTOC_8).
 *
 *     -----------------------------------------------------------
 *       removable media hotpluggable platform   |   Default Label
 *     -----------------------------------------------------------
 *             false          false    sparc     |     No
 *             false          true      x86      |     Yes
 *             false          true     sparc     |     Yes
 *             true             x        x       |     Yes
 *     ----------------------------------------------------------
 *
 *
 * 5. Supported blocksizes of target devices
 *
 *     Sd supports non-512-byte blocksize for removable media devices only.
 *     For other devices, only 512-byte blocksize is supported. This may be
 *     changed in near future because some RAID devices require non-512-byte
 *     blocksize
 *
 *     -----------------------------------------------------------
 *     removable media    hotpluggable    | non-512-byte blocksize
 *     -----------------------------------------------------------
 *           false          false         |   No
 *           false          true          |   No
 *           true             x           |   Yes
 *     -----------------------------------------------------------
 *
 *
 * 6. Automatic mount & unmount
 *
 *     Sd(7d) driver provides DKIOCREMOVABLE ioctl. This ioctl is used to query
 *     if a device is removable media device. It return 1 for removable media
 *     devices, and 0 for others.
 *
 *     The automatic mounting subsystem should distinguish between the types
 *     of devices and apply automounting policies to each.
 *
 *
 * 7. fdisk partition management
 *
 *     Fdisk is traditional partition method on x86 platform. Sd(7d) driver
 *     just supports fdisk partitions on x86 platform. On sparc platform, sd
 *     doesn't support fdisk partitions at all. Note: pcfs(7fs) can recognize
 *     fdisk partitions on both x86 and SPARC platform.
 *
 *     -----------------------------------------------------------
 *       platform   removable media  USB/1394  |  fdisk supported
 *     -----------------------------------------------------------
 *        x86         X               X        |       true
 *     ------------------------------------------------------------
 *        sparc       X               X        |       false
 *     ------------------------------------------------------------
 *
 *
 * 8. MBOOT/MBR
 *
 *     Although sd(7d) doesn't support fdisk on SPARC platform, it does support
 *     read/write mboot for removable media devices on sparc platform.
 *
 *     -----------------------------------------------------------
 *       platform   removable media  USB/1394  |  mboot supported
 *     -----------------------------------------------------------
 *        x86         X               X        |       true
 *     ------------------------------------------------------------
 *        sparc      false           false     |       false
 *        sparc      false           true      |       true
 *        sparc      true            false     |       true
 *        sparc      true            true      |       true
 *     ------------------------------------------------------------
 *
 *
 * 9.  error handling during opening device
 *
 *     If failed to open a disk device, an errno is returned. For some kinds
 *     of errors, different errno is returned depending on if this device is
 *     a removable media device. This brings USB/1394 hard disks in line with
 *     expected hard disk behavior. It is not expected that this breaks any
 *     application.
 *
 *     ------------------------------------------------------
 *       removable media    hotpluggable   |  errno
 *     ------------------------------------------------------
 *             false          false        |   EIO
 *             false          true         |   EIO
 *             true             x          |   ENXIO
 *     ------------------------------------------------------
 *
 *
 * 11. ioctls: DKIOCEJECT, CDROMEJECT
 *
 *     These IOCTLs are applicable only to removable media devices.
 *
 *     -----------------------------------------------------------
 *       removable media    hotpluggable   |DKIOCEJECT, CDROMEJECT
 *     -----------------------------------------------------------
 *             false          false        |     No
 *             false          true         |     No
 *             true            x           |     Yes
 *     -----------------------------------------------------------
 *
 *
 * 12. Kstats for partitions
 *
 *     sd creates partition kstat for non-removable media devices. USB and
 *     Firewire hard disks now have partition kstats
 *
 *      ------------------------------------------------------
 *       removable media    hotpluggable   |   kstat
 *      ------------------------------------------------------
 *             false          false        |    Yes
 *             false          true         |    Yes
 *             true             x          |    No
 *       ------------------------------------------------------
 *
 *
 * 13. Removable media & hotpluggable properties
 *
 *     Sd driver creates a "removable-media" property for removable media
 *     devices. Parent nexus drivers create a "hotpluggable" property if
 *     it supports hotplugging.
 *
 *     ---------------------------------------------------------------------
 *     removable media   hotpluggable |  "removable-media"   " hotpluggable"
 *     ---------------------------------------------------------------------
 *       false            false       |    No                   No
 *       false            true        |    No                   Yes
 *       true             false       |    Yes                  No
 *       true             true        |    Yes                  Yes
 *     ---------------------------------------------------------------------
 *
 *
 * 14. Power Management
 *
 *     sd only power manages removable media devices or devices that support
 *     LOG_SENSE or have a "pm-capable" property  (PSARC/2002/250)
 *
 *     A parent nexus that supports hotplugging can also set "pm-capable"
 *     if the disk can be power managed.
 *
 *     ------------------------------------------------------------
 *       removable media hotpluggable pm-capable  |   power manage
 *     ------------------------------------------------------------
 *             false          false     false     |     No
 *             false          false     true      |     Yes
 *             false          true      false     |     No
 *             false          true      true      |     Yes
 *             true             x        x        |     Yes
 *     ------------------------------------------------------------
 *
 *      USB and firewire hard disks can now be power managed independently
 *      of the framebuffer
 *
 *
 * 15. Support for USB disks with capacity larger than 1TB
 *
 *     Currently, sd doesn't permit a fixed disk device with capacity
 *     larger than 1TB to be used in a 32-bit operating system environment.
 *     However, sd doesn't do that for removable media devices. Instead, it
 *     assumes that removable media devices cannot have a capacity larger
 *     than 1TB. Therefore, using those devices on 32-bit system is partially
 *     supported, which can cause some unexpected results.
 *
 *     ---------------------------------------------------------------------
 *       removable media    USB/1394 | Capacity > 1TB |   Used in 32-bit env
 *     ---------------------------------------------------------------------
 *             false          false  |   true         |     no
 *             false          true   |   true         |     no
 *             true           false  |   true         |     Yes
 *             true           true   |   true         |     Yes
 *     ---------------------------------------------------------------------
 *
 *
 * 16. Check write-protection at open time
 *
 *     When a removable media device is being opened for writing without NDELAY
 *     flag, sd will check if this device is writable. If attempting to open
 *     without NDELAY flag a write-protected device, this operation will abort.
 *
 *     ------------------------------------------------------------
 *       removable media    USB/1394   |   WP Check
 *     ------------------------------------------------------------
 *             false          false    |     No
 *             false          true     |     No
 *             true           false    |     Yes
 *             true           true     |     Yes
 *     ------------------------------------------------------------
 *
 *
 * 17. syslog when corrupted VTOC is encountered
 *
 *      Currently, if an invalid VTOC is encountered, sd only print syslog
 *      for fixed SCSI disks.
 *     ------------------------------------------------------------
 *       removable media    USB/1394   |   print syslog
 *     ------------------------------------------------------------
 *             false          false    |     Yes
 *             false          true     |     No
 *             true           false    |     No
 *             true           true     |     No
 *     ------------------------------------------------------------
 */
static void
sd_set_unit_attributes(struct sd_lun *un, dev_info_t *devi)
{
	int	pm_cap;

	ASSERT(un->un_sd);
	ASSERT(un->un_sd->sd_inq);

	/*
	 * Enable SYNC CACHE support for all devices.
	 */
	un->un_f_sync_cache_supported = TRUE;

	/*
	 * Set the sync cache required flag to false.
	 * This would ensure that there is no SYNC CACHE
	 * sent when there are no writes
	 */
	un->un_f_sync_cache_required = FALSE;

	if (un->un_sd->sd_inq->inq_rmb) {
		/*
		 * The media of this device is removable. And for this kind
		 * of devices, it is possible to change medium after opening
		 * devices. Thus we should support this operation.
		 */
		un->un_f_has_removable_media = TRUE;

		/*
		 * support non-512-byte blocksize of removable media devices
		 */
		un->un_f_non_devbsize_supported = TRUE;

		/*
		 * Assume that all removable media devices support DOOR_LOCK
		 */
		un->un_f_doorlock_supported = TRUE;

		/*
		 * For a removable media device, it is possible to be opened
		 * with NDELAY flag when there is no media in drive, in this
		 * case we don't care if device is writable. But if without
		 * NDELAY flag, we need to check if media is write-protected.
		 */
		un->un_f_chk_wp_open = TRUE;

		/*
		 * need to start a SCSI watch thread to monitor media state,
		 * when media is being inserted or ejected, notify syseventd.
		 */
		un->un_f_monitor_media_state = TRUE;

		/*
		 * Some devices don't support START_STOP_UNIT command.
		 * Therefore, we'd better check if a device supports it
		 * before sending it.
		 */
		un->un_f_check_start_stop = TRUE;

		/*
		 * support eject media ioctl:
		 *		FDEJECT, DKIOCEJECT, CDROMEJECT
		 */
		un->un_f_eject_media_supported = TRUE;

		/*
		 * Because many removable-media devices don't support
		 * LOG_SENSE, we couldn't use this command to check if
		 * a removable media device support power-management.
		 * We assume that they support power-management via
		 * START_STOP_UNIT command and can be spun up and down
		 * without limitations.
		 */
		un->un_f_pm_supported = TRUE;

		/*
		 * Need to create a zero length (Boolean) property
		 * removable-media for the removable media devices.
		 * Note that the return value of the property is not being
		 * checked, since if unable to create the property
		 * then do not want the attach to fail altogether. Consistent
		 * with other property creation in attach.
		 */
		(void) ddi_prop_create(DDI_DEV_T_NONE, devi,
		    DDI_PROP_CANSLEEP, "removable-media", NULL, 0);

	} else {
		/*
		 * create device ID for device
		 */
		un->un_f_devid_supported = TRUE;

		/*
		 * Spin up non-removable-media devices once it is attached
		 */
		un->un_f_attach_spinup = TRUE;

		/*
		 * According to SCSI specification, Sense data has two kinds of
		 * format: fixed format, and descriptor format. At present, we
		 * don't support descriptor format sense data for removable
		 * media.
		 */
		if (SD_INQUIRY(un)->inq_dtype == DTYPE_DIRECT) {
			un->un_f_descr_format_supported = TRUE;
		}

		/*
		 * kstats are created only for non-removable media devices.
		 *
		 * Set this in sd.conf to 0 in order to disable kstats.  The
		 * default is 1, so they are enabled by default.
		 */
		un->un_f_pkstats_enabled = (ddi_prop_get_int(DDI_DEV_T_ANY,
		    SD_DEVINFO(un), DDI_PROP_DONTPASS,
		    "enable-partition-kstats", 1));

		/*
		 * Check if HBA has set the "pm-capable" property.
		 * If "pm-capable" exists and is non-zero then we can
		 * power manage the device without checking the start/stop
		 * cycle count log sense page.
		 *
		 * If "pm-capable" exists and is set to be false (0),
		 * then we should not power manage the device.
		 *
		 * If "pm-capable" doesn't exist then pm_cap will
		 * be set to SD_PM_CAPABLE_UNDEFINED (-1).  In this case,
		 * sd will check the start/stop cycle count log sense page
		 * and power manage the device if the cycle count limit has
		 * not been exceeded.
		 */
		pm_cap = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
		    DDI_PROP_DONTPASS, "pm-capable", SD_PM_CAPABLE_UNDEFINED);
		if (SD_PM_CAPABLE_IS_UNDEFINED(pm_cap)) {
			un->un_f_log_sense_supported = TRUE;
			if (!un->un_f_power_condition_disabled &&
			    SD_INQUIRY(un)->inq_ansi == 6) {
				un->un_f_power_condition_supported = TRUE;
			}
		} else {
			/*
			 * pm-capable property exists.
			 *
			 * Convert "TRUE" values for pm_cap to
			 * SD_PM_CAPABLE_IS_TRUE to make it easier to check
			 * later. "TRUE" values are any values defined in
			 * inquiry.h.
			 */
			if (SD_PM_CAPABLE_IS_FALSE(pm_cap)) {
				un->un_f_log_sense_supported = FALSE;
			} else {
				/* SD_PM_CAPABLE_IS_TRUE case */
				un->un_f_pm_supported = TRUE;
				if (!un->un_f_power_condition_disabled &&
				    SD_PM_CAPABLE_IS_SPC_4(pm_cap)) {
					un->un_f_power_condition_supported =
					    TRUE;
				}
				if (SD_PM_CAP_LOG_SUPPORTED(pm_cap)) {
					un->un_f_log_sense_supported = TRUE;
					un->un_f_pm_log_sense_smart =
					    SD_PM_CAP_SMART_LOG(pm_cap);
				}
			}

			SD_INFO(SD_LOG_ATTACH_DETACH, un,
			    "sd_unit_attach: un:0x%p pm-capable "
			    "property set to %d.\n", un, un->un_f_pm_supported);
		}
	}

	if (un->un_f_is_hotpluggable) {

		/*
		 * Have to watch hotpluggable devices as well, since
		 * that's the only way for userland applications to
		 * detect hot removal while device is busy/mounted.
		 */
		un->un_f_monitor_media_state = TRUE;

		un->un_f_check_start_stop = TRUE;

	}
}

/*
 * sd_tg_rdwr:
 * Provides rdwr access for cmlb via sd_tgops. The start_block is
 * in sys block size, req_length in bytes.
 *
 */
static int
sd_tg_rdwr(dev_info_t *devi, uchar_t cmd, void *bufaddr,
    diskaddr_t start_block, size_t reqlength, void *tg_cookie)
{
	struct sd_lun *un;
	int path_flag = (int)(uintptr_t)tg_cookie;
	char *dkl = NULL;
	diskaddr_t real_addr = start_block;
	diskaddr_t first_byte, end_block;

	size_t	buffer_size = reqlength;
	int rval = 0;
	diskaddr_t	cap;
	uint32_t	lbasize;
	sd_ssc_t	*ssc;

	un = ddi_get_soft_state(sd_state, ddi_get_instance(devi));
	if (un == NULL)
		return (ENXIO);

	if (cmd != TG_READ && cmd != TG_WRITE)
		return (EINVAL);

	ssc = sd_ssc_init(un);
	mutex_enter(SD_MUTEX(un));
	if (un->un_f_tgt_blocksize_is_valid == FALSE) {
		mutex_exit(SD_MUTEX(un));
		rval = sd_send_scsi_READ_CAPACITY(ssc, (uint64_t *)&cap,
		    &lbasize, path_flag);
		if (rval != 0)
			goto done1;
		mutex_enter(SD_MUTEX(un));
		sd_update_block_info(un, lbasize, cap);
		if ((un->un_f_tgt_blocksize_is_valid == FALSE)) {
			mutex_exit(SD_MUTEX(un));
			rval = EIO;
			goto done;
		}
	}

	if (NOT_DEVBSIZE(un)) {
		/*
		 * sys_blocksize != tgt_blocksize, need to re-adjust
		 * blkno and save the index to beginning of dk_label
		 */
		first_byte  = SD_SYSBLOCKS2BYTES(start_block);
		real_addr = first_byte / un->un_tgt_blocksize;

		end_block = (first_byte + reqlength +
		    un->un_tgt_blocksize - 1) / un->un_tgt_blocksize;

		/* round up buffer size to multiple of target block size */
		buffer_size = (end_block - real_addr) * un->un_tgt_blocksize;

		SD_TRACE(SD_LOG_IO_PARTITION, un, "sd_tg_rdwr",
		    "label_addr: 0x%x allocation size: 0x%x\n",
		    real_addr, buffer_size);

		if (((first_byte % un->un_tgt_blocksize) != 0) ||
		    (reqlength % un->un_tgt_blocksize) != 0)
			/* the request is not aligned */
			dkl = kmem_zalloc(buffer_size, KM_SLEEP);
	}

	/*
	 * The MMC standard allows READ CAPACITY to be
	 * inaccurate by a bounded amount (in the interest of
	 * response latency).  As a result, failed READs are
	 * commonplace (due to the reading of metadata and not
	 * data). Depending on the per-Vendor/drive Sense data,
	 * the failed READ can cause many (unnecessary) retries.
	 */

	if (ISCD(un) && (cmd == TG_READ) &&
	    (un->un_f_blockcount_is_valid == TRUE) &&
	    ((start_block == (un->un_blockcount - 1))||
	    (start_block == (un->un_blockcount - 2)))) {
			path_flag = SD_PATH_DIRECT_PRIORITY;
	}

	mutex_exit(SD_MUTEX(un));
	if (cmd == TG_READ) {
		rval = sd_send_scsi_READ(ssc, (dkl != NULL)? dkl: bufaddr,
		    buffer_size, real_addr, path_flag);
		if (dkl != NULL)
			bcopy(dkl + SD_TGTBYTEOFFSET(un, start_block,
			    real_addr), bufaddr, reqlength);
	} else {
		if (dkl) {
			rval = sd_send_scsi_READ(ssc, dkl, buffer_size,
			    real_addr, path_flag);
			if (rval) {
				goto done1;
			}
			bcopy(bufaddr, dkl + SD_TGTBYTEOFFSET(un, start_block,
			    real_addr), reqlength);
		}
		rval = sd_send_scsi_WRITE(ssc, (dkl != NULL)? dkl: bufaddr,
		    buffer_size, real_addr, path_flag);
	}

done1:
	if (dkl != NULL)
		kmem_free(dkl, buffer_size);

	if (rval != 0) {
		if (rval == EIO)
			sd_ssc_assessment(ssc, SD_FMT_STATUS_CHECK);
		else
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
	}
done:
	sd_ssc_fini(ssc);
	return (rval);
}


static int
sd_tg_getinfo(dev_info_t *devi, int cmd, void *arg, void *tg_cookie)
{

	struct sd_lun *un;
	diskaddr_t	cap;
	uint32_t	lbasize;
	int		path_flag = (int)(uintptr_t)tg_cookie;
	int		ret = 0;

	un = ddi_get_soft_state(sd_state, ddi_get_instance(devi));
	if (un == NULL)
		return (ENXIO);

	switch (cmd) {
	case TG_GETPHYGEOM:
	case TG_GETVIRTGEOM:
	case TG_GETCAPACITY:
	case TG_GETBLOCKSIZE:
		mutex_enter(SD_MUTEX(un));

		if ((un->un_f_blockcount_is_valid == TRUE) &&
		    (un->un_f_tgt_blocksize_is_valid == TRUE)) {
			cap = un->un_blockcount;
			lbasize = un->un_tgt_blocksize;
			mutex_exit(SD_MUTEX(un));
		} else {
			sd_ssc_t	*ssc;
			mutex_exit(SD_MUTEX(un));
			ssc = sd_ssc_init(un);
			ret = sd_send_scsi_READ_CAPACITY(ssc, (uint64_t *)&cap,
			    &lbasize, path_flag);
			if (ret != 0) {
				if (ret == EIO)
					sd_ssc_assessment(ssc,
					    SD_FMT_STATUS_CHECK);
				else
					sd_ssc_assessment(ssc,
					    SD_FMT_IGNORE);
				sd_ssc_fini(ssc);
				return (ret);
			}
			sd_ssc_fini(ssc);
			mutex_enter(SD_MUTEX(un));
			sd_update_block_info(un, lbasize, cap);
			if ((un->un_f_blockcount_is_valid == FALSE) ||
			    (un->un_f_tgt_blocksize_is_valid == FALSE)) {
				mutex_exit(SD_MUTEX(un));
				return (EIO);
			}
			mutex_exit(SD_MUTEX(un));
		}

		if (cmd == TG_GETCAPACITY) {
			*(diskaddr_t *)arg = cap;
			return (0);
		}

		if (cmd == TG_GETBLOCKSIZE) {
			*(uint32_t *)arg = lbasize;
			return (0);
		}

		if (cmd == TG_GETPHYGEOM)
			ret = sd_get_physical_geometry(un, (cmlb_geom_t *)arg,
			    cap, lbasize, path_flag);
		else
			/* TG_GETVIRTGEOM */
			ret = sd_get_virtual_geometry(un,
			    (cmlb_geom_t *)arg, cap, lbasize);

		return (ret);

	case TG_GETATTR:
		mutex_enter(SD_MUTEX(un));
		((tg_attribute_t *)arg)->media_is_writable =
		    un->un_f_mmc_writable_media;
		((tg_attribute_t *)arg)->media_is_solid_state =
		    un->un_f_is_solid_state;
		mutex_exit(SD_MUTEX(un));
		return (0);
	default:
		return (ENOTTY);

	}
}

/*
 *    Function: sd_ssc_ereport_post
 *
 * Description: Will be called when SD driver need to post an ereport.
 *
 *    Context: Kernel thread or interrupt context.
 */

#define	DEVID_IF_KNOWN(d) "devid", DATA_TYPE_STRING, (d) ? (d) : "unknown"

static void
sd_ssc_ereport_post(sd_ssc_t *ssc, enum sd_driver_assessment drv_assess)
{
	int uscsi_path_instance = 0;
	uchar_t	uscsi_pkt_reason;
	uint32_t uscsi_pkt_state;
	uint32_t uscsi_pkt_statistics;
	uint64_t uscsi_ena;
	uchar_t op_code;
	uint8_t *sensep;
	union scsi_cdb *cdbp;
	uint_t cdblen = 0;
	uint_t senlen = 0;
	struct sd_lun *un;
	dev_info_t *dip;
	char *devid;
	int ssc_invalid_flags = SSC_FLAGS_INVALID_PKT_REASON |
	    SSC_FLAGS_INVALID_STATUS |
	    SSC_FLAGS_INVALID_SENSE |
	    SSC_FLAGS_INVALID_DATA;
	char assessment[16];

	ASSERT(ssc != NULL);
	ASSERT(ssc->ssc_uscsi_cmd != NULL);
	ASSERT(ssc->ssc_uscsi_info != NULL);

	un = ssc->ssc_un;
	ASSERT(un != NULL);

	dip = un->un_sd->sd_dev;

	/*
	 * Get the devid:
	 *	devid will only be passed to non-transport error reports.
	 */
	devid = DEVI(dip)->devi_devid_str;

	/*
	 * If we are syncing or dumping, the command will not be executed
	 * so we bypass this situation.
	 */
	if (ddi_in_panic() || (un->un_state == SD_STATE_SUSPENDED) ||
	    (un->un_state == SD_STATE_DUMPING))
		return;

	uscsi_pkt_reason = ssc->ssc_uscsi_info->ui_pkt_reason;
	uscsi_path_instance = ssc->ssc_uscsi_cmd->uscsi_path_instance;
	uscsi_pkt_state = ssc->ssc_uscsi_info->ui_pkt_state;
	uscsi_pkt_statistics = ssc->ssc_uscsi_info->ui_pkt_statistics;
	uscsi_ena = ssc->ssc_uscsi_info->ui_ena;

	sensep = (uint8_t *)ssc->ssc_uscsi_cmd->uscsi_rqbuf;
	cdbp = (union scsi_cdb *)ssc->ssc_uscsi_cmd->uscsi_cdb;

	/* In rare cases, EG:DOORLOCK, the cdb could be NULL */
	if (cdbp == NULL) {
		scsi_log(SD_DEVINFO(un), sd_label, CE_WARN,
		    "sd_ssc_ereport_post meet empty cdb\n");
		return;
	}

	op_code = cdbp->scc_cmd;

	cdblen = (int)ssc->ssc_uscsi_cmd->uscsi_cdblen;
	senlen = (int)(ssc->ssc_uscsi_cmd->uscsi_rqlen -
	    ssc->ssc_uscsi_cmd->uscsi_rqresid);

	if (senlen > 0)
		ASSERT(sensep != NULL);

	/*
	 * Initialize drv_assess to corresponding values.
	 * SD_FM_DRV_FATAL will be mapped to "fail" or "fatal" depending
	 * on the sense-key returned back.
	 */
	switch (drv_assess) {
		case SD_FM_DRV_RECOVERY:
			(void) sprintf(assessment, "%s", "recovered");
			break;
		case SD_FM_DRV_RETRY:
			(void) sprintf(assessment, "%s", "retry");
			break;
		case SD_FM_DRV_NOTICE:
			(void) sprintf(assessment, "%s", "info");
			break;
		case SD_FM_DRV_FATAL:
		default:
			(void) sprintf(assessment, "%s", "unknown");
	}
	/*
	 * If drv_assess == SD_FM_DRV_RECOVERY, this should be a recovered
	 * command, we will post ereport.io.scsi.cmd.disk.recovered.
	 * driver-assessment will always be "recovered" here.
	 */
	if (drv_assess == SD_FM_DRV_RECOVERY) {
		scsi_fm_ereport_post(un->un_sd, uscsi_path_instance, NULL,
		    "cmd.disk.recovered", uscsi_ena, devid, NULL,
		    DDI_NOSLEEP, NULL,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    DEVID_IF_KNOWN(devid),
		    "driver-assessment", DATA_TYPE_STRING, assessment,
		    "op-code", DATA_TYPE_UINT8, op_code,
		    "cdb", DATA_TYPE_UINT8_ARRAY,
		    cdblen, ssc->ssc_uscsi_cmd->uscsi_cdb,
		    "pkt-reason", DATA_TYPE_UINT8, uscsi_pkt_reason,
		    "pkt-state", DATA_TYPE_UINT32, uscsi_pkt_state,
		    "pkt-stats", DATA_TYPE_UINT32, uscsi_pkt_statistics,
		    NULL);
		return;
	}

	/*
	 * If there is un-expected/un-decodable data, we should post
	 * ereport.io.scsi.cmd.disk.dev.uderr.
	 * driver-assessment will be set based on parameter drv_assess.
	 * SSC_FLAGS_INVALID_SENSE - invalid sense data sent back.
	 * SSC_FLAGS_INVALID_PKT_REASON - invalid pkt-reason encountered.
	 * SSC_FLAGS_INVALID_STATUS - invalid stat-code encountered.
	 * SSC_FLAGS_INVALID_DATA - invalid data sent back.
	 */
	if (ssc->ssc_flags & ssc_invalid_flags) {
		if (ssc->ssc_flags & SSC_FLAGS_INVALID_SENSE) {
			scsi_fm_ereport_post(un->un_sd, uscsi_path_instance,
			    NULL, "cmd.disk.dev.uderr", uscsi_ena, devid,
			    NULL, DDI_NOSLEEP, NULL,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    DEVID_IF_KNOWN(devid),
			    "driver-assessment", DATA_TYPE_STRING,
			    drv_assess == SD_FM_DRV_FATAL ?
			    "fail" : assessment,
			    "op-code", DATA_TYPE_UINT8, op_code,
			    "cdb", DATA_TYPE_UINT8_ARRAY,
			    cdblen, ssc->ssc_uscsi_cmd->uscsi_cdb,
			    "pkt-reason", DATA_TYPE_UINT8, uscsi_pkt_reason,
			    "pkt-state", DATA_TYPE_UINT32, uscsi_pkt_state,
			    "pkt-stats", DATA_TYPE_UINT32,
			    uscsi_pkt_statistics,
			    "stat-code", DATA_TYPE_UINT8,
			    ssc->ssc_uscsi_cmd->uscsi_status,
			    "un-decode-info", DATA_TYPE_STRING,
			    ssc->ssc_info,
			    "un-decode-value", DATA_TYPE_UINT8_ARRAY,
			    senlen, sensep,
			    NULL);
		} else {
			/*
			 * For other type of invalid data, the
			 * un-decode-value field would be empty because the
			 * un-decodable content could be seen from upper
			 * level payload or inside un-decode-info.
			 */
			scsi_fm_ereport_post(un->un_sd, uscsi_path_instance,
			    NULL,
			    "cmd.disk.dev.uderr", uscsi_ena, devid,
			    NULL, DDI_NOSLEEP, NULL,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    DEVID_IF_KNOWN(devid),
			    "driver-assessment", DATA_TYPE_STRING,
			    drv_assess == SD_FM_DRV_FATAL ?
			    "fail" : assessment,
			    "op-code", DATA_TYPE_UINT8, op_code,
			    "cdb", DATA_TYPE_UINT8_ARRAY,
			    cdblen, ssc->ssc_uscsi_cmd->uscsi_cdb,
			    "pkt-reason", DATA_TYPE_UINT8, uscsi_pkt_reason,
			    "pkt-state", DATA_TYPE_UINT32, uscsi_pkt_state,
			    "pkt-stats", DATA_TYPE_UINT32,
			    uscsi_pkt_statistics,
			    "stat-code", DATA_TYPE_UINT8,
			    ssc->ssc_uscsi_cmd->uscsi_status,
			    "un-decode-info", DATA_TYPE_STRING,
			    ssc->ssc_info,
			    "un-decode-value", DATA_TYPE_UINT8_ARRAY,
			    0, NULL,
			    NULL);
		}
		ssc->ssc_flags &= ~ssc_invalid_flags;
		return;
	}

	if (uscsi_pkt_reason != CMD_CMPLT ||
	    (ssc->ssc_flags & SSC_FLAGS_TRAN_ABORT)) {
		/*
		 * pkt-reason != CMD_CMPLT or SSC_FLAGS_TRAN_ABORT was
		 * set inside sd_start_cmds due to errors(bad packet or
		 * fatal transport error), we should take it as a
		 * transport error, so we post ereport.io.scsi.cmd.disk.tran.
		 * driver-assessment will be set based on drv_assess.
		 * We will set devid to NULL because it is a transport
		 * error.
		 */
		if (ssc->ssc_flags & SSC_FLAGS_TRAN_ABORT)
			ssc->ssc_flags &= ~SSC_FLAGS_TRAN_ABORT;

		scsi_fm_ereport_post(un->un_sd, uscsi_path_instance, NULL,
		    "cmd.disk.tran", uscsi_ena, NULL, NULL, DDI_NOSLEEP, NULL,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
		    DEVID_IF_KNOWN(devid),
		    "driver-assessment", DATA_TYPE_STRING,
		    drv_assess == SD_FM_DRV_FATAL ? "fail" : assessment,
		    "op-code", DATA_TYPE_UINT8, op_code,
		    "cdb", DATA_TYPE_UINT8_ARRAY,
		    cdblen, ssc->ssc_uscsi_cmd->uscsi_cdb,
		    "pkt-reason", DATA_TYPE_UINT8, uscsi_pkt_reason,
		    "pkt-state", DATA_TYPE_UINT8, uscsi_pkt_state,
		    "pkt-stats", DATA_TYPE_UINT32, uscsi_pkt_statistics,
		    NULL);
	} else {
		/*
		 * If we got here, we have a completed command, and we need
		 * to further investigate the sense data to see what kind
		 * of ereport we should post.
		 * No ereport is needed if sense-key is KEY_RECOVERABLE_ERROR
		 * and asc/ascq is "ATA PASS-THROUGH INFORMATION AVAILABLE".
		 * Post ereport.io.scsi.cmd.disk.dev.rqs.merr if sense-key is
		 * KEY_MEDIUM_ERROR.
		 * Post ereport.io.scsi.cmd.disk.dev.rqs.derr otherwise.
		 * driver-assessment will be set based on the parameter
		 * drv_assess.
		 */
		if (senlen > 0) {
			/*
			 * Here we have sense data available.
			 */
			uint8_t sense_key = scsi_sense_key(sensep);
			uint8_t sense_asc = scsi_sense_asc(sensep);
			uint8_t sense_ascq = scsi_sense_ascq(sensep);

			if (sense_key == KEY_RECOVERABLE_ERROR &&
			    sense_asc == 0x00 && sense_ascq == 0x1d)
				return;

			if (sense_key == KEY_MEDIUM_ERROR) {
				/*
				 * driver-assessment should be "fatal" if
				 * drv_assess is SD_FM_DRV_FATAL.
				 */
				scsi_fm_ereport_post(un->un_sd,
				    uscsi_path_instance, NULL,
				    "cmd.disk.dev.rqs.merr",
				    uscsi_ena, devid, NULL, DDI_NOSLEEP, NULL,
				    FM_VERSION, DATA_TYPE_UINT8,
				    FM_EREPORT_VERS0,
				    DEVID_IF_KNOWN(devid),
				    "driver-assessment",
				    DATA_TYPE_STRING,
				    drv_assess == SD_FM_DRV_FATAL ?
				    "fatal" : assessment,
				    "op-code",
				    DATA_TYPE_UINT8, op_code,
				    "cdb",
				    DATA_TYPE_UINT8_ARRAY, cdblen,
				    ssc->ssc_uscsi_cmd->uscsi_cdb,
				    "pkt-reason",
				    DATA_TYPE_UINT8, uscsi_pkt_reason,
				    "pkt-state",
				    DATA_TYPE_UINT8, uscsi_pkt_state,
				    "pkt-stats",
				    DATA_TYPE_UINT32,
				    uscsi_pkt_statistics,
				    "stat-code",
				    DATA_TYPE_UINT8,
				    ssc->ssc_uscsi_cmd->uscsi_status,
				    "key",
				    DATA_TYPE_UINT8,
				    scsi_sense_key(sensep),
				    "asc",
				    DATA_TYPE_UINT8,
				    scsi_sense_asc(sensep),
				    "ascq",
				    DATA_TYPE_UINT8,
				    scsi_sense_ascq(sensep),
				    "sense-data",
				    DATA_TYPE_UINT8_ARRAY,
				    senlen, sensep,
				    "lba",
				    DATA_TYPE_UINT64,
				    ssc->ssc_uscsi_info->ui_lba,
				    NULL);
			} else {
				/*
				 * if sense-key == 0x4(hardware
				 * error), driver-assessment should
				 * be "fatal" if drv_assess is
				 * SD_FM_DRV_FATAL.
				 */
				scsi_fm_ereport_post(un->un_sd,
				    uscsi_path_instance, NULL,
				    "cmd.disk.dev.rqs.derr",
				    uscsi_ena, devid,
				    NULL, DDI_NOSLEEP, NULL,
				    FM_VERSION,
				    DATA_TYPE_UINT8, FM_EREPORT_VERS0,
				    DEVID_IF_KNOWN(devid),
				    "driver-assessment",
				    DATA_TYPE_STRING,
				    drv_assess == SD_FM_DRV_FATAL ?
				    (sense_key == 0x4 ?
				    "fatal" : "fail") : assessment,
				    "op-code",
				    DATA_TYPE_UINT8, op_code,
				    "cdb",
				    DATA_TYPE_UINT8_ARRAY, cdblen,
				    ssc->ssc_uscsi_cmd->uscsi_cdb,
				    "pkt-reason",
				    DATA_TYPE_UINT8, uscsi_pkt_reason,
				    "pkt-state",
				    DATA_TYPE_UINT8, uscsi_pkt_state,
				    "pkt-stats",
				    DATA_TYPE_UINT32,
				    uscsi_pkt_statistics,
				    "stat-code",
				    DATA_TYPE_UINT8,
				    ssc->ssc_uscsi_cmd->uscsi_status,
				    "key",
				    DATA_TYPE_UINT8,
				    scsi_sense_key(sensep),
				    "asc",
				    DATA_TYPE_UINT8,
				    scsi_sense_asc(sensep),
				    "ascq",
				    DATA_TYPE_UINT8,
				    scsi_sense_ascq(sensep),
				    "sense-data",
				    DATA_TYPE_UINT8_ARRAY,
				    senlen, sensep,
				    NULL);
			}
		} else {
			/*
			 * For stat_code == STATUS_GOOD, this is not a
			 * hardware error.
			 */
			if (ssc->ssc_uscsi_cmd->uscsi_status == STATUS_GOOD)
				return;

			/*
			 * Post ereport.io.scsi.cmd.disk.dev.serr if we got the
			 * stat-code but with sense data unavailable.
			 * driver-assessment will be set based on parameter
			 * drv_assess.
			 */
			scsi_fm_ereport_post(un->un_sd, uscsi_path_instance,
			    NULL,
			    "cmd.disk.dev.serr", uscsi_ena,
			    devid, NULL, DDI_NOSLEEP, NULL,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    DEVID_IF_KNOWN(devid),
			    "driver-assessment", DATA_TYPE_STRING,
			    drv_assess == SD_FM_DRV_FATAL ? "fail" : assessment,
			    "op-code", DATA_TYPE_UINT8, op_code,
			    "cdb",
			    DATA_TYPE_UINT8_ARRAY,
			    cdblen, ssc->ssc_uscsi_cmd->uscsi_cdb,
			    "pkt-reason",
			    DATA_TYPE_UINT8, uscsi_pkt_reason,
			    "pkt-state",
			    DATA_TYPE_UINT8, uscsi_pkt_state,
			    "pkt-stats",
			    DATA_TYPE_UINT32, uscsi_pkt_statistics,
			    "stat-code",
			    DATA_TYPE_UINT8,
			    ssc->ssc_uscsi_cmd->uscsi_status,
			    NULL);
		}
	}
}

/*
 *     Function: sd_ssc_extract_info
 *
 * Description: Extract information available to help generate ereport.
 *
 *     Context: Kernel thread or interrupt context.
 */
static void
sd_ssc_extract_info(sd_ssc_t *ssc, struct sd_lun *un, struct scsi_pkt *pktp,
    struct buf *bp, struct sd_xbuf *xp)
{
	size_t senlen = 0;
	union scsi_cdb *cdbp;
	int path_instance;
	/*
	 * Need scsi_cdb_size array to determine the cdb length.
	 */
	extern uchar_t	scsi_cdb_size[];

	ASSERT(un != NULL);
	ASSERT(pktp != NULL);
	ASSERT(bp != NULL);
	ASSERT(xp != NULL);
	ASSERT(ssc != NULL);
	ASSERT(mutex_owned(SD_MUTEX(un)));

	/*
	 * Transfer the cdb buffer pointer here.
	 */
	cdbp = (union scsi_cdb *)pktp->pkt_cdbp;

	ssc->ssc_uscsi_cmd->uscsi_cdblen = scsi_cdb_size[GETGROUP(cdbp)];
	ssc->ssc_uscsi_cmd->uscsi_cdb = (caddr_t)cdbp;

	/*
	 * Transfer the sense data buffer pointer if sense data is available,
	 * calculate the sense data length first.
	 */
	if ((xp->xb_sense_state & STATE_XARQ_DONE) ||
	    (xp->xb_sense_state & STATE_ARQ_DONE)) {
		/*
		 * For arq case, we will enter here.
		 */
		if (xp->xb_sense_state & STATE_XARQ_DONE) {
			senlen = MAX_SENSE_LENGTH - xp->xb_sense_resid;
		} else {
			senlen = SENSE_LENGTH;
		}
	} else {
		/*
		 * For non-arq case, we will enter this branch.
		 */
		if (SD_GET_PKT_STATUS(pktp) == STATUS_CHECK &&
		    (xp->xb_sense_state & STATE_XFERRED_DATA)) {
			senlen = SENSE_LENGTH - xp->xb_sense_resid;
		}

	}

	ssc->ssc_uscsi_cmd->uscsi_rqlen = (senlen & 0xff);
	ssc->ssc_uscsi_cmd->uscsi_rqresid = 0;
	ssc->ssc_uscsi_cmd->uscsi_rqbuf = (caddr_t)xp->xb_sense_data;

	ssc->ssc_uscsi_cmd->uscsi_status = ((*(pktp)->pkt_scbp) & STATUS_MASK);

	/*
	 * Only transfer path_instance when scsi_pkt was properly allocated.
	 */
	path_instance = pktp->pkt_path_instance;
	if (scsi_pkt_allocated_correctly(pktp) && path_instance)
		ssc->ssc_uscsi_cmd->uscsi_path_instance = path_instance;
	else
		ssc->ssc_uscsi_cmd->uscsi_path_instance = 0;

	/*
	 * Copy in the other fields we may need when posting ereport.
	 */
	ssc->ssc_uscsi_info->ui_pkt_reason = pktp->pkt_reason;
	ssc->ssc_uscsi_info->ui_pkt_state = pktp->pkt_state;
	ssc->ssc_uscsi_info->ui_pkt_statistics = pktp->pkt_statistics;
	ssc->ssc_uscsi_info->ui_lba = (uint64_t)SD_GET_BLKNO(bp);

	/*
	 * For partially read/write command, we will not create ena
	 * in case of a successful command be reconized as recovered.
	 */
	if ((pktp->pkt_reason == CMD_CMPLT) &&
	    (ssc->ssc_uscsi_cmd->uscsi_status == STATUS_GOOD) &&
	    (senlen == 0)) {
		return;
	}

	/*
	 * To associate ereports of a single command execution flow, we
	 * need a shared ena for a specific command.
	 */
	if (xp->xb_ena == 0)
		xp->xb_ena = fm_ena_generate(0, FM_ENA_FMT1);
	ssc->ssc_uscsi_info->ui_ena = xp->xb_ena;
}


/*
 *     Function: sd_check_solid_state
 *
 * Description: Query the optional INQUIRY VPD page 0xb1. If the device
 *              supports VPD page 0xb1, sd examines the MEDIUM ROTATION
 *              RATE. If the MEDIUM ROTATION RATE is 1, sd assumes the
 *              device is a solid state drive.
 *
 *     Context: Kernel thread or interrupt context.
 */

static void
sd_check_solid_state(sd_ssc_t *ssc)
{
	int		rval		= 0;
	uchar_t		*inqb1		= NULL;
	size_t		inqb1_len	= MAX_INQUIRY_SIZE;
	size_t		inqb1_resid	= 0;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	mutex_enter(SD_MUTEX(un));
	un->un_f_is_solid_state = FALSE;

	if (ISCD(un)) {
		mutex_exit(SD_MUTEX(un));
		return;
	}

	if (sd_check_vpd_page_support(ssc) == 0 &&
	    un->un_vpd_page_mask & SD_VPD_DEV_CHARACTER_PG) {
		mutex_exit(SD_MUTEX(un));
		/* collect page b1 data */
		inqb1 = kmem_zalloc(inqb1_len, KM_SLEEP);

		rval = sd_send_scsi_INQUIRY(ssc, inqb1, inqb1_len,
		    0x01, 0xB1, &inqb1_resid);

		if (rval == 0 && (inqb1_len - inqb1_resid > 5)) {
			SD_TRACE(SD_LOG_COMMON, un,
			    "sd_check_solid_state: \
			    successfully get VPD page: %x \
			    PAGE LENGTH: %x BYTE 4: %x \
			    BYTE 5: %x", inqb1[1], inqb1[3], inqb1[4],
			    inqb1[5]);

			mutex_enter(SD_MUTEX(un));
			/*
			 * Check the MEDIUM ROTATION RATE. If it is set
			 * to 1, the device is a solid state drive.
			 */
			if (inqb1[4] == 0 && inqb1[5] == 1) {
				un->un_f_is_solid_state = TRUE;
				/* solid state drives don't need disksort */
				un->un_f_disksort_disabled = TRUE;
			}
			mutex_exit(SD_MUTEX(un));
		} else if (rval != 0) {
			sd_ssc_assessment(ssc, SD_FMT_IGNORE);
		}

		kmem_free(inqb1, inqb1_len);
	} else {
		mutex_exit(SD_MUTEX(un));
	}
}

/*
 *	Function: sd_check_emulation_mode
 *
 *   Description: Check whether the SSD is at emulation mode
 *		  by issuing READ_CAPACITY_16 to see whether
 *		  we can get physical block size of the drive.
 *
 *	 Context: Kernel thread or interrupt context.
 */

static void
sd_check_emulation_mode(sd_ssc_t *ssc)
{
	int		rval = 0;
	uint64_t	capacity;
	uint_t		lbasize;
	uint_t		pbsize;
	int		i;
	int		devid_len;
	struct sd_lun	*un;

	ASSERT(ssc != NULL);
	un = ssc->ssc_un;
	ASSERT(un != NULL);
	ASSERT(!mutex_owned(SD_MUTEX(un)));

	mutex_enter(SD_MUTEX(un));
	if (ISCD(un)) {
		mutex_exit(SD_MUTEX(un));
		return;
	}

	if (un->un_f_descr_format_supported) {
		mutex_exit(SD_MUTEX(un));
		rval = sd_send_scsi_READ_CAPACITY_16(ssc, &capacity, &lbasize,
		    &pbsize, SD_PATH_DIRECT);
		mutex_enter(SD_MUTEX(un));

		if (rval != 0) {
			un->un_phy_blocksize = DEV_BSIZE;
		} else {
			if (!ISP2(pbsize % DEV_BSIZE) || pbsize == 0) {
				un->un_phy_blocksize = DEV_BSIZE;
			} else if (pbsize > un->un_phy_blocksize) {
				/*
				 * Don't reset the physical blocksize
				 * unless we've detected a larger value.
				 */
				un->un_phy_blocksize = pbsize;
			}
		}
	}

	for (i = 0; i < sd_flash_dev_table_size; i++) {
		devid_len = (int)strlen(sd_flash_dev_table[i]);
		if (sd_sdconf_id_match(un, sd_flash_dev_table[i], devid_len)
		    == SD_SUCCESS) {
			un->un_phy_blocksize = SSD_SECSIZE;
			if (un->un_f_is_solid_state &&
			    un->un_phy_blocksize != un->un_tgt_blocksize)
				un->un_f_enable_rmw = TRUE;
		}
	}

	mutex_exit(SD_MUTEX(un));
}
