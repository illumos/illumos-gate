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
 *  Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 *  Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

/*
 * SCSI	 SCSA-compliant and not-so-DDI-compliant Tape Driver
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG	1
#endif

#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/mtio.h>
#include <sys/scsi/targets/stdef.h>
#include <sys/file.h>
#include <sys/kstat.h>
#include <sys/ddidmareq.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>

#define	IOSP	KSTAT_IO_PTR(un->un_stats)
/*
 * stats maintained only for reads/writes as commands
 * like rewind etc skew the wait/busy times
 */
#define	IS_RW(bp) 	((bp)->b_bcount > 0)
#define	ST_DO_KSTATS(bp, kstat_function) \
	if ((bp != un->un_sbufp) && un->un_stats && IS_RW(bp)) { \
		kstat_function(IOSP); \
	}

#define	ST_DO_ERRSTATS(un, x)  \
	if (un->un_errstats) { \
		struct st_errstats *stp; \
		stp = (struct st_errstats *)un->un_errstats->ks_data; \
		stp->x.value.ul++; \
	}

#define	FILL_SCSI1_LUN(devp, pkt) 					\
	if ((devp)->sd_inq->inq_ansi == 0x1) {				\
		int _lun;						\
		_lun = ddi_prop_get_int(DDI_DEV_T_ANY, (devp)->sd_dev,	\
		    DDI_PROP_DONTPASS, SCSI_ADDR_PROP_LUN, 0);		\
		if (_lun > 0) {						\
			((union scsi_cdb *)(pkt)->pkt_cdbp)->scc_lun =	\
			    _lun;					\
		}							\
	}

/*
 * get an available contig mem header, cp.
 * when big_enough is true, we will return NULL, if no big enough
 * contig mem is found.
 * when big_enough is false, we will try to find cp containing big
 * enough contig mem. if not found, we will ruturn the last cp available.
 *
 * used by st_get_contig_mem()
 */
#define	ST_GET_CONTIG_MEM_HEAD(un, cp, len, big_enough) {		\
	struct contig_mem *tmp_cp = NULL;				\
	for ((cp) = (un)->un_contig_mem;				\
	    (cp) != NULL;						\
	    tmp_cp = (cp), (cp) = (cp)->cm_next) { 			\
		if (((cp)->cm_len >= (len)) || 				\
		    (!(big_enough) && ((cp)->cm_next == NULL))) { 	\
			if (tmp_cp == NULL) { 				\
				(un)->un_contig_mem = (cp)->cm_next; 	\
			} else { 					\
				tmp_cp->cm_next = (cp)->cm_next; 	\
			} 						\
			(cp)->cm_next = NULL; 				\
			(un)->un_contig_mem_available_num--; 		\
			break; 						\
		} 							\
	} 								\
}

#define	ST_NUM_MEMBERS(array)	(sizeof (array) / sizeof (array[0]))
#define	COPY_POS(dest, source) bcopy(source, dest, sizeof (tapepos_t))
#define	ISALNUM(byte) \
	(((byte) >= 'a' && (byte) <= 'z') || \
	((byte) >= 'A' && (byte) <= 'Z') || \
	((byte) >= '0' && (byte) <= '9'))

#define	ONE_K	1024

#define	MAX_SPACE_CNT(cnt) if (cnt >= 0) { \
		if (cnt > MIN(SP_CNT_MASK, INT32_MAX)) \
			return (EINVAL); \
	} else { \
		if (-(cnt) > MIN(SP_CNT_MASK, INT32_MAX)) \
			return (EINVAL); \
	} \

/*
 * Global External Data Definitions
 */
extern struct scsi_key_strings scsi_cmds[];
extern uchar_t	scsi_cdb_size[];

/*
 * Local Static Data
 */
static void *st_state;
static char *const st_label = "st";
static volatile int st_recov_sz = sizeof (recov_info);
static const char mp_misconf[] = {
	"St Tape is misconfigured, MPxIO enabled and "
	"tape-command-recovery-disable set in st.conf\n"
};

#ifdef	__x86
/*
 * We need to use below DMA attr to alloc physically contiguous
 * memory to do I/O in big block size
 */
static ddi_dma_attr_t st_contig_mem_dma_attr = {
	DMA_ATTR_V0,    /* version number */
	0x0,		/* lowest usable address */
	0xFFFFFFFFull,  /* high DMA address range */
	0xFFFFFFFFull,  /* DMA counter register */
	1,		/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xFFFFFFFFull,  /* max DMA xfer size */
	0xFFFFFFFFull,  /* segment boundary */
	1,		/* s/g list length */
	1,		/* granularity of device */
	0		/* DMA transfer flags */
};

static ddi_device_acc_attr_t st_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/* set limitation for the number of contig_mem */
static int st_max_contig_mem_num = ST_MAX_CONTIG_MEM_NUM;
#endif

/*
 * Tunable parameters
 *
 * DISCLAIMER
 * ----------
 * These parameters are intended for use only in system testing; if you use
 * them in production systems, you do so at your own risk. Altering any
 * variable not listed below may cause unpredictable system behavior.
 *
 * st_check_media_time
 *
 *   Three second state check
 *
 * st_allow_large_xfer
 *
 *   Gated with ST_NO_RECSIZE_LIMIT
 *
 *   0 - Transfers larger than 64KB will not be allowed
 *       regardless of the setting of ST_NO_RECSIZE_LIMIT
 *   1 - Transfers larger than 64KB will be allowed
 *       if ST_NO_RECSIZE_LIMIT is TRUE for the drive
 *
 * st_report_soft_errors_on_close
 *
 *  Gated with ST_SOFT_ERROR_REPORTING
 *
 *  0 - Errors will not be reported on close regardless
 *      of the setting of ST_SOFT_ERROR_REPORTING
 *
 *  1 - Errors will be reported on close if
 *      ST_SOFT_ERROR_REPORTING is TRUE for the drive
 */
static int st_selection_retry_count = ST_SEL_RETRY_COUNT;
static int st_retry_count	= ST_RETRY_COUNT;

static int st_io_time		= ST_IO_TIME;
static int st_long_timeout_x	= ST_LONG_TIMEOUT_X;

static int st_space_time	= ST_SPACE_TIME;
static int st_long_space_time_x	= ST_LONG_SPACE_TIME_X;

static int st_error_level	= SCSI_ERR_RETRYABLE;
static int st_check_media_time	= 3000000;	/* 3 Second State Check */

static int st_max_throttle	= ST_MAX_THROTTLE;

static clock_t st_wait_cmds_complete = ST_WAIT_CMDS_COMPLETE;

static int st_allow_large_xfer = 1;
static int st_report_soft_errors_on_close = 1;

/*
 * End of tunable parameters list
 */



/*
 * Asynchronous I/O and persistent errors, refer to PSARC/1995/228
 *
 * Asynchronous I/O's main offering is that it is a non-blocking way to do
 * reads and writes.  The driver will queue up all the requests it gets and
 * have them ready to transport to the HBA.  Unfortunately, we cannot always
 * just ship the I/O requests to the HBA, as there errors and exceptions
 * that may happen when we don't want the HBA to continue.  Therein comes
 * the flush-on-errors capability.  If the HBA supports it, then st will
 * send in st_max_throttle I/O requests at the same time.
 *
 * Persistent errors : This was also reasonably simple.  In the interrupt
 * routines, if there was an error or exception (FM, LEOT, media error,
 * transport error), the persistent error bits are set and shuts everything
 * down, but setting the throttle to zero.  If we hit and exception in the
 * HBA, and flush-on-errors were set, we wait for all outstanding I/O's to
 * come back (with CMD_ABORTED), then flush all bp's in the wait queue with
 * the appropriate error, and this will preserve order. Of course, depending
 * on the exception we have to show a zero read or write before we show
 * errors back to the application.
 */

extern const int st_ndrivetypes;	/* defined in st_conf.c */
extern const struct st_drivetype st_drivetypes[];
extern const char st_conf_version[];

#ifdef STDEBUG
static int st_soft_error_report_debug = 0;
volatile int st_debug = 0;
static volatile dev_info_t *st_lastdev;
static kmutex_t st_debug_mutex;
#endif

#define	ST_MT02_NAME	"Emulex  MT02 QIC-11/24  "

static const struct vid_drivetype {
	char	*vid;
	char	type;
} st_vid_dt[] = {
	{"LTO-CVE ",	MT_LTO},
	{"QUANTUM ",    MT_ISDLT},
	{"SONY    ",    MT_ISAIT},
	{"STK     ",	MT_ISSTK9840}
};

static const struct driver_minor_data {
	char	*name;
	int	minor;
} st_minor_data[] = {
	/*
	 * The top 4 entries are for the default densities,
	 * don't alter their position.
	 */
	{"",	0},
	{"n",	MT_NOREWIND},
	{"b",	MT_BSD},
	{"bn",	MT_NOREWIND | MT_BSD},
	{"l",	MT_DENSITY1},
	{"m",	MT_DENSITY2},
	{"h",	MT_DENSITY3},
	{"c",	MT_DENSITY4},
	{"u",	MT_DENSITY4},
	{"ln",	MT_DENSITY1 | MT_NOREWIND},
	{"mn",	MT_DENSITY2 | MT_NOREWIND},
	{"hn",	MT_DENSITY3 | MT_NOREWIND},
	{"cn",	MT_DENSITY4 | MT_NOREWIND},
	{"un",	MT_DENSITY4 | MT_NOREWIND},
	{"lb",	MT_DENSITY1 | MT_BSD},
	{"mb",	MT_DENSITY2 | MT_BSD},
	{"hb",	MT_DENSITY3 | MT_BSD},
	{"cb",	MT_DENSITY4 | MT_BSD},
	{"ub",	MT_DENSITY4 | MT_BSD},
	{"lbn",	MT_DENSITY1 | MT_NOREWIND | MT_BSD},
	{"mbn",	MT_DENSITY2 | MT_NOREWIND | MT_BSD},
	{"hbn",	MT_DENSITY3 | MT_NOREWIND | MT_BSD},
	{"cbn",	MT_DENSITY4 | MT_NOREWIND | MT_BSD},
	{"ubn",	MT_DENSITY4 | MT_NOREWIND | MT_BSD}
};

/* strings used in many debug and warning messages */
static const char wr_str[]  = "write";
static const char rd_str[]  = "read";
static const char wrg_str[] = "writing";
static const char rdg_str[] = "reading";
static const char *space_strs[] = {
	"records",
	"filemarks",
	"sequential filemarks",
	"eod",
	"setmarks",
	"sequential setmarks",
	"Reserved",
	"Reserved"
};
static const char *load_strs[] = {
	"unload",		/* LD_UNLOAD		0 */
	"load",			/* LD_LOAD		1 */
	"retension",		/* LD_RETEN		2 */
	"load reten",		/* LD_LOAD | LD_RETEN	3 */
	"eod",			/* LD_EOT		4 */
	"load EOD",		/* LD_LOAD | LD_EOT	5 */
	"reten EOD",		/* LD_RETEN | LD_EOT	6 */
	"load reten EOD"	/* LD_LOAD|LD_RETEN|LD_EOT 7 */
	"hold",			/* LD_HOLD		8 */
	"load and hold"		/* LD_LOAD | LD_HOLD	9 */
};

static const char *errstatenames[] = {
	"COMMAND_DONE",
	"COMMAND_DONE_ERROR",
	"COMMAND_DONE_ERROR_RECOVERED",
	"QUE_COMMAND",
	"QUE_BUSY_COMMAND",
	"QUE_SENSE",
	"JUST_RETURN",
	"COMMAND_DONE_EACCES",
	"QUE_LAST_COMMAND",
	"COMMAND_TIMEOUT",
	"PATH_FAILED",
	"DEVICE_RESET",
	"DEVICE_TAMPER",
	"ATTEMPT_RETRY"
};

const char *bogusID = "Unknown Media ID";

/* default density offsets in the table above */
#define	DEF_BLANK	0
#define	DEF_NOREWIND	1
#define	DEF_BSD		2
#define	DEF_BSD_NR	3

/* Sense Key, ASC/ASCQ for which tape ejection is needed */

static struct tape_failure_code {
	uchar_t key;
	uchar_t add_code;
	uchar_t qual_code;
} st_tape_failure_code[] = {
	{ KEY_HARDWARE_ERROR, 0x15, 0x01},
	{ KEY_HARDWARE_ERROR, 0x44, 0x00},
	{ KEY_HARDWARE_ERROR, 0x53, 0x00},
	{ KEY_HARDWARE_ERROR, 0x53, 0x01},
	{ KEY_NOT_READY, 0x53, 0x00},
	{ 0xff}
};

/*  clean bit position and mask */

static struct cln_bit_position {
	ushort_t cln_bit_byte;
	uchar_t cln_bit_mask;
} st_cln_bit_position[] = {
	{ 21, 0x08},
	{ 70, 0xc0},
	{ 18, 0x81}  /* 80 bit indicates in bit mode, 1 bit clean light is on */
};

/*
 * architecture dependent allocation restrictions. For x86, we'll set
 * dma_attr_addr_hi to st_max_phys_addr and dma_attr_sgllen to
 * st_sgl_size during _init().
 */
#if defined(__sparc)
static ddi_dma_attr_t st_alloc_attr = {
	DMA_ATTR_V0,	/* version number */
	0x0,		/* lowest usable address */
	0xFFFFFFFFull,	/* high DMA address range */
	0xFFFFFFFFull,	/* DMA counter register */
	1,		/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xFFFFFFFFull,	/* max DMA xfer size */
	0xFFFFFFFFull,	/* segment boundary */
	1,		/* s/g list length */
	512,		/* granularity of device */
	0		/* DMA transfer flags */
};
#elif defined(__x86)
static ddi_dma_attr_t st_alloc_attr = {
	DMA_ATTR_V0,	/* version number */
	0x0,		/* lowest usable address */
	0x0,		/* high DMA address range [set in _init()] */
	0xFFFFull,	/* DMA counter register */
	512,		/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xFFFFFFFFull,	/* max DMA xfer size */
	0xFFFFFFFFull,  /* segment boundary */
	0,		/* s/g list length */
	512,		/* granularity of device [set in _init()] */
	0		/* DMA transfer flags */
};
uint64_t st_max_phys_addr = 0xFFFFFFFFull;
int st_sgl_size = 0xF;

#endif

/*
 * Configuration Data:
 *
 * Device driver ops vector
 */
static int st_aread(dev_t dev, struct aio_req *aio, cred_t *cred_p);
static int st_awrite(dev_t dev, struct aio_req *aio, cred_t *cred_p);
static int st_read(dev_t  dev,  struct   uio   *uio_p,   cred_t *cred_p);
static int st_write(dev_t  dev,  struct  uio   *uio_p,   cred_t *cred_p);
static int st_open(dev_t  *devp,  int  flag,  int  otyp,  cred_t *cred_p);
static int st_close(dev_t  dev,  int  flag,  int  otyp,  cred_t *cred_p);
static int st_strategy(struct buf *bp);
static int st_queued_strategy(buf_t *bp);
static int st_ioctl(dev_t dev, int cmd, intptr_t arg, int  flag,
	cred_t *cred_p, int *rval_p);
extern int nulldev(), nodev();

static struct cb_ops st_cb_ops = {
	st_open,		/* open */
	st_close,		/* close */
	st_queued_strategy,	/* strategy Not Block device but async checks */
	nodev,			/* print */
	nodev,			/* dump */
	st_read,		/* read */
	st_write,		/* write */
	st_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_64BIT | D_MP | D_NEW | D_HOTPLUG |
	D_OPEN_RETURNS_EINTR,	/* cb_flag */
	CB_REV,			/* cb_rev */
	st_aread, 		/* async I/O read entry point */
	st_awrite		/* async I/O write entry point */

};

static int st_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int st_probe(dev_info_t *dev);
static int st_attach(dev_info_t *dev, ddi_attach_cmd_t cmd);
static int st_detach(dev_info_t *dev, ddi_detach_cmd_t cmd);

static struct dev_ops st_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	st_info,		/* info */
	nulldev,		/* identify */
	st_probe,		/* probe */
	st_attach,		/* attach */
	st_detach,		/* detach */
	nodev,			/* reset */
	&st_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

/*
 * Local Function Declarations
 */
static char *st_print_scsi_cmd(char cmd);
static void st_print_cdb(dev_info_t *dip, char *label, uint_t level,
    char *title, char *cdb);
static void st_clean_print(dev_info_t *dev, char *label, uint_t level,
    char *title, char *data, int len);
static int st_doattach(struct scsi_device *devp, int (*canwait)());
static void st_known_tape_type(struct scsi_tape *un);
static int st_get_conf_from_st_dot_conf(struct scsi_tape *, char *,
    struct st_drivetype *);
static int st_get_conf_from_st_conf_dot_c(struct scsi_tape *, char *,
    struct st_drivetype *);
static int st_get_conf_from_tape_drive(struct scsi_tape *, char *,
    struct st_drivetype *);
static int st_get_densities_from_tape_drive(struct scsi_tape *,
    struct st_drivetype *);
static int st_get_timeout_values_from_tape_drive(struct scsi_tape *,
    struct st_drivetype *);
static int st_get_timeouts_value(struct scsi_tape *, uchar_t, ushort_t *,
    ushort_t);
static int st_get_default_conf(struct scsi_tape *, char *,
    struct st_drivetype *);
static int st_rw(dev_t dev, struct uio *uio, int flag);
static int st_arw(dev_t dev, struct aio_req *aio, int flag);
static int st_find_eod(struct scsi_tape *un);
static int st_check_density_or_wfm(dev_t dev, int wfm, int mode, int stepflag);
static int st_uscsi_cmd(struct scsi_tape *un, struct uscsi_cmd *, int flag);
static int st_mtioctop(struct scsi_tape *un, intptr_t arg, int flag);
static int st_mtiocltop(struct scsi_tape *un, intptr_t arg, int flag);
static int st_do_mtioctop(struct scsi_tape *un, struct mtlop *mtop);
static void st_start(struct scsi_tape *un);
static int st_handle_start_busy(struct scsi_tape *un, struct buf *bp,
    clock_t timeout_interval, int queued);
static int st_handle_intr_busy(struct scsi_tape *un, struct buf *bp,
    clock_t timeout_interval);
static int st_handle_intr_retry_lcmd(struct scsi_tape *un, struct buf *bp);
static void st_done_and_mutex_exit(struct scsi_tape *un, struct buf *bp);
static void st_init(struct scsi_tape *un);
static void st_make_cmd(struct scsi_tape *un, struct buf *bp,
    int (*func)(caddr_t));
static void st_make_uscsi_cmd(struct scsi_tape *, struct uscsi_cmd *,
    struct buf *bp, int (*func)(caddr_t));
static void st_intr(struct scsi_pkt *pkt);
static void st_set_state(struct scsi_tape *un, buf_t *bp);
static void st_test_append(struct buf *bp);
static int st_runout(caddr_t);
static int st_cmd(struct scsi_tape *un, int com, int64_t count, int wait);
static int st_setup_cmd(struct scsi_tape *un, buf_t *bp, int com,
    int64_t count);
static int st_set_compression(struct scsi_tape *un);
static int st_write_fm(dev_t dev, int wfm);
static int st_determine_generic(struct scsi_tape *un);
static int st_determine_density(struct scsi_tape *un, int rw);
static int st_get_density(struct scsi_tape *un);
static int st_set_density(struct scsi_tape *un);
static int st_loadtape(struct scsi_tape *un);
static int st_modesense(struct scsi_tape *un);
static int st_modeselect(struct scsi_tape *un);
static errstate st_handle_incomplete(struct scsi_tape *un, struct buf *bp);
static int st_wrongtapetype(struct scsi_tape *un);
static errstate st_check_error(struct scsi_tape *un, struct scsi_pkt *pkt);
static errstate st_handle_sense(struct scsi_tape *un, struct buf *bp,
    tapepos_t *);
static errstate st_handle_autosense(struct scsi_tape *un, struct buf *bp,
    tapepos_t *);
static int st_get_error_entry(struct scsi_tape *un, intptr_t arg, int flag);
static void st_update_error_stack(struct scsi_tape *un, struct scsi_pkt *pkt,
    struct scsi_arq_status *cmd);
static void st_empty_error_stack(struct scsi_tape *un);
static errstate st_decode_sense(struct scsi_tape *un, struct buf *bp, int amt,
    struct scsi_arq_status *, tapepos_t *);
static int st_report_soft_errors(dev_t dev, int flag);
static void st_delayed_cv_broadcast(void *arg);
static int st_check_media(dev_t dev, enum mtio_state state);
static int st_media_watch_cb(caddr_t arg, struct scsi_watch_result *resultp);
static void st_intr_restart(void *arg);
static void st_start_restart(void *arg);
static int st_gen_mode_sense(struct scsi_tape *un, ubufunc_t ubf, int page,
    struct seq_mode *page_data, int page_size);
static int st_change_block_size(struct scsi_tape *un, uint32_t nblksz);
static int st_gen_mode_select(struct scsi_tape *un, ubufunc_t ubf,
    struct seq_mode *page_data, int page_size);
static int st_read_block_limits(struct scsi_tape *un,
    struct read_blklim *read_blk);
static int st_report_density_support(struct scsi_tape *un,
    uchar_t *density_data, size_t buflen);
static int st_report_supported_operation(struct scsi_tape *un,
    uchar_t *oper_data, uchar_t option_code, ushort_t service_action);
static int st_tape_init(struct scsi_tape *un);
static void st_flush(struct scsi_tape *un);
static void st_set_pe_errno(struct scsi_tape *un);
static void st_hba_unflush(struct scsi_tape *un);
static void st_turn_pe_on(struct scsi_tape *un);
static void st_turn_pe_off(struct scsi_tape *un);
static void st_set_pe_flag(struct scsi_tape *un);
static void st_clear_pe(struct scsi_tape *un);
static void st_wait_for_io(struct scsi_tape *un);
static int st_set_devconfig_page(struct scsi_tape *un, int compression_on);
static int st_set_datacomp_page(struct scsi_tape *un, int compression_on);
static int st_reserve_release(struct scsi_tape *un, int command, ubufunc_t ubf);
static int st_check_cdb_for_need_to_reserve(struct scsi_tape *un, uchar_t *cdb);
static int st_check_cmd_for_need_to_reserve(struct scsi_tape *un, uchar_t cmd,
    int count);
static int st_take_ownership(struct scsi_tape *un, ubufunc_t ubf);
static int st_check_asc_ascq(struct scsi_tape *un);
static int st_check_clean_bit(struct scsi_tape *un);
static int st_check_alert_flags(struct scsi_tape *un);
static int st_check_sequential_clean_bit(struct scsi_tape *un);
static int st_check_sense_clean_bit(struct scsi_tape *un);
static int st_clear_unit_attentions(dev_t dev_instance, int max_trys);
static void st_calculate_timeouts(struct scsi_tape *un);
static writablity st_is_drive_worm(struct scsi_tape *un);
static int st_read_attributes(struct scsi_tape *un, uint16_t attribute,
    void *buf, size_t size, ubufunc_t bufunc);
static int st_get_special_inquiry(struct scsi_tape *un, uchar_t size,
    caddr_t dest, uchar_t page);
static int st_update_block_pos(struct scsi_tape *un, bufunc_t bf,
    int post_space);
static int st_interpret_read_pos(struct scsi_tape const *un, tapepos_t *dest,
    read_p_types type, size_t data_sz, const caddr_t responce, int post_space);
static int st_get_read_pos(struct scsi_tape *un, buf_t *bp);
static int st_logical_block_locate(struct scsi_tape *un, ubufunc_t ubf,
    tapepos_t *pos, uint64_t lblk, uchar_t partition);
static int st_mtfsf_ioctl(struct scsi_tape *un, int64_t files);
static int st_mtfsr_ioctl(struct scsi_tape *un, int64_t count);
static int st_mtbsf_ioctl(struct scsi_tape *un, int64_t files);
static int st_mtnbsf_ioctl(struct scsi_tape *un, int64_t count);
static int st_mtbsr_ioctl(struct scsi_tape *un, int64_t num);
static int st_mtfsfm_ioctl(struct scsi_tape *un, int64_t cnt);
static int st_mtbsfm_ioctl(struct scsi_tape *un, int64_t cnt);
static int st_backward_space_files(struct scsi_tape *un, int64_t count,
    int infront);
static int st_forward_space_files(struct scsi_tape *un, int64_t files);
static int st_scenic_route_to_begining_of_file(struct scsi_tape *un,
    int32_t fileno);
static int st_space_to_begining_of_file(struct scsi_tape *un);
static int st_space_records(struct scsi_tape *un, int64_t records);
static int st_get_media_identification(struct scsi_tape *un, ubufunc_t bufunc);
static errstate st_command_recovery(struct scsi_tape *un, struct scsi_pkt *pkt,
    errstate onentry);
static void st_recover(void *arg);
static void st_recov_cb(struct scsi_pkt *pkt);
static int st_rcmd(struct scsi_tape *un, int com, int64_t count, int wait);
static int st_uscsi_rcmd(struct scsi_tape *un, struct uscsi_cmd *ucmd,
    int flag);
static void st_add_recovery_info_to_pkt(struct scsi_tape *un, buf_t *bp,
    struct scsi_pkt *cmd);
static int st_check_mode_for_change(struct scsi_tape *un, ubufunc_t ubf);
static int st_test_path_to_device(struct scsi_tape *un);
static int st_recovery_read_pos(struct scsi_tape *un, read_p_types type,
    read_pos_data_t *raw);
static int st_recovery_get_position(struct scsi_tape *un, tapepos_t *read,
    read_pos_data_t *raw);
static int st_compare_expected_position(struct scsi_tape *un, st_err_info *ei,
    cmd_attribute const * cmd_att, tapepos_t *read);
static errstate st_recover_reissue_pkt(struct scsi_tape *us,
    struct scsi_pkt *pkt);
static int st_transport(struct scsi_tape *un, struct scsi_pkt *pkt);
static buf_t *st_remove_from_queue(buf_t **head, buf_t **tail, buf_t *bp);
static void st_add_to_queue(buf_t **head, buf_t **tail, buf_t *end, buf_t *bp);
static int st_reset(struct scsi_tape *un, int reset_type);
static void st_reset_notification(caddr_t arg);
static const cmd_attribute *st_lookup_cmd_attribute(unsigned char cmd);

static int st_set_target_TLR_mode(struct scsi_tape *un, ubufunc_t ubf);
static int st_make_sure_mode_data_is_correct(struct scsi_tape *un,
    ubufunc_t ubf);

#ifdef	__x86
/*
 * routines for I/O in big block size
 */
static void st_release_contig_mem(struct scsi_tape *un, struct contig_mem *cp);
static struct contig_mem *st_get_contig_mem(struct scsi_tape *un, size_t len,
    int alloc_flags);
static int st_bigblk_xfer_done(struct buf *bp);
static struct buf *st_get_bigblk_bp(struct buf *bp);
#endif
static void st_print_position(dev_info_t *dev, char *label, uint_t level,
    const char *comment, tapepos_t *pos);

/*
 * error statistics create/update functions
 */
static int st_create_errstats(struct scsi_tape *, int);
static int st_validate_tapemarks(struct scsi_tape *un, ubufunc_t ubf,
    tapepos_t *pos);

#ifdef STDEBUG
static void st_debug_cmds(struct scsi_tape *un, int com, int count, int wait);
#endif /* STDEBUG */
static char *st_dev_name(dev_t dev);

#if !defined(lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt",
    scsi_pkt buf uio scsi_cdb uscsi_cmd))
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", scsi_extended_sense scsi_status))
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", recov_info))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_device))
_NOTE(DATA_READABLE_WITHOUT_LOCK(st_drivetype scsi_address))
#endif

/*
 * autoconfiguration routines.
 */

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"SCSI tape Driver", 	/* Name of the module. */
	&st_ops			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * Notes on Post Reset Behavior in the tape driver:
 *
 * When the tape drive is opened, the driver  attempts  to make sure that
 * the tape head is positioned exactly where it was left when it was last
 * closed  provided  the  medium  is not  changed.  If the tape  drive is
 * opened in O_NDELAY mode, the repositioning  (if necessary for any loss
 * of position due to reset) will happen when the first tape operation or
 * I/O occurs.  The repositioning (if required) may not be possible under
 * certain situations such as when the device firmware not able to report
 * the medium  change in the REQUEST  SENSE data  because of a reset or a
 * misbehaving  bus  not  allowing  the  reposition  to  happen.  In such
 * extraordinary  situations, where the driver fails to position the head
 * at its  original  position,  it will fail the open the first  time, to
 * save the applications from overwriting the data.  All further attempts
 * to open the tape device will result in the driver  attempting  to load
 * the  tape at BOT  (beginning  of  tape).  Also a  warning  message  to
 * indicate  that further  attempts to open the tape device may result in
 * the tape being  loaded at BOT will be printed on the  console.  If the
 * tape  device is opened  in  O_NDELAY  mode,  failure  to  restore  the
 * original tape head  position,  will result in the failure of the first
 * tape  operation  or I/O,  Further,  the  driver  will  invalidate  its
 * internal tape position  which will  necessitate  the  applications  to
 * validate the position by using either a tape  positioning  ioctl (such
 * as MTREW) or closing and reopening the tape device.
 *
 */

int
_init(void)
{
	int e;

	if (((e = ddi_soft_state_init(&st_state,
	    sizeof (struct scsi_tape), ST_MAXUNIT)) != 0)) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&st_state);
	} else {
#ifdef STDEBUG
		mutex_init(&st_debug_mutex, NULL, MUTEX_DRIVER, NULL);
#endif

#if defined(__x86)
		/* set the max physical address for iob allocs on x86 */
		st_alloc_attr.dma_attr_addr_hi = st_max_phys_addr;

		/*
		 * set the sgllen for iob allocs on x86. If this is set less
		 * than the number of pages the buffer will take
		 * (taking into account alignment), it would force the
		 * allocator to try and allocate contiguous pages.
		 */
		st_alloc_attr.dma_attr_sgllen = st_sgl_size;
#endif
	}

	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0) {
		return (e);
	}

#ifdef STDEBUG
	mutex_destroy(&st_debug_mutex);
#endif

	ddi_soft_state_fini(&st_state);

	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int
st_probe(dev_info_t *devi)
{
	int instance;
	struct scsi_device *devp;
	int rval;

#if !defined(__sparc)
	char    *tape_prop;
	int	tape_prop_len;
#endif

	ST_ENTR(devi, st_probe);

	/* If self identifying device */
	if (ddi_dev_is_sid(devi) == DDI_SUCCESS) {
		return (DDI_PROBE_DONTCARE);
	}

#if !defined(__sparc)
	/*
	 * Since some x86 HBAs have devnodes that look like SCSI as
	 * far as we can tell but aren't really SCSI (DADK, like mlx)
	 * we check for the presence of the "tape" property.
	 */
	if (ddi_prop_op(DDI_DEV_T_NONE, devi, PROP_LEN_AND_VAL_ALLOC,
	    DDI_PROP_CANSLEEP, "tape",
	    (caddr_t)&tape_prop, &tape_prop_len) != DDI_PROP_SUCCESS) {
		return (DDI_PROBE_FAILURE);
	}
	if (strncmp(tape_prop, "sctp", tape_prop_len) != 0) {
		kmem_free(tape_prop, tape_prop_len);
		return (DDI_PROBE_FAILURE);
	}
	kmem_free(tape_prop, tape_prop_len);
#endif

	devp = ddi_get_driver_private(devi);
	instance = ddi_get_instance(devi);

	if (ddi_get_soft_state(st_state, instance) != NULL) {
		return (DDI_PROBE_PARTIAL);
	}


	/*
	 * Turn around and call probe routine to see whether
	 * we actually have a tape at this SCSI nexus.
	 */
	if (scsi_probe(devp, NULL_FUNC) == SCSIPROBE_EXISTS) {

		/*
		 * In checking the whole inq_dtype byte we are looking at both
		 * the Peripheral Qualifier and the Peripheral Device Type.
		 * For this driver we are only interested in sequential devices
		 * that are connected or capable if connecting to this logical
		 * unit.
		 */
		if (devp->sd_inq->inq_dtype ==
		    (DTYPE_SEQUENTIAL | DPQ_POSSIBLE)) {
			ST_DEBUG6(devi, st_label, SCSI_DEBUG,
			    "probe exists\n");
			rval = DDI_PROBE_SUCCESS;
		} else {
			rval = DDI_PROBE_FAILURE;
		}
	} else {
		ST_DEBUG6(devi, st_label, SCSI_DEBUG,
		    "probe failure: nothing there\n");
		rval = DDI_PROBE_FAILURE;
	}
	scsi_unprobe(devp);
	return (rval);
}

static int
st_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int 	instance;
	int	wide;
	int 	dev_instance;
	int	ret_status;
	struct	scsi_device *devp;
	int	node_ix;
	struct	scsi_tape *un;

	ST_ENTR(devi, st_attach);

	devp = ddi_get_driver_private(devi);
	instance = ddi_get_instance(devi);

	switch (cmd) {
		case DDI_ATTACH:
			if (ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
			    "tape-command-recovery-disable", 0) != 0) {
				st_recov_sz = sizeof (pkt_info);
			}
			if (st_doattach(devp, SLEEP_FUNC) == DDI_FAILURE) {
				return (DDI_FAILURE);
			}
			break;
		case DDI_RESUME:
			/*
			 * Suspend/Resume
			 *
			 * When the driver suspended, there might be
			 * outstanding cmds and therefore we need to
			 * reset the suspended flag and resume the scsi
			 * watch thread and restart commands and timeouts
			 */

			if (!(un = ddi_get_soft_state(st_state, instance))) {
				return (DDI_FAILURE);
			}
			dev_instance = ((un->un_dev == 0) ? MTMINOR(instance) :
			    un->un_dev);

			mutex_enter(ST_MUTEX);

			un->un_throttle = un->un_max_throttle;
			un->un_tids_at_suspend = 0;
			un->un_pwr_mgmt = ST_PWR_NORMAL;

			if (un->un_swr_token) {
				scsi_watch_resume(un->un_swr_token);
			}

			/*
			 * Restart timeouts
			 */
			if ((un->un_tids_at_suspend & ST_DELAY_TID) != 0) {
				mutex_exit(ST_MUTEX);
				un->un_delay_tid = timeout(
				    st_delayed_cv_broadcast, un,
				    drv_usectohz((clock_t)
				    MEDIA_ACCESS_DELAY));
				mutex_enter(ST_MUTEX);
			}

			if (un->un_tids_at_suspend & ST_HIB_TID) {
				mutex_exit(ST_MUTEX);
				un->un_hib_tid = timeout(st_intr_restart, un,
				    ST_STATUS_BUSY_TIMEOUT);
				mutex_enter(ST_MUTEX);
			}

			ret_status = st_clear_unit_attentions(dev_instance, 5);

			/*
			 * now check if we need to restore the tape position
			 */
			if ((un->un_suspend_pos.pmode != invalid) &&
			    ((un->un_suspend_pos.fileno > 0) ||
			    (un->un_suspend_pos.blkno > 0)) ||
			    (un->un_suspend_pos.lgclblkno > 0)) {
				if (ret_status != 0) {
					/*
					 * tape didn't get good TUR
					 * just print out error messages
					 */
					scsi_log(ST_DEVINFO, st_label, CE_WARN,
					    "st_attach-RESUME: tape failure "
					    " tape position will be lost");
				} else {
					/* this prints errors */
					(void) st_validate_tapemarks(un,
					    st_uscsi_cmd, &un->un_suspend_pos);
				}
				/*
				 * there are no retries, if there is an error
				 * we don't know if the tape has changed
				 */
				un->un_suspend_pos.pmode = invalid;
			}

			/* now we are ready to start up any queued I/Os */
			if (un->un_ncmds || un->un_quef) {
				st_start(un);
			}

			cv_broadcast(&un->un_suspend_cv);
			mutex_exit(ST_MUTEX);
			return (DDI_SUCCESS);

		default:
			return (DDI_FAILURE);
	}

	un = ddi_get_soft_state(st_state, instance);

	ST_DEBUG(devi, st_label, SCSI_DEBUG,
	    "st_attach: instance=%x\n", instance);

	/*
	 * Add a zero-length attribute to tell the world we support
	 * kernel ioctls (for layered drivers)
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);

	ddi_report_dev((dev_info_t *)devi);

	/*
	 * If it's a SCSI-2 tape drive which supports wide,
	 * tell the host adapter to use wide.
	 */
	wide = ((devp->sd_inq->inq_rdf == RDF_SCSI2) &&
	    (devp->sd_inq->inq_wbus16 || devp->sd_inq->inq_wbus32)) ?  1 : 0;

	if (scsi_ifsetcap(ROUTE, "wide-xfer", wide, 1) == 1) {
		ST_DEBUG(devi, st_label, SCSI_DEBUG,
		    "Wide Transfer %s\n", wide ? "enabled" : "disabled");
	}

	/*
	 * enable autorequest sense; keep the rq packet around in case
	 * the autorequest sense fails because of a busy condition
	 * do a getcap first in case the capability is not variable
	 */
	if (scsi_ifgetcap(ROUTE, "auto-rqsense", 1) == 1) {
		un->un_arq_enabled = 1;
	} else {
		un->un_arq_enabled =
		    ((scsi_ifsetcap(ROUTE, "auto-rqsense", 1, 1) == 1) ? 1 : 0);
	}

	ST_DEBUG(devi, st_label, SCSI_DEBUG, "auto request sense %s\n",
	    (un->un_arq_enabled ? "enabled" : "disabled"));

	un->un_untagged_qing =
	    (scsi_ifgetcap(ROUTE, "untagged-qing", 0) == 1);

	/*
	 * XXX - This is just for 2.6.  to tell users that write buffering
	 *	has gone away.
	 */
	if (un->un_arq_enabled && un->un_untagged_qing) {
		if (ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
		    "tape-driver-buffering", 0) != 0) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "Write Data Buffering has been depricated. Your "
			    "applications should continue to work normally.\n"
			    " But, they should  ported to use Asynchronous "
			    " I/O\n"
			    " For more information, read about "
			    " tape-driver-buffering "
			    "property in the st(7d) man page\n");
		}
	}

	un->un_max_throttle = un->un_throttle = un->un_last_throttle = 1;
	un->un_flush_on_errors = 0;
	un->un_mkr_pkt = (struct scsi_pkt *)NULL;

	ST_DEBUG(devi, st_label, SCSI_DEBUG,
	    "throttle=%x, max_throttle = %x\n",
	    un->un_throttle, un->un_max_throttle);

	/* initialize persistent errors to nil */
	un->un_persistence = 0;
	un->un_persist_errors = 0;

	/*
	 * Get dma-max from HBA driver. If it is not defined, use 64k
	 */
	un->un_maxdma	= scsi_ifgetcap(&devp->sd_address, "dma-max", 1);
	if (un->un_maxdma == -1) {
		ST_DEBUG(devi, st_label, SCSI_DEBUG,
		    "Received a value that looked like -1. Using 64k maxdma");
		un->un_maxdma = (64 * ONE_K);
	}

#ifdef	__x86
	/*
	 * for x86, the device may be able to DMA more than the system will
	 * allow under some circumstances. We need account for both the HBA's
	 * and system's contraints.
	 *
	 * Get the maximum DMA under worse case conditions. e.g. looking at the
	 * device constraints, the max copy buffer size, and the worse case
	 * fragmentation. NOTE: this may differ from dma-max since dma-max
	 * doesn't take the worse case framentation into account.
	 *
	 * e.g. a device may be able to DMA 16MBytes, but can only DMA 1MByte
	 * if none of the pages are contiguous. Keeping track of both of these
	 * values allows us to support larger tape block sizes on some devices.
	 */
	un->un_maxdma_arch = scsi_ifgetcap(&devp->sd_address, "dma-max-arch",
	    1);

	/*
	 * If the dma-max-arch capability is not implemented, or the value
	 * comes back higher than what was reported in dma-max, use dma-max.
	 */
	if ((un->un_maxdma_arch == -1) ||
	    ((uint_t)un->un_maxdma < (uint_t)un->un_maxdma_arch)) {
		un->un_maxdma_arch = un->un_maxdma;
	}
#endif

	/*
	 * Get the max allowable cdb size
	 */
	un->un_max_cdb_sz =
	    scsi_ifgetcap(&devp->sd_address, "max-cdb-length", 1);
	if (un->un_max_cdb_sz < CDB_GROUP0) {
		ST_DEBUG(devi, st_label, SCSI_DEBUG,
		    "HBA reported max-cdb-length as %d\n", un->un_max_cdb_sz);
		un->un_max_cdb_sz = CDB_GROUP4; /* optimistic default */
	}

	if (strcmp(ddi_driver_name(ddi_get_parent(ST_DEVINFO)), "scsi_vhci")) {
		un->un_multipath = 0;
	} else {
		un->un_multipath = 1;
	}

	un->un_maxbsize = MAXBSIZE_UNKNOWN;

	un->un_mediastate = MTIO_NONE;
	un->un_HeadClean  = TAPE_ALERT_SUPPORT_UNKNOWN;

	/*
	 * initialize kstats
	 */
	un->un_stats = kstat_create("st", instance, NULL, "tape",
	    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT);
	if (un->un_stats) {
		un->un_stats->ks_lock = ST_MUTEX;
		kstat_install(un->un_stats);
	}
	(void) st_create_errstats(un, instance);

	/*
	 * find the drive type for this target
	 */
	mutex_enter(ST_MUTEX);
	un->un_dev = MTMINOR(instance);
	st_known_tape_type(un);
	un->un_dev = 0;
	mutex_exit(ST_MUTEX);

	for (node_ix = 0; node_ix < ST_NUM_MEMBERS(st_minor_data); node_ix++) {
		int minor;
		char *name;

		name  = st_minor_data[node_ix].name;
		minor = st_minor_data[node_ix].minor;

		/*
		 * For default devices set the density to the
		 * preferred default density for this device.
		 */
		if (node_ix <= DEF_BSD_NR) {
			minor |= un->un_dp->default_density;
		}
		minor |= MTMINOR(instance);

		if (ddi_create_minor_node(devi, name, S_IFCHR, minor,
		    DDI_NT_TAPE, NULL) == DDI_SUCCESS) {
			continue;
		}

		ddi_remove_minor_node(devi, NULL);

		(void) scsi_reset_notify(ROUTE, SCSI_RESET_CANCEL,
		    st_reset_notification, (caddr_t)un);
		cv_destroy(&un->un_clscv);
		cv_destroy(&un->un_sbuf_cv);
		cv_destroy(&un->un_queue_cv);
		cv_destroy(&un->un_state_cv);
#ifdef	__x86
		cv_destroy(&un->un_contig_mem_cv);
#endif
		cv_destroy(&un->un_suspend_cv);
		cv_destroy(&un->un_tape_busy_cv);
		cv_destroy(&un->un_recov_buf_cv);
		if (un->un_recov_taskq) {
			ddi_taskq_destroy(un->un_recov_taskq);
		}
		if (un->un_sbufp) {
			freerbuf(un->un_sbufp);
		}
		if (un->un_recov_buf) {
			freerbuf(un->un_recov_buf);
		}
		if (un->un_uscsi_rqs_buf) {
			kmem_free(un->un_uscsi_rqs_buf, SENSE_LENGTH);
		}
		if (un->un_mspl) {
			i_ddi_mem_free((caddr_t)un->un_mspl, NULL);
		}
		if (un->un_dp_size) {
			kmem_free(un->un_dp, un->un_dp_size);
		}
		if (un->un_state) {
			kstat_delete(un->un_stats);
		}
		if (un->un_errstats) {
			kstat_delete(un->un_errstats);
		}

		scsi_destroy_pkt(un->un_rqs);
		scsi_free_consistent_buf(un->un_rqs_bp);
		ddi_soft_state_free(st_state, instance);
		devp->sd_private = NULL;
		devp->sd_sense = NULL;

		ddi_prop_remove_all(devi);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * st_detach:
 *
 * we allow a detach if and only if:
 *	- no tape is currently inserted
 *	- tape position is at BOT or unknown
 *		(if it is not at BOT then a no rewind
 *		device was opened and we have to preserve state)
 *	- it must be in a closed state : no timeouts or scsi_watch requests
 *		will exist if it is closed, so we don't need to check for
 *		them here.
 */
/*ARGSUSED*/
static int
st_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	int result;
	struct scsi_device *devp;
	struct scsi_tape *un;
	clock_t wait_cmds_complete;

	ST_ENTR(devi, st_detach);

	instance = ddi_get_instance(devi);

	if (!(un = ddi_get_soft_state(st_state, instance))) {
		return (DDI_FAILURE);
	}

	mutex_enter(ST_MUTEX);

	/*
	 * Clear error entry stack
	 */
	st_empty_error_stack(un);

	mutex_exit(ST_MUTEX);

	switch (cmd) {

	case DDI_DETACH:
		/*
		 * Undo what we did in st_attach & st_doattach,
		 * freeing resources and removing things we installed.
		 * The system framework guarantees we are not active
		 * with this devinfo node in any other entry points at
		 * this time.
		 */

		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_detach: instance=%x, un=%p\n", instance,
		    (void *)un);

		if (((un->un_dp->options & ST_UNLOADABLE) == 0) ||
		    ((un->un_rsvd_status & ST_APPLICATION_RESERVATIONS) != 0) ||
		    (un->un_ncmds != 0) || (un->un_quef != NULL) ||
		    (un->un_state != ST_STATE_CLOSED)) {
			/*
			 * we cannot unload some targets because the
			 * inquiry returns junk unless immediately
			 * after a reset
			 */
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "cannot unload instance %x\n", instance);
			un->un_unit_attention_flags |= 4;
			return (DDI_FAILURE);
		}

		/*
		 * if the tape has been removed then we may unload;
		 * do a test unit ready and if it returns NOT READY
		 * then we assume that it is safe to unload.
		 * as a side effect, pmode may be set to invalid if the
		 * the test unit ready fails;
		 * also un_state may be set to non-closed, so reset it
		 */
		if ((un->un_dev) &&		/* Been opened since attach */
		    ((un->un_pos.pmode == legacy) &&
		    (un->un_pos.fileno > 0) ||	/* Known position not rewound */
		    (un->un_pos.blkno != 0)) ||	/* Or within first file */
		    ((un->un_pos.pmode == logical) &&
		    (un->un_pos.lgclblkno > 0))) {
			mutex_enter(ST_MUTEX);
			/*
			 * Send Test Unit Ready in the hopes that if
			 * the drive is not in the state we think it is.
			 * And the state will be changed so it can be detached.
			 * If the command fails to reach the device and
			 * the drive was not rewound or unloaded we want
			 * to fail the detach till a user command fails
			 * where after the detach will succead.
			 */
			result = st_cmd(un, SCMD_TEST_UNIT_READY, 0, SYNC_CMD);
			/*
			 * After TUR un_state may be set to non-closed,
			 * so reset it back.
			 */
			un->un_state = ST_STATE_CLOSED;
			mutex_exit(ST_MUTEX);
		}
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "un_status=%x, fileno=%x, blkno=%x\n",
		    un->un_status, un->un_pos.fileno, un->un_pos.blkno);

		/*
		 * check again:
		 * if we are not at BOT then it is not safe to unload
		 */
		if ((un->un_dev) &&		/* Been opened since attach */
		    (result != EACCES) &&	/* drive is use by somebody */
		    ((((un->un_pos.pmode == legacy) &&
		    (un->un_pos.fileno > 0) ||	/* Known position not rewound */
		    (un->un_pos.blkno != 0)) ||	/* Or within first file */
		    ((un->un_pos.pmode == logical) &&
		    (un->un_pos.lgclblkno > 0))) &&
		    ((un->un_state == ST_STATE_CLOSED) &&
		    (un->un_laststate == ST_STATE_CLOSING)))) {

			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "cannot detach: pmode=%d fileno=0x%x, blkno=0x%x"
			    " lgclblkno=0x%"PRIx64"\n", un->un_pos.pmode,
			    un->un_pos.fileno, un->un_pos.blkno,
			    un->un_pos.lgclblkno);
			un->un_unit_attention_flags |= 4;
			return (DDI_FAILURE);
		}

		/*
		 * Just To make sure that we have released the
		 * tape unit .
		 */
		if (un->un_dev && (un->un_rsvd_status & ST_RESERVE) &&
		    !DEVI_IS_DEVICE_REMOVED(devi)) {
			mutex_enter(ST_MUTEX);
			(void) st_reserve_release(un, ST_RELEASE, st_uscsi_cmd);
			mutex_exit(ST_MUTEX);
		}

		/*
		 * now remove other data structures allocated in st_doattach()
		 */
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "destroying/freeing\n");

		(void) scsi_reset_notify(ROUTE, SCSI_RESET_CANCEL,
		    st_reset_notification, (caddr_t)un);
		cv_destroy(&un->un_clscv);
		cv_destroy(&un->un_sbuf_cv);
		cv_destroy(&un->un_queue_cv);
		cv_destroy(&un->un_suspend_cv);
		cv_destroy(&un->un_tape_busy_cv);
		cv_destroy(&un->un_recov_buf_cv);

		if (un->un_recov_taskq) {
			ddi_taskq_destroy(un->un_recov_taskq);
		}

		if (un->un_hib_tid) {
			(void) untimeout(un->un_hib_tid);
			un->un_hib_tid = 0;
		}

		if (un->un_delay_tid) {
			(void) untimeout(un->un_delay_tid);
			un->un_delay_tid = 0;
		}
		cv_destroy(&un->un_state_cv);

#ifdef	__x86
		cv_destroy(&un->un_contig_mem_cv);

		if (un->un_contig_mem_hdl != NULL) {
			ddi_dma_free_handle(&un->un_contig_mem_hdl);
		}
#endif
		if (un->un_sbufp) {
			freerbuf(un->un_sbufp);
		}
		if (un->un_recov_buf) {
			freerbuf(un->un_recov_buf);
		}
		if (un->un_uscsi_rqs_buf) {
			kmem_free(un->un_uscsi_rqs_buf, SENSE_LENGTH);
		}
		if (un->un_mspl) {
			i_ddi_mem_free((caddr_t)un->un_mspl, NULL);
		}
		if (un->un_rqs) {
			scsi_destroy_pkt(un->un_rqs);
			scsi_free_consistent_buf(un->un_rqs_bp);
		}
		if (un->un_mkr_pkt) {
			scsi_destroy_pkt(un->un_mkr_pkt);
		}
		if (un->un_arq_enabled) {
			(void) scsi_ifsetcap(ROUTE, "auto-rqsense", 0, 1);
		}
		if (un->un_dp_size) {
			kmem_free(un->un_dp, un->un_dp_size);
		}
		if (un->un_stats) {
			kstat_delete(un->un_stats);
			un->un_stats = (kstat_t *)0;
		}
		if (un->un_errstats) {
			kstat_delete(un->un_errstats);
			un->un_errstats = (kstat_t *)0;
		}
		if (un->un_media_id_len) {
			kmem_free(un->un_media_id, un->un_media_id_len);
		}
		devp = ST_SCSI_DEVP;
		ddi_soft_state_free(st_state, instance);
		devp->sd_private = NULL;
		devp->sd_sense = NULL;
		scsi_unprobe(devp);
		ddi_prop_remove_all(devi);
		ddi_remove_minor_node(devi, NULL);
		ST_DEBUG(0, st_label, SCSI_DEBUG, "st_detach done\n");
		return (DDI_SUCCESS);

	case DDI_SUSPEND:

		/*
		 * Suspend/Resume
		 *
		 * To process DDI_SUSPEND, we must do the following:
		 *
		 *  - check ddi_removing_power to see if power will be turned
		 *    off. if so, return DDI_FAILURE
		 *  - check if we are already suspended,
		 *    if so, return DDI_FAILURE
		 *  - check if device state is CLOSED,
		 *    if not, return DDI_FAILURE.
		 *  - wait until outstanding operations complete
		 *  - save tape state
		 *  - block new operations
		 *  - cancel pending timeouts
		 *
		 */

		if (ddi_removing_power(devi)) {
			return (DDI_FAILURE);
		}

		if (un->un_dev == 0)
			un->un_dev = MTMINOR(instance);

		mutex_enter(ST_MUTEX);

		/*
		 * Shouldn't already be suspended, if so return failure
		 */
		if (un->un_pwr_mgmt == ST_PWR_SUSPENDED) {
			mutex_exit(ST_MUTEX);
			return (DDI_FAILURE);
		}
		if (un->un_state != ST_STATE_CLOSED) {
			mutex_exit(ST_MUTEX);
			return (DDI_FAILURE);
		}

		/*
		 * Wait for all outstanding I/O's to complete
		 *
		 * we wait on both ncmds and the wait queue for times
		 * when we are flushing after persistent errors are
		 * flagged, which is when ncmds can be 0, and the
		 * queue can still have I/O's.  This way we preserve
		 * order of biodone's.
		 */
		wait_cmds_complete = ddi_get_lbolt();
		wait_cmds_complete +=
		    st_wait_cmds_complete * drv_usectohz(1000000);
		while (un->un_ncmds || un->un_quef ||
		    (un->un_state == ST_STATE_RESOURCE_WAIT)) {

			if (cv_timedwait(&un->un_tape_busy_cv, ST_MUTEX,
			    wait_cmds_complete) == -1) {
				/*
				 * Time expired then cancel the command
				 */
				if (st_reset(un, RESET_LUN) == 0) {
					if (un->un_last_throttle) {
						un->un_throttle =
						    un->un_last_throttle;
					}
					mutex_exit(ST_MUTEX);
					return (DDI_FAILURE);
				} else {
					break;
				}
			}
		}

		/*
		 * DDI_SUSPEND says that the system "may" power down, we
		 * remember the file and block number before rewinding.
		 * we also need to save state before issuing
		 * any WRITE_FILE_MARK command.
		 */
		(void) st_update_block_pos(un, st_cmd, 0);
		COPY_POS(&un->un_suspend_pos, &un->un_pos);


		/*
		 * Issue a zero write file fmk command to tell the drive to
		 * flush any buffered tape marks
		 */
		(void) st_cmd(un, SCMD_WRITE_FILE_MARK, 0, SYNC_CMD);

		/*
		 * Because not all tape drives correctly implement buffer
		 * flushing with the zero write file fmk command, issue a
		 * synchronous rewind command to force data flushing.
		 * st_validate_tapemarks() will do a rewind during DDI_RESUME
		 * anyway.
		 */
		(void) st_cmd(un, SCMD_REWIND, 0, SYNC_CMD);

		/* stop any new operations */
		un->un_pwr_mgmt = ST_PWR_SUSPENDED;
		un->un_throttle = 0;

		/*
		 * cancel any outstanding timeouts
		 */
		if (un->un_delay_tid) {
			timeout_id_t temp_id = un->un_delay_tid;
			un->un_delay_tid = 0;
			un->un_tids_at_suspend |= ST_DELAY_TID;
			mutex_exit(ST_MUTEX);
			(void) untimeout(temp_id);
			mutex_enter(ST_MUTEX);
		}

		if (un->un_hib_tid) {
			timeout_id_t temp_id = un->un_hib_tid;
			un->un_hib_tid = 0;
			un->un_tids_at_suspend |= ST_HIB_TID;
			mutex_exit(ST_MUTEX);
			(void) untimeout(temp_id);
			mutex_enter(ST_MUTEX);
		}

		/*
		 * Suspend the scsi_watch_thread
		 */
		if (un->un_swr_token) {
			opaque_t temp_token = un->un_swr_token;
			mutex_exit(ST_MUTEX);
			scsi_watch_suspend(temp_token);
		} else {
			mutex_exit(ST_MUTEX);
		}

		return (DDI_SUCCESS);

	default:
		ST_DEBUG(0, st_label, SCSI_DEBUG, "st_detach failed\n");
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
static int
st_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev;
	struct scsi_tape *un;
	int instance, error;

	ST_ENTR(dip, st_info);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = MTUNIT(dev);
		if ((un = ddi_get_soft_state(st_state, instance)) == NULL)
			return (DDI_FAILURE);
		*result = (void *) ST_DEVINFO;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = MTUNIT(dev);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static int
st_doattach(struct scsi_device *devp, int (*canwait)())
{
	struct scsi_tape *un = NULL;
	recov_info *ri;
	int km_flags = (canwait != NULL_FUNC) ? KM_SLEEP : KM_NOSLEEP;
	int instance;
	size_t rlen;

	ST_FUNC(devp->sd_dev, st_doattach);
	/*
	 * Call the routine scsi_probe to do some of the dirty work.
	 * If the INQUIRY command succeeds, the field sd_inq in the
	 * device structure will be filled in.
	 */
	ST_DEBUG(devp->sd_dev, st_label, SCSI_DEBUG,
	    "st_doattach(): probing\n");

	if (scsi_probe(devp, canwait) == SCSIPROBE_EXISTS) {

		/*
		 * In checking the whole inq_dtype byte we are looking at both
		 * the Peripheral Qualifier and the Peripheral Device Type.
		 * For this driver we are only interested in sequential devices
		 * that are connected or capable if connecting to this logical
		 * unit.
		 */
		if (devp->sd_inq->inq_dtype ==
		    (DTYPE_SEQUENTIAL | DPQ_POSSIBLE)) {
			ST_DEBUG(devp->sd_dev, st_label, SCSI_DEBUG,
			    "probe exists\n");
		} else {
			/* Something there but not a tape device */
			scsi_unprobe(devp);
			return (DDI_FAILURE);
		}
	} else {
		/* Nothing there */
		ST_DEBUG(devp->sd_dev, st_label, SCSI_DEBUG,
		    "probe failure: nothing there\n");
		scsi_unprobe(devp);
		return (DDI_FAILURE);
	}


	/*
	 * The actual unit is present.
	 * Now is the time to fill in the rest of our info..
	 */
	instance = ddi_get_instance(devp->sd_dev);

	if (ddi_soft_state_zalloc(st_state, instance) != DDI_SUCCESS) {
		goto error;
	}
	un = ddi_get_soft_state(st_state, instance);

	ASSERT(un != NULL);

	un->un_rqs_bp = scsi_alloc_consistent_buf(&devp->sd_address, NULL,
	    MAX_SENSE_LENGTH, B_READ, canwait, NULL);
	if (un->un_rqs_bp == NULL) {
		goto error;
	}
	un->un_rqs = scsi_init_pkt(&devp->sd_address, NULL, un->un_rqs_bp,
	    CDB_GROUP0, 1, st_recov_sz, PKT_CONSISTENT, canwait, NULL);
	if (!un->un_rqs) {
		goto error;
	}
	ASSERT(un->un_rqs->pkt_resid == 0);
	devp->sd_sense =
	    (struct scsi_extended_sense *)un->un_rqs_bp->b_un.b_addr;
	ASSERT(geterror(un->un_rqs_bp) == NULL);

	(void) scsi_setup_cdb((union scsi_cdb *)un->un_rqs->pkt_cdbp,
	    SCMD_REQUEST_SENSE, 0, MAX_SENSE_LENGTH, 0);
	FILL_SCSI1_LUN(devp, un->un_rqs);
	un->un_rqs->pkt_flags |= (FLAG_SENSING | FLAG_HEAD | FLAG_NODISCON);
	un->un_rqs->pkt_time = st_io_time;
	un->un_rqs->pkt_comp = st_intr;
	ri = (recov_info *)un->un_rqs->pkt_private;
	if (st_recov_sz == sizeof (recov_info)) {
		ri->privatelen = sizeof (recov_info);
	} else {
		ri->privatelen = sizeof (pkt_info);
	}

	un->un_sbufp = getrbuf(km_flags);
	un->un_recov_buf = getrbuf(km_flags);

	un->un_uscsi_rqs_buf = kmem_alloc(SENSE_LENGTH, KM_SLEEP);

	/*
	 * use i_ddi_mem_alloc() for now until we have an interface to allocate
	 * memory for DMA which doesn't require a DMA handle.
	 */
	(void) i_ddi_mem_alloc(devp->sd_dev, &st_alloc_attr,
	    sizeof (struct seq_mode), ((km_flags == KM_SLEEP) ? 1 : 0), 0,
	    NULL, (caddr_t *)&un->un_mspl, &rlen, NULL);

	(void) i_ddi_mem_alloc(devp->sd_dev, &st_alloc_attr,
	    sizeof (read_pos_data_t), ((km_flags == KM_SLEEP) ? 1 : 0), 0,
	    NULL, (caddr_t *)&un->un_read_pos_data, &rlen, NULL);

	if (!un->un_sbufp || !un->un_mspl || !un->un_read_pos_data) {
		ST_DEBUG6(devp->sd_dev, st_label, SCSI_DEBUG,
		    "probe partial failure: no space\n");
		goto error;
	}

	bzero(un->un_mspl, sizeof (struct seq_mode));

	cv_init(&un->un_sbuf_cv, NULL, CV_DRIVER, NULL);
	cv_init(&un->un_queue_cv, NULL, CV_DRIVER, NULL);
	cv_init(&un->un_clscv, NULL, CV_DRIVER, NULL);
	cv_init(&un->un_state_cv, NULL, CV_DRIVER, NULL);
#ifdef	__x86
	cv_init(&un->un_contig_mem_cv, NULL, CV_DRIVER, NULL);
#endif

	/* Initialize power managemnet condition variable */
	cv_init(&un->un_suspend_cv, NULL, CV_DRIVER, NULL);
	cv_init(&un->un_tape_busy_cv, NULL, CV_DRIVER, NULL);
	cv_init(&un->un_recov_buf_cv, NULL, CV_DRIVER, NULL);

	un->un_recov_taskq = ddi_taskq_create(devp->sd_dev,
	    "un_recov_taskq", 1, TASKQ_DEFAULTPRI, km_flags);

	ASSERT(un->un_recov_taskq != NULL);

	un->un_pos.pmode = invalid;
	un->un_sd	= devp;
	un->un_swr_token = (opaque_t)NULL;
	un->un_comp_page = ST_DEV_DATACOMP_PAGE | ST_DEV_CONFIG_PAGE;
	un->un_wormable = st_is_drive_worm;
	un->un_media_id_method = st_get_media_identification;
	/*
	 * setting long a initial as it contains logical file info.
	 * support for long format is mandatory but many drive don't do it.
	 */
	un->un_read_pos_type = LONG_POS;

	un->un_suspend_pos.pmode = invalid;

	st_add_recovery_info_to_pkt(un, un->un_rqs_bp, un->un_rqs);

#ifdef	__x86
	if (ddi_dma_alloc_handle(ST_DEVINFO, &st_contig_mem_dma_attr,
	    DDI_DMA_SLEEP, NULL, &un->un_contig_mem_hdl) != DDI_SUCCESS) {
		ST_DEBUG6(devp->sd_dev, st_label, SCSI_DEBUG,
		    "allocation of contiguous memory dma handle failed!");
		un->un_contig_mem_hdl = NULL;
		goto error;
	}
#endif

	/*
	 * Since this driver manages devices with "remote" hardware,
	 * i.e. the devices themselves have no "reg" properties,
	 * the SUSPEND/RESUME commands in detach/attach will not be
	 * called by the power management framework unless we request
	 * it by creating a "pm-hardware-state" property and setting it
	 * to value "needs-suspend-resume".
	 */
	if (ddi_prop_update_string(DDI_DEV_T_NONE, devp->sd_dev,
	    "pm-hardware-state", "needs-suspend-resume") !=
	    DDI_PROP_SUCCESS) {

		ST_DEBUG(devp->sd_dev, st_label, SCSI_DEBUG,
		    "ddi_prop_update(\"pm-hardware-state\") failed\n");
		goto error;
	}

	if (ddi_prop_create(DDI_DEV_T_NONE, devp->sd_dev, DDI_PROP_CANSLEEP,
	    "no-involuntary-power-cycles", NULL, 0) != DDI_PROP_SUCCESS) {

		ST_DEBUG(devp->sd_dev, st_label, SCSI_DEBUG,
		    "ddi_prop_create(\"no-involuntary-power-cycles\") "
		    "failed\n");
		goto error;
	}

	(void) scsi_reset_notify(ROUTE, SCSI_RESET_NOTIFY,
	    st_reset_notification, (caddr_t)un);

	ST_DEBUG6(devp->sd_dev, st_label, SCSI_DEBUG, "attach success\n");
	return (DDI_SUCCESS);

error:
	devp->sd_sense = NULL;

	ddi_remove_minor_node(devp->sd_dev, NULL);
	if (un) {
		if (un->un_mspl) {
			i_ddi_mem_free((caddr_t)un->un_mspl, NULL);
		}
		if (un->un_read_pos_data) {
			i_ddi_mem_free((caddr_t)un->un_read_pos_data, 0);
		}
		if (un->un_sbufp) {
			freerbuf(un->un_sbufp);
		}
		if (un->un_recov_buf) {
			freerbuf(un->un_recov_buf);
		}
		if (un->un_uscsi_rqs_buf) {
			kmem_free(un->un_uscsi_rqs_buf, SENSE_LENGTH);
		}
#ifdef	__x86
		if (un->un_contig_mem_hdl != NULL) {
			ddi_dma_free_handle(&un->un_contig_mem_hdl);
		}
#endif
		if (un->un_rqs) {
			scsi_destroy_pkt(un->un_rqs);
		}

		if (un->un_rqs_bp) {
			scsi_free_consistent_buf(un->un_rqs_bp);
		}

		ddi_soft_state_free(st_state, instance);
		devp->sd_private = NULL;
	}

	if (devp->sd_inq) {
		scsi_unprobe(devp);
	}
	return (DDI_FAILURE);
}

typedef int
(*cfg_functp)(struct scsi_tape *, char *vidpid, struct st_drivetype *);

static cfg_functp config_functs[] = {
	st_get_conf_from_st_dot_conf,
	st_get_conf_from_st_conf_dot_c,
	st_get_conf_from_tape_drive,
	st_get_default_conf
};


/*
 * determine tape type, using tape-config-list or built-in table or
 * use a generic tape config entry
 */
static void
st_known_tape_type(struct scsi_tape *un)
{
	struct st_drivetype *dp;
	cfg_functp *config_funct;
	uchar_t reserved;

	ST_FUNC(ST_DEVINFO, st_known_tape_type);

	reserved = (un->un_rsvd_status & ST_RESERVE) ? ST_RESERVE
	    : ST_RELEASE;

	/*
	 * XXX:  Emulex MT-02 (and emulators) predates SCSI-1 and has
	 *	 no vid & pid inquiry data.  So, we provide one.
	 */
	if (ST_INQUIRY->inq_len == 0 ||
	    (bcmp("\0\0\0\0\0\0\0\0", ST_INQUIRY->inq_vid, 8) == 0)) {
		(void) strcpy((char *)ST_INQUIRY->inq_vid, ST_MT02_NAME);
	}

	if (un->un_dp_size == 0) {
		un->un_dp_size = sizeof (struct st_drivetype);
		dp = kmem_zalloc((size_t)un->un_dp_size, KM_SLEEP);
		un->un_dp = dp;
	} else {
		dp = un->un_dp;
	}

	un->un_dp->non_motion_timeout = st_io_time;
	/*
	 * Loop through the configuration methods till one works.
	 */
	for (config_funct = &config_functs[0]; ; config_funct++) {
		if ((*config_funct)(un, ST_INQUIRY->inq_vid, dp)) {
			break;
		}
	}

	/*
	 * If we didn't just make up this configuration and
	 * all the density codes are the same..
	 * Set Auto Density over ride.
	 */
	if (*config_funct != st_get_default_conf) {
		/*
		 * If this device is one that is configured and all
		 * densities are the same, This saves doing gets and set
		 * that yield nothing.
		 */
		if ((dp->densities[0]) == (dp->densities[1]) &&
		    (dp->densities[0]) == (dp->densities[2]) &&
		    (dp->densities[0]) == (dp->densities[3])) {

			dp->options |= ST_AUTODEN_OVERRIDE;
		}
	}


	/*
	 * Store tape drive characteristics.
	 */
	un->un_status = 0;
	un->un_attached = 1;
	un->un_init_options = dp->options;

	/* setup operation time-outs based on options */
	st_calculate_timeouts(un);

	/* TLR support */
	if (un->un_dp->type != ST_TYPE_INVALID) {
		int result;

		/* try and enable TLR */
		un->un_tlr_flag = TLR_SAS_ONE_DEVICE;
		result = st_set_target_TLR_mode(un, st_uscsi_cmd);
		if (result == EACCES) {
			/*
			 * From attach command failed.
			 * Set dp type so is run again on open.
			 */
			un->un_dp->type = ST_TYPE_INVALID;
			un->un_tlr_flag = TLR_NOT_KNOWN;
		} else if (result == 0) {
			if (scsi_ifgetcap(&un->un_sd->sd_address,
			    "tran-layer-retries", 1) == -1) {
				un->un_tlr_flag = TLR_NOT_SUPPORTED;
				(void) st_set_target_TLR_mode(un, st_uscsi_cmd);
			} else {
				un->un_tlr_flag = TLR_SAS_ONE_DEVICE;
			}
		} else {
			un->un_tlr_flag = TLR_NOT_SUPPORTED;
		}
	}

	/* make sure if we are supposed to be variable, make it variable */
	if (dp->options & ST_VARIABLE) {
		dp->bsize = 0;
	}

	if (reserved != ((un->un_rsvd_status & ST_RESERVE) ? ST_RESERVE
	    : ST_RELEASE)) {
		(void) st_reserve_release(un, reserved, st_uscsi_cmd);
	}

	un->un_unit_attention_flags |= 1;

	scsi_log(ST_DEVINFO, st_label, CE_NOTE, "?<%s>\n", dp->name);

}


typedef struct {
	int mask;
	int bottom;
	int top;
	char *name;
} conf_limit;

static const conf_limit conf_limits[] = {

	-1,		1,		2,		"conf version",
	-1,		MT_ISTS,	ST_LAST_TYPE,	"drive type",
	-1,		0,		0xffffff,	"block size",
	ST_VALID_OPTS,	0,		ST_VALID_OPTS,	"options",
	-1,		0,		4,		"number of densities",
	-1,		0,		UINT8_MAX,	"density code",
	-1,		0,		3,		"default density",
	-1,		0,		UINT16_MAX,	"non motion timeout",
	-1,		0,		UINT16_MAX,	"I/O timeout",
	-1,		0,		UINT16_MAX,	"space timeout",
	-1,		0,		UINT16_MAX,	"load timeout",
	-1,		0,		UINT16_MAX,	"unload timeout",
	-1,		0,		UINT16_MAX,	"erase timeout",
	0,		0,		0,		NULL
};

static int
st_validate_conf_data(struct scsi_tape *un, int *list, int list_len,
    const char *conf_name)
{
	int dens;
	int ndens;
	int value;
	int type;
	int count;
	const conf_limit *limit = &conf_limits[0];

	ST_FUNC(ST_DEVINFO, st_validate_conf_data);

	ST_DEBUG3(ST_DEVINFO, st_label, CE_NOTE,
	    "Checking %d entrys total with %d densities\n", list_len, list[4]);

	count = list_len;
	type = *list;
	for (;  count && limit->name; count--, list++, limit++) {

		value = *list;
		if (value & ~limit->mask) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "%s %s value invalid bits set: 0x%X\n",
			    conf_name, limit->name, value & ~limit->mask);
			*list &= limit->mask;
		} else if (value < limit->bottom) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "%s %s value too low: value = %d limit %d\n",
			    conf_name, limit->name, value, limit->bottom);
		} else if (value > limit->top) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "%s %s value too high: value = %d limit %d\n",
			    conf_name, limit->name, value, limit->top);
		} else {
			ST_DEBUG3(ST_DEVINFO, st_label, CE_CONT,
			    "%s %s value = 0x%X\n",
			    conf_name, limit->name, value);
		}

		/* If not the number of densities continue */
		if (limit != &conf_limits[4]) {
			continue;
		}

		/* If number of densities is not in range can't use config */
		if (value < limit->bottom || value > limit->top) {
			return (-1);
		}

		ndens = min(value, NDENSITIES);
		if ((type == 1) && (list_len - ndens) != 6) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "%s conf version 1 with %d densities has %d items"
			    " should have %d",
			    conf_name, ndens, list_len, 6 + ndens);
		} else if ((type == 2) && (list_len - ndens) != 13) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "%s conf version 2 with %d densities has %d items"
			    " should have %d",
			    conf_name, ndens, list_len, 13 + ndens);
		}

		limit++;
		for (dens = 0; dens < ndens && count; dens++) {
			count--;
			list++;
			value = *list;
			if (value < limit->bottom) {
				scsi_log(ST_DEVINFO, st_label, CE_NOTE,
				    "%s density[%d] value too low: value ="
				    " 0x%X limit 0x%X\n",
				    conf_name, dens, value, limit->bottom);
			} else if (value > limit->top) {
				scsi_log(ST_DEVINFO, st_label, CE_NOTE,
				    "%s density[%d] value too high: value ="
				    " 0x%X limit 0x%X\n",
				    conf_name, dens, value, limit->top);
			} else {
				ST_DEBUG3(ST_DEVINFO, st_label, CE_CONT,
				    "%s density[%d] value = 0x%X\n",
				    conf_name, dens, value);
			}
		}
	}

	return (0);
}

static int
st_get_conf_from_st_dot_conf(struct scsi_tape *un, char *vidpid,
    struct st_drivetype *dp)
{
	caddr_t config_list = NULL;
	caddr_t data_list = NULL;
	int	*data_ptr;
	caddr_t vidptr, prettyptr, datanameptr;
	size_t	vidlen, prettylen, datanamelen, tripletlen = 0;
	int config_list_len, data_list_len, len, i;
	int version;
	int found = 0;

	ST_FUNC(ST_DEVINFO, st_get_conf_from_st_dot_conf);

	/*
	 * Determine type of tape controller. Type is determined by
	 * checking the vendor ids of the earlier inquiry command and
	 * comparing those with vids in tape-config-list defined in st.conf
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ST_DEVINFO, DDI_PROP_DONTPASS,
	    "tape-config-list", (caddr_t)&config_list, &config_list_len)
	    != DDI_PROP_SUCCESS) {
		return (found);
	}

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_get_conf_from_st_dot_conf(): st.conf has tape-config-list\n");

	/*
	 * Compare vids in each triplet - if it matches, get value for
	 * data_name and contruct a st_drivetype struct
	 * tripletlen is not set yet!
	 */
	for (len = config_list_len, vidptr = config_list;
	    len > 0;
	    vidptr += tripletlen, len -= tripletlen) {

		vidlen = strlen(vidptr);
		prettyptr = vidptr + vidlen + 1;
		prettylen = strlen(prettyptr);
		datanameptr = prettyptr + prettylen + 1;
		datanamelen = strlen(datanameptr);
		tripletlen = vidlen + prettylen + datanamelen + 3;

		if (vidlen == 0) {
			continue;
		}

		/*
		 * If inquiry vid dosen't match this triplets vid,
		 * try the next.
		 */
		if (strncasecmp(vidpid, vidptr, vidlen)) {
			continue;
		}

		/*
		 * if prettylen is zero then use the vid string
		 */
		if (prettylen == 0) {
			prettyptr = vidptr;
			prettylen = vidlen;
		}

		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "vid = %s, pretty=%s, dataname = %s\n",
		    vidptr, prettyptr, datanameptr);

		/*
		 * get the data list
		 */
		if (ddi_getlongprop(DDI_DEV_T_ANY, ST_DEVINFO, 0,
		    datanameptr, (caddr_t)&data_list,
		    &data_list_len) != DDI_PROP_SUCCESS) {
			/*
			 * Error in getting property value
			 * print warning!
			 */
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "data property (%s) has no value\n",
			    datanameptr);
			continue;
		}

		/*
		 * now initialize the st_drivetype struct
		 */
		(void) strncpy(dp->name, prettyptr, ST_NAMESIZE - 1);
		dp->length = (int)min(vidlen, (VIDPIDLEN - 1));
		(void) strncpy(dp->vid, vidptr, dp->length);
		data_ptr = (int *)data_list;
		/*
		 * check if data is enough for version, type,
		 * bsize, options, # of densities, density1,
		 * density2, ..., default_density
		 */
		if ((data_list_len < 5 * sizeof (int)) ||
		    (data_list_len < 6 * sizeof (int) +
		    *(data_ptr + 4) * sizeof (int))) {
			/*
			 * print warning and skip to next triplet.
			 */
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "data property (%s) incomplete\n",
			    datanameptr);
			kmem_free(data_list, data_list_len);
			continue;
		}

		if (st_validate_conf_data(un, data_ptr,
		    data_list_len / sizeof (int), datanameptr)) {
			kmem_free(data_list, data_list_len);
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "data property (%s) rejected\n",
			    datanameptr);
			continue;
		}

		/*
		 * check version
		 */
		version = *data_ptr++;
		if (version != 1 && version != 2) {
			/* print warning but accept it */
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "Version # for data property (%s) "
			    "not set to 1 or 2\n", datanameptr);
		}

		dp->type    = *data_ptr++;
		dp->bsize   = *data_ptr++;
		dp->options = *data_ptr++;
		dp->options |= ST_DYNAMIC;
		len = *data_ptr++;
		for (i = 0; i < NDENSITIES; i++) {
			if (i < len) {
				dp->densities[i] = *data_ptr++;
			}
		}
		dp->default_density = *data_ptr << 3;
		if (version == 2 &&
		    data_list_len >= (13 + len) * sizeof (int)) {
			data_ptr++;
			dp->non_motion_timeout	= *data_ptr++;
			dp->io_timeout		= *data_ptr++;
			dp->rewind_timeout	= *data_ptr++;
			dp->space_timeout	= *data_ptr++;
			dp->load_timeout	= *data_ptr++;
			dp->unload_timeout	= *data_ptr++;
			dp->erase_timeout	= *data_ptr++;
		}
		kmem_free(data_list, data_list_len);
		found = 1;
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "found in st.conf: vid = %s, pretty=%s\n",
		    dp->vid, dp->name);
		break;
	}

	/*
	 * free up the memory allocated by ddi_getlongprop
	 */
	if (config_list) {
		kmem_free(config_list, config_list_len);
	}
	return (found);
}

static int
st_get_conf_from_st_conf_dot_c(struct scsi_tape *un, char *vidpid,
    struct st_drivetype *dp)
{
	int i;

	ST_FUNC(ST_DEVINFO, st_get_conf_from_st_conf_dot_c);
	/*
	 * Determine type of tape controller.  Type is determined by
	 * checking the result of the earlier inquiry command and
	 * comparing vendor ids with strings in a table declared in st_conf.c.
	 */
	ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_get_conf_from_st_conf_dot_c(): looking at st_drivetypes\n");

	for (i = 0; i < st_ndrivetypes; i++) {
		if (st_drivetypes[i].length == 0) {
			continue;
		}
		if (strncasecmp(vidpid, st_drivetypes[i].vid,
		    st_drivetypes[i].length)) {
			continue;
		}
		bcopy(&st_drivetypes[i], dp, sizeof (st_drivetypes[i]));
		return (1);
	}
	return (0);
}

static int
st_get_conf_from_tape_drive(struct scsi_tape *un, char *vidpid,
    struct st_drivetype *dp)
{
	int bsize;
	ulong_t maxbsize;
	caddr_t buf;
	struct st_drivetype *tem_dp;
	struct read_blklim *blklim;
	int rval;
	int i;

	ST_FUNC(ST_DEVINFO, st_get_conf_from_tape_drive);

	/*
	 * Determine the type of tape controller. Type is determined by
	 * sending SCSI commands to tape drive and deriving the type from
	 * the returned data.
	 */
	ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_get_conf_from_tape_drive(): asking tape drive\n");

	tem_dp = kmem_zalloc(sizeof (struct st_drivetype), KM_SLEEP);

	/*
	 * Make up a name
	 */
	bcopy(vidpid, tem_dp->name, VIDPIDLEN);
	tem_dp->name[VIDPIDLEN] = '\0';
	tem_dp->length = min(strlen(ST_INQUIRY->inq_vid), (VIDPIDLEN - 1));
	(void) strncpy(tem_dp->vid, ST_INQUIRY->inq_vid, tem_dp->length);
	/*
	 * 'clean' vendor and product strings of non-printing chars
	 */
	for (i = 0; i < VIDPIDLEN - 1; i ++) {
		if (tem_dp->name[i] < ' ' || tem_dp->name[i] > '~') {
			tem_dp->name[i] = '.';
		}
	}

	/*
	 * MODE SENSE to determine block size.
	 */
	un->un_dp->options |= ST_MODE_SEL_COMP | ST_UNLOADABLE;
	rval = st_modesense(un);
	if (rval) {
		if (rval == EACCES) {
			un->un_dp->type = ST_TYPE_INVALID;
			rval = 1;
		} else {
			un->un_dp->options &= ~ST_MODE_SEL_COMP;
			rval = 0;
		}
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_conf_from_tape_drive(): fail to mode sense\n");
		goto exit;
	}

	/* Can mode sense page 0x10 or 0xf */
	tem_dp->options |= ST_MODE_SEL_COMP;
	bsize = (un->un_mspl->high_bl << 16)	|
	    (un->un_mspl->mid_bl << 8)		|
	    (un->un_mspl->low_bl);

	if (bsize == 0) {
		tem_dp->options |= ST_VARIABLE;
		tem_dp->bsize = 0;
	} else if (bsize > ST_MAXRECSIZE_FIXED) {
		rval = st_change_block_size(un, 0);
		if (rval) {
			if (rval == EACCES) {
				un->un_dp->type = ST_TYPE_INVALID;
				rval = 1;
			} else {
				rval = 0;
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_get_conf_from_tape_drive(): "
				    "Fixed record size is too large and"
				    "cannot switch to variable record size");
			}
			goto exit;
		}
		tem_dp->options |= ST_VARIABLE;
	} else {
		rval = st_change_block_size(un, 0);
		if (rval == 0) {
			tem_dp->options |= ST_VARIABLE;
			tem_dp->bsize = 0;
		} else if (rval != EACCES) {
			tem_dp->bsize = bsize;
		} else {
			un->un_dp->type = ST_TYPE_INVALID;
			rval = 1;
			goto exit;
		}
	}

	/*
	 * If READ BLOCk LIMITS works and upper block size limit is
	 * more than 64K, ST_NO_RECSIZE_LIMIT is supported.
	 */
	blklim = kmem_zalloc(sizeof (struct read_blklim), KM_SLEEP);
	rval = st_read_block_limits(un, blklim);
	if (rval) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_conf_from_tape_drive(): "
		    "fail to read block limits.\n");
		rval = 0;
		kmem_free(blklim, sizeof (struct read_blklim));
		goto exit;
	}
	maxbsize = (blklim->max_hi << 16) +
	    (blklim->max_mid << 8) + blklim->max_lo;
	if (maxbsize > ST_MAXRECSIZE_VARIABLE) {
		tem_dp->options |= ST_NO_RECSIZE_LIMIT;
	}
	kmem_free(blklim, sizeof (struct read_blklim));

	/*
	 * Inquiry VPD page 0xb0 to see if the tape drive supports WORM
	 */
	buf = kmem_zalloc(6, KM_SLEEP);
	rval = st_get_special_inquiry(un, 6, buf, 0xb0);
	if (rval) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_conf_from_tape_drive(): "
		    "fail to read vitial inquiry.\n");
		rval = 0;
		kmem_free(buf, 6);
		goto exit;
	}
	if (buf[4] & 1) {
		tem_dp->options |= ST_WORMABLE;
	}
	kmem_free(buf, 6);

	/* Assume BSD BSR KNOWS_EOD */
	tem_dp->options |= ST_BSF | ST_BSR | ST_KNOWS_EOD | ST_UNLOADABLE;
	tem_dp->max_rretries = -1;
	tem_dp->max_wretries = -1;

	/*
	 * Decide the densities supported by tape drive by sending
	 * REPORT DENSITY SUPPORT command.
	 */
	if (st_get_densities_from_tape_drive(un, tem_dp) == 0) {
		goto exit;
	}

	/*
	 * Decide the timeout values for several commands by sending
	 * REPORT SUPPORTED OPERATION CODES command.
	 */
	rval = st_get_timeout_values_from_tape_drive(un, tem_dp);
	if (rval == 0 || ((rval == 1) && (tem_dp->type == ST_TYPE_INVALID))) {
		goto exit;
	}

	bcopy(tem_dp, dp, sizeof (struct st_drivetype));
	rval = 1;

exit:
	un->un_status = KEY_NO_SENSE;
	kmem_free(tem_dp, sizeof (struct st_drivetype));
	return (rval);
}

static int
st_get_densities_from_tape_drive(struct scsi_tape *un,
    struct st_drivetype *dp)
{
	int i, p;
	size_t buflen;
	ushort_t des_len;
	uchar_t *den_header;
	uchar_t num_den;
	uchar_t den[NDENSITIES];
	uchar_t deflt[NDENSITIES];
	struct report_density_desc *den_desc;

	ST_FUNC(ST_DEVINFO, st_get_densities_from_type_drive);

	/*
	 * Since we have no idea how many densitiy support entries
	 * will be returned, we send the command firstly assuming
	 * there is only one. Then we can decide the number of
	 * entries by available density support length. If multiple
	 * entries exist, we will resend the command with enough
	 * buffer size.
	 */
	buflen = sizeof (struct report_density_header) +
	    sizeof (struct report_density_desc);
	den_header = kmem_zalloc(buflen, KM_SLEEP);
	if (st_report_density_support(un, den_header, buflen) != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_conf_from_tape_drive(): fail to report density.\n");
		kmem_free(den_header, buflen);
		return (0);
	}
	des_len =
	    BE_16(((struct report_density_header *)den_header)->ava_dens_len);
	num_den = (des_len - 2) / sizeof (struct report_density_desc);

	if (num_den > 1) {
		kmem_free(den_header, buflen);
		buflen = sizeof (struct report_density_header) +
		    sizeof (struct report_density_desc) * num_den;
		den_header = kmem_zalloc(buflen, KM_SLEEP);
		if (st_report_density_support(un, den_header, buflen) != 0) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_get_conf_from_tape_drive(): "
			    "fail to report density.\n");
			kmem_free(den_header, buflen);
			return (0);
		}
	}

	den_desc = (struct report_density_desc *)(den_header
	    + sizeof (struct report_density_header));

	/*
	 * Decide the drive type by assigning organization
	 */
	for (i = 0; i < ST_NUM_MEMBERS(st_vid_dt); i ++) {
		if (strncmp(st_vid_dt[i].vid, (char *)(den_desc->ass_org),
		    8) == 0) {
			dp->type = st_vid_dt[i].type;
			break;
		}
	}
	if (i == ST_NUM_MEMBERS(st_vid_dt)) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_conf_from_tape_drive(): "
		    "can't find match of assigned ort.\n");
		kmem_free(den_header, buflen);
		return (0);
	}

	/*
	 * The tape drive may support many tape formats, but the st driver
	 * supports only the four highest densities. Since density code
	 * values are returned by ascending sequence, we start from the
	 * last entry of density support data block descriptor.
	 */
	p = 0;
	den_desc += num_den - 1;
	for (i = 0; i < num_den && p < NDENSITIES; i ++, den_desc --) {
		if ((den_desc->pri_den != 0) && (den_desc->wrtok)) {
			if (p != 0) {
				if (den_desc->pri_den >= den[p - 1]) {
					continue;
				}
			}
			den[p] = den_desc->pri_den;
			deflt[p] = den_desc->deflt;
			p ++;
		}
	}

	switch (p) {
	case 0:
		bzero(dp->densities, NDENSITIES);
		dp->options |= ST_AUTODEN_OVERRIDE;
		dp->default_density = MT_DENSITY4;
		break;

	case 1:
		(void) memset(dp->densities, den[0], NDENSITIES);
		dp->options |= ST_AUTODEN_OVERRIDE;
		dp->default_density = MT_DENSITY4;
		break;

	case 2:
		dp->densities[0] = den[1];
		dp->densities[1] = den[1];
		dp->densities[2] = den[0];
		dp->densities[3] = den[0];
		if (deflt[0]) {
			dp->default_density = MT_DENSITY4;
		} else {
			dp->default_density = MT_DENSITY2;
		}
		break;

	case 3:
		dp->densities[0] = den[2];
		dp->densities[1] = den[1];
		dp->densities[2] = den[0];
		dp->densities[3] = den[0];
		if (deflt[0]) {
			dp->default_density = MT_DENSITY4;
		} else if (deflt[1]) {
			dp->default_density = MT_DENSITY2;
		} else {
			dp->default_density = MT_DENSITY1;
		}
		break;

	default:
		for (i = p; i > p - NDENSITIES; i --) {
			dp->densities[i - 1] = den[p - i];
		}
		if (deflt[0]) {
			dp->default_density = MT_DENSITY4;
		} else if (deflt[1]) {
			dp->default_density = MT_DENSITY3;
		} else if (deflt[2]) {
			dp->default_density = MT_DENSITY2;
		} else {
			dp->default_density = MT_DENSITY1;
		}
		break;
	}

	bzero(dp->mediatype, NDENSITIES);

	kmem_free(den_header, buflen);
	return (1);
}

static int
st_get_timeout_values_from_tape_drive(struct scsi_tape *un,
    struct st_drivetype *dp)
{
	ushort_t timeout;
	int rval;

	ST_FUNC(ST_DEVINFO, st_get_timeout_values_from_type_drive);

	rval = st_get_timeouts_value(un, SCMD_ERASE, &timeout, 0);
	if (rval) {
		if (rval == EACCES) {
			un->un_dp->type = ST_TYPE_INVALID;
			dp->type = ST_TYPE_INVALID;
			return (1);
		}
		return (0);
	}
	dp->erase_timeout = timeout;

	rval = st_get_timeouts_value(un, SCMD_READ, &timeout, 0);
	if (rval) {
		if (rval == EACCES) {
			un->un_dp->type = ST_TYPE_INVALID;
			dp->type = ST_TYPE_INVALID;
			return (1);
		}
		return (0);
	}
	dp->io_timeout = timeout;

	rval = st_get_timeouts_value(un, SCMD_WRITE, &timeout, 0);
	if (rval) {
		if (rval == EACCES) {
			un->un_dp->type = ST_TYPE_INVALID;
			dp->type = ST_TYPE_INVALID;
			return (1);
		}
		return (0);
	}
	dp->io_timeout = max(dp->io_timeout, timeout);

	rval = st_get_timeouts_value(un, SCMD_SPACE, &timeout, 0);
	if (rval) {
		if (rval == EACCES) {
			un->un_dp->type = ST_TYPE_INVALID;
			dp->type = ST_TYPE_INVALID;
			return (1);
		}
		return (0);
	}
	dp->space_timeout = timeout;

	rval = st_get_timeouts_value(un, SCMD_LOAD, &timeout, 0);
	if (rval) {
		if (rval == EACCES) {
			un->un_dp->type = ST_TYPE_INVALID;
			dp->type = ST_TYPE_INVALID;
			return (1);
		}
		return (0);
	}
	dp->load_timeout = timeout;
	dp->unload_timeout = timeout;

	rval = st_get_timeouts_value(un, SCMD_REWIND, &timeout, 0);
	if (rval) {
		if (rval == EACCES) {
			un->un_dp->type = ST_TYPE_INVALID;
			dp->type = ST_TYPE_INVALID;
			return (1);
		}
		return (0);
	}
	dp->rewind_timeout = timeout;

	rval = st_get_timeouts_value(un, SCMD_INQUIRY, &timeout, 0);
	if (rval) {
		if (rval == EACCES) {
			un->un_dp->type = ST_TYPE_INVALID;
			dp->type = ST_TYPE_INVALID;
			return (1);
		}
		return (0);
	}
	dp->non_motion_timeout = timeout;

	return (1);
}

static int
st_get_timeouts_value(struct scsi_tape *un, uchar_t option_code,
    ushort_t *timeout_value, ushort_t service_action)
{
	uchar_t *timeouts;
	uchar_t *oper;
	uchar_t support;
	uchar_t cdbsize;
	uchar_t ctdp;
	size_t buflen;
	int rval;

	ST_FUNC(ST_DEVINFO, st_get_timeouts_value);

	buflen = sizeof (struct one_com_des) +
	    sizeof (struct com_timeout_des);
	oper = kmem_zalloc(buflen, KM_SLEEP);
	rval = st_report_supported_operation(un, oper, option_code,
	    service_action);

	if (rval) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_timeouts_value(): "
		    "fail to timeouts value for command %d.\n", option_code);
		kmem_free(oper, buflen);
		return (rval);
	}

	support = ((struct one_com_des *)oper)->support;
	if ((support != SUPPORT_VALUES_SUPPORT_SCSI) &&
	    (support != SUPPORT_VALUES_SUPPORT_VENDOR)) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_timeouts_value(): "
		    "command %d is not supported.\n", option_code);
		kmem_free(oper, buflen);
		return (ENOTSUP);
	}

	ctdp = ((struct one_com_des *)oper)->ctdp;
	if (!ctdp) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_timeouts_value(): "
		    "command timeout is not included.\n");
		kmem_free(oper, buflen);
		return (ENOTSUP);
	}

	cdbsize = BE_16(((struct one_com_des *)oper)->cdb_size);
	timeouts = (uchar_t *)(oper + cdbsize + 4);

	/*
	 * Timeout value in seconds is 4 bytes, but we only support the lower 2
	 * bytes. If the higher 2 bytes are not zero, the timeout value is set
	 * to 0xFFFF.
	 */
	if (*(timeouts + 8) != 0 || *(timeouts + 9) != 0) {
		*timeout_value = USHRT_MAX;
	} else {
		*timeout_value = ((*(timeouts + 10)) << 8) |
		    (*(timeouts + 11));
	}

	kmem_free(oper, buflen);
	return (0);
}

static int
st_get_default_conf(struct scsi_tape *un, char *vidpid, struct st_drivetype *dp)
{
	int i;

	ST_FUNC(ST_DEVINFO, st_get_default_conf);

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_get_default_conf(): making drivetype from INQ cmd\n");

	/*
	 * Make up a name
	 */
	bcopy("Vendor '", dp->name, 8);
	bcopy(vidpid, &dp->name[8], VIDLEN);
	bcopy("' Product '", &dp->name[16], 11);
	bcopy(&vidpid[8], &dp->name[27], PIDLEN);
	dp->name[ST_NAMESIZE - 2] = '\'';
	dp->name[ST_NAMESIZE - 1] = '\0';
	dp->length = min(strlen(ST_INQUIRY->inq_vid), (VIDPIDLEN - 1));
	(void) strncpy(dp->vid, ST_INQUIRY->inq_vid, dp->length);
	/*
	 * 'clean' vendor and product strings of non-printing chars
	 */
	for (i = 0; i < ST_NAMESIZE - 2; i++) {
		if (dp->name[i] < ' ' || dp->name[i] > '~') {
			dp->name[i] = '.';
		}
	}
	dp->type = ST_TYPE_INVALID;
	dp->options |= (ST_DYNAMIC | ST_UNLOADABLE | ST_MODE_SEL_COMP);

	return (1); /* Can Not Fail */
}

/*
 * Regular Unix Entry points
 */



/* ARGSUSED */
static int
st_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	dev_t dev = *dev_p;
	int rval = 0;

	GET_SOFT_STATE(dev);

	ST_ENTR(ST_DEVINFO, st_open);

	/*
	 * validate that we are addressing a sensible unit
	 */
	mutex_enter(ST_MUTEX);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_open(node = %s dev = 0x%lx, flag = %d, otyp = %d)\n",
	    st_dev_name(dev), *dev_p, flag, otyp);

	/*
	 * All device accesss go thru st_strategy() where we check
	 * suspend status
	 */

	if (!un->un_attached) {
		st_known_tape_type(un);
		if (!un->un_attached) {
			rval = ENXIO;
			goto exit;
		}

	}

	/*
	 * Check for the case of the tape in the middle of closing.
	 * This isn't simply a check of the current state, because
	 * we could be in state of sensing with the previous state
	 * that of closing.
	 *
	 * And don't allow multiple opens.
	 */
	if (!(flag & (FNDELAY | FNONBLOCK)) && IS_CLOSING(un)) {
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_CLOSE_PENDING_OPEN;
		while (IS_CLOSING(un) ||
		    un->un_state == ST_STATE_CLOSE_PENDING_OPEN) {
			if (cv_wait_sig(&un->un_clscv, ST_MUTEX) == 0) {
				rval = EINTR;
				un->un_state = un->un_laststate;
				goto exit;
			}
		}
	} else if (un->un_state != ST_STATE_CLOSED) {
		rval = EBUSY;
		goto busy;
	}

	/*
	 * record current dev
	 */
	un->un_dev = dev;
	un->un_oflags = flag;	/* save for use in st_tape_init() */
	un->un_errno = 0;	/* no errors yet */
	un->un_restore_pos = 0;
	un->un_rqs_state = 0;

	/*
	 * If we are opening O_NDELAY, or O_NONBLOCK, we don't check for
	 * anything, leave internal states alone, if fileno >= 0
	 */
	if (flag & (FNDELAY | FNONBLOCK)) {
		switch (un->un_pos.pmode) {

		case invalid:
			un->un_state = ST_STATE_OFFLINE;
			break;

		case legacy:
			/*
			 * If position is anything other than rewound.
			 */
			if (un->un_pos.fileno != 0 || un->un_pos.blkno != 0) {
				/*
				 * set un_read_only/write-protect status.
				 *
				 * If the tape is not bot we can assume
				 * that mspl->wp_status is set properly.
				 * else
				 * we need to do a mode sense/Tur once
				 * again to get the actual tape status.(since
				 * user might have replaced the tape)
				 * Hence make the st state OFFLINE so that
				 * we re-intialize the tape once again.
				 */
				un->un_read_only =
				    (un->un_oflags & FWRITE) ? RDWR : RDONLY;
				un->un_state = ST_STATE_OPEN_PENDING_IO;
			} else {
				un->un_state = ST_STATE_OFFLINE;
			}
			break;
		case logical:
			if (un->un_pos.lgclblkno == 0) {
				un->un_state = ST_STATE_OFFLINE;
			} else {
				un->un_read_only =
				    (un->un_oflags & FWRITE) ? RDWR : RDONLY;
				un->un_state = ST_STATE_OPEN_PENDING_IO;
			}
			break;
		}
		rval = 0;
	} else {
		/*
		 * Not opening O_NDELAY.
		 */
		un->un_state = ST_STATE_OPENING;

		/*
		 * Clear error entry stack
		 */
		st_empty_error_stack(un);

		rval = st_tape_init(un);
		if ((rval == EACCES) && (un->un_read_only & WORM)) {
			un->un_state = ST_STATE_OPEN_PENDING_IO;
			rval = 0; /* so open doesn't fail */
		} else if (rval) {
			/*
			 * Release the tape unit, if reserved and not
			 * preserve reserve.
			 */
			if ((un->un_rsvd_status &
			    (ST_RESERVE | ST_PRESERVE_RESERVE)) == ST_RESERVE) {
				(void) st_reserve_release(un, ST_RELEASE,
				    st_uscsi_cmd);
			}
		} else {
			un->un_state = ST_STATE_OPEN_PENDING_IO;
		}
	}

exit:
	/*
	 * we don't want any uninvited guests scrogging our data when we're
	 * busy with something, so for successful opens or failed opens
	 * (except for EBUSY), reset these counters and state appropriately.
	 */
	if (rval != EBUSY) {
		if (rval) {
			un->un_state = ST_STATE_CLOSED;
		}
		un->un_err_resid = 0;
		un->un_retry_ct = 0;
	}
busy:
	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_open: return val = %x, state = %d\n", rval, un->un_state);
	mutex_exit(ST_MUTEX);
	return (rval);

}

static int
st_tape_init(struct scsi_tape *un)
{
	int err;
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_tape_init);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_tape_init(un = 0x%p, oflags = %d)\n", (void*)un, un->un_oflags);

	/*
	 * Clean up after any errors left by 'last' close.
	 * This also handles the case of the initial open.
	 */
	if (un->un_state != ST_STATE_INITIALIZING) {
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_OPENING;
	}

	un->un_kbytes_xferred = 0;

	/*
	 * do a throw away TUR to clear check condition
	 */
	err = st_cmd(un, SCMD_TEST_UNIT_READY, 0, SYNC_CMD);

	/*
	 * If test unit ready fails because the drive is reserved
	 * by another host fail the open for no access.
	 */
	if (err) {
		if (un->un_rsvd_status & ST_RESERVATION_CONFLICT) {
			un->un_state = ST_STATE_CLOSED;
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_tape_init: RESERVATION CONFLICT\n");
			rval = EACCES;
			goto exit;
		} else if ((un->un_rsvd_status &
		    ST_APPLICATION_RESERVATIONS) != 0) {
			if ((ST_RQSENSE != NULL) &&
			    (ST_RQSENSE->es_add_code == 0x2a &&
			    ST_RQSENSE->es_qual_code == 0x03)) {
				un->un_state = ST_STATE_CLOSED;
				rval = EACCES;
				goto exit;
			}
		}
	}

	/*
	 * Tape self identification could fail if the tape drive is used by
	 * another host during attach time. We try to get the tape type
	 * again. This is also applied to any posponed configuration methods.
	 */
	if (un->un_dp->type == ST_TYPE_INVALID) {
		un->un_comp_page = ST_DEV_DATACOMP_PAGE | ST_DEV_CONFIG_PAGE;
		st_known_tape_type(un);
	}

	/*
	 * If the tape type is still invalid, try to determine the generic
	 * configuration.
	 */
	if (un->un_dp->type == ST_TYPE_INVALID) {
		rval = st_determine_generic(un);
		if (rval) {
			if (rval != EACCES) {
				rval = EIO;
			}
			un->un_state = ST_STATE_CLOSED;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_tape_init: %s invalid type\n",
			    rval == EACCES ? "EACCES" : "EIO");
			goto exit;
		}
		/*
		 * If this is a Unknown Type drive,
		 * Use the READ BLOCK LIMITS to determine if
		 * allow large xfer is approprate if not globally
		 * disabled with st_allow_large_xfer.
		 */
		un->un_allow_large_xfer = (uchar_t)st_allow_large_xfer;
	} else {

		/*
		 * If we allow_large_xfer (ie >64k) and have not yet found out
		 * the max block size supported by the drive,
		 * find it by issueing a READ_BLKLIM command.
		 * if READ_BLKLIM cmd fails, assume drive doesn't
		 * allow_large_xfer and min/max block sizes as 1 byte and 63k.
		 */
		un->un_allow_large_xfer = st_allow_large_xfer &&
		    (un->un_dp->options & ST_NO_RECSIZE_LIMIT);
	}
	/*
	 * if maxbsize is unknown, set the maximum block size.
	 */
	if (un->un_maxbsize == MAXBSIZE_UNKNOWN) {

		/*
		 * Get the Block limits of the tape drive.
		 * if un->un_allow_large_xfer = 0 , then make sure
		 * that maxbsize is <= ST_MAXRECSIZE_FIXED.
		 */
		un->un_rbl = kmem_zalloc(RBLSIZE, KM_SLEEP);

		err = st_cmd(un, SCMD_READ_BLKLIM, RBLSIZE, SYNC_CMD);
		if (err) {
			/* Retry */
			err = st_cmd(un, SCMD_READ_BLKLIM, RBLSIZE, SYNC_CMD);
		}
		if (!err) {

			/*
			 * if cmd successful, use limit returned
			 */
			un->un_maxbsize = (un->un_rbl->max_hi << 16) +
			    (un->un_rbl->max_mid << 8) +
			    un->un_rbl->max_lo;
			un->un_minbsize = (un->un_rbl->min_hi << 8) +
			    un->un_rbl->min_lo;
			un->un_data_mod = 1 << un->un_rbl->granularity;
			if ((un->un_maxbsize == 0) ||
			    (un->un_allow_large_xfer == 0 &&
			    un->un_maxbsize > ST_MAXRECSIZE_FIXED)) {
				un->un_maxbsize = ST_MAXRECSIZE_FIXED;

			} else if (un->un_dp->type == ST_TYPE_DEFAULT) {
				/*
				 * Drive is not one that is configured, But the
				 * READ BLOCK LIMITS tells us it can do large
				 * xfers.
				 */
				if (un->un_maxbsize > ST_MAXRECSIZE_FIXED) {
					un->un_dp->options |=
					    ST_NO_RECSIZE_LIMIT;
				}
				/*
				 * If max and mimimum block limits are the
				 * same this is a fixed block size device.
				 */
				if (un->un_maxbsize == un->un_minbsize) {
					un->un_dp->options &= ~ST_VARIABLE;
				}
			}

			if (un->un_minbsize == 0) {
				un->un_minbsize = 1;
			}

		} else { /* error on read block limits */

			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "!st_tape_init: Error on READ BLOCK LIMITS,"
			    " errno = %d un_rsvd_status = 0x%X\n",
			    err, un->un_rsvd_status);

			/*
			 * since read block limits cmd failed,
			 * do not allow large xfers.
			 * use old values in st_minphys
			 */
			if (un->un_rsvd_status & ST_RESERVATION_CONFLICT) {
				rval = EACCES;
			} else {
				un->un_allow_large_xfer = 0;
				scsi_log(ST_DEVINFO, st_label, CE_NOTE,
				    "!Disabling large transfers\n");

				/*
				 * we guess maxbsize and minbsize
				 */
				if (un->un_bsize) {
					un->un_maxbsize = un->un_minbsize =
					    un->un_bsize;
				} else {
					un->un_maxbsize = ST_MAXRECSIZE_FIXED;
					un->un_minbsize = 1;
				}
				/*
				 * Data Mod must be set,
				 * Even if read block limits fails.
				 * Prevents Divide By Zero in st_rw().
				 */
				un->un_data_mod = 1;
			}
		}
		if (un->un_rbl) {
			kmem_free(un->un_rbl, RBLSIZE);
			un->un_rbl = NULL;
		}

		if (rval) {
			goto exit;
		}
	}

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "maxdma = %d, maxbsize = %d, minbsize = %d, %s large xfer\n",
	    un->un_maxdma, un->un_maxbsize, un->un_minbsize,
	    (un->un_allow_large_xfer ? "ALLOW": "DON'T ALLOW"));

	err = st_cmd(un, SCMD_TEST_UNIT_READY, 0, SYNC_CMD);

	if (err != 0) {
		if (err == EINTR) {
			un->un_laststate = un->un_state;
			un->un_state = ST_STATE_CLOSED;
			rval = EINTR;
			goto exit;
		}
		/*
		 * Make sure the tape is ready
		 */
		un->un_pos.pmode = invalid;
		if (un->un_status != KEY_UNIT_ATTENTION) {
			/*
			 * allow open no media.  Subsequent MTIOCSTATE
			 * with media present will complete the open
			 * logic.
			 */
			un->un_laststate = un->un_state;
			if (un->un_oflags & (FNONBLOCK|FNDELAY)) {
				un->un_mediastate = MTIO_EJECTED;
				un->un_state = ST_STATE_OFFLINE;
				rval = 0;
				goto exit;
			} else {
				un->un_state = ST_STATE_CLOSED;
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_tape_init EIO no media, not opened "
				    "O_NONBLOCK|O_EXCL\n");
				rval = EIO;
				goto exit;
			}
		}
	}

	/*
	 * On each open, initialize block size from drivetype struct,
	 * as it could have been changed by MTSRSZ ioctl.
	 * Now, ST_VARIABLE simply means drive is capable of variable
	 * mode. All drives are assumed to support fixed records.
	 * Hence, un_bsize tells what mode the drive is in.
	 *	un_bsize	= 0	- variable record length
	 *			= x	- fixed record length is x
	 */
	un->un_bsize = un->un_dp->bsize;

	/*
	 * If saved position is valid go there
	 */
	if (un->un_restore_pos) {
		un->un_restore_pos = 0;
		un->un_pos.fileno = un->un_save_fileno;
		un->un_pos.blkno = un->un_save_blkno;
		rval = st_validate_tapemarks(un, st_uscsi_cmd, &un->un_pos);
		if (rval != 0) {
			if (rval != EACCES) {
				rval = EIO;
			}
			un->un_laststate = un->un_state;
			un->un_state = ST_STATE_CLOSED;
			goto exit;
		}
	}

	if (un->un_pos.pmode == invalid) {
		rval = st_loadtape(un);
		if (rval) {
			if (rval != EACCES) {
				rval = EIO;
			}
			un->un_laststate = un->un_state;
			un->un_state = ST_STATE_CLOSED;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_tape_init: %s can't open tape\n",
			    rval == EACCES ? "EACCES" : "EIO");
			goto exit;
		}
	}

	/*
	 * do a mode sense to pick up state of current write-protect,
	 * Could cause reserve and fail due to conflict.
	 */
	if (un->un_unit_attention_flags) {
		rval = st_modesense(un);
		if (rval == EACCES) {
			goto exit;
		}
	}

	/*
	 * If we are opening the tape for writing, check
	 * to make sure that the tape can be written.
	 */
	if (un->un_oflags & FWRITE) {
		err = 0;
		if (un->un_mspl->wp) {
			un->un_status = KEY_WRITE_PROTECT;
			un->un_laststate = un->un_state;
			un->un_state = ST_STATE_CLOSED;
			rval = EACCES;
			/*
			 * STK sets the wp bit if volsafe tape is loaded.
			 */
			if ((un->un_dp->type == MT_ISSTK9840) &&
			    (un->un_dp->options & ST_WORMABLE)) {
				un->un_read_only = RDONLY;
			} else {
				goto exit;
			}
		} else {
			un->un_read_only = RDWR;
		}
	} else {
		un->un_read_only = RDONLY;
	}

	if (un->un_dp->options & ST_WORMABLE &&
	    un->un_unit_attention_flags) {
		un->un_read_only |= un->un_wormable(un);

		if (((un->un_read_only == WORM) ||
		    (un->un_read_only == RDWORM)) &&
		    ((un->un_oflags & FWRITE) == FWRITE)) {
			un->un_status = KEY_DATA_PROTECT;
			rval = EACCES;
			ST_DEBUG4(ST_DEVINFO, st_label, CE_NOTE,
			    "read_only = %d eof = %d oflag = %d\n",
			    un->un_read_only, un->un_pos.eof, un->un_oflags);
		}
	}

	/*
	 * If we're opening the tape write-only, we need to
	 * write 2 filemarks on the HP 1/2 inch drive, to
	 * create a null file.
	 */
	if ((un->un_read_only == RDWR) ||
	    (un->un_read_only == WORM) && (un->un_oflags & FWRITE)) {
		if (un->un_dp->options & ST_REEL) {
			un->un_fmneeded = 2;
		} else {
			un->un_fmneeded = 1;
		}
	} else {
		un->un_fmneeded = 0;
	}

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "fmneeded = %x\n", un->un_fmneeded);

	/*
	 * Make sure the density can be selected correctly.
	 * If WORM can only write at the append point which in most cases
	 * isn't BOP. st_determine_density() with a B_WRITE only attempts
	 * to set and try densities if a BOP.
	 */
	if (st_determine_density(un,
	    un->un_read_only == RDWR ? B_WRITE : B_READ)) {
		un->un_status = KEY_ILLEGAL_REQUEST;
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_CLOSED;
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_tape_init: EIO can't determine density\n");
		rval = EIO;
		goto exit;
	}

	/*
	 * Destroy the knowledge that we have 'determined'
	 * density so that a later read at BOT comes along
	 * does the right density determination.
	 */

	un->un_density_known = 0;


	/*
	 * Okay, the tape is loaded and either at BOT or somewhere past.
	 * Mark the state such that any I/O or tape space operations
	 * will get/set the right density, etc..
	 */
	un->un_laststate = un->un_state;
	un->un_lastop = ST_OP_NIL;
	un->un_mediastate = MTIO_INSERTED;
	cv_broadcast(&un->un_state_cv);

	/*
	 *  Set test append flag if writing.
	 *  First write must check that tape is positioned correctly.
	 */
	un->un_test_append = (un->un_oflags & FWRITE);

	/*
	 * if there are pending unit attention flags.
	 * Check that the media has not changed.
	 */
	if (un->un_unit_attention_flags) {
		rval = st_get_media_identification(un, st_uscsi_cmd);
		if (rval != 0 && rval != EACCES) {
			rval = EIO;
		}
		un->un_unit_attention_flags = 0;
	}

exit:
	un->un_err_resid = 0;
	un->un_last_resid = 0;
	un->un_last_count = 0;

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_tape_init: return val = %x\n", rval);
	return (rval);

}



/* ARGSUSED */
static int
st_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	int err = 0;
	int count, last_state;
	minor_t minor = getminor(dev);
#ifdef	__x86
	struct contig_mem *cp, *cp_temp;
#endif

	GET_SOFT_STATE(dev);

	ST_ENTR(ST_DEVINFO, st_close);

	/*
	 * wait till all cmds in the pipeline have been completed
	 */
	mutex_enter(ST_MUTEX);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_close(dev = 0x%lx, flag = %d, otyp = %d)\n", dev, flag, otyp);

	st_wait_for_io(un);

	/* turn off persistent errors on close, as we want close to succeed */
	st_turn_pe_off(un);

	/*
	 * set state to indicate that we are in process of closing
	 */
	last_state = un->un_laststate = un->un_state;
	un->un_state = ST_STATE_CLOSING;

	ST_POS(ST_DEVINFO, "st_close1:", &un->un_pos);

	/*
	 * BSD behavior:
	 * a close always causes a silent span to the next file if we've hit
	 * an EOF (but not yet read across it).
	 */
	if ((minor & MT_BSD) && (un->un_pos.eof == ST_EOF)) {
		if (un->un_pos.pmode != invalid) {
			un->un_pos.fileno++;
			un->un_pos.blkno = 0;
		}
		un->un_pos.eof = ST_NO_EOF;
	}

	/*
	 * SVR4 behavior for skipping to next file:
	 *
	 * If we have not seen a filemark, space to the next file
	 *
	 * If we have already seen the filemark we are physically in the next
	 * file and we only increment the filenumber
	 */
	if (((minor & (MT_BSD | MT_NOREWIND)) == MT_NOREWIND) &&
	    (flag & FREAD) &&		/* reading or at least asked to */
	    (un->un_mediastate == MTIO_INSERTED) &&	/* tape loaded */
	    (un->un_pos.pmode != invalid) &&		/* XXX position known */
	    ((un->un_pos.blkno != 0) && 		/* inside a file */
	    (un->un_lastop != ST_OP_WRITE) &&		/* Didn't just write */
	    (un->un_lastop != ST_OP_WEOF))) {		/* or write filemarks */
		switch (un->un_pos.eof) {
		case ST_NO_EOF:
			/*
			 * if we were reading and did not read the complete file
			 * skip to the next file, leaving the tape correctly
			 * positioned to read the first record of the next file
			 * Check first for REEL if we are at EOT by trying to
			 * read a block
			 */
			if ((un->un_dp->options & ST_REEL) &&
			    (!(un->un_dp->options & ST_READ_IGNORE_EOFS)) &&
			    (un->un_pos.blkno == 0)) {
				if (st_cmd(un, SCMD_SPACE, Blk(1), SYNC_CMD)) {
					ST_DEBUG2(ST_DEVINFO, st_label,
					    SCSI_DEBUG,
					    "st_close : EIO can't space\n");
					err = EIO;
					goto error_out;
				}
				if (un->un_pos.eof >= ST_EOF_PENDING) {
					un->un_pos.eof = ST_EOT_PENDING;
					un->un_pos.fileno += 1;
					un->un_pos.blkno   = 0;
					break;
				}
			}
			if (st_cmd(un, SCMD_SPACE, Fmk(1), SYNC_CMD)) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_close: EIO can't space #2\n");
				err = EIO;
				goto error_out;
			} else {
				ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_close2: fileno=%x,blkno=%x,eof=%x\n",
				    un->un_pos.fileno, un->un_pos.blkno,
				    un->un_pos.eof);
				un->un_pos.eof = ST_NO_EOF;
			}
			break;

		case ST_EOF_PENDING:
		case ST_EOF:
			un->un_pos.fileno += 1;
			un->un_pos.lgclblkno += 1;
			un->un_pos.blkno   = 0;
			un->un_pos.eof = ST_NO_EOF;
			break;

		case ST_EOT:
		case ST_EOT_PENDING:
		case ST_EOM:
			/* nothing to do */
			break;
		default:
			ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
			    "Undefined state 0x%x", un->un_pos.eof);

		}
	}


	/*
	 * For performance reasons (HP 88780), the driver should
	 * postpone writing the second tape mark until just before a file
	 * positioning ioctl is issued (e.g., rewind).	This means that
	 * the user must not manually rewind the tape because the tape will
	 * be missing the second tape mark which marks EOM.
	 * However, this small performance improvement is not worth the risk.
	 */

	/*
	 * We need to back up over the filemark we inadvertently popped
	 * over doing a read in between the two filemarks that constitute
	 * logical eot for 1/2" tapes. Note that ST_EOT_PENDING is only
	 * set while reading.
	 *
	 * If we happen to be at physical eot (ST_EOM) (writing case),
	 * the writing of filemark(s) will clear the ST_EOM state, which
	 * we don't want, so we save this state and restore it later.
	 */

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "flag=%x, fmneeded=%x, lastop=%x, eof=%x\n",
	    flag, un->un_fmneeded, un->un_lastop, un->un_pos.eof);

	if (un->un_pos.eof == ST_EOT_PENDING) {
		if (minor & MT_NOREWIND) {
			if (st_cmd(un, SCMD_SPACE, Fmk(-1), SYNC_CMD)) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_close: EIO can't space #3\n");
				err = EIO;
				goto error_out;
			} else {
				un->un_pos.blkno = 0;
				un->un_pos.eof = ST_EOT;
			}
		} else {
			un->un_pos.eof = ST_NO_EOF;
		}

	/*
	 * Do we need to write a file mark?
	 *
	 * only write filemarks if there are fmks to be written and
	 *   - open for write (possibly read/write)
	 *   - the last operation was a write
	 * or:
	 *   -	opened for wronly
	 *   -	no data was written
	 */
	} else if ((un->un_pos.pmode != invalid) &&
	    (un->un_fmneeded > 0) &&
	    (((flag & FWRITE) &&
	    ((un->un_lastop == ST_OP_WRITE)||(un->un_lastop == ST_OP_WEOF))) ||
	    ((flag == FWRITE) && (un->un_lastop == ST_OP_NIL)))) {

		/* save ST_EOM state */
		int was_at_eom = (un->un_pos.eof == ST_EOM) ? 1 : 0;

		/*
		 * Note that we will write a filemark if we had opened
		 * the tape write only and no data was written, thus
		 * creating a null file.
		 *
		 * If the user already wrote one, we only have to write 1 more.
		 * If they wrote two, we don't have to write any.
		 */

		count = un->un_fmneeded;
		if (count > 0) {
			if (st_cmd(un, SCMD_WRITE_FILE_MARK, count, SYNC_CMD)) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_close : EIO can't wfm\n");
				err = EIO;
				goto error_out;
			}
			if ((un->un_dp->options & ST_REEL) &&
			    (minor & MT_NOREWIND)) {
				if (st_cmd(un, SCMD_SPACE, Fmk(-1), SYNC_CMD)) {
					ST_DEBUG2(ST_DEVINFO, st_label,
					    SCSI_DEBUG,
					    "st_close : EIO space fmk(-1)\n");
					err = EIO;
					goto error_out;
				}
				un->un_pos.eof = ST_NO_EOF;
				/* fix up block number */
				un->un_pos.blkno = 0;
			}
		}

		/*
		 * If we aren't going to be rewinding, and we were at
		 * physical eot, restore the state that indicates we
		 * are at physical eot. Once you have reached physical
		 * eot, and you close the tape, the only thing you can
		 * do on the next open is to rewind. Access to trailer
		 * records is only allowed without closing the device.
		 */
		if ((minor & MT_NOREWIND) == 0 && was_at_eom) {
			un->un_pos.eof = ST_EOM;
		}
	}

	/*
	 * report soft errors if enabled and available, if we never accessed
	 * the drive, don't get errors. This will prevent some DAT error
	 * messages upon LOG SENSE.
	 */
	if (st_report_soft_errors_on_close &&
	    (un->un_dp->options & ST_SOFT_ERROR_REPORTING) &&
	    (last_state != ST_STATE_OFFLINE)) {
		if (st_report_soft_errors(dev, flag)) {
			err = EIO;
			goto error_out;
		}
	}


	/*
	 * Do we need to rewind? Can we rewind?
	 */
	if ((minor & MT_NOREWIND) == 0 &&
	    un->un_pos.pmode != invalid && err == 0) {
		/*
		 * We'd like to rewind with the
		 * 'immediate' bit set, but this
		 * causes problems on some drives
		 * where subsequent opens get a
		 * 'NOT READY' error condition
		 * back while the tape is rewinding,
		 * which is impossible to distinguish
		 * from the condition of 'no tape loaded'.
		 *
		 * Also, for some targets, if you disconnect
		 * with the 'immediate' bit set, you don't
		 * actually return right away, i.e., the
		 * target ignores your request for immediate
		 * return.
		 *
		 * Instead, we'll fire off an async rewind
		 * command. We'll mark the device as closed,
		 * and any subsequent open will stall on
		 * the first TEST_UNIT_READY until the rewind
		 * completes.
		 */

		/*
		 * Used to be if reserve was not supported we'd send an
		 * asynchronious rewind. Comments above may be slightly invalid
		 * as the immediate bit was never set. Doing an immedate rewind
		 * makes sense, I think fixes to not ready status might handle
		 * the problems described above.
		 */
		if (un->un_sd->sd_inq->inq_ansi < 2) {
			if (st_cmd(un, SCMD_REWIND, 0, SYNC_CMD)) {
				err = EIO;
			}
		} else {
			/* flush data for older drives per scsi spec. */
			if (st_cmd(un, SCMD_WRITE_FILE_MARK, 0, SYNC_CMD)) {
				err = EIO;
			} else {
				/* release the drive before rewind immediate */
				if ((un->un_rsvd_status &
				    (ST_RESERVE | ST_PRESERVE_RESERVE)) ==
				    ST_RESERVE) {
					if (st_reserve_release(un, ST_RELEASE,
					    st_uscsi_cmd)) {
						err = EIO;
					}
				}

				/* send rewind with immediate bit set */
				if (st_cmd(un, SCMD_REWIND, 1, ASYNC_CMD)) {
					err = EIO;
				}
			}
		}
		/*
		 * Setting positions invalid in case the rewind doesn't
		 * happen. Drives don't like to rewind if resets happen
		 * they will tend to move back to where the rewind was
		 * issued if a reset or something happens so that if a
		 * write happens the data doesn't get clobbered.
		 *
		 * Not a big deal if the position is invalid when the
		 * open occures it will do a read position.
		 */
		un->un_pos.pmode = invalid;
		un->un_running.pmode = invalid;

		if (err == EIO) {
			goto error_out;
		}
	}

	/*
	 * eject tape if necessary
	 */
	if (un->un_eject_tape_on_failure) {
		un->un_eject_tape_on_failure = 0;
		if (st_cmd(un, SCMD_LOAD, LD_UNLOAD, SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_close : can't unload tape\n");
			err = EIO;
			goto error_out;
		} else {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_close : tape unloaded \n");
			un->un_pos.eof = ST_NO_EOF;
			un->un_mediastate = MTIO_EJECTED;
		}
	}
	/*
	 * Release the tape unit, if default reserve/release
	 * behaviour.
	 */
	if ((un->un_rsvd_status &
	    (ST_RESERVE | ST_PRESERVE_RESERVE |
	    ST_APPLICATION_RESERVATIONS)) == ST_RESERVE) {
		(void) st_reserve_release(un, ST_RELEASE, st_uscsi_cmd);
	}
error_out:
	/*
	 * clear up state
	 */
	un->un_laststate = un->un_state;
	un->un_state = ST_STATE_CLOSED;
	un->un_lastop = ST_OP_NIL;
	un->un_throttle = 1;	/* assume one request at time, for now */
	un->un_retry_ct = 0;
	un->un_errno = 0;
	un->un_swr_token = (opaque_t)NULL;
	un->un_rsvd_status &= ~(ST_INIT_RESERVE);

	/* Restore the options to the init time settings */
	if (un->un_init_options & ST_READ_IGNORE_ILI) {
		un->un_dp->options |= ST_READ_IGNORE_ILI;
	} else {
		un->un_dp->options &= ~ST_READ_IGNORE_ILI;
	}

	if (un->un_init_options & ST_READ_IGNORE_EOFS) {
		un->un_dp->options |= ST_READ_IGNORE_EOFS;
	} else {
		un->un_dp->options &= ~ST_READ_IGNORE_EOFS;
	}

	if (un->un_init_options & ST_SHORT_FILEMARKS) {
		un->un_dp->options |= ST_SHORT_FILEMARKS;
	} else {
		un->un_dp->options &= ~ST_SHORT_FILEMARKS;
	}

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * Signal anyone awaiting a close operation to complete.
	 */
	cv_signal(&un->un_clscv);

	/*
	 * any kind of error on closing causes all state to be tossed
	 */
	if (err && un->un_status != KEY_ILLEGAL_REQUEST) {
		/*
		 * note that st_intr has already set
		 * un_pos.pmode to invalid.
		 */
		un->un_density_known = 0;
	}

#ifdef	__x86
	/*
	 * free any contiguous mem alloc'ed for big block I/O
	 */
	cp = un->un_contig_mem;
	while (cp) {
		if (cp->cm_addr) {
			ddi_dma_mem_free(&cp->cm_acc_hdl);
		}
		cp_temp = cp;
		cp = cp->cm_next;
		kmem_free(cp_temp,
		    sizeof (struct contig_mem) + biosize());
	}
	un->un_contig_mem_total_num = 0;
	un->un_contig_mem_available_num = 0;
	un->un_contig_mem = NULL;
	un->un_max_contig_mem_len = 0;
#endif

	ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_close3: return val = %x, fileno=%x, blkno=%x, eof=%x\n",
	    err, un->un_pos.fileno, un->un_pos.blkno, un->un_pos.eof);

	mutex_exit(ST_MUTEX);
	return (err);
}

/*
 * These routines perform raw i/o operations.
 */

/* ARGSUSED2 */
static int
st_aread(dev_t dev, struct aio_req *aio, cred_t *cred_p)
{
#ifdef STDEBUG
	GET_SOFT_STATE(dev);
	ST_ENTR(ST_DEVINFO, st_aread);
#endif
	return (st_arw(dev, aio, B_READ));
}


/* ARGSUSED2 */
static int
st_awrite(dev_t dev, struct aio_req *aio, cred_t *cred_p)
{
#ifdef STDEBUG
	GET_SOFT_STATE(dev);
	ST_ENTR(ST_DEVINFO, st_awrite);
#endif
	return (st_arw(dev, aio, B_WRITE));
}



/* ARGSUSED */
static int
st_read(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
#ifdef STDEBUG
	GET_SOFT_STATE(dev);
	ST_ENTR(ST_DEVINFO, st_read);
#endif
	return (st_rw(dev, uiop, B_READ));
}

/* ARGSUSED */
static int
st_write(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
#ifdef STDEBUG
	GET_SOFT_STATE(dev);
	ST_ENTR(ST_DEVINFO, st_write);
#endif
	return (st_rw(dev, uiop, B_WRITE));
}

/*
 * Due to historical reasons, old limits are: For variable-length devices:
 * if greater than 64KB - 1 (ST_MAXRECSIZE_VARIABLE), block into 64 KB - 2
 * ST_MAXRECSIZE_VARIABLE_LIMIT) requests; otherwise,
 * (let it through unmodified. For fixed-length record devices:
 * 63K (ST_MAXRECSIZE_FIXED) is max (default minphys).
 *
 * The new limits used are un_maxdma (retrieved using scsi_ifgetcap()
 * from the HBA) and un_maxbsize (retrieved by sending SCMD_READ_BLKLIM
 * command to the drive).
 *
 */
static void
st_minphys(struct buf *bp)
{
	struct scsi_tape *un;

	un = ddi_get_soft_state(st_state, MTUNIT(bp->b_edev));

	ST_FUNC(ST_DEVINFO, st_minphys);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_minphys(bp = 0x%p): b_bcount = 0x%lx\n", (void *)bp,
	    bp->b_bcount);

	if (un->un_allow_large_xfer) {

		/*
		 * check un_maxbsize for variable length devices only
		 */
		if (un->un_bsize == 0 && bp->b_bcount > un->un_maxbsize) {
			bp->b_bcount = un->un_maxbsize;
		}
		/*
		 * can't go more that HBA maxdma limit in either fixed-length
		 * or variable-length tape drives.
		 */
		if (bp->b_bcount > un->un_maxdma) {
			bp->b_bcount = un->un_maxdma;
		}
	} else {

		/*
		 *  use old fixed limits
		 */
		if (un->un_bsize == 0) {
			if (bp->b_bcount > ST_MAXRECSIZE_VARIABLE) {
				bp->b_bcount = ST_MAXRECSIZE_VARIABLE_LIMIT;
			}
		} else {
			if (bp->b_bcount > ST_MAXRECSIZE_FIXED) {
				bp->b_bcount = ST_MAXRECSIZE_FIXED;
			}
		}
	}

	/*
	 * For regular raw I/O and Fixed Block length devices, make sure
	 * the adjusted block count is a whole multiple of the device
	 * block size.
	 */
	if (bp != un->un_sbufp && un->un_bsize) {
		bp->b_bcount -= (bp->b_bcount % un->un_bsize);
	}
}

static int
st_rw(dev_t dev, struct uio *uio, int flag)
{
	int rval = 0;
	long len;

	GET_SOFT_STATE(dev);

	ST_FUNC(ST_DEVINFO, st_rw);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_rw(dev = 0x%lx, flag = %s)\n", dev,
	    (flag == B_READ ? rd_str: wr_str));

	/* get local copy of transfer length */
	len = uio->uio_iov->iov_len;

	mutex_enter(ST_MUTEX);

	/*
	 * Clear error entry stack
	 */
	st_empty_error_stack(un);

	/*
	 * If in fixed block size mode and requested read or write
	 * is not an even multiple of that block size.
	 */
	if ((un->un_bsize != 0) && (len % un->un_bsize != 0)) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "%s: not modulo %d block size\n",
		    (flag == B_WRITE) ? wr_str : rd_str, un->un_bsize);
		rval = EINVAL;
	}

	/* If device has set granularity in the READ_BLKLIM we honor it. */
	if ((un->un_data_mod != 0) && (len % un->un_data_mod != 0)) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "%s: not modulo %d device granularity\n",
		    (flag == B_WRITE) ? wr_str : rd_str, un->un_data_mod);
		rval = EINVAL;
	}

	if (st_recov_sz != sizeof (recov_info) && un->un_multipath) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN, mp_misconf);
		rval = EFAULT;
	}

	if (rval != 0) {
		un->un_errno = rval;
		mutex_exit(ST_MUTEX);
		return (rval);
	}

	/*
	 * Reset this so it can be set if Berkeley and read over a filemark.
	 */
	un->un_silent_skip = 0;
	mutex_exit(ST_MUTEX);

	len = uio->uio_resid;

	rval = physio(st_queued_strategy, (struct buf *)NULL,
	    dev, flag, st_minphys, uio);
	/*
	 * if we have hit logical EOT during this xfer and there is not a
	 * full residue, then set eof back  to ST_EOM to make sure that
	 * the user will see at least one zero write
	 * after this short write
	 */
	mutex_enter(ST_MUTEX);
	if (un->un_pos.eof > ST_NO_EOF) {
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		"eof=%d resid=%lx\n", un->un_pos.eof, uio->uio_resid);
	}
	if (un->un_pos.eof >= ST_EOM && (flag == B_WRITE)) {
		if ((uio->uio_resid != len) && (uio->uio_resid != 0)) {
			un->un_pos.eof = ST_EOM;
		} else if (uio->uio_resid == len) {
			un->un_pos.eof = ST_NO_EOF;
		}
	}

	if (un->un_silent_skip && uio->uio_resid != len) {
		un->un_pos.eof = ST_EOF;
		un->un_pos.blkno = un->un_save_blkno;
		un->un_pos.fileno--;
	}

	un->un_errno = rval;

	mutex_exit(ST_MUTEX);

	return (rval);
}

static int
st_arw(dev_t dev, struct aio_req *aio, int flag)
{
	struct uio *uio = aio->aio_uio;
	int rval = 0;
	long len;

	GET_SOFT_STATE(dev);

	ST_FUNC(ST_DEVINFO, st_arw);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_arw(dev = 0x%lx, flag = %s)\n", dev,
	    (flag == B_READ ? rd_str: wr_str));

	/* get local copy of transfer length */
	len = uio->uio_iov->iov_len;

	mutex_enter(ST_MUTEX);

	/*
	 * If in fixed block size mode and requested read or write
	 * is not an even multiple of that block size.
	 */
	if ((un->un_bsize != 0) && (len % un->un_bsize != 0)) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "%s: not modulo %d block size\n",
		    (flag == B_WRITE) ? wr_str : rd_str, un->un_bsize);
		rval = EINVAL;
	}

	/* If device has set granularity in the READ_BLKLIM we honor it. */
	if ((un->un_data_mod != 0) && (len % un->un_data_mod != 0)) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "%s: not modulo %d device granularity\n",
		    (flag == B_WRITE) ? wr_str : rd_str, un->un_data_mod);
		rval = EINVAL;
	}

	if (st_recov_sz != sizeof (recov_info) && un->un_multipath) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN, mp_misconf);
		rval = EFAULT;
	}

	if (rval != 0) {
		un->un_errno = rval;
		mutex_exit(ST_MUTEX);
		return (rval);
	}

	mutex_exit(ST_MUTEX);

	len = uio->uio_resid;

	rval =
	    aphysio(st_queued_strategy, anocancel, dev, flag, st_minphys, aio);

	/*
	 * if we have hit logical EOT during this xfer and there is not a
	 * full residue, then set eof back  to ST_EOM to make sure that
	 * the user will see at least one zero write
	 * after this short write
	 *
	 * we keep this here just in case the application is not using
	 * persistent errors
	 */
	mutex_enter(ST_MUTEX);
	if (un->un_pos.eof > ST_NO_EOF) {
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "eof=%d resid=%lx\n", un->un_pos.eof, uio->uio_resid);
	}
	if (un->un_pos.eof >= ST_EOM && (flag == B_WRITE)) {
		if ((uio->uio_resid != len) && (uio->uio_resid != 0)) {
			un->un_pos.eof = ST_EOM;
		} else if (uio->uio_resid == len &&
		    !(un->un_persistence && un->un_persist_errors)) {
			un->un_pos.eof = ST_NO_EOF;
		}
	}
	un->un_errno = rval;
	mutex_exit(ST_MUTEX);

	return (rval);
}



static int
st_queued_strategy(buf_t *bp)
{
	struct scsi_tape *un;
	char reading = bp->b_flags & B_READ;
	int wasopening = 0;

	/*
	 * validate arguments
	 */
	un = ddi_get_soft_state(st_state, MTUNIT(bp->b_edev));
	if (un == NULL) {
		bp->b_resid = bp->b_bcount;
		bioerror(bp, ENXIO);
		ST_DEBUG6(NULL, st_label, SCSI_DEBUG,
		    "st_queued_strategy: ENXIO error exit\n");
		biodone(bp);
		return (0);
	}

	ST_ENTR(ST_DEVINFO, st_queued_strategy);

	mutex_enter(ST_MUTEX);

	while (un->un_pwr_mgmt == ST_PWR_SUSPENDED) {
		cv_wait(&un->un_suspend_cv, ST_MUTEX);
	}

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_queued_strategy(): bcount=0x%lx, fileno=%d, blkno=%x, eof=%d\n",
	    bp->b_bcount, un->un_pos.fileno, un->un_pos.blkno, un->un_pos.eof);

	/*
	 * If persistent errors have been flagged, just nix this one. We wait
	 * for any outstanding I/O's below, so we will be in order.
	 */
	if (un->un_persistence && un->un_persist_errors) {
		goto exit;
	}

	/*
	 * If last command was non queued, wait till it finishes.
	 */
	while (un->un_sbuf_busy) {
		cv_wait(&un->un_sbuf_cv, ST_MUTEX);
		/* woke up because of an error */
		if (un->un_persistence && un->un_persist_errors) {
			goto exit;
		}
	}

	/*
	 * s_buf and recovery commands shouldn't come here.
	 */
	ASSERT(bp != un->un_recov_buf);
	ASSERT(bp != un->un_sbufp);

	/*
	 * If we haven't done/checked reservation on the tape unit
	 * do it now.
	 */
	if ((un->un_rsvd_status &
	    (ST_RESERVE | ST_APPLICATION_RESERVATIONS)) == 0) {
		if ((un->un_dp->options & ST_NO_RESERVE_RELEASE) == 0) {
			if (st_reserve_release(un, ST_RESERVE, st_uscsi_cmd)) {
				st_bioerror(bp, un->un_errno);
				goto exit;
			}
		} else if (un->un_state == ST_STATE_OPEN_PENDING_IO) {
			/*
			 * Enter here to restore position for possible
			 * resets when the device was closed and opened
			 * in O_NDELAY mode subsequently
			 */
			un->un_state = ST_STATE_INITIALIZING;
			(void) st_cmd(un, SCMD_TEST_UNIT_READY,
			    0, SYNC_CMD);
			un->un_state = ST_STATE_OPEN_PENDING_IO;
		}
		un->un_rsvd_status |= ST_INIT_RESERVE;
	}

	/*
	 * If we are offline, we have to initialize everything first.
	 * This is to handle either when opened with O_NDELAY, or
	 * we just got a new tape in the drive, after an offline.
	 * We don't observe O_NDELAY past the open,
	 * as it will not make sense for tapes.
	 */
	if (un->un_state == ST_STATE_OFFLINE || un->un_restore_pos) {
		/*
		 * reset state to avoid recursion
		 */
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_INITIALIZING;
		if (st_tape_init(un)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "stioctl : OFFLINE init failure ");
			un->un_state = ST_STATE_OFFLINE;
			un->un_pos.pmode = invalid;
			goto b_done_err;
		}
		/* un_restore_pos make invalid */
		un->un_state = ST_STATE_OPEN_PENDING_IO;
		un->un_restore_pos = 0;
	}
	/*
	 * Check for legal operations
	 */
	if (un->un_pos.pmode == invalid) {
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "strategy with un->un_pos.pmode invalid\n");
		goto b_done_err;
	}

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_queued_strategy(): regular io\n");

	/*
	 * Process this first. If we were reading, and we're pending
	 * logical eot, that means we've bumped one file mark too far.
	 */

	/*
	 * Recursion warning: st_cmd will route back through here.
	 * Not anymore st_cmd will go through st_strategy()!
	 */
	if (un->un_pos.eof == ST_EOT_PENDING) {
		if (st_cmd(un, SCMD_SPACE, Fmk(-1), SYNC_CMD)) {
			un->un_pos.pmode = invalid;
			un->un_density_known = 0;
			goto b_done_err;
		}
		un->un_pos.blkno = 0; /* fix up block number.. */
		un->un_pos.eof = ST_EOT;
	}

	/*
	 * If we are in the process of opening, we may have to
	 * determine/set the correct density. We also may have
	 * to do a test_append (if QIC) to see whether we are
	 * in a position to append to the end of the tape.
	 *
	 * If we're already at logical eot, we transition
	 * to ST_NO_EOF. If we're at physical eot, we punt
	 * to the switch statement below to handle.
	 */
	if ((un->un_state == ST_STATE_OPEN_PENDING_IO) ||
	    (un->un_test_append && (un->un_dp->options & ST_QIC))) {

		if (un->un_state == ST_STATE_OPEN_PENDING_IO) {
			if (st_determine_density(un, (int)reading)) {
				goto b_done_err;
			}
		}

		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "pending_io@fileno %d rw %d qic %d eof %d\n",
		    un->un_pos.fileno, (int)reading,
		    (un->un_dp->options & ST_QIC) ? 1 : 0,
		    un->un_pos.eof);

		if (!reading && un->un_pos.eof != ST_EOM) {
			if (un->un_pos.eof == ST_EOT) {
				un->un_pos.eof = ST_NO_EOF;
			} else if (un->un_pos.pmode != invalid &&
			    (un->un_dp->options & ST_QIC)) {
				/*
				 * st_test_append() will do it all
				 */
				st_test_append(bp);
				mutex_exit(ST_MUTEX);
				return (0);
			}
		}
		if (un->un_state == ST_STATE_OPEN_PENDING_IO) {
			wasopening = 1;
		}
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_OPEN;
	}


	/*
	 * Process rest of END OF FILE and END OF TAPE conditions
	 */

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "eof=%x, wasopening=%x\n",
	    un->un_pos.eof, wasopening);

	switch (un->un_pos.eof) {
	case ST_EOM:
		/*
		 * This allows writes to proceed past physical
		 * eot. We'll *really* be in trouble if the
		 * user continues blindly writing data too
		 * much past this point (unwind the tape).
		 * Physical eot really means 'early warning
		 * eot' in this context.
		 *
		 * Every other write from now on will succeed
		 * (if sufficient  tape left).
		 * This write will return with resid == count
		 * but the next one should be successful
		 *
		 * Note that we only transition to logical EOT
		 * if the last state wasn't the OPENING state.
		 * We explicitly prohibit running up to physical
		 * eot, closing the device, and then re-opening
		 * to proceed. Trailer records may only be gotten
		 * at by keeping the tape open after hitting eot.
		 *
		 * Also note that ST_EOM cannot be set by reading-
		 * this can only be set during writing. Reading
		 * up to the end of the tape gets a blank check
		 * or a double-filemark indication (ST_EOT_PENDING),
		 * and we prohibit reading after that point.
		 *
		 */
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG, "EOM\n");
		if (wasopening == 0) {
			/*
			 * this allows st_rw() to reset it back to
			 * will see a zero write
			 */
			un->un_pos.eof = ST_WRITE_AFTER_EOM;
		}
		un->un_status = SUN_KEY_EOT;
		goto b_done;

	case ST_WRITE_AFTER_EOM:
	case ST_EOT:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG, "EOT\n");
		un->un_status = SUN_KEY_EOT;
		if (SVR4_BEHAVIOR && reading) {
			goto b_done_err;
		}

		if (reading) {
			goto b_done;
		}
		un->un_pos.eof = ST_NO_EOF;
		break;

	case ST_EOF_PENDING:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "EOF PENDING\n");
		un->un_status = SUN_KEY_EOF;
		if (SVR4_BEHAVIOR) {
			un->un_pos.eof = ST_EOF;
			goto b_done;
		}
		/* FALLTHROUGH */
	case ST_EOF:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG, "EOF\n");
		un->un_status = SUN_KEY_EOF;
		if (SVR4_BEHAVIOR) {
			goto b_done_err;
		}

		if (BSD_BEHAVIOR) {
			un->un_pos.eof = ST_NO_EOF;
			un->un_pos.fileno += 1;
			un->un_pos.blkno   = 0;
		}

		if (reading) {
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "now file %d (read)\n",
			    un->un_pos.fileno);
			goto b_done;
		}
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "now file %d (write)\n", un->un_pos.fileno);
		break;
	default:
		un->un_status = 0;
		break;
	}

	bp->b_flags &= ~(B_DONE);
	st_bioerror(bp, 0);
	bp->av_forw = NULL;
	bp->b_resid = 0;
	SET_BP_PKT(bp, 0);


	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_queued_strategy: cmd=0x%p  count=%ld  resid=%ld flags=0x%x"
	    " pkt=0x%p\n",
	    (void *)bp->b_forw, bp->b_bcount,
	    bp->b_resid, bp->b_flags, (void *)BP_PKT(bp));

#ifdef	__x86
	/*
	 * We will replace bp with a new bp that can do big blk xfer
	 * if the requested xfer size is bigger than un->un_maxdma_arch
	 *
	 * Also, we need to make sure that we're handling real I/O
	 * by checking group 0/1 SCSI I/O commands, if needed
	 */
	if (bp->b_bcount > un->un_maxdma_arch &&
	    ((uchar_t)(uintptr_t)bp->b_forw == SCMD_READ ||
	    (uchar_t)(uintptr_t)bp->b_forw == SCMD_READ_G4 ||
	    (uchar_t)(uintptr_t)bp->b_forw == SCMD_WRITE ||
	    (uchar_t)(uintptr_t)bp->b_forw == SCMD_WRITE_G4)) {
		mutex_exit(ST_MUTEX);
		bp = st_get_bigblk_bp(bp);
		mutex_enter(ST_MUTEX);
	}
#endif

	/* put on wait queue */
	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_queued_strategy: un->un_quef = 0x%p, bp = 0x%p\n",
	    (void *)un->un_quef, (void *)bp);

	st_add_to_queue(&un->un_quef, &un->un_quel, un->un_quel, bp);

	ST_DO_KSTATS(bp, kstat_waitq_enter);

	st_start(un);

	mutex_exit(ST_MUTEX);
	return (0);

b_done_err:
	st_bioerror(bp, EIO);
	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_queued_strategy : EIO b_done_err\n");

b_done:
	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_queued_strategy: b_done\n");

exit:
	/*
	 * make sure no commands are outstanding or waiting before closing,
	 * so we can guarantee order
	 */
	st_wait_for_io(un);
	un->un_err_resid = bp->b_resid = bp->b_bcount;

	/* override errno here, if persistent errors were flagged */
	if (un->un_persistence && un->un_persist_errors)
		bioerror(bp, un->un_errno);

	mutex_exit(ST_MUTEX);

	biodone(bp);
	ASSERT(mutex_owned(ST_MUTEX) == 0);
	return (0);
}


static int
st_strategy(struct buf *bp)
{
	struct scsi_tape *un;

	/*
	 * validate arguments
	 */
	un = ddi_get_soft_state(st_state, MTUNIT(bp->b_edev));
	if (un == NULL) {
		bp->b_resid = bp->b_bcount;
		bioerror(bp, ENXIO);
		ST_DEBUG6(NULL, st_label, SCSI_DEBUG,
		    "st_strategy: ENXIO error exit\n");

		biodone(bp);
		return (0);

	}

	ST_ENTR(ST_DEVINFO, st_strategy);

	mutex_enter(ST_MUTEX);

	while (un->un_pwr_mgmt == ST_PWR_SUSPENDED) {
		cv_wait(&un->un_suspend_cv, ST_MUTEX);
	}

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_strategy(): bcount=0x%lx, fileno=%d, blkno=%x, eof=%d\n",
	    bp->b_bcount, un->un_pos.fileno, un->un_pos.blkno, un->un_pos.eof);

	ASSERT((bp == un->un_recov_buf) || (bp == un->un_sbufp));

	bp->b_flags &= ~(B_DONE);
	st_bioerror(bp, 0);
	bp->av_forw = NULL;
	bp->b_resid = 0;
	SET_BP_PKT(bp, 0);


	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_strategy: cmd=0x%x  count=%ld  resid=%ld flags=0x%x"
	    " pkt=0x%p\n",
	    (unsigned char)(uintptr_t)bp->b_forw, bp->b_bcount,
	    bp->b_resid, bp->b_flags, (void *)BP_PKT(bp));
	ST_DO_KSTATS(bp, kstat_waitq_enter);

	st_start(un);

	mutex_exit(ST_MUTEX);
	return (0);
}

/*
 * this routine spaces forward over filemarks
 */
static int
st_space_fmks(struct scsi_tape *un, int64_t count)
{
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_space_fmks);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_space_fmks(dev = 0x%lx, count = %"PRIx64")\n",
	    un->un_dev, count);

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * the risk with doing only one space operation is that we
	 * may accidentily jump in old data
	 * the exabyte 8500 reading 8200 tapes cannot use KNOWS_EOD
	 * because the 8200 does not append a marker; in order not to
	 * sacrifice the fast file skip, we do a slow skip if the low
	 * density device has been opened
	 */

	if ((un->un_dp->options & ST_KNOWS_EOD) &&
	    !((un->un_dp->type == ST_TYPE_EXB8500 &&
	    MT_DENSITY(un->un_dev) == 0))) {
		if (st_cmd(un, SCMD_SPACE, Fmk(count), SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "space_fmks : EIO can't do space cmd #1\n");
			rval = EIO;
		}
	} else {
		while (count > 0) {
			if (st_cmd(un, SCMD_SPACE, Fmk(1), SYNC_CMD)) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "space_fmks : EIO can't do space cmd #2\n");
				rval = EIO;
				break;
			}
			count -= 1;
			/*
			 * read a block to see if we have reached
			 * end of medium (double filemark for reel or
			 * medium error for others)
			 */
			if (count > 0) {
				if (st_cmd(un, SCMD_SPACE, Blk(1), SYNC_CMD)) {
					ST_DEBUG2(ST_DEVINFO, st_label,
					    SCSI_DEBUG,
					    "space_fmks : EIO can't do "
					    "space cmd #3\n");
					rval = EIO;
					break;
				}
				if ((un->un_pos.eof >= ST_EOF_PENDING) &&
				    (un->un_dp->options & ST_REEL)) {
					un->un_status = SUN_KEY_EOT;
					ST_DEBUG2(ST_DEVINFO, st_label,
					    SCSI_DEBUG,
					    "space_fmks : EIO ST_REEL\n");
					rval = EIO;
					break;
				} else if (IN_EOF(un->un_pos)) {
					un->un_pos.eof = ST_NO_EOF;
					un->un_pos.fileno++;
					un->un_pos.blkno = 0;
					count--;
				} else if (un->un_pos.eof > ST_EOF) {
					ST_DEBUG2(ST_DEVINFO, st_label,
					    SCSI_DEBUG,
					    "space_fmks, EIO > ST_EOF\n");
					rval = EIO;
					break;
				}

			}
		}
		un->un_err_resid = count;
		COPY_POS(&un->un_pos, &un->un_err_pos);
	}
	ASSERT(mutex_owned(ST_MUTEX));
	return (rval);
}

/*
 * this routine spaces to EOD
 *
 * it keeps track of the current filenumber and returns the filenumber after
 * the last successful space operation, we keep the number high because as
 * tapes are getting larger, the possibility of more and more files exist,
 * 0x100000 (1 Meg of files) probably will never have to be changed any time
 * soon
 */
#define	MAX_SKIP	0x100000 /* somewhat arbitrary */

static int
st_find_eod(struct scsi_tape *un)
{
	tapepos_t savepos;
	int64_t sp_type;
	int result;

	if (un == NULL) {
		return (-1);
	}

	ST_FUNC(ST_DEVINFO, st_find_eod);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_find_eod(dev = 0x%lx): fileno = %d\n", un->un_dev,
	    un->un_pos.fileno);

	ASSERT(mutex_owned(ST_MUTEX));

	COPY_POS(&savepos, &un->un_pos);

	/*
	 * see if the drive is smart enough to do the skips in
	 * one operation; 1/2" use two filemarks
	 * the exabyte 8500 reading 8200 tapes cannot use KNOWS_EOD
	 * because the 8200 does not append a marker; in order not to
	 * sacrifice the fast file skip, we do a slow skip if the low
	 * density device has been opened
	 */
	if ((un->un_dp->options & ST_KNOWS_EOD) != 0) {
		if ((un->un_dp->type == ST_TYPE_EXB8500) &&
		    (MT_DENSITY(un->un_dev) == 0)) {
			sp_type = Fmk(1);
		} else if (un->un_pos.pmode == logical) {
			sp_type = SPACE(SP_EOD, 0);
		} else {
			sp_type = Fmk(MAX_SKIP);
		}
	} else {
		sp_type = Fmk(1);
	}

	for (;;) {
		result = st_cmd(un, SCMD_SPACE, sp_type, SYNC_CMD);

		if (result == 0) {
			COPY_POS(&savepos, &un->un_pos);
		}

		if (sp_type == SPACE(SP_EOD, 0)) {
			if (result != 0) {
				sp_type = Fmk(MAX_SKIP);
				continue;
			}

			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_find_eod: 0x%"PRIx64"\n",
			    savepos.lgclblkno);
			/*
			 * What we return will become the current file position.
			 * After completing the space command with the position
			 * mode that is not invalid a read position command will
			 * be automaticly issued. If the drive support the long
			 * read position format a valid file position can be
			 * returned.
			 */
			return (un->un_pos.fileno);
		}

		if (result != 0) {
			break;
		}

		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "count=%"PRIx64", eof=%x, status=%x\n",
		    SPACE_CNT(sp_type),  un->un_pos.eof, un->un_status);

		/*
		 * If we're not EOM smart,  space a record
		 * to see whether we're now in the slot between
		 * the two sequential filemarks that logical
		 * EOM consists of (REEL) or hit nowhere land
		 * (8mm).
		 */
		if (sp_type == Fmk(1)) {
			/*
			 * no fast skipping, check a record
			 */
			if (st_cmd(un, SCMD_SPACE, Blk((1)), SYNC_CMD)) {
				break;
			}
			if ((un->un_pos.eof >= ST_EOF_PENDING) &&
			    (un->un_dp->options & ST_REEL)) {
				un->un_status = KEY_BLANK_CHECK;
				un->un_pos.fileno++;
				un->un_pos.blkno = 0;
				break;
			}
			if (IN_EOF(un->un_pos)) {
				un->un_pos.eof = ST_NO_EOF;
				un->un_pos.fileno++;
				un->un_pos.blkno = 0;
			}
			if (un->un_pos.eof > ST_EOF) {
				break;
			}
		} else {
			if (un->un_pos.eof > ST_EOF) {
				break;
			}
		}
	}

	if (un->un_dp->options & ST_KNOWS_EOD) {
		COPY_POS(&savepos, &un->un_pos);
	}

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_find_eod: %x\n", savepos.fileno);
	return (savepos.fileno);
}


/*
 * this routine is frequently used in ioctls below;
 * it determines whether we know the density and if not will
 * determine it
 * if we have written the tape before, one or more filemarks are written
 *
 * depending on the stepflag, the head is repositioned to where it was before
 * the filemarks were written in order not to confuse step counts
 */
#define	STEPBACK    0
#define	NO_STEPBACK 1

static int
st_check_density_or_wfm(dev_t dev, int wfm, int mode, int stepflag)
{

	GET_SOFT_STATE(dev);

	ST_FUNC(ST_DEVINFO, st_check_density_or_wfm);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_check_density_or_wfm(dev= 0x%lx, wfm= %d, mode= %d, stpflg= %d)"
	    "\n", dev, wfm, mode, stepflag);

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * If we don't yet know the density of the tape we have inserted,
	 * we have to either unconditionally set it (if we're 'writing'),
	 * or we have to determine it. As side effects, check for any
	 * write-protect errors, and for the need to put out any file-marks
	 * before positioning a tape.
	 *
	 * If we are going to be spacing forward, and we haven't determined
	 * the tape density yet, we have to do so now...
	 */
	if (un->un_state == ST_STATE_OPEN_PENDING_IO) {
		if (st_determine_density(un, mode)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "check_density_or_wfm : EIO can't determine "
			    "density\n");
			un->un_errno = EIO;
			return (EIO);
		}
		/*
		 * Presumably we are at BOT. If we attempt to write, it will
		 * either work okay, or bomb. We don't do a st_test_append
		 * unless we're past BOT.
		 */
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_OPEN;

	} else if (un->un_pos.pmode != invalid && un->un_fmneeded > 0 &&
	    ((un->un_lastop == ST_OP_WEOF && wfm) ||
	    (un->un_lastop == ST_OP_WRITE && wfm))) {

		tapepos_t spos;

		COPY_POS(&spos, &un->un_pos);

		/*
		 * We need to write one or two filemarks.
		 * In the case of the HP, we need to
		 * position the head between the two
		 * marks.
		 */
		if ((un->un_fmneeded > 0) || (un->un_lastop == ST_OP_WEOF)) {
			wfm = un->un_fmneeded;
			un->un_fmneeded = 0;
		}

		if (st_write_fm(dev, wfm)) {
			un->un_pos.pmode = invalid;
			un->un_density_known = 0;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "check_density_or_wfm : EIO can't write fm\n");
			un->un_errno = EIO;
			return (EIO);
		}

		if (stepflag == STEPBACK) {
			if (st_cmd(un, SCMD_SPACE, Fmk(-wfm), SYNC_CMD)) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "check_density_or_wfm : EIO can't space "
				    "(-wfm)\n");
				un->un_errno = EIO;
				return (EIO);
			}
			COPY_POS(&un->un_pos, &spos);
		}
	}

	/*
	 * Whatever we do at this point clears the state of the eof flag.
	 */

	un->un_pos.eof = ST_NO_EOF;

	/*
	 * If writing, let's check that we're positioned correctly
	 * at the end of tape before issuing the next write.
	 */
	if (un->un_read_only == RDWR) {
		un->un_test_append = 1;
	}

	ASSERT(mutex_owned(ST_MUTEX));
	return (0);
}


/*
 * Wait for all outstaning I/O's to complete
 *
 * we wait on both ncmds and the wait queue for times when we are flushing
 * after persistent errors are flagged, which is when ncmds can be 0, and the
 * queue can still have I/O's.  This way we preserve order of biodone's.
 */
static void
st_wait_for_io(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_wait_for_io);
	ASSERT(mutex_owned(ST_MUTEX));
	while ((un->un_ncmds) || (un->un_quef) || (un->un_runqf)) {
		cv_wait(&un->un_queue_cv, ST_MUTEX);
	}
}

/*
 * This routine implements the ioctl calls.  It is called
 * from the device switch at normal priority.
 */
/*ARGSUSED*/
static int
st_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p,
    int *rval_p)
{
	int tmp, rval = 0;

	GET_SOFT_STATE(dev);

	ST_ENTR(ST_DEVINFO, st_ioctl);

	mutex_enter(ST_MUTEX);

	ASSERT(un->un_recov_buf_busy == 0);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_ioctl(): fileno=%x, blkno=%x, eof=%x, state = %d, "
	    "pe_flag = %d\n",
	    un->un_pos.fileno, un->un_pos.blkno, un->un_pos.eof, un->un_state,
	    un->un_persistence && un->un_persist_errors);

	/*
	 * We don't want to block on these, so let them through
	 * and we don't care about setting driver states here.
	 */
	if ((cmd == MTIOCGETDRIVETYPE) ||
	    (cmd == MTIOCGUARANTEEDORDER) ||
	    (cmd == MTIOCPERSISTENTSTATUS)) {
		goto check_commands;
	}

	/*
	 * We clear error entry stack except command
	 * MTIOCGETERROR and MTIOCGET
	 */
	if ((cmd != MTIOCGETERROR) &&
	    (cmd != MTIOCGET)) {
		st_empty_error_stack(un);
	}

	/*
	 * wait for all outstanding commands to complete, or be dequeued.
	 * And because ioctl's are synchronous commands, any return value
	 * after this,  will be in order
	 */
	st_wait_for_io(un);

	/*
	 * allow only a through clear errors and persistent status, and
	 * status
	 */
	if (un->un_persistence && un->un_persist_errors) {
		if ((cmd == MTIOCLRERR) ||
		    (cmd == MTIOCPERSISTENT) ||
		    (cmd == MTIOCGET)) {
			goto check_commands;
		} else {
			rval = un->un_errno;
			goto exit;
		}
	}

	ASSERT(un->un_throttle != 0);
	un->un_throttle = 1;	/* > 1 will never happen here */
	un->un_errno = 0;	/* start clean from here */

	/*
	 * first and foremost, handle any ST_EOT_PENDING cases.
	 * That is, if a logical eot is pending notice, notice it.
	 */
	if (un->un_pos.eof == ST_EOT_PENDING) {
		int resid = un->un_err_resid;
		uchar_t status = un->un_status;
		uchar_t lastop = un->un_lastop;

		if (st_cmd(un, SCMD_SPACE, Fmk(-1), SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "stioctl : EIO can't space fmk(-1)\n");
			rval = EIO;
			goto exit;
		}
		un->un_lastop = lastop; /* restore last operation */
		if (status == SUN_KEY_EOF) {
			un->un_status = SUN_KEY_EOT;
		} else {
			un->un_status = status;
		}
		un->un_err_resid  = resid;
		/* fix up block number */
		un->un_err_pos.blkno = un->un_pos.blkno = 0;
		/* now we're at logical eot */
		un->un_pos.eof = ST_EOT;
	}

	/*
	 * now, handle the rest of the situations
	 */
check_commands:
	switch (cmd) {
	case MTIOCGET:
	{
#ifdef _MULTI_DATAMODEL
		/*
		 * For use when a 32 bit app makes a call into a
		 * 64 bit ioctl
		 */
		struct mtget32		mtg_local32;
		struct mtget32 		*mtget_32 = &mtg_local32;
#endif /* _MULTI_DATAMODEL */

			/* Get tape status */
		struct mtget mtg_local;
		struct mtget *mtget = &mtg_local;
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl: MTIOCGET\n");

		bzero((caddr_t)mtget, sizeof (struct mtget));
		mtget->mt_erreg = un->un_status;
		mtget->mt_resid = un->un_err_resid;
		mtget->mt_dsreg = un->un_retry_ct;
		if (un->un_err_pos.pmode == legacy) {
			mtget->mt_fileno = un->un_err_pos.fileno;
		} else {
			mtget->mt_fileno = -1;
		}
		/*
		 * If the value is positive fine.
		 * If its negative we need to return a value based on the
		 * old way if counting backwards from INF (1,000,000,000).
		 */
		if (un->un_err_pos.blkno >= 0) {
			mtget->mt_blkno = un->un_err_pos.blkno;
		} else {
			mtget->mt_blkno = INF + 1 - (-un->un_err_pos.blkno);
		}
		mtget->mt_type = un->un_dp->type;
		mtget->mt_flags = MTF_SCSI | MTF_ASF;
		if (un->un_read_pos_type != NO_POS) {
			mtget->mt_flags |= MTF_LOGICAL_BLOCK;
		}
		if (un->un_dp->options & ST_REEL) {
			mtget->mt_flags |= MTF_REEL;
			mtget->mt_bf = 20;
		} else {		/* 1/4" cartridges */
			switch (mtget->mt_type) {
			/* Emulex cartridge tape */
			case MT_ISMT02:
				mtget->mt_bf = 40;
				break;
			default:
				mtget->mt_bf = 126;
				break;
			}
		}

		/*
		 * If large transfers are allowed and drive options
		 * has no record size limit set. Calculate blocking
		 * factor from the lesser of maxbsize and maxdma.
		 */
		if ((un->un_allow_large_xfer) &&
		    (un->un_dp->options & ST_NO_RECSIZE_LIMIT)) {
			mtget->mt_bf = min(un->un_maxbsize,
			    un->un_maxdma) / SECSIZE;
		}

		if (un->un_read_only == WORM ||
		    un->un_read_only == RDWORM) {
			mtget->mt_flags |= MTF_WORM_MEDIA;
		}

		/*
		 * In persistent error mode sending a non-queued can hang
		 * because this ioctl gets to be run without turning off
		 * persistense. Fake the answer based on previous info.
		 */
		if (un->un_persistence) {
			rval = 0;
		} else {
			rval = st_check_clean_bit(un);
		}
		if (rval == 0) {
			/*
			 * If zero is returned or in persistent mode,
			 * use the old data.
			 */
			if ((un->un_HeadClean & (TAPE_ALERT_SUPPORTED |
			    TAPE_SEQUENTIAL_SUPPORTED|TAPE_ALERT_NOT_SUPPORTED))
			    != TAPE_ALERT_NOT_SUPPORTED) {
				mtget->mt_flags |= MTF_TAPE_CLN_SUPPORTED;
			}
			if (un->un_HeadClean & (TAPE_PREVIOUSLY_DIRTY |
			    TAPE_ALERT_STILL_DIRTY)) {
				mtget->mt_flags |= MTF_TAPE_HEAD_DIRTY;
			}
		} else {
			mtget->mt_flags |= (ushort_t)rval;
			rval = 0;
		}

		un->un_status = 0;		/* Reset status */
		un->un_err_resid = 0;
		tmp = sizeof (struct mtget);

#ifdef _MULTI_DATAMODEL

		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
			/*
			 * Convert 64 bit back to 32 bit before doing
			 * copyout. This is what the ILP32 app expects.
			 */
			mtget_32->mt_erreg = 	mtget->mt_erreg;
			mtget_32->mt_resid = 	mtget->mt_resid;
			mtget_32->mt_dsreg = 	mtget->mt_dsreg;
			mtget_32->mt_fileno = 	(daddr32_t)mtget->mt_fileno;
			mtget_32->mt_blkno = 	(daddr32_t)mtget->mt_blkno;
			mtget_32->mt_type =  	mtget->mt_type;
			mtget_32->mt_flags = 	mtget->mt_flags;
			mtget_32->mt_bf = 	mtget->mt_bf;

			if (ddi_copyout(mtget_32, (void *)arg,
			    sizeof (struct mtget32), flag)) {
				rval = EFAULT;
			}
			break;

		case DDI_MODEL_NONE:
			if (ddi_copyout(mtget, (void *)arg, tmp, flag)) {
				rval = EFAULT;
			}
			break;
		}
#else /* ! _MULTI_DATAMODE */
		if (ddi_copyout(mtget, (void *)arg, tmp, flag)) {
			rval = EFAULT;
		}
#endif /* _MULTI_DATAMODE */

		break;
	}
	case MTIOCGETERROR:
			/*
			 * get error entry from error stack
			 */
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl: MTIOCGETERROR\n");

			rval = st_get_error_entry(un, arg, flag);

			break;

	case MTIOCSTATE:
		{
			/*
			 * return when media presence matches state
			 */
			enum mtio_state state;

			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl: MTIOCSTATE\n");

			if (ddi_copyin((void *)arg, &state, sizeof (int), flag))
				rval = EFAULT;

			mutex_exit(ST_MUTEX);

			rval = st_check_media(dev, state);

			mutex_enter(ST_MUTEX);

			if (rval != 0) {
				break;
			}

			if (ddi_copyout(&un->un_mediastate, (void *)arg,
			    sizeof (int), flag))
				rval = EFAULT;
			break;

		}

	case MTIOCGETDRIVETYPE:
		{
#ifdef _MULTI_DATAMODEL
		/*
		 * For use when a 32 bit app makes a call into a
		 * 64 bit ioctl
		 */
		struct mtdrivetype_request32	mtdtrq32;
#endif /* _MULTI_DATAMODEL */

			/*
			 * return mtdrivetype
			 */
			struct mtdrivetype_request mtdtrq;
			struct mtdrivetype mtdrtyp;
			struct mtdrivetype *mtdt = &mtdrtyp;
			struct st_drivetype *stdt = un->un_dp;

			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl: MTIOCGETDRIVETYPE\n");

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			if (ddi_copyin((void *)arg, &mtdtrq32,
			    sizeof (struct mtdrivetype_request32), flag)) {
				rval = EFAULT;
				break;
			}
			mtdtrq.size = mtdtrq32.size;
			mtdtrq.mtdtp =
			    (struct  mtdrivetype *)(uintptr_t)mtdtrq32.mtdtp;
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl: size 0x%x\n", mtdtrq.size);
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &mtdtrq,
			    sizeof (struct mtdrivetype_request), flag)) {
				rval = EFAULT;
				break;
			}
			break;
		}

#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &mtdtrq,
		    sizeof (struct mtdrivetype_request), flag)) {
			rval = EFAULT;
			break;
		}
#endif /* _MULTI_DATAMODEL */

			/*
			 * if requested size is < 0 then return
			 * error.
			 */
			if (mtdtrq.size < 0) {
				rval = EINVAL;
				break;
			}
			bzero(mtdt, sizeof (struct mtdrivetype));
			(void) strncpy(mtdt->name, stdt->name, ST_NAMESIZE);
			(void) strncpy(mtdt->vid, stdt->vid, VIDPIDLEN - 1);
			mtdt->type = stdt->type;
			mtdt->bsize = stdt->bsize;
			mtdt->options = stdt->options;
			mtdt->max_rretries = stdt->max_rretries;
			mtdt->max_wretries = stdt->max_wretries;
			for (tmp = 0; tmp < NDENSITIES; tmp++) {
				mtdt->densities[tmp] = stdt->densities[tmp];
			}
			mtdt->default_density = stdt->default_density;
			/*
			 * Speed hasn't been used since the hayday of reel tape.
			 * For all drives not setting the option ST_KNOWS_MEDIA
			 * the speed member renamed to mediatype are zeros.
			 * Those drives that have ST_KNOWS_MEDIA set use the
			 * new mediatype member which is used to figure the
			 * type of media loaded.
			 *
			 * So as to not break applications speed in the
			 * mtdrivetype structure is not renamed.
			 */
			for (tmp = 0; tmp < NDENSITIES; tmp++) {
				mtdt->speeds[tmp] = stdt->mediatype[tmp];
			}
			mtdt->non_motion_timeout = stdt->non_motion_timeout;
			mtdt->io_timeout = stdt->io_timeout;
			mtdt->rewind_timeout = stdt->rewind_timeout;
			mtdt->space_timeout = stdt->space_timeout;
			mtdt->load_timeout = stdt->load_timeout;
			mtdt->unload_timeout = stdt->unload_timeout;
			mtdt->erase_timeout = stdt->erase_timeout;

			/*
			 * Limit the maximum length of the result to
			 * sizeof (struct mtdrivetype).
			 */
			tmp = sizeof (struct mtdrivetype);
			if (mtdtrq.size < tmp)
				tmp = mtdtrq.size;
			if (ddi_copyout(mtdt, mtdtrq.mtdtp, tmp, flag)) {
				rval = EFAULT;
			}
			break;
		}
	case MTIOCPERSISTENT:

		if (ddi_copyin((void *)arg, &tmp, sizeof (tmp), flag)) {
			rval = EFAULT;
			break;
		}

		if (tmp) {
			st_turn_pe_on(un);
		} else {
			st_turn_pe_off(un);
		}

		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl: MTIOCPERSISTENT : persistence = %d\n",
		    un->un_persistence);

		break;

	case MTIOCPERSISTENTSTATUS:
		tmp = (int)un->un_persistence;

		if (ddi_copyout(&tmp, (void *)arg, sizeof (tmp), flag)) {
			rval = EFAULT;
		}
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl: MTIOCPERSISTENTSTATUS:persistence = %d\n",
		    un->un_persistence);

		break;

	case MTIOCLRERR:
		{
			/* clear persistent errors */

			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl: MTIOCLRERR\n");

			st_clear_pe(un);

			break;
		}

	case MTIOCGUARANTEEDORDER:
		{
			/*
			 * this is just a holder to make a valid ioctl and
			 * it won't be in any earlier release
			 */
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl: MTIOCGUARANTEEDORDER\n");

			break;
		}

	case MTIOCRESERVE:
		{
			ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl: MTIOCRESERVE\n");

			/*
			 * Check if Reserve/Release is supported.
			 */
			if (un->un_dp->options & ST_NO_RESERVE_RELEASE) {
				rval = ENOTTY;
				break;
			}

			rval = st_reserve_release(un, ST_RESERVE, st_uscsi_cmd);

			if (rval == 0) {
				un->un_rsvd_status |= ST_PRESERVE_RESERVE;
			}
			break;
		}

	case MTIOCRELEASE:
		{
			ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl: MTIOCRELEASE\n");

			/*
			 * Check if Reserve/Release is supported.
			 */
			if (un->un_dp->options & ST_NO_RESERVE_RELEASE) {
				rval = ENOTTY;
				break;
			}

			/*
			 * Used to just clear ST_PRESERVE_RESERVE which
			 * made the reservation release at next close.
			 * As the user may have opened and then done a
			 * persistant reservation we now need to drop
			 * the reservation without closing if the user
			 * attempts to do this.
			 */
			rval = st_reserve_release(un, ST_RELEASE, st_uscsi_cmd);

			un->un_rsvd_status &= ~ST_PRESERVE_RESERVE;

			break;
		}

	case MTIOCFORCERESERVE:
	{
		ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl: MTIOCFORCERESERVE\n");

		/*
		 * Check if Reserve/Release is supported.
		 */
		if (un->un_dp->options & ST_NO_RESERVE_RELEASE) {
			rval = ENOTTY;
			break;
		}
		/*
		 * allow only super user to run this.
		 */
		if (drv_priv(cred_p) != 0) {
			rval = EPERM;
			break;
		}
		/*
		 * Throw away reserve,
		 * not using test-unit-ready
		 * since reserve can succeed without tape being
		 * present in the drive.
		 */
		(void) st_reserve_release(un, ST_RESERVE, st_uscsi_cmd);

		rval = st_take_ownership(un, st_uscsi_cmd);

		break;
	}

	case USCSICMD:
	{
		cred_t	*cr;

		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl: USCSICMD\n");

		cr = ddi_get_cred();
		if ((drv_priv(cred_p) != 0) && (drv_priv(cr) != 0)) {
			rval = EPERM;
		} else {
			rval = st_uscsi_cmd(un, (struct uscsi_cmd *)arg, flag);
		}
		break;
	}
	case MTIOCTOP:
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl: MTIOCTOP\n");
		rval = st_mtioctop(un, arg, flag);
		break;

	case MTIOCLTOP:
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl: MTIOLCTOP\n");
		rval = st_mtiocltop(un, arg, flag);
		break;

	case MTIOCREADIGNOREILI:
		{
			int set_ili;

			if (ddi_copyin((void *)arg, &set_ili,
			    sizeof (set_ili), flag)) {
				rval = EFAULT;
				break;
			}

			if (un->un_bsize) {
				rval = ENOTTY;
				break;
			}

			switch (set_ili) {
			case 0:
				un->un_dp->options &= ~ST_READ_IGNORE_ILI;
				break;

			case 1:
				un->un_dp->options |= ST_READ_IGNORE_ILI;
				break;

			default:
				rval = EINVAL;
				break;
			}
			break;
		}

	case MTIOCREADIGNOREEOFS:
		{
			int ignore_eof;

			if (ddi_copyin((void *)arg, &ignore_eof,
			    sizeof (ignore_eof), flag)) {
				rval = EFAULT;
				break;
			}

			if (!(un->un_dp->options & ST_REEL)) {
				rval = ENOTTY;
				break;
			}

			switch (ignore_eof) {
			case 0:
				un->un_dp->options &= ~ST_READ_IGNORE_EOFS;
				break;

			case 1:
				un->un_dp->options |= ST_READ_IGNORE_EOFS;
				break;

			default:
				rval = EINVAL;
				break;
			}
			break;
		}

	case MTIOCSHORTFMK:
	{
		int short_fmk;

		if (ddi_copyin((void *)arg, &short_fmk,
		    sizeof (short_fmk), flag)) {
			rval = EFAULT;
			break;
		}

		switch (un->un_dp->type) {
		case ST_TYPE_EXB8500:
		case ST_TYPE_EXABYTE:
			if (!short_fmk) {
				un->un_dp->options &= ~ST_SHORT_FILEMARKS;
			} else if (short_fmk == 1) {
				un->un_dp->options |= ST_SHORT_FILEMARKS;
			} else {
				rval = EINVAL;
			}
			break;

		default:
			rval = ENOTTY;
			break;
		}
		break;
	}

	case MTIOCGETPOS:
		rval = st_update_block_pos(un, st_cmd, 0);
		if (rval == 0) {
			if (ddi_copyout((void *)&un->un_pos, (void *)arg,
			    sizeof (tapepos_t), flag)) {
				scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "MTIOCGETPOS copy out failed\n");
				rval = EFAULT;
			}
		}
		break;

	case MTIOCRESTPOS:
	{
		tapepos_t dest;

		if (ddi_copyin((void *)arg, &dest, sizeof (tapepos_t),
		    flag) != 0) {
			scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "MTIOCRESTPOS copy in failed\n");
			rval = EFAULT;
			break;
		}
		rval = st_validate_tapemarks(un, st_uscsi_cmd, &dest);
		if (rval != 0) {
			rval = EIO;
		}
		break;
	}
	default:
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl: unknown ioctl\n");
		rval = ENOTTY;
	}

exit:
	if (!(un->un_persistence && un->un_persist_errors)) {
		un->un_errno = rval;
	}

	mutex_exit(ST_MUTEX);

	return (rval);
}


/*
 * do some MTIOCTOP tape operations
 */
static int
st_mtioctop(struct scsi_tape *un, intptr_t arg, int flag)
{
#ifdef _MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl
	 */
	struct mtop32	mtop_32_for_64;
#endif /* _MULTI_DATAMODEL */
	struct mtop passed;
	struct mtlop local;
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_mtioctop);

	ASSERT(mutex_owned(ST_MUTEX));

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, &mtop_32_for_64,
		    sizeof (struct mtop32), flag)) {
			return (EFAULT);
		}
		local.mt_op = mtop_32_for_64.mt_op;
		local.mt_count =  (int64_t)mtop_32_for_64.mt_count;
		break;

	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &passed, sizeof (passed), flag)) {
			return (EFAULT);
		}
		local.mt_op = passed.mt_op;
		/* prevent sign extention */
		local.mt_count = (UINT32_MAX & passed.mt_count);
		break;
	}

#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &passed, sizeof (passed), flag)) {
		return (EFAULT);
	}
	local.mt_op = passed.mt_op;
	/* prevent sign extention */
	local.mt_count = (UINT32_MAX & passed.mt_count);
#endif /* _MULTI_DATAMODEL */

	rval = st_do_mtioctop(un, &local);

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (((uint64_t)local.mt_count) > UINT32_MAX) {
			rval = ERANGE;
			break;
		}
		/*
		 * Convert 64 bit back to 32 bit before doing
		 * copyout. This is what the ILP32 app expects.
		 */
		mtop_32_for_64.mt_op = local.mt_op;
		mtop_32_for_64.mt_count = local.mt_count;

		if (ddi_copyout(&mtop_32_for_64, (void *)arg,
		    sizeof (struct mtop32), flag)) {
			rval = EFAULT;
		}
		break;

	case DDI_MODEL_NONE:
		passed.mt_count = local.mt_count;
		passed.mt_op = local.mt_op;
		if (ddi_copyout(&passed, (void *)arg, sizeof (passed), flag)) {
			rval = EFAULT;
		}
		break;
	}
#else /* ! _MULTI_DATAMODE */
	if (((uint64_t)local.mt_count) > UINT32_MAX) {
		rval = ERANGE;
	} else {
		passed.mt_op = local.mt_op;
		passed.mt_count = local.mt_count;
		if (ddi_copyout(&passed, (void *)arg, sizeof (passed), flag)) {
			rval = EFAULT;
		}
	}
#endif /* _MULTI_DATAMODE */


	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_ioctl: fileno=%x, blkno=%x, eof=%x\n", un->un_pos.fileno,
	    un->un_pos.blkno, un->un_pos.eof);

	if (un->un_pos.pmode == invalid) {
		un->un_density_known = 0;
	}

	ASSERT(mutex_owned(ST_MUTEX));
	return (rval);
}

static int
st_mtiocltop(struct scsi_tape *un, intptr_t arg, int flag)
{
	struct mtlop local;
	int rval;

	ST_FUNC(ST_DEVINFO, st_mtiocltop);
	if (ddi_copyin((void *)arg, &local, sizeof (local), flag)) {
		return (EFAULT);
	}

	rval = st_do_mtioctop(un, &local);

	if (ddi_copyout(&local, (void *)arg, sizeof (local), flag)) {
		rval = EFAULT;
	}
	return (rval);
}


static int
st_do_mtioctop(struct scsi_tape *un, struct mtlop *mtop)
{
	dev_t dev = un->un_dev;
	int savefile;
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_do_mtioctop);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_do_mtioctop(): mt_op=%x\n", mtop->mt_op);
	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "fileno=%x, blkno=%x, eof=%x\n",
	    un->un_pos.fileno, un->un_pos.blkno, un->un_pos.eof);

	un->un_status = 0;

	/*
	 * if we are going to mess with a tape, we have to make sure we have
	 * one and are not offline (i.e. no tape is initialized).  We let
	 * commands pass here that don't actually touch the tape, except for
	 * loading and initialization (rewinding).
	 */
	if (un->un_state == ST_STATE_OFFLINE) {
		switch (mtop->mt_op) {
		case MTLOAD:
		case MTNOP:
			/*
			 * We don't want strategy calling st_tape_init here,
			 * so, change state
			 */
			un->un_state = ST_STATE_INITIALIZING;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : OFFLINE state = %d\n",
			    un->un_state);
			break;
		default:
			/*
			 * reinitialize by normal means
			 */
			rval = st_tape_init(un);
			if (rval) {
				un->un_state = ST_STATE_INITIALIZING;
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_do_mtioctop : OFFLINE init failure ");
				un->un_state = ST_STATE_OFFLINE;
				un->un_pos.pmode = invalid;
				if (rval != EACCES) {
					rval = EIO;
				}
				return (rval);
			}
			un->un_state = ST_STATE_OPEN_PENDING_IO;
			break;
		}
	}

	/*
	 * If the file position is invalid, allow only those
	 * commands that properly position the tape and fail
	 * the rest with EIO
	 */
	if (un->un_pos.pmode == invalid) {
		switch (mtop->mt_op) {
		case MTWEOF:
		case MTRETEN:
		case MTERASE:
		case MTEOM:
		case MTFSF:
		case MTFSR:
		case MTBSF:
		case MTNBSF:
		case MTBSR:
		case MTSRSZ:
		case MTGRSZ:
		case MTSEEK:
		case MTBSSF:
		case MTFSSF:
			return (EIO);
			/* NOTREACHED */
		case MTREW:
		case MTLOAD:
		case MTOFFL:
		case MTNOP:
		case MTTELL:
		case MTLOCK:
		case MTUNLOCK:
			break;

		default:
			return (ENOTTY);
			/* NOTREACHED */
		}
	}

	switch (mtop->mt_op) {
	case MTERASE:
		/*
		 * MTERASE rewinds the tape, erase it completely, and returns
		 * to the beginning of the tape
		 */
		if (un->un_mspl->wp || un->un_read_only & WORM) {
			un->un_status = KEY_WRITE_PROTECT;
			un->un_err_resid = mtop->mt_count;
			COPY_POS(&un->un_err_pos, &un->un_pos);
			return (EACCES);
		}
		if (un->un_dp->options & ST_REEL) {
			un->un_fmneeded = 2;
		} else {
			un->un_fmneeded = 1;
		}
		mtop->mt_count = mtop->mt_count ? 1 : 0;
		if (st_check_density_or_wfm(dev, 1, B_WRITE, NO_STEPBACK) ||
		    st_cmd(un, SCMD_REWIND, 0, SYNC_CMD) ||
		    st_cmd(un, SCMD_ERASE, mtop->mt_count, SYNC_CMD)) {
			un->un_pos.pmode = invalid;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO space or erase or "
			    "check den)\n");
			rval = EIO;
		} else {
			/* QIC and helical scan rewind after erase */
			if (un->un_dp->options & ST_REEL) {
				(void) st_cmd(un, SCMD_REWIND, 0, ASYNC_CMD);
			}
		}
		break;

	case MTWEOF:
		/*
		 * write an end-of-file record
		 */
		if (un->un_mspl->wp || un->un_read_only & RDONLY) {
			un->un_status = KEY_WRITE_PROTECT;
			un->un_err_resid = mtop->mt_count;
			COPY_POS(&un->un_err_pos, &un->un_pos);
			return (EACCES);
		}

		/*
		 * zero count means just flush buffers
		 * negative count is not permitted
		 */
		if (mtop->mt_count < 0) {
			return (EINVAL);
		}

		/* Not on worm */
		if (un->un_read_only == RDWR) {
			un->un_test_append = 1;
		}

		if (un->un_state == ST_STATE_OPEN_PENDING_IO) {
			if (st_determine_density(un, B_WRITE)) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_do_mtioctop : EIO : MTWEOF can't "
				    "determine density");
				return (EIO);
			}
		}

		rval = st_write_fm(dev, (int)mtop->mt_count);
		if ((rval != 0) && (rval != EACCES)) {
			/*
			 * Failure due to something other than illegal
			 * request results in loss of state (st_intr).
			 */
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO : MTWEOF can't write "
			    "file mark");
			rval = EIO;
		}
		break;

	case MTRETEN:
		/*
		 * retension the tape
		 */
		if (st_check_density_or_wfm(dev, 1, 0, NO_STEPBACK) ||
		    st_cmd(un, SCMD_LOAD, LD_LOAD | LD_RETEN, SYNC_CMD)) {
			un->un_pos.pmode = invalid;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO : MTRETEN ");
			rval = EIO;
		}
		break;

	case MTREW:
		/*
		 * rewind  the tape
		 */
		if (st_check_density_or_wfm(dev, 1, 0, NO_STEPBACK)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO:MTREW check "
			    "density/wfm failed");
			return (EIO);
		}
		if (st_cmd(un, SCMD_REWIND, 0, SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO : MTREW ");
			rval = EIO;
		}
		break;

	case MTOFFL:
		/*
		 * rewinds, and, if appropriate, takes the device offline by
		 * unloading the tape
		 */
		if (st_check_density_or_wfm(dev, 1, 0, NO_STEPBACK)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop :EIO:MTOFFL check "
			    "density/wfm failed");
			return (EIO);
		}
		(void) st_cmd(un, SCMD_REWIND, 0, SYNC_CMD);
		if (st_cmd(un, SCMD_LOAD, LD_UNLOAD, SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO : MTOFFL");
			return (EIO);
		}
		un->un_pos.eof = ST_NO_EOF;
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_OFFLINE;
		un->un_mediastate = MTIO_EJECTED;
		break;

	case MTLOAD:
		/*
		 * This is to load a tape into the drive
		 * Note that if the tape is not loaded, the device will have
		 * to be opened via O_NDELAY or O_NONBLOCK.
		 */
		/*
		 * Let's try and clean things up, if we are not
		 * initializing, and then send in the load command, no
		 * matter what.
		 *
		 * load after a media change by the user.
		 */

		if (un->un_state > ST_STATE_INITIALIZING) {
			(void) st_check_density_or_wfm(dev, 1, 0, NO_STEPBACK);
		}
		rval = st_cmd(un, SCMD_LOAD, LD_LOAD, SYNC_CMD);
		/* Load command to a drive that doesn't support load */
		if ((rval == EIO) &&
		    ((un->un_status == KEY_NOT_READY) &&
			/* Medium not present */
		    (un->un_uscsi_rqs_buf->es_add_code == 0x3a) ||
		    ((un->un_status == KEY_ILLEGAL_REQUEST) &&
		    (un->un_dp->type == MT_ISSTK9840) &&
			/* CSL not present */
		    (un->un_uscsi_rqs_buf->es_add_code == 0x80)))) {
			rval = ENOTTY;
			break;
		} else if (rval != EACCES && rval != 0) {
			rval = EIO;
		}
		if (rval) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : %s : MTLOAD\n",
			    rval == EACCES ? "EACCES" : "EIO");
			/*
			 * If load tape fails, who knows what happened...
			 */
			un->un_pos.pmode = invalid;
			break;
		}

		/*
		 * reset all counters appropriately using rewind, as if LOAD
		 * succeeds, we are at BOT
		 */
		un->un_state = ST_STATE_INITIALIZING;

		rval = st_tape_init(un);
		if ((rval == EACCES) && (un->un_read_only & WORM)) {
			rval = 0;
			break;
		}

		if (rval != 0) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO : MTLOAD calls "
			    "st_tape_init\n");
			rval = EIO;
			un->un_state = ST_STATE_OFFLINE;
		}

		break;

	case MTNOP:
		un->un_status = 0;		/* Reset status */
		un->un_err_resid = 0;
		mtop->mt_count = MTUNIT(dev);
		break;

	case MTEOM:
		/*
		 * positions the tape at a location just after the last file
		 * written on the tape. For cartridge and 8 mm, this after
		 * the last file mark; for reel, this is inbetween the two
		 * last 2 file marks
		 */
		if ((un->un_pos.pmode == legacy && un->un_pos.eof >= ST_EOT) ||
		    (un->un_lastop == ST_OP_WRITE) ||
		    (un->un_lastop == ST_OP_WEOF)) {
			/*
			 * If the command wants to move to logical end
			 * of media, and we're already there, we're done.
			 * If we were at logical eot, we reset the state
			 * to be *not* at logical eot.
			 *
			 * If we're at physical or logical eot, we prohibit
			 * forward space operations (unconditionally).
			 *
			 * Also if the last operation was a write of any
			 * kind the tape is at EOD.
			 */
			return (0);
		}
		/*
		 * physical tape position may not be what we've been
		 * telling the user; adjust the request accordingly
		 */
		if (IN_EOF(un->un_pos)) {
			un->un_pos.fileno++;
			un->un_pos.blkno = 0;
		}

		if (st_check_density_or_wfm(dev, 1, B_READ, NO_STEPBACK)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO:MTEOM check density/wfm "
			    " failed");
			return (EIO);
		}

		/*
		 * st_find_eod() returns the last fileno we knew about;
		 */
		savefile = st_find_eod(un);

		if ((un->un_status != KEY_BLANK_CHECK) &&
		    (un->un_status != SUN_KEY_EOT)) {
			un->un_pos.pmode = invalid;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO : MTEOM status check failed");
			rval = EIO;
		} else {
			/*
			 * For 1/2" reel tapes assume logical EOT marked
			 * by two file marks or we don't care that we may
			 * be extending the last file on the tape.
			 */
			if (un->un_dp->options & ST_REEL) {
				if (st_cmd(un, SCMD_SPACE, Fmk(-1), SYNC_CMD)) {
					un->un_pos.pmode = invalid;
					ST_DEBUG2(ST_DEVINFO, st_label,
					    SCSI_DEBUG,
					    "st_do_mtioctop : EIO : MTEOM space"
					    " cmd failed");
					rval = EIO;
					break;
				}
				/*
				 * Fix up the block number.
				 */
				un->un_pos.blkno = 0;
				un->un_err_pos.blkno = 0;
			}
			un->un_err_resid = 0;
			un->un_pos.fileno = savefile;
			un->un_pos.eof = ST_EOT;
		}
		un->un_status = 0;
		break;

	case MTFSF:
		MAX_SPACE_CNT(mtop->mt_count);
		rval = st_mtfsf_ioctl(un, mtop->mt_count);
		break;

	case MTFSR:
		MAX_SPACE_CNT(mtop->mt_count);
		rval = st_mtfsr_ioctl(un, mtop->mt_count);
		break;

	case MTBSF:
		MAX_SPACE_CNT(mtop->mt_count);
		rval = st_mtbsf_ioctl(un, mtop->mt_count);
		break;

	case MTNBSF:
		MAX_SPACE_CNT(mtop->mt_count);
		rval = st_mtnbsf_ioctl(un, mtop->mt_count);
		break;

	case MTBSR:
		MAX_SPACE_CNT(mtop->mt_count);
		rval = st_mtbsr_ioctl(un, mtop->mt_count);
		break;

	case MTBSSF:
		MAX_SPACE_CNT(mtop->mt_count);
		rval = st_mtbsfm_ioctl(un, mtop->mt_count);
		break;

	case MTFSSF:
		MAX_SPACE_CNT(mtop->mt_count);
		rval = st_mtfsfm_ioctl(un, mtop->mt_count);
		break;

	case MTSRSZ:

		/*
		 * Set record-size to that sent by user
		 * Check to see if there is reason that the requested
		 * block size should not be set.
		 */

		/* If requesting variable block size is it ok? */
		if ((mtop->mt_count == 0) &&
		    ((un->un_dp->options & ST_VARIABLE) == 0)) {
			return (ENOTTY);
		}

		/*
		 * If requested block size is not variable "0",
		 * is it less then minimum.
		 */
		if ((mtop->mt_count != 0) &&
		    (mtop->mt_count < un->un_minbsize)) {
			return (EINVAL);
		}

		/* Is the requested block size more then maximum */
		if ((mtop->mt_count > min(un->un_maxbsize, un->un_maxdma)) &&
		    (un->un_maxbsize != 0)) {
			return (EINVAL);
		}

		/* Is requested block size a modulus the device likes */
		if ((mtop->mt_count % un->un_data_mod) != 0) {
			return (EINVAL);
		}

		if (st_change_block_size(un, (uint32_t)mtop->mt_count) != 0) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl : MTSRSZ : EIO : cant set block size");
			return (EIO);
		}

		return (0);

	case MTGRSZ:
		/*
		 * Get record-size to the user
		 */
		mtop->mt_count = un->un_bsize;
		rval = 0;
		break;

	case MTTELL:
		rval = st_update_block_pos(un, st_cmd, 0);
		mtop->mt_count = un->un_pos.lgclblkno;
		break;

	case MTSEEK:
		rval = st_logical_block_locate(un, st_uscsi_cmd, &un->un_pos,
		    (uint64_t)mtop->mt_count, un->un_pos.partition);
		/*
		 * This bit of magic make mt print the actual position if
		 * the resulting position was not what was asked for.
		 */
		if (rval == ESPIPE) {
			rval = EIO;
			if ((uint64_t)mtop->mt_count != un->un_pos.lgclblkno) {
				mtop->mt_op = MTTELL;
				mtop->mt_count = un->un_pos.lgclblkno;
			}
		}
		break;

	case MTLOCK:
		if (st_cmd(un, SCMD_DOORLOCK, MR_LOCK, SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO : MTLOCK");
			rval = EIO;
		}
		break;

	case MTUNLOCK:
		if (st_cmd(un, SCMD_DOORLOCK, MR_UNLOCK, SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_do_mtioctop : EIO : MTUNLOCK");
			rval = EIO;
		}
		break;

	default:
		rval = ENOTTY;
	}

	return (rval);
}


/*
 * Run a command for uscsi ioctl.
 */
static int
st_uscsi_cmd(struct scsi_tape *un, struct uscsi_cmd *ucmd, int flag)
{
	struct uscsi_cmd	*uscmd;
	struct buf	*bp;
	enum uio_seg	uioseg;
	int	offline_state = 0;
	int	err = 0;
	dev_t dev = un->un_dev;

	ST_FUNC(ST_DEVINFO, st_uscsi_cmd);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_uscsi_cmd(dev = 0x%lx)\n", un->un_dev);

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * We really don't know what commands are coming in here and
	 * we don't want to limit the commands coming in.
	 *
	 * If st_tape_init() gets called from st_strategy(), then we
	 * will hang the process waiting for un->un_sbuf_busy to be cleared,
	 * which it never will, as we set it below.  To prevent
	 * st_tape_init() from getting called, we have to set state to other
	 * than ST_STATE_OFFLINE, so we choose ST_STATE_INITIALIZING, which
	 * achieves this purpose already.
	 *
	 * We use offline_state to preserve the OFFLINE state, if it exists,
	 * so other entry points to the driver might have the chance to call
	 * st_tape_init().
	 */
	if (un->un_state == ST_STATE_OFFLINE) {
		un->un_laststate = ST_STATE_OFFLINE;
		un->un_state = ST_STATE_INITIALIZING;
		offline_state = 1;
	}

	mutex_exit(ST_MUTEX);
	err = scsi_uscsi_alloc_and_copyin((intptr_t)ucmd, flag, ROUTE, &uscmd);
	mutex_enter(ST_MUTEX);
	if (err != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_uscsi_cmd: scsi_uscsi_alloc_and_copyin failed\n");
		goto exit;
	}

	uioseg = (flag & FKIOCTL) ? UIO_SYSSPACE : UIO_USERSPACE;

	/* check to see if this command requires the drive to be reserved */
	if (uscmd->uscsi_cdb != NULL) {
		err = st_check_cdb_for_need_to_reserve(un,
		    (uchar_t *)uscmd->uscsi_cdb);
		if (err) {
			goto exit_free;
		}
		/*
		 * If this is a space command we need to save the starting
		 * point so we can retry from there if the command fails.
		 */
		if ((uscmd->uscsi_cdb[0] == SCMD_SPACE) ||
		    (uscmd->uscsi_cdb[0] == (char)SCMD_SPACE_G4)) {
			(void) st_update_block_pos(un, st_cmd, 0);
		}
	}

	/*
	 * Forground should not be doing anything while recovery is active.
	 */
	ASSERT(un->un_recov_buf_busy == 0);

	/*
	 * Get buffer resources...
	 */
	while (un->un_sbuf_busy)
		cv_wait(&un->un_sbuf_cv, ST_MUTEX);
	un->un_sbuf_busy = 1;

#ifdef STDEBUG
	if ((uscmd->uscsi_cdb != NULL) && (st_debug & 0x7) > 6) {
		int rw = (uscmd->uscsi_flags & USCSI_READ) ? B_READ : B_WRITE;
		st_print_cdb(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "uscsi cdb", uscmd->uscsi_cdb);
		if (uscmd->uscsi_buflen) {
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "uscsi %s of %ld bytes %s %s space\n",
			    (rw == B_READ) ? rd_str : wr_str,
			    uscmd->uscsi_buflen,
			    (rw == B_READ) ? "to" : "from",
			    (uioseg == UIO_SYSSPACE) ? "system" : "user");
		}
	}
#endif /* STDEBUG */

	/*
	 * Although st_uscsi_cmd() never makes use of these
	 * now, we are just being safe and consistent.
	 */
	uscmd->uscsi_flags &= ~(USCSI_NOINTR | USCSI_NOPARITY |
	    USCSI_OTAG | USCSI_HTAG | USCSI_HEAD);

	un->un_srqbufp = uscmd->uscsi_rqbuf;
	bp = un->un_sbufp;
	bzero(bp, sizeof (buf_t));
	if (uscmd->uscsi_cdb != NULL) {
		bp->b_forw = (struct buf *)(uintptr_t)uscmd->uscsi_cdb[0];
	}
	bp->b_back = (struct buf *)uscmd;

	mutex_exit(ST_MUTEX);
	err = scsi_uscsi_handle_cmd(dev, uioseg, uscmd, st_strategy, bp, NULL);
	mutex_enter(ST_MUTEX);

	/*
	 * If scsi reset successful, don't write any filemarks.
	 */
	if ((err == 0) && (uscmd->uscsi_flags &
	    (USCSI_RESET_LUN | USCSI_RESET_TARGET | USCSI_RESET_ALL))) {
		un->un_fmneeded = 0;
	}

exit_free:
	/*
	 * Free resources
	 */
	un->un_sbuf_busy = 0;
	un->un_srqbufp = NULL;

	/*
	 * If was a space command need to update logical block position.
	 * If the command failed such that positioning is invalid, Don't
	 * update the position as the user must do this to validate the
	 * position for data protection.
	 */
	if ((uscmd->uscsi_cdb != NULL) &&
	    ((uscmd->uscsi_cdb[0] == SCMD_SPACE) ||
	    (uscmd->uscsi_cdb[0] == (char)SCMD_SPACE_G4)) &&
	    (un->un_pos.pmode != invalid)) {
		un->un_running.pmode = invalid;
		(void) st_update_block_pos(un, st_cmd, 1);
		/*
		 * Set running position to invalid so it updates on the
		 * next command.
		 */
		un->un_running.pmode = invalid;
	}
	cv_signal(&un->un_sbuf_cv);
	mutex_exit(ST_MUTEX);
	(void) scsi_uscsi_copyout_and_free((intptr_t)ucmd, uscmd);
	mutex_enter(ST_MUTEX);
	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_uscsi_cmd returns 0x%x\n", err);

exit:
	/* don't lose offline state */
	if (offline_state) {
		un->un_state = ST_STATE_OFFLINE;
	}

	ASSERT(mutex_owned(ST_MUTEX));
	return (err);
}

static int
st_write_fm(dev_t dev, int wfm)
{
	int i;
	int rval;

	GET_SOFT_STATE(dev);

	ST_FUNC(ST_DEVINFO, st_write_fm);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_write_fm(dev = 0x%lx, wfm = %d)\n", dev, wfm);

	/*
	 * write one filemark at the time after EOT
	 */
	if (un->un_pos.eof >= ST_EOT) {
		for (i = 0; i < wfm; i++) {
			rval = st_cmd(un, SCMD_WRITE_FILE_MARK, 1, SYNC_CMD);
			if (rval == EACCES) {
				return (rval);
			}
			if (rval != 0) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_write_fm : EIO : write EOT file mark");
				return (EIO);
			}
		}
	} else {
		rval = st_cmd(un, SCMD_WRITE_FILE_MARK, wfm, SYNC_CMD);
		if (rval == EACCES) {
			return (rval);
		}
		if (rval) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_write_fm : EIO : write file mark");
			return (EIO);
		}
	}

	ASSERT(mutex_owned(ST_MUTEX));
	return (0);
}

#ifdef STDEBUG
static void
st_start_dump(struct scsi_tape *un, struct buf *bp)
{
	struct scsi_pkt *pkt = BP_PKT(bp);
	uchar_t *cdbp = (uchar_t *)pkt->pkt_cdbp;

	ST_FUNC(ST_DEVINFO, st_start_dump);

	if ((st_debug & 0x7) < 6)
		return;
	scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_start: cmd=0x%p count=%ld resid=%ld flags=0x%x pkt=0x%p\n",
	    (void *)bp->b_forw, bp->b_bcount,
	    bp->b_resid, bp->b_flags, (void *)BP_PKT(bp));
	st_print_cdb(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_start: cdb",  (caddr_t)cdbp);
	scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_start: fileno=%d, blk=%d\n",
	    un->un_pos.fileno, un->un_pos.blkno);
}
#endif


/*
 * Command start && done functions
 */

/*
 * st_start()
 *
 * Called from:
 *  st_strategy() to start a command.
 *  st_runout() to retry when scsi_pkt allocation fails on previous attempt(s).
 *  st_attach() when resuming from power down state.
 *  st_start_restart() to retry transport when device was previously busy.
 *  st_done_and_mutex_exit() to start the next command when previous is done.
 *
 * On entry:
 *  scsi_pkt may or may not be allocated.
 *
 */
static void
st_start(struct scsi_tape *un)
{
	struct buf *bp;
	int status;
	int queued;

	ST_FUNC(ST_DEVINFO, st_start);
	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_start(): dev = 0x%lx\n", un->un_dev);

	if (un->un_recov_buf_busy) {
		/* recovery commands can happen anytime */
		bp = un->un_recov_buf;
		queued = 0;
	} else if (un->un_sbuf_busy) {
		/* sbuf commands should only happen with an empty queue. */
		ASSERT(un->un_quef == NULL);
		ASSERT(un->un_runqf == NULL);
		bp = un->un_sbufp;
		queued = 0;
	} else if (un->un_quef != NULL) {
		if (un->un_persistence && un->un_persist_errors) {
			return;
		}
		bp = un->un_quef;
		queued = 1;
	} else {
		scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_start() returning no buf found\n");
		return;
	}

	ASSERT((bp->b_flags & B_DONE) == 0);

	/*
	 * Don't send more than un_throttle commands to the HBA
	 */
	if ((un->un_throttle <= 0) || (un->un_ncmds >= un->un_throttle)) {
		/*
		 * if doing recovery we know there is outstanding commands.
		 */
		if (bp != un->un_recov_buf) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_start returning throttle = %d or ncmds = %d\n",
			    un->un_throttle, un->un_ncmds);
			if (un->un_ncmds == 0) {
				typedef void (*func)();
				func fnc = (func)st_runout;

				scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "Sending delayed start to st_runout()\n");
				mutex_exit(ST_MUTEX);
				(void) timeout(fnc, un, drv_usectohz(1000000));
				mutex_enter(ST_MUTEX);
			}
			return;
		}
	}

	/*
	 * If the buf has no scsi_pkt call st_make_cmd() to get one and
	 * build the command.
	 */
	if (BP_PKT(bp) == NULL) {
		ASSERT((bp->b_flags & B_DONE) == 0);
		st_make_cmd(un, bp, st_runout);
		ASSERT((bp->b_flags & B_DONE) == 0);
		status = geterror(bp);

		/*
		 * Some HBA's don't call bioerror() to set an error.
		 * And geterror() returns zero if B_ERROR is not set.
		 * So if we get zero we must check b_error.
		 */
		if (status == 0 && bp->b_error != 0) {
			status = bp->b_error;
			bioerror(bp, status);
		}

		/*
		 * Some HBA's convert DDI_DMA_NORESOURCES into ENOMEM.
		 * In tape ENOMEM has special meaning so we'll change it.
		 */
		if (status == ENOMEM) {
			status = 0;
			bioerror(bp, status);
		}

		/*
		 * Did it fail and is it retryable?
		 * If so return and wait for the callback through st_runout.
		 * Also looks like scsi_init_pkt() will setup a callback even
		 * if it isn't retryable.
		 */
		if (BP_PKT(bp) == NULL) {
			if (status == 0) {
				/*
				 * If first attempt save state.
				 */
				if (un->un_state != ST_STATE_RESOURCE_WAIT) {
					un->un_laststate = un->un_state;
					un->un_state = ST_STATE_RESOURCE_WAIT;
				}
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "temp no resources for pkt\n");
			} else if (status == EINVAL) {
				scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "scsi_init_pkt rejected pkt as too big\n");
				if (un->un_persistence) {
					st_set_pe_flag(un);
				}
			} else {
				/*
				 * Unlikely that it would be retryable then not.
				 */
				if (un->un_state == ST_STATE_RESOURCE_WAIT) {
					un->un_state = un->un_laststate;
				}
				scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "perm no resources for pkt errno = 0x%x\n",
				    status);
			}
			return;
		}
		/*
		 * Worked this time set the state back.
		 */
		if (un->un_state == ST_STATE_RESOURCE_WAIT) {
			un->un_state = un->un_laststate;
		}
	}

	if (queued) {
		/*
		 * move from waitq to runq
		 */
		(void) st_remove_from_queue(&un->un_quef, &un->un_quel, bp);
		st_add_to_queue(&un->un_runqf, &un->un_runql, un->un_runql, bp);
	}


#ifdef STDEBUG
	st_start_dump(un, bp);
#endif

	/* could not get here if throttle was zero */
	un->un_last_throttle = un->un_throttle;
	un->un_throttle = 0;	/* so nothing else will come in here */
	un->un_ncmds++;

	ST_DO_KSTATS(bp, kstat_waitq_to_runq);

	status = st_transport(un, BP_PKT(bp));

	if (un->un_last_throttle) {
		un->un_throttle = un->un_last_throttle;
	}

	if (status != TRAN_ACCEPT) {
		ST_DO_KSTATS(bp, kstat_runq_back_to_waitq);
		ST_DEBUG(ST_DEVINFO, st_label, CE_WARN,
		    "Unhappy transport packet status 0x%x\n", status);

		if (status == TRAN_BUSY) {
			pkt_info *pkti = BP_PKT(bp)->pkt_private;

			/*
			 * If command recovery is enabled and this isn't
			 * a recovery command try command recovery.
			 */
			if (pkti->privatelen == sizeof (recov_info) &&
			    bp != un->un_recov_buf) {
				ST_RECOV(ST_DEVINFO, st_label, CE_WARN,
				    "Command Recovery called on busy send\n");
				if (st_command_recovery(un, BP_PKT(bp),
				    ATTEMPT_RETRY) == JUST_RETURN) {
					return;
				}
			} else {
				mutex_exit(ST_MUTEX);
				if (st_handle_start_busy(un, bp,
				    ST_TRAN_BUSY_TIMEOUT, queued) == 0) {
					mutex_enter(ST_MUTEX);
					return;
				}
				/*
				 * if too many retries, fail the transport
				 */
				mutex_enter(ST_MUTEX);
			}
		}
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "transport rejected %d\n", status);
		bp->b_resid = bp->b_bcount;

		ST_DO_KSTATS(bp, kstat_waitq_exit);
		ST_DO_ERRSTATS(un, st_transerrs);
		if ((bp == un->un_recov_buf) && (status == TRAN_BUSY)) {
			st_bioerror(bp, EBUSY);
		} else {
			st_bioerror(bp, EIO);
			st_set_pe_flag(un);
		}
		st_done_and_mutex_exit(un, bp);
		mutex_enter(ST_MUTEX);
	}

	ASSERT(mutex_owned(ST_MUTEX));
}

/*
 * if the transport is busy, then put this bp back on the waitq
 */
static int
st_handle_start_busy(struct scsi_tape *un, struct buf *bp,
    clock_t timeout_interval, int queued)
{

	pkt_info *pktinfo = BP_PKT(bp)->pkt_private;

	ST_FUNC(ST_DEVINFO, st_handle_start_busy);

	mutex_enter(ST_MUTEX);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_handle_start_busy()\n");

	/*
	 * Check to see if we hit the retry timeout and one last check for
	 * making sure this is the last on the runq, if it is not, we have
	 * to fail
	 */
	if ((pktinfo->str_retry_cnt++ > st_retry_count) ||
	    ((queued) && (un->un_runql != bp))) {
		mutex_exit(ST_MUTEX);
		return (-1);
	}

	if (queued) {
		/* put the bp back on the waitq */
		st_add_to_queue(&un->un_quef, &un->un_quel, un->un_quef, bp);
	}

	/*
	 * Decrement un_ncmds so that this
	 * gets thru' st_start() again.
	 */
	un->un_ncmds--;

	if (queued) {
		/*
		 * since this is an error case, we won't have to do this list
		 * walking much. We've already made sure this bp was the
		 * last on the runq
		 */
		(void) st_remove_from_queue(&un->un_runqf, &un->un_runql, bp);

		/*
		 * send a marker pkt, if appropriate
		 */
		st_hba_unflush(un);

	}
	/*
	 * all queues are aligned, we are just waiting to
	 * transport, don't alloc any more buf p's, when
	 * st_start is reentered.
	 */
	(void) timeout(st_start_restart, un, timeout_interval);

	mutex_exit(ST_MUTEX);
	return (0);
}


/*
 * st_runout a callback that is called what a resource allocatation failed
 */
static int
st_runout(caddr_t arg)
{
	struct scsi_tape *un = (struct scsi_tape *)arg;
	struct buf *bp;
	int queued;

	ASSERT(un != NULL);

	ST_FUNC(ST_DEVINFO, st_runout);

	mutex_enter(ST_MUTEX);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_runout()\n");

	if (un->un_recov_buf_busy != 0) {
		bp = un->un_recov_buf;
		queued = 0;
	} else if (un->un_sbuf_busy != 0) {
		/* sbuf commands should only happen with an empty queue. */
		ASSERT(un->un_quef == NULL);
		ASSERT(un->un_runqf == NULL);
		bp = un->un_sbufp;
		queued = 0;
	} else if (un->un_quef != NULL) {
		bp = un->un_quef;
		if (un->un_persistence && un->un_persist_errors) {
			mutex_exit(ST_MUTEX);
			bp->b_resid = bp->b_bcount;
			biodone(bp);
			return (1);
		}
		queued = 1;
	} else {
		ASSERT(1 == 0);
		mutex_exit(ST_MUTEX);
		return (1);
	}

	/*
	 * failed scsi_init_pkt(). If errno is zero its retryable.
	 */
	if ((bp != NULL) && (geterror(bp) != 0)) {

		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "errors after pkt alloc (b_flags=0x%x, b_error=0x%x)\n",
		    bp->b_flags, geterror(bp));
		ASSERT((bp->b_flags & B_DONE) == 0);

		if (queued) {
			(void) st_remove_from_queue(&un->un_quef, &un->un_quel,
			    bp);
		}
		mutex_exit(ST_MUTEX);

		ASSERT((bp->b_flags & B_DONE) == 0);

		/*
		 * Set resid, Error already set, then unblock calling thread.
		 */
		bp->b_resid = bp->b_bcount;
		biodone(bp);
	} else {
		/*
		 * Try Again
		 */
		st_start(un);
		mutex_exit(ST_MUTEX);
	}

	/*
	 * Comments courtesy of sd.c
	 * The scsi_init_pkt routine allows for the callback function to
	 * return a 0 indicating the callback should be rescheduled or a 1
	 * indicating not to reschedule. This routine always returns 1
	 * because the driver always provides a callback function to
	 * scsi_init_pkt. This results in a callback always being scheduled
	 * (via the scsi_init_pkt callback implementation) if a resource
	 * failure occurs.
	 */

	return (1);
}

/*
 * st_done_and_mutex_exit()
 *	- remove bp from runq
 *	- start up the next request
 *	- if this was an asynch bp, clean up
 *	- exit with released mutex
 */
static void
st_done_and_mutex_exit(struct scsi_tape *un, struct buf *bp)
{
	int pe_flagged = 0;
	struct scsi_pkt *pkt = BP_PKT(bp);
	pkt_info *pktinfo = pkt->pkt_private;

	ASSERT(MUTEX_HELD(&un->un_sd->sd_mutex));
#if !defined(lint)
	_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&un->un_sd->sd_mutex))
#endif

	ST_FUNC(ST_DEVINFO, st_done_and_mutex_exit);

	ASSERT(mutex_owned(ST_MUTEX));

	(void) st_remove_from_queue(&un->un_runqf, &un->un_runql, bp);

	un->un_ncmds--;
	cv_signal(&un->un_queue_cv);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_done_and_mutex_exit(): cmd=0x%x count=%ld resid=%ld  flags="
	    "0x%x\n", pkt->pkt_cdbp[0], bp->b_bcount,
	    bp->b_resid, bp->b_flags);


	/*
	 * update kstats with transfer count info
	 */
	if (un->un_stats && (bp != un->un_sbufp) && IS_RW(bp)) {
		uint32_t n_done =  bp->b_bcount - bp->b_resid;
		if (bp->b_flags & B_READ) {
			IOSP->reads++;
			IOSP->nread += n_done;
		} else {
			IOSP->writes++;
			IOSP->nwritten += n_done;
		}
	}

	/*
	 * Start the next one before releasing resources on this one, if
	 * there is something on the queue and persistent errors has not been
	 * flagged
	 */

	if ((pe_flagged = (un->un_persistence && un->un_persist_errors)) != 0) {
		un->un_last_resid = bp->b_resid;
		un->un_last_count = bp->b_bcount;
	}

	if (un->un_pwr_mgmt == ST_PWR_SUSPENDED) {
		cv_broadcast(&un->un_tape_busy_cv);
	} else if (un->un_quef && un->un_throttle && !pe_flagged &&
	    (bp != un->un_recov_buf)) {
		st_start(un);
	}

	un->un_retry_ct = max(pktinfo->pkt_retry_cnt, pktinfo->str_retry_cnt);

	if (bp == un->un_sbufp && (bp->b_flags & B_ASYNC)) {
		/*
		 * Since we marked this ourselves as ASYNC,
		 * there isn't anybody around waiting for
		 * completion any more.
		 */
		uchar_t *cmd = pkt->pkt_cdbp;
		if (*cmd == SCMD_READ || *cmd == SCMD_WRITE) {
			bp->b_un.b_addr = (caddr_t)0;
		}
		ST_DEBUG(ST_DEVINFO, st_label, CE_NOTE,
		    "st_done_and_mutex_exit(async): freeing pkt\n");
		st_print_cdb(ST_DEVINFO, st_label, CE_NOTE,
		    "CDB sent with B_ASYNC",  (caddr_t)cmd);
		if (pkt) {
			scsi_destroy_pkt(pkt);
		}
		un->un_sbuf_busy = 0;
		cv_signal(&un->un_sbuf_cv);
		mutex_exit(ST_MUTEX);
		return;
	}

	if (bp == un->un_sbufp && BP_UCMD(bp)) {
		/*
		 * Copy status from scsi_pkt to uscsi_cmd
		 * since st_uscsi_cmd needs it
		 */
		BP_UCMD(bp)->uscsi_status = SCBP_C(BP_PKT(bp));
	}


#ifdef STDEBUG
	if (((st_debug & 0x7) >= 4) &&
	    (((un->un_pos.blkno % 100) == 0) ||
	    (un->un_persistence && un->un_persist_errors))) {

		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_d_a_m_exit(): ncmds = %d, thr = %d, "
		    "un_errno = %d, un_pe = %d\n",
		    un->un_ncmds, un->un_throttle, un->un_errno,
		    un->un_persist_errors);
	}

#endif

	mutex_exit(ST_MUTEX);
	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_done_and_mutex_exit: freeing pkt\n");

	if (pkt) {
		scsi_destroy_pkt(pkt);
	}

	biodone(bp);

	/*
	 * now that we biodoned that command, if persistent errors have been
	 * flagged, flush the waitq
	 */
	if (pe_flagged)
		st_flush(un);
}


/*
 * Tape error, flush tape driver queue.
 */
static void
st_flush(struct scsi_tape *un)
{
	struct buf *bp;

	ST_FUNC(ST_DEVINFO, st_flush);

	mutex_enter(ST_MUTEX);

	ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_flush(), ncmds = %d, quef = 0x%p\n",
	    un->un_ncmds, (void *)un->un_quef);

	/*
	 * if we still have commands outstanding, wait for them to come in
	 * before flushing the queue, and make sure there is a queue
	 */
	if (un->un_ncmds || !un->un_quef)
		goto exit;

	/*
	 * we have no more commands outstanding, so let's deal with special
	 * cases in the queue for EOM and FM. If we are here, and un_errno
	 * is 0, then we know there was no error and we return a 0 read or
	 * write before showing errors
	 */

	/* Flush the wait queue. */
	while ((bp = un->un_quef) != NULL) {
		un->un_quef = bp->b_actf;

		bp->b_resid = bp->b_bcount;

		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_flush() : blkno=%d, err=%d, b_bcount=%ld\n",
		    un->un_pos.blkno, un->un_errno, bp->b_bcount);

		st_set_pe_errno(un);

		bioerror(bp, un->un_errno);

		mutex_exit(ST_MUTEX);
		/* it should have one, but check anyway */
		if (BP_PKT(bp)) {
			scsi_destroy_pkt(BP_PKT(bp));
		}
		biodone(bp);
		mutex_enter(ST_MUTEX);
	}

	/*
	 * It's not a bad practice to reset the
	 * waitq tail pointer to NULL.
	 */
	un->un_quel = NULL;

exit:
	/* we mucked with the queue, so let others know about it */
	cv_signal(&un->un_queue_cv);
	mutex_exit(ST_MUTEX);
}


/*
 * Utility functions
 */
static int
st_determine_generic(struct scsi_tape *un)
{
	int bsize;
	static char *cart = "0.25 inch cartridge";
	char *sizestr;

	ST_FUNC(ST_DEVINFO, st_determine_generic);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_determine_generic(un = 0x%p)\n", (void*)un);

	ASSERT(mutex_owned(ST_MUTEX));

	if (st_modesense(un)) {
		return (-1);
	}

	bsize = (un->un_mspl->high_bl << 16)	|
	    (un->un_mspl->mid_bl << 8)	|
	    (un->un_mspl->low_bl);

	if (bsize == 0) {
		un->un_dp->options |= ST_VARIABLE;
		un->un_dp->bsize = 0;
		un->un_bsize = 0;
	} else if (bsize > ST_MAXRECSIZE_FIXED) {
		/*
		 * record size of this device too big.
		 * try and convert it to variable record length.
		 *
		 */
		un->un_dp->options |= ST_VARIABLE;
		if (st_change_block_size(un, 0) != 0) {
			ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
			    "Fixed Record Size %d is too large\n", bsize);
			ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
			    "Cannot switch to variable record size\n");
			un->un_dp->options &= ~ST_VARIABLE;
			return (-1);
		}
	} else if (st_change_block_size(un, 0) == 0) {
		/*
		 * If the drive was set to a non zero block size,
		 * See if it can be set to a zero block size.
		 * If it works, ST_VARIABLE so user can set it as they want.
		 */
		un->un_dp->options |= ST_VARIABLE;
		un->un_dp->bsize = 0;
		un->un_bsize = 0;
	} else {
		un->un_dp->bsize = bsize;
		un->un_bsize = bsize;
	}


	switch (un->un_mspl->density) {
	default:
	case 0x0:
		/*
		 * default density, cannot determine any other
		 * information.
		 */
		sizestr = "Unknown type- assuming 0.25 inch cartridge";
		un->un_dp->type = ST_TYPE_DEFAULT;
		un->un_dp->options |= (ST_AUTODEN_OVERRIDE|ST_QIC);
		break;
	case 0x1:
	case 0x2:
	case 0x3:
	case 0x6:
		/*
		 * 1/2" reel
		 */
		sizestr = "0.50 inch reel";
		un->un_dp->type = ST_TYPE_REEL;
		un->un_dp->options |= ST_REEL;
		un->un_dp->densities[0] = 0x1;
		un->un_dp->densities[1] = 0x2;
		un->un_dp->densities[2] = 0x6;
		un->un_dp->densities[3] = 0x3;
		break;
	case 0x4:
	case 0x5:
	case 0x7:
	case 0x0b:

		/*
		 * Quarter inch.
		 */
		sizestr = cart;
		un->un_dp->type = ST_TYPE_DEFAULT;
		un->un_dp->options |= ST_QIC;

		un->un_dp->densities[1] = 0x4;
		un->un_dp->densities[2] = 0x5;
		un->un_dp->densities[3] = 0x7;
		un->un_dp->densities[0] = 0x0b;
		break;

	case 0x0f:
	case 0x10:
	case 0x11:
	case 0x12:
		/*
		 * QIC-120, QIC-150, QIC-320, QIC-600
		 */
		sizestr = cart;
		un->un_dp->type = ST_TYPE_DEFAULT;
		un->un_dp->options |= ST_QIC;
		un->un_dp->densities[0] = 0x0f;
		un->un_dp->densities[1] = 0x10;
		un->un_dp->densities[2] = 0x11;
		un->un_dp->densities[3] = 0x12;
		break;

	case 0x09:
	case 0x0a:
	case 0x0c:
	case 0x0d:
		/*
		 * 1/2" cartridge tapes. Include HI-TC.
		 */
		sizestr = cart;
		sizestr[2] = '5';
		sizestr[3] = '0';
		un->un_dp->type = ST_TYPE_HIC;
		un->un_dp->densities[0] = 0x09;
		un->un_dp->densities[1] = 0x0a;
		un->un_dp->densities[2] = 0x0c;
		un->un_dp->densities[3] = 0x0d;
		break;

	case 0x13:
			/* DDS-2/DDS-3 scsi spec densities */
	case 0x24:
	case 0x25:
	case 0x26:
		sizestr = "DAT Data Storage (DDS)";
		un->un_dp->type = ST_TYPE_DAT;
		un->un_dp->options |= ST_AUTODEN_OVERRIDE;
		break;

	case 0x14:
		/*
		 * Helical Scan (Exabyte) devices
		 */
		sizestr = "8mm helical scan cartridge";
		un->un_dp->type = ST_TYPE_EXABYTE;
		un->un_dp->options |= ST_AUTODEN_OVERRIDE;
		break;
	}

	/*
	 * Assume LONG ERASE, BSF and BSR
	 */

	un->un_dp->options |=
	    (ST_LONG_ERASE | ST_UNLOADABLE | ST_BSF | ST_BSR | ST_KNOWS_EOD);

	/*
	 * Only if mode sense data says no buffered write, set NOBUF
	 */
	if (un->un_mspl->bufm == 0)
		un->un_dp->options |= ST_NOBUF;

	/*
	 * set up large read and write retry counts
	 */

	un->un_dp->max_rretries = un->un_dp->max_wretries = 1000;

	/*
	 * If this is a 0.50 inch reel tape, and
	 * it is *not* variable mode, try and
	 * set it to variable record length
	 * mode.
	 */
	if ((un->un_dp->options & ST_REEL) && un->un_bsize != 0 &&
	    (un->un_dp->options & ST_VARIABLE)) {
		if (st_change_block_size(un, 0) == 0) {
			un->un_dp->bsize = 0;
			un->un_mspl->high_bl = un->un_mspl->mid_bl =
			    un->un_mspl->low_bl = 0;
		}
	}

	/*
	 * Write to console about type of device found
	 */
	ST_DEBUG6(ST_DEVINFO, st_label, CE_NOTE,
	    "Generic Drive, Vendor=%s\n\t%s", un->un_dp->name,
	    sizestr);
	if (un->un_dp->options & ST_VARIABLE) {
		scsi_log(ST_DEVINFO, st_label, CE_NOTE,
		    "!Variable record length I/O\n");
	} else {
		scsi_log(ST_DEVINFO, st_label, CE_NOTE,
		    "!Fixed record length (%d byte blocks) I/O\n",
		    un->un_dp->bsize);
	}
	ASSERT(mutex_owned(ST_MUTEX));
	return (0);
}

static int
st_determine_density(struct scsi_tape *un, int rw)
{
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_determine_density);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_determine_density(un = 0x%p, rw = %s)\n",
	    (void*)un, (rw == B_WRITE ? wr_str: rd_str));

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * If we're past BOT, density is determined already.
	 */
	if (un->un_pos.pmode == logical) {
		if (un->un_pos.lgclblkno != 0) {
			goto exit;
		}
	} else if (un->un_pos.pmode == legacy) {
		if ((un->un_pos.fileno != 0) || (un->un_pos.blkno != 0)) {
			/*
			 * XXX: put in a bitch message about attempting to
			 * XXX: change density past BOT.
			 */
			goto exit;
		}
	} else {
		goto exit;
	}
	if ((un->un_pos.pmode == logical) &&
	    (un->un_pos.lgclblkno != 0)) {
		goto exit;
	}


	/*
	 * If we're going to be writing, we set the density
	 */
	if (rw == 0 || rw == B_WRITE) {
		/* un_curdens is used as an index into densities table */
		un->un_curdens = MT_DENSITY(un->un_dev);
		if (st_set_density(un)) {
			rval = -1;
		}
		goto exit;
	}

	/*
	 * If density is known already,
	 * we don't have to get it again.(?)
	 */
	if (!un->un_density_known) {
		if (st_get_density(un)) {
			rval = -1;
		}
	}

exit:
	ASSERT(mutex_owned(ST_MUTEX));
	return (rval);
}


/*
 * Try to determine density. We do this by attempting to read the
 * first record off the tape, cycling through the available density
 * codes as we go.
 */

static int
st_get_density(struct scsi_tape *un)
{
	int succes = 0, rval = -1, i;
	uint_t size;
	uchar_t dens, olddens;

	ST_FUNC(ST_DEVINFO, st_get_density);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_get_density(un = 0x%p)\n", (void*)un);

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * If Auto Density override is enabled The drive has
	 * only one density and there is no point in attempting
	 * find the correct one.
	 *
	 * Since most modern drives auto detect the density
	 * and format of the recorded media before they come
	 * ready. What this function does is a legacy behavior
	 * and modern drives not only don't need it, The backup
	 * utilities that do positioning via uscsi find the un-
	 * expected rewinds problematic.
	 *
	 * The drives that need this are old reel to reel devices.
	 * I took a swag and said they must be scsi-1 or older.
	 * I don't beleave there will any of the newer devices
	 * that need this. There will be some scsi-1 devices that
	 * don't need this but I don't think they will be using the
	 * BIG aftermarket backup and restore utilitys.
	 */
	if ((un->un_dp->options & ST_AUTODEN_OVERRIDE) ||
	    (un->un_sd->sd_inq->inq_ansi > 1)) {
		un->un_density_known = 1;
		rval = 0;
		goto exit;
	}

	/*
	 * This will only work on variable record length tapes
	 * if and only if all variable record length tapes autodensity
	 * select.
	 */
	size = (unsigned)(un->un_dp->bsize ? un->un_dp->bsize : SECSIZE);
	un->un_tmpbuf = kmem_alloc(size, KM_SLEEP);

	/*
	 * Start at the specified density
	 */

	dens = olddens = un->un_curdens = MT_DENSITY(un->un_dev);

	for (i = 0; i < NDENSITIES; i++, ((un->un_curdens == NDENSITIES - 1) ?
	    (un->un_curdens = 0) : (un->un_curdens += 1))) {
		/*
		 * If we've done this density before,
		 * don't bother to do it again.
		 */
		dens = un->un_dp->densities[un->un_curdens];
		if (i > 0 && dens == olddens)
			continue;
		olddens = dens;
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "trying density 0x%x\n", dens);
		if (st_set_density(un)) {
			continue;
		}

		/*
		 * XXX - the creates lots of headaches and slowdowns - must
		 * fix.
		 */
		succes = (st_cmd(un, SCMD_READ, (int)size, SYNC_CMD) == 0);
		if (st_cmd(un, SCMD_REWIND, 0, SYNC_CMD)) {
			break;
		}
		if (succes) {
			st_init(un);
			rval = 0;
			un->un_density_known = 1;
			break;
		}
	}
	kmem_free(un->un_tmpbuf, size);
	un->un_tmpbuf = 0;

exit:
	ASSERT(mutex_owned(ST_MUTEX));
	return (rval);
}

static int
st_set_density(struct scsi_tape *un)
{
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_set_density);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_set_density(un = 0x%p): density = 0x%x\n", (void*)un,
	    un->un_dp->densities[un->un_curdens]);

	ASSERT(mutex_owned(ST_MUTEX));

	un->un_mspl->density = un->un_dp->densities[un->un_curdens];

	if ((un->un_dp->options & ST_AUTODEN_OVERRIDE) == 0) {
		/*
		 * If auto density override is not set, Use mode select
		 * to set density and compression.
		 */
		if (st_modeselect(un)) {
			rval = -1;
		}
	} else if ((un->un_dp->options & ST_MODE_SEL_COMP) != 0) {
		/*
		 * If auto density and mode select compression are set,
		 * This is a drive with one density code but compression
		 * can be enabled or disabled.
		 * Set compression but no need to set density.
		 */
		rval = st_set_compression(un);
		if ((rval != 0) && (rval != EALREADY)) {
			rval = -1;
		} else {
			rval = 0;
		}
	}

	/* If sucessful set density and/or compression, mark density known */
	if (rval == 0) {
		un->un_density_known = 1;
	}

	ASSERT(mutex_owned(ST_MUTEX));
	return (rval);
}

static int
st_loadtape(struct scsi_tape *un)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_loadtape);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_loadtape(un = 0x%p)\n", (void*) un);

	ASSERT(mutex_owned(ST_MUTEX));

	rval = st_update_block_pos(un, st_cmd, 0);
	if (rval == EACCES) {
		return (rval);
	}

	/*
	 * 'LOAD' the tape to BOT by rewinding
	 */
	rval = st_cmd(un, SCMD_REWIND, 1, SYNC_CMD);
	if (rval == 0) {
		st_init(un);
		un->un_density_known = 0;
	}

	ASSERT(mutex_owned(ST_MUTEX));
	return (rval);
}


/*
 * Note: QIC devices aren't so smart.  If you try to append
 * after EOM, the write can fail because the device doesn't know
 * it's at EOM.	 In that case, issue a read.  The read should fail
 * because there's no data, but the device knows it's at EOM,
 * so a subsequent write should succeed.  To further confuse matters,
 * the target returns the same error if the tape is positioned
 * such that a write would overwrite existing data.  That's why
 * we have to do the append test.  A read in the middle of
 * recorded data would succeed, thus indicating we're attempting
 * something illegal.
 */


static void
st_test_append(struct buf *bp)
{
	dev_t dev = bp->b_edev;
	struct scsi_tape *un;
	uchar_t status;
	unsigned bcount;

	un = ddi_get_soft_state(st_state, MTUNIT(dev));

	ST_FUNC(ST_DEVINFO, st_test_append);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_test_append(): fileno %d\n", un->un_pos.fileno);

	un->un_laststate = un->un_state;
	un->un_state = ST_STATE_APPEND_TESTING;
	un->un_test_append = 0;

	/*
	 * first, map in the buffer, because we're doing a double write --
	 * first into the kernel, then onto the tape.
	 */
	bp_mapin(bp);

	/*
	 * get a copy of the data....
	 */
	un->un_tmpbuf = kmem_alloc((unsigned)bp->b_bcount, KM_SLEEP);
	bcopy(bp->b_un.b_addr, un->un_tmpbuf, (uint_t)bp->b_bcount);

	/*
	 * attempt the write..
	 */

	if (st_cmd(un, (int)SCMD_WRITE, (int)bp->b_bcount, SYNC_CMD) == 0) {
success:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "append write succeeded\n");
		bp->b_resid = un->un_sbufp->b_resid;
		mutex_exit(ST_MUTEX);
		bcount = (unsigned)bp->b_bcount;
		biodone(bp);
		mutex_enter(ST_MUTEX);
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_OPEN;
		kmem_free(un->un_tmpbuf, bcount);
		un->un_tmpbuf = NULL;
		return;
	}

	/*
	 * The append failed. Do a short read. If that fails,  we are at EOM
	 * so we can retry the write command. If that succeeds, than we're
	 * all screwed up (the controller reported a real error).
	 *
	 * XXX: should the dummy read be > SECSIZE? should it be the device's
	 * XXX: block size?
	 *
	 */
	status = un->un_status;
	un->un_status = 0;
	(void) st_cmd(un, SCMD_READ, SECSIZE, SYNC_CMD);
	if (un->un_status == KEY_BLANK_CHECK) {
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "append at EOM\n");
		/*
		 * Okay- the read failed. We should actually have confused
		 * the controller enough to allow writing. In any case, the
		 * i/o is on its own from here on out.
		 */
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_OPEN;
		bcopy(bp->b_un.b_addr, un->un_tmpbuf, (uint_t)bp->b_bcount);
		if (st_cmd(un, (int)SCMD_WRITE, (int)bp->b_bcount,
		    SYNC_CMD) == 0) {
			goto success;
		}
	}

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "append write failed- not at EOM\n");
	bp->b_resid = bp->b_bcount;
	st_bioerror(bp, EIO);

	ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_test_append : EIO : append write failed - not at EOM");

	/*
	 * backspace one record to get back to where we were
	 */
	if (st_cmd(un, SCMD_SPACE, Blk(-1), SYNC_CMD)) {
		un->un_pos.pmode = invalid;
	}

	un->un_err_resid = bp->b_resid;
	un->un_status = status;

	/*
	 * Note: biodone will do a bp_mapout()
	 */
	mutex_exit(ST_MUTEX);
	bcount = (unsigned)bp->b_bcount;
	biodone(bp);
	mutex_enter(ST_MUTEX);
	un->un_laststate = un->un_state;
	un->un_state = ST_STATE_OPEN_PENDING_IO;
	kmem_free(un->un_tmpbuf, bcount);
	un->un_tmpbuf = NULL;
}

/*
 * Special command handler
 */

/*
 * common st_cmd code. The fourth parameter states
 * whether the caller wishes to await the results
 * Note the release of the mutex during most of the function
 */
static int
st_cmd(struct scsi_tape *un, int com, int64_t count, int wait)
{
	struct buf *bp;
	int err;
	uint_t last_err_resid;

	ST_FUNC(ST_DEVINFO, st_cmd);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_cmd(dev = 0x%lx, com = 0x%x, count = %"PRIx64", wait = %d)\n",
	    un->un_dev, com, count, wait);

	ASSERT(MUTEX_HELD(&un->un_sd->sd_mutex));
	ASSERT(mutex_owned(ST_MUTEX));

#ifdef STDEBUG
	if ((st_debug & 0x7)) {
		st_debug_cmds(un, com, count, wait);
	}
#endif

	st_wait_for_io(un);

	/* check to see if this command requires the drive to be reserved */
	err = st_check_cmd_for_need_to_reserve(un, com, count);

	if (err) {
		return (err);
	}

	/*
	 * A space command is not recoverable if we don't know were we
	 * were when it was issued.
	 */
	if ((com == SCMD_SPACE) || (com == SCMD_SPACE_G4)) {
		(void) st_update_block_pos(un, st_cmd, 0);
	}

	/*
	 * Forground should not be doing anything while recovery is active.
	 */
	ASSERT(un->un_recov_buf_busy == 0);

	while (un->un_sbuf_busy)
		cv_wait(&un->un_sbuf_cv, ST_MUTEX);
	un->un_sbuf_busy = 1;

	bp = un->un_sbufp;
	bzero(bp, sizeof (buf_t));

	bp->b_flags = (wait) ? B_BUSY : B_BUSY|B_ASYNC;

	err = st_setup_cmd(un, bp, com, count);

	un->un_sbuf_busy = 0;

	/*
	 * If was a space command need to update logical block position.
	 * Only do this if the command was sucessful or it will mask the fact
	 * that the space command failed by promoting the pmode to logical.
	 */
	if (((com == SCMD_SPACE) || (com == SCMD_SPACE_G4)) &&
	    (un->un_pos.pmode != invalid)) {
		un->un_running.pmode = invalid;
		last_err_resid = un->un_err_resid;
		(void) st_update_block_pos(un, st_cmd, 1);
		/*
		 * Set running position to invalid so it updates on the
		 * next command.
		 */
		un->un_running.pmode = invalid;
		un->un_err_resid = last_err_resid;
	}

	cv_signal(&un->un_sbuf_cv);

	return (err);
}

static int
st_setup_cmd(struct scsi_tape *un, buf_t *bp, int com, int64_t count)
{
	int err;
	dev_t dev = un->un_dev;

	ST_FUNC(ST_DEVINFO, st_setup_cmd);
	/*
	 * Set count to the actual size of the data tranfer.
	 * For commands with no data transfer, set bp->b_bcount
	 * to the value to be used when constructing the
	 * cdb in st_make_cmd().
	 */
	switch (com) {
	case SCMD_READ:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "special read %"PRId64"\n", count);
		bp->b_flags |= B_READ;
		bp->b_un.b_addr = un->un_tmpbuf;
		break;

	case SCMD_WRITE:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "special write %"PRId64"\n", count);
		bp->b_un.b_addr = un->un_tmpbuf;
		break;

	case SCMD_WRITE_FILE_MARK:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "write %"PRId64" file marks\n", count);
		bp->b_bcount = count;
		count = 0;
		break;

	case SCMD_REWIND:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG, "rewind\n");
		bp->b_bcount = count;
		count = 0;
		break;

	case SCMD_SPACE:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG, "space\n");
		/*
		 * If the user could have entered a number that will
		 * not fit in the 12 bit count field of space(8),
		 * use space(16).
		 */
		if (((int64_t)SPACE_CNT(count) > 0x7fffff) ||
		    ((int64_t)SPACE_CNT(count) < -(0x7fffff))) {
			com = SCMD_SPACE_G4;
		}
		bp->b_bcount = count;
		count = 0;
		break;

	case SCMD_RESERVE:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG, "reserve");
		bp->b_bcount = 0;
		count = 0;
		break;

	case SCMD_RELEASE:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG, "release");
		bp->b_bcount = 0;
		count = 0;
		break;

	case SCMD_LOAD:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "%s tape\n", (count & LD_LOAD) ? "load" : "unload");
		bp->b_bcount = count;
		count = 0;
		break;

	case SCMD_ERASE:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "erase tape\n");
		bp->b_bcount = count;
		count = 0;
		break;

	case SCMD_MODE_SENSE:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "mode sense\n");
		bp->b_flags |= B_READ;
		bp->b_un.b_addr = (caddr_t)(un->un_mspl);
		break;

	case SCMD_MODE_SELECT:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "mode select\n");
		bp->b_un.b_addr = (caddr_t)(un->un_mspl);
		break;

	case SCMD_READ_BLKLIM:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "read block limits\n");
		bp->b_bcount = count;
		bp->b_flags |= B_READ;
		bp->b_un.b_addr = (caddr_t)(un->un_rbl);
		break;

	case SCMD_TEST_UNIT_READY:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "test unit ready\n");
		bp->b_bcount = 0;
		count = 0;
		break;

	case SCMD_DOORLOCK:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "%s tape\n", (count & MR_LOCK) ? "lock" : "unlock");
		bp->b_bcount = count = 0;
		break;

	case SCMD_READ_POSITION:
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "read position\n");
		switch (un->un_read_pos_type) {
		case LONG_POS:
			count = sizeof (tape_position_long_t);
			break;
		case EXT_POS:
			count = min(count, sizeof (tape_position_ext_t));
			break;
		case SHORT_POS:
			count = sizeof (tape_position_t);
			break;
		default:
			ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
			    "Unknown read position type 0x%x in "
			    "st_make_cmd()\n", un->un_read_pos_type);
		}
		bp->b_bcount = count;
		bp->b_flags |= B_READ;
		bp->b_un.b_addr = (caddr_t)un->un_read_pos_data;
		break;

	default:
		ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
		    "Unhandled scsi command 0x%x in st_setup_cmd()\n", com);
	}

	mutex_exit(ST_MUTEX);

	if (count > 0) {
		int flg = (bp->b_flags & B_READ) ? B_READ : B_WRITE;
		/*
		 * We're going to do actual I/O.
		 * Set things up for physio.
		 */
		struct iovec aiov;
		struct uio auio;
		struct uio *uio = &auio;

		bzero(&auio, sizeof (struct uio));
		bzero(&aiov, sizeof (struct iovec));
		aiov.iov_base = bp->b_un.b_addr;
		aiov.iov_len = count;

		uio->uio_iov = &aiov;
		uio->uio_iovcnt = 1;
		uio->uio_resid = aiov.iov_len;
		uio->uio_segflg = UIO_SYSSPACE;

		/*
		 * Let physio do the rest...
		 */
		bp->b_forw = (struct buf *)(uintptr_t)com;
		bp->b_back = NULL;
		err = physio(st_strategy, bp, dev, flg, st_minphys, uio);
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_setup_cmd: physio returns %d\n", err);
	} else {
		/*
		 * Mimic physio
		 */
		bp->b_forw = (struct buf *)(uintptr_t)com;
		bp->b_back = NULL;
		bp->b_edev = dev;
		bp->b_dev = cmpdev(dev);
		bp->b_blkno = 0;
		bp->b_resid = 0;
		(void) st_strategy(bp);
		if (bp->b_flags & B_ASYNC) {
			/*
			 * This is an async command- the caller won't wait
			 * and doesn't care about errors.
			 */
			mutex_enter(ST_MUTEX);
			return (0);
		}

		/*
		 * BugTraq #4260046
		 * ----------------
		 * Restore Solaris 2.5.1 behavior, namely call biowait
		 * unconditionally. The old comment said...
		 *
		 * "if strategy was flagged with  persistent errors, we would
		 *  have an error here, and the bp would never be sent, so we
		 *  don't want to wait on a bp that was never sent...or hang"
		 *
		 * The new rationale, courtesy of Chitrank...
		 *
		 * "we should unconditionally biowait() here because
		 *  st_strategy() will do a biodone() in the persistent error
		 *  case and the following biowait() will return immediately.
		 *  If not, in the case of "errors after pkt alloc" in
		 *  st_start(), we will not biowait here which will cause the
		 *  next biowait() to return immediately which will cause
		 *  us to send out the next command. In the case where both of
		 *  these use the sbuf, when the first command completes we'll
		 *  free the packet attached to sbuf and the same pkt will
		 *  get freed again when we complete the second command.
		 *  see esc 518987.  BTW, it is necessary to do biodone() in
		 *  st_start() for the pkt alloc failure case because physio()
		 *  does biowait() and will hang if we don't do biodone()"
		 */

		err = biowait(bp);
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_setup_cmd: biowait returns %d\n", err);
	}

	mutex_enter(ST_MUTEX);

	return (err);
}

static int
st_set_compression(struct scsi_tape *un)
{
	int rval;
	int turn_compression_on;
	minor_t minor;

	ST_FUNC(ST_DEVINFO, st_set_compression);

	/*
	 * Drive either dosn't have compression or it is controlled with
	 * special density codes. Return ENOTTY so caller
	 * knows nothing was done.
	 */
	if ((un->un_dp->options & ST_MODE_SEL_COMP) == 0) {
		un->un_comp_page = 0;
		return (ENOTTY);
	}

	/* set compression based on minor node opened */
	minor = MT_DENSITY(un->un_dev);

	/*
	 * If this the compression density or
	 * the drive has two densities and uses mode select for
	 * control of compression turn on compression for MT_DENSITY2
	 * as well.
	 */
	if ((minor == ST_COMPRESSION_DENSITY) ||
	    (minor == MT_DENSITY(MT_DENSITY2)) &&
	    (un->un_dp->densities[0] == un->un_dp->densities[1]) &&
	    (un->un_dp->densities[2] == un->un_dp->densities[3]) &&
	    (un->un_dp->densities[0] != un->un_dp->densities[2])) {

		turn_compression_on = 1;
	} else {
		turn_compression_on = 0;
	}

	un->un_mspl->high_bl = (uchar_t)(un->un_bsize >> 16);
	un->un_mspl->mid_bl  = (uchar_t)(un->un_bsize >> 8);
	un->un_mspl->low_bl  = (uchar_t)(un->un_bsize);

	/*
	 * Need to determine which page does the device use for compression.
	 * First try the data compression page. If this fails try the device
	 * configuration page
	 */

	if ((un->un_comp_page & ST_DEV_DATACOMP_PAGE) == ST_DEV_DATACOMP_PAGE) {
		rval = st_set_datacomp_page(un, turn_compression_on);
		if (rval == EALREADY) {
			return (rval);
		}
		if (rval != 0) {
			if (un->un_status == KEY_ILLEGAL_REQUEST) {
				/*
				 * This device does not support data
				 * compression page
				 */
				un->un_comp_page = ST_DEV_CONFIG_PAGE;
			} else if (un->un_state >= ST_STATE_OPEN) {
				un->un_pos.pmode = invalid;
				rval = EIO;
			} else {
				rval = -1;
			}
		} else {
			un->un_comp_page = ST_DEV_DATACOMP_PAGE;
		}
	}

	if ((un->un_comp_page & ST_DEV_CONFIG_PAGE) == ST_DEV_CONFIG_PAGE) {
		rval = st_set_devconfig_page(un, turn_compression_on);
		if (rval == EALREADY) {
			return (rval);
		}
		if (rval != 0) {
			if (un->un_status == KEY_ILLEGAL_REQUEST) {
				/*
				 * This device does not support
				 * compression at all advice the
				 * user and unset ST_MODE_SEL_COMP
				 */
				un->un_dp->options &= ~ST_MODE_SEL_COMP;
				un->un_comp_page = 0;
				scsi_log(ST_DEVINFO, st_label, CE_NOTE,
				    "Device Does Not Support Compression\n");
			} else if (un->un_state >= ST_STATE_OPEN) {
				un->un_pos.pmode = invalid;
				rval = EIO;
			} else {
				rval = -1;
			}
		}
	}

	return (rval);
}

/*
 * set or unset compression thru device configuration page.
 */
static int
st_set_devconfig_page(struct scsi_tape *un, int compression_on)
{
	unsigned char cflag;
	int rval = 0;


	ST_FUNC(ST_DEVINFO, st_set_devconfig_page);

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * if the mode sense page is not the correct one, load the correct one.
	 */
	if (un->un_mspl->page_code != ST_DEV_CONFIG_PAGE) {
		rval = st_gen_mode_sense(un, st_uscsi_cmd, ST_DEV_CONFIG_PAGE,
		    un->un_mspl, sizeof (struct seq_mode));
		if (rval)
			return (rval);
	}

	/*
	 * Figure what to set compression flag to.
	 */
	if (compression_on) {
		/* They have selected a compression node */
		if (un->un_dp->type == ST_TYPE_FUJI) {
			cflag = 0x84;   /* use EDRC */
		} else {
			cflag = ST_DEV_CONFIG_DEF_COMP;
		}
	} else {
		cflag = ST_DEV_CONFIG_NO_COMP;
	}

	/*
	 * If compression is already set the way it was requested.
	 * And if this not the first time we has tried.
	 */
	if ((cflag == un->un_mspl->page.dev.comp_alg) &&
	    (un->un_comp_page == ST_DEV_CONFIG_PAGE)) {
		return (EALREADY);
	}

	un->un_mspl->page.dev.comp_alg = cflag;
	/*
	 * need to send mode select even if correct compression is
	 * already set since need to set density code
	 */

#ifdef STDEBUG
	if ((st_debug & 0x7) >= 6) {
		st_clean_print(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_set_devconfig_page: sense data for mode select",
		    (char *)un->un_mspl, sizeof (struct seq_mode));
	}
#endif
	rval = st_gen_mode_select(un, st_uscsi_cmd, un->un_mspl,
	    sizeof (struct seq_mode));

	return (rval);
}

/*
 * set/reset compression bit thru data compression page
 */
static int
st_set_datacomp_page(struct scsi_tape *un, int compression_on)
{
	int compression_on_already;
	int rval = 0;


	ST_FUNC(ST_DEVINFO, st_set_datacomp_page);

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * if the mode sense page is not the correct one, load the correct one.
	 */
	if (un->un_mspl->page_code != ST_DEV_DATACOMP_PAGE) {
		rval = st_gen_mode_sense(un, st_uscsi_cmd, ST_DEV_DATACOMP_PAGE,
		    un->un_mspl, sizeof (struct seq_mode));
		if (rval)
			return (rval);
	}

	/*
	 * If drive is not capable of compression (at this time)
	 * return EALREADY so caller doesn't think that this page
	 * is not supported. This check is for drives that can
	 * disable compression from the front panel or configuration.
	 * I doubt that a drive that supports this page is not really
	 * capable of compression.
	 */
	if (un->un_mspl->page.comp.dcc == 0) {
		return (EALREADY);
	}

	/* See if compression currently turned on */
	if (un->un_mspl->page.comp.dce) {
		compression_on_already = 1;
	} else {
		compression_on_already = 0;
	}

	/*
	 * If compression is already set the way it was requested.
	 * And if this not the first time we has tried.
	 */
	if ((compression_on == compression_on_already) &&
	    (un->un_comp_page == ST_DEV_DATACOMP_PAGE)) {
		return (EALREADY);
	}

	/*
	 * if we are already set to the appropriate compression
	 * mode, don't set it again
	 */
	if (compression_on) {
		/* compression selected */
		un->un_mspl->page.comp.dce = 1;
	} else {
		un->un_mspl->page.comp.dce = 0;
	}


#ifdef STDEBUG
	if ((st_debug & 0x7) >= 6) {
		st_clean_print(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_set_datacomp_page: sense data for mode select",
		    (char *)un->un_mspl, sizeof (struct seq_mode));
	}
#endif
	rval = st_gen_mode_select(un, st_uscsi_cmd, un->un_mspl,
	    sizeof (struct seq_mode));

	return (rval);
}

static int
st_modesense(struct scsi_tape *un)
{
	int rval;
	uchar_t page;

	ST_FUNC(ST_DEVINFO, st_modesense);

	page = un->un_comp_page;

	switch (page) {
	case ST_DEV_DATACOMP_PAGE:
	case ST_DEV_CONFIG_PAGE: /* FALLTHROUGH */
		rval = st_gen_mode_sense(un, st_uscsi_cmd, page, un->un_mspl,
		    sizeof (struct seq_mode));
		break;

	case ST_DEV_DATACOMP_PAGE | ST_DEV_CONFIG_PAGE:
		if (un->un_dp->options & ST_MODE_SEL_COMP) {
			page = ST_DEV_DATACOMP_PAGE;
			rval = st_gen_mode_sense(un, st_uscsi_cmd, page,
			    un->un_mspl, sizeof (struct seq_mode));
			if (rval == 0 && un->un_mspl->page_code == page) {
				un->un_comp_page = page;
				break;
			}
			page = ST_DEV_CONFIG_PAGE;
			rval = st_gen_mode_sense(un, st_uscsi_cmd, page,
			    un->un_mspl, sizeof (struct seq_mode));
			if (rval == 0 && un->un_mspl->page_code == page) {
				un->un_comp_page = page;
				break;
			}
			un->un_dp->options &= ~ST_MODE_SEL_COMP;
			un->un_comp_page = 0;
		} else {
			un->un_comp_page = 0;
		}

	default:	/* FALLTHROUGH */
		rval = st_cmd(un, SCMD_MODE_SENSE, MSIZE, SYNC_CMD);
	}
	return (rval);
}

static int
st_modeselect(struct scsi_tape *un)
{
	int rval = 0;
	int ix;

	ST_FUNC(ST_DEVINFO, st_modeselect);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_modeselect(dev = 0x%lx): density = 0x%x\n",
	    un->un_dev, un->un_mspl->density);

	ASSERT(mutex_owned(ST_MUTEX));

	/*
	 * The parameter list should be the same for all of the
	 * cases that follow so set them here
	 *
	 * Try mode select first if if fails set fields manually
	 */
	rval = st_modesense(un);
	if (rval != 0) {
		ST_DEBUG3(ST_DEVINFO, st_label, CE_WARN,
		    "st_modeselect: First mode sense failed\n");
		un->un_mspl->bd_len  = 8;
		un->un_mspl->high_nb = 0;
		un->un_mspl->mid_nb  = 0;
		un->un_mspl->low_nb  = 0;
	}
	un->un_mspl->high_bl = (uchar_t)(un->un_bsize >> 16);
	un->un_mspl->mid_bl  = (uchar_t)(un->un_bsize >> 8);
	un->un_mspl->low_bl  = (uchar_t)(un->un_bsize);


	/*
	 * If configured to use a specific density code for a media type.
	 * curdens is previously set by the minor node opened.
	 * If the media type doesn't match the minor node we change it so it
	 * looks like the correct one was opened.
	 */
	if (un->un_dp->options & ST_KNOWS_MEDIA) {
		uchar_t best;

		for (best = 0xff, ix = 0; ix < NDENSITIES; ix++) {
			if (un->un_mspl->media_type ==
			    un->un_dp->mediatype[ix]) {
				best = ix;
				/*
				 * It matches but it might not be the only one.
				 * Use the highest matching media type but not
				 * to exceed the density selected by the open.
				 */
				if (ix < un->un_curdens) {
					continue;
				}
				un->un_curdens = ix;
				break;
			}
		}
		/* If a match was found best will not be 0xff any more */
		if (best < NDENSITIES) {
			ST_DEBUG3(ST_DEVINFO, st_label, CE_WARN,
			    "found media 0x%X using density 0x%X\n",
			    un->un_mspl->media_type,
			    un->un_dp->densities[best]);
			un->un_mspl->density = un->un_dp->densities[best];
		} else {
			/* Otherwise set density based on minor node opened */
			un->un_mspl->density =
			    un->un_dp->densities[un->un_curdens];
		}
	} else {
		un->un_mspl->density = un->un_dp->densities[un->un_curdens];
	}

	if (un->un_dp->options & ST_NOBUF) {
		un->un_mspl->bufm = 0;
	} else {
		un->un_mspl->bufm = 1;
	}

	rval = st_set_compression(un);

	/*
	 * If st_set_compression returned invalid or already it
	 * found no need to do the mode select.
	 * So do it here.
	 */
	if ((rval == ENOTTY) || (rval == EALREADY)) {

		/* Zero non-writeable fields */
		un->un_mspl->data_len = 0;
		un->un_mspl->media_type = 0;
		un->un_mspl->wp = 0;

		/* need to set the density code */
		rval = st_cmd(un, SCMD_MODE_SELECT, MSIZE, SYNC_CMD);
		if (rval != 0) {
			if (un->un_state >= ST_STATE_OPEN) {
				ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
				    "unable to set tape mode\n");
				un->un_pos.pmode = invalid;
				rval = EIO;
			} else {
				rval = -1;
			}
		}
	}

	/*
	 * The spec recommends to send a mode sense after a mode select
	 */
	(void) st_modesense(un);

	ASSERT(mutex_owned(ST_MUTEX));

	return (rval);
}

/*
 * st_gen_mode_sense
 *
 * generic mode sense.. it allows for any page
 */
static int
st_gen_mode_sense(struct scsi_tape *un, ubufunc_t ubf, int page,
    struct seq_mode *page_data, int page_size)
{

	int r;
	char	cdb[CDB_GROUP0];
	struct uscsi_cmd *com;
	struct scsi_arq_status status;

	ST_FUNC(ST_DEVINFO, st_gen_mode_sense);

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);

	bzero(cdb, CDB_GROUP0);
	cdb[0] = SCMD_MODE_SENSE;
	cdb[2] = (char)page;
	cdb[4] = (char)page_size;

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP0;
	com->uscsi_bufaddr = (caddr_t)page_data;
	com->uscsi_buflen = page_size;
	com->uscsi_rqlen = sizeof (status);
	com->uscsi_rqbuf = (caddr_t)&status;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;
	com->uscsi_flags = USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_READ;

	r = ubf(un, com, FKIOCTL);
	kmem_free(com, sizeof (*com));
	return (r);
}

/*
 * st_gen_mode_select
 *
 * generic mode select.. it allows for any page
 */
static int
st_gen_mode_select(struct scsi_tape *un, ubufunc_t ubf,
    struct seq_mode *page_data, int page_size)
{

	int r;
	char cdb[CDB_GROUP0];
	struct uscsi_cmd *com;
	struct scsi_arq_status status;

	ST_FUNC(ST_DEVINFO, st_gen_mode_select);

	/* Zero non-writeable fields */
	page_data->data_len = 0;
	page_data->media_type = 0;
	page_data->wp = 0;

	/*
	 * If mode select has any page data, zero the ps (Page Savable) bit.
	 */
	if (page_size > MSIZE) {
		page_data->ps = 0;
	}


	com = kmem_zalloc(sizeof (*com), KM_SLEEP);

	/*
	 * then, do a mode select to set what ever info
	 */
	bzero(cdb, CDB_GROUP0);
	cdb[0] = SCMD_MODE_SELECT;
	cdb[1] = 0x10;		/* set PF bit for many third party drives */
	cdb[4] = (char)page_size;

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP0;
	com->uscsi_bufaddr = (caddr_t)page_data;
	com->uscsi_buflen = page_size;
	com->uscsi_rqlen = sizeof (status);
	com->uscsi_rqbuf = (caddr_t)&status;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;
	com->uscsi_flags = USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_WRITE;

	r = ubf(un, com, FKIOCTL);

	kmem_free(com, sizeof (*com));
	return (r);
}

static int
st_read_block_limits(struct scsi_tape *un, struct read_blklim *read_blk)
{
	int rval;
	char cdb[CDB_GROUP0];
	struct uscsi_cmd *com;
	struct scsi_arq_status status;

	ST_FUNC(ST_DEVINFO, st_read_block_limits);

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);

	bzero(cdb, CDB_GROUP0);
	cdb[0] = SCMD_READ_BLKLIM;

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP0;
	com->uscsi_bufaddr = (caddr_t)read_blk;
	com->uscsi_buflen = sizeof (struct read_blklim);
	com->uscsi_rqlen = sizeof (status);
	com->uscsi_rqbuf = (caddr_t)&status;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;
	com->uscsi_flags = USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_READ;

	rval = st_uscsi_cmd(un, com, FKIOCTL);
	if (com->uscsi_status || com->uscsi_resid) {
		rval = -1;
	}

	kmem_free(com, sizeof (*com));
	return (rval);
}

static int
st_report_density_support(struct scsi_tape *un, uchar_t *density_data,
    size_t buflen)
{
	int rval;
	char cdb[CDB_GROUP1];
	struct uscsi_cmd *com;
	struct scsi_arq_status status;

	ST_FUNC(ST_DEVINFO, st_report_density_support);

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);

	bzero(cdb, CDB_GROUP1);
	cdb[0] = SCMD_REPORT_DENSITIES;
	cdb[7] = (buflen & 0xff00) >> 8;
	cdb[8] = buflen & 0xff;

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP1;
	com->uscsi_bufaddr = (caddr_t)density_data;
	com->uscsi_buflen = buflen;
	com->uscsi_rqlen = sizeof (status);
	com->uscsi_rqbuf = (caddr_t)&status;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;
	com->uscsi_flags = USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_READ;

	rval = st_uscsi_cmd(un, com, FKIOCTL);
	if (com->uscsi_status || com->uscsi_resid) {
		rval = -1;
	}

	kmem_free(com, sizeof (*com));
	return (rval);
}

static int
st_report_supported_operation(struct scsi_tape *un, uchar_t *oper_data,
    uchar_t option_code, ushort_t service_action)
{
	int rval;
	char cdb[CDB_GROUP5];
	struct uscsi_cmd *com;
	struct scsi_arq_status status;
	uint32_t allo_length;

	ST_FUNC(ST_DEVINFO, st_report_supported_operation);

	allo_length = sizeof (struct one_com_des) +
	    sizeof (struct com_timeout_des);
	com = kmem_zalloc(sizeof (*com), KM_SLEEP);

	bzero(cdb, CDB_GROUP5);
	cdb[0] = (char)SCMD_MAINTENANCE_IN;
	cdb[1] = SSVC_ACTION_GET_SUPPORTED_OPERATIONS;
	if (service_action) {
		cdb[2] = (char)(ONE_COMMAND_DATA_FORMAT | 0x80); /* RCTD */
		cdb[4] = (service_action & 0xff00) >> 8;
		cdb[5] = service_action & 0xff;
	} else {
		cdb[2] = (char)(ONE_COMMAND_NO_SERVICE_DATA_FORMAT |
		    0x80); /* RCTD */
	}
	cdb[3] = option_code;
	cdb[6] = (allo_length & 0xff000000) >> 24;
	cdb[7] = (allo_length & 0xff0000) >> 16;
	cdb[8] = (allo_length & 0xff00) >> 8;
	cdb[9] = allo_length & 0xff;

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP5;
	com->uscsi_bufaddr = (caddr_t)oper_data;
	com->uscsi_buflen = allo_length;
	com->uscsi_rqlen = sizeof (status);
	com->uscsi_rqbuf = (caddr_t)&status;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;
	com->uscsi_flags = USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_READ;

	rval = st_uscsi_cmd(un, com, FKIOCTL);
	if (com->uscsi_status) {
		rval = -1;
	}

	kmem_free(com, sizeof (*com));
	return (rval);
}

/*
 * Changes devices blocksize and bsize to requested blocksize nblksz.
 * Returns returned value from first failed call or zero on success.
 */
static int
st_change_block_size(struct scsi_tape *un, uint32_t nblksz)
{
	struct seq_mode *current;
	int rval;
	uint32_t oldblksz;

	ST_FUNC(ST_DEVINFO, st_change_block_size);

	current = kmem_zalloc(MSIZE, KM_SLEEP);

	/*
	 * If we haven't got the compression page yet, do that first.
	 */
	if (un->un_comp_page == (ST_DEV_DATACOMP_PAGE | ST_DEV_CONFIG_PAGE)) {
		(void) st_modesense(un);
	}

	/* Read current settings */
	rval = st_gen_mode_sense(un, st_uscsi_cmd, 0, current, MSIZE);
	if (rval != 0) {
		scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "mode sense for change block size failed: rval = %d", rval);
		goto finish;
	}

	/* Figure the current block size */
	oldblksz =
	    (current->high_bl << 16) |
	    (current->mid_bl << 8) |
	    (current->low_bl);

	/* If current block size is the same as requested were done */
	if (oldblksz == nblksz) {
		un->un_bsize = nblksz;
		rval = 0;
		goto finish;
	}

	/* Change to requested block size */
	current->high_bl = (uchar_t)(nblksz >> 16);
	current->mid_bl  = (uchar_t)(nblksz >> 8);
	current->low_bl  = (uchar_t)(nblksz);

	/* Attempt to change block size */
	rval = st_gen_mode_select(un, st_uscsi_cmd, current, MSIZE);
	if (rval != 0) {
		scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Set new block size failed: rval = %d", rval);
		goto finish;
	}

	/* Read back and verify setting */
	rval = st_modesense(un);
	if (rval == 0) {
		un->un_bsize =
		    (un->un_mspl->high_bl << 16) |
		    (un->un_mspl->mid_bl << 8) |
		    (un->un_mspl->low_bl);

		if (un->un_bsize != nblksz) {
			scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Blocksize set does not equal requested blocksize"
			    "(read: %u requested: %u)\n", nblksz, un->un_bsize);
			rval = EIO;
		}
	}
finish:
	kmem_free(current, MSIZE);
	return (rval);
}


static void
st_init(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_init);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_init(): dev = 0x%lx, will reset fileno, blkno, eof\n",
	    un->un_dev);

	un->un_pos.blkno = 0;
	un->un_pos.fileno = 0;
	un->un_lastop = ST_OP_NIL;
	un->un_pos.eof = ST_NO_EOF;
	un->un_pwr_mgmt = ST_PWR_NORMAL;
	if (st_error_level != SCSI_ERR_ALL) {
		if (DEBUGGING) {
			st_error_level = SCSI_ERR_ALL;
		} else {
			st_error_level = SCSI_ERR_RETRYABLE;
		}
	}
}


static void
st_make_cmd(struct scsi_tape *un, struct buf *bp, int (*func)(caddr_t))
{
	struct scsi_pkt *pkt;
	struct uscsi_cmd *ucmd;
	recov_info *ri;
	int tval = 0;
	int64_t count;
	uint32_t additional = 0;
	uint32_t address = 0;
	union scsi_cdb *ucdb;
	int flags = 0;
	int cdb_len = CDB_GROUP0; /* default */
	uchar_t com;
	char fixbit;
	char short_fm = 0;
	optype prev_op = un->un_lastop;
	int stat_size =
	    (un->un_arq_enabled ? sizeof (struct scsi_arq_status) : 1);

	ST_FUNC(ST_DEVINFO, st_make_cmd);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_make_cmd(): dev = 0x%lx\n", un->un_dev);


	/*
	 * fixbit is for setting the Fixed Mode and Suppress Incorrect
	 * Length Indicator bits on read/write commands, for setting
	 * the Long bit on erase commands, and for setting the Code
	 * Field bits on space commands.
	 */

	/* regular raw I/O */
	if ((bp != un->un_sbufp) && (bp != un->un_recov_buf)) {
		pkt = scsi_init_pkt(ROUTE, NULL, bp,
		    CDB_GROUP0, stat_size, st_recov_sz, 0, func,
		    (caddr_t)un);
		if (pkt == NULL) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "Read Write scsi_init_pkt() failure\n");
			goto exit;
		}
		ASSERT(pkt->pkt_resid == 0);
#ifdef STDEBUG
		bzero(pkt->pkt_private, st_recov_sz);
		bzero(pkt->pkt_scbp, stat_size);
#endif
		ri = (recov_info *)pkt->pkt_private;
		ri->privatelen = st_recov_sz;
		if (un->un_bsize == 0) {
			count = bp->b_bcount;
			fixbit = 0;
		} else {
			count = bp->b_bcount / un->un_bsize;
			fixbit = 1;
		}
		if (bp->b_flags & B_READ) {
			com = SCMD_READ;
			un->un_lastop = ST_OP_READ;
			if ((un->un_bsize == 0) && /* Not Fixed Block */
			    (un->un_dp->options & ST_READ_IGNORE_ILI)) {
				fixbit = 2;
			}
		} else {
			com = SCMD_WRITE;
			un->un_lastop = ST_OP_WRITE;
		}
		tval = un->un_dp->io_timeout;

		/*
		 * For really large xfers, increase timeout
		 */
		if (bp->b_bcount > (10 * ONE_MEG))
			tval *= bp->b_bcount/(10 * ONE_MEG);

		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "%s %d amt 0x%lx\n", (com == SCMD_WRITE) ?
		    wr_str: rd_str, un->un_pos.blkno, bp->b_bcount);

	} else if ((ucmd = BP_UCMD(bp)) != NULL) {
		/*
		 * uscsi - build command, allocate scsi resources
		 */
		st_make_uscsi_cmd(un, ucmd, bp, func);
		goto exit;

	} else {				/* special I/O */
		struct buf *allocbp = NULL;
		com = (uchar_t)(uintptr_t)bp->b_forw;
		count = bp->b_bcount;

		switch (com) {
		case SCMD_READ:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "special read %"PRId64"\n", count);
			if (un->un_bsize == 0) {
				fixbit = 2;	/* suppress SILI */
			} else {
				fixbit = 1;	/* Fixed Block Mode */
				count /= un->un_bsize;
			}
			allocbp = bp;
			un->un_lastop = ST_OP_READ;
			tval = un->un_dp->io_timeout;
			break;

		case SCMD_WRITE:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "special write %"PRId64"\n", count);
			if (un->un_bsize != 0) {
				fixbit = 1;	/* Fixed Block Mode */
				count /= un->un_bsize;
			} else {
				fixbit = 0;
			}
			allocbp = bp;
			un->un_lastop = ST_OP_WRITE;
			tval = un->un_dp->io_timeout;
			break;

		case SCMD_WRITE_FILE_MARK:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "write %"PRId64" file marks\n", count);
			un->un_lastop = ST_OP_WEOF;
			fixbit = 0;
			tval = un->un_dp->io_timeout;
			/*
			 * If ST_SHORT_FILEMARKS bit is ON for EXABYTE
			 * device, set the Vendor Unique bit to
			 * write Short File Mark.
			 */
			if ((un->un_dp->options & ST_SHORT_FILEMARKS) &&
			    ((un->un_dp->type == ST_TYPE_EXB8500) ||
			    (un->un_dp->type == ST_TYPE_EXABYTE))) {
				/*
				 * Now the Vendor Unique bit 7 in Byte 5 of CDB
				 * is set to to write Short File Mark
				 */
				short_fm = 1;
			}
			break;

		case SCMD_REWIND:
			/*
			 * In the case of rewind we're gona do the rewind with
			 * the immediate bit set so status will be retured when
			 * the command is accepted by the device. We clear the
			 * B_ASYNC flag so we wait for that acceptance.
			 */
			fixbit = 0;
			if (bp->b_flags & B_ASYNC) {
				allocbp = bp;
				if (count) {
					fixbit = 1;
					bp->b_flags &= ~B_ASYNC;
				}
			}
			count = 0;
			bp->b_bcount = 0;
			un->un_lastop = ST_OP_CTL;
			tval = un->un_dp->rewind_timeout;
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "rewind\n");
			break;

		case SCMD_SPACE_G4:
			cdb_len = CDB_GROUP4;
			fixbit = SPACE_TYPE(bp->b_bcount);
			count = SPACE_CNT(bp->b_bcount);
			ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
			    " %s space %s %"PRId64" from file %d blk %d\n",
			    bp->b_bcount & SP_BACKSP ? "backward" : "forward",
			    space_strs[fixbit & 7], count,
			    un->un_pos.fileno, un->un_pos.blkno);
			address = (count >> 48) & 0x1fff;
			additional = (count >> 16) & 0xffffffff;
			count &= 0xffff;
			count <<= 16;
			un->un_lastop = ST_OP_CTL;
			tval = un->un_dp->space_timeout;
			break;

		case SCMD_SPACE:
			fixbit = SPACE_TYPE(bp->b_bcount);
			count = SPACE_CNT(bp->b_bcount);
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    " %s space %s %"PRId64" from file %d blk %d\n",
			    bp->b_bcount & SP_BACKSP ? "backward" : "forward",
			    space_strs[fixbit & 7], count,
			    un->un_pos.fileno, un->un_pos.blkno);
			count &= 0xffffffff;
			un->un_lastop = ST_OP_CTL;
			tval = un->un_dp->space_timeout;
			break;

		case SCMD_LOAD:
			ASSERT(count < 10);
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "%s tape\n", load_strs[count]);
			fixbit = 0;

			/* Loading or Unloading */
			if (count & LD_LOAD) {
				tval = un->un_dp->load_timeout;
			} else {
				tval = un->un_dp->unload_timeout;
			}
			/* Is Retension requested */
			if (count & LD_RETEN) {
				tval += un->un_dp->rewind_timeout;
			}
			un->un_lastop = ST_OP_CTL;
			break;

		case SCMD_ERASE:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "erase tape\n");
			ASSERT(count == 1); /* mt sets this */
			if (count == 1) {
				/*
				 * do long erase
				 */
				fixbit = 1; /* Long */

				/* Drive might not honor immidiate bit */
				tval = un->un_dp->erase_timeout;
			} else {
				/* Short Erase */
				tval = un->un_dp->erase_timeout;
				fixbit = 0;
			}
			un->un_lastop = ST_OP_CTL;
			count = 0;
			break;

		case SCMD_MODE_SENSE:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "mode sense\n");
			allocbp = bp;
			fixbit = 0;
			tval = un->un_dp->non_motion_timeout;
			un->un_lastop = ST_OP_CTL;
			break;

		case SCMD_MODE_SELECT:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "mode select\n");
			allocbp = bp;
			fixbit = 0;
			tval = un->un_dp->non_motion_timeout;
			un->un_lastop = ST_OP_CTL;
			break;

		case SCMD_RESERVE:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "reserve\n");
			fixbit = 0;
			tval = un->un_dp->non_motion_timeout;
			un->un_lastop = ST_OP_CTL;
			break;

		case SCMD_RELEASE:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "release\n");
			fixbit = 0;
			tval = un->un_dp->non_motion_timeout;
			un->un_lastop = ST_OP_CTL;
			break;

		case SCMD_READ_BLKLIM:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "read block limits\n");
			allocbp = bp;
			fixbit = count = 0;
			tval = un->un_dp->non_motion_timeout;
			un->un_lastop = ST_OP_CTL;
			break;

		case SCMD_TEST_UNIT_READY:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "test unit ready\n");
			fixbit = 0;
			tval = un->un_dp->non_motion_timeout;
			un->un_lastop = ST_OP_CTL;
			break;

		case SCMD_DOORLOCK:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "prevent/allow media removal\n");
			fixbit = 0;
			tval = un->un_dp->non_motion_timeout;
			un->un_lastop = ST_OP_CTL;
			break;

		case SCMD_READ_POSITION:
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "read position\n");
			fixbit = un->un_read_pos_type;
			cdb_len = CDB_GROUP1;
			tval = un->un_dp->non_motion_timeout;
			allocbp = bp;
			un->un_lastop = ST_OP_CTL;
			switch (un->un_read_pos_type) {
			case LONG_POS:
				count = 0;
				break;
			case EXT_POS:
				count = sizeof (tape_position_ext_t);
				break;
			case SHORT_POS:
				count = 0;
				break;
			default:
				ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
				    "Unknown read position type 0x%x in "
				    " st_make_cmd()\n", un->un_read_pos_type);
			}
			break;

		default:
			ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
			    "Unhandled scsi command 0x%x in st_make_cmd()\n",
			    com);
		}

		pkt = scsi_init_pkt(ROUTE, NULL, allocbp, cdb_len, stat_size,
		    st_recov_sz, 0, func, (caddr_t)un);
		if (pkt == NULL) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "generic command scsi_init_pkt() failure\n");
			goto exit;
		}

		ASSERT(pkt->pkt_resid == 0);
#ifdef STDEBUG
		bzero(pkt->pkt_private, st_recov_sz);
		bzero(pkt->pkt_scbp, stat_size);
#endif
		ri = (recov_info *)pkt->pkt_private;
		ri->privatelen = st_recov_sz;
		if (allocbp) {
			ASSERT(geterror(allocbp) == 0);
		}

	}

	ucdb = (union scsi_cdb *)pkt->pkt_cdbp;

	(void) scsi_setup_cdb(ucdb, com, address, (uint_t)count, additional);
	FILL_SCSI1_LUN(un->un_sd, pkt);
	/*
	 * Initialize the SILI/Fixed bits of the byte 1 of cdb.
	 */
	ucdb->t_code = fixbit;
	ucdb->g0_vu_1 = short_fm;
	pkt->pkt_flags = flags;

	ASSERT(tval);
	pkt->pkt_time = tval;
	if (bp == un->un_recov_buf) {
		pkt->pkt_comp = st_recov_cb;
	} else {
		pkt->pkt_comp = st_intr;
	}

	st_add_recovery_info_to_pkt(un, bp, pkt);

	/*
	 * If we just write data to tape and did a command that doesn't
	 * change position, we still need to write a filemark.
	 */
	if ((prev_op == ST_OP_WRITE) || (prev_op == ST_OP_WEOF)) {
		recov_info *rcvi = pkt->pkt_private;
		cmd_attribute const *atrib;

		if (rcvi->privatelen == sizeof (recov_info)) {
			atrib = rcvi->cmd_attrib;
		} else {
			atrib = st_lookup_cmd_attribute(com);
		}
		if (atrib->chg_tape_direction == DIR_NONE) {
			un->un_lastop = prev_op;
		}
	}

exit:
	ASSERT(mutex_owned(ST_MUTEX));
}


/*
 * Build a command based on a uscsi command;
 */
static void
st_make_uscsi_cmd(struct scsi_tape *un, struct uscsi_cmd *ucmd,
    struct buf *bp, int (*func)(caddr_t))
{
	struct scsi_pkt *pkt;
	recov_info *ri;
	caddr_t cdb;
	int	cdblen;
	int	stat_size = 1;
	int	flags = 0;

	ST_FUNC(ST_DEVINFO, st_make_uscsi_cmd);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_make_uscsi_cmd(): dev = 0x%lx\n", un->un_dev);

	if (ucmd->uscsi_flags & USCSI_RQENABLE) {
		if (un->un_arq_enabled) {
			if (ucmd->uscsi_rqlen > SENSE_LENGTH) {
				stat_size = (int)(ucmd->uscsi_rqlen) +
				    sizeof (struct scsi_arq_status) -
				    sizeof (struct scsi_extended_sense);
				flags = PKT_XARQ;
			} else {
				stat_size = sizeof (struct scsi_arq_status);
			}
		}
	}

	ASSERT(mutex_owned(ST_MUTEX));

	cdb = ucmd->uscsi_cdb;
	cdblen = ucmd->uscsi_cdblen;

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_make_uscsi_cmd: buflen=%ld bcount=%ld\n",
	    ucmd->uscsi_buflen, bp->b_bcount);
	pkt = scsi_init_pkt(ROUTE, NULL,
	    (bp->b_bcount > 0) ? bp : NULL,
	    cdblen, stat_size, st_recov_sz, flags, func, (caddr_t)un);
	if (pkt == NULL) {
		scsi_log(ST_DEVINFO, st_label, CE_NOTE,
		    "uscsi command scsi_init_pkt() failure\n");
		goto exit;
	}

	ASSERT(pkt->pkt_resid == 0);
#ifdef STDEBUG
	bzero(pkt->pkt_private, st_recov_sz);
	bzero(pkt->pkt_scbp, stat_size);
#endif
	ri = (recov_info *)pkt->pkt_private;
	ri->privatelen = st_recov_sz;

	bcopy(cdb, pkt->pkt_cdbp, (uint_t)cdblen);

#ifdef STDEBUG
	if ((st_debug & 0x7) >= 6) {
		st_clean_print(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "pkt_cdbp", (char *)cdb, cdblen);
	}
#endif

	if (ucmd->uscsi_flags & USCSI_SILENT) {
		pkt->pkt_flags |= FLAG_SILENT;
	}

	(void) scsi_uscsi_pktinit(ucmd, pkt);

	pkt->pkt_time = ucmd->uscsi_timeout;
	if (bp == un->un_recov_buf) {
		pkt->pkt_comp = st_recov_cb;
	} else {
		pkt->pkt_comp = st_intr;
	}

	st_add_recovery_info_to_pkt(un, bp, pkt);
exit:
	ASSERT(mutex_owned(ST_MUTEX));
}


/*
 * restart cmd currently at the head of the runq
 *
 * If scsi_transport() succeeds or the retries
 * count exhausted, restore the throttle that was
 * zeroed out in st_handle_intr_busy().
 *
 */
static void
st_intr_restart(void *arg)
{
	struct scsi_tape *un = arg;
	struct buf *bp;
	int queued;
	int status = TRAN_ACCEPT;

	mutex_enter(ST_MUTEX);

	ST_FUNC(ST_DEVINFO, st_intr_restart);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_intr_restart(), un = 0x%p\n", (void *)un);

	un->un_hib_tid = 0;

	if (un->un_recov_buf_busy != 0) {
		bp = un->un_recov_buf;
		queued = 0;
	} else if (un->un_sbuf_busy != 0) {
		bp = un->un_sbufp;
		queued = 0;
	} else if (un->un_quef != NULL) {
		bp = un->un_quef;
		queued = 1;
	} else {
		mutex_exit(ST_MUTEX);
		return;
	}

	/*
	 * Here we know :
	 *	throttle = 0, via st_handle_intr_busy
	 */

	if (queued) {
		/*
		 * move from waitq to runq, if there is anything on the waitq
		 */
		(void) st_remove_from_queue(&un->un_quef, &un->un_quef, bp);

		if (un->un_runqf) {
			/*
			 * not good, we don't want to requeue something after
			 * another.
			 */
			goto done_error;
		} else {
			un->un_runqf = bp;
			un->un_runql = bp;
		}
	}

	ST_CDB(ST_DEVINFO, "Interrupt restart CDB",
	    (char *)BP_PKT(bp)->pkt_cdbp);

	ST_DO_KSTATS(bp, kstat_waitq_to_runq);

	status = st_transport(un, BP_PKT(bp));

	if (status != TRAN_ACCEPT) {
		ST_DO_KSTATS(bp, kstat_runq_back_to_waitq);

		if (status == TRAN_BUSY) {
			pkt_info *pkti = BP_PKT(bp)->pkt_private;

			if (pkti->privatelen == sizeof (recov_info) &&
			    un->un_unit_attention_flags &&
			    bp != un->un_recov_buf) {
			un->un_unit_attention_flags = 0;
				ST_RECOV(ST_DEVINFO, st_label, CE_WARN,
				    "Command Recovery called on busy resend\n");
				if (st_command_recovery(un, BP_PKT(bp),
				    ATTEMPT_RETRY) == JUST_RETURN) {
					mutex_exit(ST_MUTEX);
					return;
				}
			}
			mutex_exit(ST_MUTEX);
			if (st_handle_intr_busy(un, bp,
			    ST_TRAN_BUSY_TIMEOUT) == 0)
				return;	/* timeout is setup again */
			mutex_enter(ST_MUTEX);
		}

done_error:
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "restart transport rejected\n");
		bp->b_resid = bp->b_bcount;

		if (un->un_last_throttle) {
			un->un_throttle = un->un_last_throttle;
		}
		if (status != TRAN_ACCEPT) {
			ST_DO_ERRSTATS(un, st_transerrs);
		}
		ST_DO_KSTATS(bp, kstat_waitq_exit);
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "busy restart aborted\n");
		st_set_pe_flag(un);
		st_bioerror(bp, EIO);
		st_done_and_mutex_exit(un, bp);
	} else {
		if (un->un_last_throttle) {
			un->un_throttle = un->un_last_throttle;
		}
		mutex_exit(ST_MUTEX);
	}
}

/*
 * st_check_media():
 * Periodically check the media state using scsi_watch service;
 * this service calls back after TUR and possibly request sense
 * the callback handler (st_media_watch_cb()) decodes the request sense
 * data (if any)
 */

static int
st_check_media(dev_t dev, enum mtio_state state)
{
	int rval = 0;
	enum mtio_state	prev_state;
	opaque_t token = NULL;

	GET_SOFT_STATE(dev);

	ST_FUNC(ST_DEVINFO, st_check_media);

	mutex_enter(ST_MUTEX);

	ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_check_media:state=%x, mediastate=%x\n",
	    state, un->un_mediastate);

	prev_state = un->un_mediastate;

	/*
	 * is there anything to do?
	 */
retry:
	if (state == un->un_mediastate || un->un_mediastate == MTIO_NONE) {
		/*
		 * submit the request to the scsi_watch service;
		 * scsi_media_watch_cb() does the real work
		 */
		mutex_exit(ST_MUTEX);
		token = scsi_watch_request_submit(ST_SCSI_DEVP,
		    st_check_media_time, SENSE_LENGTH,
		    st_media_watch_cb, (caddr_t)dev);
		if (token == NULL) {
			rval = EAGAIN;
			goto done;
		}
		mutex_enter(ST_MUTEX);

		un->un_swr_token = token;
		un->un_specified_mediastate = state;

		/*
		 * now wait for media change
		 * we will not be signalled unless mediastate == state but it
		 * still better to test for this condition, since there
		 * is a 5 sec cv_broadcast delay when
		 *  mediastate == MTIO_INSERTED
		 */
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_check_media:waiting for media state change\n");
		while (un->un_mediastate == state) {
			if (cv_wait_sig(&un->un_state_cv, ST_MUTEX) == 0) {
				mutex_exit(ST_MUTEX);
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_check_media:waiting for media state "
				    "was interrupted\n");
				rval = EINTR;
				goto done;
			}
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_check_media:received signal, state=%x\n",
			    un->un_mediastate);
		}
	}

	/*
	 * if we transitioned to MTIO_INSERTED, media has really been
	 * inserted.  If TUR fails, it is probably a exabyte slow spin up.
	 * Reset and retry the state change.  If everything is ok, replay
	 * the open() logic.
	 */
	if ((un->un_mediastate == MTIO_INSERTED) &&
	    (un->un_state == ST_STATE_OFFLINE)) {
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_check_media: calling st_cmd to confirm inserted\n");

		/*
		 * set this early so that TUR will make it through strategy
		 * without triggering a st_tape_init().  We needed it set
		 * before calling st_tape_init() ourselves anyway.  If TUR
		 * fails, set it back
		 */
		un->un_state = ST_STATE_INITIALIZING;

		/*
		 * If not reserved fail as getting reservation conflict
		 * will make this hang forever.
		 */
		if ((un->un_rsvd_status &
		    (ST_RESERVE | ST_APPLICATION_RESERVATIONS)) == 0) {
			mutex_exit(ST_MUTEX);
			rval = EACCES;
			goto done;
		}
		rval = st_cmd(un, SCMD_TEST_UNIT_READY, 0, SYNC_CMD);
		if (rval == EACCES) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_check_media: TUR got Reservation Conflict\n");
			mutex_exit(ST_MUTEX);
			goto done;
		}
		if (rval) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_check_media: TUR failed, going to retry\n");
			un->un_mediastate = prev_state;
			un->un_state = ST_STATE_OFFLINE;
			goto retry;
		}
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_check_media: media inserted\n");

		/* this also rewinds the tape */
		rval = st_tape_init(un);
		if (rval != 0) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_check_media : OFFLINE init failure ");
			un->un_state = ST_STATE_OFFLINE;
			un->un_pos.pmode = invalid;
		} else {
			un->un_state = ST_STATE_OPEN_PENDING_IO;
		}
	} else if ((un->un_mediastate == MTIO_EJECTED) &&
	    (un->un_state != ST_STATE_OFFLINE)) {
		/*
		 * supported devices must be rewound before ejection
		 * rewind resets fileno & blkno
		 */
		un->un_laststate = un->un_state;
		un->un_state = ST_STATE_OFFLINE;
	}
	mutex_exit(ST_MUTEX);
done:
	if (token) {
		(void) scsi_watch_request_terminate(token,
		    SCSI_WATCH_TERMINATE_WAIT);
		mutex_enter(ST_MUTEX);
		un->un_swr_token = (opaque_t)NULL;
		mutex_exit(ST_MUTEX);
	}

	ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG, "st_check_media: done\n");

	return (rval);
}

/*
 * st_media_watch_cb() is called by scsi_watch_thread for
 * verifying the request sense data (if any)
 */
static int
st_media_watch_cb(caddr_t arg, struct scsi_watch_result *resultp)
{
	struct scsi_status *statusp = resultp->statusp;
	struct scsi_extended_sense *sensep = resultp->sensep;
	uchar_t actual_sense_length = resultp->actual_sense_length;
	struct scsi_tape *un;
	enum mtio_state state = MTIO_NONE;
	int instance;
	dev_t dev = (dev_t)arg;

	instance = MTUNIT(dev);
	if ((un = ddi_get_soft_state(st_state, instance)) == NULL) {
		return (-1);
	}

	mutex_enter(ST_MUTEX);
	ST_FUNC(ST_DEVINFO, st_media_watch_cb);
	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_media_watch_cb: status=%x, sensep=%p, len=%x\n",
	    *((char *)statusp), (void *)sensep,
	    actual_sense_length);


	/*
	 * if there was a check condition then sensep points to valid
	 * sense data
	 * if status was not a check condition but a reservation or busy
	 * status then the new state is MTIO_NONE
	 */
	if (sensep) {
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_media_watch_cb: KEY=%x, ASC=%x, ASCQ=%x\n",
		    sensep->es_key, sensep->es_add_code, sensep->es_qual_code);

		switch (un->un_dp->type) {
		default:
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_media_watch_cb: unknown drive type %d, "
			    "default to ST_TYPE_HP\n", un->un_dp->type);
		/* FALLTHROUGH */

		case ST_TYPE_STC3490:	/* STK 4220 1/2" cartridge */
		case ST_TYPE_FUJI:	/* 1/2" cartridge */
		case ST_TYPE_HP:	/* HP 88780 1/2" reel */
			if (un->un_dp->type == ST_TYPE_FUJI) {
				ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_media_watch_cb: ST_TYPE_FUJI\n");
			} else {
				ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_media_watch_cb: ST_TYPE_HP\n");
			}
			switch (sensep->es_key) {
			case KEY_UNIT_ATTENTION:
				/* not ready to ready transition */
				/* hp/es_qual_code == 80 on>off>on */
				/* hp/es_qual_code == 0 on>off>unld>ld>on */
				if (sensep->es_add_code == 0x28) {
					state = MTIO_INSERTED;
				}
				break;
			case KEY_NOT_READY:
				/* in process, rewinding or loading */
				if ((sensep->es_add_code == 0x04) &&
				    (sensep->es_qual_code == 0x00)) {
					state = MTIO_EJECTED;
				}
				break;
			}
			break;

		case ST_TYPE_EXB8500:	/* Exabyte 8500 */
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_media_watch_cb: ST_TYPE_EXB8500\n");
			switch (sensep->es_key) {
			case KEY_UNIT_ATTENTION:
				/* operator medium removal request */
				if ((sensep->es_add_code == 0x5a) &&
				    (sensep->es_qual_code == 0x01)) {
					state = MTIO_EJECTED;
				/* not ready to ready transition */
				} else if ((sensep->es_add_code == 0x28) &&
				    (sensep->es_qual_code == 0x00)) {
					state = MTIO_INSERTED;
				}
				break;
			case KEY_NOT_READY:
				/* medium not present */
				if (sensep->es_add_code == 0x3a) {
					state = MTIO_EJECTED;
				}
				break;
			}
			break;
		case ST_TYPE_EXABYTE:	/* Exabyte 8200 */
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_media_watch_cb: ST_TYPE_EXABYTE\n");
			switch (sensep->es_key) {
			case KEY_NOT_READY:
				if ((sensep->es_add_code == 0x04) &&
				    (sensep->es_qual_code == 0x00)) {
					/* volume not mounted? */
					state = MTIO_EJECTED;
				} else if (sensep->es_add_code == 0x3a) {
					state = MTIO_EJECTED;
				}
				break;
			case KEY_UNIT_ATTENTION:
				state = MTIO_EJECTED;
				break;
			}
			break;

		case ST_TYPE_DLT:		/* quantum DLT4xxx */
			switch (sensep->es_key) {
			case KEY_UNIT_ATTENTION:
				if (sensep->es_add_code == 0x28) {
					state = MTIO_INSERTED;
				}
				break;
			case KEY_NOT_READY:
				if (sensep->es_add_code == 0x04) {
					/* in transition but could be either */
					state = un->un_specified_mediastate;
				} else if ((sensep->es_add_code == 0x3a) &&
				    (sensep->es_qual_code == 0x00)) {
					state = MTIO_EJECTED;
				}
				break;
			}
			break;
		}
	} else if (*((char *)statusp) == STATUS_GOOD) {
		state = MTIO_INSERTED;
	}

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_media_watch_cb:state=%x, specified=%x\n",
	    state, un->un_specified_mediastate);

	/*
	 * now signal the waiting thread if this is *not* the specified state;
	 * delay the signal if the state is MTIO_INSERTED
	 * to allow the target to recover
	 */
	if (state != un->un_specified_mediastate) {
		un->un_mediastate = state;
		if (state == MTIO_INSERTED) {
			/*
			 * delay the signal to give the drive a chance
			 * to do what it apparently needs to do
			 */
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_media_watch_cb:delayed cv_broadcast\n");
			un->un_delay_tid = timeout(st_delayed_cv_broadcast,
			    un, drv_usectohz((clock_t)MEDIA_ACCESS_DELAY));
		} else {
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_media_watch_cb:immediate cv_broadcast\n");
			cv_broadcast(&un->un_state_cv);
		}
	}
	mutex_exit(ST_MUTEX);
	return (0);
}

/*
 * delayed cv_broadcast to allow for target to recover
 * from media insertion
 */
static void
st_delayed_cv_broadcast(void *arg)
{
	struct scsi_tape *un = arg;

	ST_FUNC(ST_DEVINFO, st_delayed_cv_broadcast);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_delayed_cv_broadcast:delayed cv_broadcast\n");

	mutex_enter(ST_MUTEX);
	cv_broadcast(&un->un_state_cv);
	mutex_exit(ST_MUTEX);
}

/*
 * restart cmd currently at the start of the waitq
 */
static void
st_start_restart(void *arg)
{
	struct scsi_tape *un = arg;

	ST_FUNC(ST_DEVINFO, st_start_restart);

	ASSERT(un != NULL);

	mutex_enter(ST_MUTEX);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_tran_restart()\n");

	st_start(un);

	mutex_exit(ST_MUTEX);
}


/*
 * Command completion processing
 *
 */
static void
st_intr(struct scsi_pkt *pkt)
{
	recov_info *rcv = pkt->pkt_private;
	struct buf *bp = rcv->cmd_bp;
	struct scsi_tape *un;
	errstate action = COMMAND_DONE;
	clock_t	timout;
	int	status;

	un = ddi_get_soft_state(st_state, MTUNIT(bp->b_edev));

	ST_FUNC(ST_DEVINFO, st_intr);

	ASSERT(un != NULL);

	mutex_enter(ST_MUTEX);

	ASSERT(bp != un->un_recov_buf);

	un->un_rqs_state &= ~(ST_RQS_ERROR);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_intr()\n");

	if (pkt->pkt_reason != CMD_CMPLT) {
		ST_DEBUG(ST_DEVINFO, st_label, CE_WARN,
		    "Unhappy packet status reason = %s statistics = 0x%x\n",
		    scsi_rname(pkt->pkt_reason), pkt->pkt_statistics);

		/* If device has gone away not much else to do */
		if (pkt->pkt_reason == CMD_DEV_GONE) {
			action = COMMAND_DONE_ERROR;
		} else if ((pkt == un->un_rqs) ||
		    (un->un_state == ST_STATE_SENSING)) {
			ASSERT(pkt == un->un_rqs);
			ASSERT(un->un_state == ST_STATE_SENSING);
			un->un_state = un->un_laststate;
			rcv->cmd_bp = un->un_rqs_bp;
			ST_DO_ERRSTATS(un, st_transerrs);
			action = COMMAND_DONE_ERROR;
		} else {
			action = st_handle_incomplete(un, bp);
		}
	/*
	 * At this point we know that the command was successfully
	 * completed. Now what?
	 */
	} else if ((pkt == un->un_rqs) || (un->un_state == ST_STATE_SENSING)) {
		/*
		 * okay. We were running a REQUEST SENSE. Find
		 * out what to do next.
		 */
		ASSERT(pkt == un->un_rqs);
		ASSERT(un->un_state == ST_STATE_SENSING);
		scsi_sync_pkt(pkt);
		action = st_handle_sense(un, bp, &un->un_pos);
		/*
		 * Make rqs isn't going to be retied.
		 */
		if (action != QUE_BUSY_COMMAND && action != QUE_COMMAND) {
			/*
			 * set pkt back to original packet in case we will have
			 * to requeue it
			 */
			pkt = BP_PKT(bp);
			rcv->cmd_bp = un->un_rqs_bp;
			/*
			 * some actions are based on un_state, hence
			 * restore the state st was in before ST_STATE_SENSING.
			 */
			un->un_state = un->un_laststate;
		}

	} else if (un->un_arq_enabled && (pkt->pkt_state & STATE_ARQ_DONE)) {
		/*
		 * the transport layer successfully completed an autorqsense
		 */
		action = st_handle_autosense(un, bp, &un->un_pos);

	} else  if ((SCBP(pkt)->sts_busy) ||
	    (SCBP(pkt)->sts_chk) ||
	    (SCBP(pkt)->sts_vu7)) {
		/*
		 * Okay, we weren't running a REQUEST SENSE. Call a routine
		 * to see if the status bits we're okay. If a request sense
		 * is to be run, that will happen.
		 */
		action = st_check_error(un, pkt);
	}

	if (un->un_pwr_mgmt == ST_PWR_SUSPENDED) {
		switch (action) {
			case QUE_COMMAND:
				/*
				 * return cmd to head to the queue
				 * since we are suspending so that
				 * it gets restarted during resume
				 */
				st_add_to_queue(&un->un_runqf, &un->un_runql,
				    un->un_runqf, bp);

				action = JUST_RETURN;
				break;

			case QUE_SENSE:
				action = COMMAND_DONE_ERROR;
				break;

			default:
				break;
		}
	}

	/*
	 * check for undetected path failover.
	 */
	if (un->un_multipath) {

		struct uscsi_cmd *ucmd = BP_UCMD(bp);
		int pkt_valid = 0;

		if (ucmd) {
			/*
			 * Also copies path instance to the uscsi structure.
			 */
			pkt_valid = scsi_uscsi_pktfini(pkt, ucmd);

			/*
			 * scsi_uscsi_pktfini() zeros pkt_path_instance.
			 */
			pkt->pkt_path_instance = ucmd->uscsi_path_instance;
		} else {
			pkt_valid = scsi_pkt_allocated_correctly(pkt);
		}

		/*
		 * If the scsi_pkt was not allocated correctly the
		 * pkt_path_instance is not even there.
		 */
		if ((pkt_valid != 0) &&
		    (un->un_last_path_instance != pkt->pkt_path_instance)) {
			/*
			 * Don't recover the path change if it was done
			 * intentionally or if the device has not completely
			 * opened yet.
			 */
			if (((pkt->pkt_flags & FLAG_PKT_PATH_INSTANCE) == 0) &&
			    (un->un_state > ST_STATE_OPENING)) {
				ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
				    "Failover detected, action is %s\n",
				    errstatenames[action]);
				if (action == COMMAND_DONE) {
					action = PATH_FAILED;
				}
			}
			un->un_last_path_instance = pkt->pkt_path_instance;
		}
	}

	/*
	 * Restore old state if we were sensing.
	 */
	if (un->un_state == ST_STATE_SENSING && action != QUE_SENSE) {
		un->un_state = un->un_laststate;
	}

	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_intr: pkt=%p, bp=%p, action=%s, status=%x\n",
	    (void *)pkt, (void *)bp, errstatenames[action], SCBP_C(pkt));

again:
	switch (action) {
	case COMMAND_DONE_EACCES:
		/* this is to report a reservation conflict */
		st_bioerror(bp, EACCES);
		ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Reservation Conflict \n");
		un->un_pos.pmode = invalid;

		/*FALLTHROUGH*/
	case COMMAND_DONE_ERROR:
		if (un->un_pos.eof < ST_EOT_PENDING &&
		    un->un_state >= ST_STATE_OPEN) {
			/*
			 * all errors set state of the tape to 'unknown'
			 * unless we're at EOT or are doing append testing.
			 * If sense key was illegal request, preserve state.
			 */
			if (un->un_status != KEY_ILLEGAL_REQUEST) {
				un->un_pos.pmode = invalid;
			}
		}

		un->un_err_resid = bp->b_resid = bp->b_bcount;
		/*
		 * since we have an error (COMMAND_DONE_ERROR), we want to
		 * make sure an error ocurrs, so make sure at least EIO is
		 * returned
		 */
		if (geterror(bp) == 0)
			st_bioerror(bp, EIO);

		st_set_pe_flag(un);
		if (!(un->un_rqs_state & ST_RQS_ERROR) &&
		    (un->un_errno == EIO)) {
			un->un_rqs_state &= ~(ST_RQS_VALID);
		}
		break;

	case COMMAND_DONE_ERROR_RECOVERED:
		un->un_err_resid = bp->b_resid = bp->b_bcount;
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_intr(): COMMAND_DONE_ERROR_RECOVERED");
		if (geterror(bp) == 0) {
			st_bioerror(bp, EIO);
		}
		st_set_pe_flag(un);
		if (!(un->un_rqs_state & ST_RQS_ERROR) &&
		    (un->un_errno == EIO)) {
			un->un_rqs_state &= ~(ST_RQS_VALID);
		}
		/*FALLTHROUGH*/
	case COMMAND_DONE:
		st_set_state(un, bp);
		break;

	case QUE_SENSE:
		if ((un->un_ncmds > 1) && !un->un_flush_on_errors)
			goto sense_error;

		if (un->un_state != ST_STATE_SENSING) {
			un->un_laststate = un->un_state;
			un->un_state = ST_STATE_SENSING;
		}

		/*
		 * zero the sense data.
		 */
		bzero(un->un_rqs->pkt_scbp, SENSE_LENGTH);

		/*
		 * If this is not a retry on QUE_SENSE point to the original
		 * bp of the command that got us here.
		 */
		if (pkt != un->un_rqs) {
			((recov_info *)un->un_rqs->pkt_private)->cmd_bp = bp;
		}

		if (un->un_throttle) {
			un->un_last_throttle = un->un_throttle;
			un->un_throttle = 0;
		}

		ST_CDB(ST_DEVINFO, "Queue sense CDB",
		    (char *)BP_PKT(bp)->pkt_cdbp);

		/*
		 * never retry this, some other command will have nuked the
		 * sense, anyway
		 */
		status = st_transport(un, un->un_rqs);

		if (un->un_last_throttle) {
			un->un_throttle = un->un_last_throttle;
		}

		if (status == TRAN_ACCEPT) {
			mutex_exit(ST_MUTEX);
			return;
		}
		if (status != TRAN_BUSY)
			ST_DO_ERRSTATS(un, st_transerrs);
sense_error:
		un->un_pos.pmode = invalid;
		st_bioerror(bp, EIO);
		st_set_pe_flag(un);
		break;

	case QUE_BUSY_COMMAND:
		/* longish timeout */
		timout = ST_STATUS_BUSY_TIMEOUT;
		goto que_it_up;

	case QUE_COMMAND:
		/* short timeout */
		timout = ST_TRAN_BUSY_TIMEOUT;
que_it_up:
		/*
		 * let st_handle_intr_busy put this bp back on waitq and make
		 * checks to see if it is ok to requeue the command.
		 */
		ST_DO_KSTATS(bp, kstat_runq_back_to_waitq);

		/*
		 * Save the throttle before setting up the timeout
		 */
		if (un->un_throttle) {
			un->un_last_throttle = un->un_throttle;
		}
		mutex_exit(ST_MUTEX);
		if (st_handle_intr_busy(un, bp, timout) == 0)
			return;		/* timeout is setup again */

		mutex_enter(ST_MUTEX);
		un->un_pos.pmode = invalid;
		un->un_err_resid = bp->b_resid = bp->b_bcount;
		st_bioerror(bp, EIO);
		st_set_pe_flag(un);
		break;

	case QUE_LAST_COMMAND:

		if ((un->un_ncmds > 1) && !un->un_flush_on_errors) {
			scsi_log(ST_DEVINFO, st_label, CE_CONT,
			    "un_ncmds: %d can't retry cmd \n", un->un_ncmds);
			goto last_command_error;
		}
		mutex_exit(ST_MUTEX);
		if (st_handle_intr_retry_lcmd(un, bp) == 0)
			return;
		mutex_enter(ST_MUTEX);
last_command_error:
		un->un_err_resid = bp->b_resid = bp->b_bcount;
		un->un_pos.pmode = invalid;
		st_bioerror(bp, EIO);
		st_set_pe_flag(un);
		break;

	case COMMAND_TIMEOUT:
	case DEVICE_RESET:
	case DEVICE_TAMPER:
	case ATTEMPT_RETRY:
	case PATH_FAILED:
		ST_RECOV(ST_DEVINFO, st_label, CE_WARN,
		    "Command Recovery called on %s status\n",
		    errstatenames[action]);
		action = st_command_recovery(un, pkt, action);
		goto again;

	default:
		ASSERT(0);
		/* FALLTHRU */
	case JUST_RETURN:
		ST_DO_KSTATS(bp, kstat_runq_back_to_waitq);
		mutex_exit(ST_MUTEX);
		return;
	}

	ST_DO_KSTATS(bp, kstat_runq_exit);
	st_done_and_mutex_exit(un, bp);
}

static errstate
st_handle_incomplete(struct scsi_tape *un, struct buf *bp)
{
	static char *fail = "SCSI transport failed: reason '%s': %s\n";
	recov_info *rinfo;
	errstate rval = COMMAND_DONE_ERROR;
	struct scsi_pkt *pkt = (un->un_state == ST_STATE_SENSING) ?
	    un->un_rqs : BP_PKT(bp);
	int result;

	ST_FUNC(ST_DEVINFO, st_handle_incomplete);

	rinfo = (recov_info *)pkt->pkt_private;

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_handle_incomplete(): dev = 0x%lx\n", un->un_dev);

	ASSERT(mutex_owned(ST_MUTEX));

	/* prevent infinite number of retries */
	if (rinfo->pkt_retry_cnt++ > st_retry_count) {
		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "Recovery stopped for incomplete %s command, "
		    "retries exhausted",
		    st_print_scsi_cmd(pkt->pkt_cdbp[0]));
		return (COMMAND_DONE_ERROR);
	}

	switch (pkt->pkt_reason) {
	case CMD_INCOMPLETE:	/* tran stopped with not normal state */
		/*
		 * this occurs when accessing a powered down drive, no
		 * need to complain; just fail the open
		 */
		ST_CDB(ST_DEVINFO, "Incomplete CDB", (char *)pkt->pkt_cdbp);

		/*
		 * if we have commands outstanding in HBA, and a command
		 * comes back incomplete, we're hosed, so reset target
		 * If we have the bus, but cmd_incomplete, we probably just
		 * have a failed selection, so don't reset the target, just
		 * requeue the command and try again
		 */
		if ((un->un_ncmds > 1) || (pkt->pkt_state != STATE_GOT_BUS)) {
			goto reset_target;
		}

		/*
		 * Retry selection a couple more times if we're
		 * open.  If opening, we only try just once to
		 * reduce probe time for nonexistant devices.
		 */
		if ((un->un_laststate > ST_STATE_OPENING) &&
		    (rinfo->pkt_retry_cnt < st_selection_retry_count)) {
			/* XXX check retriable? */
			rval = QUE_COMMAND;
		}
		ST_DO_ERRSTATS(un, st_transerrs);
		break;

	case CMD_ABORTED:
		/*
		 * most likely this is caused by flush-on-error support. If
		 * it was not there, the we're in trouble.
		 */
		if (!un->un_flush_on_errors) {
			un->un_status = SUN_KEY_FATAL;
			goto reset_target;
		}

		st_set_pe_errno(un);
		bioerror(bp, un->un_errno);
		if (un->un_errno)
			return (COMMAND_DONE_ERROR);
		else
			return (COMMAND_DONE);

	case CMD_TIMEOUT:	/* Command timed out */
		un->un_status = SUN_KEY_TIMEOUT;
		return (COMMAND_TIMEOUT);

	case CMD_TRAN_ERR:
	case CMD_RESET:
		if (pkt->pkt_statistics & (STAT_BUS_RESET | STAT_DEV_RESET)) {
			if ((un->un_rsvd_status &
			    (ST_RESERVE | ST_APPLICATION_RESERVATIONS)) ==
			    ST_RESERVE) {
				un->un_rsvd_status |= ST_LOST_RESERVE;
				ST_DEBUG3(ST_DEVINFO, st_label, CE_WARN,
				    "Lost Reservation\n");
			}
			rval = DEVICE_RESET;
			return (rval);
		}
		if (pkt->pkt_statistics & (STAT_ABORTED | STAT_TERMINATED)) {
			rval = DEVICE_RESET;
			return (rval);
		}
		/*FALLTHROUGH*/
	default:
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "Unhandled packet status reason = %s statistics = 0x%x\n",
		    scsi_rname(pkt->pkt_reason), pkt->pkt_statistics);
reset_target:

		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "transport completed with %s\n",
		    scsi_rname(pkt->pkt_reason));
		ST_DO_ERRSTATS(un, st_transerrs);
		if ((pkt->pkt_state & STATE_GOT_TARGET) &&
		    ((pkt->pkt_statistics & (STAT_BUS_RESET | STAT_DEV_RESET |
		    STAT_ABORTED)) == 0)) {

			/*
			 * If we haven't reserved the drive don't reset it.
			 */
			if ((un->un_rsvd_status &
			    (ST_RESERVE | ST_APPLICATION_RESERVATIONS)) == 0) {
				return (rval);
			}

			/*
			 * if we aren't lost yet we will be soon.
			 */
			un->un_pos.pmode = invalid;

			result = st_reset(un, RESET_LUN);

			if ((result == 0) && (un->un_state >= ST_STATE_OPEN)) {
				/* no hope left to recover */
				scsi_log(ST_DEVINFO, st_label, CE_WARN,
				    "recovery by resets failed\n");
				return (rval);
			}
		}
	}


	if (un->un_pwr_mgmt == ST_PWR_SUSPENDED) {
		rval = QUE_COMMAND;
	} else if (bp == un->un_sbufp) {
		if (rinfo->privatelen == sizeof (recov_info)) {
			if (rinfo->cmd_attrib->retriable) {
				/*
				 * These commands can be rerun
				 * with impunity
				 */
				rval = QUE_COMMAND;
			}
		} else {
			cmd_attribute const *attrib;
			attrib = st_lookup_cmd_attribute(pkt->pkt_cdbp[0]);
			if (attrib->retriable) {
				rval = QUE_COMMAND;
			}
		}
	}

	if (un->un_state >= ST_STATE_OPEN) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    fail, scsi_rname(pkt->pkt_reason),
		    (rval == COMMAND_DONE_ERROR)?
		    "giving up" : "retrying command");
	}
	return (rval);
}

/*
 * if the device is busy, then put this bp back on the waitq, on the
 * interrupt thread, where we want the head of the queue and not the
 * end
 *
 * The callers of this routine should take measures to save the
 * un_throttle in un_last_throttle which will be restored in
 * st_intr_restart(). The only exception should be st_intr_restart()
 * calling this routine for which the saving is already done.
 */
static int
st_handle_intr_busy(struct scsi_tape *un, struct buf *bp,
	clock_t timeout_interval)
{

	int queued;
	int rval = 0;
	pkt_info *pktinfo = BP_PKT(bp)->pkt_private;

	mutex_enter(ST_MUTEX);

	ST_FUNC(ST_DEVINFO, st_handle_intr_busy);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_handle_intr_busy(), un = 0x%p\n", (void *)un);

	if ((bp != un->un_sbufp) && (bp != un->un_recov_buf)) {
		queued = 1;
	} else {
		queued = 0;
	}

	/*
	 * Check to see if we hit the retry timeout. We check to make sure
	 * this is the first one on the runq and make sure we have not
	 * queued up any more, so this one has to be the last on the list
	 * also. If it is not, we have to fail.  If it is not the first, but
	 * is the last we are in trouble anyway, as we are in the interrupt
	 * context here.
	 */
	if ((pktinfo->str_retry_cnt++ > st_retry_count) ||
	    ((un->un_runqf != bp) && (un->un_runql != bp) && (queued))) {
		rval = -1;
		goto exit;
	}

	/* put the bp back on the waitq */
	if (queued) {
		(void) st_remove_from_queue(&un->un_runqf, &un->un_runql, bp);
		st_add_to_queue(&un->un_quef, &un->un_quel, un->un_quef, bp);
	}

	/*
	 * We don't want any other commands being started in the mean time.
	 * If start had just released mutex after putting something on the
	 * runq, we won't even get here.
	 */
	un->un_throttle = 0;

	/*
	 * send a marker pkt, if appropriate
	 */
	st_hba_unflush(un);

	/*
	 * all queues are aligned, we are just waiting to
	 * transport
	 */
	un->un_hib_tid = timeout(st_intr_restart, un, timeout_interval);

exit:
	mutex_exit(ST_MUTEX);
	return (rval);
}

/*
 * To get one error entry from error stack
 */
static int
st_get_error_entry(struct scsi_tape *un, intptr_t arg, int flag)
{
#ifdef _MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl
	 */
	struct mterror_entry32 err_entry32;
#endif /* _MULTI_DATAMODEL */

	int rval = 0;
	struct mterror_entry err_entry;
	struct mterror_entry_stack *err_link_entry_p;
	size_t arq_status_len_in, arq_status_len_kr;

	ST_FUNC(ST_DEVINFO, st_get_error_entry);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_get_error_entry()\n");

	/*
	 * if error record stack empty, return ENXIO
	 */
	if (un->un_error_entry_stk == NULL) {
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_error_entry: Error Entry Stack Empty!\n");
		rval = ENXIO;
		goto ret;
	}

	/*
	 * get the top entry from stack
	 */
	err_link_entry_p = un->un_error_entry_stk;
	arq_status_len_kr =
	    err_link_entry_p->mtees_entry.mtee_arq_status_len;

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, &err_entry32,
		    MTERROR_ENTRY_SIZE_32, flag)) {
			rval = EFAULT;
			goto ret;
		}

		arq_status_len_in =
		    (size_t)err_entry32.mtee_arq_status_len;

		err_entry32.mtee_cdb_len =
		    (size32_t)err_link_entry_p->mtees_entry.mtee_cdb_len;

		if (arq_status_len_in > arq_status_len_kr)
			err_entry32.mtee_arq_status_len =
			    (size32_t)arq_status_len_kr;

		if (ddi_copyout(
		    err_link_entry_p->mtees_entry.mtee_cdb_buf,
		    (void *)(uintptr_t)err_entry32.mtee_cdb_buf,
		    err_entry32.mtee_cdb_len, flag)) {
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_get_error_entry: Copy cdb buffer error!");
			rval = EFAULT;
		}

		if (ddi_copyout(
		    err_link_entry_p->mtees_entry.mtee_arq_status,
		    (void *)(uintptr_t)err_entry32.mtee_arq_status,
		    err_entry32.mtee_arq_status_len, flag)) {
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_get_error_entry: copy arq status error!");
			rval = EFAULT;
		}

		if (ddi_copyout(&err_entry32, (void *)arg,
		    MTERROR_ENTRY_SIZE_32, flag)) {
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_get_error_entry: copy arq status out error!");
			rval = EFAULT;
		}
		break;

	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &err_entry,
		    MTERROR_ENTRY_SIZE_64, flag)) {
			rval = EFAULT;
			goto ret;
		}
		arq_status_len_in = err_entry.mtee_arq_status_len;

		err_entry.mtee_cdb_len =
		    err_link_entry_p->mtees_entry.mtee_cdb_len;

		if (arq_status_len_in > arq_status_len_kr)
			err_entry.mtee_arq_status_len =
			    arq_status_len_kr;

		if (ddi_copyout(
		    err_link_entry_p->mtees_entry.mtee_cdb_buf,
		    err_entry.mtee_cdb_buf,
		    err_entry.mtee_cdb_len, flag)) {
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_get_error_entry: Copy cdb buffer error!");
			rval = EFAULT;
		}

		if (ddi_copyout(
		    err_link_entry_p->mtees_entry.mtee_arq_status,
		    err_entry.mtee_arq_status,
		    err_entry.mtee_arq_status_len, flag)) {
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_get_error_entry: copy arq status error!");
			rval = EFAULT;
		}

		if (ddi_copyout(&err_entry, (void *)arg,
		    MTERROR_ENTRY_SIZE_64, flag)) {
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_get_error_entry: copy arq status out error!");
			rval = EFAULT;
		}
		break;
	}
#else /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &err_entry,
	    MTERROR_ENTRY_SIZE_64, flag)) {
		rval = EFAULT;
		goto ret;
	}
	arq_status_len_in = err_entry.mtee_arq_status_len;

	err_entry.mtee_cdb_len =
	    err_link_entry_p->mtees_entry.mtee_cdb_len;

	if (arq_status_len_in > arq_status_len_kr)
		err_entry.mtee_arq_status_len =
		    arq_status_len_kr;

	if (ddi_copyout(
	    err_link_entry_p->mtees_entry.mtee_cdb_buf,
	    err_entry.mtee_cdb_buf,
	    err_entry.mtee_cdb_len, flag)) {
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_error_entry: Copy cdb buffer error!");
		rval = EFAULT;
	}

	if (ddi_copyout(
	    err_link_entry_p->mtees_entry.mtee_arq_status,
	    err_entry.mtee_arq_status,
	    err_entry.mtee_arq_status_len, flag)) {
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_error_entry: copy arq status buffer error!");
		rval = EFAULT;
	}

	if (ddi_copyout(&err_entry, (void *)arg,
	    MTERROR_ENTRY_SIZE_64, flag)) {
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_error_entry: copy arq status out error!");
		rval = EFAULT;
	}
#endif /* _MULTI_DATAMODEL */

	/*
	 * update stack
	 */
	un->un_error_entry_stk = err_link_entry_p->mtees_nextp;

	kmem_free(err_link_entry_p->mtees_entry.mtee_cdb_buf,
	    err_link_entry_p->mtees_entry.mtee_cdb_len);
	err_link_entry_p->mtees_entry.mtee_cdb_buf = NULL;

	kmem_free(err_link_entry_p->mtees_entry.mtee_arq_status,
	    SECMDS_STATUS_SIZE);
	err_link_entry_p->mtees_entry.mtee_arq_status = NULL;

	kmem_free(err_link_entry_p, MTERROR_LINK_ENTRY_SIZE);
	err_link_entry_p = NULL;
ret:
	return (rval);
}

/*
 * MTIOCGETERROR ioctl needs to retrieve the current sense data along with
 * the scsi CDB command which causes the error and generates sense data and
 * the scsi status.
 *
 *      error-record stack
 *
 *
 *             TOP                                     BOTTOM
 *              ------------------------------------------
 *              |   0   |   1   |   2   |   ...  |   n   |
 *              ------------------------------------------
 *                  ^
 *                  |
 *       pointer to error entry
 *
 * when st driver generates one sense data record, it creates a error-entry
 * and pushes it onto the stack.
 *
 */

static void
st_update_error_stack(struct scsi_tape *un,
			struct scsi_pkt *pkt,
			struct scsi_arq_status *cmd)
{
	struct mterror_entry_stack *err_entry_tmp;
	uchar_t *cdbp = (uchar_t *)pkt->pkt_cdbp;
	size_t cdblen = scsi_cdb_size[CDB_GROUPID(cdbp[0])];

	ST_FUNC(ST_DEVINFO, st_update_error_stack);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_update_error_stack()\n");

	ASSERT(cmd);
	ASSERT(cdbp);
	if (cdblen == 0) {
		ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_update_error_stack: CDB length error!\n");
		return;
	}

	err_entry_tmp = kmem_alloc(MTERROR_LINK_ENTRY_SIZE, KM_SLEEP);
	ASSERT(err_entry_tmp != NULL);

	err_entry_tmp->mtees_entry.mtee_cdb_buf =
	    kmem_alloc(cdblen, KM_SLEEP);
	ASSERT(err_entry_tmp->mtees_entry.mtee_cdb_buf != NULL);

	err_entry_tmp->mtees_entry.mtee_arq_status =
	    kmem_alloc(SECMDS_STATUS_SIZE, KM_SLEEP);
	ASSERT(err_entry_tmp->mtees_entry.mtee_arq_status != NULL);

	/*
	 * copy cdb command & length to current error entry
	 */
	err_entry_tmp->mtees_entry.mtee_cdb_len = cdblen;
	bcopy(cdbp, err_entry_tmp->mtees_entry.mtee_cdb_buf, cdblen);

	/*
	 * copy scsi status length to current error entry
	 */
	err_entry_tmp->mtees_entry.mtee_arq_status_len =
	    SECMDS_STATUS_SIZE;

	/*
	 * copy sense data and scsi status to current error entry
	 */
	bcopy(cmd, err_entry_tmp->mtees_entry.mtee_arq_status,
	    SECMDS_STATUS_SIZE);

	err_entry_tmp->mtees_nextp = un->un_error_entry_stk;
	un->un_error_entry_stk = err_entry_tmp;

}

/*
 * Empty all the error entry in stack
 */
static void
st_empty_error_stack(struct scsi_tape *un)
{
	struct mterror_entry_stack *linkp;

	ST_FUNC(ST_DEVINFO, st_empty_error_stack);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_empty_entry_stack()\n");

	while (un->un_error_entry_stk != NULL) {
		linkp = un->un_error_entry_stk;
		un->un_error_entry_stk =
		    un->un_error_entry_stk->mtees_nextp;

		if (linkp->mtees_entry.mtee_cdb_buf != NULL)
			kmem_free(linkp->mtees_entry.mtee_cdb_buf,
			    linkp->mtees_entry.mtee_cdb_len);

		if (linkp->mtees_entry.mtee_arq_status != NULL)
			kmem_free(linkp->mtees_entry.mtee_arq_status,
			    linkp->mtees_entry.mtee_arq_status_len);

		kmem_free(linkp, MTERROR_LINK_ENTRY_SIZE);
		linkp = NULL;
	}
}

static errstate
st_handle_sense(struct scsi_tape *un, struct buf *bp, tapepos_t *pos)
{
	struct scsi_pkt *pkt = BP_PKT(bp);
	struct scsi_pkt *rqpkt = un->un_rqs;
	struct scsi_arq_status arqstat;
	recov_info *rcif = pkt->pkt_private;

	errstate rval = COMMAND_DONE_ERROR;
	int amt;

	ST_FUNC(ST_DEVINFO, st_handle_sense);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_handle_sense()\n");

	if (SCBP(rqpkt)->sts_busy) {
		if (rcif->privatelen == sizeof (recov_info)) {
			ST_RECOV(ST_DEVINFO, st_label, CE_WARN,
			    "Attempt recovery of busy unit on request sense\n");
			rval = ATTEMPT_RETRY;
		} else if (rcif->pkt_retry_cnt++ < st_retry_count) {
			ST_DEBUG4(ST_DEVINFO, st_label, CE_WARN,
			    "Retry busy unit on request sense\n");
			rval = QUE_BUSY_COMMAND;
		}
		return (rval);
	} else if (SCBP(rqpkt)->sts_chk) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "Check Condition on REQUEST SENSE\n");
		return (rval);
	}

	/*
	 * Make sure there is sense data to look at.
	 */
	if ((rqpkt->pkt_state & (STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS)) != (STATE_GOT_BUS |
	    STATE_GOT_TARGET | STATE_SENT_CMD | STATE_GOT_STATUS)) {
		return (rval);
	}

	/* was there enough data? */
	amt = (int)MAX_SENSE_LENGTH - rqpkt->pkt_resid;
	if ((rqpkt->pkt_state & STATE_XFERRED_DATA) == 0 ||
	    (amt < SUN_MIN_SENSE_LENGTH)) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "REQUEST SENSE couldn't get sense data\n");
		return (rval);
	}

	bcopy(SCBP(pkt), &arqstat.sts_status,
	    sizeof (struct scsi_status));
	bcopy(SCBP(rqpkt), &arqstat.sts_rqpkt_status,
	    sizeof (struct scsi_status));
	arqstat.sts_rqpkt_reason = rqpkt->pkt_reason;
	arqstat.sts_rqpkt_resid = rqpkt->pkt_resid;
	arqstat.sts_rqpkt_state = rqpkt->pkt_state;
	arqstat.sts_rqpkt_statistics = rqpkt->pkt_statistics;
	bcopy(ST_RQSENSE, &arqstat.sts_sensedata, SENSE_LENGTH);

	/*
	 * copy one arqstat entry in the sense data buffer
	 */
	st_update_error_stack(un, pkt, &arqstat);
	return (st_decode_sense(un, bp, amt, &arqstat, pos));
}

static errstate
st_handle_autosense(struct scsi_tape *un, struct buf *bp, tapepos_t *pos)
{
	struct scsi_pkt *pkt = BP_PKT(bp);
	struct scsi_arq_status *arqstat =
	    (struct scsi_arq_status *)pkt->pkt_scbp;
	errstate rval = COMMAND_DONE_ERROR;
	int amt;

	ST_FUNC(ST_DEVINFO, st_handle_autosense);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_handle_autosense()\n");

	if (arqstat->sts_rqpkt_status.sts_busy) {
		ST_DEBUG4(ST_DEVINFO, st_label, CE_WARN,
		    "busy unit on request sense\n");
		/*
		 * we return QUE_SENSE so st_intr will setup the SENSE cmd.
		 * the disadvantage is that we do not have any delay for the
		 * second retry of rqsense and we have to keep a packet around
		 */
		return (QUE_SENSE);

	} else if (arqstat->sts_rqpkt_reason != CMD_CMPLT) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "transport error on REQUEST SENSE\n");
		if ((arqstat->sts_rqpkt_state & STATE_GOT_TARGET) &&
		    ((arqstat->sts_rqpkt_statistics &
		    (STAT_BUS_RESET | STAT_DEV_RESET | STAT_ABORTED)) == 0)) {
			if (st_reset(un, RESET_LUN) == 0) {
				ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
				    "recovery by resets failed\n");
			}
		}
		return (rval);

	} else if (arqstat->sts_rqpkt_status.sts_chk) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "Check Condition on REQUEST SENSE\n");
		return (rval);
	}


	/* was there enough data? */
	if (pkt->pkt_state & STATE_XARQ_DONE) {
		amt = (int)MAX_SENSE_LENGTH - arqstat->sts_rqpkt_resid;
	} else {
		if (arqstat->sts_rqpkt_resid > SENSE_LENGTH) {
			amt = (int)MAX_SENSE_LENGTH - arqstat->sts_rqpkt_resid;
		} else {
			amt = (int)SENSE_LENGTH - arqstat->sts_rqpkt_resid;
		}
	}
	if ((arqstat->sts_rqpkt_state & STATE_XFERRED_DATA) == 0 ||
	    (amt < SUN_MIN_SENSE_LENGTH)) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "REQUEST SENSE couldn't get sense data\n");
		return (rval);
	}

	if (pkt->pkt_state & STATE_XARQ_DONE) {
		bcopy(&arqstat->sts_sensedata, ST_RQSENSE, MAX_SENSE_LENGTH);
	} else {
		bcopy(&arqstat->sts_sensedata, ST_RQSENSE, SENSE_LENGTH);
	}

	/*
	 * copy one arqstat entry in the sense data buffer
	 */
	st_update_error_stack(un, pkt, arqstat);

	return (st_decode_sense(un, bp, amt, arqstat, pos));
}

static errstate
st_decode_sense(struct scsi_tape *un, struct buf *bp, int amt,
    struct scsi_arq_status *statusp, tapepos_t *pos)
{
	struct scsi_pkt *pkt = BP_PKT(bp);
	recov_info *ri = pkt->pkt_private;
	errstate rval = COMMAND_DONE_ERROR;
	cmd_attribute const *attrib;
	long resid;
	struct scsi_extended_sense *sensep = ST_RQSENSE;
	int severity;
	int get_error;

	ST_FUNC(ST_DEVINFO, st_decode_sense);

	ASSERT(mutex_owned(ST_MUTEX));
	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_decode_sense()\n");

	/*
	 * For uscsi commands, squirrel away a copy of the
	 * results of the Request Sense.
	 */
	if (USCSI_CMD(bp)) {
		struct uscsi_cmd *ucmd = BP_UCMD(bp);
		ucmd->uscsi_rqstatus = *(uchar_t *)statusp;
		if (ucmd->uscsi_rqlen && un->un_srqbufp) {
			uchar_t rqlen = min((uchar_t)amt, ucmd->uscsi_rqlen);
			ucmd->uscsi_rqresid = ucmd->uscsi_rqlen - rqlen;
			bcopy(ST_RQSENSE, un->un_srqbufp, rqlen);
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_decode_sense: stat=0x%x resid=0x%x\n",
			    ucmd->uscsi_rqstatus, ucmd->uscsi_rqresid);
		}
	}

	if (ri->privatelen == sizeof (recov_info)) {
		attrib = ri->cmd_attrib;
	} else {
		attrib = st_lookup_cmd_attribute(pkt->pkt_cdbp[0]);
	}

	/*
	 * If the drive is an MT-02, reposition the
	 * secondary error code into the proper place.
	 *
	 * XXX	MT-02 is non-CCS tape, so secondary error code
	 * is in byte 8.  However, in SCSI-2, tape has CCS definition
	 * so it's in byte 12.
	 */
	if (un->un_dp->type == ST_TYPE_EMULEX) {
		sensep->es_code = sensep->es_add_info[0];
	}

	ST_CDB(ST_DEVINFO, "st_decode_sense failed CDB",
	    (caddr_t)&CDBP(pkt)->scc_cmd);

	ST_SENSE(ST_DEVINFO, "st_decode_sense sense data", (caddr_t)statusp,
	    sizeof (*statusp));

	/* for normal I/O check extract the resid values. */
	if (bp != un->un_sbufp && bp != un->un_recov_buf) {
		if (sensep->es_valid) {
			resid =
			    (sensep->es_info_1 << 24) |
			    (sensep->es_info_2 << 16) |
			    (sensep->es_info_3 << 8)  |
			    (sensep->es_info_4);
			/* If fixed block */
			if (un->un_bsize) {
				resid *= un->un_bsize;
			}
		} else if (pkt->pkt_state & STATE_XFERRED_DATA) {
			resid = pkt->pkt_resid;
		} else {
			resid = bp->b_bcount;
		}
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_decode_sense (rw): xferred bit = %d, resid=%ld (%d), "
		    "pkt_resid=%ld\n", pkt->pkt_state & STATE_XFERRED_DATA,
		    resid,
		    (sensep->es_info_1 << 24) |
		    (sensep->es_info_2 << 16) |
		    (sensep->es_info_3 << 8)  |
		    (sensep->es_info_4),
		    pkt->pkt_resid);
		/*
		 * The problem is, what should we believe?
		 */
		if (resid && (pkt->pkt_resid == 0)) {
			pkt->pkt_resid = resid;
		}
	} else {
		/*
		 * If the command is SCMD_SPACE, we need to get the
		 * residual as returned in the sense data, to adjust
		 * our idea of current tape position correctly
		 */
		if ((sensep->es_valid) &&
		    (CDBP(pkt)->scc_cmd == SCMD_LOCATE) ||
		    (CDBP(pkt)->scc_cmd == SCMD_LOCATE_G4) ||
		    (CDBP(pkt)->scc_cmd == SCMD_SPACE) ||
		    (CDBP(pkt)->scc_cmd == SCMD_SPACE_G4) ||
		    (CDBP(pkt)->scc_cmd == SCMD_WRITE_FILE_MARK)) {
			resid =
			    (sensep->es_info_1 << 24) |
			    (sensep->es_info_2 << 16) |
			    (sensep->es_info_3 << 8)  |
			    (sensep->es_info_4);
			bp->b_resid = resid;
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_decode_sense(other):	resid=%ld\n", resid);
		} else {
			/*
			 * If the special command is SCMD_READ,
			 * the correct resid will be set later.
			 */
			if (attrib->get_cnt != NULL) {
				resid = attrib->get_cnt(pkt->pkt_cdbp);
			} else {
				resid = bp->b_bcount;
			}
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_decode_sense(special read):  resid=%ld\n",
			    resid);
		}
	}

	if ((un->un_state >= ST_STATE_OPEN) &&
	    (DEBUGGING || st_error_level == SCSI_ERR_ALL)) {
		st_print_cdb(ST_DEVINFO, st_label, CE_NOTE,
		    "Failed CDB", (char *)pkt->pkt_cdbp);
		st_clean_print(ST_DEVINFO, st_label, CE_CONT,
		    "sense data", (char *)sensep, amt);
		scsi_log(ST_DEVINFO, st_label, CE_CONT,
		    "count 0x%lx resid 0x%lx pktresid 0x%lx\n",
		    bp->b_bcount, resid, pkt->pkt_resid);
	}

	switch (un->un_status = sensep->es_key) {
	case KEY_NO_SENSE:
		severity = SCSI_ERR_INFO;

		/*
		 * Erase, locate or rewind operation in progress, retry
		 * ASC  ASCQ
		 *  00   18    Erase operation in progress
		 *  00   19    Locate operation in progress
		 *  00   1A    Rewind operation in progress
		 */
		if (sensep->es_add_code == 0 &&
		    ((sensep->es_qual_code == 0x18) ||
		    (sensep->es_qual_code == 0x19) ||
		    (sensep->es_qual_code == 0x1a))) {
			rval = QUE_BUSY_COMMAND;
			break;
		}

		goto common;

	case KEY_RECOVERABLE_ERROR:
		severity = SCSI_ERR_RECOVERED;
		if ((sensep->es_class == CLASS_EXTENDED_SENSE) &&
		    (sensep->es_code == ST_DEFERRED_ERROR)) {
			if (un->un_dp->options &
			    ST_RETRY_ON_RECOVERED_DEFERRED_ERROR) {
				rval = QUE_LAST_COMMAND;
				scsi_errmsg(ST_SCSI_DEVP, pkt, st_label,
				    severity, pos->lgclblkno,
				    un->un_err_pos.lgclblkno, scsi_cmds,
				    sensep);
				scsi_log(ST_DEVINFO, st_label, CE_CONT,
				    "Command will be retried\n");
			} else {
				severity = SCSI_ERR_FATAL;
				rval = COMMAND_DONE_ERROR_RECOVERED;
				ST_DO_ERRSTATS(un, st_softerrs);
				scsi_errmsg(ST_SCSI_DEVP, pkt, st_label,
				    severity, pos->lgclblkno,
				    un->un_err_pos.lgclblkno, scsi_cmds,
				    sensep);
			}
			break;
		}
common:
		/*
		 * XXX only want reads to be stopped by filemarks.
		 * Don't want them to be stopped by EOT.  EOT matters
		 * only on write.
		 */
		if (sensep->es_filmk && !sensep->es_eom) {
			rval = COMMAND_DONE;
		} else if (sensep->es_eom) {
			rval = COMMAND_DONE;
		} else if (sensep->es_ili) {
			/*
			 * Fun with variable length record devices:
			 * for specifying larger blocks sizes than the
			 * actual physical record size.
			 */
			if (un->un_bsize == 0 && resid > 0) {
				/*
				 * XXX! Ugly.
				 * The requested blocksize is > tape blocksize,
				 * so this is ok, so we just return the
				 * actual size xferred.
				 */
				pkt->pkt_resid = resid;
				rval = COMMAND_DONE;
			} else if (un->un_bsize == 0 && resid < 0) {
				/*
				 * The requested blocksize is < tape blocksize,
				 * so this is not ok, so we err with ENOMEM
				 */
				rval = COMMAND_DONE_ERROR_RECOVERED;
				st_bioerror(bp, ENOMEM);
			} else {
				ST_DO_ERRSTATS(un, st_softerrs);
				severity = SCSI_ERR_FATAL;
				rval = COMMAND_DONE_ERROR;
				st_bioerror(bp, EINVAL);
				un->un_running.pmode = invalid;
			}
		} else {
			/*
			 * we hope and pray for this just being
			 * something we can ignore (ie. a
			 * truly recoverable soft error)
			 */
			rval = COMMAND_DONE;
		}
		if (sensep->es_filmk) {
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "filemark\n");
			un->un_status = SUN_KEY_EOF;
			pos->eof = ST_EOF_PENDING;
			st_set_pe_flag(un);
		}

		/*
		 * ignore eom when reading, a fmk should terminate reading
		 */
		if ((sensep->es_eom) &&
		    (CDBP(pkt)->scc_cmd != SCMD_READ)) {
			if ((sensep->es_add_code == 0) &&
			    (sensep->es_qual_code == 4)) {
				ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "bot\n");
				un->un_status = SUN_KEY_BOT;
				pos->eof = ST_NO_EOF;
				pos->lgclblkno = 0;
				pos->fileno = 0;
				pos->blkno = 0;
				if (pos->pmode != legacy)
					pos->pmode = legacy;
			} else {
				ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "eom\n");
				un->un_status = SUN_KEY_EOT;
				pos->eof = ST_EOM;
			}
			st_set_pe_flag(un);
		}

		break;

	case KEY_ILLEGAL_REQUEST:

		if (un->un_laststate >= ST_STATE_OPEN) {
			ST_DO_ERRSTATS(un, st_softerrs);
			severity = SCSI_ERR_FATAL;
		} else {
			severity = SCSI_ERR_INFO;
		}
		break;

	case KEY_MEDIUM_ERROR:
		ST_DO_ERRSTATS(un, st_harderrs);
		severity = SCSI_ERR_FATAL;
		un->un_pos.pmode = invalid;
		un->un_running.pmode = invalid;
check_keys:
		/*
		 * attempt to process the keys in the presence of
		 * other errors
		 */
		if (sensep->es_ili && rval != COMMAND_DONE_ERROR) {
			/*
			 * Fun with variable length record devices:
			 * for specifying larger blocks sizes than the
			 * actual physical record size.
			 */
			if (un->un_bsize == 0 && resid > 0) {
				/*
				 * XXX! Ugly
				 */
				pkt->pkt_resid = resid;
			} else if (un->un_bsize == 0 && resid < 0) {
				st_bioerror(bp, EINVAL);
			} else {
				severity = SCSI_ERR_FATAL;
				rval = COMMAND_DONE_ERROR;
				st_bioerror(bp, EINVAL);
			}
		}
		if (sensep->es_filmk) {
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "filemark\n");
			un->un_status = SUN_KEY_EOF;
			pos->eof = ST_EOF_PENDING;
			st_set_pe_flag(un);
		}

		/*
		 * ignore eom when reading, a fmk should terminate reading
		 */
		if ((sensep->es_eom) &&
		    (CDBP(pkt)->scc_cmd != SCMD_READ)) {
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG, "eom\n");
			un->un_status = SUN_KEY_EOT;
			pos->eof = ST_EOM;
			st_set_pe_flag(un);
		}

		break;

	case KEY_VOLUME_OVERFLOW:
		ST_DO_ERRSTATS(un, st_softerrs);
		pos->eof = ST_EOM;
		severity = SCSI_ERR_FATAL;
		rval = COMMAND_DONE_ERROR;
		goto check_keys;

	case KEY_HARDWARE_ERROR:
		ST_DO_ERRSTATS(un, st_harderrs);
		severity = SCSI_ERR_FATAL;
		rval = COMMAND_DONE_ERROR;
		if (un->un_dp->options & ST_EJECT_ON_CHANGER_FAILURE)
			un->un_eject_tape_on_failure = st_check_asc_ascq(un);
		break;

	case KEY_BLANK_CHECK:
		ST_DO_ERRSTATS(un, st_softerrs);
		severity = SCSI_ERR_INFO;

		/*
		 * if not a special request and some data was xferred then it
		 * it is not an error yet
		 */
		if (bp != un->un_sbufp && (bp->b_flags & B_READ)) {
			/*
			 * no error for read with or without data xferred
			 */
			un->un_status = SUN_KEY_EOT;
			pos->eof = ST_EOT;
			rval = COMMAND_DONE_ERROR;
			un->un_running.pmode = invalid;
			st_set_pe_flag(un);
			goto check_keys;
		} else if (bp != un->un_sbufp &&
		    (pkt->pkt_state & STATE_XFERRED_DATA)) {
			rval = COMMAND_DONE;
		} else {
			rval = COMMAND_DONE_ERROR_RECOVERED;
		}

		if (un->un_laststate >= ST_STATE_OPEN) {
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "blank check\n");
			pos->eof = ST_EOM;
		}
		if ((CDBP(pkt)->scc_cmd == SCMD_LOCATE) ||
		    (CDBP(pkt)->scc_cmd == SCMD_LOCATE_G4) ||
		    (CDBP(pkt)->scc_cmd == SCMD_SPACE) &&
		    (un->un_dp->options & ST_KNOWS_EOD)) {
			/*
			 * we were doing a fast forward by skipping
			 * multiple fmk at the time
			 */
			st_bioerror(bp, EIO);
			severity = SCSI_ERR_RECOVERED;
			rval	 = COMMAND_DONE;
		}
		st_set_pe_flag(un);
		goto check_keys;

	case KEY_WRITE_PROTECT:
		if (st_wrongtapetype(un)) {
			un->un_status = SUN_KEY_WRONGMEDIA;
			ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
			    "wrong tape for writing- use DC6150 tape "
			    "(or equivalent)\n");
			severity = SCSI_ERR_UNKNOWN;
		} else {
			severity = SCSI_ERR_FATAL;
		}
		ST_DO_ERRSTATS(un, st_harderrs);
		rval = COMMAND_DONE_ERROR;
		st_bioerror(bp, EACCES);
		break;

	case KEY_UNIT_ATTENTION:
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "KEY_UNIT_ATTENTION : un_state = %d\n", un->un_state);

		un->un_unit_attention_flags |= 1;
		/*
		 * If we have detected a Bus Reset and the tape
		 * drive has been reserved.
		 */
		if (ST_RQSENSE->es_add_code == 0x29) {
			rval = DEVICE_RESET;
			if ((un->un_rsvd_status &
			    (ST_RESERVE | ST_APPLICATION_RESERVATIONS)) ==
			    ST_RESERVE) {
				un->un_rsvd_status |= ST_LOST_RESERVE;
				ST_DEBUG(ST_DEVINFO, st_label, CE_WARN,
				    "st_decode_sense: Lost Reservation\n");
			}
		}

		/*
		 * If this is a recovery command and retrable, retry.
		 */
		if (bp == un->un_recov_buf) {
			severity = SCSI_ERR_INFO;
			if (attrib->retriable &&
			    ri->pkt_retry_cnt++ < st_retry_count) {
				rval = QUE_COMMAND;
			} else {
				rval = COMMAND_DONE_ERROR;
			}
			break; /* Don't set position invalid */
		}

		/*
		 * If ST_APPLICATION_RESERVATIONS is set,
		 * If the asc/ascq indicates that the reservation
		 * has been cleared just allow the write to continue
		 * which would force a scsi 2 reserve.
		 * If preempted that persistent reservation
		 * the scsi 2 reserve would get a reservation conflict.
		 */
		if ((un->un_rsvd_status &
		    ST_APPLICATION_RESERVATIONS) != 0) {
			/*
			 * RESERVATIONS PREEMPTED
			 * With MPxIO this could be a fail over? XXX
			 */
			if (ST_RQSENSE->es_add_code == 0x2a &&
			    ST_RQSENSE->es_qual_code == 0x03) {
				severity = SCSI_ERR_INFO;
				rval = COMMAND_DONE_ERROR;
				pos->pmode = invalid;
				break;
			/*
			 * RESERVATIONS RELEASED
			 */
			} else if (ST_RQSENSE->es_add_code == 0x2a &&
			    ST_RQSENSE->es_qual_code == 0x04) {
				severity = SCSI_ERR_INFO;
				rval = COMMAND_DONE;
				break;
			}
		}

		if (un->un_state <= ST_STATE_OPENING) {
			/*
			 * Look, the tape isn't open yet, now determine
			 * if the cause is a BUS RESET, Save the file
			 * and Block positions for the callers to
			 * recover from the loss of position.
			 */
			severity = SCSI_ERR_INFO;
			if ((pos->pmode != invalid) &&
			    (rval == DEVICE_RESET) &&
			    (un->un_restore_pos != 1)) {
				un->un_save_fileno = pos->fileno;
				un->un_save_blkno = pos->blkno;
				un->un_restore_pos = 1;
			}

			if (attrib->retriable &&
			    ri->pkt_retry_cnt++ < st_retry_count) {
				rval = QUE_COMMAND;
			} else if (rval == DEVICE_RESET) {
				break;
			} else {
				rval = COMMAND_DONE_ERROR;
			}
		/*
		 * Means it thinks the mode parameters have changed.
		 * This is the result of a reset clearing settings or
		 * another initiator changing what we set.
		 */
		}
		if (ST_RQSENSE->es_add_code == 0x2a) {
			if (ST_RQSENSE->es_qual_code == 0x1) {
				/* Error recovery will modeselect and retry. */
				rval = DEVICE_TAMPER;
				severity = SCSI_ERR_INFO;
				break; /* don't set position invalid */
			}
			if (ST_RQSENSE->es_qual_code == 0x0 ||
			    ST_RQSENSE->es_qual_code == 0x2 ||
			    ST_RQSENSE->es_qual_code == 0x3 ||
			    ST_RQSENSE->es_qual_code == 0x4 ||
			    ST_RQSENSE->es_qual_code == 0x5 ||
			    ST_RQSENSE->es_qual_code == 0x6 ||
			    ST_RQSENSE->es_qual_code == 0x7) {
				rval = DEVICE_TAMPER;
				severity = SCSI_ERR_INFO;
			}
		} else if (ST_RQSENSE->es_add_code == 0x28 &&
		    ((ST_RQSENSE->es_qual_code == 0x0) ||
		    ST_RQSENSE->es_qual_code == 0x5)) {
			/*
			 * Not Ready to Ready change, Media may have changed.
			 */
			rval = DEVICE_TAMPER;
			severity = SCSI_ERR_RETRYABLE;
		} else {
			if (rval != DEVICE_RESET) {
				rval = COMMAND_DONE_ERROR;
			} else {
				/*
				 * Returning DEVICE_RESET will call
				 * error recovery.
				 */
				severity = SCSI_ERR_INFO;
				break; /* don't set position invalid */
			}
			/*
			 * Check if it is an Unexpected Unit Attention.
			 * If state is >= ST_STATE_OPEN, we have
			 * already done the initialization .
			 * In this case it is Fatal Error
			 * since no further reading/writing
			 * can be done with fileno set to < 0.
			 */
			if (un->un_state >= ST_STATE_OPEN) {
				ST_DO_ERRSTATS(un, st_harderrs);
				severity = SCSI_ERR_FATAL;
			} else {
				severity = SCSI_ERR_INFO;
			}
		}

		pos->pmode = invalid;

		break;

	case KEY_NOT_READY:
		/*
		 * If in process of getting ready retry.
		 */
		if (sensep->es_add_code == 0x04) {
			switch (sensep->es_qual_code) {
			case 0x07:
				/*
				 * We get here when the tape is rewinding.
				 * QUE_BUSY_COMMAND retries every 10 seconds.
				 */
				if (ri->pkt_retry_cnt++ <
				    (un->un_dp->rewind_timeout / 10)) {
					rval = QUE_BUSY_COMMAND;
					severity = SCSI_ERR_INFO;
				} else {
					/* give up */
					rval = COMMAND_DONE_ERROR;
					severity = SCSI_ERR_FATAL;
				}
				break;
			case 0x01:
				if (ri->pkt_retry_cnt++ < st_retry_count) {
					rval = QUE_COMMAND;
					severity = SCSI_ERR_INFO;
					break;
				}
			default: /* FALLTHRU */
				/* give up */
				rval = COMMAND_DONE_ERROR;
				severity = SCSI_ERR_FATAL;
			}
		} else {
			/* give up */
			rval = COMMAND_DONE_ERROR;
			severity = SCSI_ERR_FATAL;
		}

		/*
		 * If this was an error and after device opened
		 * do error stats.
		 */
		if (rval == COMMAND_DONE_ERROR &&
		    un->un_state > ST_STATE_OPENING) {
			ST_DO_ERRSTATS(un, st_harderrs);
		}

		if (ST_RQSENSE->es_add_code == 0x3a) {
			if (st_error_level >= SCSI_ERR_FATAL)
				scsi_log(ST_DEVINFO, st_label, CE_NOTE,
				    "Tape not inserted in drive\n");
			un->un_mediastate = MTIO_EJECTED;
			cv_broadcast(&un->un_state_cv);
		}
		if ((un->un_dp->options & ST_EJECT_ON_CHANGER_FAILURE) &&
		    (rval != QUE_COMMAND))
			un->un_eject_tape_on_failure = st_check_asc_ascq(un);
		break;

	case KEY_ABORTED_COMMAND:
		/* XXX Do drives return this when they see a lost light? */
		/* Testing would say yes */

		if (ri->pkt_retry_cnt++ < st_retry_count) {
			rval = ATTEMPT_RETRY;
			severity = SCSI_ERR_RETRYABLE;
			goto check_keys;
		}
		/*
		 * Probably a parity error...
		 * if we retry here then this may cause data to be
		 * written twice or data skipped during reading
		 */
		ST_DO_ERRSTATS(un, st_harderrs);
		severity = SCSI_ERR_FATAL;
		rval = COMMAND_DONE_ERROR;
		goto check_keys;

	default:
		/*
		 * Undecoded sense key.	 Try retries and hope
		 * that will fix the problem.  Otherwise, we're
		 * dead.
		 */
		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "Unhandled Sense Key '%s'\n",
		    sense_keys[un->un_status]);
		ST_DO_ERRSTATS(un, st_harderrs);
		severity = SCSI_ERR_FATAL;
		rval = COMMAND_DONE_ERROR;
		goto check_keys;
	}

	if ((!(pkt->pkt_flags & FLAG_SILENT) &&
	    un->un_state >= ST_STATE_OPEN) && (DEBUGGING ||
	    (un->un_laststate > ST_STATE_OPENING) &&
	    (severity >= st_error_level))) {

		scsi_errmsg(ST_SCSI_DEVP, pkt, st_label, severity,
		    pos->lgclblkno, un->un_err_pos.lgclblkno,
		    scsi_cmds, sensep);
		if (sensep->es_filmk) {
			scsi_log(ST_DEVINFO, st_label, CE_CONT,
			    "File Mark Detected\n");
		}
		if (sensep->es_eom) {
			scsi_log(ST_DEVINFO, st_label, CE_CONT,
			    "End-of-Media Detected\n");
		}
		if (sensep->es_ili) {
			scsi_log(ST_DEVINFO, st_label, CE_CONT,
			    "Incorrect Length Indicator Set\n");
		}
	}
	get_error = geterror(bp);
	if (((rval == COMMAND_DONE_ERROR) ||
	    (rval == COMMAND_DONE_ERROR_RECOVERED)) &&
	    ((get_error == EIO) || (get_error == 0))) {
		un->un_rqs_state |= (ST_RQS_ERROR | ST_RQS_VALID);
		bcopy(ST_RQSENSE, un->un_uscsi_rqs_buf, SENSE_LENGTH);
		if (un->un_rqs_state & ST_RQS_READ) {
			un->un_rqs_state &= ~(ST_RQS_READ);
		} else {
			un->un_rqs_state |= ST_RQS_OVR;
		}
	}

	return (rval);
}


static int
st_handle_intr_retry_lcmd(struct scsi_tape *un, struct buf *bp)
{
	int status = TRAN_ACCEPT;
	pkt_info *pktinfo = BP_PKT(bp)->pkt_private;

	mutex_enter(ST_MUTEX);

	ST_FUNC(ST_DEVINFO, st_handle_intr_retry_lcmd);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_handle_intr_rtr_lcmd(), un = 0x%p\n", (void *)un);

	/*
	 * Check to see if we hit the retry timeout. We check to make sure
	 * this is the first one on the runq and make sure we have not
	 * queued up any more, so this one has to be the last on the list
	 * also. If it is not, we have to fail.  If it is not the first, but
	 * is the last we are in trouble anyway, as we are in the interrupt
	 * context here.
	 */
	if ((pktinfo->pkt_retry_cnt > st_retry_count) ||
	    ((un->un_runqf != bp) && (un->un_runql != bp))) {
		goto exit;
	}

	if (un->un_throttle) {
		un->un_last_throttle = un->un_throttle;
		un->un_throttle = 0;
	}

	/*
	 * Here we know : bp is the first and last one on the runq
	 * it is not necessary to put it back on the head of the
	 * waitq and then move from waitq to runq. Save this queuing
	 * and call scsi_transport.
	 */
	ST_CDB(ST_DEVINFO, "Retry lcmd CDB", (char *)BP_PKT(bp)->pkt_cdbp);

	status = st_transport(un, BP_PKT(bp));

	if (status == TRAN_ACCEPT) {
		if (un->un_last_throttle) {
			un->un_throttle = un->un_last_throttle;
		}
		mutex_exit(ST_MUTEX);

		ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
		    "restart transport \n");
		return (0);
	}

	ST_DO_KSTATS(bp, kstat_runq_back_to_waitq);
	mutex_exit(ST_MUTEX);

	if (status == TRAN_BUSY) {
		if (st_handle_intr_busy(un, bp, ST_TRAN_BUSY_TIMEOUT) == 0) {
			return (0);
		}
	}
	ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
	    "restart transport rejected\n");
	mutex_enter(ST_MUTEX);
	ST_DO_ERRSTATS(un, st_transerrs);
	if (un->un_last_throttle) {
		un->un_throttle = un->un_last_throttle;
	}
exit:
	mutex_exit(ST_MUTEX);
	return (-1);
}

static int
st_wrongtapetype(struct scsi_tape *un)
{

	ST_FUNC(ST_DEVINFO, st_wrongtapetype);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_wrongtapetype()\n");

	/*
	 * Hack to handle  600A, 600XTD, 6150 && 660 vs. 300XL tapes...
	 */
	if (un->un_dp && (un->un_dp->options & ST_QIC) && un->un_mspl) {
		switch (un->un_dp->type) {
		case ST_TYPE_WANGTEK:
		case ST_TYPE_ARCHIVE:
			/*
			 * If this really worked, we could go off of
			 * the density codes set in the modesense
			 * page. For this drive, 0x10 == QIC-120,
			 * 0xf == QIC-150, and 0x5 should be for
			 * both QIC-24 and, maybe, QIC-11. However,
			 * the h/w doesn't do what the manual says
			 * that it should, so we'll key off of
			 * getting a WRITE PROTECT error AND wp *not*
			 * set in the mode sense information.
			 */
			/*
			 * XXX but we already know that status is
			 * write protect, so don't check it again.
			 */

			if (un->un_status == KEY_WRITE_PROTECT &&
			    un->un_mspl->wp == 0) {
				return (1);
			}
			break;
		default:
			break;
		}
	}
	return (0);
}

static errstate
st_check_error(struct scsi_tape *un, struct scsi_pkt *pkt)
{
	errstate action;
	recov_info *rcvi = pkt->pkt_private;
	buf_t *bp = rcvi->cmd_bp;
	struct scsi_arq_status *stat = (struct scsi_arq_status *)pkt->pkt_scbp;

	ST_FUNC(ST_DEVINFO, st_check_error);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_check_error()\n");

	switch (SCBP_C(pkt)) {
	case STATUS_RESERVATION_CONFLICT:
		/*
		 * Command recovery is enabled, not just opening,
		 * we had the drive reserved and we thing its ours.
		 * Call recovery to attempt to take it back.
		 */
		if ((rcvi->privatelen == sizeof (recov_info)) &&
		    (bp != un->un_recov_buf) &&
		    (un->un_state > ST_STATE_OPEN_PENDING_IO) &&
		    ((un->un_rsvd_status & (ST_RESERVE |
		    ST_APPLICATION_RESERVATIONS)) != 0)) {
			action = ATTEMPT_RETRY;
			un->un_rsvd_status |= ST_LOST_RESERVE;
		} else {
			action = COMMAND_DONE_EACCES;
			un->un_rsvd_status |= ST_RESERVATION_CONFLICT;
		}
		break;

	case STATUS_BUSY:
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG, "unit busy\n");
		if (rcvi->privatelen == sizeof (recov_info) &&
		    un->un_multipath && (pkt->pkt_state == (STATE_GOT_BUS |
		    STATE_GOT_TARGET | STATE_SENT_CMD | STATE_GOT_STATUS))) {
			/*
			 * Status returned by scsi_vhci indicating path
			 * has failed over.
			 */
			action = PATH_FAILED;
			break;
		}
		/* FALLTHRU */
	case STATUS_QFULL:
		if (rcvi->privatelen == sizeof (recov_info)) {
			/*
			 * If recovery is inabled use it instead of
			 * blind reties.
			 */
			action = ATTEMPT_RETRY;
		} else if (rcvi->pkt_retry_cnt++ < st_retry_count) {
			action = QUE_BUSY_COMMAND;
		} else if ((un->un_rsvd_status &
		    (ST_RESERVE | ST_APPLICATION_RESERVATIONS)) == 0) {
			/*
			 * If this is a command done before reserve is done
			 * don't reset.
			 */
			action = COMMAND_DONE_ERROR;
		} else {
			ST_DEBUG2(ST_DEVINFO, st_label, CE_WARN,
			    "unit busy too long\n");
			(void) st_reset(un, RESET_ALL);
			action = COMMAND_DONE_ERROR;
		}
		break;

	case STATUS_CHECK:
	case STATUS_TERMINATED:
		/*
		 * we should only get here if the auto rqsense failed
		 * thru a uscsi cmd without autorequest sense
		 * so we just try again
		 */
		if (un->un_arq_enabled &&
		    stat->sts_rqpkt_reason == CMD_CMPLT &&
		    (stat->sts_rqpkt_state & (STATE_GOT_BUS |
		    STATE_GOT_TARGET | STATE_SENT_CMD | STATE_GOT_STATUS)) ==
		    (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
		    STATE_GOT_STATUS)) {

			ST_DEBUG2(ST_DEVINFO, st_label, CE_WARN,
			    "Really got sense data\n");
			action = st_decode_sense(un, bp, MAX_SENSE_LENGTH -
			    pkt->pkt_resid, stat, &un->un_pos);
		} else {
			ST_DEBUG2(ST_DEVINFO, st_label, CE_WARN,
			    "Trying to queue sense command\n");
			action = QUE_SENSE;
		}
		break;

	case STATUS_TASK_ABORT:
		/*
		 * This is an aborted task. This can be a reset on the other
		 * port of a multiport drive. Lets try and recover it.
		 */
		action = DEVICE_RESET;
		break;

	default:
		action = COMMAND_DONE;
		ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
		    "Unexpected scsi status byte 0x%x\n", SCBP_C(pkt));
	}
	return (action);
}

static void
st_calc_bnum(struct scsi_tape *un, struct buf *bp, struct scsi_pkt *pkt)
{
	int nblks;
	int nfiles;
	long count;
	recov_info *ri = pkt->pkt_private;
	cmd_attribute const *attrib;

	ST_FUNC(ST_DEVINFO, st_calc_bnum);

	ASSERT(mutex_owned(ST_MUTEX));

	if (ri->privatelen == sizeof (recov_info)) {
		attrib = ri->cmd_attrib;
		ASSERT(attrib->recov_pos_type == POS_EXPECTED);
		ASSERT(attrib->chg_tape_pos);
	} else {
		ri = NULL;
		attrib = st_lookup_cmd_attribute(pkt->pkt_cdbp[0]);
	}

	count = bp->b_bcount - bp->b_resid;

	/* Command reads or writes data */
	if (attrib->transfers_data != TRAN_NONE) {
		if (count == 0) {
			if (attrib->transfers_data == TRAN_WRTE) {
				ASSERT(un->un_pos.eof == ST_EOM);
				nblks = 0;
				nfiles = 0;
			} else {
				ASSERT(un->un_pos.eof == ST_EOF_PENDING);
				nblks = 0;
				nfiles = 1;
			}
		} else if (un->un_bsize == 0) {
			/*
			 * If variable block mode.
			 * Fixed bit in CBD should be zero.
			 */
			ASSERT((pkt->pkt_cdbp[1] & 1) == 0);
			nblks = 1;
			un->un_kbytes_xferred += (count / ONE_K);
			nfiles = 0;
		} else {
			/*
			 * If fixed block mode.
			 * Fixed bit in CBD should be one.
			 */
			ASSERT((pkt->pkt_cdbp[1] & 1) == 1);
			nblks = (count / un->un_bsize);
			un->un_kbytes_xferred += (nblks * un->un_bsize) / ONE_K;
			nfiles = 0;
		}
		/*
		 * So its possable to read some blocks and hit a filemark.
		 * Example reading in fixed block mode where more then one
		 * block at a time is requested. In this case because the
		 * filemark is hit something less then the requesed number
		 * of blocks is read.
		 */
		if (un->un_pos.eof == ST_EOF_PENDING && bp->b_resid) {
			nfiles = 1;
		}
	} else {
		nblks = 0;
		nfiles = count;
	}

	/*
	 * If some command failed after this one started and it seems
	 * to have finshed without error count the position.
	 */
	if (un->un_persistence && un->un_persist_errors) {
		ASSERT(un->un_pos.pmode != invalid);
	}

	if (attrib->chg_tape_direction == DIR_FORW) {
		un->un_pos.blkno += nblks;
		un->un_pos.lgclblkno += nblks;
		un->un_pos.lgclblkno += nfiles;
	} else if (attrib->chg_tape_direction == DIR_REVC) {
		un->un_pos.blkno -= nblks;
		un->un_pos.lgclblkno -= nblks;
		un->un_pos.lgclblkno -= nfiles;
	} else {
		ASSERT(0);
	}

	/* recovery disabled */
	if (ri == NULL) {
		un->un_running.pmode = invalid;
		return;
	}

	/*
	 * If we didn't just read a filemark.
	 */
	if (un->un_pos.eof != ST_EOF_PENDING) {
		ASSERT(nblks != 0 && nfiles == 0);
		/*
		 * If Previously calulated expected position does not match
		 * debug the expected position.
		 */
		if ((ri->pos.pmode != invalid) && nblks &&
		    ((un->un_pos.blkno != ri->pos.blkno) ||
		    (un->un_pos.lgclblkno != ri->pos.lgclblkno))) {
#ifdef STDEBUG
			st_print_position(ST_DEVINFO, st_label, CE_NOTE,
			    "Expected", &ri->pos);
			st_print_position(ST_DEVINFO, st_label, CE_NOTE,
			    "But Got", &un->un_pos);
#endif
			un->un_running.pmode = invalid;
		}
	} else {
		ASSERT(nfiles != 0);
		if (un->un_running.pmode != invalid) {
			/*
			 * blkno and lgclblkno already counted in
			 * st_add_recovery_info_to_pkt(). Since a block was not
			 * read and a filemark was.
			 */
			if (attrib->chg_tape_direction == DIR_FORW) {
				un->un_running.fileno++;
				un->un_running.blkno = 0;
			} else if (attrib->chg_tape_direction == DIR_REVC) {
				un->un_running.fileno--;
				un->un_running.blkno = LASTBLK;
			}
		}
	}
}

static void
st_set_state(struct scsi_tape *un, struct buf *bp)
{
	struct scsi_pkt *sp = BP_PKT(bp);
	struct uscsi_cmd *ucmd;

	ST_FUNC(ST_DEVINFO, st_set_state);

	ASSERT(mutex_owned(ST_MUTEX));
	ASSERT(bp != un->un_recov_buf);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_set_state(): eof=%x	fmneeded=%x  pkt_resid=0x%lx (%ld)\n",
	    un->un_pos.eof, un->un_fmneeded, sp->pkt_resid, sp->pkt_resid);

	if (bp != un->un_sbufp) {
#ifdef STDEBUG
		if (DEBUGGING && sp->pkt_resid) {
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "pkt_resid %ld bcount %ld\n",
			    sp->pkt_resid, bp->b_bcount);
		}
#endif
		bp->b_resid = sp->pkt_resid;
		if (geterror(bp) != EIO) {
			st_calc_bnum(un, bp, sp);
		}
		if (bp->b_flags & B_READ) {
			un->un_lastop = ST_OP_READ;
			un->un_fmneeded = 0;
		} else {
			un->un_lastop = ST_OP_WRITE;
			if (un->un_dp->options & ST_REEL) {
				un->un_fmneeded = 2;
			} else {
				un->un_fmneeded = 1;
			}
		}
		/*
		 * all is honky dory at this point, so let's
		 * readjust the throttle, to increase speed, if we
		 * have not throttled down.
		 */
		if (un->un_throttle) {
			un->un_throttle = un->un_max_throttle;
		}
	} else {
		optype new_lastop = ST_OP_NIL;
		uchar_t cmd = (uchar_t)(intptr_t)bp->b_forw;

		switch (cmd) {
		case SCMD_WRITE:
		case SCMD_WRITE_G4:
			bp->b_resid = sp->pkt_resid;
			new_lastop = ST_OP_WRITE;
			if (geterror(bp) == EIO) {
				break;
			}
			st_calc_bnum(un, bp, sp);
			if (un->un_dp->options & ST_REEL) {
				un->un_fmneeded = 2;
			} else {
				un->un_fmneeded = 1;
			}
			break;
		case SCMD_READ:
		case SCMD_READ_G4:
			bp->b_resid = sp->pkt_resid;
			new_lastop = ST_OP_READ;
			un->un_lastop = ST_OP_READ;
			if (geterror(bp) == EIO) {
				break;
			}
			st_calc_bnum(un, bp, sp);
			un->un_fmneeded = 0;
			break;
		case SCMD_WRITE_FILE_MARK_G4:
		case SCMD_WRITE_FILE_MARK:
		{
			int fmdone;

			if (un->un_pos.eof != ST_EOM) {
				un->un_pos.eof = ST_NO_EOF;
			}
			fmdone = (bp->b_bcount - bp->b_resid);
			if (fmdone > 0) {
				un->un_lastop = new_lastop = ST_OP_WEOF;
				un->un_pos.lgclblkno += fmdone;
				un->un_pos.fileno += fmdone;
				un->un_pos.blkno = 0;
			} else {
				new_lastop = ST_OP_CTL;
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "Flushed buffer\n");
			}
			if (fmdone > un->un_fmneeded) {
				un->un_fmneeded = 0;
			} else {
				un->un_fmneeded -= fmdone;
			}
			break;
		}
		case SCMD_REWIND:
			un->un_pos.eof = ST_NO_EOF;
			un->un_pos.fileno = 0;
			un->un_pos.blkno = 0;
			un->un_pos.lgclblkno = 0;
			if (un->un_pos.pmode != legacy)
				un->un_pos.pmode = legacy;
			new_lastop = ST_OP_CTL;
			un->un_restore_pos = 0;
			break;

		case SCMD_SPACE:
		case SCMD_SPACE_G4:
		{
			int64_t count;
			int64_t resid;
			int64_t done;
			cmd_attribute const *attrib;
			recov_info *ri = sp->pkt_private;

			if (ri->privatelen == sizeof (recov_info)) {
				attrib = ri->cmd_attrib;
			} else {
				attrib =
				    st_lookup_cmd_attribute(sp->pkt_cdbp[0]);
			}

			resid = (int64_t)SPACE_CNT(bp->b_resid);
			count = (int64_t)attrib->get_cnt(sp->pkt_cdbp);

			if (count >= 0) {
				done = (count - resid);
			} else {
				done = ((-count) - resid);
			}
			if (done > 0) {
				un->un_lastop = new_lastop = ST_OP_CTL;
			} else {
				new_lastop = ST_OP_CTL;
			}

			ST_SPAC(ST_DEVINFO, st_label, CE_WARN,
			    "space cmd: cdb[1] = %s\n"
			    "space data:       = 0x%lx\n"
			    "space count:      = %"PRId64"\n"
			    "space resid:      = %"PRId64"\n"
			    "spaces done:      = %"PRId64"\n"
			    "fileno before     = %d\n"
			    "blkno before      = %d\n",
			    space_strs[sp->pkt_cdbp[1] & 7],
			    bp->b_bcount,
			    count, resid, done,
			    un->un_pos.fileno, un->un_pos.blkno);

			switch (sp->pkt_cdbp[1]) {
			case SPACE_TYPE(SP_FLM):
				/* Space file forward */
				if (count >= 0) {
					if (un->un_pos.eof <= ST_EOF) {
						un->un_pos.eof = ST_NO_EOF;
					}
					un->un_pos.fileno += done;
					un->un_pos.blkno = 0;
					break;
				}
				/* Space file backward */
				if (done > un->un_pos.fileno) {
					un->un_pos.fileno = 0;
					un->un_pos.blkno = 0;
				} else {
					un->un_pos.fileno -= done;
					un->un_pos.blkno = LASTBLK;
					un->un_running.pmode = invalid;
				}
				break;
			case SPACE_TYPE(SP_BLK):
				/* Space block forward */
				if (count >= 0) {
					un->un_pos.blkno += done;
					break;
				}
				/* Space block backward */
				if (un->un_pos.eof >= ST_EOF_PENDING) {
				/*
				 * we stepped back into
				 * a previous file; we are not
				 * making an effort to pretend that
				 * we are still in the current file
				 * ie. logical == physical position
				 * and leave it to st_ioctl to correct
				 */
					if (done > un->un_pos.blkno) {
						un->un_pos.blkno = 0;
					} else {
						un->un_pos.fileno--;
						un->un_pos.blkno = LASTBLK;
						un->un_running.pmode = invalid;
					}
				} else {
					un->un_pos.blkno -= done;
				}
				break;
			case SPACE_TYPE(SP_SQFLM):
				un->un_pos.pmode = logical;
				un->un_pos.blkno = 0;
				un->un_lastop = new_lastop = ST_OP_CTL;
				break;
			case SPACE_TYPE(SP_EOD):
				un->un_pos.pmode = logical;
				un->un_pos.eof = ST_EOM;
				un->un_status = KEY_BLANK_CHECK;
				break;
			default:
				un->un_pos.pmode = invalid;
				scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "Unsupported space cmd: %s\n",
				    space_strs[sp->pkt_cdbp[1] & 7]);

				un->un_lastop = new_lastop = ST_OP_CTL;
			}

			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "after_space rs %"PRId64" fil %d blk %d\n",
			    resid, un->un_pos.fileno, un->un_pos.blkno);

			break;
		}
		case SCMD_LOAD:
			if ((bp->b_bcount & (LD_LOAD | LD_EOT)) == LD_LOAD) {
				un->un_pos.fileno = 0;
				if (un->un_pos.pmode != legacy)
					un->un_pos.pmode = legacy;
			} else {
				un->un_state = ST_STATE_OFFLINE;
				un->un_pos.pmode = invalid;

			}
			/*
			 * If we are loading or unloading we expect the media id
			 * to change. Lets make it unknown.
			 */
			if (un->un_media_id != bogusID && un->un_media_id_len) {
				kmem_free(un->un_media_id, un->un_media_id_len);
				un->un_media_id = NULL;
				un->un_media_id_len = 0;
			}
			un->un_density_known = 0;
			un->un_pos.eof = ST_NO_EOF;
			un->un_pos.blkno = 0;
			un->un_lastop = new_lastop = ST_OP_CTL;
			break;
		case SCMD_ERASE:
			un->un_pos.eof = ST_NO_EOF;
			un->un_pos.blkno = 0;
			un->un_pos.fileno = 0;
			un->un_pos.lgclblkno = 0;
			if (un->un_pos.pmode != legacy)
				un->un_pos.pmode = legacy;
			new_lastop = ST_OP_CTL;
			break;
		case SCMD_RESERVE:
			un->un_rsvd_status |= ST_RESERVE;
			un->un_rsvd_status &=
			    ~(ST_RELEASE | ST_LOST_RESERVE |
			    ST_RESERVATION_CONFLICT | ST_INITIATED_RESET);
			new_lastop = ST_OP_CTL;
			break;
		case SCMD_RELEASE:
			un->un_rsvd_status |= ST_RELEASE;
			un->un_rsvd_status &=
			    ~(ST_RESERVE | ST_LOST_RESERVE |
			    ST_RESERVATION_CONFLICT | ST_INITIATED_RESET);
			new_lastop = ST_OP_CTL;
			break;
		case SCMD_PERSISTENT_RESERVE_IN:
			ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
			    "PGR_IN command\n");
			new_lastop = ST_OP_CTL;
			break;
		case SCMD_PERSISTENT_RESERVE_OUT:
			switch (sp->pkt_cdbp[1] & ST_SA_MASK) {
			case ST_SA_SCSI3_RESERVE:
			case ST_SA_SCSI3_PREEMPT:
			case ST_SA_SCSI3_PREEMPTANDABORT:
				un->un_rsvd_status |=
				    (ST_APPLICATION_RESERVATIONS | ST_RESERVE);
				un->un_rsvd_status &= ~(ST_RELEASE |
				    ST_LOST_RESERVE | ST_RESERVATION_CONFLICT |
				    ST_INITIATED_RESET);
				ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
				    "PGR Reserve and set: entering"
				    " ST_APPLICATION_RESERVATIONS mode");
				break;
			case ST_SA_SCSI3_REGISTER:
				ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
				    "PGR Reserve register key");
				un->un_rsvd_status |= ST_INIT_RESERVE;
				break;
			case ST_SA_SCSI3_CLEAR:
				un->un_rsvd_status &= ~ST_INIT_RESERVE;
				/* FALLTHROUGH */
			case ST_SA_SCSI3_RELEASE:
				un->un_rsvd_status &=
				    ~(ST_APPLICATION_RESERVATIONS | ST_RESERVE |
				    ST_LOST_RESERVE | ST_RESERVATION_CONFLICT |
				    ST_INITIATED_RESET);
				un->un_rsvd_status |= ST_RELEASE;
				ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
				    "PGR Release and reset: exiting"
				    " ST_APPLICATION_RESERVATIONS mode");
				break;
			}
			new_lastop = ST_OP_CTL;
			break;
		case SCMD_TEST_UNIT_READY:
		case SCMD_READ_BLKLIM:
		case SCMD_REQUEST_SENSE:
		case SCMD_INQUIRY:
		case SCMD_RECOVER_BUF:
		case SCMD_MODE_SELECT:
		case SCMD_MODE_SENSE:
		case SCMD_DOORLOCK:
		case SCMD_READ_BUFFER:
		case SCMD_REPORT_DENSITIES:
		case SCMD_LOG_SELECT_G1:
		case SCMD_LOG_SENSE_G1:
		case SCMD_REPORT_LUNS:
		case SCMD_READ_ATTRIBUTE:
		case SCMD_WRITE_ATTRIBUTE:
		case SCMD_SVC_ACTION_IN_G5:
		case SCMD_SECURITY_PROTO_IN:
		case SCMD_SECURITY_PROTO_OUT:
			new_lastop = ST_OP_CTL;
			break;
		case SCMD_READ_POSITION:
			new_lastop = ST_OP_CTL;
			/*
			 * Only if the buf used was un_sbufp.
			 * Among other things the prevents read positions used
			 * as part of error recovery from messing up our
			 * current position as they will use un_recov_buf.
			 */
			if (USCSI_CMD(bp)) {
				(void) st_get_read_pos(un, bp);
			}
			break;
		case SCMD_LOCATE:
		case SCMD_LOCATE_G4:
			/* Locate makes position mode no longer legacy */
			un->un_lastop = new_lastop = ST_OP_CTL;
			break;
		case SCMD_MAINTENANCE_IN:
			switch (sp->pkt_cdbp[1]) {
			case SSVC_ACTION_GET_SUPPORTED_OPERATIONS:
			case SSVC_ACTION_SET_TARGET_PORT_GROUPS:
				new_lastop = ST_OP_CTL;
				break;
			}
			if (new_lastop != ST_OP_NIL) {
				break;
			}
		default:
			/*
			 * Unknown command, If was USCSI and USCSI_SILENT
			 * flag was not set, set position to unknown.
			 */
			if ((((ucmd = BP_UCMD(bp)) != NULL) &&
			    (ucmd->uscsi_flags & USCSI_SILENT) == 0)) {
				ST_DEBUG2(ST_DEVINFO, st_label, CE_WARN,
				    "unknown cmd 0x%X caused loss of state\n",
				    cmd);
			} else {
				/*
				 * keep the old agreement to allow unknown
				 * commands with the USCSI_SILENT set.
				 * This prevents ASSERT below.
				 */
				new_lastop = ST_OP_CTL;
				break;
			}
			/* FALLTHROUGH */
		case SCMD_WRITE_BUFFER: /* Writes new firmware to device */
			un->un_pos.pmode = invalid;
			un->un_lastop = new_lastop = ST_OP_CTL;
			break;
		}

		/* new_lastop should have been changed */
		ASSERT(new_lastop != ST_OP_NIL);

		/* If un_lastop should copy new_lastop  */
		if (((un->un_lastop == ST_OP_WRITE) ||
		    (un->un_lastop == ST_OP_WEOF)) &&
		    new_lastop != ST_OP_CTL) {
			un->un_lastop = new_lastop;
		}
	}

	/*
	 * In the st driver we have a logical and physical file position.
	 * Under BSD behavior, when you get a zero read, the logical position
	 * is before the filemark but after the last record of the file.
	 * The physical position is after the filemark. MTIOCGET should always
	 * return the logical file position.
	 *
	 * The next read gives a silent skip to the next file.
	 * Under SVR4, the logical file position remains before the filemark
	 * until the file is closed or a space operation is performed.
	 * Hence set err_resid and err_file before changing fileno if case
	 * BSD Behaviour.
	 */
	un->un_err_resid = bp->b_resid;
	COPY_POS(&un->un_err_pos, &un->un_pos);


	/*
	 * If we've seen a filemark via the last read operation
	 * advance the file counter, but mark things such that
	 * the next read operation gets a zero count. We have
	 * to put this here to handle the case of sitting right
	 * at the end of a tape file having seen the file mark,
	 * but the tape is closed and then re-opened without
	 * any further i/o. That is, the position information
	 * must be updated before a close.
	 */

	if (un->un_lastop == ST_OP_READ && un->un_pos.eof == ST_EOF_PENDING) {
		/*
		 * If we're a 1/2" tape, and we get a filemark
		 * right on block 0, *AND* we were not in the
		 * first file on the tape, and we've hit logical EOM.
		 * We'll mark the state so that later we do the
		 * right thing (in st_close(), st_strategy() or
		 * st_ioctl()).
		 *
		 */
		if ((un->un_dp->options & ST_REEL) &&
		    !(un->un_dp->options & ST_READ_IGNORE_EOFS) &&
		    un->un_pos.blkno == 0 && un->un_pos.fileno > 0) {
			un->un_pos.eof = ST_EOT_PENDING;
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "eot pending\n");
			un->un_pos.fileno++;
			un->un_pos.blkno = 0;
		} else if (BP_UCMD(bp)) {
			/*
			 * Uscsi reads have no concept of Berkley ver System IV.
			 * Counts here must match raw device.
			 * A non-full resid implies fix block mode where an
			 * attempt to read X blocks resulted in less then X.
			 */
			if (bp->b_resid != bp->b_bcount) {
				un->un_pos.eof = ST_EOF;
			} else {
				/* Read over a file mark */
				un->un_pos.fileno++;
				/* logical block is counted up elsewhere */
				/* we're before the first block in next file */
				un->un_pos.blkno = 0;
				/* EOF is no longer pending */
				un->un_pos.eof = ST_NO_EOF;
			}
		} else if (BSD_BEHAVIOR) {
			/*
			 * If the read of the filemark was a side effect
			 * of reading some blocks (i.e., data was actually
			 * read), then the EOF mark is pending and the
			 * bump into the next file awaits the next read
			 * operation (which will return a zero count), or
			 * a close or a space operation, else the bump
			 * into the next file occurs now.
			 */
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "resid=%lx, bcount=%lx\n",
			    bp->b_resid, bp->b_bcount);

			if (bp->b_resid != bp->b_bcount) {
				un->un_pos.eof = ST_EOF;
			} else {
				un->un_silent_skip = 1;
				un->un_pos.eof = ST_NO_EOF;
				un->un_pos.fileno++;
				un->un_pos.lgclblkno++;
				un->un_save_blkno = un->un_pos.blkno;
				un->un_pos.blkno = 0;
			}
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "eof of file %d, eof=%d\n",
			    un->un_pos.fileno, un->un_pos.eof);
		} else if (SVR4_BEHAVIOR) {
			/*
			 * If the read of the filemark was a side effect
			 * of reading some blocks (i.e., data was actually
			 * read), then the next read should return 0
			 */
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "resid=%lx, bcount=%lx\n",
			    bp->b_resid, bp->b_bcount);
			if (bp->b_resid == bp->b_bcount) {
				un->un_pos.eof = ST_EOF;
			}
			ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "eof of file=%d, eof=%d\n",
			    un->un_pos.fileno, un->un_pos.eof);
		}
	}
}

/*
 * set the correct un_errno, to take corner cases into consideration
 */
static void
st_set_pe_errno(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_set_pe_errno);

	ASSERT(mutex_owned(ST_MUTEX));

	/* if errno is already set, don't reset it */
	if (un->un_errno)
		return;

	/* here un_errno == 0 */
	/*
	 * if the last transfer before flushing all the
	 * waiting I/O's, was 0 (resid = count), then we
	 * want to give the user an error on all the rest,
	 * so here.  If there was a transfer, we set the
	 * resid and counts to 0, and let it drop through,
	 * giving a zero return.  the next I/O will then
	 * give an error.
	 */
	if (un->un_last_resid == un->un_last_count) {
		switch (un->un_pos.eof) {
		case ST_EOM:
			un->un_errno = ENOMEM;
			break;
		case ST_EOT:
		case ST_EOF:
			un->un_errno = EIO;
			break;
		}
	} else {
		/*
		 * we know they did not have a zero, so make
		 * sure they get one
		 */
		un->un_last_resid = un->un_last_count = 0;
	}
}


/*
 * send in a marker pkt to terminate flushing of commands by BBA (via
 * flush-on-errors) property.  The HBA will always return TRAN_ACCEPT
 */
static void
st_hba_unflush(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_hba_unflush);

	ASSERT(mutex_owned(ST_MUTEX));

	if (!un->un_flush_on_errors)
		return;

#ifdef FLUSH_ON_ERRORS

	if (!un->un_mkr_pkt) {
		un->un_mkr_pkt = scsi_init_pkt(ROUTE, NULL, (struct buf *)NULL,
		    NULL, 0, 0, 0, SLEEP_FUNC, NULL);

		/* we slept, so it must be there */
		pkt->pkt_flags |= FLAG_FLUSH_MARKER;
	}

	st_transport(un, un->un_mkr_pkt);
#endif
}

static char *
st_print_scsi_cmd(char cmd)
{
	char tmp[64];
	char *cpnt;

	cpnt = scsi_cmd_name(cmd, scsi_cmds, tmp);
	/* tmp goes out of scope on return and caller sees garbage */
	if (cpnt == tmp) {
		cpnt = "Unknown Command";
	}
	return (cpnt);
}

static void
st_print_cdb(dev_info_t *dip, char *label, uint_t level,
    char *title, char *cdb)
{
	int len = scsi_cdb_size[CDB_GROUPID(cdb[0])];
	char buf[256];
	struct scsi_tape *un;
	int instance = ddi_get_instance(dip);

	un = ddi_get_soft_state(st_state, instance);

	ST_FUNC(dip, st_print_cdb);

	/* force one line output so repeated commands are printed once */
	if ((st_debug & 0x180) == 0x100) {
		scsi_log(dip, label, level, "node %s cmd %s\n",
		    st_dev_name(un->un_dev), st_print_scsi_cmd(*cdb));
		return;
	}

	/* force one line output so repeated CDB's are printed once */
	if ((st_debug & 0x180) == 0x80) {
		st_clean_print(dip, label, level, NULL, cdb, len);
	} else {
		(void) sprintf(buf, "%s for cmd(%s)", title,
		    st_print_scsi_cmd(*cdb));
		st_clean_print(dip, label, level, buf, cdb, len);
	}
}

static void
st_clean_print(dev_info_t *dev, char *label, uint_t level,
    char *title, char *data, int len)
{
	int	i;
	int 	c;
	char	*format;
	char	buf[256];
	uchar_t	byte;

	ST_FUNC(dev, st_clean_print);


	if (title) {
		(void) sprintf(buf, "%s:\n", title);
		scsi_log(dev, label, level, "%s", buf);
		level = CE_CONT;
	}

	for (i = 0; i < len; ) {
		buf[0] = 0;
		for (c = 0; c < 8 && i < len; c++, i++) {
			byte = (uchar_t)data[i];
			if (byte < 0x10)
				format = "0x0%x ";
			else
				format = "0x%x ";
			(void) sprintf(&buf[(int)strlen(buf)], format, byte);
		}
		(void) sprintf(&buf[(int)strlen(buf)], "\n");

		scsi_log(dev, label, level, "%s\n", buf);
		level = CE_CONT;
	}
}

/*
 * Conditionally enabled debugging
 */
#ifdef	STDEBUG
static void
st_debug_cmds(struct scsi_tape *un, int com, int count, int wait)
{
	char tmpbuf[64];

	ST_FUNC(ST_DEVINFO, st_debug_cmds);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "cmd=%s count=0x%x (%d)	 %ssync\n",
	    scsi_cmd_name(com, scsi_cmds, tmpbuf),
	    count, count,
	    wait == ASYNC_CMD ? "a" : "");
}
#endif	/* STDEBUG */

/*
 * Returns pointer to name of minor node name of device 'dev'.
 */
static char *
st_dev_name(dev_t dev)
{
	struct scsi_tape *un;
	const char density[] = { 'l', 'm', 'h', 'c' };
	static char name[32];
	minor_t minor;
	int instance;
	int nprt = 0;

	minor = getminor(dev);
	instance = ((minor & 0xff80) >> 5) | (minor & 3);
	un = ddi_get_soft_state(st_state, instance);
	if (un) {
		ST_FUNC(ST_DEVINFO, st_dev_name);
	}

	name[nprt] = density[(minor & MT_DENSITY_MASK) >> 3];

	if (minor & MT_BSD) {
		name[++nprt] = 'b';
	}

	if (minor & MT_NOREWIND) {
		name[++nprt] = 'n';
	}

	/* NULL terminator */
	name[++nprt] = 0;

	return (name);
}

/*
 * Soft error reporting, so far unique to each drive
 *
 * Currently supported: exabyte and DAT soft error reporting
 */
static int
st_report_exabyte_soft_errors(dev_t dev, int flag)
{
	uchar_t *sensep;
	int amt;
	int rval = 0;
	char cdb[CDB_GROUP0], *c = cdb;
	struct uscsi_cmd *com;

	GET_SOFT_STATE(dev);

	ST_FUNC(ST_DEVINFO, st_report_exabyte_soft_errors);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_report_exabyte_soft_errors(dev = 0x%lx, flag = %d)\n",
	    dev, flag);

	ASSERT(mutex_owned(ST_MUTEX));

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	sensep = kmem_zalloc(TAPE_SENSE_LENGTH, KM_SLEEP);

	*c++ = SCMD_REQUEST_SENSE;
	*c++ = 0;
	*c++ = 0;
	*c++ = 0;
	*c++ = TAPE_SENSE_LENGTH;
	/*
	 * set CLRCNT (byte 5, bit 7 which clears the error counts)
	 */
	*c   = (char)0x80;

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP0;
	com->uscsi_bufaddr = (caddr_t)sensep;
	com->uscsi_buflen = TAPE_SENSE_LENGTH;
	com->uscsi_flags = USCSI_DIAGNOSE | USCSI_SILENT | USCSI_READ;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;

	rval = st_uscsi_cmd(un, com, FKIOCTL);
	if (rval || com->uscsi_status) {
		goto done;
	}

	/*
	 * was there enough data?
	 */
	amt = (int)TAPE_SENSE_LENGTH - com->uscsi_resid;

	if ((amt >= 19) && un->un_kbytes_xferred) {
		uint_t count, error_rate;
		uint_t rate;

		if (sensep[21] & CLN) {
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "Periodic head cleaning required");
		}
		if (un->un_kbytes_xferred < (EXABYTE_MIN_TRANSFER/ONE_K)) {
			goto done;
		}
		/*
		 * check if soft error reporting needs to be done.
		 */
		count = sensep[16] << 16 | sensep[17] << 8 | sensep[18];
		count &= 0xffffff;
		error_rate = (count * 100)/un->un_kbytes_xferred;

#ifdef	STDEBUG
		if (st_soft_error_report_debug) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "Exabyte Soft Error Report:\n");
			scsi_log(ST_DEVINFO, st_label, CE_CONT,
			    "read/write error counter: %d\n", count);
			scsi_log(ST_DEVINFO, st_label, CE_CONT,
			    "number of bytes transferred: %dK\n",
			    un->un_kbytes_xferred);
			scsi_log(ST_DEVINFO, st_label, CE_CONT,
			    "error_rate: %d%%\n", error_rate);

			if (amt >= 22) {
				scsi_log(ST_DEVINFO, st_label, CE_CONT,
				    "unit sense: 0x%b 0x%b 0x%b\n",
				    sensep[19], SENSE_19_BITS,
				    sensep[20], SENSE_20_BITS,
				    sensep[21], SENSE_21_BITS);
			}
			if (amt >= 27) {
				scsi_log(ST_DEVINFO, st_label, CE_CONT,
				    "tracking retry counter: %d\n",
				    sensep[26]);
				scsi_log(ST_DEVINFO, st_label, CE_CONT,
				    "read/write retry counter: %d\n",
				    sensep[27]);
			}
		}
#endif

		if (flag & FWRITE) {
			rate = EXABYTE_WRITE_ERROR_THRESHOLD;
		} else {
			rate = EXABYTE_READ_ERROR_THRESHOLD;
		}
		if (error_rate >= rate) {
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "Soft error rate (%d%%) during %s was too high",
			    error_rate,
			    ((flag & FWRITE) ? wrg_str : rdg_str));
			scsi_log(ST_DEVINFO, st_label, CE_CONT,
			    "Please, replace tape cartridge\n");
		}
	}

done:
	kmem_free(com, sizeof (*com));
	kmem_free(sensep, TAPE_SENSE_LENGTH);

	if (rval != 0) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "exabyte soft error reporting failed\n");
	}
	return (rval);
}

/*
 * this is very specific to Archive 4mm dat
 */
#define	ONE_GIG	(ONE_K * ONE_K * ONE_K)

static int
st_report_dat_soft_errors(dev_t dev, int flag)
{
	uchar_t *sensep;
	int amt, i;
	int rval = 0;
	char cdb[CDB_GROUP1], *c = cdb;
	struct uscsi_cmd *com;
	struct scsi_arq_status status;

	GET_SOFT_STATE(dev);

	ST_FUNC(ST_DEVINFO, st_report_dat_soft_errors);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_report_dat_soft_errors(dev = 0x%lx, flag = %d)\n", dev, flag);

	ASSERT(mutex_owned(ST_MUTEX));

	com = kmem_zalloc(sizeof (*com), KM_SLEEP);
	sensep = kmem_zalloc(LOG_SENSE_LENGTH, KM_SLEEP);

	*c++ = SCMD_LOG_SENSE_G1;
	*c++ = 0;
	*c++ = (flag & FWRITE) ? 0x42 : 0x43;
	*c++ = 0;
	*c++ = 0;
	*c++ = 0;
	*c++ = 2;
	*c++ = 0;
	*c++ = (char)LOG_SENSE_LENGTH;
	*c   = 0;
	com->uscsi_cdb    = cdb;
	com->uscsi_cdblen  = CDB_GROUP1;
	com->uscsi_bufaddr = (caddr_t)sensep;
	com->uscsi_buflen  = LOG_SENSE_LENGTH;
	com->uscsi_rqlen = sizeof (status);
	com->uscsi_rqbuf = (caddr_t)&status;
	com->uscsi_flags   = USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_READ;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;
	rval = st_uscsi_cmd(un, com, FKIOCTL);
	if (rval) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "DAT soft error reporting failed\n");
	}
	if (rval || com->uscsi_status) {
		goto done;
	}

	/*
	 * was there enough data?
	 */
	amt = (int)LOG_SENSE_LENGTH - com->uscsi_resid;

	if ((amt >= MIN_LOG_SENSE_LENGTH) && un->un_kbytes_xferred) {
		int total, retries, param_code;

		total = -1;
		retries = -1;
		amt = sensep[3] + 4;


#ifdef STDEBUG
		if (st_soft_error_report_debug) {
			(void) printf("logsense:");
			for (i = 0; i < MIN_LOG_SENSE_LENGTH; i++) {
				if (i % 16 == 0) {
					(void) printf("\t\n");
				}
				(void) printf(" %x", sensep[i]);
			}
			(void) printf("\n");
		}
#endif

		/*
		 * parse the param_codes
		 */
		if (sensep[0] == 2 || sensep[0] == 3) {
			for (i = 4; i < amt; i++) {
				param_code = (sensep[i++] << 8);
				param_code += sensep[i++];
				i++; /* skip control byte */
				if (param_code == 5) {
					if (sensep[i++] == 4) {
						total = (sensep[i++] << 24);
						total += (sensep[i++] << 16);
						total += (sensep[i++] << 8);
						total += sensep[i];
					}
				} else if (param_code == 0x8007) {
					if (sensep[i++] == 2) {
						retries = sensep[i++] << 8;
						retries += sensep[i];
					}
				} else {
					i += sensep[i];
				}
			}
		}

		/*
		 * if the log sense returned valid numbers then determine
		 * the read and write error thresholds based on the amount of
		 * data transferred
		 */

		if (total > 0 && retries > 0) {
			short normal_retries = 0;
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "total xferred (%s) =%x, retries=%x\n",
			    ((flag & FWRITE) ? wrg_str : rdg_str),
			    total, retries);

			if (flag & FWRITE) {
				if (total <=
				    WRITE_SOFT_ERROR_WARNING_THRESHOLD) {
					normal_retries =
					    DAT_SMALL_WRITE_ERROR_THRESHOLD;
				} else {
					normal_retries =
					    DAT_LARGE_WRITE_ERROR_THRESHOLD;
				}
			} else {
				if (total <=
				    READ_SOFT_ERROR_WARNING_THRESHOLD) {
					normal_retries =
					    DAT_SMALL_READ_ERROR_THRESHOLD;
				} else {
					normal_retries =
					    DAT_LARGE_READ_ERROR_THRESHOLD;
				}
			}

			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			"normal retries=%d\n", normal_retries);

			if (retries >= normal_retries) {
				scsi_log(ST_DEVINFO, st_label, CE_WARN,
				    "Soft error rate (retries = %d) during "
				    "%s was too high",  retries,
				    ((flag & FWRITE) ? wrg_str : rdg_str));
				scsi_log(ST_DEVINFO, st_label, CE_CONT,
				    "Periodic head cleaning required "
				    "and/or replace tape cartridge\n");
			}

		} else if (total == -1 || retries == -1) {
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "log sense parameter code does not make sense\n");
		}
	}

	/*
	 * reset all values
	 */
	c = cdb;
	*c++ = SCMD_LOG_SELECT_G1;
	*c++ = 2;	/* this resets all values */
	*c++ = (char)0xc0;
	*c++ = 0;
	*c++ = 0;
	*c++ = 0;
	*c++ = 0;
	*c++ = 0;
	*c++ = 0;
	*c   = 0;
	com->uscsi_bufaddr = NULL;
	com->uscsi_buflen  = 0;
	com->uscsi_flags   = USCSI_DIAGNOSE | USCSI_SILENT;
	rval = st_uscsi_cmd(un, com, FKIOCTL);
	if (rval) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "DAT soft error reset failed\n");
	}
done:
	kmem_free(com, sizeof (*com));
	kmem_free(sensep, LOG_SENSE_LENGTH);
	return (rval);
}

static int
st_report_soft_errors(dev_t dev, int flag)
{
	GET_SOFT_STATE(dev);

	ST_FUNC(ST_DEVINFO, st_report_soft_errors);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_report_soft_errors(dev = 0x%lx, flag = %d)\n", dev, flag);

	ASSERT(mutex_owned(ST_MUTEX));

	switch (un->un_dp->type) {
	case ST_TYPE_EXB8500:
	case ST_TYPE_EXABYTE:
		return (st_report_exabyte_soft_errors(dev, flag));
		/*NOTREACHED*/
	case ST_TYPE_PYTHON:
		return (st_report_dat_soft_errors(dev, flag));
		/*NOTREACHED*/
	default:
		un->un_dp->options &= ~ST_SOFT_ERROR_REPORTING;
		return (-1);
	}
}

/*
 * persistent error routines
 */

/*
 * enable persistent errors, and set the throttle appropriately, checking
 * for flush-on-errors capability
 */
static void
st_turn_pe_on(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_turn_pe_on);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_pe_on\n");
	ASSERT(mutex_owned(ST_MUTEX));

	un->un_persistence = 1;

	/*
	 * only use flush-on-errors if auto-request-sense and untagged-qing are
	 * enabled.  This will simplify the error handling for request senses
	 */

	if (un->un_arq_enabled && un->un_untagged_qing) {
		uchar_t f_o_e;

		mutex_exit(ST_MUTEX);
		f_o_e = (scsi_ifsetcap(ROUTE, "flush-on-errors", 1, 1) == 1) ?
		    1 : 0;
		mutex_enter(ST_MUTEX);

		un->un_flush_on_errors = f_o_e;
	} else {
		un->un_flush_on_errors = 0;
	}

	if (un->un_flush_on_errors)
		un->un_max_throttle = (uchar_t)st_max_throttle;
	else
		un->un_max_throttle = 1;

	if (un->un_dp->options & ST_RETRY_ON_RECOVERED_DEFERRED_ERROR)
		un->un_max_throttle = 1;

	/* this will send a marker pkt */
	st_clear_pe(un);
}

/*
 * This turns persistent errors permanently off
 */
static void
st_turn_pe_off(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_turn_pe_off);
	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_pe_off\n");
	ASSERT(mutex_owned(ST_MUTEX));

	/* turn it off for good */
	un->un_persistence = 0;

	/* this will send a marker pkt */
	st_clear_pe(un);

	/* turn off flush on error capability, if enabled */
	if (un->un_flush_on_errors) {
		mutex_exit(ST_MUTEX);
		(void) scsi_ifsetcap(ROUTE, "flush-on-errors", 0, 1);
		mutex_enter(ST_MUTEX);
	}


	un->un_flush_on_errors = 0;
}

/*
 * This clear persistent errors, allowing more commands through, and also
 * sending a marker packet.
 */
static void
st_clear_pe(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_clear_pe);
	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_pe_clear\n");
	ASSERT(mutex_owned(ST_MUTEX));

	un->un_persist_errors = 0;
	un->un_throttle = un->un_last_throttle = 1;
	un->un_errno = 0;
	st_hba_unflush(un);
}

/*
 * This will flag persistent errors, shutting everything down, if the
 * application had enabled persistent errors via MTIOCPERSISTENT
 */
static void
st_set_pe_flag(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_set_pe_flag);
	ASSERT(mutex_owned(ST_MUTEX));

	if (un->un_persistence) {
		ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG, "st_pe_flag\n");
		un->un_persist_errors = 1;
		un->un_throttle = un->un_last_throttle = 0;
		cv_broadcast(&un->un_sbuf_cv);
	}
}

static int
st_do_reserve(struct scsi_tape *un)
{
	int rval;
	int was_lost = un->un_rsvd_status & ST_LOST_RESERVE;

	ST_FUNC(ST_DEVINFO, st_do_reserve);

	/*
	 * Issue a Throw-Away reserve command to clear the
	 * check condition.
	 * If the current behaviour of reserve/release is to
	 * hold reservation across opens , and if a Bus reset
	 * has been issued between opens then this command
	 * would set the ST_LOST_RESERVE flags in rsvd_status.
	 * In this case return an EACCES so that user knows that
	 * reservation has been lost in between opens.
	 * If this error is not returned and we continue with
	 * successful open , then user may think position of the
	 * tape is still the same but inreality we would rewind the
	 * tape and continue from BOT.
	 */
	rval = st_reserve_release(un, ST_RESERVE, st_uscsi_cmd);
	if (rval) {
		if ((un->un_rsvd_status & ST_LOST_RESERVE_BETWEEN_OPENS) ==
		    ST_LOST_RESERVE_BETWEEN_OPENS) {
			un->un_rsvd_status &= ~(ST_LOST_RESERVE | ST_RESERVE);
			un->un_errno = EACCES;
			return (EACCES);
		}
		rval = st_reserve_release(un, ST_RESERVE, st_uscsi_cmd);
	}
	if (rval == 0) {
		un->un_rsvd_status |= ST_INIT_RESERVE;
	}
	if (was_lost) {
		un->un_running.pmode = invalid;
	}

	return (rval);
}

static int
st_check_cdb_for_need_to_reserve(struct scsi_tape *un, uchar_t *cdb)
{
	int rval;
	cmd_attribute const *attrib;

	ST_FUNC(ST_DEVINFO, st_check_cdb_for_need_to_reserve);

	/*
	 * If already reserved no need to do it again.
	 * Also if Reserve and Release are disabled Just return.
	 */
	if ((un->un_rsvd_status & (ST_APPLICATION_RESERVATIONS)) ||
	    ((un->un_rsvd_status & (ST_RESERVE | ST_LOST_RESERVE)) ==
	    ST_RESERVE) || (un->un_dp->options & ST_NO_RESERVE_RELEASE)) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_NOTE,
		    "st_check_cdb_for_need_to_reserve() reserve unneeded %s",
		    st_print_scsi_cmd((uchar_t)cdb[0]));
		return (0);
	}

	/* See if command is on the list */
	attrib = st_lookup_cmd_attribute(cdb[0]);

	if (attrib == NULL) {
		rval = 1; /* Not found, when in doubt reserve */
	} else if ((attrib->requires_reserve) != 0) {
		rval = 1;
	} else if ((attrib->reserve_byte) != 0) {
		/*
		 * cmd is on list.
		 * if byte is zero always allowed.
		 */
		rval = 1;
	} else if (((cdb[attrib->reserve_byte]) &
	    (attrib->reserve_mask)) != 0) {
		rval = 1;
	} else {
		rval = 0;
	}

	if (rval) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_NOTE,
		    "Command %s requires reservation",
		    st_print_scsi_cmd(cdb[0]));

		rval = st_do_reserve(un);
	}

	return (rval);
}

static int
st_check_cmd_for_need_to_reserve(struct scsi_tape *un, uchar_t cmd, int cnt)
{
	int rval;
	cmd_attribute const *attrib;

	ST_FUNC(ST_DEVINFO, st_check_cmd_for_need_to_reserve);

	/*
	 * Do not reserve when already reserved, when not supported or when
	 * auto-rewinding on device closure.
	 */
	if ((un->un_rsvd_status & (ST_APPLICATION_RESERVATIONS)) ||
	    ((un->un_rsvd_status & (ST_RESERVE | ST_LOST_RESERVE)) ==
	    ST_RESERVE) || (un->un_dp->options & ST_NO_RESERVE_RELEASE) ||
	    ((un->un_state == ST_STATE_CLOSING) && (cmd == SCMD_REWIND))) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_NOTE,
		    "st_check_cmd_for_need_to_reserve() reserve unneeded %s",
		    st_print_scsi_cmd(cmd));
		return (0);
	}

	/* search for this command on the list */
	attrib = st_lookup_cmd_attribute(cmd);

	if (attrib == NULL) {
		rval = 1; /* Not found, when in doubt reserve */
	} else if ((attrib->requires_reserve) != 0) {
		rval = 1;
	} else if ((attrib->reserve_byte) != 0) {
		/*
		 * cmd is on list.
		 * if byte is zero always allowed.
		 */
		rval = 1;
	} else if (((attrib->reserve_mask) & cnt) != 0) {
		rval = 1;
	} else {
		rval = 0;
	}

	if (rval) {
		ST_DEBUG6(ST_DEVINFO, st_label, CE_NOTE,
		    "Cmd %s requires reservation", st_print_scsi_cmd(cmd));

		rval = st_do_reserve(un);
	}

	return (rval);
}

static int
st_reserve_release(struct scsi_tape *un, int cmd, ubufunc_t ubf)
{
	struct uscsi_cmd	uscsi_cmd;
	int			rval;
	char			cdb[CDB_GROUP0];
	struct scsi_arq_status	stat;



	ST_FUNC(ST_DEVINFO, st_reserve_release);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_reserve_release: %s \n",
	    (cmd == ST_RELEASE)?  "Releasing":"Reserving");

	bzero(&cdb, CDB_GROUP0);
	if (cmd == ST_RELEASE) {
		cdb[0] = SCMD_RELEASE;
	} else {
		cdb[0] = SCMD_RESERVE;
	}
	bzero(&uscsi_cmd, sizeof (struct uscsi_cmd));
	uscsi_cmd.uscsi_flags = USCSI_WRITE | USCSI_RQENABLE;
	uscsi_cmd.uscsi_cdb = cdb;
	uscsi_cmd.uscsi_cdblen = CDB_GROUP0;
	uscsi_cmd.uscsi_timeout = un->un_dp->non_motion_timeout;
	uscsi_cmd.uscsi_rqbuf = (caddr_t)&stat;
	uscsi_cmd.uscsi_rqlen = sizeof (stat);

	rval = ubf(un, &uscsi_cmd, FKIOCTL);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_reserve_release: rval(1)=%d\n", rval);

	if (rval) {
		if (uscsi_cmd.uscsi_status == STATUS_RESERVATION_CONFLICT) {
			rval = EACCES;
		}
		/*
		 * dynamically turn off reserve/release support
		 * in case of drives which do not support
		 * reserve/release command(ATAPI drives).
		 */
		if (un->un_status == KEY_ILLEGAL_REQUEST) {
			if ((un->un_dp->options & ST_NO_RESERVE_RELEASE) == 0) {
				un->un_dp->options |= ST_NO_RESERVE_RELEASE;
				ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "Tape unit does not support "
				    "reserve/release \n");
			}
			rval = 0;
		}
	}
	return (rval);
}

static int
st_take_ownership(struct scsi_tape *un, ubufunc_t ubf)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_take_ownership);

	ASSERT(mutex_owned(ST_MUTEX));

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_take_ownership: Entering ...\n");


	rval = st_reserve_release(un, ST_RESERVE, ubf);
	/*
	 * XXX -> Should reset be done only if we get EACCES.
	 * .
	 */
	if (rval) {
		if (st_reset(un, RESET_LUN) == 0) {
			return (EIO);
		}
		un->un_rsvd_status &=
		    ~(ST_LOST_RESERVE | ST_RESERVATION_CONFLICT);

		mutex_exit(ST_MUTEX);
		delay(drv_usectohz(ST_RESERVATION_DELAY));
		mutex_enter(ST_MUTEX);
		/*
		 * remove the check condition.
		 */
		(void) st_reserve_release(un, ST_RESERVE, ubf);
		rval = st_reserve_release(un, ST_RESERVE, ubf);
		if (rval != 0) {
			if ((st_reserve_release(un, ST_RESERVE, ubf))
			    != 0) {
				rval = (un->un_rsvd_status &
				    ST_RESERVATION_CONFLICT) ? EACCES : EIO;
				return (rval);
			}
		}
		/*
		 * Set tape state to ST_STATE_OFFLINE , in case if
		 * the user wants to continue and start using
		 * the tape.
		 */
		un->un_state = ST_STATE_OFFLINE;
		un->un_rsvd_status |= ST_INIT_RESERVE;
	}
	return (rval);
}

static int
st_create_errstats(struct scsi_tape *un, int instance)
{
	char	kstatname[KSTAT_STRLEN];

	ST_FUNC(ST_DEVINFO, st_create_errstats);

	/*
	 * Create device error kstats
	 */

	if (un->un_errstats == (kstat_t *)0) {
		(void) sprintf(kstatname, "st%d,err", instance);
		un->un_errstats = kstat_create("sterr", instance, kstatname,
		    "device_error", KSTAT_TYPE_NAMED,
		    sizeof (struct st_errstats) / sizeof (kstat_named_t),
		    KSTAT_FLAG_PERSISTENT);

		if (un->un_errstats) {
			struct st_errstats	*stp;

			stp = (struct st_errstats *)un->un_errstats->ks_data;
			kstat_named_init(&stp->st_softerrs, "Soft Errors",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&stp->st_harderrs, "Hard Errors",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&stp->st_transerrs, "Transport Errors",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&stp->st_vid, "Vendor",
			    KSTAT_DATA_CHAR);
			kstat_named_init(&stp->st_pid, "Product",
			    KSTAT_DATA_CHAR);
			kstat_named_init(&stp->st_revision, "Revision",
			    KSTAT_DATA_CHAR);
			kstat_named_init(&stp->st_serial, "Serial No",
			    KSTAT_DATA_CHAR);
			un->un_errstats->ks_private = un;
			un->un_errstats->ks_update = nulldev;
			kstat_install(un->un_errstats);
			/*
			 * Fill in the static data
			 */
			(void) strncpy(&stp->st_vid.value.c[0],
			    ST_INQUIRY->inq_vid, 8);
			/*
			 * XXX:  Emulex MT-02 (and emulators) predates
			 *	 SCSI-1 and has no vid & pid inquiry data.
			 */
			if (ST_INQUIRY->inq_len != 0) {
				(void) strncpy(&stp->st_pid.value.c[0],
				    ST_INQUIRY->inq_pid, 16);
				(void) strncpy(&stp->st_revision.value.c[0],
				    ST_INQUIRY->inq_revision, 4);
			}
		}
	}
	return (0);
}

static int
st_validate_tapemarks(struct scsi_tape *un, ubufunc_t ubf, tapepos_t *pos)
{
	int rval;
	bufunc_t bf = (ubf == st_uscsi_rcmd) ? st_rcmd : st_cmd;

	ST_FUNC(ST_DEVINFO, st_validate_tapemarks);

	ASSERT(MUTEX_HELD(&un->un_sd->sd_mutex));
	ASSERT(mutex_owned(ST_MUTEX));

	/* Can't restore an invalid position */
	if (pos->pmode == invalid) {
		return (4);
	}

	/*
	 * Assumtions:
	 *	If a position was read and is in logical position mode.
	 *	If a drive supports read position it supports locate.
	 *	If the read position type is not NO_POS. even though
	 *	   a read position make not have been attemped yet.
	 *
	 *	The drive can locate to the position.
	 */
	if (pos->pmode == logical || un->un_read_pos_type != NO_POS) {
		/*
		 * If position mode is logical or legacy mode try
		 * to locate there as it is faster.
		 * If it fails try the old way.
		 */
		scsi_log(ST_DEVINFO, st_label, CE_NOTE,
		    "Restoring tape position to lgclblkbo=0x%"PRIx64"....",
		    pos->lgclblkno);

		if (st_logical_block_locate(un, st_uscsi_cmd, &un->un_pos,
		    pos->lgclblkno, pos->partition) == 0) {
			/* Assume we are there copy rest of position back */
			if (un->un_pos.lgclblkno == pos->lgclblkno) {
				COPY_POS(&un->un_pos, pos);
			}
			return (0);
		}

		/*
		 * If logical block locate failed to restore a logical
		 * position, can't recover.
		 */
		if (pos->pmode == logical) {
			return (-1);
		}
	}


	scsi_log(ST_DEVINFO, st_label, CE_NOTE,
	    "Restoring tape position at fileno=%x, blkno=%x....",
	    pos->fileno, pos->blkno);

	/*
	 * Rewind ? Oh yeah, Fidelity has got the STK F/W changed
	 * so as not to rewind tape on RESETS: Gee, Has life ever
	 * been simple in tape land ?
	 */
	rval = bf(un, SCMD_REWIND, 0, SYNC_CMD);
	if (rval) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "Failed to restore the last file and block position: In"
		    " this state, Tape will be loaded at BOT during next open");
		un->un_pos.pmode = invalid;
		return (rval);
	}

	/* If the position was as the result of back space file */
	if (pos->blkno > (INF / 2)) {
		/* Go one extra file forward */
		pos->fileno++;
		/* Figure how many blocks to back into the previous file */
		pos->blkno = -(INF - pos->blkno);
	}

	/* Go to requested fileno */
	if (pos->fileno) {
		rval = st_cmd(un, SCMD_SPACE, Fmk(pos->fileno), SYNC_CMD);
		if (rval) {
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "Failed to restore the last file position: In this "
			    " state, Tape will be loaded at BOT during next"
			    " open %d", __LINE__);
			un->un_pos.pmode = invalid;
			pos->pmode = invalid;
			return (rval);
		}
	}

	/*
	 * If backing into a file we already did an extra file forward.
	 * Now we have to back over the filemark to get to the end of
	 * the previous file. The blkno has been ajusted to a negative
	 * value so we will get to the expected location.
	 */
	if (pos->blkno) {
		rval = bf(un, SCMD_SPACE, Fmk(-1), SYNC_CMD);
		if (rval) {
			scsi_log(ST_DEVINFO, st_label, CE_WARN,
			    "Failed to restore the last file position: In this "
			    " state, Tape will be loaded at BOT during next"
			    " open %d", __LINE__);
			un->un_pos.pmode = invalid;
			pos->pmode = invalid;
			return (rval);
		}
	}

	/*
	 * The position mode, block and fileno should be correct,
	 * This updates eof and logical position information.
	 */
	un->un_pos.eof = pos->eof;
	un->un_pos.lgclblkno = pos->lgclblkno;

	return (0);
}

/*
 * check sense key, ASC, ASCQ in order to determine if the tape needs
 * to be ejected
 */

static int
st_check_asc_ascq(struct scsi_tape *un)
{
	struct scsi_extended_sense *sensep = ST_RQSENSE;
	struct tape_failure_code   *code;

	ST_FUNC(ST_DEVINFO, st_check_asc_ascq);

	for (code = st_tape_failure_code; code->key != 0xff; code++) {
		if ((code->key  == sensep->es_key) &&
		    (code->add_code  == sensep->es_add_code) &&
		    (code->qual_code == sensep->es_qual_code))
			return (1);
	}
	return (0);
}

/*
 * st_logpage_supported() sends a Log Sense command with
 * page code = 0 = Supported Log Pages Page to the device,
 * to see whether the page 'page' is supported.
 * Return values are:
 * -1 if the Log Sense command fails
 * 0 if page is not supported
 * 1 if page is supported
 */

static int
st_logpage_supported(struct scsi_tape *un, uchar_t page)
{
	uchar_t *sp, *sensep;
	unsigned length;
	struct uscsi_cmd *com;
	struct scsi_arq_status status;
	int rval;
	char cdb[CDB_GROUP1] = {
		SCMD_LOG_SENSE_G1,
		0,
		SUPPORTED_LOG_PAGES_PAGE,
		0,
		0,
		0,
		0,
		0,
		(char)LOG_SENSE_LENGTH,
		0
	};

	ST_FUNC(ST_DEVINFO, st_logpage_supported);

	ASSERT(mutex_owned(ST_MUTEX));

	com = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);
	sensep = kmem_zalloc(LOG_SENSE_LENGTH, KM_SLEEP);

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP1;
	com->uscsi_bufaddr = (caddr_t)sensep;
	com->uscsi_buflen = LOG_SENSE_LENGTH;
	com->uscsi_rqlen = sizeof (status);
	com->uscsi_rqbuf = (caddr_t)&status;
	com->uscsi_flags =
	    USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_READ;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;
	rval = st_uscsi_cmd(un, com, FKIOCTL);
	if (rval || com->uscsi_status) {
		/* uscsi-command failed */
		rval = -1;
	} else {

		sp = sensep + 3;

		for (length = *sp++; length > 0; length--, sp++) {

			if (*sp == page) {
				rval = 1;
				break;
			}
		}
	}
	kmem_free(com, sizeof (struct uscsi_cmd));
	kmem_free(sensep, LOG_SENSE_LENGTH);
	return (rval);
}


/*
 * st_check_clean_bit() gets the status of the tape's cleaning bit.
 *
 * If the device does support the TapeAlert log page, then the cleaning bit
 * information will be read from this page. Otherwise we will see if one of
 * ST_CLN_TYPE_1, ST_CLN_TYPE_2 or ST_CLN_TYPE_3 is set in the properties of
 * the device, which means, that we can get the cleaning bit information via
 * a RequestSense command.
 * If both methods of getting cleaning bit information are not supported
 * st_check_clean_bit() will return with 0. Otherwise st_check_clean_bit()
 * returns with
 * - MTF_TAPE_CLN_SUPPORTED if cleaning bit is not set or
 * - MTF_TAPE_CLN_SUPPORTED | MTF_TAPE_HEAD_DIRTY if cleaning bit is set.
 * If the call to st_uscsi_cmd() to do the Log Sense or the Request Sense
 * command fails, or if the amount of Request Sense data is not enough, then
 *  st_check_clean_bit() returns with -1.
 */

static int
st_check_clean_bit(struct scsi_tape *un)
{
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_check_clean_bit);

	ASSERT(mutex_owned(ST_MUTEX));

	if (un->un_HeadClean & TAPE_ALERT_NOT_SUPPORTED) {
		return (rval);
	}

	if (un->un_HeadClean == TAPE_ALERT_SUPPORT_UNKNOWN) {

		rval = st_logpage_supported(un, TAPE_SEQUENTIAL_PAGE);
		if (rval == -1) {
			return (0);
		}
		if (rval == 1) {

			un->un_HeadClean |= TAPE_SEQUENTIAL_SUPPORTED;
		}

		rval = st_logpage_supported(un, TAPE_ALERT_PAGE);
		if (rval == -1) {
			return (0);
		}
		if (rval == 1) {

			un->un_HeadClean |= TAPE_ALERT_SUPPORTED;
		}

		if (un->un_HeadClean == TAPE_ALERT_SUPPORT_UNKNOWN) {

			un->un_HeadClean = TAPE_ALERT_NOT_SUPPORTED;
		}
	}

	rval = 0;

	if (un->un_HeadClean & TAPE_SEQUENTIAL_SUPPORTED) {

		rval = st_check_sequential_clean_bit(un);
		if (rval == -1) {
			return (0);
		}
	}

	if ((rval == 0) && (un->un_HeadClean & TAPE_ALERT_SUPPORTED)) {

		rval = st_check_alert_flags(un);
		if (rval == -1) {
			return (0);
		}
	}

	if ((rval == 0) && (un->un_dp->options & ST_CLN_MASK)) {

		rval = st_check_sense_clean_bit(un);
		if (rval == -1) {
			return (0);
		}
	}

	/*
	 * If found a supported means to check need to clean.
	 */
	if (rval & MTF_TAPE_CLN_SUPPORTED) {

		/*
		 * head needs to be cleaned.
		 */
		if (rval & MTF_TAPE_HEAD_DIRTY) {

			/*
			 * Print log message only first time
			 * found needing cleaned.
			 */
			if ((un->un_HeadClean & TAPE_PREVIOUSLY_DIRTY) == 0) {

				scsi_log(ST_DEVINFO, st_label, CE_WARN,
				    "Periodic head cleaning required");

				un->un_HeadClean |= TAPE_PREVIOUSLY_DIRTY;
			}

		} else {

			un->un_HeadClean &= ~TAPE_PREVIOUSLY_DIRTY;
		}
	}

	return (rval);
}


static int
st_check_sequential_clean_bit(struct scsi_tape *un)
{
	int rval;
	int ix;
	ushort_t parameter;
	struct uscsi_cmd *cmd;
	struct log_sequential_page *sp;
	struct log_sequential_page_parameter *prm;
	struct scsi_arq_status status;
	char cdb[CDB_GROUP1] = {
		SCMD_LOG_SENSE_G1,
		0,
		TAPE_SEQUENTIAL_PAGE | CURRENT_CUMULATIVE_VALUES,
		0,
		0,
		0,
		0,
		(char)(sizeof (struct log_sequential_page) >> 8),
		(char)(sizeof (struct log_sequential_page)),
		0
	};

	ST_FUNC(ST_DEVINFO, st_check_sequential_clean_bit);

	cmd = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);
	sp  = kmem_zalloc(sizeof (struct log_sequential_page), KM_SLEEP);

	cmd->uscsi_flags   =
	    USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_READ;
	cmd->uscsi_timeout = un->un_dp->non_motion_timeout;
	cmd->uscsi_cdb	   = cdb;
	cmd->uscsi_cdblen  = CDB_GROUP1;
	cmd->uscsi_bufaddr = (caddr_t)sp;
	cmd->uscsi_buflen  = sizeof (struct log_sequential_page);
	cmd->uscsi_rqlen   = sizeof (status);
	cmd->uscsi_rqbuf   = (caddr_t)&status;

	rval = st_uscsi_cmd(un, cmd, FKIOCTL);

	if (rval || cmd->uscsi_status || cmd->uscsi_resid) {

		rval = -1;

	} else if (sp->log_page.code != TAPE_SEQUENTIAL_PAGE) {

		rval = -1;
	}

	prm = &sp->param[0];

	for (ix = 0; rval == 0 && ix < TAPE_SEQUENTIAL_PAGE_PARA; ix++) {

		if (prm->log_param.length == 0) {
			break;
		}

		parameter = (((prm->log_param.pc_hi << 8) & 0xff00) +
		    (prm->log_param.pc_lo & 0xff));

		if (parameter == SEQUENTIAL_NEED_CLN) {

			rval = MTF_TAPE_CLN_SUPPORTED;
			if (prm->param_value[prm->log_param.length - 1]) {

				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "sequential log says head dirty\n");
				rval |= MTF_TAPE_HEAD_DIRTY;
			}
		}
		prm = (struct log_sequential_page_parameter *)
		    &prm->param_value[prm->log_param.length];
	}

	kmem_free(cmd, sizeof (struct uscsi_cmd));
	kmem_free(sp,  sizeof (struct log_sequential_page));

	return (rval);
}


static int
st_check_alert_flags(struct scsi_tape *un)
{
	struct st_tape_alert *ta;
	struct uscsi_cmd *com;
	struct scsi_arq_status status;
	unsigned ix, length;
	int rval;
	tape_alert_flags flag;
	char cdb[CDB_GROUP1] = {
		SCMD_LOG_SENSE_G1,
		0,
		TAPE_ALERT_PAGE | CURRENT_THRESHOLD_VALUES,
		0,
		0,
		0,
		0,
		(char)(sizeof (struct st_tape_alert) >> 8),
		(char)(sizeof (struct st_tape_alert)),
		0
	};

	ST_FUNC(ST_DEVINFO, st_check_alert_clean_bit);

	com = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);
	ta  = kmem_zalloc(sizeof (struct st_tape_alert), KM_SLEEP);

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP1;
	com->uscsi_bufaddr = (caddr_t)ta;
	com->uscsi_buflen = sizeof (struct st_tape_alert);
	com->uscsi_rqlen = sizeof (status);
	com->uscsi_rqbuf = (caddr_t)&status;
	com->uscsi_flags =
	    USCSI_DIAGNOSE | USCSI_RQENABLE | USCSI_READ;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;

	rval = st_uscsi_cmd(un, com, FKIOCTL);

	if (rval || com->uscsi_status || com->uscsi_resid) {

		rval = -1; /* uscsi-command failed */

	} else if (ta->log_page.code != TAPE_ALERT_PAGE) {

		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		"Not Alert Log Page returned 0x%X\n", ta->log_page.code);
		rval = -1;
	}

	length = (ta->log_page.length_hi << 8) + ta->log_page.length_lo;


	if (length != TAPE_ALERT_PARAMETER_LENGTH) {

		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "TapeAlert length %d\n", length);
	}


	for (ix = 0; ix < TAPE_ALERT_MAX_PARA; ix++) {

		/*
		 * if rval is bad before the first pass don't bother
		 */
		if (ix == 0 && rval != 0) {

			break;
		}

		flag = ((ta->param[ix].log_param.pc_hi << 8) +
		    ta->param[ix].log_param.pc_lo);

		if ((ta->param[ix].param_value & 1) == 0) {
			continue;
		}
		/*
		 * check to see if current parameter is of interest.
		 * CLEAN_FOR_ERRORS is vendor specific to 9840 9940 stk's.
		 */
		if ((flag == TAF_CLEAN_NOW) ||
		    (flag == TAF_CLEAN_PERIODIC) ||
		    ((flag == CLEAN_FOR_ERRORS) &&
		    (un->un_dp->type == ST_TYPE_STK9840))) {

			rval = MTF_TAPE_CLN_SUPPORTED;


			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "alert_page drive needs clean %d\n", flag);
			un->un_HeadClean |= TAPE_ALERT_STILL_DIRTY;
			rval |= MTF_TAPE_HEAD_DIRTY;

		} else if (flag == TAF_CLEANING_MEDIA) {

			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "alert_page drive was cleaned\n");
			un->un_HeadClean &= ~TAPE_ALERT_STILL_DIRTY;
		}

	}

	/*
	 * Report it as dirty till we see it cleaned
	 */
	if (un->un_HeadClean & TAPE_ALERT_STILL_DIRTY) {

		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "alert_page still dirty\n");
		rval |= MTF_TAPE_HEAD_DIRTY;
	}

	kmem_free(com, sizeof (struct uscsi_cmd));
	kmem_free(ta,  sizeof (struct st_tape_alert));

	return (rval);
}


static int
st_check_sense_clean_bit(struct scsi_tape *un)
{
	uchar_t *sensep;
	char cdb[CDB_GROUP0];
	struct uscsi_cmd *com;
	ushort_t byte_pos;
	uchar_t bit_mask;
	unsigned length;
	int index;
	int rval;

	ST_FUNC(ST_DEVINFO, st_check_sense_clean_bit);

	/*
	 * Since this tape does not support Tape Alert,
	 * we now try to get the cleanbit status via
	 * Request Sense.
	 */

	if ((un->un_dp->options & ST_CLN_MASK) == ST_CLN_TYPE_1) {

		index = 0;

	} else if ((un->un_dp->options & ST_CLN_MASK) == ST_CLN_TYPE_2) {

		index = 1;

	} else if ((un->un_dp->options & ST_CLN_MASK) == ST_CLN_TYPE_3) {

		index = 2;

	} else {

		return (-1);
	}

	byte_pos  = st_cln_bit_position[index].cln_bit_byte;
	bit_mask  = st_cln_bit_position[index].cln_bit_mask;
	length = byte_pos + 1;

	com    = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);
	sensep = kmem_zalloc(length, KM_SLEEP);

	cdb[0] = SCMD_REQUEST_SENSE;
	cdb[1] = 0;
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = (char)length;
	cdb[5] = 0;

	com->uscsi_cdb = cdb;
	com->uscsi_cdblen = CDB_GROUP0;
	com->uscsi_bufaddr = (caddr_t)sensep;
	com->uscsi_buflen = length;
	com->uscsi_flags =
	    USCSI_DIAGNOSE | USCSI_SILENT | USCSI_READ;
	com->uscsi_timeout = un->un_dp->non_motion_timeout;

	rval = st_uscsi_cmd(un, com, FKIOCTL);

	if (rval || com->uscsi_status || com->uscsi_resid) {

		rval = -1;

	} else {

		rval = MTF_TAPE_CLN_SUPPORTED;
		if ((sensep[byte_pos] & bit_mask) == bit_mask) {

			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "sense data says head dirty\n");
			rval |= MTF_TAPE_HEAD_DIRTY;
		}
	}

	kmem_free(com, sizeof (struct uscsi_cmd));
	kmem_free(sensep, length);
	return (rval);
}

/*
 * st_clear_unit_attention
 *
 *  	run test unit ready's to clear out outstanding
 * 	unit attentions.
 * 	returns zero for SUCCESS or the errno from st_cmd call
 */
static int
st_clear_unit_attentions(dev_t dev_instance, int max_trys)
{
	int	i    = 0;
	int	rval;

	GET_SOFT_STATE(dev_instance);
	ST_FUNC(ST_DEVINFO, st_clear_unit_attentions);

	do {
		rval = st_cmd(un, SCMD_TEST_UNIT_READY, 0, SYNC_CMD);
	} while ((rval != 0) && (rval != ENXIO) && (++i < max_trys));
	return (rval);
}

static void
st_calculate_timeouts(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_calculate_timeouts);

	if (un->un_dp->non_motion_timeout == 0) {
		if (un->un_dp->options & ST_LONG_TIMEOUTS) {
			un->un_dp->non_motion_timeout =
			    st_io_time * st_long_timeout_x;
		} else {
			un->un_dp->non_motion_timeout = (ushort_t)st_io_time;
		}
	}

	if (un->un_dp->io_timeout == 0) {
		if (un->un_dp->options & ST_LONG_TIMEOUTS) {
			un->un_dp->io_timeout = st_io_time * st_long_timeout_x;
		} else {
			un->un_dp->io_timeout = (ushort_t)st_io_time;
		}
	}

	if (un->un_dp->rewind_timeout == 0) {
		if (un->un_dp->options & ST_LONG_TIMEOUTS) {
			un->un_dp->rewind_timeout =
			    st_space_time * st_long_timeout_x;
		} else {
			un->un_dp->rewind_timeout = (ushort_t)st_space_time;
		}
	}

	if (un->un_dp->space_timeout == 0) {
		if (un->un_dp->options & ST_LONG_TIMEOUTS) {
			un->un_dp->space_timeout =
			    st_space_time * st_long_timeout_x;
		} else {
			un->un_dp->space_timeout = (ushort_t)st_space_time;
		}
	}

	if (un->un_dp->load_timeout == 0) {
		if (un->un_dp->options & ST_LONG_TIMEOUTS) {
			un->un_dp->load_timeout =
			    st_space_time * st_long_timeout_x;
		} else {
			un->un_dp->load_timeout = (ushort_t)st_space_time;
		}
	}

	if (un->un_dp->unload_timeout == 0) {
		if (un->un_dp->options & ST_LONG_TIMEOUTS) {
			un->un_dp->unload_timeout =
			    st_space_time * st_long_timeout_x;
		} else {
			un->un_dp->unload_timeout = (ushort_t)st_space_time;
		}
	}

	if (un->un_dp->erase_timeout == 0) {
		if (un->un_dp->options & ST_LONG_ERASE) {
			un->un_dp->erase_timeout =
			    st_space_time * st_long_space_time_x;
		} else {
			un->un_dp->erase_timeout = (ushort_t)st_space_time;
		}
	}
}


static writablity
st_is_not_wormable(struct scsi_tape *un)
{
	ST_FUNC(ST_DEVINFO, st_is_not_wormable);
	return (RDWR);
}

static writablity
st_is_hp_dat_tape_worm(struct scsi_tape *un)
{
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_hp_dat_tape_worm);

	/* Mode sense should be current */
	if (un->un_mspl->media_type == 1) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has WORM media loaded\n");
		wrt = WORM;
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has non WORM media loaded\n");
		wrt = RDWR;
	}
	return (wrt);
}

#define	HP_DAT_INQUIRY 0x4A
static writablity
st_is_hp_dat_worm(struct scsi_tape *un)
{
	char *buf;
	int result;
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_hp_dat_worm);

	buf = kmem_zalloc(HP_DAT_INQUIRY, KM_SLEEP);

	result = st_get_special_inquiry(un, HP_DAT_INQUIRY, buf, 0);

	if (result != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Read Standard Inquiry for WORM support failed");
		wrt = FAILED;
	} else if ((buf[40] & 1) == 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive is NOT WORMable\n");
		/* This drive doesn't support it so don't check again */
		un->un_dp->options &= ~ST_WORMABLE;
		wrt = RDWR;
		un->un_wormable = st_is_not_wormable;
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive supports WORM version %d\n", buf[40] >> 1);
		un->un_wormable = st_is_hp_dat_tape_worm;
		wrt = un->un_wormable(un);
	}

	kmem_free(buf, HP_DAT_INQUIRY);

	/*
	 * If drive doesn't support it no point in checking further.
	 */
	return (wrt);
}

static writablity
st_is_hp_lto_tape_worm(struct scsi_tape *un)
{
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_hp_lto_tape_worm);

	/* Mode sense should be current */
	switch (un->un_mspl->media_type) {
	case 0x00:
		switch (un->un_mspl->density) {
		case 0x40:
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Drive has standard Gen I media loaded\n");
			break;
		case 0x42:
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Drive has standard Gen II media loaded\n");
			break;
		case 0x44:
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Drive has standard Gen III media loaded\n");
			break;
		case 0x46:
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Drive has standard Gen IV media loaded\n");
			break;
		default:
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Drive has standard unknown 0x%X media loaded\n",
			    un->un_mspl->density);
		}
		wrt = RDWR;
		break;
	case 0x01:
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has WORM medium loaded\n");
		wrt = WORM;
		break;
	case 0x80:
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has CD-ROM emulation medium loaded\n");
		wrt = WORM;
		break;
	default:
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has an unexpected medium type 0x%X loaded\n",
		    un->un_mspl->media_type);
		wrt = RDWR;
	}

	return (wrt);
}

#define	LTO_REQ_INQUIRY 44
static writablity
st_is_hp_lto_worm(struct scsi_tape *un)
{
	char *buf;
	int result;
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_hp_lto_worm);

	buf = kmem_zalloc(LTO_REQ_INQUIRY, KM_SLEEP);

	result = st_get_special_inquiry(un, LTO_REQ_INQUIRY, buf, 0);

	if (result != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Read Standard Inquiry for WORM support failed");
		wrt = FAILED;
	} else if ((buf[40] & 1) == 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive is NOT WORMable\n");
		/* This drive doesn't support it so don't check again */
		un->un_dp->options &= ~ST_WORMABLE;
		wrt = RDWR;
		un->un_wormable = st_is_not_wormable;
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive supports WORM version %d\n", buf[40] >> 1);
		un->un_wormable = st_is_hp_lto_tape_worm;
		wrt = un->un_wormable(un);
	}

	kmem_free(buf, LTO_REQ_INQUIRY);

	/*
	 * If drive doesn't support it no point in checking further.
	 */
	return (wrt);
}

static writablity
st_is_t10_worm_device(struct scsi_tape *un)
{
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_t10_worm_device);

	if (un->un_mspl->media_type == 0x3c) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has WORM media loaded\n");
		wrt = WORM;
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has non WORM media loaded\n");
		wrt = RDWR;
	}
	return (wrt);
}

#define	SEQ_CAP_PAGE	(char)0xb0
static writablity
st_is_t10_worm(struct scsi_tape *un)
{
	char *buf;
	int result;
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_t10_worm);

	buf = kmem_zalloc(6, KM_SLEEP);

	result = st_get_special_inquiry(un, 6, buf, SEQ_CAP_PAGE);

	if (result != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Read Vitial Inquiry for Sequental Capability"
		    " WORM support failed %x", result);
		wrt = FAILED;
	} else if ((buf[4] & 1) == 0) {
		ASSERT(buf[1] == SEQ_CAP_PAGE);
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive is NOT WORMable\n");
		/* This drive doesn't support it so don't check again */
		un->un_dp->options &= ~ST_WORMABLE;
		wrt = RDWR;
		un->un_wormable = st_is_not_wormable;
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive supports WORM\n");
		un->un_wormable = st_is_t10_worm_device;
		wrt = un->un_wormable(un);
	}

	kmem_free(buf, 6);

	return (wrt);
}


#define	STK_REQ_SENSE 26

static writablity
st_is_stk_worm(struct scsi_tape *un)
{
	char cdb[CDB_GROUP0] = {SCMD_REQUEST_SENSE, 0, 0, 0, STK_REQ_SENSE, 0};
	struct scsi_extended_sense *sense;
	struct uscsi_cmd *cmd;
	char *buf;
	int result;
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_stk_worm);

	cmd = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);
	buf = kmem_alloc(STK_REQ_SENSE, KM_SLEEP);
	sense = (struct scsi_extended_sense *)buf;

	cmd->uscsi_flags = USCSI_READ;
	cmd->uscsi_timeout = un->un_dp->non_motion_timeout;
	cmd->uscsi_cdb = &cdb[0];
	cmd->uscsi_bufaddr = buf;
	cmd->uscsi_buflen = STK_REQ_SENSE;
	cmd->uscsi_cdblen = CDB_GROUP0;
	cmd->uscsi_rqlen = 0;
	cmd->uscsi_rqbuf = NULL;

	result = st_uscsi_cmd(un, cmd, FKIOCTL);

	if (result != 0 || cmd->uscsi_status != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Request Sense for WORM failed");
		wrt = RDWR;
	} else if (sense->es_add_len + 8 < 24) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive didn't send enough sense data for WORM byte %d\n",
		    sense->es_add_len + 8);
		wrt = RDWR;
		un->un_wormable = st_is_not_wormable;
	} else if ((buf[24]) & 0x02) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has WORM tape loaded\n");
		wrt = WORM;
		un->un_wormable = st_is_stk_worm;
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive has normal tape loaded\n");
		wrt = RDWR;
		un->un_wormable = st_is_stk_worm;
	}

	kmem_free(buf, STK_REQ_SENSE);
	kmem_free(cmd, sizeof (struct uscsi_cmd));
	return (wrt);
}

#define	DLT_INQ_SZ 44

static writablity
st_is_dlt_tape_worm(struct scsi_tape *un)
{
	caddr_t buf;
	int result;
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_dlt_tape_worm);

	buf = kmem_alloc(DLT_INQ_SZ, KM_SLEEP);

	/* Read Attribute Media Type */

	result = st_read_attributes(un, 0x0408, buf, 10, st_uscsi_cmd);

	/*
	 * If this quantum drive is attached via an HBA that cannot
	 * support thr read attributes command return error in the
	 * hope that someday they will support the t10 method.
	 */
	if (result == EINVAL && un->un_max_cdb_sz < CDB_GROUP4) {
		scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Read Attribute Command for WORM Media detection is not "
		    "supported on the HBA that this drive is attached to.");
		wrt = RDWR;
		un->un_wormable = st_is_not_wormable;
		goto out;
	}

	if (result != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Read Attribute Command for WORM Media returned 0x%x",
		    result);
		wrt = RDWR;
		un->un_dp->options &= ~ST_WORMABLE;
		goto out;
	}

	if ((uchar_t)buf[9] == 0x80) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive media is WORM\n");
		wrt = WORM;
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive media is not WORM Media 0x%x\n", (uchar_t)buf[9]);
		wrt = RDWR;
	}

out:
	kmem_free(buf, DLT_INQ_SZ);
	return (wrt);
}

static writablity
st_is_dlt_worm(struct scsi_tape *un)
{
	caddr_t buf;
	int result;
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_dlt_worm);

	buf = kmem_alloc(DLT_INQ_SZ, KM_SLEEP);

	result = st_get_special_inquiry(un, DLT_INQ_SZ, buf, 0xC0);

	if (result != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Read Vendor Specific Inquiry for WORM support failed");
		wrt = RDWR;
		goto out;
	}

	if ((buf[2] & 1) == 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive is not WORMable\n");
		wrt = RDWR;
		un->un_dp->options &= ~ST_WORMABLE;
		un->un_wormable = st_is_not_wormable;
		goto out;
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Drive is WORMable\n");
		un->un_wormable = st_is_dlt_tape_worm;
		wrt = un->un_wormable(un);
	}
out:
	kmem_free(buf, DLT_INQ_SZ);

	return (wrt);
}

typedef struct {
	struct modeheader_seq header;
#if defined(_BIT_FIELDS_LTOH) /* X86 */
	uchar_t pagecode	:6,
				:2;
	uchar_t page_len;
	uchar_t syslogalive	:2,
		device		:1,
		abs		:1,
		ulpbot		:1,
		prth		:1,
		ponej		:1,
		ait		:1;
	uchar_t span;

	uchar_t			:6,
		worm		:1,
		mic		:1;
	uchar_t worm_cap	:1,
				:7;
	uint32_t		:32;
#else /* SPARC */
	uchar_t			:2,
		pagecode	:6;
	uchar_t page_len;
	uchar_t ait		:1,
		device		:1,
		abs		:1,
		ulpbot		:1,
		prth		:1,
		ponej		:1,
		syslogalive	:2;
	uchar_t span;
	uchar_t mic		:1,
		worm		:1,
				:6;
	uchar_t			:7,
		worm_cap	:1;
	uint32_t		:32;
#endif
}ait_dev_con;

#define	AIT_DEV_PAGE 0x31
static writablity
st_is_sony_worm(struct scsi_tape *un)
{
	int result;
	writablity wrt;
	ait_dev_con *ait_conf;

	ST_FUNC(ST_DEVINFO, st_is_sony_worm);

	ait_conf = kmem_zalloc(sizeof (ait_dev_con), KM_SLEEP);

	result = st_gen_mode_sense(un, st_uscsi_cmd, AIT_DEV_PAGE,
	    (struct seq_mode *)ait_conf, sizeof (ait_dev_con));

	if (result == 0) {

		if (ait_conf->pagecode != AIT_DEV_PAGE) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "returned page 0x%x not 0x%x AIT_DEV_PAGE\n",
			    ait_conf->pagecode, AIT_DEV_PAGE);
			wrt = RDWR;
			un->un_wormable = st_is_not_wormable;

		} else if (ait_conf->worm_cap) {

			un->un_wormable = st_is_sony_worm;

			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Drives is WORMable\n");
			if (ait_conf->worm) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "Media is WORM\n");
				wrt = WORM;
			} else {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "Media is not WORM\n");
				wrt = RDWR;
			}

		} else {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Drives not is WORMable\n");
			wrt = RDWR;
			/* No further checking required */
			un->un_dp->options &= ~ST_WORMABLE;
		}

	} else {

		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "AIT device config mode sense page read command failed"
		    " result = %d ", result);
		wrt = FAILED;
		un->un_wormable = st_is_not_wormable;
	}

	kmem_free(ait_conf, sizeof (ait_dev_con));
	return (wrt);
}

static writablity
st_is_drive_worm(struct scsi_tape *un)
{
	writablity wrt;

	ST_FUNC(ST_DEVINFO, st_is_sony_worm);

	switch (un->un_dp->type) {
	case MT_ISDLT:
		wrt = st_is_dlt_worm(un);
		break;

	case MT_ISSTK9840:
		wrt = st_is_stk_worm(un);
		break;

	case MT_IS8MM:
	case MT_ISAIT:
		wrt = st_is_sony_worm(un);
		break;

	case MT_LTO:
		if (strncmp("HP ", un->un_dp->vid, 3) == 0) {
			wrt = st_is_hp_lto_worm(un);
		} else {
			wrt = st_is_t10_worm(un);
		}
		break;

	case MT_ISDAT:
		if (strncmp("HP ", un->un_dp->vid, 3) == 0) {
			wrt = st_is_hp_dat_worm(un);
		} else {
			wrt = st_is_t10_worm(un);
		}
		break;

	default:
		wrt = FAILED;
		break;
	}

	/*
	 * If any of the above failed try the t10 standard method.
	 */
	if (wrt == FAILED) {
		wrt = st_is_t10_worm(un);
	}

	/*
	 * Unknown method for detecting WORM media.
	 */
	if (wrt == FAILED) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Unknown method for WORM media detection\n");
		wrt = RDWR;
		un->un_dp->options &= ~ST_WORMABLE;
	}

	return (wrt);
}

static int
st_read_attributes(struct scsi_tape *un, uint16_t attribute, void *pnt,
    size_t size, ubufunc_t bufunc)
{
	char cdb[CDB_GROUP4];
	int result;
	struct uscsi_cmd *cmd;
	struct scsi_arq_status status;

	caddr_t buf = (caddr_t)pnt;

	ST_FUNC(ST_DEVINFO, st_read_attributes);

	if (un->un_sd->sd_inq->inq_ansi < 3) {
		return (ENOTTY);
	}

	cmd = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);

	cdb[0] = (char)SCMD_READ_ATTRIBUTE;
	cdb[1] = 0;
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = 0;
	cdb[5] = 0;
	cdb[6] = 0;
	cdb[7] = 0;
	cdb[8] = (char)(attribute >> 8);
	cdb[9] = (char)(attribute);
	cdb[10] = (char)(size >> 24);
	cdb[11] = (char)(size >> 16);
	cdb[12] = (char)(size >> 8);
	cdb[13] = (char)(size);
	cdb[14] = 0;
	cdb[15] = 0;


	cmd->uscsi_flags = USCSI_READ | USCSI_RQENABLE | USCSI_DIAGNOSE;
	cmd->uscsi_timeout = un->un_dp->non_motion_timeout;
	cmd->uscsi_cdb = &cdb[0];
	cmd->uscsi_bufaddr = (caddr_t)buf;
	cmd->uscsi_buflen = size;
	cmd->uscsi_cdblen = sizeof (cdb);
	cmd->uscsi_rqlen = sizeof (status);
	cmd->uscsi_rqbuf = (caddr_t)&status;

	result = bufunc(un, cmd, FKIOCTL);

	if (result != 0 || cmd->uscsi_status != 0) {
		ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_read_attribute failed: result %d status %d\n",
		    result, cmd->uscsi_status);
		/*
		 * If this returns invalid operation code don't try again.
		 */
		if (un->un_sd->sd_sense->es_key == KEY_ILLEGAL_REQUEST &&
		    un->un_sd->sd_sense->es_add_code == 0x20) {
			result = ENOTTY;
		} else if (result == 0) {
			result = EIO;
		}

	} else {

		/*
		 * The attribute retured should match the attribute requested.
		 */
		if (buf[4] != cdb[8] || buf[5] != cdb[9]) {
			scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_read_attribute got wrong data back expected "
			    "0x%x got 0x%x\n", attribute, buf[6] << 8 | buf[7]);
			st_clean_print(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "bad? data", buf, size);
			result = EIO;
		}
	}

	kmem_free(cmd, sizeof (struct uscsi_cmd));

	return (result);
}

static int
st_get_special_inquiry(struct scsi_tape *un, uchar_t size, caddr_t dest,
    uchar_t page)
{
	char cdb[CDB_GROUP0];
	struct scsi_extended_sense *sense;
	struct uscsi_cmd *cmd;
	int result;

	ST_FUNC(ST_DEVINFO, st_get_special_inquiry);

	cdb[0] = SCMD_INQUIRY;
	cdb[1] = page ? 1 : 0;
	cdb[2] = page;
	cdb[3] = 0;
	cdb[4] = size;
	cdb[5] = 0;

	cmd = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);
	sense = kmem_alloc(sizeof (struct scsi_extended_sense), KM_SLEEP);

	cmd->uscsi_flags = USCSI_READ | USCSI_RQENABLE;
	cmd->uscsi_timeout = un->un_dp->non_motion_timeout;
	cmd->uscsi_cdb = &cdb[0];
	cmd->uscsi_bufaddr = dest;
	cmd->uscsi_buflen = size;
	cmd->uscsi_cdblen = CDB_GROUP0;
	cmd->uscsi_rqlen = sizeof (struct scsi_extended_sense);
	cmd->uscsi_rqbuf = (caddr_t)sense;

	result = st_uscsi_cmd(un, cmd, FKIOCTL);

	if (result != 0 || cmd->uscsi_status != 0) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_special_inquiry() failed for page %x", page);
		if (result == 0) {
			result = EIO;
		}
	}

	kmem_free(sense, sizeof (struct scsi_extended_sense));
	kmem_free(cmd, sizeof (struct uscsi_cmd));

	return (result);
}


static int
st_update_block_pos(struct scsi_tape *un, bufunc_t bf, int post_space)
{
	int rval = ENOTTY;
	uchar_t status = un->un_status;
	posmode previous_pmode = un->un_running.pmode;

	ST_FUNC(ST_DEVINFO, st_update_block_pos);

	while (un->un_read_pos_type != NO_POS) {
		rval = bf(un, SCMD_READ_POSITION, 32, SYNC_CMD);

		/*
		 * If read position command returned good status
		 * Parse the data to see if the position can be interpreted.
		 */
		if ((rval == 0) &&
		    ((rval = st_interpret_read_pos(un, &un->un_pos,
		    un->un_read_pos_type, 32, (caddr_t)un->un_read_pos_data,
		    post_space)) == 0)) {
			/*
			 * Update the running position as well if un_pos was
			 * ok. But only if recovery is enabled.
			 */
			if (st_recov_sz != sizeof (recov_info)) {
				break;
			}
			rval = st_interpret_read_pos(un, &un->un_running,
			    un->un_read_pos_type, 32,
			    (caddr_t)un->un_read_pos_data, post_space);
			un->un_status = status;
			break;
		} else if (un->un_status == KEY_UNIT_ATTENTION) {
			un->un_running.pmode = previous_pmode;
			continue;
		} else if (un->un_status != KEY_ILLEGAL_REQUEST) {
			scsi_log(ST_DEVINFO, st_label, CE_NOTE,
			    "st_update_block_pos() read position cmd 0x%x"
			    " returned 0x%x un_status = %d",
			    un->un_read_pos_type, rval, un->un_status);
			/* ENOTTY means it read garbage. try something else. */
			if (rval == ENOTTY) {
				rval = EIO; /* so ENOTTY is not final rval */
			} else {
				break;
			}
		} else {
			ST_DEBUG4(ST_DEVINFO, st_label, CE_NOTE,
			    "st_update_block_pos() read position cmd %x"
			    " returned %x", un->un_read_pos_type, rval);
			un->un_running.pmode = previous_pmode;
		}

		switch (un->un_read_pos_type) {
		case SHORT_POS:
			un->un_read_pos_type = NO_POS;
			break;

		case LONG_POS:
			un->un_read_pos_type = EXT_POS;
			break;

		case EXT_POS:
			un->un_read_pos_type = SHORT_POS;
			break;

		default:
			ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
			    "Unexpected read position type 0x%x",
			    un->un_read_pos_type);
		}
		un->un_status = KEY_NO_SENSE;
	}

	return (rval);
}

static int
st_get_read_pos(struct scsi_tape *un, buf_t *bp)
{
	int result;
	size_t d_sz;
	caddr_t pos_info;
	struct uscsi_cmd *cmd = (struct uscsi_cmd *)bp->b_back;

	ST_FUNC(ST_DEVINFO, st_get_read_pos);

	if (cmd->uscsi_bufaddr == NULL || cmd->uscsi_buflen <= 0) {
		return (0);
	}

	if (bp_mapin_common(bp, VM_NOSLEEP) == NULL) {

		scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "bp_mapin_common() failed");

		return (EIO);
	}

	d_sz = bp->b_bcount - bp->b_resid;
	if (d_sz == 0) {
		bp_mapout(bp);
		return (EIO);
	}

	/*
	 * Copy the buf to a double-word aligned memory that can hold the
	 * tape_position_t data structure.
	 */
	if ((pos_info = kmem_alloc(d_sz, KM_NOSLEEP)) == NULL) {
		scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "kmem_alloc() failed");
		bp_mapout(bp);
		return (EIO);
	}
	bcopy(bp->b_un.b_addr, pos_info, d_sz);

#ifdef STDEBUG
	if ((st_debug & 0x7) > 2) {
		st_clean_print(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_get_read_pos() position info",
		    pos_info, bp->b_bcount);
	}
#endif

	result = st_interpret_read_pos(un, &un->un_pos, cmd->uscsi_cdb[1],
	    d_sz, pos_info, 0);

	COPY_POS(&un->un_running, &un->un_pos);

	kmem_free(pos_info, d_sz);
	bp_mapout(bp);

	return (result);
}

#if defined(_BIG_ENDIAN)

#define	FIX_ENDIAN16(x)
#define	FIX_ENDIAN32(x)
#define	FIX_ENDIAN64(x)

#elif defined(_LITTLE_ENDIAN)

static void
st_swap16(uint16_t *val)
{
	uint16_t tmp;

	tmp = (*val >>  8) & 0xff;
	tmp |= (*val <<  8) & 0xff00;

	*val = tmp;
}

static void
st_swap32(uint32_t *val)
{
	uint32_t tmp;

	tmp =  (*val >> 24) & 0xff;
	tmp |= (*val >>  8) & 0xff00;
	tmp |= (*val <<  8) & 0xff0000;
	tmp |= (*val << 24) & 0xff000000;

	*val = tmp;
}

static void
st_swap64(uint64_t *val)
{
	uint32_t low;
	uint32_t high;

	low =  (uint32_t)(*val);
	high = (uint32_t)(*val >> 32);

	st_swap32(&low);
	st_swap32(&high);

	*val =  high;
	*val |= ((uint64_t)low << 32);
}

#define	FIX_ENDIAN16(x) st_swap16(x)
#define	FIX_ENDIAN32(x) st_swap32(x)
#define	FIX_ENDIAN64(x) st_swap64(x)
#endif

/*
 * st_interpret_read_pos()
 *
 * Returns:
 *	0	If secsessful.
 *	EIO	If read postion responce data was unuseable or invalid.
 *	ERANGE	If the position of the drive is too large for the read_p_type.
 *	ENOTTY	If the responce data looks invalid for the read position type.
 */

static int
st_interpret_read_pos(struct scsi_tape const *un, tapepos_t *dest,
    read_p_types type, size_t data_sz, const caddr_t responce, int post_space)
{
	int rval = 0;
	int flag = 0;
	tapepos_t org;

	ST_FUNC(ST_DEVINFO, st_interpret_read_pos);

	/*
	 * We expect the position value to change after a space command.
	 * So if post_space is set we don't print out what has changed.
	 */
	if ((dest != &un->un_pos) && (post_space == 0) &&
	    (st_recov_sz == sizeof (recov_info))) {
		COPY_POS(&org, dest);
		flag = 1;
	}

	/*
	 * See what kind of read position was requested.
	 */
	switch (type) {

	case SHORT_POS: /* Short data format */
	{
		tape_position_t *pos_info = (tape_position_t *)responce;
		uint32_t value;

		/* If reserved fields are non zero don't use the data */
		if (pos_info->reserved0 || pos_info->reserved1 ||
		    pos_info->reserved2[0] || pos_info->reserved2[1] ||
		    pos_info->reserved3) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Invalid Read Short Position Data returned\n");
			rval = EIO;
			break;
		}
		/*
		 * Position is to large to use this type of read position.
		 */
		if (pos_info->posi_err == 1) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Drive reported position error\n");
			rval = ERANGE;
			break;
		}
		/*
		 * If your at the begining of partition and end at the same
		 * time it's very small partition or bad data.
		 */
		if (pos_info->begin_of_part && pos_info->end_of_part) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "SHORT_POS returned begin and end of"
			    " partition\n");
			rval = EIO;
			break;
		}

		if (pos_info->blk_posi_unkwn == 0) {

			value = pos_info->host_block;
			FIX_ENDIAN32(&value);

			/*
			 * If the tape is rewound the host blcok should be 0.
			 */
			if ((pos_info->begin_of_part == 1) &&
			    (value != 0)) {
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "SHORT_POS returned begin of partition"
				    " but host block was 0x%x\n", value);
				rval = EIO;
				break;
			}

			if (dest->lgclblkno != value) {
				if (flag)
					flag++;
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "SHORT_POS current logical 0x%"PRIx64" read"
				    " 0x%x\n", dest->lgclblkno, value);
			}

			dest->lgclblkno = (uint64_t)value;

			/*
			 * If the begining of partition is true and the
			 * block number is zero we will beleive that it is
			 * rewound. Promote the pmode to legacy.
			 */
			if ((pos_info->begin_of_part == 1) &&
			    (value == 0)) {
				dest->blkno = 0;
				dest->fileno = 0;
				if (dest->pmode != legacy)
					dest->pmode = legacy;
			/*
			 * otherwise if the pmode was invalid,
			 * promote it to logical.
			 */
			} else if (dest->pmode == invalid) {
				dest->pmode = logical;
			}

			if (dest->partition != pos_info->partition_number) {
				if (flag)
					flag++;
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "SHORT_POS current partition %d read %d\n",
				    dest->partition,
				    pos_info->partition_number);
			}

			dest->partition = pos_info->partition_number;

		} else {
			dest->pmode = invalid;
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Tape drive reported block position as unknown\n");
		}
		break;
	}

	case LONG_POS: /* Long data format */
	{
		uint64_t value;
		tape_position_long_t *long_pos_info =
		    (tape_position_long_t *)responce;

		/* If reserved fields are non zero don't use the data */
		if ((long_pos_info->reserved0) ||
		    (long_pos_info->reserved1) ||
		    (long_pos_info->reserved2)) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Invalid Read Long Position Data returned\n");
			rval = ENOTTY;
			break;
		}

		/* Is position Valid */
		if (long_pos_info->blk_posi_unkwn == 0) {
			uint32_t part;

			value = long_pos_info->block_number;
			FIX_ENDIAN64(&value);

			/*
			 * If it says we are at the begining of partition
			 * the block value better be 0.
			 */
			if ((long_pos_info->begin_of_part == 1) &&
			    (value != 0)) {
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "LONG_POS returned begin of partition but"
				    " block number was 0x%"PRIx64"\n", value);
				rval = ENOTTY;
				break;
			}
			/*
			 * Can't be at the start and the end of the partition
			 * at the same time if the partition is larger the 0.
			 */
			if (long_pos_info->begin_of_part &&
			    long_pos_info->end_of_part) {
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "LONG_POS returned begin and end of"
				    " partition\n");
				rval = ENOTTY;
				break;
			}

			/*
			 * If the logical block number is not what we expected.
			 */
			if (dest->lgclblkno != value) {
				if (flag)
					flag++;
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "LONG_POS current logical 0x%"PRIx64
				    " read 0x%"PRIx64"\n",
				    dest->lgclblkno, value);
			}
			dest->lgclblkno = value;

			/*
			 * If the begining of partition is true and the
			 * block number is zero we will beleive that it is
			 * rewound. Promote the pmode to legacy.
			 */
			if ((long_pos_info->begin_of_part == 1) &&
			    (long_pos_info->block_number == 0)) {
				dest->blkno = 0;
				dest->fileno = 0;
				if (dest->pmode != legacy)
					dest->pmode = legacy;
			/*
			 * otherwise if the pmode was invalid,
			 * promote it to logical.
			 */
			} else if (dest->pmode == invalid) {
				dest->pmode = logical;
			}

			part = long_pos_info->partition;
			FIX_ENDIAN32(&part);
			if (dest->partition != part) {
				if (flag)
					flag++;
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "LONG_POS current partition %d"
				    " read %d\n", dest->partition, part);
			}
			dest->partition = part;
		} else {
			/*
			 * If the drive doesn't know location,
			 * we don't either.
			 */
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Tape drive reported block position as unknown\n");
			dest->pmode = invalid;
		}

		/* Is file position valid */
		if (long_pos_info->mrk_posi_unkwn == 0) {
			value = long_pos_info->file_number;
			FIX_ENDIAN64(&value);
			/*
			 * If it says we are at the begining of partition
			 * the block value better be 0.
			 */
			if ((long_pos_info->begin_of_part == 1) &&
			    (value != 0)) {
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "LONG_POS returned begin of partition but"
				    " block number was 0x%"PRIx64"\n", value);
				rval = ENOTTY;
				break;
			}
			if (((dest->pmode == legacy) ||
			    (dest->pmode == logical)) &&
			    (dest->fileno != value)) {
				if (flag)
					flag++;
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "LONG_POS fileno 0x%"PRIx64
				    " not un_pos %x\n", value,
				    dest->fileno);
			} else if (dest->pmode == invalid) {
				dest->pmode = logical;
			}
			dest->fileno = (int32_t)value;
		}

		if (dest->pmode != invalid && long_pos_info->end_of_part) {
			dest->eof = ST_EOT;
		}

		break;
	}

	case EXT_POS: /* Extended data format */
	{
		uint64_t value;
		uint16_t len;
		tape_position_ext_t *ext_pos_info =
		    (tape_position_ext_t *)responce;

		/* Make sure that there is enough data there */
		if (data_sz < 16) {
			break;
		}

		/* If reserved fields are non zero don't use the data */
		if (ext_pos_info->reserved0 || ext_pos_info->reserved1) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "EXT_POS reserved fields not zero\n");
			rval = ENOTTY;
			break;
		}

		/*
		 * In the unlikely event of overflowing 64 bits of position.
		 */
		if (ext_pos_info->posi_err != 0) {
			rval = ERANGE;
			break;
		}

		len = ext_pos_info->parameter_len;
		FIX_ENDIAN16(&len);

		if (len != 0x1c) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "EXT_POS parameter_len should be 0x1c was 0x%x\n",
			    len);
			rval = ENOTTY;
			break;
		}

		/* Is block position information valid */
		if (ext_pos_info->blk_posi_unkwn == 0) {

			value = ext_pos_info->host_block;
			FIX_ENDIAN64(&value);
			if ((ext_pos_info->begin_of_part == 1) &&
			    (value != 0)) {
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "EXT_POS returned begining of partition but"
				    " the host block was 0x%"PRIx64"\n", value);
				rval = ENOTTY;
				break;
			}

			if (dest->lgclblkno != value) {
				if (flag)
					flag++;
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "EXT_POS current logical 0x%"PRIx64
				    " read 0x%"PRIx64"\n",
				    dest->lgclblkno, value);
			}
			dest->lgclblkno = value;

			/*
			 * If the begining of partition is true and the
			 * block number is zero we will beleive that it is
			 * rewound. Promote the pmode to legacy.
			 */
			if ((ext_pos_info->begin_of_part == 1) &&
			    (ext_pos_info->host_block == 0)) {
				dest->blkno = 0;
				dest->fileno = 0;
				if (dest->pmode != legacy) {
					dest->pmode = legacy;
				}
			/*
			 * otherwise if the pmode was invalid,
			 * promote it to logical.
			 */
			} else if (dest->pmode == invalid) {
				dest->pmode = logical;
			}

			if (dest->partition != ext_pos_info->partition) {
				if (flag)
					flag++;
				ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "EXT_POS current partition %d read %d\n",
				    dest->partition,
				    ext_pos_info->partition);
			}
			dest->partition = ext_pos_info->partition;

		} else {
			dest->pmode = invalid;
		}
		break;
	}

	default:
		ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
		    "Got unexpected SCMD_READ_POSITION type %d\n", type);
		rval = EIO;
	}

	if ((flag > 1) && (rval == 0) && (org.pmode != invalid)) {
		st_print_position(ST_DEVINFO, st_label, CE_NOTE,
		    "position read in", &org);
		st_print_position(ST_DEVINFO, st_label, CE_NOTE,
		    "position read out", dest);
	}

	return (rval);
}

static int
st_logical_block_locate(struct scsi_tape *un, ubufunc_t ubf, tapepos_t *pos,
    uint64_t lblk, uchar_t partition)
{
	int rval;
	char cdb[CDB_GROUP4];
	struct uscsi_cmd *cmd;
	struct scsi_extended_sense sense;
	bufunc_t bf = (ubf == st_uscsi_cmd) ? st_cmd : st_rcmd;

	ST_FUNC(ST_DEVINFO, st_logical_block_locate);
	/*
	 * Not sure what to do when doing recovery and not wanting
	 * to update un_pos
	 */

	cmd = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);

	if (lblk <= INT32_MAX) {
		cmd->uscsi_cdblen = CDB_GROUP1;
		cdb[0] = SCMD_LOCATE;
		cdb[1] = pos->partition == partition ? 0 : 2;
		cdb[2] = 0;
		cdb[3] = (char)(lblk >> 24);
		cdb[4] = (char)(lblk >> 16);
		cdb[5] = (char)(lblk >> 8);
		cdb[6] = (char)(lblk);
		cdb[7] = 0;
		cdb[8] = partition;
		cdb[9] = 0;
	} else {
		/*
		 * If the drive doesn't give a 64 bit read position data
		 * it is unlikely it will accept 64 bit locates.
		 */
		if (un->un_read_pos_type != LONG_POS) {
			kmem_free(cmd, sizeof (struct uscsi_cmd));
			return (ERANGE);
		}
		cmd->uscsi_cdblen = CDB_GROUP4;
		cdb[0] = (char)SCMD_LOCATE_G4;
		cdb[1] = pos->partition == partition ? 0 : 2;
		cdb[2] = 0;
		cdb[3] = partition;
		cdb[4] = (char)(lblk >> 56);
		cdb[5] = (char)(lblk >> 48);
		cdb[6] = (char)(lblk >> 40);
		cdb[7] = (char)(lblk >> 32);
		cdb[8] = (char)(lblk >> 24);
		cdb[9] = (char)(lblk >> 16);
		cdb[10] = (char)(lblk >> 8);
		cdb[11] = (char)(lblk);
		cdb[12] = 0;
		cdb[13] = 0;
		cdb[14] = 0;
		cdb[15] = 0;
	}


	cmd->uscsi_flags = USCSI_WRITE | USCSI_DIAGNOSE | USCSI_RQENABLE;
	cmd->uscsi_rqbuf = (caddr_t)&sense;
	cmd->uscsi_rqlen = sizeof (sense);
	cmd->uscsi_timeout = un->un_dp->space_timeout;
	cmd->uscsi_cdb = cdb;

	rval = ubf(un, cmd, FKIOCTL);

	pos->pmode = logical;
	pos->eof = ST_NO_EOF;

	if (lblk > INT32_MAX) {
		/*
		 * XXX This is a work around till we handle Descriptor format
		 * sense data. Since we are sending a command where the standard
		 * sense data can not correctly represent a correct residual in
		 * 4 bytes.
		 */
		if (un->un_status == KEY_ILLEGAL_REQUEST) {
			scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Big LOCATE ILLEGAL_REQUEST: rval = %d\n", rval);
			/* Doesn't like big locate command */
			un->un_status = 0;
			rval = ERANGE;
		} else if ((un->un_pos.pmode == invalid) || (rval != 0)) {
			/* Aborted big locate command */
			scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Big LOCATE resulted in invalid pos: rval = %d\n",
			    rval);
			un->un_status = 0;
			rval = EIO;
		} else if (st_update_block_pos(un, bf, 1)) {
			/* read position failed */
			scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Big LOCATE and read pos: rval = %d\n", rval);
			rval = EIO;
		} else if (lblk > un->un_pos.lgclblkno) {
			/* read position worked but position was not expected */
			scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Big LOCATE and recover read less then desired 0x%"
			    PRIx64"\n", un->un_pos.lgclblkno);
			un->un_err_resid = lblk - un->un_pos.lgclblkno;
			un->un_status = KEY_BLANK_CHECK;
			rval = ESPIPE;
		} else if (lblk == un->un_pos.lgclblkno) {
			/* read position was what was expected */
			scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "Big LOCATE and recover seems to have worked\n");
			un->un_err_resid = 0;
			rval = 0;
		} else {
			ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
			    "BIGLOCATE end up going backwards");
			un->un_err_resid = lblk;
			rval = EIO;
		}

	} else if (rval == 0) {
		/* Worked as requested */
		pos->lgclblkno = lblk;

	} else if (((cmd->uscsi_status & ST_STATUS_MASK) == STATUS_CHECK) &&
	    (cmd->uscsi_resid != 0)) {
		/* Got part way there but wasn't enough blocks on tape */
		pos->lgclblkno = lblk - cmd->uscsi_resid;
		un->un_err_resid = cmd->uscsi_resid;
		un->un_status = KEY_BLANK_CHECK;
		rval = ESPIPE;

	} else if (st_update_block_pos(un, bf, 1) == 0) {
		/* Got part way there but drive didn't tell what we missed by */
		un->un_err_resid = lblk - pos->lgclblkno;
		un->un_status = KEY_BLANK_CHECK;
		rval = ESPIPE;

	} else {
		scsi_log(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Failed LOCATE and recover pos: rval = %d status = %d\n",
		    rval, cmd->uscsi_status);
		un->un_err_resid = lblk;
		un->un_status = KEY_ILLEGAL_REQUEST;
		pos->pmode = invalid;
		rval = EIO;
	}

	kmem_free(cmd, sizeof (struct uscsi_cmd));

	return (rval);
}

static int
st_mtfsf_ioctl(struct scsi_tape *un, int64_t files)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_mtfsf_ioctl);


	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_mtfsf_ioctl: count=%"PRIx64", eof=%x\n", files, un->un_pos.eof);
#if 0
	if ((IN_EOF(un->un_pos)) && (files == 1)) {
		un->un_pos.fileno++;
		un->un_pos.blkno = 0;
		return (0);
	}
#endif
	/* pmode == invalid already handled */
	if (un->un_pos.pmode == legacy) {
		/*
		 * forward space over filemark
		 *
		 * For ASF we allow a count of 0 on fsf which means
		 * we just want to go to beginning of current file.
		 * Equivalent to "nbsf(0)" or "bsf(1) + fsf".
		 * Allow stepping over double fmk with reel
		 */
		if ((un->un_pos.eof >= ST_EOT) &&
		    (files > 0) &&
		    ((un->un_dp->options & ST_REEL) == 0)) {
			/* we're at EOM */
			un->un_err_resid = files;
			un->un_status = KEY_BLANK_CHECK;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_mtfsf_ioctl: EIO : MTFSF at EOM");
			return (EIO);
		}

		/*
		 * physical tape position may not be what we've been
		 * telling the user; adjust the request accordingly
		 */
		if (IN_EOF(un->un_pos)) {
			un->un_pos.fileno++;
			un->un_pos.blkno = 0;
			/*
			 * For positive direction case, we're now covered.
			 * For zero or negative direction, we're covered
			 * (almost)
			 */
			files--;
		}

	}

	if (st_check_density_or_wfm(un->un_dev, 1, B_READ, STEPBACK)) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_mtfsf_ioctl: EIO : MTFSF density/wfm failed");
		return (EIO);
	}


	/*
	 * Forward space file marks.
	 * We leave ourselves at block zero
	 * of the target file number.
	 */
	if (files < 0) {
		rval = st_backward_space_files(un, -files, 0);
	} else {
		rval = st_forward_space_files(un, files);
	}

	return (rval);
}

static int
st_forward_space_files(struct scsi_tape *un, int64_t count)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_forward_space_files);

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "fspace: count=%"PRIx64", eof=%x\n", count, un->un_pos.eof);

	ASSERT(count >= 0);
	ASSERT(un->un_pos.pmode != invalid);

	/*
	 * A space with a count of zero means take me to the start of file.
	 */
	if (count == 0) {

		/* Hay look were already there */
		if (un->un_pos.pmode == legacy && un->un_pos.blkno == 0) {
			un->un_err_resid = 0;
			COPY_POS(&un->un_err_pos, &un->un_pos);
			return (0);
		}

		/*
		 * Well we are in the first file.
		 * A rewind will get to the start.
		 */
		if (un->un_pos.pmode == legacy && un->un_pos.fileno == 0) {
			rval = st_cmd(un, SCMD_REWIND, 0, SYNC_CMD);

		/*
		 * Can we backspace to get there?
		 * This should work in logical mode.
		 */
		} else if (un->un_dp->options & ST_BSF) {
			rval = st_space_to_begining_of_file(un);

		/*
		 * Can't back space but current file number is known,
		 * So rewind and space from the begining of the partition.
		 */
		} else if (un->un_pos.pmode == legacy) {
			rval = st_scenic_route_to_begining_of_file(un,
			    un->un_pos.fileno);

		/*
		 * pmode is logical and ST_BSF is not set.
		 * The LONG_POS read position contains the fileno.
		 * If the read position works, rewind and space.
		 */
		} else if (un->un_read_pos_type == LONG_POS) {
			rval = st_cmd(un, SCMD_READ_POSITION, 0, SYNC_CMD);
			if (rval) {
				/*
				 * We didn't get the file position from the
				 * read position command.
				 * We are going to trust the drive to backspace
				 * and then position after the filemark.
				 */
				rval = st_space_to_begining_of_file(un);
			}
			rval = st_interpret_read_pos(un, &un->un_pos, LONG_POS,
			    32, (caddr_t)un->un_read_pos_data, 0);
			if ((rval) && (un->un_pos.pmode == invalid)) {
				rval = st_space_to_begining_of_file(un);
			} else {
				rval = st_scenic_route_to_begining_of_file(un,
				    un->un_pos.fileno);
			}
		} else {
			rval = EIO;
		}
		/*
		 * If something didn't work we are lost
		 */
		if (rval != 0) {
			un->un_pos.pmode = invalid;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_mtioctop : EIO : fspace pmode invalid");

			rval = EIO;
		}

	} else {
		rval = st_space_fmks(un, count);
	}

	if (rval != EIO && count < 0) {
		/*
		 * we came here with a count < 0; we now need
		 * to skip back to end up before the filemark
		 */
		rval = st_backward_space_files(un, 1, 1);
	}

	return (rval);
}

static int
st_scenic_route_to_begining_of_file(struct scsi_tape *un, int32_t fileno)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_scenic_route_to_begining_of_file);

	if (st_cmd(un, SCMD_REWIND, 0, SYNC_CMD)) {
		rval = EIO;
	} else if (st_cmd(un, SCMD_SPACE, Fmk(fileno), SYNC_CMD)) {
		rval = EIO;
	}

	return (rval);
}

static int
st_space_to_begining_of_file(struct scsi_tape *un)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_space_to_begining_of_file);

	/*
	 * Back space of the file at the begining of the file.
	 */
	rval = st_cmd(un, SCMD_SPACE, Fmk(-1), SYNC_CMD);
	if (rval) {
		rval = EIO;
		return (rval);
	}

	/*
	 * Other interesting answers might be crashed BOT which isn't bad.
	 */
	if (un->un_status == SUN_KEY_BOT) {
		return (rval);
	}

	un->un_running.pmode = invalid;

	/*
	 * Now we are on the BOP side of the filemark. Forward space to
	 * the EOM side and we are at the begining of the file.
	 */
	rval = st_cmd(un, SCMD_SPACE, Fmk(1), SYNC_CMD);
	if (rval) {
		rval = EIO;
	}

	return (rval);
}

static int
st_mtfsr_ioctl(struct scsi_tape *un, int64_t count)
{

	ST_FUNC(ST_DEVINFO, st_mtfsr_ioctl);

	/*
	 * forward space to inter-record gap
	 *
	 */

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_ioctl_fsr: count=%"PRIx64", eof=%x\n", count, un->un_pos.eof);

	if (un->un_pos.pmode == legacy) {
		/*
		 * If were are at end of tape and count is forward.
		 * Return blank check.
		 */
		if ((un->un_pos.eof >= ST_EOT) && (count > 0)) {
			/* we're at EOM */
			un->un_err_resid = count;
			un->un_status = KEY_BLANK_CHECK;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_mtfsr_ioctl: EIO : MTFSR eof > ST_EOT");
			return (EIO);
		}

		/*
		 * If count is zero there is nothing to do.
		 */
		if (count == 0) {
			un->un_err_pos.fileno = un->un_pos.fileno;
			un->un_err_pos.blkno = un->un_pos.blkno;
			un->un_err_resid = 0;
			if (IN_EOF(un->un_pos) && SVR4_BEHAVIOR) {
				un->un_status = SUN_KEY_EOF;
			}
			return (0);
		}

		/*
		 * physical tape position may not be what we've been
		 * telling the user; adjust the position accordingly
		 */
		if (IN_EOF(un->un_pos)) {
			daddr_t blkno = un->un_pos.blkno;
			int fileno = un->un_pos.fileno;

			optype lastop = un->un_lastop;
			if (st_cmd(un, SCMD_SPACE, Fmk(-1), SYNC_CMD)
			    == -1) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_mtfsr_ioctl:EIO:MTFSR count && IN_EOF");
				return (EIO);
			}

			un->un_pos.blkno = blkno;
			un->un_pos.fileno = fileno;
			un->un_lastop = lastop;
		}
	}

	if (st_check_density_or_wfm(un->un_dev, 1, B_READ, STEPBACK)) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_mtfsr_ioctl: EIO : MTFSR st_check_den");
		return (EIO);
	}

	return (st_space_records(un, count));
}

static int
st_space_records(struct scsi_tape *un, int64_t count)
{
	int64_t dblk;
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_space_records);

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_space_records: count=%"PRIx64", eof=%x\n",
	    count, un->un_pos.eof);

	if (un->un_pos.pmode == logical) {
		rval = st_cmd(un, SCMD_SPACE, Blk(count), SYNC_CMD);
		if (rval != 0) {
			rval = EIO;
		}
		return (rval);
	}

	dblk = count + un->un_pos.blkno;

	/* Already there */
	if (dblk == un->un_pos.blkno) {
		un->un_err_resid = 0;
		COPY_POS(&un->un_err_pos, &un->un_pos);
		return (0);
	}

	/*
	 * If the destination block is forward
	 * or the drive will backspace records.
	 */
	if (un->un_pos.blkno < dblk || (un->un_dp->options & ST_BSR)) {
		/*
		 * If we're spacing forward, or the device can
		 * backspace records, we can just use the SPACE
		 * command.
		 */
		dblk -= un->un_pos.blkno;
		if (st_cmd(un, SCMD_SPACE, Blk(dblk), SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_space_records:EIO:space_records can't spc");
			rval = EIO;
		} else if (un->un_pos.eof >= ST_EOF_PENDING) {
			/*
			 * check if we hit BOT/EOT
			 */
			if (dblk < 0 && un->un_pos.eof == ST_EOM) {
				un->un_status = SUN_KEY_BOT;
				un->un_pos.eof = ST_NO_EOF;
			} else if (dblk < 0 &&
			    un->un_pos.eof == ST_EOF_PENDING) {
				int residue = un->un_err_resid;
				/*
				 * we skipped over a filemark
				 * and need to go forward again
				 */
				if (st_cmd(un, SCMD_SPACE, Fmk(1), SYNC_CMD)) {
					ST_DEBUG2(ST_DEVINFO, st_label,
					    SCSI_DEBUG, "st_space_records: EIO"
					    " : can't space #2");
					rval = EIO;
				}
				un->un_err_resid = residue;
			}
			if (rval == 0) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_space_records: EIO : space_rec rval"
				    " == 0");
				rval = EIO;
			}
		}
	} else {
		/*
		 * else we rewind, space forward across filemarks to
		 * the desired file, and then space records to the
		 * desired block.
		 */

		int dfile = un->un_pos.fileno;	/* save current file */

		if (dblk < 0) {
			/*
			 * Wups - we're backing up over a filemark
			 */
			if (un->un_pos.blkno != 0 &&
			    (st_cmd(un, SCMD_REWIND, 0, SYNC_CMD) ||
			    st_cmd(un, SCMD_SPACE, Fmk(dfile), SYNC_CMD))) {
				un->un_pos.pmode = invalid;
			}
			un->un_err_resid = -dblk;
			if (un->un_pos.fileno == 0 && un->un_pos.blkno == 0) {
				un->un_status = SUN_KEY_BOT;
				un->un_pos.eof = ST_NO_EOF;
			} else if (un->un_pos.fileno > 0) {
				un->un_status = SUN_KEY_EOF;
				un->un_pos.eof = ST_NO_EOF;
			}
			COPY_POS(&un->un_err_pos, &un->un_pos);
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_space_records:EIO:space_records : dblk < 0");
			rval = EIO;
		} else if (st_cmd(un, SCMD_REWIND, 0, SYNC_CMD) ||
		    st_cmd(un, SCMD_SPACE, Fmk(dfile), SYNC_CMD) ||
		    st_cmd(un, SCMD_SPACE, Blk(dblk), SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_space_records: EIO :space_records : rewind "
			    "and space failed");
			un->un_pos.pmode = invalid;
			rval = EIO;
		}
	}

	return (rval);
}

static int
st_mtbsf_ioctl(struct scsi_tape *un, int64_t files)
{
	ST_FUNC(ST_DEVINFO, st_mtbsf_ioctl);

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_mtbsf_ioctl: count=%"PRIx64", eof=%x\n", files, un->un_pos.eof);
	/*
	 * backward space of file filemark (1/2" and 8mm)
	 * tape position will end on the beginning of tape side
	 * of the desired file mark
	 */
	if ((un->un_dp->options & ST_BSF) == 0) {
		return (ENOTTY);
	}

	if (un->un_pos.pmode == legacy) {

		/*
		 * If a negative count (which implies a forward space op)
		 * is specified, and we're at logical or physical eot,
		 * bounce the request.
		 */

		if (un->un_pos.eof >= ST_EOT && files < 0) {
			un->un_err_resid = files;
			un->un_status = SUN_KEY_EOT;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl_mt_bsf : EIO : MTBSF : eof > ST_EOF");
			return (EIO);
		}
		/*
		 * physical tape position may not be what we've been
		 * telling the user; adjust the request accordingly
		 */
		if (IN_EOF(un->un_pos)) {
			un->un_pos.fileno++;
			un->un_pos.blkno = 0;
			files++;
			ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_mtbsf_ioctl in eof: count=%"PRIx64", op=%x\n",
			    files, MTBSF);

		}
	}

	if (st_check_density_or_wfm(un->un_dev, 1, 0, STEPBACK)) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl : EIO : MTBSF : check den wfm");
		return (EIO);
	}

	if (files <= 0) {
		/*
		 * for a negative count, we need to step forward
		 * first and then step back again
		 */
		files = -files + 1;
		return (st_forward_space_files(un, files));
	}
	return (st_backward_space_files(un, files, 1));
}

static int
st_backward_space_files(struct scsi_tape *un, int64_t count, int infront)
{
	int64_t end_fileno;
	int64_t skip_cnt;
	int rval = 0;

	ST_FUNC(ST_DEVINFO, st_backward_space_files);

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_backward_space_files: count=%"PRIx64" eof=%x\n",
	    count, un->un_pos.eof);
	/*
	 * Backspace files (MTNBSF): infront == 0
	 *
	 *	For tapes that can backspace, backspace
	 *	count+1 filemarks and then run forward over
	 *	a filemark
	 *
	 *	For tapes that can't backspace,
	 *		calculate desired filenumber
	 *		(un->un_pos.fileno - count), rewind,
	 *		and then space forward this amount
	 *
	 * Backspace filemarks (MTBSF) infront == 1
	 *
	 *	For tapes that can backspace, backspace count
	 *	filemarks
	 *
	 *	For tapes that can't backspace, calculate
	 *	desired filenumber (un->un_pos.fileno - count),
	 *	add 1, rewind, space forward this amount,
	 *	and mark state as ST_EOF_PENDING appropriately.
	 */

	if (un->un_pos.pmode == logical) {

		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_backward_space_files: mt_op=%x count=%"PRIx64
		    "lgclblkno=%"PRIx64"\n", infront?MTBSF:MTNBSF, count,
		    un->un_pos.lgclblkno);


		/* In case a drive that won't back space gets in logical mode */
		if ((un->un_dp->options & ST_BSF) == 0) {
			rval = EIO;
			return (rval);
		}
		if ((infront == 1) &&
		    (st_cmd(un, SCMD_SPACE, Fmk(-count), SYNC_CMD))) {
			rval = EIO;
			return (rval);
		} else if ((infront == 0) &&
		    (st_cmd(un, SCMD_SPACE, Fmk((-count)-1), SYNC_CMD)) &&
		    (st_cmd(un, SCMD_SPACE, Fmk(1), SYNC_CMD))) {
			rval = EIO;
			return (rval);
		}
		return (rval);
	}

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_backward_space_files: mt_op=%x count=%"PRIx64
	    "fileno=%x blkno=%x\n",
	    infront?MTBSF:MTNBSF, count, un->un_pos.fileno, un->un_pos.blkno);



	/*
	 * Handle the simple case of BOT
	 * playing a role in these cmds.
	 * We do this by calculating the
	 * ending file number. If the ending
	 * file is < BOT, rewind and set an
	 * error and mark resid appropriately.
	 * If we're backspacing a file (not a
	 * filemark) and the target file is
	 * the first file on the tape, just
	 * rewind.
	 */

	/* figure expected destination of this SPACE command */
	end_fileno = un->un_pos.fileno - count;

	/*
	 * Would the end effect of this SPACE be the same as rewinding?
	 * If so just rewind instead.
	 */
	if ((infront != 0) && (end_fileno < 0) ||
	    (infront == 0) && (end_fileno <= 0)) {
		if (st_cmd(un, SCMD_REWIND, 0, SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_backward_space_files: EIO : "
			    "rewind in lou of BSF failed\n");
			rval = EIO;
		}
		if (end_fileno < 0) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_backward_space_files: EIO : "
			    "back space file greater then fileno\n");
			rval = EIO;
			un->un_err_resid = -end_fileno;
			un->un_status = SUN_KEY_BOT;
		}
		return (rval);
	}

	if (un->un_dp->options & ST_BSF) {
		skip_cnt = 1 - infront;
		/*
		 * If we are going to end up at the beginning
		 * of the file, we have to space one extra file
		 * first, and then space forward later.
		 */
		end_fileno = -(count + skip_cnt);
		ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "skip_cnt=%"PRIx64", tmp=%"PRIx64"\n",
		    skip_cnt, end_fileno);
		if (st_cmd(un, SCMD_SPACE, Fmk(end_fileno), SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_backward_space_files:EIO:back space fm failed");
			rval = EIO;
		}
	} else {
		if (st_cmd(un, SCMD_REWIND, 0, SYNC_CMD)) {
			rval = EIO;
		} else {
			skip_cnt = end_fileno + infront;
		}
	}

	/*
	 * If we have to space forward, do so...
	 */
	ST_DEBUG6(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "space forward skip_cnt=%"PRIx64", rval=%x\n", skip_cnt, rval);

	if (rval == 0 && skip_cnt) {
		if (st_cmd(un, SCMD_SPACE, Fmk(skip_cnt), SYNC_CMD)) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_backward_space_files:EIO:space fm skip count");
			rval = EIO;
		} else if (infront) {
			/*
			 * If we had to space forward, and we're
			 * not a tape that can backspace, mark state
			 * as if we'd just seen a filemark during a
			 * a read.
			 */
			if ((un->un_dp->options & ST_BSF) == 0) {
				un->un_pos.eof = ST_EOF_PENDING;
				un->un_pos.fileno -= 1;
				un->un_pos.blkno = LASTBLK;
				un->un_running.pmode = invalid;
			}
		}
	}

	if (rval != 0) {
		un->un_pos.pmode = invalid;
	}

	return (rval);
}

static int
st_mtnbsf_ioctl(struct scsi_tape *un, int64_t count)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_mtnbsf_ioctl);

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "nbsf: count=%"PRIx64", eof=%x\n", count, un->un_pos.eof);

	if (un->un_pos.pmode == legacy) {
		/*
		 * backward space file to beginning of file
		 *
		 * If a negative count (which implies a forward space op)
		 * is specified, and we're at logical or physical eot,
		 * bounce the request.
		 */

		if (un->un_pos.eof >= ST_EOT && count < 0) {
			un->un_err_resid = count;
			un->un_status = SUN_KEY_EOT;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl : EIO : > EOT and count < 0");
			return (EIO);
		}
		/*
		 * physical tape position may not be what we've been
		 * telling the user; adjust the request accordingly
		 */
		if (IN_EOF(un->un_pos)) {
			un->un_pos.fileno++;
			un->un_pos.blkno = 0;
			count++;
		}
	}

	if (st_check_density_or_wfm(un->un_dev, 1, 0, STEPBACK)) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl : EIO : MTNBSF check den and wfm");
		return (EIO);
	}

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "mtnbsf: count=%"PRIx64", eof=%x\n", count, un->un_pos.eof);

	if (count <= 0) {
		rval = st_forward_space_files(un, -count);
	} else {
		rval = st_backward_space_files(un, count, 0);
	}
	return (rval);
}

static int
st_mtbsr_ioctl(struct scsi_tape *un, int64_t num)
{
	ST_FUNC(ST_DEVINFO, st_mtbsr_ioctl);

	ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "bsr: count=%"PRIx64", eof=%x\n", num, un->un_pos.eof);

	if (un->un_pos.pmode == legacy) {
		/*
		 * backward space into inter-record gap
		 *
		 * If a negative count (which implies a forward space op)
		 * is specified, and we're at logical or physical eot,
		 * bounce the request.
		 */
		if (un->un_pos.eof >= ST_EOT && num < 0) {
			un->un_err_resid = num;
			un->un_status = SUN_KEY_EOT;
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "st_ioctl : EIO : MTBSR > EOT");
			return (EIO);
		}

		if (num == 0) {
			COPY_POS(&un->un_err_pos, &un->un_pos);
			un->un_err_resid = 0;
			if (IN_EOF(un->un_pos) && SVR4_BEHAVIOR) {
				un->un_status = SUN_KEY_EOF;
			}
			return (0);
		}

		/*
		 * physical tape position may not be what we've been
		 * telling the user; adjust the position accordingly.
		 * bsr can not skip filemarks and continue to skip records
		 * therefore if we are logically before the filemark but
		 * physically at the EOT side of the filemark, we need to step
		 * back; this allows fsr N where N > number of blocks in file
		 * followed by bsr 1 to position at the beginning of last block
		 */
		if (IN_EOF(un->un_pos)) {
			tapepos_t save;
			optype lastop = un->un_lastop;

			COPY_POS(&save, &un->un_pos);
			if (st_cmd(un, SCMD_SPACE, Fmk(-1), SYNC_CMD) == -1) {
				ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
				    "st_mtbsr_ioctl: EIO : MTBSR can't space");
				return (EIO);
			}

			COPY_POS(&un->un_pos, &save);
			un->un_lastop = lastop;
		}
	}

	un->un_pos.eof = ST_NO_EOF;

	if (st_check_density_or_wfm(un->un_dev, 1, 0, STEPBACK)) {
		ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "st_ioctl : EIO : MTBSR : can't set density or wfm");
		return (EIO);
	}

	num = -num;
	return (st_space_records(un, num));
}

static int
st_mtfsfm_ioctl(struct scsi_tape *un, int64_t cnt)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_mtfsfm_ioctl);

	rval = st_cmd(un, SCMD_SPACE, SPACE(SP_SQFLM, cnt), SYNC_CMD);
	if (rval == 0) {
		un->un_pos.pmode = logical;
	} else if ((un->un_status == KEY_ILLEGAL_REQUEST) &&
	    (un->un_sd->sd_sense->es_add_code == 0x24)) {
		/*
		 * Drive says invalid field in cdb.
		 * Doesn't like space multiple. Position isn't lost.
		 */
		un->un_err_resid = cnt;
		un->un_status = 0;
		rval = ENOTTY;
	} else {
		un->un_err_resid = cnt;
		un->un_pos.pmode = invalid;
	}
	return (rval);
}

static int
st_mtbsfm_ioctl(struct scsi_tape *un, int64_t cnt)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_mtbsfm_ioctl);

	rval = st_cmd(un, SCMD_SPACE, SPACE(SP_SQFLM, -cnt), SYNC_CMD);
	if (rval == 0) {
		un->un_pos.pmode = logical;
	} else if ((un->un_status == KEY_ILLEGAL_REQUEST) &&
	    (un->un_sd->sd_sense->es_add_code == 0x24)) {
		/*
		 * Drive says invalid field in cdb.
		 * Doesn't like space multiple. Position isn't lost.
		 */
		un->un_err_resid = cnt;
		un->un_status = 0;
		rval = ENOTTY;
	} else {
		un->un_err_resid = cnt;
		un->un_pos.pmode = invalid;
	}
	return (rval);
}

#ifdef	__x86

/*
 * release contig_mem and wake up waiting thread, if any
 */
static void
st_release_contig_mem(struct scsi_tape *un, struct contig_mem *cp)
{
	mutex_enter(ST_MUTEX);

	ST_FUNC(ST_DEVINFO, st_release_contig_mem);

	cp->cm_next = un->un_contig_mem;
	un->un_contig_mem = cp;
	un->un_contig_mem_available_num++;
	cv_broadcast(&un->un_contig_mem_cv);

	mutex_exit(ST_MUTEX);
}

/*
 * St_get_contig_mem will return a contig_mem if there is one available
 * in current system. Otherwise, it will try to alloc one, if the total
 * number of contig_mem is within st_max_contig_mem_num.
 * It will sleep, if allowed by caller or return NULL, if no contig_mem
 * is available for now.
 */
static struct contig_mem *
st_get_contig_mem(struct scsi_tape *un, size_t len, int alloc_flags)
{
	size_t rlen;
	struct contig_mem *cp = NULL;
	ddi_acc_handle_t acc_hdl;
	caddr_t addr;
	int big_enough = 0;
	int (*dma_alloc_cb)() = (alloc_flags == KM_SLEEP) ?
	    DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	/* Try to get one available contig_mem */
	mutex_enter(ST_MUTEX);

	ST_FUNC(ST_DEVINFO, st_get_contig_mem);

	if (un->un_contig_mem_available_num > 0) {
		ST_GET_CONTIG_MEM_HEAD(un, cp, len, big_enough);
	} else if (un->un_contig_mem_total_num < st_max_contig_mem_num) {
		/*
		 * we failed to get one. we're going to
		 * alloc one more contig_mem for this I/O
		 */
		mutex_exit(ST_MUTEX);
		cp = (struct contig_mem *)kmem_zalloc(
		    sizeof (struct contig_mem) + biosize(),
		    alloc_flags);
		if (cp == NULL) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "alloc contig_mem failure\n");
			return (NULL); /* cannot get one */
		}
		cp->cm_bp = (struct buf *)
		    (((caddr_t)cp) + sizeof (struct contig_mem));
		bioinit(cp->cm_bp);
		mutex_enter(ST_MUTEX);
		un->un_contig_mem_total_num++; /* one more available */
	} else {
		/*
		 * we failed to get one and we're NOT allowed to
		 * alloc more contig_mem
		 */
		if (alloc_flags == KM_SLEEP) {
			while (un->un_contig_mem_available_num <= 0) {
				cv_wait(&un->un_contig_mem_cv, ST_MUTEX);
			}
			ST_GET_CONTIG_MEM_HEAD(un, cp, len, big_enough);
		} else {
			mutex_exit(ST_MUTEX);
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "alloc contig_mem failure\n");
			return (NULL); /* cannot get one */
		}
	}
	mutex_exit(ST_MUTEX);

	/* We need to check if this block of mem is big enough for this I/O */
	if (cp->cm_len < len) {
		/* not big enough, need to alloc a new one */
		if (ddi_dma_mem_alloc(un->un_contig_mem_hdl, len, &st_acc_attr,
		    DDI_DMA_STREAMING, dma_alloc_cb, NULL,
		    &addr, &rlen, &acc_hdl) != DDI_SUCCESS) {
			ST_DEBUG2(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "alloc contig_mem failure: not enough mem\n");
			st_release_contig_mem(un, cp);
			cp = NULL;
		} else {
			if (cp->cm_addr) {
				/* release previous one before attach new one */
				ddi_dma_mem_free(&cp->cm_acc_hdl);
			}
			mutex_enter(ST_MUTEX);
			un->un_max_contig_mem_len =
			    un->un_max_contig_mem_len >= len ?
			    un->un_max_contig_mem_len : len;
			mutex_exit(ST_MUTEX);

			/* attach new mem to this cp */
			cp->cm_addr = addr;
			cp->cm_acc_hdl = acc_hdl;
			cp->cm_len = len;

			goto alloc_ok; /* get one usable cp */
		}
	} else {
		goto alloc_ok; /* get one usable cp */
	}

	/* cannot find/alloc a usable cp, when we get here */

	mutex_enter(ST_MUTEX);
	if ((un->un_max_contig_mem_len < len) ||
	    (alloc_flags != KM_SLEEP)) {
		mutex_exit(ST_MUTEX);
		return (NULL);
	}

	/*
	 * we're allowed to sleep, and there is one big enough
	 * contig mem in the system, which is currently in use,
	 * wait for it...
	 */
	big_enough = 1;
	do {
		cv_wait(&un->un_contig_mem_cv, ST_MUTEX);
		ST_GET_CONTIG_MEM_HEAD(un, cp, len, big_enough);
	} while (cp == NULL);
	mutex_exit(ST_MUTEX);

	/* we get the big enough contig mem, finally */

alloc_ok:
	/* init bp attached to this cp */
	bioreset(cp->cm_bp);
	cp->cm_bp->b_un.b_addr = cp->cm_addr;
	cp->cm_bp->b_private = (void *)cp;

	return (cp);
}

/*
 * this is the biodone func for the bp used in big block I/O
 */
static int
st_bigblk_xfer_done(struct buf *bp)
{
	struct contig_mem *cp;
	struct buf *orig_bp;
	int ioerr;
	struct scsi_tape *un;

	/* sanity check */
	if (bp == NULL) {
		return (DDI_FAILURE);
	}

	un = ddi_get_soft_state(st_state, MTUNIT(bp->b_edev));
	if (un == NULL) {
		return (DDI_FAILURE);
	}

	ST_FUNC(ST_DEVINFO, st_bigblk_xfer_done);

	cp = (struct contig_mem *)bp->b_private;
	orig_bp = cp->cm_bp; /* get back the bp we have replaced */
	cp->cm_bp = bp;

	/* special handling for special I/O */
	if (cp->cm_use_sbuf) {
#ifndef __lock_lint
		ASSERT(un->un_sbuf_busy);
#endif
		un->un_sbufp = orig_bp;
		cp->cm_use_sbuf = 0;
	}

	orig_bp->b_resid = bp->b_resid;
	ioerr = geterror(bp);
	if (ioerr != 0) {
		bioerror(orig_bp, ioerr);
	} else if (orig_bp->b_flags & B_READ) {
		/* copy data back to original bp */
		(void) bp_copyout(bp->b_un.b_addr, orig_bp, 0,
		    bp->b_bcount - bp->b_resid);
	}

	st_release_contig_mem(un, cp);

	biodone(orig_bp);

	return (DDI_SUCCESS);
}

/*
 * We use this func to replace original bp that may not be able to do I/O
 * in big block size with one that can
 */
static struct buf *
st_get_bigblk_bp(struct buf *bp)
{
	struct contig_mem *cp;
	struct scsi_tape *un;
	struct buf *cont_bp;

	un = ddi_get_soft_state(st_state, MTUNIT(bp->b_edev));
	if (un == NULL) {
		return (bp);
	}

	ST_FUNC(ST_DEVINFO, st_get_bigblk_bp);

	/* try to get one contig_mem */
	cp = st_get_contig_mem(un, bp->b_bcount, KM_SLEEP);
	if (!cp) {
		scsi_log(ST_DEVINFO, st_label, CE_WARN,
		    "Cannot alloc contig buf for I/O for %lu blk size",
		    bp->b_bcount);
		return (bp);
	}
	cont_bp = cp->cm_bp;
	cp->cm_bp = bp;

	/* make sure that we "are" using un_sbufp for special I/O */
	if (bp == un->un_sbufp) {
#ifndef __lock_lint
		ASSERT(un->un_sbuf_busy);
#endif
		un->un_sbufp = cont_bp;
		cp->cm_use_sbuf = 1;
	}

	/* clone bp */
	cont_bp->b_bcount = bp->b_bcount;
	cont_bp->b_resid = bp->b_resid;
	cont_bp->b_iodone = st_bigblk_xfer_done;
	cont_bp->b_file = bp->b_file;
	cont_bp->b_offset = bp->b_offset;
	cont_bp->b_dip = bp->b_dip;
	cont_bp->b_error = 0;
	cont_bp->b_proc = NULL;
	cont_bp->b_flags = bp->b_flags & ~(B_PAGEIO | B_PHYS | B_SHADOW);
	cont_bp->b_shadow = NULL;
	cont_bp->b_pages = NULL;
	cont_bp->b_edev = bp->b_edev;
	cont_bp->b_dev = bp->b_dev;
	cont_bp->b_lblkno = bp->b_lblkno;
	cont_bp->b_forw = bp->b_forw;
	cont_bp->b_back = bp->b_back;
	cont_bp->av_forw = bp->av_forw;
	cont_bp->av_back = bp->av_back;
	cont_bp->b_bufsize = bp->b_bufsize;

	/* get data in original bp */
	if (bp->b_flags & B_WRITE) {
		(void) bp_copyin(bp, cont_bp->b_un.b_addr, 0, bp->b_bcount);
	}

	return (cont_bp);
}
#else
#ifdef __lock_lint
static int
st_bigblk_xfer_done(struct buf *bp)
{
	return (0);
}
#endif
#endif

static const char *eof_status[] =
{
	"NO_EOF",
	"EOF_PENDING",
	"EOF",
	"EOT_PENDING",
	"EOT",
	"EOM",
	"AFTER_EOM"
};
static const char *mode[] = {
	"invalid",
	"legacy",
	"logical"
};

static void
st_print_position(dev_info_t *dev, char *label, uint_t level,
const char *comment, tapepos_t *pos)
{
	ST_FUNC(dev, st_print_position);

	scsi_log(dev, label, level,
	    "%s Position data:\n", comment);
	scsi_log(dev, label, CE_CONT,
	    "Positioning mode = %s", mode[pos->pmode]);
	scsi_log(dev, label, CE_CONT,
	    "End Of File/Tape = %s", eof_status[pos->eof]);
	scsi_log(dev, label, CE_CONT,
	    "File Number      = 0x%x", pos->fileno);
	scsi_log(dev, label, CE_CONT,
	    "Block Number     = 0x%x", pos->blkno);
	scsi_log(dev, label, CE_CONT,
	    "Logical Block    = 0x%"PRIx64, pos->lgclblkno);
	scsi_log(dev, label, CE_CONT,
	    "Partition Number = 0x%x", pos->partition);
}
static int
st_check_if_media_changed(struct scsi_tape *un, caddr_t data, int size)
{

	int result = 0;
	int i;
	ST_FUNC(ST_DEVINFO, st_check_if_media_changed);

	/*
	 * find non alpha numeric working from the end.
	 */
	for (i = size - 1; i >= 0; i--) {
		if (ISALNUM(data[i]) == 0 || data[i] == ' ') {
			data[i] = 0;
			size = i;
		}
	}

	if (size == 1) {
		/*
		 * Drive seems to think its returning useful data
		 * but it looks like all junk
		 */
		return (result);
	}

	size++;

	/*
	 * Actually got a valid serial number.
	 * If never stored one before alloc space for it.
	 */
	if (un->un_media_id_len == 0) {
		un->un_media_id = kmem_zalloc(size, KM_SLEEP);
		un->un_media_id_len = size;
		(void) strncpy(un->un_media_id, data, min(size, strlen(data)));
		un->un_media_id[min(size, strlen(data))] = 0;
		ST_DEBUG1(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Found Media Id %s length = %d\n", un->un_media_id, size);
	} else if (size > un->un_media_id_len) {
		if (strncmp(un->un_media_id, data, size) != 0) {
			result = ESPIPE;
		}
		ST_DEBUG1(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Longer Media Id old ID:%s new ID:%s\n",
		    un->un_media_id, data);
		kmem_free(un->un_media_id, un->un_media_id_len);
		un->un_media_id = kmem_zalloc(size, KM_SLEEP);
		un->un_media_id_len = size;
		(void) strncpy(un->un_media_id, data, size);
		un->un_media_id[size] = 0;
	} else if (strncmp(data, un->un_media_id,
	    min(size, un->un_media_id_len)) != 0) {
		ST_DEBUG1(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Old Media Id %s length = %d New %s length = %d\n",
		    un->un_media_id, un->un_media_id_len, data, size);
		bzero(un->un_media_id, un->un_media_id_len);
		(void) strncpy(un->un_media_id, data, min(size, strlen(data)));
		un->un_media_id[min(size, strlen(data))] = 0;
		result = ESPIPE;
	} else {
		ST_DEBUG4(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "Media Id still %s\n", un->un_media_id);
	}

	ASSERT(strlen(un->un_media_id) <= size);

	return (result);
}
#define	ID_SIZE 32
typedef struct
{
	uchar_t avilable_data0;
	uchar_t avilable_data1;
	uchar_t avilable_data2;
	uchar_t avilable_data3;
	uchar_t attribute_msb;
	uchar_t attribute_lsb;
#ifdef _BIT_FIELDS_LTOH
	uchar_t format		: 2,
				: 5,
		read_only	: 1;
#else
	uchar_t read_only	: 1,
				: 5,
		format		: 2;
#endif
	uchar_t attribute_len_msb;
	uchar_t attribute_len_lsb;
}attribute_header;

typedef struct {
	attribute_header header;
	char data[1];
}mam_attribute;

static int
st_handle_hex_media_id(struct scsi_tape *un, void *pnt, int size)
{
	int result;
	int newsize = (size << 1) + 3; /* extra for leading 0x and null term */
	int i;
	uchar_t byte;
	char *format;
	uchar_t *data = (uchar_t *)pnt;
	char *buf = kmem_alloc(newsize, KM_SLEEP);

	ST_FUNC(ST_DEVINFO, st_handle_hex_media_id);

	(void) sprintf(buf, "0x");
	for (i = 0; i < size; i++) {
		byte = data[i];
		if (byte < 0x10)
			format = "0%x";
		else
			format = "%x";
		(void) sprintf(&buf[(int)strlen(buf)], format, byte);
	}
	result = st_check_if_media_changed(un, buf, newsize);

	kmem_free(buf, newsize);

	return (result);
}


static int
st_get_media_id_via_read_attribute(struct scsi_tape *un, ubufunc_t bufunc)
{
	int result;
	mam_attribute *buffer;
	int size;
	int newsize;

	ST_FUNC(ST_DEVINFO, st_get_media_id_via_read_attribute);
	size = sizeof (attribute_header) + max(un->un_media_id_len, ID_SIZE);
again:
	buffer = kmem_zalloc(size, KM_SLEEP);
	result = st_read_attributes(un, 0x0401, buffer, size, bufunc);
	if (result == 0) {

		newsize = (buffer->header.attribute_len_msb << 8) |
		    buffer->header.attribute_len_lsb;

		if (newsize + sizeof (attribute_header) > size) {
			ST_DEBUG(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "resizing read attribute data from %d to %d format"
			    " %d\n", size, (int)sizeof (attribute_header) +
			    newsize, buffer->header.format);
			kmem_free(buffer, size);
			size = newsize + sizeof (attribute_header);
			goto again;
		}

		un->un_media_id_method = st_get_media_id_via_read_attribute;
		if (buffer->header.format == 0) {
			result =
			    st_handle_hex_media_id(un, buffer->data, newsize);
		} else {
			result = st_check_if_media_changed(un, buffer->data,
			    newsize);
		}
	} else if (result == EINVAL && un->un_max_cdb_sz < CDB_GROUP4) {
		scsi_log(ST_DEVINFO, st_label, CE_NOTE,
		    "Read Attribute Command for Media Identification is not "
		    "supported on the HBA that this drive is attached to.");
		result = ENOTTY;
	}

	kmem_free(buffer, size);
	un->un_status = 0;

	return (result);
}


static int
st_get_media_id_via_media_serial_cmd(struct scsi_tape *un, ubufunc_t bufunc)
{
	char cdb[CDB_GROUP5];
	struct uscsi_cmd *ucmd;
	struct scsi_extended_sense sense;
	int rval;
	int size = max(un->un_media_id_len, ID_SIZE);
	caddr_t buf;

	ST_FUNC(ST_DEVINFO, st_get_media_id_via_media_serial_cmd);

	if (un->un_sd->sd_inq->inq_ansi < 3) {
		return (ENOTTY);
	}

	ucmd = kmem_zalloc(sizeof (struct uscsi_cmd), KM_SLEEP);
upsize:
	buf = kmem_alloc(size, KM_SLEEP);

	cdb[0] = (char)SCMD_SVC_ACTION_IN_G5;
	cdb[1] = SSVC_ACTION_READ_MEDIA_SERIAL;
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = 0;
	cdb[5] = 0;
	cdb[6] = (char)(size >> 24);
	cdb[7] = (char)(size >> 16);
	cdb[8] = (char)(size >> 8);
	cdb[9] = (char)(size);
	cdb[10] = 0;
	cdb[11] = 0;

	ucmd->uscsi_flags = USCSI_READ | USCSI_RQENABLE;
	ucmd->uscsi_timeout = un->un_dp->non_motion_timeout;
	ucmd->uscsi_cdb = &cdb[0];
	ucmd->uscsi_cdblen = sizeof (cdb);
	ucmd->uscsi_bufaddr = buf;
	ucmd->uscsi_buflen = size;
	ucmd->uscsi_rqbuf = (caddr_t)&sense;
	ucmd->uscsi_rqlen = sizeof (sense);

	rval = bufunc(un, ucmd, FKIOCTL);

	if (rval || ucmd->uscsi_status != 0) {
		ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
		    "media serial command returned %d scsi_status %d"
		    " rqstatus %d", rval, ucmd->uscsi_status,
		    ucmd->uscsi_rqstatus);
		/*
		 * If this returns invalid operation code don't try again.
		 */
		if (sense.es_key == KEY_ILLEGAL_REQUEST &&
		    sense.es_add_code == 0x20) {
			rval = ENOTTY;
		} else if (rval == 0) {
			rval = EIO;
		}
		un->un_status = 0;
	} else {
		int act_size;

		/*
		 * get reported size.
		 */
		act_size = (int)buf[3] | (int)(buf[2] << 8) |
		    (int)(buf[1] << 16) | (int)(buf[0] << 24);

		/* documentation says mod 4. */
		while (act_size & 3) {
			act_size++;
		}

		/*
		 * If reported size is larger that we our buffer.
		 * Free the old one and allocate one that is larger
		 * enough and re-issuse the command.
		 */
		if (act_size + 4 > size) {
			kmem_free(buf, size);
			size = act_size + 4;
			goto upsize;
		}

		if (act_size == 0) {
			ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
			    "media serial number is not available");
			un->un_status = 0;
			rval = 0;
		} else {
			/*
			 * set data pointer to point to the start
			 * of that serial number.
			 */
			un->un_media_id_method =
			    st_get_media_id_via_media_serial_cmd;
			rval =
			    st_check_if_media_changed(un, &buf[4], act_size);
		}
	}

	kmem_free(ucmd, sizeof (struct uscsi_cmd));
	kmem_free(buf, size);

	return (rval);
}


/* ARGSUSED */
static int
st_bogus_media_id(struct scsi_tape *un, ubufunc_t bufunc)
{
	ST_FUNC(ST_DEVINFO, st_bogus_media_id);

	ASSERT(un->un_media_id == NULL || un->un_media_id == bogusID);
	ASSERT(un->un_media_id_len == 0);
	un->un_media_id = (char *)bogusID;
	un->un_media_id_len = 0;
	return (0);
}

typedef int (*media_chk_function)(struct scsi_tape *, ubufunc_t bufunc);

media_chk_function media_chk_functions[] = {
	st_get_media_id_via_media_serial_cmd,
	st_get_media_id_via_read_attribute,
	st_bogus_media_id
};

static int
st_get_media_identification(struct scsi_tape *un, ubufunc_t bufunc)
{
	int result = 0;
	int i;

	ST_FUNC(ST_DEVINFO, st_get_media_identification);

	for (i = 0; i < ST_NUM_MEMBERS(media_chk_functions); i++) {
		if (result == ENOTTY) {
			/*
			 * Last operation type not supported by this device.
			 * Make so next time it doesn`t do that again.
			 */
			un->un_media_id_method = media_chk_functions[i];
		} else if (un->un_media_id_method != media_chk_functions[i] &&
		    un->un_media_id_method != st_get_media_identification) {
			continue;
		}
		result = media_chk_functions[i](un, bufunc);
		/*
		 * If result indicates the function was successful or
		 * that the media is not the same as last known, break.
		 */
		if (result == 0 || result == ESPIPE) {
			break;
		}
	}

	return (result);
}

static errstate
st_command_recovery(struct scsi_tape *un, struct scsi_pkt *pkt,
    errstate onentry)
{

	int ret;
	st_err_info *errinfo;
	recov_info *ri = (recov_info *)pkt->pkt_private;

	ST_FUNC(ST_DEVINFO, st_command_recovery);

	ASSERT(MUTEX_HELD(&un->un_sd->sd_mutex));

	ASSERT(un->un_recov_buf_busy == 0);

	/*
	 * Don't try and recover a reset that this device sent.
	 */
	if (un->un_rsvd_status & ST_INITIATED_RESET &&
	    onentry == DEVICE_RESET) {
		return (COMMAND_DONE_ERROR);
	}

	/*
	 * See if expected position was passed with scsi_pkt.
	 */
	if (ri->privatelen == sizeof (recov_info)) {

		/*
		 * Not for this command.
		 */
		if (ri->cmd_attrib->do_not_recover) {
			return (COMMAND_DONE_ERROR);
		}

		/*
		 * Create structure to hold all error state info.
		 */
		errinfo = kmem_zalloc(ST_ERR_INFO_SIZE, KM_SLEEP);
		errinfo->ei_error_type = onentry;
		errinfo->ei_failing_bp = ri->cmd_bp;
		COPY_POS(&errinfo->ei_expected_pos, &ri->pos);
	} else {
		/* disabled */
		return (COMMAND_DONE_ERROR);
	}

	bcopy(pkt, &errinfo->ei_failed_pkt, scsi_pkt_size());
	bcopy(pkt->pkt_scbp, &errinfo->ei_failing_status, SECMDS_STATUS_SIZE);
	ret = ddi_taskq_dispatch(un->un_recov_taskq, st_recover, errinfo,
	    DDI_NOSLEEP);
	ASSERT(ret == DDI_SUCCESS);
	if (ret != DDI_SUCCESS) {
		kmem_free(errinfo, ST_ERR_INFO_SIZE);
		return (COMMAND_DONE_ERROR);
	}
	return (JUST_RETURN); /* release calling thread */
}


static void
st_recov_ret(struct scsi_tape *un, st_err_info *errinfo, errstate err)
{
	int error_number;
	buf_t *bp;


	ST_FUNC(ST_DEVINFO, st_recov_ret);

	ASSERT(MUTEX_HELD(&un->un_sd->sd_mutex));
#if !defined(lint)
	_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&un->un_sd->sd_mutex))
#endif

	bp = errinfo->ei_failing_bp;
	kmem_free(errinfo, ST_ERR_INFO_SIZE);

	switch (err) {
	case JUST_RETURN:
		mutex_exit(&un->un_sd->sd_mutex);
		return;

	case COMMAND_DONE:
	case COMMAND_DONE_ERROR_RECOVERED:
		ST_DO_KSTATS(bp, kstat_runq_exit);
		error_number = 0;
		break;

	default:
		ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
		    "st_recov_ret with unhandled errstat %d\n", err);
		/* FALLTHROUGH */
	case COMMAND_DONE_ERROR:
		un->un_pos.pmode = invalid;
		un->un_running.pmode = invalid;
		/* FALLTHROUGH */
	case COMMAND_DONE_EACCES:
		ST_DO_KSTATS(bp, kstat_waitq_exit);
		ST_DO_ERRSTATS(un, st_transerrs);
		error_number = EIO;
		st_set_pe_flag(un);
		break;

	}

	st_bioerror(bp, error_number);
	st_done_and_mutex_exit(un, bp);
}


static void
st_recover(void *arg)
{
	st_err_info *const errinfo = (st_err_info *)arg;
	uchar_t com = errinfo->ei_failed_pkt.pkt_cdbp[0];
	struct scsi_tape *un;
	tapepos_t cur_pos;
	int rval;
	errstate status = COMMAND_DONE_ERROR;
	recov_info *rcv;
	buf_t *bp;


	rcv = errinfo->ei_failed_pkt.pkt_private;
	ASSERT(rcv->privatelen == sizeof (recov_info));
	bp = rcv->cmd_bp;

	un = ddi_get_soft_state(st_state, MTUNIT(bp->b_edev));

	ASSERT(un != NULL);

	mutex_enter(ST_MUTEX);

	ST_FUNC(ST_DEVINFO, st_recover);

	ST_CDB(ST_DEVINFO, "Recovering command",
	    (caddr_t)errinfo->ei_failed_pkt.pkt_cdbp);
	ST_SENSE(ST_DEVINFO, "sense status for failed command",
	    (caddr_t)&errinfo->ei_failing_status,
	    sizeof (struct scsi_arq_status));
	ST_POS(ST_DEVINFO, rcv->cmd_attrib->recov_pos_type == POS_STARTING ?
	    "starting position for recovery command" :
	    "expected position for recovery command",
	    &errinfo->ei_expected_pos);

	rval = st_test_path_to_device(un);

	ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
	    "st_recover called with %s, TUR returned %d\n",
	    errstatenames[errinfo->ei_error_type], rval);
	/*
	 * If the drive responed to the TUR lets try and get it to sync
	 * any data it might have in the buffer.
	 */
	if (rval == 0 && rcv->cmd_attrib->chg_tape_data) {
		rval = st_rcmd(un, SCMD_WRITE_FILE_MARK, 0, SYNC_CMD);
		if (rval) {
			ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
			    "st_recover failed to flush, returned %d\n", rval);
			st_recov_ret(un, errinfo, COMMAND_DONE_ERROR);
			return;
		}
	}
	switch (errinfo->ei_error_type) {
	case ATTEMPT_RETRY:
	case COMMAND_TIMEOUT:
	case DEVICE_RESET:
	case PATH_FAILED:
		/*
		 * For now if we can't talk to the device we are done.
		 * If the drive is reserved we can try to get it back.
		 */
		if (rval != 0 && rval != EACCES) {
			st_recov_ret(un, errinfo, COMMAND_DONE_ERROR);
			return;
		}

		/*
		 * If reservation conflict and do a preempt, fail it.
		 */
		if ((un->un_rsvd_status &
		    (ST_APPLICATION_RESERVATIONS | ST_RESERVE)) != 0) {
			if ((errinfo->ei_failed_pkt.pkt_cdbp[0] ==
			    SCMD_PERSISTENT_RESERVE_OUT) &&
			    (errinfo->ei_failed_pkt.pkt_cdbp[1] ==
			    ST_SA_SCSI3_PREEMPT) &&
			    (SCBP_C(&errinfo->ei_failed_pkt) ==
			    STATUS_RESERVATION_CONFLICT)) {
				st_recov_ret(un, errinfo, COMMAND_DONE_ERROR);
				return;
			}
		}

		/*
		 * If we have already set a scsi II reserve and get a
		 * conflict on a scsi III type reserve fail without
		 * any attempt to recover.
		 */
		if ((un->un_rsvd_status & ST_RESERVE | ST_PRESERVE_RESERVE) &&
		    (errinfo->ei_failed_pkt.pkt_cdbp[0] ==
		    SCMD_PERSISTENT_RESERVE_OUT) ||
		    (errinfo->ei_failed_pkt.pkt_cdbp[0] ==
		    SCMD_PERSISTENT_RESERVE_IN)) {
			st_recov_ret(un, errinfo, COMMAND_DONE_EACCES);
			return;
		}

		/*
		 * If scsi II lost reserve try and get it back.
		 */
		if ((((un->un_rsvd_status &
		    (ST_LOST_RESERVE | ST_APPLICATION_RESERVATIONS)) ==
		    ST_LOST_RESERVE)) &&
		    (errinfo->ei_failed_pkt.pkt_cdbp[0] != SCMD_RELEASE)) {
			rval = st_reserve_release(un, ST_RESERVE,
			    st_uscsi_rcmd);
			if (rval != 0) {
				if (st_take_ownership(un, st_uscsi_rcmd) != 0) {
					st_recov_ret(un, errinfo,
					    COMMAND_DONE_EACCES);
					return;
				}
			}
			un->un_rsvd_status |= ST_RESERVE;
			un->un_rsvd_status &= ~(ST_RELEASE | ST_LOST_RESERVE |
			    ST_RESERVATION_CONFLICT | ST_INITIATED_RESET);
		}
		rval = st_make_sure_mode_data_is_correct(un, st_uscsi_rcmd);
		if (rval) {
			st_recov_ret(un, errinfo, COMMAND_DONE_ERROR);
			return;
		}
		break;
	case DEVICE_TAMPER:
		/*
		 * Check if the ASC/ASCQ says mode data has changed.
		 */
		if ((errinfo->ei_failing_status.sts_sensedata.es_add_code ==
		    0x2a) &&
		    (errinfo->ei_failing_status.sts_sensedata.es_qual_code ==
		    0x01)) {
			/*
			 * See if mode sense changed.
			 */
			rval = st_make_sure_mode_data_is_correct(un,
			    st_uscsi_rcmd);
			if (rval) {
				st_recov_ret(un, errinfo, COMMAND_DONE_ERROR);
				return;
			}
		}
		/*
		 * if we have a media id and its not bogus.
		 * Check to see if it the same.
		 */
		if (un->un_media_id != NULL && un->un_media_id != bogusID) {
			rval = st_get_media_identification(un, st_uscsi_rcmd);
			if (rval == ESPIPE) {
				st_recov_ret(un, errinfo, COMMAND_DONE_EACCES);
				return;
			}
		}
		break;
	default:
		ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
		    "Unhandled error type %s in st_recover() 0x%x\n",
		    errstatenames[errinfo->ei_error_type], com);
	}

	/*
	 * if command is retriable retry it.
	 * Special case here. The command attribute for SCMD_REQUEST_SENSE
	 * does not say that it is retriable. That because if you reissue a
	 * request sense and the target responds the sense data will have
	 * been consumed and no long be valid. If we get a busy status on
	 * request sense while the state is ST_STATE_SENSING this will
	 * reissue that pkt.
	 *
	 * XXX If this request sense gets sent to a different port then
	 * the original command that failed was sent on it will not get
	 * valid sense data for that command.
	 */
	if (rcv->cmd_attrib->retriable || un->un_rqs_bp == bp) {
		status = st_recover_reissue_pkt(un, &errinfo->ei_failed_pkt);

	/*
	 * if drive doesn't support read position we are done
	 */
	} else if (un->un_read_pos_type == NO_POS) {
		status = COMMAND_DONE_ERROR;
	/*
	 * If this command results in a changed tape position,
	 * lets see where we are.
	 */
	} else if (rcv->cmd_attrib->chg_tape_pos) {
		/*
		 * XXX May be a reason to choose a different type here.
		 * Long format has file position information.
		 * Short and Extended have information about whats
		 * in the buffer. St's positioning assumes in the buffer
		 * to be the same as on tape.
		 */
		rval = st_compare_expected_position(un, errinfo,
		    rcv->cmd_attrib, &cur_pos);
		if (rval == 0) {
			status = COMMAND_DONE;
		} else if (rval == EAGAIN) {
			status = st_recover_reissue_pkt(un,
			    &errinfo->ei_failed_pkt);
		} else {
			status = COMMAND_DONE_ERROR;
		}
	} else {
		ASSERT(0);
	}

	st_recov_ret(un, errinfo, status);
}

static void
st_recov_cb(struct scsi_pkt *pkt)
{
	struct scsi_tape *un;
	struct buf *bp;
	recov_info *rcv;
	errstate action = COMMAND_DONE_ERROR;
	int timout = ST_TRAN_BUSY_TIMEOUT; /* short (default) timeout */

	/*
	 * Get the buf from the packet.
	 */
	rcv = pkt->pkt_private;
	ASSERT(rcv->privatelen == sizeof (recov_info));
	bp = rcv->cmd_bp;

	/*
	 * get the unit from the buf.
	 */
	un = ddi_get_soft_state(st_state, MTUNIT(bp->b_edev));
	ASSERT(un != NULL);

	ST_FUNC(ST_DEVINFO, st_recov_cb);

	mutex_enter(ST_MUTEX);

	ASSERT(bp == un->un_recov_buf);


	switch (pkt->pkt_reason) {
	case CMD_CMPLT:
		if (un->un_arq_enabled && pkt->pkt_state & STATE_ARQ_DONE) {
			action = st_handle_autosense(un, bp, &rcv->pos);
		} else  if ((SCBP(pkt)->sts_busy) ||
		    (SCBP(pkt)->sts_chk) ||
		    (SCBP(pkt)->sts_vu7)) {
			action = st_check_error(un, pkt);
		} else {
			action = COMMAND_DONE;
		}
		break;
	case CMD_TIMEOUT:
		action = COMMAND_TIMEOUT;
		break;
	case CMD_TRAN_ERR:
		action = QUE_COMMAND;
		break;
	case CMD_DEV_GONE:
		if (un->un_multipath)
			action = PATH_FAILED;
		else
			action = COMMAND_DONE_ERROR;
		break;
	default:
		ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
		    "pkt_reason not handled yet %s",
		    scsi_rname(pkt->pkt_reason));
		action = COMMAND_DONE_ERROR;
	}

	/*
	 * check for undetected path failover.
	 */
	if (un->un_multipath) {
		if (scsi_pkt_allocated_correctly(pkt) &&
		    (un->un_last_path_instance != pkt->pkt_path_instance)) {
			if (un->un_state > ST_STATE_OPENING) {
				ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
				    "Failover detected in recovery, action is "
				    "%s\n", errstatenames[action]);
			}
			un->un_last_path_instance = pkt->pkt_path_instance;
		}
	}

	ST_RECOV(ST_DEVINFO, st_label, CE_WARN,
	    "Recovery call back got %s status on %s\n",
	    errstatenames[action], st_print_scsi_cmd(pkt->pkt_cdbp[0]));

	switch (action) {
	case COMMAND_DONE:
		break;

	case COMMAND_DONE_EACCES:
		bioerror(bp, EACCES);
		break;

	case COMMAND_DONE_ERROR_RECOVERED: /* XXX maybe wrong */
		ASSERT(0);
		break;

	case COMMAND_TIMEOUT:
	case COMMAND_DONE_ERROR:
		bioerror(bp, EIO);
		break;

	case DEVICE_RESET:
	case QUE_BUSY_COMMAND:
	case PATH_FAILED:
		/* longish timeout */
		timout = ST_STATUS_BUSY_TIMEOUT;
		/* FALLTHRU */
	case QUE_COMMAND:
	case DEVICE_TAMPER:
	case ATTEMPT_RETRY:
		/*
		 * let st_handle_intr_busy put this bp back on waitq and make
		 * checks to see if it is ok to requeue the command.
		 */
		ST_DO_KSTATS(bp, kstat_runq_back_to_waitq);

		/*
		 * Save the throttle before setting up the timeout
		 */
		if (un->un_throttle) {
			un->un_last_throttle = un->un_throttle;
		}
		mutex_exit(ST_MUTEX);
		if (st_handle_intr_busy(un, bp, timout) == 0) {
			return;		/* timeout is setup again */
		}
		mutex_enter(ST_MUTEX);
		un->un_pos.pmode = invalid;
		un->un_err_resid = bp->b_resid = bp->b_bcount;
		st_bioerror(bp, EIO);
		st_set_pe_flag(un);
		break;

	default:
		ST_DEBUG(ST_DEVINFO, st_label, CE_PANIC,
		    "Unhandled recovery state 0x%x\n", action);
		un->un_pos.pmode = invalid;
		un->un_err_resid = bp->b_resid = bp->b_bcount;
		st_bioerror(bp, EIO);
		st_set_pe_flag(un);
		break;
	}

	st_done_and_mutex_exit(un, bp);
}

static int
st_rcmd(struct scsi_tape *un, int com, int64_t count, int wait)
{
	struct buf *bp;
	int err;

	ST_FUNC(ST_DEVINFO, st_rcmd);

	ST_DEBUG3(ST_DEVINFO, st_label, SCSI_DEBUG,
	    "st_rcmd(un = 0x%p, com = 0x%x, count = %"PRIx64", wait = %d)\n",
	    (void *)un, com, count, wait);

	ASSERT(MUTEX_HELD(&un->un_sd->sd_mutex));
	ASSERT(mutex_owned(ST_MUTEX));

#ifdef STDEBUG
	if ((st_debug & 0x7)) {
		st_debug_cmds(un, com, count, wait);
	}
#endif

	while (un->un_recov_buf_busy)
		cv_wait(&un->un_recov_buf_cv, ST_MUTEX);
	un->un_recov_buf_busy = 1;

	bp = un->un_recov_buf;
	bzero(bp, sizeof (buf_t));

	bp->b_flags = (wait) ? B_BUSY : B_BUSY|B_ASYNC;

	err = st_setup_cmd(un, bp, com, count);

	un->un_recov_buf_busy = 0;

	cv_signal(&un->un_recov_buf_cv);

	return (err);
}

/* args used */
static int
st_uscsi_rcmd(struct scsi_tape *un, struct uscsi_cmd *ucmd, int flag)
{
	int rval;
	buf_t *bp;

	ST_FUNC(ST_DEVINFO, st_uscsi_rcmd);
	ASSERT(flag == FKIOCTL);

	/*
	 * Get buffer resources...
	 */
	while (un->un_recov_buf_busy)
		cv_wait(&un->un_recov_buf_cv, ST_MUTEX);
	un->un_recov_buf_busy = 1;

	bp = un->un_recov_buf;
	bzero(bp, sizeof (buf_t));

	bp->b_forw = (struct buf *)(uintptr_t)ucmd->uscsi_cdb[0];
	bp->b_back = (struct buf *)ucmd;

	mutex_exit(ST_MUTEX);
	rval = scsi_uscsi_handle_cmd(un->un_dev, UIO_SYSSPACE, ucmd,
	    st_strategy, bp, NULL);
	mutex_enter(ST_MUTEX);

	ucmd->uscsi_resid = bp->b_resid;

	/*
	 * Free resources
	 */
	un->un_recov_buf_busy = 0;
	cv_signal(&un->un_recov_buf_cv);

	return (rval);
}

/*
 * Add data to scsi_pkt to help know what to do if the command fails.
 */
static void
st_add_recovery_info_to_pkt(struct scsi_tape *un, buf_t *bp,
    struct scsi_pkt *pkt)
{
	uint64_t count;
	recov_info *rinfo = (recov_info *)pkt->pkt_private;

	ST_FUNC(ST_DEVINFO, st_add_recovery_info_to_pkt);

	ASSERT(rinfo->privatelen == sizeof (pkt_info) ||
	    rinfo->privatelen == sizeof (recov_info));

	SET_BP_PKT(bp, pkt);
	rinfo->cmd_bp = bp;

	if (rinfo->privatelen != sizeof (recov_info)) {
		return;
	}

	rinfo->cmd_bp = bp;

	rinfo->cmd_attrib = NULL;

	/*
	 * lookup the command attributes and add them to the recovery info.
	 */
	rinfo->cmd_attrib = st_lookup_cmd_attribute(pkt->pkt_cdbp[0]);

	ASSERT(rinfo->cmd_attrib);

	/*
	 * For commands that there is no way to figure the expected position
	 * once completed, we save the position the command was started from
	 * so that if they fail we can position back and try again.
	 * This has already been done in st_cmd() or st_iscsi_cmd().
	 */
	if (rinfo->cmd_attrib->recov_pos_type == POS_STARTING) {
		/* save current position as the starting position. */
		COPY_POS(&rinfo->pos, &un->un_pos);
		un->un_running.pmode = invalid;
		return;
	}

	/*
	 * Don't want to update the running position for recovery.
	 */
	if (bp == un->un_recov_buf) {
		rinfo->pos.pmode = un->un_running.pmode;
		return;
	}
	/*
	 * If running position is invalid copy the current position.
	 * Running being set invalid means we are not in a read, write
	 * or write filemark sequence.
	 * We'll copy the current position and start from there.
	 */
	if (un->un_running.pmode == invalid) {
		COPY_POS(&un->un_running, &un->un_pos);
		COPY_POS(&rinfo->pos, &un->un_running);
	} else {
		COPY_POS(&rinfo->pos, &un->un_running);
		if (rinfo->pos.pmode == legacy) {
			/*
			 * Always should be more logical blocks then
			 * data blocks and files marks.
			 */
			ASSERT((rinfo->pos.blkno >= 0) ?
			    rinfo->pos.lgclblkno >=
			    (rinfo->pos.blkno + rinfo->pos.fileno) : 1);
		}
	}

	/*
	 * If the command is not expected to change the drive position
	 * then the running position should be the expected position.
	 */
	if (rinfo->cmd_attrib->chg_tape_pos == 0) {
		ASSERT(rinfo->cmd_attrib->chg_tape_direction == DIR_NONE);
		return;
	}

	if (rinfo->cmd_attrib->explicit_cmd_set) {
		ASSERT(rinfo->pos.pmode != invalid);
		ASSERT(rinfo->cmd_attrib->get_cnt);
		count = rinfo->cmd_attrib->get_cnt(pkt->pkt_cdbp);
		/*
		 * This is a user generated CDB.
		 */
		if (bp == un->un_sbufp) {
			uint64_t lbn;

			lbn = rinfo->cmd_attrib->get_lba(pkt->pkt_cdbp);

			/*
			 * See if this CDB will generate a locate or change
			 * partition.
			 */
			if ((lbn != un->un_running.lgclblkno) ||
			    (pkt->pkt_cdbp[3] != un->un_running.partition)) {
				rinfo->pos.partition = pkt->pkt_cdbp[3];
				rinfo->pos.pmode = logical;
				rinfo->pos.lgclblkno = lbn;
				un->un_running.partition = pkt->pkt_cdbp[3];
				un->un_running.pmode = logical;
				un->un_running.lgclblkno = lbn;
			}
		} else {
			uint64_t lbn = un->un_running.lgclblkno;

			pkt->pkt_cdbp[3]  = (uchar_t)un->un_running.partition;

			pkt->pkt_cdbp[4]  = (uchar_t)(lbn >> 56);
			pkt->pkt_cdbp[5]  = (uchar_t)(lbn >> 48);
			pkt->pkt_cdbp[6]  = (uchar_t)(lbn >> 40);
			pkt->pkt_cdbp[7]  = (uchar_t)(lbn >> 32);
			pkt->pkt_cdbp[8]  = (uchar_t)(lbn >> 24);
			pkt->pkt_cdbp[9]  = (uchar_t)(lbn >> 16);
			pkt->pkt_cdbp[10] = (uchar_t)(lbn >> 8);
			pkt->pkt_cdbp[11] = (uchar_t)(lbn);
		}
		rinfo->pos.lgclblkno += count;
		rinfo->pos.blkno += count;
		un->un_running.lgclblkno += count;
		return;
	}

	if (rinfo->cmd_attrib->chg_tape_pos) {

		/* should not have got an invalid position from running. */
		if (un->un_mediastate == MTIO_INSERTED) {
			ASSERT(rinfo->pos.pmode != invalid);
		}

		/* should have either a get count or or get lba function */
		ASSERT(rinfo->cmd_attrib->get_cnt != NULL ||
		    rinfo->cmd_attrib->get_lba != NULL);

		/* only explicit commands have both and they're handled above */
		ASSERT(!(rinfo->cmd_attrib->get_cnt != NULL &&
		    rinfo->cmd_attrib->get_lba != NULL));

		/* if it has a get count function */
		if (rinfo->cmd_attrib->get_cnt != NULL) {
			count = rinfo->cmd_attrib->get_cnt(pkt->pkt_cdbp);
			if (count == 0) {
				return;
			}
			/*
			 * Changes position but doesn't transfer data.
			 * i.e. rewind, write_file_mark and load.
			 */
			if (rinfo->cmd_attrib->transfers_data == TRAN_NONE) {
				switch (rinfo->cmd_attrib->chg_tape_direction) {
				case DIR_NONE: /* Erase */
					ASSERT(rinfo->cmd_attrib->cmd ==
					    SCMD_ERASE);
					break;
				case DIR_FORW: /* write_file_mark */
					rinfo->pos.fileno += count;
					rinfo->pos.lgclblkno += count;
					rinfo->pos.blkno = 0;
					un->un_running.fileno += count;
					un->un_running.lgclblkno += count;
					un->un_running.blkno = 0;
					break;
				case DIR_REVC: /* rewind */
					rinfo->pos.fileno = 0;
					rinfo->pos.lgclblkno = 0;
					rinfo->pos.blkno = 0;
					rinfo->pos.eof = ST_NO_EOF;
					rinfo->pos.pmode = legacy;
					un->un_running.fileno = 0;
					un->un_running.lgclblkno = 0;
					un->un_running.blkno = 0;
					un->un_running.eof = ST_NO_EOF;
					if (un->un_running.pmode != legacy)
						un->un_running.pmode = legacy;
					break;
				case DIR_EITH: /* Load unload */
					ASSERT(rinfo->cmd_attrib->cmd ==
					    SCMD_LOAD);
					switch (count & (LD_LOAD | LD_RETEN |
					    LD_RETEN | LD_HOLD)) {
					case LD_UNLOAD:
					case LD_RETEN:
					case LD_HOLD:
					case LD_LOAD | LD_HOLD:
					case LD_EOT | LD_HOLD:
					case LD_RETEN | LD_HOLD:
						rinfo->pos.pmode = invalid;
						un->un_running.pmode = invalid;
						break;
					case LD_EOT:
					case LD_LOAD | LD_EOT:
						rinfo->pos.eof = ST_EOT;
						rinfo->pos.pmode = invalid;
						un->un_running.eof = ST_EOT;
						un->un_running.pmode = invalid;
						break;
					case LD_LOAD:
					case LD_RETEN | LD_LOAD:
						rinfo->pos.fileno = 0;
						rinfo->pos.lgclblkno = 0;
						rinfo->pos.blkno = 0;
						rinfo->pos.eof = ST_NO_EOF;
						rinfo->pos.pmode = legacy;
						un->un_running.fileno = 0;
						un->un_running.lgclblkno = 0;
						un->un_running.blkno = 0;
						un->un_running.eof = ST_NO_EOF;
						break;
					default:
						ASSERT(0);
					}
					break;
				default:
					ASSERT(0);
					break;
				}
			} else {
				/*
				 * Changes position and does transfer data.
				 * i.e. read or write.
				 */
				switch (rinfo->cmd_attrib->chg_tape_direction) {
				case DIR_FORW:
					rinfo->pos.lgclblkno += count;
					rinfo->pos.blkno += count;
					un->un_running.lgclblkno += count;
					un->un_running.blkno += count;
					break;
				case DIR_REVC:
					rinfo->pos.lgclblkno -= count;
					rinfo->pos.blkno -= count;
					un->un_running.lgclblkno -= count;
					un->un_running.blkno -= count;
					break;
				default:
					ASSERT(0);
					break;
				}
			}
		} else if (rinfo->cmd_attrib->get_lba != NULL) {
			/* Have a get LBA fuction. i.e. Locate */
			ASSERT(rinfo->cmd_attrib->chg_tape_direction ==
			    DIR_EITH);
			count = rinfo->cmd_attrib->get_lba(pkt->pkt_cdbp);
			un->un_running.lgclblkno = count;
			un->un_running.blkno = 0;
			un->un_running.fileno = 0;
			un->un_running.pmode = logical;
			rinfo->pos.lgclblkno = count;
			rinfo->pos.pmode = invalid;
		} else {
			ASSERT(0);
		}
		return;
	}

	ST_CDB(ST_DEVINFO, "Unhanded CDB for position prediction",
	    (char *)pkt->pkt_cdbp);

}

static int
st_make_sure_mode_data_is_correct(struct scsi_tape *un, ubufunc_t ubf)
{
	int rval;

	ST_FUNC(ST_DEVINFO, st_make_sure_mode_data_is_correct);

	/*
	 * check to see if mode data has changed.
	 */
	rval = st_check_mode_for_change(un, ubf);
	if (rval) {
		rval = st_gen_mode_select(un, ubf, un->un_mspl,
		    sizeof (struct seq_mode));
	}
	if (un->un_tlr_flag != TLR_NOT_SUPPORTED) {
		rval |= st_set_target_TLR_mode(un, ubf);
	}
	return (rval);
}

static int
st_check_mode_for_change(struct scsi_tape *un, ubufunc_t ubf)
{
	struct seq_mode *current;
	int rval;
	int i;
	caddr_t this;
	caddr_t that;

	ST_FUNC(ST_DEVINFO, st_check_mode_for_change);

	/* recovery called with mode tamper before mode selection */
	if (un->un_comp_page == (ST_DEV_DATACOMP_PAGE | ST_DEV_CONFIG_PAGE)) {
		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "Mode Select not done yet");
		return (0);
	}

	current = kmem_zalloc(sizeof (struct seq_mode), KM_SLEEP);

	rval = st_gen_mode_sense(un, ubf, un->un_comp_page, current,
	    sizeof (struct seq_mode));
	if (rval != 0) {
		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "Mode Sense for mode verification failed");
		kmem_free(current, sizeof (struct seq_mode));
		return (rval);
	}

	this = (caddr_t)current;
	that = (caddr_t)un->un_mspl;

	rval = bcmp(this, that, sizeof (struct seq_mode));
	if (rval == 0) {
		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "Found no changes in mode data");
	}
#ifdef STDEBUG
	else {
		for (i = 1; i < sizeof (struct seq_mode); i++) {
			if (this[i] != that[i]) {
				ST_RECOV(ST_DEVINFO, st_label, CE_CONT,
				    "sense data changed at byte %d was "
				    "0x%x now 0x%x", i,
				    (uchar_t)that[i], (uchar_t)this[i]);
			}
		}
	}
#endif
	kmem_free(current, sizeof (struct seq_mode));

	return (rval);
}

static int
st_test_path_to_device(struct scsi_tape *un)
{
	int rval = 0;
	int limit = st_retry_count;

	ST_FUNC(ST_DEVINFO, st_test_path_to_device);

	/*
	 * XXX Newer drives may not RESEVATION CONFLICT a TUR.
	 */
	do {
		if (rval != 0) {
			mutex_exit(ST_MUTEX);
			delay(drv_usectohz(1000000));
			mutex_enter(ST_MUTEX);
		}
		rval = st_rcmd(un, SCMD_TEST_UNIT_READY, 0, SYNC_CMD);
		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "ping TUR returned 0x%x", rval);
		limit--;
	} while (((rval == EACCES) || (rval == EBUSY)) && limit);

	if (un->un_status == KEY_NOT_READY || un->un_mediastate == MTIO_EJECTED)
		rval = 0;

	return (rval);
}

/*
 * Does read position using recov_buf and doesn't update un_pos.
 * Does what ever kind of read position you want.
 */
static int
st_recovery_read_pos(struct scsi_tape *un, read_p_types type,
    read_pos_data_t *raw)
{
	int rval;
	struct uscsi_cmd cmd;
	struct scsi_arq_status status;
	char cdb[CDB_GROUP1];

	ST_FUNC(ST_DEVINFO, st_recovery_read_pos);
	bzero(&cmd, sizeof (cmd));

	cdb[0] = SCMD_READ_POSITION;
	cdb[1] = type;
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = 0;
	cdb[5] = 0;
	cdb[6] = 0;
	cdb[7] = 0;
	cdb[8] = (type == EXT_POS) ? 28 : 0;
	cdb[9] = 0;

	cmd.uscsi_flags = USCSI_READ | USCSI_RQENABLE;
	cmd.uscsi_timeout = un->un_dp->non_motion_timeout;
	cmd.uscsi_cdb = cdb;
	cmd.uscsi_cdblen = sizeof (cdb);
	cmd.uscsi_rqlen = sizeof (status);
	cmd.uscsi_rqbuf = (caddr_t)&status;
	cmd.uscsi_bufaddr = (caddr_t)raw;
	switch (type) {
	case SHORT_POS:
		cmd.uscsi_buflen = sizeof (tape_position_t);
		break;
	case LONG_POS:
		cmd.uscsi_buflen = sizeof (tape_position_long_t);
		break;
	case EXT_POS:
		cmd.uscsi_buflen = sizeof (tape_position_ext_t);
		break;
	default:
		ASSERT(0);
	}

	rval = st_uscsi_rcmd(un, &cmd, FKIOCTL);
	if (cmd.uscsi_status) {
		rval = EIO;
	}
	return (rval);
}

static int
st_recovery_get_position(struct scsi_tape *un, tapepos_t *read,
    read_pos_data_t *raw)
{
	int rval;
	read_p_types type = un->un_read_pos_type;

	ST_FUNC(ST_DEVINFO, st_recovery_get_position);

	do {
		rval = st_recovery_read_pos(un, type, raw);
		if (rval != 0) {
			switch (type) {
			case SHORT_POS:
				type = NO_POS;
				break;

			case LONG_POS:
				type = EXT_POS;
				break;

			case EXT_POS:
				type = SHORT_POS;
				break;

			default:
				type = LONG_POS;
				break;

			}
		} else {
			if (type != un->un_read_pos_type) {
				un->un_read_pos_type = type;
			}
			break;
		}
	} while (type != NO_POS);

	if (rval == 0) {
		rval = st_interpret_read_pos(un, read, type,
		    sizeof (read_pos_data_t), (caddr_t)raw, 1);
	}
	return (rval);
}

/*
 * based on the command do we retry, continue or give up?
 * possable return values?
 *	zero do nothing looks fine.
 *	EAGAIN retry.
 *	EIO failed makes no sense.
 */
static int
st_compare_expected_position(struct scsi_tape *un, st_err_info *ei,
    cmd_attribute const * cmd_att, tapepos_t *read)
{
	int rval;
	read_pos_data_t *readp_datap;

	ST_FUNC(ST_DEVINFO, st_compare_expected_position);

	ASSERT(un != NULL);
	ASSERT(ei != NULL);
	ASSERT(read != NULL);
	ASSERT(cmd_att->chg_tape_pos);

	COPY_POS(read, &ei->ei_expected_pos);

	readp_datap = kmem_zalloc(sizeof (read_pos_data_t), KM_SLEEP);

	rval = st_recovery_get_position(un, read, readp_datap);

	kmem_free(readp_datap, sizeof (read_pos_data_t));

	if (rval != 0) {
		return (EIO);
	}

	ST_POS(ST_DEVINFO, "st_compare_expected_position", read);

	if ((read->pmode == invalid) ||
	    (ei->ei_expected_pos.pmode == invalid)) {
		return (EIO);
	}

	/*
	 * Command that changes tape position and have an expected position
	 * if it were to chave completed sucessfully.
	 */
	if (cmd_att->recov_pos_type == POS_EXPECTED) {
		uint32_t count;
		int64_t difference;
		uchar_t reposition = 0;

		ASSERT(cmd_att->get_cnt);
		count = cmd_att->get_cnt(ei->ei_failed_pkt.pkt_cdbp);

		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "Got count from CDB and it was %d\n", count);

		/*
		 * At expected?
		 */
		if (read->lgclblkno == ei->ei_expected_pos.lgclblkno) {
			ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
			    "Found drive to be at expected position\n");

			/*
			 * If the command should move tape and it got a busy
			 * it shouldn't be in the expected position.
			 */
			if (ei->ei_failing_status.sts_status.sts_busy != 0) {
				reposition = 1;

			/*
			 * If the command doesn't transfer data should be good.
			 */
			} else if (cmd_att->transfers_data == TRAN_NONE) {
				return (0); /* Good */

			/*
			 * Command transfers data, should have done so.
			 */
			} else if (ei->ei_failed_pkt.pkt_state &
			    STATE_XFERRED_DATA) {
				return (0); /* Good */
			} else {
				reposition = 1;
			}
		}

		if (cmd_att->chg_tape_direction == DIR_FORW) {
			difference =
			    ei->ei_expected_pos.lgclblkno - read->lgclblkno;

			ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
			    "difference between expected and actual is %"
			    PRId64"\n", difference);
			if (count == difference && reposition == 0) {
				ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
				    "Found failed FORW command, retrying\n");
				return (EAGAIN);
			}

			/*
			 * If rewound or somewhere between the starting position
			 * and the expected position (partial read or write).
			 * Locate to the starting position and try the whole
			 * thing over again.
			 */
			if ((read->lgclblkno == 0) ||
			    ((difference > 0) && (difference < count))) {
				rval = st_logical_block_locate(un,
				    st_uscsi_rcmd, read,
				    ei->ei_expected_pos.lgclblkno - count,
				    ei->ei_expected_pos.partition);
				if (rval == 0) {
					ST_RECOV(ST_DEVINFO, st_label,
					    CE_NOTE, "reestablished FORW"
					    " command retrying\n");
					return (EAGAIN);
				}
			/*
			 * This handles flushed read ahead on the drive or
			 * an aborted read that presents as a busy and advanced
			 * the tape position.
			 */
			} else if ((cmd_att->transfers_data == TRAN_READ) &&
			    ((difference < 0) || (reposition == 1))) {
				rval = st_logical_block_locate(un,
				    st_uscsi_rcmd, read,
				    ei->ei_expected_pos.lgclblkno - count,
				    ei->ei_expected_pos.partition);
				if (rval == 0) {
					ST_RECOV(ST_DEVINFO, st_label,
					    CE_NOTE, "reestablished FORW"
					    " read command retrying\n");
					return (EAGAIN);
				}
			/*
			 * XXX swag seeing difference of 2 on write filemark.
			 * If the space to the starting position works on a
			 * write that means the previous write made it to tape.
			 * If not we lost data and have to give up.
			 *
			 * The plot thickens. Now I am attempting to cover a
			 * count of 1 and a differance of 2 on a write.
			 */
			} else if ((difference > count) || (reposition == 1)) {
				rval = st_logical_block_locate(un,
				    st_uscsi_rcmd, read,
				    ei->ei_expected_pos.lgclblkno - count,
				    ei->ei_expected_pos.partition);
				if (rval == 0) {
					ST_RECOV(ST_DEVINFO, st_label,
					    CE_NOTE, "reestablished FORW"
					    " write command retrying\n");
					return (EAGAIN);
				}
				ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
				    "Seek to block %"PRId64" returned %d\n",
				    ei->ei_expected_pos.lgclblkno - count,
				    rval);
			} else {
				ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
				    "Not expected transfers_data = %d "
				    "difference = %"PRId64,
				    cmd_att->transfers_data, difference);
			}

			return (EIO);

		} else if (cmd_att->chg_tape_direction == DIR_REVC) {
			/* Don't think we can write backwards */
			ASSERT(cmd_att->transfers_data != TRAN_WRTE);
			difference =
			    read->lgclblkno - ei->ei_expected_pos.lgclblkno;
			ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
			    "difference between expected and actual is %"
			    PRId64"\n", difference);
			if (count == difference && reposition == 0) {
				ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
				    "Found failed REVC command, retrying\n");
				return (EAGAIN);
			}
			if ((read->lgclblkno == 0) ||
			    ((difference > 0) && (difference < count))) {
				rval = st_logical_block_locate(un,
				    st_uscsi_rcmd, read,
				    ei->ei_expected_pos.lgclblkno + count,
				    ei->ei_expected_pos.partition);
				if (rval == 0) {
					ST_RECOV(ST_DEVINFO, st_label,
					    CE_NOTE, "reestablished REVC"
					    " command retrying\n");
					return (EAGAIN);
				}
			/* This handles read ahead in reverse direction */
			} else if ((cmd_att->transfers_data == TRAN_READ) &&
			    (difference < 0) || (reposition == 1)) {
				rval = st_logical_block_locate(un,
				    st_uscsi_rcmd, read,
				    ei->ei_expected_pos.lgclblkno - count,
				    ei->ei_expected_pos.partition);
				if (rval == 0) {
					ST_RECOV(ST_DEVINFO, st_label,
					    CE_NOTE, "reestablished REVC"
					    " read command retrying\n");
					return (EAGAIN);
				}
			} else {
				ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
				    "Not expected transfers_data = %d "
				    "difference = %"PRId64,
				    cmd_att->transfers_data, difference);
			}
			return (EIO);

		} else {
			/*
			 * Commands that change tape position either
			 * direction or don't change position should not
			 * get here.
			 */
			ASSERT(0);
		}
		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "Didn't find a recoverable position, Failing\n");

	/*
	 * Command that changes tape position and can only be recovered
	 * by going back to the point of origin and retrying.
	 *
	 * Example SCMD_SPACE.
	 */
	} else if (cmd_att->recov_pos_type == POS_STARTING) {
		/*
		 * This type of command stores the starting position.
		 * If the read position is the starting position,
		 * reissue the command.
		 */
		if (ei->ei_expected_pos.lgclblkno == read->lgclblkno) {
			ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
			    "Found Space command at starting position, "
			    "Reissuing\n");
			return (EAGAIN);
		}
		/*
		 * Not in the position that the command was originally issued,
		 * Attempt to locate to that position.
		 */
		rval = st_logical_block_locate(un, st_uscsi_rcmd, read,
		    ei->ei_expected_pos.lgclblkno,
		    ei->ei_expected_pos.partition);
		if (rval) {
			ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
			    "Found Space at an unexpected position and locate "
			    "back to starting position failed\n");
			return (EIO);
		}
		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "Found Space at an unexpected position and locate "
		    "back to starting position worked, Reissuing\n");
		return (EAGAIN);
	}
	st_print_position(ST_DEVINFO, st_label, CE_NOTE,
	    "Unhandled attribute/expected position", &ei->ei_expected_pos);
	st_print_position(ST_DEVINFO, st_label, CE_NOTE,
	    "Read position above did not make sense", read);
	ASSERT(0);
	return (EIO);
}

static errstate
st_recover_reissue_pkt(struct scsi_tape *un, struct scsi_pkt *oldpkt)
{
	buf_t *bp;
	buf_t *pkt_bp;
	struct scsi_pkt *newpkt;
	cmd_attribute const *attrib;
	recov_info *rcv = oldpkt->pkt_private;
	uint_t cdblen;
	int queued = 0;
	int rval;
	int flags = 0;
	int stat_size =
	    (un->un_arq_enabled ? sizeof (struct scsi_arq_status) : 1);

	ST_FUNC(ST_DEVINFO, st_recover_reissue_pkt);

	bp = rcv->cmd_bp;

	if (rcv->privatelen == sizeof (recov_info)) {
		attrib = rcv->cmd_attrib;
	} else {
		attrib = st_lookup_cmd_attribute(oldpkt->pkt_cdbp[0]);
	}

	/*
	 * Some non-uscsi commands use the b_bcount for values that
	 * have nothing to do with how much data is transfered.
	 * In those cases we need to hide the buf_t from scsi_init_pkt().
	 */
	if ((BP_UCMD(bp)) && (bp->b_bcount)) {
		pkt_bp = bp;
	} else if (attrib->transfers_data == TRAN_NONE) {
		pkt_bp = NULL;
	} else {
		pkt_bp = bp;
	}

	/*
	 * if this is a queued command make sure it the only one in the
	 * run queue.
	 */
	if (bp != un->un_sbufp && bp != un->un_recov_buf) {
		ASSERT(un->un_runqf == un->un_runql);
		ASSERT(un->un_runqf == bp);
		queued = 1;
	}

	cdblen = scsi_cdb_size[CDB_GROUPID(oldpkt->pkt_cdbp[0])];

	if (pkt_bp == un->un_rqs_bp) {
		flags |= PKT_CONSISTENT;
		stat_size = 1;
	}

	newpkt = scsi_init_pkt(ROUTE, NULL, pkt_bp, cdblen,
	    stat_size, rcv->privatelen, flags, NULL_FUNC, NULL);
	if (newpkt == NULL) {
		ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
		    "Reissue pkt scsi_init_pkt() failure\n");
		return (COMMAND_DONE_ERROR);
	}

	ASSERT(newpkt->pkt_resid == 0);
	bp->b_flags &= ~(B_DONE);
	bp->b_resid = 0;
	st_bioerror(bp, 0);

	bcopy(oldpkt->pkt_private, newpkt->pkt_private, rcv->privatelen);

	newpkt->pkt_comp = oldpkt->pkt_comp;
	newpkt->pkt_time = oldpkt->pkt_time;

	bzero(newpkt->pkt_scbp, stat_size);
	bcopy(oldpkt->pkt_cdbp, newpkt->pkt_cdbp, cdblen);

	newpkt->pkt_state = 0;
	newpkt->pkt_statistics = 0;

	/*
	 * oldpkt passed in was a copy of the original.
	 * to distroy we need the address of the original.
	 */
	oldpkt = BP_PKT(bp);

	if (oldpkt == un->un_rqs) {
		ASSERT(bp == un->un_rqs_bp);
		un->un_rqs = newpkt;
	}

	SET_BP_PKT(bp, newpkt);

	scsi_destroy_pkt(oldpkt);

	rval = st_transport(un, newpkt);
	if (rval == TRAN_ACCEPT) {
		return (JUST_RETURN);
	}
	ST_RECOV(ST_DEVINFO, st_label, CE_NOTE,
	    "Reissue pkt st_transport(0x%x) failure\n", rval);
	if (rval != TRAN_BUSY) {
		return (COMMAND_DONE_ERROR);
	}
	mutex_exit(ST_MUTEX);
	rval = st_handle_start_busy(un, bp, ST_TRAN_BUSY_TIMEOUT, queued);
	mutex_enter(ST_MUTEX);
	if (rval) {
		return (COMMAND_DONE_ERROR);
	}

	return (JUST_RETURN);
}

static int
st_transport(struct scsi_tape *un, struct scsi_pkt *pkt)
{
	int status;

	ST_FUNC(ST_DEVINFO, st_transport);

	ST_CDB(ST_DEVINFO, "transport CDB", (caddr_t)pkt->pkt_cdbp);

	mutex_exit(ST_MUTEX);

	status = scsi_transport(pkt);

	mutex_enter(ST_MUTEX);

	return (status);
}

/*
 * Removed the buf_t bp from the queue referenced to by head and tail.
 * Returns the buf_t pointer if it is found in the queue.
 * Returns NULL if it is not found.
 */
static buf_t *
st_remove_from_queue(buf_t **head, buf_t **tail, buf_t *bp)
{
	buf_t *runqbp;
	buf_t *prevbp = NULL;

	for (runqbp = *head; runqbp != 0; runqbp = runqbp->av_forw) {
		if (runqbp == bp) {
			/* found it, is it at the head? */
			if (runqbp == *head) {
				*head = bp->av_forw;
			} else {
				prevbp->av_forw = bp->av_forw;
			}
			if (*tail == bp) {
				*tail = prevbp;
			}
			bp->av_forw = NULL;
			return (bp); /* found and removed */
		}
		prevbp = runqbp;
	}
	return (NULL);
}

/*
 * Adds a buf_t to the queue pointed to by head and tail.
 * Adds it either to the head end or the tail end based on which
 * the passed variable end (head or tail) points at.
 */
static void
st_add_to_queue(buf_t **head, buf_t **tail, buf_t *end, buf_t *bp)
{

	bp->av_forw = NULL;
	if (*head) {
		/* Queue is not empty */
		if (end == *head) {
			/* Add at front of queue */
			bp->av_forw = *head;
			*head = bp;
		} else if (end == *tail) {
			/* Add at end of queue */
			(*tail)->av_forw = bp;
			*tail = bp;
		} else {
			ASSERT(0);
		}
	} else {
		/* Queue is empty */
		*head = bp;
		*tail = bp;
	}
}


static uint64_t
st_get_cdb_g0_rw_count(uchar_t *cdb)
{
	uint64_t count;

	if ((cdb[1]) & 1) {
		/* fixed block mode, the count is the number of blocks */
		count =
		    cdb[2] << 16 |
		    cdb[3] << 8 |
		    cdb[4];
	} else {
		/* variable block mode, the count is the block size */
		count = 1;
	}
	return (count);
}

static uint64_t
st_get_cdb_g0_sign_count(uchar_t *cdb)
{
	uint64_t count;

	count =
	    cdb[2] << 16 |
	    cdb[3] << 8 |
	    cdb[4];
	/*
	 * If the sign bit of the 3 byte value is set, extended it.
	 */
	if (count & 0x800000) {
		count |= 0xffffffffff000000;
	}
	return (count);
}

static uint64_t
st_get_cdb_g0_count(uchar_t *cdb)
{
	uint64_t count;

	count =
	    cdb[2] << 16 |
	    cdb[3] << 8 |
	    cdb[4];
	return (count);
}

static uint64_t
st_get_cdb_g5_rw_cnt(uchar_t *cdb)
{
	uint64_t count;

	if ((cdb[1]) & 1) {
		/* fixed block mode */
		count =
		    cdb[12] << 16 |
		    cdb[13] << 8 |
		    cdb[14];
	} else {
		/* variable block mode */
		count = 1;
	}
	return (count);
}

static uint64_t
st_get_no_count(uchar_t *cdb)
{
	ASSERT(cdb[0] == SCMD_REWIND);
	return ((uint64_t)cdb[0]);
}

static uint64_t
st_get_load_options(uchar_t *cdb)
{
	return ((uint64_t)(cdb[4] | (LD_HOLD << 1)));
}

static uint64_t
st_get_erase_options(uchar_t *cdb)
{
	return (cdb[1] | (cdb[0] << 8));
}

static uint64_t
st_get_cdb_g1_lba(uchar_t *cdb)
{
	uint64_t lba;

	lba =
	    cdb[3] << 24 |
	    cdb[4] << 16 |
	    cdb[5] << 8 |
	    cdb[6];
	return (lba);
}

static uint64_t
st_get_cdb_g5_count(uchar_t *cdb)
{
	uint64_t count =
	    cdb[12] << 16 |
	    cdb[13] << 8 |
	    cdb[14];

	return (count);
}

static uint64_t
st_get_cdb_g4g5_cnt(uchar_t *cdb)
{
	uint64_t lba;

	lba =
	    (uint64_t)cdb[4] << 56 |
	    (uint64_t)cdb[5] << 48 |
	    (uint64_t)cdb[6] << 40 |
	    (uint64_t)cdb[7] << 32 |
	    (uint64_t)cdb[8] << 24 |
	    (uint64_t)cdb[9] << 16 |
	    (uint64_t)cdb[10] << 8 |
	    (uint64_t)cdb[11];
	return (lba);
}

static const cmd_attribute cmd_attributes[] = {
	{ SCMD_READ,
	    1, 0, 1, 0, 0, DIR_FORW, TRAN_READ, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g0_rw_count },
	{ SCMD_WRITE,
	    1, 0, 1, 1, 0, DIR_FORW, TRAN_WRTE, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g0_rw_count },
	{ SCMD_TEST_UNIT_READY,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_REWIND,
	    1, 1, 1, 0, 0, DIR_REVC, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, st_get_no_count },
	{ SCMD_REQUEST_SENSE,
	    0, 0, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_READ_BLKLIM,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_READ_G4,
	    1, 0, 1, 0, 1, DIR_FORW, TRAN_READ, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g5_rw_cnt, st_get_cdb_g4g5_cnt },
	{ SCMD_WRITE_G4,
	    1, 0, 1, 1, 1, DIR_FORW, TRAN_WRTE, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g5_rw_cnt, st_get_cdb_g4g5_cnt },
	{ SCMD_READ_REVERSE,
	    1, 0, 1, 1, 0, DIR_REVC, TRAN_READ, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g0_rw_count },
	{ SCMD_READ_REVERSE_G4,
	    1, 0, 1, 1, 1, DIR_REVC, TRAN_READ, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g5_rw_cnt, st_get_cdb_g4g5_cnt },
	{ SCMD_WRITE_FILE_MARK,
	    1, 0, 1, 1, 0, DIR_FORW, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g0_count },
	{ SCMD_WRITE_FILE_MARK_G4,
	    1, 0, 1, 1, 1, DIR_FORW, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g5_count, st_get_cdb_g4g5_cnt },
	{ SCMD_SPACE,
	    1, 0, 1, 0, 0, DIR_EITH, TRAN_NONE, POS_STARTING,
	    0, 0, 0, st_get_cdb_g0_sign_count },
	{ SCMD_SPACE_G4,
	    1, 0, 1, 0, 0, DIR_EITH, TRAN_NONE, POS_STARTING,
	    0, 0, 0, st_get_cdb_g4g5_cnt },
	{ SCMD_INQUIRY,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_VERIFY_G0,
	    1, 0, 1, 0, 0, DIR_FORW, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g0_rw_count },
	{ SCMD_VERIFY_G4,
	    1, 0, 1, 0, 1, DIR_FORW, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, st_get_cdb_g5_rw_cnt, st_get_cdb_g4g5_cnt },
	{ SCMD_RECOVER_BUF,
	    1, 0, 1, 1, 0, DIR_REVC, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_MODE_SELECT,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_WRTE, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_RESERVE,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_RELEASE,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_ERASE,
	    1, 0, 1, 1, 0, DIR_NONE, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, st_get_erase_options },
	{ SCMD_MODE_SENSE,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_LOAD,
	    1, 1, 1, 0, 0, DIR_EITH, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, st_get_load_options },
	{ SCMD_GDIAG,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    1, 0, 0 },
	{ SCMD_SDIAG,
	    1, 0, 1, 1, 0, DIR_EITH, TRAN_WRTE, POS_EXPECTED,
	    1, 0, 0 },
	{ SCMD_DOORLOCK,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_NONE, POS_EXPECTED,
	    0, 4, 3 },
	{ SCMD_LOCATE,
	    1, 1, 1, 0, 0, DIR_EITH, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, NULL, st_get_cdb_g1_lba },
	{ SCMD_READ_POSITION,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_WRITE_BUFFER,
	    1, 0, 0, 0, 0, DIR_NONE, TRAN_WRTE, POS_EXPECTED,
	    1, 0, 0 },
	{ SCMD_READ_BUFFER,
	    1, 0, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    1, 0, 0 },
	{ SCMD_REPORT_DENSITIES,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_LOG_SELECT_G1,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_WRTE, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_LOG_SENSE_G1,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_PRIN,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_PROUT,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_WRTE, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_READ_ATTRIBUTE,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_WRITE_ATTRIBUTE,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_WRTE, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_LOCATE_G4,
	    1, 1, 1, 0, 0, DIR_EITH, TRAN_NONE, POS_EXPECTED,
	    0, 0, 0, NULL, st_get_cdb_g4g5_cnt },
	{ SCMD_REPORT_LUNS,
	    0, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_SVC_ACTION_IN_G5,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_MAINTENANCE_IN,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_READ, POS_EXPECTED,
	    0, 0, 0 },
	{ SCMD_MAINTENANCE_OUT,
	    1, 1, 0, 0, 0, DIR_NONE, TRAN_WRTE, POS_EXPECTED,
	    0, 0, 0 },
	{ 0xff, /* Default attribute for unsupported commands */
	    1, 0, 0, 0, 0, DIR_NONE, TRAN_NONE, POS_STARTING,
	    1, 0, 0, NULL, NULL }
};

static const cmd_attribute *
st_lookup_cmd_attribute(unsigned char cmd)
{
	int i;
	cmd_attribute const *attribute;

	for (i = 0; i < ST_NUM_MEMBERS(cmd_attributes); i++) {
		attribute = &cmd_attributes[i];
		if (attribute->cmd == cmd) {
			return (attribute);
		}
	}
	ASSERT(attribute);
	return (attribute);
}

static int
st_reset(struct scsi_tape *un, int reset_type)
{
	int rval;

	ASSERT(MUTEX_HELD(&un->un_sd->sd_mutex));

	ST_FUNC(ST_DEVINFO, st_reset);
	un->un_rsvd_status |= ST_INITIATED_RESET;
	mutex_exit(ST_MUTEX);
	do {
		rval = scsi_reset(&un->un_sd->sd_address, reset_type);
		if (rval == 0) {
			switch (reset_type) {
			case RESET_LUN:
				ST_DEBUG3(ST_DEVINFO, st_label, CE_WARN,
				    "LUN reset failed trying target reset");
				reset_type = RESET_TARGET;
				break;
			case RESET_TARGET:
				ST_DEBUG3(ST_DEVINFO, st_label, CE_WARN,
				    "target reset failed trying bus reset");
				reset_type = RESET_BUS;
				break;
			case RESET_BUS:
				ST_DEBUG3(ST_DEVINFO, st_label, CE_WARN,
				    "bus reset failed trying all reset");
				reset_type = RESET_ALL;
			default:
				mutex_enter(ST_MUTEX);
				return (rval);
			}
		}
	} while (rval == 0);
	mutex_enter(ST_MUTEX);
	return (rval);
}

#define	SAS_TLR_MOD_LEN sizeof (struct seq_mode)
static int
st_set_target_TLR_mode(struct scsi_tape *un, ubufunc_t ubf)
{
	int ret;
	int amount = SAS_TLR_MOD_LEN;
	struct seq_mode *mode_data;

	ST_FUNC(ST_DEVINFO, st_set_target_TLR_mode);

	mode_data = kmem_zalloc(SAS_TLR_MOD_LEN, KM_SLEEP);
	ret = st_gen_mode_sense(un, ubf, 0x18, mode_data, amount);
	if (ret != DDI_SUCCESS) {
		if (ret != EACCES)
			un->un_tlr_flag = TLR_NOT_SUPPORTED;
		goto out;
	}
	if (mode_data->data_len != amount + 1) {
		amount = mode_data->data_len + 1;
	}
	/* Must be SAS protocol */
	if (mode_data->page.saslun.protocol_id != 6) {
		un->un_tlr_flag = TLR_NOT_SUPPORTED;
		ret = ENOTSUP;
		goto out;
	}
	if (un->un_tlr_flag == TLR_SAS_ONE_DEVICE) {
		if (mode_data->page.saslun.tran_layer_ret == 1)
			goto out;
		mode_data->page.saslun.tran_layer_ret = 1;
	} else {
		if (mode_data->page.saslun.tran_layer_ret == 0)
			goto out;
		mode_data->page.saslun.tran_layer_ret = 0;
	}
	ret = st_gen_mode_select(un, ubf, mode_data, amount);
	if (ret != DDI_SUCCESS) {
		if (ret != EACCES)
			un->un_tlr_flag = TLR_NOT_SUPPORTED;
	} else {
		if (mode_data->page.saslun.tran_layer_ret == 0)
			un->un_tlr_flag = TLR_NOT_KNOWN;
		else
			un->un_tlr_flag = TLR_SAS_ONE_DEVICE;
	}
#ifdef STDEBUG
	st_clean_print(ST_DEVINFO, st_label, SCSI_DEBUG, "TLR data sent",
	    (char *)mode_data, amount);
#endif
out:
	kmem_free(mode_data, SAS_TLR_MOD_LEN);
	return (ret);
}


static void
st_reset_notification(caddr_t arg)
{
	struct scsi_tape *un = (struct scsi_tape *)arg;

	ST_FUNC(ST_DEVINFO, st_reset_notification);
	mutex_enter(ST_MUTEX);

	un->un_unit_attention_flags |= 2;
	if ((un->un_rsvd_status & (ST_RESERVE | ST_APPLICATION_RESERVATIONS)) ==
	    ST_RESERVE) {
		un->un_rsvd_status |= ST_LOST_RESERVE;
		ST_DEBUG2(ST_DEVINFO, st_label, CE_WARN,
		    "Lost Reservation notification");
	} else {
		ST_DEBUG2(ST_DEVINFO, st_label, CE_WARN,
		    "reset notification");
	}

	if ((un->un_restore_pos == 0) &&
	    (un->un_state == ST_STATE_CLOSED) ||
	    (un->un_state == ST_STATE_OPEN_PENDING_IO) ||
	    (un->un_state == ST_STATE_CLOSING)) {
		un->un_restore_pos = 1;
	}
	ST_DEBUG6(ST_DEVINFO, st_label, CE_WARN,
	    "reset and state was %d\n", un->un_state);
	mutex_exit(ST_MUTEX);
}
