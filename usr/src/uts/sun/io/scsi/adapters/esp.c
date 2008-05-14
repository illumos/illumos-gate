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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * esp - Emulex SCSI Processor host adapter driver with FAS101/236,
 *	tagged and non-tagged queuing support
 */
#if defined(lint) && !defined(DEBUG)
#define	DEBUG	1
#define	ESP_CHECK
#endif

#include <sys/note.h>

#include <sys/modctl.h>
#include <sys/scsi/scsi.h>

/*
 * these are non-ddi compliant:
 */
#include <sys/varargs.h>
#include <sys/var.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/utsname.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/callb.h>

/*
 * private
 */
#include <sys/scsi/adapters/espvar.h>
#include <sys/scsi/adapters/espcmd.h>
#include <sys/scsi/impl/scsi_reset_notify.h>

/*
 * External references
 */
extern uchar_t	scsi_cdb_size[];

/*
 * tunables
 */
static int esp_burst_sizes_limit = 0xff; /* patch in case of hw problems */
static int esp_selection_timeout = 250; /* 250 milliseconds */

#ifdef ESP_KSTATS
static int esp_do_kstats = 1;
static int esp_do_bus_kstats = 1;
#endif

#ifdef	ESPDEBUG
static int espdebug = 0;
static int esp_no_sync_backoff = 0;
static void esp_stat_int_print(struct esp *esp);
static int esp_test_stop;
#endif	/* ESPDEBUG */

/*
 * Local static data
 * the global mutex protects some of these esp driver variables
 */
static kmutex_t esp_global_mutex;
static int esp_watchdog_running = 0;
static int esp_scsi_watchdog_tick;	/* in sec */
static clock_t esp_tick;		/* esp_watch() interval in Hz */
static timeout_id_t esp_reset_watch;
static timeout_id_t esp_timeout_id = 0;
static int esp_timeout_initted = 0;
static int esp_n_esps = 0;
static void *esp_state;
static kmutex_t esp_log_mutex;
static char esp_log_buf[256];

/*
 * readers/writer lock to protect the integrity of the softc structure
 * linked list while being traversed (or updated).
 */
static krwlock_t esp_global_rwlock;
static struct esp *esp_softc = (struct esp *)0;
static struct esp *esp_tail;

/*
 * variables & prototypes for torture testing
 */
#ifdef ESP_TEST_RQSENSE
static int esp_test_rqsense;
#endif /* ESP_TEST_RQSENSE */

#ifdef	ESP_TEST_PARITY
static int esp_ptest_emsgin;
static int esp_ptest_msgin;
static int esp_ptest_msg = -1;
static int esp_ptest_status;
static int esp_ptest_data_in;
#endif	/* ESP_TEST_PARITY */

#ifdef ESP_TEST_ABORT
static int esp_atest;
static int esp_atest_disc;
static int esp_atest_reconn;
static void esp_test_abort(struct esp *esp, int slot);
#endif /* ESP_TEST_ABORT */

#ifdef ESP_TEST_RESET
static int esp_rtest;
static int esp_rtest_type;
static void esp_test_reset(struct esp *esp, int slot);
#endif /* ESP_TEST_RESET */

#ifdef ESP_TEST_TIMEOUT
static int esp_force_timeout;
#endif /* ESP_TEST_TIMEOUT */

#ifdef ESP_TEST_BUS_RESET
static int esp_btest;
#endif /* ESP_TEST_BUS_RESET */

#ifdef ESP_TEST_UNTAGGED
static int esp_test_untagged;
static int esp_enable_untagged;
static int esp_test_stop;
#endif /* ESP_TEST_UNTAGGED */
#ifdef ESP_PERF
_NOTE(SCHEME_PROTECTS_DATA("Stable Data", esp_request_count))
_NOTE(SCHEME_PROTECTS_DATA("Stable Data", esp_sample_time))
_NOTE(SCHEME_PROTECTS_DATA("Stable Data", esp_intr_count))
_NOTE(SCHEME_PROTECTS_DATA("Stable Data", esp_ncmds))
_NOTE(SCHEME_PROTECTS_DATA("Stable Data", esp_ndisc))
_NOTE(SCHEME_PROTECTS_DATA("Stable Data", esp_ncmds_per_esp))

/*
 * these should really be protected but it is not really important
 * to be very accurate
 */
static int esp_request_count;
static int esp_sample_time = 0;
static int esp_intr_count;
static int esp_ncmds;
static int esp_ndisc;
#define	MAX_ESPS	80	/* should be enough */
static int esp_ncmds_per_esp[MAX_ESPS];
#endif

_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", \
	scsi_pkt esp_cmd buf scsi_cdb scsi_status))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_address scsi_device))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", esp_watchdog_running))
_NOTE(DATA_READABLE_WITHOUT_LOCK(esp_scsi_watchdog_tick))
_NOTE(DATA_READABLE_WITHOUT_LOCK(espdebug))
_NOTE(DATA_READABLE_WITHOUT_LOCK(dmaga))

/*
 * function prototypes
 *
 * scsa functions are exported by means of the transport table
 */
static int esp_scsi_tgt_probe(struct scsi_device *sd,
    int (*waitfunc)(void));
static int esp_scsi_tgt_init(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static int esp_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int esp_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int esp_reset(struct scsi_address *ap, int level);
static int esp_commoncap(struct scsi_address *ap, char *cap, int val,
    int tgtonly, int doset);
static int esp_getcap(struct scsi_address *ap, char *cap, int whom);
static int esp_setcap(struct scsi_address *ap, char *cap, int value, int whom);
static struct scsi_pkt *esp_scsi_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg);
static void esp_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);
static void esp_scsi_dmafree(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static void esp_scsi_sync_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt);

/*
 * internal functions
 */
static int esp_ustart(struct esp *esp, short start_slot, short flag);
static int esp_startcmd(struct esp *esp, struct esp_cmd *sp);
static int esp_finish(struct esp *esp);
static void esp_handle_qfull(struct esp *esp, struct esp_cmd *sp, int slot);
static void esp_restart_cmd(void *);
static int esp_dopoll(struct esp *esp, int timeout);
static uint_t esp_intr(caddr_t arg);
static void espsvc(struct esp *esp);
static int esp_phasemanage(struct esp *esp);
static int esp_handle_unknown(struct esp *esp);
static int esp_handle_cmd_start(struct esp *esp);
static int esp_handle_cmd_done(struct esp *esp);
static int esp_handle_msg_out(struct esp *esp);
static int esp_handle_msg_out_done(struct esp *esp);
static int esp_handle_clearing(struct esp *esp);
static int esp_handle_data(struct esp *esp);
static int esp_handle_data_done(struct esp *esp);
static int esp_handle_c_cmplt(struct esp *esp);
static int esp_handle_msg_in(struct esp *esp);
static int esp_handle_more_msgin(struct esp *esp);
static int esp_handle_msg_in_done(struct esp *esp);
static int esp_onebyte_msg(struct esp *esp);
static int esp_twobyte_msg(struct esp *esp);
static int esp_multibyte_msg(struct esp *esp);
static int esp_finish_select(struct esp *esp);
static int esp_reconnect(struct esp *esp);
static int esp_istart(struct esp *esp);
static void esp_runpoll(struct esp *esp, short slot, struct esp_cmd *sp);
static int esp_reset_bus(struct esp *esp);
static int esp_reset_recovery(struct esp *esp);
static int esp_handle_selection(struct esp *esp);
static void esp_makeproxy_cmd(struct esp_cmd *sp,
    struct scsi_address *ap, int nmsg, ...);
static void esp_make_sdtr(struct esp *esp, int msgout_offset,
    int period, int offset);
static void esp_watch(void *);
static void esp_watchsubr(struct esp *esp);
static void esp_cmd_timeout(struct esp *esp, struct esp_cmd *sp, int slot);
static int esp_abort_curcmd(struct esp *esp);
static int esp_abort_cmd(struct esp *esp, struct esp_cmd *sp, int slot);
static int esp_abort_allcmds(struct esp *esp);
static void esp_internal_reset(struct esp *esp, int reset_action);
static void esp_sync_backoff(struct esp *esp, struct esp_cmd *sp, int slot);
static void esp_hw_reset(struct esp *esp, int action);
/*PRINTFLIKE3*/
static void esplog(struct esp *esp, int level, const char *fmt, ...)
	__KPRINTFLIKE(3);
/*PRINTFLIKE2*/
static void eprintf(struct esp *esp, const char *fmt, ...)
	__KPRINTFLIKE(2);
static void esp_printstate(struct esp *esp, char *msg);
static void esp_dump_cmd(struct esp_cmd *sp);
static void esp_dump_state(struct esp *esp);
static char *esp_state_name(ushort_t state);
static void esp_update_props(struct esp *esp, int tgt);
static int _esp_start(struct esp *esp, struct esp_cmd *sp, int flag);
static int _esp_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int _esp_reset(struct scsi_address *ap, int level);
static int esp_alloc_tag(struct esp *esp, struct esp_cmd *sp);
static int esp_remove_readyQ(struct esp *esp, struct esp_cmd *sp, int slot);
static void esp_flush_readyQ(struct esp *esp, int slot);
static void esp_flush_tagQ(struct esp *esp, int slot);
static void esp_flush_cmd(struct esp *esp, struct esp_cmd *sp,
    uchar_t reason, uint_t stat);
static int esp_abort_connected_cmd(struct esp *esp, struct esp_cmd *sp,
    uchar_t msg);
static int esp_abort_disconnected_cmd(struct esp *esp, struct scsi_address *ap,
    struct esp_cmd *sp, uchar_t msg, int slot);
static void esp_mark_packets(struct esp *esp, int slot, uchar_t reason,
    uint_t stat);
static int esp_reset_connected_cmd(struct esp *esp, struct scsi_address *ap,
    int slot);
static int esp_reset_disconnected_cmd(struct esp *esp, struct scsi_address *ap,
    int slot);
static int esp_create_arq_pkt(struct esp *esp, struct scsi_address *ap,
    int size);
static int esp_start_arq_pkt(struct esp *esp, struct esp_cmd *sp);
static void esp_complete_arq_pkt(struct esp *esp, struct esp_cmd *sp,
    int slot);
static void esp_determine_chip_type(struct esp *esp);
static void esp_create_callback_thread(struct esp *esp);
static void esp_destroy_callback_thread(struct esp *);
static void esp_callback(struct esp *esp);
static void esp_call_pkt_comp(struct esp *esp, struct esp_cmd *sp);
static int esp_set_new_window(struct esp *esp, struct esp_cmd *sp);
static int esp_restore_pointers(struct esp *esp, struct esp_cmd *sp);
static int esp_next_window(struct esp *esp, struct esp_cmd *sp);
static void esp_start_watch_reset_delay(struct esp *);
static void esp_watch_reset_delay(void *arg);
static int esp_watch_reset_delay_subr(struct esp *esp);
void esp_wakeup_callback_thread(struct callback_info *cb_info);
static void esp_update_TQ_props(struct esp *esp, int tgt, int value);
static int esp_check_dma_error(struct esp *esp);
static void esp_reset_cleanup(struct esp *esp, int slot);
static int esp_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg);
static void esp_set_throttles(struct esp *esp, int slot,
    int n, int what);
static void esp_set_all_lun_throttles(struct esp *esp, int slot, int what);
static void esp_save_throttles(struct esp *esp, int slot, int n,
    short *throttle);
static void esp_restore_throttles(struct esp *esp, int slot, int n,
    short *throttle);
static int esp_do_proxy_cmd(struct esp *esp, struct esp_cmd *sp,
    struct scsi_address *ap, int slot, char *what);
static void esp_remove_tagged_cmd(struct esp *esp, struct esp_cmd *sp,
    int slot, int timeout);
static void esp_decrement_ncmds(struct esp *esp, struct esp_cmd *sp);
static int esp_pkt_alloc_extern(struct esp *esp, struct esp_cmd *sp,
    int cmdlen, int tgtlen, int statuslen, int kf);
static void esp_pkt_destroy_extern(struct esp *esp, struct esp_cmd *sp);
static int esp_kmem_cache_constructor(void *buf, void *cdrarg, int kmflags);
static void esp_kmem_cache_destructor(void *buf, void *cdrarg);

static void esp_flush_fifo(struct esp *esp);
static void esp_empty_startQ(struct esp *esp);

#ifdef ESP_CHECK
static void esp_check_in_transport(struct esp *esp, struct esp_cmd *sp);
#else
#define	esp_check_in_transport(esp, sp)
#endif

/*
 * esp DMA attr for all supported dma engines:
 */
static ddi_dma_attr_t dma1_espattr = {
	DMA_ATTR_V0, (unsigned long long)0,
	(unsigned long long)0xffffffff, (unsigned long long)((1<<24)-1),
	1, DEFAULT_BURSTSIZE, 1,
	(unsigned long long)0xffffffff, (unsigned long long)((1<<24)-1),
	1, 512, 0
};

/*
 * ESC1 esp dma attr
 */
static ddi_dma_attr_t esc1_espattr = {
	DMA_ATTR_V0, (unsigned long long)0,
	(unsigned long long)0xffffffff, (unsigned long long)((1<<24)-1),
	1, DEFAULT_BURSTSIZE | BURST32, 4,
	(unsigned long long)0xffffffff, (unsigned long long)((1<<24)-1),
	1, 512, 0
};

/*
 * DMA2 esp dma attr
 */
static ddi_dma_attr_t dma2_espattr = {
	DMA_ATTR_V0, (unsigned long long)0,
	(unsigned long long)0xffffffff, (unsigned long long)((1<<24)-1),
	1, DEFAULT_BURSTSIZE, 1,
	(unsigned long long)0xffffffff, (unsigned long long)((1<<24)-1),
	1, 512, 0
};

/*
 * DMA3 esp dma attr
 */
static ddi_dma_attr_t dma3_espattr = {
	DMA_ATTR_V0, (unsigned long long)0x0,
	(unsigned long long)0xffffffff, (unsigned long long)((1<<24)-1),
	1, DEFAULT_BURSTSIZE | BURST32, 1,
	(unsigned long long)0xffffffff, (unsigned long long)((1<<24)-1),
	1, 512, 0
};

/*
 * autoconfiguration routines.
 */
static int esp_attach(dev_info_t *dev, ddi_attach_cmd_t cmd);
static int esp_detach(dev_info_t *dev, ddi_detach_cmd_t cmd);
static int esp_dr_detach(dev_info_t *dev);

static struct dev_ops esp_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	esp_attach,		/* attach */
	esp_detach,		/* detach */
	nodev,			/* reset */
	NULL,			/* cb ops */
	NULL,			/* bus operations */
	ddi_power		/* power */
};

char _depends_on[] = "misc/scsi";

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	"ESP SCSI HBA Driver v%I%", /* Name of the module. */
	&esp_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int	i;

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	i = ddi_soft_state_init(&esp_state, sizeof (struct esp),
	    ESP_INIT_SOFT_STATE);
	if (i != 0)
		return (i);
	if ((i = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&esp_state);
		return (i);
	}

	mutex_init(&esp_global_mutex, NULL, MUTEX_DRIVER, NULL);
	rw_init(&esp_global_rwlock, NULL, RW_DRIVER, NULL);

	mutex_init(&esp_log_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((i = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&esp_log_mutex);
		rw_destroy(&esp_global_rwlock);
		mutex_destroy(&esp_global_mutex);
		ddi_soft_state_fini(&esp_state);
		scsi_hba_fini(&modlinkage);
		return (i);
	}

	return (i);
}

int
_fini(void)
{
	int	i;

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);
	if ((i = mod_remove(&modlinkage)) == 0) {
		mutex_destroy(&esp_log_mutex);
		scsi_hba_fini(&modlinkage);
		rw_destroy(&esp_global_rwlock);
		mutex_destroy(&esp_global_mutex);
		ddi_soft_state_fini(&esp_state);
	}
	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
esp_scsi_tgt_probe(struct scsi_device *sd,
    int (*waitfunc)(void))
{
	dev_info_t *dip = ddi_get_parent(sd->sd_dev);
	int rval = SCSIPROBE_FAILURE;
	scsi_hba_tran_t *tran;
	struct esp *esp;
	int tgt = sd->sd_address.a_target;

	tran = ddi_get_driver_private(dip);
	ASSERT(tran != NULL);
	esp = TRAN2ESP(tran);

	/*
	 * force renegotiation since Inquiry cmds do not cause
	 * check conditions
	 */
	mutex_enter(ESP_MUTEX);
	esp->e_sync_known &= ~(1 << tgt);
	mutex_exit(ESP_MUTEX);

	rval = scsi_hba_probe(sd, waitfunc);

	/*
	 * the scsi-options precedence is:
	 *	target-scsi-options		highest
	 *	device-type-scsi-options
	 *	per bus scsi-options
	 *	global scsi-options		lowest
	 */
	mutex_enter(ESP_MUTEX);
	if ((rval == SCSIPROBE_EXISTS) &&
	    ((esp->e_target_scsi_options_defined & (1 << tgt)) == 0)) {
		int options;

		options = scsi_get_device_type_scsi_options(dip, sd, -1);
		if (options != -1) {
			esp->e_target_scsi_options[tgt] = options;
			esplog(esp, CE_NOTE,
				"?target%x-scsi-options = 0x%x\n", tgt,
				esp->e_target_scsi_options[tgt]);

			if (options & SCSI_OPTIONS_FAST) {
				esp->e_default_period[tgt] = (uchar_t)
				    MIN_SYNC_PERIOD(esp);
			} else {
				esp->e_default_period[tgt] = (uchar_t)
				    CONVERT_PERIOD(DEFAULT_SYNC_PERIOD);
			}
			esp->e_neg_period[tgt] = 0;
			esp->e_sync_known &= ~(1 << tgt);
		}
	}
	mutex_exit(ESP_MUTEX);

	IPRINTF2("target%x-scsi-options = 0x%x\n",
		tgt, esp->e_target_scsi_options[tgt]);

	return (rval);
}


/*ARGSUSED*/
static int
esp_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	return (((sd->sd_address.a_target < NTARGETS) &&
		(sd->sd_address.a_lun < NLUNS_PER_TARGET)) ?
		DDI_SUCCESS : DDI_FAILURE);
}

static char *prop_cfreq = "clock-frequency";

/*ARGSUSED*/
static int
esp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct esp *esp;
	volatile struct dmaga *dmar = NULL;
	volatile struct espreg *ep;
	ddi_dma_attr_t	*esp_dma_attr;
	scsi_hba_tran_t *tran = NULL;
	ddi_device_acc_attr_t dev_attr;

	int		instance, i;
	char		buf[64];
	int		mutex_initialized = 0;
	int		add_intr_done = 0;
	int		bound_handle = 0;
	uint_t		count;
	size_t		rlen;
	char		*prop_template = "target%d-scsi-options";
	char		prop_str[32];

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		if ((tran = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		esp = TRAN2ESP(tran);
		if (!esp) {
			return (DDI_FAILURE);
		}
		mutex_enter(ESP_MUTEX);

		/*
		 * Reset hardware and softc to "no outstanding commands"
		 * Note that a check condition can result on first command
		 * to a target.
		 */
		esp_internal_reset(esp,
		    ESP_RESET_SOFTC|ESP_RESET_ESP|ESP_RESET_DMA);
		(void) esp_reset_bus(esp);

		/*
		 * esp_watchdog_running was reset at checkpoint time,
		 * enable it at resume time
		 */
		esp_watchdog_running = 1;

		esp->e_suspended = 0;

		mutex_enter(&esp_global_mutex);
		if (esp_timeout_id == 0) {
			esp_timeout_id = timeout(esp_watch, NULL, esp_tick);
			esp_timeout_initted = 1;
		}
		mutex_exit(&esp_global_mutex);

		/* make sure that things get started */
		(void) esp_istart(esp);
		ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	/*
	 * Since we know that some instantiations of this device can
	 * be plugged into slave-only SBus slots, check to see whether
	 * this is one such.
	 */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "esp%d: device in slave-only slot", instance);
		return (DDI_FAILURE);
	}

	if (ddi_intr_hilevel(dip, 0)) {
		/*
		 * Interrupt number '0' is a high-level interrupt.
		 * At this point you either add a special interrupt
		 * handler that triggers a soft interrupt at a lower level,
		 * or - more simply and appropriately here - you just
		 * fail the attach.
		 */
		cmn_err(CE_WARN,
		    "esp%d: Device is using a hilevel intr", instance);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate softc information.
	 */
	if (ddi_soft_state_zalloc(esp_state, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "esp%d: cannot allocate soft state", instance);
		return (DDI_FAILURE);
	}

	esp = (struct esp *)ddi_get_soft_state(esp_state, instance);

	if (esp == NULL) {
		return (DDI_FAILURE);
	}

	/*
	 * map in device registers
	 */
	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_regs_map_setup(dip, (uint_t)0, (caddr_t *)&ep,
	    (off_t)0, (off_t)sizeof (struct espreg),
	    &dev_attr, &esp->e_regs_acc_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "esp%d: unable to map registers", instance);
		goto exit;
	}

	dmar = dma_alloc(dip);
	if (dmar == NULL) {
		cmn_err(CE_WARN,
		    "esp%d: cannot find dma controller", instance);
		goto unmap;
	}

	/*
	 * Initialize state of DMA gate array.
	 * Must clear DMAGA_RESET on the ESC before accessing the esp.
	 */
	switch (DMAGA_REV(dmar)) {
	case DMA_REV2:
		esp_dma_attr = &dma2_espattr;
		break;
	case ESC1_REV1:
		dmar->dmaga_csr &= ~DMAGA_RESET;
		esp_dma_attr = &esc1_espattr;
		break;
	case DMA_REV3:
		esp_dma_attr = &dma3_espattr;
		break;
	case DMA_REV1:
	default:
		esp_dma_attr = &dma1_espattr;
		break;
	}

	dmar->dmaga_csr &= ~DMAGA_WRITE;

	if (ddi_dma_alloc_handle(dip, esp_dma_attr,
	    DDI_DMA_SLEEP, NULL, &esp->e_dmahandle) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "esp%d: cannot alloc dma handle", instance);
		goto fail;
	}

	if (ddi_dma_mem_alloc(esp->e_dmahandle, (uint_t)FIFOSIZE,
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, (caddr_t *)&esp->e_cmdarea, &rlen,
	    &esp->e_cmdarea_acc_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "esp%d: cannot alloc cmd area", instance);
		goto fail;
	}
	ASSERT(rlen >= FIFOSIZE);

	if (ddi_dma_addr_bind_handle(esp->e_dmahandle,
	    NULL, (caddr_t)esp->e_cmdarea,
	    rlen, DDI_DMA_RDWR|DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &esp->e_dmacookie, &count) != DDI_DMA_MAPPED) {
		cmn_err(CE_WARN,
		    "esp%d: cannot bind cmdarea", instance);
		goto fail;
	}
	bound_handle++;
	ASSERT(count == 1);

	/*
	 * Allocate a transport structure
	 */
	tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);

	/* Indicate that we are 'sizeof (scsi_*(9S))' clean. */
	scsi_size_clean(dip);		/* SCSI_SIZE_CLEAN_VERIFY ok */

	/*
	 * the ESC has a rerun bug and the workaround is
	 * to round up the ESC count; rather than
	 * doing this on each xfer we do it once here
	 * for the cmd area read xfers
	 */
	esp->e_dma_rev = DMAGA_REV(dmar);
	if (esp->e_dma_rev == ESC1_REV1) {
		uint32_t addr1 = esp->e_dmacookie.dmac_address;
		uint32_t addr2 = roundup(addr1 + FIFOSIZE, ptob(1));
		esp->e_esc_read_count = (uint32_t)(addr2 - addr1);
	}

	/*
	 * By default we assume embedded devices and save time
	 * checking for timeouts in esp_watch() by skipping the rest of luns
	 * If we're talking to any non-embedded devices, we can't cheat
	 * and skip over non-zero luns anymore in esp_watch().
	 */
	esp->e_dslot = NLUNS_PER_TARGET;

#ifdef	ESPDEBUG
	/*
	 * Initialize last state log.
	 */
	for (i = 0; i < NPHASE; i++) {
		esp->e_phase[i].e_save_state = STATE_FREE;
		esp->e_phase[i].e_save_stat = -1;
		esp->e_phase[i].e_val1 = -1;
		esp->e_phase[i].e_val2 = -1;
	}
	esp->e_phase_index = 0;
	esp->e_xfer = 0;
#endif	/* ESPDEBUG */

	/*
	 * Initialize throttles.
	 */
	esp_set_throttles(esp, 0, N_SLOTS, CLEAR_THROTTLE);

	/*
	 * initialize transport structure
	 */
	esp->e_tran			= tran;
	esp->e_dev			= dip;

	tran->tran_hba_private		= esp;
	tran->tran_tgt_private		= NULL;

	tran->tran_tgt_init		= esp_scsi_tgt_init;
	tran->tran_tgt_probe		= esp_scsi_tgt_probe;
	tran->tran_tgt_free		= NULL;

	tran->tran_start		= esp_start;
	tran->tran_abort		= esp_abort;
	tran->tran_reset		= esp_reset;
	tran->tran_getcap		= esp_getcap;
	tran->tran_setcap		= esp_setcap;
	tran->tran_init_pkt		= esp_scsi_init_pkt;
	tran->tran_destroy_pkt		= esp_scsi_destroy_pkt;
	tran->tran_dmafree		= esp_scsi_dmafree;
	tran->tran_sync_pkt		= esp_scsi_sync_pkt;
	tran->tran_reset_notify		= esp_scsi_reset_notify;
	tran->tran_get_bus_addr		= NULL;
	tran->tran_get_name		= NULL;
	tran->tran_add_eventcall	= NULL;
	tran->tran_get_eventcookie	= NULL;
	tran->tran_post_event		= NULL;
	tran->tran_remove_eventcall	= NULL;

	/* XXX need tran_quiesce and tran_unquiesce for hotplugging */
	tran->tran_bus_reset		= NULL;
	tran->tran_quiesce		= NULL;
	tran->tran_unquiesce		= NULL;

	esp->e_espconf = DEFAULT_HOSTID;
	i = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "initiator-id", -1);
	if (i == -1) {
		i = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    "scsi-initiator-id", -1);
	}
	if (i != DEFAULT_HOSTID && i >= 0 && i < NTARGETS) {
		esplog(esp, CE_NOTE, "initiator SCSI ID now %d\n", i);
		esp->e_espconf = (uchar_t)i;
	}

	for (i = 0; i < NTARGETS; i++) {
		esp->e_qfull_retries[i] = QFULL_RETRIES;
		esp->e_qfull_retry_interval[i] =
			drv_usectohz(QFULL_RETRY_INTERVAL * 1000);
	}

	esp->e_reg = ep;
	esp->e_dma = dmar;
	esp->e_last_slot = esp->e_cur_slot = UNDEFINED;

	IPRINTF1("DMA Rev: 0x%x\n", ESP_DMAGA_REV(esp));

	esp->e_dma_attr = esp_dma_attr;
	IPRINTF1("esp_dma_attr burstsize=%x\n",
	    esp_dma_attr->dma_attr_burstsizes);

	/*
	 * Attach this instance of the hba
	 */
	if (scsi_hba_attach_setup(dip, esp->e_dma_attr, tran, 0) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "esp: scsi_hba_attach failed\n");
		goto fail;
	}

	/*
	 * if scsi-options property exists, use it;
	 * otherwise use the global variable
	 */
	esp->e_scsi_options = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "scsi-options", SCSI_OPTIONS_DR);

	/* we don't support wide */
	if (esp->e_scsi_options & SCSI_OPTIONS_WIDE) {
		esp->e_scsi_options &= ~SCSI_OPTIONS_WIDE;
		(void) ddi_prop_update_int(DDI_MAJOR_T_UNKNOWN, dip,
		    "scsi-options", esp->e_scsi_options);
	}

	if ((esp->e_scsi_options & SCSI_OPTIONS_SYNC) == 0) {
		esp->e_weak = 0xff;
	}

	/*
	 * if scsi-selection-timeout property exists, use it
	 */
	esp_selection_timeout = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, 0, "scsi-selection-timeout", SCSI_DEFAULT_SELECTION_TIMEOUT);

#ifdef ESPDEBUG
	if ((esp->e_scsi_options & SCSI_DEBUG_HA) && (espdebug == 0)) {
		espdebug = 1;
	}
#endif

	/*
	 * if target<n>-scsi-options property exists, use it;
	 * otherwise use the e_scsi_options
	 */
	for (i = 0; i < NTARGETS; i++) {
		(void) sprintf(prop_str, prop_template, i);
		esp->e_target_scsi_options[i] = ddi_prop_get_int(
			DDI_DEV_T_ANY, dip, 0, prop_str, -1);
		if (esp->e_target_scsi_options[i] != -1) {
			esplog(esp, CE_NOTE,
				"?target%d_scsi_options=0x%x\n",
				i, esp->e_target_scsi_options[i]);
			esp->e_target_scsi_options_defined |= 1 << i;
		} else {
			esp->e_target_scsi_options[i] = esp->e_scsi_options;
		}

		if (((esp->e_target_scsi_options[i] & SCSI_OPTIONS_DR) == 0) &&
		    (esp->e_target_scsi_options[i] & SCSI_OPTIONS_TAG)) {
			esp->e_target_scsi_options[i] &= ~SCSI_OPTIONS_TAG;
			esplog(esp, CE_WARN,
			    "Disabled TQ since disconnects are disabled\n");
		}
	}

	esp->e_scsi_tag_age_limit =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "scsi-tag-age-limit",
	    scsi_tag_age_limit);
	IPRINTF2("esp tag age limit=%d, global=%d\n",
	    esp->e_scsi_tag_age_limit, scsi_tag_age_limit);
	if (esp->e_scsi_tag_age_limit != scsi_tag_age_limit) {
		esplog(esp, CE_NOTE, "scsi-tag-age-limit=%d\n",
		    esp->e_scsi_tag_age_limit);
	}

	esp->e_scsi_reset_delay = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "scsi-reset-delay", scsi_reset_delay);
	IPRINTF2("esp scsi_reset_delay=%x, global=%x\n",
	    esp->e_scsi_reset_delay, scsi_reset_delay);
	if (esp->e_scsi_reset_delay == 0) {
		esplog(esp, CE_NOTE,
			"scsi_reset_delay of 0 is not recommended,"
			" resetting to SCSI_DEFAULT_RESET_DELAY\n");
		esp->e_scsi_reset_delay = SCSI_DEFAULT_RESET_DELAY;
	}
	if (esp->e_scsi_reset_delay != scsi_reset_delay) {
		esplog(esp, CE_NOTE, "scsi-reset-delay=%d\n",
		    esp->e_scsi_reset_delay);
	}

	esp->e_force_async = 0;
	/*
	 * disable tagged queuing for all targets
	 * (will be enabled by target driver if necessary)
	 */
	esp->e_notag = 0xff;

	/*
	 * get iblock cookie and initialize mutexes
	 */
	if (ddi_get_iblock_cookie(dip, (uint_t)0, &esp->e_iblock)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "esp_attach: cannot get iblock cookie");
		goto fail;
	}

	mutex_init(ESP_MUTEX, NULL, MUTEX_DRIVER, esp->e_iblock);

	/*
	 * initialize mutex for startQ
	 */
	mutex_init(&esp->e_startQ_mutex, NULL, MUTEX_DRIVER, esp->e_iblock);

	/*
	 * add this esp to the linked list of esp's
	 */
	rw_enter(&esp_global_rwlock, RW_WRITER);
	if (esp_softc == (struct esp *)NULL) {
		esp_softc = esp;
	} else {
		esp_tail->e_next = esp;
	}
	esp_tail = esp;		/* point to last esp in list */
	rw_exit(&esp_global_rwlock);
	mutex_initialized++;

	/*
	 * kstat_intr support
	 */
	(void) sprintf(buf, "esp%d", instance);
	esp->e_intr_kstat = kstat_create("esp", instance, buf, "controller", \
			KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT);
	if (esp->e_intr_kstat)
		kstat_install(esp->e_intr_kstat);

	if (ddi_add_intr(dip, (uint_t)0, &esp->e_iblock, NULL, esp_intr,
								(caddr_t)esp)) {
		cmn_err(CE_WARN, "esp: cannot add intr");
		goto fail;
	}
	add_intr_done++;

	/*
	 * finally, find out what kind of ESP/FAS chip we have here
	 * now we are ready to take the reset interrupt
	 */
	esp_determine_chip_type(esp);

	/*
	 * start off one watchdog for all esp's now we are fully initialized
	 */
	if (esp_softc == esp) {
		esp_scsi_watchdog_tick =
		    ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
			"scsi-watchdog-tick", scsi_watchdog_tick);
		if (esp_scsi_watchdog_tick != scsi_watchdog_tick) {
			esplog(esp, CE_NOTE, "scsi-watchdog-tick=%d\n",
			    esp_scsi_watchdog_tick);
		}
		esp_tick = drv_usectohz((clock_t)
		    esp_scsi_watchdog_tick * 1000000);
		IPRINTF2("esp scsi watchdog tick=%x, esp_tick=%lx\n",
		    esp_scsi_watchdog_tick, esp_tick);
		mutex_enter(&esp_global_mutex);
		if (esp_timeout_id == 0) {
			esp_timeout_id = timeout(esp_watch, NULL, esp_tick);
			esp_timeout_initted = 1;
		}
		mutex_exit(&esp_global_mutex);
	}

	/*
	 * Initialize power management bookkeeping; components are
	 * created idle
	 */

	/*
	 * Since as of now, there is no power management done in
	 * scsi-HBA drivers, there is no need to create a pm_component.
	 * BUT esp is a special case with GYPSY. In gypsy, the
	 * PM_SUSPEND/PM_RESUME is used. So, the following few lines
	 * of code will be there until Gypsy machines are supported.
	 */

	if (pm_create_components(dip, 1) == DDI_SUCCESS) {
		pm_set_normal_power(dip, 0, 1);
	} else {
		goto fail;
	}

#ifdef ESP_KSTATS
	/*
	 * kstats to measure scsi bus busy time
	 */
	if (esp_do_bus_kstats) {
		if ((esp->e_scsi_bus_stats = kstat_create("esp-scsi-bus",
		    instance, NULL, "disk", KSTAT_TYPE_IO, 1,
		    KSTAT_FLAG_PERSISTENT)) != NULL) {
			esp->e_scsi_bus_stats->ks_lock = ESP_MUTEX;
			kstat_install(esp->e_scsi_bus_stats);
		}
	}
#endif /* ESP_KSTATS */

	/*
	 * create a possibly shared callback thread which will empty the
	 * callback queue
	 */
	mutex_enter(&esp_global_mutex);
	esp_create_callback_thread(esp);
	mutex_exit(&esp_global_mutex);

	/*
	 * create kmem cache for packets
	 */
	(void) sprintf(buf, "esp%d_cache", instance);
	esp->e_kmem_cache = kmem_cache_create(buf,
		ESP_CMD_SIZE, 8,
		esp_kmem_cache_constructor, esp_kmem_cache_destructor,
		NULL, (void *)esp, NULL, 0);
	if (esp->e_kmem_cache == NULL) {
		cmn_err(CE_WARN, "esp: cannot create kmem_cache");
		goto fail;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	cmn_err(CE_WARN, "esp%d: cannot attach", instance);
	if (esp) {
		struct esp *next, *prev;

		/* remove this esp from the linked list */
		rw_enter(&esp_global_rwlock, RW_WRITER);
		for (prev = NULL,  next = esp_softc; next != NULL;
		    prev = next, next = next->e_next) {
			if (next == esp) {
				if (next == esp_softc) {
					esp_softc = esp->e_next;
				} else {
					prev->e_next = esp->e_next;
				}
				if (esp_tail == esp) {
					esp_tail = prev;
				}
				break;
			}
		}
		rw_exit(&esp_global_rwlock);

		if (mutex_initialized) {
			mutex_destroy(&esp->e_startQ_mutex);
			mutex_destroy(ESP_MUTEX);
		}
		if (esp->e_intr_kstat) {
			kstat_delete(esp->e_intr_kstat);
		}
		if (add_intr_done) {
			ddi_remove_intr(dip, (uint_t)0, esp->e_iblock);
		}
		if (tran) {
			scsi_hba_tran_free(tran);
		}
		if (esp->e_kmem_cache) {
			kmem_cache_destroy(esp->e_kmem_cache);
		}
		if (esp->e_cmdarea) {
			if (bound_handle) {
				(void) ddi_dma_unbind_handle(esp->e_dmahandle);
			}
			ddi_dma_mem_free(&esp->e_cmdarea_acc_handle);
		}
		if (esp->e_dmahandle) {
			ddi_dma_free_handle(&esp->e_dmahandle);
		}
	}

	if (dmar)
		dma_free((struct dmaga *)dmar);
unmap:
	if (esp->e_regs_acc_handle)
		ddi_regs_map_free(&esp->e_regs_acc_handle);

exit:
	if (esp) {
		ddi_soft_state_free(esp_state, instance);
	}

	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
esp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct esp	*esp, *nesp;
	scsi_hba_tran_t		*tran;

	switch (cmd) {
	case DDI_DETACH:
		return (esp_dr_detach(dip));

	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		if ((tran = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		esp = TRAN2ESP(tran);
		if (!esp) {
			return (DDI_FAILURE);
		}
		mutex_enter(ESP_MUTEX);

		esp->e_suspended = 1;
		esp_watchdog_running = 0;

		if (esp->e_ncmds) {
			(void) esp_reset_bus(esp);
			(void) esp_dopoll(esp, SHORT_POLL_TIMEOUT);
		}
		/*
		 * In the current implementation of esp power management, the
		 * SCSI active terminators are turned off and so the bus
		 * signals can wander everywhere - including generating false
		 * interrupts, so they need to be disabled.  This should also
		 * be done for a full SUSPEND in theory, but since CPR writes
		 * out the state file....
		 */
		if (cmd == DDI_PM_SUSPEND) {
			esp->e_dmaga_csr &= ~DMAGA_INTEN;
			esp->e_dma->dmaga_csr = esp->e_dmaga_csr;
		}
		mutex_exit(ESP_MUTEX);

		if (esp->e_restart_cmd_timeid) {
			(void) untimeout(esp->e_restart_cmd_timeid);
			esp->e_restart_cmd_timeid = 0;
		}

		/* Last esp? */
		rw_enter(&esp_global_rwlock, RW_WRITER);
		for (nesp = esp_softc; nesp; nesp = nesp->e_next) {
			if (!nesp->e_suspended) {
				rw_exit(&esp_global_rwlock);
				return (DDI_SUCCESS);
			}
		}
		rw_exit(&esp_global_rwlock);

		mutex_enter(&esp_global_mutex);
		if (esp_timeout_initted) {
			timeout_id_t tid = esp_timeout_id;
			esp_timeout_initted = 0;
			esp_timeout_id = 0;		/* don't resched */
			mutex_exit(&esp_global_mutex);
			(void) untimeout(tid);
			mutex_enter(&esp_global_mutex);
		}

		if (esp_reset_watch) {
			mutex_exit(&esp_global_mutex);
			(void) untimeout(esp_reset_watch);
			mutex_enter(&esp_global_mutex);
			esp_reset_watch = 0;
		}
		mutex_exit(&esp_global_mutex);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
	_NOTE(NOT_REACHED)
	/* NOTREACHED */
}

static int
esp_dr_detach(dev_info_t *dev)
{
	struct esp	*esp, *e;
	scsi_hba_tran_t		*tran;
	int			i, j;

	if ((tran = ddi_get_driver_private(dev)) == NULL)
		return (DDI_FAILURE);

	esp = TRAN2ESP(tran);
	if (!esp) {
		return (DDI_FAILURE);
	}

	/*
	 * Force interrupts OFF
	 */
	esp->e_dmaga_csr &= ~DMAGA_INTEN;
	esp->e_dma->dmaga_csr = esp->e_dmaga_csr;
	ddi_remove_intr(dev, (uint_t)0, esp->e_iblock);

#ifdef ESP_KSTATS
	/*
	 * Remove kstats if any i.e., if pointer non-NULL.
	 * Note: pointer NOT explicitly NULL'ed. But buffer zalloc'd
	 */
	if (esp->e_scsi_bus_stats != (struct kstat *)NULL) {
		kmutex_t *lp = esp->e_scsi_bus_stats->ks_lock;
		if ((lp != (kmutex_t *)NULL) && !MUTEX_HELD(lp))
			kstat_delete(esp->e_scsi_bus_stats);
	}
#endif /* ESP_KSTATS */

	/*
	 * deallocate reset notify callback list
	 */
	scsi_hba_reset_notify_tear_down(esp->e_reset_notify_listf);

	/*
	 * Remove device instance from the global linked list
	 */
	rw_enter(&esp_global_rwlock, RW_WRITER);

	if (esp_softc == esp) {
		e = esp_softc = esp->e_next;
	} else {
		for (e = esp_softc; e != (struct esp *)NULL; e = e->e_next) {
			if (e->e_next == esp) {
				e->e_next = esp->e_next;
				break;
			}
		}
		if (e == (struct esp *)NULL) {
			/*
			 * Instance not in softc list. Since the
			 * instance is not there in softc list, don't
			 * enable interrupts, the instance is effectively
			 * unusable.
			 */
			cmn_err(CE_WARN, "esp_dr_detach: esp instance not"
				" in softc list!");
			rw_exit(&esp_global_rwlock);
			return (DDI_FAILURE);
		}
	}

	if (esp_tail == esp)
		esp_tail = e;

	rw_exit(&esp_global_rwlock);

	if (esp->e_intr_kstat)
		kstat_delete(esp->e_intr_kstat);

	/*
	 * disallow timeout thread rescheduling
	 */
	mutex_enter(&esp_global_mutex);
	esp->e_flags |= ESP_FLG_NOTIMEOUTS;
	mutex_exit(&esp_global_mutex);

	/*
	 * last esp? ... if active, CANCEL watch threads.
	 */
	if (esp_softc == (struct esp *)NULL) {
		mutex_enter(&esp_global_mutex);
		if (esp_timeout_initted) {
			timeout_id_t tid = esp_timeout_id;
			esp_timeout_initted = 0;
			esp_timeout_id = 0;		/* don't resched */
			mutex_exit(&esp_global_mutex);
			(void) untimeout(tid);
			mutex_enter(&esp_global_mutex);
		}

		if (esp_reset_watch) {
			mutex_exit(&esp_global_mutex);
			(void) untimeout(esp_reset_watch);
			mutex_enter(&esp_global_mutex);
			esp_reset_watch = 0;
		}
		mutex_exit(&esp_global_mutex);
	}

	if (esp->e_restart_cmd_timeid) {
		(void) untimeout(esp->e_restart_cmd_timeid);
		esp->e_restart_cmd_timeid = 0;
	}

	/*
	 * destroy outstanding ARQ pkts
	 */
	for (i = 0; i < NTARGETS; i++) {
		for (j = 0; j < NLUNS_PER_TARGET; j++) {
			int slot = i * NLUNS_PER_TARGET | j;
			if (esp->e_arq_pkt[slot]) {
				struct scsi_address	sa;
				sa.a_hba_tran = NULL;	/* not used */
				sa.a_target = (ushort_t)i;
				sa.a_lun = (uchar_t)j;
				(void) esp_create_arq_pkt(esp, &sa, 0);
			}
		}
	}

	/*
	 * destroy any outstanding tagged command info
	 */
	for (i = 0; i < N_SLOTS; i++) {
		struct t_slots *active = esp->e_tagQ[i];
		if (active) {
			for (j = 0; j < NTAGS; j++) {
				struct esp_cmd *sp = active->t_slot[j];
				if (sp) {
					struct scsi_pkt *pkt = &sp->cmd_pkt;
					if (pkt) {
						esp_scsi_destroy_pkt(
						    &pkt->pkt_address, pkt);
					}
					/* sp freed in esp_scsi_destroy_pkt */
					active->t_slot[j] = NULL;
				}
			}
			kmem_free(active, sizeof (struct t_slots));
			esp->e_tagQ[i] = NULL;
		}
		ASSERT(esp->e_tcmds[i] == 0);
	}

	/*
	 * Remove device MT locks
	 */
	mutex_destroy(&esp->e_startQ_mutex);
	mutex_destroy(ESP_MUTEX);

	/*
	 * Release miscellaneous device resources
	 */
	if (esp->e_kmem_cache) {
		kmem_cache_destroy(esp->e_kmem_cache);
	}

	if (esp->e_cmdarea != (uchar_t *)NULL) {
		(void) ddi_dma_unbind_handle(esp->e_dmahandle);
		ddi_dma_mem_free(&esp->e_cmdarea_acc_handle);
	}

	if (esp->e_dmahandle != NULL)
		ddi_dma_free_handle(&esp->e_dmahandle);

	if (esp->e_dma != (struct dmaga *)NULL)
		dma_free((struct dmaga *)esp->e_dma);

	ddi_regs_map_free(&esp->e_regs_acc_handle);

	esp_destroy_callback_thread(esp);

	/*
	 * Process shared callback resources, as required.
	 * Update callback_thread bookkeeping.
	 */
	ddi_soft_state_free(esp_state, ddi_get_instance(dev));

	/*
	 * Remove properties created during attach()
	 */
	ddi_prop_remove_all(dev);

	/*
	 * Delete the DMA limits, transport vectors and remove the device
	 * links to the scsi_transport layer.
	 *	-- ddi_set_driver_private(dip, NULL)
	 */
	(void) scsi_hba_detach(dev);

	/*
	 * Free the scsi_transport structure for this device.
	 */
	scsi_hba_tran_free(tran);

	return (DDI_SUCCESS);
}

/*
 * Hardware and Software internal reset routines
 */
static void
esp_determine_chip_type(struct esp *esp)
{
	int i;
	uchar_t clock_conv;
	clock_t ticks;
	volatile struct espreg *ep = esp->e_reg;

	if (esp->e_scsi_options & SCSI_OPTIONS_PARITY)
		esp->e_espconf |= ESP_CONF_PAREN;

	/*
	 * Determine clock frequency of attached ESP chip.
	 */
	i = ddi_prop_get_int(DDI_DEV_T_ANY, esp->e_dev, 0, prop_cfreq, -1);

	/*
	 * Valid clock freqs. are between 10 and 40 MHz.  Otherwise
	 * presume 20 MHz. and complain.  (Notice, that we wrap to
	 * zero at 40 MHz.  Ick!)  This test should NEVER fail!
	 *
	 *	freq (MHz)	clock conversion factor
	 *	10		2
	 *	10.01-15	3
	 *	15.01-20	4
	 *	20.01-25	5
	 *	25.01-30	6
	 *	30.01-35	7
	 *	35.01-40	8 (0)
	 */
	if (i > FIVE_MEG) {
		clock_conv = (i + FIVE_MEG - 1)/ FIVE_MEG;
	} else {
		clock_conv = 0;
	}
	if (clock_conv < CLOCK_10MHZ || clock_conv > CLOCK_40MHZ) {
		esplog(esp, CE_WARN,
		    "Bad clock frequency- setting 20mhz, asynchronous mode");
		esp->e_weak = 0xff;
		clock_conv = CLOCK_20MHZ;
		i = TWENTY_MEG;
	}

	esp->e_clock_conv = clock_conv;
	esp->e_clock_cycle = CLOCK_PERIOD(i);
	ticks = ESP_CLOCK_TICK(esp);
	esp->e_stval = ESP_CLOCK_TIMEOUT(ticks, esp_selection_timeout);

	IPRINTF5("%d mhz, clock_conv %d, clock_cycle %d, ticks %ld, stval %d\n",
		i, esp->e_clock_conv, esp->e_clock_cycle,
		ticks, esp->e_stval);

	ep->esp_conf2 = 0;
	ep->esp_conf2 = 0xa;
	if ((ep->esp_conf2 & 0xf) == 0xa) {
		esp->e_espconf2 = (uchar_t)ESP_CONF2_SCSI2;
		ep->esp_conf3 = 0;
		ep->esp_conf3 = 5;
		if (ep->esp_conf3 == 0x5) {
			for (i = 0; i < NTARGETS; i++) {
				esp->e_espconf3[i] = 0;
			}
			if (clock_conv > CLOCK_25MHZ) {
				/*
				 * do not enable FENABLE when using
				 * stacked cmds
				 * esp->e_espconf2 |= ESP_CONF2_FENABLE;
				 */
				ep->esp_conf2 = esp->e_espconf2;
				esp->e_type = FAST;
				IPRINTF("found FAST\n");
			} else {
				ep->esp_conf2 = esp->e_espconf2;
				esp->e_type = ESP236;
			}
			ep->esp_conf3 = 0;
		} else {
			ep->esp_conf2 = esp->e_espconf2;
			esp->e_type = ESP100A;
		}
	} else {
		esp->e_type = ESP100;
	}

	for (i = 0; i < NTARGETS; i++) {
		if (esp->e_target_scsi_options[i] & SCSI_OPTIONS_FAST) {
			esp->e_default_period[i] = (uchar_t)
			    MIN_SYNC_PERIOD(esp);
		} else {
			esp->e_default_period[i] =
			    (uchar_t)CONVERT_PERIOD(DEFAULT_SYNC_PERIOD);
		}
	}

	New_state(esp, ACTS_RESET);

	/*
	 * Avoid resetting the scsi bus since this causes a few seconds
	 * delay per esp in boot and also causes busy conditions in some
	 * tape devices.
	 * we assume that with FAS devices, we probably have OBP 2.0 or
	 * higher which resets the bus before booting.
	 * worst case, we hang during the first probe and reset then
	 */
	if ((esp->e_type == FAST) && (esp->e_weak == 0)) {
		esp_internal_reset(esp,
			ESP_RESET_SOFTC|ESP_RESET_ESP|ESP_RESET_DMA);
	} else {
		esp_internal_reset(esp, ESP_RESET_ALL);
	}
}

static void
esp_flush_fifo(struct esp *esp)
{
	Esp_cmd(esp, CMD_FLUSH);

	if (esp->e_options & ESP_OPT_SLOW_FIFO_FLUSH) {
		int i;
		for (i = 0; i < 1000; i++) {
			if (FIFO_CNT(esp->e_reg) == 0) {
				break;
			}
			drv_usecwait(1);
		}
		if (i >= 1000) {
			esplog(esp, CE_WARN, "fifo didn't flush\n");
		}
	}
}


static void
esp_internal_reset(struct esp *esp, int reset_action)
{
	if (reset_action & ESP_RESET_HW) {
		esp_hw_reset(esp, reset_action);
	}

	if (reset_action & ESP_RESET_SOFTC) {
		esp->e_last_slot = esp->e_cur_slot;
		esp->e_cur_slot = UNDEFINED;
		bzero(esp->e_slots, (sizeof (struct esp_cmd *)) * N_SLOTS);
		bzero(esp->e_offset, NTARGETS * (sizeof (uchar_t)));
		bzero(esp->e_period, NTARGETS * (sizeof (uchar_t)));
		esp->e_sync_known = esp->e_omsglen = 0;
		esp->e_cur_msgout[0] = esp->e_last_msgout =
		    esp->e_last_msgin = INVALID_MSG;
		esp->e_espconf3_last = esp->e_offset_last =
		    esp->e_period_last = (uchar_t)-1;

		/*
		 * esp->e_weak && esp->e_nodisc && ncmds && ndiscs  are
		 * preserved across softc resets.
		 */
		New_state(esp, STATE_FREE);
	}
	LOG_STATE(esp, ACTS_RESET, esp->e_stat, -1, reset_action);
}

static void
esp_hw_reset(struct esp *esp, int action)
{
	volatile struct espreg *ep = esp->e_reg;
	volatile struct dmaga *dmar = esp->e_dma;
	uchar_t junk, i;
	int sbus_reruns;

	/*
	 * never reset the dmaga while a request pending; this
	 * may cause a hang in xbox if there was a rerun pending
	 */
	if (action & ESP_RESET_SCSIBUS) {
		Esp_cmd(esp, CMD_RESET_SCSI);
		if (esp_watchdog_running && !panicstr) {
			int i;

			esp_set_throttles(esp, 0, N_SLOTS, HOLD_THROTTLE);
			for (i = 0; i < NTARGETS; i++) {
				esp->e_reset_delay[i] =
				    esp->e_scsi_reset_delay;
			}
			esp_start_watch_reset_delay(esp);
		} else {
			drv_usecwait(esp->e_scsi_reset_delay * 1000);
		}
		ESP_FLUSH_DMA(esp);
	}

	if (action & ESP_RESET_DMA) {
		int burstsizes = esp->e_dma_attr->dma_attr_burstsizes;
		burstsizes &= (ddi_dma_burstsizes(esp->e_dmahandle) &
			esp_burst_sizes_limit);

		ESP_FLUSH_DMA(esp);
		dmar->dmaga_csr = DMAGA_RESET;
		dmar->dmaga_csr &= ~DMAGA_RESET; /* clear it */

		switch (ESP_DMAGA_REV(esp)) {
		case ESC1_REV1:
			sbus_reruns =
			    ddi_prop_exists(DDI_DEV_T_ANY, esp->e_dev, 0,
			    "reruns");
			if (sbus_reruns) {
				esp->e_options |= ESP_OPT_SBUS_RERUNS;
			}
			IPRINTF2("DMA Rev: 0x%x with %s\n", ESP_DMAGA_REV(esp),
			    sbus_reruns ? "SBus Reruns" : "No SBus Reruns");

			if (!(burstsizes & BURST32)) {
				IPRINTF("16 byte burstsize\n");
				DMAESC_SETBURST16(dmar);
			}
			dmar->dmaga_csr |= DMAESC_EN_ADD;
			break;

		case DMA_REV2:
			if (esp->e_type != ESP100)
				dmar->dmaga_csr |= DMAGA_TURBO;
			break;

		case DMA_REV3:
			dmar->dmaga_csr &= ~DMAGA_TURBO;
			dmar->dmaga_csr |= DMAGA_TWO_CYCLE;

			if (burstsizes & BURST32) {
				IPRINTF("32 byte burstsize\n");
				DMA2_SETBURST32(dmar);
			}
			break;

		default:
			break;
		}
	}

	dmar->dmaga_csr = esp->e_dmaga_csr = dmar->dmaga_csr | DMAGA_INTEN;

	if (action & ESP_RESET_ESP) {
		/*
		 * according to Emulex, 2 NOPs with DMA are required here
		 * (essential for FAS101; id_code is unreliable if we don't
		 * do this)
		 */
		ESP_FLUSH_DMA(esp);
		Esp_cmd(esp, CMD_RESET_ESP);	/* hard-reset ESP chip */
		Esp_cmd(esp, CMD_NOP | CMD_DMA);
		Esp_cmd(esp, CMD_NOP | CMD_DMA);

		/*
		 * Re-load chip configurations
		 */
		ep->esp_clock_conv = esp->e_clock_conv & CLOCK_MASK;
		ep->esp_timeout = esp->e_stval;
		ep->esp_sync_period = 0;
		ep->esp_sync_offset = 0;

		/*
		 * enable default configurations
		 */
		if (esp->e_type == FAST) {
			uchar_t fcode;

			esp->e_idcode = ep->esp_id_code;
			fcode =
			    (uchar_t)(ep->esp_id_code & ESP_FCODE_MASK)>>
			    (uchar_t)3;
			if (fcode == ESP_FAS236) {
				esp->e_type = FAS236;
			} else {
				esp->e_type = FAS100A;
			}
			IPRINTF2("Family code %d, revision %d\n",
			    fcode, (esp->e_idcode & ESP_REV_MASK));
		}

		ep->esp_conf = esp->e_espconf;
		switch (esp->e_type) {
		case FAS236:
			/*
			 * used on DSBE, FSBE, galaxies
			 */
			IPRINTF("type is FAS236\n");
			for (i = 0; i < NTARGETS; i++) {
				esp->e_espconf3[i] |= ESP_CONF3_236_FASTCLK;
			}
			ep->esp_conf3 = esp->e_espconf3[0];
			esp->e_espconf3_fastscsi = ESP_CONF3_236_FASTSCSI;
			ep->esp_conf2 = esp->e_espconf2;

			/*
			 * check if differential scsi bus; if so then no
			 * req/ack delay desired
			 */
			if (ddi_prop_get_int(DDI_DEV_T_ANY, esp->e_dev,
			    DDI_PROP_DONTPASS, "differential", 0)) {
				IPRINTF("differential scsibus\n");
				esp->e_req_ack_delay = 0;
				esp->e_options |= ESP_OPT_DIFFERENTIAL;
			} else {
				esp->e_req_ack_delay =
				    DEFAULT_REQ_ACK_DELAY_236;
			}
			if ((uchar_t)(ep->esp_id_code & ESP_REV_MASK)
			    > (uchar_t)2) {
				IPRINTF1("FAS236 rev=%x Stack_cmds DISABLED\n",
				    (uchar_t)(ep->esp_id_code & ESP_REV_MASK));
				esp->e_options |= ESP_OPT_DMA_OUT_TAG
				    | ESP_OPT_FAS;
			} else {
				IPRINTF1("FAS236 rev=%x Stack_cmds ENABLED\n",
				    (uchar_t)(ep->esp_id_code & ESP_REV_MASK));
				esp->e_options |= ESP_OPT_DMA_OUT_TAG
				    | ESP_OPT_FAS | ESP_OPT_STACKED_CMDS;
			}
			break;

		case FAS100A:
			/*
			 * used on all desktop sun4m machines (macio)
			 */
			IPRINTF("type is FAS100A or 101A\n");
			for (i = 0; i < NTARGETS; i++) {
				esp->e_espconf3[i] |= ESP_CONF3_100A_FASTCLK;
			}
			ep->esp_conf3 = esp->e_espconf3[0];
			esp->e_espconf3_fastscsi = ESP_CONF3_100A_FASTSCSI;
			ep->esp_conf2 = esp->e_espconf2;
			esp->e_req_ack_delay = DEFAULT_REQ_ACK_DELAY_101;
			esp->e_options |= ESP_OPT_DMA_OUT_TAG | ESP_OPT_FAS |
				ESP_OPT_ACCEPT_STEP567;
			break;

		case ESP236:
			/*
			 * used on galaxies, SBE
			 */
			IPRINTF("type is ESP236\n");
			ep->esp_conf2 = esp->e_espconf2;
			ep->esp_conf3 = esp->e_espconf3[0];
			esp->e_options |= ESP_OPT_DMA_OUT_TAG |
						ESP_OPT_SLOW_FIFO_FLUSH;
			break;

		case ESP100A:
			/*
			 * used on SS2, IPX, sport8
			 */
			IPRINTF("type is ESP100A\n");
			ep->esp_conf2 = esp->e_espconf2;
			esp->e_options |= ESP_OPT_DMA_OUT_TAG |
			    ESP_OPT_MASK_OFF_STAT |
			    ESP_OPT_ACCEPT_STEP567;
			break;

		case ESP100:
			/*
			 * used on SS1, SS1+, IPC
			 */
			IPRINTF("type is ESP100\n");
			IPRINTF("disable sync mode\n");
			esp->e_weak = 0xff;
			esp->e_options |= ESP_OPT_MASK_OFF_STAT;
			break;

		default:
			IPRINTF("type is ???\n");
			break;
		}

		/*
		 * look up esp-options property
		 */
		esp->e_options = ddi_prop_get_int(DDI_DEV_T_ANY,
			esp->e_dev, 0, "esp-options", esp->e_options);

		esplog(esp, CE_NOTE, "?esp-options=0x%x\n", esp->e_options);

		/*
		 * Just in case...
		 * clear interrupt
		 */
		junk = ep->esp_intr;

		IPRINTF1("clock conversion = %x\n", esp->e_clock_conv);
		IPRINTF2("conf = %x (%x)\n", esp->e_espconf, ep->esp_conf);
		if (esp->e_type > ESP100) {
			IPRINTF2("conf2 = %x (%x)\n",
			    esp->e_espconf2, ep->esp_conf2);
		}
		if (esp->e_type > ESP100A) {
			EPRINTF1("conf3=%x (read back)\n", ep->esp_conf3);
			EPRINTF4("conf3 (for target 0 - 3) = %x %x %x %x\n",
			    esp->e_espconf3[0], esp->e_espconf3[1],
			    esp->e_espconf3[2], esp->e_espconf3[3]);
			EPRINTF3("conf3 (for target 4 - 6) = %x %x %x\n",
			    esp->e_espconf3[4],
			    esp->e_espconf3[5], esp->e_espconf3[6]);
			EPRINTF2("req_ack_delay (0x%p) = %x\n",
			    (void *)&esp->e_req_ack_delay,
			    esp->e_req_ack_delay);

		}
	}

#ifdef	lint
	junk = junk;
#endif	/* lint */
}

/*
 * create a thread that performs the callbacks and init associated cv and mutex
 *
 * callback tunables:
 */
static int esp_n_esps_per_callback_thread = 4;
static uchar_t esp_max_spawn = 2;	/* max of 2 extra threads for 4 esps */
static uchar_t esp_cb_now_qlen = 5;
static int esp_hi_cb_load = 50;		/* high watermark */
static int esp_lo_cb_load = 2;		/* low watermark */
static int esp_cb_load_count = 25;

static int esp_n_callback_threads = 0;
static struct callback_info  *last_esp_callback_info;

static void
esp_create_callback_thread(struct esp *esp)
{
	ASSERT(mutex_owned(&esp_global_mutex));
	ASSERT(esp->e_callback_info == NULL);

	if ((esp_n_esps++ % esp_n_esps_per_callback_thread) == 0) {
		kthread_t *t;
		struct callback_info  *cb_info;

		/*
		 * create another thread
		 */
		IPRINTF1("create callback thread %d\n", esp_n_callback_threads);

		cb_info = kmem_zalloc(sizeof (struct callback_info), KM_SLEEP);

		cv_init(&cb_info->c_cv, NULL, CV_DRIVER, NULL);
		cv_init(&cb_info->c_cvd, NULL, CV_DRIVER, NULL);

		mutex_init(&cb_info->c_mutex, NULL, MUTEX_DRIVER,
		    esp->e_iblock);

		cb_info->c_id = esp_n_callback_threads++;
		if (last_esp_callback_info) {
			last_esp_callback_info->c_next = cb_info;
		}
		last_esp_callback_info = esp->e_callback_info = cb_info;

		t = thread_create(NULL, 0, esp_callback, esp, 0, &p0,
		    TS_RUN, v.v_maxsyspri - 2);

		cb_info->c_thread = t;
		cb_info->c_spawned = esp_max_spawn;
		cb_info->c_cb_now_qlen = esp_cb_now_qlen;
	} else {
		ASSERT(last_esp_callback_info != NULL);
		IPRINTF1("sharing callback thread %d\n",
		    last_esp_callback_info->c_id);
		esp->e_callback_info = last_esp_callback_info;
	}
}

static void
esp_destroy_callback_thread(struct esp *esp)
{
	struct esp	*e;

	ASSERT(esp->e_callback_info != NULL);

	/*
	 * Remove callback
	 *
	 * We have to see if we are the last one using this cb thread
	 * before deleting it.
	 * Check the list for others referencing this cb.  We are off
	 * the list, so finding one other reference indicates shared.
	 */
	rw_enter(&esp_global_rwlock, RW_READER);
	for (e = esp_softc; e != (struct esp *)NULL; e = e->e_next) {
		if (e->e_callback_info == esp->e_callback_info) {
			break;
		}
	}
	rw_exit(&esp_global_rwlock);

	/*
	 * we couldn't find another esp sharing this cb
	 */
	if (!e) {
		struct callback_info	*ci = esp->e_callback_info;
		struct callback_info	*tci, **pci;

	IPRINTF2("esp_destroy_callback_thread: "
		    "killing callback 0x%p thread %d\n",
		    (void *)esp->e_callback_info, ci->c_id);
		mutex_enter(&ci->c_mutex);
		ci->c_exit = 1;			/* die */

		IPRINTF2("esp_destroy_callback_thread: spawned %d max %d\n",
		    ci->c_spawned, esp_max_spawn);
		while (ci->c_spawned <= (uchar_t)esp_max_spawn) {
			IPRINTF1("esp_destroy_callback_thread:%p wakeup\n",
			    (void *)ci);
			cv_broadcast(&ci->c_cv);	/* might be snoozing */
			cv_wait(&ci->c_cvd, &ci->c_mutex);
		}

		mutex_exit(&ci->c_mutex);
		IPRINTF("esp_destroy_callback_thread: all threads killed\n");

		mutex_enter(&esp_global_mutex);
		for (pci = &last_esp_callback_info;
		    (tci = *pci) != NULL; pci = &tci->c_next) {
			if (tci == ci) {
				/* take it out of list */
				*pci = tci->c_next;
				/* destroy it */
				cv_destroy(&ci->c_cv);
				cv_destroy(&ci->c_cvd);
				mutex_destroy(&ci->c_mutex);
				kmem_free(ci, sizeof (struct callback_info));
			IPRINTF1("esp_destroy_callback_thread:%p freed\n",
				    (void *)ci);
				esp->e_callback_info = NULL;
				break;
			}
		}
	} else {
		mutex_enter(&esp_global_mutex);
		IPRINTF1("esp_destroy_callback_thread: callback 0x%p shared\n",
		    (void *)esp->e_callback_info);
	}

	esp_n_esps--;
	mutex_exit(&esp_global_mutex);
}

/*
 * this is the function executed by the callback thread; it
 * empties the callback queue by calling the completion function of each
 * packet; note the release of the mutex before
 * calling the completion function
 * the cv_wait is at the end of the loop because by the time this thread
 * comes alive, there is already work to do.
 */
void
esp_wakeup_callback_thread(struct callback_info *cb_info)
{
	struct esp_cmd *sp;

	mutex_enter(&cb_info->c_mutex);
	if (cb_info->c_qlen) {
		/*
		 * callback now?
		 */
		if ((cb_info->c_qlen < cb_info->c_cb_now_qlen) || panicstr) {
			while (cb_info->c_qf) {
				sp = cb_info->c_qf;
				cb_info->c_qf = sp->cmd_forw;
				if (cb_info->c_qb == sp) {
					cb_info->c_qb = NULL;
				}
				cb_info->c_qlen--;
				mutex_exit(&cb_info->c_mutex);
				(*sp->cmd_pkt.pkt_comp)(&sp->cmd_pkt);
				mutex_enter(&cb_info->c_mutex);
			}
		/*
		 * if the queue is too long then do
		 * a wakeup for *all* callback threads
		 */
		} else if (cb_info->c_signal_needed) {
			cv_broadcast(&cb_info->c_cv);
		}
	}
	cb_info->c_signal_needed = 0;
	mutex_exit(&cb_info->c_mutex);
}

/*
 * Warlock has a problem when we use different locks
 * on the same type of structure in different contexts.
 * We use callb_cpr_t in both scsi_watch and esp_callback threads.
 * we use different mutex's in different threads. And
 * this is not acceptable to warlock. To avoid this
 * problem we use the same name for the mutex in
 * both scsi_watch & esp_callback. when __lock_lint is not defined
 * esp_callback uses the mutex on the stack and in scsi_watch
 * a static variable. But when __lock_lint is defined
 * we make a mutex which is global in esp_callback and
 * a external mutex for scsi_watch.
 */
#ifdef __lock_lint
kmutex_t cpr_mutex;
#endif

static void
esp_callback(struct esp *esp)
{
	struct esp_cmd *sp;
	struct callback_info *cb_info = esp->e_callback_info;
	int serviced = 0;
	int wakeups = 0;
	int id, load;
	int hiload = 0;
	int loload = 0;
	callb_cpr_t cpr_info;
#ifndef	__lock_lint
	kmutex_t cpr_mutex;
#endif
	int n = 0;

	_NOTE(MUTEX_PROTECTS_DATA(cpr_mutex, cpr_info))
	_NOTE(NO_COMPETING_THREADS_NOW);
	mutex_init(&cpr_mutex, NULL, MUTEX_DRIVER, esp->e_iblock);
	CALLB_CPR_INIT(&cpr_info,
		&cpr_mutex, callb_generic_cpr, "esp_callback");
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	mutex_enter(&cb_info->c_mutex);

	id = cb_info->c_count++;
#ifdef ESP_PERF
	cmn_err(CE_CONT,
	    "esp cb%d.%d thread starting\n", cb_info->c_id, id);
#endif

	for (;;) {
		TRACE_0(TR_FAC_SCSI, TR_ESP_CALLBACK_START,
			"esp_callback_start");
		while (cb_info->c_qf) {
			sp = cb_info->c_qf;
			cb_info->c_qf = sp->cmd_forw;
			if (cb_info->c_qb == sp) {
				cb_info->c_qb = NULL;
			}
			cb_info->c_qlen--;
			ASSERT(sp->cmd_pkt.pkt_comp != 0);
			serviced++;
			mutex_exit(&cb_info->c_mutex);
			(*sp->cmd_pkt.pkt_comp)(&sp->cmd_pkt);
			mutex_enter(&cb_info->c_mutex);
			n++;
		}

		/*
		 * check load
		 * if the load is consistently too high, create another
		 * thread to help out
		 * if the load is consistently too low, exit thread
		 * If the load is so high that we never exit the
		 * above while loop then esp_n_esps_per_callback_thread is
		 * too high; we are not going to deal with that condition
		 * here
		 */
		if (wakeups) {
			load  = (serviced + wakeups - 1)/wakeups;
		} else {
			load = 0;
		}

		if (cb_info->c_exit) {
			EPRINTF2("esp_callback: thread %d 0x%p exit set\n",
			    cb_info->c_id, (void *)cb_info);
			cb_info->c_spawned++;
			cv_broadcast(&cb_info->c_cvd);
			mutex_exit(&cb_info->c_mutex);
			break;
		} else if (load > esp_hi_cb_load) {
			/*
			 * load is too high
			 */
			if ((hiload++ > esp_cb_load_count) &&
			    (cb_info->c_spawned > 0)) {
				/*
				 * create another thread
				 */
				(void) thread_create(NULL, 0, esp_callback, esp,
				    0, &p0, TS_RUN, v.v_maxsyspri - 2);
				serviced = wakeups = 0;
				cb_info->c_spawned--;
				/*
				 * from now on do not allow immediate
				 * callback
				 */
				cb_info->c_cb_now_qlen = 0;
				hiload = loload = 0;
			}
		} else if (load < esp_lo_cb_load) {
			/*
			 * load is too low
			 */
			if (loload++ > esp_cb_load_count) {
				/*
				 * if this is not the first thread, exit
				 */
				if (id != 0) {
					cb_info->c_spawned++;
					mutex_exit(&cb_info->c_mutex);
					/*
					 * exit while loop and esp_callback
					 * function which destroys the
					 * thread
					 */
					break;
				} else {
					/*
					 * if only 1 thread left then set
					 * back cb_now_qlen
					 */
					if (cb_info->c_spawned ==
					    esp_max_spawn) {
						cb_info->c_cb_now_qlen =
						    esp_cb_now_qlen;
					}
				}
				hiload = loload = 0;
			}
		} else {
			/*
			 * always use deferred callback from now on
			 */
			cb_info->c_cb_now_qlen = 0;
			hiload = loload = 0;
		}

		TRACE_1(TR_FAC_SCSI, TR_ESP_CALLBACK_END,
			"esp_callback_end: (%d)", serviced);

		/*
		 * reset serviced and wakeups; if these numbers get too high
		 * then we don't adjust to bursts very well
		 */
		if (serviced >= 20000) {
#ifdef ESP_PERF
			cmn_err(CE_CONT,
	    "esp cb%d.%d: svced=%d, wkup=%d, ld=%d, spwn=%d, now_qlen=%d\n",
			    cb_info->c_id, id, serviced, wakeups,
			    load, cb_info->c_spawned,
			    cb_info->c_cb_now_qlen);
#endif
			serviced = 0;
			wakeups = 0;
		}

		mutex_enter(&cpr_mutex);
		CALLB_CPR_SAFE_BEGIN(&cpr_info);
		mutex_exit(&cpr_mutex);

		cv_wait(&cb_info->c_cv, &cb_info->c_mutex);

		mutex_exit(&cb_info->c_mutex);
		mutex_enter(&cpr_mutex);
		CALLB_CPR_SAFE_END(&cpr_info, &cpr_mutex);
		mutex_exit(&cpr_mutex);
		mutex_enter(&cb_info->c_mutex);

		cb_info->c_signal_needed = 0;
		wakeups++;
	}

#ifdef ESP_PERF
	cmn_err(CE_CONT, "esp cb%d.%d exits\n", cb_info->c_id, id);
#endif
	TRACE_1(TR_FAC_SCSI, TR_ESP_CALLBACK_END,
		"esp_callback_end:  (%d)", n);
#ifndef __lock_lint
	mutex_enter(&cpr_mutex);
	CALLB_CPR_EXIT(&cpr_info);
#endif
	mutex_destroy(&cpr_mutex);
	thread_exit();
}

/*
 * Interface functions
 *
 * Visible to the external world via the transport structure.
 *
 * These functions have been grouped together to reduce cache misses.
 *
 */
/*ARGSUSED*/
static void
esp_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct esp_cmd *cmd = (struct esp_cmd *)pkt->pkt_ha_private;

	TRACE_0(TR_FAC_SCSI, TR_ESP_SCSI_IMPL_DMAFREE_START,
	    "esp_scsi_dmafree_start");

	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		/*
		 * Free the mapping.
		 */
		(void) ddi_dma_unbind_handle(cmd->cmd_dmahandle);
		cmd->cmd_flags ^= CFLAG_DMAVALID;
	}
	TRACE_0(TR_FAC_SCSI, TR_ESP_SCSI_IMPL_DMAFREE_END,
	    "esp_scsi_dmafree_end");
}


/*ARGSUSED*/
static void
esp_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	int i;
	struct esp_cmd *sp = (struct esp_cmd *)pkt->pkt_ha_private;

	if (sp->cmd_flags & CFLAG_DMAVALID) {
		i = ddi_dma_sync(sp->cmd_dmahandle, 0, 0,
			(sp->cmd_flags & CFLAG_DMASEND) ?
			DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
		if (i != DDI_SUCCESS) {
			cmn_err(CE_WARN, "esp: sync pkt failed");
		}
	}
}


static struct scsi_pkt *
esp_scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
	struct buf *bp, int cmdlen, int statuslen, int tgtlen,
	int flags, int (*callback)(), caddr_t arg)
{
	int kf;
	int failure = 0;
	struct esp_cmd *cmd, *new_cmd;
	struct esp *esp = ADDR2ESP(ap);
	int rval;

/* #define	ESP_TEST_EXTRN_ALLOC */
#ifdef ESP_TEST_EXTRN_ALLOC
	cmdlen *= 4; statuslen *= 4; tgtlen *= 4;
#endif
	/*
	 * If we've already allocated a pkt once,
	 * this request is for dma allocation only.
	 */
	if (pkt == NULL) {
		/*
		 * First step of esp_scsi_init_pkt:  pkt allocation
		 */
		TRACE_0(TR_FAC_SCSI, TR_ESP_SCSI_IMPL_PKTALLOC_START,
		    "esp_scsi_pktalloc_start");

		failure = 0;
		kf = (callback == SLEEP_FUNC)? KM_SLEEP: KM_NOSLEEP;

		cmd = kmem_cache_alloc(esp->e_kmem_cache, kf);

		if (cmd) {
			ddi_dma_handle_t save_dma_handle;

			save_dma_handle = cmd->cmd_dmahandle;
			bzero(cmd, ESP_CMD_SIZE);
			cmd->cmd_dmahandle = save_dma_handle;

			cmd->cmd_pkt.pkt_scbp = (opaque_t)cmd->cmd_scb;
			cmd->cmd_cdblen_alloc = cmd->cmd_cdblen =
				(uchar_t)cmdlen;
			cmd->cmd_scblen		= statuslen;
			cmd->cmd_privlen	= tgtlen;
			cmd->cmd_pkt.pkt_address = *ap;

			cmd->cmd_pkt.pkt_cdbp = (opaque_t)&cmd->cmd_cdb;
			cmd->cmd_pkt.pkt_private = cmd->cmd_pkt_private;
			cmd->cmd_pkt.pkt_ha_private = (opaque_t)cmd;
		} else {
			failure++;
		}

		if (failure || (cmdlen > sizeof (cmd->cmd_cdb)) ||
		    (tgtlen > PKT_PRIV_LEN) ||
		    (statuslen > EXTCMDS_STATUS_SIZE)) {
			if (failure == 0) {
				failure = esp_pkt_alloc_extern(esp, cmd,
				    cmdlen, tgtlen, statuslen, kf);
			}
			if (failure) {
				TRACE_0(TR_FAC_SCSI,
					TR_ESP_SCSI_IMPL_PKTALLOC_END,
					"esp_scsi_pktalloc_end");
				return (NULL);
			}
		}

		new_cmd = cmd;

		TRACE_0(TR_FAC_SCSI, TR_ESP_SCSI_IMPL_PKTALLOC_END,
			"esp_scsi_pktalloc_end");
	} else {
		cmd = (struct esp_cmd *)pkt->pkt_ha_private;
		new_cmd = NULL;
	}


	/*
	 * Second step of esp_scsi_init_pkt:  dma allocation
	 * Set up dma info
	 */
	if (bp && bp->b_bcount) {
		uint_t cmd_flags, dma_flags;
		uint_t dmacookie_count;

		TRACE_0(TR_FAC_SCSI, TR_SCSI_IMPL_DMAGET_START,
		    "esp_scsi_dmaget_start");

		cmd_flags = cmd->cmd_flags;

		if (bp->b_flags & B_READ) {
			cmd_flags &= ~CFLAG_DMASEND;
			dma_flags = DDI_DMA_READ | DDI_DMA_PARTIAL;
		} else {
			cmd_flags |= CFLAG_DMASEND;
			dma_flags = DDI_DMA_WRITE | DDI_DMA_PARTIAL;
		}
		if (flags & PKT_CONSISTENT) {
			cmd_flags |= CFLAG_CMDIOPB;
			dma_flags |= DDI_DMA_CONSISTENT;
		}

		ASSERT(cmd->cmd_dmahandle != NULL);

		rval = ddi_dma_buf_bind_handle(cmd->cmd_dmahandle, bp,
			dma_flags, callback, arg, &cmd->cmd_dmacookie,
			&dmacookie_count);
dma_failure:
		if (rval && rval != DDI_DMA_PARTIAL_MAP) {
			switch (rval) {
			case DDI_DMA_NORESOURCES:
				bioerror(bp, 0);
				break;
			case DDI_DMA_BADATTR:
			case DDI_DMA_NOMAPPING:
				bioerror(bp, EFAULT);
				break;
			case DDI_DMA_TOOBIG:
			default:
				bioerror(bp, EINVAL);
				break;
			}
			cmd->cmd_flags = cmd_flags & ~CFLAG_DMAVALID;
			if (new_cmd) {
				esp_scsi_destroy_pkt(ap, &new_cmd->cmd_pkt);
			}
			TRACE_0(TR_FAC_SCSI, TR_SCSI_IMPL_DMAGET_END,
				"esp_scsi_dmaget_end");
			return ((struct scsi_pkt *)NULL);
		}
		ASSERT(dmacookie_count == 1);
		cmd->cmd_dmacount = bp->b_bcount;
		cmd->cmd_flags = cmd_flags | CFLAG_DMAVALID;

		ASSERT(cmd->cmd_dmahandle != NULL);
		TRACE_0(TR_FAC_SCSI, TR_SCSI_IMPL_DMAGET_END,
		    "esp_scsi_dmaget_end");
	}

	return (&cmd->cmd_pkt);
}

/*
 * allocate and deallocate external space (ie. not part of esp_cmd) for
 * non-standard length cdb, pkt_private, status areas
 */
/* ARGSUSED */
static int
esp_pkt_alloc_extern(struct esp *esp, struct esp_cmd *sp,
    int cmdlen, int tgtlen, int statuslen, int kf)
{
	caddr_t cdbp, scbp, tgt;
	int failure = 0;

	tgt = cdbp = scbp = NULL;
	if (cmdlen > sizeof (sp->cmd_cdb)) {
		if ((cdbp = kmem_zalloc((size_t)cmdlen, kf)) == NULL) {
			failure++;
		} else {
			sp->cmd_pkt.pkt_cdbp = (opaque_t)cdbp;
			sp->cmd_flags |= CFLAG_CDBEXTERN;
		}
	}
	if (tgtlen > PKT_PRIV_LEN) {
		if ((tgt = kmem_zalloc(tgtlen, kf)) == NULL) {
			failure++;
		} else {
			sp->cmd_flags |= CFLAG_PRIVEXTERN;
			sp->cmd_pkt.pkt_private = tgt;
		}
	}
	if (statuslen > EXTCMDS_STATUS_SIZE) {
		if ((scbp = kmem_zalloc((size_t)statuslen, kf)) == NULL) {
			failure++;
		} else {
			sp->cmd_flags |= CFLAG_SCBEXTERN;
			sp->cmd_pkt.pkt_scbp = (opaque_t)scbp;
		}
	}
	if (failure) {
		esp_pkt_destroy_extern(esp, sp);
	}
	return (failure);
}

/* ARGSUSED */
static void
esp_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct esp_cmd *sp = (struct esp_cmd *)pkt->pkt_ha_private;
	struct esp *esp = ADDR2ESP(ap);

	/*
	 * esp_scsi_dmafree inline to speed things up
	 */
	TRACE_0(TR_FAC_SCSI, TR_ESP_SCSI_IMPL_DMAFREE_START,
	    "esp_scsi_dmafree_start");

	if (sp->cmd_flags & CFLAG_DMAVALID) {
		/*
		 * Free the mapping.
		 */
		(void) ddi_dma_unbind_handle(sp->cmd_dmahandle);
		sp->cmd_flags ^= CFLAG_DMAVALID;
	}
	TRACE_0(TR_FAC_SCSI, TR_ESP_SCSI_IMPL_DMAFREE_END,
	    "esp_scsi_dmafree_end");

	TRACE_0(TR_FAC_SCSI, TR_ESP_SCSI_IMPL_PKTFREE_START,
	    "esp_scsi_pktfree_start");

	/*
	 * first test the most common case
	 */
	if ((sp->cmd_flags &
	    (CFLAG_FREE | CFLAG_CDBEXTERN | CFLAG_PRIVEXTERN |
	    CFLAG_SCBEXTERN)) == 0) {
		sp->cmd_flags = CFLAG_FREE;
		kmem_cache_free(esp->e_kmem_cache, (void *)sp);
	} else {
		esp_pkt_destroy_extern(esp, sp);
	}

	TRACE_0(TR_FAC_SCSI, TR_ESP_SCSI_IMPL_PKTFREE_END,
	    "esp_scsi_pktfree_end");
}

/* ARGSUSED */
static void
esp_pkt_destroy_extern(struct esp *esp, struct esp_cmd *sp)
{
	if (sp->cmd_flags & CFLAG_FREE) {
		panic("esp_pkt_destroy(_extern): freeing free packet");
		_NOTE(NOT_REACHED)
		/*NOTREACHED*/
	}
	if (sp->cmd_flags & CFLAG_CDBEXTERN) {
		kmem_free((caddr_t)sp->cmd_pkt.pkt_cdbp,
		    (size_t)sp->cmd_cdblen_alloc);
	}
	if (sp->cmd_flags & CFLAG_SCBEXTERN) {
		kmem_free((caddr_t)sp->cmd_pkt.pkt_scbp,
		    (size_t)sp->cmd_scblen);
	}
	if (sp->cmd_flags & CFLAG_PRIVEXTERN) {
		kmem_free((caddr_t)sp->cmd_pkt.pkt_private,
		    (size_t)sp->cmd_privlen);
	}
	sp->cmd_flags = CFLAG_FREE;
	kmem_cache_free(esp->e_kmem_cache, (void *)sp);
}

/*
 * kmem cache constructor and destructor.
 * When constructing, we bzero the cmd and allocate a handle
 * When destructing, just free the dma handle
 */
static int
esp_kmem_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct esp_cmd *cmd = buf;
	struct esp *esp = cdrarg;
	int  (*callback)(caddr_t) = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP:
					DDI_DMA_DONTWAIT;

	bzero(cmd, ESP_CMD_SIZE);

	if (ddi_dma_alloc_handle(esp->e_dev,
	    esp->e_dma_attr, callback, NULL,
	    &cmd->cmd_dmahandle) != 0) {
		return (-1);
	}
	return (0);
}

/* ARGSUSED */
static void
esp_kmem_cache_destructor(void *buf, void *cdrarg)
{
	struct esp_cmd *cmd = buf;
	if (cmd->cmd_dmahandle) {
		ddi_dma_free_handle(&cmd->cmd_dmahandle);
	}
}

/*
 * esp_prepare_pkt():
 * initialize the packet and do some sanity checks
 * before taking the lock
 */
static int
esp_prepare_pkt(struct esp *esp, struct esp_cmd *sp)
{
	int size, cmdlen;

#ifdef ESPDEBUG
	if (sp->cmd_flags & CFLAG_DMAVALID) {
		uint32_t maxdma;
		switch (ESP_DMAGA_REV(esp)) {
		default:
		case DMA_REV1:
		case DMA_REV2:
		case ESC1_REV1:
			maxdma = 1 << 24;
			break;
		case DMA_REV3:
			maxdma = 1 << 30; /* be reasonable - 2gb is enuff */
			break;
		}
		if (sp->cmd_dmacount >= maxdma) {
			IPRINTF("prepare pkt: dma count too high\n");
			return (TRAN_BADPKT);
		}
	}
	ASSERT((sp->cmd_flags & CFLAG_IN_TRANSPORT) == 0);
#endif

	/*
	 * Reinitialize some fields that need it; the packet may
	 * have been resubmitted
	 */
	sp->cmd_pkt.pkt_reason = CMD_CMPLT;
	sp->cmd_pkt.pkt_state = 0;
	sp->cmd_pkt.pkt_statistics = 0;
	sp->cmd_pkt.pkt_resid = 0;
	sp->cmd_age = 0;

	/*
	 * Copy the cdb and scb pointers to the esp_cmd area as we
	 * modify these parameters.
	 */
	sp->cmd_cdbp = sp->cmd_pkt.pkt_cdbp;
	sp->cmd_scbp = sp->cmd_pkt.pkt_scbp;
	*(sp->cmd_scbp) = 0;
	sp->cmd_flags &= ~CFLAG_TRANFLAG;
	sp->cmd_flags |= CFLAG_IN_TRANSPORT;

	if (sp->cmd_pkt.pkt_time != 0) {
		sp->cmd_flags |= CFLAG_WATCH;
	}
	sp->cmd_timeout = sp->cmd_pkt.pkt_time; /* Set timeout */

	if (sp->cmd_flags & CFLAG_DMAVALID) {
		sp->cmd_pkt.pkt_resid = sp->cmd_dmacount;

		/*
		 * if the pkt was resubmitted then the
		 * window may be at the wrong number
		 */
		if (sp->cmd_cur_win) {
			sp->cmd_cur_win = 0;
			if (esp_set_new_window(esp, sp)) {
				IPRINTF("cannot reset window\n");
				return (TRAN_BADPKT);
			}
		}
		sp->cmd_saved_cur_addr =
		    sp->cmd_cur_addr = sp->cmd_dmacookie.dmac_address;

		/*
		 * the common case is just one window, we worry
		 * about multiple windows when we run out of the
		 * current window
		 */
		sp->cmd_nwin = sp->cmd_saved_win = 0;
		sp->cmd_data_count = sp->cmd_saved_data_count = 0;

		if ((sp->cmd_flags & (CFLAG_CMDIOPB | CFLAG_DMASEND)) ==
			(CFLAG_CMDIOPB | CFLAG_DMASEND)) {
			(void) ddi_dma_sync(sp->cmd_dmahandle, 0, (uint_t)-1,
			    DDI_DMA_SYNC_FORDEV);
		}
	}

	/*
	 * The ESP chip only will automatically send 6, 10 or 12 byte
	 * cdb's.  Setting cmd_cdblen to a non-zero value signals this.
	 * Otherwise, we have to do it manually and send them out one at
	 * a time.  Setting cmd_cdblen to zero signals this condition.
	 * For non-group{0,1,2,5} cmds we use the cmdlen specified by
	 * the target driver if it is 6, 10, or 12.
	 */
	size = scsi_cdb_size[CDB_GROUPID(sp->cmd_cdbp[0])];
	cmdlen = sp->cmd_cdblen;
	if (size == 0 && (cmdlen != CDB_GROUP0 &&
	    cmdlen != CDB_GROUP1 && cmdlen != CDB_GROUP5)) {
		sp->cmd_cdblen = 0;
		IPRINTF("cdblen = 0\n");
	} else if (size != 0) {
		sp->cmd_cdblen = (uchar_t)size;
	}


#ifdef ESP_TEST_UNTAGGED
#ifndef __lock_lint
	if (esp_test_untagged > 0) {
		if (TAGGED(Tgt(sp))) {
			int slot = Tgt(sp) * NLUNS_PER_TARGET | Lun(sp);
			sp->cmd_pkt.pkt_flags &= ~FLAG_TAGMASK;
			sp->cmd_pkt.pkt_flags &= ~FLAG_NODISCON;
			sp->cmd_pkt.pkt_flags |= 0x80000000;
			esplog(esp, CE_NOTE,
				"starting untagged cmd, target=%d,"
				" tcmds=%d, sp=0x%p, throttle=%d\n",
				Tgt(sp), esp->e_tcmds[slot], (void *)sp,
				esp->e_throttle[slot]);
			esp_test_untagged = -10;
		}
	}
#endif
#endif


#ifdef ESPDEBUG
	if (NOTAG(Tgt(sp)) && (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK)) {
		IPRINTF2("tagged packet for non-tagged target %d.%d\n",
		    Tgt(sp), Lun(sp));
		sp->cmd_pkt.pkt_flags &= ~FLAG_TAGMASK;
	}

	/*
	 * the scsa spec states that it is an error to have no
	 * completion function when FLAG_NOINTR is not set
	 */
	if ((sp->cmd_pkt.pkt_comp == NULL) &&
	    ((sp->cmd_pkt.pkt_flags & FLAG_NOINTR) == 0)) {
		IPRINTF("intr packet with pkt_comp == 0\n");
		sp->cmd_flags &= ~CFLAG_IN_TRANSPORT;
		TRACE_0(TR_FAC_SCSI, TR_ESP_PREPARE_PKT_TRAN_BADPKT_END,
		    "esp_prepare_pkt_end (tran_badpkt)");
		return (TRAN_BADPKT);
	}
#endif /* ESPDEBUG */

	if (((esp->e_target_scsi_options[Tgt(sp)] & SCSI_OPTIONS_DR) == 0) ||
	    (esp->e_nodisc & (Tgt(sp) << 1)))  {
		/*
		 * no need to reset tag bits since tag queuing will
		 * not be enabled if disconnects are disabled
		 */
		sp->cmd_pkt.pkt_flags |= FLAG_NODISCON;
	}

	sp->cmd_flags |= CFLAG_PREPARED;

	ASSERT(sp->cmd_flags & CFLAG_IN_TRANSPORT);

	TRACE_0(TR_FAC_SCSI, TR_ESP_PREPARE_PKT_TRAN_ACCEPT_END,
	    "esp_prepare_pkt_end (tran_accept)");
	return (TRAN_ACCEPT);
}

/*
 * when the startQ is emptied, we cannot tolerate TRAN_BUSY.
 * if the queue is not empty when the next request comes in esp_start
 * the order of requests is not preserved
 * if a transport busy condition occurs, we queue up startQ pkts in the ready
 * queue; the disadvantage is that the target driver has initially
 * the wrong value (too high) for the target queue but eventually
 * it should get it right; there is not really a big performance hit here
 */
static void
esp_empty_startQ(struct esp *esp)
{
	struct esp_cmd *sp;
	int rval;

	ASSERT(mutex_owned(&esp->e_startQ_mutex));

	TRACE_0(TR_FAC_SCSI, TR_ESP_EMPTY_STARTQ_START,
	    "esp_empty_startQ_start");
	while (esp->e_startf) {
		sp = esp->e_startf;
		esp->e_startf = sp->cmd_forw;
		if (esp->e_startb == sp) {
			esp->e_startb = NULL;
		}
		mutex_exit(&esp->e_startQ_mutex);
		rval = _esp_start(esp, sp, NO_TRAN_BUSY);

		/*
		 * the request should have been accepted but if not,
		 * put it back on the head of startQ
		 * If the  packet was rejected for other reasons then
		 * complete it here
		 */
		if (rval != TRAN_ACCEPT) {
			if (rval != TRAN_BUSY) {
				if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {
					sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
				}
				if (sp->cmd_pkt.pkt_comp) {
					mutex_exit(ESP_MUTEX);
					(*sp->cmd_pkt.pkt_comp)(&sp->cmd_pkt);
					mutex_enter(ESP_MUTEX);
				}
				mutex_enter(&esp->e_startQ_mutex);
				continue;
			}
			mutex_enter(&esp->e_startQ_mutex);
			if (esp->e_startf == NULL) {
				esp->e_startb = esp->e_startf = sp;
				sp->cmd_forw = NULL;
			} else {
				sp->cmd_forw = esp->e_startf;
				esp->e_startf = sp;
			}
			break;
		}
		mutex_enter(&esp->e_startQ_mutex);
	}
	TRACE_0(TR_FAC_SCSI, TR_ESP_EMPTY_STARTQ_END,
	    "esp_empty_startQ_end");
}

/*
 * emptying the startQ just before releasing ESP_MUTEX is
 * tricky; there is a small window where we checked the
 * startQ and emptied it but possibly due to a
 * a kernel preemption, we don't release the ESP_MUTEX soon enough and
 * esp_start() will not be able to get the ESP_MUTEX and exit
 * The next cmd coming in or the next interrupt or esp_watch() would eventually
 * empty the startQ, though
 * Therefore, by releasing the ESP_MUTEX before releasing the startQ mutex,
 * we prevent that esp_start() fills the startQ and then cannot get the
 * ESP_MUTEX for emptying the startQ
 *
 * esp_start() - accept a esp_cmd
 */
static int
esp_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct esp_cmd *sp = (struct esp_cmd *)pkt->pkt_ha_private;
	struct esp *esp = ADDR2ESP(ap);
	int rval;

	TRACE_0(TR_FAC_SCSI, TR_ESP_START_START, "esp_start_start");

#ifdef ESP_PERF
	esp_ncmds_per_esp[CNUM]++;
#endif
#ifdef ESP_CHECK
	mutex_enter(ESP_MUTEX);
	esp_check_in_transport(esp, sp);
	mutex_exit(ESP_MUTEX);
#endif

	/*
	 * prepare packet before taking the mutex
	 */
	rval = esp_prepare_pkt(esp, sp);
	if (rval != TRAN_ACCEPT) {
		TRACE_0(TR_FAC_SCSI, TR_ESP_START_PREPARE_PKT_END,
		    "esp_start_end (prepare_pkt)");
		return (rval);
	}

	/*
	 * esp mutex can be held for a long time; therefore, if mutex is
	 * held, we queue the packet in a startQ; we now need to check
	 * the startQ on every mutex_exit(ESP_MUTEX);
	 * Don't put NOINTR cmds in startQ! Proxy cmds go directly
	 * to _esp_start
	 */
	if (sp->cmd_pkt.pkt_flags & FLAG_NOINTR) {
		mutex_enter(ESP_MUTEX);
	} else {
		mutex_enter(&esp->e_startQ_mutex);
		if (esp->e_startf || (mutex_tryenter(ESP_MUTEX) == 0)) {
			if (esp->e_startf == NULL) {
				esp->e_startb = esp->e_startf = sp;
				sp->cmd_forw = NULL;
			} else {
				struct esp_cmd *dp = esp->e_startb;
				dp->cmd_forw = esp->e_startb = sp;
				sp->cmd_forw = NULL;
			}
			/*
			 * check again the ESP_MUTEX
			 */
			if (mutex_tryenter(ESP_MUTEX)) {
				esp_empty_startQ(esp);
				mutex_exit(ESP_MUTEX);
			}
			mutex_exit(&esp->e_startQ_mutex);
			goto done;
		}
		mutex_exit(&esp->e_startQ_mutex);
	}

	rval = _esp_start(esp, sp, TRAN_BUSY_OK);
	ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp);
	ESP_WAKEUP_CALLBACK_THREAD(esp);
done:
	TRACE_1(TR_FAC_SCSI, TR_ESP_START_END, "esp_start_end: esp 0x%p",
	    (void *)esp);
	return (rval);
}

/*
 * _esp_start()
 * the flag argument is to force _esp_start to accept the pkt; pkts that were
 * on startQ cannot be bounced back with TRAN_BUSY
 */
static int
_esp_start(struct esp *esp, struct esp_cmd *sp, int flag)
{
	short slot;
	int target = Tgt(sp);
	int lun = Lun(sp);
	int rval = TRAN_ACCEPT;

	TRACE_0(TR_FAC_SCSI, TR__ESP_START_START, "_esp_start_start");
	slot =	(target * NLUNS_PER_TARGET) | lun;
	ASSERT(mutex_owned(ESP_MUTEX));
	ASSERT(esp->e_ncmds >= esp->e_ndisc);
	ASSERT(esp->e_ncmds >= 0 && esp->e_ndisc >= 0);

	if (lun) {
		EPRINTF("_esp_start: switching target and lun slot scan\n");
		esp->e_dslot = 1;
	}

	esp_check_in_transport(esp, sp);

	/*
	 * prepare (init) packet if this hasn't been done yet and do some checks
	 */
	if ((sp->cmd_flags & CFLAG_PREPARED) == 0) {
		rval = esp_prepare_pkt(esp, sp);
		if (rval != TRAN_ACCEPT) {
			IPRINTF1("prepare pkt failed, slot=%x\n", slot);
#ifdef ESPDEBUG
			sp->cmd_flags &= ~CFLAG_IN_TRANSPORT;
#endif
			goto done;
		}
	}

	/*
	 * At this point we are not going to reject the packet.
	 * we let proxy packets go thru because these packets don't call a
	 * target driver completion routine
	 */

#ifdef ESP_KSTATS
	/*
	 * create kstats if not done already
	 */
	if (esp_do_kstats) {
		int slot = (Tgt(sp) * NLUNS_PER_TARGET) | Lun(sp);

		/*
		 * don't create e_slot_stats if this is an NOINTR cmd; this
		 * may be just a probing
		 */
		if ((esp->e_slot_stats[slot] == NULL) &&
		    ((sp->cmd_pkt.pkt_flags & FLAG_NOINTR) == 0)) {
			char buf[32];

			(void) sprintf(buf, "esp%dt%dd", CNUM, target);
			if ((esp->e_slot_stats[slot] = kstat_create(
			    buf, lun, NULL, "disk",
			    KSTAT_TYPE_IO, 1,
			    KSTAT_FLAG_PERSISTENT)) != NULL) {
				esp->e_slot_stats[slot]->ks_lock = ESP_MUTEX;
				kstat_install(esp->e_slot_stats[slot]);
			}
		}
		if (esp->e_slot_stats[slot]) {
			kstat_waitq_enter(IOSP(slot));
		}
	}
#endif /* ESP_KSTATS */

#ifdef ESP_PERF
	esp_request_count++;
#endif

	/*
	 * we accepted the command; increment the count
	 * (we may reject later if TRAN_BUSY!; we test this later because
	 * we don't want to incur the extra overhead here)
	 */
	esp->e_ncmds++;

	/*
	 * if it is a nointr packet, start it now
	 * (NO_INTR pkts are not queued in the startQ)
	 */
	if (sp->cmd_pkt.pkt_flags & FLAG_NOINTR) {
		EPRINTF("starting a nointr cmd\n");
		esp_runpoll(esp, slot, sp);
#ifdef ESPDEBUG
		sp->cmd_flags &= ~CFLAG_IN_TRANSPORT;
#endif
		goto done;
	}

	/*
	 * accept the command:
	 * If no ready que and free slot, run cmd immediately.
	 * If FLAG_HEAD mode set, run cmd as soon as free slot
	 * available. if first cmd in ready Q is request sense then insert
	 * after this cmd (there shouldn't be more than one request sense).
	 * Queue up the command in the ready queue if this queue is non-empty
	 * or if we had a queue full condition
	 */
	if (esp->e_readyf[slot]) {
		if (sp->cmd_pkt.pkt_flags & FLAG_HEAD) {
			struct esp_cmd *ssp = esp->e_readyf[slot];
			EPRINTF("que head\n");
			if (*(ssp->cmd_pkt.pkt_cdbp) != SCMD_REQUEST_SENSE) {
				sp->cmd_forw = ssp;
				esp->e_readyf[slot] = sp;
			} else {
				struct esp_cmd *dp = ssp->cmd_forw;
				ssp->cmd_forw = sp;
				sp->cmd_forw = dp;
				if (esp->e_readyb[slot] == ssp) {
					esp->e_readyb[slot] = sp;
				}
			}
		} else if ((esp->e_tcmds[slot] >= esp->e_throttle[slot]) &&
			    (esp->e_throttle[slot] > HOLD_THROTTLE) &&
			    (flag == TRAN_BUSY_OK)) {
				IPRINTF2(
				    "transport busy, slot=%x, ncmds=%x\n",
				    slot, esp->e_ncmds);
				rval = TRAN_BUSY;
				esp->e_ncmds--;
				sp->cmd_flags &= ~CFLAG_PREPARED;
#ifdef ESPDEBUG
				sp->cmd_flags &= ~CFLAG_IN_TRANSPORT;
#endif
#ifdef ESP_PERF
				esp_request_count--;
#endif
				goto done;
		} else {
			struct esp_cmd *dp = esp->e_readyb[slot];

			EPRINTF("que tail\n");
			ASSERT(dp != 0);
			esp->e_readyb[slot] = sp;
			sp->cmd_forw = NULL;
			dp->cmd_forw = sp;
		}

		if ((esp->e_throttle[slot] == DRAIN_THROTTLE) &&
		    (esp->e_tcmds[slot] == 0)) {
			esp->e_throttle[slot] = CLEAR_THROTTLE;
		}

		/*
		 * just in case that the bus is free and we haven't
		 * been able to restart for some reason
		 * XXX this shouldn't really be necessary
		 */
		if (esp->e_state == STATE_FREE) {
			(void) esp_ustart(esp, slot, NEW_CMD);
		}
	} else {
		/*
		 * for tagged targets with no cmds outstanding and currently
		 * draining, reset throttle now
		 * for non-tagged targets and currently draining, always reset
		 * throttle now (t_cmds is always zero for non-tagged)
		 */
		if ((esp->e_tcmds[slot] == 0) && (esp->e_throttle[slot] ==
			DRAIN_THROTTLE)) {
			IPRINTF("reset throttle\n");
			esp->e_throttle[slot] = CLEAR_THROTTLE;
		}
		if ((esp->e_state == STATE_FREE) &&
		    (esp->e_slots[slot] == NULL) &&
		    (esp->e_tcmds[slot] < esp->e_throttle[slot])) {
			EPRINTF("start cmd (maybe)\n");
			esp->e_cur_slot = slot;
			esp->e_slots[slot] = sp;
			(void) esp_startcmd(esp, sp);
		} else {
			EPRINTF2(
			    "cmd not started: e_slot=0x%p, throttle=%x\n",
			    (void *)esp->e_slots[slot], esp->e_throttle[slot]);
			esp->e_readyf[slot] = esp->e_readyb[slot] = sp;
			sp->cmd_forw = NULL;
		}
	}
done:
	ASSERT(mutex_owned(ESP_MUTEX));
	TRACE_0(TR_FAC_SCSI, TR__ESP_START_END, "_esp_start_end");
	return (rval);
}

static char esp_tag_lookup[] =
	{0, MSG_HEAD_QTAG, MSG_ORDERED_QTAG, 0, MSG_SIMPLE_QTAG};

static int
esp_alloc_tag(struct esp *esp, struct esp_cmd *sp)
{
	struct t_slots *tag_slots;
	uchar_t tag;
	int rval = 0;
	int target = Tgt(sp);
	int lun = Lun(sp);
	short slot = (target * NLUNS_PER_TARGET) | lun;

	TRACE_0(TR_FAC_SCSI, TR_ESP_ALLOC_TAG_START,
	    "esp_alloc_tag_start");
	ASSERT(mutex_owned(ESP_MUTEX));

alloc:
	/*
	 * allocate tag
	 * Optimize for the common case, ie. success
	 */
	tag_slots = esp->e_tagQ[slot];
	if (tag_slots != NULL) {
		tag = (esp->e_tagQ[slot]->e_tags)++;
		EPRINTF1("tagged cmd, tag = %d\n", tag);

		/* Validate tag, should never fail. */
		if (tag_slots->t_slot[tag] == 0) {
			/*
			 * Store assigned tag and tag queue type.
			 * Note, in case
			 * of multiple choice, default to simple queue.
			 */
			sp->cmd_tag[1] = tag;
			sp->cmd_tag[0] = esp_tag_lookup[
			    ((sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) >> 12)];
			EPRINTF1("tag= %d\n", tag);
			tag_slots->t_slot[tag] =  sp;
			(esp->e_tcmds[slot])++;
done:
			ASSERT(mutex_owned(ESP_MUTEX));
			TRACE_0(TR_FAC_SCSI, TR_ESP_ALLOC_TAG_END,
			    "esp_alloc_tag_end");
			return (rval);
		} else {
			int age, i;

			/*
			 * Check tag age.  If timeouts enabled and
			 * tag age greater than 1, print warning msg.
			 * If timeouts enabled and tag age greater than
			 * age limit, begin draining tag que to check for
			 * lost tag cmd.
			 */
			age = tag_slots->t_slot[tag]->cmd_age++;
			if (age >= esp->e_scsi_tag_age_limit &&
			    tag_slots->t_slot[tag]->cmd_pkt.pkt_time) {
				IPRINTF2("tag %d in use, age= %d\n", tag, age);
				IPRINTF("draining tag queue\n");
				if (esp->e_reset_delay[Tgt(sp)] == 0) {
					esp->e_throttle[slot] = DRAIN_THROTTLE;
				}
			}

			/* If tag in use, scan until a free one is found. */
			for (i = 0; i < NTAGS; i++) {
				tag = esp->e_tagQ[slot]->e_tags;
				if (!tag_slots->t_slot[tag]) {
					EPRINTF1("found free tag %d\n", tag);
					break;
				}
				++(esp->e_tagQ[slot]->e_tags);
				EPRINTF1("found in use tag %d\n", tag);
			}

			/* If no free tags, we're in serious trouble. */
			if (tag_slots->t_slot[tag]) {
				esplog(esp, CE_WARN,
				    "slot %x: All tags in use!!!\n", slot);
				rval = -1;
				goto done;
			}
			goto alloc;
		}
	} else {
		EPRINTF2("Target %d.%d allocating tag que\n",
		    target, Lun(sp));
		tag_slots = kmem_zalloc(sizeof (struct t_slots), KM_NOSLEEP);
		if (tag_slots == NULL) {
			/*
			 * Couldn't get space for tagged que.  Complain
			 * and disable tagged queuing.	 It beats
			 * dying...Seriously, this should not
			 * happen.
			 */
			esplog(esp, CE_WARN,
			    "Target %d.%d cannot alloc tag queue\n",
			    target, Lun(sp));
			esp->e_notag |= 1<<target;
			sp->cmd_pkt.pkt_flags &=  ~FLAG_TAGMASK;
			goto done;
		}
		esp->e_tagQ[slot] = tag_slots;
		goto alloc;
	}
	_NOTE(NOT_REACHED)
	/* NOTREACHED */
}

/*
 * Internal Search Routine.
 *
 * Search for a command to start.
 */
static int
esp_istart(struct esp *esp)
{
	TRACE_0(TR_FAC_SCSI, TR_ESP_ISTART_START,
	    "esp_istart_start");
	EPRINTF("esp_istart:\n");

	if (esp->e_state == STATE_FREE && esp->e_ncmds > esp->e_ndisc) {
		(void) esp_ustart(esp, esp->e_last_slot, NEW_CMD);
	}
	TRACE_0(TR_FAC_SCSI, TR_ESP_ISTART_END,
	    "esp_istart_end");
	return (ACTION_RETURN);
}

static int
esp_ustart(struct esp *esp, short start_slot, short flag)
{
	struct esp_cmd *sp;
	short slot;

	TRACE_0(TR_FAC_SCSI, TR_ESP_USTART_START, "esp_ustart_start");
	EPRINTF2("esp_ustart: start_slot=%x, flag=%x\n", start_slot, flag);


	switch (flag) {
	case NEW_CMD:
	{
		int found = 0;
		short dslot = esp->e_dslot;

		slot = start_slot = esp->e_next_slot;

#ifdef ESPDEBUG
		ASSERT(dslot != 0);
		if (dslot == NLUNS_PER_TARGET) {
			ASSERT((slot % NLUNS_PER_TARGET) == 0);
		}
#endif /* ESPDEBUG */

		/*
		 * check each std slot; if it is empty (ie. target not currently
		 * connected), then check the ready queue for packets
		 */
		do {
			sp = esp->e_slots[slot];
			if ((sp == 0) && esp->e_readyf[slot] &&
			    (esp->e_throttle[slot] >  esp->e_tcmds[slot])) {
				sp = esp->e_readyf[slot];
				esp->e_readyf[slot] = sp->cmd_forw;
				if (sp->cmd_forw == NULL) {
					esp->e_readyb[slot] = NULL;
				}
				found++;
			} else {
				slot = NEXTSLOT(slot, dslot);
			}
		} while (found == 0 && slot != start_slot);

		if (!found) {
			EPRINTF("esp_ustart: no cmds to start\n");
			TRACE_0(TR_FAC_SCSI, TR_ESP_USTART_NOT_FOUND_END,
			    "esp_ustart_end (not_found)");
			return (FALSE);
		}
		esp->e_cur_slot = slot;
		esp->e_slots[slot] = sp;
		ASSERT((sp->cmd_pkt.pkt_flags & FLAG_NOINTR) == 0);
		break;
	}
	case SAME_CMD:
		ASSERT(start_slot != UNDEFINED);
		slot = esp->e_cur_slot = start_slot;
		sp = esp->e_slots[start_slot];
		break;
	default:
		TRACE_0(TR_FAC_SCSI, TR_ESP_USTART_DEFAULT_END,
		    "esp_ustart_end (default)");
		return (FALSE);
	}

	esp->e_next_slot = NEXTSLOT(slot, esp->e_dslot);

	TRACE_0(TR_FAC_SCSI, TR_ESP_USTART_END, "esp_ustart_end");
	return (esp_startcmd(esp, sp));
}


/*
 * Start a command off
 */
#ifdef ESPDEBUG
static int esp_cmd_len;
#endif

static int
esp_startcmd(struct esp *esp, struct esp_cmd *sp)
{
	volatile struct espreg *ep = esp->e_reg;
	int cmd_len, i, nstate;
	uchar_t cmd, tshift, target, lun;
	volatile caddr_t tp = (caddr_t)esp->e_cmdarea;
	uchar_t offset, period, conf3;

	ASSERT(esp->e_slots[esp->e_cur_slot]->cmd_flags & CFLAG_IN_TRANSPORT);
	ASSERT(sp == esp->e_slots[esp->e_cur_slot]);

#define	LOAD_CMDP	*(tp++)

	target = Tgt(sp);
	lun    = Lun(sp);
	TRACE_0(TR_FAC_SCSI, TR_ESP_STARTCMD_START, "esp_startcmd_start");

	EPRINTF2("esp_startcmd: sp=0x%p flags=%x\n",
	    (void *)sp, sp->cmd_pkt.pkt_flags);

#ifdef ESPDEBUG
	if (esp->e_cur_slot != ((target * NLUNS_PER_TARGET) | lun)) {
		eprintf(esp, "cur_slot=%x, target=%x, lun=%x, sp=0x%p\n",
		esp->e_cur_slot, target, lun, (void *)sp);
		debug_enter("esp_startcmd");
	}
	ASSERT((sp->cmd_flags & CFLAG_FREE) == 0);
	ASSERT(esp->e_reset_delay[Tgt(sp)] == 0);
#endif

	/*
	 * if a non-tagged cmd is submitted to an active tagged target
	 * then drain before submitting this cmd; SCSI-2 allows RQSENSE
	 * to be untagged
	 */
	if (((sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) == 0) &&
	    TAGGED(Tgt(sp)) && esp->e_tcmds[esp->e_cur_slot] &&
	    ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) &&
	    (*(sp->cmd_pkt.pkt_cdbp) != SCMD_REQUEST_SENSE)) {
		esp->e_slots[esp->e_cur_slot] = NULL;
		if ((sp->cmd_pkt.pkt_flags & FLAG_NOINTR) == 0) {
			struct esp_cmd *dp;
			int slot = esp->e_cur_slot;

			IPRINTF("untagged cmd, start draining\n");

			if (esp->e_reset_delay[Tgt(sp)] == 0) {
				esp->e_throttle[slot] = DRAIN_THROTTLE;
			}
			dp = esp->e_readyf[slot];
			esp->e_readyf[slot] = sp;
			sp->cmd_forw = dp;
			if (esp->e_readyb[slot] == NULL) {
				esp->e_readyb[slot] = sp;
			}
		}
		return (FALSE);
	}

	/*
	 * The only reason that this should happen
	 * is if we have a re-selection attempt starting.
	 */
	if (INTPENDING(esp)) {
		int slot;
		struct esp_cmd *dp;

		slot = esp->e_cur_slot;
		ESP_PREEMPT(esp);
		LOG_STATE(esp, ACTS_PREEMPTED, esp->e_stat, Tgt(sp), lun);
		TRACE_0(TR_FAC_SCSI, TR_ESP_STARTCMD_PREEMPT_CALL,
			"esp_startcmd_preempt_call");
		/*
		 * put request back in the ready queue
		 * runpoll will retry NOINTR cmds so no need to put
		 * those on ready Q
		 */
		if ((sp->cmd_pkt.pkt_flags & FLAG_NOINTR) == 0) {
			esp->e_slots[slot] = (struct esp_cmd *)NULL;
			dp = esp->e_readyf[slot];
			esp->e_readyf[slot] = sp;
			sp->cmd_forw = dp;
			if (esp->e_readyb[slot] == NULL) {
				esp->e_readyb[slot] = sp;
			}
			esp->e_polled_intr = 1;
			espsvc(esp);
		}
		TRACE_0(TR_FAC_SCSI, TR_ESP_STARTCMD_RE_SELECTION_END,
		    "esp_startcmd_end (re_selection)");
		return (FALSE);
	}

	/*
	 * allocate a tag; if no tag available then put request back
	 * on the ready queue and return; eventually a cmd completes and we
	 * get going again
	 */
	if (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) {
		if ((esp_alloc_tag(esp, sp))) {
			int slot;
			struct esp_cmd *dp;

			slot = esp->e_cur_slot;
			dp = esp->e_readyf[slot];
			esp->e_readyf[slot] = sp;
			sp->cmd_forw = dp;
			if (esp->e_readyb[slot] == NULL) {
				esp->e_readyb[slot] = sp;
			}
			esp->e_slots[slot] = NULL;
			esp->e_last_slot = esp->e_cur_slot;
			esp->e_cur_slot = UNDEFINED;
			TRACE_0(TR_FAC_SCSI, TR_ESP_STARTCMD_ALLOC_TAG2_END,
			    "esp_startcmd_end (alloc_tag2)");
			return (FALSE);
		}
	} else {
		if (TAGGED(target)) {
			if (*(sp->cmd_pkt.pkt_cdbp) != SCMD_REQUEST_SENSE) {
				esp->e_throttle[esp->e_cur_slot] = 1;
			}
		}
	}
	esp->e_sdtr = esp->e_omsglen = 0;
	tshift = 1<<target;

#ifdef	ESPDEBUG
	esp->e_xfer = sp->cmd_dmacount;
#endif	/* ESPDEBUG */

	/*
	 * The ESP chip will only automatically
	 * send 6, 10 or 12 byte SCSI cmds.
	 * NOTE: if cmd_len is 0, we xfer cmd bytes one at the time
	 * Also note that the "SELECT with ATN and STOP" stops with ATN
	 * asserted; if no msg is available, we send a NOP. Some targets
	 * may not like this.
	 */
	cmd_len = sp->cmd_cdblen;

#ifdef ESPDEBUG
	if (esp_cmd_len)
		cmd_len = 0;
#endif

	if ((sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) &&
	    (esp->e_sync_known & tshift ||
	    (esp->e_target_scsi_options[target] & SCSI_OPTIONS_SYNC) == 0)) {
		EPRINTF("tag cmd\n");

		ASSERT((sp->cmd_pkt.pkt_flags & FLAG_NODISCON) == 0);
		LOAD_CMDP = esp->e_last_msgout = MSG_DR_IDENTIFY | lun;

		if (cmd_len) {
			LOAD_CMDP = sp->cmd_tag[0];
			LOAD_CMDP = sp->cmd_tag[1];

			nstate = STATE_SELECT_NORMAL;
			cmd = CMD_SEL_ATN3 | CMD_DMA;

		} else {
			esp->e_cur_msgout[0] = sp->cmd_tag[0];
			esp->e_cur_msgout[1] = sp->cmd_tag[1];
			esp->e_omsglen = 2;
			EPRINTF2("tag %d, omsglen=%x\n",
			    sp->cmd_tag[1], esp->e_omsglen);

			cmd_len = 0;
			nstate = STATE_SELECT_N_TAG;
			cmd = CMD_SEL_STOP | CMD_DMA;
		}
		LOG_STATE(esp, ACTS_SELECT, target, lun, -1);
		LOG_STATE(esp, ACTS_TAG, sp->cmd_tag[0], sp->cmd_tag[1], -1);

	} else if (sp->cmd_flags & CFLAG_CMDPROXY) {

		IPRINTF2("proxy cmd, len=%x, msg=%x\n",
		    sp->cmd_cdb[ESP_PROXY_DATA],
		    sp->cmd_cdb[ESP_PROXY_DATA+1]);

		/*
		 * This is a proxy command. It will have
		 * a message to send as part of post-selection
		 * (e.g, MSG_ABORT or MSG_DEVICE_RESET)
		 * XXX: We should check to make sure that
		 * this is a valid PROXY command, i.e,
		 * a  valid message length.
		 */
		LOAD_CMDP = esp->e_last_msgout = MSG_IDENTIFY | lun;
		esp->e_omsglen = sp->cmd_cdb[ESP_PROXY_DATA];
		for (i = 0; i < (uint_t)esp->e_omsglen; i++) {
			esp->e_cur_msgout[i] =
			    sp->cmd_cdb[ESP_PROXY_DATA+1+i];
		}
		sp->cmd_cdb[ESP_PROXY_RESULT] = FALSE;
		nstate = STATE_SELECT_N_SENDMSG;
		cmd = CMD_SEL_STOP | CMD_DMA;
		cmd_len = 0;
		LOG_STATE(esp, ACTS_PROXY, esp->e_stat,
			esp->e_cur_msgout[0], nstate);

	} else if (((esp->e_sync_known & tshift) == 0) &&
		(esp->e_target_scsi_options[target] & SCSI_OPTIONS_SYNC)) {

		if (sp->cmd_pkt.pkt_flags & FLAG_NODISCON) {
			LOAD_CMDP = esp->e_last_msgout = MSG_IDENTIFY | lun;
			ASSERT((sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) == 0);
		} else {
			LOAD_CMDP = esp->e_last_msgout =
			    MSG_DR_IDENTIFY | lun;
		}

		/*
		 * Set up to send synch. negotiating message.  This is getting
		 * a bit tricky as we dma out the identify message and
		 * send the other messages via the fifo buffer.
		 */
		EPRINTF1("cmd with sdtr msg, tag=%x\n", sp->cmd_tag[1]);
		LOG_STATE(esp, ACTS_SELECT, target, lun, -1);

		/* First the tag message bytes */
		i = 0;
		if (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) {
			esp->e_cur_msgout[i++] = sp->cmd_tag[0];
			esp->e_cur_msgout[i++] = sp->cmd_tag[1];
			LOG_STATE(esp, ACTS_TAG,
			    sp->cmd_tag[0], sp->cmd_tag[1], -1);
		}

		if (esp->e_weak & tshift) {
			nstate = STATE_SELECT_NORMAL;
			cmd = CMD_SEL_ATN | CMD_DMA;
		} else {
			int period = esp->e_default_period[target];
			int offset = DEFAULT_OFFSET;

			if (esp->e_force_async & (1<<target)) {
				offset = 0;
			}
			if (esp->e_backoff[target] == 1) {
				period = esp->e_neg_period[target];
			} else if (esp->e_backoff[target] > 1) {
				period = esp->e_neg_period[target];
				offset = 0;
			}
			esp_make_sdtr(esp, i, (int)period,
			    (int)offset);
			LOG_STATE(esp, ACTS_SYNCHOUT, esp->e_stat,
			    period, offset);
			cmd_len = 0;
			cmd = CMD_SEL_STOP | CMD_DMA;
			nstate = STATE_SELECT_N_SENDMSG;
		}
		/*
		 * XXX: Set sync known here because the Sony CDrom
		 * ignores the synch negotiation msg. Net effect
		 * is we negotiate on every I/O request forever.
		 */
		esp->e_sync_known |= (1<<target);

	} else	{

		ASSERT((sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) == 0);

		if (sp->cmd_pkt.pkt_flags & FLAG_NODISCON) {
			LOAD_CMDP = esp->e_last_msgout = MSG_IDENTIFY | lun;
		} else {
			LOAD_CMDP = esp->e_last_msgout =
			    MSG_DR_IDENTIFY | lun;
		}

		/* Send cmd. */
		if (cmd_len) {
			EPRINTF("std. cmd\n");
			nstate = STATE_SELECT_NORMAL;
			cmd = CMD_SEL_ATN | CMD_DMA;
		/*
		 * XXX: Things get a bit complicated for cdb's the esp
		 *	chip doesn't understand.  We have to send them out
		 *	one byte at a time.  This is not a fast process!
		 */
		} else {
			IPRINTF("sending special cmd\n");
			cmd = CMD_SEL_STOP | CMD_DMA;
			nstate = STATE_SELECT_N_STOP;
		}
		LOG_STATE(esp, ACTS_SELECT, target, lun, -1);
	}

	/*
	 * Now load cdb (if any)
	 */
	for (i = 0; i < cmd_len; i++) {
		LOAD_CMDP = sp->cmd_cdbp[i];
	}
	if (cmd_len) {
		LOG_STATE(esp, ACTS_CMD_START, esp->e_stat, sp->cmd_cdbp[0],
		    nstate);
	}

	/*
	 * calculate total dma amount:
	 */
	esp->e_lastcount = (uintptr_t)tp - (uintptr_t)esp->e_cmdarea;

	/*
	 * load rest of chip registers, if needed
	 */
	ep->esp_busid = target;

	period =  esp->e_period[target] & SYNC_PERIOD_MASK;
	offset = esp->e_offset[target];
	conf3 = esp->e_espconf3[target];
	if ((esp->e_period_last != period) ||
	    (esp->e_offset_last != offset) ||
	    (esp->e_espconf3_last != conf3)) {
		esp->e_period_last = ep->esp_sync_period = period;
		esp->e_offset_last = ep->esp_sync_offset = offset;
		esp->e_espconf3_last = ep->esp_conf3 = conf3;
	}

	if ((esp->e_target_scsi_options[target] & SCSI_OPTIONS_PARITY) &&
	    (sp->cmd_pkt.pkt_flags & FLAG_NOPARITY)) {
		ep->esp_conf = esp->e_espconf & ~ESP_CONF_PAREN;
	}
	SET_DMAESC_COUNT(esp->e_dma, esp->e_esc_read_count);
	ESP_DMA_READ(esp, esp->e_lastcount, esp->e_dmacookie.dmac_address);

	Esp_cmd(esp, (int)cmd);
	New_state(esp, (int)nstate);
	LOG_STATE(esp, nstate, esp->e_stat, target, lun);

#ifdef ESPDEBUG
	if (DEBUGGING) {
		auto char buf[256];
		buf[0] = '\0';
		(void) sprintf(&buf[strlen(buf)], "sel %d.%d cmd[ ",
		    target, lun);
		for (i = 0; i < (int)sp->cmd_cdblen; i++) {
			(void) sprintf(&buf[strlen(buf)],
			    "0x%x ", sp->cmd_cdbp[i] & 0xff);
		}
		(void) sprintf(&buf[strlen(buf)], "]\n\tstate=%s\n",
		    esp_state_name(esp->e_state));
		eprintf(esp, "%s", buf);
	}
#endif /* ESPDEBUG */

	/*
	 * set up timeout here; there is a risk of preemption in which
	 * case we don't adjust the timeout. So, we hope that this
	 * cmd gets started fairly quickly after a preemption.
	 */
	if (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) {
		short slot = esp->e_cur_slot;
		struct t_slots *tag_slots = esp->e_tagQ[slot];

		i = sp->cmd_pkt.pkt_time - tag_slots->e_timebase;

		if (i == 0) {
			EPRINTF("dup timeout\n");
			(tag_slots->e_dups)++;
			tag_slots->e_timeout = tag_slots->e_timebase;
		} else if (i > 0) {
			EPRINTF("new timeout\n");
			tag_slots->e_timeout = tag_slots->e_timebase =
			    sp->cmd_pkt.pkt_time;
			tag_slots->e_dups = 1;
		}
	}

#ifdef ESP_KSTATS
	if (esp_do_kstats && esp->e_slot_stats[esp->e_cur_slot]) {
		kstat_waitq_to_runq(IOSP(esp->e_cur_slot));
	}
#endif /* ESP_KSTATS */
	TRACE_0(TR_FAC_SCSI, TR_ESP_STARTCMD_END, "esp_startcmd_end");

	return (TRUE);
}

/*
 * Autovector Interrupt Entry Point.
 *
 */

static uint_t
esp_intr(caddr_t arg)
{
	struct esp *esp = (struct esp *)arg;
	int kstat_updated = 0;
	int rval = DDI_INTR_UNCLAIMED;

#ifdef ESP_PERF
	esp_intr_count++;
#endif
	do {
		mutex_enter(ESP_MUTEX);
		while (INTPENDING(esp)) {
			espsvc(esp);
			rval = DDI_INTR_CLAIMED;
		}

		if (esp->e_polled_intr) {
			rval = DDI_INTR_CLAIMED;
			esp->e_polled_intr = 0;
		}
		if (!kstat_updated && esp->e_intr_kstat &&
					rval == DDI_INTR_CLAIMED) {
			ESP_KSTAT_INTR(esp);
			kstat_updated++;
		}

		/*
		 * check and empty the startQ
		 */
		ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp);
		ESP_WAKEUP_CALLBACK_THREAD(esp);
	} while (INTPENDING(esp));

	return (rval);
}

/*
 * General interrupt service routine.
 */
static char *dmaga_bits = DMAGA_BITS;

static void
espsvc(struct esp *esp)
{
	static int (*evec[])(struct esp *esp) = {
		esp_finish_select,
		esp_reconnect,
		esp_phasemanage,
		esp_finish,
		esp_reset_recovery,
		esp_istart,
		esp_abort_curcmd,
		esp_abort_allcmds,
		esp_reset_bus,
		esp_handle_selection
	};
	int action;
	uchar_t intr;
	volatile struct espreg *ep = esp->e_reg;
	int i = 0;

	TRACE_0(TR_FAC_SCSI, TR_ESPSVC_START, "espsvc_start");

	/*
	 * A read of ESP interrupt register clears interrupt,
	 * so any other volatile information needs to be latched
	 * up prior to reading the interrupt register.
	 */
	esp->e_stat = ep->esp_stat;

	/*
	 * unclear what could cause a gross error;
	 * most of the time we get a data overrun after this.
	 */
	if (esp->e_stat & ESP_STAT_GERR) {
		esplog(esp, CE_WARN,
		    "gross error in esp status (%x)", esp->e_stat);
		IPRINTF5("esp_cmd=%x, stat=%x, intr=%x, step=%x, fifoflag=%x\n",
		    ep->esp_cmd, esp->e_stat, esp->e_intr, ep->esp_step,
		    ep->esp_fifo_flag);
		if (esp->e_cur_slot != UNDEFINED) {
			struct esp_cmd *sp = CURRENT_CMD(esp);
			if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {
				sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
			}
		} else {
			action = ACTION_ABORT_ALLCMDS;
			goto start_action;
		}
	}

#ifdef ESPDEBUG
	if (esp_check_dma_error(esp)) {
		action = ACTION_RESET;
		goto start_action;
	}
#endif

	/*
	 * the esp may post an interrupt even though we have just reset
	 * the bus and blown away the targets; therefore, check on
	 * reset state first and deal with reset recovery immediately
	 */
	if (esp->e_state == ACTS_RESET) {
		action = ACTION_FINRST;
		goto start_action;
	}


	/*
	 * While some documentation claims that the
	 * ESP100A's msb in the stat register is an
	 * INTERRUPT PENDING bit, an errata sheet
	 * warned that you shouldn't depend on that
	 * being so (unless you're an ESP-236)
	 */
	if (esp->e_options & ESP_OPT_MASK_OFF_STAT) {
		esp->e_stat &= ~ESP_STAT_RES;
	} else	if ((esp->e_stat & ESP_STAT_IPEND) == 0) {
		esp->e_intr = intr = ep->esp_intr;
		if (esp->e_intr & ESP_INT_RESET) {
			action = ACTION_FINRST;
			goto start_action;
		}

		if (esp_check_dma_error(esp)) {
			action = ACTION_RESET;
			goto start_action;
		}

		esplog(esp, CE_WARN, "Spurious interrupt");
		action = ACTION_RETURN;
		goto exit;
	}

	/*
	 * now it is finally safe to read the interrupt register
	 */
	esp->e_intr = intr = ep->esp_intr;

#ifdef	ESPDEBUG
	if (DEBUGGING) {
		eprintf(esp, "espsvc: dma csr 0x%b addr 0x%x\n",
		    esp->e_dma->dmaga_csr, dmaga_bits, esp->e_dma->dmaga_addr);
		esp_stat_int_print(esp);
		eprintf(esp, "\tState %s Laststate %s\n",
			esp_state_name(esp->e_state),
			esp_state_name(esp->e_laststate));
	}
#endif	/* ESPDEBUG */

	/*
	 * Based upon the current state of the host adapter driver
	 * we should be able to figure out what to do with an interrupt.
	 * We have several possible interrupt sources, some of them
	 * modified by various status conditions.
	 *
	 * Basically, we'll get an interrupt through the dma gate array
	 * for one or more of the following three conditions:
	 *
	 *	1. The ESP is asserting an interrupt request.
	 *
	 *	2. There has been a memory exception of some kind.
	 *
	 * In the latter case we are either in one of the SCSI
	 * DATA phases or are using dma in sending a command to a
	 * target. We will let the various handlers for these kind
	 * of states decode any error conditions in the gate array.
	 *
	 * The ESP asserts an interrupt with one or more of 8 possible
	 * bits set in its interrupt register. These conditions are
	 * SCSI bus reset detected, an illegal command fed to the ESP,
	 * one of DISCONNECT, BUS SERVICE, FUNCTION COMPLETE conditions
	 * for the ESP, a Reselection interrupt, or one of Selection
	 * or Selection with Attention.
	 *
	 * Of these possible interrupts, we can deal with some right
	 * here and now, irrespective of the current state of the driver.
	 *
	 * take care of the most likely interrupts first and call the action
	 * immediately
	 */
	if ((intr & (ESP_INT_RESET|ESP_INT_ILLEGAL|ESP_INT_SEL|ESP_INT_SELATN|
	    ESP_INT_RESEL)) == 0) {
		/*
		 * The rest of the reasons for an interrupt, including
		 * interrupts just from the dma gate array itself, can
		 * be handled based purely on the state that the driver
		 * is currently in now.
		 */
		if (esp->e_state & STATE_SELECTING) {
			action = esp_finish_select(esp);

		} else if (esp->e_state & STATE_ITPHASES) {
			action = esp_phasemanage(esp);

		} else {
#ifdef	ESPDEBUG
			esp_printstate(esp, "spurious interrupt");
#endif	/* ESPDEBUG */
			esplog(esp, CE_WARN, "spurious interrupt");
			action = ACTION_RETURN;
		}

	} else if ((intr & ESP_INT_RESEL) && ((intr &
	    (ESP_INT_RESET|ESP_INT_ILLEGAL|ESP_INT_SEL|ESP_INT_SELATN)) == 0)) {

		if (esp->e_state & STATE_SELECTING) {
			action = esp_finish_select(esp);

		} else if (esp->e_state != STATE_FREE) {
			/*
			 * this 'cannot happen'.
			 */
			esp_printstate(esp, "illegal reselection");
			action = ACTION_RESET;
		} else {
			action = esp_reconnect(esp);
		}


	} else if (intr & ESP_INT_RESET) {
		/*
		 * If we detect a SCSI reset, we blow away the current
		 * command (if there is one) and all disconnected commands
		 * because we now don't know the state of them at all.
		 */
		action = ACTION_FINRST;

	} else if (intr & ESP_INT_ILLEGAL) {
		/*
		 * This should not happen. The one situation where
		 * we can get an ILLEGAL COMMAND interrupt is due to
		 * a bug in the ESP100 during reselection which we
		 * should be handling in esp_reconnect().
		 */
		IPRINTF1("lastcmd=%x\n", esp->e_reg->esp_cmd);
		esp_printstate(esp, "ILLEGAL bit set");
		action = ACTION_RESET;

	} else if (intr & (ESP_INT_SEL|ESP_INT_SELATN)) {
		action = ACTION_SELECT;
	}

start_action:
	while (action != ACTION_RETURN) {
		ASSERT((action >= 0) && (action <= ACTION_SELECT));
		TRACE_3(TR_FAC_SCSI, TR_ESPSVC_ACTION_CALL,
			"espsvc call: esp 0x%p, action %d (%d)",
			(void *)esp, action, i);
		i++;
		action = (*evec[action])(esp);
	}
exit:
	TRACE_0(TR_FAC_SCSI, TR_ESPSVC_END, "espsvc_end");
}


/*
 * Manage phase transitions.
 */
static int
esp_phasemanage(struct esp *esp)
{
	ushort_t state;
	int action;
	static int (*pvecs[])(struct esp *esp) = {
		esp_handle_cmd_start,
		esp_handle_cmd_done,
		esp_handle_msg_out,
		esp_handle_msg_out_done,
		esp_handle_msg_in,
		esp_handle_more_msgin,
		esp_handle_msg_in_done,
		esp_handle_clearing,
		esp_handle_data,
		esp_handle_data_done,
		esp_handle_c_cmplt,
		esp_reconnect
	};
	int i = 0;

	TRACE_0(TR_FAC_SCSI, TR_ESP_PHASEMANAGE_START, "esp_phasemanage_start");

	do {
		EPRINTF1("esp_phasemanage: %s\n",
		    esp_state_name(esp->e_state & STATE_ITPHASES));

		TRACE_2(TR_FAC_SCSI, TR_ESP_PHASEMANAGE_CALL,
			"esp_phasemanage_call: esp 0x%p (%d)", (void *)esp, i);

		i++;
		state = esp->e_state;

		if (state == ACTS_UNKNOWN) {
			action = esp_handle_unknown(esp);
		} else if (state == STATE_FREE || state > ACTS_ENDVEC) {
			esplog(esp, CE_WARN, "lost state in phasemanage");
			action = ACTION_ABORT_ALLCMDS;
		} else {
			ASSERT(pvecs[state-1] != NULL);
			action = (*pvecs[state-1]) (esp);
		}

	} while (action == ACTION_PHASEMANAGE);

	TRACE_0(TR_FAC_SCSI, TR_ESP_PHASEMANAGE_END, "esp_phasemanage_end");
	return (action);
}

/*
 * remove a tagged cmd from t_slot list and if timeout is set, then
 * adjust timeouts; if a the same cmd will be resubmitted soon, don't
 * bother to adjust timeouts
 */
static void
esp_remove_tagged_cmd(struct esp *esp, struct esp_cmd *sp, int slot,
    int new_timeout_flag)
{
	ASSERT(sp != NULL);
	ASSERT(slot >= 0 && slot < N_SLOTS);
	ASSERT(esp->e_ncmds >= esp->e_ndisc);

	if (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) {
		int tag = sp->cmd_tag[1];
		struct t_slots *tag_slots = esp->e_tagQ[slot];

		EPRINTF4("remove tag %d slot %d for target %d.%d\n",
		    tag, slot, Tgt(sp), Lun(sp));

		ASSERT(sp != esp->e_slots[slot]);
		ASSERT(tag_slots != NULL);

		if (sp == tag_slots->t_slot[tag]) {
			tag_slots->t_slot[tag] = NULL;
			esp->e_tcmds[slot]--;
		}
		ASSERT(esp->e_tcmds[slot] >= 0);

		/*
		 * If all cmds drained from tag Q, clear throttle and
		 * start queuing up new cmds again.
		 */
		if (esp->e_throttle[slot] == DRAIN_THROTTLE &&
		    esp->e_tcmds[slot] == 0) {
			IPRINTF("reset throttle\n");
			esp->e_throttle[slot] = CLEAR_THROTTLE;
		}
		if (new_timeout_flag != NEW_TIMEOUT) {
			return;
		}

		/*
		 * Figure out what to set tag Q timeout for...
		 *
		 * Optimize: If we have duplicate's of same timeout
		 * we're using, then we'll use it again until we run
		 * out of duplicates.  This should be the normal case
		 * for block and raw I/O.
		 * If no duplicates, we have to scan through tag que and
		 * find the longest timeout value and use it.  This is
		 * going to take a while...
		 */
		if (sp->cmd_pkt.pkt_time == tag_slots->e_timebase) {
		    if (--(tag_slots->e_dups) <= 0) {
			if (esp->e_tcmds[slot]) {
				struct esp_cmd *ssp;
				uint_t n = 0;
				int i;

				/*
				 * This crude check assumes we don't do
				 * this too often which seems reasonable
				 * for block and raw I/O.
				 */
				for (i = 0; i < NTAGS; i++) {
					ssp = tag_slots->t_slot[i];
					if (ssp == NULL) {
						continue;
					}
					if (ssp->cmd_pkt.pkt_time > n) {
						n = ssp->cmd_pkt.pkt_time;
						tag_slots->e_dups = 1;
					} else if (
						ssp->cmd_pkt.pkt_time == n) {
						tag_slots->e_dups++;
					}
				}
				tag_slots->e_timebase = n;
			} else {
				tag_slots->e_dups =
					tag_slots->e_timebase = 0;
			}
		    }
		}
		tag_slots->e_timeout = tag_slots->e_timebase;
	}
}


/*
 * Most commonly called phase handlers:
 *
 * Finish routines
 */
static int
esp_finish(struct esp *esp)
{
	short last_slot;
	struct esp_cmd *sp = CURRENT_CMD(esp);
	int action = ACTION_SEARCH;
	struct scsi_status *status =
	    (struct  scsi_status *)sp->cmd_pkt.pkt_scbp;

	TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_START,
	    "esp_finish_start");
	EPRINTF("esp_finish\n");
	ASSERT(esp->e_ncmds > esp->e_ndisc);

	if ((sp->cmd_pkt.pkt_state & STATE_GOT_STATUS) == 0) {
		status->sts_chk = 0;
	}

	last_slot = esp->e_last_slot = esp->e_cur_slot;
	esp->e_cur_slot = UNDEFINED;
	esp->e_ncmds--;
	sp->cmd_flags |= CFLAG_FINISHED;


#ifdef ESP_TEST_UNTAGGED
	if (esp_test_stop && (sp->cmd_pkt.pkt_flags & 0x80000000)) {
		debug_enter("untagged cmd completed");
	}
#endif


#ifdef	ESPDEBUG
	if (esp_test_stop && (sp->cmd_pkt.pkt_statistics & STAT_PERR)) {
		debug_enter("parity errors");
	}

	if (DEBUGGING) {
		eprintf(esp, "%d.%d; cmds=%d disc=%d lastmsg 0x%x\n",
			Tgt(sp), Lun(sp), esp->e_ncmds, esp->e_ndisc,
			esp->e_last_msgin);
		eprintf(esp, "\treason '%s'; cmd state 0x%b\n",
			scsi_rname(sp->cmd_pkt.pkt_reason),
			sp->cmd_pkt.pkt_state, scsi_state_bits);
	}
#endif	/* ESPDEBUG */

	if (status->sts_chk) {
		/*
		 * In the case that we are getting a check condition
		 * clear our knowledge of synchronous capabilities.
		 * This will unambiguously force a renegotiation
		 * prior to any possible data transfer (we hope),
		 * including the data transfer for a UNIT ATTENTION
		 * condition generated by somebody powering on and
		 * off a target.
		 * Note: only renegotiate if we were running sync mode
		 * with this target
		 */
		if (esp->e_offset[Tgt(sp)] != 0) {
			esp->e_sync_known &= ~(1<<Tgt(sp));
		}
	}

	/*
	 * backoff sync if there were parity errors
	 */
	if (sp->cmd_pkt.pkt_statistics & STAT_PERR) {
		esp_sync_backoff(esp, sp, last_slot);
	}

	/*
	 * go to state free and try to start a new cmd now
	 * don't start the next cmd if the current cmd was a RQSENSE; this
	 * will give the target driver a chance to do some recovery
	 */
	New_state(esp, STATE_FREE);

	esp->e_slots[last_slot] = NULL;

	/*
	 * Free tagged slot
	 */
	esp_remove_tagged_cmd(esp, sp, last_slot, NEW_TIMEOUT);

	if ((esp->e_ncmds > esp->e_ndisc) && (*((char *)status) == 0) &&
	    (*(sp->cmd_pkt.pkt_cdbp) != SCMD_REQUEST_SENSE)) {
		if (esp_ustart(esp, esp->e_last_slot, NEW_CMD)) {
			/*
			 * we used to always set action to ACTION_RETURN
			 * this leaves a small window where the
			 * ready queue is non-empty
			 * and doesn't get started
			 */
			action = ACTION_RETURN;
		}
	}

#ifdef ESP_TEST_RQSENSE
	if ((esp_test_rqsense & (1 << Tgt(sp))) &&
	    (*(sp->cmd_pkt.pkt_cdbp) != SCMD_REQUEST_SENSE)) {
		status->sts_chk = 1;
		esp->e_sync_known &= ~(1<<Tgt(sp));
		esp_test_rqsense = 0;
	}
#endif
#ifdef ESPDEBUG
	if ((sp->cmd_pkt.pkt_state & STATE_GOT_STATUS) && (espdebug > 1) &&
	    (status->sts_chk) && (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK)) {
		debug_enter("esp_finish with check condition");
	}
#endif

	if (sp->cmd_pkt.pkt_state & STATE_XFERRED_DATA) {
		sp->cmd_pkt.pkt_resid = sp->cmd_dmacount - sp->cmd_data_count;
		if (sp->cmd_flags & CFLAG_CMDIOPB) {
			(void) ddi_dma_sync(sp->cmd_dmahandle, 0, (uint_t)-1,
			    DDI_DMA_SYNC_FORCPU);
		}
#ifdef	ESPDEBUG
		if ((espdebug > 1) && (sp->cmd_pkt.pkt_resid)) {
			eprintf(esp, "%d.%d finishes with %ld resid\n",
			    Tgt(sp), Lun(sp), sp->cmd_pkt.pkt_resid);
		}
#endif	/* ESPDEBUG */
	}

#ifdef ESP_KSTATS
	/*
	 * update kstats
	 */
	if (esp_do_kstats && esp->e_slot_stats[last_slot]) {
		if (sp->cmd_flags & CFLAG_DMAVALID) {
			if (sp->cmd_flags & CFLAG_DMASEND) {
				IOSP(last_slot)->writes++;
				IOSP(last_slot)->nwritten += sp->cmd_data_count;
			} else {
				IOSP(last_slot)->reads++;
				IOSP(last_slot)->nread += sp->cmd_data_count;
			}
		}
		kstat_runq_exit(IOSP(last_slot));
	}
#endif /* ESP_KSTATS */


	/*
	 * NO_INTR pkts shouldn't have a pkt_comp callback
	 * but we call esp_call_pkt_comp() just to clean up
	 */
	if (sp->cmd_pkt.pkt_flags & FLAG_NOINTR) {
		esp_call_pkt_comp(esp, sp);
		action = ACTION_RETURN;

	} else if ((*sp->cmd_scbp & STATUS_MASK) == STATUS_QFULL) {
		esp_handle_qfull(esp, sp, last_slot);
	} else {
		/*
		 * start an autorequest sense if there was a check condition
		 */
		if (status->sts_chk &&
		    (sp->cmd_scblen >= sizeof (struct scsi_arq_status))) {
			if (esp_start_arq_pkt(esp, sp)) {
				/*
				 * auto request sense failed
				 * let the target driver handle it
				 */
				esp_call_pkt_comp(esp, sp);
			} else {
				action = ACTION_RETURN;
			}
		} else {
			esp_call_pkt_comp(esp, sp);
		}
	}

	TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_END, "esp_finish_end");
	return (action);
}

/*
 * Request sense commands are priority commands and can't get
 * QFULL condition.
 */
static void
esp_handle_qfull(struct esp *esp, struct esp_cmd *sp, int slot)
{
	if ((++sp->cmd_qfull_retries > esp->e_qfull_retries[Tgt(sp)]) ||
		(esp->e_qfull_retries[Tgt(sp)] == 0)) {
		/*
		 * We have exhausted the retries on QFULL, or,
		 * the target driver has indicated that it
		 * wants to handle QFULL itself by setting
		 * qfull-retries capability to 0. In either case
		 * we want the target driver's QFULL handling
		 * to kick in. We do this by having pkt_reason
		 * as CMD_CMPLT and pkt_scbp as STATUS_QFULL.
		 */
		IPRINTF2("%d.%d: status queue full, retries over\n",
			Tgt(sp), Lun(sp));
		esp_set_all_lun_throttles(esp, slot, DRAIN_THROTTLE);
		esp_call_pkt_comp(esp, sp);
	} else {
		if (esp->e_reset_delay[Tgt(sp)] == 0) {
			esp->e_throttle[slot] =
				max((esp->e_tcmds[slot] - 2), 0);
		}
		IPRINTF3("%d.%d: status queue full, new throttle = %d, "
			"retrying\n", Tgt(sp), Lun(sp), esp->e_throttle[slot]);
		sp->cmd_pkt.pkt_flags |= FLAG_HEAD;
		sp->cmd_flags &= ~CFLAG_TRANFLAG;
		(void) _esp_start(esp, sp, NO_TRAN_BUSY);
		if (esp->e_throttle[slot] == HOLD_THROTTLE) {
			/*
			 * By setting throttle to QFULL_THROTTLE, we
			 * avoid submitting new commands and in
			 * esp_restart_cmd find out slots which need
			 * their throttles to be cleared.
			 */
			esp_set_all_lun_throttles(esp, slot, QFULL_THROTTLE);
			mutex_enter(&esp_global_mutex);
			if ((esp->e_restart_cmd_timeid == 0) && ESP_CAN_SCHED) {
				esp->e_restart_cmd_timeid =
				    timeout(esp_restart_cmd, esp,
				    esp->e_qfull_retry_interval[Tgt(sp)]);
			}
			mutex_exit(&esp_global_mutex);
		}
	}
}

static void
esp_restart_cmd(void *esp_arg)
{
	struct esp *esp = esp_arg;
	int i;

	IPRINTF("esp_restart_cmd:\n");

	mutex_enter(ESP_MUTEX);
	esp->e_restart_cmd_timeid = 0;

	for (i = 0; i < N_SLOTS; i += NLUNS_PER_TARGET) {
		if (esp->e_reset_delay[i/NLUNS_PER_TARGET]) {
			continue;
		}
		if (esp->e_throttle[i] == QFULL_THROTTLE) {
			esp_set_all_lun_throttles(esp, i, CLEAR_THROTTLE);
		}
	}

	(void) esp_istart(esp);
	mutex_exit(ESP_MUTEX);
}

#ifdef ESP_CHECK
/*
 * this function checks whether a cmd is already queued
 * and also checks the counts (which are not always accurate but
 * usually on completion of the error recovery are OK again
 */
static int esp_do_check = 0;

static void
esp_check_in_transport(struct esp *esp, struct esp_cmd *sp)
{
	struct callback_info *cb_info = esp->e_callback_info;
	struct esp_cmd *qsp;
	int ncmds, ndiscs, i, slot;

	if (sp) {
		slot = Tgt(sp) * NLUNS_PER_TARGET | Lun(sp);

		ASSERT(sp != esp->e_slots[slot]);
		if (esp->e_tagQ[slot] != NULL) {
			for (i = 0; i < NTAGS; i++) {
				ASSERT(sp != esp->e_tagQ[slot]->t_slot[i]);
			}
		}

		mutex_enter(&cb_info->c_mutex);
		qsp = cb_info->c_qf;

		while (qsp) {
			ASSERT(sp != qsp);
			qsp = qsp->cmd_forw;
		}
		mutex_exit(&cb_info->c_mutex);

		/*
		 * command has not been started yet and is still
		 * in the ready queue
		 */

		if (esp->e_readyf[slot]) {
			for (qsp = esp->e_readyf[slot]; qsp != NULL;
			    qsp = qsp->cmd_forw) {
				ASSERT(qsp != sp);
				ASSERT((qsp->cmd_flags & CFLAG_COMPLETED)
				    == 0);
				ASSERT((qsp->cmd_flags & CFLAG_FREE) == 0);
				ASSERT((qsp->cmd_flags & CFLAG_FINISHED)
				    == 0);
				ASSERT((qsp->cmd_flags & CFLAG_CMDDISC) == 0);
			}
		}
	}

	/* count the number of cmds */
	ncmds = ndiscs = 0;
	for (slot = 0; slot < N_SLOTS; slot++) {
		if (esp->e_slots[slot]) {
			ncmds++;
			if ((esp->e_slots[slot])->cmd_flags & CFLAG_CMDDISC) {
				ndiscs++;
			}
		}

		for (qsp = esp->e_readyf[slot]; qsp != NULL;
		    qsp = qsp->cmd_forw) {
			if (qsp) {
				ncmds++;
				ASSERT((qsp->cmd_flags & CFLAG_COMPLETED)
				    == 0);
				ASSERT((qsp->cmd_flags & CFLAG_FREE) == 0);
				ASSERT((qsp->cmd_flags & CFLAG_FINISHED)
				    == 0);
			}
		}

		if (esp->e_tagQ[slot] != NULL) {
			for (i = 0; i < NTAGS; i++) {
			    if ((esp->e_tagQ[slot]->t_slot[i] != NULL) &&
				(esp->e_tagQ[slot]->t_slot[i] !=
				esp->e_slots[slot])) {
				    ncmds++;
				    qsp = esp->e_tagQ[slot]->t_slot[i];
				    if (qsp->cmd_flags & CFLAG_CMDDISC) {
					ndiscs++;
				    }
				    ASSERT((qsp->cmd_flags &
						CFLAG_COMPLETED) == 0);
				    ASSERT((qsp->cmd_flags & CFLAG_FREE)
								== 0);
				    ASSERT((qsp->cmd_flags &
							CFLAG_FINISHED) == 0);
			    }
			}
		}
	}

	if ((ncmds != esp->e_ncmds) || (ndiscs != esp->e_ndisc)) {
		if (esp_do_check)
			debug_enter("ncmds problem");
		eprintf(esp, "ncmds = %d, %d, ndisc = %d, %d\n",
			ncmds, esp->e_ncmds, ndiscs, esp->e_ndisc);
	}
}
#endif

/*
 * esp_call_pkt_comp does sanity checking to ensure that we don't
 * call completion twice on the same packet or a packet that has been freed.
 * if there is a completion function specified, the packet is queued
 * up and it is left to the esp_callback thread to empty the queue at
 * a lower priority; note that there is one callback queue per esp
 *
 * we use a separate thread for calling back into the target driver
 * this thread unqueues packets from the callback queue
 */
static void
esp_call_pkt_comp(struct esp *esp, struct esp_cmd *sp)
{
	TRACE_0(TR_FAC_SCSI, TR_ESP_CALL_PKT_COMP_START,
	    "esp_call_pkt_comp_start");
	ASSERT(sp != 0);
	ASSERT((sp->cmd_flags & CFLAG_COMPLETED) == 0);
	ASSERT((sp->cmd_flags & CFLAG_FREE) == 0);
	ASSERT(esp->e_ncmds >= esp->e_ndisc);

	esp_check_in_transport(esp, sp);

	sp->cmd_flags &= ~CFLAG_IN_TRANSPORT;
	sp->cmd_flags |= CFLAG_COMPLETED;
	sp->cmd_qfull_retries = 0;


	/*
	 * if there is a completion function and this is not an arq pkt
	 * or immediate callback pkt then queue up the callback
	 */
	if (sp->cmd_pkt.pkt_comp && !(sp->cmd_flags & CFLAG_CMDARQ) &&
	    !(sp->cmd_pkt.pkt_flags & FLAG_IMMEDIATE_CB)) {
		struct callback_info *cb_info = esp->e_callback_info;

		if (sp->cmd_pkt.pkt_reason != CMD_CMPLT) {
			IPRINTF6("completion for %d.%d, sp=0x%p, "
			    "reason=%s, stats=%x, state=%x\n",
				Tgt(sp), Lun(sp), (void *)sp,
				scsi_rname(sp->cmd_pkt.pkt_reason),
				sp->cmd_pkt.pkt_statistics,
				sp->cmd_pkt.pkt_state);
		} else {
			EPRINTF2("completion queued for %d.%d\n",
				Tgt(sp), Lun(sp));
		}

		/*
		 * append the packet or start a new queue
		 */
		mutex_enter(&cb_info->c_mutex);
		if (cb_info->c_qf) {
			/*
			 * add to tail
			 */
			struct esp_cmd *dp = cb_info->c_qb;
			ASSERT(dp != NULL);
			cb_info->c_qb = sp;
			sp->cmd_forw = NULL;
			dp->cmd_forw = sp;
		} else {
			/*
			 * start new queue
			 */
			cb_info->c_qf = cb_info->c_qb = sp;
			sp->cmd_forw = NULL;
		}
		cb_info->c_qlen++;
		esp->e_callback_signal_needed = cb_info->c_signal_needed = 1;
		mutex_exit(&cb_info->c_mutex);

	} else if ((sp->cmd_flags & CFLAG_CMDARQ) && sp->cmd_pkt.pkt_comp) {
		/*
		 * pkt_comp may be NULL when we are aborting/resetting but then
		 * the callback will be redone later
		 */
		int slot = Tgt(sp) * NLUNS_PER_TARGET | Lun(sp);
		/*
		 * this recurses!
		 */
		esp_complete_arq_pkt(esp, sp, slot);

	} else if ((sp->cmd_pkt.pkt_flags & FLAG_IMMEDIATE_CB) &&
	    sp->cmd_pkt.pkt_comp) {
		mutex_exit(ESP_MUTEX);
		(*sp->cmd_pkt.pkt_comp)(&sp->cmd_pkt);
		mutex_enter(ESP_MUTEX);
	} else {
		EPRINTF2("No completion routine for 0x%p reason %x\n",
		    (void *)sp, sp->cmd_pkt.pkt_reason);
	}
	TRACE_0(TR_FAC_SCSI, TR_ESP_CALL_PKT_COMP_END,
	    "esp_call_pkt_comp_end");
}

/*
 * Complete the process of selecting a target
 */
static int
esp_finish_select(struct esp *esp)
{
	volatile struct espreg *ep = esp->e_reg;
	volatile struct dmaga *dmar = esp->e_dma;
	struct esp_cmd *sp = CURRENT_CMD(esp);
	int cmdamt, fifoamt;
	uchar_t intr = esp->e_intr;
	uchar_t step;
	ushort_t state = esp->e_state;
	int target;

	TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_SELECT_START,
	    "esp_finish_select_start");
	EPRINTF("esp_finish_select:\n");
	step = esp->e_step = (ep->esp_step & ESP_STEP_MASK);

	ASSERT(esp->e_cur_slot != UNDEFINED);

	if (sp == NULL) {
		/*
		 * this shouldn't happen but sometimes does after a
		 * device reset
		 */
		esplog(esp, CE_WARN, "bad selection");
		return (ACTION_RESET);
	}

	target = Tgt(sp);

	ASSERT(esp->e_cur_slot == ((Tgt(sp) * NLUNS_PER_TARGET) | Lun(sp)));

	/*
	 * Check for DMA gate array errors
	 */
	if ((esp->e_dmaga_csr = dmar->dmaga_csr) & DMAGA_ERRPEND) {
		/*
		 * It would be desirable to set the ATN* line and attempt to
		 * do the whole schmear of INITIATOR DETECTED ERROR here,
		 * but that is too hard to do at present.
		 */
		esplog(esp, CE_WARN,
		    "Unrecoverable DMA error during selection");
		if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
			sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
		TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_SELECT_RESET1_END,
		    "esp_finish_select_end (ACTION_RESET1)");
		return (ACTION_RESET);
	}

	/*
	 * Latch up fifo count
	 */
	fifoamt = FIFO_CNT(ep);

	/*
	 * How far did we go (by the DMA gate array's reckoning)?
	 */
	cmdamt = dmar->dmaga_addr - esp->e_lastdma;

	/*
	 * If the NEXTBYTE value is non-zero (and we have the
	 * rev 1 DMA gate array), we went one longword further
	 * less 4 minus the NEXTBYTE value....
	 */
	if (ESP_DMAGA_REV(esp) == DMA_REV1) {
		int i;
		if ((i = DMAGA_NEXTBYTE(dmar)) != 0) {
			cmdamt -= (4-i);
		}
	}

	/*
	 * Shut off DMA gate array
	 */
	ESP_FLUSH_DMA(esp);

	/*
	 * Now adjust cmdamt by the amount of data left in the fifo
	 */
	cmdamt -= fifoamt;

	/*
	 * Be a bit defensive...
	 */
	if (cmdamt < 0 || cmdamt > FIFOSIZE) {
		cmdamt = 0;
	}

#ifdef	ESPDEBUG
	if (DEBUGGING) {
		eprintf(esp,
		    "finsel: state %s, step %d; did %d of %d; fifo %d\n",
		    esp_state_name(state), step, cmdamt,
		    esp->e_lastcount, fifoamt);
		esp_stat_int_print(esp);
	}
#endif	/* ESPDEBUG */

	/*
	 * Did something respond to selection?
	 */
	if (intr == (ESP_INT_BUS|ESP_INT_FCMP)) {
		/*
		 * We successfully selected a target (we think).
		 * Now we figure out how botched things are
		 * based upon the kind of selection we were
		 * doing and the state of the step register.
		 */

		switch (step) {
		case ESP_STEP_ARBSEL:
			/*
			 * In this case, we selected the target, but went
			 * neither into MESSAGE OUT nor COMMAND phase.
			 * However, this isn't a fatal error, so we just
			 * drive on.
			 *
			 * This might be a good point to note that we have
			 * a target that appears to not accommodate
			 * disconnecting,
			 * but it really isn't worth the effort to distinguish
			 * such targets especially from others.
			 */
			/* FALLTHROUGH */

		case ESP_STEP_SENTID:
			/*
			 * In this case, we selected the target and sent
			 * message byte and have stopped with ATN* still on.
			 * This case should only occur if we use the SELECT
			 * AND STOP command.
			 */
			/* FALLTHROUGH */

		case ESP_STEP_NOTCMD:
			/*
			 * In this case, we either didn't transition to command
			 * phase, or,
			 * if we were using the SELECT WITH ATN3 command,
			 * we possibly didn't send all message bytes.
			 */
			cmdamt = 0;
			break;

		case ESP_STEP_PCMD:
			/*
			 * In this case, not all command bytes transferred.
			 */
			/* FALLTHROUGH */

		case ESP_STEP_DONE:
step_done:
			/*
			 * This is the usual 'good' completion point.
			 * If we we sent message byte(s), we subtract
			 * off the number of message bytes that were
			 * ahead of the command.
			 */
			sp->cmd_pkt.pkt_state |= STATE_SENT_CMD;
			if (state == STATE_SELECT_NORMAL)
				cmdamt -= 1;
			break;

		case ESP_STEP_DONE5:
		case ESP_STEP_DONE6:
		case ESP_STEP_DONE7:
			/*
			 * this happens on some sun4m boards; probably a hw bug
			 */
			if ((esp->e_options & ESP_OPT_ACCEPT_STEP567)) {
				goto step_done;
			}
			/* FALLTHROUGH */

		default:
			esplog(esp, CE_WARN,
			    "bad sequence step (0x%x) in selection", step);
			TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_SELECT_RESET3_END,
			    "esp_finish_select_end (ACTION_RESET3)");
			return (ACTION_RESET);
		}

		if ((esp->e_options & ESP_OPT_FAS) == 0) {
			/*
			 * If we sent any messages or sent a command, as
			 * per ESP errata sheets, we have to hit the
			 * chip with a CMD_NOP in order to unlatch the
			 * fifo counter.
			 */
			Esp_cmd(esp, CMD_NOP);

			/*
			 * *Carefully* dump out any cruft left in the fifo.
			 * If this target has shifted to synchronous DATA IN
			 * phase, then the ESP has already flushed the fifo
			 * for us.
			 */
			if (fifoamt != 0 &&
			    ((esp->e_stat & ESP_PHASE_MASK) !=
			    ESP_PHASE_DATA_IN ||
			    esp->e_offset[target] == 0)) {
				esp_flush_fifo(esp);
			}
		}

		/*
		 * OR in common state...
		 */
		sp->cmd_pkt.pkt_state |= (STATE_GOT_BUS|STATE_GOT_TARGET);

		/*
		 * advance command pointer
		 */
		if (cmdamt > 0) {
			sp->cmd_pkt.pkt_state |= STATE_SENT_CMD;
			sp->cmd_cdbp = (uchar_t *)sp->cmd_cdbp + cmdamt;
		}

		/*
		 * data pointer initialization has already been done
		 */
		New_state(esp, ACTS_UNKNOWN);
		TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_SELECT_ACTION3_END,
		    "esp_finish_select_end (action3)");
		return (esp_handle_unknown(esp));

	} else if (intr == ESP_INT_DISCON) {
		/*
		 * This takes care of getting the bus, but no
		 * target responding to selection. Clean up the
		 * chip state.
		 */
		esp_chip_disconnect(esp, sp);

		/*
		 * There is a definite problem where the MT02
		 * drops BSY if you use the SELECT && STOP command,
		 * which leaves ATN asserted after sending an identify
		 * message.
		 */
		if (step != 0 &&
		    (state == STATE_SELECT_N_SENDMSG ||
		    state == STATE_SELECT_N_TAG ||
		    state == STATE_SELECT_N_STOP)) {

			if ((state == STATE_SELECT_N_SENDMSG ||
			    (state == STATE_SELECT_N_STOP)) &&
			    esp->e_cur_msgout[0] == MSG_EXTENDED) {
				int slot = esp->e_cur_slot;

				IPRINTF("esp_finish_sel:  sync neg. failed\n");
				esp->e_sync_known |= (1<<target);
				esp->e_weak |= (1<<target);
				New_state(esp, STATE_FREE);
				if ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) {

					/*
					 * Rerun the command again.
					 * if not a proxy cmd
					 */
#ifdef ESP_KSTATS
					/*
					 * update kstats
					 */
					if (esp_do_kstats &&
					    esp->e_slot_stats[slot]) {
					    kstat_runq_back_to_waitq(
						IOSP(slot));
					}
#endif /* ESP_KSTATS */
					(void) esp_ustart(esp, slot, SAME_CMD);
					TRACE_0(TR_FAC_SCSI,
					    TR_ESP_FINISH_SELECT_RETURN1_END,
					    "esp_finish_select_end (RETURN1)");
					return (ACTION_RETURN);
				}

			} else if (esp->e_state == STATE_SELECT_N_TAG) {
				int slot = esp->e_cur_slot;
				/*
				 * target rejected tag and dropped off the
				 * bus
				 * clear tag slot and tag
				 */
				IPRINTF("esp_finish_sel: tag asking failed\n");

				esp_remove_tagged_cmd(esp, sp, slot, 0);
				esp->e_notag |= (1<<target);
				sp->cmd_pkt.pkt_flags &=  ~FLAG_TAGMASK;

				/*
				 * Rerun the command again.
				 */
#ifdef ESP_KSTATS
				/*
				 * update kstats
				 */
				if (esp_do_kstats &&
				    esp->e_slot_stats[slot]) {
				    kstat_runq_back_to_waitq(IOSP(slot));
				}
#endif /* ESP_KSTATS */
				New_state(esp, STATE_FREE);

				/* esp_runpoll() will retry nointr cmds */
				if ((sp->cmd_pkt.pkt_flags &
				    FLAG_NOINTR) == 0) {
					(void) esp_ustart(esp, slot, SAME_CMD);
				}

				TRACE_0(TR_FAC_SCSI,
				    TR_ESP_FINISH_SELECT_RETURN2_END,
				    "esp_finish_select_end (ACTION_RETURN2)");
				return (ACTION_RETURN);
			}
		}

		sp->cmd_pkt.pkt_state |= STATE_GOT_BUS;
		if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
			sp->cmd_pkt.pkt_reason = CMD_INCOMPLETE;
		TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_SELECT_FINISH_END,
		    "esp_finish_select_end (ACTION_FINISH)");
		return (ACTION_FINISH);

	} else if (intr == (ESP_INT_FCMP|ESP_INT_RESEL)) {
		/*
		 * A reselection attempt glotzed our selection attempt.
		 * If we were running w/o checking parity on this
		 * command, restore parity checking.
		 * we put request back in the ready queue
		 */
		int slot;
		struct esp_cmd *dp;

		slot = esp->e_cur_slot;
#ifdef ESP_KSTATS
		if (esp_do_kstats && esp->e_slot_stats[slot]) {
			kstat_runq_back_to_waitq(IOSP(slot));
		}
#endif /* ESP_KSTATS */
		ESP_PREEMPT(esp);
		LOG_STATE(esp, ACTS_PREEMPTED, esp->e_stat, 0, -1);
		if ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) {
			esp->e_slots[slot] = (struct esp_cmd *)NULL;
			esp_remove_tagged_cmd(esp, sp, slot, 0);
		}
		if (sp->cmd_pkt.pkt_flags & FLAG_NOINTR) {
			/*
			 * runpoll will try again so no need to put it
			 * on ready Q
			 */
			TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_SELECT_ACTION1_END,
			    "esp_finish_select_end (action1)");
			return (esp_reconnect(esp));
		}

		dp = esp->e_readyf[slot];
		esp->e_readyf[slot] = sp;
		sp->cmd_forw = dp;
		if (esp->e_readyb[slot] == NULL) {
			esp->e_readyb[slot] = sp;
		}
		if ((esp->e_target_scsi_options[target] &
			SCSI_OPTIONS_PARITY) &&
			(sp->cmd_pkt.pkt_flags & FLAG_NOPARITY)) {
			ep->esp_conf = esp->e_espconf;
		}
		TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_SELECT_ACTION2_END,
		    "esp_finish_select_end (action2)");
		return (esp_reconnect(esp));

	} else if (intr != (ESP_INT_BUS|ESP_INT_FCMP)) {
		esplog(esp, CE_WARN, "undetermined selection failure");
#ifdef ESPDEBUG
		esp_stat_int_print(esp);
#endif
		TRACE_0(TR_FAC_SCSI, TR_ESP_FINISH_SELECT_RESET2_END,
		    "esp_finish_select_end (ACTION_RESET2)");
		return (ACTION_RESET);
	}
	_NOTE(NOT_REACHED)
	/* NOTREACHED */
	return (ACTION_FINSEL);
}

/*
 * Handle the reconnection of a target
 */
static char *botched_tag =
	"Target %d.%d botched tagged queuing msg (0x%x, 0x%x)";

/*
 * Identify msg. to target number conversion table.
 * Note, id's > 64 are multi-bit and thus invalid so we don't
 * need bigger table.
 */
static char scsi_targetid[] = {
/*	 0   1	 2   3	 4   5	 6   7	 8   9	 a   b	 c   d	 e   f */
	-1,  0,	 1, -1,	 2, -1, -1, -1,	 3, -1, -1, -1, -1, -1, -1, -1,
	04, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	05, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	06, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	7
};

static int
esp_reconnect(struct esp *esp)
{
	volatile struct espreg *ep = esp->e_reg;
	struct esp_cmd *sp;
	char target, lun;
	uchar_t tmp, myid = (1<<MY_ID(esp));
	short slot = -1;
	uchar_t period, offset, conf3;
	int msg_accept_issued = 0;
	char *bad_reselect = NULL;

	TRACE_0(TR_FAC_SCSI, TR_ESP_RECONNECT_START,
	    "esp_reconnect_start");
	EPRINTF("esp_reconnect:\n");

	switch (esp->e_state) {
	default:
		/*
		 * normal initial reconnect; we get another interrupt later
		 * for the tag
		 */
		New_state(esp, ACTS_RESEL);

		/*
		 * Pick up target id from fifo
		 *
		 * There should only be the reselecting target's id
		 * and an identify message in the fifo.
		 */
		if (FIFO_CNT(ep) != 2) {
			bad_reselect = "bad reselect bytes";
			goto bad;
		}

		tmp = ep->esp_fifo_data;

		if ((tmp & myid) == 0) {
			/*
			 * Our SCSI id is missing. This 'cannot happen'.
			 */
			bad_reselect = "scsi id is missing";
			goto bad;
		}

		/*
		 * Turn off our id
		 */
		tmp ^= myid;

		if (tmp == 0) {
			/*
			 * There is no other SCSI id, therefore we cannot
			 * tell who is reselecting us. This 'cannot happen'.
			 */
			bad_reselect = "no other scsi id";
			goto bad;
		}

		target = scsi_targetid[tmp];
		if (target == -1) {
			/*
			 * There is more than one reselection id on the bus.
			 * This 'cannot happen'.
			 */
			bad_reselect = ">2 reselection IDs on the bus";
			goto bad;
		}

		/*
		 * Now pick up identify message byte, and acknowledge it.
		 */
		if ((esp->e_stat & ESP_PHASE_MASK) != ESP_PHASE_MSG_IN) {
			/*
			 * If we aren't in MESSAGE IN phase,
			 * things are really screwed up.
			 */
			bad_reselect = "not in msg-in phase";
			goto bad;
		}

		tmp = esp->e_last_msgin = ep->esp_fifo_data;

		/*
		 * XXX: Oh boy. We have problems. What happens
		 * XXX: if we have a parity error on the IDENTIFY
		 * XXX: message? We cannot know which lun is
		 * XXX: reconnecting, but we really need to know
		 * XXX: that in order to go through all the
		 * XXX: rigamarole of sending a MSG_PARITY_ERR
		 * XXX: message back to the target.
		 * XXX:
		 * XXX: In order to minimize a panic situation,
		 * XXX: we'll assume a lun of zero (i.e., synthesize
		 * XXX: the IDENTIFY message), and only panic
		 * XXX: if there is more than one active lun on
		 * XXX: this target.
		 */
		if (esp->e_stat & ESP_STAT_PERR) {
			tmp = MSG_IDENTIFY;
		}

		/*
		 * Check sanity of message.
		 */
		if (!(IS_IDENTIFY_MSG(tmp)) || (tmp & INI_CAN_DISCON)) {
			bad_reselect = "bad message";
			goto bad;
		}

		lun = tmp & (NLUNS_PER_TARGET-1);

		LOG_STATE(esp, ACTS_RESEL, esp->e_stat, target, lun);

		if ((esp->e_options & ESP_OPT_FAS) == 0) {

			esp_flush_fifo(esp);

			/*
			 * As per the ESP100 errata sheets, if a selection
			 * attempt is preempted by a reselection coming in,
			 * we'll get a spurious ILLEGAL COMMAND error
			 * interrupt from the ESP100.
			 * Instead of trying to figure out whether we were
			 * preempted or not, just gate off of whether
			 * we are an ESP100 or not.
			 */
			if (IS_53C90(esp)) {
				tmp = ep->esp_intr;
				if (tmp & ESP_INT_RESET) {
					TRACE_0(TR_FAC_SCSI,
					    TR_ESP_RECONNECT_F1_END,
					    "esp_reconnect_end (_F1)");
					return (ACTION_FINRST);
				}
			}

			/*
			 * I believe that this needs to be done to
			 * unlatch the ESP.
			 */
			Esp_cmd(esp, CMD_NOP);
		}


		/*
		 * If this target is synchronous, here is the
		 * place to set it up during a reconnect.
		 * Must setup for sync xfers because once identify msg ack'ed,
		 * we can go into data in phase and begin transferring data.
		 */
		period =  esp->e_period[target] & SYNC_PERIOD_MASK;
		offset = esp->e_offset[target];
		conf3 = esp->e_espconf3[target];
		if ((esp->e_period_last != period) ||
		    (esp->e_offset_last != offset) ||
		    (esp->e_espconf3_last != conf3)) {
			esp->e_period_last = ep->esp_sync_period = period;
			esp->e_offset_last = ep->esp_sync_offset = offset;
			esp->e_espconf3_last = ep->esp_conf3 = conf3;
		}

		esp->e_cur_slot = slot = (target * NLUNS_PER_TARGET) | lun;

		/*
		 * If tag queuing in use, DMA in tag.
		 * Otherwise, we're ready to go.
		 * XXX make this non-polled, interrupt driven
		 */
		if (TAGGED(target) && esp->e_tcmds[slot]) {
			volatile uchar_t *c =
				(uchar_t *)esp->e_cmdarea;

			/*
			 * accept the identify msg
			 */
			Esp_cmd(esp, CMD_MSG_ACPT);

			/*
			 * If we've been doing tagged queuing and this
			 * request doesn't  do it,
			 * maybe it was disabled for this one.	This is rather
			 * dangerous as it blows all pending tagged cmds away.
			 * But if target is confused, then we'll blow up
			 * shortly.
			 */
			*c++ = INVALID_MSG;
			*c   = INVALID_MSG;

			ESP_DMA_WRITE(esp, 2,
			    esp->e_dmacookie.dmac_address);

			/*
			 * For tagged queuing, we should still be in msgin
			 * phase.
			 * If not, then either we aren't running tagged
			 * queuing like we thought or the target died.
			 */
			if (INTPENDING(esp) == 0) {
				EPRINTF1("slow reconnect, slot=%x\n", slot);
				TRACE_0(TR_FAC_SCSI,
				    TR_ESP_RECONNECT_RETURN1_END,
				    "esp_reconnect_end (_RETURN1)");
				return (ACTION_RETURN);
			}

			esp->e_stat = ep->esp_stat;
			esp->e_intr = ep->esp_intr;
			if (esp->e_intr & ESP_INT_RESET) {
				TRACE_0(TR_FAC_SCSI, TR_ESP_RECONNECT_F2_END,
				    "esp_reconnect_end (_F2)");
				return (ACTION_FINRST);
			}
			if ((esp->e_stat & ESP_PHASE_MASK) !=
			    ESP_PHASE_MSG_IN) {
				bad_reselect = "not in msgin phase";
				sp = NULL;
				goto NO_TAG_MSG;
			}

			if (esp->e_intr & ESP_INT_DISCON) {
				bad_reselect = "unexpected bus free";
				goto bad;
			}
		} else {
			sp = esp->e_slots[slot];
			break;
		}
		/*FALLTHROUGH*/

	case ACTS_RESEL:
		{
			volatile uchar_t *c =
				(uchar_t *)esp->e_cmdarea;
			struct t_slots *tag_slots;
			int id, tag;
			uint_t i;

			if ((esp->e_stat & ESP_PHASE_MASK) !=
			    ESP_PHASE_MSG_IN) {
				IPRINTF1("no tag for slot %x\n",
				    esp->e_cur_slot);
				if (esp->e_intr & ~(ESP_INT_BUS |
				    ESP_INT_FCMP)) {
					New_state(esp, ACTS_UNKNOWN);
					TRACE_0(TR_FAC_SCSI,
					    TR_ESP_RECONNECT_PHASEMANAGE_END,
					    "esp_reconnect_end (_PHASEMANAGE)");
					return (ACTION_PHASEMANAGE);
				} else {
					sp = NULL;
					bad_reselect = "not in msgin phase";
					break;
				}
			}

			Esp_cmd(esp, CMD_DMA | CMD_TRAN_INFO);
			msg_accept_issued = 1;
			Esp_cmd(esp, CMD_MSG_ACPT);

			for (i = 0; i < (uint_t)RECONNECT_TAG_RCV_TIMEOUT;
			    i++) {
				/*
				 * timeout is not very accurate but this
				 * should take no time at all
				 */
				if (INTPENDING(esp)) {
					esp->e_stat = esp->e_reg->esp_stat;
					esp->e_intr = esp->e_reg->esp_intr;
					if (esp->e_intr & ESP_INT_RESET) {
						TRACE_0(TR_FAC_SCSI,
						    TR_ESP_RECONNECT_F3_END,
						    "esp_reconnect_end (_F3)");
						return (ACTION_FINRST);
					}
					if (esp->e_intr & ESP_INT_FCMP) {
						break;
					}
				}
				drv_usecwait(1);
			}

			if (i == (uint_t)RECONNECT_TAG_RCV_TIMEOUT) {
				bad_reselect = "timeout on tag byte";
				sp = NULL;
				goto NO_TAG_MSG;
			}

			ESP_DRAIN_DMA(esp);

			/*
			 * XXX we should really do a sync here but that
			 * hurts performance too much; we'll just hang
			 * around till the tag byte flips
			 * This is necessary on any system with an
			 * XBox
			 */
			if (*c == INVALID_MSG) {
				EPRINTF(
				    "esp_reconnect: invalid msg, polling\n");
				for (i = 0; i < 1000000; i++) {
					if (*c != INVALID_MSG)
						break;
				}
			}

			if (esp->e_stat & ESP_STAT_PERR) {
				sp = NULL;
				bad_reselect = "parity error in tag msg";
				goto NO_TAG_MSG;
			}

			slot = esp->e_cur_slot;
			target = slot/NLUNS_PER_TARGET;

			if ((esp->e_stat & ESP_STAT_XZERO) == 0 ||
			    (id = *c++) < MSG_SIMPLE_QTAG ||
			    id > MSG_ORDERED_QTAG) {
				/*
				 * Target agreed to do tagged queuing
				 * and lied!
				 * This problem implies the drive firmware is
				 *  broken.
				 */
				lun = slot % NLUNS_PER_TARGET;
				esplog(esp, CE_WARN, botched_tag, target,
				    lun, id, *c);
				sp = NULL;
				bad_reselect = "botched tag";
				goto NO_TAG_MSG;
			}
			tag = *c;

			LOG_STATE(esp, ACTS_TAG, id, tag, -1);

			/* Set ptr to reconnecting scsi pkt */
			tag_slots = esp->e_tagQ[slot];
			if (tag_slots != NULL) {
				sp = tag_slots->t_slot[tag];
			} else {
				EPRINTF2("Invalid tag, que= 0x%x tag= %d\n",
				    id, tag);
				sp = NULL;
				bad_reselect = "invalid tag";
			}

			esp->e_slots[slot] = sp;
		}
	}

NO_TAG_MSG:
	if (esp->e_stat & ESP_STAT_PERR) {
		bad_reselect = "parity error";
		sp = 0;
	}

	if ((sp == (struct esp_cmd *)0) ||
#ifdef ESP_TEST_ABORT
	    (esp_atest_reconn & (1<<Tgt(sp))) ||
#endif
	    (sp->cmd_flags & (CFLAG_CMDDISC|CFLAG_CMDPROXY)) == 0) {
		/*
		 * this shouldn't really happen, so it is better
		 * to reset the bus; some disks accept the abort
		 * and then still reconnect
		 */
#ifdef ESP_TEST_ABORT
		esp_atest_reconn = 0;
#endif
		if (bad_reselect == NULL) {
			bad_reselect = "no valid cmd";
		}
		goto bad;

	} else if (sp->cmd_flags & CFLAG_CMDPROXY) {
		/*
		 * If we got here, we were already attempting to
		 * run a polled proxy command for this target.
		 * Set ATN and, copy in the message, and drive
		 * on (ignoring any parity error on the identify).
		 * XXX this may not be very useful....
		 */
		IPRINTF2("esp_reconnect: fielding proxy cmd for %d.%d\n",
		    target, lun);
		Esp_cmd(esp, CMD_SET_ATN);
		esp->e_omsglen = sp->cmd_cdb[ESP_PROXY_DATA];
		tmp = 0;
		while (tmp < esp->e_omsglen) {
			esp->e_cur_msgout[tmp] =
			    sp->cmd_cdb[ESP_PROXY_DATA+1+tmp];
			tmp++;
		}
		sp->cmd_cdb[ESP_PROXY_RESULT] = FALSE;

		/*
		 * pretend that the disconnected cmd is still disconnected
		 * (this prevents ndisc from going negative)
		 */
		esp->e_ndisc++;

	} else if (esp->e_target_scsi_options[target] & SCSI_OPTIONS_PARITY) {
		/*
		 * If we are doing PARITY checking, check for a parity
		 * error on the IDENTIFY message.
		 */
		if (sp->cmd_pkt.pkt_flags & FLAG_NOPARITY) {
			/*
			 * If we had detected a parity error
			 * on the IDENTIFY message, and this
			 * command is being run without checking,
			 * act as if we didn't get a parity
			 * error. The assumption here is that
			 * we only disable parity checking for
			 * targets that don't generate parity.
			 */
			ep->esp_conf = esp->e_espconf & ~ESP_CONF_PAREN;
		} else if (esp->e_stat & ESP_STAT_PERR) {
			esp->e_cur_msgout[0] = MSG_MSG_PARITY;
			esp->e_omsglen = 1;
		}
	}
	ASSERT(sp->cmd_flags & CFLAG_IN_TRANSPORT);

	/*
	 * Accept the last message if we haven't done so
	 */
	if (msg_accept_issued == 0) {
		Esp_cmd(esp, CMD_MSG_ACPT);
	}

	ASSERT(esp->e_cur_slot == slot);
	ASSERT(esp->e_ndisc > 0);
	esp->e_ndisc--;
	sp->cmd_flags &= ~CFLAG_CMDDISC;
	New_state(esp, ACTS_UNKNOWN);

	/*
	 * A reconnect may imply a restore pointers operation
	 * Note that some older disks (Micropolis in Pbox) do not
	 * send a save data ptr on disconnect if all data has been
	 * xferred. So, we cannot restore ptrs yet here.
	 */
	if ((sp->cmd_flags & CFLAG_DMAVALID) &&
	    (sp->cmd_data_count != sp->cmd_saved_data_count)) {
		sp->cmd_flags |= CFLAG_RESTORE_PTRS;
	}

	/*
	 * And zero out the SYNC negotiation counter
	 */
	esp->e_sdtr = 0;

	/*
	 * Return to await the FUNCTION COMPLETE interrupt we
	 * should get out of accepting the IDENTIFY message.
	 */
	EPRINTF2("Reconnecting %d.%d\n", target, lun);
	TRACE_0(TR_FAC_SCSI, TR_ESP_RECONNECT_RETURN2_END,
	    "esp_reconnect_end (_RETURN2)");
	return (ACTION_RETURN);

bad:
	esplog(esp, CE_WARN, "failed reselection (%s)", bad_reselect);
#ifdef ESPDEBUG
	esp_printstate(esp, "failed reselection");
#endif
	LOG_STATE(esp, ACTS_BAD_RESEL, esp->e_stat, -1, -1);
	TRACE_0(TR_FAC_SCSI, TR_ESP_RECONNECT_RESET5_END,
	    "esp_reconnect_end (_RESET5)");
	return (ACTION_RESET);
}

static int
esp_handle_unknown(struct esp *esp)
{
	TRACE_1(TR_FAC_SCSI, TR_ESP_HANDLE_UNKNOWN_START,
	    "esp_handle_unknown_start: esp 0x%p", (void *)esp);
	EPRINTF("esp_handle_unknown:\n");
	LOG_STATE(esp, ACTS_UNKNOWN, esp->e_stat, -1, -1);

	if ((esp->e_intr & ESP_INT_DISCON) == 0) {
		/*
		 * we call actions here rather than returning to phasemanage
		 * (this is the most frequently called action)
		 */
		switch (esp->e_stat & ESP_PHASE_MASK) {
		case ESP_PHASE_DATA_IN:
		case ESP_PHASE_DATA_OUT:
			New_state(esp, ACTS_DATA);
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_UNKNOWN_PHASE_DATA_END,
			    "esp_handle_unknown_end (phase_data)");
			return (esp_handle_data(esp));

		case ESP_PHASE_MSG_OUT:
			New_state(esp, ACTS_MSG_OUT);
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_UNKNOWN_PHASE_MSG_OUT_END,
			    "esp_handle_unknown_end (phase_msg_out)");
			return (esp_handle_msg_out(esp));

		case ESP_PHASE_MSG_IN:
			New_state(esp, ACTS_MSG_IN);
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_UNKNOWN_PHASE_MSG_IN_END,
			    "esp_handle_unknown_end (phase_msg_in)");
			return (esp_handle_msg_in(esp));

		case ESP_PHASE_STATUS:
			esp_flush_fifo(esp);
#ifdef	ESP_TEST_PARITY
			if (esp_ptest_status & (1<<Tgt(CURRENT_CMD(esp)))) {
				Esp_cmd(esp, CMD_SET_ATN);
			}
#endif	/* ESP_TEST_PARITY */
			if (esp->e_options & ESP_OPT_STACKED_CMDS) {
				/*
				 * use a stacked cmd to complete
				 * and accept the msg
				 *
				 * stacked cmds sometimes fail with FAS101
				 * and some slow disks; they are only
				 * reliable on FAS236
				 */
				volatile uchar_t *c =
					(uchar_t *)esp->e_cmdarea;

				*c++ = INVALID_MSG;
				*c   = INVALID_MSG;

				ESP_DMA_WRITE(esp, 2,
				    esp->e_dmacookie.dmac_address);

				Esp_cmd(esp, CMD_COMP_SEQ | CMD_DMA);
				/*
				 * no back to back accesses to esp
				 */
				New_state(esp, ACTS_C_CMPLT);
				Esp_cmd(esp, CMD_MSG_ACPT);
			} else {
				Esp_cmd(esp, CMD_COMP_SEQ);
				New_state(esp, ACTS_C_CMPLT);
			}
			LOG_STATE(esp, ACTS_C_CMPLT, esp->e_stat, -1, -1);
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_UNKNOWN_PHASE_STATUS_END,
			    "esp_handle_unknown_end (phase_status)");
			return (esp_handle_c_cmplt(esp));

		case ESP_PHASE_COMMAND:
			New_state(esp, ACTS_CMD_START);
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_UNKNOWN_PHASE_CMD_END,
			    "esp_handle_unknown_end (phase_cmd)");
			return (esp_handle_cmd_start(esp));
		}

		esp_printstate(esp, "Unknown bus phase");
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_UNKNOWN_RESET_END,
		    "esp_handle_unknown_end (reset)");
		return (ACTION_RESET);

	} else {
		/*
		 * Okay. What to do now? Let's try (for the time being)
		 * assuming that the target went south and dropped busy,
		 * as a disconnect implies that either we received
		 * a completion or a disconnect message, or that we
		 * had sent an ABORT OPERATION or BUS DEVICE RESET
		 * message. In either case, we expected the disconnect
		 * and should have fielded it elsewhere.
		 *
		 * If we see a chip disconnect here, this is an unexpected
		 * loss of BSY*. Clean up the state of the chip and return.
		 *
		 */
		int msgout = esp->e_cur_msgout[0];
		struct esp_cmd *sp = CURRENT_CMD(esp);
		int target = Tgt(sp);

		esp_chip_disconnect(esp, sp);

		if (msgout == MSG_HEAD_QTAG || msgout == MSG_SIMPLE_QTAG) {
			msgout = esp->e_cur_msgout[2];
		}
		EPRINTF4("msgout: %x %x %x, last_msgout=%x\n",
			esp->e_cur_msgout[0], esp->e_cur_msgout[1],
			esp->e_cur_msgout[2], esp->e_last_msgout);

		if (msgout == MSG_ABORT || msgout == MSG_ABORT_TAG ||
		    msgout == MSG_DEVICE_RESET) {
			IPRINTF2("Successful %s message to target %d\n",
			    scsi_mname(msgout), Tgt(sp));

			if (sp->cmd_flags & CFLAG_CMDPROXY) {
				sp->cmd_cdb[ESP_PROXY_RESULT] = TRUE;
			}
			if (msgout == MSG_ABORT || msgout == MSG_ABORT_TAG) {
				esp->e_abort++;
				if ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) {
					MARK_PKT(sp, CMD_ABORTED, STAT_ABORTED);
				}
			} else if (msgout == MSG_DEVICE_RESET) {
				esp->e_reset++;
				if ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) {
					MARK_PKT(sp, CMD_RESET,
					    STAT_DEV_RESET);
				}
				esp->e_offset[target] = 0;
				esp->e_sync_known &= ~(1<<target);
			}
		} else {
			if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
				sp->cmd_pkt.pkt_reason = CMD_UNX_BUS_FREE;
			LOG_STATE(esp, ACTS_CMD_LOST,
			    esp->e_stat, esp->e_xfer, -1);
			esp_flush_fifo(esp);
#ifdef ESPDEBUG
			esp_printstate(esp, "unexpected bus free");
#endif
		}
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_UNKNOWN_INT_DISCON_END,
		    "esp_handle_unknown_end (int_discon)");
		return (ACTION_FINISH);
	}
	_NOTE(NOT_REACHED)
	/* NOTREACHED */
}


static int
esp_handle_clearing(struct esp *esp)
{
	struct esp_cmd *sp = CURRENT_CMD(esp);

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CLEARING_START,
	    "esp_handle_clearing_start");
	EPRINTF("esp_handle_clearing:\n");

	if (esp->e_laststate == ACTS_C_CMPLT ||
	    esp->e_laststate == ACTS_MSG_IN_DONE) {
		if (INTPENDING(esp)) {
			volatile struct espreg *ep = esp->e_reg;
			if (esp->e_options & ESP_OPT_MASK_OFF_STAT) {
				esp->e_stat = ep->esp_stat & ~ESP_STAT_RES;
			} else {
				esp->e_stat = ep->esp_stat;
			}
			esp->e_intr = ep->esp_intr;
			if (esp->e_intr & ESP_INT_RESET) {
				TRACE_0(TR_FAC_SCSI,
				    TR_ESP_HANDLE_CLEARING_FINRST_END,
				    "esp_handle_clearing_end (ACTION_FINRST)");
				return (ACTION_FINRST);
			}
		} else {
			/*
			 * change e_laststate for the next time around
			 */
			esp->e_laststate = ACTS_CLEARING;
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CLEARING_RETURN1_END,
			    "esp_handle_clearing_end (ACTION_RETURN1)");
			return (ACTION_RETURN);
		}
	}

	if (esp->e_intr == ESP_INT_DISCON) {
		/*
		 * At this point the ESP chip has disconnected. The bus should
		 * be either quiet or someone may be attempting a reselection
		 * of us (or somebody else). Call the routine that sets the
		 * chip back to a correct and known state.
		 * If the last message in was a disconnect, search
		 * for new work to do, else return to call esp_finish()
		 */
		if (esp->e_last_msgin == MSG_DISCONNECT) {
			sp->cmd_pkt.pkt_statistics |= STAT_DISCON;
			sp->cmd_flags |= CFLAG_CMDDISC;
			if ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) {
				esp->e_ndisc++;
			}
			esp_chip_disconnect(esp, sp);
			New_state(esp, STATE_FREE);
			ASSERT(esp->e_cur_slot != UNDEFINED);
			EPRINTF2("disconnecting %d.%d\n", Tgt(sp), Lun(sp));

			if (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) {
				esp->e_slots[esp->e_cur_slot] = NULL;
			}

			esp->e_last_slot = esp->e_cur_slot;
			esp->e_cur_slot = UNDEFINED;

			/*
			 * start a cmd here to save time
			 */
			if (esp_ustart(esp, esp->e_last_slot, NEW_CMD)) {
				TRACE_0(TR_FAC_SCSI,
				    TR_ESP_HANDLE_CLEARING_RETURN2_END,
				    "esp_handle_clearing_end (ACTION_RETURN2)");
				return (ACTION_RETURN);
			}
			esp->e_last_msgout = 0xff;
			esp->e_omsglen = 0;
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CLEARING_RETURN3_END,
			    "esp_handle_clearing_end (ACTION_RETURN3)");
			return (ACTION_RETURN);
		} else {
			esp_chip_disconnect(esp, sp);
			esp->e_last_msgout = 0xff;
			esp->e_omsglen = 0;
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CLEARING_END,
			    "esp_handle_clearing_end");
			return (esp_finish(esp));
		}
	} else {
		/*
		 * If the chip/target didn't disconnect from the
		 * bus, that is a gross fatal error.
		 */
		esplog(esp, CE_WARN,
		    "Target %d didn't disconnect after sending %s",
		    Tgt(sp), scsi_mname(esp->e_last_msgin));
		if (sp->cmd_pkt.pkt_reason ==  CMD_CMPLT)
			sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
#ifdef ESPDEBUG
		IPRINTF4("msgout: %x %x %x, last_msgout=%x\n",
			esp->e_cur_msgout[0], esp->e_cur_msgout[1],
			esp->e_cur_msgout[2], esp->e_last_msgout);
		IPRINTF1("last msgin=%x\n", esp->e_last_msgin);
		esp_dump_state(esp);
#endif
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CLEARING_ABORT_END,
		    "esp_handle_clearing_end (ACTION_ABORT_CURCMD)");
		return (ACTION_ABORT_ALLCMDS);
	}
}



static int
esp_handle_data(struct esp *esp)
{
	uint64_t end;
	uint32_t amt;
	struct esp_cmd *sp = CURRENT_CMD(esp);
	int sending;

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_START,
	    "esp_handle_data_start");
	EPRINTF2("esp_handle_data: sp=0x%p, flags=%x\n",
	    (void *)sp, sp->cmd_flags);

	if (IS_53C90(esp)) {
		Esp_cmd(esp, CMD_NOP);	/* per ESP errata sheet */
	}

	if ((sp->cmd_flags & CFLAG_DMAVALID) == 0) {
		esp_printstate(esp, "unexpected data phase");
		/*
		 * XXX: This isn't the right reason
		 */
bad:
		if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
			sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_ABORT1_END,
		    "esp_handle_data_end (ACTION_ABORT_CURCMD1)");
		return (ACTION_ABORT_CURCMD);
	} else {
		sending = (sp->cmd_flags & CFLAG_DMASEND)? 1 : 0;
	}

	if (sp->cmd_flags & CFLAG_RESTORE_PTRS) {
		if (esp_restore_pointers(esp, sp)) {
			return (ACTION_ABORT_CURCMD);
		}
		sp->cmd_flags &= ~CFLAG_RESTORE_PTRS;
	}

	/*
	 * make sure our DMA pointers are in good shape.
	 *
	 * Because SCSI is SCSI, the current DMA pointer has got to be
	 * greater than or equal to our DMA base address. All other cases
	 * that might have affected this always set curaddr to be >=
	 * to the DMA base address.
	 */
	ASSERT(sp->cmd_cur_addr >= sp->cmd_dmacookie.dmac_address);
	end = (uint64_t)sp->cmd_dmacookie.dmac_address +
		(uint64_t)sp->cmd_dmacookie.dmac_size;

	EPRINTF5("cmd_data_count=%x, dmacount=%x, cur_addr=%x, end=%"
	    PRIx64 ", nwin=%x\n",
	    sp->cmd_data_count, sp->cmd_dmacount, sp->cmd_cur_addr, end,
	    sp->cmd_nwin);
	EPRINTF2("dmac_address=%x, dmac_size=%lx\n",
	    sp->cmd_dmacookie.dmac_address, sp->cmd_dmacookie.dmac_size);

	if ((sp->cmd_data_count >= sp->cmd_dmacount) ||
	    (sp->cmd_cur_addr >= end)) {
		if (esp_next_window(esp, sp)) {
			goto bad;
		}
		end = (uint64_t)sp->cmd_dmacookie.dmac_address +
			(uint64_t)sp->cmd_dmacookie.dmac_size;
		IPRINTF2("dmac_address=%x, dmac_size=%lx\n",
		    sp->cmd_dmacookie.dmac_address,
		    sp->cmd_dmacookie.dmac_size);
	}

	amt = end - sp->cmd_cur_addr;
	if (ESP_MAX_DMACOUNT < amt) {
		amt = ESP_MAX_DMACOUNT;
	}
	EPRINTF3("amt=%x, end=%lx, cur_addr=%x\n", amt, end, sp->cmd_cur_addr);

#ifdef ESPDEBUG
	/*
	 * Make sure that we don't cross a boundary we can't handle
	 * This is probably checked as well by the DMA framework
	 */
	end = (uint64_t)sp->cmd_cur_addr + (uint64_t)amt - 1;
	if ((end & ~esp->e_dma_attr->dma_attr_seg) !=
	    (sp->cmd_cur_addr & ~esp->e_dma_attr->dma_attr_seg)) {
		IPRINTF3("cur_addr %x cur_addr+amt %" PRIx64
		    " cntr_max %" PRIx64 "\n",
		    sp->cmd_cur_addr, end, esp->e_dma_attr->dma_attr_seg);
		amt = (end & ~esp->e_dma_attr->dma_attr_seg) -
			sp->cmd_cur_addr;
		if (amt == 0 || amt > ESP_MAX_DMACOUNT) {
			esplog(esp, CE_WARN, "illegal DMA boundary? %x", amt);
			goto bad;
		}
	}
#endif
	end = (uint64_t)sp->cmd_dmacookie.dmac_address +
		(uint64_t)sp->cmd_dmacookie.dmac_size -
		(uint64_t)sp->cmd_cur_addr;
	EPRINTF3("amt=%x, end=%lx, cur_addr=%x\n", amt, end, sp->cmd_cur_addr);

	if (amt > end) {
		IPRINTF4("ovflow amt=%x end=%" PRIx64 " curaddr=%x count=%x\n",
		    amt, end, sp->cmd_cur_addr, sp->cmd_dmacount);
		amt = end;
	}

	esp->e_lastcount = amt;
#ifdef	ESPDEBUG
	esp->e_xfer = amt;
#endif	/* ESPDEBUG */

	EPRINTF4("%d.%d cmd 0x%x to xfer %x\n", Tgt(sp), Lun(sp),
	    sp->cmd_pkt.pkt_cdbp[0], amt);

	if ((esp->e_stat & ESP_PHASE_MASK) == ESP_PHASE_DATA_OUT) {
		if (!sending) {
			esplog(esp, CE_WARN,
			    "unwanted data out for Target %d", Tgt(sp));
			if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
				sp->cmd_pkt.pkt_reason = CMD_DMA_DERR;
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_ABORT2_END,
			    "esp_handle_data_end (ACTION_ABORT_CURCMD2)");
			return (ACTION_ABORT_CURCMD);
		}
		ESP_SET_ESC_READ_COUNT(esp, amt, sp->cmd_cur_addr);
		ESP_DMA_READ(esp, amt, sp->cmd_cur_addr);

		LOG_STATE(esp, ACTS_DATAOUT, esp->e_stat, amt, -1);
	} else {
		if (sending) {
			esplog(esp, CE_WARN,
			    "unwanted data in for Target %d", Tgt(sp));
			if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
				sp->cmd_pkt.pkt_reason = CMD_DMA_DERR;
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_ABORT3_END,
			    "esp_handle_data_end (ACTION_ABORT_CURCMD3)");
			return (ACTION_ABORT_CURCMD);
		}
		ESP_DMA_WRITE(esp, amt, sp->cmd_cur_addr);
		LOG_STATE(esp, ACTS_DATAIN, esp->e_stat, amt, -1);
	}


#ifdef	ESP_TEST_PARITY
	if (!sending && (esp_ptest_data_in & (1<<Tgt(sp)))) {
		Esp_cmd(esp, CMD_SET_ATN);
	}
#endif	/* ESP_TEST_PARITY */

	/*
	 * XXX DON't change the order of these two statements, see 1162008
	 */
	New_state(esp, ACTS_DATA_DONE);
	Esp_cmd(esp, CMD_TRAN_INFO|CMD_DMA);

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_END,
	    "esp_handle_data_end (ACTION_RETURN)");
	return (ACTION_RETURN);
}

static int
esp_handle_data_done(struct esp *esp)
{
	volatile struct espreg *ep = esp->e_reg;
	volatile struct dmaga *dmar = esp->e_dma;
	struct esp_cmd *sp = CURRENT_CMD(esp);
	uint32_t xfer_amt;
	char spurious_data, do_drain_fifo, was_sending;
	uchar_t stat, tgt, fifoamt;

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_DONE_START,
	    "esp_handle_data_done_start");
	EPRINTF("esp_handle_data_done:\n");

	tgt = Tgt(sp);
	stat = esp->e_stat;
	was_sending = (sp->cmd_flags & CFLAG_DMASEND) ? 1 : 0;
	spurious_data = do_drain_fifo = 0;

	/*
	 * Check for DMAGA errors (parity or memory fault)
	 */
	if ((esp->e_dmaga_csr = dmar->dmaga_csr) & DMAGA_ERRPEND) {
		/*
		 * It would be desirable to set the ATN* line and attempt to
		 * do the whole schmear of INITIATOR DETECTED ERROR here,
		 * but that is too hard to do at present.
		 */
		esplog(esp, CE_WARN, "Unrecoverable DMA error on dma %s",
		    (was_sending) ? "send" : "receive");
		if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
			sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_DONE_RESET_END,
		    "esp_handle_data_done_end (ACTION_RESET)");
		return (ACTION_RESET);
	}

	/*
	 * Data Receive conditions:
	 *
	 * Check for parity errors. If we have a parity error upon
	 * receive, the ESP chip has asserted ATN* for us already.
	 *
	 * For Rev-1 and Rev-2 dma gate arrays,
	 * make sure the last bytes have flushed.
	 */
	if (!was_sending) {
#ifdef	ESP_TEST_PARITY
		if (esp_ptest_data_in & (1<<tgt)) {
			esp_ptest_data_in = 0;
			stat |= ESP_STAT_PERR;
		}
#endif	/* ESP_TEST_PARITY */
		if (stat & ESP_STAT_PERR) {
			esplog(esp, CE_WARN,
			    "SCSI bus DATA IN phase parity error");
			esp->e_cur_msgout[0] = MSG_INITIATOR_ERROR;
			esp->e_omsglen = 1;
			sp->cmd_pkt.pkt_statistics |= STAT_PERR;
			sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
		}
		ESP_DRAIN_DMA(esp);
	} else {
		/*
		 * clear state of dma gate array
		 */
		ESP_FLUSH_DMA(esp);
	}

	/*
	 * Check to make sure we're still connected to the target.
	 * If the target dropped the bus, that is a fatal error.
	 * We don't even attempt to count what we were transferring
	 * here. Let esp_handle_unknown clean up for us.
	 */
	if (esp->e_intr != ESP_INT_BUS) {
		New_state(esp, ACTS_UNKNOWN);
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_DONE_PHASEMANAGE_END,
		    "esp_handle_data_done_end (ACTION_PHASEMANAGE)");
		return (ACTION_PHASEMANAGE);
	}

	/*
	 * Figure out how far we got.
	 * Latch up fifo amount first.
	 */

	fifoamt = FIFO_CNT(ep);

	if (stat & ESP_STAT_XZERO) {
		xfer_amt = esp->e_lastcount;
	} else {
		GET_ESP_COUNT(ep, xfer_amt);
		xfer_amt = esp->e_lastcount - xfer_amt;
	}

	/*
	 * Unconditionally knock off by the amount left
	 * in the fifo if we were sending out the SCSI bus.
	 *
	 * If we were receiving from the SCSI bus, believe
	 * what the chip told us (either XZERO or by the
	 * value calculated from the counter register).
	 * The reason we don't look at the fifo for
	 * incoming data is that in synchronous mode
	 * the fifo may have further data bytes, and
	 * for async mode we assume that all data in
	 * the fifo will have been transferred before
	 * the esp asserts an interrupt.
	 */
	if (was_sending) {
		xfer_amt -= fifoamt;
	}

	/*
	 * If this was a synchronous transfer, flag it.
	 * Also check for the errata condition of long
	 * last REQ/ pulse for some synchronous targets
	 */
	if (esp->e_offset[tgt]) {
		/*
		 * flag that a synchronous data xfer took place
		 */
		sp->cmd_pkt.pkt_statistics |= STAT_SYNC;

		if (IS_53C90(esp)) {
			static char *spur =
			    "Spurious %s phase from target %d\n";
			uchar_t phase;

			/*
			 * Okay, latch up new status register value
			 */

			/*
			 * Get a new stat from the esp chip register.
			 */

			esp->e_stat = stat = phase = ep->esp_stat;
			phase &= ESP_PHASE_MASK;

			/*
			 * Now, if we're still (maybe) in a data phase,
			 * check to be real sure that we are...
			 */

			if (phase == ESP_PHASE_DATA_IN) {
				if (FIFO_CNT(ep) == 0)
					spurious_data = 1;
			} else if (phase == ESP_PHASE_DATA_OUT) {
				if ((ep->esp_fifo_flag & ESP_FIFO_ONZ) == 0)
					spurious_data = -1;
			}

			if (spurious_data) {
				Esp_cmd(esp, CMD_MSG_ACPT);
				esplog(esp, CE_WARN,
				    spur, (spurious_data < 0) ?
				    "data out": "data in", tgt);

				/*
				 * It turns out that this can also
				 * come about if the target resets
				 * (and goes back to async SCSI mode)
				 * and we don't know about it.
				 *
				 * The degenerate case for this is
				 * turning off a lunchbox- this clears
				 * it's state. The trouble is is that
				 * we'll get a check condition (likely)
				 * on the next command after a power-cycle
				 * for this target, but we'll have to
				 * go into a DATA IN phase to pick up
				 * the sense information for the Request
				 * Sense that will likely follow that
				 * Check Condition.
				 *
				 * As a temporary fix, I'll clear
				 * the 'sync_known' flag for this
				 * target so that the next selection
				 * for this target will renegotiate
				 * the sync protocol to be followed.
				 */

				esp->e_sync_known &= ~(1<<tgt);
			}
			if (spurious_data == 0 && was_sending)
				do_drain_fifo = 1;
		} else {
			/*
			 * The need to handle for the ESP100A the case
			 * of turning off/on a target, thus destroying
			 * it's sync. setting is covered in esp_finish()
			 * where a CHECK CONDITION status causes the
			 * esp->e_sync_known flag to be cleared.
			 *
			 * If we are doing synchronous DATA OUT,
			 * we should probably drain the fifo.
			 * If we are doing synchronous DATA IN,
			 * we really don't dare do that (in case
			 * we are going from data phase to data
			 * phase).
			 */

			if (was_sending)
				do_drain_fifo = 1;
		}
	} else {
		/*
		 * If we aren't doing Synchronous Data Transfers,
		 * definitely offload the fifo.
		 */
		do_drain_fifo = 1;
	}

	/*
	 * Drain the fifo here of any left over
	 * that weren't transferred (if desirable).
	 */
	if (do_drain_fifo) {
		esp_flush_fifo(esp);
	}

	/*
	 * adjust pointers...
	 */
	sp->cmd_data_count += xfer_amt;
	sp->cmd_cur_addr += xfer_amt;

#ifdef	ESPDEBUG
	if (espdebug > 1 && esp->e_lastcount >= 0x200 && (xfer_amt & 0x1ff)) {
		eprintf(esp,
		    "DATA %s phase for %d.%d did 0x%x of 0x%x bytes\n",
		    (was_sending)? "OUT" : "IN", tgt, Lun(sp),
		    xfer_amt, esp->e_lastcount);
		esp_stat_int_print(esp);
	}
#endif	/* ESPDEBUG */

	sp->cmd_pkt.pkt_state |= STATE_XFERRED_DATA;
	New_state(esp, ACTS_UNKNOWN);
	if (spurious_data == 0) {
		stat &= ESP_PHASE_MASK;
		if (stat == ESP_PHASE_DATA_IN || stat == ESP_PHASE_DATA_OUT) {
			esp->e_state = ACTS_DATA;
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_DATA_DONE_ACTION1_END,
			    "esp_handle_data_done_end (action1)");
			return (esp_handle_data(esp));
		} else {
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_DATA_DONE_ACTION2_END,
			    "esp_handle_data_done_end (action2)");
			return (esp_handle_unknown(esp));
		}
	} else {
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_DATA_DONE_END,
		    "esp_handle_data_done_end (ACTION_RETURN)");
		return (ACTION_RETURN);
	}
}

static char *msginperr = "SCSI bus MESSAGE IN phase parity error\n";

static int
esp_handle_c_cmplt(struct esp *esp)
{
	struct esp_cmd *sp = CURRENT_CMD(esp);
	volatile struct espreg *ep = esp->e_reg;
	uchar_t sts, msg, msgout, intr, perr;
	volatile uchar_t *c = (uchar_t *)esp->e_cmdarea;

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_START,
	    "esp_handle_c_cmplt_start");
	EPRINTF("esp_handle_c_cmplt:\n");

	/*
	 * if target is fast, we can get cmd. completion by the time we get
	 * here. Otherwise, we'll have to taken an interrupt.
	 */
	if (esp->e_laststate == ACTS_UNKNOWN) {
		if (INTPENDING(esp)) {
			if (esp->e_options & ESP_OPT_MASK_OFF_STAT) {
				esp->e_stat = ep->esp_stat & ~ESP_STAT_RES;
			} else {
				esp->e_stat = ep->esp_stat;
			}
			esp->e_intr = intr = ep->esp_intr;
			if (intr & ESP_INT_RESET) {
				TRACE_0(TR_FAC_SCSI,
				    TR_ESP_HANDLE_C_CMPLT_FINRST_END,
				    "esp_handle_c_cmplt_end (ACTION_FINRST)");
				return (ACTION_FINRST);
			}
		} else {
			/*
			 * change e_laststate for the next time around
			 */
			esp->e_laststate = ACTS_C_CMPLT;
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_RETURN1_END,
			    "esp_handle_c_cmplt_end (ACTION_RETURN1)");
			return (ACTION_RETURN);
		}
	} else {
		intr = esp->e_intr;
	}

#ifdef	ESP_TEST_PARITY
	if (esp_ptest_status & (1<<Tgt(sp))) {
		esp_ptest_status = 0;
		esp->e_stat |= ESP_STAT_PERR;
	} else if ((esp_ptest_msgin & (1<<Tgt(sp))) && esp_ptest_msg == 0) {
		Esp_cmd(esp, CMD_SET_ATN);
		esp_ptest_msgin = 0;
		esp_ptest_msg = -1;
		esp->e_stat |= ESP_STAT_PERR;
	}
#endif	/* ESP_TEST_PARITY */

	if (intr == ESP_INT_DISCON) {
		New_state(esp, ACTS_UNKNOWN);
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_ACTION1_END,
		    "esp_handle_c_cmplt_end (action1)");
		return (esp_handle_unknown(esp));
	}

	if ((perr = (esp->e_stat & ESP_STAT_PERR)) != 0) {
		sp->cmd_pkt.pkt_statistics |= STAT_PERR;
	}

	if (esp->e_options & ESP_OPT_STACKED_CMDS) {
		ESP_DRAIN_DMA(esp);
		/*
		 * we really need a ddi_dma_sync() here but that is too
		 * expensive; this loop is necessary for xbox, see
		 * also in esp_reconnect()
		 */
		if (*c == INVALID_MSG) {
			int i;
			EPRINTF("esp_handle_c_cmplt: invalid msg\n");
			for (i = 0; i < 1000000; i++) {
				if (*c != INVALID_MSG) {
					break;
				}
			}
		}
	} else {
		/*
		 * if we haven't done a stacked cmd with a MSG_ACPT,
		 * do a msg accept now and read the fifo data
		 */
		if (intr & ESP_INT_FCMP) {
			Esp_cmd(esp, CMD_MSG_ACPT);
			*c = ep->esp_fifo_data;
			*(c+1) = ep->esp_fifo_data;
		}
	}

	msgout = 0;
	msg = sts = INVALID_MSG;

	/*
	 * The ESP manuals state that this sequence completes
	 * with a BUS SERVICE interrupt if just the status
	 * byte was received, else a FUNCTION COMPLETE interrupt
	 * if both status and a message was received.
	 *
	 * The manuals also state that ATN* is asserted if
	 * bad parity is detected.
	 *
	 * The one case that we cannot handle is where we detect
	 * bad parity for the status byte, but the target refuses
	 * to go to MESSAGE OUT phase right away. This means that
	 * if that happens, we will misconstrue the parity error
	 * to be for the completion message, not the status byte.
	 */
	if (intr & ESP_INT_FCMP) {
		sts = *c++;
		esp->e_last_msgin = esp->e_imsgarea[0] = msg = *c;
		if (perr) {
			esplog(esp, CE_WARN, msginperr);
			msgout = MSG_MSG_PARITY;
		}
	} else if (intr == ESP_INT_BUS) {
		/*
		 * We only got the status byte.
		 */
		sts = *c;

		IPRINTF1("esp_handle_cmd_cmplt: sts=%x, no msg byte\n", sts);

		if (perr) {
			/*
			 * If we get a parity error on a status byte
			 * assume that it was a CHECK CONDITION
			 */
			sts = STATUS_CHECK;
			esplog(esp, CE_WARN,
			    "SCSI bus STATUS phase parity error");
			msgout = MSG_INITIATOR_ERROR;
		}
	} else {
		IPRINTF("esp_handle_cmd_cmplt: unexpected int\n");
		New_state(esp, ACTS_UNKNOWN);
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_ACTION2_END,
		    "esp_handle_c_cmplt_end (action2)");
		return (esp_handle_unknown(esp));
	}

	EPRINTF2("esp_handle_c_cmplt: status=%x, msg=%x\n", sts, msg);

	if (sts != INVALID_MSG) {
		sp->cmd_pkt.pkt_state |= STATE_GOT_STATUS;
		*(sp->cmd_scbp) = sts;
		EPRINTF1("Status=0x%x\n", sts);
	}
	LOG_STATE(esp, ACTS_STATUS, esp->e_stat, sts, msg);

	if (msgout == 0) {
		EPRINTF1("Completion Message=%s\n", scsi_mname(msg));
		if (msg == MSG_COMMAND_COMPLETE) {
			/*
			 * Actually, if the message was a 'linked command
			 * complete' message, the target isn't going to be
			 * clearing the bus.
			 */
			New_state(esp, ACTS_CLEARING);
		} else {
			esp->e_imsglen = 1;
			esp->e_imsgindex = 1;
			New_state(esp, ACTS_MSG_IN_DONE);
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_ACTION3_END,
			    "esp_handle_c_cmplt_end (action3)");
			return (esp_handle_msg_in_done(esp));
		}
	} else {
		esp->e_cur_msgout[0] = msgout;
		esp->e_omsglen = 1;
		New_state(esp, ACTS_UNKNOWN);
	}
	LOG_STATE(esp, ACTS_C_CMPLT, esp->e_stat, esp->e_xfer, -1);

	if (intr != ESP_INT_BUS) {
		if (esp->e_state == ACTS_CLEARING) {
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_ACTION4_END,
			    "esp_handle_c_cmplt_end (action4)");
			return (esp_handle_clearing(esp));
		}
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_RETURN2_END,
		    "esp_handle_c_cmplt_end (ACTION_RETURN2)");
		return (ACTION_RETURN);
	} else {
		if (esp->e_state == ACTS_UNKNOWN) {
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_ACTION5_END,
			    "esp_handle_c_cmplt_end (action5)");
			return (esp_handle_unknown(esp));
		}
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_C_CMPLT_PHASEMANAGE_END,
		    "esp_handle_c_cmplt_end (ACTION_PHASEMANAGE)");
		return (ACTION_PHASEMANAGE);
	}
}

static int
esp_handle_msg_in(struct esp *esp)
{
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_IN_START,
	    "esp_handle_msg_in_start");
	EPRINTF("esp_handle_msg_in\n");

	/*
	 * Pick up a message byte.
	 * Clear the FIFO so we
	 * don't get confused.
	 */
	esp_flush_fifo(esp);
	if (IS_53C90(esp)) {
		Esp_cmd(esp, CMD_NOP);
	}
	Esp_cmd(esp, CMD_TRAN_INFO);
	esp->e_imsglen = 1;
	esp->e_imsgindex = 0;
	New_state(esp, ACTS_MSG_IN_DONE);

	/*
	 * give a little extra time by returning to phasemanage
	 */
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_IN_END,
	    "esp_handle_msg_in_end (ACTION_PHASEMANAGE)");
	return (ACTION_PHASEMANAGE);
}

/*
 * We come here after issuing a MSG_ACCEPT
 * command and are expecting more message bytes.
 * The ESP should be asserting a BUS SERVICE
 * interrupt status, but may have asserted
 * a different interrupt in the case that
 * the target disconnected and dropped BSY*.
 *
 * In the case that we are eating up message
 * bytes (and throwing them away unread) because
 * we have ATN* asserted (we are trying to send
 * a message), we do not consider it an error
 * if the phase has changed out of MESSAGE IN.
 */
static int
esp_handle_more_msgin(struct esp *esp)
{
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MORE_MSGIN_START,
	    "esp_handle_more_msgin_start");
	EPRINTF("esp_handle_more_msgin\n");

	if (esp->e_intr & ESP_INT_BUS) {
		if ((esp->e_stat & ESP_PHASE_MASK) == ESP_PHASE_MSG_IN) {
			/*
			 * Fetch another byte of a message in.
			 */
			Esp_cmd(esp, CMD_TRAN_INFO);
			New_state(esp, ACTS_MSG_IN_DONE);
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_MORE_MSGIN_RETURN1_END,
			    "esp_handle_more_msgin_end (ACTION_RETURN)");
			return (ACTION_RETURN);
		}

		/*
		 * If we were gobbling up a message and we have
		 * changed phases, handle this silently, else
		 * complain. In either case, we return to let
		 * esp_phasemanage() handle things.
		 *
		 * If it wasn't a BUS SERVICE interrupt,
		 * let esp_phasemanage() find out if the
		 * chip disconnected.
		 */
		if (esp->e_imsglen != 0) {
			esplog(esp, CE_WARN,
			    "Premature end of extended message");
		}
	}
	New_state(esp, ACTS_UNKNOWN);
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MORE_MSGIN_RETURN2_END,
	    "esp_handle_more_msgin_end (action)");
	return (esp_handle_unknown(esp));
}


static int
esp_handle_msg_in_done(struct esp *esp)
{
	struct esp_cmd *sp = CURRENT_CMD(esp);
	volatile struct espreg *ep = esp->e_reg;
	int sndmsg = 0;
	uchar_t msgin;

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_IN_DONE_START,
	    "esp_handle_msg_in_done_start");
	EPRINTF("esp_handle_msg_in_done:\n");
	if (esp->e_laststate == ACTS_MSG_IN) {
		if (INTPENDING(esp)) {
			if (esp->e_options & ESP_OPT_MASK_OFF_STAT) {
				esp->e_stat = ep->esp_stat & ~ESP_STAT_RES;
			} else {
				esp->e_stat = ep->esp_stat;
			}
			esp->e_intr = ep->esp_intr;
			if (esp->e_intr & ESP_INT_RESET) {
				TRACE_0(TR_FAC_SCSI,
				    TR_ESP_HANDLE_MSG_IN_DONE_FINRST_END,
				    "esp_handle_msg_in_done_end (_FINRST)");
				return (ACTION_FINRST);
			}
		} else {
			/*
			 * change e_laststate for the next time around
			 */
			esp->e_laststate = ACTS_MSG_IN_DONE;
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_MSG_IN_DONE_RETURN1_END,
			    "esp_handle_msg_in_done_end (ACTION_RETURN1)");
			return (ACTION_RETURN);
		}
	}

	/*
	 * We can be called here for both the case where
	 * we had requested the ESP chip to fetch a message
	 * byte from the target (at the target's request).
	 * We can also be called in the case where we had
	 * been using the CMD_COMP_SEQ command to pick up
	 * both a status byte and a completion message from
	 * a target, but where the message wasn't one of
	 * COMMAND COMPLETE, LINKED COMMAND COMPLETE, or
	 * LINKED COMMAND COMPLETE (with flag). This is a
	 * legal (albeit extremely unusual) SCSI bus trans-
	 * -ition, so we have to handle it.
	 */
	if (esp->e_laststate != ACTS_C_CMPLT) {
#ifdef	ESP_TEST_PARITY
reloop:
#endif	/* ESP_TEST_PARITY */

		if (esp->e_intr & ESP_INT_DISCON) {
			esplog(esp, CE_WARN,
			    "premature end of input message");
			New_state(esp, ACTS_UNKNOWN);
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_MSG_IN_DONE_PHASEMANAGE_END,
			    "esp_handle_msg_in_done_end (ACTION_PHASEMANAGE)");
			return (ACTION_PHASEMANAGE);
		}

		/*
		 * Note that if e_imsglen is zero, then we are skipping
		 * input message bytes, so there is no reason to look for
		 * parity errors.
		 */
		if (esp->e_imsglen != 0 && (esp->e_stat & ESP_STAT_PERR)) {

			esplog(esp, CE_WARN, msginperr);
			sndmsg = MSG_MSG_PARITY;
			sp->cmd_pkt.pkt_statistics |= STAT_PERR;
			esp_flush_fifo(esp);

		} else if ((msgin = (FIFO_CNT(ep))) != 1) {

			/*
			 * If we have got more than one byte in the fifo,
			 * that is a gross screwup, and we should let the
			 * target know that we have completely fouled up.
			 */
			eprintf(esp, "fifocount=%x\n", msgin);
			esp_printstate(esp, "input message botch");
			sndmsg = MSG_INITIATOR_ERROR;
			esp_flush_fifo(esp);
			esplog(esp, CE_WARN, "input message botch");

		} else if (esp->e_imsglen == 0) {


			/*
			 * If we are in the middle of gobbling up and throwing
			 * away a message (due to a previous message input
			 * error), drive on.
			 */
			msgin = ep->esp_fifo_data;
			New_state(esp, ACTS_MSG_IN_MORE);

		} else {
			esp->e_imsgarea[esp->e_imsgindex++] =
			    msgin = ep->esp_fifo_data;
		}

	} else {
		/*
		 * In this case, we have been called (from
		 * esp_handle_c_cmplt()) with the message
		 * already stored in the message array.
		 */
		msgin = esp->e_imsgarea[0];
	}

	/*
	 * Process this message byte (but not if we are
	 * going to be trying to send back some error
	 * anyway)
	 */
	if (sndmsg == 0 && esp->e_imsglen != 0) {

		if (esp->e_imsgindex < esp->e_imsglen) {

			EPRINTF2("message byte %d: 0x%x\n",
			    esp->e_imsgindex-1,
			    esp->e_imsgarea[esp->e_imsgindex-1]);

			New_state(esp, ACTS_MSG_IN_MORE);

		} else if (esp->e_imsglen == 1) {

#ifdef	ESP_TEST_PARITY
			if ((esp_ptest_msgin & (1<<Tgt(sp))) &&
			    esp_ptest_msg == msgin) {
				esp_ptest_msgin = 0;
				esp_ptest_msg = -1;
				Esp_cmd(esp, CMD_SET_ATN);
				esp->e_stat |= ESP_STAT_PERR;
				esp->e_imsgindex -= 1;
				goto reloop;
			}
#endif	/* ESP_TEST_PARITY */

			sndmsg = esp_onebyte_msg(esp);

		} else if (esp->e_imsglen == 2) {
#ifdef	ESP_TEST_PARITY
			if (esp_ptest_emsgin & (1<<Tgt(sp))) {
				esp_ptest_emsgin = 0;
				Esp_cmd(esp, CMD_SET_ATN);
				esp->e_stat |= ESP_STAT_PERR;
				esp->e_imsgindex -= 1;
				goto reloop;
			}
#endif	/* ESP_TEST_PARITY */

			if (esp->e_imsgarea[0] ==  MSG_EXTENDED) {
				static char *tool =
				    "Extended message 0x%x is too long";

				/*
				 * Is the incoming message too long
				 * to be stored in our local array?
				 */
				if ((int)(msgin+2) > IMSGSIZE) {
					esplog(esp, CE_WARN,
					    tool, esp->e_imsgarea[0]);
					sndmsg = MSG_REJECT;
				} else {
					esp->e_imsglen = msgin + 2;
					New_state(esp, ACTS_MSG_IN_MORE);
				}
			} else {
				sndmsg = esp_twobyte_msg(esp);
			}

		} else {
			sndmsg = esp_multibyte_msg(esp);
		}
	}

	if (sndmsg < 0) {
		/*
		 * If sndmsg is less than zero, one of the subsidiary
		 * routines needs to return some other state than
		 * ACTION_RETURN.
		 */
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_IN_DONE_SNDMSG_END,
		    "esp_handle_msg_in_done_end (-sndmsg)");
		return (-sndmsg);
	} else if (sndmsg > 0) {
		if (IS_1BYTE_MSG(sndmsg)) {
			esp->e_omsglen = 1;
		}
		esp->e_cur_msgout[0] = (uchar_t)sndmsg;

		/*
		 * The target is not guaranteed to go to message out
		 * phase, period. Moreover, until the entire incoming
		 * message is transferred, the target may (and likely
		 * will) continue to transfer message bytes (which
		 * we will have to ignore).
		 *
		 * In order to do this, we'll go to 'infinite'
		 * message in handling by setting the current input
		 * message length to a sentinel of zero.
		 *
		 * This works regardless of the message we are trying
		 * to send out. At the point in time which we want
		 * to send a message in response to an incoming message
		 * we do not care any more about the incoming message.
		 *
		 * If we are sending a message in response to detecting
		 * a parity error on input, the ESP chip has already
		 * set ATN* for us, but it doesn't hurt to set it here
		 * again anyhow.
		 */
		Esp_cmd(esp, CMD_SET_ATN);
		New_state(esp, ACTS_MSG_IN_MORE);
		esp->e_imsglen = 0;
	}

	/*
	 * do not give a MSG_ACPT if we are not in msg phase anymore
	 * and the target already dropped off the bus
	 * this is not worth the extra PIO read on viking based machines
	 * with FAS chips
	 */
	if ((esp->e_options & ESP_OPT_FAS) == 0) {
		esp->e_stat = esp->e_reg->esp_stat;
		if ((esp->e_stat & (ESP_STAT_MSG | ESP_STAT_CD)) ==
		    (ESP_STAT_MSG | ESP_STAT_CD)) {
			Esp_cmd(esp, CMD_MSG_ACPT);
		}
	} else {
		Esp_cmd(esp, CMD_MSG_ACPT);
	}

	if ((esp->e_laststate == ACTS_MSG_IN_DONE) &&
	    (esp->e_state == ACTS_CLEARING)) {
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_IN_DONE_ACTION_END,
		    "esp_handle_msg_in_done_end (action)");
		return (esp_handle_clearing(esp));
	}
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_IN_DONE_RETURN2_END,
	    "esp_handle_msg_in_done_end (ACTION_RETURN2)");
	return (ACTION_RETURN);
}

static int
esp_onebyte_msg(struct esp *esp)
{
	struct esp_cmd *sp = CURRENT_CMD(esp);
	int msgout = 0;
	uchar_t msgin = esp->e_last_msgin = esp->e_imsgarea[0];
	int tgt = Tgt(sp);

	EPRINTF("esp_onebyte_msg\n");

	if (msgin & MSG_IDENTIFY) {
		/*
		 * How did we get here? We should only see identify
		 * messages on a reconnection, but we'll handle this
		 * fine here (just in case we get this) as long as
		 * we believe that this is a valid identify message.
		 *
		 * For this to be a valid incoming message,
		 * bits 6-4 must must be zero. Also, the
		 * bit that says that I'm an initiator and
		 * can support disconnection cannot possibly
		 * be set here.
		 */

		char garbled = ((msgin & (BAD_IDENTIFY|INI_CAN_DISCON)) != 0);

		esplog(esp, CE_WARN, "%s message 0x%x from Target %d",
		    garbled ? "Garbled" : "Identify", msgin, tgt);

		if (garbled) {
			/*
			 * If it's a garbled message,
			 * try and tell the target...
			 */
			msgout = MSG_INITIATOR_ERROR;
		} else {
			New_state(esp, ACTS_UNKNOWN);
		}
		LOG_STATE(esp, ACTS_MSG_IN, esp->e_stat, msgin, -1);
		return (msgout);

	} else if (IS_2BYTE_MSG(msgin) || IS_EXTENDED_MSG(msgin)) {
		esp->e_imsglen = 2;
		New_state(esp, ACTS_MSG_IN_MORE);
		return (0);
	}

	New_state(esp, ACTS_UNKNOWN);

	switch (msgin) {
	case MSG_DISCONNECT:
		/*
		 * If we 'cannot' disconnect- reject this message.
		 * Note that we only key off of the pkt_flags here-
		 * it would be inappropriate to test against esp->e_scsi_options
		 * or esp->e_nodisc here (they might have been changed
		 * after this command started). I realize that this
		 * isn't complete coverage against this error, but it
		 * is the best we can do. I thought briefly about setting
		 * the FLAG_NODISCON bit in a packet
		 * if either of esp->e_scsi_options or esp->e_nodisc indicated
		 * that disconnect/reconnect has been turned off, but
		 * that might really bolix up the true owner of the
		 * packet (the target driver) who has really only
		 * *loaned* us this packet during transport.
		 */
		if (sp->cmd_pkt.pkt_flags & FLAG_NODISCON) {
			msgout = MSG_REJECT;
			break;
		}
		LOG_STATE(esp, ACTS_DISCONNECT, esp->e_stat, esp->e_xfer, -1);
		/* FALLTHROUGH */
	case MSG_COMMAND_COMPLETE:
		/* FALLTHROUGH */
	case MSG_LINK_CMPLT:
		/* FALLTHROUGH */
	case MSG_LINK_CMPLT_FLAG:
		esp->e_state = ACTS_CLEARING;
		LOG_STATE(esp, ACTS_MSG_IN, esp->e_stat, msgin, -1);
		break;

	/* This has been taken care of above	*/
	/* case MSG_EXTENDED:			*/

	case MSG_NOP:
		LOG_STATE(esp, ACTS_NOP, esp->e_stat, -1, -1);
		break;

	case MSG_REJECT:
	{
		uchar_t reason = 0;
		uchar_t lastmsg = esp->e_last_msgout;
		/*
		 * The target is rejecting the last message we sent.
		 *
		 * If the last message we attempted to send out was an
		 * extended message, we were trying to negotiate sync
		 * xfers- and we're okay.
		 *
		 * Otherwise, a target has rejected a message that
		 * it should have handled. We will abort the operation
		 * in progress and set the pkt_reason value here to
		 * show why we have completed. The process of aborting
		 * may be via a message or may be via a bus reset (as
		 * a last resort).
		 */
		msgout = (TAGGED(tgt)? MSG_ABORT_TAG : MSG_ABORT);
		LOG_STATE(esp, ACTS_REJECT, esp->e_stat, -1, -1);

		switch (lastmsg) {
		case MSG_EXTENDED:
			esp->e_sdtr = 0;
			esp->e_offset[tgt] = 0;
			esp->e_sync_known |= (1<<tgt);
			esp->e_weak |= (1<<tgt);
			msgout = 0;
			break;

		case MSG_NOP:
			reason = CMD_NOP_FAIL;
			break;
		case MSG_INITIATOR_ERROR:
			reason = CMD_IDE_FAIL;
			break;
		case MSG_MSG_PARITY:
			reason = CMD_PER_FAIL;
			break;
		case MSG_REJECT:
			reason = CMD_REJECT_FAIL;
			break;
		case MSG_SIMPLE_QTAG:
		case MSG_ORDERED_QTAG:
		case MSG_HEAD_QTAG:
			msgout = MSG_ABORT;
			reason = CMD_TAG_REJECT;
			break;
		case MSG_DEVICE_RESET:
		case MSG_ABORT:
		case MSG_ABORT_TAG:
			/*
			 * If an RESET/ABORT OPERATION message is rejected
			 * it is time to yank the chain on the bus...
			 */
			reason = CMD_ABORT_FAIL;
			msgout = -ACTION_ABORT_CURCMD;
			break;
		default:
			if (IS_IDENTIFY_MSG(lastmsg)) {
				if (TAGGED(tgt)) {
					/*
					 * this often happens when the
					 * target rejected our tag
					 */
					reason = CMD_TAG_REJECT;
				} else {
					reason = CMD_ID_FAIL;
				}
			} else {
				reason = CMD_TRAN_ERR;
				msgout = -ACTION_ABORT_CURCMD;
			}

			break;
		}

		if (msgout) {
			esplog(esp, CE_WARN,
			    "Target %d rejects our message '%s'",
			    tgt, scsi_mname(lastmsg));
			if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {
				IPRINTF2("sp=0x%p, pkt_reason=%x\n",
				    (void *)sp, reason);
				sp->cmd_pkt.pkt_reason = reason;
			}
		}
		break;
	}
	case MSG_RESTORE_PTRS:
		if (sp->cmd_data_count != sp->cmd_saved_data_count) {
			if (esp_restore_pointers(esp, sp)) {
				msgout = -ACTION_ABORT_CURCMD;
			}
		}
		LOG_STATE(esp, ACTS_RESTOREDP, esp->e_stat, esp->e_xfer, -1);
		break;

	case MSG_SAVE_DATA_PTR:
		sp->cmd_saved_data_count = sp->cmd_data_count;
		sp->cmd_saved_win  = sp->cmd_cur_win;
		sp->cmd_saved_cur_addr = sp->cmd_cur_addr;
		LOG_STATE(esp, ACTS_SAVEDP, esp->e_stat, esp->e_xfer, -1);
		break;

	/* These don't make sense for us, and	*/
	/* will be rejected			*/
	/*	case MSG_INITIATOR_ERROR	*/
	/*	case MSG_ABORT			*/
	/*	case MSG_MSG_PARITY		*/
	/*	case MSG_DEVICE_RESET		*/
	default:
		msgout = MSG_REJECT;
		esplog(esp, CE_WARN,
		    "Rejecting message '%s' from Target %d",
		    scsi_mname(msgin), tgt);
		LOG_STATE(esp, ACTS_MSG_IN, esp->e_stat, msgin, -1);
		break;
	}

	EPRINTF1("Message in: %s\n", scsi_mname(msgin));

	return (msgout);
}

/*
 * phase handlers that are rarely used
 */
static int
esp_handle_cmd_start(struct esp *esp)
{
	volatile struct espreg *ep = esp->e_reg;
	struct esp_cmd *sp = CURRENT_CMD(esp);
	int amt = sp->cmd_cdblen;
	uint_t cmd_distance;

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CMD_START_START,
	    "esp_handle_cmd_start_start");
	EPRINTF("esp_handle_cmd:\n");

	/*
	 * If the cmd is a defined scsi-2 cdb and it'll fit in our dma buffer,
	 * we'll use dma.  If not, we send it one byte at a time and take
	 * forever!
	 */
	if (amt > 0) {
		volatile caddr_t tp = (caddr_t)esp->e_cmdarea;
		int i;

		EPRINTF("esp_handle_cmd: send cmd\n");
		for (i = 0; i < amt; i++) {
			*tp++ = sp->cmd_cdbp[i];
		}
		esp_flush_fifo(esp);

		SET_DMAESC_COUNT(esp->e_dma, esp->e_esc_read_count);
		ESP_DMA_READ(esp, amt, esp->e_dmacookie.dmac_address);

		Esp_cmd(esp, CMD_DMA | CMD_TRAN_INFO);
		esp->e_lastcount = amt;
		LOG_STATE(esp, ACTS_CMD, sp->cmd_cdbp[0], -1, -1);
	} else {
		/*
		 * Check for command overflow.
		 */
		cmd_distance =
		    (uintptr_t)sp->cmd_cdbp - (uintptr_t)sp->cmd_pkt.pkt_cdbp;
		if (cmd_distance >= (uint_t)CDB_GROUP5) {
			if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
				sp->cmd_pkt.pkt_reason = CMD_CMD_OVR;
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_CMD_START_ABORT_CMD_END,
			    "esp_handle_cmd_start_end (abort_cmd)");
			return (ACTION_ABORT_CURCMD);
		}
		if (cmd_distance == 0) {
			LOG_STATE(esp, ACTS_CMD_START, esp->e_stat,
			    sp->cmd_cdbp[0], -1);
		}

		/*
		 * Stuff next command byte into fifo
		 */
		esp_flush_fifo(esp);

		/* delay here: prevents problems with CDROM, see 1068706 */
		SET_ESP_COUNT(ep, 1);
		ep->esp_fifo_data = *(sp->cmd_cdbp++);

		Esp_cmd(esp, CMD_TRAN_INFO);
	}

	New_state(esp, ACTS_CMD_DONE);
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CMD_START_END,
	    "esp_handle_cmd_start_end");
	return (ACTION_RETURN);
}

static int
esp_handle_cmd_done(struct esp *esp)
{
	struct esp_cmd *sp = CURRENT_CMD(esp);
	uchar_t intr = esp->e_intr;

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CMD_DONE_START,
	    "esp_handle_cmd_done_start");
	EPRINTF("esp_handle_cmd_done\n");

	/*
	 * The NOP command is required following a COMMAND
	 * or MESSAGE OUT phase in order to unlatch the
	 * FIFO flags register. This is needed for all
	 * ESP chip variants.
	 */
	Esp_cmd(esp, CMD_NOP);

	/*
	 * We should have gotten a BUS SERVICE interrupt.
	 * If it isn't that, and it isn't a DISCONNECT
	 * interrupt, we have a "cannot happen" situation.
	 */
	if ((intr & ESP_INT_BUS) == 0) {
		if ((intr & ESP_INT_DISCON) == 0) {
			esp_printstate(esp, "cmd transmission error");
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CMD_DONE_ABORT1_END,
			    "esp_handle_cmd_done_end (abort1)");
			return (ACTION_ABORT_CURCMD);
		}
	} else {
		sp->cmd_pkt.pkt_state |= STATE_SENT_CMD;
	}

	/*
	 * If we dma'ed out the cdb, we have a little cleanup to do...
	 */
	if (sp->cmd_cdblen > 0) {
		volatile struct dmaga *dmar = esp->e_dma;
		int amt, i;

		esp->e_dmaga_csr = dmar->dmaga_csr;
		ESP_FLUSH_DMA(esp);
		amt = dmar->dmaga_addr - esp->e_lastdma;

		if (ESP_DMAGA_REV(esp) != ESC1_REV1) {
			if ((i = DMAGA_NEXTBYTE(dmar)) != 0) {
				amt -= (4-i);
			}
		}

		if (amt < esp->e_lastcount) {
			i = esp->e_lastcount - amt;
			esplog(esp, CE_WARN, "cmd dma error");
			TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CMD_DONE_ABORT2_END,
			    "esp_handle_cmd_done_end (abort2)");
			return (ACTION_ABORT_CURCMD);
		}
	}

	New_state(esp, ACTS_UNKNOWN);
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_CMD_DONE_END,
	    "esp_handle_cmd_done_end");
	return (esp_handle_unknown(esp));
}

/*
 * Begin to send a message out
 */
static int
esp_handle_msg_out(struct esp *esp)
{
	struct esp_cmd *sp = CURRENT_CMD(esp);
	volatile struct espreg *ep = esp->e_reg;
	uchar_t *msgout = esp->e_cur_msgout;
	char amt = esp->e_omsglen;

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_OUT_START,
	    "esp_handle_msg_out_start");
	EPRINTF("esp_handle_msg_out\n");

	/*
	 * Check to make *sure* that we are really
	 * in MESSAGE OUT phase. If the last state
	 * was ACTS_MSG_OUT_DONE, then we are trying
	 * to resend a message that the target stated
	 * had a parity error in it.
	 *
	 * If this is the case, and mark completion reason as CMD_NOMSGOUT.
	 * XXX: Right now, we just *drive* on. Should we abort the command?
	 */
	if ((esp->e_stat & ESP_PHASE_MASK) != ESP_PHASE_MSG_OUT &&
	    esp->e_laststate == ACTS_MSG_OUT_DONE) {
		esplog(esp, CE_WARN,
		    "Target %d refused message resend", Tgt(sp));
		if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
			sp->cmd_pkt.pkt_reason = CMD_NOMSGOUT;
		New_state(esp, ACTS_UNKNOWN);
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_OUT_PHASEMANAGE_END,
		    "esp_handle_msg_out_end (ACTION_PHASEMANAGE)");
		return (ACTION_PHASEMANAGE);
	}

	/*
	 * Clean the fifo.
	 */
	esp_flush_fifo(esp);

	/*
	 * If msg only 1 byte, just dump it in the fifo and go.	 For
	 * multi-byte msgs, dma them to save time.  If we have no
	 * msg to send and we're in msg out phase, send a NOP.
	 *
	 * XXX: If target rejects synch. negotiate, we'll end up
	 *	having to send a nop msg because the esp chip doesn't
	 *	drop ATN* fast enough.
	 */
	if (amt == 1) {
		ep->esp_fifo_data = *msgout;
		ep->esp_cmd = CMD_TRAN_INFO;

	} else if (amt > 1) {
		volatile caddr_t tp = (caddr_t)esp->e_cmdarea;
		char i;

		for (i = 0; i < amt; i++)
			*tp++ = *msgout++;
		SET_DMAESC_COUNT(esp->e_dma, esp->e_esc_read_count);
		ESP_DMA_READ(esp, amt, esp->e_dmacookie.dmac_address);

		Esp_cmd(esp, CMD_DMA | CMD_TRAN_INFO);
		esp->e_lastcount = amt;
	} else {
		/*
		 * this happens when the target reject the first byte
		 * of an extended msg such as synch negotiate
		 * (see also comment above)
		 */
		ep->esp_fifo_data = *msgout = MSG_NOP;
		esp->e_omsglen = 1;
		Esp_cmd(esp, CMD_TRAN_INFO);
	}

	New_state(esp, ACTS_MSG_OUT_DONE);
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_OUT_END,
	    "esp_handle_msg_out_end");
	return (ACTION_RETURN);
}

static int
esp_handle_msg_out_done(struct esp *esp)
{
	struct esp_cmd *sp = CURRENT_CMD(esp);
	volatile struct espreg *ep = esp->e_reg;
	uchar_t msgout, phase, fifocnt;
	int target = Tgt(sp);
	int	amt = esp->e_omsglen;
	int action;

	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_OUT_DONE_START,
	    "esp_handle_msg_out_done_start");
	msgout = esp->e_cur_msgout[0];
	if (msgout == MSG_HEAD_QTAG || msgout == MSG_SIMPLE_QTAG) {
		msgout = esp->e_cur_msgout[2];
	}
	EPRINTF4("msgout: %x %x %x, last_msgout=%x\n",
		esp->e_cur_msgout[0], esp->e_cur_msgout[1],
		esp->e_cur_msgout[2], esp->e_last_msgout);

	EPRINTF1("esp_handle_msgout_done: msgout=%x\n", msgout);

	/*
	 * If we dma'ed out the msg, we have a little cleanup to do...
	 */
	if (amt > 1) {
		volatile struct dmaga *dmar = esp->e_dma;
		int i;

		esp->e_dmaga_csr = dmar->dmaga_csr;
		ESP_FLUSH_DMA(esp);
		amt = dmar->dmaga_addr - esp->e_lastdma;
		if (ESP_DMAGA_REV(esp) != ESC1_REV1) {
			if ((i = DMAGA_NEXTBYTE(dmar)) != 0) {
				amt -= (4-i);
			}
		}
		EPRINTF2("xfer= %d(%d)\n", amt, esp->e_lastcount);
	}

	/*
	 * If the ESP disconnected, then the message we sent caused
	 * the target to decide to drop BSY* and clear the bus.
	 */
	if (esp->e_intr == ESP_INT_DISCON) {
		if (msgout == MSG_DEVICE_RESET || msgout == MSG_ABORT ||
		    msgout == MSG_ABORT_TAG) {
			esp_chip_disconnect(esp, sp);
			/*
			 * If we sent a device reset msg, then we need to do
			 * a synch negotiate again unless we have already
			 * inhibited synch.
			 */
			if (msgout == MSG_ABORT || msgout == MSG_ABORT_TAG) {
				esp->e_abort++;
				if ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) {
				    MARK_PKT(sp, CMD_ABORTED, STAT_ABORTED);
				}
			} else if (msgout == MSG_DEVICE_RESET) {
				esp->e_reset++;
				if ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) {
				    MARK_PKT(sp, CMD_RESET, STAT_DEV_RESET);
				}
				esp->e_offset[target] = 0;
				esp->e_sync_known &= ~(1<<target);
			}
			EPRINTF2("Successful %s message to target %d\n",
			    scsi_mname(msgout), target);

			if (sp->cmd_flags & CFLAG_CMDPROXY) {
				sp->cmd_cdb[ESP_PROXY_RESULT] = TRUE;
			}
			TRACE_0(TR_FAC_SCSI,
			    TR_ESP_HANDLE_MSG_OUT_DONE_FINISH_END,
			    "esp_handle_msg_out_done_end (ACTION_FINISH)");
			return (ACTION_FINISH);
		}
		/*
		 * If the target dropped busy on any other message, it
		 * wasn't expected. We will let the code in esp_phasemanage()
		 * handle this unexpected bus free event.
		 */
		goto out;
	}

	/*
	 * What phase have we transitioned to?
	 */
	phase = esp->e_stat & ESP_PHASE_MASK;

	/*
	 * Save current fifo count
	 */
	fifocnt = FIFO_CNT(ep);

	/*
	 * As per the ESP errata sheets, this must be done for
	 * all ESP chip variants.
	 *
	 * This releases the FIFO counter from its latched state.
	 * Note that we read the fifo counter above prior to doing
	 * this.
	 */
	Esp_cmd(esp, CMD_NOP);

	/*
	 * Clean the fifo? Yes, if and only if we haven't
	 * transitioned to Synchronous DATA IN phase.
	 * The ESP chip manual notes that in the case
	 * that the target has shifted to Synchronous
	 * DATA IN phase, that while the FIFO count
	 * register stays latched up with the number
	 * of bytes not transferred out, that the fifo
	 * itself is cleared and will contain only
	 * the incoming data bytes.
	 *
	 * The manual doesn't state what happens in
	 * other receive cases (transition to STATUS,
	 * MESSAGE IN, or asynchronous DATA IN phase),
	 * but I'll assume that there is probably
	 * a single-byte pad between the fifo and
	 * the SCSI bus which the ESP uses to hold
	 * the currently asserted data on the bus
	 * (known valid by a true REQ* signal). In
	 * the case of synchronous data in, up to
	 * 15 bytes of data could arrive, so the
	 * ESP must have to make room for by clearing
	 * the fifo, but in other cases it can just
	 * hold the current byte until the next
	 * ESP chip command that would cause a
	 * data transfer.
	 * XXX STILL NEEDED????
	 */
	if (fifocnt != 0 && (phase != ESP_PHASE_DATA_IN ||
	    esp->e_offset[target] == 0)) {
		esp_flush_fifo(esp);
	}

	/*
	 * If we finish sending a message out, and we are
	 * still in message out phase, then the target has
	 * detected one or more parity errors in the message
	 * we just sent and it is asking us to resend the
	 * previous message.
	 */
	if ((esp->e_intr & ESP_INT_BUS) && phase == ESP_PHASE_MSG_OUT) {
		/*
		 * As per SCSI-2 specification, if the message to
		 * be re-sent is greater than one byte, then we
		 * have to set ATN*.
		 */
		if (amt > 1) {
			Esp_cmd(esp, CMD_SET_ATN);
		}
		esplog(esp, CE_WARN,
		    "SCSI bus MESSAGE OUT phase parity error");
		sp->cmd_pkt.pkt_statistics |= STAT_PERR;
		New_state(esp, ACTS_MSG_OUT);
		TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_OUT_DONE_PHASEMANAGE_END,
		    "esp_handle_msg_out_done_end (ACTION_PHASEMANAGE)");
		return (ACTION_PHASEMANAGE);
	}

	/*
	 * Count that we sent a SYNCHRONOUS DATA TRANSFER message.
	 * (allow for a tag message before the sdtr msg)
	 */
	if (((esp->e_omsglen == 5 && msgout == MSG_EXTENDED &&
	    esp->e_cur_msgout[2] == MSG_SYNCHRONOUS)) ||
	    ((esp->e_omsglen == 7 &&
	    esp->e_cur_msgout[2] == MSG_EXTENDED &&
	    esp->e_cur_msgout[4] == MSG_SYNCHRONOUS))) {
		esp->e_sdtr++;
	}

out:
	esp->e_last_msgout = msgout;
	esp->e_omsglen = 0;
	New_state(esp, ACTS_UNKNOWN);
	action = esp_handle_unknown(esp);
	TRACE_0(TR_FAC_SCSI, TR_ESP_HANDLE_MSG_OUT_DONE_END,
	    "esp_handle_msg_out_done_end");
	return (action);
}


static int
esp_twobyte_msg(struct esp *esp)
{
	esplog(esp, CE_WARN,
	    "Two byte message '%s' 0x%x rejected",
	    scsi_mname(esp->e_imsgarea[0]), esp->e_imsgarea[1]);
	return (MSG_REJECT);
}

/*
 * esp_update_props creates/modifies/removes a target sync mode speed
 * property containing tickval (KB/sec in hex)
 * If offset is 0 then asynchronous mode is assumed and the property
 * is removed
 */
static void
esp_update_props(struct esp *esp, int tgt)
{
	static char *prop_template = "target%d-sync-speed";
	char property[32];
	dev_info_t *dip = esp->e_dev;
	uint_t offset = esp->e_offset[tgt];
	uint_t regval = esp->e_period[tgt];
	uint_t tickval;

	if (offset) {
		/*
		 * Convert input clock cycle per
		 * byte to nanoseconds per byte.
		 * (ns/b), and convert that to
		 * k-bytes/second.
		 */

		tickval = ESP_SYNC_KBPS((regval *
				esp->e_clock_cycle) / 1000);
	} else {
		tickval = 0;
	}
	ASSERT(mutex_owned(ESP_MUTEX));
	/*
	 * We cannot hold any mutex at this point because the call to
	 * ddi_prop_update_int, ddi_prop_remove  may block.
	 */
	mutex_exit(ESP_MUTEX);
	(void) sprintf(property, prop_template, tgt);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, property)) {
		if (offset == 0) {
			/*
			 * if target was switched back to async mode,
			 * remove property
			 */
			if (ddi_prop_remove(DDI_DEV_T_NONE, dip, property) !=
			    DDI_PROP_SUCCESS) {
				IPRINTF1("cannot remove %s property\n",
				    property);
			}
			mutex_enter(ESP_MUTEX);
			return;
		}
	}
	if (offset != 0) {
		if (ddi_prop_update_int(DDI_DEV_T_NONE, dip, property,
		    (int)tickval) != DDI_PROP_SUCCESS) {
			IPRINTF1("cannot create %s property\n", property);
		}
	}
	mutex_enter(ESP_MUTEX);
}

static int
esp_multibyte_msg(struct esp *esp)
{
#ifdef ESPDEBUG
/*
 * XXX: Should be able to use %d.03%d instead of three different messages.
 */
	static char *mbs =
	    "Target %d now Synchronous at %d.%d MB/s max transmit rate\n";
	static char *mbs1 =
	    "Target %d now Synchronous at %d.0%d MB/s max transmit rate\n";
	static char *mbs2 =
	    "Target %d now Synchronous at %d.00%d MB/s max transmit rate\n";
#endif
	struct esp_cmd *sp = CURRENT_CMD(esp);
	volatile struct espreg *ep = esp->e_reg;
	uchar_t emsg = esp->e_imsgarea[2];
	int tgt = Tgt(sp);
	int msgout = 0;

	EPRINTF("esp_multibyte_msg:\n");

	if (emsg == MSG_SYNCHRONOUS) {
		uint_t period, offset, regval;
		uint_t minsync, maxsync, clockval;

		period = esp->e_imsgarea[3]&0xff;
		offset = esp->e_imsgarea[4]&0xff;
		minsync = MIN_SYNC_PERIOD(esp);
		maxsync = MAX_SYNC_PERIOD(esp);
		EPRINTF3("received period %d offset %d from tgt %d\n",
		    period, offset, tgt);
		EPRINTF3("calculated minsync %d, maxsync %d for tgt %d\n",
		    minsync, maxsync, tgt);

		if ((++(esp->e_sdtr)) & 1) {
			/*
			 * In cases where the target negotiates synchronous
			 * mode before we do, and we either have sync mode
			 * disbled, or this target is known to be a weak
			 * signal target, we send back a message indicating
			 * a desire to stay in asynchronous mode (the SCSI-2
			 * spec states that if we have synchronous capability
			 * that we cannot reject a SYNCHRONOUS DATA TRANSFER
			 * REQUEST message).
			 */
			IPRINTF1("SYNC neg. initiated by tgt %d:\n", tgt);
			IPRINTF2("period=%x, offset=%x\n", period, offset);
			msgout = MSG_EXTENDED;
			period = max(period, esp->e_default_period[tgt]);
			offset = min(DEFAULT_OFFSET, offset);

			if ((esp->e_weak & (1<<tgt)) ||
			    (esp->e_target_scsi_options[tgt] &
				SCSI_OPTIONS_SYNC) == 0) {
				/*
				 * Only zero out the offset. Don't change
				 * the period.
				 */
				esp_make_sdtr(esp, 0, (int)period, 0);
				IPRINTF("sending async back\n");
				esp->e_neg_period[tgt] = 0;
				esp->e_period[tgt] = 0;
				esp->e_offset[tgt] = 0;
				esp->e_espconf3_last = esp->e_period_last =
				    esp->e_offset_last = (uchar_t)-1;
				goto out;
			}
			if (esp->e_backoff[tgt] == 1) {
				period = max(period, esp->e_neg_period[tgt]);
			} else if (esp->e_backoff[tgt] > 1) {
				period = max(period, esp->e_neg_period[tgt]);
				offset = 0;
			}
		}

		regval = 0;

		/*
		 * If the target's offset is bigger than ours,
		 * the target has violated the scsi protocol.
		 */
		if (offset > DEFAULT_OFFSET) {
			period = offset = 0;
			msgout = MSG_REJECT;
			goto out;
		}

		if (offset && period > maxsync) {
			/*
			 * We cannot transmit data in synchronous
			 * mode this slow, so convert to asynchronous
			 * mode.
			 */
			msgout = MSG_EXTENDED;
			esp_make_sdtr(esp, 0, (int)period, 0);
			goto out;

		} else if (offset && period < minsync) {
			/*
			 * If the target's period is less than ours,
			 * the target has violated the scsi protocol.
			 */
			period = offset = 0;
			msgout = MSG_REJECT;
			goto out;

		} else if (offset) {
			/*
			 * Conversion method for received PERIOD value
			 * to the number of input clock ticks to the ESP.
			 *
			 * We adjust the input period value such that
			 * we always will transmit data *not* faster
			 * than the period value received.
			 */

			clockval = esp->e_clock_cycle / 1000;
			regval = (((period << 2) + clockval - 1) / clockval);

			/*
			 * correct for FAS if xfer rate <= 5MB/sec
			 */
			if (regval && (esp->e_options & ESP_OPT_FAS)) {
				if (period >= FASTSCSI_THRESHOLD) {
					regval--;
				}
			}

			/*
			 * Strictly paranoia!
			 */
			if (regval > MAX_SYNC(esp)) {
				msgout = MSG_EXTENDED;
				esp_make_sdtr(esp, 0, (int)period, 0);
				goto out;
			}
		}

		esp->e_neg_period[tgt] = period;
		esp->e_offset[tgt] = offset;

		if (offset) {
			esp->e_period[tgt] =
			    esp->e_period_last = ep->esp_sync_period =
			    regval & SYNC_PERIOD_MASK;

			esp->e_offset_last = ep->esp_sync_offset =
			    esp->e_offset[tgt] = offset | esp->e_req_ack_delay;

			if (esp->e_options & ESP_OPT_FAS) {
				/*
				 * if transferring > 5 MB/sec then enable
				 * fastscsi in conf3
				 */
				if (period < FASTSCSI_THRESHOLD) {
					esp->e_espconf3[tgt] |=
					    esp->e_espconf3_fastscsi;
				} else {
					esp->e_espconf3[tgt] &=
					    ~esp->e_espconf3_fastscsi;
				}
				esp->e_espconf3_last =
				    ep->esp_conf3 = esp->e_espconf3[tgt];
			}

			EPRINTF4(
				"sending period %d (%d), offset %d to tgt %d\n",
				period, esp->e_period[tgt] & SYNC_PERIOD_MASK,
				esp->e_offset[tgt] & 0xf, tgt);
			EPRINTF1("req/ack delay = %x\n", esp->e_req_ack_delay);
			EPRINTF1("conf3 = %x\n", esp->e_espconf3[tgt]);

#ifdef ESPDEBUG
		{
			uint_t xfer_freq, xfer_div, xfer_mod;
			/*
			 * Convert input clock cycle per
			 * byte to nanoseconds per byte.
			 * (ns/b), and convert that to
			 * k-bytes/second.
			 */
			xfer_freq = ESP_SYNC_KBPS((regval *
				esp->e_clock_cycle) / 1000);
			xfer_div = xfer_freq / 1000;
			xfer_mod = xfer_freq % 1000;


			if (xfer_mod > 99) {
				IPRINTF3(mbs, tgt, xfer_div, xfer_mod);
			} else if (xfer_mod > 9) {
				IPRINTF3(mbs1, tgt, xfer_div, xfer_mod);
			} else {
				IPRINTF3(mbs2, tgt, xfer_div, xfer_mod);
			}
		}
#endif /* ESPDEBUG */
		} else {
			/*
			 * We are converting back to async mode.
			 */
			esp->e_period_last = ep->esp_sync_period =
			    esp->e_period[tgt] = 0;
			esp->e_offset_last = ep->esp_sync_offset =
			    esp->e_offset[tgt] = 0;
			esp->e_espconf3[tgt] &= ~esp->e_espconf3_fastscsi;
			esp->e_espconf3_last =
			    ep->esp_conf3 = esp->e_espconf3[tgt];
		}

		if (msgout) {
			esp_make_sdtr(esp, 0, (int)period, (int)offset);
		}
		esp->e_sync_known |= (1<<tgt);

		esp->e_props_update |= (1<<tgt);

	} else if (emsg == MSG_MODIFY_DATA_PTR) {
		msgout = MSG_REJECT;
	} else {
		if (emsg != MSG_WIDE_DATA_XFER) {
			esplog(esp, CE_WARN,
			    "Rejecting message %s 0x%x from Target %d",
			    scsi_mname(MSG_EXTENDED), emsg, tgt);
		} else {
			IPRINTF3(
			    "Rejecting message %s 0x%x from Target %d",
			    scsi_mname(MSG_EXTENDED), emsg, tgt);
		}
		msgout = MSG_REJECT;
	}
out:
	New_state(esp, ACTS_UNKNOWN);
	return (msgout);
}

static int
esp_handle_selection(struct esp *esp)
{
	Esp_cmd(esp, CMD_DISCONNECT);
	return (ACTION_RETURN);
}

/*
 * dma window handling
 */
static int
esp_restore_pointers(struct esp *esp, struct esp_cmd *sp)
{
	if (sp->cmd_data_count != sp->cmd_saved_data_count) {
		sp->cmd_data_count = sp->cmd_saved_data_count;
		sp->cmd_cur_addr = sp->cmd_saved_cur_addr;

		if (sp->cmd_cur_win != sp->cmd_saved_win) {
			sp->cmd_cur_win = sp->cmd_saved_win;
			if (esp_set_new_window(esp, sp)) {
				return (-1);
			}
		}
		IPRINTF1("curaddr=%x\n", sp->cmd_cur_addr);
	}
	return (0);
}

static int
esp_set_new_window(struct esp *esp, struct esp_cmd *sp)
{
	off_t offset;
	size_t len;
	uint_t count;

	if (ddi_dma_getwin(sp->cmd_dmahandle, sp->cmd_cur_win,
	    &offset, &len, &sp->cmd_dmacookie, &count) != DDI_SUCCESS) {
		return (-1);
	}

	IPRINTF4("new window %x: off=%lx, len=%lx, count=%x\n",
	    sp->cmd_cur_win, offset, len, count);

	ASSERT(count == 1);
	return (0);
}

static int
esp_next_window(struct esp *esp, struct esp_cmd *sp)
{

	/* are there more windows? */
	if (sp->cmd_nwin == 0) {
		uint_t nwin = 0;
		(void) ddi_dma_numwin(sp->cmd_dmahandle, &nwin);
		sp->cmd_nwin = (uchar_t)nwin;
	}

	IPRINTF4(
	    "cmd_data_count=%x, dmacount=%x, curaddr=%x, nwin=%x\n",
	    sp->cmd_data_count, sp->cmd_dmacount, sp->cmd_cur_addr,
	    sp->cmd_nwin);

	/*
	 * if there are no more windows, we have a data overrun condition
	 */
	if (++sp->cmd_cur_win >= sp->cmd_nwin) {
		int slot = Tgt(sp) * NTARGETS | Lun(sp);

		esp_printstate(esp, "data transfer overrun");

		if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {
			sp->cmd_pkt.pkt_reason = CMD_DATA_OVR;
		}
		/*
		 * A fix for bug id 1048141- if we get data transfer
		 * overruns, assume we have a weak scsi bus. Note that
		 * this won't catch consistent underruns or other
		 * noise related syndromes.
		 */
		esp_sync_backoff(esp, sp, slot);
		return (-1);

	} else {
		if (esp_set_new_window(esp, sp)) {
			sp->cmd_cur_win--;
			return (-1);
		}
	}
	sp->cmd_cur_addr = sp->cmd_dmacookie.dmac_address;
	IPRINTF1("cur_addr=%x\n", sp->cmd_cur_addr);
	return (0);
}

/*
 * dma error checking
 */
static int
esp_check_dma_error(struct esp *esp)
{
	/*
	 * was there a dmaga error that caused espsvc() to be called?
	 */
	if (esp->e_dma->dmaga_csr & DMAGA_ERRPEND) {
		/*
		 * It would be desirable to set the ATN* line and attempt to
		 * do the whole schmear of INITIATOR DETECTED ERROR here,
		 * but that is too hard to do at present.
		 */
		esp_printstate(esp, "dma error");
		esplog(esp, CE_WARN, "Unrecoverable DMA error on dma");
		if (esp->e_cur_slot != UNDEFINED) {
			struct esp_cmd *sp = CURRENT_CMD(esp);
			if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
				sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
		}
		return (-1);
	}
	return (0);
}

/*
 * run a polled cmd
 */
static void
esp_runpoll(struct esp *esp, short slot, struct esp_cmd *sp)
{
	int limit, i, n;
	int timeout = 0;

	IPRINTF4("runpoll: slot=%x, cmd=%x, e_slots=0x%p, tcmds=%x\n",
		slot, *((uchar_t *)sp->cmd_pkt.pkt_cdbp),
		(void *)esp->e_slots[slot], esp->e_tcmds[slot]);

	TRACE_0(TR_FAC_SCSI, TR_ESP_RUNPOLL_START, "esp_runpoll_start");

	/*
	 * wait for cmd to complete
	 * don't start new cmds so set throttles to HOLD_THROTTLE
	 */
	while ((sp->cmd_flags & CFLAG_COMPLETED) == 0) {
		struct esp_cmd *savesp = esp->e_slots[slot];

		esp_check_in_transport(esp, NULL);

		if (savesp) {
			ASSERT(savesp->cmd_flags & CFLAG_IN_TRANSPORT);
		}

		esp_set_all_lun_throttles(esp, slot, HOLD_THROTTLE);
		if ((esp->e_state != STATE_FREE) || INTPENDING(esp)) {
			if (esp_dopoll(esp, POLL_TIMEOUT) <= 0) {
				IPRINTF("runpoll: timeout on draining\n");
				goto bad;
			}
		}

		/*
		 * if this is not a proxy cmd, don't start the cmd
		 * without draining the active cmd(s)
		 * for proxy cmds, we zap the active cmd and assume
		 * that the caller will take care of this
		 * For tagged cmds, wait with submitting a non-tagged
		 * cmd until the queue has been drained
		 * If the cmd is a request sense, then draining won't
		 * help since we are in contingence allegiance condition
		 * XXX this shouldn't really be necessary but it is
		 * safer
		 */
		if (!(sp->cmd_flags & CFLAG_CMDPROXY)) {
			uchar_t *cmdp = (uchar_t *)sp->cmd_pkt.pkt_cdbp;
			if (((esp->e_slots[slot] != NULL) &&
			    (sp != esp->e_slots[slot])) ||
			    (((sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) == 0) &&
			    TAGGED(Tgt(sp)) && esp->e_tcmds[slot]) &&
			    (*cmdp != SCMD_REQUEST_SENSE)) {
				if (timeout < POLL_TIMEOUT) {
					timeout += 100;
					drv_usecwait(100);
					continue;
				} else {
					esplog(esp, CE_WARN,
					    "polled cmd failed (target busy)");
					goto cleanup;
				}
			}
			ASSERT((esp->e_slots[slot] == NULL) ||
			    (esp->e_slots[slot] == sp));
		}

		/*
		 * If the draining of active commands killed the
		 * the current polled command, we're done..
		 * XXX this is not very likely
		 */
		if (sp->cmd_flags & CFLAG_COMPLETED) {
			break;
		}

		/*
		 * ensure we are not accessing a target too quickly
		 * after a reset. the throttles get set back later
		 * by the reset delay watch; hopefully, we don't go
		 * thru this loop more than once
		 */
		if (esp->e_reset_delay[slot/NLUNS_PER_TARGET]) {
			IPRINTF1("reset delay set for slot %x\n", slot);
			drv_usecwait(esp->e_scsi_reset_delay * 1000);
			for (i = 0; i < NTARGETS; i++) {
				if (esp->e_reset_delay[i]) {
					int s = i * NLUNS_PER_TARGET;
					int e = s + NLUNS_PER_TARGET;
					esp->e_reset_delay[i] = 0;
					for (; s < e; s++) {
						esp->e_throttle[s] =
						    CLEAR_THROTTLE;
					}
				}
			}
		}

		/*
		 * the draining should have cleaned everything up
		 */
		ASSERT(esp->e_state == STATE_FREE);
		if (esp->e_slots[slot] && (esp->e_slots[slot] != sp)) {
			ASSERT(savesp == esp->e_slots[slot]);
			ASSERT(savesp->cmd_flags & CFLAG_CMDDISC);
			ASSERT(savesp->cmd_flags & CFLAG_IN_TRANSPORT);

			/* adjust the counts since this cmd is now gone */
			esp_decrement_ncmds(esp, savesp);
			/*
			 * set finished flag so the counts won't get
			 * decremented again for this cmd
			 */
			savesp->cmd_flags |= CFLAG_FINISHED;
		}

		esp->e_slots[slot] = sp;
		esp->e_cur_slot = slot;
		ASSERT(sp->cmd_flags & CFLAG_IN_TRANSPORT);

		/* make sure the throttles are still on hold */
		esp_set_all_lun_throttles(esp, slot, HOLD_THROTTLE);

		/*
		 * esp_startcmd() will return false if preempted and will
		 * not service the interrupt if NOINTR cmd
		 * if this cmd was a non-tagged cmd for a tagged cmd
		 * esp_startcmd will also return false
		 */
		if (esp_startcmd(esp, sp) != TRUE) {
			continue;
		}

		/*
		 * We're now 'running' this command.
		 *
		 * esp_dopoll will always return when
		 * esp->e_state is STATE_FREE, and
		 */
		ASSERT(sp != 0);
		ASSERT(sp == esp->e_slots[slot]);
		limit = sp->cmd_pkt.pkt_time * 1000000;
		if (limit == 0) {
			limit = POLL_TIMEOUT;
		}

		/*
		 * if the cmd disconnected, the first call to esp_dopoll
		 * will return with bus free; we go thru the loop one more
		 * time and wait limit usec for the target to reconnect
		 */
		for (i = 0; i <= POLL_TIMEOUT; i += 100) {

			if ((n = esp_dopoll(esp, limit)) <= 0) {
				IPRINTF("runpoll: timeout on polling\n");
				goto bad;
			}

			/*
			 * If a preemption occurred that caused this
			 * command to actually not start, go around
			 * the loop again. If CFLAG_COMPLETED is set, the
			 * command completed
			 */
			if ((sp->cmd_flags & CFLAG_COMPLETED) ||
			    (sp->cmd_pkt.pkt_state == 0)) {
				break;
			}

			/*
			 * the bus may have gone free because the target
			 * disconnected; go thru the loop again
			 */
			ASSERT(esp->e_state == STATE_FREE);
			if (n == 0) {
				/*
				 * bump i, we have waited limit usecs in
				 * esp_dopoll
				 */
				i += limit - 100;
			}
		}

		if ((sp->cmd_flags & CFLAG_COMPLETED) == 0) {

			if (i > POLL_TIMEOUT) {
				IPRINTF("polled timeout on disc. cmd\n");
				goto bad;
			}

			if (sp->cmd_pkt.pkt_state) {
				/*
				 * don't go thru the loop again; the cmd
				 * was already started
				 */
				IPRINTF("esp_runpoll: cmd started??\n");
				goto bad;
			}
		}
	}

	esp_check_in_transport(esp, NULL);

	/*
	 * blindly restore throttles which is preferable over
	 * leaving throttle hanging at HOLD_THROTTLE and none to clear it
	 */
	esp_set_all_lun_throttles(esp, slot, CLEAR_THROTTLE);


	/*
	 * If we stored up commands to do, start them off now.
	 */
	if ((esp->e_state == STATE_FREE) &&
	    (!(sp->cmd_flags & CFLAG_CMDPROXY))) {
		(void) esp_ustart(esp, NEXTSLOT(slot, esp->e_dslot), NEW_CMD);
	}
exit:
	TRACE_0(TR_FAC_SCSI, TR_ESP_RUNPOLL_END, "esp_runpoll_end");
	return;

bad:
	esplog(esp, CE_WARN, "Polled cmd failed");
#ifdef ESPDEBUG
	esp_printstate(esp, "esp_runpoll: polled cmd failed");
#endif /* ESPDEBUG */

cleanup:
	esp_check_in_transport(esp, NULL);

	esp_set_all_lun_throttles(esp, slot, CLEAR_THROTTLE);

	/*
	 * clean up all traces of this sp because esp_runpoll will return
	 * before esp_reset_recovery() cleans up
	 */
	if (esp->e_slots[slot] == sp) {
		esp->e_slots[slot] = NULL;
	}
	esp_remove_tagged_cmd(esp, sp, slot, NEW_TIMEOUT);
	esp_decrement_ncmds(esp, sp);

	if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {
		sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
	}
	if ((sp->cmd_flags & CFLAG_CMDPROXY) == 0) {
		(void) esp_abort_allcmds(esp);
	}
	goto exit;
}

/*
 * Interrupt Service Section:
 * Poll for command completion (i.e., no interrupts)
 * limit is in usec (and will not be very accurate)
 */
static int
esp_dopoll(struct esp *esp, int limit)
{
	int i, n;

	/*
	 * timeout is not very accurate since we don't know how
	 * long the poll takes
	 * also if the packet gets started fairly late, we may
	 * timeout prematurely
	 * esp_dopoll always returns if e_state transitions to STATE_FREE
	 */
	TRACE_0(TR_FAC_SCSI, TR_ESP_DOPOLL_START, "esp_dopoll_start");

	if (limit == 0) {
		limit = POLL_TIMEOUT;
	}

	for (n = i = 0; i < limit; i += 100) {
		if (INTPENDING(esp)) {
			esp->e_polled_intr = 1;
			n++;
			espsvc(esp);
			if (esp->e_state == STATE_FREE)
				break;
		}
		drv_usecwait(100);
	}

	if (i >= limit && esp->e_state != STATE_FREE) {
		esp_printstate(esp, "polled command timeout");
		n = -1;
	}
	TRACE_1(TR_FAC_SCSI, TR_ESP_DOPOLL_END, "esp_dopoll_end: rval %x", n);
	return (n);
}

static void
esp_makeproxy_cmd(struct esp_cmd *sp, struct scsi_address *ap, int nmsgs, ...)
{
	va_list vap;
	int i;

	ASSERT(nmsgs <= (CDB_GROUP5 - CDB_GROUP0 - 3));
	bzero(sp, ESP_CMD_SIZE);
	sp->cmd_pkt.pkt_address = *ap;
	sp->cmd_pkt.pkt_flags = FLAG_NOINTR|FLAG_NOPARITY;
	sp->cmd_pkt.pkt_scbp = (opaque_t)&sp->cmd_scb[0];
	sp->cmd_pkt.pkt_cdbp = (opaque_t)&sp->cmd_cdb[0];
	sp->cmd_flags = CFLAG_CMDPROXY;
	sp->cmd_cdb[ESP_PROXY_TYPE] = ESP_PROXY_SNDMSG;
	sp->cmd_cdb[ESP_PROXY_RESULT] = FALSE;
	sp->cmd_cdb[ESP_PROXY_DATA] = (char)nmsgs;
	va_start(vap, nmsgs);
	for (i = 0; i < nmsgs; i++) {
		sp->cmd_cdb[ESP_PROXY_DATA + 1 + i] = (uchar_t)va_arg(vap, int);
	}
	va_end(vap);
}

static int
esp_do_proxy_cmd(struct esp *esp, struct esp_cmd *sp,
    struct scsi_address *ap, int slot, char *what)
{
	IPRINTF3("Sending proxy %s message to %d.%d\n", what,
	    ap->a_target, ap->a_lun);
	if (_esp_start(esp, sp, TRAN_BUSY_OK) == TRAN_ACCEPT &&
	    sp->cmd_pkt.pkt_reason == CMD_CMPLT &&
	    sp->cmd_cdb[ESP_PROXY_RESULT] == TRUE) {
		IPRINTF3("Proxy %s succeeded for %d.%d\n", what,
		    ap->a_target, ap->a_lun);
		return (TRUE);
	} else {
		IPRINTF5(
		"Proxy %s failed for %d.%d, result=%x, reason=%x\n", what,
		    ap->a_target, ap->a_lun, sp->cmd_cdb[ESP_PROXY_RESULT],
		    sp->cmd_pkt.pkt_reason);
		if (esp->e_slots[slot] == sp) {
			esp->e_slots[slot] = 0;
		}
		return (FALSE);
	}
}

static void
esp_make_sdtr(struct esp *esp, int msgout_offset, int period, int offset)
{
	uchar_t *p = esp->e_cur_msgout + msgout_offset;
	*p++ = (uchar_t)MSG_EXTENDED;
	*p++ = (uchar_t)3;
	*p++ = (uchar_t)MSG_SYNCHRONOUS;
	*p++ = (uchar_t)period;
	*p++ = (uchar_t)offset;
	esp->e_omsglen = 5 + msgout_offset;
	IPRINTF2("esp_make_sdtr: period = %x, offset = %x\n", period, offset);
}

/*
 * Command watchdog routines
 */
/*ARGSUSED*/
static void
esp_watch(void *arg)
{
	struct esp *esp;
	int	i;
	ushort_t	props_update = 0;

	TRACE_0(TR_FAC_SCSI, TR_ESP_WATCH_START, "esp_watch_start");

#ifdef ESP_PERF
	esp_sample_time += esp_scsi_watchdog_tick;

	if (esp_request_count >= 20000) {
		cmn_err(CE_CONT,
	    "%d reqs/sec (ticks=%d, intrs=%d, reqs=%d, n_cmds=%d, n_disc=%d)\n",
			esp_request_count/esp_sample_time, esp_sample_time,
			esp_intr_count, esp_request_count,
			(esp_ncmds * esp_scsi_watchdog_tick)/esp_sample_time,
			(esp_ndisc * esp_scsi_watchdog_tick)/esp_sample_time);

		for (i = 0; i < MAX_ESPS; i++) {
			if (esp_ncmds_per_esp[i] == 0) {
				continue;
			}
			cmn_err(CE_CONT,
			"esp%d: ncmds = %d\n", i, esp_ncmds_per_esp[i]);
			esp_ncmds_per_esp[i] = 0;
		}

		esp_request_count = esp_sample_time = esp_intr_count =
			esp_ncmds = esp_ndisc = 0;
	}
#endif

	if (esp_watchdog_running == 0) {
		esp_watchdog_running++;
	}

	rw_enter(&esp_global_rwlock, RW_READER);

	for (esp = esp_softc; esp != (struct esp *)NULL; esp = esp->e_next) {

		mutex_enter(ESP_MUTEX);
		EPRINTF2("ncmds=%x, ndisc=%x\n", esp->e_ncmds, esp->e_ndisc);
		if (esp->e_ncmds) {
			esp_watchsubr(esp);

			/*
			 * reset throttle. the throttle may have been
			 * too low if queue full was caused by
			 * another initiator
			 * Only reset throttle if no cmd active in e_slots
			 */
#ifdef ESP_TEST_UNTAGGED
			if (esp_enable_untagged) {
				esp_test_untagged++;
			}
#endif
			for (i = 0; i < N_SLOTS; i++) {
				if ((esp->e_throttle[i] > 0) &&
				    (esp->e_slots[i] == NULL)) {
					esp->e_throttle[i] = CLEAR_THROTTLE;
				}
			}
		}

#ifdef ESP_PERF
		esp_ncmds += esp->e_ncmds;
		esp_ndisc += esp->e_ndisc;
#endif
		if (esp->e_props_update) {
			int i;
			/*
			 * e_mutex will be released and reentered in
			 * esp_props_update().
			 * Hence we save the esp->e_props_update now and
			 * set to 0 indicating that property has been
			 * updated. This will avoid a race condition with
			 * any thread that runs in interrupt context that
			 * attempts to set the e_props_update to non-zero value
			 */
			props_update = esp->e_props_update;
			esp->e_props_update = 0;
			for (i = 0; i < NTARGETS; i++) {
				if (props_update & (1<<i)) {
					esp_update_props(esp, i);
				}
			}
		}

		ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp);
		ESP_WAKEUP_CALLBACK_THREAD(esp);
	}
	rw_exit(&esp_global_rwlock);

again:
	mutex_enter(&esp_global_mutex);
	if (esp_timeout_initted && esp_timeout_id) {
	    esp_timeout_id = timeout(esp_watch, NULL, esp_tick);
	}
	mutex_exit(&esp_global_mutex);
	TRACE_0(TR_FAC_SCSI, TR_ESP_WATCH_END, "esp_watch_end");
}

static void
esp_watchsubr(struct esp *esp)
{
	short slot;
	struct esp_cmd *sp;
	int d = ((esp->e_dslot == 0)? 1 : esp->e_dslot);
	struct t_slots *tag_slots;

#ifdef ESP_TEST_BUS_RESET
	if (esp_btest) {
		esp_btest = 0;
		(void) esp_abort_allcmds(esp);
		return;
	}
#endif /* ESP_TEST_BUS_RESET */

	for (slot = 0; slot < N_SLOTS; slot += d)  {

#ifdef ESP_TEST_TIMEOUT
		if (esp_force_timeout &&
		    (esp->e_tcmds[slot] || esp->e_slots[slot])) {
			esp_force_timeout = 0;
			esp_cmd_timeout(esp, 0, slot);
			return;
		}
#endif /* ESP_TEST_TIMEOUT */
#ifdef ESP_TEST_RESET
		esp_test_reset(esp, slot);
#endif /* ESP_TEST_RESET */
#ifdef ESP_TEST_ABORT
		esp_test_abort(esp, slot);
#endif /* ESP_TEST_ABORT */

		/*
		 * check tagged cmds first
		 */
		tag_slots = esp->e_tagQ[slot];
		if (tag_slots && tag_slots->e_timebase) {
			EPRINTF3(
			"esp_watchsubr: slot %x: tcmds=%x, timeout=%x\n",
			slot, esp->e_tcmds[slot], tag_slots->e_timeout);

			if (esp->e_tcmds[slot] > 0) {
				tag_slots->e_timeout -=
					esp_scsi_watchdog_tick;

				if (tag_slots->e_timeout < 0) {
					if (INTPENDING(esp)) {
						/*
						 * A pending interrupt
						 * defers the sentence
						 * of death.
						 */
						esp->e_polled_intr = 1;
						espsvc(esp);
						break;
					}
					esp_cmd_timeout(esp,
					    esp->e_slots[slot], slot);
					break;
				}
				if ((tag_slots->e_timeout) <=
				    esp_scsi_watchdog_tick) {
					int i;
					IPRINTF1("pending timeout on slot=%x\n",
						slot);
					IPRINTF("draining all tag queues\n");
					for (i = 0; i < N_SLOTS; i += d) {
						if (esp->e_tcmds[i] &&
						    (esp->e_reset_delay[slot/
						    NLUNS_PER_TARGET] == 0)) {
							esp->e_throttle[i] =
								DRAIN_THROTTLE;
						}
					}
				}
			} else {
				/*
				 * reset timeouts since there aren't
				 * any cmds outstanding for this slot
				 */
				tag_slots->e_dups = 0;
				tag_slots->e_timeout = 0;
				tag_slots->e_timebase = 0;
			}
			continue;
		}

		if ((sp = esp->e_slots[slot]) == NULL) {
			continue;
		}

		/*
		 * This command hasn't officially been started yet- drive on
		 */
		if (sp->cmd_pkt.pkt_state == 0 &&
		    esp->e_cur_slot != UNDEFINED && sp != CURRENT_CMD(esp)) {
			continue;
		}

		/*
		 * This command not to be watched- drive on
		 */
		if ((sp->cmd_flags & CFLAG_WATCH) == 0) {
			continue;
		}

		/*
		 * Else, knock	off  the timer if any time left.
		 */
		if (sp->cmd_timeout > 0) {
			sp->cmd_timeout -= esp_scsi_watchdog_tick;
			continue;
		}

		/*
		 * No time left for this command. Last check
		 * before killing it.
		 */
		if (INTPENDING(esp)) {
			/*
			 * A pending interrupt
			 * defers the sentence
			 * of death.
			 */
			esp->e_polled_intr = 1;
			espsvc(esp);
			break;
		}

		esp_cmd_timeout(esp, sp, slot);
	}
}

static void
esp_cmd_timeout(struct esp *esp, struct esp_cmd *sp,
    int slot)
{
	int target = slot / NLUNS_PER_TARGET;
	int lun	   = slot % NLUNS_PER_TARGET;
	int d = ((esp->e_dslot == 0)? 1 : esp->e_dslot);
	int i;

	for (i = 0; i < N_SLOTS; i += d) {
		if (esp->e_throttle[i] == DRAIN_THROTTLE) {
			esp->e_throttle[i] = CLEAR_THROTTLE;
		}
	}


	/*
	 * if no interrupt pending for next second then the current
	 * cmd must be stuck; switch slot and sp to current slot and cmd.
	 * we used to call esp_dopoll() here but this causes more
	 * polled cmd timeout messages. We are really only interested
	 * in whether we are stuck or not
	 */
	if ((esp->e_state != STATE_FREE) &&
	    (esp->e_cur_slot != UNDEFINED)) {
		for (i = 0; (i < 10000) && (INTPENDING(esp) == 0); i++) {
			drv_usecwait(100);
		}

		if ((INTPENDING(esp) == 0) &&
		    (esp->e_slots[esp->e_cur_slot])) {
			IPRINTF2("timeout is not slot %x but %x\n",
			slot, esp->e_cur_slot);
			slot = esp->e_cur_slot;
			sp = esp->e_slots[slot];
			ASSERT(sp);
			target = Tgt(sp);
			lun = Lun(sp);
			ASSERT(sp == CURRENT_CMD(esp));
		}
	}

	/*
	 * dump all we know about this timeout
	 */
	if (sp) {
		if (sp->cmd_flags & CFLAG_CMDDISC) {
			esplog(esp, CE_WARN,
			    "Disconnected command timeout for Target %d.%d",
			    target, lun);
		} else {
			ASSERT(sp == CURRENT_CMD(esp));
			esplog(esp, CE_WARN,
			    "Connected command timeout for Target %d.%d",
			    target, lun);
		}
	} else {
		esplog(esp, CE_WARN,
		    "Disconnected tagged cmds (%d) timeout for Target %d.%d",
		    esp->e_tcmds[slot], target, lun);
	}

#ifdef ESPDEBUG
	if (sp) {
		auto char buf[128];
		uchar_t *cp;
		int i;

		esplog(0, CE_WARN, "State=%s (0x%x), Last State=%s (0x%x)",
		    esp_state_name(esp->e_state), esp->e_state,
		    esp_state_name(esp->e_laststate), esp->e_laststate);

		cp = (uchar_t *)sp->cmd_pkt.pkt_cdbp;
		esplog(0, CE_WARN, "Cmd dump for Target %d Lun %d:",
				Tgt(sp), Lun(sp));
		buf[0] = '\0';
		for (i = 0; i < (int)sp->cmd_cdblen; i++) {
			(void) sprintf(&buf[strlen(buf)], " 0x%x", *cp++);
			if (strlen(buf) > 124)
				break;
		}
		esplog(0, CE_WARN, "cdb=[%s ]", buf);
		if (sp->cmd_pkt.pkt_state & STATE_GOT_STATUS)
			esplog(esp, CE_WARN,
			    "Status=0x%x", sp->cmd_pkt.pkt_scbp[0]);
	}

	if (INFORMATIVE) {
		int dma_enabled = 0;
		volatile struct dmaga *dmar = esp->e_dma;

		if (sp == 0 || sp->cmd_flags & CFLAG_CMDDISC) {
			esp_printstate(esp, "Disconnected cmd timeout");
		} else {
			esp_printstate(esp, "Current cmd timeout");
		}

		/*
		 * disable DVMA to avoid a timeout on SS1
		 */
		if (dmar->dmaga_csr & DMAGA_ENDVMA) {
			while (dmar->dmaga_csr & DMAGA_REQPEND)
				;
			dmar->dmaga_csr &= ~DMAGA_ENDVMA;
			dma_enabled++;
		}
		if (esp->e_options & ESP_OPT_MASK_OFF_STAT) {
			esp->e_stat = esp->e_reg->esp_stat & ~ESP_STAT_RES;
		} else {
			esp->e_stat = esp->e_reg->esp_stat;
		}
		if (dma_enabled) {
			dmar->dmaga_csr |= DMAGA_ENDVMA;
		}
	}
#endif	/* ESPDEBUG */

	/*
	 * Current command timeout appears to relate often to noisy SCSI
	 * in synchronous mode.
	 */
	if (sp && ((sp->cmd_flags & CFLAG_CMDDISC) == 0)) {
		esp_sync_backoff(esp, sp, slot);
	}

	if (sp) {
		if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {
			sp->cmd_pkt.pkt_reason = CMD_TIMEOUT;
		}
		sp->cmd_pkt.pkt_statistics |= STAT_TIMEOUT | STAT_ABORTED;
	} else if (esp->e_tcmds[slot] && esp->e_tagQ[slot]) {
		int tag;

		for (tag = 0; tag < NTAGS; tag++) {
			sp = esp->e_tagQ[slot]->t_slot[tag];
			if (sp) {
				if (sp->cmd_pkt.pkt_reason == CMD_CMPLT)
					sp->cmd_pkt.pkt_reason = CMD_TIMEOUT;

				sp->cmd_pkt.pkt_statistics |=
				    STAT_TIMEOUT | STAT_ABORTED;
			}
		}
		sp = 0;
	}

	/*
	 * clear reset delay to prevent a deadlock
	 */
	esp->e_reset_delay[target] = 0;

	if (esp_abort_cmd(esp, sp, slot) == ACTION_SEARCH) {
		(void) esp_ustart(esp, 0, NEW_CMD);
	}
}

static void
esp_sync_backoff(struct esp *esp, struct esp_cmd *sp,
    int slot)
{
	char phase = esp->e_reg->esp_stat & ESP_PHASE_MASK;
	ushort_t state = esp->e_state;
	uchar_t tgt = slot / NLUNS_PER_TARGET;
	uchar_t lun = slot % NLUNS_PER_TARGET;

#ifdef ESPDEBUG
	if (esp_no_sync_backoff) {
		return;
	}
#endif
	/*
	 * Only process data phase hangs.  Also, ignore any data phase
	 * hangs caused by request sense cmds as it's possible they could
	 * be caused by target reverting to asynch.
	 *
	 * Allow sync backoff for parity errors detected and called from
	 * esp_finish.
	 */
	IPRINTF3("esp_sync_backoff: target %d: state=%x, phase=%x\n",
	    tgt, state, phase);

	if (sp && ((sp->cmd_pkt.pkt_statistics & STAT_PERR) == 0)) {
		if (state != ACTS_DATA && state != ACTS_DATA_DONE) {
			IPRINTF2("Target %d.%d hang state not in data phase\n",
				tgt, lun);
			return;
		} else if (
		    phase != ESP_PHASE_DATA_IN && phase != ESP_PHASE_DATA_OUT) {
			IPRINTF2("Target %d.%d hang bus not in data phase\n",
				tgt, lun);
			return;
		} else if (
		    (uchar_t)*(sp->cmd_pkt.pkt_cdbp) == SCMD_REQUEST_SENSE) {
			IPRINTF2("Target %d.%d ignoring request sense hang\n",
				tgt, lun);
			return;
		}
	}

	/*
	 * First we reduce xfer rate 100% and always enable slow cable mode
	 * and if that fails we revert to async with slow cable mode
	 */
	if (esp->e_offset[tgt] != 0) {
#ifdef ESPDEBUG
		uint_t regval, maxreg;
		regval = esp->e_period[tgt];
		maxreg = MAX_SYNC(esp);
		IPRINTF4("regval %d maxreg %d backoff %d for tgt %d\n",
		    regval, maxreg, esp->e_backoff[tgt], tgt);
		/*
		 * Compute sync transfer limits for later compensation.
		 */
		IPRINTF3("Target %d.%d back off using %s params\n", tgt,
			lun, ((esp->e_options & ESP_OPT_FAS)? "FAS" : "ESP"));
#endif
		if (esp->e_backoff[tgt]) {
			esp->e_period[tgt] = 0;
			esp->e_offset[tgt] = 0;
			esplog(esp, CE_WARN,
			    "Target %d.%d reverting to async. mode",
			    tgt, lun);
			(esp->e_backoff[tgt])++;
		} else {
			esplog(esp, CE_WARN,
			    "Target %d.%d reducing sync. transfer rate",
			    tgt, lun);
			/* increase period by 100% */
			esp->e_neg_period[tgt] *= 2;
			(esp->e_backoff[tgt])++;
		}

		/*
		 * Paranoia: Force sync. renegotiate
		 */
		esp->e_sync_known &= ~(1<<tgt);

	}

	if (((esp->e_options & ESP_OPT_FAS) == 0) &&
	    ((esp->e_espconf & ESP_CONF_SLOWMODE) == 0)) {
		/*
		 * always enable slow cable mode
		 */
		esp->e_espconf |= ESP_CONF_SLOWMODE;
		esp->e_reg->esp_conf |= ESP_CONF_SLOWMODE;
		esplog(esp, CE_WARN, "Reverting to slow SCSI cable mode");
	}
}

/*
 * Abort routines
 */
static int
esp_abort_curcmd(struct esp *esp)
{
	if (esp->e_cur_slot != UNDEFINED) {
		return (esp_abort_cmd(esp, CURRENT_CMD(esp), esp->e_cur_slot));
	} else {
		return (ACTION_RETURN);
	}
}

static int
esp_abort_cmd(struct esp *esp, struct esp_cmd *sp, int slot)
{
	struct scsi_address ap;

	ap.a_hba_tran = esp->e_tran;
	ap.a_target = slot / NLUNS_PER_TARGET;
	ap.a_lun    = slot % NLUNS_PER_TARGET;

	if (sp) {
		ASSERT(ap.a_target == Tgt(sp));
		ASSERT(ap.a_lun == Lun(sp));
	}

	/*
	 * attempting to abort a connected cmd is usually fruitless, so
	 * only try disconnected cmds (sp == NULL indicates a bunch of
	 * tagged cmds are disconnected and timed out)
	 * a reset is preferable over an abort (see 1161701)
	 */
	if ((sp == NULL) || (sp->cmd_flags & CFLAG_CMDDISC)) {
		IPRINTF2("attempting to reset target %d.%d\n",
		    ap.a_target, ap.a_lun);
		if (_esp_reset(&ap, RESET_TARGET)) {
			return (ACTION_RETURN);
		}
	}

	/*
	 * if the target won't listen, then a retry is useless
	 * there is also the possibility that the cmd still completed while
	 * we were trying to reset and the target driver may have done a
	 * device reset which has blown away this sp.
	 * well, we've tried, now pull the chain
	 */
	IPRINTF("aborting all cmds by bus reset\n");
	return (esp_abort_allcmds(esp));
}

static int
esp_abort_allcmds(struct esp *esp)
{
	/*
	 * Last resort: Reset everything.
	 * wait here for the reset recovery; this makes nested error
	 * recovery more manageable
	 */
	(void) esp_reset_bus(esp);
	(void) esp_dopoll(esp, SHORT_POLL_TIMEOUT);
	return (ACTION_SEARCH);
}

/*
 * auto request sense handling:
 * for arq, we create a pkt per slot and save it in e_arq_pkt list. the
 * original pkt is always saved in e_save_pkt list. Only one arq
 * can be in progress at any point in time
 */
static int
esp_create_arq_pkt(struct esp *esp, struct scsi_address *ap, int create)
{
	/*
	 * Allocate a request sense packet using get_pktiopb
	 */
	struct esp_cmd	*rqcmd;
	struct scsi_pkt	*rqpkt;
	struct buf	*bp;
	int slot = ap->a_target * NLUNS_PER_TARGET | ap->a_lun;
	int rval = 0;

	if (create == 0) {
		/*
		 * if there is still a pkt saved or no rqpkt
		 * then we cannot deallocate or there is nothing to do
		 */
		if (esp->e_save_pkt[slot]) {
			rval = -1;
		} else if ((rqcmd = esp->e_arq_pkt[slot]) != 0) {
			rqpkt = &rqcmd->cmd_pkt;
			bp = (struct buf *)rqpkt->pkt_private;
			scsi_destroy_pkt(rqpkt);
			scsi_free_consistent_buf(bp);
			esp->e_rq_sense_data[slot] = 0;
			esp->e_arq_pkt[slot] = 0;
		}
	} else {
		/*
		 * it would be nicer if we could allow the target driver
		 * to specify the size but this is easier and OK for most
		 * drivers to use SENSE_LENGTH
		 * Allocate a request sense packet.
		 */

		/*
		 * if one exists, don't create another
		 */
		if (esp->e_arq_pkt[slot] != 0) {
			return (rval);
		}
		bp = scsi_alloc_consistent_buf(ap, (struct buf *)NULL,
		    SENSE_LENGTH, B_READ, SLEEP_FUNC, NULL);
		rqpkt = scsi_init_pkt(ap, (struct scsi_pkt *)NULL,
		    bp, CDB_GROUP0, 1, 0, PKT_CONSISTENT, SLEEP_FUNC, NULL);
		rqcmd = (struct esp_cmd *)rqpkt->pkt_ha_private;
		esp->e_rq_sense_data[slot] =
		    (struct scsi_extended_sense *)bp->b_un.b_addr;
		rqpkt->pkt_private = (opaque_t)bp;

		RQ_MAKECOM_G0(rqpkt,
		    FLAG_NOPARITY | FLAG_SENSING | FLAG_HEAD | FLAG_NODISCON,
		    (char)SCMD_REQUEST_SENSE, 0, (char)SENSE_LENGTH);
		rqcmd->cmd_flags |= CFLAG_CMDARQ;
		esp->e_arq_pkt[slot] = rqcmd;
		/*
		 * we need a function ptr here so abort/reset can
		 * delay callbacks; esp_call_pkt_comp() calls
		 * esp_complete_arq_pkt() directly without releasing the lock
		 */
#ifndef __lock_lint
		rqpkt->pkt_comp =
			(void (*)(struct scsi_pkt *))esp_complete_arq_pkt;
#endif
	}
	return (rval);
}

/*
 * complete an arq packet by copying over transport info and the actual
 * request sense data; called with mutex held from esp_call_pkt_comp()
 */
static void
esp_complete_arq_pkt(struct esp *esp, struct esp_cmd *sp, int slot)
{
	struct esp_cmd *ssp;
	struct scsi_arq_status *arqstat;

	EPRINTF1("completing arq pkt sp=0x%p\n", (void *)sp);
	ssp = esp->e_save_pkt[slot];
	ASSERT(sp == esp->e_arq_pkt[slot]);

	esp_check_in_transport(esp, NULL);

	if (sp && ssp) {
		arqstat = (struct scsi_arq_status *)(ssp->cmd_pkt.pkt_scbp);
		arqstat->sts_rqpkt_status = *((struct scsi_status *)
			(sp->cmd_pkt.pkt_scbp));
		arqstat->sts_rqpkt_reason = sp->cmd_pkt.pkt_reason;
		arqstat->sts_rqpkt_state  = sp->cmd_pkt.pkt_state;
		arqstat->sts_rqpkt_statistics = sp->cmd_pkt.pkt_statistics;
		arqstat->sts_rqpkt_resid  = sp->cmd_pkt.pkt_resid;
		arqstat->sts_sensedata = *(esp->e_rq_sense_data[slot]);
		ssp->cmd_pkt.pkt_state |= STATE_ARQ_DONE;
		esp->e_save_pkt[slot] = NULL;
	}

	/*
	 * now we can  finally complete the original packet
	 */
	if (ssp) {
		esp_check_in_transport(esp, ssp);
		esp_call_pkt_comp(esp, ssp);
	}
}

/*
 * start an arq packet
 */
static int
esp_start_arq_pkt(struct esp *esp, struct esp_cmd *sp)
{
	struct esp_cmd *arqsp;
	int slot = Tgt(sp) * NLUNS_PER_TARGET | Lun(sp);

	arqsp = esp->e_arq_pkt[slot];

	esp_check_in_transport(esp, sp);

	if (arqsp == NULL || arqsp == sp) {
		IPRINTF("no arq packet or cannot arq on arq pkt\n");
		return (-1);
	}

	EPRINTF1("starting arq for slot 0x%p\n", (void *)sp);
	bzero(esp->e_rq_sense_data[slot], sizeof (struct scsi_extended_sense));
	EPRINTF3("slot=%x, arqsp=0x%p, save_pkt=0x%p\n", slot, (void *)arqsp,
		(void *)esp->e_arq_pkt[slot]);

	if (esp->e_save_pkt[slot] != NULL) {
		if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {
			sp->cmd_pkt.pkt_reason = CMD_TRAN_ERR;
		}
		return (-1);
	}

	esp->e_save_pkt[slot] = sp;

	/*
	 * copy the timeout from the original packet by lack of a better
	 * value
	 * we could take the residue of the timeout but that could cause
	 * premature timeouts perhaps
	 */
	arqsp->cmd_pkt.pkt_time = sp->cmd_pkt.pkt_time;
	arqsp->cmd_flags &= ~CFLAG_TRANFLAG;

	/*
	 * set throttle to full throttle so the request sense
	 * can be submitted even if there was a queue full condition
	 */
	if (esp->e_throttle[slot] != HOLD_THROTTLE) {
		esp_set_throttles(esp, slot, 1, CLEAR_THROTTLE);
	}

	if (_esp_start(esp, arqsp, TRAN_BUSY_OK) != TRAN_ACCEPT) {
		esp->e_save_pkt[slot] = 0;
		IPRINTF("arq packet has not been accepted\n");
		return (-1);
	}
	return (0);
}

/*
 * esp_abort: abort a current cmd or all cmds for a target
 */
static int
esp_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct esp *esp = ADDR2ESP(ap);
	int rval;

	IPRINTF2("esp_abort: target %d.%d\n", ap->a_target, ap->a_lun);

	mutex_enter(ESP_MUTEX);
	rval =	_esp_abort(ap, pkt);
	ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp);
	ESP_WAKEUP_CALLBACK_THREAD(esp);

	return (rval);
}

/*
 * _esp_abort() assumes that we already have the mutex
 * during the abort, we hold the mutex and prevent callbacks by setting
 * completion pointer to NULL. this will also avoid that a target driver
 * attempts to do a scsi_abort/reset while we are aborting.
 * because the completion pointer is NULL  we can still update the
 * packet after completion
 * the throttle for this slot is cleared either by esp_abort_connected_cmd
 * or esp_runpoll which prevents new cmds from starting while aborting
 */
static int
_esp_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct esp *esp = ADDR2ESP(ap);
	struct esp_cmd *sp = (struct esp_cmd *)pkt->pkt_ha_private;
	int rval = FALSE;
	short slot = (ap->a_target * NLUNS_PER_TARGET) | ap->a_lun;
	struct esp_cmd *cur_sp = esp->e_slots[slot];
	void	(*cur_savec)(), (*sp_savec)();
	int	cur_tagged_flag, sp_tagged_flag;
	int	abort_msg;
	int	abort_disconnected = 0;
	short	throttles[1];

	/*
	 *   If no specific command was passed, all cmds here will be aborted
	 *   If a specific command was passed as an argument (to be aborted)
	 *   only the specified command will be aborted
	 */
	ASSERT(mutex_owned(ESP_MUTEX));
	IPRINTF4("esp_abort for slot %x, sp=0x%p, pkt_flags=%x, cur_sp=0x%p\n",
	    slot, (void *)sp, (sp? sp->cmd_pkt.pkt_flags : 0), (void *)cur_sp);

	esp_check_in_transport(esp, NULL);

	if (cur_sp) {
		/*
		 * prevent completion on current cmd
		 */
		cur_savec = cur_sp->cmd_pkt.pkt_comp;
		cur_sp->cmd_pkt.pkt_comp = NULL;
		cur_tagged_flag = (cur_sp->cmd_pkt.pkt_flags & FLAG_TAGMASK);
	}

	esp_save_throttles(esp, slot, 1, throttles);
	esp_set_throttles(esp, slot, 1, HOLD_THROTTLE);

	if (sp) {
		IPRINTF3("aborting one command 0x%p for %d.%d\n",
		    (void *)sp, ap->a_target, ap->a_lun);
		rval = esp_remove_readyQ(esp, sp, slot);
		esp_check_in_transport(esp, NULL);
		if (rval) {
			IPRINTF("aborted one ready cmd\n");
			MARK_PKT(sp, CMD_ABORTED, STAT_ABORTED);
			esp_decrement_ncmds(esp, sp);
			if (cur_sp) {
				cur_sp->cmd_pkt.pkt_comp = cur_savec;
			}
			esp_call_pkt_comp(esp, sp);
			goto exit;
		}

		if ((sp != cur_sp) && (TAGGED(ap->a_target) &&
		    (sp != esp->e_tagQ[slot]->t_slot[sp->cmd_tag[1]]))) {
			IPRINTF("cmd doesn't exist here\n");
			if (cur_sp) {
				cur_sp->cmd_pkt.pkt_comp = cur_savec;
			}
			rval = TRUE;
			goto exit;
		}

		/*
		 * the cmd exists here. is it connected or disconnected?
		 * if connected but still selecting then can't abort now.
		 * the selection may be preempted and we may then attempt
		 * to abort a pkt that is yet issued to the target. On
		 * completion of the successful proxy msg, the cmd may
		 * be submitted while we think it has been aborted
		 *
		 * prevent completion on this cmd
		 */
		sp_tagged_flag = (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK);
		abort_msg = (sp_tagged_flag? MSG_ABORT_TAG : MSG_ABORT);
		sp_savec = sp->cmd_pkt.pkt_comp;
		sp->cmd_pkt.pkt_comp = NULL;

		/* connected but not selecting? */
		if ((sp == cur_sp) && (esp->e_state != STATE_FREE) &&
		    (esp->e_cur_slot == slot) && (sp->cmd_pkt.pkt_state)) {
			rval = esp_abort_connected_cmd(esp, sp, abort_msg);
		}
		esp_check_in_transport(esp, NULL);

		/* disconnected? */
		if ((rval == 0) &&
		    ((sp->cmd_flags & CFLAG_COMPLETED) == 0) &&
		    (sp->cmd_flags & CFLAG_CMDDISC)) {
			rval = esp_abort_disconnected_cmd(esp, ap, sp,
				abort_msg, slot);
			abort_disconnected++;
		}
		esp_check_in_transport(esp, NULL);

		sp->cmd_pkt.pkt_comp = sp_savec;
		if (rval) {
			if (sp != esp->e_save_pkt[slot]) {
				sp->cmd_flags |= CFLAG_COMPLETED;
			}
			MARK_PKT(sp, CMD_ABORTED, STAT_ABORTED);
		}
	} else {
		IPRINTF2("aborting all commands for %d.%d\n",
		    ap->a_target, ap->a_lun);
		abort_msg = MSG_ABORT;

		/* active and not selecting ? */
		if (cur_sp && (esp->e_state != STATE_FREE) &&
		    (esp->e_cur_slot == slot) &&
		    cur_sp->cmd_pkt.pkt_state) {
			rval = esp_abort_connected_cmd(esp, cur_sp, abort_msg);
		}
		esp_check_in_transport(esp, NULL);
		if (rval == 0) {
			rval = esp_abort_disconnected_cmd(esp, ap,
				    NULL, abort_msg, slot);
			abort_disconnected++;
		}
	}

	/*
	 * complete the sp passed as 2nd arg now otherwise the
	 * the check_in_transport will fail because the cmd has been
	 * completed but not yet removed from the queues
	 */
	if (sp && (sp != cur_sp) && (sp->cmd_flags & CFLAG_COMPLETED)) {
		sp->cmd_flags &= ~CFLAG_COMPLETED;
		esp_remove_tagged_cmd(esp, sp, slot, NEW_TIMEOUT);
		esp_decrement_ncmds(esp, sp);
		esp_call_pkt_comp(esp, sp);
	}

	esp_check_in_transport(esp, NULL);

	if ((rval == FALSE) && cur_sp && !cur_tagged_flag &&
	    ((cur_sp->cmd_flags & CFLAG_COMPLETED) == 0) &&
	    (esp->e_slots[slot] != cur_sp)) {
		/*
		 * a proxy cmd zapped the active slot for non-tagged tgts.
		 * regardless whether it actually aborted, it has to be
		 * completed here; otherwise it is lost forever.
		 */
		if (cur_sp != esp->e_save_pkt[slot]) {
			cur_sp->cmd_flags |= CFLAG_COMPLETED;
		}
		MARK_PKT(cur_sp, CMD_ABORTED, STAT_ABORTED);
	}

	/* complete the current sp */
	if (cur_sp) {
		cur_sp->cmd_pkt.pkt_comp = cur_savec;

		/* is this packet still on the lists but not completed? */
		if ((cur_sp != esp->e_slots[slot]) &&
		    ((cur_sp->cmd_flags & CFLAG_COMPLETED) == 0) &&
		    (cur_sp != esp->e_save_pkt[slot])) {

			if (!cur_tagged_flag ||
			    (cur_tagged_flag && esp->e_tagQ[slot] &&
			    (cur_sp != esp->e_tagQ[slot]->
					t_slot[cur_sp->cmd_tag[1]]))) {
				cur_sp->cmd_flags |= CFLAG_COMPLETED;
				MARK_PKT(cur_sp, CMD_ABORTED, STAT_ABORTED);
			}
		}

		if (cur_sp->cmd_flags & CFLAG_COMPLETED) {
			/*
			 * make sure it is not on the ready list
			 */
			(void) esp_remove_readyQ(esp, cur_sp, slot);
			esp_remove_tagged_cmd(esp, cur_sp, slot, NEW_TIMEOUT);
			cur_sp->cmd_flags &= ~CFLAG_COMPLETED;
			esp_decrement_ncmds(esp, cur_sp);
			esp_call_pkt_comp(esp, cur_sp);
		}
	}
	esp_check_in_transport(esp, NULL);


	/* clean up all cmds for this slot */
	if (rval && (abort_msg == MSG_ABORT)) {
		/*
		 * mark all commands here as aborted
		 * abort msg has been accepted, now cleanup queues;
		 */
		esp_mark_packets(esp, slot, CMD_ABORTED, STAT_ABORTED);
		esp_flush_tagQ(esp, slot);
		esp_flush_readyQ(esp, slot);
	}

exit:
	esp_check_in_transport(esp, NULL);
	esp_restore_throttles(esp, slot, 1, throttles);

	if (esp->e_state == STATE_FREE) {
		(void) esp_ustart(esp, NEXTSLOT(slot, esp->e_dslot), NEW_CMD);
	}


#ifdef ESPDEBUG
	if (rval && esp_test_stop)
		debug_enter("abort done");
#endif
	ASSERT(mutex_owned(ESP_MUTEX));
	return (rval);
}

/*
 * mark all packets with new reason and update statistics
 */
static void
esp_mark_packets(struct esp *esp, int slot, uchar_t reason, uint_t stat)
{
	struct esp_cmd *sp;

	if ((sp = esp->e_slots[slot]) != 0) {
		MARK_PKT(sp, reason, stat);
	}
	sp = esp->e_readyf[slot];
	while (sp != 0) {
		MARK_PKT(sp, reason, STAT_ABORTED);
		sp = sp->cmd_forw;
	}
	if (esp->e_tcmds[slot]) {
		int n = 0;
		int tag;

		for (tag = 0; tag < NTAGS; tag++) {
			if ((sp = esp->e_tagQ[slot]->t_slot[tag]) != 0) {
				MARK_PKT(sp, reason, stat);
				n++;
			}
		}
		ASSERT(esp->e_tcmds[slot] == n);
	}
}

/*
 * delete specified packet from the ready queue
 */
static int
esp_remove_readyQ(struct esp *esp, struct esp_cmd *sp, int slot)
{
	struct esp_cmd *ssp, *psp;

	/*
	 * command has not been started yet and is still in the ready queue
	 */

	if (sp == 0 || (esp->e_readyf[slot] == NULL)) {
		return (FALSE);
	}

	ASSERT(esp->e_ncmds > 0);
	IPRINTF3("aborting sp=0x%p %d.%d (not yet started)\n",
		(void *)sp, Tgt(sp), Lun(sp));

	/*
	 * find packet on the ready queue and remove it
	 */
	for (psp = NULL, ssp = esp->e_readyf[slot]; ssp != NULL;
	    psp = ssp, ssp = ssp->cmd_forw) {
		if (ssp == sp) {
			if (esp->e_readyf[slot] == sp) {
				esp->e_readyf[slot] = sp->cmd_forw;
			} else {
				psp->cmd_forw = sp->cmd_forw;
			}
			if (esp->e_readyb[slot] == sp) {
				esp->e_readyb[slot] = psp;
			}
			return (TRUE);
		}
	}
	return (FALSE);
}

/*
 * cleanup cmds in ready queue
 */
static void
esp_flush_readyQ(struct esp *esp, int slot)
{
	struct esp_cmd *sp, *nsp;

	if (esp->e_readyf[slot] == 0) {
		return;
	}

	esp_check_in_transport(esp, NULL);

	IPRINTF1("flushing ready queue, slot=%x\n", slot);
	ASSERT(esp->e_ncmds > 0);

	sp = esp->e_readyf[slot];
	esp->e_readyf[slot] = esp->e_readyb[slot] = (struct esp_cmd *)NULL;

	while (sp != 0) {
		/*
		 * save the forward pointer before calling the completion
		 * routine
		 */
		nsp = sp->cmd_forw;
		ASSERT((sp->cmd_flags & CFLAG_FREE) == 0);
		ASSERT(Tgt(sp) == slot/NLUNS_PER_TARGET);
		esp_decrement_ncmds(esp, sp);
		esp_call_pkt_comp(esp, sp);
		sp = nsp;
	}
	EPRINTF2("ncmds = %x, ndisc=%x\n", esp->e_ncmds, esp->e_ndisc);
}

/*
 * cleanup the tag queue
 * preserve some order by starting with the oldest tag
 */
static void
esp_flush_tagQ(struct esp *esp, int slot)
{
	int tag, starttag;
	struct esp_cmd *sp;
	struct t_slots *tagque = esp->e_tagQ[slot];

	esp_check_in_transport(esp, NULL);

	if (esp->e_tcmds[slot] == 0) {
		/*
		 * is there a non-tagged cmd?
		 */
		if ((sp = esp->e_slots[slot]) != 0) {
			ASSERT(Tgt(sp) == slot/NLUNS_PER_TARGET);
			esp_flush_cmd(esp, sp, 0, 0);
		}
		return;
	}

	ASSERT(esp->e_ncmds > 0);
	IPRINTF2("flushing entire tag queue, slot=%x, tcmds=%x\n",
	    slot, esp->e_tcmds[slot]);

#ifdef ESPDEBUG
	{
		int n = 0;
		for (tag = 0; tag < NTAGS; tag++) {
			if ((sp = tagque->t_slot[tag]) != 0) {
				n++;
				ASSERT((sp->cmd_flags & CFLAG_FREE) == 0);
				if (sp->cmd_pkt.pkt_reason == CMD_CMPLT) {
					if ((sp->cmd_flags & CFLAG_FINISHED) ==
					    0) {
						debug_enter("esp_flush_tagQ");
					}
				}
			}
		}
		ASSERT(esp->e_tcmds[slot] == n);
	}
#endif
	tag = starttag = esp->e_tagQ[slot]->e_tags;

	do {
		if ((sp = tagque->t_slot[tag]) != 0) {
			esp_flush_cmd(esp, sp, 0, 0);
		}
		tag = (tag + 1) % NTAGS;
	} while (tag != starttag);

	ASSERT(esp->e_tcmds[slot] == 0);
	EPRINTF2("ncmds = %x, ndisc=%x\n", esp->e_ncmds, esp->e_ndisc);

	esp_check_in_transport(esp, NULL);
}

/*
 * cleanup one active command
 */
static void
esp_flush_cmd(struct esp *esp, struct esp_cmd *sp, uchar_t reason,
    uint_t stat)
{
	short slot = (Tgt(sp) * NLUNS_PER_TARGET) | Lun(sp);

	ASSERT(esp->e_ncmds > 0);
	ASSERT((sp->cmd_flags & CFLAG_FREE) == 0);
	if (sp->cmd_pkt.pkt_flags & FLAG_TAGMASK) {
		ASSERT(sp == esp->e_tagQ[slot]->t_slot[sp->cmd_tag[1]]);
		esp_remove_tagged_cmd(esp, sp, slot, NEW_TIMEOUT);
	}

	if (esp->e_slots[slot] == sp) {
		esp->e_slots[slot] = (struct esp_cmd *)NULL;
	}
	esp_decrement_ncmds(esp, sp);
	COMPLETE_PKT(sp, reason, stat);
	EPRINTF2("ncmds = %x, ndisc=%x\n", esp->e_ncmds, esp->e_ndisc);
}

/*
 * decrement e_ncmds and e_disc for this cmd before completing
 * during nested error recovery, our counts may get somewhat inaccurate;
 * therefore, ensure that both counts remain >= 0
 */
static void
esp_decrement_ncmds(struct esp *esp, struct esp_cmd *sp)
{
	ASSERT((sp->cmd_flags & CFLAG_FREE) == 0);
	if ((sp->cmd_flags & CFLAG_FINISHED) == 0) {
		if (esp->e_ncmds > 0) {
			esp->e_ncmds--;
		}
		if ((sp->cmd_flags & CFLAG_CMDDISC) &&
		    (esp->e_ndisc > 0)) {
			esp->e_ndisc--;
		}
		sp->cmd_flags = (sp->cmd_flags | CFLAG_FINISHED) &
					~CFLAG_CMDDISC;
	}
	ASSERT((esp->e_ncmds >= 0) && (esp->e_ndisc >= 0));
	ASSERT(esp->e_ncmds >= esp->e_ndisc);
}

/*
 * assert ATN to force the target to go to msg out phase.
 * need to disable DVMA to avoid watchdogs and bus timeouts on sun4c
 */
static void
esp_assert_atn(struct esp *esp)
{
	volatile struct dmaga *dmar = esp->e_dma;

	if (dmar->dmaga_csr & DMAGA_ENDVMA) {
		while (dmar->dmaga_csr & DMAGA_REQPEND)
			;
		dmar->dmaga_csr &= ~DMAGA_ENDVMA;
		Esp_cmd(esp, CMD_SET_ATN);
		dmar->dmaga_csr |= DMAGA_ENDVMA;
	} else {
		Esp_cmd(esp, CMD_SET_ATN);
	}
}

/*
 * abort a connected command by sending an abort msg; hold off on
 * starting new cmds by setting throttles to HOLD_THROTTLE
 */
static int
esp_abort_connected_cmd(struct esp *esp, struct esp_cmd *sp, uchar_t msg)
{
	int rval = FALSE;
	int flags = sp->cmd_pkt.pkt_flags;

	/*
	 * if reset delay active we cannot  access the target
	 */
	if (esp->e_reset_delay[Tgt(sp)]) {
		return (rval);
	}

	IPRINTF3("Sending abort message %s to connected %d.%d\n",
	    scsi_mname(msg), Tgt(sp), Lun(sp));

	esp->e_abort = 0;
	esp->e_omsglen = 1;
	esp->e_cur_msgout[0] = msg;
	sp->cmd_pkt.pkt_flags |= FLAG_NOINTR;
	esp_assert_atn(esp);

	(void) esp_dopoll(esp, SHORT_POLL_TIMEOUT);

	/*
	 * now check if the msg was taken
	 * e_abort is set in esp_handle_msg_out_done when the abort
	 * msg has actually gone out (ie. msg out phase occurred
	 */
	if (esp->e_abort && (sp->cmd_flags & CFLAG_COMPLETED)) {
		IPRINTF2("target %d.%d aborted\n",
			Tgt(sp), Lun(sp));
		rval = TRUE;
	} else {
		IPRINTF2("target %d.%d did not abort\n",
			Tgt(sp), Lun(sp));
	}
	sp->cmd_pkt.pkt_flags = flags;
	esp->e_omsglen = 0;
	return (rval);
}


/*
 * abort a disconnected command; if it is a tagged command, we need
 * to include the tag
 */
static int
esp_abort_disconnected_cmd(struct esp *esp, struct scsi_address *ap,
    struct esp_cmd *sp, uchar_t msg, int slot)
{
	struct esp_cmd	*proxy_cmdp;
	int		target = ap->a_target;
	int		rval;

	/*
	 * if reset delay is active, we cannot start a selection
	 * and there shouldn't be a cmd outstanding
	 */
	if (esp->e_reset_delay[target] != 0) {
		return (FALSE);
	}

	IPRINTF1("aborting disconnected tagged cmd(s) with %s\n",
		scsi_mname(msg));
	proxy_cmdp = kmem_alloc(ESP_CMD_SIZE, KM_SLEEP);
	if (TAGGED(target) && (msg == MSG_ABORT)) {
		esp_makeproxy_cmd(proxy_cmdp, ap, 1, msg);
	} else if (sp) {
		if (TAGGED(target) && (msg == MSG_ABORT_TAG)) {
			int tag = sp->cmd_tag[1];
			ASSERT(sp == esp->e_tagQ[slot]->t_slot[tag]);
			esp_makeproxy_cmd(proxy_cmdp, ap, 3,
			    MSG_SIMPLE_QTAG, tag, msg);
		} else if (NOTAG(target) && (msg == MSG_ABORT)) {
			esp_makeproxy_cmd(proxy_cmdp, ap, 1, msg);
		} else {
			rval = FALSE;
			goto out;
		}
	} else {
		esp_makeproxy_cmd(proxy_cmdp, ap, 1, msg);
	}

	rval = esp_do_proxy_cmd(esp, proxy_cmdp, ap, slot, scsi_mname(msg));
out:	kmem_free(proxy_cmdp, ESP_CMD_SIZE);
	return (rval);
}

/*
 * set throttles for all luns of this target
 */
static void
esp_set_throttles(struct esp *esp, int slot, int n, int what)
{
	int i;

	ASSERT((n == 1) || (n == N_SLOTS) || (n == NLUNS_PER_TARGET));
	ASSERT((slot + n) <= N_SLOTS);
	if (n == NLUNS_PER_TARGET) {
		slot &= ~(NLUNS_PER_TARGET - 1);
	}
	for (i = slot; i < (slot + n); i++) {
		if (esp->e_reset_delay[i/NLUNS_PER_TARGET] == 0) {
			esp->e_throttle[i] = what;
		} else {
			ASSERT(esp->e_throttle[i] == HOLD_THROTTLE);
		}
	}
}

static void
esp_set_all_lun_throttles(struct esp *esp, int slot, int what)
{
	/*
	 * esp_set_throttles adjusts slot to starting at LUN0
	 */
	esp_set_throttles(esp, slot, NLUNS_PER_TARGET, what);
}


/*
 * restore throttle unless reset delay in progress
 */
static void
esp_restore_throttles(struct esp *esp, int slot, int n, short *throttles)
{
	int i;

	ASSERT((n == 1) || (n == N_SLOTS) || (n == NLUNS_PER_TARGET));
	ASSERT((slot + n) <= N_SLOTS);
	if (n == NLUNS_PER_TARGET) {
		slot &= ~(NLUNS_PER_TARGET - 1);
	}
	for (i = slot; i < (slot + n); i++) {
		if (esp->e_reset_delay[i/NLUNS_PER_TARGET] == 0) {
			if (throttles[i - slot] < HOLD_THROTTLE) {
				esp->e_throttle[i] = CLEAR_THROTTLE;
			} else {
				esp->e_throttle[i] = throttles[i - slot];
			}
		} else {
			ASSERT(esp->e_throttle[i] == HOLD_THROTTLE);
		}
	}
}

/*
 * save throttles
 */
static void
esp_save_throttles(struct esp *esp, int slot, int n, short *throttles)
{
	ASSERT((n == 1) || (n == N_SLOTS) || (n == NLUNS_PER_TARGET));
	ASSERT((slot + n) <= N_SLOTS);
	if (n == NLUNS_PER_TARGET) {
		slot &= ~(NLUNS_PER_TARGET - 1);
	}
	bcopy(&esp->e_throttle[slot], throttles,
	    n * sizeof (esp->e_throttle[slot]));
}

/*
 * reset handling
 */
static int
esp_reset(struct scsi_address *ap, int level)
{
	struct esp *esp = ADDR2ESP(ap);
	int rval;

	IPRINTF3("esp_reset: target %d.%d, level %d\n",
		ap->a_target, ap->a_lun, level);

	mutex_enter(ESP_MUTEX);
	rval = _esp_reset(ap, level);
	ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp);
	ESP_WAKEUP_CALLBACK_THREAD(esp);

	return (rval);
}

/*
 * _esp_reset assumes that we have already entered the mutex
 */
static int
_esp_reset(struct scsi_address *ap, int level)
{
	int rval = FALSE;
	struct esp *esp = ADDR2ESP(ap);
	short slot = (ap->a_target * NLUNS_PER_TARGET) | ap->a_lun;

	ASSERT(mutex_owned(ESP_MUTEX));
	IPRINTF3("esp_reset for slot %x, level=%x, tcmds=%x\n",
		slot, level, esp->e_tcmds[slot]);

	if (level == RESET_ALL) {
		/*
		 * horrible hack for esp100, see bugid 1172190
		 * do not reset the bus during dumping for esp100
		 */
		if (panicstr && (esp->e_type == ESP100) && esp->e_ncmds) {
			return (TRUE);
		}

		/*
		 * We know that esp_reset_bus() returns ACTION_RETURN.
		 */
		(void) esp_reset_bus(esp);

		/*
		 * Now call esp_dopoll() to field the reset interrupt
		 * which will then call esp_reset_recovery which will
		 * call the completion function for all commands.
		 */
		if (esp_dopoll(esp, SHORT_POLL_TIMEOUT) <= 0) {
			/*
			 * reset esp
			 */
			esp_internal_reset(esp, ESP_RESET_ESP);
			(void) esp_reset_bus(esp);
			if (esp_dopoll(esp, SHORT_POLL_TIMEOUT) <= 0) {
				esplog(esp,
				    CE_WARN, "reset scsi bus failed");
				New_state(esp, STATE_FREE);
			} else {
				rval = TRUE;
			}
		} else {
			rval = TRUE;
		}
	} else {
		struct esp_cmd *cur_sp = esp->e_slots[slot];
		void (*savec)() = NULL;

		esp_check_in_transport(esp, NULL);

		/*
		 * if reset delay active we cannot  access the target
		 */
		if (esp->e_reset_delay[ap->a_target]) {
			return (rval);
		}

		/*
		 * zero pkt_comp so it won't complete during the reset and
		 * we can still update the packet after the reset.
		 */
		if (cur_sp) {
			savec = cur_sp->cmd_pkt.pkt_comp;
			cur_sp->cmd_pkt.pkt_comp = NULL;
		}

		esp_set_all_lun_throttles(esp, slot, HOLD_THROTTLE);

		/*
		 * is this a connected cmd but not selecting?
		 */
		if ((esp->e_state != STATE_FREE) && cur_sp &&
		    (cur_sp->cmd_pkt.pkt_state != 0)) {
			rval = esp_reset_connected_cmd(esp, ap, slot);
		}

		esp_check_in_transport(esp, NULL);

		/*
		 * if not connected or esp_reset_connected_cmd() failed,
		 * attempt a reset_disconnected_cmd
		 * NOTE: a proxy cmd zaps the currently disconnected
		 * non-tagged cmd; also this could cause a failed reselection
		 * if the target reselects just after zapping
		 */
		if (rval == FALSE) {
			rval = esp_reset_disconnected_cmd(esp, ap, slot);

			if ((rval == TRUE) && cur_sp &&
			    (cur_sp != esp->e_save_pkt[slot]) &&
			    ((cur_sp->cmd_flags & CFLAG_COMPLETED) == 0)) {
				cur_sp->cmd_flags |= CFLAG_COMPLETED;
					ASSERT((esp->e_slots[slot] !=
					    cur_sp));
					MARK_PKT(cur_sp, CMD_RESET,
					    STAT_DEV_RESET);
			}
		}


		/*
		 * a proxy cmd zapped the active slot for non-tagged tgts.
		 *
		 * regardless whether the devices was  actually reset,
		 * it has to be completed here; otherwise it is lost forever.
		 * tagged cmds will just timeout eventually
		 *
		 * don't set completed for cmds that are in arq.
		 */
		if ((rval == FALSE) && cur_sp &&
		    (!(cur_sp->cmd_pkt.pkt_flags & FLAG_TAGMASK)) &&
		    ((cur_sp->cmd_flags & CFLAG_COMPLETED) == 0) &&
		    (esp->e_slots[slot] != cur_sp)) {
			if (cur_sp != esp->e_save_pkt[slot]) {
				cur_sp->cmd_flags |= CFLAG_COMPLETED;
			}
			MARK_PKT(cur_sp, CMD_RESET, STAT_BUS_RESET);

			/* blow everything away */
			(void) _esp_reset(ap, RESET_ALL);
		}


		/*
		 * cleanup if reset was successful
		 * complete the current sp first.
		 * unless it is currently in auto request sense
		 */
		if (cur_sp) {
			cur_sp->cmd_pkt.pkt_comp = savec;
			if (cur_sp->cmd_flags & CFLAG_COMPLETED) {

				/*
				 * the packet shouldn't be on readyQ but
				 * just in case, check for it
				 */
				(void) esp_remove_readyQ(esp, cur_sp, slot);
				esp_remove_tagged_cmd(esp, cur_sp, slot,
					NEW_TIMEOUT);
				cur_sp->cmd_flags &= ~CFLAG_COMPLETED;

				esp_decrement_ncmds(esp, cur_sp);

				esp_check_in_transport(esp, cur_sp);

				esp_call_pkt_comp(esp, cur_sp);
				ASSERT(cur_sp != esp->e_slots[slot]);
			}
		}

		esp_check_in_transport(esp, NULL);

		if (rval == TRUE) {
			if (cur_sp) {
				ASSERT(cur_sp != esp->e_slots[slot]);
			}
			esp_reset_cleanup(esp, slot);
		} else {
			esp_set_all_lun_throttles(esp, slot, CLEAR_THROTTLE);
			IPRINTF1("esp_reset failed for slot %x\n", slot);
		}

		if (esp->e_state == STATE_FREE) {
			(void) esp_ustart(esp, NEXTSLOT(slot, esp->e_dslot),
			    NEW_CMD);
		}
	}
exit:
	ASSERT(mutex_owned(ESP_MUTEX));
	ASSERT(esp->e_ncmds >= esp->e_ndisc);

#ifdef ESPDEBUG
	if (rval && esp_test_stop)
		debug_enter("reset done");
#endif
	return (rval);
}

/*
 * reset delay is now handled by a separate watchdog; this ensures that
 * regardless of esp_scsi_watchdog_tick, the reset delay will not change
 */
static void
esp_start_watch_reset_delay(struct esp *esp)
{
	mutex_enter(&esp_global_mutex);
	if ((esp_reset_watch == 0) && ESP_CAN_SCHED) {
		esp_reset_watch = timeout(esp_watch_reset_delay, NULL,
		    drv_usectohz((clock_t)ESP_WATCH_RESET_DELAY_TICK * 1000));
	}
	ASSERT((esp_reset_watch != 0) || (esp->e_flags & ESP_FLG_NOTIMEOUTS));
	mutex_exit(&esp_global_mutex);
}

/*ARGSUSED*/
static void
esp_watch_reset_delay(void *arg)
{
	struct esp *esp;
	int not_done;

	mutex_enter(&esp_global_mutex);
	esp_reset_watch = 0;
	mutex_exit(&esp_global_mutex);

	rw_enter(&esp_global_rwlock, RW_READER);
	for (esp = esp_softc; esp != (struct esp *)NULL; esp = esp->e_next) {
		if (esp->e_tran == 0) {
			continue;
		}
		mutex_enter(ESP_MUTEX);
		not_done = esp_watch_reset_delay_subr(esp);
		ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp);
		ESP_WAKEUP_CALLBACK_THREAD(esp);
		if (not_done) {
			EPRINTF("\trestart watch reset delay\n");
			esp_start_watch_reset_delay(esp);
		} else {
			EPRINTF("\tno more reset delay watching\n");
		}
	}
	rw_exit(&esp_global_rwlock);
}

static int
esp_watch_reset_delay_subr(struct esp *esp)
{
	short slot, s;
	int start_slot = -1;
	int done = 0;

	for (slot = 0; slot < N_SLOTS; slot += NLUNS_PER_TARGET)  {

		/*
		 * check if a reset delay is active; if so clear throttle
		 * which will unleash the cmds in the ready Q
		 */
		s = slot/NLUNS_PER_TARGET;
		if (esp->e_reset_delay[s] != 0) {
			EPRINTF2("target%d: reset delay=%d\n", s,
			    esp->e_reset_delay[s]);
			esp->e_reset_delay[s] -= ESP_WATCH_RESET_DELAY_TICK;
			if (esp->e_reset_delay[s] <= 0) {
				/*
				 * clear throttle for all luns on  this target
				 */
				esp->e_reset_delay[s] = 0;
				esp_set_all_lun_throttles(esp, slot,
				    CLEAR_THROTTLE);
				IPRINTF1("reset delay completed, slot=%x\n",
				    slot);
				if (start_slot == -1) {
					start_slot = slot;
				}
			} else {
				done = -1;
			}
		}
	}

	/*
	 * start a cmd if a reset delay expired
	 */
	if (start_slot != -1 && esp->e_state == STATE_FREE) {
		(void) esp_ustart(esp, start_slot, NEW_CMD);
	}
	return (done);
}

static void
esp_reset_cleanup(struct esp *esp, int slot)
{
	/*
	 * reset msg has been accepted, now cleanup queues;
	 * for all luns of this target
	 */
	int i, start, end;
	int target  = slot/NLUNS_PER_TARGET;

	esp_check_in_transport(esp, NULL);

	start = slot & ~(NLUNS_PER_TARGET-1);
	end = start + NLUNS_PER_TARGET;
	IPRINTF4("esp_reset_cleanup: slot %x, start=%x, end=%x, tcmds=%x\n",
	    slot, start, end, esp->e_tcmds[slot]);

	/*
	 * if the watchdog is running, set up a reset delay for this target
	 * a throttle of HOLD_THROTTLE forces all new requests into the ready Q
	 * if the watchdog is not running then delay here
	 */
	if (esp_watchdog_running && !panicstr) {
		esp_set_all_lun_throttles(esp, start, HOLD_THROTTLE);
		esp->e_reset_delay[target] = esp->e_scsi_reset_delay;
		esp_start_watch_reset_delay(esp);
	} else {
		drv_usecwait(esp->e_scsi_reset_delay * 1000);
	}

	for (i = start; i < end; i++) {
		esp_mark_packets(esp, i, CMD_RESET, STAT_DEV_RESET);
		esp_flush_tagQ(esp, i);
		esp_flush_readyQ(esp, i);
		ASSERT(esp->e_tcmds[i] == 0);
		ASSERT(esp->e_save_pkt[i] == NULL);
		ASSERT(esp->e_slots[i] == NULL);
	}
	ASSERT(esp->e_ncmds >= esp->e_ndisc);
	esp_check_in_transport(esp, NULL);
}

/*
 * reset a currently disconnected target
 */
static int
esp_reset_disconnected_cmd(struct esp *esp, struct scsi_address *ap, int slot)
{
	struct esp_cmd	*proxy_cmdp;
	int		rval;

	/*
	 * if reset delay active we cannot  access the target
	 */
	if (esp->e_reset_delay[ap->a_target]) {
		return (FALSE);
	}

	esp_check_in_transport(esp, NULL);

	proxy_cmdp = kmem_alloc(ESP_CMD_SIZE, KM_SLEEP);
	esp_makeproxy_cmd(proxy_cmdp, ap, 1, MSG_DEVICE_RESET);
	rval = esp_do_proxy_cmd(esp, proxy_cmdp, ap, slot,
	    scsi_mname(MSG_DEVICE_RESET));
	kmem_free(proxy_cmdp, ESP_CMD_SIZE);
	return (rval);
}

/*
 * reset a target with a currently connected command
 * Assert ATN and send MSG_DEVICE_RESET, clear throttles temporarily
 * to prevent new cmds from starting regardless of the outcome
 */
static int
esp_reset_connected_cmd(struct esp *esp, struct scsi_address *ap, int slot)
{
	int rval = FALSE;
	struct esp_cmd *sp = esp->e_slots[slot];
	int flags = sp->cmd_pkt.pkt_flags;

	/*
	 * if reset delay active we cannot  access the target
	 */
	if (esp->e_reset_delay[ap->a_target]) {
		return (rval);
	}

	IPRINTF2("Sending reset message to connected %d.%d\n",
	    ap->a_target, ap->a_lun);
	esp->e_reset = 0;
	esp->e_omsglen = 1;
	esp->e_cur_msgout[0] = MSG_DEVICE_RESET;
	sp->cmd_pkt.pkt_flags |= FLAG_NOINTR;
	esp_assert_atn(esp);
	(void) esp_dopoll(esp, SHORT_POLL_TIMEOUT);

	/*
	 * now check if the msg was taken
	 * e_reset is set in esp_handle_msg_out_done when
	 * msg has actually gone out  (ie. msg out phase occurred)
	 */
	if (esp->e_reset && (sp->cmd_flags & CFLAG_COMPLETED)) {
		IPRINTF2("target %d.%d reset\n", ap->a_target, ap->a_lun);
		rval = TRUE;
	} else {
		IPRINTF2("target %d.%d did not reset\n",
			ap->a_target, ap->a_lun);
	}
	sp->cmd_pkt.pkt_flags = flags;
	esp->e_omsglen = 0;

	return (rval);
}

/*
 * error handling, reset and abort stuff
 */
static int
esp_reset_bus(struct esp *esp)
{
	IPRINTF("esp_reset_bus:\n");
	New_state(esp, ACTS_RESET);

	esp_internal_reset(esp, ESP_RESET_SCSIBUS);

	/*
	 * Now that we've reset the SCSI bus, we'll take a SCSI RESET
	 * interrupt and use that to clean up the state of things.
	 */
	return (ACTION_RETURN);
}

static int
esp_reset_recovery(struct esp *esp)
{
	struct esp_cmd *sp;
	short slot, start_slot;
	auto struct esp_cmd *eslots[N_SLOTS];
	int i;

	IPRINTF("esp_reset_recovery:\n");
	if (esp->e_state != ACTS_RESET) {
		/*
		 * this reset was not expected, so probably external reset
		 */
		IPRINTF("external reset recovery\n");
		if (esp_watchdog_running && !panicstr) {
			int i;

			for (i = 0; i < N_SLOTS; i++) {
				esp->e_throttle[i] = HOLD_THROTTLE;
			}
			for (i = 0; i < NTARGETS; i++) {
				esp->e_reset_delay[i] =
				    esp->e_scsi_reset_delay;
			}
			esp_start_watch_reset_delay(esp);
		} else {
			drv_usecwait(esp->e_scsi_reset_delay * 1000);
		}
		if (esp->e_ncmds) {
			esplog(esp, CE_WARN, "external SCSI bus reset");
		}
	}

	/*
	 * Renegotiate sync immediately on next command
	 */
	esp->e_sync_known = 0;

	/*
	 * Flush DMA, clear interrupts until they go away, and clear fifo
	 */
	ESP_FLUSH_DMA(esp);

	while (INTPENDING(esp)) {
		volatile struct espreg *ep = esp->e_reg;
		esp->e_stat = ep->esp_stat;
		esp->e_intr = ep->esp_intr;
	}

	esp_flush_fifo(esp);

	if (esp->e_ncmds == 0) {
		New_state(esp, STATE_FREE);
		return (ACTION_RETURN);
	}

	if ((start_slot = esp->e_cur_slot) == UNDEFINED) {
		start_slot = 0;
	}

	/*
	 * for right now just claim that all
	 * commands have been destroyed by a SCSI reset
	 * and let already set reason fields or callers
	 * decide otherwise for specific commands.
	 *
	 * We're blowing it all away. Remove any dead wood to the
	 * side so that completion routines don't get confused.
	 */
	bcopy(esp->e_slots, eslots, sizeof (struct esp_cmd *) * N_SLOTS);
	bzero(esp->e_slots, sizeof (struct esp_cmd *) * N_SLOTS);

	for (i = 0; i < N_SLOTS; i++) {
		if (esp->e_tagQ[i]) {
			esp->e_tagQ[i]->e_timebase = 0;
			esp->e_tagQ[i]->e_timeout = 0;
			esp->e_tagQ[i]->e_dups = 0;
		}
	}

	/*
	 * Call this routine to completely reset the state of the softc data.
	 */
	esp_internal_reset(esp, ESP_RESET_SOFTC);

	/*
	 * Hold the state of the host adapter open
	 */
	New_state(esp, ACTS_FROZEN);

	slot = start_slot;
	do {
		esp_mark_packets(esp, slot, CMD_RESET, STAT_BUS_RESET);
		if ((sp = eslots[slot]) != 0) {
			esp_flush_cmd(esp, sp, CMD_RESET, STAT_BUS_RESET);
		}

		esp_flush_tagQ(esp, slot);
		esp_flush_readyQ(esp, slot);
		slot = NEXTSLOT(slot, esp->e_dslot);
	} while (slot != start_slot);

	/*
	 * Move the state back to free...
	 */
	New_state(esp, STATE_FREE);

	ASSERT(esp->e_ndisc == 0);

	/*
	 * there might be cmds in the ready list again because
	 * for immediate callback cmds, the mutex has been released
	 * Therefore, do not check on ncdms == 0
	 */

	/*
	 * perform the reset notification callbacks that are registered.
	 */
	(void) scsi_hba_reset_notify_callback(&esp->e_mutex,
		&esp->e_reset_notify_listf);

	return (ACTION_RETURN);
}

/*
 * routine for reset notification setup, to register or cancel.
 */
static int
esp_scsi_reset_notify(struct scsi_address *ap, int flag,
void (*callback)(caddr_t), caddr_t arg)
{
	struct esp	*esp = ADDR2ESP(ap);

	return (scsi_hba_reset_notify_setup(ap, flag, callback, arg,
		&esp->e_mutex, &esp->e_reset_notify_listf));
}

/*
 * torture test functions
 */
#ifdef ESP_TEST_RESET
static void
esp_test_reset(struct esp *esp, int slot)
{
	struct scsi_address ap;
	char target = slot/NLUNS_PER_TARGET;

	if (esp_rtest & (1 << target)) {
		ap.a_hba_tran = esp->e_tran;
		ap.a_target = target;
		ap.a_lun = 0;
		if ((esp_rtest_type == 1) &&
		    (esp->e_state == ACTS_DATA_DONE)) {
			if (_esp_reset(&ap, RESET_TARGET)) {
				esp_rtest = 0;
			}
		} else if ((esp_rtest_type == 2) &&
		    (esp->e_state == ACTS_DATA_DONE)) {
			if (_esp_reset(&ap, RESET_ALL)) {
				esp_rtest = 0;
			}
		} else {
			if (_esp_reset(&ap, RESET_TARGET)) {
				esp_rtest = 0;
			}
		}
	}
}
#endif

#ifdef ESP_TEST_ABORT
static void
esp_test_abort(struct esp *esp, int slot)
{
	struct esp_cmd *sp = esp->e_slots[slot];
	struct scsi_address ap;
	char target = slot/NLUNS_PER_TARGET;
	struct scsi_pkt *pkt = NULL;

	if (esp_atest & (1 << target)) {
		ap.a_hba_tran = esp->e_tran;
		ap.a_target = target;
		ap.a_lun = 0;

		if ((esp_atest_disc == 0) && sp &&
		    ((sp->cmd_flags & CFLAG_CMDDISC) == 0)) {
			pkt = &sp->cmd_pkt;
		} else if ((esp_atest_disc == 1) && NOTAG(target) && sp &&
		    (sp->cmd_flags & CFLAG_CMDDISC)) {
			pkt = &sp->cmd_pkt;
		} else if ((esp_atest_disc == 1) && (sp == 0) &&
		    (esp->e_tcmds[slot] != 0)) {
			int tag;
			/*
			 * find the oldest tag
			 */
			for (tag = NTAGS-1; tag >= 0; tag--) {
				if ((sp = esp->e_tagQ[slot]->t_slot[tag]) != 0)
				    break;
			}
			if (sp) {
				pkt = &sp->cmd_pkt;
			}
		} else if (esp_atest_disc == 2 && (sp == 0) &&
		    (esp->e_tcmds[slot] != 0)) {
			pkt = NULL;
		} else if (esp_atest_disc == 2 && NOTAG(target)) {
			pkt = NULL;
		} else if (esp_atest_disc == 3 && esp->e_readyf[slot]) {
			pkt = &(esp->e_readyf[slot]->cmd_pkt);
		} else if (esp_atest_disc == 4 &&
		    esp->e_readyf[slot] && esp->e_readyf[slot]->cmd_forw) {
			pkt = &(esp->e_readyf[slot]->cmd_forw->cmd_pkt);
		} else if (esp_atest_disc == 5 && esp->e_readyb[slot]) {
			pkt = &(esp->e_readyb[slot]->cmd_pkt);
		} else if ((esp_atest_disc == 6) &&
		    (esp->e_state == ACTS_DATA_DONE)) {
			pkt = &sp->cmd_pkt;
		} else if (esp_atest_disc == 7) {
			if ((esp->e_tcmds[slot] == 0) &&
			    (esp->e_slots[slot] == NULL)) {
				if (_esp_abort(&ap, NULL) &&
					_esp_reset(&ap, RESET_TARGET)) {
						esp_atest = 0;
						return;
				} else {
					esplog(esp, CE_NOTE,
						"abort/reset failed\n");
				}
				return;
			}
		}
		if (_esp_abort(&ap, pkt)) {
			esp_atest = 0;
		}
	}
}
#endif

/*
 * capability interface
 */
static int
esp_commoncap(struct scsi_address *ap, char *cap, int val,
    int tgtonly, int doset)
{
	struct esp *esp = ADDR2ESP(ap);
	int cidx;
	uchar_t tshift = (1<<ap->a_target);
	uchar_t ntshift = ~tshift;
	int rval = FALSE;

	mutex_enter(ESP_MUTEX);

	if (cap == (char *)0) {
		goto exit;
	}

	cidx = scsi_hba_lookup_capstr(cap);
	if (cidx == -1) {
		rval = UNDEFINED;
	} else if (doset) {
		switch (cidx) {
		case SCSI_CAP_DMA_MAX:
		case SCSI_CAP_MSG_OUT:
		case SCSI_CAP_PARITY:
		case SCSI_CAP_INITIATOR_ID:
		case SCSI_CAP_LINKED_CMDS:
		case SCSI_CAP_UNTAGGED_QING:
		case SCSI_CAP_RESET_NOTIFICATION:
			/*
			 * None of these are settable via
			 * the capability interface.
			 */
			break;
		case SCSI_CAP_DISCONNECT:

			if ((esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_DR) == 0) {
				break;
			} else if (tgtonly) {
				if (val)
					esp->e_nodisc &= ntshift;
				else
					esp->e_nodisc |= tshift;
			} else {
				esp->e_nodisc = (val) ? 0 : 0xff;
			}
			rval = TRUE;
			break;
		case SCSI_CAP_SYNCHRONOUS:

			if ((esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_SYNC) == 0) {
				break;
			} else if (tgtonly) {
				if ((esp->e_weak & tshift) && val) {
					IPRINTF2(
					"target %d.%d: can't set sync cap!\n",
					ap->a_target, ap->a_lun);
					rval = FALSE;
					break;
				}
				if (val) {
					esp->e_force_async &=
						~(1<<ap->a_target);
				} else {
					esp->e_force_async |=
						(1<<ap->a_target);
				}
				esp->e_sync_known &= ntshift;
			} else {
				if (esp->e_weak != 0) {
					IPRINTF(
					"can't set sync cap!\n");
					rval = FALSE;
					break;
				}
				esp->e_force_async = (val) ? 0 : 0xff;
				esp->e_sync_known = 0;
			}
			rval = TRUE;
			break;
		case SCSI_CAP_TAGGED_QING:
			/* Must have disco/reco enabled for tagged queuing. */
			if (((esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_DR) == 0) ||
			    ((esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_TAG) == 0) ||
			    ((esp->e_options & ESP_OPT_FAS) == 0)) {
				break;
			} else if (tgtonly) {
				if (val) {
					/*
					 * allocate the tagQ area later
					 */
					IPRINTF1("target %d: TQ enabled\n",
					    ap->a_target);
					esp->e_notag &= ntshift; /* enable */
				} else {
					int start, end, slot;
					int target = ap->a_target;
					uint_t size = sizeof (struct t_slots);

					esp->e_notag |= tshift; /* disable */
					IPRINTF1("target %d: TQ disabled\n",
					    target);

					/*
					 * free all tagQ space
					 */
					start =	 target * NLUNS_PER_TARGET;
					end   =	 start + NLUNS_PER_TARGET;
					for (slot = start; slot < end; slot++) {
					    if ((esp->e_tagQ[slot]) &&
						(esp->e_tcmds[slot] == 0)) {
						    kmem_free((caddr_t)
							    esp->e_tagQ[slot],
							    size);
						    esp->e_tagQ[slot] = NULL;
					    }
					}
				}
			} else {
				esp->e_notag = (val) ? 0 : 0xff;
			}

			/*
			 * update TQ properties
			 */
			if (tgtonly) {
				esp_update_TQ_props(esp, ap->a_target, val);
			} else {
				int i;
				for (i = 0; i < NTARGETS; i++) {
					esp_update_TQ_props(esp, i, val);
				}
			}
			rval = TRUE;
			break;
		case SCSI_CAP_ARQ:
			if (esp_create_arq_pkt(esp, ap, val) == 0) {
				rval = TRUE;
			}
			break;

		case SCSI_CAP_QFULL_RETRIES:
			if (tgtonly) {
				esp->e_qfull_retries[ap->a_target] =
					(uchar_t)val;
			} else {
				int i;
				for (i = 0; i < NTARGETS; i++) {
					esp->e_qfull_retries[i] = (uchar_t)val;
				}
			}
			rval = TRUE;
			break;

		case SCSI_CAP_QFULL_RETRY_INTERVAL:
			if (tgtonly) {
				esp->e_qfull_retry_interval[ap->a_target] =
					drv_usectohz(val * 1000);
			} else {
				int i;
				for (i = 0; i < NTARGETS; i++) {
					esp->e_qfull_retry_interval[i] =
						drv_usectohz(val * 1000);
				}
			}
			rval = TRUE;
			break;
		default:
			rval = UNDEFINED;
			break;
		}

	} else if (doset == 0) {
		switch (cidx) {
		case SCSI_CAP_DMA_MAX:
			/*
			 * very high limit because of multiple dma windows
			 * The return value can not be 0xFFFFFFFF (-1)
			 * as it is the value returned for error.
			 */
			rval = 1<<30;
			break;
		case SCSI_CAP_MSG_OUT:
			rval = TRUE;
			break;
		case SCSI_CAP_DISCONNECT:
			if ((esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_DR) &&
			    (tgtonly == 0 || (esp->e_nodisc & tshift) == 0)) {
				rval = TRUE;
			}
			break;
		case SCSI_CAP_SYNCHRONOUS:
			if ((esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_SYNC) &&
			    (tgtonly == 0 || esp->e_offset[ap->a_target])) {
				rval = TRUE;
			}
			break;
		case SCSI_CAP_PARITY:
			if (esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_PARITY)
				rval = TRUE;
			break;
		case SCSI_CAP_INITIATOR_ID:
			rval = MY_ID(esp);
			break;
		case SCSI_CAP_TAGGED_QING:
			/* Must have disco/reco enabled for tagged queuing. */
			if (((esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_DR) == 0) ||
			    ((esp->e_target_scsi_options[ap->a_target] &
				SCSI_OPTIONS_TAG) == 0) ||
			    ((esp->e_options & ESP_OPT_FAS) == 0)) {
				break;

			} else if (tgtonly && (esp->e_notag & tshift)) {
				break;
			}
			rval = TRUE;
			break;
		case SCSI_CAP_UNTAGGED_QING:
			rval = TRUE;
			break;
		case SCSI_CAP_ARQ:
			{
				int slot = ap->a_target * NLUNS_PER_TARGET |
				    ap->a_lun;
				if (esp->e_rq_sense_data[slot]) {
					rval = TRUE;
				}
			}
			break;
		case SCSI_CAP_LINKED_CMDS:
			break;
		case SCSI_CAP_RESET_NOTIFICATION:
			rval = TRUE;
			break;
		case SCSI_CAP_QFULL_RETRIES:
			rval = esp->e_qfull_retries[ap->a_target];
			break;

		case SCSI_CAP_QFULL_RETRY_INTERVAL:
			rval = drv_hztousec(
				esp->e_qfull_retry_interval[ap->a_target]) /
				1000;
			break;
		default:
			rval = UNDEFINED;
			break;
		}
	}
exit:

	ESP_CHECK_STARTQ_AND_ESP_MUTEX_EXIT(esp);

	if (doset) {
		IPRINTF6(
	    "esp_commoncap:tgt=%x,cap=%s,tgtonly=%x,doset=%x,val=%x,rval=%x\n",
		ap->a_target, cap, tgtonly, doset, val, rval);
	}

	return (rval);
}

static int
esp_getcap(struct scsi_address *ap, char *cap, int whom)
{
	return (esp_commoncap(ap, cap, 0, whom, 0));
}

static int
esp_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	return (esp_commoncap(ap, cap, value, whom, 1));
}

static void
esp_update_TQ_props(struct esp *esp, int tgt, int value)
{
	static	char *prop_template = "target%d-TQ";
	char property[32];
	dev_info_t *dip = esp->e_dev;

	(void) sprintf(property, prop_template, tgt);

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, property)) {
		if (value == 0) {
			if (ddi_prop_remove(DDI_DEV_T_NONE, dip, property) !=
			    DDI_PROP_SUCCESS) {
				IPRINTF1("cannot remove %s property\n",
				    property);
			}
		}
	} else if (value) {
		/*
		 * create a boolean property (not supported with the
		 * new property interfaces)
		 */
		if (ddi_prop_create(DDI_DEV_T_NONE, dip, 0, property,
		    NULL, 0) != DDI_PROP_SUCCESS) {
			IPRINTF1("cannot create %s property\n", property);
		}
	}
}

/*
 * Error logging, printing, and debug print routines
 */
static char *esp_label = "esp";

/*PRINTFLIKE3*/
static void
esplog(struct esp *esp, int level, const char *fmt, ...)
{
	dev_info_t *dev;
	va_list ap;

	if (esp) {
		dev = esp->e_dev;
	} else {
		dev = 0;
	}

	mutex_enter(&esp_log_mutex);

	va_start(ap, fmt);
	(void) vsprintf(esp_log_buf, fmt, ap);
	va_end(ap);
	scsi_log(dev, esp_label, level, "%s", esp_log_buf);

	mutex_exit(&esp_log_mutex);
}

/*PRINTFLIKE2*/
static void
eprintf(struct esp *esp, const char *fmt, ...)
{
	dev_info_t *dev;
	va_list ap;

	if (esp) {
		dev = esp->e_dev;
	} else {
		dev = 0;
	}

	mutex_enter(&esp_log_mutex);

	va_start(ap, fmt);
	(void) vsprintf(esp_log_buf, fmt, ap);
	va_end(ap);

#ifdef ESPDEBUG
	scsi_log(dev, esp_label, SCSI_DEBUG, "%s", esp_log_buf);
#else
	{
		char label[32];
		if (dev) {
			(void) sprintf(label, "%s%d", esp_label, CNUM);
		} else {
			(void) sprintf(label, "%s", esp_label);
		}
		scsi_log(dev, label, CE_CONT, "%s", esp_log_buf);
	}
#endif
	mutex_exit(&esp_log_mutex);
}

static char *esp_int_bits = ESP_INT_BITS;
static char *esp_stat_bits = ESP_STAT_BITS;

#ifdef ESPDEBUG
static void
esp_stat_int_print(struct esp *esp)
{
	eprintf(esp, "\tStat=0x%b, Intr=0x%b\n", esp->e_stat,
	    esp_stat_bits, esp->e_intr, esp_int_bits);
}
#endif /* ESPDEBUG */


static void
esp_printstate(struct esp *esp, char *msg)
{
	volatile struct espreg *ep = esp->e_reg;
	volatile struct dmaga *dmar = esp->e_dma;
	struct esp_cmd *sp;
	uchar_t fifo_flag;
	uint_t csr = dmar->dmaga_csr;
	uint_t count = dmar->dmaga_count;
	uint_t addr = dmar->dmaga_addr;

	esplog(esp, CE_WARN, "%s: current esp state:", msg);
	eprintf((struct esp *)0,
	    "\tState=%s Last State=%s\n", esp_state_name(esp->e_state),
	    esp_state_name(esp->e_laststate));

	/*
	 * disable DVMA to avoid a timeout on SS1
	 */
	if (dmar->dmaga_csr & DMAGA_ENDVMA) {
		while (dmar->dmaga_csr & DMAGA_REQPEND)
			;
		dmar->dmaga_csr &= ~DMAGA_ENDVMA;
		fifo_flag = ep->esp_fifo_flag;
		dmar->dmaga_csr |= DMAGA_ENDVMA;
	} else {
		fifo_flag = ep->esp_fifo_flag;
	}

	eprintf((struct esp *)0,
	    "\tLatched stat=0x%b intr=0x%b fifo 0x%x\n", esp->e_stat,
	    esp_stat_bits, esp->e_intr, esp_int_bits, fifo_flag);
	eprintf((struct esp *)0,
	    "\tlast msg out: %s; last msg in: %s\n",
	    scsi_mname(esp->e_last_msgout), scsi_mname(esp->e_last_msgin));
	eprintf((struct esp *)0, "\tDMA csr=0x%b\n", csr, dmaga_bits);
	eprintf((struct esp *)0,
	    "\taddr=%x dmacnt=%x last=%x last_cnt=%x\n", addr, count,
	    esp->e_lastdma, esp->e_lastcount);

	if (esp->e_cur_slot != UNDEFINED && (sp = CURRENT_CMD(esp))) {
		esp_dump_cmd(sp);
	}
#ifdef	ESPDEBUG
	if (espdebug)
		esp_dump_state(esp);
#endif	/* ESPDEBUG */
}

#ifdef	ESPDEBUG
static void
esp_dump_state(struct esp *esp)
{
	short x, z;
	auto char buf[128];

	z = esp->e_phase_index;
	for (x = 1; x <= NPHASE; x++) {
		short y;

		z = (z - 1) & (NPHASE - 1);
		y = esp->e_phase[z].e_save_state;
		if (y == STATE_FREE)
			break;

		(void) sprintf(&buf[0], "\tcurrent phase 0x%x=%s",
			y, esp_state_name((ushort_t)y));

		(void) sprintf(&buf[strlen(buf)], "\tstat=0x%x",
			esp->e_phase[z].e_save_stat);

		if (esp->e_phase[z].e_val1 != -1) {
			(void) sprintf(&buf[strlen(buf)], "\t0x%x",
				esp->e_phase[z].e_val1);
		}

		if (esp->e_phase[z].e_val2 != -1) {
			(void) sprintf(&buf[strlen(buf)], "\t0x%x",
				esp->e_phase[z].e_val2);
		}
		eprintf((struct esp *)0, "%s\n", buf);
	}
}
#endif	/* ESPDEBUG */

static void
esp_dump_cmd(struct esp_cmd *sp)
{
	int i;
	uchar_t *cp = (uchar_t *)sp->cmd_pkt.pkt_cdbp;
	auto char buf[128];

	buf[0] = '\0';
	eprintf((struct esp *)0,
	    "\tCmd dump for Target %d Lun %d:\n", Tgt(sp), Lun(sp));
	(void) sprintf(&buf[0], "\tcdblen=%d, cdb=[", sp->cmd_cdblen);
	for (i = 0; i < (int)sp->cmd_cdblen; i++) {
		(void) sprintf(&buf[strlen(buf)], " 0x%x", *cp++);
	}
	if (sp->cmd_pkt.pkt_state & STATE_GOT_STATUS) {
		(void) sprintf(&buf[strlen(buf)],
		    " ]; Status=0x%x\n", sp->cmd_pkt.pkt_scbp[0]);
	} else {
		(void) sprintf(&buf[strlen(buf)], " ]\n");
	}
	eprintf((struct esp *)0, buf);

	eprintf((struct esp *)0,
	    "\tpkt_state=0x%b pkt_flags=0x%x pkt_statistics=0x%x\n",
	    sp->cmd_pkt.pkt_state, scsi_state_bits, sp->cmd_pkt.pkt_flags,
	    sp->cmd_pkt.pkt_statistics);
	eprintf((struct esp *)0,
	    "\tcmd_flags=0x%x cmd_timeout=%ld\n", sp->cmd_flags,
	    sp->cmd_timeout);
}

static char *
esp_state_name(ushort_t state)
{
	if (state == STATE_FREE) {
		return ("FREE");
	} else if ((state & STATE_SELECTING) &&
		    (!(state & ACTS_LOG))) {
		if (state == STATE_SELECT_NORMAL)
			return ("SELECT");
		else if (state == STATE_SELECT_N_STOP)
			return ("SEL&STOP");
		else if (state == STATE_SELECT_N_SENDMSG)
			return ("SELECT_SNDMSG");
		else if (state == STATE_SELECT_N_TAG)
			return ("STATE_SELECT_N_TAG");
		else
			return ("SEL_NO_ATN");
	} else {
		static struct {
			char *sname;
			char state;
		} names[] = {
			"CMD_START",		ACTS_CMD_START,
			"CMD_DONE",		ACTS_CMD_DONE,
			"MSG_OUT",		ACTS_MSG_OUT,
			"MSG_OUT_DONE",		ACTS_MSG_OUT_DONE,
			"MSG_IN",		ACTS_MSG_IN,
			"MSG_IN_MORE",		ACTS_MSG_IN_MORE,
			"MSG_IN_DONE",		ACTS_MSG_IN_DONE,
			"CLEARING",		ACTS_CLEARING,
			"DATA",			ACTS_DATA,
			"DATA_DONE",		ACTS_DATA_DONE,
			"CMD_CMPLT",		ACTS_C_CMPLT,
			"UNKNOWN",		ACTS_UNKNOWN,
			"RESEL",		ACTS_RESEL,
			"ENDVEC",		ACTS_ENDVEC,
			"RESET",		ACTS_RESET,
			"ABORTING",		ACTS_ABORTING,
			"SPANNING",		ACTS_SPANNING,
			"FROZEN",		ACTS_FROZEN,
			"PREEMPTED",		ACTS_PREEMPTED,
			"PROXY",		ACTS_PROXY,
			"SYNCHOUT",		ACTS_SYNCHOUT,
			"CMD_LOST",		ACTS_CMD_LOST,
			"DATAOUT",		ACTS_DATAOUT,
			"DATAIN",		ACTS_DATAIN,
			"STATUS",		ACTS_STATUS,
			"DISCONNECT",		ACTS_DISCONNECT,
			"NOP",			ACTS_NOP,
			"REJECT",		ACTS_REJECT,
			"RESTOREDP",		ACTS_RESTOREDP,
			"SAVEDP",		ACTS_SAVEDP,
			"BAD_RESEL",		ACTS_BAD_RESEL,
			"LOG",			ACTS_LOG,
			"TAG",			ACTS_TAG,
			"CMD",			ACTS_CMD,
			"SELECT",		ACTS_SELECT,
			0
		};
		int i;
		for (i = 0; names[i].sname; i++) {
			if (names[i].state == state)
				return (names[i].sname);
		}
	}
	return ("<BAD>");
}
