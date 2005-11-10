/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PSMI 1.1 extensions are supported only in 2.6 and later versions.
 * PSMI 1.2 extensions are supported only in 2.7 and later versions.
 * PSMI 1.3 and 1.4 extensions are supported in Solaris 10.
 * PSMI 1.5 extensions are supported in Solaris Nevada.
 */
#define	PSMI_1_5

#include <sys/processor.h>
#include <sys/time.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>
#include <sys/cram.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/psm_common.h>
#include "apic.h"
#include <sys/pit.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/promif.h>
#include <sys/x86_archext.h>
#include <sys/cpc_impl.h>
#include <sys/uadmin.h>
#include <sys/panic.h>
#include <sys/debug.h>
#include <sys/archsystm.h>
#include <sys/trap.h>
#include <sys/machsystm.h>
#include <sys/cpuvar.h>
#include <sys/rm_platter.h>
#include <sys/privregs.h>
#include <sys/cyclic.h>
#include <sys/note.h>
#include <sys/pci_intr_lib.h>

/*
 *	Local Function Prototypes
 */
static void apic_init_intr();
static void apic_ret();
static int apic_handle_defconf();
static int apic_parse_mpct(caddr_t mpct, int bypass);
static struct apic_mpfps_hdr *apic_find_fps_sig(caddr_t fptr, int size);
static int apic_checksum(caddr_t bptr, int len);
static int get_apic_cmd1();
static int get_apic_pri();
static int apic_find_bus_type(char *bus);
static int apic_find_bus(int busid);
static int apic_find_bus_id(int bustype);
static struct apic_io_intr *apic_find_io_intr(int irqno);
int apic_allocate_irq(int irq);
static int apic_find_free_irq(int start, int end);
static uchar_t apic_allocate_vector(int ipl, int irq, int pri);
static void apic_modify_vector(uchar_t vector, int irq);
static void apic_mark_vector(uchar_t oldvector, uchar_t newvector);
static uchar_t apic_xlate_vector(uchar_t oldvector);
static void apic_xlate_vector_free_timeout_handler(void *arg);
static void apic_free_vector(uchar_t vector);
static void apic_reprogram_timeout_handler(void *arg);
static int apic_check_stuck_interrupt(apic_irq_t *irq_ptr, int old_bind_cpu,
    int new_bind_cpu, volatile int32_t *ioapic, int intin_no, int which_irq);
static int apic_setup_io_intr(apic_irq_t *irqptr, int irq);
static int apic_setup_io_intr_deferred(apic_irq_t *irqptr, int irq);
static void apic_record_rdt_entry(apic_irq_t *irqptr, int irq);
static struct apic_io_intr *apic_find_io_intr_w_busid(int irqno, int busid);
static int apic_find_intin(uchar_t ioapic, uchar_t intin);
static int apic_handle_pci_pci_bridge(dev_info_t *idip, int child_devno,
    int child_ipin, struct apic_io_intr **intrp);
static int apic_setup_irq_table(dev_info_t *dip, int irqno,
    struct apic_io_intr *intrp, struct intrspec *ispec, iflag_t *intr_flagp,
    int type);
static int apic_setup_sci_irq_table(int irqno, uchar_t ipl,
    iflag_t *intr_flagp);
static void apic_nmi_intr(caddr_t arg);
uchar_t apic_bind_intr(dev_info_t *dip, int irq, uchar_t ioapicid,
    uchar_t intin);
static int apic_rebind(apic_irq_t *irq_ptr, int bind_cpu, int acquire_lock,
    int when);
static int apic_rebind_all(apic_irq_t *irq_ptr, int bind_cpu, int safe);
static void apic_intr_redistribute();
static void apic_cleanup_busy();
static void apic_set_pwroff_method_from_mpcnfhdr(struct apic_mp_cnf_hdr *hdrp);
int apic_introp_xlate(dev_info_t *dip, struct intrspec *ispec, int type);

/* ACPI support routines */
static int acpi_probe(void);
static int apic_acpi_irq_configure(acpi_psm_lnk_t *acpipsmlnkp, dev_info_t *dip,
    int *pci_irqp, iflag_t *intr_flagp);

static int apic_acpi_translate_pci_irq(dev_info_t *dip, int busid, int devid,
    int ipin, int *pci_irqp, iflag_t *intr_flagp);
static uchar_t acpi_find_ioapic(int irq);
static int acpi_intr_compatible(iflag_t iflag1, iflag_t iflag2);

/*
 *	standard MP entries
 */
static int	apic_probe();
static int	apic_clkinit();
static int	apic_getclkirq(int ipl);
static uint_t	apic_calibrate(volatile uint32_t *addr,
    uint16_t *pit_ticks_adj);
static hrtime_t apic_gettime();
static hrtime_t apic_gethrtime();
static void	apic_init();
static void	apic_picinit(void);
static void	apic_cpu_start(processorid_t cpun, caddr_t rm_code);
static int	apic_post_cpu_start(void);
static void	apic_send_ipi(int cpun, int ipl);
static void	apic_set_softintr(int softintr);
static void	apic_set_idlecpu(processorid_t cpun);
static void	apic_unset_idlecpu(processorid_t cpun);
static int	apic_softlvl_to_irq(int ipl);
static int	apic_intr_enter(int ipl, int *vect);
static void	apic_intr_exit(int ipl, int vect);
static void	apic_setspl(int ipl);
static int	apic_addspl(int ipl, int vector, int min_ipl, int max_ipl);
static int	apic_delspl(int ipl, int vector, int min_ipl, int max_ipl);
static void	apic_shutdown(int cmd, int fcn);
static void	apic_preshutdown(int cmd, int fcn);
static int	apic_disable_intr(processorid_t cpun);
static void	apic_enable_intr(processorid_t cpun);
static processorid_t	apic_get_next_processorid(processorid_t cpun);
static int		apic_get_ipivect(int ipl, int type);
static void	apic_timer_reprogram(hrtime_t time);
static void	apic_timer_enable(void);
static void	apic_timer_disable(void);
static void	apic_post_cyclic_setup(void *arg);
extern int	apic_intr_ops(dev_info_t *, ddi_intr_handle_impl_t *,
		    psm_intr_op_t, int *);

static int	apic_oneshot = 0;
int	apic_oneshot_enable = 1; /* to allow disabling one-shot capability */

/*
 * These variables are frequently accessed in apic_intr_enter(),
 * apic_intr_exit and apic_setspl, so group them together
 */
volatile uint32_t *apicadr =  NULL;	/* virtual addr of local APIC	*/
int apic_setspl_delay = 1;		/* apic_setspl - delay enable	*/
int apic_clkvect;

/* ACPI SCI interrupt configuration; -1 if SCI not used */
int apic_sci_vect = -1;
iflag_t apic_sci_flags;

/* vector at which error interrupts come in */
int apic_errvect;
int apic_enable_error_intr = 1;
int apic_error_display_delay = 100;

/* vector at which performance counter overflow interrupts come in */
int apic_cpcovf_vect;
int apic_enable_cpcovf_intr = 1;

/* Max wait time (in microsecs) for flags to clear in an RDT entry. */
static int apic_max_usecs_clear_pending = 1000;

/* Amt of usecs to wait before checking if RDT flags have reset. */
#define	APIC_USECS_PER_WAIT_INTERVAL 100

/* Maximum number of times to retry reprogramming via the timeout */
#define	APIC_REPROGRAM_MAX_TIMEOUTS 10

/* timeout delay for IOAPIC delayed reprogramming */
#define	APIC_REPROGRAM_TIMEOUT_DELAY 5 /* microseconds */

/* Parameter to apic_rebind(): Should reprogramming be done now or later? */
#define	DEFERRED 1
#define	IMMEDIATE 0

/*
 * number of bits per byte, from <sys/param.h>
 */
#define	UCHAR_MAX	((1 << NBBY) - 1)

uchar_t	apic_reserved_irqlist[MAX_ISA_IRQ];

/*
 * The following vector assignments influence the value of ipltopri and
 * vectortoipl. Note that vectors 0 - 0x1f are not used. We can program
 * idle to 0 and IPL 0 to 0x10 to differentiate idle in case
 * we care to do so in future. Note some IPLs which are rarely used
 * will share the vector ranges and heavily used IPLs (5 and 6) have
 * a wide range.
 *	IPL		Vector range.		as passed to intr_enter
 *	0		none.
 *	1,2,3		0x20-0x2f		0x0-0xf
 *	4		0x30-0x3f		0x10-0x1f
 *	5		0x40-0x5f		0x20-0x3f
 *	6		0x60-0x7f		0x40-0x5f
 *	7,8,9		0x80-0x8f		0x60-0x6f
 *	10		0x90-0x9f		0x70-0x7f
 *	11		0xa0-0xaf		0x80-0x8f
 *	...		...
 *	16		0xf0-0xff		0xd0-0xdf
 */
uchar_t apic_vectortoipl[APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL] = {
	3, 4, 5, 5, 6, 6, 9, 10, 11, 12, 13, 14, 15, 16
};
	/*
	 * The ipl of an ISR at vector X is apic_vectortoipl[X<<4]
	 * NOTE that this is vector as passed into intr_enter which is
	 * programmed vector - 0x20 (APIC_BASE_VECT)
	 */

uchar_t	apic_ipltopri[MAXIPL + 1];	/* unix ipl to apic pri	*/
	/* The taskpri to be programmed into apic to mask given ipl */

#if defined(__amd64)
uchar_t	apic_cr8pri[MAXIPL + 1];	/* unix ipl to cr8 pri	*/
#endif

/*
 * Patchable global variables.
 */
int	apic_forceload = 0;

#define	INTR_ROUND_ROBIN_WITH_AFFINITY	0
#define	INTR_ROUND_ROBIN		1
#define	INTR_LOWEST_PRIORITY		2

int	apic_intr_policy = INTR_ROUND_ROBIN_WITH_AFFINITY;

static int	apic_next_bind_cpu = 2; /* For round robin assignment */
					/* start with cpu 1 */

int	apic_coarse_hrtime = 1;		/* 0 - use accurate slow gethrtime() */
					/* 1 - use gettime() for performance */
int	apic_flat_model = 0;		/* 0 - clustered. 1 - flat */
int	apic_enable_hwsoftint = 0;	/* 0 - disable, 1 - enable	*/
int	apic_enable_bind_log = 1;	/* 1 - display interrupt binding log */
int	apic_panic_on_nmi = 0;
int	apic_panic_on_apic_error = 0;

int	apic_verbose = 0;

/* Flag definitions for apic_verbose */
#define	APIC_VERBOSE_IOAPIC_FLAG		0x00000001
#define	APIC_VERBOSE_IRQ_FLAG			0x00000002
#define	APIC_VERBOSE_POWEROFF_FLAG		0x00000004
#define	APIC_VERBOSE_POWEROFF_PAUSE_FLAG	0x00000008


#define	APIC_VERBOSE_IOAPIC(fmt) \
	if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG) \
		cmn_err fmt;

#define	APIC_VERBOSE_IRQ(fmt) \
	if (apic_verbose & APIC_VERBOSE_IRQ_FLAG) \
		cmn_err fmt;

#define	APIC_VERBOSE_POWEROFF(fmt) \
	if (apic_verbose & APIC_VERBOSE_POWEROFF_FLAG) \
		prom_printf fmt;


/* Now the ones for Dynamic Interrupt distribution */
int	apic_enable_dynamic_migration = 1;

/*
 * If enabled, the distribution works as follows:
 * On every interrupt entry, the current ipl for the CPU is set in cpu_info
 * and the irq corresponding to the ipl is also set in the aci_current array.
 * interrupt exit and setspl (due to soft interrupts) will cause the current
 * ipl to be be changed. This is cache friendly as these frequently used
 * paths write into a per cpu structure.
 *
 * Sampling is done by checking the structures for all CPUs and incrementing
 * the busy field of the irq (if any) executing on each CPU and the busy field
 * of the corresponding CPU.
 * In periodic mode this is done on every clock interrupt.
 * In one-shot mode, this is done thru a cyclic with an interval of
 * apic_redistribute_sample_interval (default 10 milli sec).
 *
 * Every apic_sample_factor_redistribution times we sample, we do computations
 * to decide which interrupt needs to be migrated (see comments
 * before apic_intr_redistribute().
 */

/*
 * Following 3 variables start as % and can be patched or set using an
 * API to be defined in future. They will be scaled to
 * sample_factor_redistribution which is in turn set to hertz+1 (in periodic
 * mode), or 101 in one-shot mode to stagger it away from one sec processing
 */

int	apic_int_busy_mark = 60;
int	apic_int_free_mark = 20;
int	apic_diff_for_redistribution = 10;

/* sampling interval for interrupt redistribution for dynamic migration */
int	apic_redistribute_sample_interval = NANOSEC / 100; /* 10 millisec */

/*
 * number of times we sample before deciding to redistribute interrupts
 * for dynamic migration
 */
int	apic_sample_factor_redistribution = 101;

/* timeout for xlate_vector, mark_vector */
int	apic_revector_timeout = 16 * 10000; /* 160 millisec */

int	apic_redist_cpu_skip = 0;
int	apic_num_imbalance = 0;
int	apic_num_rebind = 0;

int	apic_nproc = 0;
int	apic_defconf = 0;
int	apic_irq_translate = 0;
int	apic_spec_rev = 0;
int	apic_imcrp = 0;

int	apic_use_acpi = 1;	/* 1 = use ACPI, 0 = don't use ACPI */
int	apic_use_acpi_madt_only = 0;	/* 1=ONLY use MADT from ACPI */

/*
 * For interrupt link devices, if apic_unconditional_srs is set, an irq resource
 * will be assigned (via _SRS). If it is not set, use the current
 * irq setting (via _CRS), but only if that irq is in the set of possible
 * irqs (returned by _PRS) for the device.
 */
int	apic_unconditional_srs = 1;

/*
 * For interrupt link devices, if apic_prefer_crs is set when we are
 * assigning an IRQ resource to a device, prefer the current IRQ setting
 * over other possible irq settings under same conditions.
 */

int	apic_prefer_crs = 1;


/* minimum number of timer ticks to program to */
int apic_min_timer_ticks = 1;
/*
 *	Local static data
 */
static struct	psm_ops apic_ops = {
	apic_probe,

	apic_init,
	apic_picinit,
	apic_intr_enter,
	apic_intr_exit,
	apic_setspl,
	apic_addspl,
	apic_delspl,
	apic_disable_intr,
	apic_enable_intr,
	apic_softlvl_to_irq,
	apic_set_softintr,

	apic_set_idlecpu,
	apic_unset_idlecpu,

	apic_clkinit,
	apic_getclkirq,
	(void (*)(void))NULL,		/* psm_hrtimeinit */
	apic_gethrtime,

	apic_get_next_processorid,
	apic_cpu_start,
	apic_post_cpu_start,
	apic_shutdown,
	apic_get_ipivect,
	apic_send_ipi,

	(int (*)(dev_info_t *, int))NULL,	/* psm_translate_irq */
	(int (*)(todinfo_t *))NULL,	/* psm_tod_get */
	(int (*)(todinfo_t *))NULL,	/* psm_tod_set */
	(void (*)(int, char *))NULL,	/* psm_notify_error */
	(void (*)(int))NULL,		/* psm_notify_func */
	apic_timer_reprogram,
	apic_timer_enable,
	apic_timer_disable,
	apic_post_cyclic_setup,
	apic_preshutdown,
	apic_intr_ops			/* Advanced DDI Interrupt framework */
};


static struct	psm_info apic_psm_info = {
	PSM_INFO_VER01_5,			/* version */
	PSM_OWN_EXCLUSIVE,			/* ownership */
	(struct psm_ops *)&apic_ops,		/* operation */
	"pcplusmp",				/* machine name */
	"pcplusmp v1.4 compatible %I%",
};

static void *apic_hdlp;

#ifdef DEBUG
#define	DENT		0x0001
int	apic_debug = 0;
/*
 * set apic_restrict_vector to the # of vectors we want to allow per range
 * useful in testing shared interrupt logic by setting it to 2 or 3
 */
int	apic_restrict_vector = 0;

#define	APIC_DEBUG_MSGBUFSIZE	2048
int	apic_debug_msgbuf[APIC_DEBUG_MSGBUFSIZE];
int	apic_debug_msgbufindex = 0;

/*
 * Put "int" info into debug buffer. No MP consistency, but light weight.
 * Good enough for most debugging.
 */
#define	APIC_DEBUG_BUF_PUT(x) \
	apic_debug_msgbuf[apic_debug_msgbufindex++] = x; \
	if (apic_debug_msgbufindex >= (APIC_DEBUG_MSGBUFSIZE - NCPU)) \
		apic_debug_msgbufindex = 0;

#endif /* DEBUG */

apic_cpus_info_t	*apic_cpus;

static uint_t	apic_cpumask = 0;
static uint_t	apic_flag;

/* Flag to indicate that we need to shut down all processors */
static uint_t	apic_shutdown_processors;

uint_t apic_nsec_per_intr = 0;

/*
 * apic_let_idle_redistribute can have the following values:
 * 0 - If clock decremented it from 1 to 0, clock has to call redistribute.
 * apic_redistribute_lock prevents multiple idle cpus from redistributing
 */
int	apic_num_idle_redistributions = 0;
static	int apic_let_idle_redistribute = 0;
static	uint_t apic_nticks = 0;
static	uint_t apic_skipped_redistribute = 0;

/* to gather intr data and redistribute */
static void apic_redistribute_compute(void);

static	uint_t last_count_read = 0;
static	lock_t	apic_gethrtime_lock;
volatile int	apic_hrtime_stamp = 0;
volatile hrtime_t apic_nsec_since_boot = 0;
static uint_t apic_hertz_count, apic_nsec_per_tick;
static hrtime_t apic_nsec_max;

static	hrtime_t	apic_last_hrtime = 0;
int		apic_hrtime_error = 0;
int		apic_remote_hrterr = 0;
int		apic_num_nmis = 0;
int		apic_apic_error = 0;
int		apic_num_apic_errors = 0;
int		apic_num_cksum_errors = 0;

static	uchar_t	apic_io_id[MAX_IO_APIC];
static	uchar_t	apic_io_ver[MAX_IO_APIC];
static	uchar_t	apic_io_vectbase[MAX_IO_APIC];
static	uchar_t	apic_io_vectend[MAX_IO_APIC];
volatile int32_t *apicioadr[MAX_IO_APIC];

/*
 * First available slot to be used as IRQ index into the apic_irq_table
 * for those interrupts (like MSI/X) that don't have a physical IRQ.
 */
int apic_first_avail_irq  = APIC_FIRST_FREE_IRQ;

/*
 * apic_ioapic_lock protects the ioapics (reg select), the status, temp_bound
 * and bound elements of cpus_info and the temp_cpu element of irq_struct
 */
lock_t	apic_ioapic_lock;

/*
 * apic_ioapic_reprogram_lock prevents a CPU from exiting
 * apic_intr_exit before IOAPIC reprogramming information
 * is collected.
 */
static	lock_t	apic_ioapic_reprogram_lock;
static	int	apic_io_max = 0;	/* no. of i/o apics enabled */

static	struct apic_io_intr *apic_io_intrp = 0;
static	struct apic_bus	*apic_busp;

uchar_t	apic_vector_to_irq[APIC_MAX_VECTOR+1];
static	uchar_t	apic_resv_vector[MAXIPL+1];

static	char	apic_level_intr[APIC_MAX_VECTOR+1];
static	int	apic_error = 0;
/* values which apic_error can take. Not catastrophic, but may help debug */
#define	APIC_ERR_BOOT_EOI		0x1
#define	APIC_ERR_GET_IPIVECT_FAIL	0x2
#define	APIC_ERR_INVALID_INDEX		0x4
#define	APIC_ERR_MARK_VECTOR_FAIL	0x8
#define	APIC_ERR_APIC_ERROR		0x40000000
#define	APIC_ERR_NMI			0x80000000

static	int	apic_cmos_ssb_set = 0;

static	uint32_t	eisa_level_intr_mask = 0;
	/* At least MSB will be set if EISA bus */

static	int	apic_pci_bus_total = 0;
static	uchar_t	apic_single_pci_busid = 0;


/*
 * airq_mutex protects additions to the apic_irq_table - the first
 * pointer and any airq_nexts off of that one. It also protects
 * apic_max_device_irq & apic_min_device_irq. It also guarantees
 * that share_id is unique as new ids are generated only when new
 * irq_t structs are linked in. Once linked in the structs are never
 * deleted. temp_cpu & mps_intr_index field indicate if it is programmed
 * or allocated. Note that there is a slight gap between allocating in
 * apic_introp_xlate and programming in addspl.
 */
kmutex_t	airq_mutex;
apic_irq_t	*apic_irq_table[APIC_MAX_VECTOR+1];
int		apic_max_device_irq = 0;
int		apic_min_device_irq = APIC_MAX_VECTOR;

/* use to make sure only one cpu handles the nmi */
static	lock_t	apic_nmi_lock;
/* use to make sure only one cpu handles the error interrupt */
static	lock_t	apic_error_lock;

/*
 * Following declarations are for revectoring; used when ISRs at different
 * IPLs share an irq.
 */
static	lock_t	apic_revector_lock;
static	int	apic_revector_pending = 0;
static	uchar_t	*apic_oldvec_to_newvec;
static	uchar_t	*apic_newvec_to_oldvec;

/* Ensures that the IOAPIC-reprogramming timeout is not reentrant */
static	kmutex_t	apic_reprogram_timeout_mutex;

static	struct	ioapic_reprogram_data {
	int		valid;	 /* This entry is valid */
	int		bindcpu; /* The CPU to which the int will be bound */
	unsigned	timeouts; /* # times the reprogram timeout was called */
} apic_reprogram_info[APIC_MAX_VECTOR+1];
/*
 * APIC_MAX_VECTOR + 1 is the maximum # of IRQs as well. apic_reprogram_info
 * is indexed by IRQ number, NOT by vector number.
 */


/*
 * The following added to identify a software poweroff method if available.
 */

static struct {
	int	poweroff_method;
	char	oem_id[APIC_MPS_OEM_ID_LEN + 1];	/* MAX + 1 for NULL */
	char	prod_id[APIC_MPS_PROD_ID_LEN + 1];	/* MAX + 1 for NULL */
} apic_mps_ids[] = {
	{ APIC_POWEROFF_VIA_RTC,	"INTEL",	"ALDER" },   /* 4300 */
	{ APIC_POWEROFF_VIA_RTC,	"NCR",		"AMC" },    /* 4300 */
	{ APIC_POWEROFF_VIA_ASPEN_BMC,	"INTEL",	"A450NX" },  /* 4400? */
	{ APIC_POWEROFF_VIA_ASPEN_BMC,	"INTEL",	"AD450NX" }, /* 4400 */
	{ APIC_POWEROFF_VIA_ASPEN_BMC,	"INTEL",	"AC450NX" }, /* 4400R */
	{ APIC_POWEROFF_VIA_SITKA_BMC,	"INTEL",	"S450NX" },  /* S50  */
	{ APIC_POWEROFF_VIA_SITKA_BMC,	"INTEL",	"SC450NX" }  /* S50? */
};

int	apic_poweroff_method = APIC_POWEROFF_NONE;

static	struct {
	uchar_t	cntl;
	uchar_t	data;
} aspen_bmc[] = {
	{ CC_SMS_WR_START,	0x18 },		/* NetFn/LUN */
	{ CC_SMS_WR_NEXT,	0x24 },		/* Cmd SET_WATCHDOG_TIMER */
	{ CC_SMS_WR_NEXT,	0x84 },		/* DataByte 1: SMS/OS no log */
	{ CC_SMS_WR_NEXT,	0x2 },		/* DataByte 2: Power Down */
	{ CC_SMS_WR_NEXT,	0x0 },		/* DataByte 3: no pre-timeout */
	{ CC_SMS_WR_NEXT,	0x0 },		/* DataByte 4: timer expir. */
	{ CC_SMS_WR_NEXT,	0xa },		/* DataByte 5: init countdown */
	{ CC_SMS_WR_END,	0x0 },		/* DataByte 6: init countdown */

	{ CC_SMS_WR_START,	0x18 },		/* NetFn/LUN */
	{ CC_SMS_WR_END,	0x22 }		/* Cmd RESET_WATCHDOG_TIMER */
};

static	struct {
	int	port;
	uchar_t	data;
} sitka_bmc[] = {
	{ SMS_COMMAND_REGISTER,	SMS_WRITE_START },
	{ SMS_DATA_REGISTER,	0x18 },		/* NetFn/LUN */
	{ SMS_DATA_REGISTER,	0x24 },		/* Cmd SET_WATCHDOG_TIMER */
	{ SMS_DATA_REGISTER,	0x84 },		/* DataByte 1: SMS/OS no log */
	{ SMS_DATA_REGISTER,	0x2 },		/* DataByte 2: Power Down */
	{ SMS_DATA_REGISTER,	0x0 },		/* DataByte 3: no pre-timeout */
	{ SMS_DATA_REGISTER,	0x0 },		/* DataByte 4: timer expir. */
	{ SMS_DATA_REGISTER,	0xa },		/* DataByte 5: init countdown */
	{ SMS_COMMAND_REGISTER,	SMS_WRITE_END },
	{ SMS_DATA_REGISTER,	0x0 },		/* DataByte 6: init countdown */

	{ SMS_COMMAND_REGISTER,	SMS_WRITE_START },
	{ SMS_DATA_REGISTER,	0x18 },		/* NetFn/LUN */
	{ SMS_COMMAND_REGISTER,	SMS_WRITE_END },
	{ SMS_DATA_REGISTER,	0x22 }		/* Cmd RESET_WATCHDOG_TIMER */
};


/* Patchable global variables. */
int		apic_kmdb_on_nmi = 0;		/* 0 - no, 1 - yes enter kmdb */
int		apic_debug_mps_id = 0;		/* 1 - print MPS ID strings */

/*
 * ACPI definitions
 */
/* _PIC method arguments */
#define	ACPI_PIC_MODE	0
#define	ACPI_APIC_MODE	1

/* APIC error flags we care about */
#define	APIC_SEND_CS_ERROR	0x01
#define	APIC_RECV_CS_ERROR	0x02
#define	APIC_CS_ERRORS		(APIC_SEND_CS_ERROR|APIC_RECV_CS_ERROR)

/*
 * ACPI variables
 */
/* 1 = acpi is enabled & working, 0 = acpi is not enabled or not there */
static	int apic_enable_acpi = 0;

/* ACPI Multiple APIC Description Table ptr */
static	MULTIPLE_APIC_TABLE *acpi_mapic_dtp = NULL;

/* ACPI Interrupt Source Override Structure ptr */
static	MADT_INTERRUPT_OVERRIDE *acpi_isop = NULL;
static	int acpi_iso_cnt = 0;

/* ACPI Non-maskable Interrupt Sources ptr */
static	MADT_NMI_SOURCE *acpi_nmi_sp = NULL;
static	int acpi_nmi_scnt = 0;
static	MADT_LOCAL_APIC_NMI *acpi_nmi_cp = NULL;
static	int acpi_nmi_ccnt = 0;

/*
 * extern declarations
 */
extern	int	intr_clear(void);
extern	void	intr_restore(uint_t);
#if defined(__amd64)
extern	int	intpri_use_cr8;
#endif	/* __amd64 */

extern int	apic_pci_msi_enable_vector(dev_info_t *, int, int,
		    int, int, int);
extern apic_irq_t *apic_find_irq(dev_info_t *, struct intrspec *, int);

/*
 *	This is the loadable module wrapper
 */

int
_init(void)
{
	if (apic_coarse_hrtime)
		apic_ops.psm_gethrtime = &apic_gettime;
	return (psm_mod_init(&apic_hdlp, &apic_psm_info));
}

int
_fini(void)
{
	return (psm_mod_fini(&apic_hdlp, &apic_psm_info));
}

int
_info(struct modinfo *modinfop)
{
	return (psm_mod_info(&apic_hdlp, &apic_psm_info, modinfop));
}

/*
 * Auto-configuration routines
 */

/*
 * Look at MPSpec 1.4 (Intel Order # 242016-005) for details of what we do here
 * May work with 1.1 - but not guaranteed.
 * According to the MP Spec, the MP floating pointer structure
 * will be searched in the order described below:
 * 1. In the first kilobyte of Extended BIOS Data Area (EBDA)
 * 2. Within the last kilobyte of system base memory
 * 3. In the BIOS ROM address space between 0F0000h and 0FFFFh
 * Once we find the right signature with proper checksum, we call
 * either handle_defconf or parse_mpct to get all info necessary for
 * subsequent operations.
 */
static int
apic_probe()
{
	uint32_t mpct_addr, ebda_start = 0, base_mem_end;
	caddr_t	biosdatap;
	caddr_t	mpct;
	caddr_t	fptr;
	int	i, mpct_size, mapsize, retval = PSM_FAILURE;
	ushort_t	ebda_seg, base_mem_size;
	struct	apic_mpfps_hdr	*fpsp;
	struct	apic_mp_cnf_hdr	*hdrp;
	int bypass_cpu_and_ioapics_in_mptables;
	int acpi_user_options;

	if (apic_forceload < 0)
		return (retval);

	/* Allow override for MADT-only mode */
	acpi_user_options = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    "acpi-user-options", 0);
	apic_use_acpi_madt_only = ((acpi_user_options & ACPI_OUSER_MADT) != 0);

	/* Allow apic_use_acpi to override MADT-only mode */
	if (!apic_use_acpi)
		apic_use_acpi_madt_only = 0;

	retval = acpi_probe();

	/*
	 * mapin the bios data area 40:0
	 * 40:13h - two-byte location reports the base memory size
	 * 40:0Eh - two-byte location for the exact starting address of
	 *	    the EBDA segment for EISA
	 */
	biosdatap = psm_map_phys(0x400, 0x20, PROT_READ);
	if (!biosdatap)
		return (retval);
	fpsp = (struct apic_mpfps_hdr *)NULL;
	mapsize = MPFPS_RAM_WIN_LEN;
	/*LINTED: pointer cast may result in improper alignment */
	ebda_seg = *((ushort_t *)(biosdatap+0xe));
	/* check the 1k of EBDA */
	if (ebda_seg) {
		ebda_start = ((uint32_t)ebda_seg) << 4;
		fptr = psm_map_phys(ebda_start, MPFPS_RAM_WIN_LEN, PROT_READ);
		if (fptr) {
			if (!(fpsp =
			    apic_find_fps_sig(fptr, MPFPS_RAM_WIN_LEN)))
				psm_unmap_phys(fptr, MPFPS_RAM_WIN_LEN);
		}
	}
	/* If not in EBDA, check the last k of system base memory */
	if (!fpsp) {
		/*LINTED: pointer cast may result in improper alignment */
		base_mem_size = *((ushort_t *)(biosdatap + 0x13));

		if (base_mem_size > 512)
			base_mem_end = 639 * 1024;
		else
			base_mem_end = 511 * 1024;
		/* if ebda == last k of base mem, skip to check BIOS ROM */
		if (base_mem_end != ebda_start) {

			fptr = psm_map_phys(base_mem_end, MPFPS_RAM_WIN_LEN,
			    PROT_READ);

			if (fptr) {
				if (!(fpsp = apic_find_fps_sig(fptr,
				    MPFPS_RAM_WIN_LEN)))
					psm_unmap_phys(fptr, MPFPS_RAM_WIN_LEN);
			}
		}
	}
	psm_unmap_phys(biosdatap, 0x20);

	/* If still cannot find it, check the BIOS ROM space */
	if (!fpsp) {
		mapsize = MPFPS_ROM_WIN_LEN;
		fptr = psm_map_phys(MPFPS_ROM_WIN_START,
		    MPFPS_ROM_WIN_LEN, PROT_READ);
		if (fptr) {
			if (!(fpsp =
			    apic_find_fps_sig(fptr, MPFPS_ROM_WIN_LEN))) {
				psm_unmap_phys(fptr, MPFPS_ROM_WIN_LEN);
				return (retval);
			}
		}
	}

	if (apic_checksum((caddr_t)fpsp, fpsp->mpfps_length * 16) != 0) {
		psm_unmap_phys(fptr, MPFPS_ROM_WIN_LEN);
		return (retval);
	}

	apic_spec_rev = fpsp->mpfps_spec_rev;
	if ((apic_spec_rev != 04) && (apic_spec_rev != 01)) {
		psm_unmap_phys(fptr, MPFPS_ROM_WIN_LEN);
		return (retval);
	}

	/* check IMCR is present or not */
	apic_imcrp = fpsp->mpfps_featinfo2 & MPFPS_FEATINFO2_IMCRP;

	/* check default configuration (dual CPUs) */
	if ((apic_defconf = fpsp->mpfps_featinfo1) != 0) {
		psm_unmap_phys(fptr, mapsize);
		return (apic_handle_defconf());
	}

	/* MP Configuration Table */
	mpct_addr = (uint32_t)(fpsp->mpfps_mpct_paddr);

	psm_unmap_phys(fptr, mapsize); /* unmap floating ptr struct */

	/*
	 * Map in enough memory for the MP Configuration Table Header.
	 * Use this table to read the total length of the BIOS data and
	 * map in all the info
	 */
	/*LINTED: pointer cast may result in improper alignment */
	hdrp = (struct apic_mp_cnf_hdr *)psm_map_phys(mpct_addr,
	    sizeof (struct apic_mp_cnf_hdr), PROT_READ);
	if (!hdrp)
		return (retval);

	/* check mp configuration table signature PCMP */
	if (hdrp->mpcnf_sig != 0x504d4350) {
		psm_unmap_phys((caddr_t)hdrp, sizeof (struct apic_mp_cnf_hdr));
		return (retval);
	}
	mpct_size = (int)hdrp->mpcnf_tbl_length;

	apic_set_pwroff_method_from_mpcnfhdr(hdrp);

	psm_unmap_phys((caddr_t)hdrp, sizeof (struct apic_mp_cnf_hdr));

	if ((retval == PSM_SUCCESS) && !apic_use_acpi_madt_only) {
		/* This is an ACPI machine No need for further checks */
		return (retval);
	}

	/*
	 * Map in the entries for this machine, ie. Processor
	 * Entry Tables, Bus Entry Tables, etc.
	 * They are in fixed order following one another
	 */
	mpct = psm_map_phys(mpct_addr, mpct_size, PROT_READ);
	if (!mpct)
		return (retval);

	if (apic_checksum(mpct, mpct_size) != 0)
		goto apic_fail1;


	/*LINTED: pointer cast may result in improper alignment */
	hdrp = (struct apic_mp_cnf_hdr *)mpct;
	/*LINTED: pointer cast may result in improper alignment */
	apicadr = (uint32_t *)psm_map_phys((uint32_t)hdrp->mpcnf_local_apic,
	    APIC_LOCAL_MEMLEN, PROT_READ | PROT_WRITE);
	if (!apicadr)
		goto apic_fail1;

	/* Parse all information in the tables */
	bypass_cpu_and_ioapics_in_mptables = (retval == PSM_SUCCESS);
	if (apic_parse_mpct(mpct, bypass_cpu_and_ioapics_in_mptables) ==
	    PSM_SUCCESS)
		return (PSM_SUCCESS);

	for (i = 0; i < apic_io_max; i++)
		psm_unmap_phys((caddr_t)apicioadr[i], APIC_IO_MEMLEN);
	if (apic_cpus)
		kmem_free(apic_cpus, sizeof (*apic_cpus) * apic_nproc);
	if (apicadr)
		psm_unmap_phys((caddr_t)apicadr, APIC_LOCAL_MEMLEN);
apic_fail1:
	psm_unmap_phys(mpct, mpct_size);
	return (retval);
}

static void
apic_set_pwroff_method_from_mpcnfhdr(struct apic_mp_cnf_hdr *hdrp)
{
	int	i;

	for (i = 0; i < (sizeof (apic_mps_ids) / sizeof (apic_mps_ids[0]));
	    i++) {
		if ((strncmp(hdrp->mpcnf_oem_str, apic_mps_ids[i].oem_id,
		    strlen(apic_mps_ids[i].oem_id)) == 0) &&
		    (strncmp(hdrp->mpcnf_prod_str, apic_mps_ids[i].prod_id,
		    strlen(apic_mps_ids[i].prod_id)) == 0)) {

			apic_poweroff_method = apic_mps_ids[i].poweroff_method;
			break;
		}
	}

	if (apic_debug_mps_id != 0) {
		cmn_err(CE_CONT, "pcplusmp: MPS OEM ID = '%c%c%c%c%c%c%c%c'"
		    "Product ID = '%c%c%c%c%c%c%c%c%c%c%c%c'\n",
		    hdrp->mpcnf_oem_str[0],
		    hdrp->mpcnf_oem_str[1],
		    hdrp->mpcnf_oem_str[2],
		    hdrp->mpcnf_oem_str[3],
		    hdrp->mpcnf_oem_str[4],
		    hdrp->mpcnf_oem_str[5],
		    hdrp->mpcnf_oem_str[6],
		    hdrp->mpcnf_oem_str[7],
		    hdrp->mpcnf_prod_str[0],
		    hdrp->mpcnf_prod_str[1],
		    hdrp->mpcnf_prod_str[2],
		    hdrp->mpcnf_prod_str[3],
		    hdrp->mpcnf_prod_str[4],
		    hdrp->mpcnf_prod_str[5],
		    hdrp->mpcnf_prod_str[6],
		    hdrp->mpcnf_prod_str[7],
		    hdrp->mpcnf_prod_str[8],
		    hdrp->mpcnf_prod_str[9],
		    hdrp->mpcnf_prod_str[10],
		    hdrp->mpcnf_prod_str[11]);
	}
}

static int
acpi_probe(void)
{
	int			i, id, intmax, ver, index, rv;
	int			acpi_verboseflags = 0;
	int			madt_seen, madt_size;
	APIC_HEADER		*ap;
	MADT_PROCESSOR_APIC	*mpa;
	MADT_IO_APIC		*mia;
	MADT_IO_SAPIC		*misa;
	MADT_INTERRUPT_OVERRIDE	*mio;
	MADT_NMI_SOURCE		*mns;
	MADT_INTERRUPT_SOURCE	*mis;
	MADT_LOCAL_APIC_NMI	*mlan;
	MADT_ADDRESS_OVERRIDE	*mao;
	ACPI_OBJECT_LIST 	arglist;
	ACPI_OBJECT		arg;
	int			sci;
	iflag_t			sci_flags;
	volatile int32_t	*ioapic;
	char			local_ids[NCPU];
	char			proc_ids[NCPU];
	uchar_t			hid;

	if (!apic_use_acpi)
		return (PSM_FAILURE);

	if (AcpiGetFirmwareTable(APIC_SIG, 1, ACPI_LOGICAL_ADDRESSING,
	    (ACPI_TABLE_HEADER **) &acpi_mapic_dtp) != AE_OK)
		return (PSM_FAILURE);

	apicadr = (uint32_t *)psm_map_phys(
	    (uint32_t)acpi_mapic_dtp->LocalApicAddress,
	    APIC_LOCAL_MEMLEN, PROT_READ | PROT_WRITE);
	if (!apicadr)
		return (PSM_FAILURE);

	id = apicadr[APIC_LID_REG];
	local_ids[0] = (uchar_t)(((uint_t)id) >> 24);
	apic_nproc = index = 1;
	apic_io_max = 0;

	ap = (APIC_HEADER *) (acpi_mapic_dtp + 1);
	madt_size = acpi_mapic_dtp->Length;
	madt_seen = sizeof (*acpi_mapic_dtp);

	while (madt_seen < madt_size) {
		switch (ap->Type) {
		case APIC_PROCESSOR:
			mpa = (MADT_PROCESSOR_APIC *) ap;
			if (mpa->ProcessorEnabled) {
				if (mpa->LocalApicId == local_ids[0])
					proc_ids[0] = mpa->ProcessorId;
				else if (apic_nproc < NCPU) {
					local_ids[index] = mpa->LocalApicId;
					proc_ids[index] = mpa->ProcessorId;
					index++;
					apic_nproc++;
				} else
					cmn_err(CE_WARN, "pcplusmp: exceeded "
					    "maximum no. of CPUs (= %d)", NCPU);
			}
			break;

		case APIC_IO:
			mia = (MADT_IO_APIC *) ap;
			if (apic_io_max < MAX_IO_APIC) {
				apic_io_id[apic_io_max] = mia->IoApicId;
				apic_io_vectbase[apic_io_max] =
				    mia->Interrupt;
				ioapic = apicioadr[apic_io_max] =
				    (int32_t *)psm_map_phys(
				    (uint32_t)mia->Address,
				    APIC_IO_MEMLEN, PROT_READ | PROT_WRITE);
				if (!ioapic)
					goto cleanup;
				apic_io_max++;
			}
			break;

		case APIC_XRUPT_OVERRIDE:
			mio = (MADT_INTERRUPT_OVERRIDE *) ap;
			if (acpi_isop == NULL)
				acpi_isop = mio;
			acpi_iso_cnt++;
			break;

		case APIC_NMI:
			/* UNIMPLEMENTED */
			mns = (MADT_NMI_SOURCE *) ap;
			if (acpi_nmi_sp == NULL)
				acpi_nmi_sp = mns;
			acpi_nmi_scnt++;

			cmn_err(CE_NOTE, "!apic: nmi source: %d %d %d\n",
				mns->Interrupt, mns->Polarity,
				mns->TriggerMode);
			break;

		case APIC_LOCAL_NMI:
			/* UNIMPLEMENTED */
			mlan = (MADT_LOCAL_APIC_NMI *) ap;
			if (acpi_nmi_cp == NULL)
				acpi_nmi_cp = mlan;
			acpi_nmi_ccnt++;

			cmn_err(CE_NOTE, "!apic: local nmi: %d %d %d %d\n",
				mlan->ProcessorId, mlan->Polarity,
				mlan->TriggerMode, mlan->Lint);
			break;

		case APIC_ADDRESS_OVERRIDE:
			/* UNIMPLEMENTED */
			mao = (MADT_ADDRESS_OVERRIDE *) ap;
			cmn_err(CE_NOTE, "!apic: address override: %lx\n",
				(long)mao->Address);
			break;

		case APIC_IO_SAPIC:
			/* UNIMPLEMENTED */
			misa = (MADT_IO_SAPIC *) ap;

			cmn_err(CE_NOTE, "!apic: io sapic: %d %d %lx\n",
				misa->IoSapicId, misa->InterruptBase,
				(long)misa->Address);
			break;

		case APIC_XRUPT_SOURCE:
			/* UNIMPLEMENTED */
			mis = (MADT_INTERRUPT_SOURCE *) ap;

			cmn_err(CE_NOTE,
				"!apic: irq source: %d %d %d %d %d %d %d\n",
				mis->ProcessorId, mis->ProcessorEid,
				mis->Interrupt, mis->Polarity,
				mis->TriggerMode, mis->InterruptType,
				mis->IoSapicVector);
			break;
		case APIC_RESERVED:
		default:
			goto cleanup;
		}

		/* advance to next entry */
		madt_seen += ap->Length;
		ap = (APIC_HEADER *)(((char *)ap) + ap->Length);
	}

	if ((apic_cpus = kmem_zalloc(sizeof (*apic_cpus) * apic_nproc,
	    KM_NOSLEEP)) == NULL)
		goto cleanup;

	apic_cpumask = (1 << apic_nproc) - 1;

	/*
	 * ACPI doesn't provide the local apic ver, get it directly from the
	 * local apic
	 */
	ver = apicadr[APIC_VERS_REG];
	for (i = 0; i < apic_nproc; i++) {
		apic_cpus[i].aci_local_id = local_ids[i];
		apic_cpus[i].aci_local_ver = (uchar_t)(ver & 0xFF);
	}
	for (i = 0; i < apic_io_max; i++) {
		ioapic = apicioadr[i];

		/*
		 * need to check Sitka on the following acpi problem
		 * On the Sitka, the ioapic's apic_id field isn't reporting
		 * the actual io apic id. We have reported this problem
		 * to Intel. Until they fix the problem, we will get the
		 * actual id directly from the ioapic.
		 */
		ioapic[APIC_IO_REG] = APIC_ID_CMD;
		id = ioapic[APIC_IO_DATA];
		hid = (uchar_t)(((uint_t)id) >> 24);

		if (hid != apic_io_id[i]) {
			if (apic_io_id[i] == 0)
				apic_io_id[i] = hid;
			else { /* set ioapic id to whatever reported by ACPI */
				id = ((int32_t)apic_io_id[i]) << 24;
				ioapic[APIC_IO_REG] = APIC_ID_CMD;
				ioapic[APIC_IO_DATA] = id;
			}
		}
		ioapic[APIC_IO_REG] = APIC_VERS_CMD;
		ver = ioapic[APIC_IO_DATA];
		apic_io_ver[i] = (uchar_t)(ver & 0xff);
		intmax = (ver >> 16) & 0xff;
		apic_io_vectend[i] = apic_io_vectbase[i] + intmax;
		if (apic_first_avail_irq <= apic_io_vectend[i])
			apic_first_avail_irq = apic_io_vectend[i] + 1;
	}


	/*
	 * Process SCI configuration here
	 * An error may be returned here if
	 * acpi-user-options specifies legacy mode
	 * (no SCI, no ACPI mode)
	 */
	if (acpica_get_sci(&sci, &sci_flags) != AE_OK)
		sci = -1;

	/*
	 * Now call acpi_init() to generate namespaces
	 * If this fails, we don't attempt to use ACPI
	 * even if we were able to get a MADT above
	 */
	if (acpica_init() != AE_OK)
		goto cleanup;

	/*
	 * Squirrel away the SCI and flags for later on
	 * in apic_picinit() when we're ready
	 */
	apic_sci_vect = sci;
	apic_sci_flags = sci_flags;

	if (apic_verbose & APIC_VERBOSE_IRQ_FLAG)
		acpi_verboseflags |= PSM_VERBOSE_IRQ_FLAG;

	if (apic_verbose & APIC_VERBOSE_POWEROFF_FLAG)
		acpi_verboseflags |= PSM_VERBOSE_POWEROFF_FLAG;

	if (apic_verbose & APIC_VERBOSE_POWEROFF_PAUSE_FLAG)
		acpi_verboseflags |= PSM_VERBOSE_POWEROFF_PAUSE_FLAG;

	if (acpi_psm_init(apic_psm_info.p_mach_idstring, acpi_verboseflags) ==
	    ACPI_PSM_FAILURE)
		goto cleanup;

	/* Enable ACPI APIC interrupt routing */
	arglist.Count = 1;
	arglist.Pointer = &arg;
	arg.Type = ACPI_TYPE_INTEGER;
	arg.Integer.Value = ACPI_APIC_MODE;	/* 1 */
	rv = AcpiEvaluateObject(NULL, "\\_PIC", &arglist, NULL);
	if (rv == AE_OK) {
		build_reserved_irqlist((uchar_t *)apic_reserved_irqlist);
		apic_enable_acpi = 1;
		if (apic_use_acpi_madt_only) {
			cmn_err(CE_CONT,
			    "?Using ACPI for CPU/IOAPIC information ONLY\n");
		}
		return (PSM_SUCCESS);
	}
	/* if setting APIC mode failed above, we fall through to cleanup */

cleanup:
	if (apicadr != NULL) {
		psm_unmap_phys((caddr_t)apicadr, APIC_LOCAL_MEMLEN);
		apicadr = NULL;
	}
	apic_nproc = 0;
	for (i = 0; i < apic_io_max; i++) {
		psm_unmap_phys((caddr_t)apicioadr[i], APIC_IO_MEMLEN);
		apicioadr[i] = NULL;
	}
	apic_io_max = 0;
	acpi_isop = NULL;
	acpi_iso_cnt = 0;
	acpi_nmi_sp = NULL;
	acpi_nmi_scnt = 0;
	acpi_nmi_cp = NULL;
	acpi_nmi_ccnt = 0;
	return (PSM_FAILURE);
}

/*
 * Handle default configuration. Fill in reqd global variables & tables
 * Fill all details as MP table does not give any more info
 */
static int
apic_handle_defconf()
{
	uint_t	lid;

	/*LINTED: pointer cast may result in improper alignment */
	apicioadr[0] = (int32_t *)psm_map_phys(APIC_IO_ADDR,
	    APIC_IO_MEMLEN, PROT_READ | PROT_WRITE);
	/*LINTED: pointer cast may result in improper alignment */
	apicadr = (uint32_t *)psm_map_phys(APIC_LOCAL_ADDR,
	    APIC_LOCAL_MEMLEN, PROT_READ | PROT_WRITE);
	apic_cpus = (apic_cpus_info_t *)
	    kmem_zalloc(sizeof (*apic_cpus) * 2, KM_NOSLEEP);
	if ((!apicadr) || (!apicioadr[0]) || (!apic_cpus))
		goto apic_handle_defconf_fail;
	apic_cpumask = 3;
	apic_nproc = 2;
	lid = apicadr[APIC_LID_REG];
	apic_cpus[0].aci_local_id = (uchar_t)(lid >> APIC_ID_BIT_OFFSET);
	/*
	 * According to the PC+MP spec 1.1, the local ids
	 * for the default configuration has to be 0 or 1
	 */
	if (apic_cpus[0].aci_local_id == 1)
		apic_cpus[1].aci_local_id = 0;
	else if (apic_cpus[0].aci_local_id == 0)
		apic_cpus[1].aci_local_id = 1;
	else
		goto apic_handle_defconf_fail;

	apic_io_id[0] = 2;
	apic_io_max = 1;
	if (apic_defconf >= 5) {
		apic_cpus[0].aci_local_ver = APIC_INTEGRATED_VERS;
		apic_cpus[1].aci_local_ver = APIC_INTEGRATED_VERS;
		apic_io_ver[0] = APIC_INTEGRATED_VERS;
	} else {
		apic_cpus[0].aci_local_ver = 0;		/* 82489 DX */
		apic_cpus[1].aci_local_ver = 0;
		apic_io_ver[0] = 0;
	}
	if (apic_defconf == 2 || apic_defconf == 3 || apic_defconf == 6)
		eisa_level_intr_mask = (inb(EISA_LEVEL_CNTL + 1) << 8) |
		    inb(EISA_LEVEL_CNTL) | ((uint_t)INT32_MAX + 1);
	return (PSM_SUCCESS);

apic_handle_defconf_fail:
	if (apic_cpus)
		kmem_free(apic_cpus, sizeof (*apic_cpus) * 2);
	if (apicadr)
		psm_unmap_phys((caddr_t)apicadr, APIC_LOCAL_MEMLEN);
	if (apicioadr[0])
		psm_unmap_phys((caddr_t)apicioadr[0], APIC_IO_MEMLEN);
	return (PSM_FAILURE);
}

/* Parse the entries in MP configuration table and collect info that we need */
static int
apic_parse_mpct(caddr_t mpct, int bypass_cpus_and_ioapics)
{
	struct	apic_procent	*procp;
	struct	apic_bus	*busp;
	struct	apic_io_entry	*ioapicp;
	struct	apic_io_intr	*intrp;
	volatile int32_t	*ioapic;
	uint_t	lid;
	int	id;
	uchar_t hid;

	/*LINTED: pointer cast may result in improper alignment */
	procp = (struct apic_procent *)(mpct + sizeof (struct apic_mp_cnf_hdr));

	/* No need to count cpu entries if we won't use them */
	if (!bypass_cpus_and_ioapics) {

		/* Find max # of CPUS and allocate structure accordingly */
		apic_nproc = 0;
		while (procp->proc_entry == APIC_CPU_ENTRY) {
			if (procp->proc_cpuflags & CPUFLAGS_EN) {
				apic_nproc++;
			}
			procp++;
		}
		if (apic_nproc > NCPU)
			cmn_err(CE_WARN, "pcplusmp: exceeded "
			    "maximum no. of CPUs (= %d)", NCPU);
		if (!apic_nproc || !(apic_cpus = (apic_cpus_info_t *)
		    kmem_zalloc(sizeof (*apic_cpus)*apic_nproc, KM_NOSLEEP)))
			return (PSM_FAILURE);
	}

	/*LINTED: pointer cast may result in improper alignment */
	procp = (struct apic_procent *)(mpct + sizeof (struct apic_mp_cnf_hdr));

	/*
	 * start with index 1 as 0 needs to be filled in with Boot CPU, but
	 * if we're bypassing this information, it has already been filled
	 * in by acpi_probe(), so don't overwrite it.
	 */
	if (!bypass_cpus_and_ioapics)
		apic_nproc = 1;

	while (procp->proc_entry == APIC_CPU_ENTRY) {
		/* check whether the cpu exists or not */
		if (!bypass_cpus_and_ioapics &&
		    procp->proc_cpuflags & CPUFLAGS_EN) {
			if (procp->proc_cpuflags & CPUFLAGS_BP) { /* Boot CPU */
				lid = apicadr[APIC_LID_REG];
				apic_cpus[0].aci_local_id = procp->proc_apicid;
				if (apic_cpus[0].aci_local_id !=
				    (uchar_t)(lid >> APIC_ID_BIT_OFFSET)) {
					return (PSM_FAILURE);
				}
				apic_cpus[0].aci_local_ver =
				    procp->proc_version;
			} else {

				apic_cpus[apic_nproc].aci_local_id =
				    procp->proc_apicid;
				apic_cpus[apic_nproc].aci_local_ver =
				    procp->proc_version;
				apic_nproc++;

			}
		}
		procp++;
	}

	if (!bypass_cpus_and_ioapics) {
		/* convert the number of processors into a cpumask */
		apic_cpumask = (1 << apic_nproc) - 1;
	}

	/*
	 * Save start of bus entries for later use.
	 * Get EISA level cntrl if EISA bus is present.
	 * Also get the CPI bus id for single CPI bus case
	 */
	apic_busp = busp = (struct apic_bus *)procp;
	while (busp->bus_entry == APIC_BUS_ENTRY) {
		lid = apic_find_bus_type((char *)&busp->bus_str1);
		if (lid	== BUS_EISA) {
			eisa_level_intr_mask = (inb(EISA_LEVEL_CNTL + 1) << 8) |
			    inb(EISA_LEVEL_CNTL) | ((uint_t)INT32_MAX + 1);
		} else if (lid == BUS_PCI) {
			/*
			 * apic_single_pci_busid will be used only if
			 * apic_pic_bus_total is equal to 1
			 */
			apic_pci_bus_total++;
			apic_single_pci_busid = busp->bus_id;
		}
		busp++;
	}

	ioapicp = (struct apic_io_entry *)busp;

	if (!bypass_cpus_and_ioapics)
		apic_io_max = 0;
	do {
		if (!bypass_cpus_and_ioapics && apic_io_max < MAX_IO_APIC) {
			if (ioapicp->io_flags & IOAPIC_FLAGS_EN) {
				apic_io_id[apic_io_max] = ioapicp->io_apicid;
				apic_io_ver[apic_io_max] = ioapicp->io_version;
		/*LINTED: pointer cast may result in improper alignment */
				apicioadr[apic_io_max] =
				    (int32_t *)psm_map_phys(
				    (uint32_t)ioapicp->io_apic_addr,
				    APIC_IO_MEMLEN, PROT_READ | PROT_WRITE);

				if (!apicioadr[apic_io_max])
					return (PSM_FAILURE);

				ioapic = apicioadr[apic_io_max];
				ioapic[APIC_IO_REG] = APIC_ID_CMD;
				id = ioapic[APIC_IO_DATA];
				hid = (uchar_t)(((uint_t)id) >> 24);

				if (hid != apic_io_id[apic_io_max]) {
					if (apic_io_id[apic_io_max] == 0)
						apic_io_id[apic_io_max] = hid;
					else {
						/*
						 * set ioapic id to whatever
						 * reported by MPS
						 *
						 * may not need to set index
						 * again ???
						 * take it out and try
						 */

						id = ((int32_t)
						    apic_io_id[apic_io_max]) <<
						    24;

						ioapic[APIC_IO_REG] =
						    APIC_ID_CMD;

						ioapic[APIC_IO_DATA] = id;

					}
				}
				apic_io_max++;
			}
		}
		ioapicp++;
	} while (ioapicp->io_entry == APIC_IO_ENTRY);

	apic_io_intrp = (struct apic_io_intr *)ioapicp;

	intrp = apic_io_intrp;
	while (intrp->intr_entry == APIC_IO_INTR_ENTRY) {
		if ((intrp->intr_irq > APIC_MAX_ISA_IRQ) ||
		    (apic_find_bus(intrp->intr_busid) == BUS_PCI)) {
			apic_irq_translate = 1;
			break;
		}
		intrp++;
	}

	return (PSM_SUCCESS);
}

static struct apic_mpfps_hdr *
apic_find_fps_sig(caddr_t cptr, int len)
{
	int	i;

	/* Look for the pattern "_MP_" */
	for (i = 0; i < len; i += 16) {
		if ((*(cptr+i) == '_') &&
		    (*(cptr+i+1) == 'M') &&
		    (*(cptr+i+2) == 'P') &&
		    (*(cptr+i+3) == '_'))
		    /*LINTED: pointer cast may result in improper alignment */
			return ((struct apic_mpfps_hdr *)(cptr + i));
	}
	return (NULL);
}

static int
apic_checksum(caddr_t bptr, int len)
{
	int	i;
	uchar_t	cksum;

	cksum = 0;
	for (i = 0; i < len; i++)
		cksum += *bptr++;
	return ((int)cksum);
}


/*
 * Initialise vector->ipl and ipl->pri arrays. level_intr and irqtable
 * are also set to NULL. vector->irq is set to a value which cannot map
 * to a real irq to show that it is free.
 */
void
apic_init()
{
	int	i;
	int	*iptr;

	int	j = 1;
	apic_ipltopri[0] = APIC_VECTOR_PER_IPL; /* leave 0 for idle */
	for (i = 0; i < (APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL); i++) {
		if ((i < ((APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL) - 1)) &&
		    (apic_vectortoipl[i + 1] == apic_vectortoipl[i]))
			/* get to highest vector at the same ipl */
			continue;
		for (; j <= apic_vectortoipl[i]; j++) {
			apic_ipltopri[j] = (i << APIC_IPL_SHIFT) +
			    APIC_BASE_VECT;
		}
	}
	for (; j < MAXIPL + 1; j++)
		/* fill up any empty ipltopri slots */
		apic_ipltopri[j] = (i << APIC_IPL_SHIFT) + APIC_BASE_VECT;

	/* cpu 0 is always up */
	apic_cpus[0].aci_status = APIC_CPU_ONLINE | APIC_CPU_INTR_ENABLE;

	iptr = (int *)&apic_irq_table[0];
	for (i = 0; i <= APIC_MAX_VECTOR; i++) {
		apic_level_intr[i] = 0;
		*iptr++ = NULL;
		apic_vector_to_irq[i] = APIC_RESV_IRQ;
		apic_reprogram_info[i].valid = 0;
		apic_reprogram_info[i].bindcpu = 0;
		apic_reprogram_info[i].timeouts = 0;
	}

	/*
	 * Allocate a dummy irq table entry for the reserved entry.
	 * This takes care of the race between removing an irq and
	 * clock detecting a CPU in that irq during interrupt load
	 * sampling.
	 */
	apic_irq_table[APIC_RESV_IRQ] =
	    kmem_zalloc(sizeof (apic_irq_t), KM_NOSLEEP);

	mutex_init(&airq_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&apic_reprogram_timeout_mutex, NULL, MUTEX_DEFAULT, NULL);
#if defined(__amd64)
	/*
	 * Make cpu-specific interrupt info point to cr8pri vector
	 */
	for (i = 0; i <= MAXIPL; i++)
		apic_cr8pri[i] = apic_ipltopri[i] >> APIC_IPL_SHIFT;
	CPU->cpu_pri_data = apic_cr8pri;
	intpri_use_cr8 = 1;
#endif	/* __amd64 */
}

/*
 * handler for APIC Error interrupt. Just print a warning and continue
 */
static int
apic_error_intr()
{
	uint_t	error0, error1, error;
	uint_t	i;

	/*
	 * We need to write before read as per 7.4.17 of system prog manual.
	 * We do both and or the results to be safe
	 */
	error0 = apicadr[APIC_ERROR_STATUS];
	apicadr[APIC_ERROR_STATUS] = 0;
	error1 = apicadr[APIC_ERROR_STATUS];
	error = error0 | error1;

	/*
	 * Clear the APIC error status (do this on all cpus that enter here)
	 * (two writes are required due to the semantics of accessing the
	 * error status register.)
	 */
	apicadr[APIC_ERROR_STATUS] = 0;
	apicadr[APIC_ERROR_STATUS] = 0;

	/*
	 * Prevent more than 1 CPU from handling error interrupt causing
	 * double printing (interleave of characters from multiple
	 * CPU's when using prom_printf)
	 */
	if (lock_try(&apic_error_lock) == 0)
		return (error ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
	if (error) {
#if	DEBUG
		if (apic_debug)
			debug_enter("pcplusmp: APIC Error interrupt received");
#endif /* DEBUG */
		if (apic_panic_on_apic_error)
			cmn_err(CE_PANIC,
			    "APIC Error interrupt on CPU %d. Status = %x\n",
			    psm_get_cpu_id(), error);
		else {
			if ((error & ~APIC_CS_ERRORS) == 0) {
				/* cksum error only */
				apic_error |= APIC_ERR_APIC_ERROR;
				apic_apic_error |= error;
				apic_num_apic_errors++;
				apic_num_cksum_errors++;
			} else {
				/*
				 * prom_printf is the best shot we have of
				 * something which is problem free from
				 * high level/NMI type of interrupts
				 */
				prom_printf("APIC Error interrupt on CPU %d. "
				    "Status 0 = %x, Status 1 = %x\n",
				    psm_get_cpu_id(), error0, error1);
				apic_error |= APIC_ERR_APIC_ERROR;
				apic_apic_error |= error;
				apic_num_apic_errors++;
				for (i = 0; i < apic_error_display_delay; i++) {
					tenmicrosec();
				}
				/*
				 * provide more delay next time limited to
				 * roughly 1 clock tick time
				 */
				if (apic_error_display_delay < 500)
					apic_error_display_delay *= 2;
			}
		}
		lock_clear(&apic_error_lock);
		return (DDI_INTR_CLAIMED);
	} else {
		lock_clear(&apic_error_lock);
		return (DDI_INTR_UNCLAIMED);
	}
	/* NOTREACHED */
}

/*
 * Turn off the mask bit in the performance counter Local Vector Table entry.
 */
static void
apic_cpcovf_mask_clear(void)
{
	apicadr[APIC_PCINT_VECT] &= ~APIC_LVT_MASK;
}

static void
apic_init_intr()
{
	processorid_t	cpun = psm_get_cpu_id();

#if defined(__amd64)
	setcr8((ulong_t)(APIC_MASK_ALL >> APIC_IPL_SHIFT));
#else
	apicadr[APIC_TASK_REG] = APIC_MASK_ALL;
#endif

	if (apic_flat_model)
		apicadr[APIC_FORMAT_REG] = APIC_FLAT_MODEL;
	else
		apicadr[APIC_FORMAT_REG] = APIC_CLUSTER_MODEL;
	apicadr[APIC_DEST_REG] = AV_HIGH_ORDER >> cpun;

	/* need to enable APIC before unmasking NMI */
	apicadr[APIC_SPUR_INT_REG] = AV_UNIT_ENABLE | APIC_SPUR_INTR;

	apicadr[APIC_LOCAL_TIMER] = AV_MASK;
	apicadr[APIC_INT_VECT0]	= AV_MASK;	/* local intr reg 0 */
	apicadr[APIC_INT_VECT1] = AV_NMI;	/* enable NMI */

	if (apic_cpus[cpun].aci_local_ver < APIC_INTEGRATED_VERS)
		return;

	/* Enable performance counter overflow interrupt */

	if ((x86_feature & X86_MSR) != X86_MSR)
		apic_enable_cpcovf_intr = 0;
	if (apic_enable_cpcovf_intr) {
		if (apic_cpcovf_vect == 0) {
			int ipl = APIC_PCINT_IPL;
			int irq = apic_get_ipivect(ipl, -1);

			ASSERT(irq != -1);
			apic_cpcovf_vect = apic_irq_table[irq]->airq_vector;
			ASSERT(apic_cpcovf_vect);
			(void) add_avintr(NULL, ipl,
			    (avfunc)kcpc_hw_overflow_intr,
			    "apic pcint", irq, NULL, NULL, NULL);
			kcpc_hw_overflow_intr_installed = 1;
			kcpc_hw_enable_cpc_intr = apic_cpcovf_mask_clear;
		}
		apicadr[APIC_PCINT_VECT] = apic_cpcovf_vect;
	}

	/* Enable error interrupt */

	if (apic_enable_error_intr) {
		if (apic_errvect == 0) {
			int ipl = 0xf;	/* get highest priority intr */
			int irq = apic_get_ipivect(ipl, -1);

			ASSERT(irq != -1);
			apic_errvect = apic_irq_table[irq]->airq_vector;
			ASSERT(apic_errvect);
			/*
			 * Not PSMI compliant, but we are going to merge
			 * with ON anyway
			 */
			(void) add_avintr((void *)NULL, ipl,
			    (avfunc)apic_error_intr, "apic error intr",
			    irq, NULL, NULL, NULL);
		}
		apicadr[APIC_ERR_VECT] = apic_errvect;
		apicadr[APIC_ERROR_STATUS] = 0;
		apicadr[APIC_ERROR_STATUS] = 0;
	}
}

static void
apic_disable_local_apic()
{
	apicadr[APIC_TASK_REG] = APIC_MASK_ALL;
	apicadr[APIC_LOCAL_TIMER] = AV_MASK;
	apicadr[APIC_INT_VECT0] = AV_MASK;	/* local intr reg 0 */
	apicadr[APIC_INT_VECT1] = AV_MASK;	/* disable NMI */
	apicadr[APIC_ERR_VECT] = AV_MASK;	/* and error interrupt */
	apicadr[APIC_PCINT_VECT] = AV_MASK;	/* and perf counter intr */
	apicadr[APIC_SPUR_INT_REG] = APIC_SPUR_INTR;
}

static void
apic_picinit(void)
{
	int i, j;
	uint_t isr;
	volatile int32_t *ioapic;
	apic_irq_t	*irqptr;
	struct intrspec ispec;

	/*
	 * On UniSys Model 6520, the BIOS leaves vector 0x20 isr
	 * bit on without clearing it with EOI.  Since softint
	 * uses vector 0x20 to interrupt itself, so softint will
	 * not work on this machine.  In order to fix this problem
	 * a check is made to verify all the isr bits are clear.
	 * If not, EOIs are issued to clear the bits.
	 */
	for (i = 7; i >= 1; i--) {
		if ((isr = apicadr[APIC_ISR_REG + (i * 4)]) != 0)
			for (j = 0; ((j < 32) && (isr != 0)); j++)
				if (isr & (1 << j)) {
					apicadr[APIC_EOI_REG] = 0;
					isr &= ~(1 << j);
					apic_error |= APIC_ERR_BOOT_EOI;
				}
	}

	/* set a flag so we know we have run apic_picinit() */
	apic_flag = 1;
	LOCK_INIT_CLEAR(&apic_gethrtime_lock);
	LOCK_INIT_CLEAR(&apic_ioapic_lock);
	LOCK_INIT_CLEAR(&apic_revector_lock);
	LOCK_INIT_CLEAR(&apic_ioapic_reprogram_lock);
	LOCK_INIT_CLEAR(&apic_error_lock);

	picsetup();	 /* initialise the 8259 */

	/* add nmi handler - least priority nmi handler */
	LOCK_INIT_CLEAR(&apic_nmi_lock);

	if (!psm_add_nmintr(0, (avfunc) apic_nmi_intr,
	    "pcplusmp NMI handler", (caddr_t)NULL))
		cmn_err(CE_WARN, "pcplusmp: Unable to add nmi handler");

	apic_init_intr();

	/* enable apic mode if imcr present */
	if (apic_imcrp) {
		outb(APIC_IMCR_P1, (uchar_t)APIC_IMCR_SELECT);
		outb(APIC_IMCR_P2, (uchar_t)APIC_IMCR_APIC);
	}

	/* mask interrupt vectors					*/
	for (j = 0; j < apic_io_max; j++) {
		int intin_max;
		ioapic = apicioadr[j];
		ioapic[APIC_IO_REG] = APIC_VERS_CMD;
		/* Bits 23-16 define the maximum redirection entries */
		intin_max = (ioapic[APIC_IO_DATA] >> 16) & 0xff;
		for (i = 0; i < intin_max; i++) {
			ioapic[APIC_IO_REG] = APIC_RDT_CMD + 2 * i;
			ioapic[APIC_IO_DATA] = AV_MASK;
		}
	}

	/*
	 * Hack alert: deal with ACPI SCI interrupt chicken/egg here
	 */
	if (apic_sci_vect > 0) {
		/*
		 * acpica has already done add_avintr(); we just
		 * to finish the job by mimicing translate_irq()
		 *
		 * Fake up an intrspec and setup the tables
		 */
		ispec.intrspec_vec = apic_sci_vect;
		ispec.intrspec_pri = SCI_IPL;

		if (apic_setup_irq_table(NULL, apic_sci_vect, NULL,
		    &ispec, &apic_sci_flags, DDI_INTR_TYPE_FIXED) < 0) {
			cmn_err(CE_WARN, "!apic: SCI setup failed");
			return;
		}
		irqptr = apic_irq_table[apic_sci_vect];

		/* Program I/O APIC */
		(void) apic_setup_io_intr(irqptr, apic_sci_vect);
	}
}


static void
apic_cpu_start(processorid_t cpun, caddr_t rm_code)
{
	int		loop_count;
	uint32_t	vector;
	uint_t		cpu_id, iflag;

	cpu_id = apic_cpus[cpun].aci_local_id;

	apic_cmos_ssb_set = 1;

	/*
	 * Interrupts on BSP cpu will be disabled during these startup
	 * steps in order to avoid unwanted side effects from
	 * executing interrupt handlers on a problematic BIOS.
	 */

	iflag = intr_clear();
	outb(CMOS_ADDR, SSB);
	outb(CMOS_DATA, BIOS_SHUTDOWN);

	while (get_apic_cmd1() & AV_PENDING)
		apic_ret();

	/* for integrated - make sure there is one INIT IPI in buffer */
	/* for external - it will wake up the cpu */
	apicadr[APIC_INT_CMD2] = cpu_id << APIC_ICR_ID_BIT_OFFSET;
	apicadr[APIC_INT_CMD1] = AV_ASSERT | AV_RESET;

	/* If only 1 CPU is installed, PENDING bit will not go low */
	for (loop_count = 0x1000; loop_count; loop_count--)
		if (get_apic_cmd1() & AV_PENDING)
			apic_ret();
		else
			break;

	apicadr[APIC_INT_CMD2] = cpu_id << APIC_ICR_ID_BIT_OFFSET;
	apicadr[APIC_INT_CMD1] = AV_DEASSERT | AV_RESET;

	drv_usecwait(20000);		/* 20 milli sec */

	if (apic_cpus[cpun].aci_local_ver >= APIC_INTEGRATED_VERS) {
		/* integrated apic */

		rm_code = (caddr_t)(uintptr_t)rm_platter_pa;
		vector = (rm_platter_pa >> MMU_PAGESHIFT) &
		    (APIC_VECTOR_MASK | APIC_IPL_MASK);

		/* to offset the INIT IPI queue up in the buffer */
		apicadr[APIC_INT_CMD2] = cpu_id << APIC_ICR_ID_BIT_OFFSET;
		apicadr[APIC_INT_CMD1] = vector | AV_STARTUP;

		drv_usecwait(200);		/* 20 micro sec */

		apicadr[APIC_INT_CMD2] = cpu_id << APIC_ICR_ID_BIT_OFFSET;
		apicadr[APIC_INT_CMD1] = vector | AV_STARTUP;

		drv_usecwait(200);		/* 20 micro sec */
	}
	intr_restore(iflag);
}


#ifdef	DEBUG
int	apic_break_on_cpu = 9;
int	apic_stretch_interrupts = 0;
int	apic_stretch_ISR = 1 << 3;	/* IPL of 3 matches nothing now */

void
apic_break()
{
}
#endif /* DEBUG */

/*
 * platform_intr_enter
 *
 *	Called at the beginning of the interrupt service routine to
 *	mask all level equal to and below the interrupt priority
 *	of the interrupting vector.  An EOI should be given to
 *	the interrupt controller to enable other HW interrupts.
 *
 *	Return -1 for spurious interrupts
 *
 */
/*ARGSUSED*/
static int
apic_intr_enter(int ipl, int *vectorp)
{
	uchar_t vector;
	int nipl;
	int irq, iflag;
	apic_cpus_info_t *cpu_infop;

	/*
	 * The real vector programmed in APIC is *vectorp + 0x20
	 * But, cmnint code subtracts 0x20 before pushing it.
	 * Hence APIC_BASE_VECT is 0x20.
	 */

	vector = (uchar_t)*vectorp;

	/* if interrupted by the clock, increment apic_nsec_since_boot */
	if (vector == apic_clkvect) {
		if (!apic_oneshot) {
			/* NOTE: this is not MT aware */
			apic_hrtime_stamp++;
			apic_nsec_since_boot += apic_nsec_per_intr;
			apic_hrtime_stamp++;
			last_count_read = apic_hertz_count;
			apic_redistribute_compute();
		}

		/* We will avoid all the book keeping overhead for clock */
		nipl = apic_vectortoipl[vector >> APIC_IPL_SHIFT];
#if defined(__amd64)
		setcr8((ulong_t)apic_cr8pri[nipl]);
#else
		apicadr[APIC_TASK_REG] = apic_ipltopri[nipl];
#endif
		*vectorp = apic_vector_to_irq[vector + APIC_BASE_VECT];
		apicadr[APIC_EOI_REG] = 0;
		return (nipl);
	}

	cpu_infop = &apic_cpus[psm_get_cpu_id()];

	if (vector == (APIC_SPUR_INTR - APIC_BASE_VECT)) {
		cpu_infop->aci_spur_cnt++;
		return (APIC_INT_SPURIOUS);
	}

	/* Check if the vector we got is really what we need */
	if (apic_revector_pending) {
		/*
		 * Disable interrupts for the duration of
		 * the vector translation to prevent a self-race for
		 * the apic_revector_lock.  This cannot be done
		 * in apic_xlate_vector because it is recursive and
		 * we want the vector translation to be atomic with
		 * respect to other (higher-priority) interrupts.
		 */
		iflag = intr_clear();
		vector = apic_xlate_vector(vector + APIC_BASE_VECT) -
		    APIC_BASE_VECT;
		intr_restore(iflag);
	}

	nipl = apic_vectortoipl[vector >> APIC_IPL_SHIFT];
	*vectorp = irq = apic_vector_to_irq[vector + APIC_BASE_VECT];

#if defined(__amd64)
	setcr8((ulong_t)apic_cr8pri[nipl]);
#else
	apicadr[APIC_TASK_REG] = apic_ipltopri[nipl];
#endif

	cpu_infop->aci_current[nipl] = (uchar_t)irq;
	cpu_infop->aci_curipl = (uchar_t)nipl;
	cpu_infop->aci_ISR_in_progress |= 1 << nipl;

	/*
	 * apic_level_intr could have been assimilated into the irq struct.
	 * but, having it as a character array is more efficient in terms of
	 * cache usage. So, we leave it as is.
	 */
	if (!apic_level_intr[irq])
		apicadr[APIC_EOI_REG] = 0;

#ifdef	DEBUG
	APIC_DEBUG_BUF_PUT(vector);
	APIC_DEBUG_BUF_PUT(irq);
	APIC_DEBUG_BUF_PUT(nipl);
	APIC_DEBUG_BUF_PUT(psm_get_cpu_id());
	if ((apic_stretch_interrupts) && (apic_stretch_ISR & (1 << nipl)))
		drv_usecwait(apic_stretch_interrupts);

	if (apic_break_on_cpu == psm_get_cpu_id())
		apic_break();
#endif /* DEBUG */
	return (nipl);
}

static void
apic_intr_exit(int prev_ipl, int irq)
{
	apic_cpus_info_t *cpu_infop;

#if defined(__amd64)
	setcr8((ulong_t)apic_cr8pri[prev_ipl]);
#else
	apicadr[APIC_TASK_REG] = apic_ipltopri[prev_ipl];
#endif

	cpu_infop = &apic_cpus[psm_get_cpu_id()];
	if (apic_level_intr[irq])
		apicadr[APIC_EOI_REG] = 0;

	cpu_infop->aci_curipl = (uchar_t)prev_ipl;
	/* ISR above current pri could not be in progress */
	cpu_infop->aci_ISR_in_progress &= (2 << prev_ipl) - 1;
}

/*
 * Mask all interrupts below or equal to the given IPL
 */
static void
apic_setspl(int ipl)
{

#if defined(__amd64)
	setcr8((ulong_t)apic_cr8pri[ipl]);
#else
	apicadr[APIC_TASK_REG] = apic_ipltopri[ipl];
#endif

	/* interrupts at ipl above this cannot be in progress */
	apic_cpus[psm_get_cpu_id()].aci_ISR_in_progress &= (2 << ipl) - 1;
	/*
	 * this is a patch fix for the ALR QSMP P5 machine, so that interrupts
	 * have enough time to come in before the priority is raised again
	 * during the idle() loop.
	 */
	if (apic_setspl_delay)
		(void) get_apic_pri();
}

/*
 * trigger a software interrupt at the given IPL
 */
static void
apic_set_softintr(int ipl)
{
	int vector;
	uint_t flag;

	vector = apic_resv_vector[ipl];

	flag = intr_clear();

	while (get_apic_cmd1() & AV_PENDING)
		apic_ret();

	/* generate interrupt at vector on itself only */
	apicadr[APIC_INT_CMD1] = AV_SH_SELF | vector;

	intr_restore(flag);
}

/*
 * generates an interprocessor interrupt to another CPU
 */
static void
apic_send_ipi(int cpun, int ipl)
{
	int vector;
	uint_t flag;

	vector = apic_resv_vector[ipl];

	flag = intr_clear();

	while (get_apic_cmd1() & AV_PENDING)
		apic_ret();

	apicadr[APIC_INT_CMD2] =
	    apic_cpus[cpun].aci_local_id << APIC_ICR_ID_BIT_OFFSET;
	apicadr[APIC_INT_CMD1] = vector;

	intr_restore(flag);
}


/*ARGSUSED*/
static void
apic_set_idlecpu(processorid_t cpun)
{
}

/*ARGSUSED*/
static void
apic_unset_idlecpu(processorid_t cpun)
{
}


static void
apic_ret()
{
}

static int
get_apic_cmd1()
{
	return (apicadr[APIC_INT_CMD1]);
}

static int
get_apic_pri()
{
#if defined(__amd64)
	return ((int)getcr8());
#else
	return (apicadr[APIC_TASK_REG]);
#endif
}

/*
 * If apic_coarse_time == 1, then apic_gettime() is used instead of
 * apic_gethrtime().  This is used for performance instead of accuracy.
 */

static hrtime_t
apic_gettime()
{
	int old_hrtime_stamp;
	hrtime_t temp;

	/*
	 * In one-shot mode, we do not keep time, so if anyone
	 * calls psm_gettime() directly, we vector over to
	 * gethrtime().
	 * one-shot mode MUST NOT be enabled if this psm is the source of
	 * hrtime.
	 */

	if (apic_oneshot)
		return (gethrtime());


gettime_again:
	while ((old_hrtime_stamp = apic_hrtime_stamp) & 1)
		apic_ret();

	temp = apic_nsec_since_boot;

	if (apic_hrtime_stamp != old_hrtime_stamp) {	/* got an interrupt */
		goto gettime_again;
	}
	return (temp);
}

/*
 * Here we return the number of nanoseconds since booting.  Note every
 * clock interrupt increments apic_nsec_since_boot by the appropriate
 * amount.
 */
static hrtime_t
apic_gethrtime()
{
	int curr_timeval, countval, elapsed_ticks, oflags;
	int old_hrtime_stamp, status;
	hrtime_t temp;
	uchar_t	cpun;


	/*
	 * In one-shot mode, we do not keep time, so if anyone
	 * calls psm_gethrtime() directly, we vector over to
	 * gethrtime().
	 * one-shot mode MUST NOT be enabled if this psm is the source of
	 * hrtime.
	 */

	if (apic_oneshot)
		return (gethrtime());

	oflags = intr_clear();	/* prevent migration */

	cpun = (uchar_t)((uint_t)apicadr[APIC_LID_REG] >> APIC_ID_BIT_OFFSET);

	lock_set(&apic_gethrtime_lock);

gethrtime_again:
	while ((old_hrtime_stamp = apic_hrtime_stamp) & 1)
		apic_ret();

	/*
	 * Check to see which CPU we are on.  Note the time is kept on
	 * the local APIC of CPU 0.  If on CPU 0, simply read the current
	 * counter.  If on another CPU, issue a remote read command to CPU 0.
	 */
	if (cpun == apic_cpus[0].aci_local_id) {
		countval = apicadr[APIC_CURR_COUNT];
	} else {
		while (get_apic_cmd1() & AV_PENDING)
			apic_ret();

		apicadr[APIC_INT_CMD2] =
		    apic_cpus[0].aci_local_id << APIC_ICR_ID_BIT_OFFSET;
		apicadr[APIC_INT_CMD1] = APIC_CURR_ADD|AV_REMOTE;

		while ((status = get_apic_cmd1()) & AV_READ_PENDING)
			apic_ret();

		if (status & AV_REMOTE_STATUS)	/* 1 = valid */
			countval = apicadr[APIC_REMOTE_READ];
		else {	/* 0 = invalid */
			apic_remote_hrterr++;
			/*
			 * return last hrtime right now, will need more
			 * testing if change to retry
			 */
			temp = apic_last_hrtime;

			lock_clear(&apic_gethrtime_lock);

			intr_restore(oflags);

			return (temp);
		}
	}
	if (countval > last_count_read)
		countval = 0;
	else
		last_count_read = countval;

	elapsed_ticks = apic_hertz_count - countval;

	curr_timeval = elapsed_ticks * apic_nsec_per_tick;
	temp = apic_nsec_since_boot + curr_timeval;

	if (apic_hrtime_stamp != old_hrtime_stamp) {	/* got an interrupt */
		/* we might have clobbered last_count_read. Restore it */
		last_count_read = apic_hertz_count;
		goto gethrtime_again;
	}

	if (temp < apic_last_hrtime) {
		/* return last hrtime if error occurs */
		apic_hrtime_error++;
		temp = apic_last_hrtime;
	}
	else
		apic_last_hrtime = temp;

	lock_clear(&apic_gethrtime_lock);
	intr_restore(oflags);

	return (temp);
}

/* apic NMI handler */
/*ARGSUSED*/
static void
apic_nmi_intr(caddr_t arg)
{
	if (apic_shutdown_processors) {
		apic_disable_local_apic();
		return;
	}

	if (lock_try(&apic_nmi_lock)) {
		if (apic_kmdb_on_nmi) {
			if (psm_debugger() == 0) {
				cmn_err(CE_PANIC,
				    "NMI detected, kmdb is not available.");
			} else {
				debug_enter("\nNMI detected, entering kmdb.\n");
			}
		} else {
			if (apic_panic_on_nmi) {
				/* Keep panic from entering kmdb. */
				nopanicdebug = 1;
				cmn_err(CE_PANIC, "pcplusmp: NMI received");
			} else {
				/*
				 * prom_printf is the best shot we have
				 * of something which is problem free from
				 * high level/NMI type of interrupts
				 */
				prom_printf("pcplusmp: NMI received\n");
				apic_error |= APIC_ERR_NMI;
				apic_num_nmis++;
			}
		}
		lock_clear(&apic_nmi_lock);
	}
}

/*
 * Add mask bits to disable interrupt vector from happening
 * at or above IPL. In addition, it should remove mask bits
 * to enable interrupt vectors below the given IPL.
 *
 * Both add and delspl are complicated by the fact that different interrupts
 * may share IRQs. This can happen in two ways.
 * 1. The same H/W line is shared by more than 1 device
 * 1a. with interrupts at different IPLs
 * 1b. with interrupts at same IPL
 * 2. We ran out of vectors at a given IPL and started sharing vectors.
 * 1b and 2 should be handled gracefully, except for the fact some ISRs
 * will get called often when no interrupt is pending for the device.
 * For 1a, we just hope that the machine blows up with the person who
 * set it up that way!. In the meantime, we handle it at the higher IPL.
 */
/*ARGSUSED*/
static int
apic_addspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	uchar_t vector;
	int iflag;
	apic_irq_t *irqptr, *irqheadptr;
	int irqindex;

	ASSERT(max_ipl <= UCHAR_MAX);
	irqindex = IRQINDEX(irqno);

	if ((irqindex == -1) || (!apic_irq_table[irqindex]))
		return (PSM_FAILURE);

	irqptr = irqheadptr = apic_irq_table[irqindex];

	DDI_INTR_IMPLDBG((CE_CONT, "apic_addspl: dip=0x%p type=%d irqno=0x%x "
	    "vector=0x%x\n", (void *)irqptr->airq_dip,
	    irqptr->airq_mps_intr_index, irqno, irqptr->airq_vector));

	while (irqptr) {
		if (VIRTIRQ(irqindex, irqptr->airq_share_id) == irqno)
			break;
		irqptr = irqptr->airq_next;
	}
	irqptr->airq_share++;

	/* return if it is not hardware interrupt */
	if (irqptr->airq_mps_intr_index == RESERVE_INDEX)
		return (PSM_SUCCESS);

	/* Or if there are more interupts at a higher IPL */
	if (ipl != max_ipl)
		return (PSM_SUCCESS);

	/*
	 * if apic_picinit() has not been called yet, just return.
	 * At the end of apic_picinit(), we will call setup_io_intr().
	 */

	if (!apic_flag)
		return (PSM_SUCCESS);

	iflag = intr_clear();

	/*
	 * Upgrade vector if max_ipl is not earlier ipl. If we cannot allocate,
	 * return failure. Not very elegant, but then we hope the
	 * machine will blow up with ...
	 */
	if (irqptr->airq_ipl != max_ipl) {
		vector = apic_allocate_vector(max_ipl, irqindex, 1);
		if (vector == 0) {
			intr_restore(iflag);
			irqptr->airq_share--;
			return (PSM_FAILURE);
		}
		irqptr = irqheadptr;
		apic_mark_vector(irqptr->airq_vector, vector);
		while (irqptr) {
			irqptr->airq_vector = vector;
			irqptr->airq_ipl = (uchar_t)max_ipl;
			/*
			 * reprogram irq being added and every one else
			 * who is not in the UNINIT state
			 */
			if ((VIRTIRQ(irqindex, irqptr->airq_share_id) ==
			    irqno) || (irqptr->airq_temp_cpu != IRQ_UNINIT)) {
				apic_record_rdt_entry(irqptr, irqindex);
				(void) apic_setup_io_intr(irqptr, irqindex);
			}
			irqptr = irqptr->airq_next;
		}
		intr_restore(iflag);
		return (PSM_SUCCESS);
	}

	ASSERT(irqptr);
	(void) apic_setup_io_intr(irqptr, irqindex);
	intr_restore(iflag);
	return (PSM_SUCCESS);
}

/*
 * Recompute mask bits for the given interrupt vector.
 * If there is no interrupt servicing routine for this
 * vector, this function should disable interrupt vector
 * from happening at all IPLs. If there are still
 * handlers using the given vector, this function should
 * disable the given vector from happening below the lowest
 * IPL of the remaining hadlers.
 */
/*ARGSUSED*/
static int
apic_delspl(int irqno, int ipl, int min_ipl, int max_ipl)
{
	uchar_t vector, bind_cpu;
	int	iflag, intin, irqindex;
	volatile int32_t *ioapic;
	apic_irq_t	*irqptr, *irqheadptr;

	irqindex = IRQINDEX(irqno);
	irqptr = irqheadptr = apic_irq_table[irqindex];

	DDI_INTR_IMPLDBG((CE_CONT, "apic_delspl: dip=0x%p type=%d irqno=0x%x "
	    "vector=0x%x\n", (void *)irqptr->airq_dip,
	    irqptr->airq_mps_intr_index, irqno, irqptr->airq_vector));

	while (irqptr) {
		if (VIRTIRQ(irqindex, irqptr->airq_share_id) == irqno)
			break;
		irqptr = irqptr->airq_next;
	}
	ASSERT(irqptr);

	irqptr->airq_share--;

	if (ipl < max_ipl)
		return (PSM_SUCCESS);

	/* return if it is not hardware interrupt */
	if (irqptr->airq_mps_intr_index == RESERVE_INDEX)
		return (PSM_SUCCESS);

	if (!apic_flag) {
		/*
		 * Clear irq_struct. If two devices shared an intpt
		 * line & 1 unloaded before picinit, we are hosed. But, then
		 * we hope the machine will ...
		 */
		irqptr->airq_mps_intr_index = FREE_INDEX;
		irqptr->airq_temp_cpu = IRQ_UNINIT;
		apic_free_vector(irqptr->airq_vector);
		return (PSM_SUCCESS);
	}
	/*
	 * Downgrade vector to new max_ipl if needed.If we cannot allocate,
	 * use old IPL. Not very elegant, but then we hope ...
	 */
	if ((irqptr->airq_ipl != max_ipl) && (max_ipl != PSM_INVALID_IPL)) {
		apic_irq_t	*irqp;
		if (vector = apic_allocate_vector(max_ipl, irqno, 1)) {
			apic_mark_vector(irqheadptr->airq_vector, vector);
			irqp = irqheadptr;
			while (irqp) {
				irqp->airq_vector = vector;
				irqp->airq_ipl = (uchar_t)max_ipl;
				if (irqp->airq_temp_cpu != IRQ_UNINIT) {
					apic_record_rdt_entry(irqp, irqindex);
					(void) apic_setup_io_intr(irqp,
					    irqindex);
				}
				irqp = irqp->airq_next;
			}
		}
	}

	if (irqptr->airq_share)
		return (PSM_SUCCESS);

	ioapic = apicioadr[irqptr->airq_ioapicindex];
	intin = irqptr->airq_intin_no;
	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);
	ioapic[APIC_IO_REG] = APIC_RDT_CMD + 2 * intin;
	ioapic[APIC_IO_DATA] = AV_MASK;

	/* Disable the MSI/X vector */
	if (APIC_IS_MSI_OR_MSIX_INDEX(irqptr->airq_mps_intr_index)) {
		int type = (irqptr->airq_mps_intr_index == MSI_INDEX) ?
		    DDI_INTR_TYPE_MSI : DDI_INTR_TYPE_MSIX;

		/*
		 * Make sure we only disable on the last
		 * of the multi-MSI support
		 */
		if (i_ddi_intr_get_current_nintrs(irqptr->airq_dip) == 1) {
			(void) pci_msi_unconfigure(irqptr->airq_dip, type,
			    irqptr->airq_ioapicindex);

			(void) pci_msi_disable_mode(irqptr->airq_dip, type,
			    irqptr->airq_ioapicindex);
		}
	}

	if (max_ipl == PSM_INVALID_IPL) {
		ASSERT(irqheadptr == irqptr);
		bind_cpu = irqptr->airq_temp_cpu;
		if (((uchar_t)bind_cpu != IRQ_UNBOUND) &&
		    ((uchar_t)bind_cpu != IRQ_UNINIT)) {
			ASSERT((bind_cpu & ~IRQ_USER_BOUND) < apic_nproc);
			if (bind_cpu & IRQ_USER_BOUND) {
				/* If hardbound, temp_cpu == cpu */
				bind_cpu &= ~IRQ_USER_BOUND;
				apic_cpus[bind_cpu].aci_bound--;
			} else
				apic_cpus[bind_cpu].aci_temp_bound--;
		}
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
		irqptr->airq_temp_cpu = IRQ_UNINIT;
		irqptr->airq_mps_intr_index = FREE_INDEX;
		apic_free_vector(irqptr->airq_vector);
		return (PSM_SUCCESS);
	}
	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	mutex_enter(&airq_mutex);
	if ((irqptr == apic_irq_table[irqindex])) {
		apic_irq_t	*oldirqptr;
		/* Move valid irq entry to the head */
		irqheadptr = oldirqptr = irqptr;
		irqptr = irqptr->airq_next;
		ASSERT(irqptr);
		while (irqptr) {
			if (irqptr->airq_mps_intr_index != FREE_INDEX)
				break;
			oldirqptr = irqptr;
			irqptr = irqptr->airq_next;
		}
		/* remove all invalid ones from the beginning */
		apic_irq_table[irqindex] = irqptr;
		/*
		 * and link them back after the head. The invalid ones
		 * begin with irqheadptr and end at oldirqptr
		 */
		oldirqptr->airq_next = irqptr->airq_next;
		irqptr->airq_next = irqheadptr;
	}
	mutex_exit(&airq_mutex);

	irqptr->airq_temp_cpu = IRQ_UNINIT;
	irqptr->airq_mps_intr_index = FREE_INDEX;
	return (PSM_SUCCESS);
}

/*
 * Return HW interrupt number corresponding to the given IPL
 */
/*ARGSUSED*/
static int
apic_softlvl_to_irq(int ipl)
{
	/*
	 * Do not use apic to trigger soft interrupt.
	 * It will cause the system to hang when 2 hardware interrupts
	 * at the same priority with the softint are already accepted
	 * by the apic.  Cause the AV_PENDING bit will not be cleared
	 * until one of the hardware interrupt is eoi'ed.  If we need
	 * to send an ipi at this time, we will end up looping forever
	 * to wait for the AV_PENDING bit to clear.
	 */
	return (PSM_SV_SOFTWARE);
}

static int
apic_post_cpu_start()
{
	int i, cpun;
	apic_irq_t *irq_ptr;

	apic_init_intr();

	/*
	 * since some systems don't enable the internal cache on the non-boot
	 * cpus, so we have to enable them here
	 */
	setcr0(getcr0() & ~(0x60000000));

	while (get_apic_cmd1() & AV_PENDING)
		apic_ret();

	cpun = psm_get_cpu_id();
	apic_cpus[cpun].aci_status = APIC_CPU_ONLINE | APIC_CPU_INTR_ENABLE;

	for (i = apic_min_device_irq; i <= apic_max_device_irq; i++) {
		irq_ptr = apic_irq_table[i];
		if ((irq_ptr == NULL) ||
		    ((irq_ptr->airq_cpu & ~IRQ_USER_BOUND) != cpun))
			continue;

		while (irq_ptr) {
			if (irq_ptr->airq_temp_cpu != IRQ_UNINIT)
				(void) apic_rebind(irq_ptr, cpun, 1, IMMEDIATE);
			irq_ptr = irq_ptr->airq_next;
		}
	}

	return (PSM_SUCCESS);
}

processorid_t
apic_get_next_processorid(processorid_t cpu_id)
{

	int i;

	if (cpu_id == -1)
		return ((processorid_t)0);

	for (i = cpu_id + 1; i < NCPU; i++) {
		if (apic_cpumask & (1 << i))
			return (i);
	}

	return ((processorid_t)-1);
}


/*
 * type == -1 indicates it is an internal request. Do not change
 * resv_vector for these requests
 */
static int
apic_get_ipivect(int ipl, int type)
{
	uchar_t vector;
	int irq;

	if (irq = apic_allocate_irq(APIC_VECTOR(ipl))) {
		if (vector = apic_allocate_vector(ipl, irq, 1)) {
			apic_irq_table[irq]->airq_mps_intr_index =
			    RESERVE_INDEX;
			apic_irq_table[irq]->airq_vector = vector;
			if (type != -1) {
				apic_resv_vector[ipl] = vector;
			}
			return (irq);
		}
	}
	apic_error |= APIC_ERR_GET_IPIVECT_FAIL;
	return (-1);	/* shouldn't happen */
}

static int
apic_getclkirq(int ipl)
{
	int	irq;

	if ((irq = apic_get_ipivect(ipl, -1)) == -1)
		return (-1);
	/*
	 * Note the vector in apic_clkvect for per clock handling.
	 */
	apic_clkvect = apic_irq_table[irq]->airq_vector - APIC_BASE_VECT;
	APIC_VERBOSE_IOAPIC((CE_NOTE, "get_clkirq: vector = %x\n",
	    apic_clkvect));
	return (irq);
}

/*
 * Return the number of APIC clock ticks elapsed for 8245 to decrement
 * (APIC_TIME_COUNT + pit_ticks_adj) ticks.
 */
static uint_t
apic_calibrate(volatile uint32_t *addr, uint16_t *pit_ticks_adj)
{
	uint8_t		pit_tick_lo;
	uint16_t	pit_tick, target_pit_tick;
	uint32_t	start_apic_tick, end_apic_tick;
	int		iflag;

	addr += APIC_CURR_COUNT;

	iflag = intr_clear();

	do {
		pit_tick_lo = inb(PITCTR0_PORT);
		pit_tick = (inb(PITCTR0_PORT) << 8) | pit_tick_lo;
	} while (pit_tick < APIC_TIME_MIN ||
	    pit_tick_lo <= APIC_LB_MIN || pit_tick_lo >= APIC_LB_MAX);

	/*
	 * Wait for the 8254 to decrement by 5 ticks to ensure
	 * we didn't start in the middle of a tick.
	 * Compare with 0x10 for the wrap around case.
	 */
	target_pit_tick = pit_tick - 5;
	do {
		pit_tick_lo = inb(PITCTR0_PORT);
		pit_tick = (inb(PITCTR0_PORT) << 8) | pit_tick_lo;
	} while (pit_tick > target_pit_tick || pit_tick_lo < 0x10);

	start_apic_tick = *addr;

	/*
	 * Wait for the 8254 to decrement by
	 * (APIC_TIME_COUNT + pit_ticks_adj) ticks
	 */
	target_pit_tick = pit_tick - APIC_TIME_COUNT;
	do {
		pit_tick_lo = inb(PITCTR0_PORT);
		pit_tick = (inb(PITCTR0_PORT) << 8) | pit_tick_lo;
	} while (pit_tick > target_pit_tick || pit_tick_lo < 0x10);

	end_apic_tick = *addr;

	*pit_ticks_adj = target_pit_tick - pit_tick;

	intr_restore(iflag);

	return (start_apic_tick - end_apic_tick);
}

/*
 * Initialise the APIC timer on the local APIC of CPU 0 to the desired
 * frequency.  Note at this stage in the boot sequence, the boot processor
 * is the only active processor.
 * hertz value of 0 indicates a one-shot mode request.  In this case
 * the function returns the resolution (in nanoseconds) for the hardware
 * timer interrupt.  If one-shot mode capability is not available,
 * the return value will be 0. apic_enable_oneshot is a global switch
 * for disabling the functionality.
 * A non-zero positive value for hertz indicates a periodic mode request.
 * In this case the hardware will be programmed to generate clock interrupts
 * at hertz frequency and returns the resolution of interrupts in
 * nanosecond.
 */

static int
apic_clkinit(int hertz)
{

	uint_t		apic_ticks = 0;
	uint_t		pit_time;
	int		ret;
	uint16_t	pit_ticks_adj;
	static int	firsttime = 1;

	if (firsttime) {
		/* first time calibrate */

		apicadr[APIC_DIVIDE_REG] = 0x0;
		apicadr[APIC_INIT_COUNT] = APIC_MAXVAL;

		/* set periodic interrupt based on CLKIN */
		apicadr[APIC_LOCAL_TIMER] =
		    (apic_clkvect + APIC_BASE_VECT) | AV_TIME;
		tenmicrosec();

		apic_ticks = apic_calibrate(apicadr, &pit_ticks_adj);

		apicadr[APIC_LOCAL_TIMER] =
		    (apic_clkvect + APIC_BASE_VECT) | AV_MASK;
		/*
		 * pit time is the amount of real time (in nanoseconds ) it took
		 * the 8254 to decrement (APIC_TIME_COUNT + pit_ticks_adj) ticks
		 */
		pit_time = ((longlong_t)(APIC_TIME_COUNT +
		    pit_ticks_adj) * NANOSEC) / PIT_HZ;

		/*
		 * Determine the number of nanoseconds per APIC clock tick
		 * and then determine how many APIC ticks to interrupt at the
		 * desired frequency
		 */
		apic_nsec_per_tick = pit_time / apic_ticks;
		if (apic_nsec_per_tick == 0)
			apic_nsec_per_tick = 1;

		/* the interval timer initial count is 32 bit max */
		apic_nsec_max = (hrtime_t)apic_nsec_per_tick * APIC_MAXVAL;
		firsttime = 0;
	}

	if (hertz != 0) {
		/* periodic */
		apic_nsec_per_intr = NANOSEC / hertz;
		apic_hertz_count = (longlong_t)apic_nsec_per_intr /
		    apic_nsec_per_tick;
		apic_sample_factor_redistribution = hertz + 1;
	}

	apic_int_busy_mark = (apic_int_busy_mark *
	    apic_sample_factor_redistribution) / 100;
	apic_int_free_mark = (apic_int_free_mark *
	    apic_sample_factor_redistribution) / 100;
	apic_diff_for_redistribution = (apic_diff_for_redistribution *
	    apic_sample_factor_redistribution) / 100;

	if (hertz == 0) {
		/* requested one_shot */
		if (!apic_oneshot_enable)
			return (0);
		apic_oneshot = 1;
		ret = (int)apic_nsec_per_tick;
	} else {
		/* program the local APIC to interrupt at the given frequency */
		apicadr[APIC_INIT_COUNT] = apic_hertz_count;
		apicadr[APIC_LOCAL_TIMER] =
		    (apic_clkvect + APIC_BASE_VECT) | AV_TIME;
		apic_oneshot = 0;
		ret = NANOSEC / hertz;
	}

	return (ret);

}

/*
 * apic_preshutdown:
 * Called early in shutdown whilst we can still access filesystems to do
 * things like loading modules which will be required to complete shutdown
 * after filesystems are all unmounted.
 */
static void
apic_preshutdown(int cmd, int fcn)
{
	APIC_VERBOSE_POWEROFF(("apic_preshutdown(%d,%d); m=%d a=%d\n",
	    cmd, fcn, apic_poweroff_method, apic_enable_acpi));

	if ((cmd != A_SHUTDOWN) || (fcn != AD_POWEROFF)) {
		return;
	}
}

static void
apic_shutdown(int cmd, int fcn)
{
	int iflag, restarts, attempts;
	int i, j;
	volatile int32_t *ioapic;
	uchar_t	byte;

	/* Send NMI to all CPUs except self to do per processor shutdown */
	iflag = intr_clear();
	while (get_apic_cmd1() & AV_PENDING)
		apic_ret();
	apic_shutdown_processors = 1;
	apicadr[APIC_INT_CMD1] = AV_NMI | AV_LEVEL | AV_SH_ALL_EXCSELF;

	/* restore cmos shutdown byte before reboot */
	if (apic_cmos_ssb_set) {
		outb(CMOS_ADDR, SSB);
		outb(CMOS_DATA, 0);
	}
	/* Disable the I/O APIC redirection entries */
	for (j = 0; j < apic_io_max; j++) {
		int intin_max;
		ioapic = apicioadr[j];
		ioapic[APIC_IO_REG] = APIC_VERS_CMD;
		/* Bits 23-16 define the maximum redirection entries */
		intin_max = (ioapic[APIC_IO_DATA] >> 16) & 0xff;
		for (i = 0; i < intin_max; i++) {
			ioapic[APIC_IO_REG] = APIC_RDT_CMD + 2 * i;
			ioapic[APIC_IO_DATA] = AV_MASK;
		}
	}

	/*	disable apic mode if imcr present	*/
	if (apic_imcrp) {
		outb(APIC_IMCR_P1, (uchar_t)APIC_IMCR_SELECT);
		outb(APIC_IMCR_P2, (uchar_t)APIC_IMCR_PIC);
	}

	apic_disable_local_apic();

	intr_restore(iflag);

	if ((cmd != A_SHUTDOWN) || (fcn != AD_POWEROFF)) {
		return;
	}

	switch (apic_poweroff_method) {
		case APIC_POWEROFF_VIA_RTC:

			/* select the extended NVRAM bank in the RTC */
			outb(CMOS_ADDR, RTC_REGA);
			byte = inb(CMOS_DATA);
			outb(CMOS_DATA, (byte | EXT_BANK));

			outb(CMOS_ADDR, PFR_REG);

			/* for Predator must toggle the PAB bit */
			byte = inb(CMOS_DATA);

			/*
			 * clear power active bar, wakeup alarm and
			 * kickstart
			 */
			byte &= ~(PAB_CBIT | WF_FLAG | KS_FLAG);
			outb(CMOS_DATA, byte);

			/* delay before next write */
			drv_usecwait(1000);

			/* for S40 the following would suffice */
			byte = inb(CMOS_DATA);

			/* power active bar control bit */
			byte |= PAB_CBIT;
			outb(CMOS_DATA, byte);

			break;

		case APIC_POWEROFF_VIA_ASPEN_BMC:
			restarts = 0;
restart_aspen_bmc:
			if (++restarts == 3)
				break;
			attempts = 0;
			do {
				byte = inb(MISMIC_FLAG_REGISTER);
				byte &= MISMIC_BUSY_MASK;
				if (byte != 0) {
					drv_usecwait(1000);
					if (attempts >= 3)
						goto restart_aspen_bmc;
					++attempts;
				}
			} while (byte != 0);
			outb(MISMIC_CNTL_REGISTER, CC_SMS_GET_STATUS);
			byte = inb(MISMIC_FLAG_REGISTER);
			byte |= 0x1;
			outb(MISMIC_FLAG_REGISTER, byte);
			i = 0;
			for (; i < (sizeof (aspen_bmc)/sizeof (aspen_bmc[0]));
			    i++) {
				attempts = 0;
				do {
					byte = inb(MISMIC_FLAG_REGISTER);
					byte &= MISMIC_BUSY_MASK;
					if (byte != 0) {
						drv_usecwait(1000);
						if (attempts >= 3)
							goto restart_aspen_bmc;
						++attempts;
					}
				} while (byte != 0);
				outb(MISMIC_CNTL_REGISTER, aspen_bmc[i].cntl);
				outb(MISMIC_DATA_REGISTER, aspen_bmc[i].data);
				byte = inb(MISMIC_FLAG_REGISTER);
				byte |= 0x1;
				outb(MISMIC_FLAG_REGISTER, byte);
			}
			break;

		case APIC_POWEROFF_VIA_SITKA_BMC:
			restarts = 0;
restart_sitka_bmc:
			if (++restarts == 3)
				break;
			attempts = 0;
			do {
				byte = inb(SMS_STATUS_REGISTER);
				byte &= SMS_STATE_MASK;
				if ((byte == SMS_READ_STATE) ||
				    (byte == SMS_WRITE_STATE)) {
					drv_usecwait(1000);
					if (attempts >= 3)
						goto restart_sitka_bmc;
					++attempts;
				}
			} while ((byte == SMS_READ_STATE) ||
			    (byte == SMS_WRITE_STATE));
			outb(SMS_COMMAND_REGISTER, SMS_GET_STATUS);
			i = 0;
			for (; i < (sizeof (sitka_bmc)/sizeof (sitka_bmc[0]));
			    i++) {
				attempts = 0;
				do {
					byte = inb(SMS_STATUS_REGISTER);
					byte &= SMS_IBF_MASK;
					if (byte != 0) {
						drv_usecwait(1000);
						if (attempts >= 3)
							goto restart_sitka_bmc;
						++attempts;
					}
				} while (byte != 0);
				outb(sitka_bmc[i].port, sitka_bmc[i].data);
			}
			break;

		case APIC_POWEROFF_NONE:

			/* If no APIC direct method, we will try using ACPI */
			if (apic_enable_acpi) {
				if (acpi_poweroff() == 1)
					return;
			} else
				return;

			break;
	}
	/*
	 * Wait a limited time here for power to go off.
	 * If the power does not go off, then there was a
	 * problem and we should continue to the halt which
	 * prints a message for the user to press a key to
	 * reboot.
	 */
	drv_usecwait(7000000); /* wait seven seconds */

}

/*
 * Try and disable all interrupts. We just assign interrupts to other
 * processors based on policy. If any were bound by user request, we
 * let them continue and return failure. We do not bother to check
 * for cache affinity while rebinding.
 */

static int
apic_disable_intr(processorid_t cpun)
{
	int bind_cpu = 0, i, hardbound = 0, iflag;
	apic_irq_t *irq_ptr;

	if (cpun == 0)
		return (PSM_FAILURE);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);
	apic_cpus[cpun].aci_status &= ~APIC_CPU_INTR_ENABLE;
	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
	apic_cpus[cpun].aci_curipl = 0;
	i = apic_min_device_irq;
	for (; i <= apic_max_device_irq; i++) {
		/*
		 * If there are bound interrupts on this cpu, then
		 * rebind them to other processors.
		 */
		if ((irq_ptr = apic_irq_table[i]) != NULL) {
			ASSERT((irq_ptr->airq_temp_cpu == IRQ_UNBOUND) ||
			    (irq_ptr->airq_temp_cpu == IRQ_UNINIT) ||
			    ((irq_ptr->airq_temp_cpu & ~IRQ_USER_BOUND) <
			    apic_nproc));

			if (irq_ptr->airq_temp_cpu == (cpun | IRQ_USER_BOUND)) {
				hardbound = 1;
				continue;
			}

			if (irq_ptr->airq_temp_cpu == cpun) {
				do {
					apic_next_bind_cpu += 2;
					bind_cpu = apic_next_bind_cpu / 2;
					if (bind_cpu >= apic_nproc) {
						apic_next_bind_cpu = 1;
						bind_cpu = 0;

					}
				} while (apic_rebind_all(irq_ptr, bind_cpu, 1));
			}
		}
	}
	if (hardbound) {
		cmn_err(CE_WARN, "Could not disable interrupts on %d"
		    "due to user bound interrupts", cpun);
		return (PSM_FAILURE);
	}
	else
		return (PSM_SUCCESS);
}

static void
apic_enable_intr(processorid_t cpun)
{
	int	i, iflag;
	apic_irq_t *irq_ptr;

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);
	apic_cpus[cpun].aci_status |= APIC_CPU_INTR_ENABLE;
	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	i = apic_min_device_irq;
	for (i = apic_min_device_irq; i <= apic_max_device_irq; i++) {
		if ((irq_ptr = apic_irq_table[i]) != NULL) {
			if ((irq_ptr->airq_cpu & ~IRQ_USER_BOUND) == cpun) {
				(void) apic_rebind_all(irq_ptr,
				    irq_ptr->airq_cpu, 1);
			}
		}
	}
}

/*
 * apic_introp_xlate() replaces apic_translate_irq() and is
 * called only from apic_intr_ops().  With the new ADII framework,
 * the priority can no longer be retrived through i_ddi_get_intrspec().
 * It has to be passed in from the caller.
 */
int
apic_introp_xlate(dev_info_t *dip, struct intrspec *ispec, int type)
{
	char dev_type[16];
	int dev_len, pci_irq, newirq, bustype, devid, busid, i;
	int irqno = ispec->intrspec_vec;
	ddi_acc_handle_t cfg_handle;
	uchar_t ipin;
	struct apic_io_intr *intrp;
	iflag_t intr_flag;
	APIC_HEADER	*hp;
	MADT_INTERRUPT_OVERRIDE	*isop;
	apic_irq_t *airqp;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_introp_xlate: dip=0x%p name=%s "
	    "type=%d irqno=0x%x\n", (void *)dip, ddi_get_name(dip), type,
	    irqno));

	if (DDI_INTR_IS_MSI_OR_MSIX(type)) {
		if ((airqp = apic_find_irq(dip, ispec, type)) != NULL)
			return (apic_vector_to_irq[airqp->airq_vector]);
		return (apic_setup_irq_table(dip, irqno, NULL, ispec,
		    NULL, type));
	}

	bustype = 0;

	/* check if we have already translated this irq */
	mutex_enter(&airq_mutex);
	newirq = apic_min_device_irq;
	for (; newirq <= apic_max_device_irq; newirq++) {
		airqp = apic_irq_table[newirq];
		while (airqp) {
			if ((airqp->airq_dip == dip) &&
			    (airqp->airq_origirq == irqno) &&
			    (airqp->airq_mps_intr_index != FREE_INDEX)) {

				mutex_exit(&airq_mutex);
				return (VIRTIRQ(newirq, airqp->airq_share_id));
			}
			airqp = airqp->airq_next;
		}
	}
	mutex_exit(&airq_mutex);

	if (apic_defconf)
		goto defconf;

	if ((dip == NULL) || (!apic_irq_translate && !apic_enable_acpi))
		goto nonpci;

	dev_len = sizeof (dev_type);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device_type", (caddr_t)dev_type,
	    &dev_len) != DDI_PROP_SUCCESS) {
		goto nonpci;
	}

	if ((strcmp(dev_type, "pci") == 0) ||
	    (strcmp(dev_type, "pciex") == 0)) {
		/* pci device */
		if (acpica_get_bdf(dip, &busid, &devid, NULL) != 0)
			goto nonpci;
		if (busid == 0 && apic_pci_bus_total == 1)
			busid = (int)apic_single_pci_busid;

		if (pci_config_setup(dip, &cfg_handle) != DDI_SUCCESS)
			goto nonpci;
		ipin = pci_config_get8(cfg_handle, PCI_CONF_IPIN) - PCI_INTA;
		pci_config_teardown(&cfg_handle);
		if (apic_enable_acpi && !apic_use_acpi_madt_only) {
			if (apic_acpi_translate_pci_irq(dip, busid, devid,
			    ipin, &pci_irq, &intr_flag) != ACPI_PSM_SUCCESS)
				goto nonpci;

			intr_flag.bustype = BUS_PCI;
			if ((newirq = apic_setup_irq_table(dip, pci_irq, NULL,
			    ispec, &intr_flag, type)) == -1)
				goto nonpci;
			return (newirq);
		} else {
			pci_irq = ((devid & 0x1f) << 2) | (ipin & 0x3);
			if ((intrp = apic_find_io_intr_w_busid(pci_irq, busid))
			    == NULL) {
				if ((pci_irq = apic_handle_pci_pci_bridge(dip,
				    devid, ipin, &intrp)) == -1)
					goto nonpci;
			}
			if ((newirq = apic_setup_irq_table(dip, pci_irq, intrp,
			    ispec, NULL, type)) == -1)
				goto nonpci;
			return (newirq);
		}
	} else if (strcmp(dev_type, "isa") == 0)
		bustype = BUS_ISA;
	else if (strcmp(dev_type, "eisa") == 0)
		bustype = BUS_EISA;

nonpci:
	if (apic_enable_acpi && !apic_use_acpi_madt_only) {
		/* search iso entries first */
		if (acpi_iso_cnt != 0) {
			hp = (APIC_HEADER *)acpi_isop;
			i = 0;
			while (i < acpi_iso_cnt) {
				if (hp->Type == APIC_XRUPT_OVERRIDE) {
					isop = (MADT_INTERRUPT_OVERRIDE *)hp;
					if (isop->Bus == 0 &&
					    isop->Source == irqno) {
						newirq = isop->Interrupt;
						intr_flag.intr_po =
						    isop->Polarity;
						intr_flag.intr_el =
						    isop->TriggerMode;
						intr_flag.bustype = BUS_ISA;

						return (apic_setup_irq_table(
						    dip, newirq, NULL, ispec,
						    &intr_flag, type));

					}
					i++;
				}
				hp = (APIC_HEADER *)(((char *)hp) +
				    hp->Length);
			}
		}
		intr_flag.intr_po = INTR_PO_ACTIVE_HIGH;
		intr_flag.intr_el = INTR_EL_EDGE;
		intr_flag.bustype = BUS_ISA;
		return (apic_setup_irq_table(dip, irqno, NULL, ispec,
		    &intr_flag, type));
	} else {
		if (bustype == 0)
			bustype = eisa_level_intr_mask ? BUS_EISA : BUS_ISA;
		for (i = 0; i < 2; i++) {
			if (((busid = apic_find_bus_id(bustype)) != -1) &&
			    ((intrp = apic_find_io_intr_w_busid(irqno, busid))
			    != NULL)) {
				if ((newirq = apic_setup_irq_table(dip, irqno,
				    intrp, ispec, NULL, type)) != -1) {
					return (newirq);
				}
				goto defconf;
			}
			bustype = (bustype == BUS_EISA) ? BUS_ISA : BUS_EISA;
		}
	}

/* MPS default configuration */
defconf:
	newirq = apic_setup_irq_table(dip, irqno, NULL, ispec, NULL, type);
	if (newirq == -1)
		return (newirq);
	ASSERT(IRQINDEX(newirq) == irqno);
	ASSERT(apic_irq_table[irqno]);
	return (newirq);
}






/*
 * On machines with PCI-PCI bridges, a device behind a PCI-PCI bridge
 * needs special handling.  We may need to chase up the device tree,
 * using the PCI-PCI Bridge specification's "rotating IPIN assumptions",
 * to find the IPIN at the root bus that relates to the IPIN on the
 * subsidiary bus (for ACPI or MP).  We may, however, have an entry
 * in the MP table or the ACPI namespace for this device itself.
 * We handle both cases in the search below.
 */
/* this is the non-acpi version */
static int
apic_handle_pci_pci_bridge(dev_info_t *idip, int child_devno, int child_ipin,
			struct apic_io_intr **intrp)
{
	dev_info_t *dipp, *dip;
	int pci_irq;
	ddi_acc_handle_t cfg_handle;
	int bridge_devno, bridge_bus;
	int ipin;

	dip = idip;

	/*CONSTCOND*/
	while (1) {
		if ((dipp = ddi_get_parent(dip)) == (dev_info_t *)NULL)
			return (-1);
		if ((pci_config_setup(dipp, &cfg_handle) == DDI_SUCCESS) &&
		    (pci_config_get8(cfg_handle, PCI_CONF_BASCLASS) ==
		    PCI_CLASS_BRIDGE) && (pci_config_get8(cfg_handle,
		    PCI_CONF_SUBCLASS) == PCI_BRIDGE_PCI)) {
			pci_config_teardown(&cfg_handle);
			if (acpica_get_bdf(dipp, &bridge_bus, &bridge_devno,
			    NULL) != 0)
				return (-1);
			/*
			 * This is the rotating scheme that Compaq is using
			 * and documented in the pci to pci spec.  Also, if
			 * the pci to pci bridge is behind another pci to
			 * pci bridge, then it need to keep transversing
			 * up until an interrupt entry is found or reach
			 * the top of the tree
			 */
			ipin = (child_devno + child_ipin) % PCI_INTD;
				if (bridge_bus == 0 && apic_pci_bus_total == 1)
					bridge_bus = (int)apic_single_pci_busid;
				pci_irq = ((bridge_devno & 0x1f) << 2) |
				    (ipin & 0x3);
				if ((*intrp = apic_find_io_intr_w_busid(pci_irq,
				    bridge_bus)) != NULL) {
					return (pci_irq);
				}
			dip = dipp;
			child_devno = bridge_devno;
			child_ipin = ipin;
		} else
			return (-1);
	}
	/*LINTED: function will not fall off the bottom */
}




static uchar_t
acpi_find_ioapic(int irq)
{
	int i;

	for (i = 0; i < apic_io_max; i++) {
		if (irq >= apic_io_vectbase[i] && irq <= apic_io_vectend[i])
			return (i);
	}
	return (0xFF);	/* shouldn't happen */
}

/*
 * See if two irqs are compatible for sharing a vector.
 * Currently we only support sharing of PCI devices.
 */
static int
acpi_intr_compatible(iflag_t iflag1, iflag_t iflag2)
{
	uint_t	level1, po1;
	uint_t	level2, po2;

	/* Assume active high by default */
	po1 = 0;
	po2 = 0;

	if (iflag1.bustype != iflag2.bustype || iflag1.bustype != BUS_PCI)
		return (0);

	if (iflag1.intr_el == INTR_EL_CONFORM)
		level1 = AV_LEVEL;
	else
		level1 = (iflag1.intr_el == INTR_EL_LEVEL) ? AV_LEVEL : 0;

	if (level1 && ((iflag1.intr_po == INTR_PO_ACTIVE_LOW) ||
	    (iflag1.intr_po == INTR_PO_CONFORM)))
		po1 = AV_ACTIVE_LOW;

	if (iflag2.intr_el == INTR_EL_CONFORM)
		level2 = AV_LEVEL;
	else
		level2 = (iflag2.intr_el == INTR_EL_LEVEL) ? AV_LEVEL : 0;

	if (level2 && ((iflag2.intr_po == INTR_PO_ACTIVE_LOW) ||
	    (iflag2.intr_po == INTR_PO_CONFORM)))
		po2 = AV_ACTIVE_LOW;

	if ((level1 == level2) && (po1 == po2))
		return (1);

	return (0);
}

/*
 * Attempt to share vector with someone else
 */
static int
apic_share_vector(int irqno, iflag_t *intr_flagp, short intr_index, int ipl,
	uchar_t ioapicindex, uchar_t ipin, apic_irq_t **irqptrp)
{
#ifdef DEBUG
	apic_irq_t *tmpirqp = NULL;
#endif /* DEBUG */
	apic_irq_t *irqptr, dummyirq;
	int	newirq, chosen_irq = -1, share = 127;
	int	lowest, highest, i;
	uchar_t	share_id;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_share_vector: irqno=0x%x "
	    "intr_index=0x%x ipl=0x%x\n", irqno, intr_index, ipl));

	highest = apic_ipltopri[ipl] + APIC_VECTOR_MASK;
	lowest = apic_ipltopri[ipl-1] + APIC_VECTOR_PER_IPL;

	if (highest < lowest) /* Both ipl and ipl-1 map to same pri */
		lowest -= APIC_VECTOR_PER_IPL;
	dummyirq.airq_mps_intr_index = intr_index;
	dummyirq.airq_ioapicindex = ioapicindex;
	dummyirq.airq_intin_no = ipin;
	if (intr_flagp)
		dummyirq.airq_iflag = *intr_flagp;
	apic_record_rdt_entry(&dummyirq, irqno);
	for (i = lowest; i <= highest; i++) {
		newirq = apic_vector_to_irq[i];
		if (newirq == APIC_RESV_IRQ)
			continue;
		irqptr = apic_irq_table[newirq];

		if ((dummyirq.airq_rdt_entry & 0xFF00) !=
		    (irqptr->airq_rdt_entry & 0xFF00))
			/* not compatible */
			continue;

		if (irqptr->airq_share < share) {
			share = irqptr->airq_share;
			chosen_irq = newirq;
		}
	}
	if (chosen_irq != -1) {
		/*
		 * Assign a share id which is free or which is larger
		 * than the largest one.
		 */
		share_id = 1;
		mutex_enter(&airq_mutex);
		irqptr = apic_irq_table[chosen_irq];
		while (irqptr) {
			if (irqptr->airq_mps_intr_index == FREE_INDEX) {
				share_id = irqptr->airq_share_id;
				break;
			}
			if (share_id <= irqptr->airq_share_id)
				share_id = irqptr->airq_share_id + 1;
#ifdef DEBUG
			tmpirqp = irqptr;
#endif /* DEBUG */
			irqptr = irqptr->airq_next;
		}
		if (!irqptr) {
			irqptr = kmem_zalloc(sizeof (apic_irq_t), KM_SLEEP);
			irqptr->airq_temp_cpu = IRQ_UNINIT;
			irqptr->airq_next =
			    apic_irq_table[chosen_irq]->airq_next;
			apic_irq_table[chosen_irq]->airq_next = irqptr;
#ifdef	DEBUG
			tmpirqp = apic_irq_table[chosen_irq];
#endif /* DEBUG */
		}
		irqptr->airq_mps_intr_index = intr_index;
		irqptr->airq_ioapicindex = ioapicindex;
		irqptr->airq_intin_no = ipin;
		if (intr_flagp)
			irqptr->airq_iflag = *intr_flagp;
		irqptr->airq_vector = apic_irq_table[chosen_irq]->airq_vector;
		irqptr->airq_share_id = share_id;
		apic_record_rdt_entry(irqptr, irqno);
		*irqptrp = irqptr;
#ifdef	DEBUG
		/* shuffle the pointers to test apic_delspl path */
		if (tmpirqp) {
			tmpirqp->airq_next = irqptr->airq_next;
			irqptr->airq_next = apic_irq_table[chosen_irq];
			apic_irq_table[chosen_irq] = irqptr;
		}
#endif /* DEBUG */
		mutex_exit(&airq_mutex);
		return (VIRTIRQ(chosen_irq, share_id));
	}
	return (-1);
}

/*
 *
 */
static int
apic_setup_irq_table(dev_info_t *dip, int irqno, struct apic_io_intr *intrp,
    struct intrspec *ispec, iflag_t *intr_flagp, int type)
{
	int origirq = ispec->intrspec_vec;
	uchar_t ipl = ispec->intrspec_pri;
	int	newirq, intr_index;
	uchar_t	ipin, ioapic, ioapicindex, vector;
	apic_irq_t *irqptr;
	major_t	major;
	dev_info_t	*sdip;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_setup_irq_table: dip=0x%p type=%d "
	    "irqno=0x%x origirq=0x%x\n", (void *)dip, type, irqno, origirq));

	ASSERT(ispec != NULL);

	major =  (dip != NULL) ? ddi_name_to_major(ddi_get_name(dip)) : 0;

	if (DDI_INTR_IS_MSI_OR_MSIX(type)) {
		/* MSI/X doesn't need to setup ioapic stuffs */
		ioapicindex = 0xff;
		ioapic = 0xff;
		ipin = (uchar_t)0xff;
		intr_index = (type == DDI_INTR_TYPE_MSI) ? MSI_INDEX :
		    MSIX_INDEX;
		mutex_enter(&airq_mutex);
		if ((irqno = apic_allocate_irq(apic_first_avail_irq)) == -1) {
			mutex_exit(&airq_mutex);
			/* need an irq for MSI/X to index into autovect[] */
			cmn_err(CE_WARN, "No interrupt irq: %s instance %d",
			    ddi_get_name(dip), ddi_get_instance(dip));
			return (-1);
		}
		mutex_exit(&airq_mutex);

	} else if (intrp != NULL) {
		intr_index = (int)(intrp - apic_io_intrp);
		ioapic = intrp->intr_destid;
		ipin = intrp->intr_destintin;
		/* Find ioapicindex. If destid was ALL, we will exit with 0. */
		for (ioapicindex = apic_io_max - 1; ioapicindex; ioapicindex--)
			if (apic_io_id[ioapicindex] == ioapic)
				break;
		ASSERT((ioapic == apic_io_id[ioapicindex]) ||
		    (ioapic == INTR_ALL_APIC));

		/* check whether this intin# has been used by another irqno */
		if ((newirq = apic_find_intin(ioapicindex, ipin)) != -1) {
			return (newirq);
		}

	} else if (intr_flagp != NULL) {
		/* ACPI case */
		intr_index = ACPI_INDEX;
		ioapicindex = acpi_find_ioapic(irqno);
		ASSERT(ioapicindex != 0xFF);
		ioapic = apic_io_id[ioapicindex];
		ipin = irqno - apic_io_vectbase[ioapicindex];
		if (apic_irq_table[irqno] &&
		    apic_irq_table[irqno]->airq_mps_intr_index == ACPI_INDEX) {
			ASSERT(apic_irq_table[irqno]->airq_intin_no == ipin &&
			    apic_irq_table[irqno]->airq_ioapicindex ==
			    ioapicindex);
			return (irqno);
		}

	} else {
		/* default configuration */
		ioapicindex = 0;
		ioapic = apic_io_id[ioapicindex];
		ipin = (uchar_t)irqno;
		intr_index = DEFAULT_INDEX;
	}

	if (ispec == NULL) {
		APIC_VERBOSE_IOAPIC((CE_WARN, "No intrspec for irqno = %x\n",
		    irqno));
	} else if ((vector = apic_allocate_vector(ipl, irqno, 0)) == 0) {
		if ((newirq = apic_share_vector(irqno, intr_flagp, intr_index,
		    ipl, ioapicindex, ipin, &irqptr)) != -1) {
			irqptr->airq_ipl = ipl;
			irqptr->airq_origirq = (uchar_t)origirq;
			irqptr->airq_dip = dip;
			irqptr->airq_major = major;
			sdip = apic_irq_table[IRQINDEX(newirq)]->airq_dip;
			/* This is OK to do really */
			if (sdip == NULL) {
				cmn_err(CE_WARN, "Sharing vectors: %s"
				    " instance %d and SCI",
				    ddi_get_name(dip), ddi_get_instance(dip));
			} else {
				cmn_err(CE_WARN, "Sharing vectors: %s"
				    " instance %d and %s instance %d",
				    ddi_get_name(sdip), ddi_get_instance(sdip),
				    ddi_get_name(dip), ddi_get_instance(dip));
			}
			return (newirq);
		}
		/* try high priority allocation now  that share has failed */
		if ((vector = apic_allocate_vector(ipl, irqno, 1)) == 0) {
			cmn_err(CE_WARN, "No interrupt vector: %s instance %d",
			    ddi_get_name(dip), ddi_get_instance(dip));
			return (-1);
		}
	}

	mutex_enter(&airq_mutex);
	if (apic_irq_table[irqno] == NULL) {
		irqptr = kmem_zalloc(sizeof (apic_irq_t), KM_SLEEP);
		irqptr->airq_temp_cpu = IRQ_UNINIT;
		apic_irq_table[irqno] = irqptr;
	} else {
		irqptr = apic_irq_table[irqno];
		if (irqptr->airq_mps_intr_index != FREE_INDEX) {
			/*
			 * The slot is used by another irqno, so allocate
			 * a free irqno for this interrupt
			 */
			newirq = apic_allocate_irq(apic_first_avail_irq);
			if (newirq == -1) {
				mutex_exit(&airq_mutex);
				return (-1);
			}
			irqno = newirq;
			irqptr = apic_irq_table[irqno];
			if (irqptr == NULL) {
				irqptr = kmem_zalloc(sizeof (apic_irq_t),
				    KM_SLEEP);
				irqptr->airq_temp_cpu = IRQ_UNINIT;
				apic_irq_table[irqno] = irqptr;
			}
			apic_modify_vector(vector, newirq);
		}
	}
	apic_max_device_irq = max(irqno, apic_max_device_irq);
	apic_min_device_irq = min(irqno, apic_min_device_irq);
	mutex_exit(&airq_mutex);
	irqptr->airq_ioapicindex = ioapicindex;
	irqptr->airq_intin_no = ipin;
	irqptr->airq_ipl = ipl;
	irqptr->airq_vector = vector;
	irqptr->airq_origirq = (uchar_t)origirq;
	irqptr->airq_share_id = 0;
	irqptr->airq_mps_intr_index = (short)intr_index;
	irqptr->airq_dip = dip;
	irqptr->airq_major = major;
	irqptr->airq_cpu = apic_bind_intr(dip, irqno, ioapic, ipin);
	if (intr_flagp)
		irqptr->airq_iflag = *intr_flagp;

	if (!DDI_INTR_IS_MSI_OR_MSIX(type)) {
		/* setup I/O APIC entry for non-MSI/X interrupts */
		apic_record_rdt_entry(irqptr, irqno);
	}
	return (irqno);
}

/*
 * return the cpu to which this intr should be bound.
 * Check properties or any other mechanism to see if user wants it
 * bound to a specific CPU. If so, return the cpu id with high bit set.
 * If not, use the policy to choose a cpu and return the id.
 */
uchar_t
apic_bind_intr(dev_info_t *dip, int irq, uchar_t ioapicid, uchar_t intin)
{
	int	instance, instno, prop_len, bind_cpu, count;
	uint_t	i, rc;
	uchar_t	cpu;
	major_t	major;
	char	*name, *drv_name, *prop_val, *cptr;
	char	prop_name[32];


	if (apic_intr_policy == INTR_LOWEST_PRIORITY)
		return (IRQ_UNBOUND);

	drv_name = NULL;
	rc = DDI_PROP_NOT_FOUND;
	major = (major_t)-1;
	if (dip != NULL) {
		name = ddi_get_name(dip);
		major = ddi_name_to_major(name);
		drv_name = ddi_major_to_name(major);
		instance = ddi_get_instance(dip);
		if (apic_intr_policy == INTR_ROUND_ROBIN_WITH_AFFINITY) {
			i = apic_min_device_irq;
			for (; i <= apic_max_device_irq; i++) {

				if ((i == irq) || (apic_irq_table[i] == NULL) ||
				    (apic_irq_table[i]->airq_mps_intr_index
				    == FREE_INDEX))
					continue;

				if ((apic_irq_table[i]->airq_major == major) &&
				    (!(apic_irq_table[i]->airq_cpu &
				    IRQ_USER_BOUND))) {

					cpu = apic_irq_table[i]->airq_cpu;

					cmn_err(CE_CONT,
					    "!pcplusmp: %s (%s) instance #%d "
					    "vector 0x%x ioapic 0x%x "
					    "intin 0x%x is bound to cpu %d\n",
					    name, drv_name, instance, irq,
					    ioapicid, intin, cpu);
					return (cpu);
				}
			}
		}
		/*
		 * search for "drvname"_intpt_bind_cpus property first, the
		 * syntax of the property should be "a[,b,c,...]" where
		 * instance 0 binds to cpu a, instance 1 binds to cpu b,
		 * instance 3 binds to cpu c...
		 * ddi_getlongprop() will search /option first, then /
		 * if "drvname"_intpt_bind_cpus doesn't exist, then find
		 * intpt_bind_cpus property.  The syntax is the same, and
		 * it applies to all the devices if its "drvname" specific
		 * property doesn't exist
		 */
		(void) strcpy(prop_name, drv_name);
		(void) strcat(prop_name, "_intpt_bind_cpus");
		rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, 0, prop_name,
		    (caddr_t)&prop_val, &prop_len);
		if (rc != DDI_PROP_SUCCESS) {
			rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, 0,
			    "intpt_bind_cpus", (caddr_t)&prop_val, &prop_len);
		}
	}
	if (rc == DDI_PROP_SUCCESS) {
		for (i = count = 0; i < (prop_len - 1); i++)
			if (prop_val[i] == ',')
				count++;
		if (prop_val[i-1] != ',')
			count++;
		/*
		 * if somehow the binding instances defined in the
		 * property are not enough for this instno., then
		 * reuse the pattern for the next instance until
		 * it reaches the requested instno
		 */
		instno = instance % count;
		i = 0;
		cptr = prop_val;
		while (i < instno)
			if (*cptr++ == ',')
				i++;
		bind_cpu = stoi(&cptr);
		kmem_free(prop_val, prop_len);
		/* if specific cpu is bogus, then default to cpu 0 */
		if (bind_cpu >= apic_nproc) {
			cmn_err(CE_WARN, "pcplusmp: %s=%s: CPU %d not present",
			    prop_name, prop_val, bind_cpu);
			bind_cpu = 0;
		} else {
			/* indicate that we are bound at user request */
			bind_cpu |= IRQ_USER_BOUND;
		}
		/*
		 * no need to check apic_cpus[].aci_status, if specific cpu is
		 * not up, then post_cpu_start will handle it.
		 */
	} else {
		/*
		 * We change bind_cpu only for every two calls
		 * as most drivers still do 2 add_intrs for every
		 * interrupt
		 */
		bind_cpu = (apic_next_bind_cpu++) / 2;
		if (bind_cpu >= apic_nproc) {
			apic_next_bind_cpu = 1;
			bind_cpu = 0;
		}
	}
	if (drv_name != NULL)
		cmn_err(CE_CONT, "!pcplusmp: %s (%s) instance %d "
		    "vector 0x%x ioapic 0x%x intin 0x%x is bound to cpu %d\n",
		    name, drv_name, instance,
		    irq, ioapicid, intin, bind_cpu & ~IRQ_USER_BOUND);
	else
		cmn_err(CE_CONT, "!pcplusmp: "
		    "vector 0x%x ioapic 0x%x intin 0x%x is bound to cpu %d\n",
		    irq, ioapicid, intin, bind_cpu & ~IRQ_USER_BOUND);

	return ((uchar_t)bind_cpu);
}

static struct apic_io_intr *
apic_find_io_intr_w_busid(int irqno, int busid)
{
	struct	apic_io_intr	*intrp;

	/*
	 * It can have more than 1 entry with same source bus IRQ,
	 * but unique with the source bus id
	 */
	intrp = apic_io_intrp;
	if (intrp != NULL) {
		while (intrp->intr_entry == APIC_IO_INTR_ENTRY) {
			if (intrp->intr_irq == irqno &&
			    intrp->intr_busid == busid &&
			    intrp->intr_type == IO_INTR_INT)
				return (intrp);
			intrp++;
		}
	}
	APIC_VERBOSE_IOAPIC((CE_NOTE, "Did not find io intr for irqno:"
	    "busid %x:%x\n", irqno, busid));
	return ((struct apic_io_intr *)NULL);
}


struct mps_bus_info {
	char	*bus_name;
	int	bus_id;
} bus_info_array[] = {
	"ISA ", BUS_ISA,
	"PCI ", BUS_PCI,
	"EISA ", BUS_EISA,
	"XPRESS", BUS_XPRESS,
	"PCMCIA", BUS_PCMCIA,
	"VL ", BUS_VL,
	"CBUS ", BUS_CBUS,
	"CBUSII", BUS_CBUSII,
	"FUTURE", BUS_FUTURE,
	"INTERN", BUS_INTERN,
	"MBI ", BUS_MBI,
	"MBII ", BUS_MBII,
	"MPI ", BUS_MPI,
	"MPSA ", BUS_MPSA,
	"NUBUS ", BUS_NUBUS,
	"TC ", BUS_TC,
	"VME ", BUS_VME
};

static int
apic_find_bus_type(char *bus)
{
	int	i = 0;

	for (; i < sizeof (bus_info_array)/sizeof (struct mps_bus_info); i++)
		if (strncmp(bus, bus_info_array[i].bus_name,
		    strlen(bus_info_array[i].bus_name)) == 0)
			return (bus_info_array[i].bus_id);
	APIC_VERBOSE_IOAPIC((CE_WARN, "Did not find bus type for bus %s", bus));
	return (0);
}

static int
apic_find_bus(int busid)
{
	struct	apic_bus	*busp;

	busp = apic_busp;
	while (busp->bus_entry == APIC_BUS_ENTRY) {
		if (busp->bus_id == busid)
			return (apic_find_bus_type((char *)&busp->bus_str1));
		busp++;
	}
	APIC_VERBOSE_IOAPIC((CE_WARN, "Did not find bus for bus id %x", busid));
	return (0);
}

static int
apic_find_bus_id(int bustype)
{
	struct	apic_bus	*busp;

	busp = apic_busp;
	while (busp->bus_entry == APIC_BUS_ENTRY) {
		if (apic_find_bus_type((char *)&busp->bus_str1) == bustype)
			return (busp->bus_id);
		busp++;
	}
	APIC_VERBOSE_IOAPIC((CE_WARN, "Did not find bus id for bustype %x",
	    bustype));
	return (-1);
}

/*
 * Check if a particular irq need to be reserved for any io_intr
 */
static struct apic_io_intr *
apic_find_io_intr(int irqno)
{
	struct	apic_io_intr	*intrp;

	intrp = apic_io_intrp;
	if (intrp != NULL) {
		while (intrp->intr_entry == APIC_IO_INTR_ENTRY) {
			if (intrp->intr_irq == irqno &&
			    intrp->intr_type == IO_INTR_INT)
				return (intrp);
			intrp++;
		}
	}
	return ((struct apic_io_intr *)NULL);
}

/*
 * Check if the given ioapicindex intin combination has already been assigned
 * an irq. If so return irqno. Else -1
 */
static int
apic_find_intin(uchar_t ioapic, uchar_t intin)
{
	apic_irq_t *irqptr;
	int	i;

	/* find ioapic and intin in the apic_irq_table[] and return the index */
	for (i = apic_min_device_irq; i <= apic_max_device_irq; i++) {
		irqptr = apic_irq_table[i];
		while (irqptr) {
			if ((irqptr->airq_mps_intr_index >= 0) &&
			    (irqptr->airq_intin_no == intin) &&
			    (irqptr->airq_ioapicindex == ioapic)) {
				APIC_VERBOSE_IOAPIC((CE_NOTE, "!Found irq "
				    "entry for ioapic:intin %x:%x "
				    "shared interrupts ?", ioapic, intin));
				return (i);
			}
			irqptr = irqptr->airq_next;
		}
	}
	return (-1);
}

int
apic_allocate_irq(int irq)
{
	int	freeirq, i;

	if ((freeirq = apic_find_free_irq(irq, (APIC_RESV_IRQ - 1))) == -1)
		if ((freeirq = apic_find_free_irq(APIC_FIRST_FREE_IRQ,
		    (irq - 1))) == -1) {
			/*
			 * if BIOS really defines every single irq in the mps
			 * table, then don't worry about conflicting with
			 * them, just use any free slot in apic_irq_table
			 */
			for (i = APIC_FIRST_FREE_IRQ; i < APIC_RESV_IRQ; i++) {
				if ((apic_irq_table[i] == NULL) ||
				    apic_irq_table[i]->airq_mps_intr_index ==
				    FREE_INDEX) {
				freeirq = i;
				break;
			}
		}
		if (freeirq == -1) {
			/* This shouldn't happen, but just in case */
			cmn_err(CE_WARN, "pcplusmp: NO available IRQ");
			return (-1);
		}
	}
	if (apic_irq_table[freeirq] == NULL) {
		apic_irq_table[freeirq] =
		    kmem_zalloc(sizeof (apic_irq_t), KM_NOSLEEP);
		if (apic_irq_table[freeirq] == NULL) {
			cmn_err(CE_WARN, "pcplusmp: NO memory to allocate IRQ");
			return (-1);
		}
		apic_irq_table[freeirq]->airq_mps_intr_index = FREE_INDEX;
	}
	return (freeirq);
}

static int
apic_find_free_irq(int start, int end)
{
	int	i;

	for (i = start; i <= end; i++)
		/* Check if any I/O entry needs this IRQ */
		if (apic_find_io_intr(i) == NULL) {
			/* Then see if it is free */
			if ((apic_irq_table[i] == NULL) ||
			    (apic_irq_table[i]->airq_mps_intr_index ==
			    FREE_INDEX)) {
				return (i);
			}
		}
	return (-1);
}

/*
 * Allocate a free vector for irq at ipl. Takes care of merging of multiple
 * IPLs into a single APIC level as well as stretching some IPLs onto multiple
 * levels. APIC_HI_PRI_VECTS interrupts are reserved for high priority
 * requests and allocated only when pri is set.
 */
static uchar_t
apic_allocate_vector(int ipl, int irq, int pri)
{
	int	lowest, highest, i;

	highest = apic_ipltopri[ipl] + APIC_VECTOR_MASK;
	lowest = apic_ipltopri[ipl - 1] + APIC_VECTOR_PER_IPL;

	if (highest < lowest) /* Both ipl and ipl - 1 map to same pri */
		lowest -= APIC_VECTOR_PER_IPL;

#ifdef	DEBUG
	if (apic_restrict_vector)	/* for testing shared interrupt logic */
		highest = lowest + apic_restrict_vector + APIC_HI_PRI_VECTS;
#endif /* DEBUG */
	if (pri == 0)
		highest -= APIC_HI_PRI_VECTS;

	for (i = lowest; i < highest; i++) {
		if ((i == T_FASTTRAP) || (i == APIC_SPUR_INTR) ||
			(i == T_SYSCALLINT) || (i == T_DTRACE_PROBE) ||
			(i == T_DTRACE_RET))
			continue;
		if (apic_vector_to_irq[i] == APIC_RESV_IRQ) {
			apic_vector_to_irq[i] = (uchar_t)irq;
			return (i);
		}
	}

	return (0);
}

static void
apic_modify_vector(uchar_t vector, int irq)
{
	apic_vector_to_irq[vector] = (uchar_t)irq;
}

/*
 * Mark vector as being in the process of being deleted. Interrupts
 * may still come in on some CPU. The moment an interrupt comes with
 * the new vector, we know we can free the old one. Called only from
 * addspl and delspl with interrupts disabled. Because an interrupt
 * can be shared, but no interrupt from either device may come in,
 * we also use a timeout mechanism, which we arbitrarily set to
 * apic_revector_timeout microseconds.
 */
static void
apic_mark_vector(uchar_t oldvector, uchar_t newvector)
{
	int iflag = intr_clear();
	lock_set(&apic_revector_lock);
	if (!apic_oldvec_to_newvec) {
		apic_oldvec_to_newvec =
		    kmem_zalloc(sizeof (newvector) * APIC_MAX_VECTOR * 2,
		    KM_NOSLEEP);

		if (!apic_oldvec_to_newvec) {
			/*
			 * This failure is not catastrophic.
			 * But, the oldvec will never be freed.
			 */
			apic_error |= APIC_ERR_MARK_VECTOR_FAIL;
			lock_clear(&apic_revector_lock);
			intr_restore(iflag);
			return;
		}
		apic_newvec_to_oldvec = &apic_oldvec_to_newvec[APIC_MAX_VECTOR];
	}

	/* See if we already did this for drivers which do double addintrs */
	if (apic_oldvec_to_newvec[oldvector] != newvector) {
		apic_oldvec_to_newvec[oldvector] = newvector;
		apic_newvec_to_oldvec[newvector] = oldvector;
		apic_revector_pending++;
	}
	lock_clear(&apic_revector_lock);
	intr_restore(iflag);
	(void) timeout(apic_xlate_vector_free_timeout_handler,
	    (void *)(uintptr_t)oldvector, drv_usectohz(apic_revector_timeout));
}

/*
 * xlate_vector is called from intr_enter if revector_pending is set.
 * It will xlate it if needed and mark the old vector as free.
 */
static uchar_t
apic_xlate_vector(uchar_t vector)
{
	uchar_t	newvector, oldvector = 0;

	lock_set(&apic_revector_lock);
	/* Do we really need to do this ? */
	if (!apic_revector_pending) {
		lock_clear(&apic_revector_lock);
		return (vector);
	}
	if ((newvector = apic_oldvec_to_newvec[vector]) != 0)
		oldvector = vector;
	else {
		/*
		 * The incoming vector is new . See if a stale entry is
		 * remaining
		 */
		if ((oldvector = apic_newvec_to_oldvec[vector]) != 0)
			newvector = vector;
	}

	if (oldvector) {
		apic_revector_pending--;
		apic_oldvec_to_newvec[oldvector] = 0;
		apic_newvec_to_oldvec[newvector] = 0;
		apic_free_vector(oldvector);
		lock_clear(&apic_revector_lock);
		/* There could have been more than one reprogramming! */
		return (apic_xlate_vector(newvector));
	}
	lock_clear(&apic_revector_lock);
	return (vector);
}

void
apic_xlate_vector_free_timeout_handler(void *arg)
{
	int iflag;
	uchar_t oldvector, newvector;

	oldvector = (uchar_t)(uintptr_t)arg;
	iflag = intr_clear();
	lock_set(&apic_revector_lock);
	if ((newvector = apic_oldvec_to_newvec[oldvector]) != 0) {
		apic_free_vector(oldvector);
		apic_oldvec_to_newvec[oldvector] = 0;
		apic_newvec_to_oldvec[newvector] = 0;
		apic_revector_pending--;
	}

	lock_clear(&apic_revector_lock);
	intr_restore(iflag);
}


/* Mark vector as not being used by any irq */
static void
apic_free_vector(uchar_t vector)
{
	apic_vector_to_irq[vector] = APIC_RESV_IRQ;
}

/*
 * compute the polarity, trigger mode and vector for programming into
 * the I/O apic and record in airq_rdt_entry.
 */
static void
apic_record_rdt_entry(apic_irq_t *irqptr, int irq)
{
	int	ioapicindex, bus_type, vector;
	short	intr_index;
	uint_t	level, po, io_po;
	struct apic_io_intr *iointrp;

	intr_index = irqptr->airq_mps_intr_index;
	DDI_INTR_IMPLDBG((CE_CONT, "apic_record_rdt_entry: intr_index=%d "
	    "irq = 0x%x dip = 0x%p vector = 0x%x\n", intr_index, irq,
	    (void *)irqptr->airq_dip, irqptr->airq_vector));

	if (intr_index == RESERVE_INDEX) {
		apic_error |= APIC_ERR_INVALID_INDEX;
		return;
	} else if (APIC_IS_MSI_OR_MSIX_INDEX(intr_index)) {
		return;
	}

	vector = irqptr->airq_vector;
	ioapicindex = irqptr->airq_ioapicindex;
	/* Assume edge triggered by default */
	level = 0;
	/* Assume active high by default */
	po = 0;

	if (intr_index == DEFAULT_INDEX || intr_index == FREE_INDEX) {
		ASSERT(irq < 16);
		if (eisa_level_intr_mask & (1 << irq))
			level = AV_LEVEL;
		if (intr_index == FREE_INDEX && apic_defconf == 0)
			apic_error |= APIC_ERR_INVALID_INDEX;
	} else if (intr_index == ACPI_INDEX) {
		bus_type = irqptr->airq_iflag.bustype;
		if (irqptr->airq_iflag.intr_el == INTR_EL_CONFORM) {
			if (bus_type == BUS_PCI)
				level = AV_LEVEL;
		} else
			level = (irqptr->airq_iflag.intr_el == INTR_EL_LEVEL) ?
			    AV_LEVEL : 0;
		if (level &&
		    ((irqptr->airq_iflag.intr_po == INTR_PO_ACTIVE_LOW) ||
		    (irqptr->airq_iflag.intr_po == INTR_PO_CONFORM &&
		    bus_type == BUS_PCI)))
			po = AV_ACTIVE_LOW;
	} else {
		iointrp = apic_io_intrp + intr_index;
		bus_type = apic_find_bus(iointrp->intr_busid);
		if (iointrp->intr_el == INTR_EL_CONFORM) {
			if ((irq < 16) && (eisa_level_intr_mask & (1 << irq)))
				level = AV_LEVEL;
			else if (bus_type == BUS_PCI)
				level = AV_LEVEL;
		} else
			level = (iointrp->intr_el == INTR_EL_LEVEL) ?
			    AV_LEVEL : 0;
		if (level && ((iointrp->intr_po == INTR_PO_ACTIVE_LOW) ||
		    (iointrp->intr_po == INTR_PO_CONFORM &&
		    bus_type == BUS_PCI)))
			po = AV_ACTIVE_LOW;
	}
	if (level)
		apic_level_intr[irq] = 1;
	/*
	 * The 82489DX External APIC cannot do active low polarity interrupts.
	 */
	if (po && (apic_io_ver[ioapicindex] != IOAPIC_VER_82489DX))
		io_po = po;
	else
		io_po = 0;

	if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG)
		printf("setio: ioapic=%x intin=%x level=%x po=%x vector=%x\n",
		    ioapicindex, irqptr->airq_intin_no, level, io_po, vector);

	irqptr->airq_rdt_entry = level|io_po|vector;
}

/*
 * Call rebind to do the actual programming.
 */
static int
apic_setup_io_intr(apic_irq_t *irqptr, int irq)
{
	int rv;

	if (rv = apic_rebind(irqptr, apic_irq_table[irq]->airq_cpu, 1,
	    IMMEDIATE))
		/* CPU is not up or interrupt is disabled. Fall back to 0 */
		rv = apic_rebind(irqptr, 0, 1, IMMEDIATE);

	return (rv);
}

/*
 * Deferred reprogramming: Call apic_rebind to do the real work.
 */
static int
apic_setup_io_intr_deferred(apic_irq_t *irqptr, int irq)
{
	int rv;

	if (rv = apic_rebind(irqptr, apic_irq_table[irq]->airq_cpu, 1,
	    DEFERRED))
		/* CPU is not up or interrupt is disabled. Fall back to 0 */
		rv = apic_rebind(irqptr, 0, 1, DEFERRED);

	return (rv);
}

/*
 * Bind interrupt corresponding to irq_ptr to bind_cpu. acquire_lock
 * if false (0) means lock is already held (e.g: in rebind_all).
 */
static int
apic_rebind(apic_irq_t *irq_ptr, int bind_cpu, int acquire_lock, int when)
{
	int			intin_no;
	volatile int32_t	*ioapic;
	uchar_t			airq_temp_cpu;
	apic_cpus_info_t	*cpu_infop;
	int			iflag;
	int		which_irq = apic_vector_to_irq[irq_ptr->airq_vector];

	intin_no = irq_ptr->airq_intin_no;
	ioapic = apicioadr[irq_ptr->airq_ioapicindex];
	airq_temp_cpu = irq_ptr->airq_temp_cpu;
	if (airq_temp_cpu != IRQ_UNINIT && airq_temp_cpu != IRQ_UNBOUND) {
		if (airq_temp_cpu & IRQ_USER_BOUND)
			/* Mask off high bit so it can be used as array index */
			airq_temp_cpu &= ~IRQ_USER_BOUND;

		ASSERT(airq_temp_cpu < apic_nproc);
	}

	iflag = intr_clear();

	if (acquire_lock)
		lock_set(&apic_ioapic_lock);

	/*
	 * Can't bind to a CPU that's not online:
	 */
	cpu_infop = &apic_cpus[bind_cpu & ~IRQ_USER_BOUND];
	if (!(cpu_infop->aci_status & APIC_CPU_INTR_ENABLE)) {

		if (acquire_lock)
			lock_clear(&apic_ioapic_lock);

		intr_restore(iflag);
		return (1);
	}

	/*
	 * If this is a deferred reprogramming attempt, ensure we have
	 * not been passed stale data:
	 */
	if ((when == DEFERRED) &&
	    (apic_reprogram_info[which_irq].valid == 0)) {
		/* stale info, so just return */
		if (acquire_lock)
			lock_clear(&apic_ioapic_lock);

		intr_restore(iflag);
		return (0);
	}

	/*
	 * If this interrupt has been delivered to a CPU and that CPU
	 * has not handled it yet, we cannot reprogram the IOAPIC now:
	 */
	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index) &&
	    apic_check_stuck_interrupt(irq_ptr, airq_temp_cpu, bind_cpu,
	    ioapic, intin_no, which_irq) != 0) {

		if (acquire_lock)
			lock_clear(&apic_ioapic_lock);

		intr_restore(iflag);
		return (0);
	}

	/*
	 * NOTE: We do not unmask the RDT here, as an interrupt MAY still
	 * come in before we have a chance to reprogram it below.  The
	 * reprogramming below will simultaneously change and unmask the
	 * RDT entry.
	 */

	if ((uchar_t)bind_cpu == IRQ_UNBOUND) {
		/* Write the RDT entry -- no specific CPU binding */
		WRITE_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapic, intin_no, AV_TOALL);

		if (airq_temp_cpu != IRQ_UNINIT && airq_temp_cpu != IRQ_UNBOUND)
			apic_cpus[airq_temp_cpu].aci_temp_bound--;

		/* Write the vector, trigger, and polarity portion of the RDT */
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no,
		    AV_LDEST | AV_LOPRI | irq_ptr->airq_rdt_entry);
		if (acquire_lock)
			lock_clear(&apic_ioapic_lock);
		irq_ptr->airq_temp_cpu = IRQ_UNBOUND;
		intr_restore(iflag);
		return (0);
	}

	if (bind_cpu & IRQ_USER_BOUND) {
		cpu_infop->aci_bound++;
	} else {
		cpu_infop->aci_temp_bound++;
	}
	ASSERT((bind_cpu & ~IRQ_USER_BOUND) < apic_nproc);
	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {
		/* Write the RDT entry -- bind to a specific CPU: */
		WRITE_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapic, intin_no,
		    cpu_infop->aci_local_id << APIC_ID_BIT_OFFSET);
	}
	if ((airq_temp_cpu != IRQ_UNBOUND) && (airq_temp_cpu != IRQ_UNINIT)) {
		apic_cpus[airq_temp_cpu].aci_temp_bound--;
	}
	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {
		/* Write the vector, trigger, and polarity portion of the RDT */
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no,
		    AV_PDEST | AV_FIXED | irq_ptr->airq_rdt_entry);
	} else {
		if (irq_ptr->airq_ioapicindex == irq_ptr->airq_origirq) {
			/* first one */
			DDI_INTR_IMPLDBG((CE_CONT, "apic_rebind: call "
			    "apic_pci_msi_enable_vector\n"));
			if (apic_pci_msi_enable_vector(irq_ptr->airq_dip,
			    (irq_ptr->airq_mps_intr_index == MSI_INDEX) ?
			    DDI_INTR_TYPE_MSI : DDI_INTR_TYPE_MSIX, which_irq,
			    irq_ptr->airq_vector, irq_ptr->airq_intin_no,
			    cpu_infop->aci_local_id) != PSM_SUCCESS) {
				cmn_err(CE_WARN, "pcplusmp: "
					"apic_pci_msi_enable_vector "
					"returned PSM_FAILURE");
			}
		}
		if ((irq_ptr->airq_ioapicindex + irq_ptr->airq_intin_no - 1) ==
		    irq_ptr->airq_origirq) { /* last one */
			DDI_INTR_IMPLDBG((CE_CONT, "apic_rebind: call "
			    "pci_msi_enable_mode\n"));
			if (pci_msi_enable_mode(irq_ptr->airq_dip,
			    (irq_ptr->airq_mps_intr_index == MSI_INDEX) ?
			    DDI_INTR_TYPE_MSI : DDI_INTR_TYPE_MSIX,
			    which_irq) != DDI_SUCCESS) {
				DDI_INTR_IMPLDBG((CE_CONT, "pcplusmp: "
				    "pci_msi_enable failed\n"));
				(void) pci_msi_unconfigure(irq_ptr->airq_dip,
				(irq_ptr->airq_mps_intr_index == MSI_INDEX) ?
				DDI_INTR_TYPE_MSI : DDI_INTR_TYPE_MSIX,
				which_irq);
			}
		}
	}
	if (acquire_lock)
		lock_clear(&apic_ioapic_lock);
	irq_ptr->airq_temp_cpu = (uchar_t)bind_cpu;
	apic_redist_cpu_skip &= ~(1 << (bind_cpu & ~IRQ_USER_BOUND));
	intr_restore(iflag);
	return (0);
}

/*
 * Checks to see if the IOAPIC interrupt entry specified has its Remote IRR
 * bit set.  Sets up a timeout to perform the reprogramming at a later time
 * if it cannot wait for the Remote IRR bit to clear (or if waiting did not
 * result in the bit's clearing).
 *
 * This function will mask the RDT entry if the Remote IRR bit is set.
 *
 * Returns non-zero if the caller should defer IOAPIC reprogramming.
 */
static int
apic_check_stuck_interrupt(apic_irq_t *irq_ptr, int old_bind_cpu,
	int new_bind_cpu, volatile int32_t *ioapic, int intin_no, int which_irq)
{
	int32_t			rdt_entry;
	int			waited;

	/* Mask the RDT entry, but only if it's a level-triggered interrupt */
	rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no);
	if ((rdt_entry & (AV_LEVEL|AV_MASK)) == AV_LEVEL) {

		/* Mask it */
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no,
		    AV_MASK | rdt_entry);
	}

	/*
	 * Wait for the delivery pending bit to clear.
	 */
	if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no) &
	    (AV_LEVEL|AV_PENDING)) == (AV_LEVEL|AV_PENDING)) {

		/*
		 * If we're still waiting on the delivery of this interrupt,
		 * continue to wait here until it is delivered (this should be
		 * a very small amount of time, but include a timeout just in
		 * case).
		 */
		for (waited = 0; waited < apic_max_usecs_clear_pending;
		    waited += APIC_USECS_PER_WAIT_INTERVAL) {
			if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no)
			    & AV_PENDING) == 0) {
				break;
			}
			drv_usecwait(APIC_USECS_PER_WAIT_INTERVAL);
		}

		if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no) &
		    AV_PENDING) != 0) {
			cmn_err(CE_WARN, "!IOAPIC %d intin %d: Could not "
			    "deliver interrupt to local APIC within "
			    "%d usecs.", irq_ptr->airq_ioapicindex,
			    irq_ptr->airq_intin_no,
			    apic_max_usecs_clear_pending);
		}
	}

	/*
	 * If the remote IRR bit is set, then the interrupt has been sent
	 * to a CPU for processing.  We have no choice but to wait for
	 * that CPU to process the interrupt, at which point the remote IRR
	 * bit will be cleared.
	 */
	if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no) &
	    (AV_LEVEL|AV_REMOTE_IRR)) == (AV_LEVEL|AV_REMOTE_IRR)) {

		/*
		 * If the CPU that this RDT is bound to is NOT the current
		 * CPU, wait until that CPU handles the interrupt and ACKs
		 * it.  If this interrupt is not bound to any CPU (that is,
		 * if it's bound to the logical destination of "anyone"), it
		 * may have been delivered to the current CPU so handle that
		 * case by deferring the reprogramming (below).
		 */
		kpreempt_disable();
		if ((old_bind_cpu != IRQ_UNBOUND) &&
		    (old_bind_cpu != IRQ_UNINIT) &&
		    (old_bind_cpu != psm_get_cpu_id())) {
			for (waited = 0; waited < apic_max_usecs_clear_pending;
			    waited += APIC_USECS_PER_WAIT_INTERVAL) {
				if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic,
				    intin_no) & AV_REMOTE_IRR) == 0) {

					/* Clear the reprogramming state: */
					lock_set(&apic_ioapic_reprogram_lock);

					apic_reprogram_info[which_irq].valid
					    = 0;
					apic_reprogram_info[which_irq].bindcpu
					    = 0;
					apic_reprogram_info[which_irq].timeouts
					    = 0;

					lock_clear(&apic_ioapic_reprogram_lock);

					/* Remote IRR has cleared! */
					kpreempt_enable();
					return (0);
				}
				drv_usecwait(APIC_USECS_PER_WAIT_INTERVAL);
			}
		}
		kpreempt_enable();

		/*
		 * If we waited and the Remote IRR bit is still not cleared,
		 * AND if we've invoked the timeout APIC_REPROGRAM_MAX_TIMEOUTS
		 * times for this interrupt, try the last-ditch workarounds:
		 */
		if (apic_reprogram_info[which_irq].timeouts >=
		    APIC_REPROGRAM_MAX_TIMEOUTS) {

			if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic, intin_no)
			    & AV_REMOTE_IRR) != 0) {
				/*
				 * Trying to clear the bit through normal
				 * channels has failed.  So as a last-ditch
				 * effort, try to set the trigger mode to
				 * edge, then to level.  This has been
				 * observed to work on many systems.
				 */
				WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic,
				    intin_no,
				    READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic,
				    intin_no) & ~AV_LEVEL);

				WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic,
				    intin_no,
				    READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic,
				    intin_no) | AV_LEVEL);

				/*
				 * If the bit's STILL set, declare total and
				 * utter failure
				 */
				if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic,
				    intin_no) & AV_REMOTE_IRR) != 0) {
					cmn_err(CE_WARN, "!IOAPIC %d intin %d: "
					    "Remote IRR failed to reset "
					    "within %d usecs.  Interrupts to "
					    "this pin may cease to function.",
					    irq_ptr->airq_ioapicindex,
					    irq_ptr->airq_intin_no,
					    apic_max_usecs_clear_pending);
				}
			}
			/* Clear the reprogramming state: */
			lock_set(&apic_ioapic_reprogram_lock);

			apic_reprogram_info[which_irq].valid = 0;
			apic_reprogram_info[which_irq].bindcpu = 0;
			apic_reprogram_info[which_irq].timeouts = 0;

			lock_clear(&apic_ioapic_reprogram_lock);
		} else {
#ifdef DEBUG
			cmn_err(CE_WARN, "Deferring reprogramming of irq %d",
			    which_irq);
#endif	/* DEBUG */
			/*
			 * If waiting for the Remote IRR bit (above) didn't
			 * allow it to clear, defer the reprogramming:
			 */
			lock_set(&apic_ioapic_reprogram_lock);

			apic_reprogram_info[which_irq].valid = 1;
			apic_reprogram_info[which_irq].bindcpu = new_bind_cpu;
			apic_reprogram_info[which_irq].timeouts++;

			lock_clear(&apic_ioapic_reprogram_lock);

			/* Fire up a timeout to handle this later */
			(void) timeout(apic_reprogram_timeout_handler,
			    (void *) 0,
			    drv_usectohz(APIC_REPROGRAM_TIMEOUT_DELAY));

			/* Inform caller to defer IOAPIC programming: */
			return (1);
		}
	}
	return (0);
}

/*
 * Timeout handler that performs the APIC reprogramming
 */
/*ARGSUSED*/
static void
apic_reprogram_timeout_handler(void *arg)
{
	/*LINTED: set but not used in function*/
	int i, result;

	/* Serialize access to this function */
	mutex_enter(&apic_reprogram_timeout_mutex);

	/*
	 * For each entry in the reprogramming state that's valid,
	 * try the reprogramming again:
	 */
	for (i = 0; i < APIC_MAX_VECTOR; i++) {
		if (apic_reprogram_info[i].valid == 0)
			continue;
		/*
		 * Though we can't really do anything about errors
		 * at this point, keep track of them for reporting.
		 * Note that it is very possible for apic_setup_io_intr
		 * to re-register this very timeout if the Remote IRR bit
		 * has not yet cleared.
		 */
		result = apic_setup_io_intr_deferred(apic_irq_table[i], i);

#ifdef DEBUG
		if (result)
			cmn_err(CE_WARN, "apic_reprogram_timeout: "
			    "apic_setup_io_intr returned nonzero for "
			    "irq=%d!", i);
#endif	/* DEBUG */
	}

	mutex_exit(&apic_reprogram_timeout_mutex);
}


/*
 * Called to migrate all interrupts at an irq to another cpu. safe
 * if true means we are not being called from an interrupt
 * context and hence it is safe to do a lock_set. If false
 * do only a lock_try and return failure ( non 0 ) if we cannot get it
 */
static int
apic_rebind_all(apic_irq_t *irq_ptr, int bind_cpu, int safe)
{
	apic_irq_t	*irqptr = irq_ptr;
	int		retval = 0;
	int		iflag;

	iflag = intr_clear();
	if (!safe) {
		if (lock_try(&apic_ioapic_lock) == 0) {
			intr_restore(iflag);
			return (1);
		}
	} else
		lock_set(&apic_ioapic_lock);

	while (irqptr) {
		if (irqptr->airq_temp_cpu != IRQ_UNINIT)
			retval |= apic_rebind(irqptr, bind_cpu, 0, IMMEDIATE);
		irqptr = irqptr->airq_next;
	}
	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);
	return (retval);
}

/*
 * apic_intr_redistribute does all the messy computations for identifying
 * which interrupt to move to which CPU. Currently we do just one interrupt
 * at a time. This reduces the time we spent doing all this within clock
 * interrupt. When it is done in idle, we could do more than 1.
 * First we find the most busy and the most free CPU (time in ISR only)
 * skipping those CPUs that has been identified as being ineligible (cpu_skip)
 * Then we look for IRQs which are closest to the difference between the
 * most busy CPU and the average ISR load. We try to find one whose load
 * is less than difference.If none exists, then we chose one larger than the
 * difference, provided it does not make the most idle CPU worse than the
 * most busy one. In the end, we clear all the busy fields for CPUs. For
 * IRQs, they are cleared as they are scanned.
 */
static void
apic_intr_redistribute()
{
	int busiest_cpu, most_free_cpu;
	int cpu_free, cpu_busy, max_busy, min_busy;
	int min_free, diff;
	int	average_busy, cpus_online;
	int i, busy;
	apic_cpus_info_t *cpu_infop;
	apic_irq_t *min_busy_irq = NULL;
	apic_irq_t *max_busy_irq = NULL;

	busiest_cpu = most_free_cpu = -1;
	cpu_free = cpu_busy = max_busy = average_busy = 0;
	min_free = apic_sample_factor_redistribution;
	cpus_online = 0;
	/*
	 * Below we will check for CPU_INTR_ENABLE, bound, temp_bound, temp_cpu
	 * without ioapic_lock. That is OK as we are just doing statistical
	 * sampling anyway and any inaccuracy now will get corrected next time
	 * The call to rebind which actually changes things will make sure
	 * we are consistent.
	 */
	for (i = 0; i < apic_nproc; i++) {
		if (!(apic_redist_cpu_skip & (1 << i)) &&
		    (apic_cpus[i].aci_status & APIC_CPU_INTR_ENABLE)) {

			cpu_infop = &apic_cpus[i];
			/*
			 * If no unbound interrupts or only 1 total on this
			 * CPU, skip
			 */
			if (!cpu_infop->aci_temp_bound ||
			    (cpu_infop->aci_bound + cpu_infop->aci_temp_bound)
			    == 1) {
				apic_redist_cpu_skip |= 1 << i;
				continue;
			}

			busy = cpu_infop->aci_busy;
			average_busy += busy;
			cpus_online++;
			if (max_busy < busy) {
				max_busy = busy;
				busiest_cpu = i;
			}
			if (min_free > busy) {
				min_free = busy;
				most_free_cpu = i;
			}
			if (busy > apic_int_busy_mark) {
				cpu_busy |= 1 << i;
			} else {
				if (busy < apic_int_free_mark)
					cpu_free |= 1 << i;
			}
		}
	}
	if ((cpu_busy && cpu_free) ||
	    (max_busy >= (min_free + apic_diff_for_redistribution))) {

		apic_num_imbalance++;
#ifdef	DEBUG
		if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG) {
			prom_printf(
			    "redistribute busy=%x free=%x max=%x min=%x",
			    cpu_busy, cpu_free, max_busy, min_free);
		}
#endif /* DEBUG */


		average_busy /= cpus_online;

		diff = max_busy - average_busy;
		min_busy = max_busy; /* start with the max possible value */
		max_busy = 0;
		min_busy_irq = max_busy_irq = NULL;
		i = apic_min_device_irq;
		for (; i < apic_max_device_irq; i++) {
			apic_irq_t *irq_ptr;
			/* Change to linked list per CPU ? */
			if ((irq_ptr = apic_irq_table[i]) == NULL)
				continue;
			/* Check for irq_busy & decide which one to move */
			/* Also zero them for next round */
			if ((irq_ptr->airq_temp_cpu == busiest_cpu) &&
			    irq_ptr->airq_busy) {
				if (irq_ptr->airq_busy < diff) {
					/*
					 * Check for least busy CPU,
					 * best fit or what ?
					 */
					if (max_busy < irq_ptr->airq_busy) {
						/*
						 * Most busy within the
						 * required differential
						 */
						max_busy = irq_ptr->airq_busy;
						max_busy_irq = irq_ptr;
					}
				} else {
					if (min_busy > irq_ptr->airq_busy) {
						/*
						 * least busy, but more than
						 * the reqd diff
						 */
						if (min_busy <
						    (diff + average_busy -
						    min_free)) {
							/*
							 * Making sure new cpu
							 * will not end up
							 * worse
							 */
							min_busy =
							    irq_ptr->airq_busy;

							min_busy_irq = irq_ptr;
						}
					}
				}
			}
			irq_ptr->airq_busy = 0;
		}

		if (max_busy_irq != NULL) {
#ifdef	DEBUG
			if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG) {
				prom_printf("rebinding %x to %x",
				    max_busy_irq->airq_vector, most_free_cpu);
			}
#endif /* DEBUG */
			if (apic_rebind_all(max_busy_irq, most_free_cpu, 0)
			    == 0)
				/* Make change permenant */
				max_busy_irq->airq_cpu = (uchar_t)most_free_cpu;
		} else if (min_busy_irq != NULL) {
#ifdef	DEBUG
			if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG) {
				prom_printf("rebinding %x to %x",
				    min_busy_irq->airq_vector, most_free_cpu);
			}
#endif /* DEBUG */

			if (apic_rebind_all(min_busy_irq, most_free_cpu, 0) ==
			    0)
				/* Make change permenant */
				min_busy_irq->airq_cpu = (uchar_t)most_free_cpu;
		} else {
			if (cpu_busy != (1 << busiest_cpu)) {
				apic_redist_cpu_skip |= 1 << busiest_cpu;
				/*
				 * We leave cpu_skip set so that next time we
				 * can choose another cpu
				 */
			}
		}
		apic_num_rebind++;
	} else {
		/*
		 * found nothing. Could be that we skipped over valid CPUs
		 * or we have balanced everything. If we had a variable
		 * ticks_for_redistribution, it could be increased here.
		 * apic_int_busy, int_free etc would also need to be
		 * changed.
		 */
		if (apic_redist_cpu_skip)
			apic_redist_cpu_skip = 0;
	}
	for (i = 0; i < apic_nproc; i++) {
		apic_cpus[i].aci_busy = 0;
	}
}

static void
apic_cleanup_busy()
{
	int i;
	apic_irq_t *irq_ptr;

	for (i = 0; i < apic_nproc; i++) {
		apic_cpus[i].aci_busy = 0;
	}

	for (i = apic_min_device_irq; i < apic_max_device_irq; i++) {
		if ((irq_ptr = apic_irq_table[i]) != NULL)
			irq_ptr->airq_busy = 0;
	}
	apic_skipped_redistribute = 0;
}


/*
 * This function will reprogram the timer.
 *
 * When in oneshot mode the argument is the absolute time in future to
 * generate the interrupt at.
 *
 * When in periodic mode, the argument is the interval at which the
 * interrupts should be generated. There is no need to support the periodic
 * mode timer change at this time.
 */
static void
apic_timer_reprogram(hrtime_t time)
{
	hrtime_t now;
	uint_t ticks;

	/*
	 * We should be called from high PIL context (CBE_HIGH_PIL),
	 * so kpreempt is disabled.
	 */

	if (!apic_oneshot) {
		/* time is the interval for periodic mode */
		ticks = (uint_t)((time) / apic_nsec_per_tick);
	} else {
		/* one shot mode */

		now = gethrtime();

		if (time <= now) {
			/*
			 * requested to generate an interrupt in the past
			 * generate an interrupt as soon as possible
			 */
			ticks = apic_min_timer_ticks;
		} else if ((time - now) > apic_nsec_max) {
			/*
			 * requested to generate an interrupt at a time
			 * further than what we are capable of. Set to max
			 * the hardware can handle
			 */

			ticks = APIC_MAXVAL;
#ifdef DEBUG
			cmn_err(CE_CONT, "apic_timer_reprogram, request at"
			    "  %lld  too far in future, current time"
			    "  %lld \n", time, now);
#endif	/* DEBUG */
		} else
			ticks = (uint_t)((time - now) / apic_nsec_per_tick);
	}

	if (ticks < apic_min_timer_ticks)
		ticks = apic_min_timer_ticks;

	apicadr[APIC_INIT_COUNT] = ticks;

}

/*
 * This function will enable timer interrupts.
 */
static void
apic_timer_enable(void)
{
	/*
	 * We should be Called from high PIL context (CBE_HIGH_PIL),
	 * so kpreempt is disabled.
	 */

	if (!apic_oneshot)
		apicadr[APIC_LOCAL_TIMER] =
		    (apic_clkvect + APIC_BASE_VECT) | AV_TIME;
	else {
		/* one shot */
		apicadr[APIC_LOCAL_TIMER] = (apic_clkvect + APIC_BASE_VECT);
	}
}

/*
 * This function will disable timer interrupts.
 */
static void
apic_timer_disable(void)
{
	/*
	 * We should be Called from high PIL context (CBE_HIGH_PIL),
	 * so kpreempt is disabled.
	 */

	apicadr[APIC_LOCAL_TIMER] = (apic_clkvect + APIC_BASE_VECT) | AV_MASK;
}


cyclic_id_t apic_cyclic_id;

/*
 * If this module needs to be a consumer of cyclic subsystem, they
 * can be added here, since at this time kernel cyclic subsystem is initialized
 * argument is not currently used, and is reserved for future.
 */
static void
apic_post_cyclic_setup(void *arg)
{
_NOTE(ARGUNUSED(arg))
	cyc_handler_t hdlr;
	cyc_time_t when;

	/* cpu_lock is held */

	/* set up cyclics for intr redistribution */

	/*
	 * In peridoc mode intr redistribution processing is done in
	 * apic_intr_enter during clk intr processing
	 */
	if (!apic_oneshot)
		return;

	hdlr.cyh_level = CY_LOW_LEVEL;
	hdlr.cyh_func = (cyc_func_t)apic_redistribute_compute;
	hdlr.cyh_arg = NULL;

	when.cyt_when = 0;
	when.cyt_interval = apic_redistribute_sample_interval;
	apic_cyclic_id = cyclic_add(&hdlr, &when);


}

static void
apic_redistribute_compute(void)
{
	int	i, j, max_busy;

	if (apic_enable_dynamic_migration) {
		if (++apic_nticks == apic_sample_factor_redistribution) {
			/*
			 * Time to call apic_intr_redistribute().
			 * reset apic_nticks. This will cause max_busy
			 * to be calculated below and if it is more than
			 * apic_int_busy, we will do the whole thing
			 */
			apic_nticks = 0;
		}
		max_busy = 0;
		for (i = 0; i < apic_nproc; i++) {

			/*
			 * Check if curipl is non zero & if ISR is in
			 * progress
			 */
			if (((j = apic_cpus[i].aci_curipl) != 0) &&
			    (apic_cpus[i].aci_ISR_in_progress & (1 << j))) {

				int	irq;
				apic_cpus[i].aci_busy++;
				irq = apic_cpus[i].aci_current[j];
				apic_irq_table[irq]->airq_busy++;
			}

			if (!apic_nticks &&
			    (apic_cpus[i].aci_busy > max_busy))
				max_busy = apic_cpus[i].aci_busy;
		}
		if (!apic_nticks) {
			if (max_busy > apic_int_busy_mark) {
			/*
			 * We could make the following check be
			 * skipped > 1 in which case, we get a
			 * redistribution at half the busy mark (due to
			 * double interval). Need to be able to collect
			 * more empirical data to decide if that is a
			 * good strategy. Punt for now.
			 */
				if (apic_skipped_redistribute)
					apic_cleanup_busy();
				else
					apic_intr_redistribute();
			} else
				apic_skipped_redistribute++;
		}
	}
}


static int
apic_acpi_translate_pci_irq(dev_info_t *dip, int busid, int devid,
    int ipin, int *pci_irqp, iflag_t *intr_flagp)
{

	int status;
	acpi_psm_lnk_t acpipsmlnk;

	if ((status = acpi_get_irq_cache_ent(busid, devid, ipin, pci_irqp,
	    intr_flagp)) == ACPI_PSM_SUCCESS) {
		APIC_VERBOSE_IRQ((CE_CONT, "!pcplusmp: Found irqno %d "
		    "from cache for device %s, instance #%d\n", *pci_irqp,
		    ddi_get_name(dip), ddi_get_instance(dip)));
		return (status);
	}

	bzero(&acpipsmlnk, sizeof (acpi_psm_lnk_t));

	if ((status = acpi_translate_pci_irq(dip, ipin, pci_irqp, intr_flagp,
	    &acpipsmlnk)) == ACPI_PSM_FAILURE) {
		APIC_VERBOSE_IRQ((CE_WARN, "pcplusmp: "
		    " acpi_translate_pci_irq failed for device %s, instance"
		    " #%d", ddi_get_name(dip), ddi_get_instance(dip)));
		return (status);
	}

	if (status == ACPI_PSM_PARTIAL && acpipsmlnk.lnkobj != NULL) {
		status = apic_acpi_irq_configure(&acpipsmlnk, dip, pci_irqp,
		    intr_flagp);
		if (status != ACPI_PSM_SUCCESS) {
			status = acpi_get_current_irq_resource(&acpipsmlnk,
			    pci_irqp, intr_flagp);
		}
	}

	if (status == ACPI_PSM_SUCCESS) {
		acpi_new_irq_cache_ent(busid, devid, ipin, *pci_irqp,
		    intr_flagp, &acpipsmlnk);

		APIC_VERBOSE_IRQ((CE_CONT, "pcplusmp: [ACPI] "
		    "new irq %d for device %s, instance #%d\n",
		    *pci_irqp, ddi_get_name(dip), ddi_get_instance(dip)));
	}

	return (status);
}

/*
 * Configures the irq for the interrupt link device identified by
 * acpipsmlnkp.
 *
 * Gets the current and the list of possible irq settings for the
 * device. If apic_unconditional_srs is not set, and the current
 * resource setting is in the list of possible irq settings,
 * current irq resource setting is passed to the caller.
 *
 * Otherwise, picks an irq number from the list of possible irq
 * settings, and sets the irq of the device to this value.
 * If prefer_crs is set, among a set of irq numbers in the list that have
 * the least number of devices sharing the interrupt, we pick current irq
 * resource setting if it is a member of this set.
 *
 * Passes the irq number in the value pointed to by pci_irqp, and
 * polarity and sensitivity in the structure pointed to by dipintrflagp
 * to the caller.
 *
 * Note that if setting the irq resource failed, but successfuly obtained
 * the current irq resource settings, passes the current irq resources
 * and considers it a success.
 *
 * Returns:
 * ACPI_PSM_SUCCESS on success.
 *
 * ACPI_PSM_FAILURE if an error occured during the configuration or
 * if a suitable irq was not found for this device, or if setting the
 * irq resource and obtaining the current resource fails.
 *
 */
static int
apic_acpi_irq_configure(acpi_psm_lnk_t *acpipsmlnkp, dev_info_t *dip,
    int *pci_irqp, iflag_t *dipintr_flagp)
{

	int i, min_share, foundnow, done = 0;
	int32_t irq;
	int32_t share_irq = -1;
	int32_t chosen_irq = -1;
	int cur_irq = -1;
	acpi_irqlist_t *irqlistp;
	acpi_irqlist_t *irqlistent;

	if ((acpi_get_possible_irq_resources(acpipsmlnkp, &irqlistp))
	    == ACPI_PSM_FAILURE) {
		APIC_VERBOSE_IRQ((CE_WARN, "!pcplusmp: Unable to determine "
		    "or assign IRQ for device %s, instance #%d: The system was "
		    "unable to get the list of potential IRQs from ACPI.",
		    ddi_get_name(dip), ddi_get_instance(dip)));

		return (ACPI_PSM_FAILURE);
	}

	if ((acpi_get_current_irq_resource(acpipsmlnkp, &cur_irq,
	    dipintr_flagp) == ACPI_PSM_SUCCESS) && (!apic_unconditional_srs) &&
	    (cur_irq > 0)) {
		/*
		 * If an IRQ is set in CRS and that IRQ exists in the set
		 * returned from _PRS, return that IRQ, otherwise print
		 * a warning
		 */

		if (acpi_irqlist_find_irq(irqlistp, cur_irq, NULL)
		    == ACPI_PSM_SUCCESS) {

			acpi_free_irqlist(irqlistp);
			ASSERT(pci_irqp != NULL);
			*pci_irqp = cur_irq;
			return (ACPI_PSM_SUCCESS);
		}

		APIC_VERBOSE_IRQ((CE_WARN, "!pcplusmp: Could not find the "
		    "current irq %d for device %s, instance #%d in ACPI's "
		    "list of possible irqs for this device. Picking one from "
		    " the latter list.", cur_irq, ddi_get_name(dip),
		    ddi_get_instance(dip)));
	}

	irqlistent = irqlistp;
	min_share = 255;

	while (irqlistent != NULL) {
		irqlistent->intr_flags.bustype = BUS_PCI;

		for (foundnow = 0, i = 0; i < irqlistent->num_irqs; i++) {

			irq = irqlistent->irqs[i];

			if ((irq < 16) && (apic_reserved_irqlist[irq]))
				continue;

			if (irq == 0) {
				/* invalid irq number */
				continue;
			}

			if ((apic_irq_table[irq] == NULL) ||
			    (apic_irq_table[irq]->airq_dip == dip)) {
				chosen_irq = irq;
				foundnow = 1;
				/*
				 * If we do not prefer current irq from crs
				 * or if we do and this irq is the same as
				 * current irq from crs, this is the one
				 * to pick.
				 */
				if (!(apic_prefer_crs) || (irq == cur_irq)) {
					done = 1;
					break;
				}
				continue;
			}

			if (irqlistent->intr_flags.intr_el == INTR_EL_EDGE)
				continue;

			if (!acpi_intr_compatible(irqlistent->intr_flags,
			    apic_irq_table[irq]->airq_iflag))
				continue;

			if ((apic_irq_table[irq]->airq_share < min_share) ||
			    ((apic_irq_table[irq]->airq_share == min_share) &&
			    (cur_irq == irq) && (apic_prefer_crs))) {
				min_share = apic_irq_table[irq]->airq_share;
				share_irq = irq;
				foundnow = 1;
			}
		}

		/*
		 * If we found an IRQ in the inner loop this time, save the
		 * details from the irqlist for later use.
		 */
		if (foundnow && ((chosen_irq != -1) || (share_irq != -1))) {
			/*
			 * Copy the acpi_prs_private_t and flags from this
			 * irq list entry, since we found an irq from this
			 * entry.
			 */
			acpipsmlnkp->acpi_prs_prv = irqlistent->acpi_prs_prv;
			*dipintr_flagp = irqlistent->intr_flags;
		}

		if (done)
			break;

		/* Go to the next irqlist entry */
		irqlistent = irqlistent->next;
	}


	acpi_free_irqlist(irqlistp);
	if (chosen_irq != -1)
		irq = chosen_irq;
	else if (share_irq != -1)
		irq = share_irq;
	else {
		APIC_VERBOSE_IRQ((CE_WARN, "!pcplusmp: Could not find a "
		    "suitable irq from the list of possible irqs for device "
		    "%s, instance #%d in ACPI's list of possible irqs",
		    ddi_get_name(dip), ddi_get_instance(dip)));
		return (ACPI_PSM_FAILURE);
	}

	APIC_VERBOSE_IRQ((CE_CONT, "!pcplusmp: Setting irq %d for device %s "
	    "instance #%d\n", irq, ddi_get_name(dip), ddi_get_instance(dip)));

	if ((acpi_set_irq_resource(acpipsmlnkp, irq)) == ACPI_PSM_SUCCESS) {
		/*
		 * setting irq was successful, check to make sure CRS
		 * reflects that. If CRS does not agree with what we
		 * set, return the irq that was set.
		 */

		if (acpi_get_current_irq_resource(acpipsmlnkp, &cur_irq,
		    dipintr_flagp) == ACPI_PSM_SUCCESS) {

			if (cur_irq != irq)
				APIC_VERBOSE_IRQ((CE_WARN, "!pcplusmp: "
				    "IRQ resource set (irqno %d) for device %s "
				    "instance #%d, differs from current "
				    "setting irqno %d",
				    irq, ddi_get_name(dip),
				    ddi_get_instance(dip), cur_irq));
		}

		/*
		 * return the irq that was set, and not what CRS reports,
		 * since CRS has been seen to be bogus on some systems
		 */
		cur_irq = irq;
	} else {
		APIC_VERBOSE_IRQ((CE_WARN, "!pcplusmp: set resource irq %d "
		    "failed for device %s instance #%d",
		    irq, ddi_get_name(dip), ddi_get_instance(dip)));

		if (cur_irq == -1)
			return (ACPI_PSM_FAILURE);
	}

	ASSERT(pci_irqp != NULL);
	*pci_irqp = cur_irq;
	return (ACPI_PSM_SUCCESS);
}
