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

/*
 * PSMI 1.1 extensions are supported only in 2.6 and later versions.
 * PSMI 1.2 extensions are supported only in 2.7 and later versions.
 * PSMI 1.3 and 1.4 extensions are supported in Solaris 10.
 * PSMI 1.5 extensions are supported in Solaris Nevada.
 * PSMI 1.6 extensions are supported in Solaris Nevada.
 */
#define	PSMI_1_6

#include <sys/processor.h>
#include <sys/time.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>
#include <sys/cram.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/psm_common.h>
#include <sys/apic.h>
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
#include <sys/sunndi.h>


/*
 *	Local Function Prototypes
 */
static int apic_handle_defconf();
static int apic_parse_mpct(caddr_t mpct, int bypass);
static struct apic_mpfps_hdr *apic_find_fps_sig(caddr_t fptr, int size);
static int apic_checksum(caddr_t bptr, int len);
static int apic_find_bus_type(char *bus);
static int apic_find_bus(int busid);
static int apic_find_bus_id(int bustype);
static struct apic_io_intr *apic_find_io_intr(int irqno);
static int apic_find_free_irq(int start, int end);
static void apic_mark_vector(uchar_t oldvector, uchar_t newvector);
static void apic_xlate_vector_free_timeout_handler(void *arg);
static int apic_check_stuck_interrupt(apic_irq_t *irq_ptr, int old_bind_cpu,
    int new_bind_cpu, int apicindex, int intin_no, int which_irq,
    struct ioapic_reprogram_data *drep);
static void apic_record_rdt_entry(apic_irq_t *irqptr, int irq);
static struct apic_io_intr *apic_find_io_intr_w_busid(int irqno, int busid);
static int apic_find_intin(uchar_t ioapic, uchar_t intin);
static int apic_handle_pci_pci_bridge(dev_info_t *idip, int child_devno,
    int child_ipin, struct apic_io_intr **intrp);
static int apic_setup_irq_table(dev_info_t *dip, int irqno,
    struct apic_io_intr *intrp, struct intrspec *ispec, iflag_t *intr_flagp,
    int type);
static void apic_set_pwroff_method_from_mpcnfhdr(struct apic_mp_cnf_hdr *hdrp);
static void apic_try_deferred_reprogram(int ipl, int vect);
static void delete_defer_repro_ent(int which_irq);
static void apic_ioapic_wait_pending_clear(int ioapicindex,
    int intin_no);
static boolean_t apic_is_ioapic_AMD_813x(uint32_t physaddr);
static int apic_acpi_enter_apicmode(void);

int apic_debug_mps_id = 0;	/* 1 - print MPS ID strings */

/* ACPI SCI interrupt configuration; -1 if SCI not used */
int apic_sci_vect = -1;
iflag_t apic_sci_flags;

/*
 * psm name pointer
 */
static char *psm_name;

/* ACPI support routines */
static int acpi_probe(char *);
static int apic_acpi_irq_configure(acpi_psm_lnk_t *acpipsmlnkp, dev_info_t *dip,
    int *pci_irqp, iflag_t *intr_flagp);

static int apic_acpi_translate_pci_irq(dev_info_t *dip, int busid, int devid,
    int ipin, int *pci_irqp, iflag_t *intr_flagp);
static uchar_t acpi_find_ioapic(int irq);
static int acpi_intr_compatible(iflag_t iflag1, iflag_t iflag2);

/*
 * number of bits per byte, from <sys/param.h>
 */
#define	UCHAR_MAX	((1 << NBBY) - 1)

/* Max wait time (in repetitions) for flags to clear in an RDT entry. */
int apic_max_reps_clear_pending = 1000;

/* The irq # is implicit in the array index: */
struct ioapic_reprogram_data apic_reprogram_info[APIC_MAX_VECTOR+1];
/*
 * APIC_MAX_VECTOR + 1 is the maximum # of IRQs as well. ioapic_reprogram_info
 * is indexed by IRQ number, NOT by vector number.
 */

int	apic_intr_policy = INTR_ROUND_ROBIN_WITH_AFFINITY;

int	apic_next_bind_cpu = 1; /* For round robin assignment */
				/* start with cpu 1 */

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
size_t	apic_cpus_size = 0;
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

uchar_t	apic_io_id[MAX_IO_APIC];
volatile uint32_t *apicioadr[MAX_IO_APIC];
static	uchar_t	apic_io_ver[MAX_IO_APIC];
static	uchar_t	apic_io_vectbase[MAX_IO_APIC];
static	uchar_t	apic_io_vectend[MAX_IO_APIC];
uchar_t apic_reserved_irqlist[MAX_ISA_IRQ + 1];
uint32_t apic_physaddr[MAX_IO_APIC];

static	boolean_t ioapic_mask_workaround[MAX_IO_APIC];

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
 * apic_defer_reprogram_lock ensures that only one processor is handling
 * deferred interrupt programming at *_intr_exit time.
 */
static	lock_t	apic_defer_reprogram_lock;

/*
 * The current number of deferred reprogrammings outstanding
 */
uint_t	apic_reprogram_outstanding = 0;

#ifdef DEBUG
/*
 * Counters that keep track of deferred reprogramming stats
 */
uint_t	apic_intr_deferrals = 0;
uint_t	apic_intr_deliver_timeouts = 0;
uint_t	apic_last_ditch_reprogram_failures = 0;
uint_t	apic_deferred_setup_failures = 0;
uint_t	apic_defer_repro_total_retries = 0;
uint_t	apic_defer_repro_successes = 0;
uint_t	apic_deferred_spurious_enters = 0;
#endif

static	int	apic_io_max = 0;	/* no. of i/o apics enabled */

static	struct apic_io_intr *apic_io_intrp = 0;
static	struct apic_bus	*apic_busp;

uchar_t	apic_vector_to_irq[APIC_MAX_VECTOR+1];
uchar_t	apic_resv_vector[MAXIPL+1];

char	apic_level_intr[APIC_MAX_VECTOR+1];

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

/*
 * Following declarations are for revectoring; used when ISRs at different
 * IPLs share an irq.
 */
static	lock_t	apic_revector_lock;
int	apic_revector_pending = 0;
static	uchar_t	*apic_oldvec_to_newvec;
static	uchar_t	*apic_newvec_to_oldvec;

typedef struct prs_irq_list_ent {
	int			list_prio;
	int32_t			irq;
	iflag_t			intrflags;
	acpi_prs_private_t	prsprv;
	struct prs_irq_list_ent	*next;
} prs_irq_list_t;


/*
 * ACPI variables
 */
/* 1 = acpi is enabled & working, 0 = acpi is not enabled or not there */
int apic_enable_acpi = 0;

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
int
apic_probe_common(char *modname)
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

	/*
	 * Remember who we are
	 */
	psm_name = modname;

	/* Allow override for MADT-only mode */
	acpi_user_options = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    "acpi-user-options", 0);
	apic_use_acpi_madt_only = ((acpi_user_options & ACPI_OUSER_MADT) != 0);

	/* Allow apic_use_acpi to override MADT-only mode */
	if (!apic_use_acpi)
		apic_use_acpi_madt_only = 0;

	retval = acpi_probe(modname);

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
	apicadr = (uint32_t *)mapin_apic((uint32_t)hdrp->mpcnf_local_apic,
	    APIC_LOCAL_MEMLEN, PROT_READ | PROT_WRITE);
	if (!apicadr)
		goto apic_fail1;

	/* Parse all information in the tables */
	bypass_cpu_and_ioapics_in_mptables = (retval == PSM_SUCCESS);
	if (apic_parse_mpct(mpct, bypass_cpu_and_ioapics_in_mptables) ==
	    PSM_SUCCESS)
		return (PSM_SUCCESS);

	for (i = 0; i < apic_io_max; i++)
		mapout_ioapic((caddr_t)apicioadr[i], APIC_IO_MEMLEN);
	if (apic_cpus)
		kmem_free(apic_cpus, apic_cpus_size);
	if (apicadr)
		mapout_apic((caddr_t)apicadr, APIC_LOCAL_MEMLEN);
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
		cmn_err(CE_CONT, "%s: MPS OEM ID = '%c%c%c%c%c%c%c%c'"
		    "Product ID = '%c%c%c%c%c%c%c%c%c%c%c%c'\n",
		    psm_name,
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
acpi_probe(char *modname)
{
	int			i, intmax, index;
	uint32_t		id, ver;
	int			acpi_verboseflags = 0;
	int			madt_seen, madt_size;
	APIC_HEADER		*ap;
	MADT_PROCESSOR_APIC	*mpa;
	MADT_PROCESSOR_X2APIC	*mpx2a;
	MADT_IO_APIC		*mia;
	MADT_IO_SAPIC		*misa;
	MADT_INTERRUPT_OVERRIDE	*mio;
	MADT_NMI_SOURCE		*mns;
	MADT_INTERRUPT_SOURCE	*mis;
	MADT_LOCAL_APIC_NMI	*mlan;
	MADT_LOCAL_X2APIC_NMI	*mx2alan;
	MADT_ADDRESS_OVERRIDE	*mao;
	int			sci;
	iflag_t			sci_flags;
	volatile uint32_t	*ioapic;
	int			ioapic_ix;
	uint32_t		local_ids[NCPU];
	uint32_t		proc_ids[NCPU];
	uchar_t			hid;

	if (!apic_use_acpi)
		return (PSM_FAILURE);

	if (AcpiGetFirmwareTable(APIC_SIG, 1, ACPI_LOGICAL_ADDRESSING,
	    (ACPI_TABLE_HEADER **) &acpi_mapic_dtp) != AE_OK)
		return (PSM_FAILURE);

	apicadr = mapin_apic((uint32_t)acpi_mapic_dtp->LocalApicAddress,
	    APIC_LOCAL_MEMLEN, PROT_READ | PROT_WRITE);
	if (!apicadr)
		return (PSM_FAILURE);

	/*
	 * We don't enable x2APIC when Solaris is running under xVM.
	 */
#if !defined(__xpv)
	if (apic_detect_x2apic()) {
		apic_enable_x2apic();
	}
#endif

	id = apic_reg_ops->apic_read(APIC_LID_REG);
	local_ids[0] = (uchar_t)(id >> 24);
	apic_nproc = index = 1;
	CPUSET_ONLY(apic_cpumask, 0);
	apic_io_max = 0;

	ap = (APIC_HEADER *) (acpi_mapic_dtp + 1);
	madt_size = acpi_mapic_dtp->Length;
	madt_seen = sizeof (*acpi_mapic_dtp);

	while (madt_seen < madt_size) {
		switch (ap->Type) {
		case APIC_PROCESSOR:
			mpa = (MADT_PROCESSOR_APIC *) ap;
			if (mpa->ProcessorEnabled) {
				if (mpa->LocalApicId == local_ids[0]) {
					proc_ids[0] = mpa->ProcessorId;
					acpica_map_cpu(0, mpa->ProcessorId);
				} else if (apic_nproc < NCPU && use_mp &&
				    apic_nproc < boot_ncpus) {
					local_ids[index] = mpa->LocalApicId;
					proc_ids[index] = mpa->ProcessorId;
					CPUSET_ADD(apic_cpumask, index);
					acpica_map_cpu(index, mpa->ProcessorId);
					index++;
					apic_nproc++;
				} else if (apic_nproc == NCPU)
					cmn_err(CE_WARN, "%s: exceeded "
					    "maximum no. of CPUs (= %d)",
					    psm_name,  NCPU);
			}
			break;

		case APIC_IO:
			mia = (MADT_IO_APIC *) ap;
			if (apic_io_max < MAX_IO_APIC) {
				ioapic_ix = apic_io_max;
				apic_io_id[apic_io_max] = mia->IoApicId;
				apic_io_vectbase[apic_io_max] =
				    mia->Interrupt;
				apic_physaddr[apic_io_max] =
				    (uint32_t)mia->Address;
				ioapic = apicioadr[apic_io_max] =
				    mapin_ioapic((uint32_t)mia->Address,
				    APIC_IO_MEMLEN, PROT_READ | PROT_WRITE);
				if (!ioapic)
					goto cleanup;
				ioapic_mask_workaround[apic_io_max] =
				    apic_is_ioapic_AMD_813x(mia->Address);
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

		case X2APIC_PROCESSOR:
			mpx2a = (MADT_PROCESSOR_X2APIC *) ap;

			/*
			 * All logical processors with APIC ID values
			 * of 255 and greater will have their APIC
			 * reported through Processor X2APIC structure.
			 * All logical processors with APIC ID less than
			 * 255 will have their APIC reported through
			 * Processor Local APIC.
			 */
			if ((mpx2a->ProcessorEnabled) &&
			    (mpx2a->X2LocalApicId >> 8)) {
				if (apic_nproc < NCPU && use_mp &&
				    apic_nproc < boot_ncpus) {
					local_ids[index] =
					    mpx2a->X2LocalApicId;
					CPUSET_ADD(apic_cpumask, index);
					acpica_map_cpu(index,
					    mpx2a->ProcessorUID);
					index++;
					apic_nproc++;
				} else if (apic_nproc == NCPU) {
					cmn_err(CE_WARN, "%s: exceeded"
					    " maximum no. of CPUs ("
					    "=%d)", psm_name, NCPU);
				}
			}

			break;

		case X2APIC_LOCAL_NMI:
			/* UNIMPLEMENTED */
			mx2alan = (MADT_LOCAL_X2APIC_NMI *) ap;
			if (mx2alan->ProcessorUID >> 8)
				acpi_nmi_ccnt++;

#ifdef	DEBUG
			cmn_err(CE_NOTE, "!apic: local x2apic nmi: %d %d %d %d"
			    "\n", mx2alan->ProcessorUID, mx2alan->Polarity,
			    mx2alan->TriggerMode, mx2alan->Lint);
#endif

			break;

		default:
			break;
		}

		/* advance to next entry */
		madt_seen += ap->Length;
		ap = (APIC_HEADER *)(((char *)ap) + ap->Length);
	}

	apic_cpus_size = apic_nproc * sizeof (*apic_cpus);
	if ((apic_cpus = kmem_zalloc(apic_cpus_size, KM_NOSLEEP)) == NULL)
		goto cleanup;

	/*
	 * ACPI doesn't provide the local apic ver, get it directly from the
	 * local apic
	 */
	ver = apic_reg_ops->apic_read(APIC_VERS_REG);
	for (i = 0; i < apic_nproc; i++) {
		apic_cpus[i].aci_local_id = local_ids[i];
		apic_cpus[i].aci_local_ver = (uchar_t)(ver & 0xFF);
	}

	for (i = 0; i < apic_io_max; i++) {
		ioapic_ix = i;

		/*
		 * need to check Sitka on the following acpi problem
		 * On the Sitka, the ioapic's apic_id field isn't reporting
		 * the actual io apic id. We have reported this problem
		 * to Intel. Until they fix the problem, we will get the
		 * actual id directly from the ioapic.
		 */
		id = ioapic_read(ioapic_ix, APIC_ID_CMD);
		hid = (uchar_t)(id >> 24);

		if (hid != apic_io_id[i]) {
			if (apic_io_id[i] == 0)
				apic_io_id[i] = hid;
			else { /* set ioapic id to whatever reported by ACPI */
				id = ((uint32_t)apic_io_id[i]) << 24;
				ioapic_write(ioapic_ix, APIC_ID_CMD, id);
			}
		}
		ver = ioapic_read(ioapic_ix, APIC_VERS_CMD);
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
	 * Call acpica_build_processor_map() now that we have
	 * ACPI namesspace access
	 */
	acpica_build_processor_map();

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

	if (acpi_psm_init(modname, acpi_verboseflags) == ACPI_PSM_FAILURE)
		goto cleanup;

	/* Enable ACPI APIC interrupt routing */
	if (apic_acpi_enter_apicmode() != PSM_FAILURE) {
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
		mapout_apic((caddr_t)apicadr, APIC_LOCAL_MEMLEN);
		apicadr = NULL;
	}
	apic_nproc = 0;
	for (i = 0; i < apic_io_max; i++) {
		mapout_ioapic((caddr_t)apicioadr[i], APIC_IO_MEMLEN);
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
	apicioadr[0] = mapin_ioapic(APIC_IO_ADDR,
	    APIC_IO_MEMLEN, PROT_READ | PROT_WRITE);
	/*LINTED: pointer cast may result in improper alignment */
	apicadr = (uint32_t *)psm_map_phys(APIC_LOCAL_ADDR,
	    APIC_LOCAL_MEMLEN, PROT_READ);
	apic_cpus_size = 2 * sizeof (*apic_cpus);
	apic_cpus = (apic_cpus_info_t *)
	    kmem_zalloc(apic_cpus_size, KM_NOSLEEP);
	if ((!apicadr) || (!apicioadr[0]) || (!apic_cpus))
		goto apic_handle_defconf_fail;
	CPUSET_ONLY(apic_cpumask, 0);
	CPUSET_ADD(apic_cpumask, 1);
	apic_nproc = 2;
	lid = apic_reg_ops->apic_read(APIC_LID_REG);
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
		kmem_free(apic_cpus, apic_cpus_size);
	if (apicadr)
		mapout_apic((caddr_t)apicadr, APIC_LOCAL_MEMLEN);
	if (apicioadr[0])
		mapout_ioapic((caddr_t)apicioadr[0], APIC_IO_MEMLEN);
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
	int			ioapic_ix;
	uint_t	lid;
	uint32_t	id;
	uchar_t hid;
	int	warned = 0;

	/*LINTED: pointer cast may result in improper alignment */
	procp = (struct apic_procent *)(mpct + sizeof (struct apic_mp_cnf_hdr));

	/* No need to count cpu entries if we won't use them */
	if (!bypass_cpus_and_ioapics) {

		/* Find max # of CPUS and allocate structure accordingly */
		apic_nproc = 0;
		CPUSET_ZERO(apic_cpumask);
		while (procp->proc_entry == APIC_CPU_ENTRY) {
			if (procp->proc_cpuflags & CPUFLAGS_EN) {
				if (apic_nproc < NCPU && use_mp &&
				    apic_nproc < boot_ncpus) {
					CPUSET_ADD(apic_cpumask, apic_nproc);
					apic_nproc++;
				} else if (apic_nproc == NCPU && !warned) {
					cmn_err(CE_WARN, "%s: exceeded "
					    "maximum no. of CPUs (= %d)",
					    psm_name, NCPU);
					warned = 1;
				}

			}
			procp++;
		}
		apic_cpus_size = apic_nproc * sizeof (*apic_cpus);
		if (!apic_nproc || !(apic_cpus = (apic_cpus_info_t *)
		    kmem_zalloc(apic_cpus_size, KM_NOSLEEP)))
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
				lid = apic_reg_ops->apic_read(APIC_LID_REG);
				apic_cpus[0].aci_local_id = procp->proc_apicid;
				if (apic_cpus[0].aci_local_id !=
				    (uchar_t)(lid >> APIC_ID_BIT_OFFSET)) {
					return (PSM_FAILURE);
				}
				apic_cpus[0].aci_local_ver =
				    procp->proc_version;
			} else if (apic_nproc < NCPU && use_mp &&
			    apic_nproc < boot_ncpus) {
				apic_cpus[apic_nproc].aci_local_id =
				    procp->proc_apicid;

				apic_cpus[apic_nproc].aci_local_ver =
				    procp->proc_version;
				apic_nproc++;

			}
		}
		procp++;
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
				    mapin_ioapic(
				    (uint32_t)ioapicp->io_apic_addr,
				    APIC_IO_MEMLEN, PROT_READ | PROT_WRITE);

				if (!apicioadr[apic_io_max])
					return (PSM_FAILURE);

				ioapic_mask_workaround[apic_io_max] =
				    apic_is_ioapic_AMD_813x(
				    ioapicp->io_apic_addr);

				ioapic_ix = apic_io_max;
				id = ioapic_read(ioapic_ix, APIC_ID_CMD);
				hid = (uchar_t)(id >> 24);

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

						id = ((uint32_t)
						    apic_io_id[apic_io_max]) <<
						    24;

						ioapic_write(ioapic_ix,
						    APIC_ID_CMD, id);
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

boolean_t
apic_cpu_in_range(int cpu)
{
	return ((cpu & ~IRQ_USER_BOUND) < apic_nproc);
}

uint16_t
apic_get_apic_version()
{
	int i;
	uchar_t min_io_apic_ver = 0;
	static uint16_t version;		/* Cache as value is constant */
	static boolean_t found = B_FALSE;	/* Accomodate zero version */

	if (found == B_FALSE) {
		found = B_TRUE;

		/*
		 * Don't assume all IO APICs in the system are the same.
		 *
		 * Set to the minimum version.
		 */
		for (i = 0; i < apic_io_max; i++) {
			if ((apic_io_ver[i] != 0) &&
			    ((min_io_apic_ver == 0) ||
			    (min_io_apic_ver >= apic_io_ver[i])))
				min_io_apic_ver = apic_io_ver[i];
		}

		/* Assume all local APICs are of the same version. */
		version = (min_io_apic_ver << 8) | apic_cpus[0].aci_local_ver;
	}
	return (version);
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
apic_init_common()
{
	int	i, j, indx;
	int	*iptr;

	/*
	 * Initialize apic_ipls from apic_vectortoipl.  This array is
	 * used in apic_intr_enter to determine the IPL to use for the
	 * corresponding vector.  On some systems, due to hardware errata
	 * and interrupt sharing, the IPL may not correspond to the IPL listed
	 * in apic_vectortoipl (see apic_addspl and apic_delspl).
	 */
	for (i = 0; i < (APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL); i++) {
		indx = i * APIC_VECTOR_PER_IPL;

		for (j = 0; j < APIC_VECTOR_PER_IPL; j++, indx++)
			apic_ipls[indx] = apic_vectortoipl[i];
	}

	/* cpu 0 is always up (for now) */
	apic_cpus[0].aci_status = APIC_CPU_ONLINE | APIC_CPU_INTR_ENABLE;

	iptr = (int *)&apic_irq_table[0];
	for (i = 0; i <= APIC_MAX_VECTOR; i++) {
		apic_level_intr[i] = 0;
		*iptr++ = NULL;
		apic_vector_to_irq[i] = APIC_RESV_IRQ;

		/* These *must* be initted to B_TRUE! */
		apic_reprogram_info[i].done = B_TRUE;
		apic_reprogram_info[i].irqp = NULL;
		apic_reprogram_info[i].tries = 0;
		apic_reprogram_info[i].bindcpu = 0;
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
}

void
ioapic_init_intr(int mask_apic)
{
	int ioapic_ix;
	struct intrspec ispec;
	apic_irq_t *irqptr;
	int i, j;
	ulong_t iflag;

	LOCK_INIT_CLEAR(&apic_revector_lock);
	LOCK_INIT_CLEAR(&apic_defer_reprogram_lock);

	/* mask interrupt vectors */
	for (j = 0; j < apic_io_max && mask_apic; j++) {
		int intin_max;

		ioapic_ix = j;
		/* Bits 23-16 define the maximum redirection entries */
		intin_max = (ioapic_read(ioapic_ix, APIC_VERS_CMD) >> 16)
		    & 0xff;
		for (i = 0; i <= intin_max; i++)
			ioapic_write(ioapic_ix, APIC_RDT_CMD + 2 * i, AV_MASK);
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

		iflag = intr_clear();
		lock_set(&apic_ioapic_lock);

		/* Program I/O APIC */
		(void) apic_setup_io_intr(irqptr, apic_sci_vect, B_FALSE);

		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);

		irqptr->airq_share++;
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
int
apic_addspl_common(int irqno, int ipl, int min_ipl, int max_ipl)
{
	uchar_t vector;
	ulong_t iflag;
	apic_irq_t *irqptr, *irqheadptr;
	int irqindex;

	ASSERT(max_ipl <= UCHAR_MAX);
	irqindex = IRQINDEX(irqno);

	if ((irqindex == -1) || (!apic_irq_table[irqindex]))
		return (PSM_FAILURE);

	mutex_enter(&airq_mutex);
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

	mutex_exit(&airq_mutex);

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

	if (!apic_picinit_called)
		return (PSM_SUCCESS);

	/*
	 * Upgrade vector if max_ipl is not earlier ipl. If we cannot allocate,
	 * return failure. Not very elegant, but then we hope the
	 * machine will blow up with ...
	 */
	if (irqptr->airq_ipl != max_ipl &&
	    !ioapic_mask_workaround[irqptr->airq_ioapicindex]) {

		vector = apic_allocate_vector(max_ipl, irqindex, 1);
		if (vector == 0) {
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

				iflag = intr_clear();
				lock_set(&apic_ioapic_lock);

				(void) apic_setup_io_intr(irqptr, irqindex,
				    B_FALSE);

				lock_clear(&apic_ioapic_lock);
				intr_restore(iflag);
			}
			irqptr = irqptr->airq_next;
		}
		return (PSM_SUCCESS);

	} else if (irqptr->airq_ipl != max_ipl &&
	    ioapic_mask_workaround[irqptr->airq_ioapicindex]) {
		/*
		 * We cannot upgrade the vector, but we can change
		 * the IPL that this vector induces.
		 *
		 * Note that we subtract APIC_BASE_VECT from the vector
		 * here because this array is used in apic_intr_enter
		 * (no need to add APIC_BASE_VECT in that hot code
		 * path since we can do it in the rarely-executed path
		 * here).
		 */
		apic_ipls[irqptr->airq_vector - APIC_BASE_VECT] =
		    (uchar_t)max_ipl;

		irqptr = irqheadptr;
		while (irqptr) {
			irqptr->airq_ipl = (uchar_t)max_ipl;
			irqptr = irqptr->airq_next;
		}

		return (PSM_SUCCESS);
	}

	ASSERT(irqptr);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	(void) apic_setup_io_intr(irqptr, irqindex, B_FALSE);

	lock_clear(&apic_ioapic_lock);
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
int
apic_delspl_common(int irqno, int ipl, int min_ipl, int max_ipl)
{
	uchar_t vector;
	uint32_t bind_cpu;
	int intin, irqindex;
	int ioapic_ix;
	apic_irq_t	*irqptr, *irqheadptr, *irqp;
	ulong_t iflag;

	mutex_enter(&airq_mutex);
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

	mutex_exit(&airq_mutex);

	if (ipl < max_ipl)
		return (PSM_SUCCESS);

	/* return if it is not hardware interrupt */
	if (irqptr->airq_mps_intr_index == RESERVE_INDEX)
		return (PSM_SUCCESS);

	if (!apic_picinit_called) {
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
	if ((irqptr->airq_ipl != max_ipl) && (max_ipl != PSM_INVALID_IPL) &&
	    !ioapic_mask_workaround[irqptr->airq_ioapicindex]) {
		apic_irq_t	*irqp;
		if (vector = apic_allocate_vector(max_ipl, irqno, 1)) {
			apic_mark_vector(irqheadptr->airq_vector, vector);
			irqp = irqheadptr;
			while (irqp) {
				irqp->airq_vector = vector;
				irqp->airq_ipl = (uchar_t)max_ipl;
				if (irqp->airq_temp_cpu != IRQ_UNINIT) {
					apic_record_rdt_entry(irqp, irqindex);

					iflag = intr_clear();
					lock_set(&apic_ioapic_lock);

					(void) apic_setup_io_intr(irqp,
					    irqindex, B_FALSE);

					lock_clear(&apic_ioapic_lock);
					intr_restore(iflag);
				}
				irqp = irqp->airq_next;
			}
		}

	} else if (irqptr->airq_ipl != max_ipl &&
	    max_ipl != PSM_INVALID_IPL &&
	    ioapic_mask_workaround[irqptr->airq_ioapicindex]) {

	/*
	 * We cannot downgrade the IPL of the vector below the vector's
	 * hardware priority. If we did, it would be possible for a
	 * higher-priority hardware vector to interrupt a CPU running at an IPL
	 * lower than the hardware priority of the interrupting vector (but
	 * higher than the soft IPL of this IRQ). When this happens, we would
	 * then try to drop the IPL BELOW what it was (effectively dropping
	 * below base_spl) which would be potentially catastrophic.
	 *
	 * (e.g. Suppose the hardware vector associated with this IRQ is 0x40
	 * (hardware IPL of 4).  Further assume that the old IPL of this IRQ
	 * was 4, but the new IPL is 1.  If we forced vector 0x40 to result in
	 * an IPL of 1, it would be possible for the processor to be executing
	 * at IPL 3 and for an interrupt to come in on vector 0x40, interrupting
	 * the currently-executing ISR.  When apic_intr_enter consults
	 * apic_irqs[], it will return 1, bringing the IPL of the CPU down to 1
	 * so even though the processor was running at IPL 4, an IPL 1
	 * interrupt will have interrupted it, which must not happen)).
	 *
	 * Effectively, this means that the hardware priority corresponding to
	 * the IRQ's IPL (in apic_ipls[]) cannot be lower than the vector's
	 * hardware priority.
	 *
	 * (In the above example, then, after removal of the IPL 4 device's
	 * interrupt handler, the new IPL will continue to be 4 because the
	 * hardware priority that IPL 1 implies is lower than the hardware
	 * priority of the vector used.)
	 */
		/* apic_ipls is indexed by vector, starting at APIC_BASE_VECT */
		const int apic_ipls_index = irqptr->airq_vector -
		    APIC_BASE_VECT;
		const int vect_inherent_hwpri = irqptr->airq_vector >>
		    APIC_IPL_SHIFT;

		/*
		 * If there are still devices using this IRQ, determine the
		 * new ipl to use.
		 */
		if (irqptr->airq_share) {
			int vect_desired_hwpri, hwpri;

			ASSERT(max_ipl < MAXIPL);
			vect_desired_hwpri = apic_ipltopri[max_ipl] >>
			    APIC_IPL_SHIFT;

			/*
			 * If the desired IPL's hardware priority is lower
			 * than that of the vector, use the hardware priority
			 * of the vector to determine the new IPL.
			 */
			hwpri = (vect_desired_hwpri < vect_inherent_hwpri) ?
			    vect_inherent_hwpri : vect_desired_hwpri;

			/*
			 * Now, to get the right index for apic_vectortoipl,
			 * we need to subtract APIC_BASE_VECT from the
			 * hardware-vector-equivalent (in hwpri).  Since hwpri
			 * is already shifted, we shift APIC_BASE_VECT before
			 * doing the subtraction.
			 */
			hwpri -= (APIC_BASE_VECT >> APIC_IPL_SHIFT);

			ASSERT(hwpri >= 0);
			ASSERT(hwpri < MAXIPL);
			max_ipl = apic_vectortoipl[hwpri];
			apic_ipls[apic_ipls_index] = max_ipl;

			irqp = irqheadptr;
			while (irqp) {
				irqp->airq_ipl = (uchar_t)max_ipl;
				irqp = irqp->airq_next;
			}
		} else {
			/*
			 * No more devices on this IRQ, so reset this vector's
			 * element in apic_ipls to the original IPL for this
			 * vector
			 */
			apic_ipls[apic_ipls_index] =
			    apic_vectortoipl[vect_inherent_hwpri];
		}
	}

	if (irqptr->airq_share)
		return (PSM_SUCCESS);

	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	if (irqptr->airq_mps_intr_index == MSI_INDEX) {
		/*
		 * Disable the MSI vector
		 * Make sure we only disable on the last
		 * of the multi-MSI support
		 */
		if (i_ddi_intr_get_current_nintrs(irqptr->airq_dip) == 1) {
			apic_pci_msi_unconfigure(irqptr->airq_dip,
			    DDI_INTR_TYPE_MSI, irqptr->airq_ioapicindex);

			apic_pci_msi_disable_mode(irqptr->airq_dip,
			    DDI_INTR_TYPE_MSI);
		}
	} else if (irqptr->airq_mps_intr_index == MSIX_INDEX) {
		/*
		 * Disable the MSI-X vector
		 * needs to clear its mask and addr/data for each MSI-X
		 */
		apic_pci_msi_unconfigure(irqptr->airq_dip, DDI_INTR_TYPE_MSIX,
		    irqptr->airq_origirq);
		/*
		 * Make sure we only disable on the last MSI-X
		 */
		if (i_ddi_intr_get_current_nintrs(irqptr->airq_dip) == 1) {
			apic_pci_msi_disable_mode(irqptr->airq_dip,
			    DDI_INTR_TYPE_MSIX);
		}
	} else {
		/*
		 * The assumption here is that this is safe, even for
		 * systems with IOAPICs that suffer from the hardware
		 * erratum because all devices have been quiesced before
		 * they unregister their interrupt handlers.  If that
		 * assumption turns out to be false, this mask operation
		 * can induce the same erratum result we're trying to
		 * avoid.
		 */
		ioapic_ix = irqptr->airq_ioapicindex;
		intin = irqptr->airq_intin_no;
		ioapic_write(ioapic_ix, APIC_RDT_CMD + 2 * intin, AV_MASK);
	}

	if (max_ipl == PSM_INVALID_IPL) {
		ASSERT(irqheadptr == irqptr);
		bind_cpu = irqptr->airq_temp_cpu;
		if (((uint32_t)bind_cpu != IRQ_UNBOUND) &&
		    ((uint32_t)bind_cpu != IRQ_UNINIT)) {
			ASSERT((bind_cpu & ~IRQ_USER_BOUND) < apic_nproc);
			if (bind_cpu & IRQ_USER_BOUND) {
				/* If hardbound, temp_cpu == cpu */
				bind_cpu &= ~IRQ_USER_BOUND;
				apic_cpus[bind_cpu].aci_bound--;
			} else
				apic_cpus[bind_cpu].aci_temp_bound--;
		}
		irqptr->airq_temp_cpu = IRQ_UNINIT;
		irqptr->airq_mps_intr_index = FREE_INDEX;
		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
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
 * apic_introp_xlate() replaces apic_translate_irq() and is
 * called only from apic_intr_ops().  With the new ADII framework,
 * the priority can no longer be retrieved through i_ddi_get_intrspec().
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
	int parent_is_pci_or_pciex = 0;
	int child_is_pciex = 0;

	DDI_INTR_IMPLDBG((CE_CONT, "apic_introp_xlate: dip=0x%p name=%s "
	    "type=%d irqno=0x%x\n", (void *)dip, ddi_get_name(dip), type,
	    irqno));

	dev_len = sizeof (dev_type);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device_type", (caddr_t)dev_type,
	    &dev_len) == DDI_PROP_SUCCESS) {
		if ((strcmp(dev_type, "pci") == 0) ||
		    (strcmp(dev_type, "pciex") == 0))
			parent_is_pci_or_pciex = 1;
	}

	if (parent_is_pci_or_pciex && ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie-capid-pointer", PCI_CAP_NEXT_PTR_NULL) !=
	    PCI_CAP_NEXT_PTR_NULL) {
		child_is_pciex = 1;
	}

	if (DDI_INTR_IS_MSI_OR_MSIX(type)) {
		if ((airqp = apic_find_irq(dip, ispec, type)) != NULL) {
			airqp->airq_iflag.bustype =
			    child_is_pciex ? BUS_PCIE : BUS_PCI;
			return (apic_vector_to_irq[airqp->airq_vector]);
		}
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

	if (parent_is_pci_or_pciex) {
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

			intr_flag.bustype = child_is_pciex ? BUS_PCIE : BUS_PCI;
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
		if (((dipp = ddi_get_parent(dip)) == (dev_info_t *)NULL) ||
		    (pci_config_setup(dipp, &cfg_handle) != DDI_SUCCESS))
			return (-1);
		if ((pci_config_get8(cfg_handle, PCI_CONF_BASCLASS) ==
		    PCI_CLASS_BRIDGE) && (pci_config_get8(cfg_handle,
		    PCI_CONF_SUBCLASS) == PCI_BRIDGE_PCI)) {
			pci_config_teardown(&cfg_handle);
			if (acpica_get_bdf(dipp, &bridge_bus, &bridge_devno,
			    NULL) != 0)
				return (-1);
			/*
			 * This is the rotating scheme documented in the
			 * PCI-to-PCI spec.  If the PCI-to-PCI bridge is
			 * behind another PCI-to-PCI bridge, then it needs
			 * to keep ascending until an interrupt entry is
			 * found or the root is reached.
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
		} else {
			pci_config_teardown(&cfg_handle);
			return (-1);
		}
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
			vector = apic_modify_vector(vector, newirq);
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
uint32_t
apic_bind_intr(dev_info_t *dip, int irq, uchar_t ioapicid, uchar_t intin)
{
	int	instance, instno, prop_len, bind_cpu, count;
	uint_t	i, rc;
	uint32_t cpu;
	major_t	major;
	char	*name, *drv_name, *prop_val, *cptr;
	char	prop_name[32];


	if (apic_intr_policy == INTR_LOWEST_PRIORITY)
		return (IRQ_UNBOUND);

	if (apic_nproc == 1)
		return (0);

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
					    "!%s: %s (%s) instance #%d "
					    "vector 0x%x ioapic 0x%x "
					    "intin 0x%x is bound to cpu %d\n",
					    psm_name,
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
			cmn_err(CE_WARN, "%s: %s=%s: CPU %d not present",
			    psm_name, prop_name, prop_val, bind_cpu);
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
		bind_cpu = apic_next_bind_cpu++;
		if (bind_cpu >= apic_nproc) {
			apic_next_bind_cpu = 1;
			bind_cpu = 0;
		}
	}
	if (drv_name != NULL)
		cmn_err(CE_CONT, "!%s: %s (%s) instance %d "
		    "vector 0x%x ioapic 0x%x intin 0x%x is bound to cpu %d\n",
		    psm_name, name, drv_name, instance,
		    irq, ioapicid, intin, bind_cpu & ~IRQ_USER_BOUND);
	else
		cmn_err(CE_CONT, "!%s: "
		    "vector 0x%x ioapic 0x%x intin 0x%x is bound to cpu %d\n",
		    psm_name, irq, ioapicid, intin, bind_cpu & ~IRQ_USER_BOUND);

	return ((uint32_t)bind_cpu);
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
	"VME ", BUS_VME,
	"PCI-E ", BUS_PCIE
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
			cmn_err(CE_WARN, "%s: NO available IRQ", psm_name);
			return (-1);
		}
	}
	if (apic_irq_table[freeirq] == NULL) {
		apic_irq_table[freeirq] =
		    kmem_zalloc(sizeof (apic_irq_t), KM_NOSLEEP);
		if (apic_irq_table[freeirq] == NULL) {
			cmn_err(CE_WARN, "%s: NO memory to allocate IRQ",
			    psm_name);
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
	ulong_t iflag;

	iflag = intr_clear();
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
uchar_t
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
	ulong_t iflag;
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
 * Bind interrupt corresponding to irq_ptr to bind_cpu.
 * Must be called with interrupts disabled and apic_ioapic_lock held
 */
int
apic_rebind(apic_irq_t *irq_ptr, int bind_cpu,
    struct ioapic_reprogram_data *drep)
{
	int			ioapicindex, intin_no;
	uint32_t		airq_temp_cpu;
	apic_cpus_info_t	*cpu_infop;
	uint32_t		rdt_entry;
	int			which_irq;

	which_irq = apic_vector_to_irq[irq_ptr->airq_vector];

	intin_no = irq_ptr->airq_intin_no;
	ioapicindex = irq_ptr->airq_ioapicindex;
	airq_temp_cpu = irq_ptr->airq_temp_cpu;
	if (airq_temp_cpu != IRQ_UNINIT && airq_temp_cpu != IRQ_UNBOUND) {
		if (airq_temp_cpu & IRQ_USER_BOUND)
			/* Mask off high bit so it can be used as array index */
			airq_temp_cpu &= ~IRQ_USER_BOUND;

		ASSERT(airq_temp_cpu < apic_nproc);
	}

	/*
	 * Can't bind to a CPU that's not accepting interrupts:
	 */
	cpu_infop = &apic_cpus[bind_cpu & ~IRQ_USER_BOUND];
	if (!(cpu_infop->aci_status & APIC_CPU_INTR_ENABLE))
		return (1);

	/*
	 * If we are about to change the interrupt vector for this interrupt,
	 * and this interrupt is level-triggered, attached to an IOAPIC,
	 * has been delivered to a CPU and that CPU has not handled it
	 * yet, we cannot reprogram the IOAPIC now.
	 */
	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {

		rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapicindex,
		    intin_no);

		if ((irq_ptr->airq_vector != RDT_VECTOR(rdt_entry)) &&
		    apic_check_stuck_interrupt(irq_ptr, airq_temp_cpu,
		    bind_cpu, ioapicindex, intin_no, which_irq, drep) != 0) {

			return (0);
		}

		/*
		 * NOTE: We do not unmask the RDT here, as an interrupt MAY
		 * still come in before we have a chance to reprogram it below.
		 * The reprogramming below will simultaneously change and
		 * unmask the RDT entry.
		 */

		if ((uint32_t)bind_cpu == IRQ_UNBOUND) {
			rdt_entry = AV_LDEST | AV_LOPRI |
			    irq_ptr->airq_rdt_entry;

			/* Write the RDT entry -- no specific CPU binding */
			WRITE_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapicindex, intin_no,
			    AV_TOALL);

			if (airq_temp_cpu != IRQ_UNINIT && airq_temp_cpu !=
			    IRQ_UNBOUND)
				apic_cpus[airq_temp_cpu].aci_temp_bound--;

			/*
			 * Write the vector, trigger, and polarity portion of
			 * the RDT
			 */
			WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapicindex, intin_no,
			    rdt_entry);

			irq_ptr->airq_temp_cpu = IRQ_UNBOUND;
			return (0);
		}
	}

	if (bind_cpu & IRQ_USER_BOUND) {
		cpu_infop->aci_bound++;
	} else {
		cpu_infop->aci_temp_bound++;
	}
	ASSERT((bind_cpu & ~IRQ_USER_BOUND) < apic_nproc);
	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {
		/* Write the RDT entry -- bind to a specific CPU: */
		WRITE_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapicindex, intin_no,
		    cpu_infop->aci_local_id << APIC_ID_BIT_OFFSET);
	}
	if ((airq_temp_cpu != IRQ_UNBOUND) && (airq_temp_cpu != IRQ_UNINIT)) {
		apic_cpus[airq_temp_cpu].aci_temp_bound--;
	}
	if (!APIC_IS_MSI_OR_MSIX_INDEX(irq_ptr->airq_mps_intr_index)) {

		rdt_entry = AV_PDEST | AV_FIXED | irq_ptr->airq_rdt_entry;

		/* Write the vector, trigger, and polarity portion of the RDT */
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapicindex, intin_no,
		    rdt_entry);

	} else {
		int type = (irq_ptr->airq_mps_intr_index == MSI_INDEX) ?
		    DDI_INTR_TYPE_MSI : DDI_INTR_TYPE_MSIX;
		if (type == DDI_INTR_TYPE_MSI) {
			if (irq_ptr->airq_ioapicindex ==
			    irq_ptr->airq_origirq) {
				/* first one */
				DDI_INTR_IMPLDBG((CE_CONT, "apic_rebind: call "
				    "apic_pci_msi_enable_vector\n"));
				apic_pci_msi_enable_vector(irq_ptr->airq_dip,
				    type, which_irq, irq_ptr->airq_vector,
				    irq_ptr->airq_intin_no,
				    cpu_infop->aci_local_id);
			}
			if ((irq_ptr->airq_ioapicindex +
			    irq_ptr->airq_intin_no - 1) ==
			    irq_ptr->airq_origirq) { /* last one */
				DDI_INTR_IMPLDBG((CE_CONT, "apic_rebind: call "
				    "apic_pci_msi_enable_mode\n"));
				apic_pci_msi_enable_mode(irq_ptr->airq_dip,
				    type, which_irq);
			}
		} else { /* MSI-X */
			apic_pci_msi_enable_vector(irq_ptr->airq_dip, type,
			    irq_ptr->airq_origirq, irq_ptr->airq_vector, 1,
			    cpu_infop->aci_local_id);
			apic_pci_msi_enable_mode(irq_ptr->airq_dip, type,
			    irq_ptr->airq_origirq);
		}
	}
	irq_ptr->airq_temp_cpu = (uint32_t)bind_cpu;
	apic_redist_cpu_skip &= ~(1 << (bind_cpu & ~IRQ_USER_BOUND));
	return (0);
}

static void
apic_last_ditch_clear_remote_irr(int ioapic_ix, int intin_no)
{
	if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no)
	    & AV_REMOTE_IRR) != 0) {
		/*
		 * Trying to clear the bit through normal
		 * channels has failed.  So as a last-ditch
		 * effort, try to set the trigger mode to
		 * edge, then to level.  This has been
		 * observed to work on many systems.
		 */
		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no,
		    READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no) & ~AV_LEVEL);

		WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no,
		    READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no) | AV_LEVEL);

		/*
		 * If the bit's STILL set, this interrupt may
		 * be hosed.
		 */
		if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no) & AV_REMOTE_IRR) != 0) {

			prom_printf("%s: Remote IRR still "
			    "not clear for IOAPIC %d intin %d.\n"
			    "\tInterrupts to this pin may cease "
			    "functioning.\n", psm_name, ioapic_ix,
			    intin_no);
#ifdef DEBUG
			apic_last_ditch_reprogram_failures++;
#endif
		}
	}
}

/*
 * This function is protected by apic_ioapic_lock coupled with the
 * fact that interrupts are disabled.
 */
static void
delete_defer_repro_ent(int which_irq)
{
	ASSERT(which_irq >= 0);
	ASSERT(which_irq <= 255);

	if (apic_reprogram_info[which_irq].done)
		return;

	apic_reprogram_info[which_irq].done = B_TRUE;

#ifdef DEBUG
	apic_defer_repro_total_retries +=
	    apic_reprogram_info[which_irq].tries;

	apic_defer_repro_successes++;
#endif

	if (--apic_reprogram_outstanding == 0) {

		setlvlx = psm_intr_exit_fn();
	}
}


/*
 * Interrupts must be disabled during this function to prevent
 * self-deadlock.  Interrupts are disabled because this function
 * is called from apic_check_stuck_interrupt(), which is called
 * from apic_rebind(), which requires its caller to disable interrupts.
 */
static void
add_defer_repro_ent(apic_irq_t *irq_ptr, int which_irq, int new_bind_cpu)
{
	ASSERT(which_irq >= 0);
	ASSERT(which_irq <= 255);

	/*
	 * On the off-chance that there's already a deferred
	 * reprogramming on this irq, check, and if so, just update the
	 * CPU and irq pointer to which the interrupt is targeted, then return.
	 */
	if (!apic_reprogram_info[which_irq].done) {
		apic_reprogram_info[which_irq].bindcpu = new_bind_cpu;
		apic_reprogram_info[which_irq].irqp = irq_ptr;
		return;
	}

	apic_reprogram_info[which_irq].irqp = irq_ptr;
	apic_reprogram_info[which_irq].bindcpu = new_bind_cpu;
	apic_reprogram_info[which_irq].tries = 0;
	/*
	 * This must be the last thing set, since we're not
	 * grabbing any locks, apic_try_deferred_reprogram() will
	 * make its decision about using this entry iff done
	 * is false.
	 */
	apic_reprogram_info[which_irq].done = B_FALSE;

	/*
	 * If there were previously no deferred reprogrammings, change
	 * setlvlx to call apic_try_deferred_reprogram()
	 */
	if (++apic_reprogram_outstanding == 1) {

		setlvlx = apic_try_deferred_reprogram;
	}
}

static void
apic_try_deferred_reprogram(int prev_ipl, int irq)
{
	int reproirq;
	ulong_t iflag;
	struct ioapic_reprogram_data *drep;

	(*psm_intr_exit_fn())(prev_ipl, irq);

	if (!lock_try(&apic_defer_reprogram_lock)) {
		return;
	}

	/*
	 * Acquire the apic_ioapic_lock so that any other operations that
	 * may affect the apic_reprogram_info state are serialized.
	 * It's still possible for the last deferred reprogramming to clear
	 * between the time we entered this function and the time we get to
	 * the for loop below.  In that case, *setlvlx will have been set
	 * back to *_intr_exit and drep will be NULL. (There's no way to
	 * stop that from happening -- we would need to grab a lock before
	 * calling *setlvlx, which is neither realistic nor prudent).
	 */
	iflag = intr_clear();
	lock_set(&apic_ioapic_lock);

	/*
	 * For each deferred RDT entry, try to reprogram it now.  Note that
	 * there is no lock acquisition to read apic_reprogram_info because
	 * '.done' is set only after the other fields in the structure are set.
	 */

	drep = NULL;
	for (reproirq = 0; reproirq <= APIC_MAX_VECTOR; reproirq++) {
		if (apic_reprogram_info[reproirq].done == B_FALSE) {
			drep = &apic_reprogram_info[reproirq];
			break;
		}
	}

	/*
	 * Either we found a deferred action to perform, or
	 * we entered this function spuriously, after *setlvlx
	 * was restored to point to *_intr_exit.  Any other
	 * permutation is invalid.
	 */
	ASSERT(drep != NULL || *setlvlx == psm_intr_exit_fn());

	/*
	 * Though we can't really do anything about errors
	 * at this point, keep track of them for reporting.
	 * Note that it is very possible for apic_setup_io_intr
	 * to re-register this very timeout if the Remote IRR bit
	 * has not yet cleared.
	 */

#ifdef DEBUG
	if (drep != NULL) {
		if (apic_setup_io_intr(drep, reproirq, B_TRUE) != 0) {
			apic_deferred_setup_failures++;
		}
	} else {
		apic_deferred_spurious_enters++;
	}
#else
	if (drep != NULL)
		(void) apic_setup_io_intr(drep, reproirq, B_TRUE);
#endif

	lock_clear(&apic_ioapic_lock);
	intr_restore(iflag);

	lock_clear(&apic_defer_reprogram_lock);
}

static void
apic_ioapic_wait_pending_clear(int ioapic_ix, int intin_no)
{
	int waited;

	/*
	 * Wait for the delivery pending bit to clear.
	 */
	if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no) &
	    (AV_LEVEL|AV_PENDING)) == (AV_LEVEL|AV_PENDING)) {

		/*
		 * If we're still waiting on the delivery of this interrupt,
		 * continue to wait here until it is delivered (this should be
		 * a very small amount of time, but include a timeout just in
		 * case).
		 */
		for (waited = 0; waited < apic_max_reps_clear_pending;
		    waited++) {
			if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
			    intin_no) & AV_PENDING) == 0) {
				break;
			}
		}
	}
}


/*
 * Checks to see if the IOAPIC interrupt entry specified has its Remote IRR
 * bit set.  Calls functions that modify the function that setlvlx points to,
 * so that the reprogramming can be retried very shortly.
 *
 * This function will mask the RDT entry if the interrupt is level-triggered.
 * (The caller is responsible for unmasking the RDT entry.)
 *
 * Returns non-zero if the caller should defer IOAPIC reprogramming.
 */
static int
apic_check_stuck_interrupt(apic_irq_t *irq_ptr, int old_bind_cpu,
    int new_bind_cpu, int ioapic_ix, int intin_no, int which_irq,
    struct ioapic_reprogram_data *drep)
{
	int32_t			rdt_entry;
	int			waited;
	int			reps = 0;

	/*
	 * Wait for the delivery pending bit to clear.
	 */
	do {
		++reps;

		apic_ioapic_wait_pending_clear(ioapic_ix, intin_no);

		/*
		 * Mask the RDT entry, but only if it's a level-triggered
		 * interrupt
		 */
		rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
		    intin_no);
		if ((rdt_entry & (AV_LEVEL|AV_MASK)) == AV_LEVEL) {

			/* Mask it */
			WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no,
			    AV_MASK | rdt_entry);
		}

		if ((rdt_entry & AV_LEVEL) == AV_LEVEL) {
			/*
			 * If there was a race and an interrupt was injected
			 * just before we masked, check for that case here.
			 * Then, unmask the RDT entry and try again.  If we're
			 * on our last try, don't unmask (because we want the
			 * RDT entry to remain masked for the rest of the
			 * function).
			 */
			rdt_entry = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
			    intin_no);
			if ((rdt_entry & AV_PENDING) &&
			    (reps < apic_max_reps_clear_pending)) {
				/* Unmask it */
				WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
				    intin_no, rdt_entry & ~AV_MASK);
			}
		}

	} while ((rdt_entry & AV_PENDING) &&
	    (reps < apic_max_reps_clear_pending));

#ifdef DEBUG
		if (rdt_entry & AV_PENDING)
			apic_intr_deliver_timeouts++;
#endif

	/*
	 * If the remote IRR bit is set, then the interrupt has been sent
	 * to a CPU for processing.  We have no choice but to wait for
	 * that CPU to process the interrupt, at which point the remote IRR
	 * bit will be cleared.
	 */
	if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, intin_no) &
	    (AV_LEVEL|AV_REMOTE_IRR)) == (AV_LEVEL|AV_REMOTE_IRR)) {

		/*
		 * If the CPU that this RDT is bound to is NOT the current
		 * CPU, wait until that CPU handles the interrupt and ACKs
		 * it.  If this interrupt is not bound to any CPU (that is,
		 * if it's bound to the logical destination of "anyone"), it
		 * may have been delivered to the current CPU so handle that
		 * case by deferring the reprogramming (below).
		 */
		if ((old_bind_cpu != IRQ_UNBOUND) &&
		    (old_bind_cpu != IRQ_UNINIT) &&
		    (old_bind_cpu != psm_get_cpu_id())) {
			for (waited = 0; waited < apic_max_reps_clear_pending;
			    waited++) {
				if ((READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix,
				    intin_no) & AV_REMOTE_IRR) == 0) {

					delete_defer_repro_ent(which_irq);

					/* Remote IRR has cleared! */
					return (0);
				}
			}
		}

		/*
		 * If we waited and the Remote IRR bit is still not cleared,
		 * AND if we've invoked the timeout APIC_REPROGRAM_MAX_TIMEOUTS
		 * times for this interrupt, try the last-ditch workaround:
		 */
		if (drep && drep->tries >= APIC_REPROGRAM_MAX_TRIES) {

			apic_last_ditch_clear_remote_irr(ioapic_ix, intin_no);

			/* Mark this one as reprogrammed: */
			delete_defer_repro_ent(which_irq);

			return (0);
		} else {
#ifdef DEBUG
			apic_intr_deferrals++;
#endif

			/*
			 * If waiting for the Remote IRR bit (above) didn't
			 * allow it to clear, defer the reprogramming.
			 * Add a new deferred-programming entry if the
			 * caller passed a NULL one (and update the existing one
			 * in case anything changed).
			 */
			add_defer_repro_ent(irq_ptr, which_irq, new_bind_cpu);
			if (drep)
				drep->tries++;

			/* Inform caller to defer IOAPIC programming: */
			return (1);
		}

	}

	/* Remote IRR is clear */
	delete_defer_repro_ent(which_irq);

	return (0);
}

/*
 * Called to migrate all interrupts at an irq to another cpu.
 * Must be called with interrupts disabled and apic_ioapic_lock held
 */
int
apic_rebind_all(apic_irq_t *irq_ptr, int bind_cpu)
{
	apic_irq_t	*irqptr = irq_ptr;
	int		retval = 0;

	while (irqptr) {
		if (irqptr->airq_temp_cpu != IRQ_UNINIT)
			retval |= apic_rebind(irqptr, bind_cpu, NULL);
		irqptr = irqptr->airq_next;
	}

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
void
apic_intr_redistribute()
{
	int busiest_cpu, most_free_cpu;
	int cpu_free, cpu_busy, max_busy, min_busy;
	int min_free, diff;
	int average_busy, cpus_online;
	int i, busy;
	ulong_t iflag;
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
		for (; i <= apic_max_device_irq; i++) {
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
			iflag = intr_clear();
			if (lock_try(&apic_ioapic_lock)) {
				if (apic_rebind_all(max_busy_irq,
				    most_free_cpu) == 0) {
					/* Make change permenant */
					max_busy_irq->airq_cpu =
					    (uint32_t)most_free_cpu;
				}
				lock_clear(&apic_ioapic_lock);
			}
			intr_restore(iflag);

		} else if (min_busy_irq != NULL) {
#ifdef	DEBUG
			if (apic_verbose & APIC_VERBOSE_IOAPIC_FLAG) {
				prom_printf("rebinding %x to %x",
				    min_busy_irq->airq_vector, most_free_cpu);
			}
#endif /* DEBUG */

			iflag = intr_clear();
			if (lock_try(&apic_ioapic_lock)) {
				if (apic_rebind_all(min_busy_irq,
				    most_free_cpu) == 0) {
					/* Make change permenant */
					min_busy_irq->airq_cpu =
					    (uint32_t)most_free_cpu;
				}
				lock_clear(&apic_ioapic_lock);
			}
			intr_restore(iflag);

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

void
apic_cleanup_busy()
{
	int i;
	apic_irq_t *irq_ptr;

	for (i = 0; i < apic_nproc; i++) {
		apic_cpus[i].aci_busy = 0;
	}

	for (i = apic_min_device_irq; i <= apic_max_device_irq; i++) {
		if ((irq_ptr = apic_irq_table[i]) != NULL)
			irq_ptr->airq_busy = 0;
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
		APIC_VERBOSE_IRQ((CE_CONT, "!%s: Found irqno %d "
		    "from cache for device %s, instance #%d\n", psm_name,
		    *pci_irqp, ddi_get_name(dip), ddi_get_instance(dip)));
		return (status);
	}

	bzero(&acpipsmlnk, sizeof (acpi_psm_lnk_t));

	if ((status = acpi_translate_pci_irq(dip, ipin, pci_irqp, intr_flagp,
	    &acpipsmlnk)) == ACPI_PSM_FAILURE) {
		APIC_VERBOSE_IRQ((CE_WARN, "%s: "
		    " acpi_translate_pci_irq failed for device %s, instance"
		    " #%d", psm_name, ddi_get_name(dip),
		    ddi_get_instance(dip)));
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

		APIC_VERBOSE_IRQ((CE_CONT, "%s: [ACPI] "
		    "new irq %d for device %s, instance #%d\n", psm_name,
		    *pci_irqp, ddi_get_name(dip), ddi_get_instance(dip)));
	}

	return (status);
}

/*
 * Adds an entry to the irq list passed in, and returns the new list.
 * Entries are added in priority order (lower numerical priorities are
 * placed closer to the head of the list)
 */
static prs_irq_list_t *
acpi_insert_prs_irq_ent(prs_irq_list_t *listp, int priority, int irq,
    iflag_t *iflagp, acpi_prs_private_t *prsprvp)
{
	struct prs_irq_list_ent *newent, *prevp = NULL, *origlistp;

	newent = kmem_zalloc(sizeof (struct prs_irq_list_ent), KM_SLEEP);

	newent->list_prio = priority;
	newent->irq = irq;
	newent->intrflags = *iflagp;
	newent->prsprv = *prsprvp;
	/* ->next is NULL from kmem_zalloc */

	/*
	 * New list -- return the new entry as the list.
	 */
	if (listp == NULL)
		return (newent);

	/*
	 * Save original list pointer for return (since we're not modifying
	 * the head)
	 */
	origlistp = listp;

	/*
	 * Insertion sort, with entries with identical keys stored AFTER
	 * existing entries (the less-than-or-equal test of priority does
	 * this for us).
	 */
	while (listp != NULL && listp->list_prio <= priority) {
		prevp = listp;
		listp = listp->next;
	}

	newent->next = listp;

	if (prevp == NULL) { /* Add at head of list (newent is the new head) */
		return (newent);
	} else {
		prevp->next = newent;
		return (origlistp);
	}
}

/*
 * Frees the list passed in, deallocating all memory and leaving *listpp
 * set to NULL.
 */
static void
acpi_destroy_prs_irq_list(prs_irq_list_t **listpp)
{
	struct prs_irq_list_ent *nextp;

	ASSERT(listpp != NULL);

	while (*listpp != NULL) {
		nextp = (*listpp)->next;
		kmem_free(*listpp, sizeof (struct prs_irq_list_ent));
		*listpp = nextp;
	}
}

/*
 * apic_choose_irqs_from_prs returns a list of irqs selected from the list of
 * irqs returned by the link device's _PRS method.  The irqs are chosen
 * to minimize contention in situations where the interrupt link device
 * can be programmed to steer interrupts to different interrupt controller
 * inputs (some of which may already be in use).  The list is sorted in order
 * of irqs to use, with the highest priority given to interrupt controller
 * inputs that are not shared.   When an interrupt controller input
 * must be shared, apic_choose_irqs_from_prs adds the possible irqs to the
 * returned list in the order that minimizes sharing (thereby ensuring lowest
 * possible latency from interrupt trigger time to ISR execution time).
 */
static prs_irq_list_t *
apic_choose_irqs_from_prs(acpi_irqlist_t *irqlistent, dev_info_t *dip,
    int crs_irq)
{
	int32_t irq;
	int i;
	prs_irq_list_t *prsirqlistp = NULL;
	iflag_t iflags;

	while (irqlistent != NULL) {
		irqlistent->intr_flags.bustype = BUS_PCI;

		for (i = 0; i < irqlistent->num_irqs; i++) {

			irq = irqlistent->irqs[i];

			if (irq <= 0) {
				/* invalid irq number */
				continue;
			}

			if ((irq < 16) && (apic_reserved_irqlist[irq]))
				continue;

			if ((apic_irq_table[irq] == NULL) ||
			    (apic_irq_table[irq]->airq_dip == dip)) {

				prsirqlistp = acpi_insert_prs_irq_ent(
				    prsirqlistp, 0 /* Highest priority */, irq,
				    &irqlistent->intr_flags,
				    &irqlistent->acpi_prs_prv);

				/*
				 * If we do not prefer the current irq from _CRS
				 * or if we do and this irq is the same as the
				 * current irq from _CRS, this is the one
				 * to pick.
				 */
				if (!(apic_prefer_crs) || (irq == crs_irq)) {
					return (prsirqlistp);
				}
				continue;
			}

			/*
			 * Edge-triggered interrupts cannot be shared
			 */
			if (irqlistent->intr_flags.intr_el == INTR_EL_EDGE)
				continue;

			/*
			 * To work around BIOSes that contain incorrect
			 * interrupt polarity information in interrupt
			 * descriptors returned by _PRS, we assume that
			 * the polarity of the other device sharing this
			 * interrupt controller input is compatible.
			 * If it's not, the caller will catch it when
			 * the caller invokes the link device's _CRS method
			 * (after invoking its _SRS method).
			 */
			iflags = irqlistent->intr_flags;
			iflags.intr_po =
			    apic_irq_table[irq]->airq_iflag.intr_po;

			if (!acpi_intr_compatible(iflags,
			    apic_irq_table[irq]->airq_iflag)) {
				APIC_VERBOSE_IRQ((CE_CONT, "!%s: irq %d "
				    "not compatible [%x:%x:%x !~ %x:%x:%x]",
				    psm_name, irq,
				    iflags.intr_po,
				    iflags.intr_el,
				    iflags.bustype,
				    apic_irq_table[irq]->airq_iflag.intr_po,
				    apic_irq_table[irq]->airq_iflag.intr_el,
				    apic_irq_table[irq]->airq_iflag.bustype));
				continue;
			}

			/*
			 * If we prefer the irq from _CRS, no need
			 * to search any further (and make sure
			 * to add this irq with the highest priority
			 * so it's tried first).
			 */
			if (crs_irq == irq && apic_prefer_crs) {

				return (acpi_insert_prs_irq_ent(
				    prsirqlistp,
				    0 /* Highest priority */,
				    irq, &iflags,
				    &irqlistent->acpi_prs_prv));
			}

			/*
			 * Priority is equal to the share count (lower
			 * share count is higher priority). Note that
			 * the intr flags passed in here are the ones we
			 * changed above -- if incorrect, it will be
			 * caught by the caller's _CRS flags comparison.
			 */
			prsirqlistp = acpi_insert_prs_irq_ent(
			    prsirqlistp,
			    apic_irq_table[irq]->airq_share, irq,
			    &iflags, &irqlistent->acpi_prs_prv);
		}

		/* Go to the next irqlist entry */
		irqlistent = irqlistent->next;
	}

	return (prsirqlistp);
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
	int32_t irq;
	int cur_irq = -1;
	acpi_irqlist_t *irqlistp;
	prs_irq_list_t *prs_irq_listp, *prs_irq_entp;
	boolean_t found_irq = B_FALSE;

	dipintr_flagp->bustype = BUS_PCI;

	if ((acpi_get_possible_irq_resources(acpipsmlnkp, &irqlistp))
	    == ACPI_PSM_FAILURE) {
		APIC_VERBOSE_IRQ((CE_WARN, "!%s: Unable to determine "
		    "or assign IRQ for device %s, instance #%d: The system was "
		    "unable to get the list of potential IRQs from ACPI.",
		    psm_name, ddi_get_name(dip), ddi_get_instance(dip)));

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

			ASSERT(pci_irqp != NULL);
			*pci_irqp = cur_irq;
			acpi_free_irqlist(irqlistp);
			return (ACPI_PSM_SUCCESS);
		}

		APIC_VERBOSE_IRQ((CE_WARN, "!%s: Could not find the "
		    "current irq %d for device %s, instance #%d in ACPI's "
		    "list of possible irqs for this device. Picking one from "
		    " the latter list.", psm_name, cur_irq, ddi_get_name(dip),
		    ddi_get_instance(dip)));
	}

	if ((prs_irq_listp = apic_choose_irqs_from_prs(irqlistp, dip,
	    cur_irq)) == NULL) {

		APIC_VERBOSE_IRQ((CE_WARN, "!%s: Could not find a "
		    "suitable irq from the list of possible irqs for device "
		    "%s, instance #%d in ACPI's list of possible irqs",
		    psm_name, ddi_get_name(dip), ddi_get_instance(dip)));

		acpi_free_irqlist(irqlistp);
		return (ACPI_PSM_FAILURE);
	}

	acpi_free_irqlist(irqlistp);

	for (prs_irq_entp = prs_irq_listp;
	    prs_irq_entp != NULL && found_irq == B_FALSE;
	    prs_irq_entp = prs_irq_entp->next) {

		acpipsmlnkp->acpi_prs_prv = prs_irq_entp->prsprv;
		irq = prs_irq_entp->irq;

		APIC_VERBOSE_IRQ((CE_CONT, "!%s: Setting irq %d for "
		    "device %s instance #%d\n", psm_name, irq,
		    ddi_get_name(dip), ddi_get_instance(dip)));

		if ((acpi_set_irq_resource(acpipsmlnkp, irq))
		    == ACPI_PSM_SUCCESS) {
			/*
			 * setting irq was successful, check to make sure CRS
			 * reflects that. If CRS does not agree with what we
			 * set, return the irq that was set.
			 */

			if (acpi_get_current_irq_resource(acpipsmlnkp, &cur_irq,
			    dipintr_flagp) == ACPI_PSM_SUCCESS) {

				if (cur_irq != irq)
					APIC_VERBOSE_IRQ((CE_WARN,
					    "!%s: IRQ resource set "
					    "(irqno %d) for device %s "
					    "instance #%d, differs from "
					    "current setting irqno %d",
					    psm_name, irq, ddi_get_name(dip),
					    ddi_get_instance(dip), cur_irq));
			} else {
				/*
				 * On at least one system, there was a bug in
				 * a DSDT method called by _STA, causing _STA to
				 * indicate that the link device was disabled
				 * (when, in fact, it was enabled).  Since _SRS
				 * succeeded, assume that _CRS is lying and use
				 * the iflags from this _PRS interrupt choice.
				 * If we're wrong about the flags, the polarity
				 * will be incorrect and we may get an interrupt
				 * storm, but there's not much else we can do
				 * at this point.
				 */
				*dipintr_flagp = prs_irq_entp->intrflags;
			}

			/*
			 * Return the irq that was set, and not what _CRS
			 * reports, since _CRS has been seen to return
			 * different IRQs than what was passed to _SRS on some
			 * systems (and just not return successfully on others).
			 */
			cur_irq = irq;
			found_irq = B_TRUE;
		} else {
			APIC_VERBOSE_IRQ((CE_WARN, "!%s: set resource "
			    "irq %d failed for device %s instance #%d",
			    psm_name, irq, ddi_get_name(dip),
			    ddi_get_instance(dip)));

			if (cur_irq == -1) {
				acpi_destroy_prs_irq_list(&prs_irq_listp);
				return (ACPI_PSM_FAILURE);
			}
		}
	}

	acpi_destroy_prs_irq_list(&prs_irq_listp);

	if (!found_irq)
		return (ACPI_PSM_FAILURE);

	ASSERT(pci_irqp != NULL);
	*pci_irqp = cur_irq;
	return (ACPI_PSM_SUCCESS);
}

void
ioapic_disable_redirection()
{
	int ioapic_ix;
	int intin_max;
	int intin_ix;

	/* Disable the I/O APIC redirection entries */
	for (ioapic_ix = 0; ioapic_ix < apic_io_max; ioapic_ix++) {

		/* Bits 23-16 define the maximum redirection entries */
		intin_max = (ioapic_read(ioapic_ix, APIC_VERS_CMD) >> 16)
		    & 0xff;

		for (intin_ix = 0; intin_ix <= intin_max; intin_ix++) {
			/*
			 * The assumption here is that this is safe, even for
			 * systems with IOAPICs that suffer from the hardware
			 * erratum because all devices have been quiesced before
			 * this function is called from apic_shutdown()
			 * (or equivalent). If that assumption turns out to be
			 * false, this mask operation can induce the same
			 * erratum result we're trying to avoid.
			 */
			ioapic_write(ioapic_ix, APIC_RDT_CMD + 2 * intin_ix,
			    AV_MASK);
		}
	}
}

/*
 * Looks for an IOAPIC with the specified physical address in the /ioapics
 * node in the device tree (created by the PCI enumerator).
 */
static boolean_t
apic_is_ioapic_AMD_813x(uint32_t physaddr)
{
	/*
	 * Look in /ioapics, for the ioapic with
	 * the physical address given
	 */
	dev_info_t *ioapicsnode = ddi_find_devinfo(IOAPICS_NODE_NAME, -1, 0);
	dev_info_t *ioapic_child;
	boolean_t rv = B_FALSE;
	int vid, did;
	uint64_t ioapic_paddr;
	boolean_t done = B_FALSE;

	if (ioapicsnode == NULL)
		return (B_FALSE);

	/* Load first child: */
	ioapic_child = ddi_get_child(ioapicsnode);
	while (!done && ioapic_child != 0) { /* Iterate over children */

		if ((ioapic_paddr = (uint64_t)ddi_prop_get_int64(DDI_DEV_T_ANY,
		    ioapic_child, DDI_PROP_DONTPASS, "reg", 0))
		    != 0 && physaddr == ioapic_paddr) {

			vid = ddi_prop_get_int(DDI_DEV_T_ANY, ioapic_child,
			    DDI_PROP_DONTPASS, IOAPICS_PROP_VENID, 0);

			if (vid == VENID_AMD) {

				did = ddi_prop_get_int(DDI_DEV_T_ANY,
				    ioapic_child, DDI_PROP_DONTPASS,
				    IOAPICS_PROP_DEVID, 0);

				if (did == DEVID_8131_IOAPIC ||
				    did == DEVID_8132_IOAPIC) {

					rv = B_TRUE;
					done = B_TRUE;
				}
			}
		}

		if (!done)
			ioapic_child = ddi_get_next_sibling(ioapic_child);
	}

	/* The ioapics node was held by ddi_find_devinfo, so release it */
	ndi_rele_devi(ioapicsnode);
	return (rv);
}

struct apic_state {
	int32_t as_task_reg;
	int32_t as_dest_reg;
	int32_t as_format_reg;
	int32_t as_local_timer;
	int32_t as_pcint_vect;
	int32_t as_int_vect0;
	int32_t as_int_vect1;
	int32_t as_err_vect;
	int32_t as_init_count;
	int32_t as_divide_reg;
	int32_t as_spur_int_reg;
	uint32_t as_ioapic_ids[MAX_IO_APIC];
};


static int
apic_acpi_enter_apicmode(void)
{
	ACPI_OBJECT_LIST	arglist;
	ACPI_OBJECT		arg;
	ACPI_STATUS		status;

	/* Setup parameter object */
	arglist.Count = 1;
	arglist.Pointer = &arg;
	arg.Type = ACPI_TYPE_INTEGER;
	arg.Integer.Value = ACPI_APIC_MODE;

	status = AcpiEvaluateObject(NULL, "\\_PIC", &arglist, NULL);
	if (ACPI_FAILURE(status))
		return (PSM_FAILURE);
	else
		return (PSM_SUCCESS);
}


static void
apic_save_state(struct apic_state *sp)
{
	int	i;
	ulong_t	iflag;

	PMD(PMD_SX, ("apic_save_state %p\n", (void *)sp))
	/*
	 * First the local APIC.
	 */
	sp->as_task_reg = apic_reg_ops->apic_get_pri();
	sp->as_dest_reg =  apic_reg_ops->apic_read(APIC_DEST_REG);
	if (apic_mode == LOCAL_APIC)
		sp->as_format_reg = apic_reg_ops->apic_read(APIC_FORMAT_REG);
	sp->as_local_timer = apic_reg_ops->apic_read(APIC_LOCAL_TIMER);
	sp->as_pcint_vect = apic_reg_ops->apic_read(APIC_PCINT_VECT);
	sp->as_int_vect0 = apic_reg_ops->apic_read(APIC_INT_VECT0);
	sp->as_int_vect1 = apic_reg_ops->apic_read(APIC_INT_VECT1);
	sp->as_err_vect = apic_reg_ops->apic_read(APIC_ERR_VECT);
	sp->as_init_count = apic_reg_ops->apic_read(APIC_INIT_COUNT);
	sp->as_divide_reg = apic_reg_ops->apic_read(APIC_DIVIDE_REG);
	sp->as_spur_int_reg = apic_reg_ops->apic_read(APIC_SPUR_INT_REG);

	/*
	 * If on the boot processor then save the IOAPICs' IDs
	 */
	if (psm_get_cpu_id() == 0) {

		iflag = intr_clear();
		lock_set(&apic_ioapic_lock);

		for (i = 0; i < apic_io_max; i++)
			sp->as_ioapic_ids[i] = ioapic_read(i, APIC_ID_CMD);

		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
	}
}

static void
apic_restore_state(struct apic_state *sp)
{
	int	i;
	ulong_t	iflag;

	/*
	 * First the local APIC.
	 */
	apic_reg_ops->apic_write_task_reg(sp->as_task_reg);
	if (apic_mode == LOCAL_APIC) {
		apic_reg_ops->apic_write(APIC_DEST_REG, sp->as_dest_reg);
		apic_reg_ops->apic_write(APIC_FORMAT_REG, sp->as_format_reg);
	}
	apic_reg_ops->apic_write(APIC_LOCAL_TIMER, sp->as_local_timer);
	apic_reg_ops->apic_write(APIC_PCINT_VECT, sp->as_pcint_vect);
	apic_reg_ops->apic_write(APIC_INT_VECT0, sp->as_int_vect0);
	apic_reg_ops->apic_write(APIC_INT_VECT1, sp->as_int_vect1);
	apic_reg_ops->apic_write(APIC_ERR_VECT, sp->as_err_vect);
	apic_reg_ops->apic_write(APIC_INIT_COUNT, sp->as_init_count);
	apic_reg_ops->apic_write(APIC_DIVIDE_REG, sp->as_divide_reg);
	apic_reg_ops->apic_write(APIC_SPUR_INT_REG, sp->as_spur_int_reg);

	/*
	 * the following only needs to be done once, so we do it on the
	 * boot processor, since we know that we only have one of those
	 */
	if (psm_get_cpu_id() == 0) {

		iflag = intr_clear();
		lock_set(&apic_ioapic_lock);

		/* Restore IOAPICs' APIC IDs */
		for (i = 0; i < apic_io_max; i++) {
			ioapic_write(i, APIC_ID_CMD, sp->as_ioapic_ids[i]);
		}

		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);

		/*
		 * Reenter APIC mode before restoring LNK devices
		 */
		(void) apic_acpi_enter_apicmode();

		/*
		 * restore acpi link device mappings
		 */
		acpi_restore_link_devices();
	}
}

/*
 * Returns 0 on success
 */
int
apic_state(psm_state_request_t *rp)
{
	PMD(PMD_SX, ("apic_state "))
	switch (rp->psr_cmd) {
	case PSM_STATE_ALLOC:
		rp->req.psm_state_req.psr_state =
		    kmem_zalloc(sizeof (struct apic_state), KM_NOSLEEP);
		if (rp->req.psm_state_req.psr_state == NULL)
			return (ENOMEM);
		rp->req.psm_state_req.psr_state_size =
		    sizeof (struct apic_state);
		PMD(PMD_SX, (":STATE_ALLOC: state %p, size %lx\n",
		    rp->req.psm_state_req.psr_state,
		    rp->req.psm_state_req.psr_state_size))
		return (0);

	case PSM_STATE_FREE:
		kmem_free(rp->req.psm_state_req.psr_state,
		    rp->req.psm_state_req.psr_state_size);
		PMD(PMD_SX, (" STATE_FREE: state %p, size %lx\n",
		    rp->req.psm_state_req.psr_state,
		    rp->req.psm_state_req.psr_state_size))
		return (0);

	case PSM_STATE_SAVE:
		PMD(PMD_SX, (" STATE_SAVE: state %p, size %lx\n",
		    rp->req.psm_state_req.psr_state,
		    rp->req.psm_state_req.psr_state_size))
		apic_save_state(rp->req.psm_state_req.psr_state);
		return (0);

	case PSM_STATE_RESTORE:
		apic_restore_state(rp->req.psm_state_req.psr_state);
		PMD(PMD_SX, (" STATE_RESTORE: state %p, size %lx\n",
		    rp->req.psm_state_req.psr_state,
		    rp->req.psm_state_req.psr_state_size))
		return (0);

	default:
		return (EINVAL);
	}
}
