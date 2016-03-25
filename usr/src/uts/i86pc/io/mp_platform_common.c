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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

/*
 * PSMI 1.1 extensions are supported only in 2.6 and later versions.
 * PSMI 1.2 extensions are supported only in 2.7 and later versions.
 * PSMI 1.3 and 1.4 extensions are supported in Solaris 10.
 * PSMI 1.5 extensions are supported in Solaris Nevada.
 * PSMI 1.6 extensions are supported in Solaris Nevada.
 * PSMI 1.7 extensions are supported in Solaris Nevada.
 */
#define	PSMI_1_7

#include <sys/processor.h>
#include <sys/time.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>
#include <sys/cram.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/psm_common.h>
#include <sys/apic.h>
#include <sys/apic_timer.h>
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
#if !defined(__xpv)
#include <sys/hpet.h>
#include <sys/clock.h>
#endif

/*
 *	Local Function Prototypes
 */
static int apic_handle_defconf();
static int apic_parse_mpct(caddr_t mpct, int bypass);
static struct apic_mpfps_hdr *apic_find_fps_sig(caddr_t fptr, int size);
static int apic_checksum(caddr_t bptr, int len);
static int apic_find_bus_type(char *bus);
static int apic_find_bus(int busid);
static struct apic_io_intr *apic_find_io_intr(int irqno);
static int apic_find_free_irq(int start, int end);
struct apic_io_intr *apic_find_io_intr_w_busid(int irqno, int busid);
static void apic_set_pwroff_method_from_mpcnfhdr(struct apic_mp_cnf_hdr *hdrp);
static void apic_free_apic_cpus(void);
static boolean_t apic_is_ioapic_AMD_813x(uint32_t physaddr);
static int apic_acpi_enter_apicmode(void);

int apic_handle_pci_pci_bridge(dev_info_t *idip, int child_devno,
    int child_ipin, struct apic_io_intr **intrp);
int apic_find_bus_id(int bustype);
int apic_find_intin(uchar_t ioapic, uchar_t intin);
void apic_record_rdt_entry(apic_irq_t *irqptr, int irq);

int apic_debug_mps_id = 0;	/* 1 - print MPS ID strings */

/* ACPI SCI interrupt configuration; -1 if SCI not used */
int apic_sci_vect = -1;
iflag_t apic_sci_flags;

#if !defined(__xpv)
/* ACPI HPET interrupt configuration; -1 if HPET not used */
int apic_hpet_vect = -1;
iflag_t apic_hpet_flags;
#endif

/*
 * psm name pointer
 */
char *psm_name;

/* ACPI support routines */
static int acpi_probe(char *);
static int apic_acpi_irq_configure(acpi_psm_lnk_t *acpipsmlnkp, dev_info_t *dip,
    int *pci_irqp, iflag_t *intr_flagp);

int apic_acpi_translate_pci_irq(dev_info_t *dip, int busid, int devid,
    int ipin, int *pci_irqp, iflag_t *intr_flagp);
uchar_t acpi_find_ioapic(int irq);
static int acpi_intr_compatible(iflag_t iflag1, iflag_t iflag2);

/* Max wait time (in repetitions) for flags to clear in an RDT entry. */
int apic_max_reps_clear_pending = 1000;

int	apic_intr_policy = INTR_ROUND_ROBIN;

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

int	apic_redist_cpu_skip = 0;
int	apic_num_imbalance = 0;
int	apic_num_rebind = 0;

/*
 * Maximum number of APIC CPUs in the system, -1 indicates that dynamic
 * allocation of CPU ids is disabled.
 */
int 	apic_max_nproc = -1;
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

uchar_t apic_io_id[MAX_IO_APIC];
volatile uint32_t *apicioadr[MAX_IO_APIC];
uchar_t	apic_io_ver[MAX_IO_APIC];
uchar_t	apic_io_vectbase[MAX_IO_APIC];
uchar_t	apic_io_vectend[MAX_IO_APIC];
uchar_t apic_reserved_irqlist[MAX_ISA_IRQ + 1];
uint32_t apic_physaddr[MAX_IO_APIC];

boolean_t ioapic_mask_workaround[MAX_IO_APIC];

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

int	apic_io_max = 0;	/* no. of i/o apics enabled */

struct apic_io_intr *apic_io_intrp = NULL;
static	struct apic_bus	*apic_busp;

uchar_t	apic_resv_vector[MAXIPL+1];

char	apic_level_intr[APIC_MAX_VECTOR+1];

uint32_t	eisa_level_intr_mask = 0;
	/* At least MSB will be set if EISA bus */

int	apic_pci_bus_total = 0;
uchar_t	apic_single_pci_busid = 0;

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
static	ACPI_TABLE_MADT *acpi_mapic_dtp = NULL;

/* ACPI Interrupt Source Override Structure ptr */
ACPI_MADT_INTERRUPT_OVERRIDE *acpi_isop = NULL;
int acpi_iso_cnt = 0;

/* ACPI Non-maskable Interrupt Sources ptr */
static	ACPI_MADT_NMI_SOURCE *acpi_nmi_sp = NULL;
static	int acpi_nmi_scnt = 0;
static	ACPI_MADT_LOCAL_APIC_NMI *acpi_nmi_cp = NULL;
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
	caddr_t	mpct = 0;
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
		goto apic_ret;
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
				goto apic_ret;
			}
		}
	}

	if (apic_checksum((caddr_t)fpsp, fpsp->mpfps_length * 16) != 0) {
		psm_unmap_phys(fptr, MPFPS_ROM_WIN_LEN);
		goto apic_ret;
	}

	apic_spec_rev = fpsp->mpfps_spec_rev;
	if ((apic_spec_rev != 04) && (apic_spec_rev != 01)) {
		psm_unmap_phys(fptr, MPFPS_ROM_WIN_LEN);
		goto apic_ret;
	}

	/* check IMCR is present or not */
	apic_imcrp = fpsp->mpfps_featinfo2 & MPFPS_FEATINFO2_IMCRP;

	/* check default configuration (dual CPUs) */
	if ((apic_defconf = fpsp->mpfps_featinfo1) != 0) {
		psm_unmap_phys(fptr, mapsize);
		if ((retval = apic_handle_defconf()) != PSM_SUCCESS)
			return (retval);

		goto apic_ret;
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
		goto apic_ret;

	/* check mp configuration table signature PCMP */
	if (hdrp->mpcnf_sig != 0x504d4350) {
		psm_unmap_phys((caddr_t)hdrp, sizeof (struct apic_mp_cnf_hdr));
		goto apic_ret;
	}
	mpct_size = (int)hdrp->mpcnf_tbl_length;

	apic_set_pwroff_method_from_mpcnfhdr(hdrp);

	psm_unmap_phys((caddr_t)hdrp, sizeof (struct apic_mp_cnf_hdr));

	if ((retval == PSM_SUCCESS) && !apic_use_acpi_madt_only) {
		/* This is an ACPI machine No need for further checks */
		goto apic_ret;
	}

	/*
	 * Map in the entries for this machine, ie. Processor
	 * Entry Tables, Bus Entry Tables, etc.
	 * They are in fixed order following one another
	 */
	mpct = psm_map_phys(mpct_addr, mpct_size, PROT_READ);
	if (!mpct)
		goto apic_ret;

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
	    PSM_SUCCESS) {
		retval = PSM_SUCCESS;
		goto apic_ret;
	}

apic_fail1:
	psm_unmap_phys(mpct, mpct_size);
	mpct = NULL;

apic_ret:
	if (retval == PSM_SUCCESS) {
		extern int apic_ioapic_method_probe();

		if ((retval = apic_ioapic_method_probe()) == PSM_SUCCESS)
			return (PSM_SUCCESS);
	}

	for (i = 0; i < apic_io_max; i++)
		mapout_ioapic((caddr_t)apicioadr[i], APIC_IO_MEMLEN);
	if (apic_cpus) {
		kmem_free(apic_cpus, apic_cpus_size);
		apic_cpus = NULL;
	}
	if (apicadr) {
		mapout_apic((caddr_t)apicadr, APIC_LOCAL_MEMLEN);
		apicadr = NULL;
	}
	if (mpct)
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

static void
apic_free_apic_cpus(void)
{
	if (apic_cpus != NULL) {
		kmem_free(apic_cpus, apic_cpus_size);
		apic_cpus = NULL;
		apic_cpus_size = 0;
	}
}

static int
acpi_probe(char *modname)
{
	int			i, intmax, index;
	uint32_t		id, ver;
	int			acpi_verboseflags = 0;
	int			madt_seen, madt_size;
	ACPI_SUBTABLE_HEADER		*ap;
	ACPI_MADT_LOCAL_APIC	*mpa;
	ACPI_MADT_LOCAL_X2APIC	*mpx2a;
	ACPI_MADT_IO_APIC		*mia;
	ACPI_MADT_IO_SAPIC		*misa;
	ACPI_MADT_INTERRUPT_OVERRIDE	*mio;
	ACPI_MADT_NMI_SOURCE		*mns;
	ACPI_MADT_INTERRUPT_SOURCE	*mis;
	ACPI_MADT_LOCAL_APIC_NMI	*mlan;
	ACPI_MADT_LOCAL_X2APIC_NMI	*mx2alan;
	ACPI_MADT_LOCAL_APIC_OVERRIDE	*mao;
	int			sci;
	iflag_t			sci_flags;
	volatile uint32_t	*ioapic;
	int			ioapic_ix;
	uint32_t		*local_ids;
	uint32_t		*proc_ids;
	uchar_t			hid;
	int			warned = 0;

	if (!apic_use_acpi)
		return (PSM_FAILURE);

	if (AcpiGetTable(ACPI_SIG_MADT, 1,
	    (ACPI_TABLE_HEADER **) &acpi_mapic_dtp) != AE_OK)
		return (PSM_FAILURE);

	apicadr = mapin_apic((uint32_t)acpi_mapic_dtp->Address,
	    APIC_LOCAL_MEMLEN, PROT_READ | PROT_WRITE);
	if (!apicadr)
		return (PSM_FAILURE);

	if ((local_ids = (uint32_t *)kmem_zalloc(NCPU * sizeof (uint32_t),
	    KM_NOSLEEP)) == NULL)
		return (PSM_FAILURE);

	if ((proc_ids = (uint32_t *)kmem_zalloc(NCPU * sizeof (uint32_t),
	    KM_NOSLEEP)) == NULL) {
		kmem_free(local_ids, NCPU * sizeof (uint32_t));
		return (PSM_FAILURE);
	}

	id = apic_reg_ops->apic_read(APIC_LID_REG);
	local_ids[0] = (uchar_t)(id >> 24);
	apic_nproc = index = 1;
	apic_io_max = 0;

	ap = (ACPI_SUBTABLE_HEADER *) (acpi_mapic_dtp + 1);
	madt_size = acpi_mapic_dtp->Header.Length;
	madt_seen = sizeof (*acpi_mapic_dtp);

	while (madt_seen < madt_size) {
		switch (ap->Type) {
		case ACPI_MADT_TYPE_LOCAL_APIC:
			mpa = (ACPI_MADT_LOCAL_APIC *) ap;
			if (mpa->LapicFlags & ACPI_MADT_ENABLED) {
				if (mpa->Id == local_ids[0]) {
					ASSERT(index == 1);
					proc_ids[0] = mpa->ProcessorId;
				} else if (apic_nproc < NCPU && use_mp &&
				    apic_nproc < boot_ncpus) {
					local_ids[index] = mpa->Id;
					proc_ids[index] = mpa->ProcessorId;
					index++;
					apic_nproc++;
				} else if (apic_nproc == NCPU && !warned) {
					cmn_err(CE_WARN, "%s: CPU limit "
					    "exceeded"
#if !defined(__amd64)
					    " for 32-bit mode"
#endif
					    "; Solaris will use %d CPUs.",
					    psm_name,  NCPU);
					warned = 1;
				}
			}
			break;

		case ACPI_MADT_TYPE_IO_APIC:
			mia = (ACPI_MADT_IO_APIC *) ap;
			if (apic_io_max < MAX_IO_APIC) {
				ioapic_ix = apic_io_max;
				apic_io_id[apic_io_max] = mia->Id;
				apic_io_vectbase[apic_io_max] =
				    mia->GlobalIrqBase;
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

		case ACPI_MADT_TYPE_INTERRUPT_OVERRIDE:
			mio = (ACPI_MADT_INTERRUPT_OVERRIDE *) ap;
			if (acpi_isop == NULL)
				acpi_isop = mio;
			acpi_iso_cnt++;
			break;

		case ACPI_MADT_TYPE_NMI_SOURCE:
			/* UNIMPLEMENTED */
			mns = (ACPI_MADT_NMI_SOURCE *) ap;
			if (acpi_nmi_sp == NULL)
				acpi_nmi_sp = mns;
			acpi_nmi_scnt++;

			cmn_err(CE_NOTE, "!apic: nmi source: %d 0x%x\n",
			    mns->GlobalIrq, mns->IntiFlags);
			break;

		case ACPI_MADT_TYPE_LOCAL_APIC_NMI:
			/* UNIMPLEMENTED */
			mlan = (ACPI_MADT_LOCAL_APIC_NMI *) ap;
			if (acpi_nmi_cp == NULL)
				acpi_nmi_cp = mlan;
			acpi_nmi_ccnt++;

			cmn_err(CE_NOTE, "!apic: local nmi: %d 0x%x %d\n",
			    mlan->ProcessorId, mlan->IntiFlags,
			    mlan->Lint);
			break;

		case ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE:
			/* UNIMPLEMENTED */
			mao = (ACPI_MADT_LOCAL_APIC_OVERRIDE *) ap;
			cmn_err(CE_NOTE, "!apic: address override: %lx\n",
			    (long)mao->Address);
			break;

		case ACPI_MADT_TYPE_IO_SAPIC:
			/* UNIMPLEMENTED */
			misa = (ACPI_MADT_IO_SAPIC *) ap;

			cmn_err(CE_NOTE, "!apic: io sapic: %d %d %lx\n",
			    misa->Id, misa->GlobalIrqBase,
			    (long)misa->Address);
			break;

		case ACPI_MADT_TYPE_INTERRUPT_SOURCE:
			/* UNIMPLEMENTED */
			mis = (ACPI_MADT_INTERRUPT_SOURCE *) ap;

			cmn_err(CE_NOTE,
			    "!apic: irq source: %d %d %d 0x%x %d %d\n",
			    mis->Id, mis->Eid, mis->GlobalIrq,
			    mis->IntiFlags, mis->Type,
			    mis->IoSapicVector);
			break;

		case ACPI_MADT_TYPE_LOCAL_X2APIC:
			mpx2a = (ACPI_MADT_LOCAL_X2APIC *) ap;

			/*
			 * All logical processors with APIC ID values
			 * of 255 and greater will have their APIC
			 * reported through Processor X2APIC structure.
			 * All logical processors with APIC ID less than
			 * 255 will have their APIC reported through
			 * Processor Local APIC.
			 */
			if (mpx2a->LocalApicId < 255) {
				cmn_err(CE_WARN, "!%s: ignoring invalid entry "
				    "in MADT: CPU %d has X2APIC Id %d (< 255)",
				    psm_name, mpx2a->Uid, mpx2a->LocalApicId);
			} else if (mpx2a->LapicFlags & ACPI_MADT_ENABLED) {
				if (apic_nproc < NCPU && use_mp &&
				    apic_nproc < boot_ncpus) {
					local_ids[index] = mpx2a->LocalApicId;
					proc_ids[index] = mpx2a->Uid;
					index++;
					apic_nproc++;
				} else if (apic_nproc == NCPU && !warned) {
					cmn_err(CE_WARN, "%s: CPU limit "
					    "exceeded"
#if !defined(__amd64)
					    " for 32-bit mode"
#endif
					    "; Solaris will use %d CPUs.",
					    psm_name,  NCPU);
					warned = 1;
				}
			}

			break;

		case ACPI_MADT_TYPE_LOCAL_X2APIC_NMI:
			/* UNIMPLEMENTED */
			mx2alan = (ACPI_MADT_LOCAL_X2APIC_NMI *) ap;
			if (mx2alan->Uid >> 8)
				acpi_nmi_ccnt++;

#ifdef	DEBUG
			cmn_err(CE_NOTE,
			    "!apic: local x2apic nmi: %d 0x%x %d\n",
			    mx2alan->Uid, mx2alan->IntiFlags, mx2alan->Lint);
#endif

			break;

		case ACPI_MADT_TYPE_RESERVED:
		default:
			break;
		}

		/* advance to next entry */
		madt_seen += ap->Length;
		ap = (ACPI_SUBTABLE_HEADER *)(((char *)ap) + ap->Length);
	}

	/*
	 * allocate enough space for possible hot-adding of CPUs.
	 * max_ncpus may be less than apic_nproc if it's set by user.
	 */
	if (plat_dr_support_cpu()) {
		apic_max_nproc = max_ncpus;
	}
	apic_cpus_size = max(apic_nproc, max_ncpus) * sizeof (*apic_cpus);
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
		apic_cpus[i].aci_processor_id = proc_ids[i];
		/* Only build mapping info for CPUs present at boot. */
		if (i < boot_ncpus)
			(void) acpica_map_cpu(i, proc_ids[i]);
	}

	/*
	 * To support CPU dynamic reconfiguration, the apic CPU info structure
	 * for each possible CPU will be pre-allocated at boot time.
	 * The state for each apic CPU info structure will be assigned according
	 * to the following rules:
	 * Rule 1:
	 * 	Slot index range: [0, min(apic_nproc, boot_ncpus))
	 *	State flags: 0
	 *	Note: cpu exists and will be configured/enabled at boot time
	 * Rule 2:
	 * 	Slot index range: [boot_ncpus, apic_nproc)
	 *	State flags: APIC_CPU_FREE | APIC_CPU_DIRTY
	 *	Note: cpu exists but won't be configured/enabled at boot time
	 * Rule 3:
	 * 	Slot index range: [apic_nproc, boot_ncpus)
	 *	State flags: APIC_CPU_FREE
	 *	Note: cpu doesn't exist at boot time
	 * Rule 4:
	 * 	Slot index range: [max(apic_nproc, boot_ncpus), max_ncpus)
	 *	State flags: APIC_CPU_FREE
	 *	Note: cpu doesn't exist at boot time
	 */
	CPUSET_ZERO(apic_cpumask);
	for (i = 0; i < min(boot_ncpus, apic_nproc); i++) {
		CPUSET_ADD(apic_cpumask, i);
		apic_cpus[i].aci_status = 0;
	}
	for (i = boot_ncpus; i < apic_nproc; i++) {
		apic_cpus[i].aci_status = APIC_CPU_FREE | APIC_CPU_DIRTY;
	}
	for (i = apic_nproc; i < boot_ncpus; i++) {
		apic_cpus[i].aci_status = APIC_CPU_FREE;
	}
	for (i = max(boot_ncpus, apic_nproc); i < max_ncpus; i++) {
		apic_cpus[i].aci_status = APIC_CPU_FREE;
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
	(void) acpica_build_processor_map();

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
		if (apic_sci_vect > 0) {
			acpica_set_core_feature(ACPI_FEATURE_SCI_EVENT);
		}
		if (apic_use_acpi_madt_only) {
			cmn_err(CE_CONT,
			    "?Using ACPI for CPU/IOAPIC information ONLY\n");
		}

#if !defined(__xpv)
		/*
		 * probe ACPI for hpet information here which is used later
		 * in apic_picinit().
		 */
		if (hpet_acpi_init(&apic_hpet_vect, &apic_hpet_flags) < 0) {
			cmn_err(CE_NOTE, "!ACPI HPET table query failed\n");
		}
#endif

		kmem_free(local_ids, NCPU * sizeof (uint32_t));
		kmem_free(proc_ids, NCPU * sizeof (uint32_t));
		return (PSM_SUCCESS);
	}
	/* if setting APIC mode failed above, we fall through to cleanup */

cleanup:
	apic_free_apic_cpus();
	if (apicadr != NULL) {
		mapout_apic((caddr_t)apicadr, APIC_LOCAL_MEMLEN);
		apicadr = NULL;
	}
	apic_max_nproc = -1;
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
	kmem_free(local_ids, NCPU * sizeof (uint32_t));
	kmem_free(proc_ids, NCPU * sizeof (uint32_t));
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

	/* Failed to probe ACPI MADT tables, disable CPU DR. */
	apic_max_nproc = -1;
	apic_free_apic_cpus();
	plat_dr_disable_cpu();

	apicioadr[0] = (void *)mapin_ioapic(APIC_IO_ADDR,
	    APIC_IO_MEMLEN, PROT_READ | PROT_WRITE);
	apicadr = (void *)psm_map_phys(APIC_LOCAL_ADDR,
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
					cmn_err(CE_WARN, "%s: CPU limit "
					    "exceeded"
#if !defined(__amd64)
					    " for 32-bit mode"
#endif
					    "; Solaris will use %d CPUs.",
					    psm_name,  NCPU);
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
				apicioadr[apic_io_max] =
				    (void *)mapin_ioapic(
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
	cpu &= ~IRQ_USER_BOUND;
	/* Check whether cpu id is in valid range. */
	if (cpu < 0 || cpu >= apic_nproc) {
		return (B_FALSE);
	} else if (apic_max_nproc != -1 && cpu >= apic_max_nproc) {
		/*
		 * Check whether cpuid is in valid range if CPU DR is enabled.
		 */
		return (B_FALSE);
	} else if (!CPU_IN_SET(apic_cpumask, cpu)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

processorid_t
apic_get_next_bind_cpu(void)
{
	int i, count;
	processorid_t cpuid = 0;

	for (count = 0; count < apic_nproc; count++) {
		if (apic_next_bind_cpu >= apic_nproc) {
			apic_next_bind_cpu = 0;
		}
		i = apic_next_bind_cpu++;
		if (apic_cpu_in_range(i)) {
			cpuid = i;
			break;
		}
	}

	return (cpuid);
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
 * On machines with PCI-PCI bridges, a device behind a PCI-PCI bridge
 * needs special handling.  We may need to chase up the device tree,
 * using the PCI-PCI Bridge specification's "rotating IPIN assumptions",
 * to find the IPIN at the root bus that relates to the IPIN on the
 * subsidiary bus (for ACPI or MP).  We may, however, have an entry
 * in the MP table or the ACPI namespace for this device itself.
 * We handle both cases in the search below.
 */
/* this is the non-acpi version */
int
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

uchar_t
acpi_find_ioapic(int irq)
{
	int i;

	for (i = 0; i < apic_io_max; i++) {
		if (irq >= apic_io_vectbase[i] && irq <= apic_io_vectend[i])
			return ((uchar_t)i);
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

struct apic_io_intr *
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

int
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
int
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
		apic_irq_table[freeirq]->airq_temp_cpu = IRQ_UNINIT;
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
 * compute the polarity, trigger mode and vector for programming into
 * the I/O apic and record in airq_rdt_entry.
 */
void
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
		prom_printf("setio: ioapic=0x%x intin=0x%x level=0x%x po=0x%x "
		    "vector=0x%x cpu=0x%x\n\n", ioapicindex,
		    irqptr->airq_intin_no, level, io_po, vector,
		    irqptr->airq_cpu);

	irqptr->airq_rdt_entry = level|io_po|vector;
}

int
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
	int	i, cpuid;
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
	if ((cpuid = psm_get_cpu_id()) == 0) {

		iflag = intr_clear();
		lock_set(&apic_ioapic_lock);

		for (i = 0; i < apic_io_max; i++)
			sp->as_ioapic_ids[i] = ioapic_read(i, APIC_ID_CMD);

		lock_clear(&apic_ioapic_lock);
		intr_restore(iflag);
	}

	/* apic_state() is currently invoked only in Suspend/Resume */
	apic_cpus[cpuid].aci_status |= APIC_CPU_SUSPEND;
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
