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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Netract Platform specific functions.
 *
 * 	called when :
 *	machine_type == MTYPE_MONTECARLO
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* includes */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <fcntl.h>
#include <kvm.h>
#include <kstat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/devinfo_impl.h>
#include <sys/ioccom.h>
#include <sys/systeminfo.h>
#include <libintl.h>
#include <config_admin.h>
#include "pdevinfo.h"
#include "display.h"
#include "pdevinfo_sun4u.h"
#include "display_sun4u.h"
#include "libprtdiag.h"
#include "libdevinfo.h"

/* MC specific header, might just include from MC space */
#include "mct_topology.h"
#include "envctrl_gen.h"
#include "pcf8574_nct.h"
#include "netract_gen.h"
#include "hscimpl.h"
#include "scsbioctl.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN			"SYS_TEST"
#endif

/* globals */
#define	MAXNAMESZ			128
#define	MAX_NODE_NAME_SZ		32

/* this values equates to Max Tree depth for now */
#define	MAXIMUM_DEVS			64

typedef char device_info_t[MAX_NODE_NAME_SZ];

typedef struct {
	cfga_list_data_t *ldatap;
	int req; /* If set, this list_data was requested by user */
} ap_out_t;


typedef struct {
	uint_t slot_addr;
	uint_t slot_stat;
	uint_t slot_cond;
	device_info_t devs_info[MAXIMUM_DEVS];
	uint_t number_devs;
} mc_slot_info_t;

typedef struct {
	mc_slot_info_t mc_slot_info[MC_MAX_SLOTS];
} slot_data_t;


extern char *progname;
extern int print_flag;

/* These are used to store all force loads of the drivers */
static int ps_fd[MC_MAX_PS];
static int oprom_fd;
static int slot_index			= 0;
static int idx_minuscpu			= 0;
static int num_devs			= 0;
static int sd_instances[MC_MAX_SLOTS*15];
static int gpio_instances[MC_MAX_PS+MC_MAX_FAN];
static int sd_count			= 0;
static int st_instance;
static int gpio_count			= 0;
static int slot_table_not_found		= 0;

/* default not present */
static int alarm_card_present		= 0;
static int cpu_ftm_present		= 0;

/*
 * We will store all kstat in globals so that
 * we can browse thru them later
 */
static	int fail_syssoft_prop		= 0;
static  int fail_drv_prop		= 0;
di_node_t rootnode;	/* root nexus */
slot_data_t mc_slots_data;

/* scsb driver kstats */
scsb_ks_leddata_t scsb_ks_leddata;
scsb_ks_state_t scsb_ks_state;
mct_topology_t scsb_ks_topo;

/* pcf8574(gpio) driver kstats */
envctrl_cpuvoltage_t pcf8574_ks_cpuv;
envctrl_pwrsupp_t pcf8574_ks_ps1;
envctrl_fantray_t pcf8574_ks_fant1;
envctrl_pwrsupp_t pcf8574_ks_ps2;
envctrl_fantray_t pcf8574_ks_fant2;

/* pcf8591(adc-dac) driver kstats */
envctrl_temp_t pcf8591_ks_temp;

hsc_slot_table_t hotswap_slot_table[MC_MAX_SLOTS];
hsc_prom_slot_table_t prom_slot_table[MC_MAX_SLOTS];

static char *hotswap_mode		= NULL;
static char *slot_auto_config[MC_MAX_SLOTS];
static	int slot_table_size;

/*
 * use this to ascertain what's the system,
 * default is tonga, we can add more for future variations
 * 0=tonga, 1=montecarlo
 * we need also to figure out what the system version is
 * 0 = 1.5, 1 = 1.0, 0.6 etc.
 */
int montecarlo				= 0;
int version_p15_and_p20			= 0;

#define	MAX_PRTDIAG_INFO_LENGTH		1024
#define	MAX_PRTDIAG_FRUS		22
#define	BIT_TEST(X, N)			((X) & (1 << (N)))
#define	SLOT1_OK_BIT			0
#define	SLOT2_OK_BIT			1
#define	SLOT3_OK_BIT			2
#define	SLOT4_OK_BIT			3
#define	SLOT5_OK_BIT			4
#define	SLOT6_OK_BIT			5
#define	SLOT7_OK_BIT			6
#define	SLOT8_OK_BIT			7
#define	PDU1_OK_BIT			SLOT2_OK_BIT
#define	PDU2_OK_BIT			SLOT4_OK_BIT
#define	FTM_OK_BIT			SLOT5_OK_BIT
#define	SCB_OK_BIT			SLOT6_OK_BIT
#define	FAN1_OK_BIT			SLOT1_OK_BIT
#define	FAN2_OK_BIT			SLOT2_OK_BIT
#define	DISK1_OK_BIT			SLOT4_OK_BIT
#define	DISK2_OK_BIT			SLOT5_OK_BIT
#define	DISK3_OK_BIT			SLOT6_OK_BIT
#define	PS1_OK_BIT			SLOT7_OK_BIT
#define	PS2_OK_BIT			SLOT8_OK_BIT
#define	S_FREE(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)
#define	ENVC_DEBUG_MODE			0x03
#define	OPENPROMDEV			"/dev/openprom"
#define	I2C_PCF8591_NAME 		"adc-dac"
#define	I2C_KSTAT_CPUTEMP 		"adc_temp"
#define	SCSB_DEV			"scsb"
#define	SDERR				"sderr"
#define	STERR				"sterr"
#define	OK				"ok"
#define	NOK				"Not ok"
#define	ON				"on"
#define	OFF				"off"
#define	BLINK				"blink"
#define	NA				"Not Available"
#define	UK				"Unknown "
#define	YES				"Yes"
#define	NO				"No "
#define	LO				"low"
#define	HI				"high"
#define	BLANK				" "
#define	SYSSOFT_PROP			"System software"
#define	DRV_PROP			"Driver"
#define	HSC_PROP_NAME			"hsc-slot-map"
#define	HSC_MODE			"hotswap-mode"
#define	PCI_ROOT_AP			"pci"
#define	PROPS				"Properties:"
#define	BOARDTYPE			"Board Type:"
#define	DEVS				"Devices:"
#define	CPCI_IO				"CompactPCI IO Slot"
#define	AC_CARD				"Alarm Card"
#define	CPU_FTM				"Front Transition Module"
#define	SCTRL_PROM_P06			0x00
#define	SCTRL_PROM_P10			0x01
#define	SCTRL_PROM_P15			0x02
#define	SCTRL_PROM_P20			0x03

#define	RMM_NUMBER			3

#define	MONTECARLO_PLATFORM		"SUNW,UltraSPARC-IIi-Netract"
#define	MAKAHA_PLATFORM			"SUNW,UltraSPARC-IIe-NetraCT-40"

/*
 * The follow table is indexed with the enum's defined by mct_slot_occupant_t
 * OC_UNKN OC_CPU  OC_AC    OC_BHS OC_FHS OC_HAHS
 * OC_QFE  OC_FRCH OC_COMBO OC_PMC OC_ATM
 *
 * But "scsb" can currently identify only CPU and Alarm Cards by known
 * slot numbers.
 */
char	*slot_occupants[] = {
		CPCI_IO,
		"CPU board ",
		CPCI_IO,
		"Basic HotSwap Board",
		"Full HotSwap Board",
		"HA Board",
		"QFE Board",
		"Fresh Choice Board",
		"SUN Combo Board",
		"PMC Board",
		"ATM Board"
	};

static char	*prtdiag_fru_types[] = {
		"I/O        ",	/* 0 */
		"CPU        ",
		"PSU        ",
		"HDD        ",
		"FAN        ",
		"Alarm Card ",
		"SCB        ",
		"SSB        ",
		"CFTM       ",
		"CRTM       ",
		"PRTM       ",
		"Midplane   "	/* 11 */
	};

char prtdiag_fru_info[MAX_PRTDIAG_FRUS][MAX_PRTDIAG_INFO_LENGTH];

#define	SCB_REG_READ			1
#define	SCB_REG_WRITE			2

/* Standard Device nodes - hardwired for now */
/* will include fan tray later, cpu voltage not impl */
static char	*scsb_node = NULL;
static char	**ps_node = NULL;
static char	*temp_node = NULL;

static char	*mc_scsb_node =
"/devices/pci@1f,0/pci@1,1/ebus@1/i2c@14,600000/sysctrl@0,80:scsb";

static char	*ot_scsb_node =
"/devices/pci@1f,0/pci@1,1/ebus@3/sysmgmt@14,600000/sysctrl@0,80:scsb";

static char	*mc_ps_node[] = {
"/devices/pci@1f,0/pci@1,1/ebus@1/i2c@14,600000/gpio@0,7c:pwrsuppply",
"/devices/pci@1f,0/pci@1,1/ebus@1/i2c@14,600000/gpio@0,7e:pwrsuppply"
};

static char	*ot_ps_node[] = {
"/devices/pci@1f,0/pci@1,1/ebus@3/sysmgmt@14,600000/gpio@0,7c:pwrsuppply",
"/devices/pci@1f,0/pci@1,1/ebus@3/sysmgmt@14,600000/gpio@0,7e:pwrsuppply"
};

static char	*mc_temp_node =
"/devices/pci@1f,0/pci@1,1/ebus@1/i2c@14,600000/adc-dac@0,9e:cputemp";

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (netract systems only)
 * display functions
 */
int	display(Sys_tree *, Prom_node *, struct system_kstat_data *, int);
/* local functions */
/*
 * prom function
 */
static void	gather_diaginfo(int flag);
static int	extract_slot_table_from_obp();
static int	mc_next(int id);
static void	mc_walk(int id);
static int	mc_child(int id);
static void	mc_dump_node(int id);
static int	mc_getpropval(struct openpromio *opp);

#ifdef	REDUNDANT_INFO
static int	mc_get_cpu_freq(Prom_node *node);
static int	mc_get_ecache_size(Prom_node *node);
static void	mc_display_cpus(Board_node *board);
static void	mc_display_cpu_devices(Sys_tree *tree);
#endif	/* REDUNDANT_INFO */

static void	netract_disp_prom_version();

/*
 * Since we do not have a system wide kstat for MC/Tg
 * here we have to do specific kstats to drivers that
 * post this information - MC/Tg specific drivers
 * that post kstat here are : scsb, pcf8574(gpio) and pcf8591
 */
static int	analyze_nodes(di_node_t, void*);
static void	analyze_pcipci_siblings(di_node_t);
static void	display_mc_prtdiag_info();
static int	dump_devs(di_node_t, void *);
static void	prtdiag_devinfo(void);
static void	force_load_drivers();
static int	dump_prop_list(char *name,
		    di_node_t node, di_prop_t (*nxtprop)());
static void	*config_calloc_check(size_t nelem, size_t elsize);
static void	explore_slot_occupants();
static void	do_scsb_kstat();
static void	do_pcf8574_kstat();
static void	do_pcf8591_kstat();
static void	do_promversion();
static int	mc_promopen(int oflag);
static int	scsi_disk_status(int disk_number);
static void	alarm_card_occupant();
static int	scsb_mode(int fd, scsb_op_t sop, uint8_t *new_mode);
static int	scsb_ioc_reg_read(int fd, uchar_t index,
		    scsb_ioc_rdwr_t *ioc_rd, int num);

static int	check_platform();

int
display(Sys_tree *tree,
	    Prom_node *root,
	    struct system_kstat_data *kstats,
	    int syserrlog)
{
	int exit_code = 0;   /* init to all OK */
	void *value;  /* used for opaque PROM data */
	struct mem_total memory_total;  /* Total memory in system */
	struct grp_info grps;   /* Info on all groups in system */
#ifdef	lint
	syserrlog = syserrlog;
#endif
	sys_clk = -1;  /* System clock freq. (in MHz) */
	/*
	 * Now display the machine's configuration. We do this if we
	 * are not logging or exit_code is set (machine is broke).
	 */
	if (!logging || exit_code) {
		struct utsname uts_buf;

		/*
		 * Display system banner
		 */
		(void) uname(&uts_buf);

		log_printf(dgettext(TEXT_DOMAIN,
			"System Configuration:  Sun Microsystems"
			"  %s %s\n"), uts_buf.machine,
			get_prop_val(find_prop(root, "banner-name")), 0);

		/* display system clock frequency */
		value = get_prop_val(find_prop(root, "clock-frequency"));
		if (value != NULL) {
			sys_clk = ((*((int *)value)) + 500000) / 1000000;
			log_printf(dgettext(TEXT_DOMAIN,
			    "System clock frequency: "
			    "%d MHz\n"), sys_clk, 0);
		}

		/* Display the Memory Size */
		display_memorysize(tree, kstats, &grps, &memory_total);
		/* Lets make sure we have all the needed drivers loaded */
		/* display Montecarlo/Tonga FRU information */
		if (!extract_slot_table_from_obp())
			log_printf(dgettext(TEXT_DOMAIN,
			    "\r\nslot-table not available\r\n"), 0);
		do_scsb_kstat();
		force_load_drivers();
		gather_diaginfo(print_flag && !logging);
		/* figure out if ac is present */
		alarm_card_occupant();
		/* platform specific display mod */
		display_mc_prtdiag_info();
		di_fini(rootnode);
		netract_disp_prom_version();
	}  /* if (!logging || exit_code) */

	return (exit_code);

}	/* display(....) */

static int
check_platform()
{
	char	si_platform[SYS_NMLN];

	/*
	 * Check for the platform: Montecarlo or Makaha/CP2040 based
	 */
	if (sysinfo(SI_PLATFORM, si_platform, sizeof (si_platform)) == -1) {
		return (-1);
	}

	if ((strncmp(si_platform, MONTECARLO_PLATFORM,
				strlen(MONTECARLO_PLATFORM))) == 0) {
		scsb_node = mc_scsb_node;
		ps_node = mc_ps_node;
		temp_node = mc_temp_node;
	} else if ((strncmp(si_platform, MAKAHA_PLATFORM,
				strlen(MAKAHA_PLATFORM))) == 0) {
		scsb_node = ot_scsb_node;
		ps_node = ot_ps_node;
		temp_node = NULL;
	} else {
		return (-1);
	}

	return (0);
}

void
force_load_drivers()
{
	int	i;

	if (NULL == scsb_node || NULL == ps_node) {
		if (check_platform() == -1) {
			return;
		}
	}

	/* check scb/ssb presence */
	if (scsb_ks_state.scb_present || scsb_ks_state.ssb_present) {
		if (open(scsb_node, O_RDONLY) < 0)
			log_printf(dgettext(TEXT_DOMAIN,
			    "\nscsb open FAILED!"), 0);
	}

	/* check the num of PS we have */
	for (i = 0; i < scsb_ks_topo.max_units[PS]; ++i) {
		if (scsb_ks_topo.mct_ps[i].fru_status == FRU_PRESENT) {
			if ((ps_fd[i] = open(ps_node[i], O_RDONLY)) < 0)
				log_printf(dgettext(TEXT_DOMAIN,
				    "\npowersupply%d open failed"),
				    i, 0);
		}
	} /* for */

	/* open the cpu temp driver */
	if (temp_node) {
		if (open(temp_node, O_RDONLY) < 0)
			log_printf(dgettext(TEXT_DOMAIN,
						"\ncputemp open FAILED!"), 0);
	}
}


void
explore_slot_occupants()
{
	char *cp = NULL;
	int index;
	int ret = CFGA_ERROR;
	char *estrp = NULL;
	cfga_list_data_t *list_array = NULL;
	ap_out_t *out_array = NULL;
	int nlist = 0;
	char  *prefilt_optp = NULL;
	int dyn_exp = 1;
	char *plat_opts = NULL;

	ret = config_list_ext(0, NULL, &list_array,
	    &nlist, plat_opts, prefilt_optp, &estrp,
	    dyn_exp ? CFGA_FLAG_LIST_ALL : 0);
	if (ret != CFGA_OK) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\ncannot explore configuration"), 0);
		return;
	}
	assert(nlist != 0);
	out_array = config_calloc_check(nlist, sizeof (*out_array));
	if (out_array == NULL) {
		ret = CFGA_LIB_ERROR;
		goto bail;
	}
	/* create a list of output stat data */
	for (index = 0; index < nlist; index++) {
		out_array[index].ldatap = &list_array[index];
		out_array[index].req = 0;
	}

	for (index = 0; index < nlist; index++) {
		if ((cp = strstr(out_array[index].ldatap->ap_phys_id,
		    "cpci_slot")) != NULL) {
			mc_slots_data.mc_slot_info[idx_minuscpu].slot_stat
			    = out_array[index].ldatap->ap_o_state;
			mc_slots_data.mc_slot_info[idx_minuscpu].slot_cond
			    = out_array[index].ldatap->ap_cond;
			idx_minuscpu++;
		}
	}
bail:
	S_FREE(list_array);
	S_FREE(out_array);
}


/*
 * config_calloc_check - perform allocation, check result and
 * set error indicator
 */
void *
config_calloc_check(
	size_t nelem,
	size_t elsize)
{
	void *p;
	static char alloc_fail[] =
		"%s: memory allocation failed (%d*%d bytes)\n";

	p = calloc(nelem, elsize);
	if (p == NULL) {
		log_printf(dgettext(TEXT_DOMAIN, alloc_fail), nelem, elsize, 0);
	}
	return (p);
}


void
do_scsb_kstat()
{
	kstat_ctl_t	*kc;
	kstat_t		*ksp_leddata;
	kstat_t		*ksp_state;
	kstat_t		 *ksp_topo;
	scsb_ks_leddata_t *pks_leddata;
	scsb_ks_state_t *pks_state;
	mct_topology_t  *pks_topo;
	int i;

#ifdef	DEBUG_TEMP1
		int index;
#endif
	if (!(kc = kstat_open())) {
#ifdef	DEBUG_TEMP
		log_printf("\nkstat_open failed", 0);
#endif
		return;
	}
#ifdef	lint
	kc = kc;
#endif
	/* get kstat on scsb led data */
	if ((ksp_leddata = kstat_lookup(kc, SCSB_DEV, 0, SCSB_KS_LEDDATA))
	    == NULL) {
#ifdef	DEBUG_TEMP
		log_printf("\nkstat_lookup for scsb_leddata failed", 0);
#endif
		return;
	}
	if (kstat_read(kc, ksp_leddata, NULL) == -1) {
#ifdef	DEBUG_TEMP
		log_printf("\nkstat_read for scsb_leddata failed", 0);
#endif
		return;
	}
	pks_leddata = (scsb_ks_leddata_t *)ksp_leddata->ks_data;
	scsb_ks_leddata = *pks_leddata; /* set the globals for future */
#ifdef	DEBUG_LEDS
	/* dump the kstat leddata */
	printf("\nDumping LED regs: ");
	for (i = 0; i < SCSB_LEDDATA_REGISTERS; ++i) {
		log_printf("0x%x ", pks_leddata->scb_led_regs[i] & 0xff, 0);
	}
	log_printf("\n", 0);
#endif
	/* get kstat on scsb states */
	if ((ksp_state = kstat_lookup(kc, SCSB_DEV, 0, SCSB_KS_STATE))
	    == NULL) {
#ifdef	DEBUG_TEMP
		log_printf("\nkstat_lookup for scsb_state failed", 0);
#endif
		return;
	}
	if (kstat_read(kc, ksp_state, NULL) == -1) {
#ifdef	DEBUG_TEMP
		log_printf("\nkstat_read for scsb_state failed", 0);
#endif
		return;
	}
	pks_state = (scsb_ks_state_t *)ksp_state->ks_data;
	scsb_ks_state = *pks_state; /* set the global for future */
#ifdef	DEBUG_TEMP1
	/* dump the kstat state */
	log_printf("\tSCB			is%spresent\n",
	    pks_state->scb_present ? " " : " not ", 0);
	log_printf("\tSSB			is%spresent\n",
	    pks_state->ssb_present ? " " : " not ", 0);
	log_printf("\tscsb			is%sfrozen\n",
	    pks_state->scsb_frozen ? " " : " not ", 0);
	log_printf("\tscsb mode:		", 0);
	switch (pks_state->scsb_mode) {
		case ENVC_DEBUG_MODE:
			log_printf("DEBUG MODE\n", 0);
			break;
		case ENVCTRL_DIAG_MODE:
			log_printf("DIAGNOSTIC MODE\n", 0);
			break;
		case ENVCTRL_NORMAL_MODE:
			log_printf("NORMAL MODE\n", 0);
			break;
	}
	log_printf("\tscsb event code:	0x%x\n", pks_state->event_code, 0);
#endif	/* DEBUG_TEMP1 */

	if ((ksp_topo = kstat_lookup(kc, SCSB_DEV, 0, SCSB_KS_TOPOLOGY))
	    == NULL) {
#ifdef	DEBUG_TEMP
		log_printf("\nkstat_lookup for scsb_topo failed", 0);
#endif
		return;
	}
	if (kstat_read(kc, ksp_topo, NULL) == -1) {
#ifdef	DEBUG_TEMP
		log_printf("\nkstat_read for scsb_topo failed", 0);
#endif
		return;
	}
	pks_topo = (mct_topology_t *)ksp_topo->ks_data;
	scsb_ks_topo = *pks_topo; /* set the global for future */
	/*
	 * we need to set this so that we can get status info
	 * for the 2 powersupplies in MC as we need to get
	 * kstat from both driver instances for environment
	 */
	if (pks_topo->mid_plane.fru_id == SCTRL_MPID_HALF)
		montecarlo = 1; /* Monte Carlo */
	/*
	 * HW version 0.6 and 1.0 had different led maps
	 * its assumed that HW 2.0 would not change this
	 * need to modify if it does
	 */
	if ((pks_topo->mct_scb[0].fru_version == SCTRL_PROM_P15) ||
	    (pks_topo->mct_scb[0].fru_version == SCTRL_PROM_P20)) {
		version_p15_and_p20 = 1;
	}

	/* set flag to note that CFTM is present */
	for (i = 0; i < pks_topo->max_units[CFTM]; ++i) {
		if (pks_topo->mct_cftm[i].fru_status == FRU_PRESENT)
			cpu_ftm_present = 1;
	}

#ifdef	DEBUG_TEMP1
	/*
	 * Midplane
	 */
	log_printf("Midplane type:		", 0);
	if (pks_topo->mid_plane.fru_id == SCTRL_MPID_HALF)
		log_printf("Netra ct800 server\n", 0);
	else
		log_printf("Netra ct400 server%s\n",
		    pks_topo->mid_plane.fru_id ==
		    SCTRL_MPID_QUARTER_NODSK ? ", no disk" : " with disk", 0);
	log_printf("Midplane version:	%d\n",
	    pks_topo->mid_plane.fru_version, 0);
	log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		pks_topo->mct_scb[0].fru_type,
		pks_topo->mct_scb[0].fru_unit,
		pks_topo->mct_scb[0].fru_id,
		pks_topo->mct_scb[0].fru_version, 0);
	/*
	 * Slots
	 */
	log_printf("Slots present out of maximum %d\n",
	    pks_topo->max_units[SLOT], 0);
	for (i = 0; i < pks_topo->max_units[SLOT]; ++i) {
		if (pks_topo->mct_slots[i].fru_status != FRU_PRESENT)
			continue;
		index = (int)pks_topo->mct_slots[i].fru_type;
		log_printf("\tSlot %d occupant: %s;",
		    pks_topo->mct_slots[i].fru_unit, slot_occupants[index], 0);
		log_printf(" ID 0x%x; VER 0x%x ; ",
		    pks_topo->mct_slots[i].fru_id,
		    pks_topo->mct_slots[i].fru_version, 0);
		log_printf(" Slot health %d\n",
		    pks_topo->mct_slots[i].fru_health, 0);
		/* pks_topo->mct_slots[i].fru_health */
	}

	/*
	 * PDU
	 */
	log_printf("PDUs present out of maximum %d\n",
	    pks_topo->max_units[PDU], 0);
	for (i = 0; i < pks_topo->max_units[PDU]; ++i) {
		if (pks_topo->mct_pdu[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_pdu[i].fru_type,
		    pks_topo->mct_pdu[i].fru_unit,
		    pks_topo->mct_pdu[i].fru_id,
		    pks_topo->mct_pdu[i].fru_version, 0);
		/* pks_topo->mct_pdu[i].fru_health */
	}

	/*
	 * Power Supplies
	 */
	log_printf("Power Supplies present out of maximum %d\n",
	    pks_topo->max_units[PS], 0);
	for (i = 0; i < pks_topo->max_units[PS]; ++i) {
		if (pks_topo->mct_ps[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_ps[i].fru_type,
		    pks_topo->mct_ps[i].fru_unit,
		    pks_topo->mct_ps[i].fru_id,
		    pks_topo->mct_ps[i].fru_version, 0);
	}

	/*
	 * Disks
	 */
	log_printf("Disks present out of maximum %d\n",
	    pks_topo->max_units[DISK], 0);
	for (i = 0; i < pks_topo->max_units[DISK]; ++i) {
		if (pks_topo->mct_disk[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_disk[i].fru_type,
		    pks_topo->mct_disk[i].fru_unit,
		    pks_topo->mct_disk[i].fru_id,
		    pks_topo->mct_disk[i].fru_version, 0);
	}

	/*
	 * Fans
	 */
	log_printf("Fans present out of maximum %d\n",
	    pks_topo->max_units[FAN], 0);
	for (i = 0; i < pks_topo->max_units[FAN]; ++i) {
		if (pks_topo->mct_fan[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_fan[i].fru_type,
		    pks_topo->mct_fan[i].fru_unit,
		    pks_topo->mct_fan[i].fru_id,
		    pks_topo->mct_fan[i].fru_version, 0);
	}

	/*
	 * SCBs
	 */
	log_printf("SCBs present out of maximum %d\n",
	    pks_topo->max_units[SCB], 0);
	for (i = 0; i < pks_topo->max_units[SCB]; ++i) {
		if (pks_topo->mct_scb[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_scb[i].fru_type,
		    pks_topo->mct_scb[i].fru_unit,
		    pks_topo->mct_scb[i].fru_id,
		    pks_topo->mct_scb[i].fru_version, 0);
	}

	/*
	 * SSBs
	 */
	log_printf("SSBs present out of maximum %d\n",
	    pks_topo->max_units[SSB], 0);
	for (i = 0; i < pks_topo->max_units[SSB]; ++i) {
		if (pks_topo->mct_ssb[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_ssb[i].fru_type,
		    pks_topo->mct_ssb[i].fru_unit,
		    pks_topo->mct_ssb[i].fru_id,
		    pks_topo->mct_ssb[i].fru_version, 0);
	}

	/*
	 * Alarms Cards
	 */
	log_printf("Alarm Cards present out of maximum %d\n",
	    pks_topo->max_units[ALARM], 0);
	for (i = 0; i < pks_topo->max_units[ALARM]; ++i) {
		if (pks_topo->mct_alarm[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d; unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_alarm[i].fru_type,
		    pks_topo->mct_alarm[i].fru_unit,
		    pks_topo->mct_alarm[i].fru_id,
		    pks_topo->mct_alarm[i].fru_version, 0);
	}

	/*
	 * CFTMs
	 */
	log_printf("CFTMs present out of maximum %d\n",
	    pks_topo->max_units[CFTM], 0);
	for (i = 0; i < pks_topo->max_units[CFTM]; ++i) {
		if (pks_topo->mct_cftm[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_cftm[i].fru_type,
		    pks_topo->mct_cftm[i].fru_unit,
		    pks_topo->mct_cftm[i].fru_id,
		    pks_topo->mct_cftm[i].fru_version, 0);
	}

	/*
	 * CRTMs
	 */
	log_printf("CRTMs present out of maximum %d\n",
	    pks_topo->max_units[CRTM], 0);
	for (i = 0; i < pks_topo->max_units[CRTM]; ++i) {
		if (pks_topo->mct_crtm[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_crtm[i].fru_type,
		    pks_topo->mct_crtm[i].fru_unit,
		    pks_topo->mct_crtm[i].fru_id,
		    pks_topo->mct_crtm[i].fru_version, 0);
	}

	/*
	 * PRTMs
	 */
	log_printf("PRTMs present out of maximum %d\n",
	    pks_topo->max_units[PRTM], 0);
	for (i = 0; i < pks_topo->max_units[PRTM]; ++i) {
		if (pks_topo->mct_prtm[i].fru_status != FRU_PRESENT)
			continue;
		log_printf("\ttype %d unit %d; id 0x%x; VER 0x%x\n",
		    pks_topo->mct_prtm[i].fru_type,
		    pks_topo->mct_prtm[i].fru_unit,
		    pks_topo->mct_prtm[i].fru_id,
		    pks_topo->mct_prtm[i].fru_version, 0);
	}
#endif	/* DEBUG_TEMP1 */

}	/*  do_scsb_kstat(...) */


void
do_pcf8574_kstat()
{
	kstat_ctl_t	*kc;
	kstat_t		*ksp_ps;
	kstat_t		*ksp_fan;
	envctrl_pwrsupp_t *pks_ps;
	envctrl_fantray_t *pks_fan;
	int	i;
	char	*kstat_name = NULL;

	if (!(kc = kstat_open())) {
#ifdef	DEBUG_TEMP
		log_printf("\nkstat_open for pcf8574 failed", 0);
#endif
		return;
	}

#ifdef	lint
	kc = kc;
#endif
	/* get kstat on gpio powersupply and fan states */
	for (i = 0; i < scsb_ks_topo.max_units[PS]; ++i) {
		if (i == 1) {
			kstat_name = I2C_KSTAT_PWRSUPPLY;
			strncat(kstat_name, "1", 1);
		} else {
			kstat_name = I2C_KSTAT_PWRSUPPLY;
			strncat(kstat_name, "2", 1);
		}
		if ((ksp_ps = kstat_lookup(kc, I2C_PCF8574_NAME, 0, kstat_name))
			== NULL) {
#ifdef	DEBUG_TEMP
			log_printf("\nks lookup for pwrsupply%d failed",
			    i+1, 0);
#endif
			return;
		}
		if (kstat_read(kc, ksp_ps, NULL) == -1) {
#ifdef	DEBUG_TEMP
			log_printf("\nks read for pwrsupply%d failed", i+1, 0);
#endif
			return;
		}
		pks_ps = (envctrl_pwrsupp_t *)ksp_ps->ks_data;
		if (i == 1)
			pcf8574_ks_ps1 = *pks_ps; /* ps 1 */
		else
			pcf8574_ks_ps2 = *pks_ps; /* ps 2 */
	} /* for */
	for (i = 0; i < scsb_ks_topo.max_units[FAN]; ++i) {
		if (i == 1) {
			kstat_name = I2C_KSTAT_FANTRAY;
			strncat(kstat_name, "1", 1);
		} else {
			kstat_name = I2C_KSTAT_FANTRAY;
			strncat(kstat_name, "2", 1);
		}
		if ((ksp_fan = kstat_lookup(kc, I2C_PCF8574_NAME,
		    0, kstat_name)) == NULL) {
#ifdef	DEBUG_TEMP
			log_printf("\nks lookup for fantray%d failed",
			    i+1, 0);
#endif
			return;
		}
		if (kstat_read(kc, ksp_fan, NULL) == -1) {
#ifdef	DEBUG_TEMP
			log_printf("\nks read for fantray%d failed", i+1, 0);
#endif
			return;
		}
		pks_fan = (envctrl_fantray_t *)ksp_fan->ks_data;
		if (i == 1)
			pcf8574_ks_fant1 = *pks_fan; /* fan 1 */
		else
			pcf8574_ks_fant2 = *pks_fan; /* fan 2 */
	} /* for */
	kstat_close(kc);

}	/*  do_pcf8574_kstat(...) */

void
do_pcf8591_kstat()
{
	kstat_ctl_t	*kc;
	kstat_t		*ksp_temp;

	envctrl_temp_t *pks_temp;

	if (!(kc = kstat_open())) {
#ifdef	DEBUG_TEMP
		log_printf("ks open for pcf8591 failed", 0);
#endif
		return;
	}
#ifdef	lint
	kc = kc;
#endif
	/* get kstat on adc driver's CPU temperature data */
	if ((ksp_temp = kstat_lookup(kc, I2C_PCF8591_NAME,
	    -1, I2C_KSTAT_CPUTEMP))
	    == NULL) {
#ifdef	DEBUG_TEMP
		log_printf("ks lookup for adc_temp failed", 0);
#endif
		return;
	}
	if (kstat_read(kc, ksp_temp, NULL) == -1) {
#ifdef	DEBUG_TEMP
		log_printf("ks read for adc_temp failed", 0);
#endif
		return;
	}
	pks_temp = (envctrl_temp_t *)ksp_temp->ks_data;
	pcf8591_ks_temp = *pks_temp;
	kstat_close(kc);
}	/*  do_pcf8591_kstat(.) */


void
gather_diaginfo(int flag)
{
	if (flag) {
		/* gather system environmental conditions. */
		/* obtain kstat info from gpio & temp. driver */
		do_pcf8574_kstat();
		do_pcf8591_kstat();
		explore_slot_occupants();	/* fill in some occupant info */
		prtdiag_devinfo();
		analyze_pcipci_siblings(rootnode);
	}

}	/* display_diaginfo(...) */

void
netract_disp_prom_version()
{
	/* Display Prom revision header */
	log_printf(dgettext(TEXT_DOMAIN, "System Board PROM revision:\n"), 0);
	log_printf("---------------------------\n", 0);
	do_promversion();

}	/* netract_disp_prom_version(.) */


/*
 * Get and print the PROM version.
 */
void
do_promversion(void)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);

	if (mc_promopen(O_RDONLY))  {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\nCannot open openprom device"), 0);
		return;
	}

	opp->oprom_size = MAXVALSIZE;
	if (ioctl(oprom_fd, OPROMGETVERSION, opp) < 0) {
		perror("\nOPROMGETVERSION ioctl failed");
		return;
	}
	log_printf("%s\n", opp->oprom_array, 0);

	if (close(oprom_fd) < 0) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\nclose error on %s"), OPENPROMDEV, 0);
		return;
	}
}	/* do_promversion() */

int
mc_promopen(int oflag)
{
	for (;;) {
		if ((oprom_fd = open(OPENPROMDEV, oflag)) < 0) {
			if (errno == EAGAIN) {
				(void) sleep(5);
				continue;
			}
			if (errno == ENXIO)
				return (-1);
			log_printf(dgettext(TEXT_DOMAIN,
			    "\ncannot open %s"), OPENPROMDEV, 0);
			return (1);
		} else
			return (0);
	}
}


/*
 * This will return -1 for status unknown, 0 for OK, and 1 for failed (scsi
 * hard errors)
 * swiped from envmon policies
 */
int
scsi_disk_status(int disk_number)
{
	kstat_ctl_t    *kc;
	kstat_t		*ksp_disk;
	kstat_named_t  *disk_data;

	int i;
	int nlist = 0;
	cfga_list_data_t *list_array = NULL;
	char *ap_ids[] = {"c0"};

	if ((kc = kstat_open()) == NULL) {
		log_printf(dgettext(TEXT_DOMAIN, "\nks open failed"), 0);
		return (-1);
	}

	if (disk_number == RMM_NUMBER) { /* RMM */
		if (config_list_ext(1, ap_ids, &list_array, &nlist,
			NULL, NULL, NULL, CFGA_FLAG_LIST_ALL) != CFGA_OK) {
			kstat_close(kc);
			return (-1);
		}
		for (i = 0; i < nlist; i++) {
			if (strstr(list_array[i].ap_phys_id, "rmt/0") != NULL) {
				/* Tape drive */
				if (list_array[i].ap_o_state ==
					CFGA_STAT_UNCONFIGURED) {
					kstat_close(kc);
					return (-1);
				}
				if ((ksp_disk = kstat_lookup(kc, STERR,
						st_instance, NULL)) == NULL) {
					kstat_close(kc);
					return (-1);
				}
				break;
			} else if (strstr(list_array[i].ap_phys_id,
						"dsk/c0t6d0") != NULL) {
				/* CD_ROM */
				if (list_array[i].ap_o_state ==
						CFGA_STAT_UNCONFIGURED) {
					kstat_close(kc);
					return (-1);
				}
				if ((ksp_disk = kstat_lookup(kc, SDERR,
					sd_instances[disk_number-1], NULL)) ==
									NULL) {
					kstat_close(kc);
					return (-1);
				}
				break;
			}
		}
	} else { /* Hard disk */
		if ((ksp_disk = kstat_lookup(kc, SDERR,
			sd_instances[disk_number-1], NULL)) == NULL) {
			kstat_close(kc);
			return (-1);
		}
	}

	if (kstat_read(kc, ksp_disk, NULL) == -1) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\nks read error for disk%d, drv inst%d"),
		    disk_number, sd_instances[disk_number-1], 0);
		kstat_close(kc);
		return (-1);
	}
	disk_data = KSTAT_NAMED_PTR(ksp_disk);
	/*
	 * if disk_data[].value is >0, we have a problem
	 */
	if (disk_data[1].value.ui32 == 0) {
		kstat_close(kc);
		return (0);
	} else {
		kstat_close(kc);
		return (1);
	}
}


void
prtdiag_devinfo(void)
{
	uint_t flag;
	/* lets get everything we can from kernel */
	flag = DINFOSUBTREE|DINFOPROP;
	rootnode = di_init("/", flag);
	if (rootnode == DI_NODE_NIL) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\nprtdiag_devinfo: di_init() failed"), 0);
		return;
	}
	(void) di_walk_node(rootnode, DI_WALK_CLDFIRST, NULL,
	    dump_devs);
}


/*
 * gather information about this node, returns appropriate code.
 * specific information we seek are driver names, instances
 * we will initialize some globals depending on what we find
 * from the kernel device tree info and may be private data
 * if required
 */
/*ARGSUSED1*/
int
dump_devs(di_node_t node, void *arg)
{
	char *driver_name;

	driver_name = di_driver_name(node);
	/* we will initialize our globals here */
	if ((di_instance(node) >= 0) &&
	    (driver_name != NULL) &&
	    (!(di_state(node) & DI_DRIVER_DETACHED))) {
		if (strcmp(driver_name, "pcf8574") == 0) {
			gpio_instances[gpio_count] = di_instance(node);
			gpio_count++;
		} else if (strcmp(driver_name, "sd") == 0) {
			sd_instances[sd_count] =  di_instance(node);
			sd_count++;
		} else if (strcmp(driver_name, "st") == 0) {
			st_instance = di_instance(node);
		}
	}

	if (strcmp(di_node_name(node), "pseudo") == 0)
		return (DI_WALK_PRUNECHILD);
	else
		return (DI_WALK_CONTINUE);
}



/*
 * Returns 0 if error , 1 otherwise
 */
int
dump_prop_list(char *name, di_node_t node, di_prop_t (*nxtprop)())
{
	int prop_len, i, k, max_slots_minus_cpu, n;
	uchar_t *prop_data;
	char	*p;
	char   *temp_s;
	di_prop_t prop, next;
	int ret_value = 0;

	max_slots_minus_cpu = scsb_ks_topo.max_units[SLOT]-1;

	if ((next = nxtprop(node, DI_PROP_NIL)) == DI_PROP_NIL)
		return (0);
	while (next != DI_PROP_NIL) {
		int maybe_str = 1, npossible_strs = 0;
		prop = next;
		next = nxtprop(node, prop);
		/*
		 * get prop length and value:
		 * private interface--always success
		 */
		prop_len = di_prop_rawdata(prop, &prop_data);
		if (di_prop_type(prop) == DDI_PROP_UNDEF_IT) {
			continue;
		}

		if (prop_len == 0)  {
			continue;
		}
		if (prop_data[prop_len - 1] != '\0') {
			maybe_str = 0;
		} else {
			/*
			 * Every character must be a string character or a \0,
			 * and there must not be two \0's in a row.
			 */
			for (i = 0; i < prop_len; i++) {
				if (prop_data[i] == '\0') {
					npossible_strs++;
				} else if (!isascii(prop_data[i]) ||
				    iscntrl(prop_data[i])) {
					maybe_str = 0;
					break;
				}

				if ((i > 0) && (prop_data[i] == '\0') &&
				    (prop_data[i - 1] == '\0')) {
					maybe_str = 0;
					break;
				}
			}
		}

		if (maybe_str) {
			p = (char *)prop_data;
			for (i = 0; i < npossible_strs - 1; i++) {
				if ((strcmp(name, SYSSOFT_PROP) == 0) &&
				    (strcmp(di_prop_name(prop),
				    HSC_PROP_NAME) == 0)) {
					temp_s = p;
					temp_s += strlen(temp_s) + 1;
				}
				p += strlen(p) + 1;
			}

			if ((strcmp(name, SYSSOFT_PROP) == 0) &&
			    (strcmp(di_prop_name(prop), HSC_PROP_NAME) == 0)) {
				temp_s = temp_s - prop_len+2;
				for (k = 0, n = 0; k < prop_len; k++) {
					if (temp_s[k] == 0) {
						n++;
					}
				}
				if (n % 4) {
					log_printf(dgettext(TEXT_DOMAIN,
					    "\nbad slot-table(%d)\n"), n);
					slot_table_not_found = 0;
					return (ret_value);
				}
				slot_table_size = n / 4;
				/*
				 * NOTE : We save slot table info in order
				 */
				for (k = 0; k < slot_table_size; k++) {
					char *nexus, *pcidev, *phys_slotname;
					char *ga;
					/*
					 * Pick off pointer to nexus
					 * path or PROM handle
					 */
					nexus = temp_s;
					while (*temp_s != NULL)
						temp_s++;
					temp_s++;

					/*
					 * Pick off pointer to the
					 * pci device number
					 */
					pcidev = temp_s;
					while (*temp_s != NULL)
						temp_s++;
					temp_s++;

					/* Pick off physical slot no */
					phys_slotname = temp_s;
					while (*temp_s != NULL)
						temp_s++;
					temp_s++;

					/*
					 * Pick off GA bits which
					 * we dont use for now.
					 */
					ga = temp_s;
					while (*temp_s != NULL)
						temp_s++;
					temp_s++;

					hotswap_slot_table[k].pslotnum
					    = atoi(phys_slotname);
					hotswap_slot_table[k].ga = atoi(ga);
					hotswap_slot_table[k].pci_devno
					    = atoi(pcidev);
					strcpy(hotswap_slot_table[k].nexus,
					    nexus);
				} /* for (k = 0; k < slot_table_size; k++) */

				ret_value = 1;
			} else /* (strcmp(name, SYSSOFT_PROP) */
				slot_table_not_found = 1;

			/*
			 * now we want to save off the info
			 * we would use later
			 */
			if ((strcmp(name, DRV_PROP) == 0) &&
			    (strcmp(di_prop_name(prop), HSC_MODE) == 0)) {
				hotswap_mode = p;
				ret_value = 1;
			} else if ((strcmp(name, DRV_PROP) == 0) &&
			    (strcmp(di_prop_name(prop), HSC_MODE) != 0)) {
				/* save it in order in the right index */
				slot_auto_config[max_slots_minus_cpu] = p;
				max_slots_minus_cpu--;
				ret_value = 1;
			}

		} else {
			for (i = 0; i < prop_len; ++i)  {
#if	0
				unsigned char byte;
				byte = (unsigned char)prop_data[i];
				log_printf("%2.2x", byte, 0);
#endif
			}
		}
	}
	return (ret_value);
}


void
display_mc_prtdiag_info()
{
	int i, index;
	int s_index, i1;
	int tg_cpu_index = 0;
	char *mcfru_type, *status, *mc_ok_led, *mc_nok_led;
	char *misc_info, *health, *board_type;

	log_printf("===============================", 0);
	log_printf(dgettext(TEXT_DOMAIN,
	    " FRU Information ================================\n"), 0);
	log_printf(dgettext(TEXT_DOMAIN,
	    "FRU         FRU    FRU      Green    Amber"), 0);
	log_printf(dgettext(TEXT_DOMAIN, "    Miscellaneous\n"), 0);
	log_printf(dgettext(TEXT_DOMAIN,
	    "Type        Unit#  Present  LED      LED"), 0);
	log_printf(dgettext(TEXT_DOMAIN, "      Information\n"), 0);

	log_printf("----------  -----  -------  -----    -----", 0);
	log_printf("    ----------------------------------\n", 0);

	if (scsb_ks_topo.mid_plane.fru_id == SCTRL_MPID_HALF)
		misc_info = "Netra ct800";
	else {
		misc_info = "Netra ct400";
	}
	mcfru_type = prtdiag_fru_types[MIDPLANE];
	switch (scsb_ks_topo.mid_plane.fru_status) {
		case FRU_PRESENT:
			status = YES;
			break;
		case FRU_NOT_PRESENT:
			status = NO;
			break;
		case FRU_NOT_AVAILABLE:
			status = NA; break;
		default:
			status = NA; break;
		}
	mc_ok_led = "   ";
	mc_nok_led = "   ";

	log_printf(dgettext(TEXT_DOMAIN,
	    "%10s   %-5d  %-7s %-5s    %-5s   %s\n"),
	    mcfru_type, scsb_ks_topo.mid_plane.fru_unit,
	    status, mc_ok_led, mc_nok_led,
	    misc_info, 0);
	log_printf(dgettext(TEXT_DOMAIN, "%46s%s\n"), BLANK, PROPS, 0);
	log_printf(dgettext(TEXT_DOMAIN, "%49sVersion=%d\n"), BLANK,
	    scsb_ks_topo.mid_plane.fru_version, 0);
	log_printf(dgettext(TEXT_DOMAIN, "%49sMaximum Slots=%d\n"), BLANK,
	    scsb_ks_topo.max_units[SLOT], 0);

	/* SCB & SSB */
	mcfru_type = prtdiag_fru_types[SCB];
	for (i = 0; i < scsb_ks_topo.max_units[SCB]; ++i) {
		misc_info = "System Controller Board";
		if (version_p15_and_p20) {
			mc_ok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.blink_leds[1]
			    & 0xff), SCB_OK_BIT) ? BLINK :
			    (BIT_TEST((scsb_ks_leddata.leds.p15.ok_leds[1]
			    & 0xff), SCB_OK_BIT) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.nok_leds[1]
			    & 0xff), SCB_OK_BIT) ? ON:OFF;
		} else {
			/*
			 * support for 1.0 systems -
			 * Hack! - should use tables ?
			 */
			mc_ok_led =
			    (BIT_TEST((scsb_ks_leddata.leds.p10.ok_leds[2]
			    & 0xff), 0) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p10.nok_leds[2]
			    & 0xff), 0) ? ON:OFF;
		}
		switch (scsb_ks_topo.mct_scb[i].fru_status) {
			case FRU_PRESENT:
				status = YES;
				break;
			case FRU_NOT_PRESENT:
				status = NO;
				break;
			case FRU_NOT_AVAILABLE:
				status = NA;
				break;
			default:
				status = NA;
				break;
		}
		log_printf(dgettext(TEXT_DOMAIN,
		    "%10s   %-5d  %-7s %-5s    %-5s   %s\n"),
		    mcfru_type, scsb_ks_topo.mct_scb[i].fru_unit,
		    status, mc_ok_led, mc_nok_led, misc_info, 0);
		log_printf(dgettext(TEXT_DOMAIN, "%46s%s\n"), BLANK, PROPS, 0);
		log_printf(dgettext(TEXT_DOMAIN, "%49sVersion=%d\n"), BLANK,
		    scsb_ks_topo.mct_scb[0].fru_version, 0);
		if (fail_drv_prop == 1)
			log_printf(dgettext(TEXT_DOMAIN,
			    "%49s%s=%s\n"), BLANK, HSC_MODE,
			    hotswap_mode, 0);
	} /* for */

	mcfru_type = prtdiag_fru_types[SSB];
	for (i = 0; i < scsb_ks_topo.max_units[SSB]; ++i) {
		misc_info = "System Status Panel";
		switch (scsb_ks_topo.mct_ssb[i].fru_status) {
			case FRU_PRESENT:
				status = YES;
				break;
			case FRU_NOT_PRESENT:
				status = NO;
				break;
			case FRU_NOT_AVAILABLE:
				status = NA;
				break;
			default:
				status = NA;
				break;
		}
		log_printf(dgettext(TEXT_DOMAIN,
		    "%10s   %-5d  %-7s %-5s    %-5s   %s\n"),
		    mcfru_type, scsb_ks_topo.mct_ssb[i].fru_unit,
		    status, BLANK, BLANK, misc_info, 0);
	} /* for */

	/* Slots */
	for (i = 0; i < scsb_ks_topo.max_units[SLOT]; ++i) {
		if (montecarlo) {
			if (scsb_ks_topo.mct_slots[i].fru_unit == 1)
				mcfru_type = prtdiag_fru_types[1];
			else
				mcfru_type = prtdiag_fru_types[SLOT];
			/*
			 * Another way this could have been done is,
			 * to read the sub system id
			 * it is 0x6722 for Alarm Card
			 * but this id is only valid for the new ACs
			 * older ACs still have the same susbsystem
			 * id as most other Sun PCI cards
			 * We cannot completely rely on this.
			 * Also,it turns out that Sun OpenBoot does not
			 * always follow IEEE 1275 std, hence in a few
			 * systems, the "subsystem-id" published by the
			 * PROM could not be found
			 * We know the AC slot# if present on both MC&Tg
			 * Hence we check on both - now we are sure
			 * that we have found an AC
			 */
			if ((scsb_ks_topo.mct_slots[i].fru_unit == 8) &&
			    (alarm_card_present == 1))
				board_type = AC_CARD;
			else
				board_type = UK;
		} else {
			if (scsb_ks_topo.mct_slots[i].fru_unit == 3)
				mcfru_type = prtdiag_fru_types[1];
			else
				mcfru_type = prtdiag_fru_types[SLOT];
			/*
			 * Another way this could have been done is,
			 * to read the sub system id
			 * it is 0x6722 for Alarm Card
			 * but this id is only valid for the new ACs
			 * older ACs still have the same susbsystem
			 * id as most other Sun PCI cards
			 * We cannot completely rely on this.
			 * Also,it turns out that Sun OpenBoot does not
			 * always follow IEEE 1275 std, hence in a few
			 * systems, the "subsystem-id" published by the
			 * PROM could not be found
			 * We know the AC slot# if present on both MC&Tg
			 * Hence we check on both - now we are sure
			 * that we have found an AC
			 */
			if ((scsb_ks_topo.mct_slots[i].fru_unit == 1) &&
			    (alarm_card_present == 1))
				board_type = AC_CARD;
			else
				board_type = UK;
		}
		if (version_p15_and_p20) {
			mc_ok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.blink_leds[0]
			    & 0xff), i) ? BLINK :
			    (BIT_TEST((scsb_ks_leddata.leds.p15.ok_leds[0]
			    & 0xff), i) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.nok_leds[0]
			    & 0xff), i) ? ON:OFF;
		} else {
			/*
			 * support for 1.0 systems -
			 * Hack! - should use tables ?
			 */
			if (scsb_ks_topo.mct_slots[i].fru_unit == 7) {
				mc_ok_led =
				    BIT_TEST(
				    (scsb_ks_leddata.leds.p10.blink_leds[1]
				    & 0xff), 0) ? BLINK :
				    (BIT_TEST(
				    (scsb_ks_leddata.leds.p10.ok_leds[1]
				    & 0xff), 0) ? ON:OFF);
				mc_nok_led =
				    BIT_TEST(
				    (scsb_ks_leddata.leds.p10.nok_leds[1]
				    & 0xff), 0) ? ON:OFF;
			} else  if (scsb_ks_topo.mct_slots[i].fru_unit == 8) {
				mc_ok_led =
				    BIT_TEST(
				    (scsb_ks_leddata.leds.p10.blink_leds[1]
				    & 0xff), 1) ? BLINK :
				    (BIT_TEST(
				    (scsb_ks_leddata.leds.p10.ok_leds[1]
				    & 0xff), 1) ? ON:OFF);
				mc_nok_led =
				    BIT_TEST(
				    (scsb_ks_leddata.leds.p10.nok_leds[1]
				    & 0xff), 1) ? ON:OFF;
			} else {
				/*
				 * for all other slots offset,
				 * index are the same
				 */
				mc_ok_led =
				    BIT_TEST(
				    (scsb_ks_leddata.leds.p10.blink_leds[0]
				    & 0xff), i) ? BLINK :
				    (BIT_TEST(
				    (scsb_ks_leddata.leds.p10.ok_leds[0]
				    & 0xff), i) ? ON:OFF);
				mc_nok_led =
				    BIT_TEST(
				    (scsb_ks_leddata.leds.p10.nok_leds[0]
				    & 0xff), i) ? ON:OFF;
			}

		} /* else if (!version_p15_and_p20) */

		switch (scsb_ks_topo.mct_slots[i].fru_status) {
			case FRU_PRESENT:
				status = YES;
				break;
			case FRU_NOT_PRESENT:
				status = NO;
				break;
			case FRU_NOT_AVAILABLE:
				status = NA;
				break;
			default:
				status = NA;
				break;
		}

		index = (int)scsb_ks_topo.mct_slots[i].fru_type;
		if (montecarlo) {
			if (scsb_ks_topo.mct_slots[i].fru_unit == 1) {
				/* cpu slot */
				log_printf(dgettext(TEXT_DOMAIN,
				    "%10s   %-5d  %-7s %-5s    "),
				    mcfru_type,
				    scsb_ks_topo.mct_slots[i].fru_unit,
				    status, mc_ok_led, mc_nok_led, 0);
				log_printf(dgettext(TEXT_DOMAIN, "%-5s   %s\n"),
				    mc_nok_led,
				    slot_occupants[index], 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49stemperature(celsius):%d\n"),
				    BLANK,
				    pcf8591_ks_temp.value, 0);
#ifdef	NEVER
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49sminimum temperature:%d\n"),
				    BLANK,
				    pcf8591_ks_temp.min, 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49swarning temp. threshold:%d\n"),
				    BLANK,
				    pcf8591_ks_temp.warning_threshold, 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49sshutdown temp.threshold:%d\n"),
				    BLANK,
				    pcf8591_ks_temp.shutdown_threshold, 0);
#endif	/* NEVER */
			} else if ((scsb_ks_topo.mct_slots[i].fru_unit == 2) &&
			    (cpu_ftm_present == 1)) {
				/* CFTM slot */
				/*
				 * The CFTM can only be present in Slot 2
				 * for Netract-800, for Netract-400 the FTM
				 * is not sitted in a Slot. Hence, this is
				 * another special case and we need to handle
				 * this differently than other slots
				 */
				log_printf(dgettext(TEXT_DOMAIN,
				    "%10s   %-5d  %-7s %-5s    "),
				    mcfru_type,
				    scsb_ks_topo.mct_slots[i].fru_unit,
				    status, mc_ok_led, mc_nok_led, 0);
				log_printf(dgettext(TEXT_DOMAIN, "%-5s   %s\n"),
				    mc_nok_led,
				    CPU_FTM, 0);
			} else {
				if (fail_drv_prop == 1) {
					log_printf(dgettext(TEXT_DOMAIN,
					    "%10s   %-5d  %-7s %-5s    "),
					    mcfru_type,
					    scsb_ks_topo.mct_slots[i].fru_unit,
					    status, mc_ok_led, 0);
					log_printf(dgettext(TEXT_DOMAIN,
					    "%-5s   %s\n"),
					    mc_nok_led,
					    slot_occupants[index], 0);
					log_printf(dgettext(TEXT_DOMAIN,
					    "%46s%s\n"), BLANK,
					    PROPS, 0);
					log_printf(dgettext(TEXT_DOMAIN,
					    "%49sauto-config=%s\n"),
					    BLANK,
					    slot_auto_config[i], 0);
				} else {
				log_printf(dgettext(TEXT_DOMAIN,
				    "%10s   %-5d  %-7s %-5s    "),
				    mcfru_type,
				    scsb_ks_topo.mct_slots[i].fru_unit,
				    status, mc_ok_led, 0);
				log_printf(dgettext(TEXT_DOMAIN, "%-5s   %s\n"),
				    mc_nok_led,
				    slot_occupants[index], 0);
				}
			}
		} else { /* tonga */
			if (scsb_ks_topo.mct_slots[i].fru_unit == 3) {
				/* cpu slot */
				log_printf(dgettext(TEXT_DOMAIN,
				    "%10s   %-5d  %-7s %-5s    "),
				    mcfru_type,
				    scsb_ks_topo.mct_slots[i].fru_unit,
				    status, mc_ok_led, 0);
				log_printf(dgettext(TEXT_DOMAIN, "%-5s   %s\n"),
				    mc_nok_led,
				    slot_occupants[index], 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49stemperature(celsius):%d\n"),
				    BLANK,
				    pcf8591_ks_temp.value, 0);
#ifdef	NEVER

				log_printf(dgettext(TEXT_DOMAIN,
				    "%49sminimum temperature:%d\n"),
				    BLANK,
				    pcf8591_ks_temp.min, 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49swarning temp. threshold:%d\n"),
				    BLANK,
				    pcf8591_ks_temp.warning_threshold, 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49sshutdown temp. threshold:%d\n"),
				    BLANK,
				    pcf8591_ks_temp.shutdown_threshold, 0);
#endif	/* NEVER */
			} else {
				if (fail_drv_prop == 1) {
					log_printf(dgettext(TEXT_DOMAIN,
					    "%10s   %-5d  %-7s %-5s    "),
					    mcfru_type,
					    scsb_ks_topo.mct_slots[i].fru_unit,
					    status, mc_ok_led, 0);
					log_printf(dgettext(TEXT_DOMAIN,
					    "%-5s   %s\n"),
					    mc_nok_led,
					    slot_occupants[index], 0);

					log_printf(dgettext(TEXT_DOMAIN,
					    "%46s%s\n"), BLANK, PROPS, 0);
					log_printf(dgettext(TEXT_DOMAIN,
					    "%49sauto-config=%s\n"),
					    BLANK,
					    slot_auto_config[tg_cpu_index+1],
					    0);
					if (scsb_ks_topo.mct_slots[i].fru_unit
					    != 3)
						tg_cpu_index++;
				} else {
				log_printf(dgettext(TEXT_DOMAIN,
				    "%10s   %-5d  %-7s %-5s    "),
				    mcfru_type,
				    scsb_ks_topo.mct_slots[i].fru_unit,
				    status, mc_ok_led, 0);
				log_printf(dgettext(TEXT_DOMAIN, "%-5s   %s\n"),
				    mc_nok_led,
				    slot_occupants[index], 0);
				}
			}
		}
		/* we first match the correct slot numbers */
		for (s_index = 0; s_index < slot_table_size; s_index++) {
			if (slot_table_not_found == 1) {
			/* use prom table */
			if (scsb_ks_topo.mct_slots[i].fru_unit ==
			    prom_slot_table[s_index].pslotnum) {
				/*
				 * search for the addr/pci num
				 * in all slot info structs
				 */
				for (i1 = 0; i1 < slot_index;
				    i1++) {
			if (prom_slot_table[s_index].pci_devno ==
			    mc_slots_data.mc_slot_info[i1].slot_addr) {
					int nd;
					log_printf(dgettext(TEXT_DOMAIN,
					    "%46s%s%s\n"), BLANK,
					    BOARDTYPE, board_type, 0);
					log_printf(dgettext(TEXT_DOMAIN,
					    "%46s%s\n"), BLANK, DEVS, 0);
					log_printf(dgettext(TEXT_DOMAIN,
					    "%49s%s\n"), BLANK,
					    PCI_ROOT_AP, 0);
			for (nd = 0;
			    nd < mc_slots_data.mc_slot_info[i1].number_devs;
				    nd++) {
			log_printf(dgettext(TEXT_DOMAIN, "%52s%s\n"), BLANK,
			    mc_slots_data.mc_slot_info[i1].devs_info[nd],
			    0);
						} /* for */

					} /* if */

				} /* for(i1) */

			} /* if */

		} else {
			/* use solaris lot table */
			if (fail_syssoft_prop == 1) {
				if (scsb_ks_topo.mct_slots[i].fru_unit ==
				hotswap_slot_table[s_index].pslotnum) {
					/*
					 * search for the addr/pci
					 * num in all slot info structs
					 */
					for (i1 = 0; i1 < slot_index; i1++) {
				if (hotswap_slot_table[s_index].pci_devno ==
				    mc_slots_data.mc_slot_info[i1].slot_addr) {
					int nd;
			for (nd = 0;
			    nd < mc_slots_data.mc_slot_info[i1].number_devs;
			    nd++) {
			log_printf(dgettext(TEXT_DOMAIN, "%49s%s\n"), BLANK,
			    mc_slots_data.mc_slot_info[i1].devs_info[nd],
			    0);
							}
						} /* if */

					} /* for(i1) */

				} /* if */

			} /* (fail_syssoft_prop == 1) */

			}  /* (slot_table_not_found == 1) */

		} /* for(s_index) */

	}	/* for */
	mcfru_type = "PDU";
	misc_info = "Power Distribution Unit";
	for (i = 0; i < scsb_ks_topo.max_units[PDU]; ++i) {
		if (version_p15_and_p20) {
			mc_ok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.blink_leds[1]
			    & 0xff), PDU1_OK_BIT+i*2) ? BLINK :
			    (BIT_TEST((scsb_ks_leddata.leds.p15.ok_leds[1]
			    & 0xff), PDU1_OK_BIT+i*2) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.nok_leds[1]
			    & 0xff), PDU1_OK_BIT+i*2) ? ON:OFF;
		}
		switch (scsb_ks_topo.mct_pdu[i].fru_status) {
			case FRU_PRESENT:
				status = YES;
				break;
			case FRU_NOT_PRESENT:
				status = NO;
				break;
			case FRU_NOT_AVAILABLE:
				status = NA;
				break;
			default:
				status = NA;
				break;
		}
		if (version_p15_and_p20) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "%-10s    %-5d  %-7s %-5s    %-5s   %s\n"),
			    mcfru_type, scsb_ks_topo.mct_pdu[i].fru_unit,
			    status, mc_ok_led, mc_nok_led, misc_info, 0);
		} else {
			log_printf(dgettext(TEXT_DOMAIN,
			    "%-10s    %-5d  %-7s%18s%s\n"),
			    mcfru_type, scsb_ks_topo.mct_pdu[i].fru_unit,
			    status, BLANK, misc_info, 0);
		}
	} /* for */

	/* PS */
	mcfru_type = prtdiag_fru_types[PS];
	misc_info = "Power Supply Unit";
	for (i = 0; i < scsb_ks_topo.max_units[PS]; ++i) {
		if (version_p15_and_p20) {
			mc_ok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.blink_leds[2]
			    & 0xff), PS1_OK_BIT+i) ? BLINK :
			    (BIT_TEST((scsb_ks_leddata.leds.p15.ok_leds[2]
			    & 0xff), PS1_OK_BIT+i) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.nok_leds[2]
			    & 0xff), PS1_OK_BIT+i) ? ON:OFF;
		} else {
			/*
			 * support for 1.0 systems -
			 * Hack! - should use tables ?
			 */
			mc_ok_led =
			    (BIT_TEST((scsb_ks_leddata.leds.p10.ok_leds[2]
			    & 0xff), 1+i) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p10.nok_leds[2]
			    & 0xff), 1+i) ? ON:OFF;
		}
		switch (scsb_ks_topo.mct_ps[i].fru_status) {
			case FRU_PRESENT:
				status = YES;
				break;
			case FRU_NOT_PRESENT:
				status = NO;
				break;
			case FRU_NOT_AVAILABLE:
				status = NA;
				break;
			default:
				status = NA;
				break;
		}
		log_printf(dgettext(TEXT_DOMAIN,
		    "%10s   %-5d  %-7s %-5s    %-5s   %s\n"),
		    mcfru_type, scsb_ks_topo.mct_ps[i].fru_unit,
		    status, mc_ok_led, mc_nok_led,
		    misc_info, 0);
		if (scsb_ks_topo.mct_ps[i].fru_status == FRU_PRESENT) {
			if (scsb_ks_topo.mct_ps[i].fru_unit == 1) {
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49scondition:%s\n"), BLANK,
				    ((pcf8574_ks_ps1.ps_ok)? NOK:OK), 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49stemperature:%s\n"), BLANK,
				    ((pcf8574_ks_ps1.temp_ok)? NOK:OK), 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49sps fan:%s\n"), BLANK,
				    ((pcf8574_ks_ps1.psfan_ok)? NOK:OK), 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49ssupply:%s\n"), BLANK,
				    ((pcf8574_ks_ps1.on_state)? OFF:ON), 0);
			} else {
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49scondition:%s\n"), BLANK,
				    ((pcf8574_ks_ps2.ps_ok)? NOK:OK), 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49stemperature:%s\n"), BLANK,
				    ((pcf8574_ks_ps2.temp_ok)? NOK:OK), 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49sps fan:%s\n"), BLANK,
				    ((pcf8574_ks_ps2.psfan_ok)? NOK:OK), 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49ssupply:%s\n"), BLANK,
				    ((pcf8574_ks_ps2.on_state)? OFF:ON), 0);
			} /* if */
		}

	} /* for */

	/* Fan tray */
	mcfru_type = prtdiag_fru_types[FAN];
	misc_info = "Fan Tray";
	for (i = 0; i < scsb_ks_topo.max_units[FAN]; ++i) {
		if (version_p15_and_p20) {
			mc_ok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.blink_leds[2]
			    & 0xff), FAN1_OK_BIT+i) ? BLINK :
			    (BIT_TEST((scsb_ks_leddata.leds.p15.ok_leds[2]
			    & 0xff), FAN1_OK_BIT+i) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.nok_leds[2]
			    & 0xff), FAN1_OK_BIT+i) ? ON:OFF;
		} else {
			/*
			 * support for 1.0 systems -
			 * Hack! - should use tables ?
			 */
			mc_ok_led =
			    (BIT_TEST((scsb_ks_leddata.leds.p10.ok_leds[3]
			    & 0xff), 3+i) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p10.nok_leds[3]
			    & 0xff), 3+i) ? ON:OFF;
		}
		switch (scsb_ks_topo.mct_fan[i].fru_status) {
			case FRU_PRESENT:
				status = YES;
				break;
			case FRU_NOT_PRESENT:
				status = NO;
				break;
			case FRU_NOT_AVAILABLE:
				status = NA;
				break;
			default:
				status = NA;
				break;
		}
		log_printf(dgettext(TEXT_DOMAIN,
		    "%10s   %-5d  %-7s %-5s    %-5s   %s\n"),
		    mcfru_type, scsb_ks_topo.mct_fan[i].fru_unit,
		    status, mc_ok_led, mc_nok_led,
		    misc_info, 0);
		if (scsb_ks_topo.mct_fan[i].fru_status == FRU_PRESENT) {
			if (scsb_ks_topo.mct_fan[i].fru_unit == 1) {
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49scondition:%s\n"), BLANK,
				    ((pcf8574_ks_fant1.fan_ok)? OK:NOK), 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49sfan speed:%s\n"), BLANK,
				    ((pcf8574_ks_fant1.fanspeed)? HI:LO), 0);
			} else {
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49scondition:%s\n"), BLANK,
				    ((pcf8574_ks_fant2.fan_ok)? OK:NOK), 0);
				log_printf(dgettext(TEXT_DOMAIN,
				    "%49sfan speed:%s\n"), BLANK,
				    ((pcf8574_ks_fant2.fanspeed)? HI:LO), 0);
			}
		}

	} /* for */

	/* DISKS */
	for (i = 0; i < scsb_ks_topo.max_units[DISK]; ++i) {
		if (scsb_ks_topo.mct_disk[i].fru_unit != RMM_NUMBER)
			mcfru_type = prtdiag_fru_types[DISK];
		else
			mcfru_type = "RMM        ";
		switch (scsb_ks_topo.mct_disk[i].fru_status) {
			case FRU_PRESENT:
				status = YES;
				break;
			case FRU_NOT_PRESENT:
				status = NO;
				break;
			case FRU_NOT_AVAILABLE:
				status = NA;
				break;
			default:
				status = NA;
				break;
		}
		if (version_p15_and_p20) {
			mc_ok_led =
			    BIT_TEST((scsb_ks_leddata.scb_led_regs[8]
			    & 0xff), DISK1_OK_BIT+i) ? BLINK :
			    (BIT_TEST((scsb_ks_leddata.leds.p15.ok_leds[2]
			    & 0xff), DISK1_OK_BIT+i) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p15.nok_leds[2]
			    & 0xff), DISK1_OK_BIT+i) ? ON:OFF;
		} else {
			/*
			 * support for 1.0 systems -
			 * Hack! - should use tables ?
			 */
			mc_ok_led =
			    (BIT_TEST((scsb_ks_leddata.leds.p10.ok_leds[2]
			    & 0xff), DISK1_OK_BIT+i) ? ON:OFF);
			mc_nok_led =
			    BIT_TEST((scsb_ks_leddata.leds.p10.nok_leds[2]
			    & 0xff), DISK1_OK_BIT+i) ? ON:OFF;
		}
		/* print everything except condition */
		if (scsb_ks_topo.mct_disk[i].fru_unit != RMM_NUMBER) {
			misc_info = "Hard Disk Drive";
			log_printf(dgettext(TEXT_DOMAIN,
			    "%10s   %-5d  %-7s %-5s    %-5s   %s\n"),
			    mcfru_type, scsb_ks_topo.mct_disk[i].fru_unit-1,
			    status, mc_ok_led, mc_nok_led, misc_info, 0);
		} else {
			misc_info = "Removable Media Module";
			log_printf(dgettext(TEXT_DOMAIN,
			    "%10s   %5s  %-7s %-5s    %-5s   %s\n"),
			    mcfru_type, BLANK,
			    status, mc_ok_led, mc_nok_led, misc_info, 0);
		}

		/* find out fru health from the SCSI drivers */
		if (scsb_ks_topo.mct_disk[i].fru_status == FRU_PRESENT) {
			switch (
			    scsi_disk_status(
			    scsb_ks_topo.mct_disk[i].fru_unit)) {
				case 0:
					health = OK;
					break;
				case 1:
					health = NOK;
					break;
				case -1:
					health = UK;
					break;
				default:
					health = NA;
					break;
			}
			log_printf(dgettext(TEXT_DOMAIN,
			    "%49scondition:%s\n"), BLANK, health, 0);
		}

	}	/* for */

	log_printf(dgettext(TEXT_DOMAIN, "\n"), 0);

}	/*  display_mc_prtdiag_info() */


void
analyze_pcipci_siblings(di_node_t node)
{
	di_node_t lc_node;
	/* we will find all the dev info for slots first */
	lc_node = di_drv_first_node("pci_pci", node);
	lc_node = di_child_node(lc_node);
	/* we are at "pci" node now */
	do  {
		if (di_walk_node(lc_node, DI_WALK_CLDFIRST,
		    NULL, analyze_nodes) != 0) {
			return;
		}
	} while ((lc_node = di_sibling_node(lc_node)) != DI_NODE_NIL);

	/* now we wll gather info on sysctrl */
	lc_node = di_drv_first_node(SCSB_DEV, node);
	if (lc_node != DI_NODE_NIL)
		analyze_nodes(lc_node, "sysctrl");
}	/* analyze_pcipci_siblings(.) */


int
analyze_nodes(di_node_t l_node, void *arg)
{
	char *temp;
	char *name, *pname;
	di_node_t parent;
	/*
	 *  we will figure out whether the parent node is "pci" type
	 *  we will save info only in this case as we only want to
	 * print out the nodes under AP and not others
	 */
	parent = di_parent_node(l_node);
	pname =  di_node_name(parent);
	name = di_node_name(l_node);
	/*
	 * if this is PCI bridge, we know that this is the AP for slots
	 * hence, we will save off the address(to convert to slot mapping)
	 * later, and also we will start saving off slot info struct for
	 * reporting later
	 * we will save the immediate childs of this bridge only
	 */
	if (strcmp(name, "pci") == 0) {
		num_devs = 0;
		if ((temp = di_bus_addr(l_node)) != NULL) {
			mc_slots_data.mc_slot_info[slot_index].slot_addr
			    = (int)strtol(temp, (char **)NULL, 16);
		}
		slot_index++;
	} else {
		if (strcmp(pname, "pci") == 0) {
	if ((mc_slots_data.mc_slot_info[slot_index-1].devs_info[num_devs])
	    != NULL) {
	(void) strcat(
	    mc_slots_data.mc_slot_info[slot_index-1].devs_info[num_devs],
	    name);
			} else {
	(void) strcpy(
	    mc_slots_data.mc_slot_info[slot_index-1].devs_info[num_devs],
	    name);
			} /* if ((mc_slots_data.mc_slot_inf */

			num_devs++;
			mc_slots_data.mc_slot_info[slot_index-1].number_devs
			    = num_devs;
		} /* if parent is pci */

	} /* if node is pci */
	if (arg != NULL) {
		if (strcmp((char *)arg, "sysctrl") == 0) {
			if (dump_prop_list("System", l_node,
			    di_prop_sys_next)) {
				(void) dump_prop_list(NULL, l_node,
				    di_prop_global_next);
			} else {
				fail_syssoft_prop =
				    dump_prop_list(SYSSOFT_PROP,
				    l_node, di_prop_global_next);
			}

			fail_drv_prop =
			    dump_prop_list(DRV_PROP, l_node,
			    di_prop_drv_next);
			/*
			 * (void) dump_prop_list("Hardware",
			 *   l_node, di_prop_hw_next);
			 */
			/*  dump_priv_data(l_node); */
		}
	}

	return	(0);

}	/* analyze_nodes(..) */



/*
 * To get the slot information,
 * The OBP defines the 'slot-table' property. But the OS
 * can override it with 'hsc-slot-map' property
 * through the .conf file.
 * Since the formats are different, 2 different property names
 * are chosen.
 * The OBP property format is
 * <phandle>,<pci-devno>,<phys-slotno>,<ga-bits>
 * The OS property format is (ga-bits is not used however)
 * <busnexus-path>,<pci-devno>,<phys-slotno>,<ga-bits>
 * returns 0 on error, 1 otherwise
 */
int
extract_slot_table_from_obp()
{
	if (mc_promopen(O_RDONLY))  {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\ncannot open openprom device"), 0);
		return (0);
	}

	if (mc_next(0) == 0)
		return (0);
	mc_walk(mc_next(0));

	if (close(oprom_fd) < 0) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\nclose error on %s"), OPENPROMDEV, 0);
		return (0);
	}

	return (1);

}	/* extract_slot_table_from_obp() */


int
mc_next(int id)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);

	bzero(oppbuf.buf, BUFSIZE);
	opp->oprom_size = MAXVALSIZE;
	opp->oprom_node = id;
	if (ioctl(oprom_fd, OPROMNEXT, opp) < 0) {
		log_printf(dgettext(TEXT_DOMAIN, "\nError OPROMNEXT"), 0);
		return (0);
	}
	return (opp->oprom_node);

}	/* mc_next(.) */


void
mc_walk(int id)
{
	int curnode;
	mc_dump_node(id);
	if (curnode = mc_child(id))
		mc_walk(curnode);
	if (curnode = mc_next(id))
		mc_walk(curnode);
}	/*  mc_walk(.) */

int
mc_child(int id)
{
	Oppbuf  oppbuf;
	struct openpromio *opp = &(oppbuf.opp);

	bzero(oppbuf.buf, BUFSIZE);
	opp->oprom_size = MAXVALSIZE;
	opp->oprom_node = id;
	if (ioctl(oprom_fd, OPROMCHILD, opp) < 0) {
		perror("\nOPROMCHILD");
		exit(0);
	}
	return (opp->oprom_node);

}	/* mc_child(.) */


/*
 * Print all properties and values
 */
void
mc_dump_node(int id)
{
	int k;
	Oppbuf  oppbuf;
	hsc_prom_slot_table_t	*hpstp;
	struct openpromio *opp = &(oppbuf.opp);

	/* get first prop by asking for null string */
	bzero(oppbuf.buf, BUFSIZE);
	for (;;) {
		/*
		 * get next property name
		 */
		opp->oprom_size = MAXNAMESZ;

		if (ioctl(oprom_fd, OPROMNXTPROP, opp) < 0) {
			perror("\nOPROMNXTPROP");
			return;
		}
		if (opp->oprom_size == 0)
			break;
		if (strcmp(opp->oprom_array, "slot-table") == 0) {
			if (mc_getpropval(opp) || opp->oprom_size
			    == (uint_t)-1) {
				log_printf(dgettext(TEXT_DOMAIN,
				    "\ndata not available"), 0);
				return;
			} else {
				slot_table_size =
				    opp->oprom_size /
				    sizeof (hsc_prom_slot_table_t);
				hpstp =
				    (hsc_prom_slot_table_t *)opp->oprom_array;
				for (k = 0; k < slot_table_size; k++, hpstp++) {
					prom_slot_table[k].pslotnum =
					    hpstp->pslotnum;
					prom_slot_table[k].ga =
					    hpstp->ga;
					prom_slot_table[k].pci_devno =
					    hpstp->pci_devno;
					prom_slot_table[k].phandle =
					    hpstp->phandle;
				} /* for (k = 0; k < slot_table_size; k++) */

			}
		}
	}

}	/* mc_dump_node(.) */


int
mc_getpropval(struct openpromio *opp)
{
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(oprom_fd, OPROMGETPROP, opp) < 0) {
		log_printf(dgettext(TEXT_DOMAIN, "\nError OPROMGETPROP"), 0);
		return (1);
	}
	return (0);

}	/* mc_getpropval(.) */



/*
 * This function returns nothing.
 */
void
alarm_card_occupant()
{
	int		scsb_fd;
	scsb_ioc_rdwr_t	ioc_read;
	uint8_t		new_mode = 0;
	uint8_t		old_mode = 0;
	uchar_t		reg_index;

	if (NULL == scsb_node) {
		if (check_platform() == -1) {
			return;
		}
	}

	if (version_p15_and_p20 == 1)
		reg_index = 0xe9;	/* config status reg offset on SCB */
	else
		reg_index = 0xd7;	/* config status reg offset on SCB */

	if ((scsb_fd = open(scsb_node, O_RDONLY)) < 0)  {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\n%s open failed"), scsb_node, 0);
		return;
	}

	/* save off the old mode */
	if (scsb_mode(scsb_fd, GET, &old_mode) == 0)
		return;
	/* we put scsb in diag mode to read this specific ioctl */
	new_mode = ENVCTRL_DIAG_MODE;
	if (scsb_mode(scsb_fd, SET, &new_mode) == 0)
		return;
	/* now lets read the config register */
	if (scsb_ioc_reg_read(scsb_fd, reg_index, &ioc_read, 1) == 0)
		return;
	/* restore the original mode */
	if (scsb_mode(scsb_fd, SET, &old_mode) == 0)
		return;
	alarm_card_present = (BIT_TEST(ioc_read.ioc_rbuf[0]&0xff, 0) ? 1:0);

}	/* alarm_card_occupant() */


/*
 * This function changes the SCSB mode to the desired one
 * 1 on sucess, 0 otherwise
 */
int
scsb_mode(int fd, scsb_op_t sop, uint8_t *new_mode)
{
	struct strioctl sioc;

	if (sop == GET)
		sioc.ic_cmd = ENVC_IOC_GETMODE;
	else
		sioc.ic_cmd = ENVC_IOC_SETMODE;

	sioc.ic_timout = 0;
	sioc.ic_len = sizeof (uint8_t);
	sioc.ic_dp = (char *)new_mode;


	if (ioctl(fd, I_STR, &sioc) == -1) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\nscsb_mode():scsb ioctl() failed"), 0);
		return (0);
	}
	return (1);

}	/* scsb_mode(...) */


/*
 * 1 on success, 0 otherwise
 */
int
scsb_ioc_reg_read(int fd, uchar_t index, scsb_ioc_rdwr_t *ioc_rd, int num)
{
	struct strioctl		sioc;
	scsb_ioc_rdwr_t		*rdwrp;

	rdwrp = ioc_rd;
	sioc.ic_timout = 0;
	sioc.ic_len = sizeof (scsb_ioc_rdwr_t);
	sioc.ic_dp = (char *)rdwrp;
	/* setup read command before ioctl */
	sioc.ic_cmd = SCSBIOC_REG_READ;
	rdwrp->ioc_wlen = 0;
	rdwrp->ioc_rlen = num;
	rdwrp->ioc_regindex = index;
	if (ioctl(fd, I_STR, &sioc) == -1) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "scsb_ioc_reg_read(): scsb ioctl() failed\n"), 0);
		return (0);
	}
	return (1);

}	/* scsb_ioc_reg_read(....) */
