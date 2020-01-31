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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/intreg.h>
#include <sys/autoconf.h>
#include <sys/modctl.h>
#include <sys/spl.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/machsystm.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>		/* xt_one() */
#include <sys/membar.h>
#include <sys/vm.h>
#include <vm/seg_kmem.h>
#include <vm/hat_sfmmu.h>
#include <sys/promimpl.h>
#include <sys/prom_plat.h>
#include <sys/cpu_module.h>	/* flush_instr_mem() */
#include <sys/procset.h>
#include <sys/fhc.h>
#include <sys/ac.h>
#include <sys/environ.h>
#include <sys/jtag.h>
#include <sys/nexusdebug.h>
#include <sys/ac.h>
#include <sys/ddi_subrdefs.h>
#include <sys/eeprom.h>
#include <sys/sdt.h>
#include <sys/ddi_implfuncs.h>
#include <sys/ontrap.h>

#ifndef TRUE
#define	TRUE (1)
#endif
#ifndef FALSE
#define	FALSE (0)
#endif

/*
 * Function to register and deregister callbacks, for sunfire only.
 */
extern void plat_register_tod_fault(void (*func)(enum tod_fault_type));

/*
 * This table represents the FHC interrupt priorities.  They range from
 * 1-15, and have been modeled after the sun4d interrupts. The mondo
 * number anded with 0x7 is used to index into this table. This was
 * done to save table space.
 */
static int fhc_int_priorities[] = {
	PIL_15,			/* System interrupt priority */
	PIL_12,			/* zs interrupt priority */
	PIL_15,			/* TOD interrupt priority */
	PIL_15			/* Fan Fail priority */
};

static void fhc_tod_fault(enum tod_fault_type tod_bad);
static void fhc_cpu_shutdown_self(void);
static void os_completes_shutdown(void);

/*
 * The dont_calibrate variable is meant to be set to one in /etc/system
 * or by boot -h so that the calibration tables are not used. This
 * is useful for checking thermistors whose output seems to be incorrect.
 */
static int dont_calibrate = 0;

/* Only one processor should powerdown the system. */
static int powerdown_started = 0;

/* Let user disable overtemp powerdown. */
int enable_overtemp_powerdown = 1;

/*
 * The following tables correspond to the degress Celcius for each count
 * value possible from the 8-bit A/C convertors on each type of system
 * board for the UltraSPARC Server systems. To access a temperature,
 * just index into the correct table using the count from the A/D convertor
 * register, and that is the correct temperature in degress Celsius. These
 * values can be negative.
 */
static short cpu_table[] = {
-16,	-14,	-12,	-10,	-8,	-6,	-4,	-2,	/* 0-7 */
1,	4,	6,	8,	10,	12,	13,	15,	/* 8-15 */
16,	18,	19,	20,	22,	23,	24,	25,	/* 16-23 */
26,	27,	28,	29,	30,	31,	32,	33,	/* 24-31 */
34,	35,	35,	36,	37,	38,	39,	39,	/* 32-39 */
40,	41,	41,	42,	43,	44,	44,	45,	/* 40-47 */
46,	46,	47,	47,	48,	49,	49,	50,	/* 48-55 */
51,	51,	52,	53,	53,	54,	54,	55,	/* 56-63 */
55,	56,	56,	57,	57,	58,	58,	59,	/* 64-71 */
60,	60,	61,	61,	62,	62,	63,	63,	/* 72-79 */
64,	64,	65,	65,	66,	66,	67,	67,	/* 80-87 */
68,	68,	69,	69,	70,	70,	71,	71,	/* 88-95 */
72,	72,	73,	73,	74,	74,	75,	75,	/* 96-103 */
76,	76,	77,	77,	78,	78,	79,	79,	/* 104-111 */
80,	80,	81,	81,	82,	82,	83,	83,	/* 112-119 */
84,	84,	85,	85,	86,	86,	87,	87,	/* 120-127 */
88,	88,	89,	89,	90,	90,	91,	91,	/* 128-135 */
92,	92,	93,	93,	94,	94,	95,	95,	/* 136-143 */
96,	96,	97,	98,	98,	99,	99,	100,	/* 144-151 */
100,	101,	101,	102,	103,	103,	104,	104,	/* 152-159 */
105,	106,	106,	107,	107,	108,	109,	109,	/* 160-167 */
110,								/* 168 */
};

#define	CPU_MX_CNT	(sizeof (cpu_table)/sizeof (short))

static short cpu2_table[] = {
-17,	-16,	-15,	-14,	-13,	-12,	-11,	-10,	/* 0-7 */
-9,	-8,	-7,	-6,	-5,	-4,	-3,	-2,	/* 8-15 */
-1,	0,	1,	2,	3,	4,	5,	6,	/* 16-23 */
7,	8,	9,	10,	11,	12,	13,	13,	/* 24-31 */
14,	15,	16,	16,	17,	18,	18,	19,	/* 32-39 */
20,	20,	21,	22,	22,	23,	24,	24,	/* 40-47 */
25,	25,	26,	26,	27,	27,	28,	28,	/* 48-55 */
29,	30,	30,	31,	31,	32,	32,	33,	/* 56-63 */
33,	34,	34,	35,	35,	36,	36,	37,	/* 64-71 */
37,	37,	38,	38,	39,	39,	40,	40,	/* 72-79 */
41,	41,	42,	42,	43,	43,	43,	44,	/* 80-87 */
44,	45,	45,	46,	46,	46,	47,	47,	/* 88-95 */
48,	48,	49,	49,	50,	50,	50,	51,	/* 96-103 */
51,	52,	52,	53,	53,	53,	54,	54,	/* 104-111 */
55,	55,	56,	56,	56,	57,	57,	58,	/* 112-119 */
58,	59,	59,	59,	60,	60,	61,	61,	/* 120-127 */
62,	62,	63,	63,	63,	64,	64,	65,	/* 128-135 */
65,	66,	66,	67,	67,	68,	68,	68,	/* 136-143 */
69,	69,	70,	70,	71,	71,	72,	72,	/* 144-151 */
73,	73,	74,	74,	75,	75,	76,	76,	/* 152-159 */
77,	77,	78,	78,	79,	79,	80,	80,	/* 160-167 */
81,	81,	82,	83,	83,	84,	84,	85,	/* 168-175 */
85,	86,	87,	87,	88,	88,	89,	90,	/* 176-183 */
90,	91,	92,	92,	93,	94,	94,	95,	/* 184-191 */
96,	96,	97,	98,	99,	99,	100,	101,	/* 192-199 */
102,	103,	103,	104,	105,	106,	107,	108,	/* 200-207 */
109,	110,							/* 208-209 */
};

#define	CPU2_MX_CNT	(sizeof (cpu2_table)/sizeof (short))

static short io_table[] = {
0,	0,	0,	0,	0,	0,	0,	0,	/* 0-7 */
0,	0,	0,	0,	0,	0,	0,	0,	/* 8-15 */
0,	0,	0,	0,	0,	0,	0,	0,	/* 16-23 */
0,	0,	0,	0,	0,	0,	0,	0,	/* 24-31 */
0,	0,	0,	0,	0,	0,	0,	0,	/* 32-39 */
0,	3,	7,	10,	13,	15,	17,	19,	/* 40-47 */
21,	23,	25,	27,	28,	30,	31,	32,	/* 48-55 */
34,	35,	36,	37,	38,	39,	41,	42,	/* 56-63 */
43,	44,	45,	46,	46,	47,	48,	49,	/* 64-71 */
50,	51,	52,	53,	53,	54,	55,	56,	/* 72-79 */
57,	57,	58,	59,	60,	60,	61,	62,	/* 80-87 */
62,	63,	64,	64,	65,	66,	66,	67,	/* 88-95 */
68,	68,	69,	70,	70,	71,	72,	72,	/* 96-103 */
73,	73,	74,	75,	75,	76,	77,	77,	/* 104-111 */
78,	78,	79,	80,	80,	81,	81,	82,	/* 112-119 */
};

#define	IO_MN_CNT	40
#define	IO_MX_CNT	(sizeof (io_table)/sizeof (short))

static short clock_table[] = {
0,	0,	0,	0,	0,	0,	0,	0,	/* 0-7 */
0,	0,	0,	0,	1,	2,	4,	5,	/* 8-15 */
7,	8,	10,	11,	12,	13,	14,	15,	/* 16-23 */
17,	18,	19,	20,	21,	22,	23,	24,	/* 24-31 */
24,	25,	26,	27,	28,	29,	29,	30,	/* 32-39 */
31,	32,	32,	33,	34,	35,	35,	36,	/* 40-47 */
37,	38,	38,	39,	40,	40,	41,	42,	/* 48-55 */
42,	43,	44,	44,	45,	46,	46,	47,	/* 56-63 */
48,	48,	49,	50,	50,	51,	52,	52,	/* 64-71 */
53,	54,	54,	55,	56,	57,	57,	58,	/* 72-79 */
59,	59,	60,	60,	61,	62,	63,	63,	/* 80-87 */
64,	65,	65,	66,	67,	68,	68,	69,	/* 88-95 */
70,	70,	71,	72,	73,	74,	74,	75,	/* 96-103 */
76,	77,	78,	78,	79,	80,	81,	82,	/* 104-111 */
};

#define	CLK_MN_CNT	11
#define	CLK_MX_CNT	(sizeof (clock_table)/sizeof (short))

/*
 * System temperature limits.
 *
 * The following variables are the warning and danger limits for the
 * different types of system boards. The limits are different because
 * the various boards reach different nominal temperatures because
 * of the different components that they contain.
 *
 * The warning limit is the temperature at which the user is warned.
 * The danger limit is the temperature at which the system is shutdown.
 * In the case of CPU/Memory system boards, the system will attempt
 * to offline and power down processors on a board in an attempt to
 * bring the board back into the nominal temperature range before
 * shutting down the system.
 *
 * These values can be tuned via /etc/system or boot -h.
 */
short cpu_warn_temp = 73;	/* CPU/Memory Warning Temperature */
short cpu_danger_temp = 83;	/* CPU/Memory Danger Temperature */
short io_warn_temp = 60;	/* IO Board Warning Temperature */
short io_danger_temp = 68;	/* IO Board Danger Temperature */
short clk_warn_temp = 60;	/* Clock Board Warning Temperature */
short clk_danger_temp = 68;	/* Clock Board Danger Temperature */

short dft_warn_temp = 60;	/* default warning temp value */
short dft_danger_temp = 68;	/* default danger temp value */

short cpu_warn_temp_4x = 60;	/* CPU/Memory warning temp for 400 MHZ */
short cpu_danger_temp_4x = 68;	/* CPU/Memory danger temp for 400 MHZ */

/*
 * This variable tells us if we are in a heat chamber. It is set
 * early on in boot, after we check the OBP 'mfg-mode' property in
 * the options node.
 */
static int temperature_chamber = -1;

/*
 * The fhc memloc structure is protected under the bdlist lock
 */
static struct fhc_memloc *fhc_base_memloc = NULL;

/*
 * Driver global fault list mutex and list head pointer. The list is
 * protected by the mutex and contains a record of all known faults.
 * Faults can be inherited from the PROM or detected by the kernel.
 */
static kmutex_t ftlist_mutex;
static struct ft_link_list *ft_list = NULL;
static int ft_nfaults = 0;

/*
 * Table of all known fault strings. This table is indexed by the fault
 * type. Do not change the ordering of the table without redefining the
 * fault type enum list on fhc.h.
 */
char *ft_str_table[] = {
	"Core Power Supply",		/* FT_CORE_PS */
	"Overtemp",			/* FT_OVERTEMP */
	"AC Power",			/* FT_AC_PWR */
	"Peripheral Power Supply",	/* FT_PPS */
	"System 3.3 Volt Power",	/* FT_CLK_33 */
	"System 5.0 Volt Power",	/* FT_CLK_50 */
	"Peripheral 5.0 Volt Power",	/* FT_V5_P */
	"Peripheral 12 Volt Power",	/* FT_V12_P */
	"Auxiliary 5.0 Volt Power",	/* FT_V5_AUX */
	"Peripheral 5.0 Volt Precharge", /* FT_V5_P_PCH */
	"Peripheral 12 Volt Precharge",	/* FT_V12_P_PCH */
	"System 3.3 Volt Precharge",	/* FT_V3_PCH */
	"System 5.0 Volt Precharge",	/* FT_V5_PCH */
	"Peripheral Power Supply Fans",	/* FT_PPS_FAN */
	"Rack Exhaust Fan",		/* FT_RACK_EXH */
	"Disk Drive Fan",		/* FT_DSK_FAN */
	"AC Box Fan",			/* FT_AC_FAN */
	"Key Switch Fan",		/* FT_KEYSW_FAN */
	"Minimum Power",		/* FT_INSUFFICIENT_POWER */
	"PROM detected",		/* FT_PROM */
	"Hot Plug Support System",	/* FT_HOT_PLUG */
	"TOD"				/* FT_TODFAULT */
};

static int ft_max_index = (sizeof (ft_str_table) / sizeof (char *));

/*
 * Function prototypes
 */
static int fhc_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
	void *, void *);
static int fhc_intr_ops(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);

static int fhc_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp);
static void fhc_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp);

static int fhc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int fhc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int fhc_init(struct fhc_soft_state *softsp);
static void fhc_unmap_regs(struct fhc_soft_state *softsp);
static enum board_type fhc_board_type(struct fhc_soft_state *, int);

static void
fhc_xlate_intrs(ddi_intr_handle_impl_t *hdlp, uint32_t ign);

static int
fhc_ctlops_peekpoke(ddi_ctl_enum_t, peekpoke_ctlops_t *, void *result);

static void fhc_add_kstats(struct fhc_soft_state *);
static int fhc_kstat_update(kstat_t *, int);
static int check_for_chamber(void);
static int ft_ks_snapshot(struct kstat *, void *, int);
static int ft_ks_update(struct kstat *, int);
static int check_central(int board);

/*
 * board type and A/D convertor output passed in and real temperature
 * is returned.
 */
static short calibrate_temp(enum board_type, uchar_t, uint_t);
static enum temp_state get_temp_state(enum board_type, short, int);

/* Routine to determine if there are CPUs on this board. */
static int cpu_on_board(int);

static void build_bd_display_str(char *, enum board_type, int);

/* Interrupt distribution callback function. */
static void fhc_intrdist(void *);

/* CPU power control */
int fhc_cpu_poweroff(struct cpu *);	/* cpu_poweroff()->platform */
int fhc_cpu_poweron(struct cpu *);	/* cpu_poweron()->platform */

extern struct cpu_node cpunodes[];
extern void halt(char *);

/*
 * Configuration data structures
 */
static struct bus_ops fhc_bus_ops = {
	BUSO_REV,
	ddi_bus_map,		/* map */
	0,			/* get_intrspec */
	0,			/* add_intrspec */
	0,			/* remove_intrspec */
	i_ddi_map_fault,	/* map_fault */
	ddi_no_dma_map,		/* dma_map */
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_dma_mctl,		/* dma_ctl */
	fhc_ctlops,		/* ctl */
	ddi_bus_prop_op,	/* prop_op */
	0,			/* (*bus_get_eventcookie)();	*/
	0,			/* (*bus_add_eventcall)();	*/
	0,			/* (*bus_remove_eventcall)();	*/
	0,			/* (*bus_post_event)();		*/
	0,			/* (*bus_intr_control)();	*/
	0,			/* (*bus_config)();		*/
	0,			/* (*bus_unconfig)();		*/
	0,			/* (*bus_fm_init)();		*/
	0,			/* (*bus_fm_fini)();		*/
	0,			/* (*bus_fm_access_enter)();	*/
	0,			/* (*bus_fm_access_exit)();	*/
	0,			/* (*bus_power)();		*/
	fhc_intr_ops		/* (*bus_intr_op)();		*/
};

static struct cb_ops fhc_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	nulldev,		/* read */
	nulldev,		/* write */
	nulldev,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab */
	D_MP|D_NEW|D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,			/* rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops fhc_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt  */
	ddi_no_info,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	fhc_attach,		/* attach */
	fhc_detach,		/* detach */
	nulldev,		/* reset */
	&fhc_cb_ops,		/* cb_ops */
	&fhc_bus_ops,		/* bus_ops */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Driver globals
 * TODO - We need to investigate what locking needs to be done here.
 */
void *fhcp;				/* fhc soft state hook */

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"FHC Nexus",		/* Name of module. */
	&fhc_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};


/*
 * These are the module initialization routines.
 */

static caddr_t shutdown_va;

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&fhcp,
	    sizeof (struct fhc_soft_state), 1)) != 0)
		return (error);

	fhc_bdlist_init();
	mutex_init(&ftlist_mutex, NULL, MUTEX_DEFAULT, NULL);

	shutdown_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
	ASSERT(shutdown_va != NULL);

	plat_register_tod_fault(fhc_tod_fault);

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	plat_register_tod_fault(NULL);

	mutex_destroy(&ftlist_mutex);

	fhc_bdlist_fini();

	ddi_soft_state_fini(&fhcp);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Reset the interrupt mapping registers.
 * This function resets the values during DDI_RESUME.
 *
 * NOTE: This function will not work for a full CPR cycle
 * and is currently designed to handle the RESUME after a connect.
 *
 * Note about the PROM handling of moving CENTRAL to another board:
 * The PROM moves the IGN identity (igr register) from the
 * original CENTRAL to the new one. This means that we do not
 * duplicate the fhc_attach code that sets it to (board number * 2).
 * We rely on only using FHC interrupts from one board only
 * (the UART and SYS interrupts) so that the values of the other IGNs
 * are irrelevant. The benefit of this approach is that we don't
 * have to have to tear down and rebuild the interrupt records
 * for UART and SYS. It is also why we don't try to change the
 * board number in the fhc instance for the clock board.
 */
static void
fhc_handle_imr(struct fhc_soft_state *softsp)
{
	int i;
	int cent;
	uint_t tmp_reg;


	if (softsp->is_central) {
		uint_t want_igr, act_igr;

		want_igr = softsp->list->sc.board << 1;
		act_igr = *softsp->igr & 0x1f;
		if (want_igr != act_igr) {
			*softsp->igr = want_igr;
			tmp_reg = *softsp->igr;
#ifdef lint
			tmp_reg = tmp_reg;
#endif
			/* We must now re-issue any pending interrupts. */
			for (i = 0; i < FHC_MAX_INO; i++) {
				if (*(softsp->intr_regs[i].clear_reg) == 3) {
					*(softsp->intr_regs[i].clear_reg) =
					    ISM_IDLE;

					tmp_reg =
					    *(softsp->intr_regs[i].clear_reg);
#ifdef lint
					tmp_reg = tmp_reg;
#endif
				}
			}
			cmn_err(CE_NOTE, "central IGN corruption fixed: "
			    "got %x wanted %x", act_igr, want_igr);
		}
		return;
	}

	ASSERT(softsp->list->sc.board == FHC_BSR_TO_BD(*(softsp->bsr)));
	cent = check_central(softsp->list->sc.board);

	/* Loop through all 4 FHC interrupt mapping registers */
	for (i = 0; i < FHC_MAX_INO; i++) {

		if (i == FHC_SYS_INO &&
		    *(softsp->intr_regs[i].clear_reg) == 3) {
			cmn_err(CE_NOTE,
			    "found lost system interrupt, resetting..");

			*(softsp->intr_regs[i].clear_reg) = ISM_IDLE;

			/*
			 * ensure atomic write with this read.
			 */
			tmp_reg = *(softsp->intr_regs[i].clear_reg);
#ifdef lint
			tmp_reg = tmp_reg;
#endif
		}

		/*
		 * The mapping registers on the board with the "central" bit
		 * set should not be touched as it has been taken care by POST.
		 */

		if (cent)
			continue;

		*(softsp->intr_regs[i].mapping_reg) = 0;

		/*
		 * ensure atomic write with this read.
		 */
		tmp_reg = *(softsp->intr_regs[i].mapping_reg);
#ifdef lint
		tmp_reg = tmp_reg;
#endif

	}
}

static int
check_central(int board)
{
	uint_t cs_value;

	/*
	 * This is the value of AC configuration and status reg
	 * in the Local Devices space. We access it as a physical
	 * address.
	 */
	cs_value = ldphysio(AC_BCSR(board));
	if (cs_value & AC_CENTRAL)
		return (TRUE);
	else
		return (FALSE);
}

static int
fhc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	struct fhc_soft_state *softsp;
	int instance;

	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		softsp = ddi_get_soft_state(fhcp, instance);
		/* IGR, NOT_BRD_PRES handled by prom */
		/* reset interrupt mapping registers */
		fhc_handle_imr(softsp);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}


	if (ddi_soft_state_zalloc(fhcp, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = ddi_get_soft_state(fhcp, instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;

	if (fhc_init(softsp) != DDI_SUCCESS)
		goto bad;

	ddi_report_dev(devi);

	return (DDI_SUCCESS);

bad:
	ddi_soft_state_free(fhcp, instance);
	return (DDI_FAILURE);
}

static int
fhc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int board;
	int instance;
	struct fhc_soft_state *softsp;
	fhc_bd_t *list = NULL;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	/* get the soft state pointer for this device node */
	softsp = ddi_get_soft_state(fhcp, instance);

	board = softsp->list->sc.board;

	switch (cmd) {
	case DDI_SUSPEND:

		return (DDI_SUCCESS);

	case DDI_DETACH:
		/* grab the lock on the board list */
		list = fhc_bdlist_lock(board);

		if (fhc_bd_detachable(board) &&
		    !fhc_bd_is_jtag_master(board))
			break;
		else
			fhc_bdlist_unlock();
		/* FALLTHROUGH */

	default:
		return (DDI_FAILURE);
	}

	/* Remove the interrupt redistribution callback. */
	intr_dist_rem(fhc_intrdist, (void *)devi);

	/* remove the soft state pointer from the board list */
	list->softsp = NULL;

	/* clear inherited faults from the PROM. */
	clear_fault(list->sc.board, FT_PROM, FT_BOARD);

	/* remove the kstat for this board */
	kstat_delete(softsp->fhc_ksp);

	/* destroy the mutexes in this soft state structure */
	mutex_destroy(&softsp->poll_list_lock);
	mutex_destroy(&softsp->ctrl_lock);

	/* unmap all the register sets */
	fhc_unmap_regs(softsp);

	/* release the board list lock now */
	fhc_bdlist_unlock();

	/* free the soft state structure */
	ddi_soft_state_free(fhcp, instance);

	return (DDI_SUCCESS);
}

static enum board_type
fhc_board_type(struct fhc_soft_state *softsp, int board)
{
	int proplen;
	char *board_type;
	enum board_type type;

	if (softsp->is_central)
		type = CLOCK_BOARD;
	else if (ddi_getlongprop(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, "board-type", (caddr_t)&board_type,
	    &proplen) == DDI_PROP_SUCCESS) {
		/* match the board-type string */
		if (strcmp(CPU_BD_NAME, board_type) == 0) {
			type = CPU_BOARD;
		} else if (strcmp(MEM_BD_NAME, board_type) == 0) {
			type = MEM_BOARD;
		} else if (strcmp(IO_2SBUS_BD_NAME, board_type) == 0) {
			type = IO_2SBUS_BOARD;
		} else if (strcmp(IO_SBUS_FFB_BD_NAME, board_type) == 0) {
			type = IO_SBUS_FFB_BOARD;
		} else if (strcmp(IO_2SBUS_SOCPLUS_BD_NAME, board_type) == 0) {
			type = IO_2SBUS_SOCPLUS_BOARD;
		} else if (strcmp(IO_SBUS_FFB_SOCPLUS_BD_NAME, board_type)
		    == 0) {
			type = IO_SBUS_FFB_SOCPLUS_BOARD;
		} else if (strcmp(IO_PCI_BD_NAME, board_type) == 0) {
			type = IO_PCI_BOARD;
		} else {
			type = UNKNOWN_BOARD;
		}
		kmem_free(board_type, proplen);
	} else
		type = UNKNOWN_BOARD;

	/*
	 * if the board type is indeterminate, it must be determined.
	 */
	if (type == UNKNOWN_BOARD) {
		/*
		 * Use the UPA64 bits from the FHC.
		 * This is not the best solution since we
		 * cannot fully type the IO boards.
		 */
		if (cpu_on_board(board))
			type = CPU_BOARD;
		else if ((*(softsp->bsr) & FHC_UPADATA64A) ||
		    (*(softsp->bsr) & FHC_UPADATA64B))
			type = IO_2SBUS_BOARD;
		else
			type = MEM_BOARD;
	}

	return (type);
}

static void
fhc_unmap_regs(struct fhc_soft_state *softsp)
{
	dev_info_t *dip = softsp->dip;

	if (softsp->id) {
		ddi_unmap_regs(dip, 0, (caddr_t *)&softsp->id, 0, 0);
		softsp->id = NULL;
	}
	if (softsp->igr) {
		ddi_unmap_regs(dip, 1, (caddr_t *)&softsp->igr, 0, 0);
		softsp->igr = NULL;
	}
	if (softsp->intr_regs[FHC_FANFAIL_INO].mapping_reg) {
		ddi_unmap_regs(dip, 2,
		    (caddr_t *)&softsp->intr_regs[FHC_FANFAIL_INO].mapping_reg,
		    0, 0);
		softsp->intr_regs[FHC_FANFAIL_INO].mapping_reg = NULL;
	}
	if (softsp->intr_regs[FHC_SYS_INO].mapping_reg) {
		ddi_unmap_regs(dip, 3,
		    (caddr_t *)&softsp->intr_regs[FHC_SYS_INO].mapping_reg,
		    0, 0);
		softsp->intr_regs[FHC_SYS_INO].mapping_reg = NULL;
	}
	if (softsp->intr_regs[FHC_UART_INO].mapping_reg) {
		ddi_unmap_regs(dip, 4,
		    (caddr_t *)&softsp->intr_regs[FHC_UART_INO].mapping_reg,
		    0, 0);
		softsp->intr_regs[FHC_UART_INO].mapping_reg = NULL;
	}
	if (softsp->intr_regs[FHC_TOD_INO].mapping_reg) {
		ddi_unmap_regs(dip, 5,
		    (caddr_t *)&softsp->intr_regs[FHC_TOD_INO].mapping_reg,
		    0, 0);
		softsp->intr_regs[FHC_TOD_INO].mapping_reg = NULL;
	}
}

static int
fhc_init(struct fhc_soft_state *softsp)
{
	int i;
	uint_t tmp_reg;
	int board;

	/*
	 * Map in the FHC registers. Specifying length and offset of
	 * zero maps in the entire OBP register set.
	 */

	/* map in register set 0 */
	if (ddi_map_regs(softsp->dip, 0,
	    (caddr_t *)&softsp->id, 0, 0)) {
		cmn_err(CE_WARN, "fhc%d: unable to map internal "
		    "registers", ddi_get_instance(softsp->dip));
		goto bad;
	}

	/*
	 * Fill in the virtual addresses of the registers in the
	 * fhc_soft_state structure.
	 */
	softsp->rctrl = (uint_t *)((char *)(softsp->id) +
	    FHC_OFF_RCTRL);
	softsp->ctrl = (uint_t *)((char *)(softsp->id) +
	    FHC_OFF_CTRL);
	softsp->bsr = (uint_t *)((char *)(softsp->id) +
	    FHC_OFF_BSR);
	softsp->jtag_ctrl = (uint_t *)((char *)(softsp->id) +
	    FHC_OFF_JTAG_CTRL);
	softsp->jt_master.jtag_cmd = (uint_t *)((char *)(softsp->id) +
	    FHC_OFF_JTAG_CMD);

	/* map in register set 1 */
	if (ddi_map_regs(softsp->dip, 1,
	    (caddr_t *)&softsp->igr, 0, 0)) {
		cmn_err(CE_WARN, "fhc%d: unable to map IGR "
		    "register", ddi_get_instance(softsp->dip));
		goto bad;
	}

	/*
	 * map in register set 2
	 * XXX this can never be used as an interrupt generator
	 * (hardware queue overflow in fhc)
	 */
	if (ddi_map_regs(softsp->dip, 2,
	    (caddr_t *)&softsp->intr_regs[FHC_FANFAIL_INO].mapping_reg,
	    0, 0)) {
		cmn_err(CE_WARN, "fhc%d: unable to map Fan Fail "
		    "IMR register", ddi_get_instance(softsp->dip));
		goto bad;
	}

	/* map in register set 3 */
	if (ddi_map_regs(softsp->dip, 3,
	    (caddr_t *)&softsp->intr_regs[FHC_SYS_INO].mapping_reg,
	    0, 0)) {
		cmn_err(CE_WARN, "fhc%d: unable to map System "
		    "IMR register\n", ddi_get_instance(softsp->dip));
		goto bad;
	}

	/* map in register set 4 */
	if (ddi_map_regs(softsp->dip, 4,
	    (caddr_t *)&softsp->intr_regs[FHC_UART_INO].mapping_reg,
	    0, 0)) {
		cmn_err(CE_WARN, "fhc%d: unable to map UART "
		    "IMR register\n", ddi_get_instance(softsp->dip));
		goto bad;
	}

	/* map in register set 5 */
	if (ddi_map_regs(softsp->dip, 5,
	    (caddr_t *)&softsp->intr_regs[FHC_TOD_INO].mapping_reg,
	    0, 0)) {
		cmn_err(CE_WARN, "fhc%d: unable to map FHC TOD "
		    "IMR register", ddi_get_instance(softsp->dip));
		goto bad;
	}

	/* Loop over all intr sets and setup the VAs for the ISMR */
	/* TODO - Make sure we are calculating the ISMR correctly. */
	for (i = 0; i < FHC_MAX_INO; i++) {
		softsp->intr_regs[i].clear_reg =
		    (uint_t *)((char *)(softsp->intr_regs[i].mapping_reg) +
		    FHC_OFF_ISMR);

		/* Now clear the state machines to idle */
		*(softsp->intr_regs[i].clear_reg) = ISM_IDLE;
	}

	/*
	 * It is OK to not have a OBP_BOARDNUM property. This happens for
	 * the board which is a child of central. However this FHC
	 * still needs a proper Interrupt Group Number programmed
	 * into the Interrupt Group register, because the other
	 * instance of FHC, which is not under central, will properly
	 * program the IGR. The numbers from the two settings of the
	 * IGR need to be the same. One driver cannot wait for the
	 * other to program the IGR, because there is no guarantee
	 * which instance of FHC will get attached first.
	 */
	if ((board = (int)ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, OBP_BOARDNUM, -1)) == -1) {
		/*
		 * Now determine the board number by reading the
		 * hardware register.
		 */
		board = FHC_BSR_TO_BD(*(softsp->bsr));
		softsp->is_central = 1;
	}

	/*
	 * If this fhc holds JTAG master line, and is not the central fhc,
	 * (this avoids two JTAG master nodes) then initialize the
	 * mutex and set the flag in the structure.
	 */
	if ((*(softsp->jtag_ctrl) & JTAG_MASTER_EN) && !softsp->is_central) {
		mutex_init(&(softsp->jt_master.lock), NULL, MUTEX_DEFAULT,
		    NULL);
		softsp->jt_master.is_master = 1;
	} else {
		softsp->jt_master.is_master = 0;
	}

	fhc_bd_init(softsp, board, fhc_board_type(softsp, board));

	/* Initialize the mutex guarding the poll_list. */
	mutex_init(&softsp->poll_list_lock, NULL, MUTEX_DRIVER, NULL);

	/* Initialize the mutex guarding the FHC CSR */
	mutex_init(&softsp->ctrl_lock, NULL, MUTEX_DRIVER, NULL);

	/* Initialize the poll_list to be empty */
	for (i = 0; i < MAX_ZS_CNT; i++) {
		softsp->poll_list[i].funcp = NULL;
	}

	/* Modify the various registers in the FHC now */

	/*
	 * We know this board to be present now, record that state and
	 * remove the NOT_BRD_PRES condition
	 */
	if (!(softsp->is_central)) {
		mutex_enter(&softsp->ctrl_lock);
		*(softsp->ctrl) |= FHC_NOT_BRD_PRES;
		/* Now flush the hardware store buffers. */
		tmp_reg = *(softsp->ctrl);
#ifdef lint
		tmp_reg = tmp_reg;
#endif
		/* XXX record the board state in global space */
		mutex_exit(&softsp->ctrl_lock);

		/* Add kstats for all non-central instances of the FHC. */
		fhc_add_kstats(softsp);
	}

	/*
	 * Read the device tree to see if this system is in an environmental
	 * chamber.
	 */
	if (temperature_chamber == -1) {
		temperature_chamber = check_for_chamber();
	}

	/* Check for inherited faults from the PROM. */
	if (*softsp->ctrl & FHC_LED_MID) {
		reg_fault(softsp->list->sc.board, FT_PROM, FT_BOARD);
	}

	/*
	 * setup the IGR. Shift the board number over by one to get
	 * the UPA MID.
	 */
	*(softsp->igr) = (softsp->list->sc.board) << 1;

	/* Now flush the hardware store buffers. */
	tmp_reg = *(softsp->id);
#ifdef lint
	tmp_reg = tmp_reg;
#endif

	/* Add the interrupt redistribution callback. */
	intr_dist_add(fhc_intrdist, (void *)softsp->dip);

	return (DDI_SUCCESS);
bad:
	fhc_unmap_regs(softsp);
	return (DDI_FAILURE);
}

static uint_t
fhc_intr_wrapper(caddr_t arg)
{
	uint_t intr_return;
	uint_t tmpreg;
	struct fhc_wrapper_arg *intr_info = (struct fhc_wrapper_arg *)arg;
	uint_t (*funcp)(caddr_t, caddr_t) = intr_info->funcp;
	caddr_t iarg1 = intr_info->arg1;
	caddr_t iarg2 = intr_info->arg2;
	dev_info_t *dip = intr_info->child;

	tmpreg = ISM_IDLE;

	DTRACE_PROBE4(interrupt__start, dev_info_t, dip,
	    void *, funcp, caddr_t, iarg1, caddr_t, iarg2);

	intr_return = (*funcp)(iarg1, iarg2);

	DTRACE_PROBE4(interrupt__complete, dev_info_t, dip,
	    void *, funcp, caddr_t, iarg1, int, intr_return);

	/* Idle the state machine. */
	*(intr_info->clear_reg) = tmpreg;

	/* Flush the hardware store buffers. */
	tmpreg = *(intr_info->clear_reg);
#ifdef lint
	tmpreg = tmpreg;
#endif	/* lint */

	return (intr_return);
}

/*
 * fhc_zs_intr_wrapper
 *
 * This function handles intrerrupts where more than one device may interupt
 * the fhc with the same mondo.
 */

#define	MAX_INTR_CNT 10

static uint_t
fhc_zs_intr_wrapper(caddr_t arg)
{
	struct fhc_soft_state *softsp = (struct fhc_soft_state *)arg;
	uint_t (*funcp0)(caddr_t, caddr_t);
	uint_t (*funcp1)(caddr_t, caddr_t);
	caddr_t funcp0_arg1, funcp0_arg2, funcp1_arg1, funcp1_arg2;
	uint_t tmp_reg;
	uint_t result = DDI_INTR_UNCLAIMED;
	volatile uint_t *clear_reg;
	uchar_t *spurious_cntr = &softsp->spurious_zs_cntr;

	funcp0 = softsp->poll_list[0].funcp;
	funcp1 = softsp->poll_list[1].funcp;
	funcp0_arg1 = softsp->poll_list[0].arg1;
	funcp0_arg2 = softsp->poll_list[0].arg2;
	funcp1_arg1 = softsp->poll_list[1].arg1;
	funcp1_arg2 = softsp->poll_list[1].arg2;
	clear_reg = softsp->intr_regs[FHC_UART_INO].clear_reg;

	if (funcp0 != NULL) {
		if ((funcp0)(funcp0_arg1, funcp0_arg2) == DDI_INTR_CLAIMED) {
			result = DDI_INTR_CLAIMED;
		}
	}

	if (funcp1 != NULL) {
		if ((funcp1)(funcp1_arg1, funcp1_arg2) == DDI_INTR_CLAIMED) {
			result = DDI_INTR_CLAIMED;
		}
	}

	if (result == DDI_INTR_UNCLAIMED) {
		(*spurious_cntr)++;

		if (*spurious_cntr < MAX_INTR_CNT) {
			result = DDI_INTR_CLAIMED;
		} else {
			*spurious_cntr = (uchar_t)0;
		}
	} else {
		*spurious_cntr = (uchar_t)0;
	}

	/* Idle the state machine. */
	*(clear_reg) = ISM_IDLE;

	/* flush the store buffers. */
	tmp_reg = *(clear_reg);
#ifdef lint
	tmp_reg = tmp_reg;
#endif

	return (result);
}


/*
 * add_intrspec - Add an interrupt specification.
 */
static int
fhc_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int ino;
	struct fhc_wrapper_arg *fhc_arg;
	struct fhc_soft_state *softsp = (struct fhc_soft_state *)
	    ddi_get_soft_state(fhcp, ddi_get_instance(dip));
	volatile uint_t *mondo_vec_reg;
	uint_t tmp_mondo_vec;
	uint_t tmpreg; /* HW flush reg */
	uint_t cpu_id;
	int ret = DDI_SUCCESS;

	/* Xlate the interrupt */
	fhc_xlate_intrs(hdlp,
	    (softsp->list->sc.board << BD_IVINTR_SHFT));

	/* get the mondo number */
	ino = FHC_INO(hdlp->ih_vector);
	mondo_vec_reg = softsp->intr_regs[ino].mapping_reg;

	ASSERT(ino < FHC_MAX_INO);

	/* We don't use the two spare interrupts. */
	if (ino >= FHC_MAX_INO) {
		cmn_err(CE_WARN, "fhc%d: Spare interrupt %d not usable",
		    ddi_get_instance(dip), ino);
		return (DDI_FAILURE);
	}

	/* TOD and Fan Fail interrupts are not usable */
	if (ino == FHC_TOD_INO) {
		cmn_err(CE_WARN, "fhc%d: TOD interrupt not usable",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	if (ino == FHC_FANFAIL_INO) {
		cmn_err(CE_WARN, "fhc%d: Fan fail interrupt not usable",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	/*
	 * If the interrupt is for the zs chips, use the vector
	 * polling lists. Otherwise use a straight handler.
	 */
	if (ino == FHC_UART_INO) {
		int32_t zs_inst;
		/* First lock the mutex for this poll_list */
		mutex_enter(&softsp->poll_list_lock);

		/*
		 * Add this interrupt to the polling list.
		 */

		/* figure out where to add this item in the list */
		for (zs_inst = 0; zs_inst < MAX_ZS_CNT; zs_inst++) {
			if (softsp->poll_list[zs_inst].funcp == NULL) {
				softsp->poll_list[zs_inst].arg1 =
				    hdlp->ih_cb_arg1;
				softsp->poll_list[zs_inst].arg2 =
				    hdlp->ih_cb_arg2;
				softsp->poll_list[zs_inst].funcp =
				    (ddi_intr_handler_t *)
				    hdlp->ih_cb_func;
				softsp->poll_list[zs_inst].inum =
				    hdlp->ih_inum;
				softsp->poll_list[zs_inst].child = rdip;

				break;
			}
		}

		if (zs_inst >= MAX_ZS_CNT) {
			cmn_err(CE_WARN,
			    "fhc%d: poll list overflow",
			    ddi_get_instance(dip));
			mutex_exit(&softsp->poll_list_lock);
			ret = DDI_FAILURE;
			goto done;
		}

		/*
		 * If polling list is empty, then install handler
		 * and enable interrupts for this ino.
		 */
		if (zs_inst == 0) {
			DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
			    (ddi_intr_handler_t *)fhc_zs_intr_wrapper,
			    (caddr_t)softsp, NULL);

			ret = i_ddi_add_ivintr(hdlp);

			DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
			    softsp->poll_list[zs_inst].funcp,
			    softsp->poll_list[zs_inst].arg1,
			    softsp->poll_list[zs_inst].arg2);

			if (ret != DDI_SUCCESS)
				goto done;
		}

		/*
		 * If both zs handlers are active, then this is the
		 * second add_intrspec called, so do not enable
		 * the IMR_VALID bit, it is already on.
		 */
		if (zs_inst > 0) {
				/* now release the mutex and return */
			mutex_exit(&softsp->poll_list_lock);

			goto done;
		} else {
			/* just release the mutex */
			mutex_exit(&softsp->poll_list_lock);
		}
	} else {	/* normal interrupt installation */
		int32_t i;

		/* Allocate a nexus interrupt data structure */
		fhc_arg = kmem_alloc(sizeof (struct fhc_wrapper_arg), KM_SLEEP);
		fhc_arg->child = rdip;
		fhc_arg->mapping_reg = mondo_vec_reg;
		fhc_arg->clear_reg = (softsp->intr_regs[ino].clear_reg);
		fhc_arg->softsp = softsp;
		fhc_arg->funcp =
		    (ddi_intr_handler_t *)hdlp->ih_cb_func;
		fhc_arg->arg1 = hdlp->ih_cb_arg1;
		fhc_arg->arg2 = hdlp->ih_cb_arg2;
		fhc_arg->inum = hdlp->ih_inum;

		for (i = 0; i < FHC_MAX_INO; i++) {
			if (softsp->intr_list[i] == 0) {
				softsp->intr_list[i] = fhc_arg;
				break;
			}
		}

		/*
		 * Save the fhc_arg in the ispec so we can use this info
		 * later to uninstall this interrupt spec.
		 */
		DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
		    (ddi_intr_handler_t *)fhc_intr_wrapper,
		    (caddr_t)fhc_arg, NULL);

		ret = i_ddi_add_ivintr(hdlp);

		DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp, fhc_arg->funcp,
		    fhc_arg->arg1, fhc_arg->arg2);

		if (ret != DDI_SUCCESS)
			goto done;
	}

	/*
	 * Clear out a stale 'pending' or 'transmit' state in
	 * this device's ISM that might have been left from a
	 * previous session.
	 *
	 * Since all FHC interrupts are level interrupts, any
	 * real interrupting condition will immediately transition
	 * the ISM back to pending.
	 */
	*(softsp->intr_regs[ino].clear_reg) = ISM_IDLE;

	/*
	 * Program the mondo vector accordingly.  This MUST be the
	 * last thing we do.  Once we program the ino, the device
	 * may begin to interrupt.
	 */
	cpu_id = intr_dist_cpuid();

	tmp_mondo_vec = cpu_id << INR_PID_SHIFT;

	/* don't do this for fan because fan has a special control */
	if (ino == FHC_FANFAIL_INO)
		panic("fhc%d: enabling fanfail interrupt",
		    ddi_get_instance(dip));
	else
		tmp_mondo_vec |= IMR_VALID;

	DPRINTF(FHC_INTERRUPT_DEBUG,
	    ("Mondo 0x%x mapping reg: 0x%p", hdlp->ih_vector,
	    (void *)mondo_vec_reg));

	/* Store it in the hardware reg. */
	*mondo_vec_reg = tmp_mondo_vec;

	/* Read a FHC register to flush store buffers */
	tmpreg = *(softsp->id);
#ifdef lint
	tmpreg = tmpreg;
#endif

done:
	return (ret);
}

/*
 * remove_intrspec - Remove an interrupt specification.
 */
static void
fhc_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	volatile uint_t *mondo_vec_reg;
	volatile uint_t tmpreg;
	int i;
	struct fhc_soft_state *softsp = (struct fhc_soft_state *)
	    ddi_get_soft_state(fhcp, ddi_get_instance(dip));
	int ino;

	/* Xlate the interrupt */
	fhc_xlate_intrs(hdlp,
	    (softsp->list->sc.board << BD_IVINTR_SHFT));

	/* get the mondo number */
	ino = FHC_INO(hdlp->ih_vector);

	if (ino == FHC_UART_INO) {
		int intr_found = 0;

		/* Lock the poll_list first */
		mutex_enter(&softsp->poll_list_lock);

		/*
		 * Find which entry in the poll list belongs to this
		 * intrspec.
		 */
		for (i = 0; i < MAX_ZS_CNT; i++) {
			if (softsp->poll_list[i].child == rdip &&
			    softsp->poll_list[i].inum == hdlp->ih_inum) {
				softsp->poll_list[i].funcp = NULL;
				intr_found++;
			}
		}

		/* If we did not find an entry, then we have a problem */
		if (!intr_found) {
			cmn_err(CE_WARN, "fhc%d: Intrspec not found in"
			    " poll list", ddi_get_instance(dip));
			mutex_exit(&softsp->poll_list_lock);
			goto done;
		}

		/*
		 * If we have removed all active entries for the poll
		 * list, then we have to disable interupts at this point.
		 */
		if ((softsp->poll_list[0].funcp == NULL) &&
		    (softsp->poll_list[1].funcp == NULL)) {
			mondo_vec_reg =
			    softsp->intr_regs[FHC_UART_INO].mapping_reg;
			*mondo_vec_reg &= ~IMR_VALID;

			/* flush the hardware buffers */
			tmpreg = *(softsp->ctrl);

			/* Eliminate the particular handler from the system. */
			i_ddi_rem_ivintr(hdlp);
		}

		mutex_exit(&softsp->poll_list_lock);
	} else {
		int32_t i;


		for (i = 0; i < FHC_MAX_INO; i++)
			if (softsp->intr_list[i]->child == rdip &&
			    softsp->intr_list[i]->inum == hdlp->ih_inum)
				break;

		if (i >= FHC_MAX_INO)
			goto done;

		mondo_vec_reg = softsp->intr_list[i]->mapping_reg;

		/* Turn off the valid bit in the mapping register. */
		/* XXX what about FHC_FANFAIL owned imr? */
		*mondo_vec_reg &= ~IMR_VALID;

		/* flush the hardware store buffers */
		tmpreg = *(softsp->id);
#ifdef lint
		tmpreg = tmpreg;
#endif

		/* Eliminate the particular handler from the system. */
		i_ddi_rem_ivintr(hdlp);

		kmem_free(softsp->intr_list[i],
		    sizeof (struct fhc_wrapper_arg));
		softsp->intr_list[i] = 0;
	}

done:
	;
}

/* new intr_ops structure */
static int
fhc_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int	ret = DDI_SUCCESS;

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_LEVEL;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		if (hdlp->ih_pri == 0) {
			struct fhc_soft_state *softsp =
			    (struct fhc_soft_state *)ddi_get_soft_state(fhcp,
			    ddi_get_instance(dip));

			/* Xlate the interrupt */
			fhc_xlate_intrs(hdlp,
			    (softsp->list->sc.board << BD_IVINTR_SHFT));
		}

		*(int *)result = hdlp->ih_pri;
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		ret = fhc_add_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_REMISR:
		fhc_remove_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_ENABLE:
	case DDI_INTROP_DISABLE:
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		break;
	case DDI_INTROP_SETCAP:
	case DDI_INTROP_SETMASK:
	case DDI_INTROP_CLRMASK:
	case DDI_INTROP_GETPENDING:
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		/* only support fixed interrupts */
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;
		break;
	default:
		ret = i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result);
		break;
	}

	return (ret);
}

/*
 * FHC Control Ops routine
 *
 * Requests handled here:
 *	DDI_CTLOPS_INITCHILD	see impl_ddi_sunbus_initchild() for details
 *	DDI_CTLOPS_UNINITCHILD	see fhc_uninit_child() for details
 *	DDI_CTLOPS_REPORTDEV	TODO - need to implement this.
 */
static int
fhc_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t op, void *arg, void *result)
{

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		DPRINTF(FHC_CTLOPS_DEBUG, ("DDI_CTLOPS_INITCHILD\n"));
		return (impl_ddi_sunbus_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		impl_ddi_sunbus_removechild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REPORTDEV:
		/*
		 * TODO - Figure out what makes sense to report here.
		 */
		return (DDI_SUCCESS);

	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		return (fhc_ctlops_peekpoke(op, (peekpoke_ctlops_t *)arg,
		    result));

	default:
		return (ddi_ctlops(dip, rdip, op, arg, result));
	}
}


/*
 * We're prepared to claim that the interrupt string is in
 * the form of a list of <FHCintr> specifications, or we're dealing
 * with on-board devices and we have an interrupt_number property which
 * gives us our mondo number.
 * Translate the mondos into fhcintrspecs.
 */
/* ARGSUSED */
static void
fhc_xlate_intrs(ddi_intr_handle_impl_t *hdlp, uint32_t ign)
{
	uint32_t mondo;

	mondo = hdlp->ih_vector;

	hdlp->ih_vector = (mondo | ign);
	if (hdlp->ih_pri == 0)
		hdlp->ih_pri = fhc_int_priorities[FHC_INO(mondo)];
}

static int
fhc_ctlops_peekpoke(ddi_ctl_enum_t cmd, peekpoke_ctlops_t *in_args,
    void *result)
{
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	/* No safe access except for peek/poke is supported. */
	if (in_args->handle != NULL)
		return (DDI_FAILURE);

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		if (cmd == DDI_CTLOPS_POKE) {
			otd.ot_trampoline = (uintptr_t)&poke_fault;
			err = do_poke(in_args->size, (void *)in_args->dev_addr,
			    (void *)in_args->host_addr);
		} else {
			otd.ot_trampoline = (uintptr_t)&peek_fault;
			err = do_peek(in_args->size, (void *)in_args->dev_addr,
			    (void *)in_args->host_addr);
			result = (void *)in_args->host_addr;
		}
		otd.ot_trampoline = tramp;
	} else
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();

	return (err);
}

/*
 * This function initializes the temperature arrays for use. All
 * temperatures are set in to invalid value to start.
 */
void
init_temp_arrays(struct temp_stats *envstat)
{
	int i;

	envstat->index = 0;

	for (i = 0; i < L1_SZ; i++) {
		envstat->l1[i] = NA_TEMP;
	}

	for (i = 0; i < L2_SZ; i++) {
		envstat->l2[i] = NA_TEMP;
	}

	for (i = 0; i < L3_SZ; i++) {
		envstat->l3[i] = NA_TEMP;
	}

	for (i = 0; i < L4_SZ; i++) {
		envstat->l4[i] = NA_TEMP;
	}

	for (i = 0; i < L5_SZ; i++) {
		envstat->l5[i] = NA_TEMP;
	}

	envstat->max = NA_TEMP;
	envstat->min = NA_TEMP;
	envstat->trend = TREND_UNKNOWN;
	envstat->version = TEMP_KSTAT_VERSION;
	envstat->override = NA_TEMP;
}

/* Inhibit warning messages below this temperature, eg for CPU poweron. */
static uint_t fhc_cpu_warning_temp_threshold = FHC_CPU_WARNING_TEMP_THRESHOLD;

/*
 * This function manages the temperature history in the temperature
 * statistics buffer passed in. It calls the temperature calibration
 * routines and maintains the time averaged temperature data.
 */
void
update_temp(dev_info_t *pdip, struct temp_stats *envstat, uchar_t value)
{
	uint_t index;		    /* The absolute temperature counter */
	uint_t tmp_index;	    /* temp index into upper level array */
	int count;		    /* Count of non-zero values in array */
	int total;		    /* sum total of non-zero values in array */
	short real_temp;	    /* calibrated temperature */
	int i;
	struct fhc_soft_state *softsp;
	char buffer[256];	    /* buffer for warning of overtemp */
	enum temp_state temp_state; /* Temperature state */

	/*
	 * NOTE: This global counter is not protected since we're called
	 * serially for each board.
	 */
	static int shutdown_msg = 0; /* Flag if shutdown warning issued */

	/* determine soft state pointer of parent */
	softsp = ddi_get_soft_state(fhcp, ddi_get_instance(pdip));

	envstat->index++;
	index = envstat->index;

	/*
	 * You need to update the level 5 intervals first, since
	 * they are based on the data from the level 4 intervals,
	 * and so on, down to the level 1 intervals.
	 */

	/* update the level 5 intervals if it is time */
	if (((tmp_index = L5_INDEX(index)) > 0) && (L5_REM(index) == 0)) {
		/* Generate the index within the level 5 array */
		tmp_index -= 1;		/* decrement by 1 for indexing */
		tmp_index = tmp_index % L5_SZ;

		/* take an average of the level 4 array */
		for (i = 0, count = 0, total = 0; i < L4_SZ; i++) {
			/* Do not include zero values in average */
			if (envstat->l4[i] != NA_TEMP) {
				total += (int)envstat->l4[i];
				count++;
			}
		}

		/*
		 * If there were any level 4 data points to average,
		 * do so.
		 */
		if (count != 0) {
			envstat->l5[tmp_index] = total/count;
		} else {
			envstat->l5[tmp_index] = NA_TEMP;
		}
	}

	/* update the level 4 intervals if it is time */
	if (((tmp_index = L4_INDEX(index)) > 0) && (L4_REM(index) == 0)) {
		/* Generate the index within the level 4 array */
		tmp_index -= 1;		/* decrement by 1 for indexing */
		tmp_index = tmp_index % L4_SZ;

		/* take an average of the level 3 array */
		for (i = 0, count = 0, total = 0; i < L3_SZ; i++) {
			/* Do not include zero values in average */
			if (envstat->l3[i] != NA_TEMP) {
				total += (int)envstat->l3[i];
				count++;
			}
		}

		/*
		 * If there were any level 3 data points to average,
		 * do so.
		 */
		if (count != 0) {
			envstat->l4[tmp_index] = total/count;
		} else {
			envstat->l4[tmp_index] = NA_TEMP;
		}
	}

	/* update the level 3 intervals if it is time */
	if (((tmp_index = L3_INDEX(index)) > 0) && (L3_REM(index) == 0)) {
		/* Generate the index within the level 3 array */
		tmp_index -= 1;		/* decrement by 1 for indexing */
		tmp_index = tmp_index % L3_SZ;

		/* take an average of the level 2 array */
		for (i = 0, count = 0, total = 0; i < L2_SZ; i++) {
			/* Do not include zero values in average */
			if (envstat->l2[i] != NA_TEMP) {
				total += (int)envstat->l2[i];
				count++;
			}
		}

		/*
		 * If there were any level 2 data points to average,
		 * do so.
		 */
		if (count != 0) {
			envstat->l3[tmp_index] = total/count;
		} else {
			envstat->l3[tmp_index] = NA_TEMP;
		}
	}

	/* update the level 2 intervals if it is time */
	if (((tmp_index = L2_INDEX(index)) > 0) && (L2_REM(index) == 0)) {
		/* Generate the index within the level 2 array */
		tmp_index -= 1;		/* decrement by 1 for indexing */
		tmp_index = tmp_index % L2_SZ;

		/* take an average of the level 1 array */
		for (i = 0, count = 0, total = 0; i < L1_SZ; i++) {
			/* Do not include zero values in average */
			if (envstat->l1[i] != NA_TEMP) {
				total += (int)envstat->l1[i];
				count++;
			}
		}

		/*
		 * If there were any level 1 data points to average,
		 * do so.
		 */
		if (count != 0) {
			envstat->l2[tmp_index] = total/count;
		} else {
			envstat->l2[tmp_index] = NA_TEMP;
		}
	}

	/* determine the current temperature in degrees Celcius */
	if (envstat->override != NA_TEMP) {
		/* use override temperature for this board */
		real_temp = envstat->override;
	} else {
		/* Run the calibration function using this board type */
		real_temp = calibrate_temp(softsp->list->sc.type, value,
		    softsp->list->sc.ac_compid);
	}

	envstat->l1[index % L1_SZ] = real_temp;

	/* check if the temperature state for this device needs to change */
	temp_state = get_temp_state(softsp->list->sc.type, real_temp,
	    softsp->list->sc.board);

	/* has the state changed? Then get the board string ready */
	if (temp_state != envstat->state) {
		int board = softsp->list->sc.board;
		enum board_type type = softsp->list->sc.type;

		build_bd_display_str(buffer, type, board);

		if (temp_state > envstat->state) {
			if (envstat->state == TEMP_OK) {
				if (type == CLOCK_BOARD) {
					reg_fault(0, FT_OVERTEMP, FT_SYSTEM);
				} else {
					reg_fault(board, FT_OVERTEMP,
					    FT_BOARD);
				}
			}

			/* heating up, change state now */
			envstat->temp_cnt = 0;
			envstat->state = temp_state;

			if (temp_state == TEMP_WARN) {
				/* now warn the user of the problem */
				cmn_err(CE_WARN,
				    "%s is warm (temperature: %dC). "
				    "Please check system cooling", buffer,
				    real_temp);
				fhc_bd_update(board, SYSC_EVT_BD_OVERTEMP);
				if (temperature_chamber == -1)
					temperature_chamber =
					    check_for_chamber();
			} else if (temp_state == TEMP_DANGER) {
				cmn_err(CE_WARN,
				    "%s is very hot (temperature: %dC)",
				    buffer, real_temp);

				envstat->shutdown_cnt = 1;
				if (temperature_chamber == -1)
					temperature_chamber =
					    check_for_chamber();
				if ((temperature_chamber == 0) &&
				    enable_overtemp_powerdown) {
					/*
					 * NOTE: The "%d seconds" is not
					 * necessarily accurate in the case
					 * where we have multiple boards
					 * overheating and subsequently cooling
					 * down.
					 */
					if (shutdown_msg == 0) {
						cmn_err(CE_WARN, "System "
						    "shutdown scheduled "
						    "in %d seconds due to "
						    "over-temperature "
						    "condition on %s",
						    SHUTDOWN_TIMEOUT_SEC,
						    buffer);
					}
					shutdown_msg++;
				}
			}

			/*
			 * If this is a cpu board, power them off.
			 */
			if (temperature_chamber == 0) {
				mutex_enter(&cpu_lock);
				(void) fhc_board_poweroffcpus(board, NULL,
				    CPU_FORCED);
				mutex_exit(&cpu_lock);
			}
		} else if (temp_state < envstat->state) {
			/*
			 * Avert the sigpower that would
			 * otherwise be sent to init.
			 */
			envstat->shutdown_cnt = 0;

			/* cooling down, use state counter */
			if (envstat->temp_cnt == 0) {
				envstat->temp_cnt = TEMP_STATE_COUNT;
			} else if (--envstat->temp_cnt == 0) {
				if (temp_state == TEMP_WARN) {
					cmn_err(CE_NOTE,
					    "%s is cooling "
					    "(temperature: %dC)", buffer,
					    real_temp);

				} else if (temp_state == TEMP_OK) {
					cmn_err(CE_NOTE,
					    "%s has cooled down "
					    "(temperature: %dC), system OK",
					    buffer, real_temp);

					if (type == CLOCK_BOARD) {
						clear_fault(0, FT_OVERTEMP,
						    FT_SYSTEM);
					} else {
						clear_fault(board, FT_OVERTEMP,
						    FT_BOARD);
					}
				}

				/*
				 * If we just came out of TEMP_DANGER, and
				 * a warning was issued about shutting down,
				 * let the user know it's been cancelled
				 */
				if (envstat->state == TEMP_DANGER &&
				    (temperature_chamber == 0) &&
				    enable_overtemp_powerdown &&
				    (powerdown_started == 0) &&
				    (--shutdown_msg == 0)) {
					cmn_err(CE_NOTE, "System "
					    "shutdown due to over-"
					    "temperature "
					    "condition cancelled");
				}
				envstat->state = temp_state;

				fhc_bd_update(board, SYSC_EVT_BD_TEMP_OK);
			}
		}
	} else {
		envstat->temp_cnt = 0;

		if (temp_state == TEMP_DANGER) {
			if (temperature_chamber == -1) {
				temperature_chamber = check_for_chamber();
			}

			if ((envstat->shutdown_cnt++ >= SHUTDOWN_COUNT) &&
			    (temperature_chamber == 0) &&
			    enable_overtemp_powerdown &&
			    (powerdown_started == 0)) {
				powerdown_started = 1;

				/* the system is still too hot */
				build_bd_display_str(buffer,
				    softsp->list->sc.type,
				    softsp->list->sc.board);

				cmn_err(CE_WARN, "%s still too hot "
				    "(temperature: %dC)."
				    " Overtemp shutdown started", buffer,
				    real_temp);

				fhc_reboot();
			}
		}
	}

	/* update the maximum and minimum temperatures if necessary */
	if ((envstat->max == NA_TEMP) || (real_temp > envstat->max)) {
		envstat->max = real_temp;
	}

	if ((envstat->min == NA_TEMP) || (real_temp < envstat->min)) {
		envstat->min = real_temp;
	}

	/*
	 * Update the temperature trend.  Currently, the temperature
	 * trend algorithm is based on the level 2 stats.  So, we
	 * only need to run every time the level 2 stats get updated.
	 */
	if (((tmp_index = L2_INDEX(index)) > 0) && (L2_REM(index) == 0))  {
		enum board_type type = softsp->list->sc.type;

		envstat->trend = temp_trend(envstat);

		/* Issue a warning if the temperature is rising rapidly. */
		/* For CPU boards, don't warn if CPUs just powered on. */
		if (envstat->trend == TREND_RAPID_RISE &&
		    (type != CPU_BOARD || real_temp >
		    fhc_cpu_warning_temp_threshold))  {
			int board = softsp->list->sc.board;

			build_bd_display_str(buffer, type, board);
			cmn_err(CE_WARN, "%s temperature is rising rapidly!  "
			    "Current temperature is %dC", buffer,
			    real_temp);
		}
	}
}

#define	PREV_L2_INDEX(x)    ((x) ? ((x) - 1) : (L2_SZ - 1))

/*
 * This routine determines if the temp of the device passed in is heating
 * up, cooling down, or staying stable.
 */
enum temp_trend
temp_trend(struct temp_stats *tempstat)
{
	int		ii;
	uint_t		curr_index;
	int		curr_temp;
	uint_t		prev_index;
	int		prev_temp;
	int		trail_temp;
	int		delta;
	int		read_cnt;
	enum temp_trend	result = TREND_STABLE;

	if (tempstat == NULL)
		return (TREND_UNKNOWN);

	curr_index = (L2_INDEX(tempstat->index) - 1) % L2_SZ;
	curr_temp = tempstat->l2[curr_index];

	/* Count how many temperature readings are available */
	prev_index = curr_index;
	for (read_cnt = 0; read_cnt < L2_SZ - 1; read_cnt++) {
		if (tempstat->l2[prev_index] == NA_TEMP)
			break;
		prev_index = PREV_L2_INDEX(prev_index);
	}

	switch (read_cnt) {
	case 0:
	case 1:
		result = TREND_UNKNOWN;
		break;

	default:
		delta = curr_temp - tempstat->l2[PREV_L2_INDEX(curr_index)];
		prev_index = curr_index;
		trail_temp = prev_temp = curr_temp;
		if (delta >= RAPID_RISE_THRESH) {	    /* rapid rise? */
			result = TREND_RAPID_RISE;
		} else if (delta > 0) {			    /* rise? */
			for (ii = 1; ii < read_cnt; ii++) {
				prev_index = PREV_L2_INDEX(prev_index);
				prev_temp = tempstat->l2[prev_index];
				if (prev_temp > trail_temp) {
					break;
				}
				trail_temp = prev_temp;
				if (prev_temp <= curr_temp - NOISE_THRESH) {
					result = TREND_RISE;
					break;
				}
			}
		} else if (delta <= -RAPID_FALL_THRESH) {   /* rapid fall? */
			result = TREND_RAPID_FALL;
		} else if (delta < 0) {			    /* fall? */
			for (ii = 1; ii < read_cnt; ii++) {
				prev_index = PREV_L2_INDEX(prev_index);
				prev_temp = tempstat->l2[prev_index];
				if (prev_temp < trail_temp) {
					break;
				}
				trail_temp = prev_temp;
				if (prev_temp >= curr_temp + NOISE_THRESH) {
					result = TREND_FALL;
					break;
				}
			}
		}
	}
	return (result);
}

/*
 * Reboot the system if we can, otherwise attempt a power down
 */
void
fhc_reboot(void)
{
	proc_t *initpp;

	/* send a SIGPWR to init process */
	mutex_enter(&pidlock);
	initpp = prfind(P_INITPID);
	mutex_exit(&pidlock);

	/*
	 * If we're still booting and init(1) isn't
	 * set up yet, simply halt.
	 */
	if (initpp != NULL) {
		psignal(initpp, SIGFPE);	/* init 6 */
	} else {
		power_down("Environmental Shutdown");
		halt("Power off the System");
	}
}

int
overtemp_kstat_update(kstat_t *ksp, int rw)
{
	struct temp_stats *tempstat;
	char *kstatp;
	int i;

	kstatp = (char *)ksp->ks_data;
	tempstat = (struct temp_stats *)ksp->ks_private;

	/*
	 * Kstat reads are used to retrieve the current system temperature
	 * history. Kstat writes are used to reset the max and min
	 * temperatures.
	 */
	if (rw == KSTAT_WRITE) {
		short max;	/* temporary copy of max temperature */
		short min;	/* temporary copy of min temperature */

		/*
		 * search for and reset the max and min to the current
		 * array contents. Old max and min values will get
		 * averaged out as they move into the higher level arrays.
		 */
		max = tempstat->l1[0];
		min = tempstat->l1[0];

		/* Pull the max and min from Level 1 array */
		for (i = 0; i < L1_SZ; i++) {
			if ((tempstat->l1[i] != NA_TEMP) &&
			    (tempstat->l1[i] > max)) {
				max = tempstat->l1[i];
			}

			if ((tempstat->l1[i] != NA_TEMP) &&
			    (tempstat->l1[i] < min)) {
				min = tempstat->l1[i];
			}
		}

		/* Pull the max and min from Level 2 array */
		for (i = 0; i < L2_SZ; i++) {
			if ((tempstat->l2[i] != NA_TEMP) &&
			    (tempstat->l2[i] > max)) {
				max = tempstat->l2[i];
			}

			if ((tempstat->l2[i] != NA_TEMP) &&
			    (tempstat->l2[i] < min)) {
				min = tempstat->l2[i];
			}
		}

		/* Pull the max and min from Level 3 array */
		for (i = 0; i < L3_SZ; i++) {
			if ((tempstat->l3[i] != NA_TEMP) &&
			    (tempstat->l3[i] > max)) {
				max = tempstat->l3[i];
			}

			if ((tempstat->l3[i] != NA_TEMP) &&
			    (tempstat->l3[i] < min)) {
				min = tempstat->l3[i];
			}
		}

		/* Pull the max and min from Level 4 array */
		for (i = 0; i < L4_SZ; i++) {
			if ((tempstat->l4[i] != NA_TEMP) &&
			    (tempstat->l4[i] > max)) {
				max = tempstat->l4[i];
			}

			if ((tempstat->l4[i] != NA_TEMP) &&
			    (tempstat->l4[i] < min)) {
				min = tempstat->l4[i];
			}
		}

		/* Pull the max and min from Level 5 array */
		for (i = 0; i < L5_SZ; i++) {
			if ((tempstat->l5[i] != NA_TEMP) &&
			    (tempstat->l5[i] > max)) {
				max = tempstat->l5[i];
			}

			if ((tempstat->l5[i] != NA_TEMP) &&
			    (tempstat->l5[i] < min)) {
				min = tempstat->l5[i];
			}
		}
	} else {
		/*
		 * copy the temperature history buffer into the
		 * kstat structure.
		 */
		bcopy(tempstat, kstatp, sizeof (struct temp_stats));
	}
	return (0);
}

int
temp_override_kstat_update(kstat_t *ksp, int rw)
{
	short *over;
	short *kstatp;

	kstatp = (short *)ksp->ks_data;
	over = (short *)ksp->ks_private;

	/*
	 * Kstat reads are used to get the temperature override setting.
	 * Kstat writes are used to set the temperature override setting.
	 */
	if (rw == KSTAT_WRITE) {
		*over = *kstatp;
	} else {
		*kstatp = *over;
	}
	return (0);
}

/*
 * This function uses the calibration tables at the beginning of this file
 * to lookup the actual temperature of the thermistor in degrees Celcius.
 * If the measurement is out of the bounds of the acceptable values, the
 * closest boundary value is used instead.
 */
static short
calibrate_temp(enum board_type type, uchar_t temp, uint_t ac_comp)
{
	short result = NA_TEMP;

	if (dont_calibrate == 1) {
		return ((short)temp);
	}

	switch (type) {
	case CPU_BOARD:
		/*
		 * If AC chip revision is >= 4 or if it is unitialized,
		 * then use the new calibration tables.
		 */
		if ((CHIP_REV(ac_comp) >= 4) || (CHIP_REV(ac_comp) == 0)) {
			if (temp >= CPU2_MX_CNT) {
				result = cpu2_table[CPU2_MX_CNT-1];
			} else {
				result = cpu2_table[temp];
			}
		} else {
			if (temp >= CPU_MX_CNT) {
				result = cpu_table[CPU_MX_CNT-1];
			} else {
				result = cpu_table[temp];
			}
		}
		break;

	case IO_2SBUS_BOARD:
	case IO_SBUS_FFB_BOARD:
	case IO_PCI_BOARD:
	case IO_2SBUS_SOCPLUS_BOARD:
	case IO_SBUS_FFB_SOCPLUS_BOARD:
		if (temp < IO_MN_CNT) {
			result = io_table[IO_MN_CNT];
		} else if (temp >= IO_MX_CNT) {
			result = io_table[IO_MX_CNT-1];
		} else {
			result = io_table[temp];
		}
		break;

	case CLOCK_BOARD:
		if (temp < CLK_MN_CNT) {
			result = clock_table[CLK_MN_CNT];
		} else if (temp >= CLK_MX_CNT) {
			result = clock_table[CLK_MX_CNT-1];
		} else {
			result = clock_table[temp];
		}
		break;

	default:
		break;
	}

	return (result);
}

/*
 * Determine the temperature state of this board based on its type and
 * the actual temperature in degrees Celcius.
 */
static enum temp_state
get_temp_state(enum board_type type, short temp, int board)
{
	enum temp_state state = TEMP_OK;
	short warn_limit;
	short danger_limit;
	struct cpu *cpa, *cpb;

	switch (type) {
	case CPU_BOARD:
		warn_limit = cpu_warn_temp;
		danger_limit = cpu_danger_temp;

		/*
		 * For CPU boards with frequency >= 400 MHZ,
		 * temperature zones are different.
		 */

		mutex_enter(&cpu_lock);

		if ((cpa = cpu_get(FHC_BOARD2CPU_A(board))) != NULL) {
			if ((cpa->cpu_type_info.pi_clock) >= 400) {
				warn_limit = cpu_warn_temp_4x;
				danger_limit = cpu_danger_temp_4x;
			}
		}
		if ((cpb = cpu_get(FHC_BOARD2CPU_B(board))) != NULL) {
			if ((cpb->cpu_type_info.pi_clock) >= 400) {
				warn_limit = cpu_warn_temp_4x;
				danger_limit = cpu_danger_temp_4x;
			}
		}

		mutex_exit(&cpu_lock);

		break;

	case IO_2SBUS_BOARD:
	case IO_SBUS_FFB_BOARD:
	case IO_PCI_BOARD:
	case IO_2SBUS_SOCPLUS_BOARD:
	case IO_SBUS_FFB_SOCPLUS_BOARD:
		warn_limit = io_warn_temp;
		danger_limit = io_danger_temp;
		break;

	case CLOCK_BOARD:
		warn_limit = clk_warn_temp;
		danger_limit = clk_danger_temp;
		break;

	case UNINIT_BOARD:
	case UNKNOWN_BOARD:
	case MEM_BOARD:
	default:
		warn_limit = dft_warn_temp;
		danger_limit = dft_danger_temp;
		break;
	}

	if (temp >= danger_limit) {
		state = TEMP_DANGER;
	} else if (temp >= warn_limit) {
		state = TEMP_WARN;
	}

	return (state);
}

static void
fhc_add_kstats(struct fhc_soft_state *softsp)
{
	struct kstat *fhc_ksp;
	struct fhc_kstat *fhc_named_ksp;

	if ((fhc_ksp = kstat_create("unix", softsp->list->sc.board,
	    FHC_KSTAT_NAME, "misc", KSTAT_TYPE_NAMED,
	    sizeof (struct fhc_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "fhc%d kstat_create failed",
		    ddi_get_instance(softsp->dip));
		return;
	}

	fhc_named_ksp = (struct fhc_kstat *)(fhc_ksp->ks_data);

	/* initialize the named kstats */
	kstat_named_init(&fhc_named_ksp->csr,
	    CSR_KSTAT_NAMED,
	    KSTAT_DATA_UINT32);

	kstat_named_init(&fhc_named_ksp->bsr,
	    BSR_KSTAT_NAMED,
	    KSTAT_DATA_UINT32);

	fhc_ksp->ks_update = fhc_kstat_update;
	fhc_ksp->ks_private = (void *)softsp;
	softsp->fhc_ksp = fhc_ksp;
	kstat_install(fhc_ksp);
}

static int
fhc_kstat_update(kstat_t *ksp, int rw)
{
	struct fhc_kstat *fhcksp;
	struct fhc_soft_state *softsp;

	fhcksp = (struct fhc_kstat *)ksp->ks_data;
	softsp = (struct fhc_soft_state *)ksp->ks_private;

	/* this is a read-only kstat. Bail out on a write */
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		/*
		 * copy the current state of the hardware into the
		 * kstat structure.
		 */
		fhcksp->csr.value.ui32 = *softsp->ctrl;
		fhcksp->bsr.value.ui32 = *softsp->bsr;
	}
	return (0);
}

static int
cpu_on_board(int board)
{
	int upa_a = board << 1;
	int upa_b = (board << 1) + 1;

	if ((cpunodes[upa_a].nodeid != 0) ||
	    (cpunodes[upa_b].nodeid != 0)) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * This function uses the board list and toggles the OS green board
 * LED. The mask input tells which bit fields are being modified,
 * and the value input tells the states of the bits.
 */
void
update_board_leds(fhc_bd_t *board, uint_t mask, uint_t value)
{
	volatile uint_t temp;

	ASSERT(fhc_bdlist_locked());

	/* mask off mask and value for only the LED bits */
	mask &= (FHC_LED_LEFT|FHC_LED_MID|FHC_LED_RIGHT);
	value &= (FHC_LED_LEFT|FHC_LED_MID|FHC_LED_RIGHT);

	if (board != NULL) {
		mutex_enter(&board->softsp->ctrl_lock);

		/* read the current register state */
		temp = *board->softsp->ctrl;

		/*
		 * The EPDA bits are special since the register is
		 * special.  We don't want to set them, since setting
		 * the bits on a shutdown cpu keeps the cpu permanently
		 * powered off.  Also, the CSR_SYNC bit must always be
		 * set to 0 as it is an OBP semaphore that is expected to
		 * be clear for cpu restart.
		 */
		temp &= ~(FHC_CSR_SYNC | FHC_EPDA_OFF | FHC_EPDB_OFF);

		/* mask off the bits to change */
		temp &= ~mask;

		/* or in the new values of the bits. */
		temp |= value;

		/* update the register */
		*board->softsp->ctrl = temp;

		/* flush the hardware registers */
		temp = *board->softsp->ctrl;
#ifdef lint
		temp = temp;
#endif

		mutex_exit(&board->softsp->ctrl_lock);
	}
}

static int
check_for_chamber(void)
{
	int chamber = 0;
	dev_info_t *options_dip;
	pnode_t options_node_id;
	int mfgmode_len;
	int retval;
	char *mfgmode;

	/*
	 * The operator can disable overtemp powerdown from /etc/system or
	 * boot -h.
	 */
	if (!enable_overtemp_powerdown) {
		cmn_err(CE_WARN, "Operator has disabled overtemp powerdown");
		return (1);
	}

	/*
	 * An OBP option, 'mfg-mode' is being used to inform us as to
	 * whether we are in an enviromental chamber. It exists in
	 * the 'options' node. This is where all OBP 'setenv' (eeprom)
	 * parameters live.
	 */
	if ((options_dip = ddi_find_devinfo("options", -1, 0)) != NULL) {
		options_node_id = (pnode_t)ddi_get_nodeid(options_dip);
		mfgmode_len = prom_getproplen(options_node_id, "mfg-mode");
		if (mfgmode_len == -1) {
			return (chamber);
		}
		mfgmode = kmem_alloc(mfgmode_len+1, KM_SLEEP);

		retval = prom_getprop(options_node_id, "mfg-mode", mfgmode);
		if (retval != -1) {
			mfgmode[retval] = 0;
			if (strcmp(mfgmode, CHAMBER_VALUE) == 0) {
				chamber = 1;
				cmn_err(CE_WARN, "System in Temperature"
				    " Chamber Mode. Overtemperature"
				    " Shutdown disabled");
			}
		}
		kmem_free(mfgmode, mfgmode_len+1);
	}
	return (chamber);
}

static void
build_bd_display_str(char *buffer, enum board_type type, int board)
{
	if (buffer == NULL) {
		return;
	}

	/* fill in board type to display */
	switch (type) {
	case UNINIT_BOARD:
		(void) sprintf(buffer, "Uninitialized Board type board %d",
		    board);
		break;

	case UNKNOWN_BOARD:
		(void) sprintf(buffer, "Unknown Board type board %d", board);
		break;

	case CPU_BOARD:
	case MEM_BOARD:
		(void) sprintf(buffer, "CPU/Memory board %d", board);
		break;

	case IO_2SBUS_BOARD:
		(void) sprintf(buffer, "2 SBus IO board %d", board);
		break;

	case IO_SBUS_FFB_BOARD:
		(void) sprintf(buffer, "SBus FFB IO board %d", board);
		break;

	case IO_PCI_BOARD:
		(void) sprintf(buffer, "PCI IO board %d", board);
		break;

	case CLOCK_BOARD:
		(void) sprintf(buffer, "Clock board");
		break;

	case IO_2SBUS_SOCPLUS_BOARD:
		(void) sprintf(buffer, "2 SBus SOC+ IO board %d", board);
		break;

	case IO_SBUS_FFB_SOCPLUS_BOARD:
		(void) sprintf(buffer, "SBus FFB SOC+ IO board %d", board);
		break;

	default:
		(void) sprintf(buffer, "Unrecognized board type board %d",
		    board);
		break;
	}
}

void
fhc_intrdist(void *arg)
{
	struct fhc_soft_state *softsp;
	dev_info_t *dip = (dev_info_t *)arg;
	volatile uint_t *mondo_vec_reg;
	volatile uint_t *intr_state_reg;
	uint_t mondo_vec;
	uint_t tmp_reg;
	uint_t cpu_id;
	uint_t i;

	/* extract the soft state pointer */
	softsp = ddi_get_soft_state(fhcp, ddi_get_instance(dip));

	/*
	 * Loop through all the interrupt mapping registers and reprogram
	 * the target CPU for all valid registers.
	 */
	for (i = 0; i < FHC_MAX_INO; i++) {
		mondo_vec_reg = softsp->intr_regs[i].mapping_reg;
		intr_state_reg = softsp->intr_regs[i].clear_reg;

		if ((*mondo_vec_reg & IMR_VALID) == 0)
			continue;

		cpu_id = intr_dist_cpuid();

		/* Check the current target of the mondo */
		if (((*mondo_vec_reg & INR_PID_MASK) >> INR_PID_SHIFT) ==
		    cpu_id) {
			/* It is the same, don't reprogram */
			return;
		}

		/* So it's OK to reprogram the CPU target */

		/* turn off the valid bit */
		*mondo_vec_reg &= ~IMR_VALID;

		/* flush the hardware registers */
		tmp_reg = *softsp->id;

		/*
		 * wait for the state machine to idle. Do not loop on panic, so
		 * that system does not hang.
		 */
		while (((*intr_state_reg & INT_PENDING) == INT_PENDING) &&
		    !panicstr)
			;

		/* re-target the mondo and turn it on */
		mondo_vec = (cpu_id << INR_PID_SHIFT) | IMR_VALID;

		/* write it back to the hardware. */
		*mondo_vec_reg = mondo_vec;

		/* flush the hardware buffers. */
		tmp_reg = *(softsp->id);

#ifdef	lint
		tmp_reg = tmp_reg;
#endif	/* lint */
	}
}

/*
 * reg_fault
 *
 * This routine registers a fault in the fault list. If the fault
 * is unique (does not exist in fault list) then a new fault is
 * added to the fault list, with the appropriate structure elements
 * filled in.
 */
void
reg_fault(int unit, enum ft_type type, enum ft_class fclass)
{
	struct ft_link_list *list;	/* temporary list pointer */

	if (type >= ft_max_index) {
		cmn_err(CE_WARN, "Illegal Fault type %x", type);
		return;
	}

	mutex_enter(&ftlist_mutex);

	/* Search for the requested fault. If it already exists, return. */
	for (list = ft_list; list != NULL; list = list->next) {
		if ((list->f.unit == unit) && (list->f.type == type) &&
		    (list->f.fclass == fclass)) {
			mutex_exit(&ftlist_mutex);
			return;
		}
	}

	/* Allocate a new fault structure. */
	list = kmem_zalloc(sizeof (struct ft_link_list), KM_SLEEP);

	/* fill in the fault list elements */
	list->f.unit = unit;
	list->f.type = type;
	list->f.fclass = fclass;
	list->f.create_time = (time32_t)gethrestime_sec(); /* XX64 */
	(void) strncpy(list->f.msg, ft_str_table[type], MAX_FT_DESC);

	/* link it into the list. */
	list->next = ft_list;
	ft_list = list;

	/* Update the total fault count */
	ft_nfaults++;

	mutex_exit(&ftlist_mutex);
}

/*
 * clear_fault
 *
 * This routine finds the fault list entry specified by the caller,
 * deletes it from the fault list, and frees up the memory used for
 * the entry. If the requested fault is not found, it exits silently.
 */
void
clear_fault(int unit, enum ft_type type, enum ft_class fclass)
{
	struct ft_link_list *list;		/* temporary list pointer */
	struct ft_link_list **vect;

	mutex_enter(&ftlist_mutex);

	list = ft_list;
	vect = &ft_list;

	/*
	 * Search for the requested fault. If it exists, delete it
	 * and relink the fault list.
	 */
	for (; list != NULL; vect = &list->next, list = list->next) {
		if ((list->f.unit == unit) && (list->f.type == type) &&
		    (list->f.fclass == fclass)) {
			/* remove the item from the list */
			*vect = list->next;

			/* free the memory allocated */
			kmem_free(list, sizeof (struct ft_link_list));

			/* Update the total fault count */
			ft_nfaults--;
			break;
		}
	}
	mutex_exit(&ftlist_mutex);
}

/*
 * process_fault_list
 *
 * This routine walks the global fault list and updates the board list
 * with the current status of each Yellow LED. If any faults are found
 * in the system, then a non-zero value is returned. Else zero is returned.
 */
int
process_fault_list(void)
{
	int fault = 0;
	struct ft_link_list *ftlist;	/* fault list pointer */
	fhc_bd_t *bdlist;		/* board list pointer */

	/*
	 * Note on locking. The bdlist mutex is always acquired and
	 * held around the ftlist mutex when both are needed for an
	 * operation. This is to avoid deadlock.
	 */

	/* First lock the board list */
	(void) fhc_bdlist_lock(-1);

	/* Grab the fault list lock first */
	mutex_enter(&ftlist_mutex);

	/* clear the board list of all faults first */
	for (bdlist = fhc_bd_first(); bdlist; bdlist = fhc_bd_next(bdlist))
		bdlist->fault = 0;

	/* walk the fault list here */
	for (ftlist = ft_list; ftlist != NULL; ftlist = ftlist->next) {
		fault++;

		/*
		 * If this is a board level fault, find the board, The
		 * unit number for all board class faults must be the
		 * actual board number. The caller of reg_fault must
		 * ensure this for FT_BOARD class faults.
		 */
		if (ftlist->f.fclass == FT_BOARD) {
			/* Sanity check the board first */
			if (fhc_bd_valid(ftlist->f.unit)) {
				bdlist = fhc_bd(ftlist->f.unit);
				bdlist->fault = 1;
			} else {
				cmn_err(CE_WARN, "No board %d list entry found",
				    ftlist->f.unit);
			}
		}
	}

	/* now unlock the fault list */
	mutex_exit(&ftlist_mutex);

	/* unlock the board list before leaving */
	fhc_bdlist_unlock();

	return (fault);
}

/*
 * Add a new memloc to the database (and keep 'em sorted by PA)
 */
void
fhc_add_memloc(int board, uint64_t pa, uint_t size)
{
	struct fhc_memloc *p, **pp;
	uint_t ipa = pa >> FHC_MEMLOC_SHIFT;

	ASSERT(fhc_bdlist_locked());
	ASSERT((size & (size-1)) == 0);		/* size must be power of 2 */

	/* look for a comparable memloc (as long as new PA smaller) */
	for (p = fhc_base_memloc, pp = &fhc_base_memloc;
	    p != NULL; pp = &p->next, p = p->next) {
		/* have we passed our place in the sort? */
		if (ipa < p->pa) {
			break;
		}
	}
	p = kmem_alloc(sizeof (struct fhc_memloc), KM_SLEEP);
	p->next = *pp;
	p->board = board;
	p->pa = ipa;
	p->size = size;
#ifdef DEBUG_MEMDEC
	cmn_err(CE_NOTE, "fhc_add_memloc: adding %d 0x%x 0x%x",
	    p->board, p->pa, p->size);
#endif /* DEBUG_MEMDEC */
	*pp = p;
}

/*
 * Delete all memloc records for a board from the database
 */
void
fhc_del_memloc(int board)
{
	struct fhc_memloc *p, **pp;

	ASSERT(fhc_bdlist_locked());

	/* delete all entries that match board */
	pp = &fhc_base_memloc;
	while ((p = *pp) != NULL) {
		if (p->board == board) {
#ifdef DEBUG_MEMDEC
			cmn_err(CE_NOTE, "fhc_del_memloc: removing %d "
			    "0x%x 0x%x", board, p->pa, p->size);
#endif /* DEBUG_MEMDEC */
			*pp = p->next;
			kmem_free(p, sizeof (struct fhc_memloc));
		} else {
			pp = &(p->next);
		}
	}
}

/*
 * Find a physical address range of sufficient size and return a starting PA
 */
uint64_t
fhc_find_memloc_gap(uint_t size)
{
	struct fhc_memloc *p;
	uint_t base_pa = 0;
	uint_t mask = ~(size-1);

	ASSERT(fhc_bdlist_locked());
	ASSERT((size & (size-1)) == 0);		/* size must be power of 2 */

	/*
	 * walk the list of known memlocs and measure the 'gaps'.
	 * we will need a hole that can align the 'size' requested.
	 * (e.g. a 256mb bank needs to be on a 256mb boundary).
	 */
	for (p = fhc_base_memloc; p != NULL; p = p->next) {
		if (base_pa != (base_pa & mask))
			base_pa = (base_pa + size) & mask;
		if (base_pa + size <= p->pa)
			break;
		base_pa = p->pa + p->size;
	}

	/*
	 * At this point, we assume that base_pa is good enough.
	 */
	ASSERT((base_pa + size) <= FHC_MEMLOC_MAX);
	if (base_pa != (base_pa & mask))
		base_pa = (base_pa + size) & mask;	/* align */
	return ((uint64_t)base_pa << FHC_MEMLOC_SHIFT);
}

/*
 * This simple function to write the MCRs can only be used when
 * the contents of memory are not valid as there is a bug in the AC
 * ASIC concerning refresh.
 */
static void
fhc_write_mcrs(
	uint64_t cpa,
	uint64_t dpa0,
	uint64_t dpa1,
	uint64_t c,
	uint64_t d0,
	uint64_t d1)
{
	stdphysio(cpa, c & ~AC_CSR_REFEN);
	(void) lddphysio(cpa);
	if (GRP_SIZE_IS_SET(d0)) {
		stdphysio(dpa0, d0);
		(void) lddphysio(dpa0);
	}
	if (GRP_SIZE_IS_SET(d1)) {
		stdphysio(dpa1, d1);
		(void) lddphysio(dpa1);
	}
	stdphysio(cpa, c);
	(void) lddphysio(cpa);
}

/* compute the appropriate RASIZE for bank size */
static uint_t
fhc_cvt_size(uint64_t bsz)
{
	uint_t csz;

	csz = 0;
	bsz /= 64;
	while (bsz) {
		csz++;
		bsz /= 2;
	}
	csz /= 2;

	return (csz);
}

void
fhc_program_memory(int board, uint64_t pa)
{
	uint64_t cpa, dpa0, dpa1;
	uint64_t c, d0, d1;
	uint64_t b0_pa, b1_pa;
	uint64_t memdec0, memdec1;
	uint_t b0_size, b1_size;

	/* XXX gross hack to get to board via board number */
	cpa = 0x1c0f9000060ull + (board * 0x400000000ull);
#ifdef DEBUG_MEMDEC
	prom_printf("cpa = 0x%llx\n", cpa);
#endif /* DEBUG_MEMDEC */
	dpa0 = cpa + 0x10;
	dpa1 = cpa + 0x20;

/* assume size is set by connect */
	memdec0 = lddphysio(dpa0);
#ifdef DEBUG_MEMDEC
	prom_printf("memdec0 = 0x%llx\n", memdec0);
#endif /* DEBUG_MEMDEC */
	memdec1 = lddphysio(dpa1);
#ifdef DEBUG_MEMDEC
	prom_printf("memdec1 = 0x%llx\n", memdec1);
#endif /* DEBUG_MEMDEC */
	if (GRP_SIZE_IS_SET(memdec0)) {
		b0_size = GRP_SPANMB(memdec0);
	} else {
		b0_size = 0;
	}
	if (GRP_SIZE_IS_SET(memdec1)) {
		b1_size = GRP_SPANMB(memdec1);
	} else {
		b1_size = 0;
	}

	c = lddphysio(cpa);
#ifdef DEBUG_MEMDEC
	prom_printf("c = 0x%llx\n", c);
#endif /* DEBUG_MEMDEC */
	if (b0_size) {
		b0_pa = pa;
		d0 = SETUP_DECODE(b0_pa, b0_size, 0, 0);
		d0 |= AC_MEM_VALID;

		c &= ~0x7;
		c |= 0;
		c &= ~(0x7 << 8);
		c |= (fhc_cvt_size(b0_size) << 8);  /* match row size */
	} else {
		d0 = memdec0;
	}
	if (b1_size) {
		b1_pa = pa + 0x80000000ull; /* XXX 2gb */
		d1 = SETUP_DECODE(b1_pa, b1_size, 0, 0);
		d1 |= AC_MEM_VALID;

		c &= ~(0x7 << 3);
		c |= (0 << 3);
		c &= ~(0x7 << 11);
		c |= (fhc_cvt_size(b1_size) << 11); /* match row size */
	} else {
		d1 = memdec1;
	}
#ifdef DEBUG_MEMDEC
	prom_printf("c 0x%llx, d0 0x%llx, d1 0x%llx\n", c, d0, d1);
#endif /* DEBUG_MEMDEC */
	fhc_write_mcrs(cpa, dpa0, dpa1, c, d0, d1);
}

/*
 * Creates a variable sized virtual kstat with a snapshot routine in order
 * to pass the linked list fault list up to userland. Also creates a
 * virtual kstat to pass up the string table for faults.
 */
void
create_ft_kstats(int instance)
{
	struct kstat *ksp;

	ksp = kstat_create("unix", instance, FT_LIST_KSTAT_NAME, "misc",
	    KSTAT_TYPE_RAW, 1, KSTAT_FLAG_VIRTUAL|KSTAT_FLAG_VAR_SIZE);

	if (ksp != NULL) {
		ksp->ks_data = NULL;
		ksp->ks_update = ft_ks_update;
		ksp->ks_snapshot = ft_ks_snapshot;
		ksp->ks_data_size = 1;
		ksp->ks_lock = &ftlist_mutex;
		kstat_install(ksp);
	}
}

/*
 * This routine creates a snapshot of all the fault list data. It is
 * called by the kstat framework when a kstat read is done.
 */
static int
ft_ks_snapshot(struct kstat *ksp, void *buf, int rw)
{
	struct ft_link_list *ftlist;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	ksp->ks_snaptime = gethrtime();

	for (ftlist = ft_list; ftlist != NULL; ftlist = ftlist->next) {
		bcopy(&ftlist->f, buf, sizeof (struct ft_list));
		buf = ((struct ft_list *)buf) + 1;
	}
	return (0);
}

/*
 * Setup the kstat data size for the kstat framework. This is used in
 * conjunction with the ks_snapshot routine. This routine sets the size,
 * the kstat framework allocates the memory, and ks_shapshot does the
 * data transfer.
 */
static int
ft_ks_update(struct kstat *ksp, int rw)
{
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		if (ft_nfaults) {
			ksp->ks_data_size = ft_nfaults *
			    sizeof (struct ft_list);
		} else {
			ksp->ks_data_size = 1;
		}
	}

	return (0);
}

/*
 * Power off any cpus on the board.
 */
int
fhc_board_poweroffcpus(int board, char *errbuf, int cpu_flags)
{
	cpu_t *cpa, *cpb;
	enum board_type type;
	int error = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * what type of board are we dealing with?
	 */
	type = fhc_bd_type(board);

	switch (type) {
	case CPU_BOARD:

		/*
		 * the shutdown sequence will be:
		 *
		 * idle both cpus then shut them off.
		 * it looks like the hardware gets corrupted if one
		 * cpu is busy while the other is shutting down...
		 */

		if ((cpa = cpu_get(FHC_BOARD2CPU_A(board))) != NULL &&
		    cpu_is_active(cpa)) {
			if (!cpu_intr_on(cpa)) {
				cpu_intr_enable(cpa);
			}
			if ((error = cpu_offline(cpa, cpu_flags)) != 0) {
				cmn_err(CE_WARN,
				    "Processor %d failed to offline.",
				    cpa->cpu_id);
				if (errbuf != NULL) {
					(void) snprintf(errbuf, SYSC_OUTPUT_LEN,
					    "processor %d failed to offline",
					    cpa->cpu_id);
				}
			}
		}

		if (error == 0 &&
		    (cpb = cpu_get(FHC_BOARD2CPU_B(board))) != NULL &&
		    cpu_is_active(cpb)) {
			if (!cpu_intr_on(cpb)) {
				cpu_intr_enable(cpb);
			}
			if ((error = cpu_offline(cpb, cpu_flags)) != 0) {
				cmn_err(CE_WARN,
				    "Processor %d failed to offline.",
				    cpb->cpu_id);

				if (errbuf != NULL) {
					(void) snprintf(errbuf, SYSC_OUTPUT_LEN,
					    "processor %d failed to offline",
					    cpb->cpu_id);
				}
			}
		}

		if (error == 0 && cpa != NULL && cpu_is_offline(cpa)) {
			if ((error = cpu_poweroff(cpa)) != 0) {
				cmn_err(CE_WARN,
				    "Processor %d failed to power off.",
				    cpa->cpu_id);
				if (errbuf != NULL) {
					(void) snprintf(errbuf, SYSC_OUTPUT_LEN,
					    "processor %d failed to power off",
					    cpa->cpu_id);
				}
			} else {
				cmn_err(CE_NOTE, "Processor %d powered off.",
				    cpa->cpu_id);
			}
		}

		if (error == 0 && cpb != NULL && cpu_is_offline(cpb)) {
			if ((error = cpu_poweroff(cpb)) != 0) {
				cmn_err(CE_WARN,
				    "Processor %d failed to power off.",
				    cpb->cpu_id);

				if (errbuf != NULL) {
					(void) snprintf(errbuf, SYSC_OUTPUT_LEN,
					    "processor %d failed to power off",
					    cpb->cpu_id);
				}
			} else {
				cmn_err(CE_NOTE, "Processor %d powered off.",
				    cpb->cpu_id);
			}
		}

		/*
		 * If all the shutdowns completed, ONLY THEN, clear the
		 * incorrectly valid dtags...
		 *
		 * IMPORTANT: it is an error to read or write dtags while
		 * they are 'active'
		 */
		if (error == 0 && (cpa != NULL || cpb != NULL)) {
			u_longlong_t base = 0;
			int i;
#ifdef DEBUG
			int nonz0 = 0;
			int nonz1 = 0;
#endif
			if (cpa != NULL)
				base = FHC_DTAG_BASE(cpa->cpu_id);
			if (cpb != NULL)
				base = FHC_DTAG_BASE(cpb->cpu_id);
			ASSERT(base != 0);

			for (i = 0; i < FHC_DTAG_SIZE; i += FHC_DTAG_SKIP) {
				u_longlong_t value = lddphysio(base+i);
#ifdef lint
				value = value;
#endif
#ifdef DEBUG
				if (cpa != NULL && (value & FHC_DTAG_LOW))
					nonz0++;
				if (cpb != NULL && (value & FHC_DTAG_HIGH))
					nonz1++;
#endif
				/* always clear the dtags */
				stdphysio(base + i, 0ull);
			}
#ifdef DEBUG
			if (nonz0 || nonz1) {
				cmn_err(CE_NOTE, "!dtag results: "
				    "cpua valid %d, cpub valid %d",
				    nonz0, nonz1);
			}
#endif
		}

		break;

	default:
		break;
	}

	return (error);
}

/*
 * platform code for shutting down cpus.
 */
int
fhc_cpu_poweroff(struct cpu *cp)
{
	int board;
	fhc_bd_t *bd_list;
	int delays;
	extern void idle_stop_xcall(void);

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT((cp->cpu_flags & (CPU_EXISTS | CPU_OFFLINE | CPU_QUIESCED)) ==
	    (CPU_EXISTS | CPU_OFFLINE | CPU_QUIESCED));

	/*
	 * Lock the board so that we can safely access the
	 * registers. This cannot be done inside the pause_cpus().
	 */
	board = FHC_CPU2BOARD(cp->cpu_id);
	bd_list = fhc_bdlist_lock(board);
	ASSERT(fhc_bd_valid(board) && (bd_list->sc.type == CPU_BOARD));

	/*
	 * Capture all CPUs (except for detaching proc) to prevent
	 * crosscalls to the detaching proc until it has cleared its
	 * bit in cpu_ready_set.
	 *
	 * The CPU's remain paused and the prom_mutex is known to be free.
	 * This prevents the x-trap victim from blocking when doing prom
	 * IEEE-1275 calls at a high PIL level.
	 */
	promsafe_pause_cpus();

	/*
	 * Quiesce interrupts on the target CPU. We do this by setting
	 * the CPU 'not ready'- (i.e. removing the CPU from cpu_ready_set) to
	 * prevent it from receiving cross calls and cross traps.
	 * This prevents the processor from receiving any new soft interrupts.
	 */
	mp_cpu_quiesce(cp);

	xt_one_unchecked(cp->cpu_id, (xcfunc_t *)idle_stop_xcall,
	    (uint64_t)fhc_cpu_shutdown_self, (uint64_t)NULL);

	/*
	 * Wait for slave cpu to shutdown.
	 * Sense this by watching the hardware EPDx bit.
	 */
	for (delays = FHC_SHUTDOWN_WAIT_MSEC; delays != 0; delays--) {
		uint_t temp;

		DELAY(1000);

		/* get the current cpu power status */
		temp = *bd_list->softsp->ctrl;

		/* has the cpu actually signalled shutdown? */
		if (FHC_CPU_IS_A(cp->cpu_id)) {
			if (temp & FHC_EPDA_OFF)
				break;
		} else {
			if (temp & FHC_EPDB_OFF)
				break;
		}
	}

	start_cpus();

	fhc_bdlist_unlock();

	/* A timeout means we've lost control of the cpu. */
	if (delays == 0)
		panic("Processor %d failed during shutdown", cp->cpu_id);

	return (0);
}

/*
 * shutdown_self
 * slave side shutdown.  clean up and execute the shutdown sequence.
 */
static void
fhc_cpu_shutdown_self(void)
{
	extern void flush_windows(void);

	flush_windows();

	ASSERT(CPU->cpu_intr_actv == 0);
	ASSERT(CPU->cpu_thread == CPU->cpu_idle_thread ||
	    CPU->cpu_thread == CPU->cpu_startup_thread);

	CPU->cpu_flags = CPU_POWEROFF | CPU_OFFLINE | CPU_QUIESCED;

	(void) prom_sunfire_cpu_off();	/* inform Ultra Enterprise prom */

	os_completes_shutdown();

	panic("fhc_cpu_shutdown_self: cannot return");
	/*NOTREACHED*/
}

/*
 * Warm start CPU.
 */
static int
fhc_cpu_start(struct cpu *cp)
{
	int rv;
	int cpuid = cp->cpu_id;
	pnode_t nodeid;
	extern void restart_other_cpu(int);

	ASSERT(MUTEX_HELD(&cpu_lock));

	/* power on cpu */
	nodeid = cpunodes[cpuid].nodeid;
	ASSERT(nodeid != (pnode_t)0);
	rv = prom_wakeupcpu(nodeid);
	if (rv != 0) {
		cmn_err(CE_WARN, "Processor %d failed to power on.", cpuid);
		return (EBUSY);
	}

	cp->cpu_flags &= ~CPU_POWEROFF;

	/*
	 * NOTE: restart_other_cpu pauses cpus during the slave cpu start.
	 * This helps to quiesce the bus traffic a bit which makes
	 * the tick sync routine in the prom more robust.
	 */
	restart_other_cpu(cpuid);

	return (0);
}

/*
 * Power on CPU.
 */
int
fhc_cpu_poweron(struct cpu *cp)
{
	fhc_bd_t *bd_list;
	enum temp_state state;
	int board;
	int status;
	int status_other;
	struct cpu *cp_other;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu_is_poweredoff(cp));

	/* do not power on overtemperature cpu */
	board = FHC_CPU2BOARD(cp->cpu_id);
	bd_list = fhc_bdlist_lock(board);

	ASSERT(bd_list != NULL);
	ASSERT(bd_list->sc.type == CPU_BOARD);
	ASSERT(bd_list->dev_softsp != NULL);

	state = ((struct environ_soft_state *)
	    bd_list->dev_softsp)->tempstat.state;

	fhc_bdlist_unlock();
	if ((state == TEMP_WARN) || (state == TEMP_DANGER))
		return (EBUSY);

	status = fhc_cpu_start(cp);

	/* policy for dual cpu boards */

	if ((status == 0) &&
	    ((cp_other = cpu_get(FHC_OTHER_CPU_ID(cp->cpu_id))) != NULL)) {
		/*
		 * Do not leave board's other cpu idling in the prom.
		 * Start the other cpu and set its state to P_OFFLINE.
		 */
		status_other = fhc_cpu_start(cp_other);
		if (status_other != 0) {
			panic("fhc: failed to start second CPU"
			    " in pair %d & %d, error %d",
			    cp->cpu_id, cp_other->cpu_id, status_other);
		}
	}

	return (status);
}

/*
 * complete the shutdown sequence in case the firmware doesn't.
 *
 * If the firmware returns, then complete the shutdown code.
 * (sunfire firmware presently only updates its status.  the
 * OS must flush the D-tags and execute the shutdown instruction.)
 */
static void
os_completes_shutdown(void)
{
	pfn_t			pfn;
	tte_t			tte;
	volatile uint_t		*src;
	volatile uint_t		*dst;
	caddr_t			copy_addr;
	extern void fhc_shutdown_asm(u_longlong_t, int);
	extern void fhc_shutdown_asm_end(void);

	copy_addr = shutdown_va + FHC_SRAM_OS_OFFSET;

	/* compute sram global address for this operation */
	pfn = FHC_LOCAL_OS_PAGEBASE >> MMU_PAGESHIFT;

	/* force load i and d translations */
	tte.tte_inthi = TTE_VALID_INT | TTE_SZ_INT(TTE8K) |
	    TTE_PFN_INTHI(pfn);
	tte.tte_intlo = TTE_PFN_INTLO(pfn) |
	    TTE_HWWR_INT | TTE_PRIV_INT | TTE_LCK_INT; /* un$ */
	sfmmu_dtlb_ld_kva(shutdown_va, &tte);	/* load dtlb */
	sfmmu_itlb_ld_kva(shutdown_va, &tte);	/* load itlb */

	/*
	 * copy the special shutdown function to sram
	 * (this is a special integer copy that synchronizes with localspace
	 * accesses.  we need special throttling to ensure copy integrity)
	 */
	for (src = (uint_t *)fhc_shutdown_asm, dst = (uint_t *)copy_addr;
	    src < (uint_t *)fhc_shutdown_asm_end;
	    src++, dst++) {
		volatile uint_t dummy;

		*dst = *src;
		/*
		 * ensure non corrupting single write operations to
		 * localspace sram by interleaving reads with writes.
		 */
		dummy = *dst;
#ifdef lint
		dummy = dummy;
#endif
	}

	/*
	 * Call the shutdown sequencer.
	 * NOTE: the base flush address must be unique for each MID.
	 */
	((void (*)(u_longlong_t, int))copy_addr)(
	    FHC_BASE_NOMEM + CPU->cpu_id * FHC_MAX_ECACHE_SIZE,
	    cpunodes[CPU->cpu_id].ecache_size);
}

enum temp_state
fhc_env_temp_state(int board)
{
	fhc_bd_t *bdp;
	struct environ_soft_state *envp;

	ASSERT(fhc_bd_valid(board));

	bdp = fhc_bd(board);

	/*
	 * Due to asynchronous attach of environ, environ may
	 * not be attached by the time we start calling this routine
	 * to check the temperature state.  Environ not attaching is
	 * pathological so this will only cover the time between
	 * board connect and environ attach.
	 */
	if (!bdp->dev_softsp) {
		return (TEMP_OK);
	}
	envp = (struct environ_soft_state *)bdp->dev_softsp;

	return (envp->tempstat.state);
}

static void
fhc_tod_fault(enum tod_fault_type tod_bad)
{
	int board_num = 0;
	enum ft_class class = FT_SYSTEM;
	uint64_t addr;

	addr = (va_to_pa((void *)v_eeprom_addr)) >> BOARD_PHYADDR_SHIFT;

	if ((addr & CLOCKBOARD_PHYADDR_BITS) != CLOCKBOARD_PHYADDR_BITS) {
		/* if tod is not on clock board, */
		/* it'd be on one of io boards */
		board_num = (addr >> IO_BOARD_NUMBER_SHIFT)
		    & IO_BOARD_NUMBER_MASK;
		class = FT_BOARD;
	}

	switch (tod_bad) {
	case TOD_NOFAULT:
		clear_fault(board_num, FT_TODFAULT, class);
		break;
	case TOD_REVERSED:
	case TOD_STALLED:
	case TOD_JUMPED:
	case TOD_RATECHANGED:
		reg_fault(board_num, FT_TODFAULT, class);
		break;
	default:
		break;
	}
}
